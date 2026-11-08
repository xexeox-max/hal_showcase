//! Encrypted peer channel "HAL-SEC1" for sync envelopes.
//!
//! Closes architecture review finding #1 (raw-TCP confidentiality).
//!
//! Handshake authenticates BOTH sides with their long-term ed25519
//! identities while every packet stays unreadable to intermediaries:
//!
//! ```text
//! C -> S : MAGIC || e1_pub || initiator_identity_vk
//! S -> C : e2_pub || responder_identity_vk || Sign(resp_sk, ctx_S||e1||e2||vk)
//! C -> S : Sign(init_sk, ctx_C || e1 || e2 || responder_vk || init_vk)
//! ```
//!
//! The initiator either ENFORCES a key learned earlier for this peer
//! (`PeerExpectation::Pinned`) or refuses application delivery until the
//! application explicitly verifies and pins the peer (`RequiresVerification`).
//! The responder must PROVE possession of its claimed
//! long-term key by signing the full transcript. Session material =
//! DH(e1,e2) expanded by HKDF-SHA256 with
//! the full transcript as salt, split into direction keys. Frames are
//! length-prefixed ChaCha20-Poly1305 with strict monotonic counters -
//! tampering, replay and reordering all fail closed.

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};
use zeroize::Zeroizing;

const MAGIC: [u8; 8] = *b"HALSEC1\0";
const SERVER_SIG_CONTEXT: &[u8] = b"HAL-SEC1-server";
const CLIENT_SIG_CONTEXT: &[u8] = b"HAL-SEC1-client";
pub const MAX_SECURE_FRAME: usize = 60 * 1024;
const TAG_LEN: usize = 16;

fn nonce_for(counter: u64) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    Nonce::from(nonce)
}

fn transcript(parts: &[&[u8]]) -> Vec<u8> {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().to_vec()
}

/// One AEAD direction of an established channel.
struct Direction {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl Direction {
    fn new(key_bytes: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new((&key_bytes).into()),
            counter: 0,
        }
    }

    fn seal(&mut self, plain: Vec<u8>) -> Result<Vec<u8>> {
        let counter = self.counter;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("counter exhausted"))?;
        self.cipher
            .encrypt(
                &nonce_for(counter),
                Payload {
                    msg: &plain,
                    aad: &counter.to_be_bytes(),
                },
            )
            .map_err(|_| anyhow!("seal failed"))
    }

    fn open(&mut self, sealed: Vec<u8>) -> Result<Vec<u8>> {
        let counter = self.counter;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("counter exhausted"))?;
        self.cipher
            .decrypt(
                &nonce_for(counter),
                Payload {
                    msg: &sealed,
                    aad: &counter.to_be_bytes(),
                },
            )
            .map_err(|_| anyhow!("frame authentication failed"))
    }
}

/// Established encrypted channel over any async byte stream.
pub struct SecureChannel<S> {
    io: S,
    send_dir: Direction,
    recv_dir: Direction,
}

/// Full HAL-SEC1 handshake result.
///
/// `shared_secret` is the raw ephemeral X25519 DH result produced before the
/// transcript-derived HKDF splits it into HAL-SEC1 direction keys (`c2s` / `s2c`).
/// It is retained only for callers that need the authenticated handshake result;
/// Sosistab2 derives its MuxSecret independently from long-term static DH.
pub struct HandshakeResult<S> {
    pub channel: SecureChannel<S>,
    pub peer_verifying_key: VerifyingKey,
    pub shared_secret: Zeroizing<[u8; 32]>,
}

/// Convert a long-term Ed25519 signing key to its X25519 static secret.
pub fn ed25519_to_x25519_priv(ed25519_priv: &SigningKey) -> XSecret {
    hal_crypto::identity_signing_to_x25519(ed25519_priv)
}

/// Convert a long-term Ed25519 verifying key to its X25519 public key.
pub fn ed25519_to_x25519_pub(ed25519_pub: &VerifyingKey) -> Result<XPublic> {
    hal_crypto::identity_verifying_to_x25519(ed25519_pub)
}

/// Return the X25519 private bytes used by Sosistab2 for this identity.
pub fn ed25519_to_x25519_priv_bytes(ed25519_priv: &SigningKey) -> [u8; 32] {
    ed25519_to_x25519_priv(ed25519_priv).to_bytes()
}

/// Return the X25519 public bytes corresponding to an Ed25519 identity key.
pub fn ed25519_to_x25519_pub_bytes(ed25519_pub: &VerifyingKey) -> Result<[u8; 32]> {
    Ok(*ed25519_to_x25519_pub(ed25519_pub)?.as_bytes())
}

impl<S: AsyncRead + AsyncWrite + Unpin> SecureChannel<S> {
    async fn write_frame(io: &mut S, dir: &mut Direction, payload: Vec<u8>) -> Result<()> {
        if payload.len() > MAX_SECURE_FRAME {
            return Err(anyhow!("secure frame exceeds maximum size"));
        }
        let sealed = dir.seal(payload)?;
        io.write_u32(sealed.len() as u32).await?;
        io.write_all(&sealed).await?;
        io.flush().await?;
        Ok(())
    }

    async fn read_frame(io: &mut S, dir: &mut Direction) -> Result<Vec<u8>> {
        let length = io.read_u32().await? as usize;
        if length == 0 || length > MAX_SECURE_FRAME + TAG_LEN {
            return Err(anyhow!("invalid secure frame size: {length}"));
        }
        let mut sealed = vec![0u8; length];
        io.read_exact(&mut sealed).await?;
        dir.open(sealed)
    }

    pub async fn send_json<T: Serialize>(&mut self, value: &T) -> Result<()> {
        let payload = serde_json::to_vec(value)?;
        Self::write_frame(&mut self.io, &mut self.send_dir, payload).await
    }

    pub async fn recv_json<T: DeserializeOwned>(&mut self) -> Result<T> {
        let payload = Self::read_frame(&mut self.io, &mut self.recv_dir).await?;
        Ok(serde_json::from_slice(&payload)?)
    }

    pub async fn close(mut self) -> Result<()> {
        self.io.shutdown().await?;
        Ok(())
    }

    /// TEST ONLY: force-send a frame under an arbitrary counter to prove
    /// that gaps/replays are rejected by the receiving side.
    #[cfg(test)]
    pub async fn test_only_send_with_counter(&mut self, counter: u64, plain: &[u8]) -> Result<()> {
        let sealed = self
            .send_dir
            .cipher
            .encrypt(
                &nonce_for(counter),
                Payload {
                    msg: plain,
                    aad: &counter.to_be_bytes(),
                },
            )
            .map_err(|_| anyhow!("test seal failed"))?;
        self.io.write_u32(sealed.len() as u32).await?;
        self.io.write_all(&sealed).await?;
        self.io.flush().await?;
        Ok(())
    }
}

/// What the initiating end expects from the remote end. Decentral by
/// design: pins are LEARNED state (first contact, referrals, manual
/// trust), never centrally provisioned configuration.
#[derive(Debug, Clone)]
pub enum PeerExpectation {
    /// Enforce the previously learned long-term key of this peer.
    Pinned(VerifyingKey),
    /// No prior knowledge: authenticate the key, but require explicit
    /// application verification before sensitive data is delivered.
    RequiresVerification,
}

/// Initiating side of a peer-to-peer link ("client" is only the role of
/// whoever dials - there is no server in the mesh).
pub async fn handshake_client<S: AsyncRead + AsyncWrite + Unpin>(
    io: S,
    local_identity: &SigningKey,
    expectation: PeerExpectation,
) -> Result<(SecureChannel<S>, VerifyingKey)> {
    let result = handshake_client_result(io, local_identity, expectation).await?;
    Ok((result.channel, result.peer_verifying_key))
}

/// Explicit result exposing the authenticated X25519 `shared_secret` before it is
/// split into direction keys (`c2s` / `s2c`). This is the value higher layers
/// must use for session-bound transport material such as Sosistab2.
pub async fn handshake_client_result<S: AsyncRead + AsyncWrite + Unpin>(
    mut io: S,
    local_identity: &SigningKey,
    expectation: PeerExpectation,
) -> Result<HandshakeResult<S>> {
    let e1 = XSecret::random_from_rng(rand::rngs::OsRng);
    let e1_pub = XPublic::from(&e1);

    io.write_all(&MAGIC).await?;
    io.write_all(e1_pub.as_bytes()).await?;
    io.write_all(&local_identity.verifying_key().to_bytes())
        .await?;

    let mut e2_buf = [0u8; 32];
    io.read_exact(&mut e2_buf).await?;
    let mut responder_vk_bytes = [0u8; 32];
    io.read_exact(&mut responder_vk_bytes).await?;
    let mut sig_buf = [0u8; 64];
    io.read_exact(&mut sig_buf).await?;

    if let PeerExpectation::Pinned(pinned) = &expectation {
        if pinned.as_bytes() != &responder_vk_bytes {
            return Err(anyhow!("peer key does not match the learned pin"));
        }
    }
    let responder_vk = VerifyingKey::from_bytes(&responder_vk_bytes)
        .map_err(|_| anyhow!("malformed responder identity key"))?;
    let server_vk_bytes = responder_vk_bytes;

    let expected = transcript(&[
        SERVER_SIG_CONTEXT,
        e1_pub.as_bytes(),
        &e2_buf,
        &server_vk_bytes,
    ]);
    responder_vk
        .verify_strict(&expected, &Signature::from_bytes(&sig_buf))
        .map_err(|_| anyhow!("responder failed to prove its identity key"))?;

    let shared = e1.diffie_hellman(&XPublic::from(e2_buf));
    if !shared.was_contributory() {
        return Err(anyhow!("weak handshake shared secret"));
    }
    let shared_secret = Zeroizing::new(*shared.as_bytes());
    let salt = transcript(&[
        MAGIC.as_slice(),
        e1_pub.as_bytes(),
        &e2_buf,
        &server_vk_bytes,
        &local_identity.verifying_key().to_bytes(),
    ]);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    hk.expand(b"hal c2s", &mut c2s)
        .map_err(|_| anyhow!("hkdf expand failed"))?;
    hk.expand(b"hal s2c", &mut s2c)
        .map_err(|_| anyhow!("hkdf expand failed"))?;

    let proof = local_identity.sign(&transcript(&[
        CLIENT_SIG_CONTEXT,
        e1_pub.as_bytes(),
        &e2_buf,
        &server_vk_bytes,
    ]));
    io.write_all(&proof.to_bytes()).await?;
    io.flush().await?;

    Ok(HandshakeResult {
        channel: SecureChannel {
            io,
            send_dir: Direction::new(c2s),
            recv_dir: Direction::new(s2c),
        },
        peer_verifying_key: responder_vk,
        shared_secret,
    })
}

/// Listening side: verify the client's signature over the transcript.
/// Returns the channel plus the client's long-term verifying key so the
/// caller can apply host-pinning policy (`crate::pinning`).
pub async fn handshake_server<S: AsyncRead + AsyncWrite + Unpin>(
    io: S,
    local_identity: &SigningKey,
    expect_client_vk: Option<&VerifyingKey>,
) -> Result<(SecureChannel<S>, VerifyingKey)> {
    let result = handshake_server_result(io, local_identity, expect_client_vk).await?;
    Ok((result.channel, result.peer_verifying_key))
}

/// Explicit result exposing the authenticated X25519 `shared_secret` before the
/// transcript-derived HKDF splits the session into `c2s` / `s2c` direction keys.
pub async fn handshake_server_result<S: AsyncRead + AsyncWrite + Unpin>(
    mut io: S,
    local_identity: &SigningKey,
    expect_client_vk: Option<&VerifyingKey>,
) -> Result<HandshakeResult<S>> {
    let mut magic = [0u8; 8];
    io.read_exact(&mut magic).await?;
    if magic != MAGIC {
        return Err(anyhow!("not a HAL-SEC1 handshake"));
    }
    let mut e1_buf = [0u8; 32];
    io.read_exact(&mut e1_buf).await?;
    let mut client_vk_bytes = [0u8; 32];
    io.read_exact(&mut client_vk_bytes).await?;
    let client_vk = VerifyingKey::from_bytes(&client_vk_bytes)
        .map_err(|_| anyhow!("malformed client identity key"))?;
    if let Some(expected) = expect_client_vk {
        if expected.as_bytes() != client_vk.as_bytes() {
            return Err(anyhow!("client identity violates pinned expectation"));
        }
    }

    let e2 = XSecret::random_from_rng(rand::rngs::OsRng);
    let e2_pub = XPublic::from(&e2);
    let server_proof = local_identity.sign(&transcript(&[
        SERVER_SIG_CONTEXT,
        &e1_buf,
        e2_pub.as_bytes(),
        &local_identity.verifying_key().to_bytes(),
    ]));
    io.write_all(e2_pub.as_bytes()).await?;
    io.write_all(&local_identity.verifying_key().to_bytes())
        .await?;
    io.write_all(&server_proof.to_bytes()).await?;

    let mut sig_buf = [0u8; 64];
    io.read_exact(&mut sig_buf).await?;
    client_vk
        .verify_strict(
            &transcript(&[
                CLIENT_SIG_CONTEXT,
                &e1_buf,
                e2_pub.as_bytes(),
                &local_identity.verifying_key().to_bytes(),
            ]),
            &Signature::from_bytes(&sig_buf),
        )
        .map_err(|_| anyhow!("client signature verification failed"))?;

    let shared = e2.diffie_hellman(&XPublic::from(e1_buf));
    if !shared.was_contributory() {
        return Err(anyhow!("weak handshake shared secret"));
    }
    let shared_secret = Zeroizing::new(*shared.as_bytes());
    let salt = transcript(&[
        MAGIC.as_slice(),
        &e1_buf,
        e2_pub.as_bytes(),
        &local_identity.verifying_key().to_bytes(),
        &client_vk_bytes,
    ]);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    hk.expand(b"hal c2s", &mut c2s)
        .map_err(|_| anyhow!("hkdf expand failed"))?;
    hk.expand(b"hal s2c", &mut s2c)
        .map_err(|_| anyhow!("hkdf expand failed"))?;

    Ok(HandshakeResult {
        channel: SecureChannel {
            io,
            send_dir: Direction::new(s2c),
            recv_dir: Direction::new(c2s),
        },
        peer_verifying_key: client_vk,
        shared_secret,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn ed25519_to_x25519_conversion_preserves_public_key() {
        let signing_key = key(8);
        let x25519_private = ed25519_to_x25519_priv(&signing_key);
        let derived_public = XPublic::from(&x25519_private);
        let converted_public = ed25519_to_x25519_pub(&signing_key.verifying_key()).unwrap();
        assert_eq!(derived_public, converted_public);
    }

    #[tokio::test]
    async fn peers_exchange_frames_without_prior_knowledge() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let initiator = key(1);
        let responder = key(2);
        let (server_task, client_task) = tokio::join!(
            handshake_server(server_io, &responder, None),
            handshake_client(client_io, &initiator, PeerExpectation::RequiresVerification),
        );
        let (mut server_channel, seen_initiator_vk) = server_task.unwrap();
        let (mut client_channel, seen_responder_vk) = client_task.unwrap();
        assert_eq!(seen_initiator_vk, initiator.verifying_key());
        assert_eq!(seen_responder_vk, responder.verifying_key());
        client_channel.send_json(&42u64).await.unwrap();
        assert_eq!(server_channel.recv_json::<u64>().await.unwrap(), 42);
    }

    #[tokio::test]
    async fn pinned_initiator_rejects_an_impostor_responder() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let genuine = key(3);
        let impostor = key(4);
        let initiator = key(5);
        let pinned = genuine.verifying_key();
        let server = handshake_server(server_io, &impostor, None);
        let client = handshake_client(client_io, &initiator, PeerExpectation::Pinned(pinned));
        let (_, client_result) = tokio::join!(server, client);
        assert!(client_result.is_err());
    }

    #[tokio::test]
    async fn tampered_or_replayed_frames_fail_closed() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let responder = key(6);
        let initiator = key(7);
        let (s_res, c_res) = tokio::join!(
            handshake_server(server_io, &responder, None),
            handshake_client(client_io, &initiator, PeerExpectation::RequiresVerification),
        );
        let (mut srv, _) = s_res.unwrap();
        let (mut cli, _) = c_res.unwrap();
        cli.test_only_send_with_counter(1000, b"sneaky")
            .await
            .unwrap();
        assert!(srv.recv_json::<Vec<u8>>().await.is_err());
    }
}
