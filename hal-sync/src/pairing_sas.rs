use anyhow::{anyhow, Result};
use ed25519_dalek::VerifyingKey;
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

const COMMITMENT_DOMAIN: &[u8] = b"HAL-WSS-SAS-COMMIT-v1\0";
const TRANSCRIPT_DOMAIN: &[u8] = b"HAL-WSS-SAS-TRANSCRIPT-v1\0";
const SAS_INFO: &[u8] = b"HAL-WSS-SAS-CODE-v1";
const SAS_RANGE: u64 = 1_000_000;
pub(crate) const SAS_PAIRING_MAX_SESSIONS: usize = 8;
pub(crate) const SAS_PAIRING_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SasRole {
    Initiator,
    Responder,
}

impl SasRole {
    fn tag(self) -> u8 {
        match self {
            Self::Initiator => 1,
            Self::Responder => 2,
        }
    }

    fn other(self) -> Self {
        match self {
            Self::Initiator => Self::Responder,
            Self::Responder => Self::Initiator,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SasCommitment {
    pub session_id: String,
    pub role: SasRole,
    pub identity_id: String,
    pub public_key_hex: String,
    pub peer_identity_id: String,
    pub ephemeral_public_key_hex: String,
    pub commitment_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "stage", rename_all = "snake_case")]
pub enum SasPairingMessage {
    Commitment {
        commitment: SasCommitment,
    },
    Reveal {
        session_id: String,
        nonce_hex: String,
    },
    Confirm {
        session_id: String,
        accepted: bool,
    },
    Complete {
        session_id: String,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SasPairingPrompt {
    pub session_id: String,
    pub peer_identity_id: String,
    pub code: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SasPairingStatus {
    Committing,
    Revealing,
    AwaitingUserConfirmation,
    Confirming,
}

pub struct SasPairingSession {
    pub(crate) contribution: SasContribution,
    pub(crate) remote_commitment: Option<SasCommitment>,
    pub(crate) remote_nonce_hex: Option<String>,
    pub(crate) mux_sender: Option<crate::mux::MuxSender>,
    pub(crate) peer_identity_id: String,
    pub(crate) peer_public_key_hex: String,
    pub(crate) code: Option<String>,
    pub(crate) status: SasPairingStatus,
    pub(crate) local_commitment_sent: bool,
    pub(crate) local_reveal_sent: bool,
    pub(crate) local_confirmation_sent: bool,
    pub(crate) remote_confirmation_received: bool,
    pub(crate) remote_completion_received: bool,
    pub(crate) started_at: Instant,
}

#[derive(Default)]
pub struct SasPairingState {
    pub(crate) sessions: Mutex<HashMap<String, SasPairingSession>>,
    pub(crate) prompts: Mutex<HashMap<String, SasPairingPrompt>>,
}

impl SasPairingSession {
    pub(crate) fn new(
        contribution: SasContribution,
        peer_identity_id: String,
        peer_public_key_hex: String,
    ) -> Self {
        Self {
            contribution,
            remote_commitment: None,
            remote_nonce_hex: None,
            mux_sender: None,
            peer_identity_id,
            peer_public_key_hex,
            code: None,
            status: SasPairingStatus::Committing,
            local_commitment_sent: false,
            local_reveal_sent: false,
            local_confirmation_sent: false,
            remote_confirmation_received: false,
            remote_completion_received: false,
            started_at: Instant::now(),
        }
    }

    pub(crate) fn session_id(&self) -> &str {
        &self.contribution.commitment.session_id
    }

    pub(crate) fn prompt(&self) -> Option<SasPairingPrompt> {
        self.code.as_ref().map(|code| SasPairingPrompt {
            session_id: self.session_id().to_string(),
            peer_identity_id: self.peer_identity_id.clone(),
            code: code.clone(),
        })
    }

    pub(crate) fn record_local_confirmation(&mut self) -> Result<bool> {
        if self.code.is_none() {
            return Err(anyhow!("SAS code has not been verified yet"));
        }
        self.local_confirmation_sent = true;
        self.status = SasPairingStatus::Confirming;
        Ok(self.remote_confirmation_received)
    }

    pub(crate) fn record_remote_confirmation(&mut self) -> Result<bool> {
        if self.code.is_none() {
            return Err(anyhow!("SAS code has not been verified yet"));
        }
        self.remote_confirmation_received = true;
        Ok(self.local_confirmation_sent)
    }

    pub(crate) fn record_remote_completion(&mut self) -> Result<bool> {
        if self.code.is_none() {
            return Err(anyhow!("SAS code has not been verified yet"));
        }
        self.remote_completion_received = true;
        Ok(self.is_fully_confirmed())
    }

    pub(crate) fn is_fully_confirmed(&self) -> bool {
        self.local_confirmation_sent && self.remote_confirmation_received
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.is_fully_confirmed() && self.remote_completion_received
    }
}

pub struct SasContribution {
    commitment: SasCommitment,
    nonce: [u8; 32],
    ephemeral_secret: StaticSecret,
}

impl SasContribution {
    pub fn create(
        session_id: [u8; 16],
        role: SasRole,
        identity_id: String,
        public_key_hex: String,
        peer_identity_id: String,
    ) -> Result<Self> {
        let public_key_bytes: [u8; 32] = hex::decode(&public_key_hex)?
            .try_into()
            .map_err(|_| anyhow!("pairing identity public key must be 32 bytes"))?;
        let public_key = VerifyingKey::from_bytes(&public_key_bytes)?;
        if crate::dht::NodeId::from_public_key(&public_key).to_hex() != identity_id {
            return Err(anyhow!("pairing identity does not match its public key"));
        }

        let mut nonce = [0u8; 32];
        let mut ephemeral_secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        OsRng.fill_bytes(&mut ephemeral_secret_bytes);
        let ephemeral_secret = StaticSecret::from(ephemeral_secret_bytes);
        ephemeral_secret_bytes.zeroize();
        let ephemeral_public_key = X25519PublicKey::from(&ephemeral_secret).to_bytes();
        let session_id = hex::encode(session_id);
        let mut commitment = SasCommitment {
            session_id,
            role,
            identity_id,
            public_key_hex,
            peer_identity_id,
            ephemeral_public_key_hex: hex::encode(ephemeral_public_key),
            commitment_hex: String::new(),
        };
        commitment.commitment_hex = hex::encode(commitment_digest(&commitment, &nonce)?);

        Ok(Self {
            commitment,
            nonce,
            ephemeral_secret,
        })
    }

    pub fn commitment(&self) -> SasCommitment {
        self.commitment.clone()
    }

    pub fn reveal_nonce_hex(&self) -> String {
        hex::encode(self.nonce)
    }

    pub fn derive_code(
        &self,
        remote_commitment: &SasCommitment,
        remote_nonce_hex: &str,
    ) -> Result<String> {
        validate_commitment_pair(&self.commitment, remote_commitment)?;
        let remote_nonce: [u8; 32] = hex::decode(remote_nonce_hex)?
            .try_into()
            .map_err(|_| anyhow!("pairing reveal nonce must be 32 bytes"))?;
        let expected = commitment_digest(remote_commitment, &remote_nonce)?;
        if hex::encode(expected) != remote_commitment.commitment_hex {
            return Err(anyhow!("pairing reveal does not match its commitment"));
        }

        let remote_public_bytes: [u8; 32] =
            hex::decode(&remote_commitment.ephemeral_public_key_hex)?
                .try_into()
                .map_err(|_| anyhow!("pairing ephemeral public key must be 32 bytes"))?;
        let remote_public_key = X25519PublicKey::from(remote_public_bytes);
        let shared_secret = self.ephemeral_secret.diffie_hellman(&remote_public_key);
        if shared_secret.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(anyhow!("pairing produced an invalid shared secret"));
        }

        let (initiator, initiator_nonce, responder, responder_nonce) =
            if self.commitment.role == SasRole::Initiator {
                (
                    &self.commitment,
                    &self.nonce,
                    remote_commitment,
                    &remote_nonce,
                )
            } else {
                (
                    remote_commitment,
                    &remote_nonce,
                    &self.commitment,
                    &self.nonce,
                )
            };
        let mut transcript = Sha256::new();
        transcript.update(TRANSCRIPT_DOMAIN);
        transcript.update(hex::decode(&initiator.session_id)?);
        append_commitment(&mut transcript, initiator)?;
        transcript.update(initiator_nonce);
        append_commitment(&mut transcript, responder)?;
        transcript.update(responder_nonce);
        let transcript_hash = transcript.finalize();

        let hkdf = Hkdf::<Sha256>::new(Some(&transcript_hash), shared_secret.as_bytes());
        let mut code_material = [0u8; 8];
        hkdf.expand(SAS_INFO, &mut code_material)
            .map_err(|_| anyhow!("unable to derive pairing SAS"))?;
        let code = u64::from_be_bytes(code_material) % SAS_RANGE;
        Ok(format!("{code:06}"))
    }
}

fn validate_commitment_pair(local: &SasCommitment, remote: &SasCommitment) -> Result<()> {
    if local.session_id != remote.session_id
        || local.role == remote.role
        || local.role.other() != remote.role
        || local.identity_id != remote.peer_identity_id
        || local.peer_identity_id != remote.identity_id
    {
        return Err(anyhow!(
            "pairing commitments refer to different sessions or identities"
        ));
    }
    verify_identity(&local.identity_id, &local.public_key_hex)?;
    verify_identity(&remote.identity_id, &remote.public_key_hex)?;
    let local_ephemeral: [u8; 32] = hex::decode(&local.ephemeral_public_key_hex)?
        .try_into()
        .map_err(|_| anyhow!("local ephemeral public key must be 32 bytes"))?;
    let remote_ephemeral: [u8; 32] = hex::decode(&remote.ephemeral_public_key_hex)?
        .try_into()
        .map_err(|_| anyhow!("remote ephemeral public key must be 32 bytes"))?;
    if local_ephemeral.iter().all(|byte| *byte == 0)
        || remote_ephemeral.iter().all(|byte| *byte == 0)
    {
        return Err(anyhow!(
            "pairing commitment contains an invalid ephemeral key"
        ));
    }
    Ok(())
}

fn verify_identity(identity_id: &str, public_key_hex: &str) -> Result<()> {
    let public_key_bytes: [u8; 32] = hex::decode(public_key_hex)?
        .try_into()
        .map_err(|_| anyhow!("pairing identity public key must be 32 bytes"))?;
    let public_key = VerifyingKey::from_bytes(&public_key_bytes)?;
    if crate::dht::NodeId::from_public_key(&public_key).to_hex() != identity_id {
        return Err(anyhow!("pairing identity does not match its public key"));
    }
    Ok(())
}

fn commitment_digest(commitment: &SasCommitment, nonce: &[u8; 32]) -> Result<[u8; 32]> {
    let session_id: [u8; 16] = hex::decode(&commitment.session_id)?
        .try_into()
        .map_err(|_| anyhow!("pairing session ID must be 16 bytes"))?;
    let public_key: [u8; 32] = hex::decode(&commitment.public_key_hex)?
        .try_into()
        .map_err(|_| anyhow!("pairing identity public key must be 32 bytes"))?;
    let ephemeral: [u8; 32] = hex::decode(&commitment.ephemeral_public_key_hex)?
        .try_into()
        .map_err(|_| anyhow!("pairing ephemeral public key must be 32 bytes"))?;

    let mut digest = Sha256::new();
    digest.update(COMMITMENT_DOMAIN);
    digest.update(session_id);
    digest.update([commitment.role.tag()]);
    digest.update((commitment.identity_id.len() as u32).to_be_bytes());
    digest.update(commitment.identity_id.as_bytes());
    digest.update((commitment.peer_identity_id.len() as u32).to_be_bytes());
    digest.update(commitment.peer_identity_id.as_bytes());
    digest.update(public_key);
    digest.update(ephemeral);
    digest.update(nonce);
    Ok(digest.finalize().into())
}

fn append_commitment(digest: &mut Sha256, commitment: &SasCommitment) -> Result<()> {
    digest.update([commitment.role.tag()]);
    digest.update((commitment.identity_id.len() as u32).to_be_bytes());
    digest.update(commitment.identity_id.as_bytes());
    digest.update((commitment.peer_identity_id.len() as u32).to_be_bytes());
    digest.update(commitment.peer_identity_id.as_bytes());
    digest.update(hex::decode(&commitment.public_key_hex)?);
    digest.update(hex::decode(&commitment.ephemeral_public_key_hex)?);
    digest.update(hex::decode(&commitment.commitment_hex)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn identity(seed: u8) -> (String, String) {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let public_key = key.verifying_key();
        (
            crate::dht::NodeId::from_public_key(&public_key).to_hex(),
            hex::encode(public_key.to_bytes()),
        )
    }

    fn pairing_session() -> SasPairingSession {
        let (local_id, local_key) = identity(105);
        let (peer_id, peer_key) = identity(106);
        let contribution = SasContribution::create(
            [9u8; 16],
            SasRole::Initiator,
            local_id,
            local_key,
            peer_id.clone(),
        )
        .expect("pairing contribution");
        let mut session = SasPairingSession::new(contribution, peer_id, peer_key);
        session.code = Some("123456".to_string());
        session
    }

    #[test]
    fn both_peers_derive_same_sas_from_committed_reveals() {
        let (initiator_id, initiator_key) = identity(101);
        let (responder_id, responder_key) = identity(102);
        let session_id = [7u8; 16];
        let initiator = SasContribution::create(
            session_id,
            SasRole::Initiator,
            initiator_id.clone(),
            initiator_key,
            responder_id.clone(),
        )
        .expect("initiator contribution");
        let responder = SasContribution::create(
            session_id,
            SasRole::Responder,
            responder_id,
            responder_key,
            initiator_id,
        )
        .expect("responder contribution");

        let initiator_code = initiator
            .derive_code(&responder.commitment(), &responder.reveal_nonce_hex())
            .expect("initiator SAS");
        let responder_code = responder
            .derive_code(&initiator.commitment(), &initiator.reveal_nonce_hex())
            .expect("responder SAS");

        assert_eq!(initiator_code, responder_code);
        assert_eq!(initiator_code.len(), 6);
        assert!(initiator_code.bytes().all(|byte| byte.is_ascii_digit()));
    }

    #[test]
    fn sas_rejects_tampered_reveal_or_identity_binding() {
        let (initiator_id, initiator_key) = identity(103);
        let (responder_id, responder_key) = identity(104);
        let initiator = SasContribution::create(
            [8u8; 16],
            SasRole::Initiator,
            initiator_id.clone(),
            initiator_key,
            responder_id.clone(),
        )
        .expect("initiator contribution");
        let responder = SasContribution::create(
            [8u8; 16],
            SasRole::Responder,
            responder_id,
            responder_key,
            initiator_id,
        )
        .expect("responder contribution");
        let mut nonce = hex::decode(responder.reveal_nonce_hex()).expect("nonce hex");
        nonce[0] ^= 1;

        assert!(initiator
            .derive_code(&responder.commitment(), &hex::encode(nonce))
            .is_err());
    }

    #[test]
    fn mutual_sas_confirmation_is_order_independent() {
        let mut remote_first = pairing_session();
        assert!(!remote_first
            .record_remote_confirmation()
            .expect("record remote confirmation"));
        assert!(remote_first.remote_confirmation_received);
        assert!(remote_first
            .record_local_confirmation()
            .expect("record local confirmation"));

        let mut local_first = pairing_session();
        assert!(!local_first
            .record_local_confirmation()
            .expect("record local confirmation"));
        assert!(local_first
            .record_remote_confirmation()
            .expect("record remote confirmation"));
    }

    #[test]
    fn remote_completion_is_retained_until_both_confirmations() {
        let mut session = pairing_session();
        assert!(!session
            .record_remote_completion()
            .expect("record remote completion"));
        assert!(!session.is_complete());

        assert!(!session
            .record_remote_confirmation()
            .expect("record remote confirmation"));
        assert!(session
            .record_local_confirmation()
            .expect("record local confirmation"));
        assert!(session.is_complete());
    }

    #[test]
    fn sas_confirmation_is_rejected_before_code_generation() {
        let mut session = pairing_session();
        session.code = None;
        assert!(session.record_remote_confirmation().is_err());
        assert!(!session.remote_confirmation_received);
    }
}
