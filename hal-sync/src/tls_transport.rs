use crate::mux::StreamKind;
use anyhow::{anyhow, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::SignatureScheme;
use std::sync::{Arc, Once, OnceLock};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
#[cfg(test)]
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

// SECURITY MODEL:
//   TLS accept-any-cert = NO MITM protection at TLS layer.
//   MITM protection comes ONLY from channel binding:
//     - Ed25519 signature covers TLS exporter value.
//     - MITM creates two separate TLS sessions.
//     - Exporter values differ -> binding verification fails.
//
//   WITHOUT channel binding, this module is INSECURE.
//   Do not remove exporter from binding signature.
//
// TOFU WEAKNESS:
//   First contact is vulnerable to MITM (standard TOFU).
//   Use QR / invite link for first-contact verification.
//
// TESTING NOTE:
//   tls_channel_binding_replay_rejected uses a synthetic exporter
//   (all zeros) for the "different session" case. This proves the
//   cryptographic property: signature(X) does not verify under Y ≠ X.
//
//   tls_exporters_differ_between_sessions proves that two real TLS
//   sessions produce different exporters, which combined with the
//   above gives end-to-end MITM protection.

pub const MAX_TLS_ENVELOPE_SIZE: usize = 60 * 1024;
const BINDING_LABEL: &[u8] = b"hal-identity-binding";
const ALLOWED_SNI: [&str; 3] = ["www.cloudflare.com", "cdn.jsdelivr.net", "www.google.com"];

static TLS_CRYPTO_INIT: Once = Once::new();
static SERVER_CONFIG: OnceLock<Arc<rustls::ServerConfig>> = OnceLock::new();

fn init_tls_crypto() {
    TLS_CRYPTO_INIT.call_once(|| {
        let _ = CryptoProvider::install_default(default_provider());
    });
}

fn choose_sni() -> &'static str {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as usize;
    ALLOWED_SNI[seed % ALLOWED_SNI.len()]
}

pub fn sni_for_stream_kind(kind: StreamKind) -> &'static str {
    match kind {
        StreamKind::Sync | StreamKind::Priority => "www.cloudflare.com",
        StreamKind::MediaSignal | StreamKind::Dht => "cdn.jsdelivr.net",
        StreamKind::Control => "www.google.com",
    }
}

fn server_name_for_client(kind: StreamKind) -> Result<ServerName<'static>> {
    ServerName::try_from(sni_for_stream_kind(kind)).map_err(|e| anyhow!("invalid SNI: {e}"))
}

#[derive(Debug)]
struct AcceptAnyVerifier;

impl ServerCertVerifier for AcceptAnyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
        ]
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
}

pub(crate) enum TlsConn {
    Client(tokio_rustls::client::TlsStream<TcpStream>),
    Server(tokio_rustls::server::TlsStream<TcpStream>),
    StreamClient(tokio_rustls::client::TlsStream<tokio::io::DuplexStream>),
}

impl AsyncRead for TlsConn {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            TlsConn::Client(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            TlsConn::Server(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            TlsConn::StreamClient(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TlsConn {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            TlsConn::Client(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            TlsConn::Server(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            TlsConn::StreamClient(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            TlsConn::Client(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            TlsConn::Server(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            TlsConn::StreamClient(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            TlsConn::Client(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            TlsConn::Server(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            TlsConn::StreamClient(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl TlsConn {
    async fn write_u32(&mut self, value: u32) -> std::io::Result<()> {
        match self {
            TlsConn::Client(stream) => stream.write_u32(value).await,
            TlsConn::Server(stream) => stream.write_u32(value).await,
            TlsConn::StreamClient(stream) => stream.write_u32(value).await,
        }
    }

    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            TlsConn::Client(stream) => stream.write_all(buf).await,
            TlsConn::Server(stream) => stream.write_all(buf).await,
            TlsConn::StreamClient(stream) => stream.write_all(buf).await,
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            TlsConn::Client(stream) => stream.flush().await,
            TlsConn::Server(stream) => stream.flush().await,
            TlsConn::StreamClient(stream) => stream.flush().await,
        }
    }

    async fn read_u32(&mut self) -> std::io::Result<u32> {
        match self {
            TlsConn::Client(stream) => stream.read_u32().await,
            TlsConn::Server(stream) => stream.read_u32().await,
            TlsConn::StreamClient(stream) => stream.read_u32().await,
        }
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            TlsConn::Client(stream) => stream.read_exact(buf).await,
            TlsConn::Server(stream) => stream.read_exact(buf).await,
            TlsConn::StreamClient(stream) => stream.read_exact(buf).await,
        }
    }
}

fn client_config() -> Result<rustls::ClientConfig> {
    init_tls_crypto();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|error| anyhow!("TLS protocol configuration: {error}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyVerifier))
        .with_no_client_auth();

    log::info!(target: "HAL_DHT", "TLS: applied standard rustls profile");
    Ok(config)
}

fn build_server_config() -> Result<rustls::ServerConfig> {
    init_tls_crypto();
    let cert_domain = choose_sni().to_string();
    let cert =
        rcgen::generate_simple_self_signed([cert_domain]).map_err(|e| anyhow!("rcgen: {e}"))?;
    let cert_der = CertificateDer::from(cert.cert.der().clone());
    let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der())
        .map_err(|e| anyhow!("private key: {e}"))?;

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| anyhow!("server config: {e}"))
}

fn server_config() -> Result<Arc<rustls::ServerConfig>> {
    if let Some(cfg) = SERVER_CONFIG.get() {
        return Ok(Arc::clone(cfg));
    }

    let cfg = Arc::new(build_server_config()?);
    let _ = SERVER_CONFIG.set(Arc::clone(&cfg));
    Ok(SERVER_CONFIG.get().cloned().unwrap_or(cfg))
}

fn binding_message(role: &[u8], public_key: &[u8; 32], exporter: &[u8; 32]) -> Vec<u8> {
    let mut msg = b"HAL_TLS_BINDING".to_vec();
    msg.extend_from_slice(role);
    msg.extend_from_slice(public_key);
    msg.extend_from_slice(exporter);
    msg
}

#[cfg(test)]
pub(crate) fn test_binding_signature(
    local_identity: &SigningKey,
    role: &[u8],
    exporter: &[u8; 32],
) -> [u8; 64] {
    let public_key = local_identity.verifying_key().to_bytes();
    local_identity
        .sign(&binding_message(role, &public_key, exporter))
        .to_bytes()
}

#[cfg(test)]
pub(crate) fn test_verify_binding(
    remote_vk: &VerifyingKey,
    role: &[u8],
    exporter: &[u8; 32],
    sig: &[u8; 64],
) -> Result<()> {
    let signature = Signature::from_bytes(sig);
    remote_vk
        .verify(
            &binding_message(role, &remote_vk.to_bytes(), exporter),
            &signature,
        )
        .map_err(|e| anyhow!("channel binding verification failed: {e}"))?;
    Ok(())
}

fn tls_binding_export(stream: &TlsConn, role_byte: u8) -> Result<[u8; 32]> {
    let output = [0u8; 32];
    let exported = match stream {
        TlsConn::Client(inner) => {
            let (_, session) = inner.get_ref();
            session.export_keying_material(output, BINDING_LABEL, Some(&[role_byte]))?
        }
        TlsConn::Server(inner) => {
            let (_, session) = inner.get_ref();
            session.export_keying_material(output, BINDING_LABEL, Some(&[role_byte]))?
        }
        TlsConn::StreamClient(inner) => {
            let (_, session) = inner.get_ref();
            session.export_keying_material(output, BINDING_LABEL, Some(&[role_byte]))?
        }
    };
    Ok(exported)
}

#[cfg(test)]
async fn run_session(alice: &SigningKey, bob: &SigningKey) -> [u8; 32] {
    let alice_vk = alice.verifying_key();
    let bob_vk = bob.verifying_key();
    let bob_key = bob.clone();
    let alice_key = alice.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut transport = TlsTransport::accept(tcp, &bob_key, Some(alice_vk))
            .await
            .unwrap();
        let exporter = tls_binding_export(&transport.stream, b'c').unwrap();
        transport.send_envelope(b"ok").await.unwrap();
        exporter
    });

    let mut client = TlsTransport::connect(addr, &alice_key, Some(bob_vk))
        .await
        .unwrap();
    let exporter = tls_binding_export(&client.stream, b'c').unwrap();
    let packet = client.recv_envelope().await.unwrap();
    assert_eq!(packet, b"ok");
    let server_export = server.await.unwrap();
    assert_eq!(exporter, server_export);
    exporter
}

pub struct TlsTransport {
    stream: TlsConn,
    peer_identity: Option<VerifyingKey>,
}

impl TlsTransport {
    pub async fn connect(
        addr: std::net::SocketAddr,
        local_identity: &SigningKey,
        expected_peer: Option<VerifyingKey>,
    ) -> Result<Self> {
        Self::connect_with_kind(addr, local_identity, expected_peer, StreamKind::Sync).await
    }

    pub async fn connect_with_kind(
        addr: std::net::SocketAddr,
        local_identity: &SigningKey,
        expected_peer: Option<VerifyingKey>,
        kind: StreamKind,
    ) -> Result<Self> {
        log::info!(target: "HAL_DHT", "TLS: connecting to {addr}...");
        let started = tokio::time::Instant::now();
        let tcp = TcpStream::connect(addr).await?;
        log::info!(
            target: "HAL_DHT",
            "TLS: TCP connected to {addr} ({}ms). Starting handshake...",
            started.elapsed().as_millis()
        );
        Self::connect_with_kind_on_stream(tcp, local_identity, expected_peer, kind).await
    }

    pub async fn connect_with_kind_on_stream(
        tcp: TcpStream,
        local_identity: &SigningKey,
        expected_peer: Option<VerifyingKey>,
        kind: StreamKind,
    ) -> Result<Self> {
        let addr = tcp.peer_addr().ok();
        let started = tokio::time::Instant::now();
        log::info!(
            target: "HAL_DHT",
            "TLS: client handshake START with {}",
            addr.map_or_else(|| "unknown peer".to_string(), |addr| addr.to_string())
        );
        let server_name = server_name_for_client(kind)?;
        let connector = TlsConnector::from(Arc::new(client_config()?));
        let tls_stream = match connector.connect(server_name, tcp).await {
            Ok(stream) => stream,
            Err(error) => {
                log::error!(
                    target: "HAL_DHT",
                    "TLS: client handshake FAILED with {} after {}ms: {error}",
                    addr.map_or_else(|| "unknown peer".to_string(), |addr| addr.to_string()),
                    started.elapsed().as_millis()
                );
                return Err(error.into());
            }
        };
        log::info!(
            target: "HAL_DHT",
            "TLS: handshake OK with {} ({}ms); exchanging identities",
            addr.map_or_else(|| "unknown peer".to_string(), |addr| addr.to_string()),
            started.elapsed().as_millis()
        );

        let mut transport = Self {
            stream: TlsConn::Client(tls_stream),
            peer_identity: None,
        };
        let peer = match transport
            .exchange_identity(local_identity, expected_peer, false)
            .await
        {
            Ok(peer) => peer,
            Err(error) => {
                log::error!(
                    target: "HAL_DHT",
                    "TLS: client identity exchange FAILED with {} after {}ms: {error}",
                    addr.map_or_else(|| "unknown peer".to_string(), |addr| addr.to_string()),
                    started.elapsed().as_millis()
                );
                return Err(error);
            }
        };
        log::info!(
            target: "HAL_DHT",
            "TLS: client identity exchange OK with {} ({}ms total)",
            addr.map_or_else(|| "unknown peer".to_string(), |addr| addr.to_string()),
            started.elapsed().as_millis()
        );
        transport.peer_identity = Some(peer);
        Ok(transport)
    }

    pub async fn connect_with_kind_on_duplex_stream(
        stream: tokio::io::DuplexStream,
        local_identity: &SigningKey,
        expected_peer: Option<VerifyingKey>,
        kind: StreamKind,
    ) -> Result<Self> {
        let started = tokio::time::Instant::now();
        log::info!(target: "HAL_DHT", "TLS: client handshake START over WSS stream");
        let server_name = server_name_for_client(kind)?;
        let connector = TlsConnector::from(Arc::new(client_config()?));
        let tls_stream = connector.connect(server_name, stream).await.map_err(|error| {
            log::error!(target: "HAL_DHT", "TLS: client handshake FAILED over WSS after {}ms: {error}", started.elapsed().as_millis());
            error
        })?;
        log::info!(
            "WSS Transport: TLS OK over {}ms",
            started.elapsed().as_millis()
        );
        let mut transport = Self {
            stream: TlsConn::StreamClient(tls_stream),
            peer_identity: None,
        };
        let peer = transport
            .exchange_identity(local_identity, expected_peer, false)
            .await
            .map_err(|error| {
                log::error!(target: "HAL_DHT", "TLS: client identity exchange FAILED over WSS: {error}");
                error
            })?;
        log::info!("WSS Transport: mux ready");
        transport.peer_identity = Some(peer);
        Ok(transport)
    }

    pub async fn accept(
        tcp: TcpStream,
        local_identity: &SigningKey,
        expected_peer: Option<VerifyingKey>,
    ) -> Result<Self> {
        let addr = tcp.peer_addr().ok();
        let started = tokio::time::Instant::now();
        log::info!(
            target: "HAL_DHT",
            "TLS: server handshake START from {}",
            addr.map_or_else(|| "unknown peer".to_string(), |addr| addr.to_string())
        );
        let acceptor = TlsAcceptor::from(server_config()?);
        let tls_stream = match acceptor.accept(tcp).await {
            Ok(stream) => stream,
            Err(error) => {
                log::error!(
                    target: "HAL_DHT",
                    "TLS: server handshake FAILED from {} after {}ms: {error}",
                    addr.map_or_else(|| "unknown peer".to_string(), |addr| addr.to_string()),
                    started.elapsed().as_millis()
                );
                return Err(error.into());
            }
        };
        log::info!(
            target: "HAL_DHT",
            "TLS: server handshake OK from {} ({}ms); exchanging identities",
            addr.map_or_else(|| "unknown peer".to_string(), |addr| addr.to_string()),
            started.elapsed().as_millis()
        );

        let mut transport = Self {
            stream: TlsConn::Server(tls_stream),
            peer_identity: None,
        };
        let peer = match transport
            .exchange_identity(local_identity, expected_peer, true)
            .await
        {
            Ok(peer) => peer,
            Err(error) => {
                log::error!(
                    target: "HAL_DHT",
                    "TLS: server identity exchange FAILED from {} after {}ms: {error}",
                    addr.map_or_else(|| "unknown peer".to_string(), |addr| addr.to_string()),
                    started.elapsed().as_millis()
                );
                return Err(error);
            }
        };
        log::info!(
            target: "HAL_DHT",
            "TLS: server identity exchange OK from {} ({}ms total)",
            addr.map_or_else(|| "unknown peer".to_string(), |addr| addr.to_string()),
            started.elapsed().as_millis()
        );
        transport.peer_identity = Some(peer);
        Ok(transport)
    }

    pub async fn send_envelope(&mut self, envelope: &[u8]) -> Result<()> {
        if envelope.len() > MAX_TLS_ENVELOPE_SIZE {
            return Err(anyhow!(
                "TLS envelope exceeds {MAX_TLS_ENVELOPE_SIZE} bytes"
            ));
        }

        self.stream.write_u32(envelope.len() as u32).await?;
        self.stream.write_all(envelope).await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn recv_envelope(&mut self) -> Result<Vec<u8>> {
        let length = self.stream.read_u32().await? as usize;
        if length == 0 || length > MAX_TLS_ENVELOPE_SIZE {
            return Err(anyhow!("invalid TLS envelope length: {length}"));
        }

        let mut frame = vec![0u8; length];
        let read = self.stream.read_exact(&mut frame).await?;
        if read != length {
            return Err(anyhow!(
                "short TLS envelope read: expected {length}, got {read}"
            ));
        }
        Ok(frame)
    }

    pub fn peer_identity(&self) -> Option<VerifyingKey> {
        self.peer_identity
    }

    pub(crate) fn into_stream(self) -> TlsConn {
        self.stream
    }

    async fn write_blob(&mut self, value: &[u8]) -> Result<()> {
        self.stream.write_u32(value.len() as u32).await?;
        self.stream.write_all(value).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn read_blob(&mut self) -> Result<Vec<u8>> {
        let length = self.stream.read_u32().await? as usize;
        if length == 0 || length > 4096 {
            return Err(anyhow!("invalid identity payload size: {length}"));
        }

        let mut blob = vec![0u8; length];
        let read = self.stream.read_exact(&mut blob).await?;
        if read != length {
            return Err(anyhow!(
                "short identity payload read: expected {length}, got {read}"
            ));
        }
        Ok(blob)
    }

    async fn exchange_identity(
        &mut self,
        local_identity: &SigningKey,
        expected_peer: Option<VerifyingKey>,
        server_side: bool,
    ) -> Result<VerifyingKey> {
        let local_vk = local_identity.verifying_key().to_bytes();
        let local_role = if server_side { b"server" } else { b"client" };
        let local_role_byte = if server_side { b's' } else { b'c' };
        let local_export = tls_binding_export(&self.stream, local_role_byte)?;
        let local_sig = local_identity.sign(&binding_message(local_role, &local_vk, &local_export));

        self.write_blob(&local_vk).await?;
        self.write_blob(&local_sig.to_bytes()).await?;

        let remote_vk_bytes = self.read_blob().await?;
        if remote_vk_bytes.len() != 32 {
            return Err(anyhow!("remote identity is not 32 bytes"));
        }

        let remote_vk_array: [u8; 32] = remote_vk_bytes
            .try_into()
            .map_err(|_| anyhow!("remote identity length mismatch"))?;
        let remote_vk = VerifyingKey::from_bytes(&remote_vk_array)
            .map_err(|e| anyhow!("invalid remote identity key: {e}"))?;

        let remote_sig_bytes = self.read_blob().await?;
        if remote_sig_bytes.len() != 64 {
            return Err(anyhow!("remote binding signature is not 64 bytes"));
        }

        let remote_sig_array: [u8; 64] = remote_sig_bytes
            .try_into()
            .map_err(|_| anyhow!("bad signature length"))?;
        let remote_sig = Signature::from_bytes(&remote_sig_array);

        let remote_role = if server_side { b"client" } else { b"server" };
        let remote_role_byte = if server_side { b'c' } else { b's' };
        let remote_export = tls_binding_export(&self.stream, remote_role_byte)?;
        remote_vk
            .verify(
                &binding_message(remote_role, &remote_vk_array, &remote_export),
                &remote_sig,
            )
            .map_err(|e| anyhow!("channel binding verification failed: MITM detected: {e}"))?;

        if let Some(expected) = expected_peer {
            if remote_vk != expected {
                return Err(anyhow!("identity binding mismatch"));
            }
        }

        Ok(remote_vk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{AsyncReadExt as FuturesAsyncReadExt, AsyncWriteExt as FuturesAsyncWriteExt};
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn tls_roundtrip_symmetric() {
        let alice = SigningKey::from_bytes(&[1u8; 32]);
        let bob = SigningKey::from_bytes(&[2u8; 32]);
        let alice_vk = alice.verifying_key();
        let bob_vk = bob.verifying_key();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut transport = TlsTransport::accept(tcp, &bob, Some(alice_vk))
                .await
                .unwrap();
            let payload = transport.recv_envelope().await.unwrap();
            assert_eq!(payload, b"hello from alice");
            transport.send_envelope(b"hello from bob").await.unwrap();
        });

        let mut client = TlsTransport::connect(addr, &alice, Some(bob_vk))
            .await
            .unwrap();
        client.send_envelope(b"hello from alice").await.unwrap();
        let reply = client.recv_envelope().await.unwrap();
        assert_eq!(reply, b"hello from bob");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tls_channel_binding_correct() {
        let alice = SigningKey::from_bytes(&[41u8; 32]);
        let bob = SigningKey::from_bytes(&[42u8; 32]);
        let alice_vk = alice.verifying_key();
        let bob_vk = bob.verifying_key();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut transport = TlsTransport::accept(tcp, &bob, Some(alice_vk))
                .await
                .unwrap();
            let export_server = tls_binding_export(&transport.stream, b's').unwrap();
            let export_client = tls_binding_export(&transport.stream, b'c').unwrap();
            assert_ne!(export_server, export_client);
            transport.send_envelope(b"ok").await.unwrap();
            (export_client, export_server)
        });

        let mut client = TlsTransport::connect(addr, &alice, Some(bob_vk))
            .await
            .unwrap();
        let client_export = tls_binding_export(&client.stream, b'c').unwrap();
        let client_server_export = tls_binding_export(&client.stream, b's').unwrap();
        assert_ne!(client_export, client_server_export);
        let packet = client.recv_envelope().await.unwrap();
        assert_eq!(packet, b"ok");
        let (server_export_client, server_export_server) = server.await.unwrap();
        assert_eq!(client_export, server_export_client);
        assert_eq!(client_server_export, server_export_server);
    }

    #[tokio::test]
    async fn tls_channel_binding_shared_between_peers() {
        let alice = SigningKey::from_bytes(&[43u8; 32]);
        let bob = SigningKey::from_bytes(&[44u8; 32]);
        let alice_vk = alice.verifying_key();
        let bob_vk = bob.verifying_key();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut transport = TlsTransport::accept(tcp, &bob, Some(alice_vk))
                .await
                .unwrap();
            let export_client = tls_binding_export(&transport.stream, b'c').unwrap();
            let export_server = tls_binding_export(&transport.stream, b's').unwrap();
            transport.send_envelope(b"ok").await.unwrap();
            (export_client, export_server)
        });

        let mut client = TlsTransport::connect(addr, &alice, Some(bob_vk))
            .await
            .unwrap();
        let client_export = tls_binding_export(&client.stream, b'c').unwrap();
        let client_server_export = tls_binding_export(&client.stream, b's').unwrap();
        let packet = client.recv_envelope().await.unwrap();
        assert_eq!(packet, b"ok");
        let (server_client_export, server_server_export) = server.await.unwrap();
        assert_eq!(client_export, server_client_export);
        assert_eq!(client_server_export, server_server_export);
    }

    #[tokio::test]
    async fn tls_identity_binding_mismatch() {
        let alice = SigningKey::from_bytes(&[11u8; 32]);
        let bob = SigningKey::from_bytes(&[12u8; 32]);
        let wrong_peer = SigningKey::from_bytes(&[99u8; 32]).verifying_key();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let result = TlsTransport::accept(tcp, &bob, Some(wrong_peer)).await;
            assert!(result.is_err());
        });

        let result = TlsTransport::connect(addr, &alice, Some(wrong_peer)).await;
        assert!(result.is_err());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tls_accept_any_cert() {
        let alice = SigningKey::from_bytes(&[21u8; 32]);
        let bob = SigningKey::from_bytes(&[22u8; 32]);
        let alice_vk = alice.verifying_key();
        let bob_vk = bob.verifying_key();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut transport = TlsTransport::accept(tcp, &bob, Some(alice_vk))
                .await
                .unwrap();
            assert!(transport.peer_identity().is_some());
            transport.send_envelope(b"ok").await.unwrap();
        });

        let mut client = TlsTransport::connect(addr, &alice, Some(bob_vk))
            .await
            .unwrap();
        assert!(client.peer_identity().is_some());
        let packet = client.recv_envelope().await.unwrap();
        assert_eq!(packet, b"ok");
        server.await.unwrap();
    }

    #[test]
    fn tls_chacha20_used() {
        let has_chacha = default_provider()
            .cipher_suites
            .iter()
            .any(|suite| suite.suite() == rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256);
        assert!(has_chacha, "TLS 1.3 ChaCha20-Poly1305 must be supported");
    }

    #[tokio::test]
    async fn tls_channel_binding_replay_rejected() {
        let alice = SigningKey::from_bytes(&[61u8; 32]);
        let bob = SigningKey::from_bytes(&[62u8; 32]);
        let alice_vk = alice.verifying_key();
        let bob_vk = bob.verifying_key();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut transport = TlsTransport::accept(tcp, &bob, Some(alice_vk))
                .await
                .unwrap();
            let session_exporter = tls_binding_export(&transport.stream, b'c').unwrap();
            transport.send_envelope(b"ok").await.unwrap();
            session_exporter
        });

        let mut client = TlsTransport::connect(addr, &alice, Some(bob_vk))
            .await
            .unwrap();
        let session1_exporter = tls_binding_export(&client.stream, b'c').unwrap();
        let alice_sig = test_binding_signature(&alice, b"client", &session1_exporter);
        let session2_exporter = [0u8; 32];

        let session1_ok = test_verify_binding(&alice_vk, b"client", &session1_exporter, &alice_sig);
        let session2_err =
            test_verify_binding(&alice_vk, b"client", &session2_exporter, &alice_sig);

        assert!(
            session1_ok.is_ok(),
            "signature must validate for the same exporter"
        );
        assert!(
            session2_err.is_err(),
            "signature must fail for a different exporter"
        );

        let packet = client.recv_envelope().await.unwrap();
        assert_eq!(packet, b"ok");
        let server_export = server.await.unwrap();
        assert_eq!(session1_exporter, server_export);
    }

    #[tokio::test]
    async fn tls_exporters_differ_between_sessions() {
        let alice = SigningKey::from_bytes(&[71u8; 32]);
        let bob = SigningKey::from_bytes(&[72u8; 32]);

        let exporter_1 = run_session(&alice, &bob).await;
        let exporter_2 = run_session(&alice, &bob).await;

        assert_ne!(
            exporter_1, exporter_2,
            "exporter must be unique per TLS session"
        );
    }

    #[test]
    fn tls_role_mismatch_rejected() {
        let alice = SigningKey::from_bytes(&[81u8; 32]);
        let alice_vk = alice.verifying_key();
        let exporter = [42u8; 32];

        let sig_client = test_binding_signature(&alice, b"client", &exporter);

        assert!(test_verify_binding(&alice_vk, b"client", &exporter, &sig_client).is_ok());
        assert!(test_verify_binding(&alice_vk, b"server", &exporter, &sig_client).is_err());
    }

    #[tokio::test]
    async fn tls_envelope_too_large() {
        let alice = SigningKey::from_bytes(&[31u8; 32]);
        let bob = SigningKey::from_bytes(&[32u8; 32]);
        let alice_vk = alice.verifying_key();
        let bob_vk = bob.verifying_key();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut transport = TlsTransport::accept(tcp, &bob, Some(alice_vk))
                .await
                .unwrap();
            let result = transport
                .send_envelope(&vec![b'x'; MAX_TLS_ENVELOPE_SIZE + 1])
                .await;
            assert!(result.is_err());
        });

        let mut client = TlsTransport::connect(addr, &alice, Some(bob_vk))
            .await
            .unwrap();
        let result = client
            .send_envelope(&vec![b'x'; MAX_TLS_ENVELOPE_SIZE + 1])
            .await;
        assert!(result.is_err());
        server.await.unwrap();
    }

    #[test]
    fn tls_sni_not_localhost() {
        let sni = choose_sni();
        assert!(!sni.eq_ignore_ascii_case("localhost"));
        assert!(ALLOWED_SNI.contains(&sni));
    }

    #[test]
    fn tls_sni_entries_are_valid_dns_names() {
        for sni in ALLOWED_SNI.iter() {
            assert!(!sni.contains('['), "SNI contains bracket: {sni}");
            assert!(!sni.contains(']'), "SNI contains bracket: {sni}");
            assert!(!sni.contains('('), "SNI contains paren: {sni}");
            assert!(!sni.contains(')'), "SNI contains paren: {sni}");
            assert!(
                ServerName::try_from(*sni).is_ok(),
                "SNI is not valid ServerName: {sni}"
            );
        }
    }

    #[test]
    fn sni_is_deterministic_for_kind() {
        assert_eq!(sni_for_stream_kind(StreamKind::Sync), "www.cloudflare.com");
        assert_eq!(
            sni_for_stream_kind(StreamKind::MediaSignal),
            "cdn.jsdelivr.net"
        );
        assert_eq!(sni_for_stream_kind(StreamKind::Control), "www.google.com");
        assert_eq!(
            sni_for_stream_kind(StreamKind::Priority),
            "www.cloudflare.com"
        );
        assert_eq!(sni_for_stream_kind(StreamKind::Dht), "cdn.jsdelivr.net");
        assert_eq!(
            sni_for_stream_kind(StreamKind::Dht),
            sni_for_stream_kind(StreamKind::Dht)
        );
    }

    #[tokio::test]
    async fn tls_server_config_cached() {
        let cfg1 = server_config().unwrap();
        let cfg2 = server_config().unwrap();
        assert!(Arc::ptr_eq(&cfg1, &cfg2), "server config must be cached");
    }
}
