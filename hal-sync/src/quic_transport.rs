use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use quinn::{ClientConfig, Connection, Endpoint, ServerConfig, TransportConfig, VarInt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::SignatureScheme;
use serde::{Deserialize, Serialize};

use crate::abuse_metrics::AbuseMetrics;
use crate::dht::NodeId;
use crate::hole_punch::PunchOutcome;
use crate::pinning::{BindingCheck, KnownHosts};

pub const QUIC_ALPN: &[u8] = b"hal-sync";
pub const QUIC_DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
pub const QUIC_DEFAULT_MAX_STREAMS: u32 = 100;
const QUIC_IDENTITY_LABEL: &[u8] = b"EXPORTER-HAL-QUIC-IDENTITY";
const QUIC_IDENTITY_CONTEXT: &[u8] = b"hal-quic-v1";
const QUIC_IDENTITY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_IDENTITY_PROOF_SIZE: usize = 4096;

#[derive(Debug, Clone)]
pub struct QuicConfig {
    pub idle_timeout: Duration,
    pub max_concurrent_streams: u32,
    pub alpn: Vec<Vec<u8>>,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            idle_timeout: QUIC_DEFAULT_IDLE_TIMEOUT,
            max_concurrent_streams: QUIC_DEFAULT_MAX_STREAMS,
            alpn: vec![QUIC_ALPN.to_vec()],
        }
    }
}

#[derive(Debug)]
pub enum QuicError {
    BindFailed(String),
    ConnectFailed(String),
    AcceptFailed(String),
    StreamFailed(String),
    Timeout,
    CertificateError(String),
    IdentityRejected(String),
    InvalidConfig,
}

impl fmt::Display for QuicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BindFailed(err) => write!(f, "QUIC bind failed: {err}"),
            Self::ConnectFailed(err) => write!(f, "QUIC connect failed: {err}"),
            Self::AcceptFailed(err) => write!(f, "QUIC accept failed: {err}"),
            Self::StreamFailed(err) => write!(f, "QUIC stream failed: {err}"),
            Self::Timeout => write!(f, "QUIC operation timed out"),
            Self::CertificateError(err) => write!(f, "QUIC certificate error: {err}"),
            Self::IdentityRejected(err) => write!(f, "QUIC identity rejected: {err}"),
            Self::InvalidConfig => write!(f, "QUIC invalid configuration"),
        }
    }
}

impl Error for QuicError {}

pub struct QuicChannel {
    connection: Option<Connection>,
    endpoint: Option<Endpoint>,
    peer_identity: PeerIdentity,
}

#[derive(Debug, Clone)]
pub struct PeerIdentity {
    pub identity_id: NodeId,
    pub public_key_hex: String,
    pub verifying_key: VerifyingKey,
}

impl QuicChannel {
    pub fn bind_server_endpoint(
        socket: tokio::net::UdpSocket,
        signing_key: &SigningKey,
        config: QuicConfig,
    ) -> Result<Endpoint, QuicError> {
        let server_config = server_config(signing_key, &config)?;
        let socket = socket
            .into_std()
            .map_err(|error| QuicError::BindFailed(error.to_string()))?;
        let mut endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|error| QuicError::BindFailed(error.to_string()))?;
        endpoint.set_default_client_config(client_config(&config)?);
        Ok(endpoint)
    }

    pub async fn connect_on_endpoint(
        endpoint: Arc<Endpoint>,
        remote: SocketAddr,
        server_name: &str,
        signing_key: &SigningKey,
        expected_peer_key: Option<VerifyingKey>,
        known_hosts: Arc<Mutex<KnownHosts>>,
        metrics: Arc<AbuseMetrics>,
    ) -> Result<Self, QuicError> {
        let connecting = endpoint
            .connect(remote, server_name)
            .map_err(|error| QuicError::ConnectFailed(error.to_string()))?;
        let connection = connecting
            .await
            .map_err(|error| QuicError::ConnectFailed(error.to_string()))?;
        let identity_result = tokio::time::timeout(
            QUIC_IDENTITY_HANDSHAKE_TIMEOUT,
            client_identity_exchange(
                &connection,
                signing_key,
                expected_peer_key,
                &known_hosts,
                &metrics,
            ),
        )
        .await;
        let peer_identity = match identity_result {
            Ok(Ok(peer_identity)) => peer_identity,
            Ok(Err(error)) => {
                metrics
                    .quic_identity_rejected_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                connection.close(VarInt::from_u32(1), b"identity rejected");
                return Err(error);
            }
            Err(_) => {
                metrics
                    .quic_identity_rejected_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                connection.close(VarInt::from_u32(1), b"identity timeout");
                return Err(QuicError::Timeout);
            }
        };
        Ok(Self {
            connection: Some(connection),
            endpoint: Some(endpoint.as_ref().clone()),
            peer_identity,
        })
    }

    pub async fn accept_incoming(
        endpoint: Endpoint,
        incoming: quinn::Incoming,
        signing_key: &SigningKey,
        expected_peer_key: Option<VerifyingKey>,
        known_hosts: Arc<Mutex<KnownHosts>>,
        metrics: Arc<AbuseMetrics>,
    ) -> Result<Self, QuicError> {
        let connection = incoming
            .await
            .map_err(|error| QuicError::AcceptFailed(error.to_string()))?;
        let identity_result = tokio::time::timeout(
            QUIC_IDENTITY_HANDSHAKE_TIMEOUT,
            server_identity_exchange(
                &connection,
                signing_key,
                expected_peer_key,
                &known_hosts,
                &metrics,
            ),
        )
        .await;
        let peer_identity = match identity_result {
            Ok(Ok(peer_identity)) => peer_identity,
            Ok(Err(error)) => {
                metrics
                    .quic_identity_rejected_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                connection.close(VarInt::from_u32(1), b"identity rejected");
                return Err(error);
            }
            Err(_) => {
                metrics
                    .quic_identity_rejected_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                connection.close(VarInt::from_u32(1), b"identity timeout");
                return Err(QuicError::Timeout);
            }
        };
        Ok(Self {
            connection: Some(connection),
            endpoint: Some(endpoint),
            peer_identity,
        })
    }

    pub async fn connect(
        socket: tokio::net::UdpSocket,
        remote: SocketAddr,
        server_name: &str,
        signing_key: &SigningKey,
        expected_peer_key: Option<VerifyingKey>,
        known_hosts: Arc<Mutex<KnownHosts>>,
        metrics: Arc<AbuseMetrics>,
        config: QuicConfig,
    ) -> Result<Self, QuicError> {
        let client_config = client_config(&config)?;
        let socket = socket
            .into_std()
            .map_err(|error| QuicError::BindFailed(error.to_string()))?;
        let mut endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|error| QuicError::BindFailed(error.to_string()))?;
        endpoint.set_default_client_config(client_config);
        let connecting = endpoint
            .connect(remote, server_name)
            .map_err(|error| QuicError::ConnectFailed(error.to_string()))?;
        let connection = connecting
            .await
            .map_err(|error| QuicError::ConnectFailed(error.to_string()))?;
        let identity_result = tokio::time::timeout(
            QUIC_IDENTITY_HANDSHAKE_TIMEOUT,
            client_identity_exchange(
                &connection,
                signing_key,
                expected_peer_key,
                &known_hosts,
                &metrics,
            ),
        )
        .await;
        let peer_identity = match identity_result {
            Ok(Ok(peer_identity)) => peer_identity,
            Ok(Err(error)) => {
                metrics
                    .quic_identity_rejected_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                connection.close(VarInt::from_u32(1), b"identity rejected");
                return Err(error);
            }
            Err(_) => {
                metrics
                    .quic_identity_rejected_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                connection.close(VarInt::from_u32(1), b"identity timeout");
                return Err(QuicError::Timeout);
            }
        };
        Ok(Self {
            connection: Some(connection),
            endpoint: Some(endpoint),
            peer_identity,
        })
    }

    pub async fn accept(
        socket: tokio::net::UdpSocket,
        signing_key: &SigningKey,
        expected_peer_key: Option<VerifyingKey>,
        known_hosts: Arc<Mutex<KnownHosts>>,
        metrics: Arc<AbuseMetrics>,
        config: QuicConfig,
    ) -> Result<Self, QuicError> {
        let server_config = server_config(signing_key, &config)?;
        let socket = socket
            .into_std()
            .map_err(|error| QuicError::BindFailed(error.to_string()))?;
        let endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|error| QuicError::BindFailed(error.to_string()))?;
        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| QuicError::AcceptFailed("endpoint closed".to_string()))?;
        let connection = incoming
            .await
            .map_err(|error| QuicError::AcceptFailed(error.to_string()))?;
        let identity_result = tokio::time::timeout(
            QUIC_IDENTITY_HANDSHAKE_TIMEOUT,
            server_identity_exchange(
                &connection,
                signing_key,
                expected_peer_key,
                &known_hosts,
                &metrics,
            ),
        )
        .await;
        let peer_identity = match identity_result {
            Ok(Ok(peer_identity)) => peer_identity,
            Ok(Err(error)) => {
                metrics
                    .quic_identity_rejected_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                connection.close(VarInt::from_u32(1), b"identity rejected");
                return Err(error);
            }
            Err(_) => {
                metrics
                    .quic_identity_rejected_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                connection.close(VarInt::from_u32(1), b"identity timeout");
                return Err(QuicError::Timeout);
            }
        };
        Ok(Self {
            connection: Some(connection),
            endpoint: Some(endpoint),
            peer_identity,
        })
    }

    pub fn peer_identity(&self) -> &PeerIdentity {
        &self.peer_identity
    }

    /// Открыть двунаправленный QUIC stream.
    pub async fn open_stream(&self) -> Result<(quinn::SendStream, quinn::RecvStream), QuicError> {
        self.connection
            .as_ref()
            .ok_or_else(|| QuicError::StreamFailed("QUIC connection is not initialized".into()))?
            .open_bi()
            .await
            .map_err(|error| QuicError::StreamFailed(error.to_string()))
    }

    /// Принять входящий двунаправленный QUIC stream.
    pub async fn accept_stream(&self) -> Result<(quinn::SendStream, quinn::RecvStream), QuicError> {
        self.connection
            .as_ref()
            .ok_or_else(|| QuicError::StreamFailed("QUIC connection is not initialized".into()))?
            .accept_bi()
            .await
            .map_err(|error| QuicError::StreamFailed(error.to_string()))
    }

    pub fn remote_address(&self) -> Option<SocketAddr> {
        self.connection.as_ref().map(Connection::remote_address)
    }

    /// Закрыть соединение.
    pub fn close(&self, code: u32, reason: &[u8]) {
        if let Some(connection) = &self.connection {
            connection.close(code.into(), reason);
        }
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(code.into(), reason);
        }
    }
}

pub async fn connect_via_punch(
    punch_outcome: PunchOutcome,
    server_name: &str,
    signing_key: &SigningKey,
    expected_peer_key: Option<VerifyingKey>,
    known_hosts: Arc<Mutex<KnownHosts>>,
    metrics: Arc<AbuseMetrics>,
    config: QuicConfig,
) -> Result<QuicChannel, QuicError> {
    match punch_outcome {
        PunchOutcome::Punched { socket, remote } => {
            QuicChannel::connect(
                socket,
                remote,
                server_name,
                signing_key,
                expected_peer_key,
                known_hosts,
                metrics,
                config,
            )
            .await
        }
        PunchOutcome::Failed { error } => Err(QuicError::ConnectFailed(error.to_string())),
    }
}

#[derive(Serialize, Deserialize)]
struct IdentityProof {
    role: String,
    identity_id: String,
    public_key_hex: String,
    signature_hex: String,
}

fn connection_exporter(connection: &Connection) -> Result<[u8; 32], QuicError> {
    let mut output = [0u8; 32];
    connection
        .export_keying_material(&mut output, QUIC_IDENTITY_LABEL, QUIC_IDENTITY_CONTEXT)
        .map_err(|error| QuicError::IdentityRejected(format!("QUIC exporter failed: {error:?}")))?;
    Ok(output)
}

fn identity_binding_message(
    role: &str,
    identity_id: &str,
    public_key: &[u8; 32],
    exporter: &[u8; 32],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(128);
    message.extend_from_slice(b"hal-quic-v1\0");
    message.extend_from_slice(role.as_bytes());
    message.push(0);
    message.extend_from_slice(identity_id.as_bytes());
    message.push(0);
    message.extend_from_slice(public_key);
    message.extend_from_slice(exporter);
    message
}

fn create_identity_proof(
    signing_key: &SigningKey,
    role: &str,
    exporter: &[u8; 32],
) -> IdentityProof {
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_bytes();
    let identity_id = NodeId::from_public_key(&verifying_key).to_hex();
    let signature = signing_key.sign(&identity_binding_message(
        role,
        &identity_id,
        &public_key,
        exporter,
    ));
    IdentityProof {
        role: role.to_string(),
        identity_id,
        public_key_hex: hex::encode(public_key),
        signature_hex: hex::encode(signature.to_bytes()),
    }
}

fn verify_identity_proof(
    proof: &IdentityProof,
    expected_role: &str,
    exporter: &[u8; 32],
    expected_peer_key: Option<&VerifyingKey>,
    known_hosts: &Mutex<KnownHosts>,
    metrics: &AbuseMetrics,
) -> Result<PeerIdentity, QuicError> {
    if proof.role != expected_role {
        return Err(QuicError::IdentityRejected("identity role mismatch".into()));
    }
    let public_key_bytes: [u8; 32] = hex::decode(&proof.public_key_hex)
        .map_err(|error| QuicError::IdentityRejected(format!("invalid identity key: {error}")))?
        .try_into()
        .map_err(|_| QuicError::IdentityRejected("identity key must be 32 bytes".into()))?;
    let public_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|error| QuicError::IdentityRejected(format!("invalid identity key: {error}")))?;
    let identity_id = NodeId::from_public_key(&public_key);
    let identity_id_hex = identity_id.to_hex();
    if proof.identity_id != identity_id_hex {
        return Err(QuicError::IdentityRejected(
            "identity does not match public key".into(),
        ));
    }
    if let Some(expected) = expected_peer_key {
        if expected != &public_key {
            return Err(QuicError::IdentityRejected(
                "identity does not match expected key".into(),
            ));
        }
    }
    let signature_bytes: [u8; 64] = hex::decode(&proof.signature_hex)
        .map_err(|error| {
            QuicError::IdentityRejected(format!("invalid identity signature: {error}"))
        })?
        .try_into()
        .map_err(|_| QuicError::IdentityRejected("identity signature must be 64 bytes".into()))?;
    let signature = Signature::from_bytes(&signature_bytes);
    public_key
        .verify_strict(
            &identity_binding_message(expected_role, &identity_id_hex, &public_key_bytes, exporter),
            &signature,
        )
        .map_err(|error| {
            QuicError::IdentityRejected(format!("identity signature invalid: {error}"))
        })?;

    let mut known_hosts = known_hosts
        .lock()
        .map_err(|_| QuicError::IdentityRejected("known hosts lock poisoned".into()))?;
    match known_hosts.check(&identity_id_hex, &proof.public_key_hex) {
        BindingCheck::Trusted => {}
        BindingCheck::Conflicted { .. } => {
            return Err(QuicError::IdentityRejected(
                "identity conflicts with known host pin".into(),
            ));
        }
        BindingCheck::Unknown if expected_peer_key.is_some() => {}
        BindingCheck::Unknown => {
            let now = chrono::Utc::now().timestamp().max(0) as u64;
            if !known_hosts.learn_first_contact(&identity_id_hex, &proof.public_key_hex, now) {
                return Err(QuicError::IdentityRejected(
                    "TOFU identity conflicted".into(),
                ));
            }
            metrics
                .quic_identity_tofu_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    metrics
        .quic_identity_verified_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(PeerIdentity {
        identity_id,
        public_key_hex: proof.public_key_hex.clone(),
        verifying_key: public_key,
    })
}

async fn send_identity_proof(
    send: &mut quinn::SendStream,
    proof: &IdentityProof,
) -> Result<(), QuicError> {
    let payload = serde_json::to_vec(proof)
        .map_err(|error| QuicError::IdentityRejected(error.to_string()))?;
    if payload.len() > MAX_IDENTITY_PROOF_SIZE {
        return Err(QuicError::IdentityRejected(
            "identity proof too large".into(),
        ));
    }
    send.write_all(&payload)
        .await
        .map_err(|error| QuicError::IdentityRejected(error.to_string()))?;
    send.finish()
        .map_err(|error| QuicError::IdentityRejected(error.to_string()))
}

async fn receive_identity_proof(recv: &mut quinn::RecvStream) -> Result<IdentityProof, QuicError> {
    let payload = recv
        .read_to_end(MAX_IDENTITY_PROOF_SIZE)
        .await
        .map_err(|error| QuicError::IdentityRejected(error.to_string()))?;
    serde_json::from_slice(&payload)
        .map_err(|error| QuicError::IdentityRejected(format!("invalid identity proof: {error}")))
}

async fn client_identity_exchange(
    connection: &Connection,
    signing_key: &SigningKey,
    expected_peer_key: Option<VerifyingKey>,
    known_hosts: &Mutex<KnownHosts>,
    metrics: &AbuseMetrics,
) -> Result<PeerIdentity, QuicError> {
    let exporter = connection_exporter(connection)?;
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|error| QuicError::IdentityRejected(error.to_string()))?;
    send_identity_proof(
        &mut send,
        &create_identity_proof(signing_key, "client", &exporter),
    )
    .await?;
    let server_proof = receive_identity_proof(&mut recv).await?;
    verify_identity_proof(
        &server_proof,
        "server",
        &exporter,
        expected_peer_key.as_ref(),
        known_hosts,
        metrics,
    )
}

async fn server_identity_exchange(
    connection: &Connection,
    signing_key: &SigningKey,
    expected_peer_key: Option<VerifyingKey>,
    known_hosts: &Mutex<KnownHosts>,
    metrics: &AbuseMetrics,
) -> Result<PeerIdentity, QuicError> {
    let exporter = connection_exporter(connection)?;
    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .map_err(|error| QuicError::IdentityRejected(error.to_string()))?;
    let client_proof = receive_identity_proof(&mut recv).await?;
    let peer_identity = verify_identity_proof(
        &client_proof,
        "client",
        &exporter,
        expected_peer_key.as_ref(),
        known_hosts,
        metrics,
    )?;
    send_identity_proof(
        &mut send,
        &create_identity_proof(signing_key, "server", &exporter),
    )
    .await?;
    Ok(peer_identity)
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
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

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn generate_self_signed_cert(
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), QuicError> {
    let cert = rcgen::generate_simple_self_signed(vec!["hal-sync".to_string()])
        .map_err(|err| QuicError::CertificateError(err.to_string()))?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    Ok((cert_der, PrivateKeyDer::Pkcs8(key_der)))
}

fn server_config(signing_key: &SigningKey, config: &QuicConfig) -> Result<ServerConfig, QuicError> {
    let _ = signing_key;
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
    let (cert, key) = generate_self_signed_cert()?;
    let mut server = ServerConfig::with_single_cert(vec![cert], key)
        .map_err(|err| QuicError::CertificateError(err.to_string()))?;
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(
        config
            .idle_timeout
            .try_into()
            .map_err(|_| QuicError::InvalidConfig)?,
    ));
    transport.max_concurrent_bidi_streams(VarInt::from_u32(config.max_concurrent_streams));
    server.transport = Arc::new(transport);
    Ok(server)
}

fn client_config(config: &QuicConfig) -> Result<ClientConfig, QuicError> {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    let client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|err| QuicError::CertificateError(err.to_string()))?;
    let mut client = ClientConfig::new(Arc::new(client_crypto));
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(
        config
            .idle_timeout
            .try_into()
            .map_err(|_| QuicError::InvalidConfig)?,
    ));
    transport.max_concurrent_bidi_streams(VarInt::from_u32(config.max_concurrent_streams));
    client.transport_config(Arc::new(transport));
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::unix_now;

    fn test_hosts() -> Arc<Mutex<KnownHosts>> {
        Arc::new(Mutex::new(KnownHosts::new()))
    }

    fn test_metrics() -> Arc<AbuseMetrics> {
        Arc::new(AbuseMetrics::new())
    }

    fn pin_test_key(hosts: &Mutex<KnownHosts>, signing_key: &SigningKey) {
        let verifying_key = signing_key.verifying_key();
        let identity_id = NodeId::from_public_key(&verifying_key).to_hex();
        let public_key_hex = hex::encode(verifying_key.to_bytes());
        hosts
            .lock()
            .expect("known hosts lock")
            .pin_manual(&identity_id, &public_key_hex, unix_now())
            .expect("pin identity");
    }

    async fn start_identity_test_pair(
        expected_client_peer: Option<VerifyingKey>,
        expected_server_peer: Option<VerifyingKey>,
        client_hosts: Arc<Mutex<KnownHosts>>,
        server_hosts: Arc<Mutex<KnownHosts>>,
        client_metrics: Arc<AbuseMetrics>,
        server_metrics: Arc<AbuseMetrics>,
    ) -> (
        Result<QuicChannel, QuicError>,
        tokio::task::JoinHandle<Result<QuicChannel, QuicError>>,
        SigningKey,
        SigningKey,
    ) {
        let server_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind server");
        let server_addr = server_socket.local_addr().expect("server addr");
        let server_key = SigningKey::from_bytes(&[31u8; 32]);
        let client_key = SigningKey::from_bytes(&[32u8; 32]);
        let server_key_for_task = server_key.clone();
        let server_task = tokio::spawn(async move {
            QuicChannel::accept(
                server_socket,
                &server_key_for_task,
                expected_server_peer,
                server_hosts,
                server_metrics,
                QuicConfig::default(),
            )
            .await
        });

        let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind client");
        let client_result = tokio::time::timeout(
            Duration::from_secs(8),
            QuicChannel::connect(
                client_socket,
                server_addr,
                "hal-sync",
                &client_key,
                expected_client_peer,
                client_hosts,
                client_metrics,
                QuicConfig::default(),
            ),
        )
        .await
        .unwrap_or(Err(QuicError::Timeout));
        (client_result, server_task, client_key, server_key)
    }

    #[test]
    fn config_default_values() {
        let config = QuicConfig::default();
        assert_eq!(config.idle_timeout, QUIC_DEFAULT_IDLE_TIMEOUT);
        assert_eq!(config.max_concurrent_streams, QUIC_DEFAULT_MAX_STREAMS);
        assert_eq!(config.alpn, vec![QUIC_ALPN.to_vec()]);
    }

    #[test]
    fn quic_error_display() {
        let err = QuicError::ConnectFailed("boom".to_string());
        let message = err.to_string();
        assert!(message.contains("QUIC connect failed"));
        assert!(message.contains("boom"));
    }

    #[test]
    fn generate_self_signed_cert_works() {
        let (cert, key) = generate_self_signed_cert().expect("certificate generation should work");
        assert!(!cert.as_ref().is_empty());
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
    }

    #[test]
    fn quic_alpn_is_hal_sync() {
        assert_eq!(QUIC_ALPN, b"hal-sync");
    }

    #[test]
    fn skip_server_verification_supported_schemes() {
        let verifier = SkipServerVerification;
        let schemes = verifier.supported_verify_schemes();
        assert!(!schemes.is_empty());
    }

    #[test]
    fn quic_error_stream_failed_display() {
        let error = QuicError::StreamFailed("test".into());
        assert!(error.to_string().contains("test"));
    }

    #[test]
    fn quic_error_close_reason() {
        let error = QuicError::ConnectFailed("reason".into());
        assert!(error.to_string().contains("reason"));
    }

    #[test]
    fn quic_config_defaults_unchanged() {
        let config = QuicConfig::default();
        assert_eq!(config.idle_timeout, Duration::from_secs(30));
        assert_eq!(config.max_concurrent_streams, 100);
        assert_eq!(config.alpn, vec![b"hal-sync".to_vec()]);
    }

    #[test]
    fn quic_channel_new_has_no_endpoint() {
        let channel = QuicChannel {
            connection: None,
            endpoint: None,
            peer_identity: PeerIdentity {
                identity_id: NodeId::from_public_key(
                    &SigningKey::from_bytes(&[7u8; 32]).verifying_key(),
                ),
                public_key_hex: hex::encode(
                    SigningKey::from_bytes(&[7u8; 32])
                        .verifying_key()
                        .to_bytes(),
                ),
                verifying_key: SigningKey::from_bytes(&[7u8; 32]).verifying_key(),
            },
        };
        assert_eq!(channel.remote_address(), None);
    }

    #[test]
    fn quic_channel_close_without_connection_no_panic() {
        let channel = QuicChannel {
            connection: None,
            endpoint: None,
            peer_identity: PeerIdentity {
                identity_id: NodeId::from_public_key(
                    &SigningKey::from_bytes(&[8u8; 32]).verifying_key(),
                ),
                public_key_hex: hex::encode(
                    SigningKey::from_bytes(&[8u8; 32])
                        .verifying_key()
                        .to_bytes(),
                ),
                verifying_key: SigningKey::from_bytes(&[8u8; 32]).verifying_key(),
            },
        };
        channel.close(0, b"test");
    }

    #[tokio::test]
    async fn client_exchange_returns_peer_identity() {
        let client_hosts = test_hosts();
        let server_hosts = test_hosts();
        let client_metrics = test_metrics();
        let server_metrics = test_metrics();
        let server_key = SigningKey::from_bytes(&[31u8; 32]);
        let expected = server_key.verifying_key();
        let (client_result, server_task, _, _) = start_identity_test_pair(
            Some(expected),
            None,
            client_hosts,
            server_hosts,
            Arc::clone(&client_metrics),
            Arc::clone(&server_metrics),
        )
        .await;
        let client_channel = client_result.expect("client exchange");
        let server_channel = server_task
            .await
            .expect("server task")
            .expect("server exchange");
        assert_eq!(
            client_channel.peer_identity().identity_id,
            NodeId::from_public_key(&server_key.verifying_key())
        );
        assert_eq!(
            client_channel.peer_identity().public_key_hex,
            hex::encode(server_key.verifying_key().to_bytes())
        );
        assert_eq!(
            server_channel.peer_identity().identity_id,
            NodeId::from_public_key(&SigningKey::from_bytes(&[32u8; 32]).verifying_key())
        );
    }

    #[tokio::test]
    async fn shared_udp_endpoint_accepts_quic_and_supports_outbound_connections() {
        let client_key = SigningKey::from_bytes(&[41u8; 32]);
        let server_key = SigningKey::from_bytes(&[42u8; 32]);
        let client_verifying_key = client_key.verifying_key();
        let server_verifying_key = server_key.verifying_key();
        let client_endpoint = Arc::new(
            QuicChannel::bind_server_endpoint(
                tokio::net::UdpSocket::bind("127.0.0.1:0")
                    .await
                    .expect("client UDP bind"),
                &client_key,
                QuicConfig::default(),
            )
            .expect("client QUIC endpoint"),
        );
        let server_endpoint = QuicChannel::bind_server_endpoint(
            tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("server UDP bind"),
            &server_key,
            QuicConfig::default(),
        )
        .expect("server QUIC endpoint");
        let server_address = server_endpoint.local_addr().expect("server address");
        let accepting_endpoint = server_endpoint.clone();
        let server_hosts = test_hosts();
        let server_metrics = test_metrics();
        let server_key_for_task = server_key.clone();
        let server_task = tokio::spawn(async move {
            let incoming = accepting_endpoint.accept().await.expect("incoming QUIC");
            QuicChannel::accept_incoming(
                accepting_endpoint,
                incoming,
                &server_key_for_task,
                Some(client_verifying_key),
                server_hosts,
                server_metrics,
            )
            .await
        });
        let client_channel = QuicChannel::connect_on_endpoint(
            Arc::clone(&client_endpoint),
            server_address,
            "hal-sync",
            &client_key,
            Some(server_verifying_key),
            test_hosts(),
            test_metrics(),
        )
        .await
        .expect("client QUIC connection");
        let server_channel = server_task
            .await
            .expect("server QUIC task")
            .expect("server QUIC connection");
        assert_eq!(
            client_channel.peer_identity().identity_id,
            NodeId::from_public_key(&server_verifying_key)
        );
        assert_eq!(
            server_channel.peer_identity().identity_id,
            NodeId::from_public_key(&client_verifying_key)
        );
    }

    #[tokio::test]
    async fn server_exchange_returns_peer_identity() {
        let client_key = SigningKey::from_bytes(&[32u8; 32]);
        let server_key = SigningKey::from_bytes(&[31u8; 32]);
        let client_hosts = test_hosts();
        let server_hosts = test_hosts();
        let client_metrics = test_metrics();
        let server_metrics = test_metrics();
        let (client_result, server_task, _, _) = start_identity_test_pair(
            Some(server_key.verifying_key()),
            Some(client_key.verifying_key()),
            Arc::clone(&client_hosts),
            Arc::clone(&server_hosts),
            Arc::clone(&client_metrics),
            Arc::clone(&server_metrics),
        )
        .await;
        let client_channel = client_result.expect("client exchange");
        let server_channel = server_task
            .await
            .expect("server task")
            .expect("server exchange");
        assert_eq!(
            server_channel.peer_identity().identity_id,
            NodeId::from_public_key(&client_key.verifying_key())
        );
        assert_eq!(
            server_channel.peer_identity().public_key_hex,
            hex::encode(client_key.verifying_key().to_bytes())
        );
        assert_eq!(
            client_channel.peer_identity().identity_id,
            NodeId::from_public_key(&server_key.verifying_key())
        );
    }

    #[tokio::test]
    async fn quic_channel_stores_peer_identity() {
        let client_key = SigningKey::from_bytes(&[32u8; 32]);
        let server_key = SigningKey::from_bytes(&[31u8; 32]);
        let (client_result, server_task, _, _) = start_identity_test_pair(
            Some(server_key.verifying_key()),
            Some(client_key.verifying_key()),
            test_hosts(),
            test_hosts(),
            test_metrics(),
            test_metrics(),
        )
        .await;
        let client_channel = client_result.expect("client channel");
        let server_channel = server_task
            .await
            .expect("server task")
            .expect("server channel");
        assert_eq!(
            client_channel.peer_identity().identity_id,
            NodeId::from_public_key(&server_key.verifying_key())
        );
        assert_eq!(
            server_channel.peer_identity().identity_id,
            NodeId::from_public_key(&client_key.verifying_key())
        );
        assert!(!client_channel.peer_identity().public_key_hex.is_empty());
        assert!(!server_channel.peer_identity().public_key_hex.is_empty());
    }

    #[tokio::test]
    async fn two_node_quic_roundtrip() {
        use std::time::Duration;
        use tokio::time::timeout;

        let server_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind server");
        let server_addr = server_socket.local_addr().expect("server addr");

        let server_key = SigningKey::from_bytes(&[1u8; 32]);
        let client_key = SigningKey::from_bytes(&[2u8; 32]);
        let server_public_key = server_key.verifying_key();
        let server_hosts = test_hosts();
        let client_hosts = test_hosts();
        let server_metrics = test_metrics();
        let client_metrics = test_metrics();

        let server_task = tokio::spawn(async move {
            let channel = QuicChannel::accept(
                server_socket,
                &server_key,
                None,
                server_hosts,
                server_metrics,
                QuicConfig::default(),
            )
            .await
            .expect("server accept");

            let (_send, mut recv) = channel.accept_stream().await.expect("accept_stream");
            let mut data = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                match recv.read(&mut buf).await.expect("read") {
                    Some(len) if len > 0 => data.extend_from_slice(&buf[..len]),
                    Some(_) | None => break,
                }
            }
            data
        });

        let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind client");

        let client_channel = timeout(
            Duration::from_secs(5),
            QuicChannel::connect(
                client_socket,
                server_addr,
                "hal-sync",
                &client_key,
                Some(server_public_key),
                client_hosts,
                client_metrics,
                QuicConfig::default(),
            ),
        )
        .await
        .expect("connect timeout")
        .expect("client connect");

        let (mut send, _recv) = client_channel.open_stream().await.expect("open_stream");
        let payload = b"hello from client";
        send.write_all(payload).await.expect("write_all");
        send.finish().expect("finish");

        let server_data = timeout(Duration::from_secs(5), server_task)
            .await
            .expect("server timeout")
            .expect("server join");

        assert_eq!(server_data, payload);
    }

    #[tokio::test]
    async fn quic_identity_exchange_valid() {
        let client_hosts = test_hosts();
        let server_hosts = test_hosts();
        let client_metrics = test_metrics();
        let server_metrics = test_metrics();
        let server_key = SigningKey::from_bytes(&[31u8; 32]);
        let expected = server_key.verifying_key();
        let (client_result, server_task, _, _) = start_identity_test_pair(
            Some(expected),
            None,
            client_hosts,
            server_hosts,
            Arc::clone(&client_metrics),
            server_metrics,
        )
        .await;
        assert!(client_result.is_ok());
        assert!(server_task.await.expect("server task").is_ok());
        assert_eq!(client_metrics.snapshot().quic_identity_verified_total, 1);
        assert_eq!(client_metrics.snapshot().quic_identity_rejected_total, 0);
    }

    #[tokio::test]
    async fn quic_identity_exchange_wrong_key() {
        let client_metrics = test_metrics();
        let (client_result, server_task, _, _) = start_identity_test_pair(
            Some(SigningKey::from_bytes(&[33u8; 32]).verifying_key()),
            None,
            test_hosts(),
            test_hosts(),
            Arc::clone(&client_metrics),
            test_metrics(),
        )
        .await;
        assert!(matches!(client_result, Err(QuicError::IdentityRejected(_))));
        assert!(server_task.await.expect("server task").is_ok());
        assert_eq!(client_metrics.snapshot().quic_identity_rejected_total, 1);
    }

    #[tokio::test]
    async fn quic_identity_exchange_tofu() {
        let client_hosts = test_hosts();
        let server_hosts = test_hosts();
        let client_metrics = test_metrics();
        let server_metrics = test_metrics();
        let (client_result, server_task, _, _) = start_identity_test_pair(
            None,
            None,
            Arc::clone(&client_hosts),
            Arc::clone(&server_hosts),
            Arc::clone(&client_metrics),
            Arc::clone(&server_metrics),
        )
        .await;
        assert!(client_result.is_ok());
        assert!(server_task.await.expect("server task").is_ok());
        assert_eq!(client_metrics.snapshot().quic_identity_tofu_total, 1);
        assert_eq!(server_metrics.snapshot().quic_identity_tofu_total, 1);
        assert_eq!(client_hosts.lock().expect("client hosts").len(), 1);
        assert_eq!(server_hosts.lock().expect("server hosts").len(), 1);
    }

    #[tokio::test]
    async fn quic_identity_exchange_known_hosts() {
        let client_hosts = test_hosts();
        let server_hosts = test_hosts();
        let client_key = SigningKey::from_bytes(&[32u8; 32]);
        let server_key = SigningKey::from_bytes(&[31u8; 32]);
        pin_test_key(&client_hosts, &server_key);
        pin_test_key(&server_hosts, &client_key);
        let client_metrics = test_metrics();
        let server_metrics = test_metrics();
        let (client_result, server_task, _, _) = start_identity_test_pair(
            None,
            None,
            Arc::clone(&client_hosts),
            Arc::clone(&server_hosts),
            Arc::clone(&client_metrics),
            Arc::clone(&server_metrics),
        )
        .await;
        assert!(client_result.is_ok());
        assert!(server_task.await.expect("server task").is_ok());
        assert_eq!(client_metrics.snapshot().quic_identity_verified_total, 1);
        assert_eq!(server_metrics.snapshot().quic_identity_verified_total, 1);
        assert_eq!(client_metrics.snapshot().quic_identity_tofu_total, 0);
        assert_eq!(server_metrics.snapshot().quic_identity_tofu_total, 0);
    }
}
