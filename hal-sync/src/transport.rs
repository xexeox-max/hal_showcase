use crate::abuse_metrics::AbuseMetrics;
use crate::cluster::ClusterStateRecord;
use crate::integrity::{IntegrityResponse, IntegrityWave};
use crate::journal::SyncEvent;
use crate::quic_transport::QuicChannel;
use crate::runtime_context::InboundObservation;
use crate::stigma_cache::StigmaCache;
use anyhow::{anyhow, Result};
use hal_settings::NetworkTrustPolicy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const ENVELOPE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);
pub const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;

pub fn is_lan_address(address: &SocketAddr) -> bool {
    match address.ip() {
        std::net::IpAddr::V4(ip) => {
            let octets = ip.octets();
            ip.is_private() || ip.is_loopback() || (octets[0] == 169 && octets[1] == 254)
        }
        std::net::IpAddr::V6(ip) => {
            let first_segment = ip.segments()[0];
            ip.is_loopback() || first_segment & 0xfe00 == 0xfc00 || first_segment & 0xffc0 == 0xfe80
        }
    }
}

pub fn inferred_lan_peer_listener_address(remote_addr: SocketAddr) -> Option<SocketAddr> {
    if remote_addr.ip().is_loopback() || !is_lan_address(&remote_addr) {
        return None;
    }
    let port = crate::runtime::PeerRuntime::configured_peer_port().ok()?;
    Some(SocketAddr::new(remote_addr.ip(), port))
}

struct EnvelopeLimitedWriter {
    bytes: Vec<u8>,
    exceeded: bool,
}

#[derive(Serialize)]
struct PaddedEnvelope<'a> {
    identity_id: &'a str,
    public_key: &'a str,
    events: &'a [SyncEvent],
    media_signal: &'a Option<Vec<u8>>,
    integrity_response: &'a Option<IntegrityResponse>,
    cluster_state: &'a Option<ClusterStateRecord>,
    padding: Vec<u8>,
}

impl<'a> PaddedEnvelope<'a> {
    fn new(envelope: &'a SyncEnvelope) -> Self {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let padding = vec![0; rng.gen_range(0..=256)];
        Self {
            identity_id: &envelope.identity_id,
            public_key: &envelope.public_key,
            events: &envelope.events,
            media_signal: &envelope.media_signal,
            integrity_response: &envelope.integrity_response,
            cluster_state: &envelope.cluster_state,
            padding,
        }
    }
}

impl Write for EnvelopeLimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.bytes.len().saturating_add(bytes.len()) > MAX_ENVELOPE_BYTES {
            self.exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "envelope too large",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialize_envelope_bounded(
    envelope: &SyncEnvelope,
    metrics: Option<&AbuseMetrics>,
) -> Result<Vec<u8>> {
    let padded_envelope = PaddedEnvelope::new(envelope);

    serialize_padded_envelope_bounded(&padded_envelope, metrics)
}

fn serialize_padded_envelope_bounded(
    envelope: &PaddedEnvelope<'_>,
    metrics: Option<&AbuseMetrics>,
) -> Result<Vec<u8>> {
    let mut writer = EnvelopeLimitedWriter {
        bytes: Vec::with_capacity(4096),
        exceeded: false,
    };
    if let Err(error) = serde_json::to_writer(&mut writer, envelope) {
        if writer.exceeded {
            if let Some(metrics) = metrics {
                metrics
                    .envelope_send_size_exceeded_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            return Err(anyhow!(
                "outgoing envelope exceeds {MAX_ENVELOPE_BYTES} bytes"
            ));
        }
        return Err(error.into());
    }
    log::debug!("Padded envelope with {} bytes", envelope.padding.len());
    Ok(writer.bytes)
}

const MAX_TIMING_JITTER_MS: u64 = 500;

fn timing_jitter_enabled() -> bool {
    if cfg!(target_os = "android") {
        return true;
    }

    std::env::var("HAL_JITTER_ENABLED")
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn random_timing_jitter_ms() -> u64 {
    if !timing_jitter_enabled() {
        return 0;
    }

    use rand::Rng;
    rand::thread_rng().gen_range(0..=MAX_TIMING_JITTER_MS)
}

async fn apply_timing_jitter(jitter_ms: u64) {
    if jitter_ms == 0 {
        return;
    }
    log::info!(target: "HAL_DHT", "Timing jitter: sleeping for {} ms", jitter_ms);
    tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
}

async fn apply_network_send_timing_jitter() {
    apply_timing_jitter(random_timing_jitter_ms()).await;
}

async fn read_envelope_bounded<R>(reader: R, metrics: Option<&AbuseMetrics>) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut payload = Vec::with_capacity(4096);
    let mut limited = reader.take(MAX_ENVELOPE_BYTES as u64 + 1);
    limited.read_to_end(&mut payload).await?;
    if payload.len() > MAX_ENVELOPE_BYTES {
        if let Some(metrics) = metrics {
            metrics
                .envelope_size_exceeded_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        return Err(anyhow!(
            "incoming envelope exceeds {MAX_ENVELOPE_BYTES} bytes"
        ));
    }
    Ok(payload)
}

pub async fn connect_happy_eyeballs(
    candidates: &[SocketAddr],
    timeout: Duration,
) -> Result<TcpStream> {
    if candidates.is_empty() {
        return Err(anyhow!("no connection candidates"));
    }

    let mut remaining = candidates.to_vec();
    let first_ipv6 = remaining
        .iter()
        .position(SocketAddr::is_ipv6)
        .map(|index| remaining.remove(index));
    let first_ipv4 = remaining
        .iter()
        .position(SocketAddr::is_ipv4)
        .map(|index| remaining.remove(index));

    let connect = async move {
        let first_attempt = match (first_ipv6, first_ipv4) {
            (Some(ipv6_addr), Some(ipv4_addr)) => {
                let mut ipv6_attempt =
                    tokio::spawn(async move { TcpStream::connect(ipv6_addr).await });
                tokio::select! {
                    result = &mut ipv6_attempt => {
                        match result {
                            Ok(Ok(stream)) => Ok(stream),
                            Ok(Err(ipv6_error)) => TcpStream::connect(ipv4_addr)
                                .await
                                .map_err(|ipv4_error| anyhow!("IPv6 failed: {ipv6_error}; IPv4 failed: {ipv4_error}")),
                            Err(join_error) => Err(anyhow!("IPv6 attempt failed: {join_error}")),
                        }
                    }
                    _ = tokio::time::sleep(HAPPY_EYEBALLS_DELAY) => {
                        let mut ipv4_attempt = tokio::spawn(async move { TcpStream::connect(ipv4_addr).await });
                        tokio::select! {
                            result = &mut ipv6_attempt => {
                                match result {
                                    Ok(Ok(stream)) => {
                                        ipv4_attempt.abort();
                                        Ok(stream)
                                    }
                                    Ok(Err(ipv6_error)) => match ipv4_attempt.await {
                                        Ok(Ok(stream)) => Ok(stream),
                                        Ok(Err(ipv4_error)) => Err(anyhow!("IPv6 failed: {ipv6_error}; IPv4 failed: {ipv4_error}")),
                                        Err(join_error) => Err(anyhow!("IPv4 attempt failed: {join_error}")),
                                    },
                                    Err(join_error) => {
                                        ipv4_attempt.abort();
                                        Err(anyhow!("IPv6 attempt failed: {join_error}"))
                                    }
                                }
                            }
                            result = &mut ipv4_attempt => {
                                match result {
                                    Ok(Ok(stream)) => {
                                        ipv6_attempt.abort();
                                        Ok(stream)
                                    }
                                    Ok(Err(ipv4_error)) => match ipv6_attempt.await {
                                        Ok(Ok(stream)) => Ok(stream),
                                        Ok(Err(ipv6_error)) => Err(anyhow!("IPv6 failed: {ipv6_error}; IPv4 failed: {ipv4_error}")),
                                        Err(join_error) => Err(anyhow!("IPv6 attempt failed: {join_error}")),
                                    },
                                    Err(join_error) => {
                                        ipv6_attempt.abort();
                                        Err(anyhow!("IPv4 attempt failed: {join_error}"))
                                    }
                                }
                            }
                        }
                    }
                }
            }
            (Some(address), None) | (None, Some(address)) => TcpStream::connect(address)
                .await
                .map_err(|error| anyhow!("connection failed: {error}")),
            (None, None) => Err(anyhow!("candidates contain no IP addresses")),
        };
        match first_attempt {
            Ok(stream) => Ok(stream),
            Err(first_error) => {
                let mut last_error = first_error;
                for address in remaining {
                    match TcpStream::connect(address).await {
                        Ok(stream) => return Ok(stream),
                        Err(error) => {
                            last_error = anyhow!("{last_error}; {address} failed: {error}");
                        }
                    }
                }
                Err(last_error)
            }
        }
    };

    tokio::time::timeout(timeout, connect)
        .await
        .map_err(|_| anyhow!("Happy Eyeballs connection timed out"))?
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Tcp,
    TlsMux,
}

#[derive(Debug, Clone)]
pub struct EnvelopeMeta {
    pub binding_before_learn: crate::pinning::BindingCheck,
    pub was_cold: bool,
    pub remote_addr: Option<SocketAddr>,
    pub transport_peer_identity: Option<String>,
    pub session_sender: Option<crate::mux::MuxSender>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DeliveryAck {
    event_ids: Vec<String>,
    message_ids: Vec<String>,
}

impl Default for EnvelopeMeta {
    fn default() -> Self {
        Self {
            binding_before_learn: crate::pinning::BindingCheck::Trusted,
            was_cold: false,
            remote_addr: None,
            transport_peer_identity: None,
            session_sender: None,
        }
    }
}

pub(crate) fn try_send_inbound_observation(
    sender: &mpsc::Sender<InboundObservation>,
    observation: InboundObservation,
    metrics: Option<&AbuseMetrics>,
) -> bool {
    match sender.try_send(observation) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(_)) => {
            if let Some(metrics) = metrics {
                metrics
                    .inbound_observation_dropped_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            log::debug!("inbound observation channel full, dropping");
            false
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            log::debug!("inbound observation channel closed, dropping");
            false
        }
    }
}

fn reject_stigmatized_peer(
    cache: Option<&Arc<StigmaCache>>,
    identity: &crate::dht::NodeId,
    metrics: Option<&Arc<AbuseMetrics>>,
) -> bool {
    let Some(cache) = cache else {
        return false;
    };
    if !cache.is_stigmatized(identity) {
        return false;
    }
    if let Some(metrics) = metrics {
        metrics
            .transport_stigma_rejected_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    log::debug!("transport: rejected stigmatized peer {}", identity.to_hex());
    true
}

/// Стратегия проб QUIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStrategy {
    /// Только при отправке.
    Lazy,
    /// Только фоновые.
    Background,
    /// Оба.
    Hybrid,
}

/// Настройки проб QUIC. Дефолт — для домохозяйки, поля доступны для гика через UI.
#[derive(Debug, Clone)]
pub struct QuicProbeConfig {
    /// Включён ли QUIC вообще.
    pub enabled: bool,
    /// Стратегия проб.
    pub strategy: ProbeStrategy,
    /// Интервал фоновых проб.
    pub background_interval: Duration,
    /// Только на зарядке.
    pub only_while_charging: bool,
    /// Только на Wi-Fi.
    pub only_on_wifi: bool,
    /// Максимум узлов для проб.
    pub max_probe_targets: usize,
    /// Таймаут одной пробы.
    pub probe_timeout: Duration,
}

impl Default for QuicProbeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            strategy: ProbeStrategy::Hybrid,
            background_interval: Duration::from_secs(15 * 60),
            only_while_charging: false,
            only_on_wifi: false,
            max_probe_targets: 10,
            probe_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncEnvelope {
    pub identity_id: String,
    pub public_key: String,
    pub events: Vec<SyncEvent>,
    #[serde(default)]
    pub media_signal: Option<Vec<u8>>,
    #[serde(default)]
    pub integrity_response: Option<IntegrityResponse>,
    #[serde(default)]
    pub cluster_state: Option<ClusterStateRecord>,
    #[serde(default)]
    pub is_cover: bool,
}

impl SyncEnvelope {
    pub fn new(identity_id: String, public_key: String, events: Vec<SyncEvent>) -> Self {
        Self {
            identity_id,
            public_key,
            events,
            media_signal: None,
            integrity_response: None,
            cluster_state: None,
            is_cover: false,
        }
    }

    pub fn new_cover(identity_id: String, public_key: String) -> Self {
        Self {
            identity_id,
            public_key,
            events: Vec::new(),
            media_signal: None,
            integrity_response: None,
            cluster_state: None,
            is_cover: true,
        }
    }

    pub fn new_media_signal(identity_id: String, public_key: String, signal: Vec<u8>) -> Self {
        Self {
            identity_id,
            public_key,
            events: Vec::new(),
            media_signal: Some(signal),
            integrity_response: None,
            cluster_state: None,
            is_cover: false,
        }
    }

    pub fn with_integrity_response(mut self, response: IntegrityResponse) -> Self {
        self.integrity_response = Some(response);
        self
    }

    pub fn with_cluster_state(mut self, state: ClusterStateRecord) -> Self {
        self.cluster_state = Some(state);
        self
    }

    pub fn verify(&self) -> Result<()> {
        let public_key_bytes: [u8; 32] = hex::decode(&self.public_key)
            .map_err(|error| anyhow!("invalid sync public key: {error}"))?
            .try_into()
            .map_err(|_| anyhow!("sync public key must be 32 bytes"))?;
        let mut identity_hash = Sha256::new();
        identity_hash.update(public_key_bytes);
        if self.identity_id != hex::encode(identity_hash.finalize()) {
            return Err(anyhow!("sync identity does not match public key"));
        }
        if let Some(cluster_state) = &self.cluster_state {
            cluster_state.verify()?;
        }
        for event in &self.events {
            if !event.verify(&self.public_key)? {
                return Err(anyhow!("sync event signature verification failed"));
            }
        }
        Ok(())
    }

    pub fn verify_with_integrity(&self, wave: &IntegrityWave, now: u64) -> Result<()> {
        self.verify()?;
        let response = self
            .integrity_response
            .as_ref()
            .ok_or_else(|| anyhow!("sync envelope has no integrity response"))?;
        response.verify(wave, now)?;
        if response.software_measurement != wave.required_measurement {
            return Err(anyhow!(
                "sync envelope software measurement is not approved"
            ));
        }
        if response.node_id != self.identity_id || response.node_public_key != self.public_key {
            return Err(anyhow!(
                "integrity response identity does not match envelope"
            ));
        }
        Ok(())
    }
}

/// Lifecycle-managed transport for one autonomous client peer.
pub struct PeerTransport {
    pub local_address: String,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
    quic: Option<Arc<QuicChannel>>,
    incoming_tx: Option<mpsc::Sender<(SyncEnvelope, EnvelopeMeta)>>,
}

impl PeerTransport {
    pub async fn idle() -> Result<(Self, mpsc::Receiver<(SyncEnvelope, EnvelopeMeta)>)> {
        let (_tx, rx) = mpsc::channel(64);
        Ok((
            Self {
                local_address: "0.0.0.0:0".to_string(),
                shutdown: None,
                task: None,
                quic: None,
                incoming_tx: None,
            },
            rx,
        ))
    }

    pub async fn bind_secure(
        address: &str,
        local_identity: ed25519_dalek::SigningKey,
        hosts: std::sync::Arc<std::sync::Mutex<crate::pinning::KnownHosts>>,
        trust_policy: NetworkTrustPolicy,
    ) -> Result<(Self, mpsc::Receiver<(SyncEnvelope, EnvelopeMeta)>)> {
        Self::bind_secure_on_demand(address, local_identity, hosts, trust_policy).await
    }

    pub async fn bind_secure_on_demand(
        address: &str,
        local_identity: ed25519_dalek::SigningKey,
        hosts: std::sync::Arc<std::sync::Mutex<crate::pinning::KnownHosts>>,
        trust_policy: NetworkTrustPolicy,
    ) -> Result<(Self, mpsc::Receiver<(SyncEnvelope, EnvelopeMeta)>)> {
        Self::bind_secure_on_demand_with_kind(
            address,
            local_identity,
            hosts,
            trust_policy,
            TransportKind::Tcp,
            None,
            None,
        )
        .await
    }

    pub async fn bind_secure_on_demand_with_kind(
        address: &str,
        local_identity: ed25519_dalek::SigningKey,
        hosts: std::sync::Arc<std::sync::Mutex<crate::pinning::KnownHosts>>,
        trust_policy: NetworkTrustPolicy,
        transport_kind: TransportKind,
        dht_tx: Option<mpsc::Sender<(crate::Mux<crate::tls_transport::TlsConn>, crate::MuxStream)>>,
        dht_metrics: Option<std::sync::Arc<crate::dht::DhtMetrics>>,
    ) -> Result<(Self, mpsc::Receiver<(SyncEnvelope, EnvelopeMeta)>)> {
        Self::bind_secure_on_demand_with_observations(
            address,
            local_identity,
            hosts,
            trust_policy,
            transport_kind,
            dht_tx,
            dht_metrics,
            None,
            None,
        )
        .await
    }

    pub(crate) async fn bind_secure_on_demand_with_observations(
        address: &str,
        local_identity: ed25519_dalek::SigningKey,
        hosts: std::sync::Arc<std::sync::Mutex<crate::pinning::KnownHosts>>,
        trust_policy: NetworkTrustPolicy,
        transport_kind: TransportKind,
        dht_tx: Option<mpsc::Sender<(crate::Mux<crate::tls_transport::TlsConn>, crate::MuxStream)>>,
        dht_metrics: Option<std::sync::Arc<crate::dht::DhtMetrics>>,
        inbound_observations_tx: Option<mpsc::Sender<InboundObservation>>,
        abuse_metrics: Option<Arc<AbuseMetrics>>,
    ) -> Result<(Self, mpsc::Receiver<(SyncEnvelope, EnvelopeMeta)>)> {
        Self::bind_secure_on_demand_with_stigma_cache(
            address,
            local_identity,
            hosts,
            trust_policy,
            transport_kind,
            dht_tx,
            dht_metrics,
            inbound_observations_tx,
            abuse_metrics,
            None,
            None,
        )
        .await
    }

    pub(crate) async fn bind_secure_on_demand_with_stigma_cache(
        address: &str,
        local_identity: ed25519_dalek::SigningKey,
        hosts: std::sync::Arc<std::sync::Mutex<crate::pinning::KnownHosts>>,
        trust_policy: NetworkTrustPolicy,
        transport_kind: TransportKind,
        dht_tx: Option<mpsc::Sender<(crate::Mux<crate::tls_transport::TlsConn>, crate::MuxStream)>>,
        dht_metrics: Option<std::sync::Arc<crate::dht::DhtMetrics>>,
        inbound_observations_tx: Option<mpsc::Sender<InboundObservation>>,
        abuse_metrics: Option<Arc<AbuseMetrics>>,
        stigma_cache: Option<Arc<StigmaCache>>,
        degradation: Option<Arc<crate::degradation::DegradationState>>,
    ) -> Result<(Self, mpsc::Receiver<(SyncEnvelope, EnvelopeMeta)>)> {
        use crate::secure_channel::handshake_server;

        let listener = TcpListener::bind(address).await?;
        let local_address = listener.local_addr()?.to_string();
        let (incoming_tx, incoming_rx) = mpsc::channel::<(SyncEnvelope, EnvelopeMeta)>(64);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let incoming_tx_for_task = incoming_tx.clone();
        let incoming_tx_for_self = incoming_tx;

        let task = tokio::spawn(async move {
            // TLS mux drivers enforce their own keepalive and idle failure detection.
            loop {
                let accepted = tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => accepted,
                };
                let Ok((stream, remote_address)) = accepted else {
                    break;
                };
                let incoming = incoming_tx_for_task.clone();
                let hosts = hosts.clone();
                let local_identity = local_identity.clone();
                let trust_policy = trust_policy.clone();
                let transport_kind = transport_kind;
                let dht_tx = dht_tx.clone();
                let dht_metrics = dht_metrics.clone();
                let inbound_observations_tx = inbound_observations_tx.clone();
                let abuse_metrics = abuse_metrics.clone();
                let stigma_cache = stigma_cache.clone();
                let degradation = degradation.clone();
                tokio::spawn(async move {
                    let mut persistent_mux = None;
                    let result = async {
                        let mut tcp_channel = None;
                        let (envelope, client_vk, session_sender) = if transport_kind == TransportKind::TlsMux {
                            let handshake_started = tokio::time::Instant::now();
                            log::info!(
                                target: "HAL_DHT",
                                "TLS: accepted TCP from {remote_address}; starting server handshake"
                            );
                            let tls = tokio::time::timeout(
                                HANDSHAKE_TIMEOUT,
                                crate::tls_transport::TlsTransport::accept(
                                    stream,
                                    &local_identity,
                                    None,
                                ),
                            )
                            .await??;
                            log::info!(
                                target: "HAL_DHT",
                                "TLS: inbound handshake OK from {remote_address} ({}ms)",
                                handshake_started.elapsed().as_millis()
                            );
                            let client_vk = tls
                                .peer_identity()
                                .ok_or_else(|| anyhow!("TLS peer identity missing"))?;
                            let identity_node_id = crate::dht::NodeId::from_public_key(&client_vk);
                            if reject_stigmatized_peer(
                                stigma_cache.as_ref(),
                                &identity_node_id,
                                abuse_metrics.as_ref(),
                            ) {
                                return Err(anyhow!("peer is stigmatized"));
                            }
                            let mut mux = crate::mux::Mux::new(
                                tls.into_stream(),
                                crate::mux::MuxConfig::default(),
                                crate::mux::Mode::Server,
                            );
                            let session_sender = mux.sender();
                            let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, mux.accept())
                                .await?
                                .ok_or_else(|| anyhow!("TLS mux closed before stream open"))?;
                            if stream.kind() == crate::mux::StreamKind::Dht {
                                if let Some(metrics) = &dht_metrics {
                                    metrics.inc_received();
                                }
                                if let Some(tx) = &dht_tx {
                                    if tx.try_send((mux, stream)).is_err() {
                                        if let Some(metrics) = &dht_metrics {
                                            metrics.inc_dropped();
                                        }
                                        log::warn!("DHT channel full, dropping incoming stream");
                                    }
                                } else {
                                    if let Some(metrics) = &dht_metrics {
                                        metrics.inc_dropped();
                                    }
                                    log::warn!("DHT stream rejected: handler not configured");
                                }
                                return Ok(());
                            }
                            let payload = tokio::time::timeout(
                                ENVELOPE_TIMEOUT,
                                read_envelope_bounded(stream, abuse_metrics.as_deref()),
                            )
                            .await??;
                            persistent_mux = Some(mux);
                            (serde_json::from_slice(&payload)?, client_vk, Some(session_sender))
                        } else {
                            let (mut channel, client_vk) = tokio::time::timeout(
                                HANDSHAKE_TIMEOUT,
                                handshake_server(stream, &local_identity, None),
                            )
                            .await??;
                            let identity_node_id = crate::dht::NodeId::from_public_key(&client_vk);
                            if reject_stigmatized_peer(
                                stigma_cache.as_ref(),
                                &identity_node_id,
                                abuse_metrics.as_ref(),
                            ) {
                                return Err(anyhow!("peer is stigmatized"));
                            }
                            let envelope: SyncEnvelope =
                                tokio::time::timeout(ENVELOPE_TIMEOUT, channel.recv_json())
                                    .await??;
                            tcp_channel = Some(channel);
                            (envelope, client_vk, None)
                        };
                        let receipt = process_peer_envelope(
                            envelope,
                            client_vk,
                            remote_address,
                            &hosts,
                            &trust_policy,
                            degradation.as_ref(),
                            inbound_observations_tx.as_ref(),
                            &incoming,
                            abuse_metrics.as_deref(),
                            session_sender,
                        )
                        .await?;

                        if let Some(mut channel) = tcp_channel.take() {
                            log_delivery_ack_sent(&receipt);
                            tokio::time::timeout(ENVELOPE_TIMEOUT, channel.send_json(&receipt))
                                .await??;
                        }

                        if let Some(mut mux) = persistent_mux.take() {
                            send_mux_delivery_ack(&mux, &receipt).await?;
                            loop {
                                let Some(stream) = mux.accept().await else {
                                    break;
                                };
                                if stream.kind() == crate::mux::StreamKind::Control {
                                    let payload = tokio::time::timeout(
                                        ENVELOPE_TIMEOUT,
                                        read_envelope_bounded(stream, abuse_metrics.as_deref()),
                                    )
                                    .await??;
                                    if serde_json::from_slice::<DeliveryAck>(&payload).is_err() {
                                        log::warn!("invalid Mux control acknowledgement from {remote_address}");
                                    }
                                    continue;
                                }
                                if stream.kind() == crate::mux::StreamKind::Dht {
                                    if let Some(metrics) = &dht_metrics {
                                        metrics.inc_received();
                                    }
                                    if let Some(tx) = &dht_tx {
                                        if tx.try_send((mux, stream)).is_err() {
                                            if let Some(metrics) = &dht_metrics {
                                                metrics.inc_dropped();
                                            }
                                            log::warn!(
                                                "DHT channel full, dropping incoming stream"
                                            );
                                        }
                                    } else if let Some(metrics) = &dht_metrics {
                                        metrics.inc_dropped();
                                        log::warn!("DHT stream rejected: handler not configured");
                                    }
                                    return Ok(());
                                }
                                let payload = tokio::time::timeout(
                                    ENVELOPE_TIMEOUT,
                                    read_envelope_bounded(stream, abuse_metrics.as_deref()),
                                )
                                .await??;
                                let envelope = serde_json::from_slice(&payload)?;
                                let session_sender = mux.sender();
                                let receipt = process_peer_envelope(
                                    envelope,
                                    client_vk,
                                    remote_address,
                                    &hosts,
                                    &trust_policy,
                                    degradation.as_ref(),
                                    inbound_observations_tx.as_ref(),
                                    &incoming,
                                    abuse_metrics.as_deref(),
                                    Some(session_sender),
                                )
                                .await?;
                                send_mux_delivery_ack(&mux, &receipt).await?;
                            }
                        }
                        Ok(())
                    }
                    .await;
                    if let Err(error) = result {
                        log::warn!("secure sync peer rejected ({}): {error}", remote_address);
                    }
                });
            }
        });

        Ok((
            Self {
                local_address,
                shutdown: Some(shutdown_tx),
                task: Some(task),
                quic: None,
                incoming_tx: Some(incoming_tx_for_self),
            },
            incoming_rx,
        ))
    }

    pub async fn stop(mut self) -> Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.await
                .map_err(|err| anyhow!("transport task failed: {err}"))?;
        }
        Ok(())
    }

    /// Привязать QUIC-канал (после hole punching).
    pub fn attach_quic(&mut self, channel: Arc<QuicChannel>) {
        self.quic = Some(channel);
    }

    /// Есть ли QUIC-канал.
    pub fn has_quic(&self) -> bool {
        self.quic.is_some()
    }

    /// Получить QUIC-канал (клонированный Arc).
    pub fn quic_channel(&self) -> Option<Arc<QuicChannel>> {
        self.quic.clone()
    }

    /// Клонировать Sender для incoming-канала (если есть).
    pub fn incoming_tx(&self) -> Option<mpsc::Sender<(SyncEnvelope, EnvelopeMeta)>> {
        self.incoming_tx.clone()
    }

    /// Отсоединить QUIC-канал.
    pub fn detach_quic(&mut self) {
        self.quic = None;
    }

    pub async fn send_secure(
        &self,
        address: &str,
        envelope: &SyncEnvelope,
        local_identity: &ed25519_dalek::SigningKey,
        hosts: std::sync::Arc<std::sync::Mutex<crate::pinning::KnownHosts>>,
        trust_policy: NetworkTrustPolicy,
    ) -> Result<()> {
        if let Some(channel) = self.quic_channel() {
            match send_envelope_quic(&channel, envelope, None).await {
                Ok(()) => return Ok(()),
                Err(error) => {
                    log::warn!("QUIC send failed, falling back to TCP: {error}");
                }
            }
        }
        send_envelope_secure(address, envelope, local_identity, hosts, trust_policy).await
    }
}

/// Encrypted one-shot send (HAL-SEC1), fully decentralized.
///
/// Trust comes ONLY from the shared peer directory: a previously learned
/// pin is enforced; an unknown peer is accepted solely under explicit
/// first-contact policy and the observed binding is recorded. Identity/key
/// CONFLICTS always fail closed - on both sides of the link.
pub async fn send_envelope_secure(
    address: &str,
    envelope: &SyncEnvelope,
    local_identity: &ed25519_dalek::SigningKey,
    hosts: std::sync::Arc<std::sync::Mutex<crate::pinning::KnownHosts>>,
    trust_policy: NetworkTrustPolicy,
) -> Result<()> {
    // A successful return requires the authenticated receiver to acknowledge
    // that the envelope was accepted into its incoming sync queue.
    send_envelope_secure_with_expectation(
        address,
        envelope,
        local_identity,
        hosts,
        None,
        trust_policy,
        TransportKind::Tcp,
        crate::mux::StreamKind::Sync,
        None,
    )
    .await
}

/// Serialize an envelope for transmission over a QUIC stream.
fn serialize_envelope_for_quic(
    envelope: &SyncEnvelope,
    metrics: Option<&AbuseMetrics>,
) -> Result<Vec<u8>> {
    serialize_envelope_bounded(envelope, metrics)
}

/// Отправить envelope через QUIC-канал.
#[allow(dead_code)]
pub(crate) async fn send_envelope_quic(
    channel: &crate::quic_transport::QuicChannel,
    envelope: &SyncEnvelope,
    metrics: Option<&AbuseMetrics>,
) -> Result<()> {
    envelope.verify()?;
    let bytes = serialize_envelope_for_quic(envelope, metrics)?;
    let (mut send, mut recv) = channel
        .open_stream()
        .await
        .map_err(|error| anyhow!("QUIC open_stream failed: {error}"))?;
    apply_network_send_timing_jitter().await;
    send.write_all(&bytes)
        .await
        .map_err(|error| anyhow!("QUIC write failed: {error}"))?;
    send.finish()
        .map_err(|error| anyhow!("QUIC finish failed: {error}"))?;
    let response = tokio::time::timeout(ENVELOPE_TIMEOUT, recv.read_to_end(MAX_ENVELOPE_BYTES))
        .await
        .map_err(|_| anyhow!("QUIC delivery acknowledgement timed out"))?
        .map_err(|error| anyhow!("QUIC delivery acknowledgement read failed: {error}"))?;
    let receipt: DeliveryAck = serde_json::from_slice(&response)?;
    validate_delivery_ack(envelope, &receipt)?;
    log_delivery_ack_received(&receipt);
    Ok(())
}

/// Принимает входящие envelope через QUIC, передаёт в mpsc.
///
/// Работает до shutdown или до ошибки accept_stream.
pub(crate) async fn quic_incoming_loop(
    channel: Arc<QuicChannel>,
    sender: mpsc::Sender<(SyncEnvelope, EnvelopeMeta)>,
    hosts: Arc<std::sync::Mutex<crate::pinning::KnownHosts>>,
    abuse_metrics: Arc<AbuseMetrics>,
    mut shutdown: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                log::debug!("QUIC incoming loop stopped by shutdown");
                break;
            }
            result = channel.accept_stream() => {
                match result {
                    Ok((mut send, recv)) => {
                        let data = match tokio::time::timeout(
                            ENVELOPE_TIMEOUT,
                            read_envelope_bounded(recv, Some(&abuse_metrics)),
                        )
                        .await
                        {
                            Ok(Ok(data)) => data,
                            Ok(Err(error)) => {
                                log::warn!("QUIC bounded envelope read failed: {error}");
                                continue;
                            }
                            Err(_) => {
                                log::warn!("QUIC envelope read timed out");
                                continue;
                            }
                        };
                        match serde_json::from_slice::<SyncEnvelope>(&data) {
                            Ok(envelope) => {
                                let peer_identity = channel.peer_identity();
                                if envelope.identity_id != peer_identity.identity_id.to_hex()
                                    || envelope.public_key != peer_identity.public_key_hex
                                    || envelope.verify().is_err()
                                {
                                    log::warn!(
                                        "QUIC envelope identity or signature does not match authenticated peer"
                                    );
                                    continue;
                                }
                                let receipt = delivery_ack_for(&envelope);
                                let binding_before_learn = hosts
                                    .lock()
                                    .map(|known_hosts| {
                                        known_hosts.check(
                                            &envelope.identity_id,
                                            &envelope.public_key,
                                        )
                                    })
                                    .unwrap_or(crate::pinning::BindingCheck::Unknown);
                                let meta = EnvelopeMeta {
                                    was_cold: matches!(
                                        &binding_before_learn,
                                        crate::pinning::BindingCheck::Unknown
                                    ),
                                    binding_before_learn,
                                    remote_addr: channel.remote_address(),
                                    transport_peer_identity: Some(
                                        channel.peer_identity().identity_id.to_hex(),
                                    ),
                                    session_sender: None,
                                };
                                if let Err(error) = sender.send((envelope, meta)).await {
                                    log::warn!("QUIC mpsc send failed: {error}");
                                    break;
                                }
                                match serde_json::to_vec(&receipt) {
                                    Ok(response) => {
                                        if let Err(error) = send.write_all(&response).await {
                                            log::warn!("QUIC delivery acknowledgement write failed: {error}");
                                            continue;
                                        }
                                        if let Err(error) = send.finish() {
                                            log::warn!("QUIC delivery acknowledgement finish failed: {error}");
                                            continue;
                                        }
                                        log_delivery_ack_sent(&receipt);
                                    }
                                    Err(error) => {
                                        log::error!("failed to encode QUIC delivery acknowledgement: {error}");
                                    }
                                }
                            }
                            Err(error) => {
                                log::warn!("QUIC envelope deserialize failed: {error}");
                            }
                        }
                    }
                    Err(error) => {
                        log::warn!("QUIC accept_stream failed: {error}");
                        break;
                    }
                }
            }
        }
    }
}

pub async fn send_envelope_secure_with_stream_kind(
    address: &str,
    envelope: &SyncEnvelope,
    local_identity: &ed25519_dalek::SigningKey,
    hosts: std::sync::Arc<std::sync::Mutex<crate::pinning::KnownHosts>>,
    expected_peer_key: Option<ed25519_dalek::VerifyingKey>,
    trust_policy: NetworkTrustPolicy,
    stream_kind: crate::mux::StreamKind,
) -> Result<()> {
    send_envelope_secure_with_expectation(
        address,
        envelope,
        local_identity,
        hosts,
        expected_peer_key,
        trust_policy,
        TransportKind::TlsMux,
        stream_kind,
        None,
    )
    .await
}

pub(crate) async fn send_envelope_secure_with_stream_kind_and_metrics(
    address: &str,
    envelope: &SyncEnvelope,
    local_identity: &ed25519_dalek::SigningKey,
    hosts: std::sync::Arc<std::sync::Mutex<crate::pinning::KnownHosts>>,
    expected_peer_key: Option<ed25519_dalek::VerifyingKey>,
    trust_policy: NetworkTrustPolicy,
    stream_kind: crate::mux::StreamKind,
    metrics: Arc<AbuseMetrics>,
) -> Result<()> {
    send_envelope_secure_with_expectation(
        address,
        envelope,
        local_identity,
        hosts,
        expected_peer_key,
        trust_policy,
        TransportKind::TlsMux,
        stream_kind,
        Some(metrics),
    )
    .await
}

pub(crate) async fn send_envelope_secure_with_tcp_candidates(
    addresses: &[String],
    envelope: &SyncEnvelope,
    local_identity: &ed25519_dalek::SigningKey,
    hosts: std::sync::Arc<std::sync::Mutex<crate::pinning::KnownHosts>>,
    expected_peer_key: ed25519_dalek::VerifyingKey,
    trust_policy: NetworkTrustPolicy,
    metrics: Arc<AbuseMetrics>,
) -> Result<String> {
    let mut last_error = None;
    for address in addresses {
        match send_envelope_secure_with_stream_kind_and_metrics(
            address,
            envelope,
            local_identity,
            Arc::clone(&hosts),
            Some(expected_peer_key.clone()),
            trust_policy.clone(),
            crate::mux::StreamKind::Sync,
            Arc::clone(&metrics),
        )
        .await
        {
            Ok(()) => return Ok(address.clone()),
            Err(error) => {
                log::debug!(
                    target: "HAL_DHT",
                    "TCP candidate {address} failed identity-verified delivery: {error}"
                );
                last_error = Some(anyhow!("TCP candidate {address} failed: {error}"));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("no TCP endpoint candidates to try")))
}

pub async fn send_envelope_secure_pinned(
    address: &str,
    envelope: &SyncEnvelope,
    local_identity: &ed25519_dalek::SigningKey,
    hosts: std::sync::Arc<std::sync::Mutex<crate::pinning::KnownHosts>>,
    expected_peer_key: ed25519_dalek::VerifyingKey,
    trust_policy: NetworkTrustPolicy,
) -> Result<()> {
    send_envelope_secure_with_expectation(
        address,
        envelope,
        local_identity,
        hosts,
        Some(expected_peer_key),
        trust_policy,
        TransportKind::Tcp,
        crate::mux::StreamKind::Sync,
        None,
    )
    .await
}

pub async fn send_envelope_secure_with_kind(
    address: &str,
    envelope: &SyncEnvelope,
    local_identity: &ed25519_dalek::SigningKey,
    hosts: std::sync::Arc<std::sync::Mutex<crate::pinning::KnownHosts>>,
    expected_peer_key: ed25519_dalek::VerifyingKey,
    trust_policy: NetworkTrustPolicy,
    transport_kind: TransportKind,
) -> Result<()> {
    send_envelope_secure_with_expectation(
        address,
        envelope,
        local_identity,
        hosts,
        Some(expected_peer_key),
        trust_policy,
        transport_kind,
        crate::mux::StreamKind::Sync,
        None,
    )
    .await
}

async fn send_envelope_over_wss(
    url: &str,
    payload: &[u8],
    envelope: &SyncEnvelope,
    stream_kind: crate::mux::StreamKind,
    local_identity: &ed25519_dalek::SigningKey,
    expected_peer_key: Option<ed25519_dalek::VerifyingKey>,
) -> Result<()> {
    let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, crate::transport_ws::connect(url))
        .await
        .map_err(|_| anyhow!("WebSocket connection timed out"))??;
    let mut websocket = crate::transport_ws::WsStream::new(stream);
    let (tls_stream, mut websocket_io) = tokio::io::duplex(1024 * 1024);
    tokio::spawn(async move {
        if let Err(error) = tokio::io::copy_bidirectional(&mut websocket, &mut websocket_io).await {
            log::debug!("WSS Transport: relay stream closed: {error}");
        }
    });

    let tls = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        crate::tls_transport::TlsTransport::connect_with_kind_on_duplex_stream(
            tls_stream,
            local_identity,
            expected_peer_key,
            stream_kind,
        ),
    )
    .await
    .map_err(|_| anyhow!("HAL TLS handshake over WSS timed out"))??;
    let mut mux = crate::mux::Mux::new(
        tls.into_stream(),
        crate::mux::MuxConfig::default(),
        crate::mux::Mode::Client,
    );
    let mut stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, mux.open(stream_kind)).await??;
    log::info!("WSS Transport: mux ready");
    tokio::time::timeout(ENVELOPE_TIMEOUT, stream.write_all(payload)).await??;
    tokio::time::timeout(ENVELOPE_TIMEOUT, finish_mux_stream(&mut stream)).await??;
    receive_mux_delivery_ack(&mut mux, envelope).await?;
    log::info!("WSS Transport: send envelope {}", envelope.identity_id);
    Ok(())
}

pub(crate) async fn send_envelope_secure_over_wss(
    url: &str,
    envelope: &SyncEnvelope,
    local_identity: &ed25519_dalek::SigningKey,
    expected_relay_key: ed25519_dalek::VerifyingKey,
    stream_kind: crate::mux::StreamKind,
    metrics: Option<&AbuseMetrics>,
) -> Result<()> {
    let padded_envelope = PaddedEnvelope::new(envelope);
    let payload = serialize_padded_envelope_bounded(&padded_envelope, metrics)?;
    envelope.verify()?;
    send_envelope_over_wss(
        url,
        &payload,
        envelope,
        stream_kind,
        local_identity,
        Some(expected_relay_key),
    )
    .await
}

pub struct WssClientSessionHandle {
    commands: mpsc::Sender<WssSessionCommand>,
    mux_sender: crate::mux::MuxSender,
    peer_identity_id: String,
    peer_public_key_hex: String,
}

impl Clone for WssClientSessionHandle {
    fn clone(&self) -> Self {
        Self {
            commands: self.commands.clone(),
            mux_sender: self.mux_sender.clone(),
            peer_identity_id: self.peer_identity_id.clone(),
            peer_public_key_hex: self.peer_public_key_hex.clone(),
        }
    }
}

impl WssClientSessionHandle {
    pub fn peer_identity_id(&self) -> &str {
        &self.peer_identity_id
    }

    pub fn peer_public_key_hex(&self) -> &str {
        &self.peer_public_key_hex
    }

    pub fn is_alive(&self) -> bool {
        self.mux_sender.is_alive() && !self.commands.is_closed()
    }

    pub async fn send_envelope(&self, envelope: SyncEnvelope) -> Result<()> {
        let event_id = envelope
            .events
            .first()
            .map(|event| event.id.as_str())
            .unwrap_or("empty");
        log::info!("WSS Transport: send envelope {event_id}");
        let (reply, result) = oneshot::channel();
        self.commands
            .send(WssSessionCommand::Send { envelope, reply })
            .await
            .map_err(|_| anyhow!("persistent WSS session is closed"))?;
        tokio::time::timeout(ENVELOPE_TIMEOUT, result)
            .await
            .map_err(|_| anyhow!("WSS delivery acknowledgement timed out"))?
            .map_err(|_| anyhow!("WSS session closed before delivery acknowledgement"))?
    }
}

enum WssSessionCommand {
    Send {
        envelope: SyncEnvelope,
        reply: oneshot::Sender<Result<()>>,
    },
}

pub(crate) async fn connect_wss_client_session(
    url: &str,
    local_identity: &ed25519_dalek::SigningKey,
    expected_peer_key: Option<ed25519_dalek::VerifyingKey>,
) -> Result<(
    WssClientSessionHandle,
    mpsc::Receiver<(SyncEnvelope, EnvelopeMeta)>,
)> {
    log::info!("WSS Transport: dialing {url}");
    let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, crate::transport_ws::connect(url))
        .await
        .map_err(|_| anyhow!("WebSocket connection timed out"))??;
    let mut websocket = crate::transport_ws::WsStream::new(stream);
    let (tls_stream, mut websocket_io) = tokio::io::duplex(1024 * 1024);
    tokio::spawn(async move {
        if let Err(error) = tokio::io::copy_bidirectional(&mut websocket, &mut websocket_io).await {
            log::debug!("WSS Transport: persistent relay stream closed: {error}");
        }
    });

    let tls = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        crate::tls_transport::TlsTransport::connect_with_kind_on_duplex_stream(
            tls_stream,
            local_identity,
            expected_peer_key,
            crate::mux::StreamKind::Sync,
        ),
    )
    .await
    .map_err(|_| anyhow!("HAL TLS handshake over WSS timed out"))??;
    log::info!("WSS Transport: TLS OK");
    let peer_key = tls
        .peer_identity()
        .ok_or_else(|| anyhow!("WSS peer identity is missing"))?;
    let peer_identity_id = crate::dht::NodeId::from_public_key(&peer_key).to_hex();
    let peer_public_key_hex = hex::encode(peer_key.as_bytes());
    let mux = crate::mux::Mux::new(
        tls.into_stream(),
        crate::mux::MuxConfig::default(),
        crate::mux::Mode::Client,
    );
    let mux_sender = mux.sender();
    log::info!("WSS Transport: mux ready");
    log::info!("WSS Transport: connected to {url}");
    let (commands, command_rx) = mpsc::channel(32);
    let (incoming_tx, incoming_rx) = mpsc::channel(32);
    let client_handle = WssClientSessionHandle {
        commands,
        mux_sender: mux_sender.clone(),
        peer_identity_id: peer_identity_id.clone(),
        peer_public_key_hex: peer_public_key_hex.clone(),
    };
    tokio::spawn(run_wss_client_session(
        mux,
        command_rx,
        incoming_tx,
        mux_sender,
        peer_identity_id,
        peer_public_key_hex,
        peer_key,
    ));
    Ok((client_handle, incoming_rx))
}

async fn run_wss_client_session(
    mut mux: crate::mux::Mux<crate::tls_transport::TlsConn>,
    mut commands: mpsc::Receiver<WssSessionCommand>,
    incoming: mpsc::Sender<(SyncEnvelope, EnvelopeMeta)>,
    mux_sender: crate::mux::MuxSender,
    peer_identity_id: String,
    peer_public_key_hex: String,
    peer_key: ed25519_dalek::VerifyingKey,
) {
    let mut pending =
        std::collections::HashMap::<Vec<String>, (SyncEnvelope, oneshot::Sender<Result<()>>)>::new(
        );
    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(WssSessionCommand::Send { envelope, reply }) = command else {
                    break;
                };
                if let Err(error) = envelope.verify() {
                    let _ = reply.send(Err(error));
                    continue;
                }
                let event_ids = envelope.events.iter().map(|event| event.id.clone()).collect::<Vec<_>>();
                if pending.contains_key(&event_ids) {
                    let _ = reply.send(Err(anyhow!("duplicate pending WSS delivery acknowledgement key")));
                    continue;
                }
                let payload = match serialize_envelope_bounded(&envelope, None) {
                    Ok(payload) => payload,
                    Err(error) => {
                        let _ = reply.send(Err(error));
                        continue;
                    }
                };
                let send_result = async {
                    let mut stream = tokio::time::timeout(
                        HANDSHAKE_TIMEOUT,
                        mux.open(crate::mux::StreamKind::Sync),
                    )
                    .await??;
                    tokio::time::timeout(ENVELOPE_TIMEOUT, stream.write_all(&payload)).await??;
                    tokio::time::timeout(ENVELOPE_TIMEOUT, finish_mux_stream(&mut stream)).await??;
                    Ok::<(), anyhow::Error>(())
                }
                .await;
                match send_result {
                    Ok(()) => {
                        pending.insert(event_ids, (envelope, reply));
                    }
                    Err(error) => {
                        let _ = reply.send(Err(error));
                    }
                }
            }
            inbound = mux.accept() => {
                let Some(mut stream) = inbound else {
                    break;
                };
                match stream.kind() {
                    crate::mux::StreamKind::Control => {
                        let receipt = match tokio::time::timeout(
                            ENVELOPE_TIMEOUT,
                            read_envelope_bounded(&mut stream, None),
                        )
                        .await
                        {
                            Ok(Ok(payload)) => serde_json::from_slice::<DeliveryAck>(&payload),
                            Ok(Err(error)) => {
                                log::warn!("invalid WSS delivery acknowledgement: {error}");
                                continue;
                            }
                            Err(_) => {
                                log::warn!("timed out reading WSS delivery acknowledgement");
                                continue;
                            }
                        };
                        let receipt = match receipt {
                            Ok(receipt) => receipt,
                            Err(error) => {
                                log::warn!("invalid WSS delivery acknowledgement: {error}");
                                continue;
                            }
                        };
                        if let Some((envelope, reply)) = pending.remove(&receipt.event_ids) {
                            let result = validate_delivery_ack(&envelope, &receipt);
                            let _ = reply.send(result);
                        } else {
                            log::warn!("orphan WSS delivery acknowledgement");
                        }
                    }
                    crate::mux::StreamKind::Sync => {
                        let payload = match tokio::time::timeout(
                            ENVELOPE_TIMEOUT,
                            read_envelope_bounded(&mut stream, None),
                        )
                        .await
                        {
                            Ok(Ok(payload)) => payload,
                            Ok(Err(error)) => {
                                log::warn!("failed to read envelope from WSS session: {error}");
                                continue;
                            }
                            Err(_) => {
                                log::warn!("timed out reading envelope from WSS session");
                                continue;
                            }
                        };
                        let envelope: SyncEnvelope = match serde_json::from_slice(&payload) {
                            Ok(envelope) => envelope,
                            Err(error) => {
                                log::warn!("invalid envelope from WSS session: {error}");
                                continue;
                            }
                        };
                        if envelope.identity_id != peer_identity_id
                            || envelope.public_key != peer_public_key_hex
                        {
                            log::warn!("WSS envelope identity does not match authenticated peer");
                            continue;
                        }
                        if let Err(error) = verify_handshake_binding(&envelope, &peer_key) {
                            log::warn!("WSS envelope identity binding failed: {error}");
                            continue;
                        }
                        let receipt = delivery_ack_for(&envelope);
                        let meta = EnvelopeMeta {
                            binding_before_learn: crate::pinning::BindingCheck::Unknown,
                            was_cold: true,
                            remote_addr: None,
                            transport_peer_identity: Some(peer_identity_id.clone()),
                            session_sender: Some(mux_sender.clone()),
                        };
                        if incoming.send((envelope, meta)).await.is_err() {
                            break;
                        }
                        if let Err(error) = send_mux_delivery_ack_via_sender(&mux_sender, &receipt).await {
                            log::warn!("failed to acknowledge WSS envelope: {error}");
                        }
                    }
                    _ => {
                        log::warn!("unsupported stream kind on persistent WSS session");
                    }
                }
            }
        }
    }
    for (_, (_, reply)) in pending {
        let _ = reply.send(Err(anyhow!("persistent WSS session closed")));
    }
    if let Err(error) = mux.close().await {
        log::debug!("WSS mux closed with error: {error}");
    }
}

async fn send_mux_delivery_ack_via_sender(
    sender: &crate::mux::MuxSender,
    receipt: &DeliveryAck,
) -> Result<()> {
    let payload = serde_json::to_vec(receipt)?;
    let mut stream = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        sender.open(crate::mux::StreamKind::Control),
    )
    .await??;
    tokio::time::timeout(ENVELOPE_TIMEOUT, stream.write_all(&payload)).await??;
    tokio::time::timeout(ENVELOPE_TIMEOUT, stream.shutdown()).await??;
    Ok(())
}

async fn send_envelope_secure_with_expectation(
    address: &str,
    envelope: &SyncEnvelope,
    local_identity: &ed25519_dalek::SigningKey,
    hosts: std::sync::Arc<std::sync::Mutex<crate::pinning::KnownHosts>>,
    expected_peer_key: Option<ed25519_dalek::VerifyingKey>,
    trust_policy: NetworkTrustPolicy,
    transport_kind: TransportKind,
    stream_kind: crate::mux::StreamKind,
    metrics: Option<Arc<AbuseMetrics>>,
) -> Result<()> {
    use crate::secure_channel::{handshake_client, PeerExpectation};
    let padded_envelope = PaddedEnvelope::new(envelope);
    let payload = serialize_padded_envelope_bounded(&padded_envelope, metrics.as_deref())?;
    envelope.verify()?;

    // Enforce learned pins by the CLAIMED identity before dialing.
    let expectation = {
        if let Some(expected_peer_key) = expected_peer_key {
            PeerExpectation::Pinned(expected_peer_key)
        } else {
            let Ok(hosts_guard) = hosts.lock() else {
                return Err(anyhow!("known hosts mutex poisoned"));
            };
            match hosts_guard.record_of(&envelope.identity_id) {
                Some(record) => {
                    let bytes: [u8; 32] = hex::decode(&record.public_key_hex)
                        .map_err(|_| anyhow!("corrupt pinned key"))?
                        .try_into()
                        .map_err(|_| anyhow!("corrupt pinned key"))?;
                    let pinned_key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)?;
                    PeerExpectation::Pinned(pinned_key)
                }
                None => {
                    if trust_policy.allows_first_contact(address) {
                        PeerExpectation::RequiresVerification
                    } else {
                        return Err(anyhow!("unknown peer identity rejected"));
                    }
                }
            }
        }
    };

    if transport_kind == TransportKind::TlsMux {
        let addresses = address
            .split([',', ';'])
            .map(str::trim)
            .filter(|candidate| !candidate.is_empty())
            .map(|candidate| candidate.parse::<std::net::SocketAddr>())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| anyhow!("invalid peer address: {error}"))?;
        if addresses.is_empty() {
            return Err(anyhow!("peer address is empty"));
        }
        let stage_started = tokio::time::Instant::now();
        log::info!(target: "HAL_DHT", "TLS: connecting to {address}...");
        let tcp = if addresses.len() == 1 {
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(addresses[0])).await {
                Ok(Ok(tcp)) => tcp,
                Ok(Err(error)) => {
                    log::error!(
                        target: "HAL_DHT",
                        "send_pending_verified: TCP connect FAILED to {address}: {error}"
                    );
                    return Err(anyhow!("TCP connect failed to {address}: {error}"));
                }
                Err(_) => {
                    log::error!(
                        target: "HAL_DHT",
                        "send_pending_verified: TCP connect TIMED OUT to {address}"
                    );
                    return Err(anyhow!("TCP connect timed out to {address}"));
                }
            }
        } else {
            connect_happy_eyeballs(&addresses, HANDSHAKE_TIMEOUT)
                .await
                .map_err(|error| {
                    log::error!(
                        target: "HAL_DHT",
                        "send_pending_verified: TCP connect FAILED for {address}: {error}"
                    );
                    error
                })?
        };
        log::info!(
            target: "HAL_DHT",
            "TLS: TCP connected to {address} ({}ms). Starting handshake...",
            stage_started.elapsed().as_millis()
        );
        let stage_started = tokio::time::Instant::now();
        log::info!(target: "HAL_DHT", "send_pending_verified: TLS handshake START with {address}");
        let tls_result = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            crate::tls_transport::TlsTransport::connect_with_kind_on_stream(
                tcp,
                local_identity,
                expected_peer_key,
                stream_kind,
            ),
        )
        .await;
        let tls = match tls_result {
            Ok(Ok(tls)) => tls,
            Ok(Err(error)) => {
                log::error!(
                    target: "HAL_DHT",
                    "send_pending_verified: TLS handshake FAILED with {address}: {error}"
                );
                return Err(error.into());
            }
            Err(_) => {
                log::error!(
                    target: "HAL_DHT",
                    "send_pending_verified: TLS handshake TIMED OUT with {address}"
                );
                return Err(anyhow!("TLS handshake timed out with {address}"));
            }
        };
        log::info!(
            target: "HAL_DHT",
            "TLS: handshake OK with {address} ({}ms)",
            stage_started.elapsed().as_millis()
        );
        let mut mux = crate::mux::Mux::new(
            tls.into_stream(),
            crate::mux::MuxConfig::default(),
            crate::mux::Mode::Client,
        );
        let stage_started = tokio::time::Instant::now();
        log::info!(target: "HAL_DHT", "send_pending_verified: Mux open START to {address}");
        let mut stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, mux.open(stream_kind)).await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                log::error!(
                    target: "HAL_DHT",
                    "send_pending_verified: Mux open FAILED to {address}: {error}"
                );
                return Err(error.into());
            }
            Err(_) => {
                log::error!(
                    target: "HAL_DHT",
                    "send_pending_verified: Mux open TIMED OUT to {address}"
                );
                return Err(anyhow!("Mux open timed out to {address}"));
            }
        };
        log::info!(
            target: "HAL_DHT",
            "send_pending_verified: Mux open OK to {address} ({}ms)",
            stage_started.elapsed().as_millis()
        );
        let stage_started = tokio::time::Instant::now();
        log::info!(
            target: "HAL_DHT",
            "send_pending_verified: Mux write START to {address}, payload_bytes={}",
            payload.len()
        );
        apply_network_send_timing_jitter().await;
        match tokio::time::timeout(ENVELOPE_TIMEOUT, stream.write_all(&payload)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                log::error!(
                    target: "HAL_DHT",
                    "send_pending_verified: Mux write FAILED to {address}: {error}"
                );
                return Err(error.into());
            }
            Err(_) => {
                log::error!(
                    target: "HAL_DHT",
                    "send_pending_verified: Mux write TIMED OUT to {address}"
                );
                return Err(anyhow!("Mux write timed out to {address}"));
            }
        }
        log::info!(
            target: "HAL_DHT",
            "send_pending_verified: Mux write OK to {address} ({}ms)",
            stage_started.elapsed().as_millis()
        );
        match tokio::time::timeout(ENVELOPE_TIMEOUT, finish_mux_stream(&mut stream)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                log::error!(
                    target: "HAL_DHT",
                    "send_pending_verified: Mux stream finish FAILED to {address}: {error}"
                );
                return Err(error.into());
            }
            Err(_) => {
                log::error!(
                    target: "HAL_DHT",
                    "send_pending_verified: Mux stream finish TIMED OUT to {address}"
                );
                return Err(anyhow!("Mux stream finish timed out to {address}"));
            }
        }
        receive_mux_delivery_ack(&mut mux, envelope).await?;
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, mux.close()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                log::error!(
                    target: "HAL_DHT",
                    "send_pending_verified: Mux close FAILED to {address}: {error}"
                );
                return Err(error.into());
            }
            Err(_) => {
                log::error!(
                    target: "HAL_DHT",
                    "send_pending_verified: Mux close TIMED OUT to {address}"
                );
                return Err(anyhow!("Mux close timed out to {address}"));
            }
        }
        log::info!(target: "HAL_DHT", "send_pending_verified: Mux send OK to {address}");
        log::info!(target: "HAL_DHT", "send_pending_verified: DONE to {address}");
        return Ok(());
    }

    let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(address)).await??;
    let (mut channel, responder_vk) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        handshake_client(stream, local_identity, expectation),
    )
    .await??;
    apply_network_send_timing_jitter().await;
    tokio::time::timeout(ENVELOPE_TIMEOUT, channel.send_json(&padded_envelope)).await??;

    let receipt: DeliveryAck = tokio::time::timeout(ENVELOPE_TIMEOUT, channel.recv_json())
        .await
        .map_err(|_| anyhow!("delivery acknowledgement timed out"))?
        .map_err(|error| anyhow!("delivery acknowledgement failed: {error}"))?;
    validate_delivery_ack(envelope, &receipt)?;
    log_delivery_ack_received(&receipt);

    // Bind what we actually saw (no-op when already pinned identically).
    // The responder key belongs to the remote peer; envelope.public_key belongs
    // to the local sender. They must not be compared. The remote identity/key
    // binding is validated by the receiving listener before pinning. Outbound
    // pinning requires a target identity/public-key from the peer registry,
    // which this legacy address-only API does not carry.
    let _ = responder_vk;
    Ok(())
}

pub(crate) async fn send_envelope_over_mux(
    mux: &mut crate::mux::Mux<crate::tls_transport::TlsConn>,
    envelope: &SyncEnvelope,
    metrics: Option<&AbuseMetrics>,
) -> Result<()> {
    let payload = serialize_envelope_bounded(envelope, metrics)?;
    envelope.verify()?;
    let mut stream =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, mux.open(crate::mux::StreamKind::Sync)).await??;
    apply_network_send_timing_jitter().await;
    tokio::time::timeout(ENVELOPE_TIMEOUT, stream.write_all(&payload)).await??;
    tokio::time::timeout(ENVELOPE_TIMEOUT, finish_mux_stream(&mut stream)).await??;
    receive_mux_delivery_ack(mux, envelope).await?;
    Ok(())
}

async fn send_mux_delivery_ack(
    mux: &crate::mux::Mux<crate::tls_transport::TlsConn>,
    receipt: &DeliveryAck,
) -> Result<()> {
    let payload = serde_json::to_vec(receipt)?;
    let mut stream =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, mux.open(crate::mux::StreamKind::Control))
            .await??;
    tokio::time::timeout(ENVELOPE_TIMEOUT, stream.write_all(&payload)).await??;
    tokio::time::timeout(ENVELOPE_TIMEOUT, stream.shutdown()).await??;
    log_delivery_ack_sent(receipt);
    Ok(())
}

async fn receive_mux_delivery_ack(
    mux: &mut crate::mux::Mux<crate::tls_transport::TlsConn>,
    envelope: &SyncEnvelope,
) -> Result<()> {
    let mut stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, mux.accept())
        .await?
        .ok_or_else(|| anyhow!("mux closed before delivery acknowledgement"))?;
    if stream.kind() != crate::mux::StreamKind::Control {
        return Err(anyhow!(
            "unexpected mux stream {:?} while waiting for delivery acknowledgement",
            stream.kind()
        ));
    }
    let payload =
        tokio::time::timeout(ENVELOPE_TIMEOUT, read_envelope_bounded(&mut stream, None)).await??;
    let receipt: DeliveryAck = serde_json::from_slice(&payload)?;
    validate_delivery_ack(envelope, &receipt)?;
    log_delivery_ack_received(&receipt);
    Ok(())
}

fn validate_delivery_ack(envelope: &SyncEnvelope, receipt: &DeliveryAck) -> Result<()> {
    let expected_event_ids: Vec<_> = envelope
        .events
        .iter()
        .map(|event| event.id.as_str())
        .collect();
    let expected_message_ids: Vec<_> = envelope
        .events
        .iter()
        .filter(|event| event.event_type == crate::journal::SyncEventType::MessageAdded)
        .map(|event| event.id.as_str())
        .collect();
    let received_event_ids: Vec<_> = receipt.event_ids.iter().map(String::as_str).collect();
    let received_message_ids: Vec<_> = receipt.message_ids.iter().map(String::as_str).collect();
    if received_event_ids != expected_event_ids || received_message_ids != expected_message_ids {
        return Err(anyhow!(
            "delivery acknowledgement does not match sent envelope"
        ));
    }
    Ok(())
}

fn delivery_ack_for(envelope: &SyncEnvelope) -> DeliveryAck {
    DeliveryAck {
        event_ids: envelope
            .events
            .iter()
            .map(|event| event.id.clone())
            .collect(),
        message_ids: envelope
            .events
            .iter()
            .filter(|event| event.event_type == crate::journal::SyncEventType::MessageAdded)
            .map(|event| event.id.clone())
            .collect(),
    }
}

#[cfg(test)]
mod delivery_ack_tests {
    use super::*;

    #[test]
    fn delivery_ack_must_match_the_sent_message_ids() {
        let envelope = SyncEnvelope::new(
            "sender".into(),
            "public-key".into(),
            vec![SyncEvent::new(
                "message-1".into(),
                crate::journal::SyncEventType::MessageAdded,
                "{}".into(),
            )],
        );
        let receipt = DeliveryAck {
            event_ids: vec!["message-1".into()],
            message_ids: vec!["different-message".into()],
        };
        assert!(validate_delivery_ack(&envelope, &receipt).is_err());
    }
}

fn log_delivery_ack_sent(receipt: &DeliveryAck) {
    for message_id in &receipt.message_ids {
        log::info!("delivery ack sent for message_id={message_id}");
    }
}

fn log_delivery_ack_received(receipt: &DeliveryAck) {
    for message_id in &receipt.message_ids {
        log::info!("delivery ack received for message_id={message_id}");
    }
}

async fn finish_mux_stream(stream: &mut crate::mux_stream::MuxStream) -> Result<()> {
    stream.shutdown().await?;
    let mut response = [0u8; 1];
    if stream.read(&mut response).await? != 0 {
        return Err(anyhow!("unexpected response on sync stream"));
    }
    Ok(())
}

fn verify_handshake_binding(
    envelope: &SyncEnvelope,
    handshake_key: &ed25519_dalek::VerifyingKey,
) -> Result<()> {
    envelope.verify()?;
    let handshake_key_hex = hex::encode(handshake_key.as_bytes());
    if envelope.public_key != handshake_key_hex {
        return Err(anyhow!("envelope public key does not match handshake key"));
    }
    Ok(())
}

async fn process_peer_envelope(
    envelope: SyncEnvelope,
    client_vk: ed25519_dalek::VerifyingKey,
    remote_address: SocketAddr,
    hosts: &Arc<std::sync::Mutex<crate::pinning::KnownHosts>>,
    trust_policy: &NetworkTrustPolicy,
    degradation: Option<&Arc<crate::degradation::DegradationState>>,
    inbound_observations_tx: Option<&mpsc::Sender<InboundObservation>>,
    incoming: &mpsc::Sender<(SyncEnvelope, EnvelopeMeta)>,
    abuse_metrics: Option<&AbuseMetrics>,
    session_sender: Option<crate::mux::MuxSender>,
) -> Result<DeliveryAck> {
    verify_handshake_binding(&envelope, &client_vk)?;
    let receipt = delivery_ack_for(&envelope);
    let key_hex = hex::encode(client_vk.as_bytes());
    let is_sas_pairing = envelope.events.len() == 1
        && envelope.events[0].event_type == crate::journal::SyncEventType::SasPairing
        && envelope.media_signal.is_none();
    let Ok(mut hosts) = hosts.lock() else {
        return Err(anyhow!("known hosts mutex poisoned"));
    };
    let binding_before_learn = hosts.check(&envelope.identity_id, &key_hex);
    let should_learn_first_contact = match &binding_before_learn {
        crate::pinning::BindingCheck::Trusted => false,
        crate::pinning::BindingCheck::Unknown if is_sas_pairing => false,
        crate::pinning::BindingCheck::Unknown
            if trust_policy.allows_first_contact(&remote_address.to_string()) =>
        {
            if degradation.is_some_and(|state| state.is_active()) {
                return Err(anyhow!("unknown peer identity rejected in degraded mode"));
            }
            true
        }
        crate::pinning::BindingCheck::Unknown => {
            if degradation.is_some_and(|state| state.is_active()) {
                return Err(anyhow!("unknown peer identity rejected in degraded mode"));
            }
            return Err(anyhow!("unknown peer identity rejected"));
        }
        crate::pinning::BindingCheck::Conflicted { pinned_key_hex } => {
            return Err(anyhow!("identity/key conflict: pinned {pinned_key_hex}"));
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Some(sender) = inbound_observations_tx {
        if let Some(peer_address) = inferred_lan_peer_listener_address(remote_address) {
            log::info!(
                target: "HAL_DHT",
                "recording authenticated LAN peer return address {} for {} (TCP source was {})",
                peer_address,
                envelope.identity_id,
                remote_address
            );
            try_send_inbound_observation(
                sender,
                InboundObservation {
                    remote_addr: peer_address,
                    identity_id: envelope.identity_id.clone(),
                    public_key_hex: key_hex.clone(),
                    observed_at: now,
                },
                abuse_metrics,
            );
        }
    }
    let meta = EnvelopeMeta {
        was_cold: matches!(&binding_before_learn, crate::pinning::BindingCheck::Unknown),
        binding_before_learn: binding_before_learn.clone(),
        remote_addr: Some(remote_address),
        transport_peer_identity: Some(envelope.identity_id.clone()),
        session_sender,
    };
    if should_learn_first_contact
        && !hosts.learn_first_contact(&envelope.identity_id, &key_hex, now)
    {
        return Err(anyhow!("host pinning conflict"));
    }
    if envelope.media_signal.is_some() && !trust_policy.allows_media(&remote_address.to_string()) {
        return Err(anyhow!("media signal rejected by network trust policy"));
    }
    drop(hosts);
    incoming
        .try_send((envelope, meta))
        .map_err(|error| anyhow!("sync receiver unavailable: {error}"))?;
    Ok(receipt)
}

pub(crate) async fn send_envelope_over_mux_sender(
    sender: &crate::mux::MuxSender,
    envelope: &SyncEnvelope,
    metrics: Option<&AbuseMetrics>,
) -> Result<()> {
    envelope.verify()?;
    let padded_envelope = PaddedEnvelope::new(envelope);
    let payload = serialize_padded_envelope_bounded(&padded_envelope, metrics)?;
    let mut stream =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, sender.open(crate::mux::StreamKind::Sync))
            .await??;
    tokio::time::timeout(ENVELOPE_TIMEOUT, stream.write_all(&payload)).await??;
    tokio::time::timeout(ENVELOPE_TIMEOUT, finish_mux_stream(&mut stream)).await??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::sync::{Arc, Mutex};

    #[test]
    fn lan_addresses_are_prioritized_candidates() {
        assert!(is_lan_address(
            &"192.168.1.10:4001".parse().expect("IPv4 LAN")
        ));
        assert!(is_lan_address(
            &"10.0.0.10:4001".parse().expect("private IPv4")
        ));
        assert!(is_lan_address(&"[fd00::1]:4001".parse().expect("IPv6 ULA")));
        assert!(!is_lan_address(
            &"188.163.83.204:4001".parse().expect("public IPv4")
        ));
    }

    #[test]
    fn inbound_lan_source_maps_to_fixed_peer_listener_port() {
        let remote: SocketAddr = "192.168.0.105:54321".parse().expect("remote source");
        assert_eq!(
            inferred_lan_peer_listener_address(remote),
            Some("192.168.0.105:4001".parse().expect("listener address"))
        );
        assert_eq!(
            inferred_lan_peer_listener_address("188.163.83.204:54321".parse().expect("WAN source")),
            None
        );
    }

    fn envelope_with_serialized_size(size: usize) -> SyncEnvelope {
        let signing_key = SigningKey::from_bytes(&[241; 32]);
        let verifying_key = signing_key.verifying_key();
        let mut event = SyncEvent::new(
            "size-test-event".into(),
            crate::SyncEventType::MessageAdded,
            String::new(),
        );
        event.sign(&signing_key.to_bytes()).expect("sign event");
        let mut envelope = SyncEnvelope::new(
            crate::dht::NodeId::from_public_key(&verifying_key).to_hex(),
            hex::encode(verifying_key.to_bytes()),
            vec![event],
        );
        let base_size = serde_json::to_vec(&envelope)
            .expect("serialize envelope")
            .len();
        assert!(size >= base_size);
        envelope.events[0].data = "x".repeat(size - base_size);
        envelope.events[0]
            .sign(&signing_key.to_bytes())
            .expect("resign event");
        envelope
    }

    async fn read_bytes_with_limit(
        bytes: Vec<u8>,
        metrics: Option<&AbuseMetrics>,
    ) -> Result<Vec<u8>> {
        let (mut writer, reader) = tokio::io::duplex(32 * 1024);
        let writer_task = tokio::spawn(async move { writer.write_all(&bytes).await });
        let result = read_envelope_bounded(reader, metrics).await;
        writer_task.await??;
        result
    }

    #[tokio::test]
    async fn envelope_size_read_accepts_under_limit() {
        let result = read_bytes_with_limit(vec![7; 1024], None)
            .await
            .expect("under-limit payload");
        assert_eq!(result.len(), 1024);
    }

    #[tokio::test]
    async fn envelope_size_read_accepts_at_limit() {
        let result = read_bytes_with_limit(vec![7; MAX_ENVELOPE_BYTES], None)
            .await
            .expect("at-limit payload");
        assert_eq!(result.len(), MAX_ENVELOPE_BYTES);
    }

    #[tokio::test]
    async fn envelope_size_read_rejects_oversized() {
        let metrics = AbuseMetrics::new();
        let result = read_bytes_with_limit(vec![7; MAX_ENVELOPE_BYTES + 1], Some(&metrics)).await;
        assert!(result.is_err());
        assert_eq!(metrics.snapshot().envelope_size_exceeded_total, 1);
    }

    #[test]
    fn envelope_size_send_accepts_under_limit() {
        let envelope = envelope_with_serialized_size(1024);
        assert!(
            serialize_envelope_bounded(&envelope, None)
                .expect("bounded serialization")
                .len()
                <= MAX_ENVELOPE_BYTES
        );
    }

    #[test]
    fn envelope_size_send_accepts_near_limit_with_padding() {
        let envelope = envelope_with_serialized_size(MAX_ENVELOPE_BYTES - 2048);
        assert!(
            serialize_envelope_bounded(&envelope, None)
                .expect("near-limit serialization")
                .len()
                <= MAX_ENVELOPE_BYTES
        );
    }

    #[test]
    fn envelope_size_send_rejects_oversized() {
        let envelope = envelope_with_serialized_size(MAX_ENVELOPE_BYTES + 1);
        let metrics = AbuseMetrics::new();
        assert!(serialize_envelope_bounded(&envelope, Some(&metrics)).is_err());
        assert_eq!(metrics.snapshot().envelope_send_size_exceeded_total, 1);
    }

    #[test]
    fn identical_envelopes_have_variable_padded_sizes_and_deserialize_cleanly() {
        let envelope = envelope_with_serialized_size(1024);
        let mut sizes = std::collections::HashSet::new();

        for _ in 0..16 {
            let bytes =
                serialize_envelope_bounded(&envelope, None).expect("serialize padded envelope");
            let value: serde_json::Value =
                serde_json::from_slice(&bytes).expect("parse padded envelope");
            let padding = value["padding"]
                .as_array()
                .expect("padding field is an array");
            assert!(padding.len() <= 256);
            sizes.insert(bytes.len());

            let decoded: SyncEnvelope =
                serde_json::from_slice(&bytes).expect("deserialize padded envelope");
            assert_eq!(decoded.identity_id, envelope.identity_id);
            assert_eq!(decoded.public_key, envelope.public_key);
        }

        assert!(
            sizes.len() > 1,
            "padding should vary serialized envelope size"
        );
    }

    #[tokio::test]
    async fn timing_jitter_is_bounded_when_enabled() {
        let start = tokio::time::Instant::now();
        apply_timing_jitter(150).await;
        let elapsed = start.elapsed();

        assert!(elapsed >= std::time::Duration::from_millis(150));
        assert!(elapsed <= std::time::Duration::from_millis(MAX_TIMING_JITTER_MS + 100));
    }

    async fn send_test_envelope(address: String, key: SigningKey) -> Result<()> {
        use crate::secure_channel::{handshake_client, PeerExpectation};
        let stream = TcpStream::connect(address).await?;
        let (mut channel, _) =
            handshake_client(stream, &key, PeerExpectation::RequiresVerification).await?;
        let public_key = hex::encode(key.verifying_key().to_bytes());
        let envelope = SyncEnvelope::new(identity_for(&key), public_key, Vec::new());
        channel.send_json(&envelope).await
    }

    async fn receive_test_envelope(
        incoming: &mut mpsc::Receiver<(SyncEnvelope, EnvelopeMeta)>,
    ) -> SyncEnvelope {
        receive_test_envelope_with_meta(incoming).await.0
    }

    async fn receive_test_envelope_with_meta(
        incoming: &mut mpsc::Receiver<(SyncEnvelope, EnvelopeMeta)>,
    ) -> (SyncEnvelope, EnvelopeMeta) {
        tokio::time::timeout(std::time::Duration::from_secs(2), incoming.recv())
            .await
            .expect("incoming envelope timeout")
            .expect("incoming channel closed")
    }

    fn identity_for(key: &SigningKey) -> String {
        let mut hash = Sha256::new();
        hash.update(key.verifying_key().to_bytes());
        hex::encode(hash.finalize())
    }

    #[tokio::test]
    async fn channel_carries_meta_with_envelope() {
        let server_key = SigningKey::from_bytes(&[173; 32]);
        let sender_key = SigningKey::from_bytes(&[174; 32]);
        let sender_public_key = hex::encode(sender_key.verifying_key().to_bytes());
        let sender_identity = identity_for(&sender_key);
        let hosts = Arc::new(Mutex::new(crate::pinning::KnownHosts::new()));
        let hosts_for_assertion = Arc::clone(&hosts);
        let (transport, mut incoming) = PeerTransport::bind_secure_on_demand(
            "127.0.0.1:0",
            server_key,
            hosts,
            NetworkTrustPolicy::default(),
        )
        .await
        .expect("bind transport");

        send_test_envelope(transport.local_address.clone(), sender_key)
            .await
            .expect("send envelope");
        let (envelope, meta) = receive_test_envelope_with_meta(&mut incoming).await;
        assert_eq!(envelope.identity_id, sender_identity);
        assert_eq!(
            meta.binding_before_learn,
            crate::pinning::BindingCheck::Unknown
        );
        assert!(meta.was_cold);
        assert!(meta.remote_addr.is_some());
        assert!(hosts_for_assertion
            .lock()
            .expect("hosts lock")
            .record_of(&envelope.identity_id)
            .is_some());
        assert_eq!(envelope.public_key, sender_public_key);
        transport.stop().await.expect("stop transport");
    }

    #[tokio::test]
    async fn happy_eyeballs_prefers_ipv6() {
        let ipv6_listener = TcpListener::bind("[::1]:0").await.expect("IPv6 listener");
        let ipv6_address = ipv6_listener.local_addr().expect("IPv6 address");
        let ipv4_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("IPv4 listener");
        let ipv4_address = ipv4_listener.local_addr().expect("IPv4 address");
        let ipv6_task = tokio::spawn(async move {
            let (mut stream, _) = ipv6_listener.accept().await.expect("IPv6 accept");
            stream.write_all(b"ipv6").await.expect("IPv6 marker");
        });
        let ipv4_task = tokio::spawn(async move {
            let (mut stream, _) = ipv4_listener.accept().await.expect("IPv4 accept");
            stream.write_all(b"ipv4").await.expect("IPv4 marker");
        });

        let mut stream =
            connect_happy_eyeballs(&[ipv6_address, ipv4_address], Duration::from_secs(2))
                .await
                .expect("connect");
        let mut marker = [0u8; 4];
        stream.read_exact(&mut marker).await.expect("read marker");
        assert_eq!(&marker, b"ipv6");
        ipv6_task.await.expect("IPv6 task");
        ipv4_task.abort();
    }

    #[tokio::test]
    async fn happy_eyeballs_falls_back_to_ipv4() {
        let ipv4_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("IPv4 listener");
        let ipv4_address = ipv4_listener.local_addr().expect("IPv4 address");
        let ipv6_address: SocketAddr = "[2001:db8::1]:4242".parse().expect("IPv6 address");
        let ipv4_task = tokio::spawn(async move {
            let (mut stream, _) = ipv4_listener.accept().await.expect("IPv4 accept");
            stream.write_all(b"ipv4").await.expect("IPv4 marker");
        });

        let mut stream =
            connect_happy_eyeballs(&[ipv6_address, ipv4_address], Duration::from_secs(2))
                .await
                .expect("IPv4 fallback");
        let mut marker = [0u8; 4];
        stream.read_exact(&mut marker).await.expect("read marker");
        assert_eq!(&marker, b"ipv4");
        ipv4_task.await.expect("IPv4 task");
    }

    #[tokio::test]
    async fn happy_eyeballs_tries_remaining_addresses_after_refusal() {
        let refused_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("refused-address listener");
        let refused_address = refused_listener.local_addr().expect("refused address");
        drop(refused_listener);

        let fallback_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fallback listener");
        let fallback_address = fallback_listener.local_addr().expect("fallback address");
        let fallback_task = tokio::spawn(async move {
            let (mut stream, _) = fallback_listener.accept().await.expect("fallback accept");
            stream
                .write_all(b"fallback")
                .await
                .expect("fallback marker");
        });

        let mut stream =
            connect_happy_eyeballs(&[refused_address, fallback_address], Duration::from_secs(2))
                .await
                .expect("connect to next address after refusal");
        let mut marker = [0u8; 8];
        stream.read_exact(&mut marker).await.expect("read marker");
        assert_eq!(&marker, b"fallback");
        fallback_task.await.expect("fallback task");
    }

    #[tokio::test]
    async fn happy_eyeballs_all_fail() {
        let ipv4_address: SocketAddr = "192.0.2.1:1".parse().expect("TEST-NET address");
        let ipv6_address: SocketAddr = "[2001:db8::1]:4242".parse().expect("IPv6 address");
        assert!(
            connect_happy_eyeballs(&[ipv6_address, ipv4_address], Duration::from_millis(500))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn bind_secure_on_demand_accepts_multiple_sequential() {
        let server_key = SigningKey::from_bytes(&[30; 32]);
        let hosts = Arc::new(Mutex::new(crate::pinning::KnownHosts::new()));
        let policy = NetworkTrustPolicy::default();
        let (transport, mut incoming) =
            PeerTransport::bind_secure_on_demand("127.0.0.1:0", server_key, hosts, policy)
                .await
                .expect("bind listener");
        let address = transport.local_address.clone();

        for seed in 31..34 {
            send_test_envelope(address.clone(), SigningKey::from_bytes(&[seed; 32]))
                .await
                .expect("send envelope");
            receive_test_envelope(&mut incoming).await;
        }
        transport.stop().await.expect("stop listener");
    }

    #[tokio::test]
    async fn bind_secure_on_demand_accepts_multiple_concurrent() {
        let server_key = SigningKey::from_bytes(&[40; 32]);
        let hosts = Arc::new(Mutex::new(crate::pinning::KnownHosts::new()));
        let (transport, mut incoming) = PeerTransport::bind_secure_on_demand(
            "127.0.0.1:0",
            server_key,
            hosts,
            NetworkTrustPolicy::default(),
        )
        .await
        .expect("bind listener");
        let address = transport.local_address.clone();
        let mut tasks = Vec::new();
        for seed in 41..46 {
            let address = address.clone();
            tasks.push(tokio::spawn(async move {
                send_test_envelope(address, SigningKey::from_bytes(&[seed; 32])).await
            }));
        }
        for task in tasks {
            task.await.expect("sender task").expect("send envelope");
        }
        for _ in 0..5 {
            receive_test_envelope(&mut incoming).await;
        }
        transport.stop().await.expect("stop listener");
    }

    #[tokio::test]
    async fn bind_secure_on_demand_stop_terminates_loop() {
        let server_key = SigningKey::from_bytes(&[50; 32]);
        let hosts = Arc::new(Mutex::new(crate::pinning::KnownHosts::new()));
        let (transport, incoming) = PeerTransport::bind_secure_on_demand(
            "127.0.0.1:0",
            server_key,
            hosts,
            NetworkTrustPolicy::default(),
        )
        .await
        .expect("bind listener");
        let address = transport.local_address.clone();
        drop(incoming);
        transport.stop().await.expect("stop listener");
        assert!(TcpStream::connect(address).await.is_err());
    }

    #[tokio::test]
    async fn bind_secure_on_demand_unknown_peer_rejected() {
        let server_key = SigningKey::from_bytes(&[60; 32]);
        let hosts = Arc::new(Mutex::new(crate::pinning::KnownHosts::new()));
        let policy = NetworkTrustPolicy {
            local_level: 0,
            external_level: 0,
        };
        let (transport, mut incoming) =
            PeerTransport::bind_secure_on_demand("127.0.0.1:0", server_key, hosts, policy)
                .await
                .expect("bind listener");
        send_test_envelope(
            transport.local_address.clone(),
            SigningKey::from_bytes(&[61; 32]),
        )
        .await
        .expect("handshake and send");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), incoming.recv(),)
                .await
                .is_err()
        );
        transport.stop().await.expect("stop listener");
    }

    #[tokio::test]
    async fn bind_secure_on_demand_pinning_enforced() {
        let server_key = SigningKey::from_bytes(&[70; 32]);
        let hosts = Arc::new(Mutex::new(crate::pinning::KnownHosts::new()));
        let (transport, mut incoming) = PeerTransport::bind_secure_on_demand(
            "127.0.0.1:0",
            server_key,
            Arc::clone(&hosts),
            NetworkTrustPolicy::default(),
        )
        .await
        .expect("bind listener");
        let address = transport.local_address.clone();
        let peer_a = SigningKey::from_bytes(&[71; 32]);
        send_test_envelope(address.clone(), peer_a.clone())
            .await
            .expect("first send");
        receive_test_envelope(&mut incoming).await;
        assert!(matches!(
            hosts.lock().expect("known hosts mutex not poisoned").check(
                &identity_for(&peer_a),
                &hex::encode(peer_a.verifying_key().to_bytes()),
            ),
            crate::pinning::BindingCheck::Trusted
        ));

        let peer_b = SigningKey::from_bytes(&[72; 32]);
        use crate::secure_channel::{handshake_client, PeerExpectation};
        let stream = TcpStream::connect(address)
            .await
            .expect("connect second peer");
        let (mut channel, _) =
            handshake_client(stream, &peer_b, PeerExpectation::RequiresVerification)
                .await
                .expect("second handshake");
        let conflicting = SyncEnvelope::new(
            identity_for(&peer_a),
            hex::encode(peer_b.verifying_key().to_bytes()),
            Vec::new(),
        );
        channel
            .send_json(&conflicting)
            .await
            .expect("send conflicting envelope");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), incoming.recv(),)
                .await
                .is_err()
        );
        transport.stop().await.expect("stop listener");
    }

    #[tokio::test]
    async fn send_envelope_secure_uses_known_pin() {
        let server_key = SigningKey::from_bytes(&[91; 32]);
        let client_key = SigningKey::from_bytes(&[92; 32]);
        let client_identity = identity_for(&client_key);
        let client_hosts = Arc::new(Mutex::new(crate::pinning::KnownHosts::new()));
        {
            let Ok(mut client_hosts_guard) = client_hosts.lock() else {
                panic!("known hosts mutex poisoned");
            };
            client_hosts_guard
                .pin_manual(
                    &client_identity,
                    &hex::encode(server_key.verifying_key().to_bytes()),
                    1,
                )
                .expect("pin server key");
        }
        let (transport, mut incoming) = PeerTransport::bind_secure_on_demand(
            "127.0.0.1:0",
            server_key,
            Arc::new(Mutex::new(crate::pinning::KnownHosts::new())),
            NetworkTrustPolicy::default(),
        )
        .await
        .expect("bind listener");
        let envelope = SyncEnvelope::new(
            client_identity,
            hex::encode(client_key.verifying_key().to_bytes()),
            Vec::new(),
        );
        send_envelope_secure(
            &transport.local_address,
            &envelope,
            &client_key,
            client_hosts,
            NetworkTrustPolicy::default(),
        )
        .await
        .expect("send with known pin");
        assert_eq!(
            receive_test_envelope(&mut incoming).await.identity_id,
            envelope.identity_id
        );
        transport.stop().await.expect("stop listener");
    }

    #[tokio::test]
    async fn tcp_candidates_reject_foreign_identity_then_use_fallback() {
        let client_key = SigningKey::from_bytes(&[201; 32]);
        let foreign_key = SigningKey::from_bytes(&[202; 32]);
        let expected_key = SigningKey::from_bytes(&[203; 32]);
        let client_identity = identity_for(&client_key);
        let client_public_key = hex::encode(client_key.verifying_key().to_bytes());

        let (foreign, _foreign_incoming) = PeerTransport::bind_secure_on_demand_with_kind(
            "127.0.0.1:0",
            foreign_key,
            Arc::new(Mutex::new(crate::pinning::KnownHosts::new())),
            NetworkTrustPolicy::default(),
            TransportKind::TlsMux,
            None,
            None,
        )
        .await
        .expect("bind foreign identity endpoint");
        let (expected, mut expected_incoming) = PeerTransport::bind_secure_on_demand_with_kind(
            "127.0.0.1:0",
            expected_key.clone(),
            Arc::new(Mutex::new(crate::pinning::KnownHosts::new())),
            NetworkTrustPolicy::default(),
            TransportKind::TlsMux,
            None,
            None,
        )
        .await
        .expect("bind expected identity endpoint");

        let envelope = SyncEnvelope::new(client_identity, client_public_key, Vec::new());
        let candidates = vec![
            foreign.local_address.clone(),
            expected.local_address.clone(),
        ];
        let connected = send_envelope_secure_with_tcp_candidates(
            &candidates,
            &envelope,
            &client_key,
            Arc::new(Mutex::new(crate::pinning::KnownHosts::new())),
            expected_key.verifying_key(),
            NetworkTrustPolicy::default(),
            Arc::new(AbuseMetrics::default()),
        )
        .await
        .expect("fallback candidate with expected identity succeeds");

        assert_eq!(connected, expected.local_address);
        assert_eq!(
            receive_test_envelope(&mut expected_incoming)
                .await
                .identity_id,
            envelope.identity_id
        );
        foreign.stop().await.expect("stop foreign listener");
        expected.stop().await.expect("stop expected listener");
    }

    #[tokio::test]
    async fn send_envelope_secure_rejects_unknown_when_policy_denies() {
        let key = SigningKey::from_bytes(&[93; 32]);
        let (transport, _incoming) = PeerTransport::bind_secure_on_demand(
            "127.0.0.1:0",
            SigningKey::from_bytes(&[94; 32]),
            Arc::new(Mutex::new(crate::pinning::KnownHosts::new())),
            NetworkTrustPolicy::default(),
        )
        .await
        .expect("bind listener");
        let envelope = SyncEnvelope::new(
            identity_for(&key),
            hex::encode(key.verifying_key().to_bytes()),
            Vec::new(),
        );
        let error = send_envelope_secure(
            &transport.local_address,
            &envelope,
            &key,
            Arc::new(Mutex::new(crate::pinning::KnownHosts::new())),
            NetworkTrustPolicy {
                local_level: 0,
                external_level: 0,
            },
        )
        .await
        .expect_err("unknown peer must be rejected");
        assert!(error.to_string().contains("unknown peer identity rejected"));
        transport.stop().await.expect("stop listener");
    }

    #[tokio::test]
    async fn send_envelope_secure_tofu_when_policy_allows() {
        let client_key = SigningKey::from_bytes(&[95; 32]);
        let (transport, mut incoming) = PeerTransport::bind_secure_on_demand(
            "127.0.0.1:0",
            SigningKey::from_bytes(&[96; 32]),
            Arc::new(Mutex::new(crate::pinning::KnownHosts::new())),
            NetworkTrustPolicy::default(),
        )
        .await
        .expect("bind listener");
        let envelope = SyncEnvelope::new(
            identity_for(&client_key),
            hex::encode(client_key.verifying_key().to_bytes()),
            Vec::new(),
        );
        send_envelope_secure(
            &transport.local_address,
            &envelope,
            &client_key,
            Arc::new(Mutex::new(crate::pinning::KnownHosts::new())),
            NetworkTrustPolicy::default(),
        )
        .await
        .expect("TOFU send");
        assert_eq!(
            receive_test_envelope(&mut incoming).await.identity_id,
            envelope.identity_id
        );
        transport.stop().await.expect("stop listener");
    }

    #[tokio::test]
    async fn send_envelope_secure_unknown_pin_conflict() {
        let server_key = SigningKey::from_bytes(&[97; 32]);
        let client_key = SigningKey::from_bytes(&[98; 32]);
        let client_identity = identity_for(&client_key);
        let mut server_hosts = crate::pinning::KnownHosts::new();
        server_hosts
            .pin_manual(
                &client_identity,
                &hex::encode(server_key.verifying_key().to_bytes()),
                1,
            )
            .expect("pin conflicting key");
        let mut client_hosts = crate::pinning::KnownHosts::new();
        client_hosts
            .pin_manual(
                &client_identity,
                &hex::encode(server_key.verifying_key().to_bytes()),
                1,
            )
            .expect("pin server key");
        let (transport, mut incoming) = PeerTransport::bind_secure_on_demand(
            "127.0.0.1:0",
            server_key,
            Arc::new(Mutex::new(server_hosts)),
            NetworkTrustPolicy::default(),
        )
        .await
        .expect("bind listener");
        let envelope = SyncEnvelope::new(
            client_identity,
            hex::encode(client_key.verifying_key().to_bytes()),
            Vec::new(),
        );
        let result = send_envelope_secure(
            &transport.local_address,
            &envelope,
            &client_key,
            Arc::new(Mutex::new(client_hosts)),
            NetworkTrustPolicy::default(),
        )
        .await;
        assert!(
            result.as_ref().is_err_and(|error| error
                .to_string()
                .contains("delivery acknowledgement failed")),
            "receiver pin conflict must not be reported as delivered: {result:?}"
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), incoming.recv(),)
                .await
                .is_err()
        );
        transport.stop().await.expect("stop listener");
    }

    #[tokio::test]
    async fn send_recv_via_tls_mux_roundtrip() {
        let server_key = SigningKey::from_bytes(&[80; 32]);
        let client_key = SigningKey::from_bytes(&[81; 32]);
        let hosts = Arc::new(Mutex::new(crate::pinning::KnownHosts::new()));
        let (transport, mut incoming) = PeerTransport::bind_secure_on_demand_with_kind(
            "127.0.0.1:0",
            server_key.clone(),
            hosts,
            NetworkTrustPolicy::default(),
            TransportKind::TlsMux,
            None,
            None,
        )
        .await
        .expect("bind TLS mux listener");
        let envelope = SyncEnvelope::new(
            identity_for(&client_key),
            hex::encode(client_key.verifying_key().to_bytes()),
            Vec::new(),
        );
        send_envelope_secure_with_kind(
            &transport.local_address,
            &envelope,
            &client_key,
            Arc::new(Mutex::new(crate::pinning::KnownHosts::new())),
            server_key.verifying_key(),
            NetworkTrustPolicy::default(),
            TransportKind::TlsMux,
        )
        .await
        .expect("send TLS mux envelope");
        let received = receive_test_envelope(&mut incoming).await;
        assert_eq!(received.identity_id, envelope.identity_id);
        transport.stop().await.expect("stop TLS mux listener");
    }

    #[tokio::test]
    async fn bind_secure_tls_mux_accepts_multiple() {
        let server_key = SigningKey::from_bytes(&[82; 32]);
        let hosts = Arc::new(Mutex::new(crate::pinning::KnownHosts::new()));
        let (transport, mut incoming) = PeerTransport::bind_secure_on_demand_with_kind(
            "127.0.0.1:0",
            server_key.clone(),
            hosts,
            NetworkTrustPolicy::default(),
            TransportKind::TlsMux,
            None,
            None,
        )
        .await
        .expect("bind TLS mux listener");
        for seed in 83..86 {
            let client_key = SigningKey::from_bytes(&[seed; 32]);
            let envelope = SyncEnvelope::new(
                identity_for(&client_key),
                hex::encode(client_key.verifying_key().to_bytes()),
                Vec::new(),
            );
            send_envelope_secure_with_kind(
                &transport.local_address,
                &envelope,
                &client_key,
                Arc::new(Mutex::new(crate::pinning::KnownHosts::new())),
                server_key.verifying_key(),
                NetworkTrustPolicy::default(),
                TransportKind::TlsMux,
            )
            .await
            .expect("send TLS mux envelope");
            receive_test_envelope(&mut incoming).await;
        }
        transport.stop().await.expect("stop TLS mux listener");
    }

    #[tokio::test]
    async fn finishing_large_mux_stream_waits_for_peer_close_ack() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let client = crate::mux::Mux::new(
            client_io,
            crate::mux::MuxConfig::default(),
            crate::mux::Mode::Client,
        );
        let mut server = crate::mux::Mux::new(
            server_io,
            crate::mux::MuxConfig::default(),
            crate::mux::Mode::Server,
        );
        let mut outgoing = client
            .open(crate::mux::StreamKind::Sync)
            .await
            .expect("open client stream");
        let mut incoming = server.accept().await.expect("accept server stream");
        let payload = vec![0x5a; 128 * 1024];
        let expected_payload = payload.clone();
        let receiver = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let mut received = Vec::new();
            incoming
                .read_to_end(&mut received)
                .await
                .expect("read complete payload");
            received
        });

        outgoing
            .write_all(&payload)
            .await
            .expect("write complete payload");
        finish_mux_stream(&mut outgoing)
            .await
            .expect("wait for peer close acknowledgement");
        client.close().await.expect("close client mux");

        assert_eq!(receiver.await.expect("receiver task"), expected_payload);
        server.close().await.expect("close server mux");
    }

    #[tokio::test]
    async fn mitm_still_rejected_via_tls_mux() {
        let server_key = SigningKey::from_bytes(&[86; 32]);
        let wrong_key = SigningKey::from_bytes(&[87; 32]);
        let client_key = SigningKey::from_bytes(&[88; 32]);
        let hosts = Arc::new(Mutex::new(crate::pinning::KnownHosts::new()));
        let (transport, mut incoming) = PeerTransport::bind_secure_on_demand_with_kind(
            "127.0.0.1:0",
            server_key,
            hosts,
            NetworkTrustPolicy::default(),
            TransportKind::TlsMux,
            None,
            None,
        )
        .await
        .expect("bind TLS mux listener");
        let envelope = SyncEnvelope::new(
            identity_for(&client_key),
            hex::encode(client_key.verifying_key().to_bytes()),
            Vec::new(),
        );
        assert!(send_envelope_secure_with_kind(
            &transport.local_address,
            &envelope,
            &client_key,
            Arc::new(Mutex::new(crate::pinning::KnownHosts::new())),
            wrong_key.verifying_key(),
            NetworkTrustPolicy::default(),
            TransportKind::TlsMux,
        )
        .await
        .is_err());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), incoming.recv(),)
                .await
                .is_err()
        );
        transport.stop().await.expect("stop TLS mux listener");
    }

    #[tokio::test]
    async fn fallback_to_tcp_when_configured() {
        let server_key = SigningKey::from_bytes(&[89; 32]);
        let client_key = SigningKey::from_bytes(&[90; 32]);
        let (transport, mut incoming) = PeerTransport::bind_secure_on_demand(
            "127.0.0.1:0",
            server_key.clone(),
            Arc::new(Mutex::new(crate::pinning::KnownHosts::new())),
            NetworkTrustPolicy::default(),
        )
        .await
        .expect("bind TCP listener");
        let envelope = SyncEnvelope::new(
            identity_for(&client_key),
            hex::encode(client_key.verifying_key().to_bytes()),
            Vec::new(),
        );
        send_envelope_secure_with_kind(
            &transport.local_address,
            &envelope,
            &client_key,
            Arc::new(Mutex::new(crate::pinning::KnownHosts::new())),
            server_key.verifying_key(),
            NetworkTrustPolicy::default(),
            TransportKind::Tcp,
        )
        .await
        .expect("send TCP envelope");
        receive_test_envelope(&mut incoming).await;
        transport.stop().await.expect("stop TCP listener");
    }

    #[test]
    fn envelope_verifies_signed_events() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let public_key = hex::encode(key.verifying_key().to_bytes());
        let mut event = SyncEvent::new(
            "event".into(),
            crate::SyncEventType::MessageAdded,
            "payload".into(),
        );
        event.sign(&key.to_bytes()).expect("sign event");
        let envelope = SyncEnvelope::new(identity_for(&key), public_key, vec![event]);
        assert!(envelope.verify().is_ok());
    }

    #[test]
    fn envelope_rejects_unsigned_events() {
        let key = SigningKey::from_bytes(&[4; 32]);
        let envelope = SyncEnvelope::new(
            identity_for(&key),
            hex::encode(key.verifying_key().to_bytes()),
            vec![SyncEvent::new(
                "event".into(),
                crate::SyncEventType::MessageAdded,
                "payload".into(),
            )],
        );
        assert!(envelope.verify().is_err());
    }

    #[test]
    fn envelope_key_must_match_handshake_key() {
        let envelope_key = SigningKey::from_bytes(&[5; 32]);
        let handshake_key = SigningKey::from_bytes(&[6; 32]);
        let envelope = SyncEnvelope::new(
            identity_for(&envelope_key),
            hex::encode(envelope_key.verifying_key().to_bytes()),
            Vec::new(),
        );
        assert!(verify_handshake_binding(&envelope, &handshake_key.verifying_key()).is_err());
        assert!(verify_handshake_binding(&envelope, &envelope_key.verifying_key()).is_ok());
    }

    #[test]
    fn integrity_gated_envelope_rejects_missing_response_and_accepts_approved_response() {
        let authority = SigningKey::from_bytes(&[21; 32]);
        let node = SigningKey::from_bytes(&[22; 32]);
        let authority_public_key = hex::encode(authority.verifying_key().to_bytes());
        let node_public_key = hex::encode(node.verifying_key().to_bytes());
        let mut wave = IntegrityWave::new(
            "wave-transport".into(),
            3,
            100,
            200,
            "approved-build".into(),
            authority_public_key,
        );
        wave.sign(&authority.to_bytes());

        let mut event = SyncEvent::new(
            "event".into(),
            crate::SyncEventType::MessageAdded,
            "payload".into(),
        );
        event.sign(&node.to_bytes()).expect("sign event");
        let identity = {
            let mut hash = sha2::Sha256::new();
            use sha2::Digest;
            hash.update(node.verifying_key().to_bytes());
            hex::encode(hash.finalize())
        };
        let envelope = SyncEnvelope::new(identity.clone(), node_public_key.clone(), vec![event]);
        assert!(envelope.verify_with_integrity(&wave, 150).is_err());

        let mut response =
            IntegrityResponse::new(&wave, node_public_key, "approved-build".into(), 150)
                .expect("response");
        response.sign(&node.to_bytes());
        let gated = envelope.with_integrity_response(response);
        assert!(gated.verify_with_integrity(&wave, 150).is_ok());
    }

    #[test]
    fn quic_probe_config_defaults() {
        let config = QuicProbeConfig::default();
        assert!(config.enabled);
        assert_eq!(config.strategy, ProbeStrategy::Hybrid);
        assert_eq!(config.background_interval, Duration::from_secs(15 * 60));
        assert_eq!(config.max_probe_targets, 10);
        assert_eq!(config.probe_timeout, Duration::from_secs(5));
    }

    #[test]
    fn probe_strategy_variants() {
        assert_ne!(ProbeStrategy::Lazy, ProbeStrategy::Background);
        assert_ne!(ProbeStrategy::Background, ProbeStrategy::Hybrid);
        assert_ne!(ProbeStrategy::Lazy, ProbeStrategy::Hybrid);
    }

    #[test]
    fn quic_probe_config_custom() {
        let config = QuicProbeConfig {
            enabled: false,
            strategy: ProbeStrategy::Lazy,
            background_interval: Duration::from_secs(3 * 60),
            ..QuicProbeConfig::default()
        };
        assert!(!config.enabled);
        assert_eq!(config.strategy, ProbeStrategy::Lazy);
        assert_eq!(config.background_interval, Duration::from_secs(3 * 60));
    }

    #[test]
    fn peer_transport_has_quic_false_by_default() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("create test runtime");
        let (transport, _incoming) = runtime
            .block_on(PeerTransport::idle())
            .expect("create idle transport");
        assert!(!transport.has_quic());
        assert!(transport.quic_channel().is_none());
    }

    #[test]
    fn send_envelope_quic_serializes_envelope() {
        let envelope = SyncEnvelope::new("identity".into(), "public-key".into(), Vec::new());
        let bytes = serialize_envelope_for_quic(&envelope, None).expect("serialize envelope");
        let decoded: SyncEnvelope = serde_json::from_slice(&bytes).expect("deserialize envelope");
        assert_eq!(decoded.identity_id, envelope.identity_id);
        assert_eq!(decoded.public_key, envelope.public_key);
    }

    #[test]
    fn quic_probe_config_hybrid_is_default() {
        assert_eq!(QuicProbeConfig::default().strategy, ProbeStrategy::Hybrid);
    }

    #[test]
    fn quic_probe_config_lazy_strategy() {
        let config = QuicProbeConfig {
            strategy: ProbeStrategy::Lazy,
            ..QuicProbeConfig::default()
        };
        assert_eq!(config.strategy, ProbeStrategy::Lazy);
    }

    #[test]
    fn quic_envelope_serialization_roundtrip() {
        let envelope = SyncEnvelope::new("roundtrip-id".into(), "roundtrip-key".into(), Vec::new());
        let encoded = serde_json::to_vec(&envelope).expect("serialize envelope");
        let decoded: SyncEnvelope = serde_json::from_slice(&encoded).expect("deserialize envelope");
        assert_eq!(decoded.identity_id, envelope.identity_id);
        assert_eq!(decoded.public_key, envelope.public_key);
        assert_eq!(decoded.events.len(), envelope.events.len());
    }

    #[test]
    fn quic_probe_config_strategy_variants() {
        assert_ne!(ProbeStrategy::Lazy, ProbeStrategy::Background);
        assert_ne!(ProbeStrategy::Background, ProbeStrategy::Hybrid);
        assert_ne!(ProbeStrategy::Hybrid, ProbeStrategy::Lazy);
    }

    #[test]
    fn quic_probe_config_serializable_for_ui() {
        let config = QuicProbeConfig::default();
        assert!(config.enabled);
        assert_eq!(config.strategy, ProbeStrategy::Hybrid);
        assert_eq!(config.background_interval, Duration::from_secs(15 * 60));
        assert!(!config.only_while_charging);
        assert!(!config.only_on_wifi);
        assert_eq!(config.max_probe_targets, 10);
        assert_eq!(config.probe_timeout, Duration::from_secs(5));
    }
}
