use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::future::join_all;
use hal_discovery::{DiscoveryProvider, PublicDhtProvider};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::time::timeout;

use super::node_id::NodeId;
use super::peer_info::PeerInfo;
use super::routing::{BucketInsertResult, RoutingTable};
use super::transport::DhtTransport;
use super::wire::{DhtError, DhtRequest, DhtRequestPayload, DhtResponsePayload};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeedNode {
    pub node_id: NodeId,
    pub public_key: String,
    pub address: String,
}

impl SeedNode {
    pub fn verify(&self) -> Result<(), DhtError> {
        let public_key = hex::decode(&self.public_key).map_err(|_| DhtError::InvalidSignature)?;
        if public_key.len() != 32 {
            return Err(DhtError::InvalidSignature);
        }
        let mut hasher = Sha256::new();
        hasher.update(&public_key);
        if NodeId::from_bytes(hasher.finalize().into()) != self.node_id {
            return Err(DhtError::InvalidSignature);
        }
        ed25519_dalek::VerifyingKey::from_bytes(
            &public_key
                .try_into()
                .map_err(|_| DhtError::InvalidSignature)?,
        )
        .map_err(|_| DhtError::InvalidSignature)?;
        Ok(())
    }

    pub fn to_peer_info(&self, now: u64) -> PeerInfo {
        let mut peer = PeerInfo::new(self.node_id, self.public_key.clone());
        peer.add_endpoint(self.address.clone(), now);
        peer
    }
}

/// Источник DNS-seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsSeedSource {
    /// DNS дал только IP — identity неизвестна (placeholder NodeId).
    /// Используется только как gateway к другим peers.
    Placeholder,
    /// DNS TXT с signed identity (задел, пока не реализован).
    Txt,
}

/// DNS-seed: адрес без identity. Placeholder NodeId.
///
/// TODO(БЕЗОПАСНОСТЬ): placeholder NodeId — временное решение. DNS даёт
/// только IP, не identity. Риски: MITM, Sybil, routing pollution.
/// Решение: TXT-запись DNS с signed identity + pubkey, DNSSEC или fallback
/// на статический список seed'ов перед пре-альфой.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSeed {
    pub address: SocketAddr,
    pub source: DnsSeedSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapNode {
    pub address: String,
    pub last_seen: u64,
    pub score: u32,
    pub uptime_secs: u64,
}

impl BootstrapNode {
    pub fn new(address: String, now: u64) -> Self {
        Self {
            address,
            last_seen: now,
            score: 1,
            uptime_secs: 0,
        }
    }
}

pub fn bootstrap_cache_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".hal").join("bootstrap_nodes.json"))
}

pub fn load_bootstrap_nodes() -> Vec<BootstrapNode> {
    let Some(path) = bootstrap_cache_path() else {
        return Vec::new();
    };
    read_bootstrap_nodes(&path).unwrap_or_default()
}

pub fn read_bootstrap_nodes(path: &Path) -> Result<Vec<BootstrapNode>, std::io::Error> {
    let bytes = std::fs::read(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

pub fn save_bootstrap_nodes(nodes: &[BootstrapNode]) -> std::io::Result<()> {
    let Some(path) = bootstrap_cache_path() else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut nodes = nodes.to_vec();
    nodes.sort_by(|left, right| right.score.cmp(&left.score));
    nodes.truncate(20);
    let bytes = serde_json::to_vec_pretty(&nodes).map_err(std::io::Error::other)?;
    std::fs::write(path, bytes)
}

pub fn record_bootstrap_peer_exchange(peers: &[PeerInfo], now: u64) -> usize {
    let mut nodes = load_bootstrap_nodes();
    let mut received = 0;
    for peer in peers {
        for endpoint in &peer.endpoints {
            if nodes.iter().any(|node| node.address == endpoint.address) {
                continue;
            }
            if endpoint.address.parse::<SocketAddr>().is_ok() {
                nodes.push(BootstrapNode::new(endpoint.address.clone(), now));
                received += 1;
            }
        }
    }
    if received > 0 {
        if let Err(error) = save_bootstrap_nodes(&nodes) {
            log::warn!("DHT Bootstrap: failed to save peer exchange nodes: {error}");
        }
        log::info!("DHT Bootstrap: received {received} new bootstrap nodes from peer");
    }
    received
}

const PUBLIC_HAL_DHT_TOPIC: &str = "hal.network.bootstrap.v1";

pub async fn announce_public_hal_node(port: u16) -> Result<(), anyhow::Error> {
    if port == 0 {
        return Err(anyhow::anyhow!("cannot announce peer on port 0"));
    }
    PublicDhtProvider::new(PUBLIC_HAL_DHT_TOPIC)
        .announce(port)
        .await?;
    log::info!("DHT Bootstrap: announced HAL node on public DHT");
    Ok(())
}

pub async fn discover_public_hal_peers() -> Vec<std::net::SocketAddrV4> {
    let peers = match PublicDhtProvider::new(PUBLIC_HAL_DHT_TOPIC)
        .with_timeout(Duration::from_secs(15))
        .discover()
        .await
    {
        Ok(peers) => peers,
        Err(error) => {
            log::warn!("DHT Bootstrap: public peer discovery failed: {error:#}");
            return Vec::new();
        }
    };
    let peers = peers
        .into_iter()
        .filter_map(|peer| match peer {
            std::net::SocketAddr::V4(address) => Some(address),
            std::net::SocketAddr::V6(_) => None,
        })
        .collect::<Vec<_>>();
    log::info!(
        "DHT Bootstrap: found {} HAL peers on public DHT",
        peers.len()
    );
    peers
}

impl DnsSeed {
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            source: DnsSeedSource::Placeholder,
        }
    }

    pub fn with_source(address: SocketAddr, source: DnsSeedSource) -> Self {
        Self { address, source }
    }

    /// Placeholder NodeId. Используется ТОЛЬКО для контактирования
    /// DNS-seed по address. НЕ вставлять в routing.
    pub fn placeholder_node_id() -> NodeId {
        NodeId::from_bytes([0; 32])
    }

    /// Временный PeerInfo для контактирования DNS-seed по address.
    /// НЕ использовать для insert в routing — identity неизвестна.
    pub fn to_peer_info(&self, now: u64) -> PeerInfo {
        let mut peer = PeerInfo::new(Self::placeholder_node_id(), String::new());
        peer.add_endpoint(self.address.to_string(), now);
        peer
    }
}

#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    pub seeds: Vec<SeedNode>,
    /// DNS-адреса с временной placeholder identity.
    pub dns_addresses: Vec<DnsSeed>,
    /// Статические DHT endpoint'ы, заданные IP:port (offline/LAN).
    pub static_addresses: Vec<DnsSeed>,
    pub ping_timeout: Duration,
    pub find_node_timeout: Duration,
    pub refresh_interval_active: Duration,
    pub refresh_interval_normal: Duration,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            seeds: Vec::new(),
            dns_addresses: Vec::new(),
            static_addresses: Vec::new(),
            ping_timeout: Duration::from_secs(5),
            find_node_timeout: Duration::from_secs(5),
            refresh_interval_active: Duration::from_secs(10 * 60),
            refresh_interval_normal: Duration::from_secs(30 * 60),
        }
    }
}

impl BootstrapConfig {
    pub fn with_static_addresses(addresses: Vec<SocketAddr>) -> Self {
        Self {
            static_addresses: addresses.into_iter().map(DnsSeed::new).collect(),
            ..Self::default()
        }
    }

    /// Создать config из DNS-seed'ов и существующих статических seeds.
    ///
    /// TODO(БЕЗОПАСНОСТЬ): DNS-адреса не содержат identity и используют
    /// placeholder. См. DnsSeed.
    pub async fn from_dns_resolver(
        dns: &crate::dht::dns_seed::DnsSeedResolver,
        existing_seeds: Vec<SeedNode>,
    ) -> Result<Self, crate::dht::dns_seed::DnsSeedError> {
        let dns_addresses = dns.resolve().await?.into_iter().map(DnsSeed::new).collect();
        let cached_addresses = load_bootstrap_nodes()
            .into_iter()
            .filter_map(|node| node.address.parse::<SocketAddr>().ok())
            .map(DnsSeed::new)
            .collect();

        Ok(Self {
            seeds: existing_seeds,
            dns_addresses,
            static_addresses: cached_addresses,
            ..Self::default()
        })
    }
}

#[derive(Debug, Clone)]
pub struct BootstrapReport {
    pub seeds_contacted: usize,
    pub seeds_responded: usize,
    pub peers_discovered: usize,
    pub peers_inserted: usize,
    pub failures: Vec<(NodeId, String)>,
}

impl BootstrapReport {
    pub fn is_success(&self) -> bool {
        self.seeds_responded > 0
    }
}

pub struct Bootstrapper<'a> {
    local_id: NodeId,
    config: BootstrapConfig,
    transport: &'a dyn DhtTransport,
    routing: &'a mut RoutingTable,
}

impl<'a> Bootstrapper<'a> {
    pub fn new(
        local_id: NodeId,
        config: BootstrapConfig,
        transport: &'a dyn DhtTransport,
        routing: &'a mut RoutingTable,
    ) -> Self {
        Self {
            local_id,
            config,
            transport,
            routing,
        }
    }

    pub async fn bootstrap_once(&mut self) -> Result<BootstrapReport, DhtError> {
        let now = unix_now();
        let seeds = self.config.seeds.clone();
        if seeds.is_empty()
            && self.config.dns_addresses.is_empty()
            && self.config.static_addresses.is_empty()
        {
            return Ok(BootstrapReport {
                seeds_contacted: 0,
                seeds_responded: 0,
                peers_discovered: 0,
                peers_inserted: 0,
                failures: Vec::new(),
            });
        }

        let ping_timeout = self.config.ping_timeout;
        let local_id = self.local_id;
        let transport = self.transport;
        let ping_results = join_all(seeds.iter().map(|seed| async move {
            let peer = seed.to_peer_info(now);
            let request = DhtRequest::new(DhtRequestPayload::Ping, local_id, now);
            let request_id = request.request_id;
            let result = timeout(ping_timeout, transport.send_request(&peer, request)).await;
            (seed.clone(), result, request_id)
        }))
        .await;

        let mut failures = Vec::new();
        let mut responded = Vec::new();
        for (seed, result, request_id) in ping_results {
            match result {
                Ok(Ok(response)) => match response.validate(&request_id, unix_now()) {
                    Ok(()) if matches!(response.payload, DhtResponsePayload::Pong) => {
                        log::info!(
                            target: "HAL_DHT",
                            "DHT bootstrap seed {} ({}) answered PING",
                            seed.node_id.to_hex(),
                            seed.address
                        );
                        responded.push(seed)
                    }
                    Ok(()) => {
                        let error = "seed did not return PONG".to_string();
                        log::warn!(
                            target: "HAL_DHT",
                            "DHT bootstrap seed {} ({}) failed: {error}",
                            seed.node_id.to_hex(),
                            seed.address
                        );
                        failures.push((seed.node_id, error));
                    }
                    Err(error) => {
                        log::warn!(
                            target: "HAL_DHT",
                            "DHT bootstrap seed {} ({}) returned an invalid PING response: {error}",
                            seed.node_id.to_hex(),
                            seed.address
                        );
                        failures.push((seed.node_id, error.to_string()));
                    }
                },
                Ok(Err(error)) => {
                    log::warn!(
                        target: "HAL_DHT",
                        "DHT bootstrap seed {} ({}) failed PING: {error}",
                        seed.node_id.to_hex(),
                        seed.address
                    );
                    failures.push((seed.node_id, error.to_string()));
                }
                Err(_) => {
                    log::warn!(
                        target: "HAL_DHT",
                        "DHT bootstrap seed {} ({}) timed out after {ping_timeout:?}",
                        seed.node_id.to_hex(),
                        seed.address
                    );
                    failures.push((seed.node_id, "ping timeout".into()));
                }
            }
        }

        let mut inserted = 0;
        for seed in &responded {
            if seed.verify().is_err() {
                failures.push((seed.node_id, "invalid seed identity".into()));
                continue;
            }
            if matches!(
                self.routing.insert(seed.to_peer_info(now), now),
                BucketInsertResult::Inserted
            ) {
                inserted += 1;
            }
        }

        let find_timeout = self.config.find_node_timeout;
        let transport = self.transport;
        let find_results = join_all(responded.iter().map(|seed| async move {
            let peer = seed.to_peer_info(now);
            let request = DhtRequest::new(
                DhtRequestPayload::FindNode { target: local_id },
                local_id,
                now,
            );
            let request_id = request.request_id;
            let result = timeout(find_timeout, transport.send_request(&peer, request)).await;
            (seed.node_id, seed.address.clone(), result, request_id)
        }))
        .await;

        let mut discovered = 0;
        for (seed_id, seed_address, result, request_id) in find_results {
            let response = match result {
                Ok(Ok(response)) => response,
                Ok(Err(error)) => {
                    log::warn!(
                        target: "HAL_DHT",
                        "DHT bootstrap seed {} ({seed_address}) failed FIND_NODE: {error}",
                        seed_id.to_hex()
                    );
                    failures.push((seed_id, error.to_string()));
                    continue;
                }
                Err(_) => {
                    log::warn!(
                        target: "HAL_DHT",
                        "DHT bootstrap seed {} ({seed_address}) timed out during FIND_NODE after {find_timeout:?}",
                        seed_id.to_hex()
                    );
                    failures.push((seed_id, "find_node timeout".into()));
                    continue;
                }
            };
            if let Err(error) = response.validate(&request_id, unix_now()) {
                log::warn!(
                    target: "HAL_DHT",
                    "DHT bootstrap seed {} ({seed_address}) returned an invalid FIND_NODE response: {error}",
                    seed_id.to_hex()
                );
                failures.push((seed_id, error.to_string()));
                continue;
            }
            let DhtResponsePayload::Nodes { peers, .. } = response.payload else {
                log::warn!(
                    target: "HAL_DHT",
                    "DHT bootstrap seed {} ({seed_address}) did not return Nodes",
                    seed_id.to_hex()
                );
                failures.push((seed_id, "seed did not return Nodes".into()));
                continue;
            };
            log::info!(
                target: "HAL_DHT",
                "DHT bootstrap seed {} ({seed_address}) answered FIND_NODE with {} peer(s)",
                seed_id.to_hex(),
                peers.len()
            );
            discovered += peers.len();
            for peer in peers {
                if peer.node_id == self.local_id || !valid_peer_identity(&peer) {
                    continue;
                }
                record_bootstrap_peer_exchange(std::slice::from_ref(&peer), now);
                if matches!(self.routing.insert(peer, now), BucketInsertResult::Inserted) {
                    inserted += 1;
                }
            }
        }

        // DNS seeds: gateway-функция. Контактируем по address, но НЕ
        // вставляем в routing (identity неизвестна). Из ответа берём
        // только Nodes и валидируем identity перед вставкой.
        let dns_addresses: Vec<DnsSeed> = self
            .config
            .dns_addresses
            .iter()
            .chain(self.config.static_addresses.iter())
            .cloned()
            .collect();
        let dns_results = join_all(dns_addresses.iter().map(|dns_seed| async move {
            let peer = dns_seed.to_peer_info(now);
            let request = DhtRequest::new(
                DhtRequestPayload::FindNode { target: local_id },
                local_id,
                now,
            );
            let request_id = request.request_id;
            let result = timeout(find_timeout, transport.send_request(&peer, request)).await;
            (dns_seed.address, result, request_id)
        }))
        .await;

        let mut dns_responded = 0;
        for (dns_addr, result, request_id) in dns_results {
            let response = match result {
                Ok(Ok(response)) => response,
                Ok(Err(error)) => {
                    let error = format!("DNS seed {dns_addr} failed: {error}");
                    log::warn!(target: "HAL_DHT", "{error}");
                    failures.push((DnsSeed::placeholder_node_id(), error));
                    continue;
                }
                Err(_) => {
                    let error = format!("DNS seed {dns_addr} timed out after {find_timeout:?}");
                    log::warn!(target: "HAL_DHT", "{error}");
                    failures.push((DnsSeed::placeholder_node_id(), error));
                    continue;
                }
            };
            if let Err(error) = response.validate(&request_id, unix_now()) {
                let error = format!("DNS seed {dns_addr} returned an invalid response: {error}");
                log::warn!(target: "HAL_DHT", "{error}");
                failures.push((DnsSeed::placeholder_node_id(), error));
                continue;
            }
            let DhtResponsePayload::Nodes { peers, .. } = response.payload else {
                let error = format!("DNS seed {dns_addr} did not return Nodes");
                log::warn!(target: "HAL_DHT", "{error}");
                failures.push((DnsSeed::placeholder_node_id(), error));
                continue;
            };
            dns_responded += 1;
            discovered += peers.len();
            log::info!(
                target: "HAL_DHT",
                "DHT bootstrap seed {dns_addr} answered FIND_NODE with {} peer(s)",
                peers.len()
            );
            if peers.is_empty() {
                log::warn!(
                    target: "HAL_DHT",
                    "DNS seed {dns_addr} returned an empty Nodes response"
                );
            }
            for peer in peers {
                if peer.node_id == self.local_id || !valid_peer_identity(&peer) {
                    continue;
                }
                record_bootstrap_peer_exchange(std::slice::from_ref(&peer), now);
                if matches!(self.routing.insert(peer, now), BucketInsertResult::Inserted) {
                    inserted += 1;
                }
            }
        }

        Ok(BootstrapReport {
            seeds_contacted: seeds.len() + dns_addresses.len(),
            seeds_responded: responded.len() + dns_responded,
            peers_discovered: discovered,
            peers_inserted: inserted,
            failures,
        })
    }
}

fn valid_peer_identity(peer: &PeerInfo) -> bool {
    let Ok(public_key) = hex::decode(&peer.public_key) else {
        return false;
    };
    if public_key.len() != 32 {
        return false;
    }
    let mut hasher = Sha256::new();
    hasher.update(&public_key);
    NodeId::from_bytes(hasher.finalize().into()) == peer.node_id
        && ed25519_dalek::VerifyingKey::from_bytes(&public_key.try_into().unwrap_or([0; 32]))
            .is_ok()
}

pub struct RefreshScheduler {
    last_refresh: Option<u64>,
    interval: Duration,
    active_interval: Duration,
    normal_interval: Duration,
}

impl RefreshScheduler {
    pub fn new(interval: Duration) -> Self {
        Self {
            last_refresh: None,
            interval,
            active_interval: interval,
            normal_interval: interval,
        }
    }

    pub fn with_intervals(active_interval: Duration, normal_interval: Duration) -> Self {
        Self {
            last_refresh: None,
            interval: normal_interval,
            active_interval,
            normal_interval,
        }
    }

    pub fn set_interval(&mut self, interval: Duration) {
        self.interval = interval;
    }

    pub fn should_refresh(&self, now: u64) -> bool {
        self.last_refresh.map_or(true, |last| {
            now.saturating_sub(last) >= self.interval.as_secs()
        })
    }

    pub fn mark_refreshed(&mut self, now: u64) {
        self.last_refresh = Some(now);
    }

    pub fn next_refresh_at(&self) -> Option<u64> {
        self.last_refresh
            .map(|last| last.saturating_add(self.interval.as_secs()))
    }

    pub fn adapt_to_context(&mut self, charging: bool, wifi: bool) {
        self.set_interval(if charging && wifi {
            self.active_interval
        } else {
            self.normal_interval
        });
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::super::wire::DhtResponse;
    use super::*;
    use async_trait::async_trait;
    use ed25519_dalek::SigningKey;
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};
    use tokio::time::sleep;

    #[derive(Clone, Default)]
    struct MockTransport {
        responses: Arc<Mutex<HashMap<NodeId, Vec<DhtResponse>>>>,
        failures: Arc<Mutex<HashSet<NodeId>>>,
        delays: Arc<Mutex<HashMap<NodeId, Duration>>>,
    }

    #[async_trait]
    impl DhtTransport for MockTransport {
        async fn send_request(
            &self,
            peer: &PeerInfo,
            request: DhtRequest,
        ) -> Result<DhtResponse, DhtError> {
            let delay = self
                .delays
                .lock()
                .expect("delays")
                .get(&peer.node_id)
                .copied();
            if let Some(delay) = delay {
                sleep(delay).await;
            }
            if self
                .failures
                .lock()
                .expect("failures")
                .contains(&peer.node_id)
            {
                return Err(DhtError::Internal("mock failure".into()));
            }
            let response = self
                .responses
                .lock()
                .expect("responses")
                .get_mut(&peer.node_id)
                .and_then(|queue| {
                    if queue.is_empty() {
                        None
                    } else {
                        Some(queue.remove(0))
                    }
                })
                .ok_or_else(|| DhtError::Internal("no mock response".into()))?;
            let mut response = response;
            response.request_id = request.request_id;
            response.timestamp = unix_now();
            Ok(response)
        }
    }

    fn seed(value: u8, address: &str) -> SeedNode {
        let key = SigningKey::from_bytes(&[value; 32]);
        let public_key = hex::encode(key.verifying_key().to_bytes());
        let mut hasher = Sha256::new();
        hasher.update(key.verifying_key().to_bytes());
        SeedNode {
            node_id: NodeId::from_bytes(hasher.finalize().into()),
            public_key,
            address: address.into(),
        }
    }

    fn peer(value: u8, address: &str) -> PeerInfo {
        let seed = seed(value, address);
        seed.to_peer_info(unix_now())
    }

    fn response(payload: DhtResponsePayload) -> DhtResponse {
        DhtResponse {
            version: 1,
            request_id: [0; 16],
            responder_node_id: NodeId::from_bytes([8; 32]),
            timestamp: unix_now(),
            payload,
        }
    }

    fn config(seeds: Vec<SeedNode>) -> BootstrapConfig {
        BootstrapConfig {
            seeds,
            ping_timeout: Duration::from_millis(30),
            find_node_timeout: Duration::from_millis(30),
            ..BootstrapConfig::default()
        }
    }

    #[test]
    fn seed_node_verify_ok() {
        assert!(seed(1, "127.0.0.1:1").verify().is_ok());
    }

    #[test]
    fn seed_node_verify_rejects_bad_id() {
        let mut value = seed(2, "127.0.0.1:2");
        value.node_id = NodeId::from_bytes([0; 32]);
        assert!(value.verify().is_err());
    }

    #[tokio::test]
    async fn bootstrap_empty_seeds() {
        let transport = MockTransport::default();
        let local = NodeId::from_bytes([0; 32]);
        let mut routing = RoutingTable::new(local);
        let mut bootstrapper = Bootstrapper::new(local, config(vec![]), &transport, &mut routing);
        let report = bootstrapper.bootstrap_once().await.expect("bootstrap");
        assert_eq!(report.seeds_contacted, 0);
        assert!(!report.is_success());
    }

    #[tokio::test]
    async fn bootstrap_single_seed_success() {
        let seed_node = seed(3, "127.0.0.1:3");
        let transport = MockTransport::default();
        transport.responses.lock().unwrap().insert(
            seed_node.node_id,
            vec![
                response(DhtResponsePayload::Pong),
                response(DhtResponsePayload::Nodes {
                    peers: vec![],
                    truncated: false,
                }),
            ],
        );
        let local = NodeId::from_bytes([0; 32]);
        let mut routing = RoutingTable::new(local);
        let mut bootstrapper =
            Bootstrapper::new(local, config(vec![seed_node]), &transport, &mut routing);
        let report = bootstrapper.bootstrap_once().await.expect("bootstrap");
        assert_eq!(report.seeds_responded, 1);
        assert!(report.is_success());
    }

    #[tokio::test]
    async fn bootstrap_single_seed_timeout() {
        let seed_node = seed(4, "127.0.0.1:4");
        let transport = MockTransport::default();
        transport
            .delays
            .lock()
            .unwrap()
            .insert(seed_node.node_id, Duration::from_millis(100));
        let local = NodeId::from_bytes([0; 32]);
        let mut routing = RoutingTable::new(local);
        let mut bootstrapper =
            Bootstrapper::new(local, config(vec![seed_node]), &transport, &mut routing);
        let report = bootstrapper.bootstrap_once().await.expect("bootstrap");
        assert_eq!(report.seeds_responded, 0);
        assert_eq!(report.failures.len(), 1);
    }

    #[tokio::test]
    async fn bootstrap_multiple_seeds_partial() {
        let first = seed(5, "127.0.0.1:5");
        let second = seed(6, "127.0.0.1:6");
        let transport = MockTransport::default();
        transport.responses.lock().unwrap().insert(
            first.node_id,
            vec![
                response(DhtResponsePayload::Pong),
                response(DhtResponsePayload::Nodes {
                    peers: vec![],
                    truncated: false,
                }),
            ],
        );
        transport.failures.lock().unwrap().insert(second.node_id);
        let local = NodeId::from_bytes([0; 32]);
        let mut routing = RoutingTable::new(local);
        let mut bootstrapper =
            Bootstrapper::new(local, config(vec![first, second]), &transport, &mut routing);
        let report = bootstrapper.bootstrap_once().await.expect("bootstrap");
        assert_eq!(report.seeds_contacted, 2);
        assert_eq!(report.seeds_responded, 1);
        assert_eq!(report.failures.len(), 1);
    }

    #[tokio::test]
    async fn bootstrap_all_seeds_fail() {
        let first = seed(7, "127.0.0.1:7");
        let second = seed(8, "127.0.0.1:8");
        let transport = MockTransport::default();
        transport
            .failures
            .lock()
            .unwrap()
            .extend([first.node_id, second.node_id]);
        let local = NodeId::from_bytes([0; 32]);
        let mut routing = RoutingTable::new(local);
        let mut bootstrapper =
            Bootstrapper::new(local, config(vec![first, second]), &transport, &mut routing);
        let report = bootstrapper.bootstrap_once().await.expect("bootstrap");
        assert!(!report.is_success());
        assert_eq!(report.failures.len(), 2);
    }

    #[tokio::test]
    async fn bootstrap_inserts_discovered_peers() {
        let seed_node = seed(9, "127.0.0.1:9");
        let discovered = peer(10, "127.0.0.1:10");
        let transport = MockTransport::default();
        transport.responses.lock().unwrap().insert(
            seed_node.node_id,
            vec![
                response(DhtResponsePayload::Pong),
                response(DhtResponsePayload::Nodes {
                    peers: vec![discovered.clone()],
                    truncated: false,
                }),
            ],
        );
        let local = NodeId::from_bytes([0; 32]);
        let mut routing = RoutingTable::new(local);
        let mut bootstrapper =
            Bootstrapper::new(local, config(vec![seed_node]), &transport, &mut routing);
        let report = bootstrapper.bootstrap_once().await.expect("bootstrap");
        assert_eq!(report.peers_discovered, 1);
        assert!(routing.contains(&discovered.node_id));
    }

    #[tokio::test]
    async fn bootstrap_skips_invalid_peers() {
        let seed_node = seed(11, "127.0.0.1:11");
        let mut invalid = peer(12, "127.0.0.1:12");
        invalid.public_key = "00".into();
        let transport = MockTransport::default();
        transport.responses.lock().unwrap().insert(
            seed_node.node_id,
            vec![
                response(DhtResponsePayload::Pong),
                response(DhtResponsePayload::Nodes {
                    peers: vec![invalid],
                    truncated: false,
                }),
            ],
        );
        let local = NodeId::from_bytes([0; 32]);
        let mut routing = RoutingTable::new(local);
        let mut bootstrapper =
            Bootstrapper::new(local, config(vec![seed_node]), &transport, &mut routing);
        let report = bootstrapper.bootstrap_once().await.expect("bootstrap");
        assert_eq!(report.peers_discovered, 1);
        assert_eq!(report.peers_inserted, 1);
        assert_eq!(routing.len(), 1);
    }

    #[tokio::test]
    async fn bootstrap_report_accuracy() {
        let seed_node = seed(13, "127.0.0.1:13");
        let discovered = peer(14, "127.0.0.1:14");
        let transport = MockTransport::default();
        transport.responses.lock().unwrap().insert(
            seed_node.node_id,
            vec![
                response(DhtResponsePayload::Pong),
                response(DhtResponsePayload::Nodes {
                    peers: vec![discovered],
                    truncated: false,
                }),
            ],
        );
        let local = NodeId::from_bytes([0; 32]);
        let mut routing = RoutingTable::new(local);
        let mut bootstrapper =
            Bootstrapper::new(local, config(vec![seed_node]), &transport, &mut routing);
        let report = bootstrapper.bootstrap_once().await.expect("bootstrap");
        assert_eq!(
            (
                report.seeds_contacted,
                report.seeds_responded,
                report.peers_discovered
            ),
            (1, 1, 1)
        );
    }

    #[test]
    fn refresh_scheduler_initially_due() {
        let scheduler = RefreshScheduler::new(Duration::from_secs(60));
        assert!(scheduler.should_refresh(0));
        assert_eq!(scheduler.next_refresh_at(), None);
    }

    #[test]
    fn refresh_scheduler_waits_interval() {
        let mut scheduler = RefreshScheduler::new(Duration::from_secs(60));
        scheduler.mark_refreshed(100);
        assert!(!scheduler.should_refresh(159));
        assert!(scheduler.should_refresh(160));
    }

    #[test]
    fn refresh_scheduler_mark_resets() {
        let mut scheduler = RefreshScheduler::new(Duration::from_secs(60));
        scheduler.mark_refreshed(100);
        assert_eq!(scheduler.next_refresh_at(), Some(160));
        scheduler.mark_refreshed(200);
        assert_eq!(scheduler.next_refresh_at(), Some(260));
    }

    #[test]
    fn refresh_scheduler_adapts_to_charging() {
        let mut scheduler =
            RefreshScheduler::with_intervals(Duration::from_secs(10), Duration::from_secs(30));
        scheduler.adapt_to_context(true, true);
        scheduler.mark_refreshed(100);
        assert_eq!(scheduler.next_refresh_at(), Some(110));
    }

    #[test]
    fn refresh_scheduler_adapts_to_normal() {
        let mut scheduler =
            RefreshScheduler::with_intervals(Duration::from_secs(10), Duration::from_secs(30));
        scheduler.adapt_to_context(false, true);
        scheduler.mark_refreshed(100);
        assert_eq!(scheduler.next_refresh_at(), Some(130));
    }

    #[test]
    fn dns_seed_placeholder_node_id_is_zero() {
        assert_eq!(DnsSeed::placeholder_node_id(), NodeId::from_bytes([0; 32]));
    }

    #[test]
    fn dns_seed_source_default_is_placeholder() {
        let address = "127.0.0.1:9000".parse().unwrap();
        assert_eq!(DnsSeed::new(address).source, DnsSeedSource::Placeholder);
    }

    #[test]
    fn dns_seed_with_source_txt() {
        let address = "127.0.0.1:9000".parse().unwrap();
        assert_eq!(
            DnsSeed::with_source(address, DnsSeedSource::Txt).source,
            DnsSeedSource::Txt
        );
    }

    #[test]
    fn placeholder_node_id_not_inserted_in_routing() {
        let address = "127.0.0.1:9000".parse().unwrap();
        let placeholder_peer = DnsSeed::new(address).to_peer_info(100);
        assert!(!valid_peer_identity(&placeholder_peer));
    }

    #[test]
    fn dns_seed_to_peer_info_has_address() {
        let address = "127.0.0.1:9000".parse().unwrap();
        let peer = DnsSeed::new(address).to_peer_info(100);
        assert_eq!(peer.node_id, NodeId::from_bytes([0; 32]));
        assert_eq!(peer.endpoints[0].address, "127.0.0.1:9000");
        assert_eq!(peer.endpoints[0].last_seen, 100);
    }

    #[test]
    fn bootstrap_config_from_dns_resolver_works() {
        let resolver =
            crate::dht::dns_seed::DnsSeedResolver::new(crate::dht::dns_seed::DnsSeedConfig {
                hosts: vec!["localhost:9000".to_string()],
                timeout: Duration::from_secs(1),
            });
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let config = runtime
            .block_on(BootstrapConfig::from_dns_resolver(&resolver, Vec::new()))
            .expect("DNS config");
        assert!(!config.dns_addresses.is_empty());
    }

    #[test]
    fn bootstrap_config_from_dns_resolver_empty_fails() {
        let resolver =
            crate::dht::dns_seed::DnsSeedResolver::new(crate::dht::dns_seed::DnsSeedConfig {
                hosts: Vec::new(),
                timeout: Duration::from_secs(1),
            });
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(BootstrapConfig::from_dns_resolver(&resolver, Vec::new()));
        assert!(matches!(
            result,
            Err(crate::dht::dns_seed::DnsSeedError::NoHosts)
        ));
    }
}
