use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use tokio::sync::{oneshot, Mutex};
use tokio::time::interval;

use crate::abuse_metrics::AbuseMetrics;
use crate::dht::endpoint::{EndpointCache, EndpointRecord, EndpointStore, ENDPOINT_TTL_SECONDS};
use crate::dht::mux_transport::MuxDhtTransport;
use crate::dht::routing::RoutingTable;
use crate::dht::NodeId;
use crate::pinning::KnownHosts;
use crate::proof_of_live::ProofOfLive;
use crate::stun::{PublicEndpoint, StunClient, StunConfig, StunError};
use crate::trust_graph::{TrustGateDecision, TrustGraph};
use hal_settings::NetworkTrustPolicy;

pub(crate) fn retain_routable_endpoints(endpoints: &mut Vec<String>) {
    endpoints.retain(|endpoint| {
        let address = endpoint.strip_prefix("udp://").unwrap_or(endpoint);
        match address.parse::<SocketAddr>() {
            Ok(address) if address.ip().is_loopback() || address.ip().is_unspecified() => {
                log::warn!("DHT announce skipped local-only endpoint {endpoint}");
                false
            }
            _ => true,
        }
    });
    endpoints.sort();
    endpoints.dedup();
}

pub const ADDRESS_REFRESH_DEFAULT_INTERVAL: Duration = Duration::from_secs(15 * 60);
pub const ADDRESS_REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct AddressRefreshConfig {
    pub stun: StunConfig,
    pub interval: Duration,
}

impl Default for AddressRefreshConfig {
    fn default() -> Self {
        Self {
            stun: StunConfig::default(),
            interval: ADDRESS_REFRESH_DEFAULT_INTERVAL,
        }
    }
}

pub struct AddressRefresh {
    config: AddressRefreshConfig,
    stun: StunClient,
}

impl AddressRefresh {
    pub fn new(config: AddressRefreshConfig) -> Self {
        let stun = StunClient::new(config.stun.clone());
        Self { config, stun }
    }

    pub fn with_defaults() -> Self {
        Self::new(AddressRefreshConfig::default())
    }

    pub fn config(&self) -> &AddressRefreshConfig {
        &self.config
    }
}

#[derive(Debug, Clone)]
pub enum RefreshOutcome {
    Discovered { endpoint: PublicEndpoint },
    ReusedPrevious { endpoint: PublicEndpoint },
    Failed { error: AddressRefreshError },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressRefreshError {
    Stun(StunError),
    NoPreviousEndpoint,
    PublishFailed(String),
    IdentityMismatch,
}

impl fmt::Display for AddressRefreshError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stun(error) => write!(formatter, "STUN discovery failed: {error}"),
            Self::NoPreviousEndpoint => write!(formatter, "no previous endpoint available"),
            Self::PublishFailed(error) => write!(formatter, "endpoint publication failed: {error}"),
            Self::IdentityMismatch => write!(formatter, "endpoint identity does not match key"),
        }
    }
}

impl std::error::Error for AddressRefreshError {}

impl From<StunError> for AddressRefreshError {
    fn from(error: StunError) -> Self {
        Self::Stun(error)
    }
}

pub async fn discover_endpoint(
    refresh: &AddressRefresh,
    _identity_id: &str,
    _signing_key: &SigningKey,
    previous: Option<PublicEndpoint>,
    _now: u64,
) -> RefreshOutcome {
    let endpoint = match refresh.stun.discover().await {
        Ok(endpoint) => endpoint,
        Err(error) => {
            return previous.map_or(
                RefreshOutcome::Failed {
                    error: AddressRefreshError::Stun(error),
                },
                |endpoint| RefreshOutcome::ReusedPrevious { endpoint },
            );
        }
    };

    RefreshOutcome::Discovered { endpoint }
}

pub struct AddressRefreshTask {
    refresh: Arc<AddressRefresh>,
    identity_id: String,
    public_key: String,
    private_key: SigningKey,
    local_id: NodeId,
    proof_of_live: Option<Arc<ProofOfLive>>,
    routing: Arc<Mutex<RoutingTable>>,
    cache: Arc<Mutex<EndpointCache>>,
    hosts: Arc<std::sync::Mutex<KnownHosts>>,
    trust_policy: NetworkTrustPolicy,
    transport_addresses: Vec<String>,
    public_tcp_port: Option<u16>,
    public_endpoint: Option<Arc<std::sync::RwLock<Option<SocketAddr>>>>,
    public_udp_endpoint: Arc<std::sync::RwLock<Option<SocketAddr>>>,
    trust_graph: Option<Arc<TrustGraph>>,
    abuse_metrics: Option<Arc<AbuseMetrics>>,
}

impl AddressRefreshTask {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        refresh: Arc<AddressRefresh>,
        identity_id: String,
        public_key: String,
        private_key: SigningKey,
        local_id: NodeId,
        proof_of_live: Option<Arc<ProofOfLive>>,
        routing: Arc<Mutex<RoutingTable>>,
        cache: Arc<Mutex<EndpointCache>>,
        hosts: Arc<std::sync::Mutex<KnownHosts>>,
        trust_policy: NetworkTrustPolicy,
        transport_addresses: Vec<String>,
    ) -> Self {
        Self {
            refresh,
            identity_id,
            public_key,
            private_key,
            local_id,
            proof_of_live,
            routing,
            cache,
            hosts,
            trust_policy,
            transport_addresses,
            public_tcp_port: None,
            public_endpoint: None,
            public_udp_endpoint: Arc::new(std::sync::RwLock::new(None)),
            trust_graph: None,
            abuse_metrics: None,
        }
    }

    pub fn with_trust_graph(
        mut self,
        graph: Arc<TrustGraph>,
        abuse_metrics: Arc<AbuseMetrics>,
    ) -> Self {
        self.trust_graph = Some(graph);
        self.abuse_metrics = Some(abuse_metrics);
        self
    }

    pub fn with_public_tcp_port(mut self, port: u16) -> Self {
        self.public_tcp_port = (port != 0).then_some(port);
        self
    }

    pub fn with_public_endpoint_state(
        mut self,
        public_endpoint: Arc<std::sync::RwLock<Option<SocketAddr>>>,
    ) -> Self {
        self.public_endpoint = Some(public_endpoint);
        self
    }

    pub fn with_public_udp_endpoint(
        mut self,
        endpoint: Arc<std::sync::RwLock<Option<SocketAddr>>>,
    ) -> Self {
        self.public_udp_endpoint = endpoint;
        self
    }

    pub async fn run(self, mut shutdown: oneshot::Receiver<()>) {
        let interval_duration = self.refresh.config().interval;
        let mut ticker = interval(interval_duration);
        let mut previous: Option<PublicEndpoint> = None;

        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    log::debug!("address refresh task stopped");
                    break;
                }
                _ = ticker.tick() => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|duration| duration.as_secs())
                        .unwrap_or(0);
                    let outcome = discover_endpoint(
                        &self.refresh,
                        &self.identity_id,
                        &self.private_key,
                        previous,
                        now,
                    ).await;
                    match outcome {
                        RefreshOutcome::Discovered { endpoint } => {
                            let address = SocketAddr::new(endpoint.ip, endpoint.port);
                            log::info!("STUN discovered public address: {address}");
                            if let Err(error) = self.publish(endpoint).await {
                                log::warn!("failed to publish endpoint: {error}");
                            } else {
                                previous = Some(endpoint);
                            }
                        }
                        RefreshOutcome::ReusedPrevious { endpoint } => {
                            log::debug!("STUN failed, reusing previous endpoint {}:{}", endpoint.ip, endpoint.port);
                        }
                        RefreshOutcome::Failed { error } => {
                            log::warn!("address refresh failed: {error}");
                            if !self.transport_addresses.is_empty() {
                                if let Err(publish_error) =
                                    self.publish_addresses(self.transport_addresses.clone()).await
                                {
                                    log::warn!(
                                        "DHT announce with LAN fallback failed: {publish_error}"
                                    );
                                } else {
                                    log::info!(
                                        "DHT announce: using LAN fallback {}",
                                        self.transport_addresses.join(", ")
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    async fn publish(&self, endpoint: PublicEndpoint) -> Result<(), AddressRefreshError> {
        let mut endpoints = self.transport_addresses.clone();
        let public_address = self
            .public_tcp_port
            .map(|port| SocketAddr::new(endpoint.ip, port));
        if let Some(public_address) = public_address {
            if !endpoints.contains(&public_address.to_string()) {
                endpoints.push(public_address.to_string());
            }
            log::info!("DHT public TCP candidate: {public_address}");
        } else {
            log::warn!("STUN discovered a public IP, but the local TCP port is unavailable");
        }
        self.publish_addresses(endpoints).await?;
        if let (Some(public_address), Some(state)) = (public_address, self.public_endpoint.as_ref())
        {
            *state.write().map_err(|error| {
                AddressRefreshError::PublishFailed(format!(
                    "public endpoint state lock poisoned: {error}"
                ))
            })? = Some(public_address);
        }
        Ok(())
    }

    async fn publish_addresses(
        &self,
        mut endpoints: Vec<String>,
    ) -> Result<(), AddressRefreshError> {
        let public_udp_endpoint = *self.public_udp_endpoint.read().map_err(|error| {
            AddressRefreshError::PublishFailed(format!(
                "public UDP endpoint state lock poisoned: {error}"
            ))
        })?;
        if let Some(endpoint) = public_udp_endpoint {
            let candidate = format!("udp://{endpoint}");
            if !endpoints.contains(&candidate) {
                endpoints.push(candidate);
            }
            log::info!("DHT public UDP candidate: {endpoint}");
        }
        retain_routable_endpoints(&mut endpoints);
        if endpoints.is_empty() {
            log::warn!("DHT announce skipped: no non-loopback transport endpoints available");
            return Ok(());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        if let Some(proof_of_live) = self.proof_of_live.as_ref() {
            let status = proof_of_live.status(&self.local_id, now).await;
            if !status.can_use_dht_store() {
                if cfg!(all(debug_assertions, not(test))) {
                    log::info!("DHT announce bypassed PoL in debug mode");
                } else {
                    return Ok(());
                }
            }
        }
        if let Some(graph) = &self.trust_graph {
            match graph.gate(&self.local_id, now).await {
                TrustGateDecision::Allow => {}
                TrustGateDecision::Throttle { .. } | TrustGateDecision::Block { .. } => {
                    if cfg!(all(debug_assertions, not(test))) {
                        log::info!("DHT announce bypassed TrustGraph gate in debug mode");
                    } else {
                        if let Some(metrics) = &self.abuse_metrics {
                            metrics
                                .trust_gate_blocked_total
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        log::debug!("address refresh blocked by trust gate");
                        return Ok(());
                    }
                }
            }
        }
        let record = EndpointRecord::create(
            self.identity_id.clone(),
            self.public_key.clone(),
            endpoints.clone(),
            &self.private_key,
            now,
            ENDPOINT_TTL_SECONDS,
        )
        .map_err(|error| AddressRefreshError::PublishFailed(error.to_string()))?;
        let transport = MuxDhtTransport::new(
            self.private_key.clone(),
            Arc::clone(&self.hosts),
            self.trust_policy.clone(),
        );
        let mut routing = self.routing.lock().await;
        let mut cache = self.cache.lock().await;
        let mut store = EndpointStore::new(self.local_id, &transport, &mut routing, &mut cache);
        store
            .publish(record, now)
            .await
            .map_err(|error| AddressRefreshError::PublishFailed(error.to_string()))?;
        log::info!("DHT announce: {}", endpoints.join(", "));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::VerifyingKey;
    use sha2::Digest;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex as StdMutex;

    fn gated_task(
        seed: u8,
        allow: bool,
    ) -> (
        AddressRefreshTask,
        Arc<AbuseMetrics>,
        Arc<StdMutex<KnownHosts>>,
    ) {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let verifying_key = VerifyingKey::from_bytes(&key.verifying_key().to_bytes())
            .expect("valid local public key");
        let local_id = NodeId::from_public_key(&verifying_key);
        let identity_id = hex::encode(sha2::Sha256::digest(verifying_key.to_bytes()));
        let public_key = hex::encode(verifying_key.to_bytes());
        let hosts = Arc::new(StdMutex::new(KnownHosts::new()));
        if allow {
            hosts
                .lock()
                .expect("hosts lock")
                .pin_manual(&local_id.to_hex(), &public_key, 1)
                .expect("pin local identity");
        }
        let scores = Arc::new(StdMutex::new(crate::dht::trust::TrustScoreManager::new()));
        let rates = Arc::new(StdMutex::new(crate::dht::rate_limit::RateLimiter::new()));
        let groups: Arc<dyn crate::dht::group::GroupGraph> =
            Arc::new(crate::dht::group::GroupRegistry::new());
        let oracle: Arc<dyn crate::dht::trust_oracle::TrustOracle> =
            Arc::new(crate::dht::trust_oracle::BasicTrustOracle::new(
                Arc::clone(&scores),
                Arc::clone(&rates),
                Arc::clone(&hosts),
                groups,
            ));
        let abuse_metrics = Arc::new(AbuseMetrics::new());
        let graph = Arc::new(TrustGraph::new(
            Arc::clone(&hosts),
            Arc::new(Mutex::new(
                crate::dht::invite_registry::InviteRegistry::new(),
            )),
            Arc::new(Mutex::new(crate::dht::badge::BadgeStore::new())),
            oracle,
            scores,
            rates,
            Arc::clone(&abuse_metrics),
        ));
        let task = AddressRefreshTask::new(
            Arc::new(AddressRefresh::with_defaults()),
            identity_id,
            public_key,
            key,
            local_id,
            None,
            Arc::new(Mutex::new(RoutingTable::new(local_id))),
            Arc::new(Mutex::new(EndpointCache::new(8))),
            Arc::clone(&hosts),
            NetworkTrustPolicy::default(),
            vec!["192.0.2.10:4001".to_string()],
        )
        .with_trust_graph(graph, Arc::clone(&abuse_metrics));
        (task, abuse_metrics, hosts)
    }

    fn endpoint() -> PublicEndpoint {
        PublicEndpoint {
            ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            port: 4242,
            server: "192.0.2.1:3478".parse().unwrap(),
        }
    }

    #[test]
    fn dht_candidates_exclude_loopback_and_unspecified_addresses() {
        let mut endpoints = vec![
            "127.0.0.1:4001".to_string(),
            "[::1]:4001".to_string(),
            "0.0.0.0:4001".to_string(),
            "udp://127.0.0.1:4003".to_string(),
            "192.168.0.55:4001".to_string(),
            "udp://203.0.113.10:4003".to_string(),
            "192.168.0.55:4001".to_string(),
        ];

        retain_routable_endpoints(&mut endpoints);

        assert_eq!(
            endpoints,
            vec![
                "192.168.0.55:4001".to_string(),
                "udp://203.0.113.10:4003".to_string(),
            ]
        );
    }

    #[test]
    fn config_default_values() {
        let config = AddressRefreshConfig::default();
        assert_eq!(config.interval, ADDRESS_REFRESH_DEFAULT_INTERVAL);
        assert_eq!(config.stun.servers.len(), 3);
    }

    #[test]
    fn config_custom_values() {
        let config = AddressRefreshConfig {
            stun: StunConfig {
                servers: vec!["127.0.0.1:3478".to_string()],
                timeout: Duration::from_millis(50),
            },
            interval: ADDRESS_REFRESH_MIN_INTERVAL,
        };
        assert_eq!(config.interval, ADDRESS_REFRESH_MIN_INTERVAL);
        assert_eq!(config.stun.servers, vec!["127.0.0.1:3478"]);
    }

    #[test]
    fn new_creates_client() {
        let refresh = AddressRefresh::with_defaults();
        assert_eq!(refresh.config().interval, ADDRESS_REFRESH_DEFAULT_INTERVAL);
        assert_eq!(refresh.config().stun.servers.len(), 3);
    }

    #[test]
    fn discover_outcome_discovered_constructible() {
        let outcome = RefreshOutcome::Discovered {
            endpoint: endpoint(),
        };
        assert!(matches!(outcome, RefreshOutcome::Discovered { .. }));
    }

    #[test]
    fn discover_outcome_reused_constructible() {
        let outcome = RefreshOutcome::ReusedPrevious {
            endpoint: endpoint(),
        };
        assert!(matches!(outcome, RefreshOutcome::ReusedPrevious { .. }));
    }

    #[test]
    fn address_refresh_error_display() {
        let error = AddressRefreshError::from(StunError::NoServers);
        assert!(error.to_string().contains("STUN"));
        assert_eq!(
            AddressRefreshError::NoPreviousEndpoint.to_string(),
            "no previous endpoint available"
        );
    }

    #[test]
    fn task_new_constructible() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let local_id = NodeId::from_public_key(&key.verifying_key());
        let task = AddressRefreshTask::new(
            Arc::new(AddressRefresh::with_defaults()),
            "identity".to_string(),
            "public-key".to_string(),
            key,
            local_id,
            None,
            Arc::new(Mutex::new(RoutingTable::new(local_id))),
            Arc::new(Mutex::new(EndpointCache::new(8))),
            Arc::new(std::sync::Mutex::new(KnownHosts::new())),
            NetworkTrustPolicy::default(),
            Vec::new(),
        );
        assert!(task.transport_addresses.is_empty());
    }

    #[test]
    fn task_run_stops_on_shutdown() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let key = SigningKey::from_bytes(&[2; 32]);
            let local_id = NodeId::from_public_key(&key.verifying_key());
            let task = AddressRefreshTask::new(
                Arc::new(AddressRefresh::with_defaults()),
                "identity".to_string(),
                "public-key".to_string(),
                key,
                local_id,
                None,
                Arc::new(Mutex::new(RoutingTable::new(local_id))),
                Arc::new(Mutex::new(EndpointCache::new(8))),
                Arc::new(std::sync::Mutex::new(KnownHosts::new())),
                NetworkTrustPolicy::default(),
                Vec::new(),
            );
            let (shutdown, receiver) = oneshot::channel();
            shutdown.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(1), task.run(receiver))
                .await
                .expect("address refresh task stopped");
        });
    }

    #[tokio::test]
    async fn address_refresh_skips_when_gate_blocks() {
        let (task, metrics, _) = gated_task(6, false);

        task.publish(endpoint())
            .await
            .expect("blocked publish is skipped");

        assert_eq!(metrics.snapshot().trust_gate_blocked_total, 1);
        assert_eq!(task.cache.lock().await.len(), 0);
    }

    #[tokio::test]
    async fn address_refresh_proceeds_when_gate_allows() {
        let (task, metrics, _) = gated_task(7, true);

        task.publish(endpoint())
            .await
            .expect("allowed endpoint publication");

        assert_eq!(metrics.snapshot().trust_gate_blocked_total, 0);
    }

    #[test]
    fn discover_endpoint_reuses_previous_on_stun_failure() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let refresh = AddressRefresh::new(AddressRefreshConfig {
                stun: StunConfig {
                    servers: Vec::new(),
                    timeout: Duration::from_millis(1),
                },
                interval: ADDRESS_REFRESH_MIN_INTERVAL,
            });
            let previous = endpoint();
            let outcome = discover_endpoint(
                &refresh,
                "identity",
                &SigningKey::from_bytes(&[3; 32]),
                Some(previous),
                0,
            )
            .await;
            assert!(matches!(
                outcome,
                RefreshOutcome::ReusedPrevious { endpoint } if endpoint == previous
            ));
        });
    }
}
