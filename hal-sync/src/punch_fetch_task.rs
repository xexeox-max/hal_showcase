use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use hal_settings::NetworkTrustPolicy;
use tokio::sync::{oneshot, Mutex};
use tokio::time::interval;

use crate::dht::endpoint::EndpointCache;
use crate::dht::endpoint_lookup::DhtEndpointLookup;
use crate::dht::mux_transport::MuxDhtTransport;
use crate::dht::routing::RoutingTable;
use crate::dht::NodeId;
use crate::hole_punch::{punch_hole_with_strategy, PunchOutcome};
use crate::pinning::KnownHosts;
use crate::runtime_context::RuntimeContext;
use crate::signaling::PunchRequestStore;

/// Интервал по умолчанию: 60 секунд.
pub const PUNCH_FETCH_DEFAULT_INTERVAL_SECS: u64 = 60;

/// Минимальный интервал: 10 секунд.
pub const PUNCH_FETCH_MIN_INTERVAL_SECS: u64 = 10;

/// Конфиг задачи.
#[derive(Debug, Clone)]
pub struct PunchFetchConfig {
    pub interval_secs: u64,
    pub only_while_charging: bool,
    pub only_on_wifi: bool,
}

impl Default for PunchFetchConfig {
    fn default() -> Self {
        Self {
            interval_secs: PUNCH_FETCH_DEFAULT_INTERVAL_SECS,
            only_while_charging: false,
            only_on_wifi: false,
        }
    }
}

/// Задача для фонового чтения PunchRequest и запуска punch.
pub struct PunchFetchTask {
    ctx: Arc<RuntimeContext>,
    config: PunchFetchConfig,
    private_key: SigningKey,
    local_id: NodeId,
    routing: Arc<Mutex<RoutingTable>>,
    cache: Arc<Mutex<EndpointCache>>,
    hosts: Arc<std::sync::Mutex<KnownHosts>>,
    trust_policy: NetworkTrustPolicy,
}

impl PunchFetchTask {
    pub fn new(
        ctx: Arc<RuntimeContext>,
        config: PunchFetchConfig,
        private_key: SigningKey,
        local_id: NodeId,
        routing: Arc<Mutex<RoutingTable>>,
        cache: Arc<Mutex<EndpointCache>>,
        hosts: Arc<std::sync::Mutex<KnownHosts>>,
        trust_policy: NetworkTrustPolicy,
    ) -> Self {
        Self {
            ctx,
            config,
            private_key,
            local_id,
            routing,
            cache,
            hosts,
            trust_policy,
        }
    }

    pub fn config(&self) -> &PunchFetchConfig {
        &self.config
    }

    pub async fn run(self, mut shutdown: oneshot::Receiver<()>) {
        let interval_duration =
            Duration::from_secs(self.config.interval_secs.max(PUNCH_FETCH_MIN_INTERVAL_SECS));
        let mut ticker = interval(interval_duration);

        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    log::debug!("punch fetch task stopped");
                    break;
                }
                _ = ticker.tick() => {
                    if self.config.only_while_charging || self.config.only_on_wifi {
                        log::debug!("punch fetch skipped: device-state gating is not connected yet");
                        continue;
                    }
                    if let Err(error) = self.fetch_and_punch().await {
                        log::warn!("punch fetch failed: {error}");
                    }
                }
            }
        }
    }

    async fn fetch_and_punch(&self) -> anyhow::Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let transport = MuxDhtTransport::new(
            self.private_key.clone(),
            Arc::clone(&self.hosts),
            self.trust_policy.clone(),
        );
        let requests = {
            let mut routing = self.routing.lock().await;
            let mut store = PunchRequestStore::new(self.local_id, &transport, &mut routing);
            store
                .fetch(&self.local_id, now)
                .await
                .map_err(|error| anyhow::anyhow!("fetch punch requests: {error}"))?
        };

        let lookup = Arc::new(DhtEndpointLookup::new(
            self.local_id,
            self.private_key.clone(),
            Arc::clone(&self.hosts),
            self.trust_policy.clone(),
            Arc::clone(&self.routing),
            Arc::clone(&self.cache),
        ));
        let mut seen_requesters = HashSet::new();
        for request in requests {
            if !seen_requesters.insert(request.requester_id) {
                continue;
            }
            let seed = now ^ u64::from_le_bytes(request.nonce[..8].try_into().unwrap_or_default());
            match punch_hole_with_strategy(
                &self.ctx.hole_puncher,
                SocketAddr::from(([0, 0, 0, 0], 0)),
                request.requester_id,
                &self.ctx.signaling_strategy,
                Some(Arc::clone(&lookup) as Arc<dyn crate::dht::endpoint_lookup::EndpointLookup>),
                seed,
            )
            .await
            {
                PunchOutcome::Punched { remote, .. } => {
                    log::debug!("punched remote endpoint {remote} from fetched request");
                }
                PunchOutcome::Failed { error } => {
                    log::warn!(
                        "punch failed for requester {}: {error}",
                        request.requester_id.to_hex()
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::{
        BasicTrustOracle, GroupGraph, GroupRegistry, RateLimiter, TrustMetrics, TrustScoreManager,
    };
    use crate::hole_punch::HolePuncher;
    use crate::runtime::HomeRuntimeState;
    use crate::signaling::SignalingStrategy;
    use crate::SyncManager;
    use std::sync::Mutex as StdMutex;

    fn runtime_context() -> Arc<RuntimeContext> {
        let hosts = Arc::new(StdMutex::new(KnownHosts::new()));
        let scores = Arc::new(StdMutex::new(TrustScoreManager::new()));
        let rates = Arc::new(StdMutex::new(RateLimiter::new()));
        let groups: Arc<dyn GroupGraph> = Arc::new(GroupRegistry::new());
        let oracle = Arc::new(BasicTrustOracle::new(
            Arc::clone(&scores),
            Arc::clone(&rates),
            Arc::clone(&hosts),
            Arc::clone(&groups),
        ));
        let (relay_tx, relay_tracker, relay_metrics) = RuntimeContext::default_relay_channels();
        let (badge_store, badge_metrics) = RuntimeContext::default_badge_components();
        let (cold_contact_tracker, auto_badge_queue, abuse_metrics) =
            RuntimeContext::default_abuse_channels();
        Arc::new(RuntimeContext {
            sync: Arc::new(Mutex::new(SyncManager::new("punch-fetch-test".into()))),
            home_state: Arc::new(Mutex::new(HomeRuntimeState::default())),
            media_signals: Arc::new(Mutex::new(Vec::new())),
            storage: None,
            age_tracker: None,
            activity_tracker: None,
            proof_of_live: None,
            hosts,
            scores,
            rates,
            trust_graph: None,
            groups,
            trust_metrics: Arc::new(TrustMetrics::new()),
            oracle,
            address_refresh: Arc::new(crate::AddressRefresh::with_defaults()),
            hole_puncher: Arc::new(HolePuncher::with_defaults()),
            signaling_strategy: Arc::new(SignalingStrategy::default_hybrid()),
            relay_tx,
            relay_tracker,
            relay_metrics,
            relay_nonce_cache: RuntimeContext::default_relay_nonce_cache(),
            peer_directory: RuntimeContext::default_peer_directory(),
            observable: RuntimeContext::default_observable(),
            prekey_cache: RuntimeContext::default_prekey_cache(),
            local_prekey_store: None,
            session_store: RuntimeContext::session_store_with_metrics(Arc::clone(&abuse_metrics)),
            biometric_gate: Arc::new(crate::runtime_context::NoopBiometricGate),
            invite_registry: RuntimeContext::default_invite_registry(),
            degradation: RuntimeContext::default_degradation(),
            stigma_cache: RuntimeContext::default_stigma_cache(),
            inbound_observations_tx: RuntimeContext::default_inbound_observations(),
            badge_store,
            badge_metrics,
            badge_fetch_shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cold_contact_tracker,
            auto_badge_queue,
            abuse_metrics,
            identity_id: "punch-fetch-test".into(),
            public_key: String::new(),
            identity_signing_key: None,
            jury_commitment_publisher: None,
            jury_plaintext_cache: RuntimeContext::default_jury_plaintext_cache(),
            invite_redemption_transport: None,
            pending_invite_redemptions: RuntimeContext::default_pending_invite_redemptions(),
            sas_pairing: RuntimeContext::default_sas_pairing(),
            integrity: None,
        })
    }

    fn task(config: PunchFetchConfig) -> PunchFetchTask {
        let private_key = SigningKey::from_bytes(&[42; 32]);
        let local_id = NodeId::from_public_key(&private_key.verifying_key());
        let hosts = Arc::new(StdMutex::new(KnownHosts::new()));
        PunchFetchTask::new(
            runtime_context(),
            config,
            private_key,
            local_id,
            Arc::new(Mutex::new(RoutingTable::new(local_id))),
            Arc::new(Mutex::new(EndpointCache::new(8))),
            hosts,
            NetworkTrustPolicy::default(),
        )
    }

    #[test]
    fn config_default_values() {
        assert_eq!(
            PunchFetchConfig::default().interval_secs,
            PUNCH_FETCH_DEFAULT_INTERVAL_SECS
        );
        assert_eq!(PUNCH_FETCH_DEFAULT_INTERVAL_SECS, 60);
    }

    #[test]
    fn config_custom_values() {
        let config = PunchFetchConfig {
            interval_secs: 10,
            only_while_charging: true,
            only_on_wifi: true,
        };
        let task = task(config);
        assert_eq!(task.config().interval_secs, PUNCH_FETCH_MIN_INTERVAL_SECS);
        assert!(task.config().only_while_charging);
        assert!(task.config().only_on_wifi);
    }

    #[test]
    fn task_new_constructible() {
        let task = task(PunchFetchConfig::default());
        assert_eq!(
            task.config().interval_secs,
            PUNCH_FETCH_DEFAULT_INTERVAL_SECS
        );
    }
}
