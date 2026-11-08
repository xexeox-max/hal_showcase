//! PR-C: periodic fetching of DHT badges into the local BadgeStore.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hal_settings::NetworkTrustPolicy;
use tokio::sync::{oneshot, Mutex};
use tokio::time::interval;

use crate::dht::endpoint::{EndpointCache, EndpointStore};
use crate::dht::lookup::{Lookup, LookupConfig};
use crate::dht::mux_transport::MuxDhtTransport;
use crate::dht::routing::RoutingTable;
use crate::dht::{NodeId, StoredRecord};
use crate::runtime_context::RuntimeContext;

pub const BADGE_FETCH_DEFAULT_INTERVAL: Duration = Duration::from_secs(5 * 60);
pub const BADGE_FETCH_MIN_INTERVAL: Duration = Duration::from_secs(60);
pub const SUBJECT_BUDGET_PER_ROUND: usize = 32;

#[derive(Debug, Clone)]
pub struct BadgeFetchConfig {
    pub interval: Duration,
    pub subject_budget: usize,
}

impl Default for BadgeFetchConfig {
    fn default() -> Self {
        Self {
            interval: BADGE_FETCH_DEFAULT_INTERVAL,
            subject_budget: SUBJECT_BUDGET_PER_ROUND,
        }
    }
}

pub struct BadgeFetchTask {
    ctx: Arc<RuntimeContext>,
    config: BadgeFetchConfig,
    private_key: SigningKey,
    local_id: NodeId,
    routing: Arc<Mutex<RoutingTable>>,
    cache: Arc<Mutex<EndpointCache>>,
    trust_policy: NetworkTrustPolicy,
    next_subject: AtomicUsize,
}

impl BadgeFetchTask {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ctx: Arc<RuntimeContext>,
        config: BadgeFetchConfig,
        private_key: SigningKey,
        local_id: NodeId,
        routing: Arc<Mutex<RoutingTable>>,
        cache: Arc<Mutex<EndpointCache>>,
        trust_policy: NetworkTrustPolicy,
    ) -> Self {
        Self {
            ctx,
            config: BadgeFetchConfig {
                interval: config.interval.max(BADGE_FETCH_MIN_INTERVAL),
                subject_budget: config.subject_budget,
            },
            private_key,
            local_id,
            routing,
            cache,
            trust_policy,
            next_subject: AtomicUsize::new(0),
        }
    }

    pub async fn run(self, mut shutdown: oneshot::Receiver<()>) {
        let mut ticker = interval(self.config.interval);
        ticker.tick().await;

        'task: loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    log::info!("badge fetch: shutdown");
                    break;
                }
                _ = ticker.tick() => {
                    tokio::select! {
                        biased;
                        _ = &mut shutdown => {
                            log::info!("badge fetch: shutdown");
                            break 'task;
                        }
                        result = self.run_one_round() => {
                            if let Err(error) = result {
                                log::warn!("badge fetch round failed: {error}");
                            }
                        }
                    }
                }
            }
        }
    }

    async fn run_one_round(&self) -> Result<()> {
        if self.ctx.badge_fetch_shutdown.load(Ordering::Relaxed) {
            return Ok(());
        }
        let identities = {
            let hosts = self
                .ctx
                .hosts
                .lock()
                .map_err(|_| anyhow!("known hosts lock poisoned"))?;
            hosts.identities()
        };

        let total = identities.len();
        let mut subjects = Vec::with_capacity(total);
        let mut invalid_subjects = 0u64;
        for (identity_id, public_key_hex) in identities {
            let subject = match NodeId::from_hex(&identity_id) {
                Ok(subject) => subject,
                Err(_) => {
                    invalid_subjects = invalid_subjects.saturating_add(1);
                    continue;
                }
            };
            let public_key = hex::decode(public_key_hex)
                .ok()
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok());
            if !public_key.is_some_and(|key| NodeId::from_public_key(&key) == subject) {
                invalid_subjects = invalid_subjects.saturating_add(1);
                continue;
            }
            subjects.push(subject);
        }
        subjects.sort_unstable_by_key(|subject| *subject.as_bytes());

        if invalid_subjects > 0 {
            self.ctx
                .badge_metrics
                .fetch_failed_total
                .fetch_add(invalid_subjects, Ordering::Relaxed);
        }

        let budget = subjects.len().min(self.config.subject_budget);
        let start = if subjects.is_empty() {
            0
        } else {
            self.next_subject.fetch_add(budget, Ordering::Relaxed) % subjects.len()
        };
        let mut merged_total = 0usize;
        let mut failed = 0u64;
        let mut attempted = 0u64;

        for offset in 0..budget {
            if self.ctx.badge_fetch_shutdown.load(Ordering::Relaxed) {
                return Ok(());
            }
            let subject = subjects[(start + offset) % subjects.len()];
            attempted = attempted.saturating_add(1);
            match fetch_badges_from_dht(
                &self.ctx,
                &self.private_key,
                self.local_id,
                &self.routing,
                &self.cache,
                &self.trust_policy,
                &subject,
            )
            .await
            {
                Ok(merged) => merged_total = merged_total.saturating_add(merged),
                Err(error) => {
                    failed = failed.saturating_add(1);
                    log::debug!("badge fetch for {} failed: {error}", subject.to_hex());
                }
            }
        }

        if self.ctx.badge_fetch_shutdown.load(Ordering::Relaxed) {
            return Ok(());
        }

        let synced_at = unix_now();
        self.ctx.badge_store.lock().await.mark_synced(synced_at);
        self.ctx
            .badge_metrics
            .fetch_rounds_total
            .fetch_add(1, Ordering::Relaxed);
        self.ctx
            .badge_metrics
            .fetch_subjects_total
            .fetch_add(attempted, Ordering::Relaxed);
        self.ctx
            .badge_metrics
            .fetch_badges_merged_total
            .fetch_add(merged_total as u64, Ordering::Relaxed);
        self.ctx
            .badge_metrics
            .fetch_failed_total
            .fetch_add(failed, Ordering::Relaxed);

        log::debug!(
            "badge fetch round: {attempted}/{total} subjects, {merged_total} merged, {failed} failed"
        );
        Ok(())
    }
}

pub(crate) async fn fetch_badges_from_dht(
    ctx: &RuntimeContext,
    private_key: &SigningKey,
    local_id: NodeId,
    routing: &Arc<Mutex<RoutingTable>>,
    cache: &Arc<Mutex<EndpointCache>>,
    trust_policy: &NetworkTrustPolicy,
    subject: &NodeId,
) -> Result<usize> {
    let now = unix_now();
    let transport = MuxDhtTransport::new(
        private_key.clone(),
        Arc::clone(&ctx.hosts),
        trust_policy.clone(),
    );
    let key = *subject.as_bytes();
    let result = {
        let mut routing = routing.lock().await;
        let mut lookup = Lookup::new(
            local_id,
            *subject,
            LookupConfig::default(),
            &transport,
            &mut routing,
        );
        lookup
            .find_value(key)
            .await
            .map_err(|error| anyhow!("lookup badge slot: {error}"))?
    };
    let Some(value) = result.value else {
        return Ok(0);
    };
    if value.expires_at <= now {
        return Ok(0);
    }
    let badges = match StoredRecord::from_value(&value.value)? {
        StoredRecord::Badge(badges) => badges,
        _ => return Err(anyhow!("DHT value is not a Badge slot")),
    };
    StoredRecord::Badge(badges.clone()).validate_for_key(&key, now)?;

    let mut fetched = 0usize;
    for badge in badges {
        let issuer_identity = badge.assigned_by.to_hex();
        let pinned_key = ctx.hosts.lock().ok().and_then(|hosts| {
            hosts
                .record_of(&issuer_identity)
                .map(|record| record.public_key_hex.clone())
        });
        let issuer_key_hex = match pinned_key {
            Some(key) => Some(key),
            None => {
                let mut routing_guard = routing.lock().await;
                let mut cache_guard = cache.lock().await;
                let mut endpoint_store =
                    EndpointStore::new(local_id, &transport, &mut routing_guard, &mut cache_guard);
                endpoint_store
                    .lookup(&issuer_identity, now)
                    .await
                    .map_err(|error| anyhow!("lookup badge issuer endpoint: {error}"))?
                    .map(|record| record.public_key)
            }
        };
        let verified = issuer_key_hex
            .and_then(|hex_key| hex::decode(hex_key).ok())
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
            .filter(|key| NodeId::from_public_key(key) == badge.assigned_by)
            .is_some_and(|key| badge.verify(&key, now).is_ok());
        if !verified {
            ctx.badge_metrics
                .badge_verify_failed_total
                .fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let mut store = ctx.badge_store.lock().await;
        let is_new = !store.contains_badge(badge.id);
        if store.publish(badge).is_ok() && is_new {
            fetched = fetched.saturating_add(1);
        }
    }
    ctx.badge_metrics
        .badge_fetched_total
        .fetch_add(fetched as u64, Ordering::Relaxed);
    Ok(fetched)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::{
        BasicTrustOracle, GroupGraph, GroupRegistry, RateLimiter, TrustMetrics, TrustScoreManager,
    };
    use crate::hole_punch::HolePuncher;
    use crate::pinning::KnownHosts;
    use crate::runtime::HomeRuntimeState;
    use crate::signaling::SignalingStrategy;
    use crate::SyncManager;
    use ed25519_dalek::SigningKey;
    use std::sync::Mutex as StdMutex;

    fn runtime_context() -> Arc<RuntimeContext> {
        let hosts = Arc::new(StdMutex::new(KnownHosts::new()));
        let scores = Arc::new(StdMutex::new(TrustScoreManager::new()));
        let rates = Arc::new(StdMutex::new(RateLimiter::new()));
        let groups: Arc<dyn GroupGraph> = Arc::new(GroupRegistry::new());
        let oracle: Arc<dyn crate::dht::TrustOracle> = Arc::new(BasicTrustOracle::new(
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
            sync: Arc::new(Mutex::new(SyncManager::new("badge-fetch-test".into()))),
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
            identity_id: "badge-fetch-test".into(),
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

    fn task(ctx: Arc<RuntimeContext>, subject_budget: usize) -> BadgeFetchTask {
        let private_key = SigningKey::from_bytes(&[42; 32]);
        let local_id = NodeId::from_public_key(&private_key.verifying_key());
        BadgeFetchTask::new(
            ctx,
            BadgeFetchConfig {
                interval: BADGE_FETCH_DEFAULT_INTERVAL,
                subject_budget,
            },
            private_key,
            local_id,
            Arc::new(Mutex::new(RoutingTable::new(local_id))),
            Arc::new(Mutex::new(EndpointCache::new(16))),
            NetworkTrustPolicy::default(),
        )
    }

    fn add_subjects(ctx: &RuntimeContext, count: usize) {
        let mut hosts = ctx.hosts.lock().expect("hosts lock");
        for seed in 1..=count {
            let key = SigningKey::from_bytes(&[seed as u8; 32]);
            let public_key = hex::encode(key.verifying_key().to_bytes());
            let identity_id = NodeId::from_public_key(&key.verifying_key()).to_hex();
            hosts
                .pin_manual(&identity_id, &public_key, 1_000)
                .expect("valid pinned host");
        }
    }

    #[tokio::test]
    async fn round_marks_store_synced() {
        let ctx = runtime_context();
        task(Arc::clone(&ctx), 5)
            .run_one_round()
            .await
            .expect("round");
        assert!(ctx.badge_store.lock().await.last_synced_at().is_some());
    }

    #[tokio::test]
    async fn round_respects_subject_budget() {
        let ctx = runtime_context();
        add_subjects(&ctx, 100);
        task(Arc::clone(&ctx), 5)
            .run_one_round()
            .await
            .expect("round");
        assert_eq!(ctx.badge_metrics.snapshot().fetch_subjects_total, 5);
    }

    #[tokio::test]
    async fn round_skips_when_shutdown_requested() {
        let ctx = runtime_context();
        add_subjects(&ctx, 3);
        ctx.badge_fetch_shutdown.store(true, Ordering::Relaxed);
        task(Arc::clone(&ctx), 5)
            .run_one_round()
            .await
            .expect("shutdown round");
        assert_eq!(ctx.badge_metrics.snapshot().fetch_rounds_total, 0);
        assert_eq!(ctx.badge_store.lock().await.last_synced_at(), None);
    }

    #[tokio::test]
    async fn round_increments_metrics() {
        let ctx = runtime_context();
        add_subjects(&ctx, 3);
        task(Arc::clone(&ctx), 5)
            .run_one_round()
            .await
            .expect("round");
        let metrics = ctx.badge_metrics.snapshot();
        assert_eq!(metrics.fetch_rounds_total, 1);
        assert_eq!(metrics.fetch_subjects_total, 3);
        assert_eq!(metrics.fetch_badges_merged_total, 0);
        assert_eq!(metrics.fetch_failed_total, 0);
    }

    #[test]
    fn store_is_stale_when_never_synced() {
        assert!(crate::dht::BadgeStore::new().is_stale(1_000, 60));
    }

    #[test]
    fn store_not_stale_after_mark_synced() {
        let mut store = crate::dht::BadgeStore::new();
        store.mark_synced(1_000);
        assert!(!store.is_stale(1_010, 60));
    }
}
