use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use tokio::sync::{mpsc, oneshot, Mutex as TokioMutex};

use crate::abuse_metrics::AbuseMetrics;
use crate::activity_tracker::ActivityTracker;
use crate::address_refresh::AddressRefresh;
use crate::age_tracker::AgeTracker;
use crate::auto_badge_queue::AutoBadgeQueue;
use crate::biometric_gate::{BiometricError, BiometricGate};
use crate::cold_contact_tracker::ColdContactTracker;
use crate::degradation::DegradationState;
use crate::dht::badge::{BadgeMetrics, BadgeStore, IssuerContext, StigmaLevel};
use crate::dht::group::GroupGraph;
use crate::dht::prekey_cache::PrekeyCache;
use crate::dht::rate_limit::RateLimiter;
use crate::dht::trust::TrustScoreManager;
use crate::dht::trust_metrics::TrustMetrics;
use crate::dht::trust_oracle::TrustOracle;
use crate::hole_punch::HolePuncher;
use crate::jury_commitment_publisher::JuryCommitmentPublisher;
use crate::local_prekey_store::LocalPrekeyStore;
use crate::observable_events::ObservableEvents;
use crate::peer_directory::PeerDirectory;
use crate::pinning::KnownHosts;
use crate::proof_of_live::ProofOfLive;
use crate::relay::RelayResponse;
use crate::relay_nonce_cache::RelayNonceCache;
use crate::relay_service::{RelayMetrics, RelayWork};
use crate::runtime::HomeRuntimeState;
use crate::session_store::SessionStore;
use crate::signaling::SignalingStrategy;
use crate::trust_graph::{GraphStatus, TrustGraph};
use crate::{IntegrityWave, SyncManager};
use ed25519_dalek::SigningKey;
use hal_storage::ClientStorage;

pub type RelaySenderSlot = Arc<TokioMutex<Option<mpsc::Sender<RelayWork>>>>;
pub type RelayResponseTracker = Arc<TokioMutex<HashMap<[u8; 16], oneshot::Sender<RelayResponse>>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAdmission {
    Allowed { watching: bool },
    StigmaRejected,
    DegradedUnknownRejected,
}

#[derive(Debug, Clone)]
pub struct InboundObservation {
    pub remote_addr: SocketAddr,
    pub identity_id: String,
    pub public_key_hex: String,
    pub observed_at: u64,
}

/// Default gate for platforms that have not integrated biometric support.
pub struct NoopBiometricGate;

#[async_trait::async_trait]
impl BiometricGate for NoopBiometricGate {
    async fn verify(&self, _prompt: &str) -> Result<(), BiometricError> {
        Err(BiometricError::Unavailable)
    }

    fn is_available(&self) -> bool {
        false
    }
}

/// Контейнер shared state, необходимый для обработки
/// входящих и исходящих сообщений.
///
/// Создаётся в конструкторе PeerRuntime, хранится как
/// Arc<RuntimeContext>. Позволяет передавать состояние
/// в spawn_incoming_task / process_incoming_envelope
/// одним аргументом вместо восьми.
pub struct RuntimeContext {
    // Sync
    pub sync: Arc<TokioMutex<SyncManager>>,
    pub home_state: Arc<TokioMutex<HomeRuntimeState>>,
    pub media_signals: Arc<TokioMutex<Vec<(String, Vec<u8>)>>>,
    pub storage: Option<Arc<StdMutex<ClientStorage>>>,
    pub age_tracker: Option<Arc<TokioMutex<AgeTracker>>>,
    pub activity_tracker: Option<Arc<TokioMutex<ActivityTracker>>>,
    pub proof_of_live: Option<Arc<ProofOfLive>>,

    // Trust
    pub hosts: Arc<StdMutex<KnownHosts>>,
    pub scores: Arc<StdMutex<TrustScoreManager>>,
    pub rates: Arc<StdMutex<RateLimiter>>,
    pub trust_graph: Option<Arc<TrustGraph>>,
    pub groups: Arc<dyn GroupGraph>,
    pub trust_metrics: Arc<TrustMetrics>,
    pub oracle: Arc<dyn TrustOracle>,
    pub address_refresh: Arc<AddressRefresh>,
    /// Punch hole puncher (stateless config).
    pub hole_puncher: Arc<HolePuncher>,
    /// Signaling strategy (веер каналов и форматов).
    pub signaling_strategy: Arc<SignalingStrategy>,
    pub relay_tx: RelaySenderSlot,
    pub relay_tracker: RelayResponseTracker,
    pub relay_metrics: Arc<RelayMetrics>,
    pub relay_nonce_cache: Arc<TokioMutex<RelayNonceCache>>,
    pub peer_directory: Arc<TokioMutex<PeerDirectory>>,
    /// Zero-cost event notification for tests. See docs/FLAKY_HARDENING.md.
    pub observable: Arc<ObservableEvents>,
    pub prekey_cache: Arc<TokioMutex<PrekeyCache>>,
    pub local_prekey_store: Option<Arc<TokioMutex<LocalPrekeyStore>>>,
    pub session_store: Arc<TokioMutex<SessionStore>>,
    /// Platform biometric gate. Defaults to NoopBiometricGate
    /// (is_available=false), which degrades policy to AgeProof.
    pub biometric_gate: Arc<dyn BiometricGate>,
    pub invite_registry: Arc<TokioMutex<crate::dht::invite_registry::InviteRegistry>>,
    pub degradation: Arc<DegradationState>,
    pub stigma_cache: Arc<crate::stigma_cache::StigmaCache>,
    pub inbound_observations_tx: Arc<TokioMutex<Option<mpsc::Sender<InboundObservation>>>>,
    pub badge_store: Arc<TokioMutex<BadgeStore>>,
    pub badge_metrics: Arc<BadgeMetrics>,
    pub badge_fetch_shutdown: Arc<AtomicBool>,
    pub cold_contact_tracker: Arc<TokioMutex<ColdContactTracker>>,
    pub auto_badge_queue: Arc<TokioMutex<AutoBadgeQueue>>,
    pub abuse_metrics: Arc<AbuseMetrics>,

    // Identity
    pub identity_id: String,
    pub public_key: String,
    pub identity_signing_key: Option<Arc<SigningKey>>,
    /// Publisher for jury DKG commitments, configured by `PeerRuntime`.
    pub jury_commitment_publisher: Option<Arc<JuryCommitmentPublisher>>,
    pub jury_plaintext_cache: Arc<crate::jury_plaintext_cache::JuryPlaintextCache>,
    pub invite_redemption_transport:
        Option<Arc<dyn crate::invite_redemption::InviteRedemptionTransport>>,
    pub pending_invite_redemptions:
        Arc<TokioMutex<HashMap<[u8; 32], crate::invite_redemption::PendingInviteRedemption>>>,
    pub sas_pairing: Arc<crate::pairing_sas::SasPairingState>,

    // Integrity
    pub integrity: Option<IntegrityWave>,
}

impl RuntimeContext {
    pub fn default_jury_plaintext_cache() -> Arc<crate::jury_plaintext_cache::JuryPlaintextCache> {
        Arc::new(crate::jury_plaintext_cache::JuryPlaintextCache::new())
    }

    pub fn default_pending_invite_redemptions(
    ) -> Arc<TokioMutex<HashMap<[u8; 32], crate::invite_redemption::PendingInviteRedemption>>> {
        Arc::new(TokioMutex::new(HashMap::new()))
    }

    pub fn default_sas_pairing() -> Arc<crate::pairing_sas::SasPairingState> {
        Arc::new(crate::pairing_sas::SasPairingState::default())
    }

    pub fn default_observable() -> Arc<ObservableEvents> {
        Arc::new(ObservableEvents::new())
    }

    pub fn default_session_store() -> Arc<TokioMutex<SessionStore>> {
        Arc::new(TokioMutex::new(SessionStore::new()))
    }

    pub fn default_session_store_with_storage(
        storage: Arc<StdMutex<ClientStorage>>,
    ) -> Arc<TokioMutex<SessionStore>> {
        Arc::new(TokioMutex::new(SessionStore::with_storage(storage, None)))
    }

    pub fn session_store_with_metrics(metrics: Arc<AbuseMetrics>) -> Arc<TokioMutex<SessionStore>> {
        Arc::new(TokioMutex::new(SessionStore::with_metrics(metrics)))
    }

    pub fn session_store_with_storage(
        storage: Arc<StdMutex<ClientStorage>>,
        metrics: Arc<AbuseMetrics>,
    ) -> Arc<TokioMutex<SessionStore>> {
        Arc::new(TokioMutex::new(SessionStore::with_storage(
            storage,
            Some(metrics),
        )))
    }

    fn effective_rate_limit(multiplier: f32) -> usize {
        ((crate::dht::rate_limit::RATE_MESSAGES_PER_HOUR as f32 * multiplier) as usize).max(1)
    }

    pub async fn rate_exceeded(&self, identity: &crate::dht::NodeId, now: u64) -> bool {
        if cfg!(all(debug_assertions, not(test))) {
            log::debug!("debug build bypasses tier-aware rate-limit enforcement");
            return false;
        }

        let Some(graph) = self.trust_graph.as_ref() else {
            let mut rates = match self.rates.lock() {
                Ok(rates) => rates,
                Err(_) => {
                    log::error!("rate limiter lock poisoned; denying rate-limited operation");
                    return true;
                }
            };
            let tier = rates.current_tier(identity, now);
            if tier == crate::dht::rate_limit::RateTier::Blocked {
                return true;
            }
            let limit = Self::effective_rate_limit(tier.rate_multiplier());
            if tier != crate::dht::rate_limit::RateTier::Normal
                && rates.messages_in_window(identity, now) >= limit
            {
                return true;
            }
            return matches!(
                rates.check_message(identity, now),
                crate::dht::RateDecision::Reject(_)
            );
        };

        let membership = match self.storage.as_ref() {
            Some(storage) => {
                let storage = match storage.lock() {
                    Ok(storage) => storage,
                    Err(poisoned) => {
                        log::warn!(
                            "reading graph cutover state with poisoned storage lock for identity={}",
                            identity.to_hex()
                        );
                        poisoned.into_inner()
                    }
                };
                match storage.read_cutover_state() {
                    Ok(Some(_)) => {
                        // The membership future performs synchronous SQLite reads and never suspends.
                        match futures::executor::block_on(graph.graph_membership(
                            storage.connection(),
                            identity,
                            now,
                        )) {
                            Ok(status) => Some(status),
                            Err(error) => {
                                log::error!(
                                    "graph membership rejected: identity={}, status=storage_error({error})",
                                    identity.to_hex()
                                );
                                return true;
                            }
                        }
                    }
                    Ok(None) => None,
                    Err(error) => {
                        log::error!(
                            "graph membership rejected: identity={}, status=cutover_state_error({error})",
                            identity.to_hex()
                        );
                        return true;
                    }
                }
            }
            None => None,
        };
        let membership_rejected = matches!(
            membership,
            Some(
                crate::trust_graph::MembershipStatus::Lapsed
                    | crate::trust_graph::MembershipStatus::Unknown
            )
        );
        if membership_rejected {
            log::warn!(
                "graph membership rejected: identity={}, status={:?}",
                identity.to_hex(),
                membership
            );
        }
        let status = if membership_rejected {
            GraphStatus::Unknown
        } else {
            graph.status(identity, now).await
        };
        if membership_rejected {
            return true;
        }
        let effective_limit = match status {
            GraphStatus::Banned => {
                let rate_blocked = match self.rates.lock() {
                    Ok(rates) => {
                        rates.current_tier(identity, now)
                            == crate::dht::rate_limit::RateTier::Blocked
                    }
                    Err(_) => {
                        log::error!("rate limiter lock poisoned while checking blocked tier");
                        false
                    }
                };
                if rate_blocked {
                    self.abuse_metrics
                        .rate_blocked_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                return true;
            }
            GraphStatus::Stigmatized | GraphStatus::Conflicted => return false,
            GraphStatus::OracleRestricted(_) => return true,
            GraphStatus::Warning => Self::effective_rate_limit(0.01),
            GraphStatus::Watching => Self::effective_rate_limit(0.1),
            GraphStatus::Unknown | GraphStatus::KnownLimited | GraphStatus::InGraph => {
                crate::dht::rate_limit::RATE_MESSAGES_PER_HOUR as usize
            }
        };

        let mut rates = match self.rates.lock() {
            Ok(rates) => rates,
            Err(_) => {
                log::error!("rate limiter lock poisoned; denying rate-limited operation");
                return true;
            }
        };
        if rates.messages_in_window(identity, now) < effective_limit {
            return false;
        }

        match status {
            GraphStatus::Warning => {
                self.abuse_metrics
                    .rate_throttled_by_warning_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            GraphStatus::Watching => {
                self.abuse_metrics
                    .rate_throttled_by_watching_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            _ => {}
        }
        if matches!(
            status,
            GraphStatus::Unknown | GraphStatus::KnownLimited | GraphStatus::InGraph
        ) {
            let _ = rates.check_message(identity, now);
        }
        true
    }

    /// Persists accepted timestamps asynchronously when the limiter is storage-backed.
    pub fn record_rate_acceptance(&self, identity: &crate::dht::NodeId, now: u64) -> bool {
        if cfg!(all(debug_assertions, not(test))) {
            return true;
        }

        match self.rates.lock() {
            Ok(mut rates) => rates.check_message(identity, now).is_allowed(),
            Err(_) => {
                log::error!("rate limiter lock poisoned; denying rate-limited operation");
                false
            }
        }
    }

    pub fn default_age_tracker(
        storage: Option<Arc<StdMutex<ClientStorage>>>,
    ) -> Option<Arc<TokioMutex<AgeTracker>>> {
        storage.map(|storage| Arc::new(TokioMutex::new(AgeTracker::new(storage))))
    }

    pub fn default_activity_tracker(
        storage: Option<Arc<StdMutex<ClientStorage>>>,
    ) -> Option<Arc<TokioMutex<ActivityTracker>>> {
        storage.map(|storage| Arc::new(TokioMutex::new(ActivityTracker::new(storage))))
    }

    pub fn default_proof_of_live(
        age: Option<Arc<TokioMutex<AgeTracker>>>,
        activity: Option<Arc<TokioMutex<ActivityTracker>>>,
    ) -> Option<Arc<ProofOfLive>> {
        match (age, activity) {
            (Some(age), Some(activity)) => Some(Arc::new(ProofOfLive::new(age, activity))),
            _ => None,
        }
    }

    pub fn default_peer_directory() -> Arc<TokioMutex<PeerDirectory>> {
        Arc::new(TokioMutex::new(PeerDirectory::default_config()))
    }

    pub fn default_prekey_cache() -> Arc<TokioMutex<PrekeyCache>> {
        Arc::new(TokioMutex::new(PrekeyCache::default()))
    }

    pub fn default_local_prekey_store(
        storage: Option<Arc<StdMutex<ClientStorage>>>,
        metrics: Arc<AbuseMetrics>,
    ) -> Option<Arc<TokioMutex<LocalPrekeyStore>>> {
        storage.map(|storage| {
            Arc::new(TokioMutex::new(LocalPrekeyStore::with_metrics(
                storage, metrics,
            )))
        })
    }

    pub fn default_invite_registry() -> Arc<TokioMutex<crate::dht::invite_registry::InviteRegistry>>
    {
        Arc::new(TokioMutex::new(
            crate::dht::invite_registry::InviteRegistry::new(),
        ))
    }

    pub fn default_stigma_cache() -> Arc<crate::stigma_cache::StigmaCache> {
        crate::stigma_cache::StigmaCache::new()
    }

    pub fn default_degradation() -> Arc<DegradationState> {
        Arc::new(DegradationState::new())
    }

    pub fn default_inbound_observations(
    ) -> Arc<TokioMutex<Option<mpsc::Sender<InboundObservation>>>> {
        Arc::new(TokioMutex::new(None))
    }

    pub fn default_abuse_channels() -> (
        Arc<TokioMutex<ColdContactTracker>>,
        Arc<TokioMutex<AutoBadgeQueue>>,
        Arc<AbuseMetrics>,
    ) {
        (
            Arc::new(TokioMutex::new(ColdContactTracker::default_config())),
            Arc::new(TokioMutex::new(AutoBadgeQueue::default_config())),
            Arc::new(AbuseMetrics::new()),
        )
    }

    pub fn default_badge_components() -> (Arc<TokioMutex<BadgeStore>>, Arc<BadgeMetrics>) {
        (
            Arc::new(TokioMutex::new(BadgeStore::default())),
            Arc::new(BadgeMetrics::new()),
        )
    }

    pub async fn peer_admission(
        &self,
        identity_id: &str,
        public_key_hex: Option<&str>,
        now: u64,
    ) -> PeerAdmission {
        let known = self
            .hosts
            .lock()
            .map(|hosts| hosts.record_of(identity_id).is_some())
            .unwrap_or(false);

        let stigma = if let Some(public_key_hex) = public_key_hex {
            let pubkey: [u8; 32] = match hex::decode(public_key_hex)
                .ok()
                .and_then(|value| value.try_into().ok())
            {
                Some(bytes) => bytes,
                None => return PeerAdmission::DegradedUnknownRejected,
            };
            let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&pubkey) {
                Ok(key) => key,
                Err(_) => return PeerAdmission::DegradedUnknownRejected,
            };
            let node_id = crate::dht::NodeId::from_public_key(&verifying_key);
            self.stigma_gate(&node_id, now).await
        } else {
            StigmaLevel::Clean
        };

        if matches!(stigma, StigmaLevel::Stigma { .. }) {
            return PeerAdmission::StigmaRejected;
        }

        if self.degradation.is_active() && !known {
            self.abuse_metrics
                .degraded_unknown_rejected_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.degradation.unknown_rejected();
            return PeerAdmission::DegradedUnknownRejected;
        }

        if self.degradation.is_active() && known {
            self.abuse_metrics
                .degraded_known_accepted_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.degradation.known_accepted();
        }

        PeerAdmission::Allowed {
            watching: matches!(stigma, StigmaLevel::Watching { .. }),
        }
    }

    pub async fn admit_peer(
        &self,
        identity_id: &str,
        public_key_hex: Option<&str>,
        now: u64,
    ) -> bool {
        matches!(
            self.peer_admission(identity_id, public_key_hex, now).await,
            PeerAdmission::Allowed { .. }
        )
    }

    pub async fn stigma_gate(&self, subject: &crate::dht::NodeId, now: u64) -> StigmaLevel {
        let store = self.badge_store.lock().await;
        let oracle = Arc::clone(&self.oracle);
        let hosts = Arc::clone(&self.hosts);
        let result = store.stigma_of(
            subject,
            |issuer| {
                let score = oracle
                    .score(issuer, now)
                    .map(|value| f32::from(value) / 100.0)
                    .unwrap_or(1.0);
                let is_contact_of_subject = hosts
                    .lock()
                    .ok()
                    .and_then(|known_hosts| known_hosts.record_of(&issuer.to_hex()).map(|_| true))
                    .unwrap_or(false);
                IssuerContext {
                    score,
                    is_contact_of_subject,
                    under_stigma: false,
                }
            },
            now,
        );
        self.badge_metrics.badge_stigma_active_current.store(
            matches!(result, StigmaLevel::Stigma { .. }) as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        self.badge_metrics.badge_watching_current.store(
            matches!(result, StigmaLevel::Watching { .. }) as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        self.badge_metrics.store_stale_current.store(
            store.is_stale(now, 10 * 60) as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        result
    }

    pub fn default_relay_channels() -> (RelaySenderSlot, RelayResponseTracker, Arc<RelayMetrics>) {
        (
            Arc::new(TokioMutex::new(None)),
            Arc::new(TokioMutex::new(HashMap::new())),
            Arc::new(RelayMetrics::new()),
        )
    }

    pub fn default_relay_nonce_cache() -> Arc<TokioMutex<RelayNonceCache>> {
        Arc::new(TokioMutex::new(RelayNonceCache::default()))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Mutex as StdMutex;

    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::dht::rate_limit::RATE_MESSAGES_PER_HOUR;
    use crate::dht::{
        badge::{Badge, BadgeContext, BadgeKind, BADGE_REFLECTION_PERIOD_SECS},
        BasicTrustOracle, GroupGraph, GroupRegistry, RateDecision, RateLimiter, TrustMetrics,
        TrustScoreManager,
    };
    use crate::hole_punch::HolePuncher;
    use crate::runtime::HomeRuntimeState;
    use crate::signaling::SignalingStrategy;
    use crate::trust_graph::TrustGraph;
    use crate::SyncManager;

    fn test_runtime_context() -> Arc<RuntimeContext> {
        test_runtime_context_with_storage(None, "self-id".to_string())
    }

    pub(crate) fn test_runtime_context_with_storage(
        storage: Option<Arc<StdMutex<ClientStorage>>>,
        identity_id: String,
    ) -> Arc<RuntimeContext> {
        let hosts = Arc::new(StdMutex::new(KnownHosts::new()));
        let scores = Arc::new(StdMutex::new(TrustScoreManager::new()));
        let rates = Arc::new(StdMutex::new(RateLimiter::new()));
        let groups: Arc<dyn GroupGraph> = Arc::new(GroupRegistry::new());
        let oracle: Arc<dyn TrustOracle> = Arc::new(BasicTrustOracle::new(
            Arc::clone(&scores),
            Arc::clone(&rates),
            Arc::clone(&hosts),
            Arc::clone(&groups),
        ));
        let (relay_tx, relay_tracker, relay_metrics) = RuntimeContext::default_relay_channels();
        let (badge_store, badge_metrics) = RuntimeContext::default_badge_components();
        let (cold_contact_tracker, auto_badge_queue, abuse_metrics) =
            RuntimeContext::default_abuse_channels();
        let invite_registry = RuntimeContext::default_invite_registry();
        let trust_graph = Arc::new(TrustGraph::new(
            Arc::clone(&hosts),
            Arc::clone(&invite_registry),
            Arc::clone(&badge_store),
            Arc::clone(&oracle),
            Arc::clone(&scores),
            Arc::clone(&rates),
            Arc::clone(&abuse_metrics),
        ));
        Arc::new(RuntimeContext {
            sync: Arc::new(TokioMutex::new(SyncManager::new("admit-peer-test".into()))),
            home_state: Arc::new(TokioMutex::new(HomeRuntimeState::default())),
            media_signals: Arc::new(TokioMutex::new(Vec::new())),
            storage,
            age_tracker: None,
            activity_tracker: None,
            proof_of_live: None,
            hosts,
            scores,
            rates,
            trust_graph: Some(trust_graph),
            groups,
            trust_metrics: Arc::new(TrustMetrics::new()),
            oracle,
            address_refresh: Arc::new(AddressRefresh::with_defaults()),
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
            biometric_gate: Arc::new(NoopBiometricGate),
            invite_registry,
            degradation: RuntimeContext::default_degradation(),
            stigma_cache: RuntimeContext::default_stigma_cache(),
            inbound_observations_tx: RuntimeContext::default_inbound_observations(),
            badge_store,
            badge_metrics,
            badge_fetch_shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cold_contact_tracker,
            auto_badge_queue,
            abuse_metrics,
            identity_id,
            public_key: "self-key".to_string(),
            identity_signing_key: None,
            jury_commitment_publisher: None,
            jury_plaintext_cache: RuntimeContext::default_jury_plaintext_cache(),
            invite_redemption_transport: None,
            pending_invite_redemptions: RuntimeContext::default_pending_invite_redemptions(),
            sas_pairing: RuntimeContext::default_sas_pairing(),
            integrity: None,
        })
    }

    #[tokio::test]
    async fn admit_peer_rejects_unknown_when_degraded() {
        let ctx = test_runtime_context();
        ctx.degradation.activate();
        let unknown_pub = hex::encode(SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes());
        let unknown_id =
            crate::dht::NodeId::from_public_key(&SigningKey::from_bytes(&[9; 32]).verifying_key())
                .to_hex();
        assert!(!ctx.admit_peer(&unknown_id, Some(&unknown_pub), 1_000).await);
    }

    #[tokio::test]
    async fn admit_peer_allows_known_when_degraded() {
        let ctx = test_runtime_context();
        ctx.degradation.activate();
        let key = SigningKey::from_bytes(&[10; 32]);
        let pub_hex = hex::encode(key.verifying_key().to_bytes());
        let id = crate::dht::NodeId::from_public_key(&key.verifying_key()).to_hex();
        ctx.hosts
            .lock()
            .unwrap()
            .pin_manual(&id, &pub_hex, 1_000)
            .unwrap();
        assert!(ctx.admit_peer(&id, Some(&pub_hex), 1_000).await);
    }

    #[tokio::test]
    async fn admit_peer_rejects_stigmatized_known_peer() {
        let ctx = test_runtime_context();
        ctx.degradation.activate();
        let issuer = SigningKey::from_bytes(&[11; 32]);
        let subject_key = SigningKey::from_bytes(&[12; 32]);
        let subject_id = crate::dht::NodeId::from_public_key(&subject_key.verifying_key());
        let issuer_id = crate::dht::NodeId::from_public_key(&issuer.verifying_key());
        let subject_pub = hex::encode(subject_key.verifying_key().to_bytes());
        let issuer_pub = hex::encode(issuer.verifying_key().to_bytes());
        ctx.hosts
            .lock()
            .unwrap()
            .pin_manual(&subject_id.to_hex(), &subject_pub, 1_000)
            .unwrap();
        ctx.hosts
            .lock()
            .unwrap()
            .pin_manual(&issuer_id.to_hex(), &issuer_pub, 1_000)
            .unwrap();
        let now: u64 = 1_000_000;
        let badge = Badge::create(
            9001,
            subject_id,
            None,
            BadgeKind::Spammer,
            vec!["degraded test".to_string()],
            BadgeContext::KnownContact,
            "degraded stigma".to_string(),
            issuer_id,
            now.saturating_sub(BADGE_REFLECTION_PERIOD_SECS),
            None,
            &issuer,
        )
        .expect("create stigma badge");
        ctx.badge_store
            .lock()
            .await
            .publish(badge)
            .expect("publish stigma badge");
        assert!(
            !ctx.admit_peer(&subject_id.to_hex(), Some(&subject_pub), now)
                .await
        );
    }

    #[tokio::test]
    async fn admit_peer_allows_unknown_when_healthy() {
        let ctx = test_runtime_context();
        let unknown_pub = hex::encode(SigningKey::from_bytes(&[13; 32]).verifying_key().to_bytes());
        let unknown_id =
            crate::dht::NodeId::from_public_key(&SigningKey::from_bytes(&[13; 32]).verifying_key())
                .to_hex();
        assert!(ctx.admit_peer(&unknown_id, Some(&unknown_pub), 1_000).await);
    }

    fn prepare_rate_peer(
        ctx: &RuntimeContext,
        key: &SigningKey,
        accepted_start: u64,
        reject_count: usize,
    ) -> crate::dht::NodeId {
        let node_id = crate::dht::NodeId::from_public_key(&key.verifying_key());
        let public_key = hex::encode(key.verifying_key().to_bytes());
        ctx.hosts
            .lock()
            .expect("hosts lock")
            .pin_manual(&node_id.to_hex(), &public_key, accepted_start)
            .expect("pin rate test peer");
        let mut rates = ctx.rates.lock().expect("rates lock");
        for now in accepted_start..accepted_start + RATE_MESSAGES_PER_HOUR as u64 {
            assert!(rates.check_message(&node_id, now).is_allowed());
        }
        let reject_start = accepted_start + RATE_MESSAGES_PER_HOUR as u64;
        for now in reject_start..reject_start + reject_count as u64 {
            assert!(matches!(
                rates.check_message(&node_id, now),
                RateDecision::Reject(_)
            ));
        }
        node_id
    }

    #[tokio::test]
    async fn rate_exceeded_respects_tier_and_counts_throttling() {
        let ctx = test_runtime_context();
        let key = SigningKey::from_bytes(&[18; 32]);
        let now = 1_100;
        let identity = prepare_rate_peer(&ctx, &key, 1_000, 10);

        assert!(ctx.rate_exceeded(&identity, now).await);
        assert_eq!(
            ctx.abuse_metrics
                .rate_throttled_by_warning_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn rate_exceeded_allows_normal_tier() {
        let ctx = test_runtime_context();
        let key = SigningKey::from_bytes(&[19; 32]);
        let identity = crate::dht::NodeId::from_public_key(&key.verifying_key());
        let public_key = hex::encode(key.verifying_key().to_bytes());
        ctx.hosts
            .lock()
            .expect("hosts lock")
            .pin_manual(&identity.to_hex(), &public_key, 1_000)
            .expect("pin normal peer");

        assert!(!ctx.rate_exceeded(&identity, 1_000).await);
    }

    #[tokio::test]
    async fn rate_exceeded_throttles_burst_peer() {
        let ctx = test_runtime_context();
        let key = SigningKey::from_bytes(&[24; 32]);
        let identity = crate::dht::NodeId::from_public_key(&key.verifying_key());
        let public_key = hex::encode(key.verifying_key().to_bytes());
        ctx.hosts
            .lock()
            .expect("hosts lock")
            .pin_manual(&identity.to_hex(), &public_key, 0)
            .expect("pin burst test peer");
        for now in 0..=crate::dht::rate_limit::RATE_BURST_MESSAGES as u64 {
            assert!(ctx.record_rate_acceptance(&identity, now));
        }

        assert!(
            ctx.rate_exceeded(
                &identity,
                crate::dht::rate_limit::RATE_BURST_MESSAGES as u64 + 1
            )
            .await
        );
    }

    #[tokio::test]
    async fn rate_exceeded_blocks_after_blocked_tier() {
        let ctx = test_runtime_context();
        let key = SigningKey::from_bytes(&[20; 32]);
        let now = 1_100;
        let identity = prepare_rate_peer(&ctx, &key, 1_000, 50);

        assert!(ctx.rate_exceeded(&identity, now).await);
        assert_eq!(
            ctx.abuse_metrics
                .rate_blocked_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn rate_exceeded_blocks_500_reject_peer() {
        let ctx = test_runtime_context();
        let key = SigningKey::from_bytes(&[25; 32]);
        let identity = crate::dht::NodeId::from_public_key(&key.verifying_key());
        let public_key = hex::encode(key.verifying_key().to_bytes());
        ctx.hosts
            .lock()
            .expect("hosts lock")
            .pin_manual(&identity.to_hex(), &public_key, 0)
            .expect("pin rolling reject test peer");

        let mut now = 0;
        {
            let mut rates = ctx.rates.lock().expect("rates lock");
            for _ in 0..crate::dht::rate_limit::RATE_ROLLING_BLOCKED {
                for _ in 0..crate::dht::rate_limit::RATE_MESSAGES_PER_HOUR {
                    assert!(rates.check_message(&identity, now).is_allowed());
                    now += 1;
                }
                assert!(rates.check_message(&identity, now).is_rejected());
                now += crate::dht::rate_limit::RATE_MESSAGE_WINDOW_SECS + 1;
            }
            assert_eq!(
                rates.current_tier(&identity, now),
                crate::dht::rate_limit::RateTier::Blocked
            );
        }

        assert!(ctx.rate_exceeded(&identity, now).await);
    }

    fn cutover_test_context(
        seed: u8,
        grandfathered: &[crate::dht::NodeId],
    ) -> (
        Arc<RuntimeContext>,
        Arc<StdMutex<ClientStorage>>,
        std::path::PathBuf,
    ) {
        let path = std::env::temp_dir().join(format!(
            "hal-runtime-cutover-{seed}-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[seed; 32]).expect("open cutover test storage"),
        ));
        {
            let mut storage_guard = storage.lock().expect("storage lock");
            for identity in grandfathered {
                storage_guard
                    .identity_history()
                    .observe_first_seen(&identity.to_hex(), 100)
                    .expect("seed grandfathered identity");
            }
            storage_guard
                .activate_cutover(200)
                .expect("activate test cutover");
        }
        let ctx = test_runtime_context_with_storage(Some(Arc::clone(&storage)), "self-id".into());
        (ctx, storage, path)
    }

    #[tokio::test]
    async fn rate_exceeded_allows_verified_peer() {
        let verified =
            crate::dht::NodeId::from_bytes(crate::dht::invite_registry::GENESIS_NODES[0]);
        let (ctx, _storage, path) = cutover_test_context(0x71, &[]);

        assert!(!ctx.rate_exceeded(&verified, 200).await);

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn rate_exceeded_blocks_lapsed_peer() {
        let identity = crate::dht::NodeId::from_bytes([0x72; 32]);
        let (ctx, _storage, path) = cutover_test_context(0x73, &[identity]);

        assert!(ctx.rate_exceeded(&identity, 200 + 90 * 86400 + 1).await);

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn rate_exceeded_blocks_unknown_peer() {
        let (ctx, _storage, path) = cutover_test_context(0x74, &[]);
        let identity = crate::dht::NodeId::from_bytes([0x75; 32]);

        assert!(ctx.rate_exceeded(&identity, 200).await);

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn rate_exceeded_falls_back_to_hard_limit_without_graph() {
        let mut ctx = test_runtime_context();
        Arc::get_mut(&mut ctx)
            .expect("unique runtime context")
            .trust_graph = None;
        let key = SigningKey::from_bytes(&[21; 32]);
        let identity = crate::dht::NodeId::from_public_key(&key.verifying_key());
        let mut rates = ctx.rates.lock().expect("rates lock");
        for index in 0..crate::dht::rate_limit::FIRST_CONTACT_ACCEPTED_THRESHOLD as u64 {
            assert!(rates.check_message(&identity, index * 31).is_allowed());
        }
        drop(rates);
        let established_at = crate::dht::rate_limit::FIRST_CONTACT_WINDOW_SECS + 1;

        for message_index in 0..RATE_MESSAGES_PER_HOUR as u64 {
            assert!(
                !ctx.rate_exceeded(&identity, established_at + message_index * 31)
                    .await
            );
        }
        assert!(
            ctx.rate_exceeded(
                &identity,
                established_at + RATE_MESSAGES_PER_HOUR as u64 * 31
            )
            .await
        );
    }

    #[test]
    fn effective_rate_limits_floor_soft_tiers_at_one() {
        assert_eq!(RuntimeContext::effective_rate_limit(1.0), 50);
        assert_eq!(RuntimeContext::effective_rate_limit(0.1), 5);
        assert_eq!(RuntimeContext::effective_rate_limit(0.01), 1);
    }

    #[tokio::test]
    async fn rate_exceeded_uses_baseline_limit_for_unknown_status() {
        let ctx = test_runtime_context();
        let key = SigningKey::from_bytes(&[22; 32]);
        let identity = crate::dht::NodeId::from_public_key(&key.verifying_key());
        let mut rates = ctx.rates.lock().expect("rates lock");
        for now in 0..RATE_MESSAGES_PER_HOUR as u64 {
            assert!(rates.check_message(&identity, now).is_allowed());
        }
        drop(rates);

        assert!(
            ctx.rate_exceeded(&identity, RATE_MESSAGES_PER_HOUR as u64)
                .await
        );
    }

    #[tokio::test]
    async fn warning_and_watching_limits_apply_to_recorded_accepts() {
        let warning_ctx = test_runtime_context();
        let warning_key = SigningKey::from_bytes(&[23; 32]);
        let warning_id = prepare_rate_peer(&warning_ctx, &warning_key, 1_000, 10);
        let after_accepted_window = 1_000 + RATE_MESSAGES_PER_HOUR as u64 + 49 + 3_550;
        assert!(
            !warning_ctx
                .rate_exceeded(&warning_id, after_accepted_window)
                .await
        );
        assert!(warning_ctx.record_rate_acceptance(&warning_id, after_accepted_window));
        assert!(
            warning_ctx
                .rate_exceeded(&warning_id, after_accepted_window)
                .await
        );

        let watching_ctx = test_runtime_context();
        let watching_key = SigningKey::from_bytes(&[24; 32]);
        let watching_id = prepare_rate_peer(&watching_ctx, &watching_key, 1_000, 3);
        for _ in 0..5 {
            assert!(
                !watching_ctx
                    .rate_exceeded(&watching_id, after_accepted_window)
                    .await
            );
            assert!(watching_ctx.record_rate_acceptance(&watching_id, after_accepted_window));
        }
        assert!(
            watching_ctx
                .rate_exceeded(&watching_id, after_accepted_window)
                .await
        );
    }
}
