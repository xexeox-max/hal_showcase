//! PR-F1a: unified TrustGraph — единый фасад над источниками trust.
//!
//! Проблема: KnownHosts, TrustScoreManager, GroupGraph, BadgeStore,
//! InviteRegistry — каждый со своими правилами. Enforcement-точки строят
//! свою комбинацию → несогласованность.
//!
//! Решение: одна функция `is_in_graph(identity)`, все остальные — её вызовы.
//! Источники остаются как storage; TrustGraph — view / фасад.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex as StdMutex};

use tokio::sync::Mutex;

use crate::abuse_metrics::AbuseMetrics;
use crate::dht::badge::{BadgeStore, IssuerContext, StigmaLevel};
use crate::dht::invite_registry::InviteRegistry;
use crate::dht::rate_limit::{RateLimiter, RateTier};
use crate::dht::trust::TrustScoreManager;
use crate::dht::trust_oracle::{OracleAction, TrustOracle};
use crate::dht::NodeId;
use crate::pinning::{BindingCheck, KnownHosts};
use hal_storage::invite_storage::{is_grandfathered, read_cutover_state, read_invite_proof};
use rusqlite::Connection;
use std::collections::HashSet;

/// Score threshold for full graph admission. The manager's default is 50.
pub const IN_GRAPH_SCORE_THRESHOLD: u8 = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipStatus {
    /// Valid proof chain to genesis.
    Verified,
    /// Grandfathered, deadline not yet passed, no proof.
    Grandfathered,
    /// Grandfathered window passed, no valid proof.
    Lapsed,
    /// No proof, not grandfathered (unknown to this node).
    Unknown,
}

/// Состояние identity в trust-графе. Агрегат всех источников.
///
/// Приоритет (первое сработавшее — итоговый статус):
/// Banned > Stigmatized > Conflicted > OracleRestricted > Warning >
/// Watching > Unknown > KnownLimited > InGraph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphStatus {
    Banned,
    Stigmatized,
    Conflicted,
    OracleRestricted(OracleAction),
    Warning,
    Watching,
    Unknown,
    KnownLimited,
    InGraph,
}

/// Авторитетное gate-решение TrustGraph.
///
/// Заменяет ad-hoc комбинации GraphStatus + rate_multiplier в runtime.
/// PoL не участвует (§2 F1_ENFORCEMENT_MIGRATION.md): per-operation
/// PoL проверка остаётся на call-site.
#[derive(Debug, Clone, PartialEq)]
pub enum TrustGateDecision {
    Allow,
    Throttle { rate_multiplier: f32 },
    Block { reason: BlockReason },
}

impl TrustGateDecision {
    /// Единственная авторитетная мапа GraphStatus -> TrustGateDecision.
    ///
    /// Не менять без правки таблицы в docs/F1_ENFORCEMENT_MIGRATION.md §3.
    pub fn from_status(status: GraphStatus) -> Self {
        match status {
            GraphStatus::InGraph => Self::Allow,
            // KnownLimited is low history, not a sanction.
            GraphStatus::KnownLimited => Self::Allow,
            GraphStatus::Watching => Self::Throttle {
                rate_multiplier: 0.1,
            },
            GraphStatus::Warning => Self::Throttle {
                rate_multiplier: 0.01,
            },
            GraphStatus::Unknown => Self::Block {
                reason: BlockReason::NotInGraph,
            },
            GraphStatus::OracleRestricted(action) => Self::Block {
                reason: BlockReason::OracleRestricted(action),
            },
            GraphStatus::Conflicted => Self::Block {
                reason: BlockReason::Conflicted,
            },
            GraphStatus::Stigmatized => Self::Block {
                reason: BlockReason::Stigmatized,
            },
            GraphStatus::Banned => Self::Block {
                reason: BlockReason::Banned,
            },
        }
    }

    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Block { .. })
    }

    pub fn rate_multiplier(&self) -> f32 {
        match self {
            Self::Allow => 1.0,
            Self::Throttle { rate_multiplier } => *rate_multiplier,
            Self::Block { .. } => 0.0,
        }
    }
}

/// Причина блокировки. `Platform(String)` — reserve под F1c
/// (biometric fail, integrity fail); до F1c не порождается.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReason {
    NotInGraph,
    OracleRestricted(OracleAction),
    Stigmatized,
    Conflicted,
    Banned,
    /// Reserve for F1c platform-specific gates. NOT produced before F1c.
    Platform(String),
}

impl GraphStatus {
    /// Whether the identity may perform baseline operations.
    pub fn is_admissible(self) -> bool {
        matches!(
            self,
            Self::InGraph | Self::KnownLimited | Self::Watching | Self::Warning
        )
    }

    /// Whether the identity may initiate cold contact.
    pub fn is_cold_admissible(self) -> bool {
        matches!(self, Self::InGraph | Self::KnownLimited)
    }

    pub fn rate_multiplier(self) -> f32 {
        match self {
            Self::InGraph | Self::KnownLimited => 1.0,
            Self::Watching => 0.1,
            Self::Warning => 0.01,
            // Unknown's legacy 0.0 is descriptive only; runtime uses the baseline hard limit.
            Self::Banned
            | Self::Stigmatized
            | Self::Conflicted
            | Self::OracleRestricted(_)
            | Self::Unknown => 0.0,
        }
    }

    pub fn is_hostile(self) -> bool {
        matches!(self, Self::Banned | Self::Stigmatized | Self::Conflicted)
    }
}

/// Источники данных для TrustGraph.
/// Не владеет, только ссылается — все источники уже в RuntimeContext.
pub struct TrustGraph {
    hosts: Arc<std::sync::Mutex<KnownHosts>>,
    _invite_registry: Arc<Mutex<InviteRegistry>>,
    badge_store: Arc<Mutex<BadgeStore>>,
    oracle: Arc<dyn TrustOracle>,
    scores: Arc<StdMutex<TrustScoreManager>>,
    rates: Arc<StdMutex<RateLimiter>>,
    abuse_metrics: Arc<AbuseMetrics>,
}

impl TrustGraph {
    pub fn new(
        hosts: Arc<std::sync::Mutex<KnownHosts>>,
        invite_registry: Arc<Mutex<InviteRegistry>>,
        badge_store: Arc<Mutex<BadgeStore>>,
        oracle: Arc<dyn TrustOracle>,
        scores: Arc<StdMutex<TrustScoreManager>>,
        rates: Arc<StdMutex<RateLimiter>>,
        abuse_metrics: Arc<AbuseMetrics>,
    ) -> Self {
        Self {
            hosts,
            _invite_registry: invite_registry,
            badge_store,
            oracle,
            scores,
            rates,
            abuse_metrics,
        }
    }

    /// Classify an identity without a presented key. KnownHosts membership is
    /// checked by identity; use `status_with_public_key` at binding boundaries.
    pub async fn status(&self, identity: &NodeId, now: u64) -> GraphStatus {
        self.status_inner(identity, None, now).await
    }

    pub async fn graph_membership(
        &self,
        conn: &Connection,
        identity: &NodeId,
        now: u64,
    ) -> anyhow::Result<MembershipStatus> {
        let genesis: HashSet<String> = crate::dht::invite_registry::GENESIS_NODES
            .iter()
            .map(hex::encode)
            .collect();
        self.graph_membership_with_genesis(conn, identity, now, &genesis)
    }

    fn graph_membership_with_genesis(
        &self,
        conn: &Connection,
        identity: &NodeId,
        now: u64,
        genesis: &dyn crate::dht::nested_proof::GenesisProvider,
    ) -> anyhow::Result<MembershipStatus> {
        if crate::dht::invite_registry::is_genesis(identity.as_bytes()) {
            return Ok(MembershipStatus::Verified);
        }

        if let Some(proof_blob) = read_invite_proof(conn, &identity.to_hex())? {
            if let Ok(proof) =
                serde_json::from_slice::<crate::dht::nested_proof::NestedProof>(&proof_blob)
            {
                let names_identity = proof
                    .hops
                    .first()
                    .is_some_and(|hop| hop.redeemer_node_id_hex == identity.to_hex());
                if names_identity
                    && crate::dht::nested_proof::verify_nested_proof(&proof, genesis).is_ok()
                {
                    return Ok(MembershipStatus::Verified);
                }
            }
        }

        if let Some(state) = read_cutover_state(conn)? {
            if is_grandfathered(conn, identity.as_bytes())? {
                return Ok(if now <= state.deadline_at {
                    MembershipStatus::Grandfathered
                } else {
                    MembershipStatus::Lapsed
                });
            }
        }

        Ok(MembershipStatus::Unknown)
    }

    /// Classify with the remote key so pinning conflicts are observable.
    pub async fn status_with_public_key(
        &self,
        identity: &NodeId,
        public_key_hex: &str,
        now: u64,
    ) -> GraphStatus {
        self.status_inner(identity, Some(public_key_hex), now).await
    }

    async fn status_inner(
        &self,
        identity: &NodeId,
        public_key_hex: Option<&str>,
        now: u64,
    ) -> GraphStatus {
        if self.oracle.is_banned(identity, now) {
            return GraphStatus::Banned;
        }

        let oracle = Arc::clone(&self.oracle);
        let hosts = Arc::clone(&self.hosts);
        let stigma = {
            let store = self.badge_store.lock().await;
            store.stigma_of(
                identity,
                |issuer| {
                    let score = oracle
                        .score(issuer, now)
                        .map(|value| f32::from(value) / 100.0)
                        .unwrap_or(1.0);
                    let is_contact_of_subject = hosts
                        .lock()
                        .ok()
                        .and_then(|known_hosts| {
                            known_hosts.record_of(&issuer.to_hex()).map(|_| true)
                        })
                        .unwrap_or(false);
                    IssuerContext {
                        score,
                        is_contact_of_subject,
                        under_stigma: false,
                    }
                },
                now,
            )
        };

        if matches!(stigma, StigmaLevel::Stigma { .. }) {
            return GraphStatus::Stigmatized;
        }
        let badge_watching = matches!(stigma, StigmaLevel::Watching { .. });

        let binding = {
            let hosts = match self.hosts.lock() {
                Ok(hosts) => hosts,
                Err(_) => return GraphStatus::Unknown,
            };
            let identity_hex = identity.to_hex();
            match public_key_hex {
                Some(public_key_hex) => hosts.check(&identity_hex, public_key_hex),
                None if hosts.record_of(&identity_hex).is_some() => BindingCheck::Trusted,
                None => BindingCheck::Unknown,
            }
        };

        match binding {
            BindingCheck::Conflicted { .. } => return GraphStatus::Conflicted,
            BindingCheck::Unknown | BindingCheck::Trusted => {}
        }

        // OracleRestricted: for Unknown bindings, score-derived restrictions
        // from OracleAction. Banned/Stigmatized/Conflicted already returned.
        // TimeoutContacts and BlockNewMessages are restrictions;
        // ShowBadge and Normal are not.
        if matches!(&binding, BindingCheck::Unknown) {
            let action = self.oracle.action(identity, now);
            if matches!(
                action,
                OracleAction::TimeoutContacts | OracleAction::BlockNewMessages
            ) {
                return GraphStatus::OracleRestricted(action);
            }
        }

        let rate_tier = match self.rates.lock() {
            Ok(rates) => rates.current_tier(identity, now),
            Err(_) => {
                log::error!("trust graph rate limiter lock poisoned; denying graph admission");
                return GraphStatus::Unknown;
            }
        };

        if rate_tier == RateTier::Blocked {
            self.abuse_metrics
                .rate_tier_blocked_total
                .fetch_add(1, Ordering::Relaxed);
            return GraphStatus::Banned;
        }
        if rate_tier == RateTier::Warning {
            self.abuse_metrics
                .rate_tier_warning_total
                .fetch_add(1, Ordering::Relaxed);
            return GraphStatus::Warning;
        }
        if badge_watching || rate_tier == RateTier::Throttled {
            self.abuse_metrics
                .rate_tier_throttled_total
                .fetch_add(1, Ordering::Relaxed);
            return GraphStatus::Watching;
        }
        if matches!(&binding, BindingCheck::Unknown) {
            return GraphStatus::Unknown;
        }

        let score = self
            .scores
            .lock()
            .map(|scores| scores.score_of(identity))
            .unwrap_or(0);
        if score >= IN_GRAPH_SCORE_THRESHOLD {
            GraphStatus::InGraph
        } else {
            GraphStatus::KnownLimited
        }
    }

    /// Compatibility shortcut for callers that only need baseline admission.
    pub async fn is_in_graph(&self, identity: &NodeId, now: u64) -> bool {
        self.status(identity, now).await.is_admissible()
    }

    /// Авторитетное решение для peer без presented key.
    pub async fn gate(&self, identity: &NodeId, now: u64) -> TrustGateDecision {
        self.gate_inner(identity, None, now).await
    }

    /// Авторитетное решение с presented key (проверяет pinning conflict).
    pub async fn gate_with_public_key(
        &self,
        identity: &NodeId,
        public_key_hex: &str,
        now: u64,
    ) -> TrustGateDecision {
        self.gate_inner(identity, Some(public_key_hex), now).await
    }

    async fn gate_inner(
        &self,
        identity: &NodeId,
        public_key_hex: Option<&str>,
        now: u64,
    ) -> TrustGateDecision {
        let status = self.status_inner(identity, public_key_hex, now).await;
        TrustGateDecision::from_status(status)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    use ed25519_dalek::{Signer, SigningKey};
    use rusqlite::Connection;
    use sha2::Digest;

    use super::*;
    use crate::abuse_metrics::AbuseMetrics;
    use crate::dht::badge::{
        Badge, BadgeContext, BadgeKind, BadgeStore, BADGE_REFLECTION_PERIOD_SECS,
    };
    use crate::dht::invite_registry::InviteRegistry;
    use crate::dht::rate_limit::{RateDecision, RateLimiter, RATE_MESSAGES_PER_HOUR};
    use crate::dht::trust_oracle::{NodeTrust, OracleAction, Relationship, TrustOracle};
    use crate::pinning::KnownHosts;

    #[derive(Debug, Default)]
    struct FakeOracle {
        banned: HashSet<NodeId>,
        actions: HashMap<NodeId, OracleAction>,
    }

    impl TrustOracle for FakeOracle {
        fn relationship(&self, node_id: &NodeId) -> Relationship {
            if self.banned.contains(node_id) {
                Relationship::Banned
            } else {
                Relationship::Unknown
            }
        }

        fn score(&self, _node_id: &NodeId, _now: u64) -> Option<u8> {
            None
        }

        fn action(&self, node_id: &NodeId, _now: u64) -> OracleAction {
            if let Some(action) = self.actions.get(node_id) {
                return *action;
            }
            if self.banned.contains(node_id) {
                OracleAction::Ban
            } else {
                OracleAction::Normal
            }
        }

        fn trust_of(&self, node_id: &NodeId) -> NodeTrust {
            NodeTrust::new(self.relationship(node_id))
        }

        fn allows_contact_add(&self, node_id: &NodeId, now: u64) -> bool {
            self.action(node_id, now).allows_contact_add()
        }

        fn allows_message_to_stranger(&self, node_id: &NodeId, now: u64) -> bool {
            self.action(node_id, now).allows_message_to_stranger()
        }

        fn is_banned(&self, node_id: &NodeId, _now: u64) -> bool {
            self.banned.contains(node_id)
        }

        fn record_message(&self, _: &NodeId, _: bool, _: u64) {}

        fn record_contact_add(&self, _: &NodeId, _: u64) {}

        fn recompute(&self, _: &NodeId, _: u64) {}

        fn cleanup_old(&self, _: u64) {}
    }

    fn node(seed: u8) -> NodeId {
        NodeId::from_bytes([seed; 32])
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn invite_storage() -> Connection {
        let connection = Connection::open_in_memory().expect("open invite membership database");
        hal_storage::invite_storage::create_invite_tables(&connection)
            .expect("create invite membership schema");
        connection
    }

    fn valid_proof_for(identity: &NodeId, issuer: &SigningKey) -> Vec<u8> {
        let issuer_public_key = issuer.verifying_key().to_bytes();
        let issuer_hex = hex::encode(sha2::Sha256::digest(issuer_public_key));
        let token_hash = [0x9a; 32];
        let issued_at = 10u64;
        let expires_at = 1_000u64;
        let redeemed_at = 20u64;
        let mut issuance_payload = b"HAL-INV-ISSUE-v1\0".to_vec();
        issuance_payload.extend_from_slice(&token_hash);
        issuance_payload.extend_from_slice(&[0; 32]);
        issuance_payload.extend_from_slice(&issued_at.to_be_bytes());
        issuance_payload.extend_from_slice(&expires_at.to_be_bytes());
        let issuance_signature = issuer.sign(&issuance_payload).to_bytes();
        let mut redemption_payload = b"HAL-INV-REDEEM-v1\0".to_vec();
        redemption_payload.extend_from_slice(&token_hash);
        redemption_payload.extend_from_slice(identity.as_bytes());
        redemption_payload.extend_from_slice(&redeemed_at.to_be_bytes());
        let redemption_signature = issuer.sign(&redemption_payload).to_bytes();
        serde_json::to_vec(&crate::dht::nested_proof::NestedProof {
            hops: vec![crate::dht::nested_proof::ProofHop {
                token_hash,
                parent_token_hash: None,
                issuer_hex: issuer_hex.clone(),
                issuer_public_key,
                issued_at,
                expires_at,
                issuance_signature,
                redeemer_node_id_hex: identity.to_hex(),
                redeemed_at,
                redemption_signature,
            }],
        })
        .expect("serialize valid invite proof")
    }

    fn test_graph_with_score(identity: NodeId, score: Option<u8>) -> TrustGraph {
        test_graph(identity, score, false)
    }

    fn test_graph(identity: NodeId, score: Option<u8>, banned: bool) -> TrustGraph {
        test_graph_with_action(identity, score, banned, None)
    }

    fn test_graph_with_action(
        identity: NodeId,
        score: Option<u8>,
        banned: bool,
        action: Option<OracleAction>,
    ) -> TrustGraph {
        let hosts = Arc::new(StdMutex::new(KnownHosts::new()));
        let invite_registry = Arc::new(Mutex::new(InviteRegistry::new()));
        let badge_store = Arc::new(Mutex::new(BadgeStore::default()));
        let mut score_manager = TrustScoreManager::new();
        if let Some(score) = score {
            score_manager.ensure(identity, 1_000);
            if score < IN_GRAPH_SCORE_THRESHOLD {
                score_manager.penalize(
                    &identity,
                    IN_GRAPH_SCORE_THRESHOLD - score,
                    "test score",
                    1_000,
                );
            } else if score > IN_GRAPH_SCORE_THRESHOLD {
                score_manager.reward(&identity, score - IN_GRAPH_SCORE_THRESHOLD, 1_000);
            }
        }
        let oracle: Arc<dyn TrustOracle> = Arc::new(FakeOracle {
            banned: if banned {
                HashSet::from([identity])
            } else {
                HashSet::new()
            },
            actions: action
                .map(|action| HashMap::from([(identity, action)]))
                .unwrap_or_default(),
        });
        let rates = Arc::new(StdMutex::new(RateLimiter::new()));
        TrustGraph::new(
            hosts,
            invite_registry,
            badge_store,
            oracle,
            Arc::new(StdMutex::new(score_manager)),
            rates,
            Arc::new(AbuseMetrics::new()),
        )
    }

    fn record_rate_rejects(graph: &TrustGraph, identity: &NodeId, rejects: usize, start: u64) {
        let mut rates = graph.rates.lock().expect("rates lock");
        for now in start..start + RATE_MESSAGES_PER_HOUR as u64 {
            assert!(rates.check_message(identity, now).is_allowed());
        }
        let reject_start = start + RATE_MESSAGES_PER_HOUR as u64;
        for now in reject_start..reject_start + rejects as u64 {
            assert!(matches!(
                rates.check_message(identity, now),
                RateDecision::Reject(_)
            ));
        }
    }

    fn pin_node(graph: &TrustGraph, identity: &NodeId, key_seed: u8) -> String {
        let key = SigningKey::from_bytes(&[key_seed; 32]);
        let public_key_hex = hex::encode(key.verifying_key().to_bytes());
        graph
            .hosts
            .lock()
            .expect("hosts lock")
            .pin_manual(&identity.to_hex(), &public_key_hex, 1_000)
            .expect("pin host");
        public_key_hex
    }

    async fn publish_badge(
        graph: &TrustGraph,
        id: u64,
        subject: NodeId,
        issuer: NodeId,
        kind: BadgeKind,
        context: BadgeContext,
        now: u64,
        signer: &SigningKey,
    ) {
        let badge = Badge::create(
            id,
            subject,
            None,
            kind,
            vec!["test badge".to_string()],
            context,
            "trust graph test".to_string(),
            issuer,
            now.saturating_sub(BADGE_REFLECTION_PERIOD_SECS),
            None,
            signer,
        )
        .expect("valid badge");
        graph
            .badge_store
            .lock()
            .await
            .publish(badge)
            .expect("publish badge");
    }

    #[tokio::test]
    async fn status_unknown_for_empty_hosts() {
        let graph = test_graph_with_score(node(1), None);
        assert_eq!(graph.status(&node(1), 1_000).await, GraphStatus::Unknown);
    }

    #[tokio::test]
    async fn status_known_when_pinned_but_low_score() {
        let subject = node(2);
        let graph = test_graph_with_score(subject, Some(30));
        pin_node(&graph, &subject, 2);
        assert_eq!(
            graph.status(&subject, 1_000).await,
            GraphStatus::KnownLimited
        );
    }

    #[tokio::test]
    async fn status_clean_still_ingraph() {
        let subject = node(3);
        let graph = test_graph_with_score(subject, Some(50));
        pin_node(&graph, &subject, 3);
        assert_eq!(graph.status(&subject, 1_000).await, GraphStatus::InGraph);
    }

    #[tokio::test]
    async fn status_stigmatized_overrides_score() {
        let subject = node(4);
        let graph = test_graph_with_score(subject, Some(80));
        pin_node(&graph, &subject, 4);
        let issuer = node(5);
        let issuer_key = key(5);
        pin_node(&graph, &issuer, 5);
        let now = BADGE_REFLECTION_PERIOD_SECS + 2_000;
        publish_badge(
            &graph,
            9001,
            subject,
            issuer,
            BadgeKind::Spammer,
            BadgeContext::KnownContact,
            now,
            &issuer_key,
        )
        .await;
        assert_eq!(graph.status(&subject, now).await, GraphStatus::Stigmatized);
    }

    #[tokio::test]
    async fn status_stigmatized_overrides_unknown() {
        let subject = node(7);
        let graph = test_graph_with_score(subject, Some(80));
        let issuer = node(6);
        let issuer_key = key(6);
        pin_node(&graph, &issuer, 6);
        let now = BADGE_REFLECTION_PERIOD_SECS + 2_000;
        publish_badge(
            &graph,
            9002,
            subject,
            issuer,
            BadgeKind::Spammer,
            BadgeContext::KnownContact,
            now,
            &issuer_key,
        )
        .await;
        assert_eq!(graph.status(&subject, now).await, GraphStatus::Stigmatized);
    }

    #[tokio::test]
    async fn is_in_graph_true_for_ingraph() {
        let subject = node(8);
        let graph = test_graph_with_score(subject, Some(60));
        pin_node(&graph, &subject, 8);
        assert!(graph.is_in_graph(&subject, 1_000).await);
    }

    #[tokio::test]
    async fn is_in_graph_false_for_stigmatized() {
        let subject = node(9);
        let graph = test_graph_with_score(subject, Some(80));
        pin_node(&graph, &subject, 9);
        let issuer = node(10);
        let issuer_key = key(10);
        pin_node(&graph, &issuer, 10);
        let now = BADGE_REFLECTION_PERIOD_SECS + 2_000;
        publish_badge(
            &graph,
            9003,
            subject,
            issuer,
            BadgeKind::Spammer,
            BadgeContext::KnownContact,
            now,
            &issuer_key,
        )
        .await;
        assert!(!graph.is_in_graph(&subject, now).await);
    }

    #[tokio::test]
    async fn is_in_graph_false_for_unknown() {
        let graph = test_graph_with_score(node(11), Some(40));
        assert!(!graph.is_in_graph(&node(11), 1_000).await);
    }

    #[tokio::test]
    async fn graph_membership_genesis_returns_verified() {
        let graph = test_graph_with_score(node(12), Some(50));
        let connection = invite_storage();
        let genesis = NodeId::from_bytes(crate::dht::invite_registry::GENESIS_NODES[0]);

        assert_eq!(
            graph
                .graph_membership(&connection, &genesis, 1_000)
                .await
                .expect("check genesis membership"),
            MembershipStatus::Verified
        );
    }

    #[tokio::test]
    async fn graph_membership_valid_proof_returns_verified() {
        let graph = test_graph_with_score(node(13), Some(50));
        let connection = invite_storage();
        let issuer = key(120);
        let identity = node(121);
        let proof = valid_proof_for(&identity, &issuer);
        hal_storage::invite_storage::upsert_invite_proof(
            &connection,
            &identity.to_hex(),
            &proof,
            100,
        )
        .expect("persist proof");
        let genesis = HashSet::from([hex::encode(sha2::Sha256::digest(
            issuer.verifying_key().to_bytes(),
        ))]);

        assert_eq!(
            graph
                .graph_membership_with_genesis(&connection, &identity, 100, &genesis)
                .expect("check proof membership"),
            MembershipStatus::Verified
        );
    }

    #[tokio::test]
    async fn graph_membership_grandfathered_before_deadline_returns_grandfathered() {
        let graph = test_graph_with_score(node(14), Some(50));
        let mut connection = invite_storage();
        connection
            .execute_batch(
                "CREATE TABLE identity_first_seen (
                    identity_hex TEXT PRIMARY KEY,
                    first_seen_at INTEGER NOT NULL
                );",
            )
            .expect("create first-seen table");
        let identity = node(122);
        connection
            .execute(
                "INSERT INTO identity_first_seen (identity_hex, first_seen_at)
                 VALUES (?1, ?2)",
                rusqlite::params![identity.to_hex(), 10],
            )
            .expect("seed first-seen identity");
        hal_storage::invite_storage::activate_cutover(&mut connection, 100)
            .expect("activate cutover");

        assert_eq!(
            graph
                .graph_membership(&connection, &identity, 100 + 90 * 86400)
                .await
                .expect("check grandfather membership"),
            MembershipStatus::Grandfathered
        );
    }

    #[tokio::test]
    async fn graph_membership_grandfathered_after_deadline_returns_lapsed() {
        let graph = test_graph_with_score(node(15), Some(50));
        let mut connection = invite_storage();
        connection
            .execute_batch(
                "CREATE TABLE identity_first_seen (
                    identity_hex TEXT PRIMARY KEY,
                    first_seen_at INTEGER NOT NULL
                );",
            )
            .expect("create first-seen table");
        let identity = node(123);
        connection
            .execute(
                "INSERT INTO identity_first_seen (identity_hex, first_seen_at)
                 VALUES (?1, ?2)",
                rusqlite::params![identity.to_hex(), 10],
            )
            .expect("seed first-seen identity");
        hal_storage::invite_storage::activate_cutover(&mut connection, 100)
            .expect("activate cutover");

        assert_eq!(
            graph
                .graph_membership(&connection, &identity, 100 + 90 * 86400 + 1)
                .await
                .expect("check lapsed membership"),
            MembershipStatus::Lapsed
        );
    }

    #[tokio::test]
    async fn graph_membership_no_proof_not_grandfathered_returns_unknown() {
        let graph = test_graph_with_score(node(16), Some(50));
        let connection = invite_storage();

        assert_eq!(
            graph
                .graph_membership(&connection, &node(124), 100)
                .await
                .expect("check unknown membership"),
            MembershipStatus::Unknown
        );
    }

    #[tokio::test]
    async fn status_banned_from_oracle() {
        let subject = node(12);
        let graph = test_graph(subject, Some(50), true);
        pin_node(&graph, &subject, 12);
        assert_eq!(graph.status(&subject, 1_000).await, GraphStatus::Banned);
    }

    #[tokio::test]
    async fn status_conflicted_from_hosts() {
        let subject = node(13);
        let graph = test_graph_with_score(subject, Some(50));
        pin_node(&graph, &subject, 13);
        let wrong_key = hex::encode(key(14).verifying_key().to_bytes());
        assert_eq!(
            graph
                .status_with_public_key(&subject, &wrong_key, 1_000)
                .await,
            GraphStatus::Conflicted
        );
    }

    #[tokio::test]
    async fn status_watching_from_badge_still_works() {
        let subject = node(15);
        let graph = test_graph_with_score(subject, Some(50));
        pin_node(&graph, &subject, 15);
        let issuer = node(16);
        let issuer_key = key(16);
        let now = BADGE_REFLECTION_PERIOD_SECS + 2_000;
        publish_badge(
            &graph,
            9004,
            subject,
            issuer,
            BadgeKind::Spammer,
            BadgeContext::ColdContact,
            now,
            &issuer_key,
        )
        .await;
        assert_eq!(graph.status(&subject, now).await, GraphStatus::Watching);
    }

    #[tokio::test]
    async fn status_warning_from_rate_tier() {
        let subject = node(30);
        let graph = test_graph_with_score(subject, Some(50));
        pin_node(&graph, &subject, 30);
        let now = BADGE_REFLECTION_PERIOD_SECS + 2_000;
        record_rate_rejects(&graph, &subject, 10, now - 200);

        assert_eq!(graph.status(&subject, now).await, GraphStatus::Warning);
    }

    #[tokio::test]
    async fn status_watching_from_rate_throttled() {
        let subject = node(31);
        let graph = test_graph_with_score(subject, Some(50));
        pin_node(&graph, &subject, 31);
        let now = BADGE_REFLECTION_PERIOD_SECS + 2_000;
        record_rate_rejects(&graph, &subject, 3, now - 200);

        assert_eq!(graph.status(&subject, now).await, GraphStatus::Watching);
    }

    #[tokio::test]
    async fn status_blocked_from_rate_becomes_banned() {
        let subject = node(32);
        let graph = test_graph_with_score(subject, Some(50));
        pin_node(&graph, &subject, 32);
        let now = BADGE_REFLECTION_PERIOD_SECS + 2_000;
        record_rate_rejects(&graph, &subject, 50, now - 200);

        assert_eq!(graph.status(&subject, now).await, GraphStatus::Banned);
        assert_eq!(
            graph
                .abuse_metrics
                .rate_tier_blocked_total
                .load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn status_combined_max_badge_and_rate() {
        let subject = node(33);
        let graph = test_graph_with_score(subject, Some(50));
        pin_node(&graph, &subject, 33);
        let issuer = node(34);
        let issuer_key = key(34);
        let now = BADGE_REFLECTION_PERIOD_SECS + 2_000;
        record_rate_rejects(&graph, &subject, 10, now - 200);
        publish_badge(
            &graph,
            9010,
            subject,
            issuer,
            BadgeKind::Spammer,
            BadgeContext::ColdContact,
            now,
            &issuer_key,
        )
        .await;

        assert_eq!(graph.status(&subject, now).await, GraphStatus::Warning);
    }

    #[tokio::test]
    async fn status_rate_metrics_increment() {
        let subject = node(35);
        let graph = test_graph_with_score(subject, Some(50));
        pin_node(&graph, &subject, 35);
        let now = BADGE_REFLECTION_PERIOD_SECS + 2_000;
        record_rate_rejects(&graph, &subject, 10, now - 200);

        assert_eq!(graph.status(&subject, now).await, GraphStatus::Warning);
        assert_eq!(
            graph
                .abuse_metrics
                .rate_tier_warning_total
                .load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn banned_priority_over_all() {
        let subject = node(17);
        let graph = test_graph(subject, Some(50), true);
        pin_node(&graph, &subject, 17);
        let issuer = node(18);
        let issuer_key = key(18);
        pin_node(&graph, &issuer, 18);
        let now = BADGE_REFLECTION_PERIOD_SECS + 2_000;
        publish_badge(
            &graph,
            9005,
            subject,
            issuer,
            BadgeKind::Spammer,
            BadgeContext::KnownContact,
            now,
            &issuer_key,
        )
        .await;
        let wrong_key = hex::encode(key(19).verifying_key().to_bytes());
        assert_eq!(
            graph
                .status_with_public_key(&subject, &wrong_key, now)
                .await,
            GraphStatus::Banned
        );
    }

    #[test]
    fn rate_multiplier_ingraph_knownlimited_is_1() {
        assert_eq!(GraphStatus::InGraph.rate_multiplier(), 1.0);
        assert_eq!(GraphStatus::KnownLimited.rate_multiplier(), 1.0);
    }

    #[test]
    fn rate_multiplier_watching_is_0_1() {
        assert_eq!(GraphStatus::Watching.rate_multiplier(), 0.1);
    }

    #[test]
    fn rate_multiplier_warning_is_0_01() {
        assert_eq!(GraphStatus::Warning.rate_multiplier(), 0.01);
    }

    #[test]
    fn rate_multiplier_hostile_is_0() {
        assert_eq!(GraphStatus::Banned.rate_multiplier(), 0.0);
        assert_eq!(GraphStatus::Stigmatized.rate_multiplier(), 0.0);
        assert_eq!(GraphStatus::Conflicted.rate_multiplier(), 0.0);
        assert_eq!(GraphStatus::Unknown.rate_multiplier(), 0.0);
    }

    #[test]
    fn is_hostile_only_banned_stigmatized_conflicted() {
        assert!(GraphStatus::Banned.is_hostile());
        assert!(GraphStatus::Stigmatized.is_hostile());
        assert!(GraphStatus::Conflicted.is_hostile());
        assert!(!GraphStatus::Watching.is_hostile());
        assert!(!GraphStatus::Warning.is_hostile());
        assert!(!GraphStatus::Unknown.is_hostile());
        assert!(!GraphStatus::KnownLimited.is_hostile());
        assert!(!GraphStatus::InGraph.is_hostile());
    }

    #[test]
    fn is_cold_admissible_only_ingraph_knownlimited() {
        assert!(GraphStatus::InGraph.is_cold_admissible());
        assert!(GraphStatus::KnownLimited.is_cold_admissible());
        assert!(!GraphStatus::Banned.is_cold_admissible());
        assert!(!GraphStatus::Stigmatized.is_cold_admissible());
        assert!(!GraphStatus::Conflicted.is_cold_admissible());
        assert!(!GraphStatus::Watching.is_cold_admissible());
        assert!(!GraphStatus::Warning.is_cold_admissible());
        assert!(!GraphStatus::Unknown.is_cold_admissible());
    }

    #[tokio::test]
    async fn warning_not_returned_without_rate_rejects() {
        let subject = node(20);
        let graph = test_graph_with_score(subject, Some(50));
        assert_ne!(graph.status(&subject, 1_000).await, GraphStatus::Warning);
        pin_node(&graph, &subject, 20);
        assert_ne!(graph.status(&subject, 1_000).await, GraphStatus::Warning);
    }

    #[test]
    fn graph_status_is_admissible_correct() {
        assert!(GraphStatus::InGraph.is_admissible());
        assert!(GraphStatus::KnownLimited.is_admissible());
        assert!(GraphStatus::Watching.is_admissible());
        assert!(GraphStatus::Warning.is_admissible());
        assert!(!GraphStatus::Banned.is_admissible());
        assert!(!GraphStatus::Stigmatized.is_admissible());
        assert!(!GraphStatus::Conflicted.is_admissible());
        assert!(!GraphStatus::Unknown.is_admissible());
    }

    #[test]
    fn gate_decision_ingraph_is_allow() {
        assert_eq!(
            TrustGateDecision::from_status(GraphStatus::InGraph),
            TrustGateDecision::Allow
        );
    }

    #[test]
    fn gate_decision_knownlimited_is_allow_not_throttle() {
        assert_eq!(
            TrustGateDecision::from_status(GraphStatus::KnownLimited),
            TrustGateDecision::Allow
        );
    }

    #[test]
    fn gate_decision_watching_throttles_0_1() {
        assert_eq!(
            TrustGateDecision::from_status(GraphStatus::Watching),
            TrustGateDecision::Throttle {
                rate_multiplier: 0.1
            }
        );
    }

    #[test]
    fn gate_decision_warning_throttles_0_01() {
        assert_eq!(
            TrustGateDecision::from_status(GraphStatus::Warning),
            TrustGateDecision::Throttle {
                rate_multiplier: 0.01
            }
        );
    }

    #[test]
    fn gate_decision_unknown_blocks_not_in_graph() {
        assert_eq!(
            TrustGateDecision::from_status(GraphStatus::Unknown),
            TrustGateDecision::Block {
                reason: BlockReason::NotInGraph
            }
        );
    }

    #[test]
    fn gate_decision_conflicted_blocks_conflicted() {
        assert_eq!(
            TrustGateDecision::from_status(GraphStatus::Conflicted),
            TrustGateDecision::Block {
                reason: BlockReason::Conflicted
            }
        );
    }

    #[test]
    fn gate_decision_stigmatized_blocks_stigmatized() {
        assert_eq!(
            TrustGateDecision::from_status(GraphStatus::Stigmatized),
            TrustGateDecision::Block {
                reason: BlockReason::Stigmatized
            }
        );
    }

    #[test]
    fn gate_decision_banned_blocks_banned() {
        assert_eq!(
            TrustGateDecision::from_status(GraphStatus::Banned),
            TrustGateDecision::Block {
                reason: BlockReason::Banned
            }
        );
    }

    #[test]
    fn gate_decision_rate_multiplier_matches_throttle() {
        assert_eq!(
            TrustGateDecision::from_status(GraphStatus::InGraph).rate_multiplier(),
            1.0
        );
        assert_eq!(
            TrustGateDecision::from_status(GraphStatus::Watching).rate_multiplier(),
            0.1
        );
        assert_eq!(
            TrustGateDecision::from_status(GraphStatus::Warning).rate_multiplier(),
            0.01
        );
        assert_eq!(
            TrustGateDecision::from_status(GraphStatus::Banned).rate_multiplier(),
            0.0
        );
    }

    #[test]
    fn gate_decision_is_allowed_matches_allow() {
        assert!(TrustGateDecision::from_status(GraphStatus::InGraph).is_allowed());
        assert!(!TrustGateDecision::from_status(GraphStatus::Watching).is_allowed());
        assert!(!TrustGateDecision::from_status(GraphStatus::Unknown).is_allowed());
    }

    #[test]
    fn gate_decision_is_blocked_matches_block() {
        assert!(TrustGateDecision::from_status(GraphStatus::Banned).is_blocked());
        assert!(!TrustGateDecision::from_status(GraphStatus::InGraph).is_blocked());
        assert!(!TrustGateDecision::from_status(GraphStatus::Warning).is_blocked());
    }

    #[test]
    fn block_reason_platform_is_reserve_but_constructible() {
        assert_eq!(
            BlockReason::Platform("biometric fail".into()),
            BlockReason::Platform("biometric fail".into())
        );
    }

    #[tokio::test]
    async fn gate_for_unknown_identity_blocks() {
        let graph = test_graph_with_score(node(40), None);
        assert_eq!(
            graph.gate(&node(40), 1_000).await,
            TrustGateDecision::Block {
                reason: BlockReason::NotInGraph
            }
        );
    }

    #[tokio::test]
    async fn gate_for_ingraph_identity_allows() {
        let subject = node(41);
        let graph = test_graph_with_score(subject, Some(50));
        pin_node(&graph, &subject, 41);
        assert_eq!(graph.gate(&subject, 1_000).await, TrustGateDecision::Allow);
    }

    #[tokio::test]
    async fn gate_with_public_key_conflict_blocks_conflicted() {
        let subject = node(42);
        let graph = test_graph_with_score(subject, Some(50));
        pin_node(&graph, &subject, 42);
        let wrong_key = hex::encode(key(43).verifying_key().to_bytes());
        assert_eq!(
            graph
                .gate_with_public_key(&subject, &wrong_key, 1_000)
                .await,
            TrustGateDecision::Block {
                reason: BlockReason::Conflicted
            }
        );
    }

    #[tokio::test]
    async fn gate_stigmatized_overrides_ingraph_score() {
        let subject = node(44);
        let graph = test_graph_with_score(subject, Some(80));
        pin_node(&graph, &subject, 44);
        let issuer = node(45);
        let issuer_key = key(45);
        pin_node(&graph, &issuer, 45);
        let now = BADGE_REFLECTION_PERIOD_SECS + 2_000;
        publish_badge(
            &graph,
            9044,
            subject,
            issuer,
            BadgeKind::Spammer,
            BadgeContext::KnownContact,
            now,
            &issuer_key,
        )
        .await;
        assert_eq!(
            graph.gate(&subject, now).await,
            TrustGateDecision::Block {
                reason: BlockReason::Stigmatized
            }
        );
    }

    #[tokio::test]
    async fn oracle_restricted_unknown_with_timeout_contacts() {
        let subject = node(46);
        let graph =
            test_graph_with_action(subject, None, false, Some(OracleAction::TimeoutContacts));
        assert_eq!(
            graph.status(&subject, 1_000).await,
            GraphStatus::OracleRestricted(OracleAction::TimeoutContacts)
        );
    }

    #[tokio::test]
    async fn oracle_restricted_unknown_with_block_new_messages() {
        let subject = node(47);
        let graph =
            test_graph_with_action(subject, None, false, Some(OracleAction::BlockNewMessages));
        assert_eq!(
            graph.status(&subject, 1_000).await,
            GraphStatus::OracleRestricted(OracleAction::BlockNewMessages)
        );
    }

    #[tokio::test]
    async fn oracle_not_restricted_unknown_with_show_badge() {
        let subject = node(48);
        let graph = test_graph_with_action(subject, None, false, Some(OracleAction::ShowBadge));
        assert_eq!(graph.status(&subject, 1_000).await, GraphStatus::Unknown);
    }

    #[tokio::test]
    async fn oracle_not_restricted_unknown_with_normal() {
        let subject = node(49);
        let graph = test_graph_with_action(subject, None, false, Some(OracleAction::Normal));
        assert_eq!(graph.status(&subject, 1_000).await, GraphStatus::Unknown);
    }

    #[tokio::test]
    async fn oracle_not_restricted_when_pinned() {
        let subject = node(50);
        let graph = test_graph_with_action(
            subject,
            Some(50),
            false,
            Some(OracleAction::BlockNewMessages),
        );
        pin_node(&graph, &subject, 50);
        assert_eq!(graph.status(&subject, 1_000).await, GraphStatus::InGraph);
    }

    #[tokio::test]
    async fn oracle_restricted_higher_than_warning() {
        let subject = node(51);
        let graph =
            test_graph_with_action(subject, None, false, Some(OracleAction::BlockNewMessages));
        let now = BADGE_REFLECTION_PERIOD_SECS + 2_000;
        record_rate_rejects(&graph, &subject, 10, now - 200);
        assert_eq!(
            graph.status(&subject, now).await,
            GraphStatus::OracleRestricted(OracleAction::BlockNewMessages)
        );
    }

    #[tokio::test]
    async fn oracle_restricted_higher_than_unknown() {
        let subject = node(52);
        let graph =
            test_graph_with_action(subject, None, false, Some(OracleAction::TimeoutContacts));
        assert_eq!(
            graph.status(&subject, 1_000).await,
            GraphStatus::OracleRestricted(OracleAction::TimeoutContacts)
        );
    }

    #[test]
    fn gate_decision_oracle_restricted_blocks_with_reason() {
        assert_eq!(
            TrustGateDecision::from_status(GraphStatus::OracleRestricted(
                OracleAction::TimeoutContacts
            )),
            TrustGateDecision::Block {
                reason: BlockReason::OracleRestricted(OracleAction::TimeoutContacts)
            }
        );
    }

    #[tokio::test]
    async fn oracle_restricted_not_applied_to_banned() {
        let subject = node(53);
        let graph = test_graph_with_action(
            subject,
            Some(50),
            true,
            Some(OracleAction::BlockNewMessages),
        );
        pin_node(&graph, &subject, 53);
        assert_eq!(graph.status(&subject, 1_000).await, GraphStatus::Banned);
    }

    #[tokio::test]
    async fn oracle_restricted_not_applied_to_stigmatized() {
        let subject = node(54);
        let graph =
            test_graph_with_action(subject, None, false, Some(OracleAction::BlockNewMessages));
        let issuer = node(55);
        let issuer_key = key(55);
        pin_node(&graph, &issuer, 55);
        let now = BADGE_REFLECTION_PERIOD_SECS + 2_000;
        publish_badge(
            &graph,
            9054,
            subject,
            issuer,
            BadgeKind::Spammer,
            BadgeContext::KnownContact,
            now,
            &issuer_key,
        )
        .await;
        assert_eq!(graph.status(&subject, now).await, GraphStatus::Stigmatized);
    }

    #[test]
    fn oracle_restricted_is_not_hostile() {
        let status = GraphStatus::OracleRestricted(OracleAction::TimeoutContacts);
        assert!(!status.is_hostile());
        assert!(!status.is_admissible());
    }

    #[test]
    fn oracle_restricted_rate_multiplier_is_zero() {
        assert_eq!(
            GraphStatus::OracleRestricted(OracleAction::BlockNewMessages).rate_multiplier(),
            0.0
        );
        assert!(!GraphStatus::OracleRestricted(OracleAction::TimeoutContacts).is_cold_admissible());
    }
}
