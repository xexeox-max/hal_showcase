use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::dht::group::{Group, GroupId};
use crate::dht::NodeId;

/// ID бейджа.
pub type BadgeId = u64;

/// Максимальная длина reason.
pub const BADGE_MAX_REASON_LEN: usize = 256;

/// Временный бейдж по умолчанию: 30 дней.
pub const BADGE_DEFAULT_TTL_SECS: u64 = 30 * 24 * 3600;
pub const BADGE_MAX_MESSAGE_IDS: usize = 64;
pub const BADGE_MAX_MESSAGE_ID_LEN: usize = 128;
pub const BADGE_REFLECTION_PERIOD_SECS: u64 = 6 * 3600;
pub const BADGE_STIGMA_TTL_SECS: u64 = BADGE_DEFAULT_TTL_SECS;

#[derive(Debug, Default)]
pub struct BadgeMetrics {
    pub badge_published_total: AtomicU64,
    pub badge_fetched_total: AtomicU64,
    pub badge_verify_failed_total: AtomicU64,
    pub badge_stigma_active_current: AtomicU64,
    pub badge_watching_current: AtomicU64,
    pub fetch_rounds_total: AtomicU64,
    pub fetch_subjects_total: AtomicU64,
    pub fetch_badges_merged_total: AtomicU64,
    pub fetch_failed_total: AtomicU64,
    pub store_stale_current: AtomicU64,
}

impl BadgeMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> BadgeMetricsSnapshot {
        BadgeMetricsSnapshot {
            badge_published_total: self.badge_published_total.load(Ordering::Relaxed),
            badge_fetched_total: self.badge_fetched_total.load(Ordering::Relaxed),
            badge_verify_failed_total: self.badge_verify_failed_total.load(Ordering::Relaxed),
            badge_stigma_active_current: self.badge_stigma_active_current.load(Ordering::Relaxed),
            badge_watching_current: self.badge_watching_current.load(Ordering::Relaxed),
            fetch_rounds_total: self.fetch_rounds_total.load(Ordering::Relaxed),
            fetch_subjects_total: self.fetch_subjects_total.load(Ordering::Relaxed),
            fetch_badges_merged_total: self.fetch_badges_merged_total.load(Ordering::Relaxed),
            fetch_failed_total: self.fetch_failed_total.load(Ordering::Relaxed),
            store_stale_current: self.store_stale_current.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BadgeMetricsSnapshot {
    pub badge_published_total: u64,
    pub badge_fetched_total: u64,
    pub badge_verify_failed_total: u64,
    pub badge_stigma_active_current: u64,
    pub badge_watching_current: u64,
    pub fetch_rounds_total: u64,
    pub fetch_subjects_total: u64,
    pub fetch_badges_merged_total: u64,
    pub fetch_failed_total: u64,
    pub store_stale_current: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BadgeContext {
    ColdContact,
    KnownContact,
    ChannelMessage,
}

/// Тип бейджа.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BadgeKind {
    Spammer,
    Troll,
    Flooder,
    Advertiser,
    Custom(String),
}

/// Социальная метка на узле.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Badge {
    pub id: BadgeId,
    pub subject_id: NodeId,
    pub group_id: Option<GroupId>,
    pub kind: BadgeKind,
    pub message_ids: Vec<String>,
    pub context: BadgeContext,
    pub reason: String,
    pub assigned_by: NodeId,
    pub assigned_at: u64,
    pub expires_at: Option<u64>,
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
}

mod signature_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(signature: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(signature)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        bytes.try_into().map_err(|bytes: Vec<u8>| {
            serde::de::Error::custom(format!("signature must be 64 bytes, got {}", bytes.len()))
        })
    }
}

#[derive(Debug, Serialize)]
struct BadgePayload<'a> {
    id: BadgeId,
    subject_id: &'a NodeId,
    group_id: &'a Option<GroupId>,
    kind: &'a BadgeKind,
    message_ids: &'a [String],
    context: &'a BadgeContext,
    reason: &'a str,
    assigned_by: &'a NodeId,
    assigned_at: u64,
    expires_at: &'a Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadgePolicy {
    pub max_reason_len: usize,
    pub default_ttl_secs: u64,
}

impl Default for BadgePolicy {
    fn default() -> Self {
        Self {
            max_reason_len: BADGE_MAX_REASON_LEN,
            default_ttl_secs: BADGE_DEFAULT_TTL_SECS,
        }
    }
}

impl Badge {
    pub fn create(
        id: BadgeId,
        subject_id: NodeId,
        group_id: Option<GroupId>,
        kind: BadgeKind,
        message_ids: Vec<String>,
        context: BadgeContext,
        reason: String,
        assigned_by: NodeId,
        assigned_at: u64,
        expires_at: Option<u64>,
        signing_key: &SigningKey,
    ) -> Result<Self, BadgeError> {
        validate_message_ids(&message_ids)?;
        let mut reason = reason;
        if reason.len() > BADGE_MAX_REASON_LEN {
            reason.truncate(BADGE_MAX_REASON_LEN);
        }

        let payload = BadgePayload {
            id,
            subject_id: &subject_id,
            group_id: &group_id,
            kind: &kind,
            message_ids: &message_ids,
            context: &context,
            reason: &reason,
            assigned_by: &assigned_by,
            assigned_at,
            expires_at: &expires_at,
        };
        let bytes = serde_json::to_vec(&payload).unwrap_or_default();
        let signature = signing_key.sign(&bytes).to_bytes();

        Ok(Self {
            id,
            subject_id,
            group_id,
            kind,
            message_ids,
            context,
            reason,
            assigned_by,
            assigned_at,
            expires_at,
            signature,
        })
    }

    pub fn verify(&self, admin_pubkey: &VerifyingKey, now: u64) -> Result<(), BadgeError> {
        if let Some(expires_at) = self.expires_at {
            if now > expires_at {
                return Err(BadgeError::Expired);
            }
        }

        if self.reason.len() > BADGE_MAX_REASON_LEN {
            return Err(BadgeError::ReasonTooLong);
        }
        validate_message_ids(&self.message_ids)?;

        let payload = BadgePayload {
            id: self.id,
            subject_id: &self.subject_id,
            group_id: &self.group_id,
            kind: &self.kind,
            message_ids: &self.message_ids,
            context: &self.context,
            reason: &self.reason,
            assigned_by: &self.assigned_by,
            assigned_at: self.assigned_at,
            expires_at: &self.expires_at,
        };
        let bytes = serde_json::to_vec(&payload).map_err(|_| BadgeError::Malformed)?;
        let signature = Signature::from_bytes(&self.signature);
        admin_pubkey
            .verify(&bytes, &signature)
            .map_err(|_| BadgeError::InvalidSignature)
    }
}

fn validate_message_ids(message_ids: &[String]) -> Result<(), BadgeError> {
    if message_ids.is_empty() {
        return Err(BadgeError::EmptyMessageIds);
    }
    if message_ids.len() > BADGE_MAX_MESSAGE_IDS {
        return Err(BadgeError::TooManyMessageIds);
    }
    if message_ids
        .iter()
        .any(|message_id| message_id.len() > BADGE_MAX_MESSAGE_ID_LEN)
    {
        return Err(BadgeError::MessageIdTooLong);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BadgeError {
    InvalidSignature,
    Malformed,
    Expired,
    ReasonTooLong,
    EmptyMessageIds,
    TooManyMessageIds,
    MessageIdTooLong,
    NotAuthorized,
    NotFound,
}

impl fmt::Display for BadgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "invalid badge signature"),
            Self::Malformed => write!(f, "malformed badge"),
            Self::Expired => write!(f, "badge expired"),
            Self::ReasonTooLong => write!(f, "badge reason too long"),
            Self::EmptyMessageIds => write!(f, "badge requires message evidence"),
            Self::TooManyMessageIds => write!(f, "too many badge message IDs"),
            Self::MessageIdTooLong => write!(f, "badge message ID too long"),
            Self::NotAuthorized => write!(f, "not authorized to change badge"),
            Self::NotFound => write!(f, "badge not found"),
        }
    }
}

impl std::error::Error for BadgeError {}

/// In-memory хранилище бейджей.
#[derive(Debug, Default)]
pub struct BadgeRegistry {
    badges: HashMap<BadgeId, Badge>,
    next_id: BadgeId,
}

impl BadgeRegistry {
    pub fn new() -> Self {
        Self {
            badges: HashMap::new(),
            next_id: 1,
        }
    }

    pub fn add(&mut self, badge: Badge) -> Result<(), BadgeError> {
        if self.badges.contains_key(&badge.id) {
            return Err(BadgeError::Malformed);
        }
        if badge.id >= self.next_id {
            self.next_id = badge.id.saturating_add(1);
        }
        self.badges.insert(badge.id, badge);
        Ok(())
    }

    pub fn remove(&mut self, id: BadgeId) -> Option<Badge> {
        self.badges.remove(&id)
    }

    pub fn by_id(&self, id: BadgeId) -> Option<&Badge> {
        self.badges.get(&id)
    }

    pub fn of_subject(&self, subject_id: &NodeId) -> Vec<&Badge> {
        self.badges
            .values()
            .filter(|badge| badge.subject_id == *subject_id)
            .collect()
    }

    pub fn of_subject_in_group(&self, subject_id: &NodeId, group_id: GroupId) -> Vec<&Badge> {
        self.badges
            .values()
            .filter(|badge| badge.subject_id == *subject_id && badge.group_id == Some(group_id))
            .collect()
    }

    pub fn cleanup_expired(&mut self, now: u64) -> usize {
        let expired: Vec<BadgeId> = self
            .badges
            .iter()
            .filter_map(|(id, badge)| {
                if badge.expires_at.is_some_and(|expires_at| now > expires_at) {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();

        let removed = expired.len();
        for id in expired {
            self.badges.remove(&id);
        }
        removed
    }

    pub fn len(&self) -> usize {
        self.badges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.badges.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IssuerContext {
    pub score: f32,
    pub is_contact_of_subject: bool,
    pub under_stigma: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CounterClaim {
    pub badge_id: String,
    pub jury_verdict_id: String,
    pub cleared_at: u64,
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq)]
pub enum StigmaLevel {
    Clean,
    Watching {
        weight: f32,
        badge_count: u32,
    },
    Stigma {
        weight: f32,
        badge_count: u32,
        since: u64,
    },
    Cleared {
        badge_count: u32,
        cleared_at: u64,
    },
}

/// Append-only badge history plus jury counter-claims.
#[derive(Debug, Default)]
pub struct BadgeStore {
    badges: HashMap<NodeId, Vec<Badge>>,
    counter_claims: HashMap<String, CounterClaim>,
    last_synced_at: Option<u64>,
    /// TODO(PR-C): accumulate and apply vouch weights during appeal/reflection.
    pub vouch_weights: HashMap<NodeId, f32>,
}

impl BadgeStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_synced(&mut self, now: u64) {
        self.last_synced_at = Some(now);
    }

    pub fn last_synced_at(&self) -> Option<u64> {
        self.last_synced_at
    }

    pub fn is_stale(&self, now: u64, threshold_secs: u64) -> bool {
        self.last_synced_at
            .is_none_or(|last_synced_at| now.saturating_sub(last_synced_at) > threshold_secs)
    }

    pub fn publish(&mut self, badge: Badge) -> Result<(), BadgeError> {
        validate_message_ids(&badge.message_ids)?;
        if badge.reason.len() > BADGE_MAX_REASON_LEN {
            return Err(BadgeError::ReasonTooLong);
        }
        if let Some(existing) = self
            .badges
            .values()
            .flatten()
            .find(|entry| entry.id == badge.id)
        {
            return if existing == &badge {
                Ok(())
            } else {
                Err(BadgeError::Malformed)
            };
        }
        self.badges.entry(badge.subject_id).or_default().push(badge);
        Ok(())
    }

    pub fn record_counter_claim(&mut self, claim: CounterClaim) -> Result<(), BadgeError> {
        let badge_id = claim
            .badge_id
            .parse::<BadgeId>()
            .map_err(|_| BadgeError::Malformed)?;
        if !self
            .badges
            .values()
            .flatten()
            .any(|badge| badge.id == badge_id)
        {
            return Err(BadgeError::NotFound);
        }
        match self.counter_claims.get(&claim.badge_id) {
            Some(existing) if existing == &claim => Ok(()),
            Some(_) => Err(BadgeError::Malformed),
            None => {
                self.counter_claims.insert(claim.badge_id.clone(), claim);
                Ok(())
            }
        }
    }

    pub fn badges_for_subject(&self, subject: &NodeId) -> Vec<Badge> {
        self.badges.get(subject).cloned().unwrap_or_default()
    }

    pub fn contains_badge(&self, badge_id: BadgeId) -> bool {
        self.badges
            .values()
            .flatten()
            .any(|badge| badge.id == badge_id)
    }

    /// Aggregate badge weight with one bounded issuer-stigma lookup.
    ///
    /// The callback supplies score, relationship and any already-known stigma.
    /// The store may inspect an issuer's own badges once; at that leaf it does
    /// not recurse further and trusts the callback's under_stigma value.
    pub fn stigma_of<F>(&self, subject: &NodeId, issuer_context: F, now: u64) -> StigmaLevel
    where
        F: Fn(&NodeId) -> IssuerContext,
    {
        self.stigma_of_inner(subject, &issuer_context, now, 0)
    }

    fn stigma_of_inner<F>(
        &self,
        subject: &NodeId,
        issuer_context: &F,
        now: u64,
        depth: u8,
    ) -> StigmaLevel
    where
        F: Fn(&NodeId) -> IssuerContext,
    {
        let Some(badges) = self.badges.get(subject) else {
            return StigmaLevel::Clean;
        };
        let historical_count = u32::try_from(badges.len()).unwrap_or(u32::MAX);
        let mut cleared_at = None;
        let mut watching_weight = 0.0f32;
        let mut watching_count = 0u32;
        let mut stigma_weight = 0.0f32;
        let mut stigma_count = 0u32;
        let mut contact_evidence = false;
        let mut stigma_since = now;

        for badge in badges {
            if badge.expires_at.is_some_and(|expires_at| now > expires_at) {
                continue;
            }
            let badge_key = badge.id.to_string();
            if let Some(counter_claim) = self.counter_claims.get(&badge_key) {
                cleared_at = Some(cleared_at.unwrap_or(0u64).max(counter_claim.cleared_at));
                continue;
            }

            let mut context = issuer_context(&badge.assigned_by);
            if depth == 0 {
                context.under_stigma |= matches!(
                    self.stigma_of_inner(&badge.assigned_by, issuer_context, now, 1),
                    StigmaLevel::Stigma { .. }
                );
            }
            let weight = badge_weight(badge, context, now);
            if weight <= 0.0 {
                continue;
            }

            watching_weight += weight;
            watching_count = watching_count.saturating_add(1);
            if now.saturating_sub(badge.assigned_at) < BADGE_REFLECTION_PERIOD_SECS {
                continue;
            }

            stigma_weight += weight;
            stigma_count = stigma_count.saturating_add(1);
            stigma_since = stigma_since.min(
                badge
                    .assigned_at
                    .saturating_add(BADGE_REFLECTION_PERIOD_SECS),
            );
            contact_evidence |= context.is_contact_of_subject && !badge.message_ids.is_empty();
        }

        if contact_evidence || (stigma_count >= 3 && stigma_weight >= 2.0) {
            return StigmaLevel::Stigma {
                weight: stigma_weight,
                badge_count: stigma_count,
                since: stigma_since,
            };
        }
        if watching_count > 0 {
            return StigmaLevel::Watching {
                weight: watching_weight,
                badge_count: watching_count,
            };
        }
        if let Some(cleared_at) = cleared_at {
            return StigmaLevel::Cleared {
                badge_count: historical_count,
                cleared_at,
            };
        }
        StigmaLevel::Clean
    }
}

fn badge_weight(badge: &Badge, issuer: IssuerContext, now: u64) -> f32 {
    let base_weight = if issuer.under_stigma {
        0.0
    } else if issuer.is_contact_of_subject {
        1.0
    } else {
        0.1
    };
    let score_multiplier = if issuer.score < 0.3 {
        0.3
    } else if issuer.score < 0.6 {
        0.6
    } else {
        1.0
    };
    let age = now.saturating_sub(badge.assigned_at) as f64;
    let decay = (1.0 - age / BADGE_STIGMA_TTL_SECS as f64).clamp(0.0, 1.0) as f32;
    base_weight * score_multiplier * decay
}

/// Поставить бейдж. Только админ группы.
pub fn assign_badge(
    badge: Badge,
    admin_pubkey: &VerifyingKey,
    group: &Group,
    registry: &mut BadgeRegistry,
    now: u64,
) -> Result<BadgeId, BadgeError> {
    let admin_id = NodeId::from_public_key(admin_pubkey);
    if !group.members.contains(&admin_id) {
        return Err(BadgeError::NotAuthorized);
    }

    if let Some(group_id) = badge.group_id {
        if group.id != group_id {
            return Err(BadgeError::NotAuthorized);
        }
    }

    let badge_id = badge.id;
    badge.verify(admin_pubkey, now)?;
    registry.add(badge)?;
    Ok(badge_id)
}

/// Снять бейдж.
pub fn revoke_badge(
    badge_id: BadgeId,
    admin_pubkey: &VerifyingKey,
    registry: &mut BadgeRegistry,
) -> Result<Badge, BadgeError> {
    let badge = registry
        .by_id(badge_id)
        .cloned()
        .ok_or(BadgeError::NotFound)?;

    let admin_id = NodeId::from_public_key(admin_pubkey);
    if badge.assigned_by != admin_id {
        return Err(BadgeError::NotAuthorized);
    }

    registry.remove(badge_id).ok_or(BadgeError::NotFound)
}

/// Список бейджей на узле.
pub fn badges_of<'a>(registry: &'a BadgeRegistry, subject_id: &NodeId) -> Vec<&'a Badge> {
    registry.of_subject(subject_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(seed: u8) -> NodeId {
        NodeId::from_bytes([seed; 32])
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn evidence_badge(
        id: BadgeId,
        subject: NodeId,
        issuer: NodeId,
        context: BadgeContext,
        assigned_at: u64,
    ) -> Badge {
        Badge::create(
            id,
            subject,
            None,
            BadgeKind::Spammer,
            vec![format!("message-{id}")],
            context,
            "repeated unsolicited messages".into(),
            issuer,
            assigned_at,
            None,
            &key((id % 250) as u8 + 1),
        )
        .expect("valid evidence badge")
    }

    fn stranger_context(_: &NodeId) -> IssuerContext {
        IssuerContext {
            score: 0.8,
            is_contact_of_subject: false,
            under_stigma: false,
        }
    }

    #[test]
    fn badge_create_and_verify() {
        let admin_key = key(1);
        let admin_pubkey = admin_key.verifying_key();
        let badge = Badge::create(
            1,
            node(10),
            Some(7),
            BadgeKind::Troll,
            vec!["msg-1".into()],
            BadgeContext::KnownContact,
            "spam".to_string(),
            node(20),
            100,
            Some(1000),
            &admin_key,
        )
        .expect("valid badge");

        assert!(badge.verify(&admin_pubkey, 500).is_ok());
    }

    #[test]
    fn badge_expired_rejected() {
        let admin_key = key(2);
        let admin_pubkey = admin_key.verifying_key();
        let badge = Badge::create(
            2,
            node(11),
            None,
            BadgeKind::Flooder,
            vec!["msg-2".into()],
            BadgeContext::ColdContact,
            "flooding".to_string(),
            node(21),
            100,
            Some(200),
            &admin_key,
        )
        .expect("valid badge");

        assert_eq!(badge.verify(&admin_pubkey, 201), Err(BadgeError::Expired));
    }

    #[test]
    fn badge_invalid_signature_rejected() {
        let admin_key = key(3);
        let wrong_key = key(4);
        let badge = Badge::create(
            3,
            node(12),
            None,
            BadgeKind::Spammer,
            vec!["msg-3".into()],
            BadgeContext::ColdContact,
            "spam".to_string(),
            node(22),
            100,
            None,
            &admin_key,
        )
        .expect("valid badge");

        assert_eq!(
            badge.verify(&wrong_key.verifying_key(), 150),
            Err(BadgeError::InvalidSignature)
        );
    }

    #[test]
    fn badge_reason_truncated() {
        let admin_key = key(5);
        let admin_pubkey = admin_key.verifying_key();
        let long_reason = "x".repeat(BADGE_MAX_REASON_LEN + 50);
        let badge = Badge::create(
            4,
            node(13),
            None,
            BadgeKind::Custom("test".to_string()),
            vec!["msg-4".into()],
            BadgeContext::KnownContact,
            long_reason,
            node(23),
            100,
            None,
            &admin_key,
        )
        .expect("valid badge");

        assert_eq!(badge.reason.len(), BADGE_MAX_REASON_LEN);
        assert!(badge.verify(&admin_pubkey, 200).is_ok());
    }

    #[test]
    fn registry_add_and_get() {
        let mut registry = BadgeRegistry::new();
        let badge = Badge::create(
            1,
            node(14),
            None,
            BadgeKind::Advertiser,
            vec!["msg-5".into()],
            BadgeContext::KnownContact,
            "ad".to_string(),
            node(24),
            200,
            None,
            &key(6),
        )
        .expect("valid badge");

        assert!(registry.add(badge.clone()).is_ok());
        assert_eq!(registry.by_id(1).unwrap().id, 1);
    }

    #[test]
    fn registry_of_subject() {
        let mut registry = BadgeRegistry::new();
        let subject = node(15);
        let badge_a = Badge::create(
            1,
            subject,
            Some(8),
            BadgeKind::Spammer,
            vec!["msg-6".into()],
            BadgeContext::KnownContact,
            "a".to_string(),
            node(25),
            200,
            None,
            &key(7),
        )
        .expect("valid badge");
        let badge_b = Badge::create(
            2,
            node(16),
            Some(8),
            BadgeKind::Troll,
            vec!["msg-7".into()],
            BadgeContext::KnownContact,
            "b".to_string(),
            node(26),
            200,
            None,
            &key(8),
        )
        .expect("valid badge");

        registry.add(badge_a).unwrap();
        registry.add(badge_b).unwrap();

        let subject_badges = registry.of_subject(&subject);
        assert_eq!(subject_badges.len(), 1);
        assert_eq!(subject_badges[0].id, 1);
    }

    #[test]
    fn assign_badge_ok() {
        let mut registry = BadgeRegistry::new();
        let admin_key = key(9);
        let admin_pubkey = admin_key.verifying_key();
        let subject = node(17);
        let group = Group {
            id: 9,
            name: Some("family".into()),
            members: [NodeId::from_public_key(&admin_pubkey), subject]
                .into_iter()
                .collect(),
        };
        let badge = Badge::create(
            1,
            subject,
            Some(group.id),
            BadgeKind::Spammer,
            vec!["msg-8".into()],
            BadgeContext::KnownContact,
            "spam".to_string(),
            NodeId::from_public_key(&admin_pubkey),
            200,
            None,
            &admin_key,
        )
        .expect("valid badge");

        assert_eq!(
            assign_badge(badge, &admin_pubkey, &group, &mut registry, 500),
            Ok(1)
        );
    }

    #[test]
    fn cleanup_expired_removes() {
        let mut registry = BadgeRegistry::new();
        let badge_a = Badge::create(
            1,
            node(18),
            None,
            BadgeKind::Flooder,
            vec!["msg-9".into()],
            BadgeContext::KnownContact,
            "a".to_string(),
            node(27),
            10,
            Some(20),
            &key(10),
        )
        .expect("valid badge");
        let badge_b = Badge::create(
            2,
            node(19),
            None,
            BadgeKind::Advertiser,
            vec!["msg-10".into()],
            BadgeContext::KnownContact,
            "b".to_string(),
            node(28),
            10,
            Some(50),
            &key(11),
        )
        .expect("valid badge");

        registry.add(badge_a).unwrap();
        registry.add(badge_b).unwrap();

        assert_eq!(registry.cleanup_expired(30), 1);
        assert!(registry.by_id(1).is_none());
        assert!(registry.by_id(2).is_some());
    }

    #[test]
    fn badge_v2_create_requires_message_ids() {
        assert_eq!(
            Badge::create(
                1,
                node(40),
                None,
                BadgeKind::Spammer,
                Vec::new(),
                BadgeContext::ColdContact,
                "reason".into(),
                node(41),
                100,
                None,
                &key(40),
            ),
            Err(BadgeError::EmptyMessageIds)
        );
    }

    #[test]
    fn badge_v2_create_rejects_too_many_message_ids() {
        let ids = (0..=BADGE_MAX_MESSAGE_IDS)
            .map(|index| format!("message-{index}"))
            .collect();
        assert_eq!(
            Badge::create(
                2,
                node(42),
                None,
                BadgeKind::Spammer,
                ids,
                BadgeContext::ColdContact,
                "reason".into(),
                node(43),
                100,
                None,
                &key(42),
            ),
            Err(BadgeError::TooManyMessageIds)
        );
    }

    #[test]
    fn badge_v2_create_rejects_long_message_id() {
        assert_eq!(
            Badge::create(
                3,
                node(44),
                None,
                BadgeKind::Spammer,
                vec!["x".repeat(BADGE_MAX_MESSAGE_ID_LEN + 1)],
                BadgeContext::ColdContact,
                "reason".into(),
                node(45),
                100,
                None,
                &key(44),
            ),
            Err(BadgeError::MessageIdTooLong)
        );
    }

    #[test]
    fn badge_v2_context_roundtrip() {
        let badge = evidence_badge(4, node(46), node(47), BadgeContext::ChannelMessage, 100);
        let encoded = serde_json::to_vec(&badge).expect("serialize badge");
        let decoded: Badge = serde_json::from_slice(&encoded).expect("deserialize badge");
        assert_eq!(decoded, badge);
        assert_eq!(decoded.context, BadgeContext::ChannelMessage);
    }

    #[test]
    fn stigma_clean_for_no_badges() {
        assert_eq!(
            BadgeStore::default().stigma_of(&node(50), stranger_context, 10_000),
            StigmaLevel::Clean
        );
    }

    #[test]
    fn stigma_watching_for_single_stranger_badge() {
        let subject = node(51);
        let now = 1_000_000;
        let mut store = BadgeStore::default();
        store
            .publish(evidence_badge(
                1,
                subject,
                node(52),
                BadgeContext::ColdContact,
                now - BADGE_REFLECTION_PERIOD_SECS,
            ))
            .expect("publish");
        match store.stigma_of(&subject, stranger_context, now) {
            StigmaLevel::Watching {
                weight,
                badge_count,
            } => {
                assert!((weight - 0.1).abs() < 0.001);
                assert_eq!(badge_count, 1);
            }
            other => panic!("expected Watching, got {other:?}"),
        }
    }

    #[test]
    fn stigma_contact_badge_immediately() {
        let subject = node(53);
        let issuer = node(54);
        let now = 2_000_000;
        let mut store = BadgeStore::default();
        store
            .publish(evidence_badge(
                1,
                subject,
                issuer,
                BadgeContext::KnownContact,
                now - BADGE_REFLECTION_PERIOD_SECS,
            ))
            .expect("publish");
        let result = store.stigma_of(
            &subject,
            |node_id| IssuerContext {
                score: 0.8,
                is_contact_of_subject: *node_id == issuer,
                under_stigma: false,
            },
            now,
        );
        assert!(matches!(result, StigmaLevel::Stigma { badge_count: 1, .. }));
    }

    #[test]
    fn stigma_requires_accumulation_for_strangers() {
        let subject = node(55);
        let now = 3_000_000;
        let mut store = BadgeStore::default();
        for index in 0..3u8 {
            store
                .publish(evidence_badge(
                    u64::from(index) + 1,
                    subject,
                    node(60 + index),
                    BadgeContext::ColdContact,
                    now - BADGE_REFLECTION_PERIOD_SECS,
                ))
                .expect("publish stranger badge");
        }
        match store.stigma_of(&subject, stranger_context, now) {
            StigmaLevel::Watching {
                weight,
                badge_count,
            } => {
                assert!((weight - 0.3).abs() < 0.005);
                assert_eq!(badge_count, 3);
            }
            other => panic!("expected Watching for 3 strangers, got {other:?}"),
        }

        // At the end of reflection, each stranger badge has already decayed
        // slightly below 0.1; 21 are needed to cross the 2.0 threshold.
        for index in 3..21u8 {
            store
                .publish(evidence_badge(
                    u64::from(index) + 1,
                    subject,
                    node(index.wrapping_add(70)),
                    BadgeContext::ColdContact,
                    now - BADGE_REFLECTION_PERIOD_SECS,
                ))
                .expect("publish stranger badge");
        }
        assert!(matches!(
            store.stigma_of(&subject, stranger_context, now),
            StigmaLevel::Stigma {
                badge_count: 21,
                ..
            }
        ));
    }

    #[test]
    fn stigma_reflection_period_blocks_activation() {
        let subject = node(80);
        let issuer = node(81);
        let now = 4_000_000;
        let mut store = BadgeStore::default();
        store
            .publish(evidence_badge(
                1,
                subject,
                issuer,
                BadgeContext::KnownContact,
                now - 60,
            ))
            .expect("publish");
        assert!(matches!(
            store.stigma_of(
                &subject,
                |node_id| IssuerContext {
                    score: 0.8,
                    is_contact_of_subject: *node_id == issuer,
                    under_stigma: false,
                },
                now
            ),
            StigmaLevel::Watching { badge_count: 1, .. }
        ));
    }

    #[test]
    fn stigma_counter_claim_clears() {
        let subject = node(82);
        let issuer = node(83);
        let now = 5_000_000;
        let mut store = BadgeStore::default();
        store
            .publish(evidence_badge(
                1,
                subject,
                issuer,
                BadgeContext::KnownContact,
                now - BADGE_REFLECTION_PERIOD_SECS,
            ))
            .expect("publish");
        store
            .record_counter_claim(CounterClaim {
                badge_id: "1".into(),
                jury_verdict_id: "verdict-1".into(),
                cleared_at: now,
                signature: [0; 64],
            })
            .expect("record counterclaim");
        assert_eq!(
            store.stigma_of(
                &subject,
                |node_id| IssuerContext {
                    score: 0.8,
                    is_contact_of_subject: *node_id == issuer,
                    under_stigma: false,
                },
                now
            ),
            StigmaLevel::Cleared {
                badge_count: 1,
                cleared_at: now
            }
        );
        assert_eq!(store.badges.get(&subject).map(Vec::len), Some(1));
    }

    #[test]
    fn stigma_issuer_under_stigma_ignored() {
        let subject = node(84);
        let issuer = node(85);
        let now = 6_000_000;
        let mut store = BadgeStore::default();
        store
            .publish(evidence_badge(
                1,
                subject,
                issuer,
                BadgeContext::ColdContact,
                now - BADGE_REFLECTION_PERIOD_SECS,
            ))
            .expect("publish");
        assert_eq!(
            store.stigma_of(
                &subject,
                |node_id| IssuerContext {
                    score: 0.8,
                    is_contact_of_subject: false,
                    under_stigma: *node_id == issuer,
                },
                now
            ),
            StigmaLevel::Clean
        );
    }

    #[test]
    fn stigma_depth_limit_breaks_recursion() {
        let node_a = node(86);
        let node_b = node(87);
        let node_c = node(88);
        let now = 7_000_000;
        let mut store = BadgeStore::default();
        store
            .publish(evidence_badge(
                1,
                node_b,
                node_a,
                BadgeContext::KnownContact,
                now - BADGE_REFLECTION_PERIOD_SECS,
            ))
            .expect("A badge on B");
        store
            .publish(evidence_badge(
                2,
                node_c,
                node_b,
                BadgeContext::ColdContact,
                now - BADGE_REFLECTION_PERIOD_SECS,
            ))
            .expect("B badge on C");

        let result = store.stigma_of(
            &node_c,
            |issuer| IssuerContext {
                score: 0.8,
                is_contact_of_subject: *issuer == node_a,
                under_stigma: *issuer == node_a,
            },
            now,
        );
        assert!(matches!(
            result,
            StigmaLevel::Watching { badge_count: 1, .. }
        ));
    }

    #[test]
    fn stigma_time_decay_reduces_weight() {
        let subject = node(89);
        let now = 8_000_000;
        let mut store = BadgeStore::default();
        store
            .publish(evidence_badge(
                1,
                subject,
                node(90),
                BadgeContext::ColdContact,
                now - BADGE_STIGMA_TTL_SECS / 2,
            ))
            .expect("publish");
        match store.stigma_of(&subject, stranger_context, now) {
            StigmaLevel::Watching { weight, .. } => assert!((weight - 0.05).abs() < 0.001),
            other => panic!("expected decayed Watching, got {other:?}"),
        }
    }
}
