//! PR-F2: реестр выданных invites, fan-out и chain-depth enforcement.
//!
//! Реализует инварианты I4, I5, I6 из docs/TRUST_MODEL.md §2.3.
//! Один issuer — не больше MAX_INVITES_PER_ISSUER_PER_DAY за 24 часа.
//! Chain depth — не глубже MAX_CHAIN_DEPTH от genesis.
//! Cooldown — новая identity не выдаёт invites первые 7 дней.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::dht::invite::{
    Invite, INVITE_WINDOW_SECS, MAX_CHAIN_DEPTH, MAX_INVITES_PER_ISSUER_PER_DAY,
    NEW_IDENTITY_COOLDOWN_SECS,
};
use crate::dht::NodeId;
use hal_storage::ClientStorage;

/// Placeholder genesis identities. Replace these with the bootstrap NodeIds
/// before network bootstrap; zero is intentionally reserved as the placeholder.
pub const GENESIS_NODES: [[u8; 32]; 3] = [[0u8; 32], [0u8; 32], [0u8; 32]];

pub fn is_genesis(node_id: &[u8; 32]) -> bool {
    GENESIS_NODES.iter().any(|genesis| genesis == node_id)
}

#[derive(Debug, Default)]
pub struct InviteRegistryMetrics {
    pub issued_total: AtomicU64,
    pub rejected_fanout_total: AtomicU64,
    pub rejected_chain_depth_total: AtomicU64,
    pub rejected_cooldown_total: AtomicU64,
    pub revoked_total: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteCreationError {
    FanoutExceeded,
    ChainDepthExceeded,
    CooldownActive,
    IssuerNotInGraph,
    InvalidParent,
}

impl std::fmt::Display for InviteCreationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FanoutExceeded => write!(f, "invite fan-out exceeded"),
            Self::ChainDepthExceeded => write!(f, "invite chain depth exceeded"),
            Self::CooldownActive => write!(f, "invite cooldown active"),
            Self::IssuerNotInGraph => write!(f, "issuer not in graph"),
            Self::InvalidParent => write!(f, "invalid parent invite"),
        }
    }
}

impl std::error::Error for InviteCreationError {}

pub struct InviteRegistry {
    issued_by: HashMap<NodeId, VecDeque<u64>>,
    issuer_first_seen: HashMap<NodeId, u64>,
    children: HashMap<String, Vec<String>>,
    invites: HashMap<String, Invite>,
    metrics: InviteRegistryMetrics,
}

impl InviteRegistry {
    pub fn new() -> Self {
        Self {
            issued_by: HashMap::new(),
            issuer_first_seen: HashMap::new(),
            children: HashMap::new(),
            invites: HashMap::new(),
            metrics: InviteRegistryMetrics::default(),
        }
    }

    pub fn issuer_first_seen(&self, issuer: &NodeId) -> Option<u64> {
        self.issuer_first_seen.get(issuer).copied()
    }

    pub fn load_from_storage(&mut self, storage: &ClientStorage) -> anyhow::Result<()> {
        let first_seen = storage.load_invite_first_seen()?;
        self.issuer_first_seen = first_seen
            .into_iter()
            .map(|(node_id, timestamp)| (NodeId::from_bytes(node_id), timestamp))
            .collect();
        Ok(())
    }

    pub fn persist_first_seen(
        &self,
        storage: &ClientStorage,
        node_id: &[u8; 32],
    ) -> anyhow::Result<()> {
        let node = NodeId::from_bytes(*node_id);
        let first_seen = self
            .issuer_first_seen(&node)
            .ok_or_else(|| anyhow::anyhow!("no first-seen timestamp registered for node"))?;
        storage.upsert_invite_first_seen(node_id, first_seen)
    }

    /// Регистрирует факт выдачи legacy invite без хранения самого InviteData.
    pub fn register_legacy(&mut self, issuer: &NodeId, now: u64) {
        self.issuer_first_seen.entry(*issuer).or_insert(now);
        let queue = self.issued_by.entry(*issuer).or_default();
        queue.push_back(now);
        while queue
            .front()
            .is_some_and(|&ts| now.saturating_sub(ts) > INVITE_WINDOW_SECS)
        {
            queue.pop_front();
        }
        if queue.len() > MAX_INVITES_PER_ISSUER_PER_DAY {
            queue.pop_back();
        }
        self.metrics.issued_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Проверить, можно ли issuer'у выдать новый invite.
    /// issuer_first_seen — unix ts первого появления issuer в графе.
    pub fn can_issue(
        &self,
        issuer: &NodeId,
        parent_chain_depth: Option<u32>,
        issuer_first_seen: u64,
        now: u64,
    ) -> Result<(), InviteCreationError> {
        if !is_genesis(&issuer.0)
            && now.saturating_sub(issuer_first_seen) < NEW_IDENTITY_COOLDOWN_SECS
        {
            return Err(InviteCreationError::CooldownActive);
        }

        if let Some(parent_depth) = parent_chain_depth {
            if parent_depth + 1 > MAX_CHAIN_DEPTH {
                return Err(InviteCreationError::ChainDepthExceeded);
            }
        }

        let window_start = now.saturating_sub(INVITE_WINDOW_SECS);
        let count = self
            .issued_by
            .get(issuer)
            .map(|queue| queue.iter().filter(|&&ts| ts >= window_start).count())
            .unwrap_or(0);

        if count >= MAX_INVITES_PER_ISSUER_PER_DAY {
            return Err(InviteCreationError::FanoutExceeded);
        }

        Ok(())
    }

    pub fn register(&mut self, invite: Invite, now: u64) -> Result<(), InviteCreationError> {
        if invite.chain_depth > MAX_CHAIN_DEPTH {
            self.metrics
                .rejected_chain_depth_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(InviteCreationError::ChainDepthExceeded);
        }

        if let Some(parent_id) = &invite.parent_invite_id {
            let Some(parent) = self.invites.get(parent_id) else {
                return Err(InviteCreationError::InvalidParent);
            };
            if parent.chain_depth + 1 != invite.chain_depth {
                self.metrics
                    .rejected_chain_depth_total
                    .fetch_add(1, Ordering::Relaxed);
                return Err(InviteCreationError::ChainDepthExceeded);
            }
        } else if invite.chain_depth > 0 {
            self.metrics
                .rejected_chain_depth_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(InviteCreationError::ChainDepthExceeded);
        }

        let issuer = invite.issuer_id;
        self.issuer_first_seen.entry(issuer).or_insert(now);
        let queue = self.issued_by.entry(issuer).or_default();
        queue.push_back(now);
        while queue
            .front()
            .is_some_and(|&ts| now.saturating_sub(ts) > INVITE_WINDOW_SECS)
        {
            queue.pop_front();
        }

        if queue.len() > MAX_INVITES_PER_ISSUER_PER_DAY {
            queue.pop_back();
            self.metrics
                .rejected_fanout_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(InviteCreationError::FanoutExceeded);
        }

        let invite_id = invite.invite_id();
        if let Some(parent_id) = &invite.parent_invite_id {
            self.children
                .entry(parent_id.clone())
                .or_default()
                .push(invite_id.clone());
        }
        self.invites.insert(invite_id.clone(), invite.clone());
        self.metrics.issued_total.fetch_add(1, Ordering::Relaxed);

        if let Some(parent_id) = &invite.parent_invite_id {
            let parent_exists = self.invites.contains_key(parent_id);
            if !parent_exists {
                self.invites.remove(&invite_id);
                self.metrics
                    .rejected_chain_depth_total
                    .fetch_add(1, Ordering::Relaxed);
                return Err(InviteCreationError::InvalidParent);
            }
        }

        Ok(())
    }

    pub fn revoke_cascade(&mut self, invite_id: &str) -> Vec<String> {
        let mut revoked = Vec::new();
        let mut stack = vec![invite_id.to_string()];

        while let Some(current_id) = stack.pop() {
            let Some(invite) = self.invites.remove(&current_id) else {
                continue;
            };
            revoked.push(current_id.clone());
            if let Some(children) = self.children.remove(&current_id) {
                stack.extend(children);
            }
            if let Some(parent_id) = invite.parent_invite_id.as_ref() {
                if let Some(children) = self.children.get_mut(parent_id) {
                    children.retain(|child_id| child_id != &current_id);
                }
            }
        }

        self.metrics
            .revoked_total
            .fetch_add(revoked.len() as u64, Ordering::Relaxed);
        revoked
    }

    pub fn metrics(&self) -> &InviteRegistryMetrics {
        &self.metrics
    }

    pub fn len(&self) -> usize {
        self.invites.len()
    }
}

impl Default for InviteRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::invite::{
        MAX_CHAIN_DEPTH, MAX_INVITES_PER_ISSUER_PER_DAY, NEW_IDENTITY_COOLDOWN_SECS,
    };
    use ed25519_dalek::SigningKey;
    use tempfile::tempdir;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn can_issue_within_limit() {
        let issuer = NodeId::from_bytes([0x10; 32]);
        let now = 1_700_000_000;
        let registry = InviteRegistry::new();
        assert!(registry
            .can_issue(&issuer, None, now - NEW_IDENTITY_COOLDOWN_SECS - 60, now)
            .is_ok());
    }

    #[test]
    fn can_issue_fanout_exceeded() {
        let issuer = NodeId::from_bytes([0x11; 32]);
        let now = 1_700_000_100;
        let mut registry = InviteRegistry::new();
        for index in 0..MAX_INVITES_PER_ISSUER_PER_DAY {
            registry
                .issued_by
                .entry(issuer)
                .or_default()
                .push_back(now + index as u64);
        }

        assert_eq!(
            registry.can_issue(&issuer, None, now - NEW_IDENTITY_COOLDOWN_SECS, now),
            Err(InviteCreationError::FanoutExceeded)
        );
    }

    #[test]
    fn can_issue_chain_depth_exceeded() {
        let issuer = NodeId::from_bytes([0x12; 32]);
        let now = 1_700_000_200;
        let registry = InviteRegistry::new();

        assert_eq!(
            registry.can_issue(
                &issuer,
                Some(MAX_CHAIN_DEPTH),
                now - NEW_IDENTITY_COOLDOWN_SECS,
                now
            ),
            Err(InviteCreationError::ChainDepthExceeded)
        );
    }

    #[test]
    fn can_issue_cooldown_active() {
        let issuer = NodeId::from_bytes([0x13; 32]);
        let now = 1_700_000_300;
        let registry = InviteRegistry::new();

        assert_eq!(
            registry.can_issue(&issuer, None, now - 60, now),
            Err(InviteCreationError::CooldownActive)
        );
    }

    #[test]
    fn genesis_is_exempt_from_cooldown() {
        let issuer = NodeId::from_bytes(GENESIS_NODES[0]);
        let now = 1_700_000_300;
        let registry = InviteRegistry::new();

        assert!(registry.can_issue(&issuer, None, now, now + 1).is_ok());
    }

    #[test]
    fn first_seen_persists_and_loads() {
        let directory = tempdir().expect("temp directory");
        let storage = ClientStorage::open(directory.path().join("client.sqlite3"), &[0x32; 32])
            .expect("open storage");
        let issuer = NodeId::from_bytes([0x37; 32]);
        let mut registry = InviteRegistry::new();
        registry.register_legacy(&issuer, 1_700_000_123);

        registry
            .persist_first_seen(&storage, &issuer.0)
            .expect("persist timestamp");
        let mut restored = InviteRegistry::new();
        restored
            .load_from_storage(&storage)
            .expect("load timestamps");

        assert_eq!(restored.issuer_first_seen(&issuer), Some(1_700_000_123));
    }
    #[test]
    fn register_legacy_records_issuer_first_seen() {
        let issuer = NodeId::from_bytes([0x14; 32]);
        let now = 1_700_000_400;
        let mut registry = InviteRegistry::new();

        registry.register_legacy(&issuer, now);

        assert_eq!(registry.issuer_first_seen(&issuer), Some(now));
    }

    #[test]
    fn register_legacy_respects_cooldown_for_new_issuer() {
        let issuer = NodeId::from_bytes([0x15; 32]);
        let now = 1_700_000_500;
        let mut registry = InviteRegistry::new();

        registry.register_legacy(&issuer, now);

        assert_eq!(
            registry.can_issue(&issuer, None, now, now + 1),
            Err(InviteCreationError::CooldownActive)
        );
    }

    #[test]
    fn register_legacy_fanout_after_five() {
        let issuer = NodeId::from_bytes([0x16; 32]);
        let now = 1_700_000_600;
        let mut registry = InviteRegistry::new();
        registry
            .issuer_first_seen
            .insert(issuer, now - NEW_IDENTITY_COOLDOWN_SECS - 60);

        for index in 0..MAX_INVITES_PER_ISSUER_PER_DAY {
            registry.register_legacy(&issuer, now + index as u64);
        }

        assert_eq!(
            registry.can_issue(
                &issuer,
                None,
                now - NEW_IDENTITY_COOLDOWN_SECS - 60,
                now + MAX_INVITES_PER_ISSUER_PER_DAY as u64
            ),
            Err(InviteCreationError::FanoutExceeded)
        );
    }
    #[test]
    fn can_issue_cooldown_expired() {
        let issuer = NodeId::from_bytes([0x14; 32]);
        let now = 1_700_000_400;
        let registry = InviteRegistry::new();

        assert!(registry
            .can_issue(&issuer, None, now - NEW_IDENTITY_COOLDOWN_SECS - 60, now)
            .is_ok());
    }

    #[test]
    fn register_rejects_invalid_parent_chain() {
        let signing_key = key(1);
        let invite = Invite::create(
            &signing_key,
            None,
            3600,
            1_700_000_000,
            [1; 16],
            1,
            Some("missing-parent".to_string()),
            Some([0; 32]),
        );
        let mut registry = InviteRegistry::new();
        assert_eq!(
            registry.register(invite, 1_700_000_000),
            Err(InviteCreationError::InvalidParent)
        );
    }

    #[test]
    fn revoke_cascade_removes_descendants() {
        let signing_key = key(2);
        let parent = Invite::create(
            &signing_key,
            None,
            3600,
            1_700_000_000,
            [2; 16],
            0,
            None,
            None,
        );
        let parent_id = parent.invite_id();
        let child_1 = Invite::create(
            &signing_key,
            None,
            3600,
            1_700_000_010,
            [3; 16],
            1,
            Some(parent_id.clone()),
            Some([2; 32]),
        );
        let child_1_id = child_1.invite_id();
        let child_2 = Invite::create(
            &signing_key,
            None,
            3600,
            1_700_000_020,
            [4; 16],
            1,
            Some(parent_id.clone()),
            Some([2; 32]),
        );
        let child_2_id = child_2.invite_id();

        let mut registry = InviteRegistry::new();
        registry.register(parent.clone(), 1_700_000_000).unwrap();
        registry.register(child_1.clone(), 1_700_000_010).unwrap();
        registry.register(child_2.clone(), 1_700_000_020).unwrap();

        let revoked = registry.revoke_cascade(&parent_id);
        assert!(revoked.contains(&parent_id));
        assert!(revoked.contains(&child_1_id));
        assert!(revoked.contains(&child_2_id));
        assert_eq!(registry.len(), 0);
    }
}
