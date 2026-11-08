use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::dht::NodeId;

pub const DEFAULT_MAX_ENTRIES: usize = 10_000;
pub const DEFAULT_MAX_PER_IDENTITY: usize = 10;
pub const TTL_INBOUND_SECS: u64 = 5 * 60;
pub const TTL_OUTBOUND_SECS: u64 = 30 * 60;
pub const TTL_INVITE_SECS: u64 = 60 * 60;
pub const TTL_LAN_DISCOVERY_SECS: u64 = 5 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerEntrySource {
    InboundTls,
    OutboundVerified,
    Invite,
    LanDiscovery,
}

impl PeerEntrySource {
    pub fn ttl_secs(&self) -> u64 {
        match self {
            Self::InboundTls => TTL_INBOUND_SECS,
            Self::OutboundVerified => TTL_OUTBOUND_SECS,
            Self::Invite => TTL_INVITE_SECS,
            Self::LanDiscovery => TTL_LAN_DISCOVERY_SECS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerEntry {
    pub address: String,
    pub identity_id: String,
    pub public_key_hex: String,
    pub source: PeerEntrySource,
    pub first_seen: u64,
    pub last_seen: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone)]
pub struct PeerDirectoryConfig {
    pub max_entries: usize,
    pub max_per_identity: usize,
}

impl Default for PeerDirectoryConfig {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_ENTRIES,
            max_per_identity: DEFAULT_MAX_PER_IDENTITY,
        }
    }
}

#[derive(Debug, Default)]
pub struct PeerDirectoryMetrics {
    pub recorded_inbound_total: AtomicU64,
    pub recorded_outbound_total: AtomicU64,
    pub recorded_invite_total: AtomicU64,
    pub refreshed_total: AtomicU64,
    pub rejected_invalid_identity_total: AtomicU64,
    pub rejected_conflict_total: AtomicU64,
    pub evicted_lru_total: AtomicU64,
    pub evicted_per_identity_total: AtomicU64,
    pub expired_total: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerDirectoryError {
    InvalidIdentityBinding,
    InvalidPublicKey,
    InvalidAddress,
    AddressConflict,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerDirectoryMetricsSnapshot {
    pub recorded_inbound_total: u64,
    pub recorded_outbound_total: u64,
    pub recorded_invite_total: u64,
    pub refreshed_total: u64,
    pub rejected_invalid_identity_total: u64,
    pub rejected_conflict_total: u64,
    pub evicted_lru_total: u64,
    pub evicted_per_identity_total: u64,
    pub expired_total: u64,
    pub entries_current: u64,
}

pub struct PeerDirectory {
    forward: HashMap<String, PeerEntry>,
    reverse: HashMap<String, VecDeque<String>>,
    config: PeerDirectoryConfig,
    metrics: PeerDirectoryMetrics,
}

impl PeerDirectory {
    pub fn new(config: PeerDirectoryConfig) -> Self {
        Self {
            forward: HashMap::new(),
            reverse: HashMap::new(),
            config,
            metrics: PeerDirectoryMetrics::default(),
        }
    }

    pub fn default_config() -> Self {
        Self::new(PeerDirectoryConfig::default())
    }

    pub fn record_inbound(
        &mut self,
        remote_addr: SocketAddr,
        identity_id: String,
        public_key_hex: String,
        now: u64,
    ) -> Result<(), PeerDirectoryError> {
        self.insert_or_refresh(
            remote_addr.to_string(),
            identity_id,
            public_key_hex,
            PeerEntrySource::InboundTls,
            now,
        )?;
        self.metrics
            .recorded_inbound_total
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn record_outbound(
        &mut self,
        address: String,
        identity_id: String,
        public_key_hex: String,
        now: u64,
    ) -> Result<(), PeerDirectoryError> {
        self.insert_or_refresh(
            address,
            identity_id,
            public_key_hex,
            PeerEntrySource::OutboundVerified,
            now,
        )?;
        self.metrics
            .recorded_outbound_total
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn record_invite(
        &mut self,
        address: String,
        identity_id: String,
        public_key_hex: String,
        now: u64,
    ) -> Result<(), PeerDirectoryError> {
        self.insert_or_refresh(
            address,
            identity_id,
            public_key_hex,
            PeerEntrySource::Invite,
            now,
        )?;
        self.metrics
            .recorded_invite_total
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn record_lan_discovery(
        &mut self,
        address: SocketAddr,
        identity_id: String,
        public_key_hex: String,
        now: u64,
    ) -> Result<bool, PeerDirectoryError> {
        self.validate_identity_binding(&identity_id, &public_key_hex)?;
        let known_peer = self
            .reverse
            .get(&identity_id)
            .into_iter()
            .flatten()
            .filter_map(|known_address| self.forward.get(known_address))
            .any(|entry| entry.expires_at > now && entry.public_key_hex == public_key_hex);
        if !known_peer {
            return Ok(false);
        }

        self.replace_lan_address(address, identity_id, public_key_hex, now)?;
        Ok(true)
    }

    pub(crate) fn record_pinned_lan_discovery(
        &mut self,
        address: SocketAddr,
        identity_id: String,
        public_key_hex: String,
        now: u64,
    ) -> Result<(), PeerDirectoryError> {
        self.replace_lan_address(address, identity_id, public_key_hex, now)
    }

    fn replace_lan_address(
        &mut self,
        address: SocketAddr,
        identity_id: String,
        public_key_hex: String,
        now: u64,
    ) -> Result<(), PeerDirectoryError> {
        self.validate_identity_binding(&identity_id, &public_key_hex)?;
        let address = address.to_string();
        if self
            .forward
            .get(&address)
            .is_some_and(|entry| entry.identity_id != identity_id && entry.expires_at > now)
        {
            self.metrics
                .rejected_conflict_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(PeerDirectoryError::AddressConflict);
        }

        let old_lan_addresses = self
            .reverse
            .get(&identity_id)
            .into_iter()
            .flatten()
            .filter_map(|known_address| {
                self.forward.get(known_address).and_then(|entry| {
                    if entry.expires_at <= now {
                        return None;
                    }
                    let old_address = entry.address.parse::<SocketAddr>().ok()?;
                    let is_lan_address = match old_address.ip() {
                        std::net::IpAddr::V4(ip) => {
                            ip.is_loopback() || ip.is_private() || ip.is_link_local()
                        }
                        std::net::IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local(),
                    };
                    is_lan_address.then_some(entry.address.clone())
                })
            })
            .collect::<Vec<_>>();
        for old_address in old_lan_addresses {
            self.remove_address_internal(&old_address);
        }

        self.insert_or_refresh(
            address,
            identity_id,
            public_key_hex,
            PeerEntrySource::LanDiscovery,
            now,
        )?;
        Ok(())
    }

    pub fn lookup_by_address(&self, addr: &str, now: u64) -> Option<&PeerEntry> {
        self.forward
            .get(addr)
            .filter(|entry| entry.expires_at > now)
    }

    pub fn lookup_by_identity(&self, identity_id: &str, now: u64) -> Option<&PeerEntry> {
        self.reverse
            .get(identity_id)?
            .iter()
            .filter_map(|address| self.forward.get(address))
            .filter(|entry| entry.expires_at > now)
            .max_by_key(|entry| entry.last_seen)
    }

    pub fn addresses_of(&self, identity_id: &str, now: u64) -> Vec<String> {
        self.reverse
            .get(identity_id)
            .map(|queue| {
                queue
                    .iter()
                    .filter_map(|address| self.forward.get(address))
                    .filter(|entry| entry.expires_at > now)
                    .map(|entry| entry.address.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn entries(&self, hint: &[String], now: u64) -> Vec<PeerEntry> {
        let hint_set: HashSet<&String> = hint.iter().collect();
        self.forward
            .values()
            .filter(|entry| entry.expires_at > now)
            .filter(|entry| hint.is_empty() || hint_set.contains(&entry.address))
            .cloned()
            .collect()
    }

    pub fn cleanup_expired(&mut self, now: u64) -> usize {
        let expired_addresses = self
            .forward
            .iter()
            .filter_map(|(address, entry)| (entry.expires_at <= now).then_some(address.clone()))
            .collect::<Vec<_>>();
        for address in &expired_addresses {
            self.remove_address_internal(address);
            self.metrics.expired_total.fetch_add(1, Ordering::Relaxed);
        }
        expired_addresses.len()
    }

    pub fn len(&self) -> usize {
        self.forward.len()
    }

    pub fn is_empty(&self) -> bool {
        self.forward.is_empty()
    }

    pub fn metrics(&self) -> &PeerDirectoryMetrics {
        &self.metrics
    }

    pub fn metrics_snapshot(&self) -> PeerDirectoryMetricsSnapshot {
        let now = current_unix_time();
        let entries_current = self
            .forward
            .values()
            .filter(|entry| entry.expires_at > now)
            .count() as u64;

        PeerDirectoryMetricsSnapshot {
            recorded_inbound_total: self.metrics.recorded_inbound_total.load(Ordering::Relaxed),
            recorded_outbound_total: self.metrics.recorded_outbound_total.load(Ordering::Relaxed),
            recorded_invite_total: self.metrics.recorded_invite_total.load(Ordering::Relaxed),
            refreshed_total: self.metrics.refreshed_total.load(Ordering::Relaxed),
            rejected_invalid_identity_total: self
                .metrics
                .rejected_invalid_identity_total
                .load(Ordering::Relaxed),
            rejected_conflict_total: self.metrics.rejected_conflict_total.load(Ordering::Relaxed),
            evicted_lru_total: self.metrics.evicted_lru_total.load(Ordering::Relaxed),
            evicted_per_identity_total: self
                .metrics
                .evicted_per_identity_total
                .load(Ordering::Relaxed),
            expired_total: self.metrics.expired_total.load(Ordering::Relaxed),
            entries_current,
        }
    }

    fn validate_identity_binding(
        &self,
        identity_id: &str,
        public_key_hex: &str,
    ) -> Result<VerifyingKey, PeerDirectoryError> {
        let pubkey_bytes: [u8; 32] = hex::decode(public_key_hex)
            .map_err(|_| PeerDirectoryError::InvalidPublicKey)?
            .try_into()
            .map_err(|_| PeerDirectoryError::InvalidPublicKey)?;
        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|_| PeerDirectoryError::InvalidPublicKey)?;
        let derived = NodeId::from_public_key(&verifying_key).to_hex();
        if derived != identity_id {
            self.metrics
                .rejected_invalid_identity_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(PeerDirectoryError::InvalidIdentityBinding);
        }
        Ok(verifying_key)
    }

    fn insert_or_refresh(
        &mut self,
        address: String,
        identity_id: String,
        public_key_hex: String,
        source: PeerEntrySource,
        now: u64,
    ) -> Result<(), PeerDirectoryError> {
        if address.is_empty() {
            return Err(PeerDirectoryError::InvalidAddress);
        }

        self.validate_identity_binding(&identity_id, &public_key_hex)?;

        if let Some(existing) = self.forward.get(&address) {
            if existing.expires_at <= now {
                self.remove_address_internal(&address);
            } else if existing.identity_id != identity_id {
                self.metrics
                    .rejected_conflict_total
                    .fetch_add(1, Ordering::Relaxed);
                return Err(PeerDirectoryError::AddressConflict);
            } else {
                if let Some(entry) = self.forward.get_mut(&address) {
                    entry.source = source;
                    entry.last_seen = now;
                    entry.expires_at = entry.expires_at.max(now + source.ttl_secs());
                }
                self.metrics.refreshed_total.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        }

        let entry = PeerEntry {
            address: address.clone(),
            identity_id: identity_id.clone(),
            public_key_hex,
            source,
            first_seen: now,
            last_seen: now,
            expires_at: now + source.ttl_secs(),
        };

        self.evict_per_identity_if_needed(&identity_id);
        self.evict_lru_if_needed();

        self.forward.insert(address.clone(), entry);
        self.reverse
            .entry(identity_id)
            .or_default()
            .push_back(address);
        Ok(())
    }

    fn evict_lru_if_needed(&mut self) {
        if self.forward.len() < self.config.max_entries {
            return;
        }

        if let Some(victim) = self
            .forward
            .values()
            .min_by_key(|entry| entry.last_seen)
            .map(|entry| entry.address.clone())
        {
            self.remove_address_internal(&victim);
            self.metrics
                .evicted_lru_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn evict_per_identity_if_needed(&mut self, identity_id: &str) {
        let current = self
            .reverse
            .get(identity_id)
            .map(|queue| queue.len())
            .unwrap_or(0);
        if current >= self.config.max_per_identity {
            if let Some(victim) = self
                .reverse
                .get(identity_id)
                .and_then(|queue| queue.front().cloned())
            {
                self.remove_address_internal(&victim);
                self.metrics
                    .evicted_per_identity_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn remove_address_internal(&mut self, address: &str) {
        if let Some(entry) = self.forward.remove(address) {
            if let Some(queue) = self.reverse.get_mut(&entry.identity_id) {
                queue.retain(|item| item != address);
                if queue.is_empty() {
                    self.reverse.remove(&entry.identity_id);
                }
            }
        }
    }
}

fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use ed25519_dalek::SigningKey;

    use super::*;

    fn make_identity(seed: u8) -> (String, String) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let identity_id = NodeId::from_public_key(&signing_key.verifying_key()).to_hex();
        (identity_id, public_key_hex)
    }

    #[test]
    fn invite_route_ttl_is_sixty_minutes() {
        assert_eq!(PeerEntrySource::Invite.ttl_secs(), 60 * 60);

        let (identity_id, public_key_hex) = make_identity(11);
        let address = "192.168.0.2:4001".to_string();
        let mut directory = PeerDirectory::new(PeerDirectoryConfig::default());
        directory
            .record_invite(address.clone(), identity_id, public_key_hex, 100)
            .expect("valid Invite route");

        assert_eq!(
            directory
                .lookup_by_address(&address, 100)
                .map(|entry| entry.expires_at),
            Some(100 + 60 * 60)
        );
        assert!(directory
            .lookup_by_address(&address, 100 + 60 * 60)
            .is_none());
    }

    #[test]
    fn record_rejects_invalid_identity() {
        let (_, valid_pubkey) = make_identity(1);
        let (other_identity, _) = make_identity(24);
        let mut directory = PeerDirectory::new(PeerDirectoryConfig::default());
        let result = directory.record_outbound(
            "127.0.0.1:9000".to_string(),
            other_identity,
            valid_pubkey,
            1,
        );
        assert_eq!(result, Err(PeerDirectoryError::InvalidIdentityBinding));
        assert_eq!(
            directory
                .metrics()
                .rejected_invalid_identity_total
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn record_rejects_bad_pubkey_hex() {
        let (identity_id, _) = make_identity(2);
        let mut directory = PeerDirectory::new(PeerDirectoryConfig::default());
        let result = directory.record_outbound(
            "127.0.0.1:9001".to_string(),
            identity_id,
            "badhex".to_string(),
            1,
        );
        assert_eq!(result, Err(PeerDirectoryError::InvalidPublicKey));
    }

    #[test]
    fn record_rejects_wrong_pubkey_length() {
        let (identity_id, _) = make_identity(3);
        let mut directory = PeerDirectory::new(PeerDirectoryConfig::default());
        let short = [0u8; 31];
        let result = directory.record_outbound(
            "127.0.0.1:9002".to_string(),
            identity_id,
            hex::encode(short),
            1,
        );
        assert_eq!(result, Err(PeerDirectoryError::InvalidPublicKey));
    }

    #[test]
    fn record_same_identity_refreshes() {
        let (identity_id, public_key_hex) = make_identity(4);
        let mut directory = PeerDirectory::new(PeerDirectoryConfig::default());
        assert!(directory
            .record_outbound(
                "127.0.0.1:9003".to_string(),
                identity_id.clone(),
                public_key_hex.clone(),
                10
            )
            .is_ok());
        let before = directory.lookup_by_address("127.0.0.1:9003", 10).unwrap();
        let old_expires = before.expires_at;
        assert!(directory
            .record_outbound(
                "127.0.0.1:9003".to_string(),
                identity_id.clone(),
                public_key_hex,
                20
            )
            .is_ok());
        let refreshed = directory.lookup_by_address("127.0.0.1:9003", 20).unwrap();
        assert!(refreshed.expires_at >= old_expires + 1);
        assert_eq!(
            directory.metrics().refreshed_total.load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn lan_discovery_replaces_known_lan_address_and_preserves_wan_address() {
        let (identity_id, public_key_hex) = make_identity(42);
        let mut directory = PeerDirectory::new(PeerDirectoryConfig::default());
        directory
            .record_outbound(
                "192.168.0.98:4001".to_string(),
                identity_id.clone(),
                public_key_hex.clone(),
                10,
            )
            .expect("known LAN peer");
        directory
            .record_outbound(
                "188.163.83.204:4001".to_string(),
                identity_id.clone(),
                public_key_hex.clone(),
                10,
            )
            .expect("known WAN peer");

        assert!(directory
            .record_lan_discovery(
                "192.168.0.55:4001".parse().expect("new LAN endpoint"),
                identity_id.clone(),
                public_key_hex,
                20,
            )
            .expect("LAN address accepted"));

        let addresses = directory.addresses_of(&identity_id, 20);
        assert!(addresses.contains(&"192.168.0.55:4001".to_string()));
        assert!(addresses.contains(&"188.163.83.204:4001".to_string()));
        assert!(!addresses.contains(&"192.168.0.98:4001".to_string()));
    }

    #[test]
    fn lan_discovery_does_not_add_unknown_peer() {
        let (identity_id, public_key_hex) = make_identity(43);
        let mut directory = PeerDirectory::new(PeerDirectoryConfig::default());

        assert!(!directory
            .record_lan_discovery(
                "192.168.0.55:4001".parse().expect("LAN endpoint"),
                identity_id.clone(),
                public_key_hex,
                20,
            )
            .expect("unknown peer should be ignored"));
        assert!(directory.addresses_of(&identity_id, 20).is_empty());
    }

    #[test]
    fn pinned_lan_discovery_adds_peer_without_an_active_address() {
        let (identity_id, public_key_hex) = make_identity(44);
        let mut directory = PeerDirectory::new(PeerDirectoryConfig::default());

        directory
            .record_pinned_lan_discovery(
                "192.168.0.55:4001".parse().expect("LAN endpoint"),
                identity_id.clone(),
                public_key_hex,
                20,
            )
            .expect("pinned peer should be accepted");

        assert_eq!(
            directory.addresses_of(&identity_id, 20),
            vec!["192.168.0.55:4001".to_string()]
        );
    }

    #[test]
    fn record_different_identity_conflict() {
        let (first_identity, first_pubkey) = make_identity(5);
        let (second_identity, second_pubkey) = make_identity(6);
        let mut directory = PeerDirectory::new(PeerDirectoryConfig::default());
        assert!(directory
            .record_outbound(
                "127.0.0.1:9004".to_string(),
                first_identity.clone(),
                first_pubkey,
                10
            )
            .is_ok());
        let conflict = directory.record_outbound(
            "127.0.0.1:9004".to_string(),
            second_identity,
            second_pubkey,
            11,
        );
        assert_eq!(conflict, Err(PeerDirectoryError::AddressConflict));
        assert_eq!(
            directory
                .metrics()
                .rejected_conflict_total
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn record_after_expiry_overwrites() {
        let (identity_id, public_key_hex) = make_identity(7);
        let mut directory = PeerDirectory::new(PeerDirectoryConfig::default());
        assert!(directory
            .record_outbound(
                "127.0.0.1:9005".to_string(),
                identity_id.clone(),
                public_key_hex.clone(),
                10
            )
            .is_ok());
        let mut entry = directory
            .lookup_by_address("127.0.0.1:9005", 10)
            .unwrap()
            .clone();
        entry.expires_at = 10;
        directory
            .forward
            .insert("127.0.0.1:9005".to_string(), entry);
        assert!(directory
            .record_outbound(
                "127.0.0.1:9005".to_string(),
                identity_id,
                public_key_hex,
                11
            )
            .is_ok());
        assert!(directory.lookup_by_address("127.0.0.1:9005", 11).is_some());
    }

    #[test]
    fn lru_evicts_oldest() {
        let mut config = PeerDirectoryConfig::default();
        config.max_entries = 3;
        let mut directory = PeerDirectory::new(config);
        let (one_id, one_pub) = make_identity(8);
        let (two_id, two_pub) = make_identity(9);
        let (three_id, three_pub) = make_identity(10);
        let (four_id, four_pub) = make_identity(11);
        let addresses = [
            "127.0.0.1:9100",
            "127.0.0.1:9101",
            "127.0.0.1:9102",
            "127.0.0.1:9103",
        ];
        assert!(directory
            .record_outbound(addresses[0].to_string(), one_id, one_pub, 1)
            .is_ok());
        assert!(directory
            .record_outbound(addresses[1].to_string(), two_id, two_pub, 2)
            .is_ok());
        assert!(directory
            .record_outbound(addresses[2].to_string(), three_id, three_pub, 3)
            .is_ok());
        assert!(directory
            .record_outbound(addresses[3].to_string(), four_id, four_pub, 4)
            .is_ok());
        assert_eq!(directory.len(), 3);
        assert!(directory.lookup_by_address(addresses[0], 4).is_none());
        assert_eq!(
            directory
                .metrics()
                .evicted_lru_total
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn per_identity_evicts_oldest() {
        let mut config = PeerDirectoryConfig::default();
        config.max_per_identity = 2;
        let mut directory = PeerDirectory::new(config);
        let (identity_id, public_key_hex) = make_identity(12);
        assert!(directory
            .record_outbound(
                "127.0.0.1:9200".to_string(),
                identity_id.clone(),
                public_key_hex.clone(),
                1
            )
            .is_ok());
        assert!(directory
            .record_outbound(
                "127.0.0.1:9201".to_string(),
                identity_id.clone(),
                public_key_hex.clone(),
                2
            )
            .is_ok());
        assert!(directory
            .record_outbound(
                "127.0.0.1:9202".to_string(),
                identity_id.clone(),
                public_key_hex,
                3
            )
            .is_ok());
        assert_eq!(directory.addresses_of(&identity_id, 3).len(), 2);
        assert!(directory.lookup_by_address("127.0.0.1:9200", 3).is_none());
        assert_eq!(
            directory
                .metrics()
                .evicted_per_identity_total
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn lookup_returns_none_for_expired() {
        let (identity_id, public_key_hex) = make_identity(13);
        let mut directory = PeerDirectory::new(PeerDirectoryConfig::default());
        assert!(directory
            .record_outbound("127.0.0.1:9300".to_string(), identity_id, public_key_hex, 1)
            .is_ok());
        let mut entry = directory
            .lookup_by_address("127.0.0.1:9300", 1)
            .unwrap()
            .clone();
        entry.expires_at = 1;
        directory
            .forward
            .insert("127.0.0.1:9300".to_string(), entry);
        assert!(directory.lookup_by_address("127.0.0.1:9300", 2).is_none());
    }

    #[test]
    fn entries_filters_expired() {
        let (first_id, first_pub) = make_identity(14);
        let (second_id, second_pub) = make_identity(15);
        let mut directory = PeerDirectory::new(PeerDirectoryConfig::default());
        assert!(directory
            .record_outbound("127.0.0.1:9400".to_string(), first_id, first_pub, 1)
            .is_ok());
        assert!(directory
            .record_outbound("127.0.0.1:9401".to_string(), second_id, second_pub, 1)
            .is_ok());
        let mut first = directory
            .lookup_by_address("127.0.0.1:9400", 1)
            .unwrap()
            .clone();
        first.expires_at = 1;
        directory
            .forward
            .insert("127.0.0.1:9400".to_string(), first);
        let entries = directory.entries(&[], 2);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].address, "127.0.0.1:9401");
    }

    #[test]
    fn cleanup_expired_removes() {
        let (identity_id, public_key_hex) = make_identity(16);
        let mut directory = PeerDirectory::new(PeerDirectoryConfig::default());
        assert!(directory
            .record_outbound("127.0.0.1:9500".to_string(), identity_id, public_key_hex, 1)
            .is_ok());
        let mut entry = directory
            .lookup_by_address("127.0.0.1:9500", 1)
            .unwrap()
            .clone();
        entry.expires_at = 1;
        directory
            .forward
            .insert("127.0.0.1:9500".to_string(), entry);
        let removed = directory.cleanup_expired(2);
        assert_eq!(removed, 1);
        assert_eq!(directory.metrics().expired_total.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn lookup_by_address_works() {
        let (identity_id, public_key_hex) = make_identity(17);
        let mut directory = PeerDirectory::new(PeerDirectoryConfig::default());
        assert!(directory
            .record_inbound(
                "127.0.0.1:9600".parse::<SocketAddr>().unwrap(),
                identity_id.clone(),
                public_key_hex.clone(),
                10,
            )
            .is_ok());
        let entry = directory.lookup_by_address("127.0.0.1:9600", 10).unwrap();
        assert_eq!(entry.identity_id, identity_id);
        assert_eq!(entry.public_key_hex, public_key_hex);
    }

    #[test]
    fn addresses_of_returns_all_live() {
        let (identity_id, public_key_hex) = make_identity(18);
        let mut directory = PeerDirectory::new(PeerDirectoryConfig::default());
        assert!(directory
            .record_outbound(
                "127.0.0.1:9700".to_string(),
                identity_id.clone(),
                public_key_hex.clone(),
                1
            )
            .is_ok());
        assert!(directory
            .record_outbound(
                "127.0.0.1:9701".to_string(),
                identity_id.clone(),
                public_key_hex,
                2
            )
            .is_ok());
        let addresses = directory.addresses_of(&identity_id, 3);
        assert_eq!(addresses.len(), 2);
    }

    #[test]
    fn entries_with_hint_filters() {
        let (id1, pub1) = make_identity(19);
        let (id2, pub2) = make_identity(20);
        let (id3, pub3) = make_identity(21);
        let mut directory = PeerDirectory::new(PeerDirectoryConfig::default());
        assert!(directory
            .record_outbound("127.0.0.1:9800".to_string(), id1, pub1, 1)
            .is_ok());
        assert!(directory
            .record_outbound("127.0.0.1:9801".to_string(), id2, pub2, 1)
            .is_ok());
        assert!(directory
            .record_outbound("127.0.0.1:9802".to_string(), id3, pub3, 1)
            .is_ok());
        let entries = directory.entries(
            &["127.0.0.1:9800".to_string(), "127.0.0.1:9802".to_string()],
            2,
        );
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn entries_with_empty_hint_returns_all() {
        let (id1, pub1) = make_identity(22);
        let (id2, pub2) = make_identity(23);
        let mut directory = PeerDirectory::new(PeerDirectoryConfig::default());
        assert!(directory
            .record_outbound("127.0.0.1:9900".to_string(), id1, pub1, 1)
            .is_ok());
        assert!(directory
            .record_outbound("127.0.0.1:9901".to_string(), id2, pub2, 1)
            .is_ok());
        let entries = directory.entries(&[], 2);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn lookup_by_identity_returns_latest_live_key_and_ignores_expired_entries() {
        let (identity_id, public_key_hex) = make_identity(19);
        let mut directory = PeerDirectory::new(PeerDirectoryConfig::default());
        directory
            .record_outbound(
                "127.0.0.1:9710".to_string(),
                identity_id.clone(),
                public_key_hex.clone(),
                10,
            )
            .expect("record first address");
        directory
            .record_outbound(
                "127.0.0.1:9711".to_string(),
                identity_id.clone(),
                public_key_hex.clone(),
                20,
            )
            .expect("record second address");

        assert_eq!(
            directory
                .lookup_by_identity(&identity_id, 21)
                .map(|entry| entry.address.as_str()),
            Some("127.0.0.1:9711")
        );
        assert!(directory
            .lookup_by_identity(&identity_id, u64::MAX)
            .is_none());
    }
}
