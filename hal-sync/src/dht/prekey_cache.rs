use std::collections::{HashMap, VecDeque};
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use ed25519_dalek::VerifyingKey;
use hal_crypto::PrekeyBundle;
use sha2::{Digest, Sha256};
use tokio::time::timeout;

use super::lookup::{Lookup, LOOKUP_TIMEOUT_PER_RPC};
use super::node_id::NodeId;
use super::routing::RoutingTable;
use super::transport::DhtTransport;
use super::wire::{
    DhtRequest, DhtRequestPayload, DhtResponsePayload, StoredRecordType, MAX_DHT_REQUEST_BYTES,
};
use super::PublishReport;
use crate::abuse_metrics::AbuseMetrics;

pub const PREKEY_CACHE_DEFAULT_SIZE: usize = 1_000;
const PREKEY_KEY_DOMAIN: &[u8] = b"hal-prekey-bundle-v1\0";

pub fn prekey_bundle_key(identity: &NodeId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PREKEY_KEY_DOMAIN);
    hasher.update(identity.as_bytes());
    hasher.finalize().into()
}

#[derive(Debug, Clone)]
struct CacheEntry {
    bundle: PrekeyBundle,
    expires_at: u64,
}

#[derive(Debug)]
pub struct PrekeyCache {
    entries: HashMap<NodeId, CacheEntry>,
    order: VecDeque<NodeId>,
    max_size: usize,
}

impl Default for PrekeyCache {
    fn default() -> Self {
        Self::new(PREKEY_CACHE_DEFAULT_SIZE)
    }
}

impl PrekeyCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            max_size,
        }
    }

    pub fn insert(
        &mut self,
        identity: NodeId,
        bundle: PrekeyBundle,
        expires_at: u64,
        now: u64,
    ) -> Result<()> {
        bundle.verify(now).map_err(|error| anyhow!(error))?;
        if bundle.expires_at != expires_at {
            return Err(anyhow!("prekey cache expiry does not match signed bundle"));
        }
        let verifying_key =
            VerifyingKey::from_bytes(&bundle.identity_key).map_err(|error| anyhow!(error))?;
        if NodeId::from_public_key(&verifying_key) != identity {
            return Err(anyhow!("prekey bundle identity does not match cache key"));
        }
        let key = identity;
        self.entries.insert(key, CacheEntry { bundle, expires_at });
        self.order.retain(|entry| entry != &key);
        self.order.push_back(key);
        while self.entries.len() > self.max_size {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn insert_unchecked(
        &mut self,
        identity: NodeId,
        bundle: PrekeyBundle,
        expires_at: u64,
    ) {
        self.entries
            .insert(identity, CacheEntry { bundle, expires_at });
        self.order.retain(|entry| entry != &identity);
        self.order.push_back(identity);
    }

    pub fn get(&mut self, identity: &NodeId, now: u64) -> Option<&PrekeyBundle> {
        if self
            .entries
            .get(identity)
            .is_some_and(|entry| entry.expires_at <= now)
        {
            self.entries.remove(identity);
            self.order.retain(|entry| entry != identity);
            return None;
        }
        if self.entries.contains_key(identity) {
            self.order.retain(|entry| entry != identity);
            self.order.push_back(*identity);
        }
        self.entries.get(identity).map(|entry| &entry.bundle)
    }

    pub fn get_by_key(&mut self, key: &[u8; 32], now: u64) -> Option<&PrekeyBundle> {
        let identity = self
            .entries
            .keys()
            .copied()
            .find(|identity| prekey_bundle_key(identity) == *key)?;
        self.get(&identity, now)
    }

    pub fn cleanup_expired(&mut self, now: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| entry.expires_at > now);
        self.order
            .retain(|identity| self.entries.contains_key(identity));
        before - self.entries.len()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

pub struct PrekeyStore<'a> {
    local_id: NodeId,
    transport: &'a dyn DhtTransport,
    routing: &'a mut RoutingTable,
    cache: &'a mut PrekeyCache,
    metrics: &'a AbuseMetrics,
}

impl<'a> PrekeyStore<'a> {
    pub fn new(
        local_id: NodeId,
        transport: &'a dyn DhtTransport,
        routing: &'a mut RoutingTable,
        cache: &'a mut PrekeyCache,
        metrics: &'a AbuseMetrics,
    ) -> Self {
        Self {
            local_id,
            transport,
            routing,
            cache,
            metrics,
        }
    }

    pub async fn publish(&mut self, bundle: PrekeyBundle, now: u64) -> Result<PublishReport> {
        bundle.verify(now).map_err(|error| {
            self.metrics
                .prekey_bundle_verify_failed_total
                .fetch_add(1, Ordering::Relaxed);
            anyhow!(error)
        })?;
        let identity_key =
            VerifyingKey::from_bytes(&bundle.identity_key).map_err(|error| anyhow!(error))?;
        let owner = NodeId::from_public_key(&identity_key);
        if owner != self.local_id {
            return Err(anyhow!("cannot publish another identity's prekey bundle"));
        }

        let key = prekey_bundle_key(&owner);
        let mut lookup = Lookup::new(
            self.local_id,
            NodeId::from_bytes(key),
            Default::default(),
            self.transport,
            self.routing,
        );
        let peers = lookup
            .find_node()
            .await
            .map_err(|error| anyhow!(error.to_string()))?
            .peers;
        let value = serde_json::to_vec(&bundle)?;
        if value.len() > MAX_DHT_REQUEST_BYTES {
            return Err(anyhow!("prekey bundle exceeds DHT record size limit"));
        }
        let mut report = PublishReport {
            peers_contacted: peers.len(),
            peers_stored: 0,
            failures: Vec::new(),
        };
        for peer in peers {
            let request = DhtRequest::new(
                DhtRequestPayload::StoreTyped {
                    key,
                    value: value.clone(),
                    signature: bundle.bundle_signature.to_vec(),
                    expires_at: bundle.expires_at,
                    record_type: Some(StoredRecordType::PrekeyBundle),
                },
                self.local_id,
                now,
            );
            let request_id = request.request_id;
            match timeout(
                LOOKUP_TIMEOUT_PER_RPC,
                self.transport.send_request(&peer, request),
            )
            .await
            {
                Ok(Ok(response)) => match response.validate(&request_id, now) {
                    Ok(())
                        if matches!(
                            response.payload,
                            DhtResponsePayload::Stored { key: stored_key } if stored_key == key
                        ) =>
                    {
                        report.peers_stored += 1;
                        self.metrics
                            .prekey_bundle_published_total
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(()) => report
                        .failures
                        .push((peer.node_id, "unexpected STORE response".into())),
                    Err(error) => report.failures.push((peer.node_id, error.to_string())),
                },
                Ok(Err(error)) => report.failures.push((peer.node_id, error.to_string())),
                Err(_) => report.failures.push((peer.node_id, "store timeout".into())),
            }
        }
        let expires_at = bundle.expires_at;
        self.cache.insert(owner, bundle, expires_at, now)?;
        Ok(report)
    }

    pub async fn fetch(&mut self, identity: &NodeId, now: u64) -> Result<Option<PrekeyBundle>> {
        if let Some(bundle) = self.cache.get(identity, now) {
            self.metrics
                .prekey_bundle_fetch_ok_total
                .fetch_add(1, Ordering::Relaxed);
            return Ok(Some(bundle.clone()));
        }
        let key = prekey_bundle_key(identity);
        let mut lookup = Lookup::new(
            self.local_id,
            NodeId::from_bytes(key),
            Default::default(),
            self.transport,
            self.routing,
        );
        let result = lookup
            .find_value(key)
            .await
            .map_err(|error| anyhow!(error.to_string()))?;
        let Some(value) = result.value else {
            self.metrics
                .prekey_bundle_fetch_failed_total
                .fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        };
        let bundle: PrekeyBundle = serde_json::from_slice(&value.value).map_err(|error| {
            self.metrics
                .prekey_bundle_verify_failed_total
                .fetch_add(1, Ordering::Relaxed);
            anyhow!("invalid prekey bundle DHT value: {error}")
        })?;
        bundle.verify(now).map_err(|error| {
            self.metrics
                .prekey_bundle_verify_failed_total
                .fetch_add(1, Ordering::Relaxed);
            anyhow!(error)
        })?;
        if value.key != key
            || value.expires_at != bundle.expires_at
            || value.signature != bundle.bundle_signature
        {
            self.metrics
                .prekey_bundle_verify_failed_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(anyhow!("prekey bundle DHT metadata mismatch"));
        }
        self.cache
            .insert(*identity, bundle.clone(), value.expires_at, now)
            .map_err(|error| {
                self.metrics
                    .prekey_bundle_verify_failed_total
                    .fetch_add(1, Ordering::Relaxed);
                error
            })?;
        self.metrics
            .prekey_bundle_fetch_ok_total
            .fetch_add(1, Ordering::Relaxed);
        Ok(Some(bundle))
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::peer_info::PeerInfo;
    use crate::dht::routing::RoutingTable;
    use crate::dht::wire::{DhtError, DhtResponse, DhtResponsePayload, DHT_PROTOCOL_VERSION};
    use crate::dht::DhtTransport;
    use async_trait::async_trait;
    use ed25519_dalek::SigningKey;
    use std::sync::Mutex;
    use x25519_dalek::{PublicKey, StaticSecret};

    const NOW: u64 = 1_800_000_000;

    #[derive(Default)]
    struct MockTransport {
        stored: Mutex<Vec<DhtRequest>>,
        value: Option<Vec<u8>>,
    }

    #[async_trait]
    impl DhtTransport for MockTransport {
        async fn send_request(
            &self,
            _peer: &PeerInfo,
            request: DhtRequest,
        ) -> Result<DhtResponse, DhtError> {
            let payload = match &request.payload {
                DhtRequestPayload::FindNode { .. } => DhtResponsePayload::Nodes {
                    peers: Vec::new(),
                    truncated: false,
                },
                DhtRequestPayload::FindValue { key } => match &self.value {
                    Some(value) => {
                        let signature = serde_json::from_slice::<PrekeyBundle>(value)
                            .expect("valid prekey bundle fixture")
                            .bundle_signature
                            .to_vec();
                        DhtResponsePayload::Value {
                            key: *key,
                            value: value.clone(),
                            signature,
                            expires_at: NOW + 3600,
                        }
                    }
                    None => DhtResponsePayload::Nodes {
                        peers: Vec::new(),
                        truncated: false,
                    },
                },
                DhtRequestPayload::StoreTyped { key, .. } => {
                    self.stored
                        .lock()
                        .expect("stored lock")
                        .push(request.clone());
                    DhtResponsePayload::Stored { key: *key }
                }
                _ => DhtResponsePayload::Pong,
            };
            Ok(DhtResponse {
                version: DHT_PROTOCOL_VERSION,
                request_id: request.request_id,
                responder_node_id: NodeId::from_bytes([88; 32]),
                timestamp: request.timestamp,
                payload,
            })
        }
    }

    fn bundle(identity: &SigningKey, expires_at: u64) -> PrekeyBundle {
        let secret = StaticSecret::from([2; 32]);
        PrekeyBundle::create(
            identity,
            PublicKey::from(&secret).to_bytes(),
            Vec::new(),
            1,
            NOW,
            expires_at,
        )
        .expect("bundle")
    }

    fn peer() -> (NodeId, PeerInfo) {
        let key = SigningKey::from_bytes(&[99; 32]);
        let id = NodeId::from_public_key(&key.verifying_key());
        (
            id,
            PeerInfo::new(id, hex::encode(key.verifying_key().to_bytes())),
        )
    }

    #[test]
    fn cache_insert_and_get() {
        let identity_key = SigningKey::from_bytes(&[1; 32]);
        let identity = NodeId::from_public_key(&identity_key.verifying_key());
        let mut cache = PrekeyCache::new(2);
        cache
            .insert(identity, bundle(&identity_key, NOW + 100), NOW + 100, NOW)
            .expect("insert");
        assert!(cache.get(&identity, NOW).is_some());
    }

    #[test]
    fn cache_expires() {
        let identity_key = SigningKey::from_bytes(&[2; 32]);
        let identity = NodeId::from_public_key(&identity_key.verifying_key());
        let mut cache = PrekeyCache::new(2);
        cache
            .insert(identity, bundle(&identity_key, NOW + 100), NOW + 100, NOW)
            .expect("insert");
        assert!(cache.get(&identity, NOW + 100).is_none());
        assert_eq!(cache.cleanup_expired(NOW + 100), 0);
    }

    #[test]
    fn cache_evicts_lru() {
        let first_key = SigningKey::from_bytes(&[3; 32]);
        let second_key = SigningKey::from_bytes(&[4; 32]);
        let third_key = SigningKey::from_bytes(&[5; 32]);
        let first = NodeId::from_public_key(&first_key.verifying_key());
        let second = NodeId::from_public_key(&second_key.verifying_key());
        let third = NodeId::from_public_key(&third_key.verifying_key());
        let mut cache = PrekeyCache::new(2);
        cache
            .insert(first, bundle(&first_key, NOW + 100), NOW + 100, NOW)
            .expect("insert first");
        cache
            .insert(second, bundle(&second_key, NOW + 100), NOW + 100, NOW)
            .expect("insert second");
        assert!(cache.get(&first, NOW).is_some());
        cache
            .insert(third, bundle(&third_key, NOW + 100), NOW + 100, NOW)
            .expect("insert third");
        assert!(cache.get(&first, NOW).is_some());
        assert!(cache.get(&second, NOW).is_none());
    }

    #[tokio::test]
    async fn publish_prekey_bundle_sends_to_dht() {
        let identity_key = SigningKey::from_bytes(&[6; 32]);
        let local_id = NodeId::from_public_key(&identity_key.verifying_key());
        let (peer_id, peer) = peer();
        let transport = MockTransport::default();
        let mut routing = RoutingTable::new(local_id);
        routing.insert(peer, NOW);
        let metrics = AbuseMetrics::new();
        let mut cache = PrekeyCache::default();
        let bundle = bundle(&identity_key, NOW + 3600);
        let mut store = PrekeyStore::new(local_id, &transport, &mut routing, &mut cache, &metrics);
        let report = store.publish(bundle.clone(), NOW).await.expect("publish");
        assert_eq!(report.peers_contacted, 1);
        assert_eq!(report.peers_stored, 1);
        assert_eq!(transport.stored.lock().expect("stored lock").len(), 1);
        assert_eq!(metrics.snapshot().prekey_bundle_published_total, 1);
        assert!(cache.get(&local_id, NOW).is_some());
        assert_ne!(peer_id, local_id);
    }

    #[tokio::test]
    async fn fetch_prekey_bundle_decodes_and_verifies() {
        let identity_key = SigningKey::from_bytes(&[7; 32]);
        let identity = NodeId::from_public_key(&identity_key.verifying_key());
        let bundle = bundle(&identity_key, NOW + 3600);
        let transport = MockTransport {
            value: Some(serde_json::to_vec(&bundle).expect("serialize")),
            ..MockTransport::default()
        };
        let (_, peer) = peer();
        let local_id = NodeId::from_bytes([44; 32]);
        let mut routing = RoutingTable::new(local_id);
        routing.insert(peer, NOW);
        let metrics = AbuseMetrics::new();
        let mut cache = PrekeyCache::default();
        let mut store = PrekeyStore::new(local_id, &transport, &mut routing, &mut cache, &metrics);
        assert_eq!(
            store.fetch(&identity, NOW).await.expect("fetch"),
            Some(bundle)
        );
        assert_eq!(metrics.snapshot().prekey_bundle_fetch_ok_total, 1);
    }

    #[tokio::test]
    async fn fetch_prekey_bundle_not_found_returns_none() {
        let (local_id, peer) = peer();
        let target = NodeId::from_bytes([77; 32]);
        let transport = MockTransport::default();
        let mut routing = RoutingTable::new(local_id);
        routing.insert(peer, NOW);
        let metrics = AbuseMetrics::new();
        let mut cache = PrekeyCache::default();
        let mut store = PrekeyStore::new(local_id, &transport, &mut routing, &mut cache, &metrics);
        assert_eq!(
            store.fetch(&target, NOW).await.expect("fetch missing"),
            None
        );
        assert_eq!(metrics.snapshot().prekey_bundle_fetch_failed_total, 1);
    }

    #[test]
    fn prekey_bundle_key_is_namespaced() {
        let identity = NodeId::from_bytes([17; 32]);
        let mut hasher = Sha256::new();
        hasher.update(PREKEY_KEY_DOMAIN);
        hasher.update(identity.as_bytes());
        assert_eq!(
            prekey_bundle_key(&identity),
            <[u8; 32]>::from(hasher.finalize())
        );
    }

    #[test]
    fn cache_rejects_identity_and_expiry_mismatch() {
        let identity_key = SigningKey::from_bytes(&[8; 32]);
        let other_id = NodeId::from_bytes([0; 32]);
        let mut cache = PrekeyCache::default();
        let valid = bundle(&identity_key, NOW + 3600);
        assert!(cache
            .insert(other_id, valid.clone(), valid.expires_at, NOW)
            .is_err());
        let owner = NodeId::from_public_key(&identity_key.verifying_key());
        assert!(cache
            .insert(owner, valid.clone(), valid.expires_at - 1, NOW)
            .is_err());
    }

    #[test]
    fn cache_cleanup_expired_removes_all_stale_entries() {
        let first_key = SigningKey::from_bytes(&[11; 32]);
        let second_key = SigningKey::from_bytes(&[12; 32]);
        let first = NodeId::from_public_key(&first_key.verifying_key());
        let second = NodeId::from_public_key(&second_key.verifying_key());
        let mut cache = PrekeyCache::new(4);
        cache
            .insert(first, bundle(&first_key, NOW + 10), NOW + 10, NOW)
            .expect("insert first");
        cache
            .insert(second, bundle(&second_key, NOW + 20), NOW + 20, NOW)
            .expect("insert second");
        assert_eq!(cache.cleanup_expired(NOW + 10), 1);
        assert!(cache.get(&second, NOW + 10).is_some());
    }
}
