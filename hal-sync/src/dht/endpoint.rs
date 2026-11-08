use std::collections::{HashMap, VecDeque};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::time::timeout;

use super::lookup::Lookup;
use super::node_id::NodeId;
use super::routing::RoutingTable;
use super::transport::DhtTransport;
use super::wire::{DhtError, DhtRequest, DhtRequestPayload, DhtResponsePayload};

pub const ENDPOINT_TTL_SECONDS: u64 = 3600;
pub const MAX_ENDPOINTS_PER_RECORD: usize = 16;
pub const MAX_ENDPOINT_ADDR_LEN: usize = 128;
pub const MAX_DISPLAY_NAME_CHARS: usize = 64;
pub const MAX_WSS_URL_LEN: usize = 2048;

pub fn endpoint_key(identity_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(identity_id.as_bytes());
    hasher.finalize().into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndpointRecord {
    pub identity_id: String,
    pub public_key: String,
    pub endpoints: Vec<String>,
    #[serde(default)]
    pub is_relay: bool,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub wss_url: Option<String>,
    pub timestamp: u64,
    pub expires_at: u64,
    pub signature: String,
}

impl EndpointRecord {
    pub fn create(
        identity_id: String,
        public_key: String,
        endpoints: Vec<String>,
        signing_key: &SigningKey,
        now: u64,
        ttl_seconds: u64,
    ) -> anyhow::Result<Self> {
        let mut record = Self {
            identity_id,
            public_key,
            endpoints,
            is_relay: false,
            display_name: None,
            wss_url: None,
            timestamp: now,
            expires_at: now.saturating_add(ttl_seconds),
            signature: String::new(),
        };
        record.validate_shape(now)?;
        record.public_key = hex::encode(signing_key.verifying_key().to_bytes());
        record.verify_identity()?;
        record.signature = hex::encode(signing_key.sign(&record.signing_payload()).to_bytes());
        Ok(record)
    }

    pub fn verify(&self, now: u64) -> anyhow::Result<()> {
        self.validate_shape(now)?;
        self.verify_identity()?;
        let public_key: [u8; 32] = hex::decode(&self.public_key)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))?;
        let verifying_key = VerifyingKey::from_bytes(&public_key)?;
        let signature: [u8; 64] = hex::decode(&self.signature)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;
        verifying_key.verify(&self.signing_payload(), &Signature::from_bytes(&signature))?;
        Ok(())
    }

    pub fn with_relay(mut self, is_relay: bool, signing_key: &SigningKey) -> Self {
        self.is_relay = is_relay;
        self.signature = hex::encode(signing_key.sign(&self.signing_payload()).to_bytes());
        self
    }

    pub fn with_wss_url(
        mut self,
        wss_url: Option<String>,
        signing_key: &SigningKey,
    ) -> anyhow::Result<Self> {
        self.wss_url = wss_url;
        self.validate_shape(self.timestamp)?;
        self.signature = hex::encode(signing_key.sign(&self.signing_payload()).to_bytes());
        Ok(self)
    }

    pub fn with_display_name(
        mut self,
        display_name: Option<String>,
        signing_key: &SigningKey,
    ) -> anyhow::Result<Self> {
        self.display_name = display_name;
        self.validate_shape(self.timestamp)?;
        self.signature = hex::encode(signing_key.sign(&self.signing_payload()).to_bytes());
        Ok(self)
    }

    pub fn verify_identity(&self) -> anyhow::Result<()> {
        let public_key = hex::decode(&self.public_key)?;
        if public_key.len() != 32 {
            return Err(anyhow::anyhow!("public key must be 32 bytes"));
        }
        let mut hasher = Sha256::new();
        hasher.update(&public_key);
        let expected = hex::encode(hasher.finalize());
        if self.identity_id != expected {
            return Err(anyhow::anyhow!("identity does not match public key"));
        }
        Ok(())
    }

    fn signing_payload(&self) -> Vec<u8> {
        if self.display_name.is_some() {
            serde_json::to_vec(&(
                &self.identity_id,
                &self.public_key,
                &self.endpoints,
                self.is_relay,
                &self.wss_url,
                &self.display_name,
                self.timestamp,
                self.expires_at,
            ))
        } else if let Some(wss_url) = self.wss_url.as_ref() {
            serde_json::to_vec(&(
                &self.identity_id,
                &self.public_key,
                &self.endpoints,
                self.is_relay,
                wss_url,
                self.timestamp,
                self.expires_at,
            ))
        } else if self.is_relay {
            serde_json::to_vec(&(
                &self.identity_id,
                &self.public_key,
                &self.endpoints,
                true,
                self.timestamp,
                self.expires_at,
            ))
        } else {
            serde_json::to_vec(&(
                &self.identity_id,
                &self.public_key,
                &self.endpoints,
                self.timestamp,
                self.expires_at,
            ))
        }
        .unwrap_or_default()
    }

    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at <= now
    }

    fn validate_shape(&self, now: u64) -> anyhow::Result<()> {
        if self.endpoints.len() > MAX_ENDPOINTS_PER_RECORD {
            return Err(anyhow::anyhow!("too many endpoints"));
        }
        if self
            .endpoints
            .iter()
            .any(|endpoint| endpoint.is_empty() || endpoint.len() > MAX_ENDPOINT_ADDR_LEN)
        {
            return Err(anyhow::anyhow!("invalid endpoint address"));
        }
        if let Some(wss_url) = self.wss_url.as_deref() {
            if !self.is_relay
                || wss_url.is_empty()
                || wss_url.len() > MAX_WSS_URL_LEN
                || !valid_wss_url(wss_url)
            {
                return Err(anyhow::anyhow!("invalid WSS relay URL"));
            }
        }
        if let Some(display_name) = self.display_name.as_deref() {
            if display_name.trim().is_empty()
                || display_name.chars().count() > MAX_DISPLAY_NAME_CHARS
                || display_name.chars().any(char::is_control)
            {
                return Err(anyhow::anyhow!("invalid endpoint display name"));
            }
        }
        if self.expires_at <= self.timestamp || self.expires_at <= now {
            return Err(anyhow::anyhow!(
                "endpoint record is expired or has invalid expiry"
            ));
        }
        Ok(())
    }
}

fn valid_wss_url(value: &str) -> bool {
    let Ok(uri) = value.parse::<tokio_tungstenite::tungstenite::http::Uri>() else {
        return false;
    };
    matches!(uri.scheme_str(), Some("https" | "wss"))
        && uri.authority().is_some_and(|authority| {
            !authority.host().is_empty() && !authority.as_str().contains('@')
        })
}

pub struct EndpointCache {
    records: HashMap<String, EndpointRecord>,
    order: VecDeque<String>,
    max_size: usize,
}

#[derive(Debug, Clone)]
pub struct PublishReport {
    pub peers_contacted: usize,
    pub peers_stored: usize,
    pub failures: Vec<(NodeId, String)>,
}

pub struct EndpointStore<'a> {
    local_id: NodeId,
    transport: &'a dyn DhtTransport,
    routing: &'a mut RoutingTable,
    cache: &'a mut EndpointCache,
}

impl<'a> EndpointStore<'a> {
    pub fn new(
        local_id: NodeId,
        transport: &'a dyn DhtTransport,
        routing: &'a mut RoutingTable,
        cache: &'a mut EndpointCache,
    ) -> Self {
        Self {
            local_id,
            transport,
            routing,
            cache,
        }
    }

    pub async fn publish(
        &mut self,
        record: EndpointRecord,
        now: u64,
    ) -> Result<PublishReport, DhtError> {
        record
            .verify(now)
            .map_err(|error| DhtError::InvalidRequest(error.to_string()))?;
        let key = endpoint_key(&record.identity_id);
        let mut lookup = Lookup::new(
            self.local_id,
            NodeId::from_bytes(key),
            Default::default(),
            self.transport,
            self.routing,
        );
        let peers = lookup.find_node().await?.peers;
        let value =
            serde_json::to_vec(&record).map_err(|error| DhtError::Internal(error.to_string()))?;
        let mut report = PublishReport {
            peers_contacted: peers.len(),
            peers_stored: 0,
            failures: Vec::new(),
        };
        for peer in peers {
            let request = DhtRequest::new(
                DhtRequestPayload::Store {
                    key,
                    value: value.clone(),
                    signature: hex::decode(&record.signature).unwrap_or_default(),
                    expires_at: record.expires_at,
                },
                self.local_id,
                now,
            );
            let request_id = request.request_id;
            match timeout(
                super::lookup::LOOKUP_TIMEOUT_PER_RPC,
                self.transport.send_request(&peer, request),
            )
            .await
            {
                Ok(Ok(response)) => match response.validate(&request_id, now) {
                    Ok(()) if matches!(response.payload, DhtResponsePayload::Stored { key: stored_key } if stored_key == key) => {
                        report.peers_stored += 1
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
        self.cache
            .insert(record)
            .map_err(|error| DhtError::InvalidRequest(error.to_string()))?;
        Ok(report)
    }

    pub async fn lookup(
        &mut self,
        identity_id: &str,
        now: u64,
    ) -> Result<Option<EndpointRecord>, DhtError> {
        if let Some(record) = self.cache.get(identity_id) {
            if !record.is_expired(now) {
                return Ok(Some(record.clone()));
            }
        }
        let key = endpoint_key(identity_id);
        let mut lookup = Lookup::new(
            self.local_id,
            NodeId::from_bytes(key),
            Default::default(),
            self.transport,
            self.routing,
        );
        let result = lookup.find_value(key).await?;
        let Some(value) = result.value else {
            return Ok(None);
        };
        let record: EndpointRecord = serde_json::from_slice(&value.value)
            .map_err(|error| DhtError::InvalidRequest(error.to_string()))?;
        record.verify(now).map_err(|_| DhtError::InvalidSignature)?;
        if record.identity_id != identity_id || endpoint_key(&record.identity_id) != key {
            return Err(DhtError::InvalidSignature);
        }
        self.cache
            .insert(record.clone())
            .map_err(|error| DhtError::InvalidRequest(error.to_string()))?;
        Ok(Some(record))
    }

    pub async fn refresh(
        &mut self,
        identity_id: &str,
        now: u64,
    ) -> Result<Option<EndpointRecord>, DhtError> {
        self.cache.remove(identity_id);
        self.lookup(identity_id, now).await
    }
}

impl EndpointCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            records: HashMap::new(),
            order: VecDeque::new(),
            max_size,
        }
    }

    pub fn insert(&mut self, record: EndpointRecord) -> anyhow::Result<()> {
        record.verify(record.timestamp)?;
        let key = record.identity_id.clone();
        self.records.insert(key.clone(), record);
        self.order.retain(|id| id != &key);
        self.order.push_back(key);
        self.evict_if_needed();
        Ok(())
    }

    pub fn get(&self, identity_id: &str) -> Option<&EndpointRecord> {
        self.records.get(identity_id)
    }

    pub fn get_by_endpoint_key(&self, key: &[u8; 32]) -> Option<&EndpointRecord> {
        self.records
            .values()
            .find(|record| endpoint_key(&record.identity_id) == *key)
    }

    pub fn remove(&mut self, identity_id: &str) {
        self.records.remove(identity_id);
        self.order.retain(|id| id != identity_id);
    }

    pub fn cleanup_expired(&mut self, now: u64) -> usize {
        let keys = self
            .records
            .iter()
            .filter(|(_, record)| record.is_expired(now))
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        let count = keys.len();
        for key in keys {
            self.remove(&key);
        }
        count
    }

    pub fn stale_keys(&self, now: u64, threshold_secs: u64) -> Vec<String> {
        self.records
            .values()
            .filter(|record| now.saturating_sub(record.timestamp) >= threshold_secs)
            .map(|record| record.identity_id.clone())
            .collect()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn evict_if_needed(&mut self) {
        while self.records.len() > self.max_size {
            if let Some(key) = self.order.pop_front() {
                self.records.remove(&key);
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::peer_info::PeerInfo;
    use super::*;

    fn key(value: u8) -> SigningKey {
        SigningKey::from_bytes(&[value; 32])
    }
    fn identity(key: &SigningKey) -> String {
        hex::encode(Sha256::digest(key.verifying_key().to_bytes()))
    }
    fn record(value: u8, now: u64) -> EndpointRecord {
        EndpointRecord::create(
            identity(&key(value)),
            "bad".into(),
            vec!["127.0.0.1:1".into()],
            &key(value),
            now,
            100,
        )
        .expect("record")
    }

    #[test]
    fn endpoint_key_deterministic() {
        assert_eq!(endpoint_key("peer"), endpoint_key("peer"));
    }
    #[test]
    fn endpoint_record_create_signs() {
        assert!(!record(1, 100).signature.is_empty());
    }
    #[test]
    fn endpoint_record_verify_ok() {
        assert!(record(2, 100).verify(110).is_ok());
    }
    #[test]
    fn endpoint_record_wss_url_is_signed() {
        let signing_key = key(30);
        let value = EndpointRecord::create(
            identity(&signing_key),
            String::new(),
            Vec::new(),
            &signing_key,
            100,
            100,
        )
        .expect("record")
        .with_relay(true, &signing_key)
        .with_wss_url(Some("https://relay.example.com".into()), &signing_key)
        .expect("WSS record");
        assert!(serde_json::to_vec(&value).expect("serialize record").len() <= 1000);
        assert!(value.verify(110).is_ok());

        let mut tampered = value;
        tampered.wss_url = Some("https://attacker.example.com".into());
        assert!(tampered.verify(110).is_err());
    }

    #[test]
    fn endpoint_record_display_name_is_signed() {
        let signing_key = key(35);
        let value = EndpointRecord::create(
            identity(&signing_key),
            String::new(),
            Vec::new(),
            &signing_key,
            100,
            100,
        )
        .expect("record")
        .with_display_name(Some("Moto".into()), &signing_key)
        .expect("display name");
        assert_eq!(value.display_name.as_deref(), Some("Moto"));
        assert!(value.verify(110).is_ok());

        let mut tampered = value;
        tampered.display_name = Some("Impersonator".into());
        assert!(tampered.verify(110).is_err());
    }

    #[test]
    fn endpoint_record_rejects_invalid_display_name() {
        let signing_key = key(36);
        let value = EndpointRecord::create(
            identity(&signing_key),
            String::new(),
            Vec::new(),
            &signing_key,
            100,
            100,
        )
        .expect("record")
        .with_display_name(Some(" \n".into()), &signing_key);
        assert!(value.is_err());
    }

    #[test]
    fn endpoint_record_rejects_invalid_wss_url() {
        let signing_key = key(31);
        let value = EndpointRecord::create(
            identity(&signing_key),
            String::new(),
            Vec::new(),
            &signing_key,
            100,
            100,
        )
        .expect("record")
        .with_relay(true, &signing_key)
        .with_wss_url(Some("http://relay.example.com".into()), &signing_key);
        assert!(value.is_err());
    }

    #[test]
    fn endpoint_record_without_wss_url_keeps_legacy_signature() {
        let original = record(32, 100);
        let mut serialized = serde_json::to_value(&original).expect("serialize record");
        serialized
            .as_object_mut()
            .expect("object")
            .remove("wss_url");
        let restored: EndpointRecord =
            serde_json::from_value(serialized).expect("deserialize legacy record");
        assert!(restored.verify(110).is_ok());
    }
    #[test]
    fn endpoint_record_rejects_tampered() {
        let mut value = record(3, 100);
        value.endpoints[0] = "127.0.0.1:2".into();
        assert!(value.verify(110).is_err());
    }
    #[test]
    fn endpoint_record_rejects_wrong_identity() {
        let mut value = record(4, 100);
        value.identity_id = "00".repeat(32);
        assert!(value.verify(110).is_err());
    }
    #[test]
    fn endpoint_record_rejects_expired() {
        assert!(record(5, 100).verify(200).is_err());
    }
    #[test]
    fn endpoint_record_rejects_oversized() {
        let mut value = record(6, 100);
        value.endpoints[0] = "x".repeat(MAX_ENDPOINT_ADDR_LEN + 1);
        assert!(value.verify(110).is_err());
    }
    #[test]
    fn endpoint_record_rejects_too_many_endpoints() {
        let mut value = record(7, 100);
        value.endpoints = vec!["x".into(); MAX_ENDPOINTS_PER_RECORD + 1];
        assert!(value.verify(110).is_err());
    }
    #[test]
    fn cache_insert_get() {
        let mut cache = EndpointCache::new(2);
        let value = record(8, 100);
        cache.insert(value.clone()).expect("insert");
        assert_eq!(cache.get(&value.identity_id), Some(&value));
    }
    #[test]
    fn cache_lru_eviction() {
        let mut cache = EndpointCache::new(1);
        let first = record(9, 100);
        let second = record(10, 100);
        cache.insert(first.clone()).expect("first");
        cache.insert(second.clone()).expect("second");
        assert!(cache.get(&first.identity_id).is_none());
        assert!(cache.get(&second.identity_id).is_some());
    }
    #[test]
    fn cache_cleanup_expired() {
        let mut cache = EndpointCache::new(2);
        cache.insert(record(11, 100)).expect("insert");
        assert_eq!(cache.cleanup_expired(200), 1);
    }
    #[test]
    fn cache_stale_keys() {
        let mut cache = EndpointCache::new(2);
        let value = record(12, 100);
        let id = value.identity_id.clone();
        cache.insert(value).expect("insert");
        assert_eq!(cache.stale_keys(150, 50), vec![id]);
    }

    #[derive(Clone)]
    struct MockTransport {
        discovered: PeerInfo,
        value: Option<EndpointRecord>,
        fail_store: bool,
        invalid_value: bool,
    }

    #[async_trait::async_trait]
    impl super::super::transport::DhtTransport for MockTransport {
        async fn send_request(
            &self,
            _peer: &PeerInfo,
            request: super::super::wire::DhtRequest,
        ) -> Result<super::super::wire::DhtResponse, super::super::wire::DhtError> {
            use super::super::wire::{DhtResponse, DhtResponsePayload};
            let payload = match request.payload {
                super::super::wire::DhtRequestPayload::FindNode { .. } => {
                    DhtResponsePayload::Nodes {
                        peers: vec![self.discovered.clone()],
                        truncated: false,
                    }
                }
                super::super::wire::DhtRequestPayload::Store { key, .. } if self.fail_store => {
                    return Err(DhtError::Internal("store failed".into()))
                }
                super::super::wire::DhtRequestPayload::Store { key, .. } => {
                    DhtResponsePayload::Stored { key }
                }
                super::super::wire::DhtRequestPayload::FindValue { key } => match &self.value {
                    Some(record) if !self.invalid_value => DhtResponsePayload::Value {
                        key,
                        value: serde_json::to_vec(record).expect("record json"),
                        signature: hex::decode(&record.signature).expect("signature"),
                        expires_at: record.expires_at,
                    },
                    Some(record) => DhtResponsePayload::Value {
                        key,
                        value: b"bad".to_vec(),
                        signature: vec![],
                        expires_at: record.expires_at,
                    },
                    None => DhtResponsePayload::NotFound { key },
                },
                _ => DhtResponsePayload::Pong,
            };
            Ok(DhtResponse {
                version: 1,
                request_id: request.request_id,
                responder_node_id: self.discovered.node_id,
                timestamp: request.timestamp,
                payload,
            })
        }
    }

    fn store_fixture() -> (EndpointRecord, PeerInfo) {
        let destination_key = key(20);
        (
            record(21, 100),
            PeerInfo::new(
                NodeId::from_bytes([22; 32]),
                hex::encode(destination_key.verifying_key().to_bytes()),
            ),
        )
    }

    fn routing_peer(value: u8) -> PeerInfo {
        PeerInfo::new(NodeId::from_bytes([value; 32]), format!("key-{value}"))
    }

    #[tokio::test]
    async fn publish_stores_to_k_peers() {
        let (record, discovered) = store_fixture();
        let transport = MockTransport {
            discovered,
            value: None,
            fail_store: false,
            invalid_value: false,
        };
        let mut routing = RoutingTable::new(NodeId::from_bytes([0; 32]));
        routing.insert(routing_peer(30), 100);
        let mut cache = EndpointCache::new(10);
        let mut store = EndpointStore::new(
            NodeId::from_bytes([0; 32]),
            &transport,
            &mut routing,
            &mut cache,
        );
        let report = store.publish(record.clone(), 110).await.expect("publish");
        assert!(report.peers_stored >= 1);
        assert!(cache.get(&record.identity_id).is_some());
    }

    #[tokio::test]
    async fn publish_reports_failures() {
        let (record, discovered) = store_fixture();
        let transport = MockTransport {
            discovered,
            value: None,
            fail_store: true,
            invalid_value: false,
        };
        let mut routing = RoutingTable::new(NodeId::from_bytes([0; 32]));
        routing.insert(routing_peer(31), 100);
        let mut cache = EndpointCache::new(10);
        let mut store = EndpointStore::new(
            NodeId::from_bytes([0; 32]),
            &transport,
            &mut routing,
            &mut cache,
        );
        let report = store.publish(record, 110).await.expect("publish");
        assert!(!report.failures.is_empty());
    }

    #[tokio::test]
    async fn publish_rejects_invalid_record() {
        let (mut record, discovered) = store_fixture();
        record.signature = "00".into();
        let transport = MockTransport {
            discovered,
            value: None,
            fail_store: false,
            invalid_value: false,
        };
        let mut routing = RoutingTable::new(NodeId::from_bytes([0; 32]));
        let mut cache = EndpointCache::new(10);
        let mut store = EndpointStore::new(
            NodeId::from_bytes([0; 32]),
            &transport,
            &mut routing,
            &mut cache,
        );
        assert!(store.publish(record, 110).await.is_err());
    }

    #[tokio::test]
    async fn lookup_cache_hit() {
        let (record, discovered) = store_fixture();
        let transport = MockTransport {
            discovered,
            value: None,
            fail_store: true,
            invalid_value: false,
        };
        let mut routing = RoutingTable::new(NodeId::from_bytes([0; 32]));
        let mut cache = EndpointCache::new(10);
        cache.insert(record.clone()).expect("cache");
        let mut store = EndpointStore::new(
            NodeId::from_bytes([0; 32]),
            &transport,
            &mut routing,
            &mut cache,
        );
        assert_eq!(
            store
                .lookup(&record.identity_id, 110)
                .await
                .expect("lookup"),
            Some(record)
        );
    }

    #[tokio::test]
    async fn lookup_cache_miss_fetches() {
        let (record, discovered) = store_fixture();
        let transport = MockTransport {
            discovered: discovered.clone(),
            value: Some(record.clone()),
            fail_store: false,
            invalid_value: false,
        };
        let mut routing = RoutingTable::new(NodeId::from_bytes([0; 32]));
        routing.insert(discovered, 100);
        let mut cache = EndpointCache::new(10);
        let mut store = EndpointStore::new(
            NodeId::from_bytes([0; 32]),
            &transport,
            &mut routing,
            &mut cache,
        );
        assert_eq!(
            store
                .lookup(&record.identity_id, 110)
                .await
                .expect("lookup"),
            Some(record)
        );
    }

    #[tokio::test]
    async fn lookup_not_found() {
        let (record, discovered) = store_fixture();
        let transport = MockTransport {
            discovered,
            value: None,
            fail_store: false,
            invalid_value: false,
        };
        let mut routing = RoutingTable::new(NodeId::from_bytes([0; 32]));
        routing.insert(routing_peer(32), 100);
        let mut cache = EndpointCache::new(10);
        let mut store = EndpointStore::new(
            NodeId::from_bytes([0; 32]),
            &transport,
            &mut routing,
            &mut cache,
        );
        assert!(store
            .lookup(&record.identity_id, 110)
            .await
            .expect("lookup")
            .is_none());
    }

    #[tokio::test]
    async fn lookup_rejects_invalid_from_dht() {
        let (record, discovered) = store_fixture();
        let transport = MockTransport {
            discovered,
            value: Some(record.clone()),
            fail_store: false,
            invalid_value: true,
        };
        let mut routing = RoutingTable::new(NodeId::from_bytes([0; 32]));
        routing.insert(routing_peer(33), 100);
        let mut cache = EndpointCache::new(10);
        let mut store = EndpointStore::new(
            NodeId::from_bytes([0; 32]),
            &transport,
            &mut routing,
            &mut cache,
        );
        assert!(store.lookup(&record.identity_id, 110).await.is_err());
    }

    #[tokio::test]
    async fn refresh_bypasses_cache() {
        let (record, discovered) = store_fixture();
        let transport = MockTransport {
            discovered: discovered.clone(),
            value: Some(record.clone()),
            fail_store: false,
            invalid_value: false,
        };
        let mut routing = RoutingTable::new(NodeId::from_bytes([0; 32]));
        routing.insert(discovered, 100);
        let mut cache = EndpointCache::new(10);
        cache.insert(record.clone()).expect("cache");
        let mut store = EndpointStore::new(
            NodeId::from_bytes([0; 32]),
            &transport,
            &mut routing,
            &mut cache,
        );
        assert_eq!(
            store
                .refresh(&record.identity_id, 110)
                .await
                .expect("refresh"),
            Some(record)
        );
    }
}
