use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tokio::time::timeout;

use super::lookup::{LOOKUP_MAX_ROUNDS, LOOKUP_TIMEOUT_PER_RPC, LOOKUP_TOTAL_BUDGET};
use super::node_id::NodeId;
use super::revocation::{
    deserialize_revocation, revocation_dht_key, verify_revocation, RevocationLookupError,
    RevocationOracle, NEGATIVE_CACHE_TTL_SECS,
};
use super::routing::{RoutingTable, K};
use super::transport::DhtTransport;
use super::wire::{DhtRequest, DhtRequestPayload, DhtResponsePayload};

type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

struct RevocationCache {
    positive: HashSet<[u8; 32]>,
    negative: HashMap<[u8; 32], u64>,
    now_fn: Clock,
}

pub struct DhtRevocationOracle<T: DhtTransport> {
    local_id: NodeId,
    transport: Arc<T>,
    routing: Arc<tokio::sync::Mutex<RoutingTable>>,
    cache: Arc<StdMutex<RevocationCache>>,
}

impl<T: DhtTransport> DhtRevocationOracle<T> {
    pub fn new(
        local_id: NodeId,
        transport: Arc<T>,
        routing: Arc<tokio::sync::Mutex<RoutingTable>>,
    ) -> Self {
        Self::with_clock(local_id, transport, routing, Arc::new(unix_now))
    }

    pub fn with_clock(
        local_id: NodeId,
        transport: Arc<T>,
        routing: Arc<tokio::sync::Mutex<RoutingTable>>,
        now_fn: Clock,
    ) -> Self {
        Self {
            local_id,
            transport,
            routing,
            cache: Arc::new(StdMutex::new(RevocationCache {
                positive: HashSet::new(),
                negative: HashMap::new(),
                now_fn,
            })),
        }
    }

    async fn lookup(&self, token_hash: &[u8; 32]) -> Result<bool, RevocationLookupError> {
        let key = revocation_dht_key(token_hash);
        let target = NodeId::from_bytes(key);
        let mut queried = HashSet::new();
        let mut first_failure = None;
        let mut had_response = false;

        for _ in 0..LOOKUP_MAX_ROUNDS {
            let peers = self.routing.lock().await.closest(&target, K);
            let peers = peers
                .into_iter()
                .filter(|peer| peer.node_id != self.local_id && !queried.contains(&peer.node_id))
                .take(K)
                .collect::<Vec<_>>();
            if peers.is_empty() {
                break;
            }

            for peer in peers {
                queried.insert(peer.node_id);
                let now = unix_now();
                let request =
                    DhtRequest::new(DhtRequestPayload::FindValue { key }, self.local_id, now);
                let request_id = request.request_id;
                let response = match timeout(
                    LOOKUP_TIMEOUT_PER_RPC,
                    self.transport.send_request(&peer, request),
                )
                .await
                {
                    Ok(Ok(response)) => response,
                    Ok(Err(error)) => {
                        first_failure.get_or_insert_with(|| {
                            RevocationLookupError::Transport(error.to_string())
                        });
                        continue;
                    }
                    Err(_) => {
                        first_failure.get_or_insert(RevocationLookupError::Timeout);
                        continue;
                    }
                };

                if let Err(error) = response.validate(&request_id, unix_now()) {
                    first_failure
                        .get_or_insert_with(|| RevocationLookupError::Transport(error.to_string()));
                    continue;
                }
                had_response = true;
                match response.payload {
                    DhtResponsePayload::Value {
                        key: response_key,
                        value,
                        signature,
                        expires_at,
                    } => {
                        if response_key != key {
                            return Err(RevocationLookupError::InvalidRecord(
                                "DHT value key mismatch".into(),
                            ));
                        }
                        if expires_at <= unix_now() {
                            return Err(RevocationLookupError::InvalidRecord(
                                "DHT value is expired".into(),
                            ));
                        }
                        let record = deserialize_revocation(&value).map_err(|error| {
                            RevocationLookupError::InvalidRecord(error.to_string())
                        })?;
                        if record.token_hash != *token_hash {
                            return Err(RevocationLookupError::InvalidRecord(
                                "revocation token hash mismatch".into(),
                            ));
                        }
                        verify_revocation(&record).map_err(|error| {
                            RevocationLookupError::InvalidSignature(error.to_string())
                        })?;
                        if signature != record.revocation_signature {
                            return Err(RevocationLookupError::InvalidSignature(
                                "DHT signature metadata mismatch".into(),
                            ));
                        }
                        return Ok(true);
                    }
                    DhtResponsePayload::NotFound { key: response_key } => {
                        if response_key != key {
                            first_failure.get_or_insert_with(|| {
                                RevocationLookupError::Transport("DHT NotFound key mismatch".into())
                            });
                        }
                    }
                    DhtResponsePayload::Nodes { peers, .. } => {
                        let mut routing = self.routing.lock().await;
                        for peer in peers {
                            if peer.node_id != self.local_id {
                                routing.insert(peer, unix_now());
                            }
                        }
                    }
                    DhtResponsePayload::Error { code, message } => {
                        first_failure.get_or_insert_with(|| {
                            RevocationLookupError::Transport(format!("DHT error {code}: {message}"))
                        });
                    }
                    _ => {
                        first_failure.get_or_insert_with(|| {
                            RevocationLookupError::Transport(
                                "unexpected DHT response to FindValue".into(),
                            )
                        });
                    }
                }
            }
        }

        if let Some(error) = first_failure {
            return Err(error);
        }
        if !had_response {
            return Err(RevocationLookupError::Transport(
                "no DHT peers available to determine revocation status".into(),
            ));
        }
        Ok(false)
    }
}

#[async_trait]
impl<T: DhtTransport + Send + Sync> RevocationOracle for DhtRevocationOracle<T> {
    async fn is_revoked(&self, token_hash: &[u8; 32]) -> Result<bool, RevocationLookupError> {
        let now = {
            let cache = self.cache.lock().map_err(|_| {
                RevocationLookupError::Transport("revocation cache lock poisoned".into())
            })?;
            (cache.now_fn)()
        };
        {
            let mut cache = self.cache.lock().map_err(|_| {
                RevocationLookupError::Transport("revocation cache lock poisoned".into())
            })?;
            if cache.positive.contains(token_hash) {
                return Ok(true);
            }
            match cache.negative.get(token_hash).copied() {
                Some(inserted_at) if now.saturating_sub(inserted_at) < NEGATIVE_CACHE_TTL_SECS => {
                    return Ok(false);
                }
                Some(_) => {
                    cache.negative.remove(token_hash);
                }
                None => {}
            }
        }

        let is_revoked = timeout(LOOKUP_TOTAL_BUDGET, self.lookup(token_hash))
            .await
            .map_err(|_| RevocationLookupError::Timeout)??;
        let mut cache = self.cache.lock().map_err(|_| {
            RevocationLookupError::Transport("revocation cache lock poisoned".into())
        })?;
        if is_revoked {
            cache.positive.insert(*token_hash);
            cache.negative.remove(token_hash);
        } else {
            cache.negative.insert(*token_hash, now);
        }
        Ok(is_revoked)
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::revocation::{serialize_revocation, sign_revocation, RevocationRecord};
    use crate::dht::wire::{DhtError, DhtResponse, DHT_PROTOCOL_VERSION};
    use crate::dht::{PeerInfo, RoutingTable};
    use async_trait::async_trait;
    use ed25519_dalek::SigningKey;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    struct MockTransport {
        response: StdMutex<DhtResponse>,
        fail: bool,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl DhtTransport for MockTransport {
        async fn send_request(
            &self,
            _peer: &PeerInfo,
            request: DhtRequest,
        ) -> Result<DhtResponse, DhtError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(DhtError::Internal("mock transport failure".into()));
            }
            let mut response = self.response.lock().expect("mock response").clone();
            response.request_id = request.request_id;
            response.timestamp = unix_now();
            Ok(response)
        }
    }

    fn token(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn response(payload: DhtResponsePayload) -> DhtResponse {
        DhtResponse {
            version: DHT_PROTOCOL_VERSION,
            request_id: [0; 16],
            responder_node_id: NodeId::from_bytes([9; 32]),
            timestamp: unix_now(),
            payload,
        }
    }

    fn setup(
        payload: DhtResponsePayload,
        fail: bool,
        now: Arc<AtomicU64>,
    ) -> (DhtRevocationOracle<MockTransport>, Arc<MockTransport>) {
        let local_id = NodeId::from_bytes([0; 32]);
        let mut routing = RoutingTable::new(local_id);
        routing.insert(PeerInfo::new(NodeId::from_bytes([1; 32]), "peer".into()), 1);
        let transport = Arc::new(MockTransport {
            response: StdMutex::new(response(payload)),
            fail,
            calls: AtomicUsize::new(0),
        });
        let clock = now.clone();
        let oracle = DhtRevocationOracle::with_clock(
            local_id,
            Arc::clone(&transport),
            Arc::new(tokio::sync::Mutex::new(routing)),
            Arc::new(move || clock.load(Ordering::SeqCst)),
        );
        (oracle, transport)
    }

    fn valid_record(token_hash: [u8; 32]) -> RevocationRecord {
        sign_revocation(&key(42), token_hash, unix_now())
    }

    fn value_payload(record: &RevocationRecord) -> DhtResponsePayload {
        DhtResponsePayload::Value {
            key: revocation_dht_key(&record.token_hash),
            value: serialize_revocation(record).expect("serialize valid record"),
            signature: record.revocation_signature.to_vec(),
            expires_at: unix_now() + 3600,
        }
    }

    #[tokio::test]
    async fn lookup_not_found_records_negative_cache() {
        let token = token(1);
        let now = Arc::new(AtomicU64::new(1_000));
        let (oracle, transport) = setup(
            DhtResponsePayload::NotFound {
                key: revocation_dht_key(&token),
            },
            false,
            now,
        );
        assert_eq!(oracle.is_revoked(&token).await, Ok(false));
        assert_eq!(oracle.is_revoked(&token).await, Ok(false));
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn lookup_found_valid_record_returns_revoked() {
        let token = token(2);
        let record = valid_record(token);
        let (oracle, _) = setup(
            value_payload(&record),
            false,
            Arc::new(AtomicU64::new(1_000)),
        );
        assert_eq!(oracle.is_revoked(&token).await, Ok(true));
    }

    #[tokio::test]
    async fn lookup_invalid_signature_returns_error() {
        let token = token(3);
        let mut record = valid_record(token);
        record.revocation_signature[0] ^= 1;
        let (oracle, _) = setup(
            value_payload(&record),
            false,
            Arc::new(AtomicU64::new(1_000)),
        );
        assert!(matches!(
            oracle.is_revoked(&token).await,
            Err(RevocationLookupError::InvalidSignature(_))
        ));
    }

    #[tokio::test]
    async fn lookup_transport_error_propagates() {
        let token = token(4);
        let (oracle, _) = setup(
            DhtResponsePayload::NotFound {
                key: revocation_dht_key(&token),
            },
            true,
            Arc::new(AtomicU64::new(1_000)),
        );
        assert!(matches!(
            oracle.is_revoked(&token).await,
            Err(RevocationLookupError::Transport(_))
        ));
    }

    #[tokio::test]
    async fn positive_cache_never_expires() {
        let token = token(5);
        let record = valid_record(token);
        let now = Arc::new(AtomicU64::new(1_000));
        let (oracle, transport) = setup(value_payload(&record), false, now.clone());
        assert_eq!(oracle.is_revoked(&token).await, Ok(true));
        now.fetch_add(1_000_000_000, Ordering::SeqCst);
        assert_eq!(oracle.is_revoked(&token).await, Ok(true));
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn negative_cache_expires_after_ttl() {
        let token = token(6);
        let now = Arc::new(AtomicU64::new(1_000));
        let (oracle, transport) = setup(
            DhtResponsePayload::NotFound {
                key: revocation_dht_key(&token),
            },
            false,
            now.clone(),
        );
        assert_eq!(oracle.is_revoked(&token).await, Ok(false));
        now.fetch_add(NEGATIVE_CACHE_TTL_SECS - 1, Ordering::SeqCst);
        assert_eq!(oracle.is_revoked(&token).await, Ok(false));
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
        now.fetch_add(1, Ordering::SeqCst);
        assert_eq!(oracle.is_revoked(&token).await, Ok(false));
        assert_eq!(transport.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn revocation_dht_key_is_domain_separated() {
        assert_eq!(revocation_dht_key(&token(7)), revocation_dht_key(&token(7)));
        assert_ne!(revocation_dht_key(&token(7)), revocation_dht_key(&token(8)));
        assert_ne!(revocation_dht_key(&token(7)), token(7));
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let record = valid_record(token(9));
        let serialized = serialize_revocation(&record).expect("serialize");
        assert_eq!(deserialize_revocation(&serialized), Ok(record));
    }

    #[test]
    fn deserialize_rejects_truncated_bytes() {
        assert!(matches!(
            deserialize_revocation(b"{"),
            Err(crate::dht::RevocationError::Deserialization(_))
        ));
    }

    #[test]
    fn deserialize_rejects_wrong_signature_length() {
        let record = valid_record(token(12));
        let mut value: serde_json::Value =
            serde_json::from_slice(&serialize_revocation(&record).expect("serialize"))
                .expect("JSON value");
        value["revocation_signature"] = serde_json::json!(vec![0u8; 63]);
        let bytes = serde_json::to_vec(&value).expect("serialize malformed value");
        assert_eq!(
            deserialize_revocation(&bytes),
            Err(crate::dht::RevocationError::InvalidSignatureLength)
        );
    }

    #[test]
    fn deserialize_rejects_tampered_signature() {
        let mut record = valid_record(token(10));
        record.revocation_signature[0] ^= 1;
        let bytes = serialize_revocation(&record).expect("serialize");
        let decoded = deserialize_revocation(&bytes).expect("deserialize");
        assert!(verify_revocation(&decoded).is_err());
    }

    #[tokio::test]
    async fn lookup_caches_positive_across_calls() {
        let token = token(11);
        let record = valid_record(token);
        let (oracle, transport) = setup(
            value_payload(&record),
            false,
            Arc::new(AtomicU64::new(1_000)),
        );
        assert_eq!(oracle.is_revoked(&token).await, Ok(true));
        assert_eq!(oracle.is_revoked(&token).await, Ok(true));
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    }
}
