use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use tokio::sync::Mutex;

use super::badge::BadgeStore;
use super::complaint::{complaint_dht_key, verify_complaint, ComplaintRecord, COMPLAINT_TTL_SECS};
use super::endpoint::{endpoint_key, EndpointCache, EndpointRecord};
use super::journal_commit::{
    commit_dht_key, latest_dht_key, verify_commit, verify_pointer, JournalCommit,
    JournalCommitPointer, JOURNAL_COMMIT_TTL_SECS,
};
use super::jury_acceptance::{
    acceptance_dht_key, verify_acceptance, JuryAcceptanceRecord, ACCEPTANCE_TTL_SECS,
};
use super::jury_dkg_commitment::{
    commitment_dht_key, verify_commitment, JuryDkgCommitmentRecord, JURY_DKG_COMMITMENT_TTL_SECS,
};
use super::jury_dkg_commitment::{partial_dht_key, JURY_PARTIAL_TTL_SECS};
use super::node_id::NodeId;
use super::prekey_cache::{prekey_bundle_key, PrekeyCache};
use super::punch_request_cache::PunchRequestCache;
use super::revocation::{deserialize_revocation, revocation_dht_key, verify_revocation};
use super::routing::{RoutingTable, K};
use super::wire::{
    DhtRequest, DhtRequestPayload, DhtResponse, DhtResponsePayload, StoredRecord, StoredRecordType,
    ERR_INTERNAL, ERR_INVALID_REQUEST, ERR_INVALID_SIGNATURE,
};

pub struct DhtRequestHandler {
    local_id: NodeId,
    routing: Arc<Mutex<RoutingTable>>,
    cache: Arc<Mutex<EndpointCache>>,
    punch_cache: Option<Arc<Mutex<PunchRequestCache>>>,
    badge_store: Option<Arc<Mutex<BadgeStore>>>,
    prekey_cache: Option<Arc<Mutex<PrekeyCache>>>,
    revocation_records: Arc<Mutex<HashMap<[u8; 32], (Vec<u8>, Vec<u8>, u64)>>>,
    journal_commit_records: Arc<Mutex<HashMap<[u8; 32], StoredJournalCommit>>>,
    journal_commit_pointer_records: Arc<Mutex<HashMap<[u8; 32], StoredJournalCommitPointer>>>,
    jury_dkg_commitment_records: Arc<Mutex<HashMap<[u8; 32], StoredJuryDkgCommitment>>>,
    jury_partial_records: Arc<Mutex<HashMap<[u8; 32], StoredJuryPartial>>>,
    jury_vote_records: Arc<Mutex<HashMap<[u8; 32], StoredJuryPartial>>>,
    jury_verdict_records: Arc<Mutex<HashMap<[u8; 32], StoredJuryPartial>>>,
    jury_acceptance_records: Arc<Mutex<HashMap<[u8; 32], StoredJuryAcceptance>>>,
    complaint_records: Arc<Mutex<HashMap<[u8; 32], StoredComplaint>>>,
    abuse_metrics: Option<Arc<crate::abuse_metrics::AbuseMetrics>>,
    trust_graph: Option<Arc<crate::trust_graph::TrustGraph>>,
    local_public_key: String,
}

#[derive(Clone)]
struct StoredJournalCommit {
    issuer_node_id: [u8; 32],
    sequence: u64,
    value: Vec<u8>,
    signature: Vec<u8>,
    expires_at: u64,
}

#[derive(Clone)]
struct StoredJournalCommitPointer {
    latest_sequence: u64,
    value: Vec<u8>,
    signature: Vec<u8>,
    expires_at: u64,
}

#[derive(Clone)]
struct StoredJuryDkgCommitment {
    value: Vec<u8>,
    signature: Vec<u8>,
    expires_at: u64,
}

#[derive(Clone)]
struct StoredJuryPartial {
    value: Vec<u8>,
    signature: Vec<u8>,
    expires_at: u64,
}

#[derive(Clone)]
struct StoredJuryAcceptance {
    value: Vec<u8>,
    signature: Vec<u8>,
    expires_at: u64,
}

#[derive(Clone)]
struct StoredComplaint {
    value: Vec<u8>,
    signature: Vec<u8>,
    expires_at: u64,
}

impl DhtRequestHandler {
    pub fn new(
        local_id: NodeId,
        routing: Arc<Mutex<RoutingTable>>,
        cache: Arc<Mutex<EndpointCache>>,
        local_public_key: String,
    ) -> Self {
        Self {
            local_id,
            routing,
            cache,
            punch_cache: None,
            badge_store: None,
            prekey_cache: None,
            revocation_records: Arc::new(Mutex::new(HashMap::new())),
            journal_commit_records: Arc::new(Mutex::new(HashMap::new())),
            journal_commit_pointer_records: Arc::new(Mutex::new(HashMap::new())),
            jury_dkg_commitment_records: Arc::new(Mutex::new(HashMap::new())),
            jury_partial_records: Arc::new(Mutex::new(HashMap::new())),
            jury_vote_records: Arc::new(Mutex::new(HashMap::new())),
            jury_verdict_records: Arc::new(Mutex::new(HashMap::new())),
            jury_acceptance_records: Arc::new(Mutex::new(HashMap::new())),
            complaint_records: Arc::new(Mutex::new(HashMap::new())),
            abuse_metrics: None,
            trust_graph: None,
            local_public_key,
        }
    }

    pub fn with_trust_graph(mut self, graph: Arc<crate::trust_graph::TrustGraph>) -> Self {
        self.trust_graph = Some(graph);
        self
    }

    pub fn with_abuse_metrics(
        mut self,
        abuse_metrics: Arc<crate::abuse_metrics::AbuseMetrics>,
    ) -> Self {
        self.abuse_metrics = Some(abuse_metrics);
        self
    }

    pub fn with_punch_cache(mut self, punch_cache: Arc<Mutex<PunchRequestCache>>) -> Self {
        self.punch_cache = Some(punch_cache);
        self
    }

    pub fn with_badge_store(mut self, badge_store: Arc<Mutex<BadgeStore>>) -> Self {
        self.badge_store = Some(badge_store);
        self
    }

    pub fn with_prekey_cache(
        mut self,
        prekey_cache: Arc<Mutex<PrekeyCache>>,
        abuse_metrics: Arc<crate::abuse_metrics::AbuseMetrics>,
    ) -> Self {
        self.prekey_cache = Some(prekey_cache);
        self.abuse_metrics = Some(abuse_metrics);
        self
    }

    pub fn local_id(&self) -> NodeId {
        self.local_id
    }

    pub async fn handle(&self, request: DhtRequest, now: u64) -> DhtResponse {
        let _ = &self.local_public_key;
        let request_id = request.request_id;
        let sender_id = request.sender_node_id;
        let payload = match request.payload {
            DhtRequestPayload::Ping => DhtResponsePayload::Pong,
            DhtRequestPayload::FindNode { target } => {
                let peers = self.routing.lock().await.closest(&target, K);
                DhtResponsePayload::Nodes {
                    peers,
                    truncated: false,
                }
            }
            DhtRequestPayload::FindValue { key } => {
                let jury_acceptance = {
                    let mut records = self.jury_acceptance_records.lock().await;
                    records.retain(|_, record| record.expires_at > now);
                    records.get(&key).cloned()
                };
                if let Some(record) = jury_acceptance {
                    return DhtResponse {
                        version: super::wire::DHT_PROTOCOL_VERSION,
                        request_id,
                        responder_node_id: self.local_id,
                        timestamp: now,
                        payload: DhtResponsePayload::Value {
                            key,
                            value: record.value,
                            signature: record.signature,
                            expires_at: record.expires_at,
                        },
                    };
                }
                let complaint = {
                    let mut records = self.complaint_records.lock().await;
                    records.retain(|_, record| record.expires_at > now);
                    records.get(&key).cloned()
                };
                if let Some(record) = complaint {
                    return DhtResponse {
                        version: super::wire::DHT_PROTOCOL_VERSION,
                        request_id,
                        responder_node_id: self.local_id,
                        timestamp: now,
                        payload: DhtResponsePayload::Value {
                            key,
                            value: record.value,
                            signature: record.signature,
                            expires_at: record.expires_at,
                        },
                    };
                }
                let jury_partial = {
                    let mut records = self.jury_partial_records.lock().await;
                    records.retain(|_, record| record.expires_at > now);
                    records.get(&key).cloned()
                };
                if let Some(record) = jury_partial {
                    return DhtResponse {
                        version: super::wire::DHT_PROTOCOL_VERSION,
                        request_id,
                        responder_node_id: self.local_id,
                        timestamp: now,
                        payload: DhtResponsePayload::Value {
                            key,
                            value: record.value,
                            signature: record.signature,
                            expires_at: record.expires_at,
                        },
                    };
                }
                let jury_vote = {
                    let mut records = self.jury_vote_records.lock().await;
                    records.retain(|_, record| record.expires_at > now);
                    records.get(&key).cloned()
                };
                if let Some(record) = jury_vote {
                    return DhtResponse {
                        version: super::wire::DHT_PROTOCOL_VERSION,
                        request_id,
                        responder_node_id: self.local_id,
                        timestamp: now,
                        payload: DhtResponsePayload::Value {
                            key,
                            value: record.value,
                            signature: record.signature,
                            expires_at: record.expires_at,
                        },
                    };
                }
                let jury_verdict = {
                    let mut records = self.jury_verdict_records.lock().await;
                    records.retain(|_, record| record.expires_at > now);
                    records.get(&key).cloned()
                };
                if let Some(record) = jury_verdict {
                    return DhtResponse {
                        version: super::wire::DHT_PROTOCOL_VERSION,
                        request_id,
                        responder_node_id: self.local_id,
                        timestamp: now,
                        payload: DhtResponsePayload::Value {
                            key,
                            value: record.value,
                            signature: record.signature,
                            expires_at: record.expires_at,
                        },
                    };
                }
                let jury_dkg_commitment = {
                    let mut records = self.jury_dkg_commitment_records.lock().await;
                    records.retain(|_, record| record.expires_at > now);
                    records.get(&key).cloned()
                };
                if let Some(record) = jury_dkg_commitment {
                    return DhtResponse {
                        version: super::wire::DHT_PROTOCOL_VERSION,
                        request_id,
                        responder_node_id: self.local_id,
                        timestamp: now,
                        payload: DhtResponsePayload::Value {
                            key,
                            value: record.value,
                            signature: record.signature,
                            expires_at: record.expires_at,
                        },
                    };
                }
                let journal_commit_pointer = {
                    let mut records = self.journal_commit_pointer_records.lock().await;
                    records.retain(|_, record| record.expires_at > now);
                    records.get(&key).cloned()
                };
                if let Some(record) = journal_commit_pointer {
                    return DhtResponse {
                        version: super::wire::DHT_PROTOCOL_VERSION,
                        request_id,
                        responder_node_id: self.local_id,
                        timestamp: now,
                        payload: DhtResponsePayload::Value {
                            key,
                            value: record.value,
                            signature: record.signature,
                            expires_at: record.expires_at,
                        },
                    };
                }
                let journal_commit = {
                    let mut records = self.journal_commit_records.lock().await;
                    records.retain(|_, record| record.expires_at > now);
                    records.get(&key).cloned()
                };
                if let Some(record) = journal_commit {
                    return DhtResponse {
                        version: super::wire::DHT_PROTOCOL_VERSION,
                        request_id,
                        responder_node_id: self.local_id,
                        timestamp: now,
                        payload: DhtResponsePayload::Value {
                            key,
                            value: record.value,
                            signature: record.signature,
                            expires_at: record.expires_at,
                        },
                    };
                }
                let revocation = {
                    let mut records = self.revocation_records.lock().await;
                    records.retain(|_, (_, _, expires_at)| *expires_at > now);
                    records.get(&key).cloned()
                };
                if let Some((value, signature, expires_at)) = revocation {
                    return DhtResponse {
                        version: super::wire::DHT_PROTOCOL_VERSION,
                        request_id,
                        responder_node_id: self.local_id,
                        timestamp: now,
                        payload: DhtResponsePayload::Value {
                            key,
                            value,
                            signature,
                            expires_at,
                        },
                    };
                }
                let cached = self.cache.lock().await.get_by_endpoint_key(&key).cloned();
                if let Some(record) = cached.filter(|record| !record.is_expired(now)) {
                    let value = serde_json::to_vec(&record).unwrap_or_default();
                    let signature = hex::decode(&record.signature).unwrap_or_default();
                    DhtResponsePayload::Value {
                        key,
                        value,
                        signature,
                        expires_at: record.expires_at,
                    }
                } else {
                    let prekey_bundle = if let Some(prekey_cache) = &self.prekey_cache {
                        prekey_cache.lock().await.get_by_key(&key, now).cloned()
                    } else {
                        None
                    };
                    if let Some(bundle) = prekey_bundle {
                        let value = match serde_json::to_vec(&bundle) {
                            Ok(value) => value,
                            Err(error) => {
                                return self.error(
                                    request_id,
                                    now,
                                    ERR_INTERNAL,
                                    &error.to_string(),
                                );
                            }
                        };
                        if let Some(metrics) = &self.abuse_metrics {
                            metrics
                                .prekey_bundle_fetched_total
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        DhtResponsePayload::Value {
                            key,
                            value,
                            signature: bundle.bundle_signature.to_vec(),
                            expires_at: bundle.expires_at,
                        }
                    } else {
                        let punch_requests = if let Some(punch_cache) = &self.punch_cache {
                            punch_cache
                                .lock()
                                .await
                                .get(&key, now)
                                .into_iter()
                                .cloned()
                                .collect::<Vec<_>>()
                        } else {
                            Vec::new()
                        };
                        if punch_requests.is_empty() {
                            let badge_slot = if let Some(badge_store) = &self.badge_store {
                                badge_store
                                    .lock()
                                    .await
                                    .badges_for_subject(&NodeId::from_bytes(key))
                                    .into_iter()
                                    .filter(|badge| {
                                        badge.expires_at.is_none_or(|expires_at| expires_at > now)
                                    })
                                    .collect::<Vec<_>>()
                            } else {
                                Vec::new()
                            };
                            if !badge_slot.is_empty() {
                                let expires_at = badge_slot
                                    .iter()
                                    .map(|badge| {
                                        badge.expires_at.unwrap_or_else(|| {
                                            now.saturating_add(super::badge::BADGE_DEFAULT_TTL_SECS)
                                        })
                                    })
                                    .max()
                                    .unwrap_or(now);
                                let value = match StoredRecord::Badge(badge_slot).to_value() {
                                    Ok(value) => value,
                                    Err(error) => {
                                        return self.error(
                                            request_id,
                                            now,
                                            ERR_INTERNAL,
                                            &error.to_string(),
                                        );
                                    }
                                };
                                DhtResponsePayload::Value {
                                    key,
                                    value,
                                    signature: Vec::new(),
                                    expires_at,
                                }
                            } else {
                                let target = NodeId::from_bytes(key);
                                let peers = self.routing.lock().await.closest(&target, K);
                                DhtResponsePayload::Nodes {
                                    peers,
                                    truncated: false,
                                }
                            }
                        } else {
                            let value = match StoredRecord::PunchRequest(punch_requests.clone())
                                .to_value()
                            {
                                Ok(value) => value,
                                Err(error) => {
                                    return self.error(
                                        request_id,
                                        now,
                                        ERR_INTERNAL,
                                        &error.to_string(),
                                    );
                                }
                            };
                            DhtResponsePayload::Value {
                                key,
                                value,
                                signature: Vec::new(),
                                expires_at: punch_requests
                                    .iter()
                                    .map(|request| request.expires_at)
                                    .max()
                                    .unwrap_or(now),
                            }
                        }
                    }
                }
            }
            DhtRequestPayload::Store {
                key,
                value,
                signature: _,
                expires_at,
            } => {
                return self
                    .store_endpoint(request_id, now, key, value, expires_at)
                    .await
            }
            DhtRequestPayload::StoreTyped {
                key,
                value,
                signature,
                expires_at,
                record_type,
            } => {
                if let Some(graph) = &self.trust_graph {
                    match graph.gate(&sender_id, now).await {
                        crate::trust_graph::TrustGateDecision::Allow => {}
                        crate::trust_graph::TrustGateDecision::Throttle { .. }
                        | crate::trust_graph::TrustGateDecision::Block { .. } => {
                            if let Some(metrics) = &self.abuse_metrics {
                                metrics
                                    .trust_gate_blocked_total
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            return self.error(
                                request_id,
                                now,
                                ERR_INVALID_SIGNATURE,
                                "trust gate blocked",
                            );
                        }
                    }
                }
                match record_type.unwrap_or(StoredRecordType::Endpoint) {
                    StoredRecordType::Endpoint => {
                        return self
                            .store_endpoint(request_id, now, key, value, expires_at)
                            .await;
                    }
                    StoredRecordType::PunchRequest => {
                        return self
                            .store_punch_requests(request_id, now, key, value, expires_at)
                            .await;
                    }
                    StoredRecordType::Badge => {
                        return self
                            .store_badges(request_id, now, key, value, expires_at)
                            .await;
                    }
                    StoredRecordType::PrekeyBundle => {
                        return self
                            .store_prekey_bundle(request_id, now, key, value, signature, expires_at)
                            .await;
                    }
                    StoredRecordType::InviteRevocation => {
                        return self
                            .store_revocation(request_id, now, key, value, signature, expires_at)
                            .await;
                    }
                    StoredRecordType::JournalCommit => {
                        return self
                            .store_journal_commit(
                                request_id, now, key, value, signature, expires_at,
                            )
                            .await;
                    }
                    StoredRecordType::JournalCommitPointer => {
                        return self
                            .store_journal_commit_pointer(
                                request_id, now, key, value, signature, expires_at,
                            )
                            .await;
                    }
                    StoredRecordType::JuryDkgCommitment => {
                        return self
                            .store_jury_dkg_commitment(
                                request_id, now, key, value, signature, expires_at,
                            )
                            .await;
                    }
                    StoredRecordType::JuryPartial => {
                        return self
                            .store_jury_partial(request_id, now, key, value, signature, expires_at)
                            .await;
                    }
                    StoredRecordType::JuryVote => {
                        return self
                            .store_jury_vote(request_id, now, key, value, signature, expires_at)
                            .await;
                    }
                    StoredRecordType::JuryVerdict => {
                        return self
                            .store_jury_verdict(request_id, now, key, value, signature, expires_at)
                            .await;
                    }
                    StoredRecordType::JuryAcceptance => {
                        return self
                            .store_jury_acceptance(
                                request_id, now, key, value, signature, expires_at,
                            )
                            .await;
                    }
                    StoredRecordType::ComplaintRecord => {
                        return self
                            .store_complaint_record(
                                request_id, now, key, value, signature, expires_at,
                            )
                            .await;
                    }
                    StoredRecordType::Unknown => {
                        return self.error(
                            request_id,
                            now,
                            ERR_INVALID_REQUEST,
                            "unknown DHT record type",
                        );
                    }
                }
            }
        };
        DhtResponse {
            version: super::wire::DHT_PROTOCOL_VERSION,
            request_id,
            responder_node_id: self.local_id,
            timestamp: now,
            payload,
        }
    }

    async fn store_endpoint(
        &self,
        request_id: [u8; 16],
        now: u64,
        key: [u8; 32],
        value: Vec<u8>,
        expires_at: u64,
    ) -> DhtResponse {
        if expires_at <= now {
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "endpoint record expired",
            );
        }

        let record: EndpointRecord = match serde_json::from_slice(&value) {
            Ok(record) => record,
            Err(error) => {
                return self.error(request_id, now, ERR_INVALID_REQUEST, &error.to_string());
            }
        };
        if endpoint_key(&record.identity_id) != key || record.expires_at != expires_at {
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "endpoint key mismatch",
            );
        }
        if record.verify(now).is_err() || record.verify_identity().is_err() {
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "endpoint signature invalid",
            );
        }
        if self.cache.lock().await.insert(record).is_err() {
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "endpoint cache rejected record",
            );
        }
        DhtResponse {
            version: super::wire::DHT_PROTOCOL_VERSION,
            request_id,
            responder_node_id: self.local_id,
            timestamp: now,
            payload: DhtResponsePayload::Stored { key },
        }
    }

    async fn store_prekey_bundle(
        &self,
        request_id: [u8; 16],
        now: u64,
        key: [u8; 32],
        value: Vec<u8>,
        signature: Vec<u8>,
        expires_at: u64,
    ) -> DhtResponse {
        let Some(prekey_cache) = &self.prekey_cache else {
            return self.error(
                request_id,
                now,
                ERR_INTERNAL,
                "prekey bundle cache unavailable",
            );
        };
        let bundle: hal_crypto::PrekeyBundle = match serde_json::from_slice(&value) {
            Ok(bundle) => bundle,
            Err(error) => {
                self.record_prekey_verify_failure();
                return self.error(request_id, now, ERR_INVALID_REQUEST, &error.to_string());
            }
        };
        let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&bundle.identity_key) {
            Ok(key) => key,
            Err(error) => {
                self.record_prekey_verify_failure();
                return self.error(request_id, now, ERR_INVALID_SIGNATURE, &error.to_string());
            }
        };
        let identity = NodeId::from_public_key(&verifying_key);
        if prekey_bundle_key(&identity) != key
            || bundle.expires_at != expires_at
            || signature != bundle.bundle_signature
        {
            self.record_prekey_verify_failure();
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "prekey bundle key or expiry mismatch",
            );
        }
        if let Err(error) = bundle.verify(now) {
            self.record_prekey_verify_failure();
            return self.error(request_id, now, ERR_INVALID_SIGNATURE, &error.to_string());
        }
        if let Err(error) = prekey_cache
            .lock()
            .await
            .insert(identity, bundle, expires_at, now)
        {
            self.record_prekey_verify_failure();
            return self.error(request_id, now, ERR_INVALID_SIGNATURE, &error.to_string());
        }
        if let Some(metrics) = &self.abuse_metrics {
            metrics
                .prekey_bundle_stored_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        DhtResponse {
            version: super::wire::DHT_PROTOCOL_VERSION,
            request_id,
            responder_node_id: self.local_id,
            timestamp: now,
            payload: DhtResponsePayload::Stored { key },
        }
    }

    async fn store_revocation(
        &self,
        request_id: [u8; 16],
        now: u64,
        key: [u8; 32],
        value: Vec<u8>,
        signature: Vec<u8>,
        expires_at: u64,
    ) -> DhtResponse {
        if expires_at <= now {
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "revocation record expired",
            );
        }

        let record = match deserialize_revocation(&value) {
            Ok(record) => record,
            Err(error) => {
                return self.error(request_id, now, ERR_INVALID_REQUEST, &error.to_string());
            }
        };
        if revocation_dht_key(&record.token_hash) != key
            || signature != record.revocation_signature
            || verify_revocation(&record).is_err()
        {
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "revocation key or signature invalid",
            );
        }
        let mut records = self.revocation_records.lock().await;
        records.retain(|_, (_, _, record_expires_at)| *record_expires_at > now);
        if !records.contains_key(&key) && records.len() >= 4096 {
            return self.error(
                request_id,
                now,
                super::wire::ERR_STORAGE_FULL,
                "revocation store full",
            );
        }
        records.insert(key, (value, signature, expires_at));
        DhtResponse {
            version: super::wire::DHT_PROTOCOL_VERSION,
            request_id,
            responder_node_id: self.local_id,
            timestamp: now,
            payload: DhtResponsePayload::Stored { key },
        }
    }

    async fn store_journal_commit(
        &self,
        request_id: [u8; 16],
        now: u64,
        key: [u8; 32],
        value: Vec<u8>,
        signature: Vec<u8>,
        expires_at: u64,
    ) -> DhtResponse {
        let commit: JournalCommit = match serde_json::from_slice(&value) {
            Ok(commit) => commit,
            Err(error) => {
                return self.error(request_id, now, ERR_INVALID_REQUEST, &error.to_string());
            }
        };
        if verify_commit(&commit).is_err() {
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "journal commit signature invalid",
            );
        }
        let expected_key = commit_dht_key(&commit.issuer_node_id, commit.sequence);
        let maximum_expiry = commit.published_at.checked_add(JOURNAL_COMMIT_TTL_SECS);
        if expected_key != key
            || signature != commit.signature
            || commit.published_at > now
            || maximum_expiry.is_none_or(|maximum| expires_at > maximum)
            || expires_at <= now
        {
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "journal commit key, signature, or expiry invalid",
            );
        }

        let mut records = self.journal_commit_records.lock().await;
        records.retain(|_, record| record.expires_at > now);
        if let Some(existing) = records.get(&key) {
            if existing.value != value || existing.signature != signature {
                return self.error(
                    request_id,
                    now,
                    ERR_INVALID_SIGNATURE,
                    "journal commit sequence already stored with different content",
                );
            }
            return DhtResponse {
                version: super::wire::DHT_PROTOCOL_VERSION,
                request_id,
                responder_node_id: self.local_id,
                timestamp: now,
                payload: DhtResponsePayload::Stored { key },
            };
        }
        if records.values().any(|record| {
            record.issuer_node_id == commit.issuer_node_id && record.sequence >= commit.sequence
        }) {
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "journal commit sequence is not increasing",
            );
        }
        records.insert(
            key,
            StoredJournalCommit {
                issuer_node_id: commit.issuer_node_id,
                sequence: commit.sequence,
                value,
                signature,
                expires_at,
            },
        );
        DhtResponse {
            version: super::wire::DHT_PROTOCOL_VERSION,
            request_id,
            responder_node_id: self.local_id,
            timestamp: now,
            payload: DhtResponsePayload::Stored { key },
        }
    }

    async fn store_journal_commit_pointer(
        &self,
        request_id: [u8; 16],
        now: u64,
        key: [u8; 32],
        value: Vec<u8>,
        signature: Vec<u8>,
        expires_at: u64,
    ) -> DhtResponse {
        let pointer: JournalCommitPointer = match serde_json::from_slice(&value) {
            Ok(pointer) => pointer,
            Err(error) => {
                return self.error(request_id, now, ERR_INVALID_REQUEST, &error.to_string());
            }
        };
        if verify_pointer(&pointer).is_err() {
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "journal commit pointer signature invalid",
            );
        }
        let expected_key = latest_dht_key(&pointer.issuer_node_id);
        let maximum_expiry = pointer.published_at.checked_add(JOURNAL_COMMIT_TTL_SECS);
        if expected_key != key
            || signature != pointer.signature
            || pointer.published_at > now
            || maximum_expiry.is_none_or(|maximum| expires_at > maximum)
            || expires_at <= now
        {
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "journal commit pointer key, signature, or expiry invalid",
            );
        }

        let mut records = self.journal_commit_pointer_records.lock().await;
        records.retain(|_, record| record.expires_at > now);
        if let Some(existing) = records.get(&key) {
            if pointer.latest_sequence < existing.latest_sequence
                || (pointer.latest_sequence == existing.latest_sequence
                    && (existing.value != value || existing.signature != signature))
            {
                return self.error(
                    request_id,
                    now,
                    ERR_INVALID_SIGNATURE,
                    "journal commit pointer sequence is not increasing",
                );
            }
        }
        records.insert(
            key,
            StoredJournalCommitPointer {
                latest_sequence: pointer.latest_sequence,
                value,
                signature,
                expires_at,
            },
        );
        DhtResponse {
            version: super::wire::DHT_PROTOCOL_VERSION,
            request_id,
            responder_node_id: self.local_id,
            timestamp: now,
            payload: DhtResponsePayload::Stored { key },
        }
    }

    async fn store_jury_dkg_commitment(
        &self,
        request_id: [u8; 16],
        now: u64,
        key: [u8; 32],
        value: Vec<u8>,
        signature: Vec<u8>,
        expires_at: u64,
    ) -> DhtResponse {
        let record: JuryDkgCommitmentRecord = match serde_json::from_slice(&value) {
            Ok(record) => record,
            Err(error) => {
                return self.error(request_id, now, ERR_INVALID_REQUEST, &error.to_string());
            }
        };
        if verify_commitment(&record).is_err() {
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "jury DKG commitment signature or points invalid",
            );
        }
        let expected_key = commitment_dht_key(&record.complaint_id, &record.dealer_node_id);
        let maximum_expiry = record
            .published_at
            .checked_add(JURY_DKG_COMMITMENT_TTL_SECS);
        if expected_key != key
            || signature.as_slice() != record.signature
            || record.published_at > now
            || maximum_expiry != Some(expires_at)
            || expires_at <= now
        {
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "jury DKG commitment key, signature, or expiry invalid",
            );
        }

        let mut records = self.jury_dkg_commitment_records.lock().await;
        records.retain(|_, stored| stored.expires_at > now);
        if let Some(existing) = records.get(&key) {
            if existing.value != value || existing.signature != signature {
                return self.error(
                    request_id,
                    now,
                    ERR_INVALID_SIGNATURE,
                    "jury DKG commitment already stored with different content",
                );
            }
            return DhtResponse {
                version: super::wire::DHT_PROTOCOL_VERSION,
                request_id,
                responder_node_id: self.local_id,
                timestamp: now,
                payload: DhtResponsePayload::Stored { key },
            };
        }
        if records.len() >= 4096 {
            return self.error(
                request_id,
                now,
                super::wire::ERR_STORAGE_FULL,
                "jury DKG commitment store full",
            );
        }
        records.insert(
            key,
            StoredJuryDkgCommitment {
                value,
                signature,
                expires_at,
            },
        );
        DhtResponse {
            version: super::wire::DHT_PROTOCOL_VERSION,
            request_id,
            responder_node_id: self.local_id,
            timestamp: now,
            payload: DhtResponsePayload::Stored { key },
        }
    }

    async fn store_jury_acceptance(
        &self,
        request_id: [u8; 16],
        now: u64,
        key: [u8; 32],
        value: Vec<u8>,
        signature: Vec<u8>,
        expires_at: u64,
    ) -> DhtResponse {
        let record: JuryAcceptanceRecord = match serde_json::from_slice(&value) {
            Ok(record) => record,
            Err(error) => {
                return self.error(request_id, now, ERR_INVALID_REQUEST, &error.to_string());
            }
        };
        if verify_acceptance(&record).is_err() {
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "jury acceptance signature or binding invalid",
            );
        }
        let expected_key = acceptance_dht_key(&record.complaint_id, &record.juror_node_id);
        let expected_expiry = record.accepted_at.checked_add(ACCEPTANCE_TTL_SECS);
        if expected_key != key
            || signature.as_slice() != record.signature
            || record.accepted_at > now
            || expected_expiry != Some(expires_at)
            || expires_at <= now
        {
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "jury acceptance key, signature, or expiry invalid",
            );
        }

        let mut records = self.jury_acceptance_records.lock().await;
        records.retain(|_, stored| stored.expires_at > now);
        if let Some(existing) = records.get(&key) {
            if existing.value != value
                || existing.signature != signature
                || existing.expires_at != expires_at
            {
                return self.error(
                    request_id,
                    now,
                    ERR_INVALID_SIGNATURE,
                    "jury acceptance already stored with different content",
                );
            }
            return DhtResponse {
                version: super::wire::DHT_PROTOCOL_VERSION,
                request_id,
                responder_node_id: self.local_id,
                timestamp: now,
                payload: DhtResponsePayload::Stored { key },
            };
        }
        if records.len() >= 4096 {
            return self.error(
                request_id,
                now,
                super::wire::ERR_STORAGE_FULL,
                "jury acceptance store full",
            );
        }
        records.insert(
            key,
            StoredJuryAcceptance {
                value,
                signature,
                expires_at,
            },
        );
        DhtResponse {
            version: super::wire::DHT_PROTOCOL_VERSION,
            request_id,
            responder_node_id: self.local_id,
            timestamp: now,
            payload: DhtResponsePayload::Stored { key },
        }
    }

    async fn store_jury_partial(
        &self,
        request_id: [u8; 16],
        now: u64,
        key: [u8; 32],
        value: Vec<u8>,
        signature: Vec<u8>,
        expires_at: u64,
    ) -> DhtResponse {
        let partial: crate::jury_evidence::JuryPartialDecryption =
            match serde_json::from_slice(&value) {
                Ok(partial) => partial,
                Err(error) => {
                    return self.error(request_id, now, ERR_INVALID_REQUEST, &error.to_string());
                }
            };
        let public_key = match VerifyingKey::from_bytes(&partial.juror_public_key) {
            Ok(public_key) => public_key,
            Err(_) => {
                return self.error(
                    request_id,
                    now,
                    ERR_INVALID_SIGNATURE,
                    "jury partial public key invalid",
                );
            }
        };
        let expected_key = partial_dht_key(
            &partial.complaint_id,
            &partial.evidence_hash,
            &partial.juror_node_id,
        );
        let expected_expiry = partial.issued_at.checked_add(JURY_PARTIAL_TTL_SECS);
        if NodeId::from_public_key(&public_key).as_bytes() != &partial.juror_node_id
            || crate::jury_evidence::verify_partial_decryption_signature(&public_key, &partial)
                .is_err()
            || expected_key != key
            || signature.as_slice() != partial.signature
            || partial.issued_at > now
            || expected_expiry != Some(expires_at)
            || expires_at <= now
        {
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "jury partial key, signature, binding, or expiry invalid",
            );
        }

        let mut records = self.jury_partial_records.lock().await;
        records.retain(|_, record| record.expires_at > now);
        if let Some(existing) = records.get(&key) {
            if existing.value != value
                || existing.signature != signature
                || existing.expires_at != expires_at
            {
                return self.error(
                    request_id,
                    now,
                    ERR_INVALID_SIGNATURE,
                    "jury partial already stored with different content",
                );
            }
            return DhtResponse {
                version: super::wire::DHT_PROTOCOL_VERSION,
                request_id,
                responder_node_id: self.local_id,
                timestamp: now,
                payload: DhtResponsePayload::Stored { key },
            };
        }
        if records.len() >= 4096 {
            return self.error(
                request_id,
                now,
                super::wire::ERR_STORAGE_FULL,
                "jury partial store full",
            );
        }
        records.insert(
            key,
            StoredJuryPartial {
                value,
                signature,
                expires_at,
            },
        );
        DhtResponse {
            version: super::wire::DHT_PROTOCOL_VERSION,
            request_id,
            responder_node_id: self.local_id,
            timestamp: now,
            payload: DhtResponsePayload::Stored { key },
        }
    }

    async fn store_jury_vote(
        &self,
        request_id: [u8; 16],
        now: u64,
        key: [u8; 32],
        value: Vec<u8>,
        signature: Vec<u8>,
        expires_at: u64,
    ) -> DhtResponse {
        let vote: crate::jury_vote::JuryVote = match serde_json::from_slice(&value) {
            Ok(vote) => vote,
            Err(error) => {
                return self.error(request_id, now, ERR_INVALID_REQUEST, &error.to_string());
            }
        };
        let public_key = match VerifyingKey::from_bytes(&vote.juror_public_key) {
            Ok(public_key) => public_key,
            Err(_) => {
                return self.error(
                    request_id,
                    now,
                    ERR_INVALID_SIGNATURE,
                    "jury vote public key invalid",
                );
            }
        };
        let expected_expiry = vote
            .issued_at
            .checked_add(crate::jury_vote::JURY_VOTE_TTL_SECS);
        if crate::jury_vote::node_id_from_public_key(&public_key) != vote.juror_node_id
            || crate::jury_vote::verify_vote(&public_key, &vote).is_err()
            || crate::jury_vote::vote_dht_key(
                &vote.complaint_id,
                &vote.evidence_hash,
                &vote.juror_node_id,
            ) != key
            || signature.as_slice() != vote.signature
            || vote.issued_at > now
            || expected_expiry != Some(expires_at)
            || expires_at <= now
        {
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "jury vote key, signature, binding, or expiry invalid",
            );
        }

        let mut records = self.jury_vote_records.lock().await;
        records.retain(|_, record| record.expires_at > now);
        if let Some(existing) = records.get(&key) {
            if existing.value != value
                || existing.signature != signature
                || existing.expires_at != expires_at
            {
                return self.error(
                    request_id,
                    now,
                    ERR_INVALID_SIGNATURE,
                    "jury vote already stored with different content",
                );
            }
            return DhtResponse {
                version: super::wire::DHT_PROTOCOL_VERSION,
                request_id,
                responder_node_id: self.local_id,
                timestamp: now,
                payload: DhtResponsePayload::Stored { key },
            };
        }
        if records.len() >= 4096 {
            return self.error(
                request_id,
                now,
                super::wire::ERR_STORAGE_FULL,
                "jury vote store full",
            );
        }
        records.insert(
            key,
            StoredJuryPartial {
                value,
                signature,
                expires_at,
            },
        );
        DhtResponse {
            version: super::wire::DHT_PROTOCOL_VERSION,
            request_id,
            responder_node_id: self.local_id,
            timestamp: now,
            payload: DhtResponsePayload::Stored { key },
        }
    }

    async fn store_jury_verdict(
        &self,
        request_id: [u8; 16],
        now: u64,
        key: [u8; 32],
        value: Vec<u8>,
        signature: Vec<u8>,
        expires_at: u64,
    ) -> DhtResponse {
        let verdict: crate::jury_vote::JuryVerdict = match serde_json::from_slice(&value) {
            Ok(verdict) => verdict,
            Err(error) => {
                return self.error(request_id, now, ERR_INVALID_REQUEST, &error.to_string());
            }
        };
        if verdict.verdict != crate::jury_vote::JuryDecision::Guilty
            || verdict.juror_signatures.len()
                < crate::dht::jury_dkg_commitment::JURY_THRESHOLD as usize
            || crate::jury_vote::verdict_dht_key(&verdict.complaint_id, &verdict.evidence_hash)
                != key
            || verdict.issued_at > now
            || verdict
                .issued_at
                .checked_add(crate::jury_vote::JURY_VERDICT_TTL_SECS)
                != Some(expires_at)
            || expires_at <= now
            || verdict
                .juror_signatures
                .first()
                .is_none_or(|vote_ref| signature.as_slice() != vote_ref.signature)
        {
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "jury verdict binding, decision, signature count, or expiry invalid",
            );
        }

        let derived =
            match crate::jury_verdict_aggregator::derive_verdict(&verdict.juror_signatures) {
                Ok(derived) => derived,
                Err(_) => {
                    return self.error(
                        request_id,
                        now,
                        ERR_INVALID_SIGNATURE,
                        "jury verdict refs do not yield a valid verdict",
                    );
                }
            };
        if derived != verdict.verdict {
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "declared jury verdict does not match derived verdict",
            );
        }

        let mut seen_jurors = std::collections::HashSet::new();
        for vote_ref in &verdict.juror_signatures {
            if !seen_jurors.insert(vote_ref.juror_node_id) {
                return self.error(
                    request_id,
                    now,
                    ERR_INVALID_SIGNATURE,
                    "jury verdict has mismatched or duplicate juror votes",
                );
            }
            let public_key = match VerifyingKey::from_bytes(&vote_ref.juror_public_key) {
                Ok(public_key) => public_key,
                Err(_) => {
                    return self.error(
                        request_id,
                        now,
                        ERR_INVALID_SIGNATURE,
                        "jury verdict juror public key invalid",
                    );
                }
            };
            let vote = crate::jury_vote::vote_from_ref(
                verdict.complaint_id,
                verdict.evidence_hash,
                vote_ref,
            );
            if crate::jury_vote::node_id_from_public_key(&public_key) != vote_ref.juror_node_id
                || crate::jury_vote::verify_vote(&public_key, &vote).is_err()
            {
                return self.error(
                    request_id,
                    now,
                    ERR_INVALID_SIGNATURE,
                    "jury verdict contains invalid vote signature",
                );
            }
        }

        let mut records = self.jury_verdict_records.lock().await;
        records.retain(|_, record| record.expires_at > now);
        if let Some(existing) = records.get(&key) {
            if existing.value != value
                || existing.signature != signature
                || existing.expires_at != expires_at
            {
                return self.error(
                    request_id,
                    now,
                    ERR_INVALID_SIGNATURE,
                    "jury verdict already stored with different content",
                );
            }
            return DhtResponse {
                version: super::wire::DHT_PROTOCOL_VERSION,
                request_id,
                responder_node_id: self.local_id,
                timestamp: now,
                payload: DhtResponsePayload::Stored { key },
            };
        }
        if records.len() >= 4096 {
            return self.error(
                request_id,
                now,
                super::wire::ERR_STORAGE_FULL,
                "jury verdict store full",
            );
        }
        records.insert(
            key,
            StoredJuryPartial {
                value,
                signature,
                expires_at,
            },
        );
        DhtResponse {
            version: super::wire::DHT_PROTOCOL_VERSION,
            request_id,
            responder_node_id: self.local_id,
            timestamp: now,
            payload: DhtResponsePayload::Stored { key },
        }
    }

    async fn store_complaint_record(
        &self,
        request_id: [u8; 16],
        now: u64,
        key: [u8; 32],
        value: Vec<u8>,
        signature: Vec<u8>,
        expires_at: u64,
    ) -> DhtResponse {
        let record: ComplaintRecord = match serde_json::from_slice(&value) {
            Ok(record) => record,
            Err(error) => {
                return self.error(request_id, now, ERR_INVALID_REQUEST, &error.to_string());
            }
        };
        if verify_complaint(&record).is_err() {
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "complaint signature or canonical ID invalid",
            );
        }
        let expected_key = complaint_dht_key(&record.complaint_id);
        let expected_expiry = record.submitted_at.checked_add(COMPLAINT_TTL_SECS);
        if expected_key != key
            || signature.as_slice() != record.signature
            || record.submitted_at > now
            || expected_expiry != Some(expires_at)
            || expires_at <= now
        {
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "complaint key, signature, or expiry invalid",
            );
        }

        let mut records = self.complaint_records.lock().await;
        records.retain(|_, stored| stored.expires_at > now);
        if let Some(existing) = records.get(&key) {
            if existing.value != value
                || existing.signature != signature
                || existing.expires_at != expires_at
            {
                return self.error(
                    request_id,
                    now,
                    ERR_INVALID_SIGNATURE,
                    "complaint already stored with different content",
                );
            }
            return DhtResponse {
                version: super::wire::DHT_PROTOCOL_VERSION,
                request_id,
                responder_node_id: self.local_id,
                timestamp: now,
                payload: DhtResponsePayload::Stored { key },
            };
        }
        if records.len() >= 4096 {
            return self.error(
                request_id,
                now,
                super::wire::ERR_STORAGE_FULL,
                "complaint store full",
            );
        }
        records.insert(
            key,
            StoredComplaint {
                value,
                signature,
                expires_at,
            },
        );
        DhtResponse {
            version: super::wire::DHT_PROTOCOL_VERSION,
            request_id,
            responder_node_id: self.local_id,
            timestamp: now,
            payload: DhtResponsePayload::Stored { key },
        }
    }

    fn record_prekey_verify_failure(&self) {
        if let Some(metrics) = &self.abuse_metrics {
            metrics
                .prekey_bundle_verify_failed_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    async fn store_punch_requests(
        &self,
        request_id: [u8; 16],
        now: u64,
        key: [u8; 32],
        value: Vec<u8>,
        expires_at: u64,
    ) -> DhtResponse {
        if expires_at <= now {
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "punch request record expired",
            );
        }
        let requests = match StoredRecord::from_value(&value) {
            Ok(StoredRecord::PunchRequest(requests)) => requests,
            Ok(StoredRecord::Endpoint(_)) => {
                return self.error(request_id, now, ERR_INVALID_REQUEST, "record type mismatch");
            }
            Ok(StoredRecord::Badge(_)) => {
                return self.error(request_id, now, ERR_INVALID_REQUEST, "record type mismatch");
            }
            Err(error) => {
                return self.error(request_id, now, ERR_INVALID_REQUEST, &error.to_string());
            }
        };
        if let Err(error) = StoredRecord::PunchRequest(requests.clone()).validate_for_key(&key, now)
        {
            return self.error(request_id, now, ERR_INVALID_SIGNATURE, &error.to_string());
        }
        if requests.iter().map(|request| request.expires_at).max() != Some(expires_at) {
            return self.error(
                request_id,
                now,
                ERR_INVALID_REQUEST,
                "punch request expiry mismatch",
            );
        }
        let Some(punch_cache) = &self.punch_cache else {
            return self.error(
                request_id,
                now,
                ERR_INTERNAL,
                "punch request cache unavailable",
            );
        };
        let mut punch_cache = punch_cache.lock().await;
        for punch_request in requests {
            if let Err(error) = punch_cache.insert(key, punch_request, now) {
                return self.error(request_id, now, ERR_INVALID_REQUEST, &error.to_string());
            }
        }
        DhtResponse {
            version: super::wire::DHT_PROTOCOL_VERSION,
            request_id,
            responder_node_id: self.local_id,
            timestamp: now,
            payload: DhtResponsePayload::Stored { key },
        }
    }

    async fn store_badges(
        &self,
        request_id: [u8; 16],
        now: u64,
        key: [u8; 32],
        value: Vec<u8>,
        expires_at: u64,
    ) -> DhtResponse {
        if expires_at <= now {
            return self.error(
                request_id,
                now,
                ERR_INVALID_SIGNATURE,
                "badge record expired",
            );
        }
        let badges = match StoredRecord::from_value(&value) {
            Ok(StoredRecord::Badge(badges)) => badges,
            Ok(_) => {
                return self.error(request_id, now, ERR_INVALID_REQUEST, "record type mismatch");
            }
            Err(error) => {
                return self.error(request_id, now, ERR_INVALID_REQUEST, &error.to_string());
            }
        };
        if let Err(error) = StoredRecord::Badge(badges.clone()).validate_for_key(&key, now) {
            return self.error(request_id, now, ERR_INVALID_SIGNATURE, &error.to_string());
        }
        let Some(badge_store) = &self.badge_store else {
            return self.error(request_id, now, ERR_INTERNAL, "badge store unavailable");
        };
        let mut badge_store = badge_store.lock().await;
        for badge in badges {
            if let Err(error) = badge_store.publish(badge) {
                return self.error(request_id, now, ERR_INVALID_REQUEST, &error.to_string());
            }
        }
        DhtResponse {
            version: super::wire::DHT_PROTOCOL_VERSION,
            request_id,
            responder_node_id: self.local_id,
            timestamp: now,
            payload: DhtResponsePayload::Stored { key },
        }
    }

    fn error(&self, request_id: [u8; 16], now: u64, code: u16, message: &str) -> DhtResponse {
        DhtResponse {
            version: super::wire::DHT_PROTOCOL_VERSION,
            request_id,
            responder_node_id: self.local_id,
            timestamp: now,
            payload: DhtResponsePayload::Error {
                code,
                message: message.into(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::peer_info::PeerInfo;
    use super::*;
    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_COMPRESSED, scalar::Scalar};
    use ed25519_dalek::SigningKey;
    use hal_crypto::threshold_encrypt::{DleqProof, PartialDecryption};
    use sha2::Digest;
    use sha2::Sha256;
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::sync::Mutex as TokioMutex;
    use x25519_dalek::{PublicKey, StaticSecret};

    const PREKEY_NOW: u64 = 1_800_000_000;

    fn identity(key: &SigningKey) -> String {
        hex::encode(Sha256::digest(key.verifying_key().to_bytes()))
    }
    fn request(payload: DhtRequestPayload) -> DhtRequest {
        DhtRequest::new(payload, NodeId::from_bytes([9; 32]), 100)
    }

    fn punch_key(target_id: &NodeId) -> [u8; 32] {
        use sha2::Sha256;
        Sha256::digest([b"punch:".as_slice(), target_id.as_bytes()].concat()).into()
    }

    fn punch_request(seed: u8, now: u64) -> crate::signaling::PunchRequest {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        crate::signaling::PunchRequest::create(
            NodeId::from_public_key(&signing_key.verifying_key()),
            NodeId::from_bytes([99; 32]),
            "127.0.0.1:9000".parse().expect("socket address"),
            std::time::Duration::from_secs(300),
            now,
            &signing_key,
            [seed; 16],
        )
        .expect("create punch request")
    }
    fn handler() -> (
        DhtRequestHandler,
        Arc<Mutex<RoutingTable>>,
        Arc<Mutex<EndpointCache>>,
    ) {
        let routing = Arc::new(Mutex::new(RoutingTable::new(NodeId::from_bytes([1; 32]))));
        let cache = Arc::new(Mutex::new(EndpointCache::new(10)));
        (
            DhtRequestHandler::new(
                NodeId::from_bytes([1; 32]),
                routing.clone(),
                cache.clone(),
                "pub".into(),
            ),
            routing,
            cache,
        )
    }

    fn trust_graph_fixture() -> (
        Arc<crate::trust_graph::TrustGraph>,
        Arc<StdMutex<crate::pinning::KnownHosts>>,
        Arc<crate::abuse_metrics::AbuseMetrics>,
    ) {
        let hosts = Arc::new(StdMutex::new(crate::pinning::KnownHosts::new()));
        let scores = Arc::new(StdMutex::new(crate::dht::trust::TrustScoreManager::new()));
        let rates = Arc::new(StdMutex::new(crate::dht::rate_limit::RateLimiter::new()));
        let groups: Arc<dyn crate::dht::group::GroupGraph> =
            Arc::new(crate::dht::group::GroupRegistry::new());
        let oracle: Arc<dyn crate::dht::trust_oracle::TrustOracle> =
            Arc::new(crate::dht::trust_oracle::BasicTrustOracle::new(
                Arc::clone(&scores),
                Arc::clone(&rates),
                Arc::clone(&hosts),
                groups,
            ));
        let metrics = Arc::new(crate::abuse_metrics::AbuseMetrics::new());
        let graph = Arc::new(crate::trust_graph::TrustGraph::new(
            Arc::clone(&hosts),
            Arc::new(TokioMutex::new(
                crate::dht::invite_registry::InviteRegistry::new(),
            )),
            Arc::new(TokioMutex::new(crate::dht::badge::BadgeStore::new())),
            oracle,
            scores,
            rates,
            Arc::clone(&metrics),
        ));
        (graph, hosts, metrics)
    }

    fn prekey_bundle(seed: u8, issued_at: u64, expires_at: u64) -> hal_crypto::PrekeyBundle {
        let identity_key = SigningKey::from_bytes(&[seed; 32]);
        let secret = StaticSecret::from([seed.wrapping_add(1); 32]);
        hal_crypto::PrekeyBundle::create(
            &identity_key,
            PublicKey::from(&secret).to_bytes(),
            Vec::new(),
            1,
            issued_at,
            expires_at,
        )
        .expect("create prekey bundle")
    }

    fn jury_partial_record(key: &SigningKey) -> crate::jury_evidence::JuryPartialDecryption {
        let mut partial = crate::jury_evidence::JuryPartialDecryption {
            complaint_id: [91; 32],
            juror_node_id: *NodeId::from_public_key(&key.verifying_key()).as_bytes(),
            juror_public_key: [0; 32],
            juror_share_index: 1,
            evidence_hash: [92; 32],
            partial: PartialDecryption {
                share_index: 1,
                threshold: 5,
                participant_count: 7,
                partial: RISTRETTO_BASEPOINT_COMPRESSED,
                proof: DleqProof {
                    challenge: Scalar::ZERO,
                    response: Scalar::ZERO,
                    share_public: RISTRETTO_BASEPOINT_COMPRESSED,
                },
            },
            signature: [0; 64],
            issued_at: 100,
        };
        crate::jury_evidence::sign_partial_decryption(key, &mut partial)
            .expect("sign jury partial");
        partial
    }

    fn jury_vote_record(key: &SigningKey) -> crate::jury_vote::JuryVote {
        let mut vote = crate::jury_vote::JuryVote {
            complaint_id: [81; 32],
            evidence_hash: [82; 32],
            juror_node_id: *NodeId::from_public_key(&key.verifying_key()).as_bytes(),
            juror_public_key: [0; 32],
            decision: crate::jury_vote::JuryDecision::Guilty,
            issued_at: 100,
            signature: [0; 64],
        };
        crate::jury_vote::sign_vote(key, &mut vote).expect("sign jury vote");
        vote
    }

    fn with_prekey_handler(
        handler: DhtRequestHandler,
    ) -> (
        DhtRequestHandler,
        Arc<Mutex<super::super::prekey_cache::PrekeyCache>>,
        Arc<crate::abuse_metrics::AbuseMetrics>,
    ) {
        let cache = Arc::new(Mutex::new(
            super::super::prekey_cache::PrekeyCache::default(),
        ));
        let metrics = Arc::new(crate::abuse_metrics::AbuseMetrics::new());
        (
            handler.with_prekey_cache(Arc::clone(&cache), Arc::clone(&metrics)),
            cache,
            metrics,
        )
    }

    #[tokio::test]
    async fn handler_stores_and_returns_invite_revocation() {
        let (handler, _, _) = handler();
        let signing_key = SigningKey::from_bytes(&[71; 32]);
        let record = super::super::revocation::sign_revocation(&signing_key, [72; 32], 100);
        let key = super::super::revocation::revocation_dht_key(&record.token_hash);
        let value =
            super::super::revocation::serialize_revocation(&record).expect("serialize revocation");
        let signature = record.revocation_signature.to_vec();
        let stored = handler
            .handle(
                request(DhtRequestPayload::StoreTyped {
                    key,
                    value: value.clone(),
                    signature: signature.clone(),
                    expires_at: 200,
                    record_type: Some(StoredRecordType::InviteRevocation),
                }),
                100,
            )
            .await;
        assert!(matches!(
            stored.payload,
            DhtResponsePayload::Stored { key: stored_key } if stored_key == key
        ));

        let fetched = handler
            .handle(request(DhtRequestPayload::FindValue { key }), 100)
            .await;
        assert!(matches!(
            fetched.payload,
            DhtResponsePayload::Value {
                key: found_key,
                value: found_value,
                signature: found_signature,
                expires_at: 200,
            } if found_key == key && found_value == value && found_signature == signature
        ));
    }

    #[tokio::test]
    async fn handler_stores_and_returns_journal_commit() {
        let (handler, _, _) = handler();
        let signing_key = SigningKey::from_bytes(&[73; 32]);
        let commit = super::super::journal_commit::sign_commit(&signing_key, 1, [74; 32], 12, 100);
        let key = super::super::journal_commit::commit_dht_key(&commit.issuer_node_id, 1);
        let value = serde_json::to_vec(&commit).expect("serialize journal commit");
        let signature = commit.signature.to_vec();
        let expires_at = 100 + super::super::journal_commit::JOURNAL_COMMIT_TTL_SECS;

        let stored = handler
            .handle(
                request(DhtRequestPayload::StoreTyped {
                    key,
                    value: value.clone(),
                    signature: signature.clone(),
                    expires_at,
                    record_type: Some(StoredRecordType::JournalCommit),
                }),
                100,
            )
            .await;
        assert!(matches!(
            stored.payload,
            DhtResponsePayload::Stored { key: stored_key } if stored_key == key
        ));

        let fetched = handler
            .handle(request(DhtRequestPayload::FindValue { key }), 100)
            .await;
        assert!(matches!(
            fetched.payload,
            DhtResponsePayload::Value {
                key: found_key,
                value: found_value,
                signature: found_signature,
                expires_at: found_expires_at,
            } if found_key == key
                && found_value == value
                && found_signature == signature
                && found_expires_at == expires_at
        ));
    }

    #[tokio::test]
    async fn handler_stores_and_returns_journal_commit_pointer() {
        let (handler, _, _) = handler();
        let signing_key = SigningKey::from_bytes(&[78; 32]);
        let pointer = super::super::journal_commit::sign_pointer(&signing_key, 3, 100);
        let key = super::super::journal_commit::latest_dht_key(&pointer.issuer_node_id);
        let value = serde_json::to_vec(&pointer).expect("serialize journal commit pointer");
        let signature = pointer.signature.to_vec();
        let expires_at = 100 + super::super::journal_commit::JOURNAL_COMMIT_TTL_SECS;

        let stored = handler
            .handle(
                request(DhtRequestPayload::StoreTyped {
                    key,
                    value: value.clone(),
                    signature: signature.clone(),
                    expires_at,
                    record_type: Some(StoredRecordType::JournalCommitPointer),
                }),
                100,
            )
            .await;
        assert!(matches!(
            stored.payload,
            DhtResponsePayload::Stored { key: stored_key } if stored_key == key
        ));

        let fetched = handler
            .handle(request(DhtRequestPayload::FindValue { key }), 100)
            .await;
        assert!(matches!(
            fetched.payload,
            DhtResponsePayload::Value {
                key: found_key,
                value: found_value,
                signature: found_signature,
                expires_at: found_expires_at,
            } if found_key == key
                && found_value == value
                && found_signature == signature
                && found_expires_at == expires_at
        ));
    }

    #[tokio::test]
    async fn handler_stores_and_returns_jury_dkg_commitment() {
        let (handler, _, _) = handler();
        let signing_key = SigningKey::from_bytes(&[81; 32]);
        let point = curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT
            .compress()
            .to_bytes();
        let record = super::super::jury_dkg_commitment::sign_commitment(
            &signing_key,
            [82; 32],
            vec![point; super::super::jury_dkg_commitment::JURY_THRESHOLD as usize],
            100,
        )
        .expect("sign DKG commitment");
        let key = super::super::jury_dkg_commitment::commitment_dht_key(
            &record.complaint_id,
            &record.dealer_node_id,
        );
        let value = serde_json::to_vec(&record).expect("serialize DKG commitment");
        let signature = record.signature.to_vec();
        let expires_at = 100 + super::super::jury_dkg_commitment::JURY_DKG_COMMITMENT_TTL_SECS;

        let stored = handler
            .handle(
                request(DhtRequestPayload::StoreTyped {
                    key,
                    value: value.clone(),
                    signature: signature.clone(),
                    expires_at,
                    record_type: Some(StoredRecordType::JuryDkgCommitment),
                }),
                100,
            )
            .await;
        assert!(matches!(
            stored.payload,
            DhtResponsePayload::Stored { key: stored_key } if stored_key == key
        ));

        let fetched = handler
            .handle(request(DhtRequestPayload::FindValue { key }), 100)
            .await;
        assert!(matches!(
            fetched.payload,
            DhtResponsePayload::Value {
                key: found_key,
                value: found_value,
                signature: found_signature,
                expires_at: found_expires_at,
            } if found_key == key
                && found_value == value
                && found_signature == signature
                && found_expires_at == expires_at
        ));
    }

    #[tokio::test]
    async fn handler_accepts_valid_jury_partial() {
        let (handler, _, _) = handler();
        let signing_key = SigningKey::from_bytes(&[93; 32]);
        let partial = jury_partial_record(&signing_key);
        let key = partial_dht_key(
            &partial.complaint_id,
            &partial.evidence_hash,
            &partial.juror_node_id,
        );
        let value = serde_json::to_vec(&partial).expect("serialize partial");
        let signature = partial.signature.to_vec();
        let expires_at = partial.issued_at + JURY_PARTIAL_TTL_SECS;
        let stored = handler
            .handle(
                request(DhtRequestPayload::StoreTyped {
                    key,
                    value: value.clone(),
                    signature: signature.clone(),
                    expires_at,
                    record_type: Some(StoredRecordType::JuryPartial),
                }),
                100,
            )
            .await;
        assert!(matches!(
            stored.payload,
            DhtResponsePayload::Stored { key: stored_key } if stored_key == key
        ));
        assert!(matches!(
            handler
                .handle(request(DhtRequestPayload::FindValue { key }), 100)
                .await
                .payload,
            DhtResponsePayload::Value {
                key: found_key,
                value: found_value,
                signature: found_signature,
                expires_at: found_expiry,
            } if found_key == key
                && found_value == value
                && found_signature == signature
                && found_expiry == expires_at
        ));
    }

    #[tokio::test]
    async fn handler_rejects_partial_with_mismatched_juror_public_key() {
        let (handler, _, _) = handler();
        let signing_key = SigningKey::from_bytes(&[94; 32]);
        let mut partial = jury_partial_record(&signing_key);
        partial.juror_public_key = SigningKey::from_bytes(&[95; 32]).verifying_key().to_bytes();
        let key = partial_dht_key(
            &partial.complaint_id,
            &partial.evidence_hash,
            &partial.juror_node_id,
        );
        let signature = partial.signature.to_vec();
        let stored = handler
            .handle(
                request(DhtRequestPayload::StoreTyped {
                    key,
                    value: serde_json::to_vec(&partial).expect("serialize partial"),
                    signature,
                    expires_at: partial.issued_at + JURY_PARTIAL_TTL_SECS,
                    record_type: Some(StoredRecordType::JuryPartial),
                }),
                100,
            )
            .await;
        assert!(matches!(stored.payload, DhtResponsePayload::Error { .. }));
    }

    #[tokio::test]
    async fn handler_accepts_valid_jury_vote() {
        let (handler, _, _) = handler();
        let vote = jury_vote_record(&SigningKey::from_bytes(&[96; 32]));
        let key = crate::jury_vote::vote_dht_key(
            &vote.complaint_id,
            &vote.evidence_hash,
            &vote.juror_node_id,
        );
        let value = serde_json::to_vec(&vote).expect("serialize vote");
        let stored = handler
            .handle(
                request(DhtRequestPayload::StoreTyped {
                    key,
                    value: value.clone(),
                    signature: vote.signature.to_vec(),
                    expires_at: vote.issued_at + crate::jury_vote::JURY_VOTE_TTL_SECS,
                    record_type: Some(StoredRecordType::JuryVote),
                }),
                101,
            )
            .await;
        assert!(matches!(
            stored.payload,
            DhtResponsePayload::Stored { key: stored_key } if stored_key == key
        ));
        let fetched = handler
            .handle(request(DhtRequestPayload::FindValue { key }), 101)
            .await;
        assert!(matches!(
            fetched.payload,
            DhtResponsePayload::Value { value: found, .. } if found == value
        ));
    }

    #[tokio::test]
    async fn handler_rejects_vote_with_mismatched_key() {
        let (handler, _, _) = handler();
        let vote = jury_vote_record(&SigningKey::from_bytes(&[97; 32]));
        let key = [98; 32];
        let stored = handler
            .handle(
                request(DhtRequestPayload::StoreTyped {
                    key,
                    value: serde_json::to_vec(&vote).expect("serialize vote"),
                    signature: vote.signature.to_vec(),
                    expires_at: vote.issued_at + crate::jury_vote::JURY_VOTE_TTL_SECS,
                    record_type: Some(StoredRecordType::JuryVote),
                }),
                101,
            )
            .await;
        assert!(matches!(stored.payload, DhtResponsePayload::Error { .. }));
    }

    #[tokio::test]
    async fn handler_rejects_non_guilty_verdict() {
        let (handler, _, _) = handler();
        let verdict = crate::jury_vote::JuryVerdict {
            complaint_id: [81; 32],
            evidence_hash: [82; 32],
            verdict: crate::jury_vote::JuryDecision::NotGuilty,
            juror_signatures: Vec::new(),
            issued_at: 100,
        };
        let stored = handler
            .handle(
                request(DhtRequestPayload::StoreTyped {
                    key: crate::jury_vote::verdict_dht_key(
                        &verdict.complaint_id,
                        &verdict.evidence_hash,
                    ),
                    value: serde_json::to_vec(&verdict).expect("serialize verdict"),
                    signature: Vec::new(),
                    expires_at: verdict.issued_at + crate::jury_vote::JURY_VERDICT_TTL_SECS,
                    record_type: Some(StoredRecordType::JuryVerdict),
                }),
                101,
            )
            .await;
        assert!(matches!(stored.payload, DhtResponsePayload::Error { .. }));
    }

    #[tokio::test]
    async fn handler_rejects_verdict_with_derived_mismatch() {
        let (handler, _, _) = handler();
        let complaint_id = [83; 32];
        let evidence_hash = [84; 32];
        let mut refs = Vec::new();
        for index in 1..=5 {
            let key = SigningKey::from_bytes(&[index + 100; 32]);
            let mut vote = crate::jury_vote::JuryVote {
                complaint_id,
                evidence_hash,
                juror_node_id: crate::jury_vote::node_id_from_public_key(&key.verifying_key()),
                juror_public_key: [0; 32],
                decision: crate::jury_vote::JuryDecision::NotGuilty,
                issued_at: 100,
                signature: [0; 64],
            };
            crate::jury_vote::sign_vote(&key, &mut vote).expect("sign juror vote");
            refs.push(crate::jury_vote::JurorVoteRef {
                juror_node_id: vote.juror_node_id,
                juror_public_key: vote.juror_public_key,
                decision: vote.decision,
                issued_at: vote.issued_at,
                signature: vote.signature,
            });
        }
        let verdict = crate::jury_vote::JuryVerdict {
            complaint_id,
            evidence_hash,
            verdict: crate::jury_vote::JuryDecision::Guilty,
            juror_signatures: refs,
            issued_at: 100,
        };
        let key = crate::jury_vote::verdict_dht_key(&complaint_id, &evidence_hash);
        let stored = handler
            .handle(
                request(DhtRequestPayload::StoreTyped {
                    key,
                    value: serde_json::to_vec(&verdict).expect("serialize verdict"),
                    signature: verdict.juror_signatures[0].signature.to_vec(),
                    expires_at: verdict.issued_at + crate::jury_vote::JURY_VERDICT_TTL_SECS,
                    record_type: Some(StoredRecordType::JuryVerdict),
                }),
                101,
            )
            .await;
        assert!(matches!(stored.payload, DhtResponsePayload::Error { .. }));
    }

    #[tokio::test]
    async fn handler_stores_and_returns_complaint_record() {
        let (handler, _, _) = handler();
        let signing_key = SigningKey::from_bytes(&[85; 32]);
        let record = super::super::complaint::create_complaint(
            &signing_key,
            [86; 32],
            super::super::complaint::ComplaintKind::Fraud,
            100,
            200,
            300,
        )
        .expect("create complaint");
        let key = super::super::complaint::complaint_dht_key(&record.complaint_id);
        let value = serde_json::to_vec(&record).expect("serialize complaint");
        let signature = record.signature.to_vec();
        let expires_at = 300 + super::super::complaint::COMPLAINT_TTL_SECS;

        let stored = handler
            .handle(
                request(DhtRequestPayload::StoreTyped {
                    key,
                    value: value.clone(),
                    signature: signature.clone(),
                    expires_at,
                    record_type: Some(StoredRecordType::ComplaintRecord),
                }),
                301,
            )
            .await;
        assert!(matches!(
            stored.payload,
            DhtResponsePayload::Stored { key: stored_key } if stored_key == key
        ));

        let fetched = handler
            .handle(request(DhtRequestPayload::FindValue { key }), 301)
            .await;
        assert!(matches!(
            fetched.payload,
            DhtResponsePayload::Value {
                key: found_key,
                value: found_value,
                signature: found_signature,
                expires_at: found_expires_at,
            } if found_key == key
                && found_value == value
                && found_signature == signature
                && found_expires_at == expires_at
        ));
    }

    #[tokio::test]
    async fn handler_stores_and_returns_jury_acceptance() {
        let (handler, _, _) = handler();
        let signing_key = SigningKey::from_bytes(&[91; 32]);
        let record = super::super::jury_acceptance::sign_acceptance(&signing_key, [92; 32], 3, 100)
            .expect("sign jury acceptance");
        let key = super::super::jury_acceptance::acceptance_dht_key(
            &record.complaint_id,
            &record.juror_node_id,
        );
        let value = serde_json::to_vec(&record).expect("serialize jury acceptance");
        let signature = record.signature.to_vec();
        let expires_at = record.accepted_at + super::super::jury_acceptance::ACCEPTANCE_TTL_SECS;

        let stored = handler
            .handle(
                request(DhtRequestPayload::StoreTyped {
                    key,
                    value: value.clone(),
                    signature: signature.clone(),
                    expires_at,
                    record_type: Some(StoredRecordType::JuryAcceptance),
                }),
                101,
            )
            .await;
        assert!(matches!(
            stored.payload,
            DhtResponsePayload::Stored { key: stored_key } if stored_key == key
        ));

        let fetched = handler
            .handle(request(DhtRequestPayload::FindValue { key }), 101)
            .await;
        assert!(matches!(
            fetched.payload,
            DhtResponsePayload::Value {
                key: found_key,
                value: found_value,
                signature: found_signature,
                expires_at: found_expires_at,
            } if found_key == key
                && found_value == value
                && found_signature == signature
                && found_expires_at == expires_at
        ));
    }

    #[tokio::test]
    async fn handler_rejects_jury_acceptance_with_wrong_dht_key() {
        let (handler, _, _) = handler();
        let record = super::super::jury_acceptance::sign_acceptance(
            &SigningKey::from_bytes(&[93; 32]),
            [94; 32],
            1,
            100,
        )
        .expect("sign jury acceptance");
        let response = handler
            .handle(
                request(DhtRequestPayload::StoreTyped {
                    key: [95; 32],
                    value: serde_json::to_vec(&record).expect("serialize jury acceptance"),
                    signature: record.signature.to_vec(),
                    expires_at: record.accepted_at
                        + super::super::jury_acceptance::ACCEPTANCE_TTL_SECS,
                    record_type: Some(StoredRecordType::JuryAcceptance),
                }),
                101,
            )
            .await;
        assert!(matches!(
            response.payload,
            DhtResponsePayload::Error {
                code: ERR_INVALID_SIGNATURE,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn handler_rejects_complaint_with_wrong_dht_key() {
        let (handler, _, _) = handler();
        let signing_key = SigningKey::from_bytes(&[87; 32]);
        let record = super::super::complaint::create_complaint(
            &signing_key,
            [88; 32],
            super::super::complaint::ComplaintKind::Abuse,
            100,
            200,
            300,
        )
        .expect("create complaint");
        let response = handler
            .handle(
                request(DhtRequestPayload::StoreTyped {
                    key: [89; 32],
                    value: serde_json::to_vec(&record).expect("serialize complaint"),
                    signature: record.signature.to_vec(),
                    expires_at: 300 + super::super::complaint::COMPLAINT_TTL_SECS,
                    record_type: Some(StoredRecordType::ComplaintRecord),
                }),
                301,
            )
            .await;
        assert!(matches!(
            response.payload,
            DhtResponsePayload::Error {
                code: ERR_INVALID_SIGNATURE,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn handler_rejects_jury_dkg_commitment_with_wrong_dht_key() {
        let (handler, _, _) = handler();
        let signing_key = SigningKey::from_bytes(&[83; 32]);
        let point = curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT
            .compress()
            .to_bytes();
        let record = super::super::jury_dkg_commitment::sign_commitment(
            &signing_key,
            [84; 32],
            vec![point; super::super::jury_dkg_commitment::JURY_THRESHOLD as usize],
            100,
        )
        .expect("sign DKG commitment");
        let key = [0x55; 32];
        let response = handler
            .handle(
                request(DhtRequestPayload::StoreTyped {
                    key,
                    value: serde_json::to_vec(&record).expect("serialize DKG commitment"),
                    signature: record.signature.to_vec(),
                    expires_at: 100
                        + super::super::jury_dkg_commitment::JURY_DKG_COMMITMENT_TTL_SECS,
                    record_type: Some(StoredRecordType::JuryDkgCommitment),
                }),
                100,
            )
            .await;
        assert!(matches!(
            response.payload,
            DhtResponsePayload::Error {
                code: ERR_INVALID_SIGNATURE,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn handler_rejects_non_increasing_journal_commit_sequence() {
        let (handler, _, _) = handler();
        let signing_key = SigningKey::from_bytes(&[75; 32]);
        let first = super::super::journal_commit::sign_commit(&signing_key, 2, [76; 32], 12, 100);
        let next = super::super::journal_commit::sign_commit(&signing_key, 1, [77; 32], 12, 100);
        let expires_at = 100 + super::super::journal_commit::JOURNAL_COMMIT_TTL_SECS;
        for commit in [first, next] {
            let key = super::super::journal_commit::commit_dht_key(
                &commit.issuer_node_id,
                commit.sequence,
            );
            let response = handler
                .handle(
                    request(DhtRequestPayload::StoreTyped {
                        key,
                        value: serde_json::to_vec(&commit).expect("serialize commit"),
                        signature: commit.signature.to_vec(),
                        expires_at,
                        record_type: Some(StoredRecordType::JournalCommit),
                    }),
                    100,
                )
                .await;
            if commit.sequence == 1 {
                assert!(matches!(
                    response.payload,
                    DhtResponsePayload::Error {
                        code: ERR_INVALID_SIGNATURE,
                        ..
                    }
                ));
            } else {
                assert!(matches!(
                    response.payload,
                    DhtResponsePayload::Stored { .. }
                ));
            }
        }
    }

    #[tokio::test]
    async fn handler_ping_returns_pong() {
        let (handler, _, _) = handler();
        assert!(matches!(
            handler
                .handle(request(DhtRequestPayload::Ping), 100)
                .await
                .payload,
            DhtResponsePayload::Pong
        ));
    }

    #[tokio::test]
    async fn handler_find_node_returns_closest() {
        let (handler, routing, _) = handler();
        routing.lock().await.insert(
            PeerInfo::new(NodeId::from_bytes([2; 32]), "key".into()),
            100,
        );
        let response = handler
            .handle(
                request(DhtRequestPayload::FindNode {
                    target: NodeId::from_bytes([2; 32]),
                }),
                100,
            )
            .await;
        assert!(
            matches!(response.payload, DhtResponsePayload::Nodes { ref peers, .. } if peers.len() == 1)
        );
    }

    #[tokio::test]
    async fn handler_find_value_hits_cache() {
        let (handler, _, cache) = handler();
        let key = SigningKey::from_bytes(&[3; 32]);
        let record = EndpointRecord::create(
            identity(&key),
            hex::encode(key.verifying_key().to_bytes()),
            vec!["127.0.0.1:1".into()],
            &key,
            100,
            100,
        )
        .expect("record");
        let dht_key = endpoint_key(&record.identity_id);
        cache.lock().await.insert(record).expect("cache");
        assert!(matches!(
            handler
                .handle(request(DhtRequestPayload::FindValue { key: dht_key }), 110)
                .await
                .payload,
            DhtResponsePayload::Value { .. }
        ));
    }

    #[tokio::test]
    async fn handler_find_value_miss_returns_nodes() {
        let (handler, routing, _) = handler();
        routing.lock().await.insert(
            PeerInfo::new(NodeId::from_bytes([4; 32]), "key".into()),
            100,
        );
        assert!(matches!(
            handler
                .handle(request(DhtRequestPayload::FindValue { key: [5; 32] }), 100)
                .await
                .payload,
            DhtResponsePayload::Nodes { .. }
        ));
    }

    #[tokio::test]
    async fn handler_store_validates_and_inserts() {
        let (handler, _, cache) = handler();
        let key = SigningKey::from_bytes(&[6; 32]);
        let record = EndpointRecord::create(
            identity(&key),
            hex::encode(key.verifying_key().to_bytes()),
            vec!["127.0.0.1:1".into()],
            &key,
            100,
            100,
        )
        .expect("record");
        let dht_key = endpoint_key(&record.identity_id);
        let value = serde_json::to_vec(&record).expect("json");
        assert!(matches!(
            handler
                .handle(
                    request(DhtRequestPayload::Store {
                        key: dht_key,
                        value,
                        signature: vec![],
                        expires_at: record.expires_at
                    }),
                    110
                )
                .await
                .payload,
            DhtResponsePayload::Stored { .. }
        ));
        assert!(cache.lock().await.get(&record.identity_id).is_some());
    }

    #[tokio::test]
    async fn store_typed_blocked_when_trust_gate_blocks() {
        let (base, _, _) = handler();
        let (graph, _, metrics) = trust_graph_fixture();
        let handler = base
            .with_trust_graph(graph)
            .with_abuse_metrics(Arc::clone(&metrics));
        let request = DhtRequest::new(
            DhtRequestPayload::StoreTyped {
                key: [0; 32],
                value: Vec::new(),
                signature: Vec::new(),
                expires_at: PREKEY_NOW + 100,
                record_type: Some(StoredRecordType::Endpoint),
            },
            NodeId::from_bytes([44; 32]),
            PREKEY_NOW,
        );

        let response = handler.handle(request, PREKEY_NOW).await;

        assert!(matches!(
            response.payload,
            DhtResponsePayload::Error {
                code: ERR_INVALID_SIGNATURE,
                ref message,
            } if message == "trust gate blocked"
        ));
        assert_eq!(metrics.snapshot().trust_gate_blocked_total, 1);
    }

    #[tokio::test]
    async fn store_typed_allowed_when_trust_gate_allows() {
        let (base, _, cache) = handler();
        let (graph, hosts, metrics) = trust_graph_fixture();
        let sender_key = SigningKey::from_bytes(&[45; 32]);
        let sender_id = NodeId::from_public_key(&sender_key.verifying_key());
        let sender_key_hex = hex::encode(sender_key.verifying_key().to_bytes());
        hosts
            .lock()
            .expect("hosts lock")
            .pin_manual(&sender_id.to_hex(), &sender_key_hex, PREKEY_NOW)
            .expect("pin store sender");
        let handler = base
            .with_trust_graph(graph)
            .with_abuse_metrics(Arc::clone(&metrics));
        let record = EndpointRecord::create(
            identity(&sender_key),
            sender_key_hex,
            vec!["127.0.0.1:9000".into()],
            &sender_key,
            PREKEY_NOW,
            PREKEY_NOW + 300,
        )
        .expect("endpoint record");
        let key = endpoint_key(&record.identity_id);
        let response = handler
            .handle(
                DhtRequest::new(
                    DhtRequestPayload::StoreTyped {
                        key,
                        value: serde_json::to_vec(&record).expect("record JSON"),
                        signature: Vec::new(),
                        expires_at: record.expires_at,
                        record_type: Some(StoredRecordType::Endpoint),
                    },
                    sender_id,
                    PREKEY_NOW,
                ),
                PREKEY_NOW,
            )
            .await;

        assert!(matches!(
            response.payload,
            DhtResponsePayload::Stored { key: stored_key } if stored_key == key
        ));
        assert!(cache.lock().await.get(&record.identity_id).is_some());
        assert_eq!(metrics.snapshot().trust_gate_blocked_total, 0);
    }

    #[tokio::test]
    async fn store_typed_no_trust_graph_backward_compat() {
        let (handler, _, cache) = handler();
        let sender_key = SigningKey::from_bytes(&[46; 32]);
        let record = EndpointRecord::create(
            identity(&sender_key),
            hex::encode(sender_key.verifying_key().to_bytes()),
            vec!["127.0.0.1:9001".into()],
            &sender_key,
            PREKEY_NOW,
            PREKEY_NOW + 300,
        )
        .expect("endpoint record");
        let key = endpoint_key(&record.identity_id);
        let response = handler
            .handle(
                DhtRequest::new(
                    DhtRequestPayload::StoreTyped {
                        key,
                        value: serde_json::to_vec(&record).expect("record JSON"),
                        signature: Vec::new(),
                        expires_at: record.expires_at,
                        record_type: Some(StoredRecordType::Endpoint),
                    },
                    NodeId::from_bytes([47; 32]),
                    PREKEY_NOW,
                ),
                PREKEY_NOW,
            )
            .await;

        assert!(matches!(
            response.payload,
            DhtResponsePayload::Stored { .. }
        ));
        assert!(cache.lock().await.get(&record.identity_id).is_some());
    }

    #[tokio::test]
    async fn handler_store_rejects_invalid_signature() {
        let (handler, _, _) = handler();
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut record = EndpointRecord::create(
            identity(&key),
            hex::encode(key.verifying_key().to_bytes()),
            vec!["127.0.0.1:1".into()],
            &key,
            100,
            100,
        )
        .expect("record");
        record.signature = "00".into();
        let value = serde_json::to_vec(&record).expect("json");
        let response = handler
            .handle(
                request(DhtRequestPayload::Store {
                    key: endpoint_key(&record.identity_id),
                    value,
                    signature: vec![],
                    expires_at: record.expires_at,
                }),
                110,
            )
            .await;
        assert!(matches!(
            response.payload,
            DhtResponsePayload::Error {
                code: ERR_INVALID_SIGNATURE,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn handler_store_punch_request() {
        let (handler, _, _) = handler();
        let punch_cache = Arc::new(Mutex::new(PunchRequestCache::with_defaults()));
        let handler = handler.with_punch_cache(Arc::clone(&punch_cache));
        let punch = punch_request(21, 100);
        let key = punch_key(&punch.target_id);
        let expires_at = punch.expires_at;
        let value = StoredRecord::PunchRequest(vec![punch.clone()])
            .to_value()
            .expect("serialize punch slot");
        let response = handler
            .handle(
                request(DhtRequestPayload::StoreTyped {
                    key,
                    value,
                    signature: punch.signature.to_vec(),
                    expires_at,
                    record_type: Some(StoredRecordType::PunchRequest),
                }),
                100,
            )
            .await;
        assert!(
            matches!(response.payload, DhtResponsePayload::Stored { key: stored_key } if stored_key == key)
        );
        assert_eq!(punch_cache.lock().await.get(&key, 101).len(), 1);
    }

    #[tokio::test]
    async fn store_typed_prekey_bundle_accepted_and_findable() {
        let (base, _, _) = handler();
        let (handler, cache, metrics) = with_prekey_handler(base);
        let identity_key = SigningKey::from_bytes(&[31; 32]);
        let identity = NodeId::from_public_key(&identity_key.verifying_key());
        let bundle = prekey_bundle(31, PREKEY_NOW, PREKEY_NOW + 3600);
        let key = prekey_bundle_key(&identity);
        let response = handler
            .handle(
                DhtRequest::new(
                    DhtRequestPayload::StoreTyped {
                        key,
                        value: serde_json::to_vec(&bundle).expect("bundle JSON"),
                        signature: bundle.bundle_signature.to_vec(),
                        expires_at: bundle.expires_at,
                        record_type: Some(StoredRecordType::PrekeyBundle),
                    },
                    NodeId::from_bytes([9; 32]),
                    PREKEY_NOW,
                ),
                PREKEY_NOW,
            )
            .await;
        assert!(matches!(
            response.payload,
            DhtResponsePayload::Stored { key: stored_key } if stored_key == key
        ));
        assert!(cache.lock().await.get(&identity, PREKEY_NOW).is_some());
        assert_eq!(metrics.snapshot().prekey_bundle_stored_total, 1);

        let response = handler
            .handle(
                DhtRequest::new(
                    DhtRequestPayload::FindValue { key },
                    NodeId::from_bytes([9; 32]),
                    PREKEY_NOW,
                ),
                PREKEY_NOW,
            )
            .await;
        let DhtResponsePayload::Value {
            key: found_key,
            value,
            expires_at,
            ..
        } = response.payload
        else {
            panic!("expected cached prekey value");
        };
        assert_eq!(found_key, key);
        assert_eq!(expires_at, bundle.expires_at);
        assert_eq!(
            serde_json::from_slice::<hal_crypto::PrekeyBundle>(&value).expect("bundle value"),
            bundle
        );
        assert_eq!(metrics.snapshot().prekey_bundle_fetched_total, 1);
    }

    #[tokio::test]
    async fn store_typed_prekey_bundle_verify_failed() {
        let (base, _, _) = handler();
        let (handler, cache, metrics) = with_prekey_handler(base);
        let identity = NodeId::from_public_key(&SigningKey::from_bytes(&[32; 32]).verifying_key());
        let mut bundle = prekey_bundle(32, PREKEY_NOW, PREKEY_NOW + 3600);
        bundle.revision += 1;
        let response = handler
            .handle(
                DhtRequest::new(
                    DhtRequestPayload::StoreTyped {
                        key: prekey_bundle_key(&identity),
                        value: serde_json::to_vec(&bundle).expect("bundle JSON"),
                        signature: bundle.bundle_signature.to_vec(),
                        expires_at: bundle.expires_at,
                        record_type: Some(StoredRecordType::PrekeyBundle),
                    },
                    NodeId::from_bytes([9; 32]),
                    PREKEY_NOW,
                ),
                PREKEY_NOW,
            )
            .await;
        assert!(matches!(
            response.payload,
            DhtResponsePayload::Error {
                code: ERR_INVALID_SIGNATURE,
                ..
            }
        ));
        assert_eq!(cache.lock().await.len(), 0);
        assert_eq!(metrics.snapshot().prekey_bundle_verify_failed_total, 1);
    }

    #[tokio::test]
    async fn store_typed_expired_prekey_bundle_rejected() {
        let (base, _, _) = handler();
        let (handler, cache, metrics) = with_prekey_handler(base);
        let identity = NodeId::from_public_key(&SigningKey::from_bytes(&[33; 32]).verifying_key());
        let bundle = prekey_bundle(33, PREKEY_NOW - 100, PREKEY_NOW);
        let response = handler
            .handle(
                DhtRequest::new(
                    DhtRequestPayload::StoreTyped {
                        key: prekey_bundle_key(&identity),
                        value: serde_json::to_vec(&bundle).expect("bundle JSON"),
                        signature: bundle.bundle_signature.to_vec(),
                        expires_at: bundle.expires_at,
                        record_type: Some(StoredRecordType::PrekeyBundle),
                    },
                    NodeId::from_bytes([9; 32]),
                    PREKEY_NOW,
                ),
                PREKEY_NOW,
            )
            .await;
        assert!(matches!(
            response.payload,
            DhtResponsePayload::Error {
                code: ERR_INVALID_SIGNATURE,
                ..
            }
        ));
        assert_eq!(cache.lock().await.len(), 0);
        assert_eq!(metrics.snapshot().prekey_bundle_verify_failed_total, 1);
    }

    #[tokio::test]
    async fn handler_store_endpoint_legacy() {
        let (handler, _, cache) = handler();
        let key = SigningKey::from_bytes(&[22; 32]);
        let record = EndpointRecord::create(
            identity(&key),
            hex::encode(key.verifying_key().to_bytes()),
            vec!["127.0.0.1:2".into()],
            &key,
            100,
            100,
        )
        .expect("endpoint record");
        let slot_key = endpoint_key(&record.identity_id);
        let response = handler
            .handle(
                request(DhtRequestPayload::Store {
                    key: slot_key,
                    value: serde_json::to_vec(&record).expect("serialize endpoint"),
                    signature: Vec::new(),
                    expires_at: record.expires_at,
                }),
                110,
            )
            .await;
        assert!(matches!(response.payload, DhtResponsePayload::Stored { key } if key == slot_key));
        assert!(cache.lock().await.get(&record.identity_id).is_some());
    }

    #[tokio::test]
    async fn handler_find_value_punch() {
        let (handler, _, _) = handler();
        let punch_cache = Arc::new(Mutex::new(PunchRequestCache::with_defaults()));
        let handler = handler.with_punch_cache(Arc::clone(&punch_cache));
        let punch = punch_request(23, 100);
        let key = punch_key(&punch.target_id);
        punch_cache
            .lock()
            .await
            .insert(key, punch.clone(), 100)
            .expect("cache punch request");

        let response = handler
            .handle(request(DhtRequestPayload::FindValue { key }), 101)
            .await;
        let DhtResponsePayload::Value {
            key: found_key,
            value,
            ..
        } = response.payload
        else {
            panic!("expected cached punch value");
        };
        assert_eq!(found_key, key);
        let StoredRecord::PunchRequest(requests) =
            StoredRecord::from_value(&value).expect("decode punch slot")
        else {
            panic!("expected punch request record");
        };
        assert_eq!(requests, vec![punch]);
    }
}
