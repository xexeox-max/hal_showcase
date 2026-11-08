use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hal_settings::NetworkTrustPolicy;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, Mutex as TokioMutex};

use crate::dht::{EndpointCache, EndpointStore, MuxDhtTransport, NodeId, RoutingTable};
use crate::pinning::KnownHosts;
use crate::relay::{RelayForwardEvent, RelayPolicy, RelayRequest, RelayResponse};
use crate::runtime_context::RuntimeContext;
use crate::transport::{
    send_envelope_over_mux_sender, send_envelope_secure_with_stream_kind_and_metrics, SyncEnvelope,
};

pub const RELAY_QUEUE_CAPACITY: usize = 128;

pub struct RelayWork {
    pub from_identity: String,
    pub request: RelayRequest,
    pub received_at: u64,
    pub response_sender: Option<crate::mux::MuxSender>,
}

#[derive(Debug, Default)]
pub struct RelayMetrics {
    pub received_total: AtomicU64,
    pub forwarded_total: AtomicU64,
    pub rejected_total: AtomicU64,
    pub error_total: AtomicU64,
    pub queue_full_total: AtomicU64,
    pub queue_closed_total: AtomicU64,
    pub response_sent_total: AtomicU64,
    pub response_failed_total: AtomicU64,
    pub latency_micros_total: AtomicU64,
    pub latency_samples: AtomicU64,
    pub tracker_orphan_total: AtomicU64,
    pub forward_received_total: AtomicU64,
    pub forward_rejected_depth: AtomicU64,
    pub forward_rejected_binding: AtomicU64,
    pub stigma_rejected_total: AtomicU64,
    pub watching_seen_total: AtomicU64,
    pub proof_of_live_rejected_total: AtomicU64,
}

impl RelayMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> RelayMetricsSnapshot {
        let latency_micros_total = self.latency_micros_total.load(Ordering::Relaxed);
        let latency_samples = self.latency_samples.load(Ordering::Relaxed);
        RelayMetricsSnapshot {
            received_total: self.received_total.load(Ordering::Relaxed),
            forwarded_total: self.forwarded_total.load(Ordering::Relaxed),
            rejected_total: self.rejected_total.load(Ordering::Relaxed),
            error_total: self.error_total.load(Ordering::Relaxed),
            queue_full_total: self.queue_full_total.load(Ordering::Relaxed),
            queue_closed_total: self.queue_closed_total.load(Ordering::Relaxed),
            response_sent_total: self.response_sent_total.load(Ordering::Relaxed),
            response_failed_total: self.response_failed_total.load(Ordering::Relaxed),
            latency_micros_total,
            latency_samples,
            avg_latency_micros: latency_micros_total
                .checked_div(latency_samples)
                .unwrap_or_default(),
            tracker_orphan_total: self.tracker_orphan_total.load(Ordering::Relaxed),
            forward_received_total: self.forward_received_total.load(Ordering::Relaxed),
            forward_rejected_depth: self.forward_rejected_depth.load(Ordering::Relaxed),
            forward_rejected_binding: self.forward_rejected_binding.load(Ordering::Relaxed),
            stigma_rejected_total: self.stigma_rejected_total.load(Ordering::Relaxed),
            watching_seen_total: self.watching_seen_total.load(Ordering::Relaxed),
            proof_of_live_rejected_total: self.proof_of_live_rejected_total.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayMetricsSnapshot {
    pub received_total: u64,
    pub forwarded_total: u64,
    pub rejected_total: u64,
    pub error_total: u64,
    pub queue_full_total: u64,
    pub queue_closed_total: u64,
    pub response_sent_total: u64,
    pub response_failed_total: u64,
    pub latency_micros_total: u64,
    pub latency_samples: u64,
    pub avg_latency_micros: u64,
    pub tracker_orphan_total: u64,
    pub forward_received_total: u64,
    pub forward_rejected_depth: u64,
    pub forward_rejected_binding: u64,
    pub stigma_rejected_total: u64,
    pub watching_seen_total: u64,
    pub proof_of_live_rejected_total: u64,
}

pub struct RelayService {
    ctx: Arc<RuntimeContext>,
    private_key: SigningKey,
    identity_id: String,
    public_key: String,
    dht_local_id: NodeId,
    dht_routing: Arc<TokioMutex<RoutingTable>>,
    dht_cache: Arc<TokioMutex<EndpointCache>>,
    hosts: Arc<StdMutex<KnownHosts>>,
    trust_policy: NetworkTrustPolicy,
    metrics: Arc<RelayMetrics>,
    tracker: Arc<TokioMutex<HashMap<[u8; 16], oneshot::Sender<RelayResponse>>>>,
}

impl RelayService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ctx: Arc<RuntimeContext>,
        private_key: SigningKey,
        identity_id: String,
        public_key: String,
        dht_local_id: NodeId,
        dht_routing: Arc<TokioMutex<RoutingTable>>,
        dht_cache: Arc<TokioMutex<EndpointCache>>,
        hosts: Arc<StdMutex<KnownHosts>>,
        trust_policy: NetworkTrustPolicy,
    ) -> Self {
        Self {
            metrics: Arc::clone(&ctx.relay_metrics),
            tracker: Arc::clone(&ctx.relay_tracker),
            ctx,
            private_key,
            identity_id,
            public_key,
            dht_local_id,
            dht_routing,
            dht_cache,
            hosts,
            trust_policy,
        }
    }

    pub fn metrics(&self) -> Arc<RelayMetrics> {
        Arc::clone(&self.metrics)
    }

    pub fn tracker(&self) -> Arc<TokioMutex<HashMap<[u8; 16], oneshot::Sender<RelayResponse>>>> {
        Arc::clone(&self.tracker)
    }

    pub async fn handle(&self, work: RelayWork, now: u64) -> RelayResponse {
        let started = Instant::now();
        log::debug!("handling relay request from {}", work.from_identity);
        let response = self.do_handle(&work.request, now).await;
        match &response {
            RelayResponse::Forwarded => {
                self.metrics.forwarded_total.fetch_add(1, Ordering::Relaxed);
            }
            RelayResponse::Rejected { .. } => {
                self.metrics.rejected_total.fetch_add(1, Ordering::Relaxed);
            }
            RelayResponse::Error { .. } => {
                self.metrics.error_total.fetch_add(1, Ordering::Relaxed);
            }
            RelayResponse::Accepted { .. } => {}
        }
        let elapsed = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        self.metrics
            .latency_micros_total
            .fetch_add(elapsed, Ordering::Relaxed);
        self.metrics.latency_samples.fetch_add(1, Ordering::Relaxed);

        if self
            .send_response_with_session(
                work.request.requester_id,
                work.request.nonce,
                response.clone(),
                work.response_sender.as_ref(),
            )
            .await
            .is_ok()
        {
            self.metrics
                .response_sent_total
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.metrics
                .response_failed_total
                .fetch_add(1, Ordering::Relaxed);
        }
        response
    }

    pub async fn do_handle(&self, request: &RelayRequest, now: u64) -> RelayResponse {
        let envelope: SyncEnvelope = match serde_json::from_slice(&request.envelope_bytes) {
            Ok(envelope) => envelope,
            Err(error) => {
                return RelayResponse::Rejected {
                    reason: format!("malformed envelope: {error}"),
                };
            }
        };
        let requester_pubkey = match hex::decode(&envelope.public_key)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .and_then(|bytes: [u8; 32]| VerifyingKey::from_bytes(&bytes).ok())
        {
            Some(public_key) => public_key,
            None => {
                return RelayResponse::Rejected {
                    reason: "invalid envelope public_key".to_string(),
                };
            }
        };
        if NodeId::from_public_key(&requester_pubkey) != request.requester_id {
            return RelayResponse::Rejected {
                reason: "requester_id does not match envelope public_key".to_string(),
            };
        }
        if let Err(error) = request.verify(&requester_pubkey, self.dht_local_id, now) {
            return RelayResponse::Rejected {
                reason: format!("relay request verify failed: {error}"),
            };
        }
        #[cfg(all(debug_assertions, not(test)))]
        if self.ctx.proof_of_live.is_some() {
            log::trace!("PoL bypassed for debug relay request");
        }
        #[cfg(any(not(debug_assertions), test))]
        if let Some(pol) = self.ctx.proof_of_live.as_ref() {
            let status = pol.status(&request.requester_id, now).await;
            if !status.is_full() {
                self.metrics
                    .proof_of_live_rejected_total
                    .fetch_add(1, Ordering::Relaxed);
                return RelayResponse::Rejected {
                    reason: format!("requester proof-of-live: {status:?}"),
                };
            }
        }
        if self.ctx.rate_exceeded(&request.requester_id, now).await {
            return RelayResponse::Rejected {
                reason: "tier-aware rate exceeded".to_string(),
            };
        }
        match self
            .ctx
            .peer_admission(
                &request.requester_id.to_hex(),
                Some(&envelope.public_key),
                now,
            )
            .await
        {
            crate::runtime_context::PeerAdmission::Allowed { watching } => {
                if watching {
                    self.metrics
                        .watching_seen_total
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            crate::runtime_context::PeerAdmission::StigmaRejected => {
                self.metrics
                    .stigma_rejected_total
                    .fetch_add(1, Ordering::Relaxed);
                return RelayResponse::Rejected {
                    reason: "requester under stigma".to_string(),
                };
            }
            crate::runtime_context::PeerAdmission::DegradedUnknownRejected => {
                return RelayResponse::Rejected {
                    reason: "degraded: unknown peer rejected".to_string(),
                };
            }
        }
        if envelope.identity_id != request.requester_id.to_hex() {
            return RelayResponse::Rejected {
                reason: "requester identity_id does not match requester_id".to_string(),
            };
        }
        if !RelayPolicy::default_trusted().allows(
            self.ctx.oracle.as_ref(),
            &request.requester_id,
            now,
        ) {
            return RelayResponse::Rejected {
                reason: "relay policy denied".to_string(),
            };
        }
        if self.ctx.trust_graph.is_some()
            && !self.ctx.record_rate_acceptance(&request.requester_id, now)
        {
            return RelayResponse::Rejected {
                reason: "rate limit reached while reserving relay request".to_string(),
            };
        }

        let target_identity_id = request.target_id.to_hex();
        let target_session = {
            let state = self.ctx.home_state.lock().await;
            state
                .active_presence
                .get(&target_identity_id)
                .filter(|entry| {
                    entry
                        .record
                        .last_seen
                        .saturating_add(crate::peer_presence::PRESENCE_TTL_SECS)
                        > now
                        && state
                            .linked_device_pubkeys
                            .contains(&entry.record.public_key)
                        && entry.session_sender.is_alive()
                })
                .map(|entry| entry.session_sender.clone())
        };
        let target_endpoint = if target_session.is_none() {
            match self
                .lookup_authenticated_peer_directory_endpoint(&target_identity_id, now)
                .await
            {
                Some(endpoint) => {
                    log::debug!(
                        "Relay target {} resolved via authenticated peer directory",
                        target_identity_id
                    );
                    Some(endpoint)
                }
                None => match self.lookup_endpoint(&target_identity_id, now).await {
                    Ok(Some(endpoint)) => Some(endpoint),
                    Ok(None) => {
                        return RelayResponse::Rejected {
                            reason: "target endpoint not found".to_string(),
                        };
                    }
                    Err(error) => {
                        return RelayResponse::Error {
                            code: 1,
                            message: format!("target lookup failed: {error}"),
                        };
                    }
                },
            }
        } else {
            log::debug!("Relay target {target_identity_id} resolved via Home Presence session");
            None
        };
        let requester_consent = match request.to_base64() {
            Ok(consent) => consent,
            Err(error) => {
                return RelayResponse::Error {
                    code: 0,
                    message: format!("encode requester consent: {error:?}"),
                };
            }
        };
        let relay_forward_event = RelayForwardEvent {
            requester_id: request.requester_id,
            requester_identity_id: envelope.identity_id.clone(),
            requester_public_key_hex: envelope.public_key.clone(),
            relay_nonce: request.nonce,
            requester_consent,
            inner_envelope_base64: {
                use base64::{engine::general_purpose::STANDARD, Engine};
                STANDARD.encode(&request.envelope_bytes)
            },
            forwarded_at: now,
        };
        let forward_data = match relay_forward_event.to_base64() {
            Ok(encoded) => encoded,
            Err(error) => {
                return RelayResponse::Error {
                    code: 0,
                    message: format!("encode forward: {error:?}"),
                };
            }
        };
        let mut sync_event = crate::journal::SyncEvent::new(
            hex::encode(request.nonce),
            crate::journal::SyncEventType::RelayForward,
            forward_data,
        );
        if let Err(error) = sync_event.sign(&self.private_key.to_bytes()) {
            return RelayResponse::Error {
                code: 0,
                message: format!("sign forward: {error}"),
            };
        }
        let forward_envelope = SyncEnvelope::new(
            self.identity_id.clone(),
            self.public_key.clone(),
            vec![sync_event],
        );

        let used_presence_session = target_session.is_some();
        let mut forward_result = match target_session {
            Some(sender) => {
                send_envelope_over_mux_sender(
                    &sender,
                    &forward_envelope,
                    Some(&self.ctx.abuse_metrics),
                )
                .await
            }
            None => {
                let Some(endpoint) = target_endpoint.as_deref() else {
                    return RelayResponse::Error {
                        code: 1,
                        message: "no active target session or endpoint".to_string(),
                    };
                };
                send_envelope_secure_with_stream_kind_and_metrics(
                    endpoint,
                    &forward_envelope,
                    &self.private_key,
                    Arc::clone(&self.hosts),
                    None,
                    self.trust_policy.clone(),
                    crate::mux::StreamKind::Sync,
                    Arc::clone(&self.ctx.abuse_metrics),
                )
                .await
            }
        };
        let mut fallback_lookup_error = None;
        if forward_result.is_err() && used_presence_session {
            let authenticated_endpoint = self
                .lookup_authenticated_peer_directory_endpoint(&target_identity_id, now)
                .await;
            if let Some(endpoint) = authenticated_endpoint {
                forward_result = send_envelope_secure_with_stream_kind_and_metrics(
                    &endpoint,
                    &forward_envelope,
                    &self.private_key,
                    Arc::clone(&self.hosts),
                    None,
                    self.trust_policy.clone(),
                    crate::mux::StreamKind::Sync,
                    Arc::clone(&self.ctx.abuse_metrics),
                )
                .await;
            }
            if forward_result.is_err() {
                match self.lookup_endpoint(&target_identity_id, now).await {
                    Ok(Some(endpoint)) if Some(endpoint.as_str()) != target_endpoint.as_deref() => {
                        forward_result = send_envelope_secure_with_stream_kind_and_metrics(
                            &endpoint,
                            &forward_envelope,
                            &self.private_key,
                            Arc::clone(&self.hosts),
                            None,
                            self.trust_policy.clone(),
                            crate::mux::StreamKind::Sync,
                            Arc::clone(&self.ctx.abuse_metrics),
                        )
                        .await;
                    }
                    Ok(_) => {}
                    Err(error) => fallback_lookup_error = Some(error.to_string()),
                }
            }
        }
        match forward_result {
            Ok(()) => {
                log::info!(
                    "RelayForward sent to {} for requester {}",
                    request.target_id.to_hex(),
                    request.requester_id.to_hex()
                );
                RelayResponse::Forwarded
            }
            Err(error) => {
                RelayResponse::Error {
                    code: 0,
                    message: match fallback_lookup_error {
                        Some(lookup_error) => {
                            format!("forward failed: {error}; DHT fallback lookup failed: {lookup_error}")
                        }
                        None => format!("forward failed: {error}"),
                    },
                }
            }
        }
    }

    pub async fn lookup_endpoint(&self, identity_id: &str, now: u64) -> Result<Option<String>> {
        let transport = MuxDhtTransport::new(
            self.private_key.clone(),
            Arc::clone(&self.hosts),
            self.trust_policy.clone(),
        );
        let mut routing = self.dht_routing.lock().await;
        let mut cache = self.dht_cache.lock().await;
        let mut store = EndpointStore::new(self.dht_local_id, &transport, &mut routing, &mut cache);
        store
            .lookup(identity_id, now)
            .await
            .map(|record| record.and_then(|record| record.endpoints.first().cloned()))
            .map_err(|error| anyhow!(error.to_string()))
    }

    async fn lookup_authenticated_peer_directory_endpoint(
        &self,
        identity_id: &str,
        now: u64,
    ) -> Option<String> {
        let directory = self.ctx.peer_directory.lock().await;
        directory
            .lookup_by_identity(identity_id, now)
            .filter(|entry| {
                matches!(
                    entry.source,
                    crate::peer_directory::PeerEntrySource::InboundTls
                        | crate::peer_directory::PeerEntrySource::OutboundVerified
                )
            })
            .map(|entry| entry.address.clone())
    }

    pub async fn send_response(
        &self,
        requester_id: NodeId,
        request_nonce: [u8; 16],
        response: RelayResponse,
    ) -> Result<()> {
        self.send_response_with_session(requester_id, request_nonce, response, None)
            .await
    }

    async fn send_response_with_session(
        &self,
        requester_id: NodeId,
        request_nonce: [u8; 16],
        response: RelayResponse,
        session_sender: Option<&crate::mux::MuxSender>,
    ) -> Result<()> {
        let encoded_response = response.to_base64()?;
        let mut event = crate::journal::SyncEvent::new(
            hex::encode(request_nonce),
            crate::journal::SyncEventType::RelayResponse,
            encoded_response,
        );
        event.sign(&self.private_key.to_bytes())?;
        let envelope = SyncEnvelope::new(
            self.identity_id.clone(),
            self.public_key.clone(),
            vec![event],
        );
        if let Some(sender) = session_sender.filter(|sender| sender.is_alive()) {
            let session_send = tokio::time::timeout(
                Duration::from_secs(2),
                send_envelope_over_mux_sender(sender, &envelope, Some(&self.ctx.abuse_metrics)),
            )
            .await;
            if matches!(session_send, Ok(Ok(()))) {
                return Ok(());
            }
            log::warn!(
                "RelayResponse WSS session send failed for {}; falling back to DHT endpoint",
                requester_id.to_hex()
            );
        }
        let endpoint = self
            .lookup_endpoint(&requester_id.to_hex(), unix_now())
            .await?
            .ok_or_else(|| anyhow!("requester endpoint not found"))?;
        send_envelope_secure_with_stream_kind_and_metrics(
            &endpoint,
            &envelope,
            &self.private_key,
            Arc::clone(&self.hosts),
            None,
            self.trust_policy.clone(),
            crate::mux::StreamKind::Sync,
            Arc::clone(&self.ctx.abuse_metrics),
        )
        .await
        .map_err(|error| anyhow!(error.to_string()))
    }

    pub async fn deliver_to_tracker(&self, nonce: [u8; 16], response: RelayResponse) {
        let sender = self.tracker.lock().await.remove(&nonce);
        match sender {
            Some(sender) => {
                let _ = sender.send(response);
            }
            None => {
                self.metrics
                    .tracker_orphan_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

pub struct RelayWorkerTask {
    service: Arc<RelayService>,
}

impl RelayWorkerTask {
    pub fn new(service: Arc<RelayService>) -> Self {
        Self { service }
    }

    pub async fn run(self, mut rx: mpsc::Receiver<RelayWork>, mut shutdown: oneshot::Receiver<()>) {
        loop {
            let work = tokio::select! {
                biased;
                _ = &mut shutdown => break,
                work = rx.recv() => match work {
                    Some(work) => work,
                    None => break,
                },
            };
            self.service.handle(work, unix_now()).await;
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
