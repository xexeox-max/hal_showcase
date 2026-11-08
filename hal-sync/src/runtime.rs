use crate::abuse_metrics::AbuseMetrics;
use crate::address_refresh::{AddressRefresh, AddressRefreshConfig, AddressRefreshTask};
use crate::auto_badge_queue::PendingBadge;
use crate::auto_badge_worker::AutoBadgeWorker;
use crate::badge_fetch_task::{BadgeFetchConfig, BadgeFetchTask};
use crate::biometric_gate::{BiometricError, BiometricGate};
use crate::cold_contact_tracker::{
    ColdContactVerdict, COLD_CONTACT_LIMIT, COLD_CONTACT_WINDOW_SECS,
};
use crate::complainant_orchestrator::ComplainantOrchestratorTask;
use crate::dht::endpoint_lookup::{quic_dht_topic, quic_punch_dht_topic, DhtEndpointLookup};
use crate::dht::trust_oracle::Relationship;
use crate::dht::{
    Badge, BadgeMetricsSnapshot, BasicTrustOracle, BootstrapConfig, BootstrapReport,
    DhtPollerConfig, DhtRequestHandler, DhtTransport, EndpointCache, EndpointRecord, EndpointStore,
    GroupGraph, GroupRegistry, Lookup, LookupConfig, MuxDhtTransport, NodeId, PrekeyStore,
    PriorityLevel, PriorityRegistry, PublishReport, RateLimiter, RoutingTable, StigmaLevel,
    StoredRecord, StoredRecordType, TrustMetrics, TrustOracle, TrustScoreManager,
};
use crate::hole_punch::{punch_hole_with_strategy, HolePuncher, PunchOutcome};
use crate::inbound_observer_task::{InboundObserverTask, INBOUND_OBSERVATION_QUEUE_CAPACITY};
use crate::journal_commit_publisher::{dht_publish_transport, JournalCommitPublisher};
use crate::juror_orchestrator::JurorOrchestratorTask;
use crate::jury_delivery_outbox::JuryOutboxTask;
use crate::peer_directory::PeerEntry;
use crate::pinning::KnownHosts;
use crate::prekey_rotation_task::PrekeyRotationTask;
use crate::punch_fetch_task::{PunchFetchConfig, PunchFetchTask};
use crate::quic_transport::{QuicChannel, QuicConfig};
use crate::relay_service::{
    RelayMetricsSnapshot, RelayService, RelayWork, RelayWorkerTask, RELAY_QUEUE_CAPACITY,
};
use crate::retention_prune_task::RetentionPruneTask;
use crate::runtime_context::{NoopBiometricGate, RuntimeContext};
use crate::session_store::{ContactPolicy, SessionView};
use crate::signaling::SignalingStrategy;
use crate::stigma_refresh_task::StigmaRefreshTask;
use crate::tls_transport::TlsTransport;
use crate::transport::EnvelopeMeta;
use crate::transport::{send_envelope_quic, send_envelope_secure_with_stream_kind_and_metrics};
use crate::trust_graph::{TrustGateDecision, TrustGraph};
use crate::{
    open_home_sync_snapshot, seal_home_sync_snapshot, DeviceInfo, HomeSecret, HomeStack,
    HomeSyncChunk, LinkConfirm, LinkRequest, LinkResponse, LinkingQr,
};
use crate::{
    ActivityController, ActivityMode, ActivityPlan, ActivityTrigger, ChannelPollHandler,
    ChannelSource, InboundObservation, IntegrityResponse, IntegrityWave, PeerAnnouncement,
    PeerDiscovery, PeerTransport, PollDispatcher, PollRequest, PollingRuntime, SyncEnvelope,
    SyncEvent, SyncEventType, SyncManager,
};
use anyhow::{anyhow, Result};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{SigningKey, VerifyingKey};
use futures::StreamExt;
use hal_crypto::{PrekeyBundle, X3DHKeys, X3dhInitMessage, X3dhRespondMessage, X3DH};
use hal_discovery::{DiscoveryProvider, PublicDhtProvider};
use hal_protocol::invite::RedeemableInvite;
use hal_protocol::InviteData;
use hal_settings::{AvailabilityState, NetworkScanPolicy, NetworkTrustPolicy, PresencePolicy};
use hal_storage::ClientStorage;
use hal_storage::StoredPeer;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, Mutex, Mutex as TokioMutex, Notify};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

const MAX_MEDIA_SIGNALS: usize = 256;
const MAX_RELAY_FORWARD_DEPTH: u8 = 2;
const RECENT_SEND_FAILURE_WINDOW: Duration = Duration::from_secs(30);
const MAX_PEER_ADDRESS_REFRESH_ATTEMPTS: u8 = 3;
const PEER_ADDRESS_REFRESH_BACKOFF: Duration = Duration::from_secs(30);
const PUBLIC_ENDPOINT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5 * 60);
const DYNAMIC_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
const WSS_DYNAMIC_PROBE_TIMEOUT: Duration = Duration::from_secs(20);
const WSS_RELAY_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

enum DynamicProbeSuccess {
    Tcp(String),
    Quic(SocketAddr),
    Relay(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CoverTrafficState {
    #[default]
    Idle,
    Burst,
    Chaos,
}

impl CoverTrafficState {
    fn evaluate(
        last_message_time: Instant,
        is_charging: bool,
        is_wifi: bool,
        is_chat_open: bool,
        now: Instant,
    ) -> Self {
        if is_charging && is_wifi && is_chat_open {
            Self::Chaos
        } else if now.duration_since(last_message_time) < Duration::from_secs(30) {
            Self::Burst
        } else {
            Self::Idle
        }
    }
}

#[derive(Default)]
pub(crate) struct PeerAddressState {
    stale_addresses: HashMap<String, HashSet<String>>,
    refresh_attempts: HashMap<String, (u8, Instant)>,
}

impl PeerAddressState {
    fn stale_addresses(&self, identity_id: &str) -> HashSet<String> {
        self.stale_addresses
            .get(identity_id)
            .cloned()
            .unwrap_or_default()
    }

    fn mark_stale(&mut self, identity_id: &str, address: String) {
        self.stale_addresses
            .entry(identity_id.to_string())
            .or_default()
            .insert(address);
    }

    pub(crate) fn confirm_address(&mut self, identity_id: &str, address: &str) {
        self.stale_addresses.remove(identity_id);
        self.refresh_attempts.remove(identity_id);
        log::info!(
            target: "HAL_DHT",
            "peer address confirmed: {identity_id} {address}"
        );
    }

    fn begin_refresh(&mut self, identity_id: &str) -> bool {
        let now = Instant::now();
        let state = self
            .refresh_attempts
            .entry(identity_id.to_string())
            .or_insert((0, now));
        if state.0 >= MAX_PEER_ADDRESS_REFRESH_ATTEMPTS {
            if now.duration_since(state.1) < PEER_ADDRESS_REFRESH_BACKOFF {
                log::warn!(
                    target: "HAL_DHT",
                    "peer address refresh backoff: {identity_id}"
                );
                return false;
            }
            *state = (0, now);
        }
        state.0 = state.0.saturating_add(1);
        state.1 = now;
        true
    }

    fn invalidate_all(&mut self, peers: &[PeerEntry]) -> usize {
        let mut count = 0;
        for peer in peers {
            if !peer
                .address
                .parse::<SocketAddr>()
                .is_ok_and(|address| crate::transport::is_lan_address(&address))
            {
                continue;
            }
            if self
                .stale_addresses
                .entry(peer.identity_id.clone())
                .or_default()
                .insert(peer.address.clone())
            {
                count += 1;
            }
            self.refresh_attempts.remove(&peer.identity_id);
        }
        count
    }
}

fn policy_requires_biometric(policy: &ContactPolicy, now: u64) -> bool {
    match policy {
        ContactPolicy::AgeProof => false,
        ContactPolicy::Paranoid => true,
        ContactPolicy::BiometricInterval {
            interval_secs,
            last_verified,
        } => now.saturating_sub(*last_verified) >= *interval_secs,
    }
}

async fn ensure_biometric_if_required(
    gate: &dyn BiometricGate,
    policy: &ContactPolicy,
    metrics: &AbuseMetrics,
    prompt: &str,
) -> Result<ContactPolicy, crate::SessionError> {
    if !gate.is_available() {
        if !matches!(policy, ContactPolicy::AgeProof) {
            metrics
                .biometric_unavailable_total
                .fetch_add(1, Ordering::Relaxed);
            log::warn!("biometric unavailable; degrading contact policy to AgeProof");
            return Ok(ContactPolicy::AgeProof);
        }
        return Ok(*policy);
    }
    let now = unix_now();
    if !policy_requires_biometric(policy, now) {
        return Ok(*policy);
    }
    match gate.verify(prompt).await {
        Ok(()) => {
            metrics
                .biometric_verified_total
                .fetch_add(1, Ordering::Relaxed);
            Ok(match policy {
                ContactPolicy::BiometricInterval { interval_secs, .. } => {
                    ContactPolicy::BiometricInterval {
                        interval_secs: *interval_secs,
                        last_verified: now,
                    }
                }
                _ => *policy,
            })
        }
        Err(BiometricError::Unavailable) => {
            metrics
                .biometric_unavailable_total
                .fetch_add(1, Ordering::Relaxed);
            log::warn!("biometric became unavailable; degrading contact policy to AgeProof");
            Ok(ContactPolicy::AgeProof)
        }
        Err(error) => {
            metrics
                .biometric_rejected_total
                .fetch_add(1, Ordering::Relaxed);
            Err(crate::SessionError::BiometricRequired(error.to_string()))
        }
    }
}

async fn update_contact_policy(ctx: &RuntimeContext, peer: &NodeId, policy: ContactPolicy) {
    let updated = {
        let mut store = ctx.session_store.lock().await;
        if let Some(session) = store.get_mut(peer) {
            session.contact_policy = policy;
            true
        } else {
            false
        }
    };
    if updated {
        persist_session_nonfatal(ctx, peer, "contact policy update").await;
    }
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

struct PendingRatchetReceive {
    peer: NodeId,
    preview: Option<crate::ReceivePreview>,
    out_of_order: bool,
    v4_transition: Option<crate::session_store::V4RatchetAction>,
    v4_counter: u64,
    generation: u64,
    prune_previous_chain: Option<(u64, u32)>,
}

struct V4SendRollback {
    sending_chain_key: Zeroizing<[u8; 32]>,
    sending_index: u64,
    messages_since_ratchet: u32,
    prev_chain_length: Option<u32>,
    last_used_at: u64,
}

async fn load_session_on_demand(
    ctx: &RuntimeContext,
    peer: &NodeId,
) -> Result<Option<SessionView>> {
    let (needs_load, storage, persistence_lock) = {
        let store = ctx.session_store.lock().await;
        (
            store.needs_storage_load(peer),
            store.storage_handle(),
            store.persistence_lock_handle(),
        )
    };
    if !needs_load {
        return Ok(ctx.session_store.lock().await.get_view(peer));
    }
    let Some(storage) = storage else {
        ctx.session_store.lock().await.remember_storage_miss(*peer);
        return Ok(None);
    };

    let _persistence_guard = persistence_lock.lock().await;
    {
        let store = ctx.session_store.lock().await;
        if !store.needs_storage_load(peer) {
            return Ok(store.get_view(peer));
        }
    }

    let loaded = crate::session_store::SessionStore::load_session_from_storage(&storage, peer)
        .map_err(|error| anyhow!("failed to load persisted session: {error}"))?;
    let mut store = ctx.session_store.lock().await;
    if !store.needs_storage_load(peer) {
        return Ok(store.get_view(peer));
    }
    match loaded {
        Some(session) => store.install_loaded_session(session),
        None => store.remember_storage_miss(*peer),
    }
    Ok(store.get_view(peer))
}

pub(crate) async fn persist_session_nonfatal(ctx: &RuntimeContext, peer: &NodeId, reason: &str) {
    let persistence_lock = ctx.session_store.lock().await.persistence_lock_handle();
    let _persistence_guard = persistence_lock.lock().await;

    // Snapshot while holding the session-store lock, release it, then acquire storage.
    let (storage, snapshot) = {
        let store = ctx.session_store.lock().await;
        (store.storage_handle(), store.persistence_snapshot(peer))
    };
    let persistence_result = match (storage, snapshot) {
        (Some(storage), Ok(Some(snapshot))) => snapshot.persist(&storage),
        (None, Ok(None)) => return,
        (_, Ok(None)) => return,
        (_, Ok(Some(_))) => Err(crate::SessionError::Ratchet(anyhow!(
            "session persistence storage is unavailable"
        ))),
        (_, Err(error)) => Err(error),
    };
    if let Err(error) = persistence_result {
        ctx.abuse_metrics
            .session_persist_failed_total
            .fetch_add(1, Ordering::Relaxed);
        log::warn!("failed to persist session after {reason} for {peer:?}: {error}");
    }
}

async fn persist_session_required(ctx: &RuntimeContext, peer: &NodeId) -> Result<()> {
    let persistence_lock = ctx.session_store.lock().await.persistence_lock_handle();
    let _persistence_guard = persistence_lock.lock().await;
    let (storage, snapshot) = {
        let store = ctx.session_store.lock().await;
        (store.storage_handle(), store.persistence_snapshot(peer)?)
    };
    match (storage, snapshot) {
        (Some(storage), Some(snapshot)) => snapshot
            .persist(&storage)
            .map_err(|error| anyhow!("failed to persist ratchet session: {error}")),
        (None, None) => Ok(()),
        (Some(_), None) => Err(anyhow!("ratchet persistence snapshot is unavailable")),
        (None, Some(_)) => Err(anyhow!("ratchet persistence storage is unavailable")),
    }
}

async fn forget_session(ctx: &RuntimeContext, peer: &NodeId) -> Result<()> {
    let storage = ctx.session_store.lock().await.forget_from_memory(peer);
    if let Some(storage) = storage {
        let storage = storage
            .lock()
            .map_err(|_| anyhow!("session storage lock poisoned while forgetting session"))?;
        storage
            .delete_session(&peer.to_hex())
            .map_err(|error| anyhow!("failed deleting persisted session: {error}"))?;
    }
    Ok(())
}

async fn abort_pending_ratchet_receive(
    ctx: &RuntimeContext,
    pending: &mut Option<PendingRatchetReceive>,
    event_id: &str,
) {
    let Some(mut pending) = pending.take() else {
        return;
    };
    let Some(preview) = pending.preview.take() else {
        if pending.v4_transition.is_some() {
            return;
        }
        log::error!("ratchet receive preview missing during abort for event {event_id}");
        return;
    };
    if let Err(error) = ctx
        .session_store
        .lock()
        .await
        .abort_receive_preview(&pending.peer, preview)
    {
        if !matches!(error, crate::SessionError::SessionReplaced) {
            log::warn!("V3 receive abort failed for event {event_id}: {error}");
        }
    }
}

async fn commit_pending_ratchet_receive(
    ctx: &RuntimeContext,
    pending: &mut Option<PendingRatchetReceive>,
    now: u64,
    event_id: &str,
) -> bool {
    let Some(mut pending) = pending.take() else {
        return true;
    };
    let commit_result = if let Some(action) = pending.v4_transition {
        async {
            let mut store = ctx.session_store.lock().await;
            let transition_result = match action {
                crate::session_store::V4RatchetAction::CollisionCase1(peer_new)
                | crate::session_store::V4RatchetAction::CollisionCase3Larger(peer_new) => {
                    let result = store
                        .get_mut(&pending.peer)
                        .ok_or(crate::SessionError::MissingSession)
                        .and_then(|session| session.dh_ratchet_collision_abort(peer_new));
                    if result.is_ok() {
                        match action {
                            crate::session_store::V4RatchetAction::CollisionCase1(_) => {
                                ctx.abuse_metrics
                                    .dh_ratchet_collisions_case1_total
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {
                                ctx.abuse_metrics
                                    .dh_ratchet_collisions_case3_larger_total
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        ctx.abuse_metrics
                            .dh_ratchet_transitions_responder_total
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    result
                }
                crate::session_store::V4RatchetAction::CollisionCase3Smaller(peer_new) => {
                    let result = store
                        .get_mut(&pending.peer)
                        .ok_or(crate::SessionError::MissingSession)
                        .and_then(|session| session.dh_ratchet_complete(peer_new));
                    if result.is_ok() {
                        ctx.abuse_metrics
                            .dh_ratchet_collisions_case3_smaller_total
                            .fetch_add(1, Ordering::Relaxed);
                        ctx.abuse_metrics
                            .dh_ratchet_transitions_initiator_total
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    result
                }
                crate::session_store::V4RatchetAction::ResponderStep(peer_new) => {
                    let result = store
                        .get_mut(&pending.peer)
                        .ok_or(crate::SessionError::MissingSession)
                        .and_then(|session| session.dh_ratchet_step(peer_new));
                    if result.is_ok() {
                        ctx.abuse_metrics
                            .dh_ratchet_transitions_responder_total
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    result
                }
                crate::session_store::V4RatchetAction::InitiatorComplete(peer_new) => {
                    let result = store
                        .get_mut(&pending.peer)
                        .ok_or(crate::SessionError::MissingSession)
                        .and_then(|session| session.dh_ratchet_complete(peer_new));
                    if result.is_ok() {
                        ctx.abuse_metrics
                            .dh_ratchet_transitions_initiator_total
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    result
                }
                crate::session_store::V4RatchetAction::None
                | crate::session_store::V4RatchetAction::DuplicateAdvertise => Ok(()),
            };
            transition_result?;
            if let Some((old_epoch, prev_chain_length)) = pending.prune_previous_chain {
                store.prune_skipped_keys_at_or_after(
                    &pending.peer,
                    old_epoch,
                    prev_chain_length,
                )?;
            }
            let preview = store.prepare_receive_with_skipped_at(
                &pending.peer,
                pending.v4_counter,
                pending.generation,
                now,
            )?;
            let out_of_order = preview.is_out_of_order();
            store.commit_receive_preview(&pending.peer, preview, now)?;
            if out_of_order {
                ctx.abuse_metrics
                    .ratchet_out_of_order_accepted_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        }
        .await
    } else {
        let Some(preview) = pending.preview.take() else {
            log::error!("ratchet receive preview missing at commit for event {event_id}");
            return false;
        };
        ctx.session_store
            .lock()
            .await
            .commit_receive_preview(&pending.peer, preview, now)
    };
    match commit_result {
        Ok(()) => {
            if pending.out_of_order {
                ctx.abuse_metrics
                    .ratchet_out_of_order_accepted_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            true
        }
        Err(error) => {
            if matches!(error, crate::SessionError::SessionReplaced) {
                ctx.abuse_metrics
                    .ratchet_session_replaced_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            if matches!(
                error,
                crate::SessionError::ReceiveNotPrepared
                    | crate::SessionError::CounterMismatch { .. }
            ) {
                ctx.abuse_metrics
                    .ratchet_commit_mismatch_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            ctx.abuse_metrics
                .ratchet_commit_failed_total
                .fetch_add(1, Ordering::Relaxed);
            let marked = ctx
                .session_store
                .lock()
                .await
                .mark_needs_resync(&pending.peer);
            match marked {
                Ok(true) => {
                    ctx.abuse_metrics
                        .ratchet_needs_resync_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                Ok(false) => {}
                Err(mark_error) => {
                    log::error!("failed to mark peer session as needing resync: {mark_error}");
                }
            }
            log::error!("V3 receive commit failed for event {event_id}: {error}");
            false
        }
    }
}

fn session_root_key(result: &hal_crypto::X3DHResult) -> Result<[u8; 32]> {
    result
        .shared_secret
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("X3DH shared secret must be 32 bytes"))
}

fn record_capability_negotiation(ctx: &RuntimeContext, peer_capability: Option<bool>) {
    let metric = match peer_capability {
        Some(true) => &ctx.abuse_metrics.capability_negotiation_mutual_v4_total,
        Some(false) => &ctx.abuse_metrics.capability_negotiation_v3_declined_total,
        None => &ctx.abuse_metrics.capability_negotiation_v3_legacy_total,
    };
    metric.fetch_add(1, Ordering::Relaxed);
}

fn is_v4_active(session: &crate::Session) -> bool {
    session.peer_supports_v4 == Some(true)
}

async fn handle_session_init_in_context(
    ctx: &Arc<RuntimeContext>,
    init_message: X3dhInitMessage,
    now: u64,
    expected_sender: Option<[u8; 32]>,
) -> Result<()> {
    let result = async {
        let initiator_identity = init_message.verify()?;
        if init_message.one_time_prekey_id.is_none() {
            return Err(anyhow!("runtime X3DH sessions require a one-time prekey"));
        }
        if expected_sender.is_some_and(|expected| expected != init_message.sender_identity) {
            return Err(anyhow!(
                "X3DH init identity does not match authenticated envelope"
            ));
        }
        let identity_signing_key = ctx
            .identity_signing_key
            .as_ref()
            .ok_or_else(|| anyhow!("local identity signing key is unavailable"))?;
        let local_store = ctx
            .local_prekey_store
            .as_ref()
            .ok_or_else(|| anyhow!("local prekey store is unavailable"))?;
        let signed_prekey = local_store
            .lock()
            .await
            .signed_prekey_by_public_key_with_private(&init_message.signed_prekey_used, now)
            .await?
            .ok_or_else(|| anyhow!("matching signed prekey is unavailable"))?;

        let consumed_opk = match init_message.one_time_prekey_id {
            Some(id) => Some(local_store.lock().await.consume_opk(id, now).await?),
            None => None,
        };
        let one_time_prekey_private = consumed_opk.as_ref().map(|opk| opk.privkey);
        let responder_keys =
            X3DHKeys::from_identity_and_prekey(identity_signing_key, signed_prekey.privkey)?;
        if responder_keys.prekey.to_bytes() != init_message.signed_prekey_used {
            return Err(anyhow!("stored signed prekey private/public mismatch"));
        }
        let exchange =
            X3DH::respond_with_opk(&responder_keys, &init_message, one_time_prekey_private)?;
        let root_key = session_root_key(&exchange)?;
        let peer_identity = NodeId::from_public_key(&initiator_identity);
        let respond_message = X3dhRespondMessage::for_init_with_capabilities(
            &init_message,
            identity_signing_key,
            Some(true),
            Some(true),
        );
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&respond_message)?);
        ctx.sync
            .lock()
            .await
            .add_protocol_event(SyncEventType::X3dhRespond, encoded)?;
        let local_identity = NodeId::from_public_key(&identity_signing_key.verifying_key());
        {
            let mut store = ctx.session_store.lock().await;
            store.insert_with_chains(peer_identity, root_key, &local_identity, now)?;
            store.set_peer_supports_v4(&peer_identity, init_message.capability_v4_dh_ratchet)?;
            store.set_peer_supports_invite_redemption(
                &peer_identity,
                init_message.capability_invite_redemption,
            )?;
        }
        record_capability_negotiation(ctx, init_message.capability_v4_dh_ratchet);
        persist_session_nonfatal(ctx, &peer_identity, "X3DH session creation").await;
        Ok(())
    }
    .await;

    match result {
        Ok(()) => {
            ctx.abuse_metrics
                .x3dh_session_established_total
                .fetch_add(1, Ordering::Relaxed);
            ctx.abuse_metrics
                .x3dh_session_accepted_total
                .fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        Err(error) => {
            ctx.abuse_metrics
                .x3dh_session_failed_total
                .fetch_add(1, Ordering::Relaxed);
            Err(error)
        }
    }
}

async fn handle_session_respond_in_context(
    ctx: &Arc<RuntimeContext>,
    respond_message: X3dhRespondMessage,
    now: u64,
    expected_sender: Option<[u8; 32]>,
) -> Result<()> {
    let result = async {
        let responder_identity = respond_message.verify()?;
        if expected_sender.is_some_and(|expected| expected != respond_message.responder_identity) {
            return Err(anyhow!(
                "X3DH respond identity does not match authenticated envelope"
            ));
        }
        let local_identity = ctx
            .identity_signing_key
            .as_ref()
            .ok_or_else(|| anyhow!("local identity signing key is unavailable"))?
            .verifying_key()
            .to_bytes();
        if respond_message.initiator_identity != local_identity {
            return Err(anyhow!("X3DH respond targets another initiator"));
        }
        let peer_identity = NodeId::from_public_key(&responder_identity);
        let responded = {
            let mut store = ctx.session_store.lock().await;
            let responded = store.mark_responded(
                &peer_identity,
                &respond_message.ephemeral_public,
                &respond_message.signed_prekey_used,
                respond_message.one_time_prekey_id,
                now,
            );
            if responded {
                store.set_peer_supports_v4(
                    &peer_identity,
                    respond_message.capability_v4_dh_ratchet,
                )?;
                store.set_peer_supports_invite_redemption(
                    &peer_identity,
                    respond_message.capability_invite_redemption,
                )?;
            }
            responded
        };
        if !responded {
            return Err(anyhow!("X3DH respond does not match a pending session"));
        }
        record_capability_negotiation(ctx, respond_message.capability_v4_dh_ratchet);
        persist_session_nonfatal(ctx, &peer_identity, "X3DH response").await;
        Ok(())
    }
    .await;

    match result {
        Ok(()) => {
            ctx.abuse_metrics
                .x3dh_session_accepted_total
                .fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        Err(error) => {
            ctx.abuse_metrics
                .x3dh_session_failed_total
                .fetch_add(1, Ordering::Relaxed);
            Err(error)
        }
    }
}

/// Combined snapshot of runtime DHT and trust metrics.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeMetricsSnapshot {
    pub dht: crate::dht::DhtMetricsSnapshot,
    pub trust: crate::dht::trust_metrics::TrustMetricsSnapshot,
    pub relay: RelayMetricsSnapshot,
    pub peer_directory: crate::peer_directory::PeerDirectoryMetricsSnapshot,
    pub badge: BadgeMetricsSnapshot,
    pub abuse: crate::abuse_metrics::AbuseMetricsSnapshot,
}

pub(crate) async fn publish_badge_impl(
    ctx: &Arc<RuntimeContext>,
    signing_key: &SigningKey,
    identity_id: &str,
    public_key: &str,
    dht_local_id: NodeId,
    dht_routing: &Arc<TokioMutex<RoutingTable>>,
    dht_cache: &Arc<TokioMutex<EndpointCache>>,
    hosts: &Arc<StdMutex<KnownHosts>>,
    trust_policy: &NetworkTrustPolicy,
    badge: Badge,
) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if badge.assigned_by != dht_local_id {
        return Err(anyhow!("badge issuer must be the local identity"));
    }
    let badge = Badge::create(
        badge.id,
        badge.subject_id,
        badge.group_id,
        badge.kind,
        badge.message_ids,
        badge.context,
        badge.reason,
        dht_local_id,
        badge.assigned_at,
        badge.expires_at,
        signing_key,
    )?;
    let subject = badge.subject_id;
    ctx.badge_store.lock().await.publish(badge.clone())?;
    ctx.badge_metrics
        .badge_published_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let now = now.max(badge.assigned_at);
    let slot = ctx
        .badge_store
        .lock()
        .await
        .badges_for_subject(&subject)
        .into_iter()
        .filter(|stored| stored.expires_at.is_none_or(|expiry| expiry > now))
        .collect::<Vec<_>>();
    if slot.is_empty() {
        return Ok(());
    }
    let key = *subject.as_bytes();
    let value = StoredRecord::Badge(slot.clone()).to_value()?;
    let expires_at = slot
        .iter()
        .map(|stored| {
            stored
                .expires_at
                .unwrap_or_else(|| now.saturating_add(crate::dht::badge::BADGE_DEFAULT_TTL_SECS))
        })
        .max()
        .unwrap_or_else(|| now.saturating_add(crate::dht::badge::BADGE_DEFAULT_TTL_SECS));
    let transport =
        MuxDhtTransport::new(signing_key.clone(), Arc::clone(hosts), trust_policy.clone());
    let mut routing = dht_routing.lock().await;
    let mut lookup = Lookup::new(
        dht_local_id,
        subject,
        LookupConfig::default(),
        &transport,
        &mut routing,
    );
    let peers = lookup
        .find_node()
        .await
        .map_err(|error| anyhow!("find badge storage peers: {error}"))?
        .peers;
    drop(lookup);
    drop(routing);

    for peer in peers {
        let request = crate::dht::DhtRequest::new(
            crate::dht::DhtRequestPayload::StoreTyped {
                key,
                value: value.clone(),
                signature: badge.signature.to_vec(),
                expires_at,
                record_type: Some(StoredRecordType::Badge),
            },
            dht_local_id,
            now,
        );
        if let Err(error) = transport.send_request(&peer, request).await {
            log::debug!("badge store to {:?} failed: {error}", peer.node_id);
        }
    }
    let _ = identity_id;
    let _ = public_key;
    let _ = dht_cache;
    Ok(())
}

pub struct HomeRuntimeState {
    pub pending_requests: HashMap<String, PendingLinkRequest>,
    pub pending_responses: HashMap<String, LinkResponse>,
    pub pending_confirms: HashMap<String, LinkConfirm>,
    pub pending_link_targets: HashMap<String, LinkingQr>,
    pub approved_tokens: HashSet<String>,
    pub linked_device_pubkeys: HashSet<String>,
    pub home_stack_id: Option<String>,
    pub(crate) active_presence: HashMap<String, crate::peer_presence::ActivePeerPresence>,
    pub cached_presence: HashMap<String, crate::peer_presence::PeerPresenceRecord>,
    pub presence_last_request: HashMap<String, u64>,
    pub(crate) pending_presence_requests:
        HashMap<String, oneshot::Sender<crate::peer_presence::PeerPresenceMessage>>,
    pub pending_sync_transfers: HashMap<String, PendingHomeSyncTransfer>,
    pub home_secret: Option<HomeSecret>,
    pub notifications: crate::dht::notifier::Notifier,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PendingLinkRequest {
    #[serde(flatten)]
    pub request: LinkRequest,
    pub remote_addr: Option<SocketAddr>,
}

impl std::ops::Deref for PendingLinkRequest {
    type Target = LinkRequest;

    fn deref(&self) -> &Self::Target {
        &self.request
    }
}

#[derive(Debug, Clone)]
pub struct PendingHomeSyncTransfer {
    pub source_public_key: String,
    pub chunks: Vec<HomeSyncChunk>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct HomeSyncAck {
    transfer_id: String,
    digest: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct HomeDraftUpdate {
    chat_id: String,
    text: String,
    updated_at: u64,
}

async fn home_sync_worker_loop(
    ctx: Arc<RuntimeContext>,
    identity_id: String,
    public_key: String,
    private_key: SigningKey,
    hosts: Arc<StdMutex<KnownHosts>>,
    trust_policy: NetworkTrustPolicy,
    mut shutdown: oneshot::Receiver<()>,
) {
    let mut cached_revision = None;
    let mut cached_chunks: Vec<HomeSyncChunk> = Vec::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = tokio::time::sleep(Duration::from_secs(10)) => {}
        }
        if let Err(error) = home_sync_worker_tick(
            &ctx,
            &identity_id,
            &public_key,
            &private_key,
            &hosts,
            &trust_policy,
            &mut cached_revision,
            &mut cached_chunks,
        )
        .await
        {
            log::warn!("Home sync worker tick failed: {error:#}");
        }
    }
}

async fn home_sync_worker_tick(
    ctx: &RuntimeContext,
    identity_id: &str,
    public_key: &str,
    private_key: &SigningKey,
    hosts: &Arc<StdMutex<KnownHosts>>,
    trust_policy: &NetworkTrustPolicy,
    cached_revision: &mut Option<u64>,
    cached_chunks: &mut Vec<HomeSyncChunk>,
) -> Result<()> {
    let (home_secret, linked_devices) = {
        let state = ctx.home_state.lock().await;
        (
            state.home_secret.clone(),
            state.linked_device_pubkeys.clone(),
        )
    };
    let Some(home_secret) = home_secret else {
        return Ok(());
    };
    let Some(storage) = ctx.storage.as_ref() else {
        return Ok(());
    };
    let revision = storage
        .lock()
        .map_err(|_| anyhow!("client storage lock poisoned"))?
        .home_sync_revision()?;
    if *cached_revision != Some(revision) || cached_chunks.is_empty() {
        let snapshot = storage
            .lock()
            .map_err(|_| anyhow!("client storage lock poisoned"))?
            .export_home_sync_snapshot()?;
        *cached_chunks = seal_home_sync_snapshot(&snapshot, &home_secret)?;
        *cached_revision = Some(revision);
    }
    let Some(current_chunk) = cached_chunks.first() else {
        return Err(anyhow!("Home sync snapshot produced no chunks"));
    };
    let digest = current_chunk.snapshot_sha256.clone();
    let mut chunks_json = None;
    let local_public_key = hex::encode(private_key.verifying_key().to_bytes());

    for peer_public_key in &linked_devices {
        if peer_public_key == &local_public_key {
            continue;
        }
        let (acknowledged_digest, pending_digest) = {
            let storage = storage
                .lock()
                .map_err(|_| anyhow!("client storage lock poisoned"))?;
            (
                storage.home_sync_peer_digest(peer_public_key)?,
                storage.home_sync_pending_digest(peer_public_key)?,
            )
        };
        if acknowledged_digest.as_deref() == Some(digest.as_str()) {
            storage
                .lock()
                .map_err(|_| anyhow!("client storage lock poisoned"))?
                .clear_home_sync_outbox(peer_public_key)?;
        } else if pending_digest.as_deref() != Some(digest.as_str()) {
            if chunks_json.is_none() {
                chunks_json = Some(serde_json::to_string(cached_chunks)?);
            }
            storage
                .lock()
                .map_err(|_| anyhow!("client storage lock poisoned"))?
                .queue_home_sync_snapshot(
                    peer_public_key,
                    &current_chunk.transfer_id,
                    &digest,
                    chunks_json
                        .as_deref()
                        .ok_or_else(|| anyhow!("Home sync chunks were not serialized"))?,
                )?;
        }
    }

    let now = unix_now();
    let outbox = storage
        .lock()
        .map_err(|_| anyhow!("client storage lock poisoned"))?
        .pending_home_sync_outbox(now)?;
    for entry in outbox {
        if !linked_devices.contains(&entry.peer_public_key) {
            storage
                .lock()
                .map_err(|_| anyhow!("client storage lock poisoned"))?
                .clear_home_sync_outbox(&entry.peer_public_key)?;
            continue;
        }
        let chunks = match serde_json::from_str::<Vec<HomeSyncChunk>>(&entry.chunks_json) {
            Ok(chunks)
                if chunks.first().is_some_and(|chunk| {
                    chunk.transfer_id == entry.transfer_id && chunk.snapshot_sha256 == entry.digest
                }) =>
            {
                chunks
            }
            Ok(_) => {
                log::error!(
                    "discarding invalid persisted Home sync snapshot for {}",
                    entry.peer_public_key
                );
                if chunks_json.is_none() {
                    chunks_json = Some(serde_json::to_string(cached_chunks)?);
                }
                storage
                    .lock()
                    .map_err(|_| anyhow!("client storage lock poisoned"))?
                    .queue_home_sync_snapshot(
                        &entry.peer_public_key,
                        &current_chunk.transfer_id,
                        &digest,
                        chunks_json
                            .as_deref()
                            .ok_or_else(|| anyhow!("Home sync chunks were not serialized"))?,
                    )?;
                continue;
            }
            Err(error) => {
                log::error!(
                    "could not decode persisted Home sync snapshot for {}: {error}",
                    entry.peer_public_key
                );
                if chunks_json.is_none() {
                    chunks_json = Some(serde_json::to_string(cached_chunks)?);
                }
                storage
                    .lock()
                    .map_err(|_| anyhow!("client storage lock poisoned"))?
                    .queue_home_sync_snapshot(
                        &entry.peer_public_key,
                        &current_chunk.transfer_id,
                        &digest,
                        chunks_json
                            .as_deref()
                            .ok_or_else(|| anyhow!("Home sync chunks were not serialized"))?,
                    )?;
                continue;
            }
        };
        let addresses = home_sync_peer_addresses(ctx, &entry.peer_public_key).await?;
        let mut send_result = Err(anyhow!("no known address for linked Home device"));
        for address in addresses {
            match send_home_sync_chunks(
                identity_id,
                public_key,
                private_key,
                hosts,
                &ctx.abuse_metrics,
                trust_policy,
                &address,
                &chunks,
            )
            .await
            {
                Ok(()) => {
                    send_result = Ok(());
                    break;
                }
                Err(error) => send_result = Err(error),
            }
        }
        storage
            .lock()
            .map_err(|_| anyhow!("client storage lock poisoned"))?
            .mark_home_sync_outbox_attempt(&entry.peer_public_key, &entry.transfer_id, now)?;
        if let Err(error) = send_result {
            log::debug!(
                "Home sync snapshot {} remains queued for {}: {error:#}",
                entry.transfer_id,
                entry.peer_public_key
            );
        }
    }

    let acknowledgements = storage
        .lock()
        .map_err(|_| anyhow!("client storage lock poisoned"))?
        .pending_home_sync_acks(now)?;
    for ack in acknowledgements {
        if !linked_devices.contains(&ack.peer_public_key) {
            storage
                .lock()
                .map_err(|_| anyhow!("client storage lock poisoned"))?
                .remove_home_sync_ack(&ack.peer_public_key, &ack.transfer_id)?;
            continue;
        }
        let addresses = home_sync_peer_addresses(ctx, &ack.peer_public_key).await?;
        let payload = serde_json::to_string(&HomeSyncAck {
            transfer_id: ack.transfer_id.clone(),
            digest: ack.digest.clone(),
        })?;
        let mut delivered = false;
        for address in addresses {
            if send_home_sync_event(
                identity_id,
                public_key,
                private_key,
                hosts,
                &ctx.abuse_metrics,
                trust_policy,
                &address,
                SyncEventType::HomeSyncAck,
                payload.clone(),
            )
            .await
            .is_ok()
            {
                delivered = true;
                break;
            }
        }
        let storage = storage
            .lock()
            .map_err(|_| anyhow!("client storage lock poisoned"))?;
        if delivered {
            storage.remove_home_sync_ack(&ack.peer_public_key, &ack.transfer_id)?;
        } else {
            storage.mark_home_sync_ack_attempt(&ack.peer_public_key, &ack.transfer_id, now)?;
        }
    }
    Ok(())
}

async fn home_sync_peer_addresses(
    ctx: &RuntimeContext,
    peer_public_key: &str,
) -> Result<Vec<String>> {
    let key_bytes: [u8; 32] = hex::decode(peer_public_key)
        .map_err(|error| anyhow!("invalid linked Home device key: {error}"))?
        .try_into()
        .map_err(|_| anyhow!("linked Home device key must be 32 bytes"))?;
    let peer = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|error| anyhow!("invalid linked Home device key: {error}"))?;
    let identity_id = NodeId::from_public_key(&peer).to_hex();
    let mut addresses = ctx
        .peer_directory
        .lock()
        .await
        .addresses_of(&identity_id, unix_now());
    if addresses.is_empty() {
        if let Some(storage) = ctx.storage.as_ref() {
            if let Some(address) = storage
                .lock()
                .map_err(|_| anyhow!("client storage lock poisoned"))?
                .peer_registry()
                .latest_address(&identity_id)?
            {
                addresses.push(address);
            }
        }
    }
    let mut seen = HashSet::new();
    addresses.retain(|address| seen.insert(address.clone()));
    Ok(addresses)
}

async fn send_home_sync_chunks(
    identity_id: &str,
    public_key: &str,
    private_key: &SigningKey,
    hosts: &Arc<StdMutex<KnownHosts>>,
    abuse_metrics: &Arc<crate::abuse_metrics::AbuseMetrics>,
    trust_policy: &NetworkTrustPolicy,
    address: &str,
    chunks: &[HomeSyncChunk],
) -> Result<()> {
    for batch in chunks.chunks(4) {
        let mut events = Vec::with_capacity(batch.len());
        for chunk in batch {
            let mut event = SyncEvent::new(
                uuid::Uuid::new_v4().to_string(),
                SyncEventType::HomeSyncChunk,
                serde_json::to_string(chunk)?,
            );
            event.sign(&private_key.to_bytes())?;
            events.push(event);
        }
        let envelope = SyncEnvelope::new(identity_id.to_owned(), public_key.to_owned(), events);
        if serde_json::to_vec(&envelope)?.len() > crate::tls_transport::MAX_TLS_ENVELOPE_SIZE {
            return Err(anyhow!(
                "Home sync batch exceeds the TLS envelope size limit"
            ));
        }
        send_envelope_secure_with_stream_kind_and_metrics(
            address,
            &envelope,
            private_key,
            Arc::clone(hosts),
            None,
            trust_policy.clone(),
            crate::mux::StreamKind::Control,
            Arc::clone(abuse_metrics),
        )
        .await?;
    }
    Ok(())
}

async fn send_home_sync_event(
    identity_id: &str,
    public_key: &str,
    private_key: &SigningKey,
    hosts: &Arc<StdMutex<KnownHosts>>,
    abuse_metrics: &Arc<crate::abuse_metrics::AbuseMetrics>,
    trust_policy: &NetworkTrustPolicy,
    address: &str,
    event_type: SyncEventType,
    data: String,
) -> Result<()> {
    let mut event = SyncEvent::new(uuid::Uuid::new_v4().to_string(), event_type, data);
    event.sign(&private_key.to_bytes())?;
    let envelope = SyncEnvelope::new(identity_id.to_owned(), public_key.to_owned(), vec![event]);
    if serde_json::to_vec(&envelope)?.len() > crate::tls_transport::MAX_TLS_ENVELOPE_SIZE {
        return Err(anyhow!("Home event exceeds the TLS envelope size limit"));
    }
    send_envelope_secure_with_stream_kind_and_metrics(
        address,
        &envelope,
        private_key,
        Arc::clone(hosts),
        None,
        trust_policy.clone(),
        crate::mux::StreamKind::Control,
        Arc::clone(abuse_metrics),
    )
    .await
}

impl Default for HomeRuntimeState {
    fn default() -> Self {
        Self {
            pending_requests: HashMap::new(),
            pending_responses: HashMap::new(),
            pending_confirms: HashMap::new(),
            pending_link_targets: HashMap::new(),
            approved_tokens: HashSet::new(),
            linked_device_pubkeys: HashSet::new(),
            home_stack_id: None,
            active_presence: HashMap::new(),
            cached_presence: HashMap::new(),
            presence_last_request: HashMap::new(),
            pending_presence_requests: HashMap::new(),
            pending_sync_transfers: HashMap::new(),
            home_secret: None,
            notifications: crate::dht::notifier::Notifier::new(),
        }
    }
}

async fn apply_complete_home_sync_transfer(
    ctx: &RuntimeContext,
    transfer_id: &str,
) -> Result<bool> {
    let (transfer, home_secret) = {
        let state = ctx.home_state.lock().await;
        let Some(home_secret) = state.home_secret.clone() else {
            return Ok(false);
        };
        let Some(transfer) = state.pending_sync_transfers.get(transfer_id).cloned() else {
            return Ok(false);
        };
        let Some(first) = transfer.chunks.first() else {
            return Ok(false);
        };
        if transfer.chunks.len() != first.total as usize
            || !state
                .linked_device_pubkeys
                .contains(&transfer.source_public_key)
        {
            return Ok(false);
        }
        (transfer, home_secret)
    };

    let snapshot = open_home_sync_snapshot(&transfer.chunks, &home_secret)?;
    let storage = ctx
        .storage
        .as_ref()
        .ok_or_else(|| anyhow!("client storage is not configured"))?;
    storage
        .lock()
        .map_err(|_| anyhow!("client storage lock poisoned"))?
        .apply_home_sync_snapshot(&snapshot)?;
    if !snapshot.messages.is_empty() {
        log::info!(
            "Home Sync: replicated message snapshot messages={}",
            snapshot.messages.len()
        );
    }
    let first_chunk = transfer
        .chunks
        .first()
        .ok_or_else(|| anyhow!("Home sync transfer has no first chunk"))?;
    storage
        .lock()
        .map_err(|_| anyhow!("client storage lock poisoned"))?
        .record_home_sync_applied(
            &transfer.source_public_key,
            &first_chunk.transfer_id,
            &first_chunk.snapshot_sha256,
        )?;
    ctx.home_state
        .lock()
        .await
        .pending_sync_transfers
        .remove(transfer_id);
    Ok(true)
}

#[cfg(test)]
mod peer_address_state_tests {
    use super::*;

    #[test]
    fn refresh_backoff_starts_after_three_attempts() {
        let mut state = PeerAddressState::default();
        for _ in 0..MAX_PEER_ADDRESS_REFRESH_ATTEMPTS {
            assert!(state.begin_refresh("peer"));
        }
        assert!(!state.begin_refresh("peer"));

        if let Some(attempt) = state.refresh_attempts.get_mut("peer") {
            attempt.1 -= PEER_ADDRESS_REFRESH_BACKOFF;
        }
        assert!(state.begin_refresh("peer"));
    }

    #[test]
    fn authenticated_address_clears_stale_state_and_backoff() {
        let mut state = PeerAddressState::default();
        state.mark_stale("peer", "192.168.0.98:4001".to_string());
        assert_eq!(
            state.stale_addresses("peer"),
            HashSet::from(["192.168.0.98:4001".to_string()])
        );
        state.begin_refresh("peer");
        state.confirm_address("peer", "192.168.0.99:4001");
        assert!(state.stale_addresses("peer").is_empty());
        assert!(!state.refresh_attempts.contains_key("peer"));
    }

    #[test]
    fn network_change_invalidates_only_lan_peer_addresses() {
        let mut state = PeerAddressState::default();
        let peers = vec![
            PeerEntry {
                address: "192.168.0.98:4001".to_string(),
                identity_id: "lan-peer".to_string(),
                public_key_hex: String::new(),
                source: crate::peer_directory::PeerEntrySource::OutboundVerified,
                first_seen: 1,
                last_seen: 1,
                expires_at: 100,
            },
            PeerEntry {
                address: "198.51.100.10:4001".to_string(),
                identity_id: "wan-peer".to_string(),
                public_key_hex: String::new(),
                source: crate::peer_directory::PeerEntrySource::OutboundVerified,
                first_seen: 1,
                last_seen: 1,
                expires_at: 100,
            },
        ];

        assert_eq!(state.invalidate_all(&peers), 1);
        assert_eq!(
            state.stale_addresses("lan-peer"),
            HashSet::from(["192.168.0.98:4001".to_string()])
        );
        assert!(state.stale_addresses("wan-peer").is_empty());
    }

    #[test]
    fn cover_traffic_state_uses_burst_and_chaos_outside_idle() {
        let now = Instant::now();
        let recent = now - Duration::from_secs(10);

        assert_eq!(
            CoverTrafficState::evaluate(recent, true, true, true, now),
            CoverTrafficState::Chaos
        );
        assert_eq!(
            CoverTrafficState::evaluate(recent, false, false, false, now),
            CoverTrafficState::Burst
        );
        assert_eq!(
            CoverTrafficState::evaluate(now - Duration::from_secs(31), false, false, false, now),
            CoverTrafficState::Idle
        );
    }
}

enum SasPairingSendRoute {
    Wss(crate::transport::WssClientSessionHandle),
    IncomingMux(crate::mux::MuxSender),
}

fn select_sas_pairing_send_route(
    client_session: Option<crate::transport::WssClientSessionHandle>,
    mux_sender: Option<crate::mux::MuxSender>,
) -> Result<SasPairingSendRoute> {
    if let Some(session) = client_session.filter(|session| session.is_alive()) {
        return Ok(SasPairingSendRoute::Wss(session));
    }
    mux_sender
        .filter(crate::mux::MuxSender::is_alive)
        .map(SasPairingSendRoute::IncomingMux)
        .ok_or_else(|| anyhow!("WSS pairing session is no longer connected"))
}

#[cfg(test)]
mod sas_pairing_send_route_tests {
    use super::*;

    #[tokio::test]
    async fn uses_live_incoming_mux_when_no_client_session_exists() {
        let (stream, _peer) = tokio::io::duplex(1024);
        let mux = crate::mux::Mux::new(
            stream,
            crate::mux::MuxConfig::default(),
            crate::mux::Mode::Server,
        );
        let sender = mux.sender();

        match select_sas_pairing_send_route(None, Some(sender)).expect("live sender route") {
            SasPairingSendRoute::IncomingMux(sender) => assert!(sender.is_alive()),
            SasPairingSendRoute::Wss(_) => panic!("expected incoming mux route"),
        }

        mux.close().await.expect("close test mux");
    }

    #[tokio::test]
    async fn rejects_dead_incoming_mux_sender() {
        let (stream, _peer) = tokio::io::duplex(1024);
        let mux = crate::mux::Mux::new(
            stream,
            crate::mux::MuxConfig::default(),
            crate::mux::Mode::Server,
        );
        let sender = mux.sender();
        mux.close().await.expect("close test mux");

        assert!(select_sas_pairing_send_route(None, Some(sender)).is_err());
    }
}

pub struct PeerRuntime {
    pub identity_id: String,
    pub public_key: String,
    pub transport_address: String,
    private_key: SigningKey,
    transport: PeerTransport,
    incoming_task: Option<JoinHandle<()>>,
    incoming_shutdown: Option<oneshot::Sender<()>>,
    quic_incoming_task: Option<JoinHandle<()>>,
    quic_incoming_shutdown: Option<oneshot::Sender<()>>,
    quic_listener_endpoint: Arc<tokio::sync::RwLock<Option<Arc<quinn::Endpoint>>>>,
    quic_listener_task: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    quic_listener_shutdown: tokio::sync::Mutex<Option<oneshot::Sender<()>>>,
    quic_punch_task: Option<JoinHandle<()>>,
    quic_punch_shutdown: Option<oneshot::Sender<()>>,
    relay_task: Option<JoinHandle<()>>,
    relay_shutdown: Option<oneshot::Sender<()>>,
    relay_service: Option<Arc<RelayService>>,
    refresh_task: Option<JoinHandle<()>>,
    refresh_shutdown: Option<oneshot::Sender<()>>,
    endpoint_heartbeat_task: Option<JoinHandle<()>>,
    endpoint_heartbeat_shutdown: Option<oneshot::Sender<()>>,
    punch_fetch_task: Option<JoinHandle<()>>,
    punch_fetch_shutdown: Option<oneshot::Sender<()>>,
    badge_fetch_task: Option<JoinHandle<()>>,
    badge_fetch_shutdown: Option<oneshot::Sender<()>>,
    prekey_rotation_task: Option<JoinHandle<()>>,
    prekey_rotation_shutdown: Option<oneshot::Sender<()>>,
    journal_commit_task: Option<JoinHandle<()>>,
    journal_commit_shutdown: Option<oneshot::Sender<()>>,
    jury_assembly_task: Option<JoinHandle<()>>,
    jury_assembly_shutdown: Option<oneshot::Sender<()>>,
    jury_outbox_task: Option<JoinHandle<()>>,
    jury_outbox_shutdown: Option<oneshot::Sender<()>>,
    complainant_orchestrator_task: Option<JoinHandle<()>>,
    complainant_orchestrator_shutdown: Option<oneshot::Sender<()>>,
    juror_orchestrator_task: Option<JoinHandle<()>>,
    juror_orchestrator_shutdown: Option<oneshot::Sender<()>>,
    retention_prune_task: Option<JoinHandle<()>>,
    retention_prune_shutdown: Option<oneshot::Sender<()>>,
    auto_badge_task: Option<JoinHandle<()>>,
    auto_badge_shutdown: Option<oneshot::Sender<()>>,
    inbound_obs_task: Option<JoinHandle<()>>,
    inbound_obs_shutdown: Option<oneshot::Sender<()>>,
    stigma_refresh_task: Option<JoinHandle<()>>,
    stigma_refresh_shutdown: Option<oneshot::Sender<()>>,
    polling: Option<PollingRuntime>,
    poll_actions: Arc<Mutex<Vec<PollRequest>>>,
    peers: Arc<Mutex<Vec<String>>>,
    dispatcher_task: Option<JoinHandle<()>>,
    dispatcher_shutdown: Option<oneshot::Sender<()>>,
    discovery: Option<PeerDiscovery>,
    discovery_task: Option<JoinHandle<()>>,
    discovery_shutdown: Option<oneshot::Sender<()>>,
    lan_discovery: Option<crate::lan_discovery::LanDiscovery>,
    lan_discovery_task: Option<JoinHandle<()>>,
    lan_discovery_shutdown: Option<oneshot::Sender<()>>,
    public_endpoint: Arc<std::sync::RwLock<Option<SocketAddr>>>,
    public_quic_endpoint: Arc<std::sync::RwLock<Option<SocketAddr>>>,
    software_measurement: Option<String>,
    ctx: Arc<RuntimeContext>,
    presence_policy: PresencePolicy,
    trust_policy: NetworkTrustPolicy,
    relay_mode_enabled: Arc<AtomicBool>,
    force_wss_relay: AtomicBool,
    activity: Arc<Mutex<ActivityController>>,
    dispatch_notify: Arc<Notify>,
    dht_local_id: NodeId,
    dht_routing: Arc<Mutex<RoutingTable>>,
    dht_cache: Arc<Mutex<EndpointCache>>,
    dht_handler: Arc<DhtRequestHandler>,
    dht_metrics: Arc<crate::dht::DhtMetrics>,
    dht_config: Arc<Mutex<DhtPollerConfig>>,
    dht_priority: Arc<Mutex<PriorityRegistry>>,
    #[allow(dead_code)]
    dht_activity_state: Arc<Mutex<ActivityController>>,
    dht_stream_tx:
        Option<mpsc::Sender<(crate::Mux<crate::tls_transport::TlsConn>, crate::MuxStream)>>,
    dht_worker_task: Option<JoinHandle<()>>,
    active_sessions: Mutex<HashMap<String, ActivePeerSession>>,
    wss_sessions: Mutex<HashMap<String, crate::transport::WssClientSessionHandle>>,
    wss_url: Arc<Mutex<Option<String>>>,
    recent_send_failures: Mutex<HashMap<String, Instant>>,
    peer_address_state: Arc<Mutex<PeerAddressState>>,
    cover_state: Arc<Mutex<CoverTrafficState>>,
    last_message_time: Arc<Mutex<Instant>>,
    cover_traffic_task: Option<JoinHandle<()>>,
    cover_traffic_shutdown: Option<oneshot::Sender<()>>,
    home_sync_task: Option<JoinHandle<()>>,
    home_sync_shutdown: Option<oneshot::Sender<()>>,
}

fn pin_identity_in_context(
    ctx: &RuntimeContext,
    identity_id: &str,
    public_key_hex: &str,
) -> Result<()> {
    let node_id =
        pubkey_to_node_id(public_key_hex).ok_or_else(|| anyhow!("invalid peer public key"))?;
    if node_id.to_hex() != identity_id {
        return Err(anyhow!("peer identity does not match public key"));
    }
    let now = unix_now();
    let mut hosts = ctx
        .hosts
        .lock()
        .map_err(|_| anyhow!("known hosts mutex poisoned"))?;
    if let crate::pinning::BindingCheck::Conflicted { .. } =
        hosts.check(identity_id, public_key_hex)
    {
        return Err(anyhow!(
            "identity {identity_id} is already pinned to a different public key"
        ));
    }
    if let Some(storage) = ctx.storage.as_ref() {
        storage
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?
            .peer_registry()
            .pin_identity(identity_id, public_key_hex, now)
            .map_err(|error| anyhow!("failed to persist trust pin: {error}"))?;
    }
    hosts.pin_manual(identity_id, public_key_hex, now)?;
    Ok(())
}

fn read_profile_display_name(
    storage: Option<&Arc<StdMutex<ClientStorage>>>,
) -> Result<Option<String>> {
    let Some(storage) = storage else {
        return Ok(None);
    };
    let storage = storage
        .lock()
        .map_err(|error| anyhow!("client storage lock poisoned: {error}"))?;
    Ok(storage
        .get_setting("profile_display_name")?
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty()))
}

#[cfg(not(test))]
async fn publish_public_profile_record(
    identity_id: &str,
    public_key: &str,
    signing_key: &SigningKey,
    display_name: Option<String>,
    relay_mode: bool,
    wss_url: Option<String>,
    now: u64,
) -> Result<()> {
    let record = EndpointRecord::create(
        identity_id.to_owned(),
        public_key.to_owned(),
        Vec::new(),
        signing_key,
        now,
        crate::dht::ENDPOINT_TTL_SECONDS,
    )?
    .with_relay(relay_mode, signing_key)
    .with_wss_url(if relay_mode { wss_url } else { None }, signing_key)?
    .with_display_name(display_name, signing_key)?;
    crate::dht::endpoint_lookup::publish_public_endpoint_record(&record, signing_key).await
}

fn sas_pairing_envelope(
    ctx: &RuntimeContext,
    message: crate::pairing_sas::SasPairingMessage,
) -> Result<SyncEnvelope> {
    let signing_key = ctx
        .identity_signing_key
        .as_ref()
        .ok_or_else(|| anyhow!("SAS pairing requires the local identity signing key"))?;
    let mut event_id = [0u8; 16];
    OsRng.fill_bytes(&mut event_id);
    let data = serde_json::to_string(&message)?;
    let mut event = SyncEvent::new(hex::encode(event_id), SyncEventType::SasPairing, data);
    event.sign(&signing_key.to_bytes())?;
    let mut envelope =
        SyncEnvelope::new(ctx.identity_id.clone(), ctx.public_key.clone(), vec![event]);
    if let Some(wave) = ctx.integrity.as_ref() {
        let now = unix_now();
        let mut response = IntegrityResponse::new(
            wave,
            ctx.public_key.clone(),
            wave.required_measurement.clone(),
            now,
        )?;
        response.sign(&signing_key.to_bytes());
        envelope = envelope.with_integrity_response(response);
    }
    Ok(envelope)
}

async fn store_sas_pairing_prompt(
    ctx: &RuntimeContext,
    session_id: String,
    prompt: crate::pairing_sas::SasPairingPrompt,
) {
    let is_new = ctx
        .sas_pairing
        .prompts
        .lock()
        .await
        .insert(session_id, prompt.clone())
        .is_none();
    #[cfg(not(target_os = "android"))]
    if is_new {
        log::info!(
            "SAS pairing code for peer {}: {}",
            prompt.peer_identity_id,
            prompt.code
        );
        println!(
            "\n=== HAL RELAY SAS ===\nPeer: {}\nCompare this six-digit code with the paired device: {}\nConfirm only if both codes match.\n=====================\n",
            prompt.peer_identity_id, prompt.code
        );
    }
    #[cfg(target_os = "android")]
    let _ = (is_new, prompt);
}

async fn prune_expired_sas_pairings(ctx: &RuntimeContext) {
    let expired = {
        let mut sessions = ctx.sas_pairing.sessions.lock().await;
        let expired = sessions
            .iter()
            .filter(|(_, session)| {
                session.started_at.elapsed() >= crate::pairing_sas::SAS_PAIRING_TIMEOUT
            })
            .map(|(session_id, _)| session_id.clone())
            .collect::<Vec<_>>();
        sessions.retain(|_, session| {
            session.started_at.elapsed() < crate::pairing_sas::SAS_PAIRING_TIMEOUT
        });
        expired
    };
    if !expired.is_empty() {
        let mut prompts = ctx.sas_pairing.prompts.lock().await;
        for session_id in expired {
            prompts.remove(&session_id);
        }
    }
}

fn home_presence_envelope(
    ctx: &RuntimeContext,
    message: crate::peer_presence::PeerPresenceMessage,
) -> Result<SyncEnvelope> {
    let signing_key = ctx
        .identity_signing_key
        .as_ref()
        .ok_or_else(|| anyhow!("Home Presence requires the local identity signing key"))?;
    let mut event = SyncEvent::new(
        uuid::Uuid::new_v4().to_string(),
        SyncEventType::PeerPresence,
        serde_json::to_string(&message)?,
    );
    event.sign(&signing_key.to_bytes())?;
    Ok(SyncEnvelope::new(
        ctx.identity_id.clone(),
        ctx.public_key.clone(),
        vec![event],
    ))
}

async fn handle_home_presence_envelope(
    envelope: SyncEnvelope,
    meta: EnvelopeMeta,
    ctx: Arc<RuntimeContext>,
) -> Result<()> {
    if envelope.events.len() != 1 || envelope.media_signal.is_some() {
        return Err(anyhow!("Home Presence must use a single control event"));
    }
    let sender = meta
        .session_sender
        .ok_or_else(|| anyhow!("Home Presence requires a persistent WSS session"))?;
    if !sender.is_alive() {
        return Err(anyhow!("Home Presence WSS session is not alive"));
    }
    let event = envelope
        .events
        .first()
        .ok_or_else(|| anyhow!("empty Home Presence envelope"))?;
    if event.event_type != SyncEventType::PeerPresence {
        return Err(anyhow!("invalid Home Presence event"));
    }
    let message: crate::peer_presence::PeerPresenceMessage = serde_json::from_str(&event.data)
        .map_err(|error| anyhow!("invalid Home Presence message: {error}"))?;

    match message {
        crate::peer_presence::PeerPresenceMessage::Request {
            request_id,
            home_stack_id,
            endpoints,
            wss_url,
        } => {
            let now = unix_now();
            let public_key_bytes: [u8; 32] = hex::decode(&envelope.public_key)?
                .try_into()
                .map_err(|_| anyhow!("Home Presence public key must be 32 bytes"))?;
            let public_key = VerifyingKey::from_bytes(&public_key_bytes)?;
            if NodeId::from_public_key(&public_key).to_hex() != envelope.identity_id {
                return Err(anyhow!(
                    "Home Presence identity does not match its public key"
                ));
            }
            let record = crate::peer_presence::PeerPresenceRecord {
                identity_id: envelope.identity_id.clone(),
                public_key: envelope.public_key.clone(),
                endpoints,
                wss_url,
                last_seen: now,
            };
            crate::peer_presence::validate_record(&record)?;

            let response = {
                let mut state = ctx.home_state.lock().await;
                let registered_stack = state
                    .home_stack_id
                    .clone()
                    .ok_or_else(|| anyhow!("relay has no registered Home Stack"))?;
                let members = state.linked_device_pubkeys.clone();
                if registered_stack != home_stack_id || !members.contains(&envelope.public_key) {
                    return Err(anyhow!(
                        "Home Presence requester is not a member of this Home Stack"
                    ));
                }
                if state
                    .presence_last_request
                    .get(&envelope.identity_id)
                    .is_some_and(|last_request| {
                        now.saturating_sub(*last_request)
                            < crate::peer_presence::PRESENCE_MIN_REQUEST_INTERVAL_SECS
                    })
                {
                    crate::peer_presence::PeerPresenceMessage::Error {
                        request_id,
                        reason: "presence request rate limited".to_string(),
                    }
                } else {
                    state
                        .presence_last_request
                        .insert(envelope.identity_id.clone(), now);
                    state.active_presence.insert(
                        envelope.identity_id.clone(),
                        crate::peer_presence::ActivePeerPresence {
                            record,
                            session_sender: sender.clone(),
                        },
                    );
                    state.active_presence.retain(|_, entry| {
                        entry
                            .record
                            .last_seen
                            .saturating_add(crate::peer_presence::PRESENCE_TTL_SECS)
                            > now
                            && members.contains(&entry.record.public_key)
                            && entry.session_sender.is_alive()
                    });
                    state
                        .presence_last_request
                        .retain(|_, last_request| last_request.saturating_add(300) > now);
                    let mut peers = crate::peer_presence::filter_home_members(
                        state.active_presence.values().map(|entry| &entry.record),
                        &members,
                        now,
                    );
                    peers.sort_by(|left, right| left.identity_id.cmp(&right.identity_id));
                    if peers.len() > crate::peer_presence::PRESENCE_MAX_PEERS {
                        peers.truncate(crate::peer_presence::PRESENCE_MAX_PEERS);
                    }
                    crate::peer_presence::PeerPresenceMessage::Response {
                        request_id,
                        home_stack_id: registered_stack,
                        updated_at: now,
                        peers,
                    }
                }
            };
            let reply = home_presence_envelope(&ctx, response)?;
            crate::transport::send_envelope_over_mux_sender(
                &sender,
                &reply,
                Some(&ctx.abuse_metrics),
            )
            .await?;
        }
        crate::peer_presence::PeerPresenceMessage::Response {
            request_id,
            home_stack_id,
            updated_at,
            peers,
        } => {
            let relay_is_pinned = ctx
                .hosts
                .lock()
                .map_err(|_| anyhow!("known hosts mutex poisoned"))?
                .check(&envelope.identity_id, &envelope.public_key);
            if !matches!(relay_is_pinned, crate::pinning::BindingCheck::Trusted) {
                return Err(anyhow!(
                    "Home Presence response came from an unpinned relay"
                ));
            }
            let (pending, response) = {
                let mut state = ctx.home_state.lock().await;
                let expected_stack = state
                    .home_stack_id
                    .as_deref()
                    .ok_or_else(|| anyhow!("local Home Stack is not registered"))?;
                if expected_stack != home_stack_id {
                    return Err(anyhow!(
                        "Home Presence response belongs to a different Home"
                    ));
                }
                if peers.len() > crate::peer_presence::PRESENCE_MAX_PEERS {
                    return Err(anyhow!("Home Presence response exceeds the peer limit"));
                }
                for peer in &peers {
                    crate::peer_presence::validate_record(peer)?;
                    if !state.linked_device_pubkeys.contains(&peer.public_key) {
                        return Err(anyhow!(
                            "Home Presence response contains a peer outside the local Home"
                        ));
                    }
                }
                let pending = state
                    .pending_presence_requests
                    .remove(&request_id)
                    .ok_or_else(|| anyhow!("unsolicited Home Presence response"))?;
                state.cached_presence = peers
                    .iter()
                    .cloned()
                    .map(|peer| (peer.identity_id.clone(), peer))
                    .collect();
                (
                    pending,
                    crate::peer_presence::PeerPresenceMessage::Response {
                        request_id,
                        home_stack_id,
                        updated_at,
                        peers,
                    },
                )
            };
            let _ = pending.send(response);
        }
        crate::peer_presence::PeerPresenceMessage::Error { request_id, reason } => {
            let relay_is_pinned = ctx
                .hosts
                .lock()
                .map_err(|_| anyhow!("known hosts mutex poisoned"))?
                .check(&envelope.identity_id, &envelope.public_key);
            if !matches!(relay_is_pinned, crate::pinning::BindingCheck::Trusted) {
                return Err(anyhow!("Home Presence error came from an unpinned relay"));
            }
            let pending = ctx
                .home_state
                .lock()
                .await
                .pending_presence_requests
                .remove(&request_id)
                .ok_or_else(|| anyhow!("unsolicited Home Presence error response"))?;
            let _ = pending
                .send(crate::peer_presence::PeerPresenceMessage::Error { request_id, reason });
        }
    }
    Ok(())
}

async fn handle_sas_pairing_envelope(
    envelope: SyncEnvelope,
    meta: EnvelopeMeta,
    ctx: Arc<RuntimeContext>,
) -> Result<()> {
    let Some(event) = envelope.events.first() else {
        return Err(anyhow!("empty SAS pairing envelope"));
    };
    if envelope.events.len() != 1
        || event.event_type != SyncEventType::SasPairing
        || envelope.media_signal.is_some()
    {
        return Err(anyhow!("SAS pairing must use a single control event"));
    }
    let sender = meta
        .session_sender
        .ok_or_else(|| anyhow!("SAS pairing requires a persistent mux session"))?;
    prune_expired_sas_pairings(&ctx).await;
    let peer_identity_id = envelope.identity_id;
    let peer_public_key_hex = envelope.public_key;
    match ctx
        .hosts
        .lock()
        .map_err(|_| anyhow!("known hosts mutex poisoned"))?
        .check(&peer_identity_id, &peer_public_key_hex)
    {
        crate::pinning::BindingCheck::Conflicted { .. } => {
            return Err(anyhow!(
                "SAS peer identity conflicts with an existing trust pin"
            ));
        }
        crate::pinning::BindingCheck::Trusted | crate::pinning::BindingCheck::Unknown => {}
    }
    let message: crate::pairing_sas::SasPairingMessage = serde_json::from_str(&event.data)
        .map_err(|error| anyhow!("invalid SAS pairing message: {error}"))?;
    let stage = match &message {
        crate::pairing_sas::SasPairingMessage::Commitment { .. } => "commitment",
        crate::pairing_sas::SasPairingMessage::Reveal { .. } => "reveal",
        crate::pairing_sas::SasPairingMessage::Confirm { .. } => "confirmation",
        crate::pairing_sas::SasPairingMessage::Complete { .. } => "completion",
    };
    log::info!("Received WSS SAS {stage} from peer {peer_identity_id}");
    let mut outbound = Vec::new();
    let mut complete_peer = None;
    let mut finalized_peer = None;
    match message {
        crate::pairing_sas::SasPairingMessage::Commitment { commitment } => {
            if commitment.identity_id != peer_identity_id
                || commitment.public_key_hex != peer_public_key_hex
                || commitment.peer_identity_id != ctx.identity_id
            {
                return Err(anyhow!("SAS commitment identity binding mismatch"));
            }
            let session_id = commitment.session_id.clone();
            let session_id_bytes: [u8; 16] = hex::decode(&session_id)?
                .try_into()
                .map_err(|_| anyhow!("SAS session id must be 16 bytes"))?;
            let mut sessions = ctx.sas_pairing.sessions.lock().await;
            if !sessions.contains_key(&session_id) {
                if commitment.role != crate::pairing_sas::SasRole::Initiator {
                    return Err(anyhow!("unsolicited SAS responder commitment"));
                }
                if sessions.len() >= crate::pairing_sas::SAS_PAIRING_MAX_SESSIONS {
                    return Err(anyhow!("too many active SAS pairing sessions"));
                }
                let contribution = crate::pairing_sas::SasContribution::create(
                    session_id_bytes,
                    crate::pairing_sas::SasRole::Responder,
                    ctx.identity_id.clone(),
                    ctx.public_key.clone(),
                    peer_identity_id.clone(),
                )?;
                let mut session = crate::pairing_sas::SasPairingSession::new(
                    contribution,
                    peer_identity_id.clone(),
                    peer_public_key_hex.clone(),
                );
                session.mux_sender = Some(sender.clone());
                session.remote_commitment = Some(commitment.clone());
                session.local_commitment_sent = true;
                outbound.push(crate::pairing_sas::SasPairingMessage::Commitment {
                    commitment: session.contribution.commitment(),
                });
                session.local_reveal_sent = true;
                outbound.push(crate::pairing_sas::SasPairingMessage::Reveal {
                    session_id: session_id.clone(),
                    nonce_hex: session.contribution.reveal_nonce_hex(),
                });
                session.status = crate::pairing_sas::SasPairingStatus::Revealing;
                sessions.insert(session_id.clone(), session);
            } else {
                let session = sessions
                    .get_mut(&session_id)
                    .ok_or_else(|| anyhow!("SAS session disappeared"))?;
                if session.peer_identity_id != peer_identity_id
                    || session.peer_public_key_hex != peer_public_key_hex
                    || session.contribution.commitment().role == commitment.role
                    || session.contribution.commitment().peer_identity_id != commitment.identity_id
                {
                    return Err(anyhow!("SAS commitment does not match the active session"));
                }
                session.mux_sender = Some(sender.clone());
                if let Some(existing) = session.remote_commitment.as_ref() {
                    if existing != &commitment {
                        return Err(anyhow!("conflicting SAS commitment received"));
                    }
                } else {
                    session.remote_commitment = Some(commitment.clone());
                }
                if !session.local_commitment_sent {
                    session.local_commitment_sent = true;
                    outbound.push(crate::pairing_sas::SasPairingMessage::Commitment {
                        commitment: session.contribution.commitment(),
                    });
                }
                if !session.local_reveal_sent {
                    session.local_reveal_sent = true;
                    outbound.push(crate::pairing_sas::SasPairingMessage::Reveal {
                        session_id: session_id.clone(),
                        nonce_hex: session.contribution.reveal_nonce_hex(),
                    });
                }
                session.status = crate::pairing_sas::SasPairingStatus::Revealing;
                if let (Some(remote_commitment), Some(remote_nonce)) = (
                    session.remote_commitment.as_ref(),
                    session.remote_nonce_hex.as_deref(),
                ) {
                    session.code = Some(
                        session
                            .contribution
                            .derive_code(remote_commitment, remote_nonce)?,
                    );
                    session.status = crate::pairing_sas::SasPairingStatus::AwaitingUserConfirmation;
                    if let Some(prompt) = session.prompt() {
                        store_sas_pairing_prompt(&ctx, session_id.clone(), prompt).await;
                    }
                }
            }
        }
        crate::pairing_sas::SasPairingMessage::Reveal {
            session_id,
            nonce_hex,
        } => {
            let mut sessions = ctx.sas_pairing.sessions.lock().await;
            let session = sessions
                .get_mut(&session_id)
                .ok_or_else(|| anyhow!("SAS reveal received for an unknown session"))?;
            if session.peer_identity_id != peer_identity_id
                || session.peer_public_key_hex != peer_public_key_hex
            {
                return Err(anyhow!(
                    "SAS reveal identity does not match the active session"
                ));
            }
            session.mux_sender = Some(sender.clone());
            let nonce: [u8; 32] = hex::decode(&nonce_hex)?
                .try_into()
                .map_err(|_| anyhow!("SAS reveal nonce must be 32 bytes"))?;
            if session
                .remote_nonce_hex
                .as_deref()
                .is_some_and(|existing| existing != nonce_hex)
            {
                return Err(anyhow!("conflicting SAS reveal received"));
            }
            session.remote_nonce_hex = Some(nonce_hex.clone());
            if let Some(remote_commitment) = session.remote_commitment.as_ref() {
                let _ = nonce;
                session.code = Some(
                    session
                        .contribution
                        .derive_code(remote_commitment, &nonce_hex)?,
                );
                session.status = crate::pairing_sas::SasPairingStatus::AwaitingUserConfirmation;
                if let Some(prompt) = session.prompt() {
                    store_sas_pairing_prompt(&ctx, session_id, prompt).await;
                }
            }
        }
        crate::pairing_sas::SasPairingMessage::Confirm {
            session_id,
            accepted,
        } => {
            if !accepted {
                ctx.sas_pairing.sessions.lock().await.remove(&session_id);
                ctx.sas_pairing.prompts.lock().await.remove(&session_id);
                return Ok(());
            }
            let mut sessions = ctx.sas_pairing.sessions.lock().await;
            let session = sessions
                .get_mut(&session_id)
                .ok_or_else(|| anyhow!("SAS confirmation received for an unknown session"))?;
            if session.peer_identity_id != peer_identity_id
                || session.peer_public_key_hex != peer_public_key_hex
            {
                return Err(anyhow!(
                    "SAS confirmation identity does not match the session"
                ));
            }
            session.mux_sender = Some(sender.clone());
            if session.record_remote_confirmation()? {
                complete_peer = Some((
                    session.peer_identity_id.clone(),
                    session.peer_public_key_hex.clone(),
                    session_id.clone(),
                ));
            }
        }
        crate::pairing_sas::SasPairingMessage::Complete { session_id } => {
            let mut sessions = ctx.sas_pairing.sessions.lock().await;
            let Some(session) = sessions.get(&session_id) else {
                drop(sessions);
                let hosts = ctx
                    .hosts
                    .lock()
                    .map_err(|_| anyhow!("known hosts mutex poisoned"))?;
                if matches!(
                    hosts.check(&peer_identity_id, &peer_public_key_hex),
                    crate::pinning::BindingCheck::Trusted
                ) {
                    log::debug!("Ignoring duplicate SAS completion from trusted peer");
                    return Ok(());
                }
                return Err(anyhow!("SAS completion received for an unknown session"));
            };
            if session.peer_identity_id != peer_identity_id
                || session.peer_public_key_hex != peer_public_key_hex
            {
                return Err(anyhow!(
                    "SAS completion identity does not match the session"
                ));
            }
            let session = sessions
                .get_mut(&session_id)
                .ok_or_else(|| anyhow!("SAS session disappeared"))?;
            if session.record_remote_completion()? {
                finalized_peer = Some((
                    session.peer_identity_id.clone(),
                    session.peer_public_key_hex.clone(),
                    session_id.clone(),
                ));
            } else {
                log::debug!(
                    "SAS completion arrived before both confirmations; retaining the session"
                );
            }
        }
    }

    for message in outbound {
        crate::transport::send_envelope_over_mux_sender(
            &sender,
            &sas_pairing_envelope(&ctx, message)?,
            Some(&ctx.abuse_metrics),
        )
        .await?;
    }
    if let Some((identity_id, public_key_hex, session_id)) = complete_peer {
        pin_identity_in_context(&ctx, &identity_id, &public_key_hex)?;
        crate::transport::send_envelope_over_mux_sender(
            &sender,
            &sas_pairing_envelope(
                &ctx,
                crate::pairing_sas::SasPairingMessage::Complete {
                    session_id: session_id.clone(),
                },
            )?,
            Some(&ctx.abuse_metrics),
        )
        .await?;
        let remote_completion_received = ctx
            .sas_pairing
            .sessions
            .lock()
            .await
            .get(&session_id)
            .is_some_and(crate::pairing_sas::SasPairingSession::is_complete);
        if remote_completion_received {
            finalized_peer = Some((identity_id, public_key_hex, session_id));
        }
    }
    if let Some((identity_id, public_key_hex, session_id)) = finalized_peer {
        pin_identity_in_context(&ctx, &identity_id, &public_key_hex)?;
        ctx.sas_pairing.sessions.lock().await.remove(&session_id);
        ctx.sas_pairing.prompts.lock().await.remove(&session_id);
        log::info!("SAS pairing completed with peer {identity_id}");
    }
    Ok(())
}

async fn bind_runtime_quic_endpoint(
    signing_key: &SigningKey,
) -> (Option<Arc<quinn::Endpoint>>, Option<SocketAddr>) {
    if cfg!(test) {
        return bind_quic_endpoint_on_socket(
            tokio::net::UdpSocket::bind("0.0.0.0:0").await,
            signing_key,
            None,
        );
    }

    let server_names = crate::stun::STUN_DEFAULT_SERVERS
        .iter()
        .filter(|server| server.contains("google.com") || server.contains("cloudflare.com"))
        .take(2)
        .copied()
        .collect::<Vec<_>>();
    let mut servers_by_family = [Vec::new(), Vec::new()];
    for server in server_names {
        match tokio::net::lookup_host(server).await {
            Ok(addresses) => {
                for address in addresses {
                    let family = if address.is_ipv6() { 1 } else { 0 };
                    let candidates = &mut servers_by_family[family];
                    if !candidates.contains(&address) {
                        candidates.push(address);
                    }
                }
            }
            Err(error) => log::warn!("unable to resolve STUN server {server}: {error}"),
        }
    }

    let mut fallback_family = None;
    let mut symmetric_nat = false;
    for is_ipv6 in [true, false] {
        let family = if is_ipv6 { 1 } else { 0 };
        let bind_address = if is_ipv6 { "[::]:4003" } else { "0.0.0.0:4003" };
        let socket = match tokio::net::UdpSocket::bind(bind_address).await {
            Ok(socket) => socket,
            Err(error) => {
                log::warn!("unable to bind QUIC UDP listener on {bind_address}: {error}");
                continue;
            }
        };
        fallback_family.get_or_insert(is_ipv6);
        let servers = servers_by_family[family]
            .iter()
            .map(SocketAddr::to_string)
            .collect::<Vec<_>>();
        if servers.is_empty() {
            fallback_family = Some(is_ipv6);
            continue;
        }

        let stun_config = crate::stun::StunConfig {
            servers,
            timeout: Duration::from_secs(2),
        };
        match crate::stun::StunClient::new(stun_config)
            .discover_multi_on_socket(&socket)
            .await
        {
            Ok(endpoints) => {
                let mut addresses = Vec::new();
                for endpoint in endpoints {
                    let address = SocketAddr::new(endpoint.ip, endpoint.port);
                    if !addresses.contains(&address) {
                        addresses.push(address);
                    }
                }
                match addresses.as_slice() {
                    [address] => {
                        log::info!("STUN discovered public UDP address: {address}");
                        return bind_quic_endpoint_on_socket(
                            Ok(socket),
                            signing_key,
                            Some(*address),
                        );
                    }
                    [] => {}
                    _ => {
                        symmetric_nat = true;
                        log::warn!(
                            "STUN returned inconsistent UDP mappings on {}: {}",
                            if is_ipv6 { "IPv6" } else { "IPv4" },
                            addresses
                                .iter()
                                .map(SocketAddr::to_string)
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                    }
                }
            }
            Err(error) => {
                log::warn!(
                    "STUN discovery for QUIC UDP socket on {} failed: {error}",
                    if is_ipv6 { "IPv6" } else { "IPv4" }
                );
            }
        }
    }

    if symmetric_nat {
        log::warn!("Symmetric NAT detected: relay fallback required");
    }
    if let Some(is_ipv6) = fallback_family {
        let bind_address = if is_ipv6 { "[::]:4003" } else { "0.0.0.0:4003" };
        return bind_quic_endpoint_on_socket(
            tokio::net::UdpSocket::bind(bind_address).await,
            signing_key,
            None,
        );
    }
    (None, None)
}

fn bind_quic_endpoint_on_socket(
    socket: std::io::Result<tokio::net::UdpSocket>,
    signing_key: &SigningKey,
    public_address: Option<SocketAddr>,
) -> (Option<Arc<quinn::Endpoint>>, Option<SocketAddr>) {
    let socket = match socket {
        Ok(socket) => socket,
        Err(error) => {
            log::warn!("unable to bind QUIC UDP listener: {error}");
            return (None, None);
        }
    };
    match QuicChannel::bind_server_endpoint(socket, signing_key, QuicConfig::default()) {
        Ok(endpoint) => (Some(Arc::new(endpoint)), public_address),
        Err(error) => {
            log::warn!("unable to start QUIC UDP listener: {error}");
            (None, None)
        }
    }
}

struct ActivePeerSession {
    address: SocketAddr,
    mux: Arc<Mutex<crate::Mux<crate::tls_transport::TlsConn>>>,
}

impl PeerRuntime {
    pub const DEFAULT_PEER_PORT: u16 = 4001;

    pub fn new_group_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    pub fn configured_peer_port() -> Result<u16> {
        let port = std::env::var("HAL_PEER_PORT")
            .ok()
            .map(|value| {
                value
                    .parse::<u16>()
                    .map_err(|error| anyhow!("HAL_PEER_PORT must be a valid port: {error}"))
            })
            .transpose()?
            .unwrap_or(Self::DEFAULT_PEER_PORT);
        if port == 0 {
            return Err(anyhow!("HAL_PEER_PORT must be between 1 and 65535"));
        }
        Ok(port)
    }

    pub fn transport_addresses(&self) -> Vec<String> {
        let mut addresses = advertised_transport_addresses(&self.transport.local_address);
        match self.public_endpoint.read() {
            Ok(endpoint) => {
                if let Some(endpoint) = endpoint.as_ref() {
                    let address = endpoint.to_string();
                    if !addresses.contains(&address) {
                        addresses.push(address);
                    }
                }
            }
            Err(error) => {
                log::error!("public endpoint state lock poisoned: {error}");
            }
        }
        addresses
    }

    pub fn set_cover_traffic_state(&self, is_charging: bool, is_wifi: bool, is_chat_open: bool) {
        let now = Instant::now();
        let last_message_time = *self.last_message_time.blocking_lock();
        let next_state =
            CoverTrafficState::evaluate(last_message_time, is_charging, is_wifi, is_chat_open, now);
        *self.cover_state.blocking_lock() = next_state;
    }

    pub async fn note_message_activity(&self) {
        *self.last_message_time.lock().await = Instant::now();
        let mut state = self.cover_state.lock().await;
        if *state != CoverTrafficState::Idle {
            *state = CoverTrafficState::Burst;
        }
    }

    async fn generate_cover_traffic_packet(&self, state: CoverTrafficState) {
        if matches!(state, CoverTrafficState::Idle) {
            return;
        }
        let label = match state {
            CoverTrafficState::Burst => "Burst",
            CoverTrafficState::Chaos => "Chaos",
            CoverTrafficState::Idle => return,
        };
        let envelope = SyncEnvelope::new_cover(self.identity_id.clone(), self.public_key.clone());
        log::info!(target: "HAL_DHT", "CoverTraffic: generated {} packet", label);
        if let Err(error) = crate::transport::send_envelope_secure(
            &self.transport_address,
            &envelope,
            &self.private_key,
            Arc::clone(&self.ctx.hosts),
            self.trust_policy.clone(),
        )
        .await
        {
            log::warn!(target: "HAL_DHT", "CoverTraffic: failed to send {} packet: {error}", label);
        }
    }

    pub async fn activate_invite_cutover(
        &self,
        now: u64,
    ) -> Result<hal_storage::invite_storage::CutoverState> {
        let storage = self
            .ctx
            .storage
            .as_ref()
            .ok_or_else(|| anyhow!("durable storage required to activate invite cutover"))?;
        let (state, peers_without_proof) = {
            let mut storage = storage
                .lock()
                .map_err(|error| anyhow!("client storage lock poisoned: {error}"))?;
            if let Some(state) = storage.read_cutover_state()? {
                return Ok(state);
            }

            let state = storage.activate_cutover(now)?;
            let peers_without_proof = storage
                .list_grandfathered()?
                .into_iter()
                .filter(|node_id| node_id != self.dht_local_id.as_bytes())
                .filter_map(
                    |node_id| match storage.read_invite_proof(&hex::encode(node_id)) {
                        Ok(Some(_)) => None,
                        Ok(None) => Some(Ok(NodeId::from_bytes(node_id))),
                        Err(error) => Some(Err(error)),
                    },
                )
                .collect::<Result<Vec<_>>>()?;
            (state, peers_without_proof)
        };

        let mut home_state = self.ctx.home_state.lock().await;
        for peer in peers_without_proof {
            home_state.notifications.create(
                crate::dht::notifier::NotificationKind::InviteRedemptionRequired,
                peer,
                self.dht_local_id,
                None,
                now,
                crate::dht::notifier::NOTIFICATION_DEFAULT_TTL_SECS,
            );
        }
        Ok(state)
    }

    pub async fn self_proof_of_live(
        &self,
        now: u64,
    ) -> Option<crate::proof_of_live::ProofOfLiveStatus> {
        let pol = self.ctx.proof_of_live.as_ref()?;
        Some(pol.status(&self.dht_local_id, now).await)
    }

    pub async fn create_invite(&self, ttl_seconds: u64) -> Result<String> {
        self.create_invite_with_display_name(ttl_seconds, None)
            .await
    }

    pub async fn create_invite_with_display_name(
        &self,
        ttl_seconds: u64,
        display_name: Option<String>,
    ) -> Result<String> {
        self.create_invite_with_profile(ttl_seconds, display_name, None)
            .await
    }

    pub async fn create_invite_with_profile(
        &self,
        ttl_seconds: u64,
        display_name: Option<String>,
        avatar_b64: Option<String>,
    ) -> Result<String> {
        let now = unix_now();
        let debug_pol_bypass = cfg!(debug_assertions);
        if debug_pol_bypass {
            log::info!("PoL bypassed for debug invite");
        } else if let Some(pol) = self.ctx.proof_of_live.as_ref() {
            let status = pol.status(&self.dht_local_id, now).await;
            if !status.can_issue_invite() {
                self.ctx
                    .abuse_metrics
                    .proof_of_live_invite_rejected_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Err(anyhow!("invite forbidden: {:?}", status));
            }
        }
        if !debug_pol_bypass {
            if let Some(trust_graph) = &self.ctx.trust_graph {
                match trust_graph.gate(&self.dht_local_id, now).await {
                    TrustGateDecision::Allow => {}
                    TrustGateDecision::Throttle { .. } | TrustGateDecision::Block { .. } => {
                        self.ctx
                            .abuse_metrics
                            .trust_gate_blocked_total
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return Err(anyhow!("invite issuance blocked by trust gate"));
                    }
                }
            }
        }
        let issuer_id = self.dht_local_id;
        let mut registry = self.ctx.invite_registry.lock().await;
        #[cfg(debug_assertions)]
        let issuer_first_seen = now.saturating_sub(crate::dht::invite::NEW_IDENTITY_COOLDOWN_SECS);
        #[cfg(not(debug_assertions))]
        let issuer_first_seen = registry.issuer_first_seen(&issuer_id).unwrap_or(now);
        let debug_bypass_active = cfg!(all(debug_assertions, not(test)));
        if debug_bypass_active {
            log::debug!("debug build bypasses Invite fan-out limit");
        }
        let issue_check = if debug_bypass_active {
            Ok(())
        } else {
            registry.can_issue(&issuer_id, None, issuer_first_seen, now)
        };
        match issue_check {
            Ok(()) => {
                let invite_address = select_lan_invite_address(&self.transport_addresses())?;
                log::info!("creating Invite with LAN address {invite_address}");
                let mut nonce = [0u8; 16];
                OsRng.fill_bytes(&mut nonce);
                let link = InviteData::create_with_profile(
                    self.identity_id.clone(),
                    self.public_key.clone(),
                    invite_address,
                    display_name,
                    avatar_b64,
                    &self.private_key,
                    Duration::from_secs(ttl_seconds),
                    nonce,
                )?
                .to_link()?;
                registry.register_legacy(&issuer_id, now);
                if let Some(storage) = self.ctx.storage.as_ref() {
                    let storage = storage.lock().map_err(|error| {
                        anyhow!("client storage lock poisoned while persisting invite registry: {error}")
                    })?;
                    if let Err(error) = registry.persist_first_seen(&storage, issuer_id.as_bytes())
                    {
                        log::warn!("failed to persist invite registry first_seen: {error}");
                        return Err(anyhow!(
                            "failed to persist invite registry first_seen: {error}"
                        ));
                    }
                }
                Ok(link)
            }
            Err(error) => {
                match error {
                    crate::dht::invite_registry::InviteCreationError::FanoutExceeded => {
                        self.ctx
                            .abuse_metrics
                            .invite_rejected_fanout_total
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    crate::dht::invite_registry::InviteCreationError::ChainDepthExceeded => {
                        self.ctx
                            .abuse_metrics
                            .invite_rejected_chain_depth_total
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    crate::dht::invite_registry::InviteCreationError::CooldownActive => {
                        self.ctx
                            .abuse_metrics
                            .invite_rejected_cooldown_total
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    _ => {}
                }
                Err(anyhow!("invite rejected: {error:?}"))
            }
        }
    }

    pub async fn create_invite_v2(&self, ttl_seconds: u64) -> Result<String> {
        let storage = self
            .ctx
            .storage
            .as_ref()
            .ok_or_else(|| anyhow!("durable storage is required to create a v2 invite"))?;
        let now = unix_now();
        #[cfg(debug_assertions)]
        log::debug!("PoL and trust bypasses active in debug build");
        #[cfg(not(debug_assertions))]
        if let Some(pol) = self.ctx.proof_of_live.as_ref() {
            let status = pol.status(&self.dht_local_id, now).await;
            if !status.can_issue_invite() {
                self.ctx
                    .abuse_metrics
                    .proof_of_live_invite_rejected_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Err(anyhow!("invite forbidden: {:?}", status));
            }
        }
        #[cfg(not(debug_assertions))]
        if let Some(trust_graph) = &self.ctx.trust_graph {
            match trust_graph.gate(&self.dht_local_id, now).await {
                TrustGateDecision::Allow => {}
                TrustGateDecision::Throttle { .. } | TrustGateDecision::Block { .. } => {
                    self.ctx
                        .abuse_metrics
                        .trust_gate_blocked_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Err(anyhow!("invite issuance blocked by trust gate"));
                }
            }
        }

        let issuer_id = self.dht_local_id;
        let mut registry = self.ctx.invite_registry.lock().await;
        let issuer_first_seen = registry.issuer_first_seen(&issuer_id).unwrap_or(now);
        let is_genesis = crate::dht::invite_registry::is_genesis(issuer_id.as_bytes());
        let (chain_depth, parent_token_hash) = if is_genesis {
            (0, None)
        } else {
            let proof_blob = {
                let storage_guard = storage.lock().map_err(|error| {
                    anyhow!("client storage lock poisoned while reading issuer proof: {error}")
                })?;
                hal_storage::invite_storage::read_invite_proof(
                    storage_guard.connection(),
                    &issuer_id.to_hex(),
                )?
                .ok_or_else(|| anyhow!("verified invite proof for non-genesis issuer is missing"))?
            };
            let proof: crate::dht::nested_proof::NestedProof = serde_json::from_slice(&proof_blob)
                .map_err(|error| anyhow!("failed to deserialize issuer proof: {error}"))?;
            if proof
                .hops
                .first()
                .map_or(true, |hop| hop.redeemer_node_id_hex != issuer_id.to_hex())
            {
                return Err(anyhow!("stored issuer proof does not identify its subject"));
            }
            if proof.hops.len() >= crate::dht::invite::MAX_CHAIN_DEPTH as usize {
                return Err(anyhow!("invite chain depth limit reached"));
            }
            let genesis: HashSet<String> = crate::dht::invite_registry::GENESIS_NODES
                .iter()
                .map(hex::encode)
                .collect();
            crate::dht::nested_proof::verify_nested_proof(&proof, &genesis)
                .map_err(|error| anyhow!("stored issuer proof is invalid: {error}"))?;
            let parent_token_hash = proof
                .hops
                .first()
                .map(|hop| hop.token_hash)
                .ok_or_else(|| anyhow!("verified issuer proof is empty"))?;
            (
                u32::try_from(proof.hops.len())
                    .map_err(|_| anyhow!("issuer proof depth exceeds supported range"))?,
                Some(parent_token_hash),
            )
        };
        let debug_bypass_active = cfg!(all(debug_assertions, not(test)));
        if debug_bypass_active {
            log::debug!("debug build bypasses Invite fan-out limit");
        }
        let issue_check = if debug_bypass_active {
            Ok(())
        } else {
            registry.can_issue(
                &issuer_id,
                Some(chain_depth.saturating_sub(1)),
                issuer_first_seen,
                now,
            )
        };
        if let Err(error) = issue_check {
            match error {
                crate::dht::invite_registry::InviteCreationError::FanoutExceeded => {
                    self.ctx
                        .abuse_metrics
                        .invite_rejected_fanout_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                crate::dht::invite_registry::InviteCreationError::ChainDepthExceeded => {
                    self.ctx
                        .abuse_metrics
                        .invite_rejected_chain_depth_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                crate::dht::invite_registry::InviteCreationError::CooldownActive => {
                    self.ctx
                        .abuse_metrics
                        .invite_rejected_cooldown_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                _ => {}
            }
            return Err(anyhow!("invite rejected: {error:?}"));
        }

        let mut token = [0u8; 16];
        OsRng.fill_bytes(&mut token);
        let invite = RedeemableInvite::create_with_parent(
            &self.private_key,
            token,
            now,
            ttl_seconds,
            chain_depth,
            parent_token_hash,
        )
        .map_err(|error| anyhow!("failed to create v2 invite: {error}"))?;
        invite
            .verify_with_genesis(now, |_| is_genesis)
            .map_err(|error| anyhow!("generated v2 invite has invalid chain binding: {error}"))?;
        let record = crate::dht::invite::redeemable_to_record(&invite, now)
            .map_err(|error| anyhow!("failed to map v2 invite to storage: {error}"))?;
        let link = invite
            .to_link()
            .map_err(|error| anyhow!("failed to encode v2 invite: {error}"))?;

        registry.register_legacy(&issuer_id, now);
        {
            let storage_guard = storage.lock().map_err(|error| {
                anyhow!("client storage lock poisoned while persisting invite registry: {error}")
            })?;
            registry
                .persist_first_seen(&storage_guard, issuer_id.as_bytes())
                .map_err(|error| {
                    anyhow!("failed to persist invite registry first_seen: {error}")
                })?;
        }
        storage
            .lock()
            .map_err(|error| {
                anyhow!("client storage lock poisoned while inserting invite: {error}")
            })?
            .insert_invite_atomic(&record)
            .map_err(|error| anyhow!("failed to persist v2 invite: {error}"))?;

        Ok(link)
    }

    pub async fn redeem_invite(
        &self,
        token: &[u8],
        link: &str,
    ) -> Result<hal_storage::invite_storage::RedemptionReceipt> {
        let invite = RedeemableInvite::from_link(link)
            .map_err(|error| anyhow!("parse v2 invite link: {error}"))?;
        crate::invite_redemption::request_redemption(&self.ctx, token, &invite).await
    }

    pub async fn start(
        identity_id: String,
        private_key: [u8; 32],
        device_id: String,
    ) -> Result<Self> {
        Self::start_with_policy(
            identity_id,
            private_key,
            device_id,
            None,
            NetworkScanPolicy::default(),
        )
        .await
    }

    pub async fn start_with_storage(
        identity_id: String,
        private_key: [u8; 32],
        device_id: String,
        storage: Arc<StdMutex<ClientStorage>>,
    ) -> Result<Self> {
        Self::start_with_policy(
            identity_id,
            private_key,
            device_id,
            Some(storage),
            NetworkScanPolicy::default(),
        )
        .await
    }

    pub async fn start_with_storage_and_port(
        identity_id: String,
        private_key: [u8; 32],
        device_id: String,
        storage: Arc<StdMutex<ClientStorage>>,
        port: u16,
    ) -> Result<Self> {
        Self::start_with_policy_and_port(
            identity_id,
            private_key,
            device_id,
            Some(storage),
            NetworkScanPolicy::default(),
            port,
        )
        .await
    }

    pub async fn start_with_policy(
        identity_id: String,
        private_key: [u8; 32],
        device_id: String,
        storage: Option<Arc<StdMutex<ClientStorage>>>,
        policy: NetworkScanPolicy,
    ) -> Result<Self> {
        Self::start_internal(identity_id, private_key, device_id, storage, policy).await
    }

    pub async fn start_with_policy_and_port(
        identity_id: String,
        private_key: [u8; 32],
        device_id: String,
        storage: Option<Arc<StdMutex<ClientStorage>>>,
        policy: NetworkScanPolicy,
        port: u16,
    ) -> Result<Self> {
        if port == 0 {
            return Err(anyhow!("peer runtime port must be between 1 and 65535"));
        }
        Self::start_internal_with_integrity_and_bind(
            identity_id,
            private_key,
            device_id,
            storage,
            policy,
            None,
            None,
            Arc::new(NoopBiometricGate),
            format!("0.0.0.0:{port}"),
        )
        .await
    }

    pub async fn start_with_biometric_gate(
        identity_id: String,
        private_key: [u8; 32],
        device_id: String,
        storage: Option<Arc<StdMutex<ClientStorage>>>,
        biometric_gate: Arc<dyn BiometricGate>,
    ) -> Result<Self> {
        Self::start_internal_with_integrity(
            identity_id,
            private_key,
            device_id,
            storage,
            NetworkScanPolicy::default(),
            None,
            None,
            biometric_gate,
        )
        .await
    }

    pub async fn start_with_biometric_gate_and_port(
        identity_id: String,
        private_key: [u8; 32],
        device_id: String,
        storage: Option<Arc<StdMutex<ClientStorage>>>,
        biometric_gate: Arc<dyn BiometricGate>,
        port: u16,
    ) -> Result<Self> {
        if port == 0 {
            return Err(anyhow!("peer runtime port must be between 1 and 65535"));
        }
        Self::start_internal_with_integrity_and_bind(
            identity_id,
            private_key,
            device_id,
            storage,
            NetworkScanPolicy::default(),
            None,
            None,
            biometric_gate,
            format!("0.0.0.0:{port}"),
        )
        .await
    }

    pub async fn start_with_integrity(
        identity_id: String,
        private_key: [u8; 32],
        device_id: String,
        storage: Option<Arc<StdMutex<ClientStorage>>>,
        policy: NetworkScanPolicy,
        wave: IntegrityWave,
        software_measurement: String,
    ) -> Result<Self> {
        Self::start_internal_with_integrity(
            identity_id,
            private_key,
            device_id,
            storage,
            policy,
            Some(wave),
            Some(software_measurement),
            Arc::new(NoopBiometricGate),
        )
        .await
    }

    async fn start_internal(
        identity_id: String,
        private_key: [u8; 32],
        device_id: String,
        storage: Option<Arc<StdMutex<ClientStorage>>>,
        policy: NetworkScanPolicy,
    ) -> Result<Self> {
        Self::start_internal_with_integrity_and_bind(
            identity_id,
            private_key,
            device_id,
            storage,
            policy,
            None,
            None,
            Arc::new(NoopBiometricGate),
            "0.0.0.0:0".to_string(),
        )
        .await
    }

    async fn start_internal_with_integrity(
        identity_id: String,
        private_key: [u8; 32],
        device_id: String,
        storage: Option<Arc<StdMutex<ClientStorage>>>,
        policy: NetworkScanPolicy,
        integrity: Option<IntegrityWave>,
        software_measurement: Option<String>,
        biometric_gate: Arc<dyn BiometricGate>,
    ) -> Result<Self> {
        Self::start_internal_with_integrity_and_bind(
            identity_id,
            private_key,
            device_id,
            storage,
            policy,
            integrity,
            software_measurement,
            biometric_gate,
            "0.0.0.0:0".to_string(),
        )
        .await
    }

    async fn start_internal_with_integrity_and_bind(
        identity_id: String,
        private_key: [u8; 32],
        device_id: String,
        storage: Option<Arc<StdMutex<ClientStorage>>>,
        policy: NetworkScanPolicy,
        integrity: Option<IntegrityWave>,
        software_measurement: Option<String>,
        biometric_gate: Arc<dyn BiometricGate>,
        bind_address: String,
    ) -> Result<Self> {
        let presence_policy = policy.presence.clone();
        let trust_policy = policy.trust.clone();
        let signing_key = SigningKey::from_bytes(&private_key);
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());
        let mut hash = sha2::Sha256::new();
        use sha2::Digest;
        hash.update(signing_key.verifying_key().to_bytes());
        let derived_identity = hex::encode(hash.finalize());
        if identity_id != derived_identity {
            return Err(anyhow!("identity does not match private key"));
        }

        let hosts = Arc::new(std::sync::Mutex::new(KnownHosts::new()));
        if let Some(storage) = storage.as_ref() {
            let trusted_identities = storage
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?
                .peer_registry()
                .trusted_identities()
                .map_err(|error| anyhow!("failed to load persistent trust pins: {error}"))?;
            let mut known_hosts = hosts
                .lock()
                .map_err(|_| anyhow!("known hosts mutex poisoned"))?;
            for trusted_identity in trusted_identities {
                let derived_id = pubkey_to_node_id(&trusted_identity.public_key)
                    .ok_or_else(|| {
                        anyhow!("invalid persisted key for {}", trusted_identity.identity_id)
                    })?
                    .to_hex();
                if derived_id != trusted_identity.identity_id {
                    return Err(anyhow!(
                        "persisted trust pin identity/key mismatch for {}",
                        trusted_identity.identity_id
                    ));
                }
                known_hosts
                    .pin_manual(
                        &trusted_identity.identity_id,
                        &trusted_identity.public_key,
                        trusted_identity.pinned_at,
                    )
                    .map_err(|error| {
                        anyhow!(
                            "failed to restore trust pin for {}: {error}",
                            trusted_identity.identity_id
                        )
                    })?;
            }
        }
        let scores = Arc::new(StdMutex::new(TrustScoreManager::new()));
        let (cold_contact_tracker, auto_badge_queue, abuse_metrics) =
            RuntimeContext::default_abuse_channels();
        let rate_limiter = match storage.as_ref() {
            Some(storage) => RateLimiter::with_storage_and_metrics(
                Arc::clone(storage),
                Arc::clone(&abuse_metrics),
            )?,
            None => RateLimiter::new(),
        };
        let rates = Arc::new(StdMutex::new(rate_limiter));
        let groups: Arc<dyn GroupGraph> = Arc::new(GroupRegistry::new());
        let trust_metrics = Arc::new(TrustMetrics::new());
        let oracle: Arc<dyn TrustOracle> = Arc::new(BasicTrustOracle::new(
            Arc::clone(&scores),
            Arc::clone(&rates),
            Arc::clone(&hosts),
            Arc::clone(&groups),
        ));
        let address_refresh = Arc::new(AddressRefresh::new(AddressRefreshConfig::default()));
        let hole_puncher = Arc::new(HolePuncher::with_defaults());
        let signaling_strategy = Arc::new(SignalingStrategy::default_hybrid());
        let sync = Arc::new(Mutex::new(SyncManager::new(device_id)));
        let media_signals = Arc::new(Mutex::new(Vec::new()));
        let home_state = Arc::new(Mutex::new(HomeRuntimeState::default()));
        let (polling, mut poll_requests) = PollingRuntime::start(policy);
        let poll_actions = Arc::new(Mutex::new(Vec::new()));
        let dispatch_notify = Arc::new(Notify::new());
        let actions_for_task = Arc::clone(&poll_actions);
        let notify_for_actions = Arc::clone(&dispatch_notify);
        tokio::spawn(async move {
            while let Some(request) = poll_requests.recv().await {
                actions_for_task.lock().await.push(request);
                notify_for_actions.notify_one();
            }
        });
        let peers = Arc::new(Mutex::new(Vec::<String>::new()));
        let dht_local_id = NodeId::from_public_key(&signing_key.verifying_key());
        let dht_routing = Arc::new(Mutex::new(RoutingTable::new(dht_local_id)));
        let dht_cache = Arc::new(Mutex::new(EndpointCache::new(1000)));
        let prekey_cache = RuntimeContext::default_prekey_cache();
        let (badge_store, badge_metrics) = RuntimeContext::default_badge_components();
        let local_prekey_store =
            RuntimeContext::default_local_prekey_store(storage.clone(), Arc::clone(&abuse_metrics));
        let invite_registry = RuntimeContext::default_invite_registry();
        if let Some(storage) = storage.as_ref() {
            let mut registry = invite_registry.lock().await;
            let storage = storage
                .lock()
                .map_err(|error| anyhow!("client storage lock poisoned: {error}"))?;
            registry.load_from_storage(&storage)?;
        }
        let trust_graph = Arc::new(TrustGraph::new(
            Arc::clone(&hosts),
            Arc::clone(&invite_registry),
            Arc::clone(&badge_store),
            Arc::clone(&oracle),
            Arc::clone(&scores),
            Arc::clone(&rates),
            Arc::clone(&abuse_metrics),
        ));
        let stigma_cache = RuntimeContext::default_stigma_cache();
        let dht_handler = Arc::new(
            DhtRequestHandler::new(
                dht_local_id,
                Arc::clone(&dht_routing),
                Arc::clone(&dht_cache),
                public_key.clone(),
            )
            .with_badge_store(Arc::clone(&badge_store))
            .with_prekey_cache(Arc::clone(&prekey_cache), Arc::clone(&abuse_metrics))
            .with_trust_graph(Arc::clone(&trust_graph))
            .with_abuse_metrics(Arc::clone(&abuse_metrics)),
        );
        let dht_metrics = Arc::new(crate::dht::DhtMetrics::new());
        let dht_config = Arc::new(Mutex::new(DhtPollerConfig::default()));
        let dht_priority = Arc::new(Mutex::new(PriorityRegistry::new()));
        let dht_activity_state = Arc::new(Mutex::new(ActivityController::default()));
        let (dht_stream_tx, dht_stream_rx) =
            mpsc::channel(crate::dht::mux_transport::DHT_CHANNEL_CAPACITY);
        let dht_worker_task = tokio::spawn(dht_worker_loop(
            dht_stream_rx,
            Arc::clone(&dht_handler),
            Arc::clone(&dht_metrics),
            Arc::clone(&dht_config),
        ));
        let (inbound_obs_tx, inbound_obs_rx) =
            mpsc::channel::<InboundObservation>(INBOUND_OBSERVATION_QUEUE_CAPACITY);
        let degradation = RuntimeContext::default_degradation();
        let (transport, incoming) = PeerTransport::bind_secure_on_demand_with_stigma_cache(
            &bind_address,
            signing_key.clone(),
            Arc::clone(&hosts),
            trust_policy.clone(),
            crate::TransportKind::TlsMux,
            Some(dht_stream_tx.clone()),
            Some(Arc::clone(&dht_metrics)),
            Some(inbound_obs_tx.clone()),
            Some(Arc::clone(&abuse_metrics)),
            Some(Arc::clone(&stigma_cache)),
            Some(Arc::clone(&degradation)),
        )
        .await
        .map_err(|error| anyhow!("failed to bind peer runtime on {bind_address}: {error}"))?;
        let (quic_listener_endpoint, public_quic_address) =
            bind_runtime_quic_endpoint(&signing_key).await;
        let public_quic_endpoint = Arc::new(std::sync::RwLock::new(public_quic_address));
        let transport_address = advertised_transport_address(&transport.local_address);
        let (relay_tx_slot, relay_tracker, relay_metrics) =
            RuntimeContext::default_relay_channels();
        let session_store = match storage.clone() {
            Some(storage) => {
                RuntimeContext::session_store_with_storage(storage, Arc::clone(&abuse_metrics))
            }
            None => RuntimeContext::session_store_with_metrics(Arc::clone(&abuse_metrics)),
        };
        let peer_directory = RuntimeContext::default_peer_directory();
        if let Some(storage) = storage.as_ref() {
            let stored_peers = storage
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?
                .peer_registry()
                .active_peers(unix_now(), crate::peer_directory::DEFAULT_MAX_ENTRIES)
                .map_err(|error| anyhow!("failed to load persisted peer addresses: {error}"))?;
            let mut directory = peer_directory.lock().await;
            for peer in stored_peers {
                if let Err(error) = directory.record_outbound(
                    peer.transport_address,
                    peer.identity_id,
                    peer.public_key,
                    unix_now(),
                ) {
                    log::warn!("ignored invalid persisted peer address: {error:?}");
                }
            }
        }
        let jury_commitment_publisher = storage.as_ref().map(|storage| {
            Arc::new(
                crate::jury_commitment_publisher::JuryCommitmentPublisher::new(
                    Arc::clone(storage),
                    dht_publish_transport(
                        dht_local_id,
                        signing_key.clone(),
                        Arc::clone(&dht_routing),
                        Arc::clone(&hosts),
                        trust_policy.clone(),
                    ),
                ),
            )
        });
        let invite_redemption_transport = Some(
            crate::invite_redemption::DirectInviteRedemptionTransport::new(
                signing_key.clone(),
                Arc::clone(&hosts),
                Arc::clone(&dht_routing),
                trust_policy.clone(),
                Arc::clone(&abuse_metrics),
            ),
        );
        let age_tracker = RuntimeContext::default_age_tracker(storage.clone());
        let activity_tracker = RuntimeContext::default_activity_tracker(storage.clone());
        let proof_of_live =
            RuntimeContext::default_proof_of_live(age_tracker.clone(), activity_tracker.clone());
        if let Some(age_tracker) = age_tracker.as_ref() {
            age_tracker.lock().await.observe(dht_local_id, unix_now())?;
        }
        let ctx = Arc::new(RuntimeContext {
            sync: Arc::clone(&sync),
            home_state: Arc::clone(&home_state),
            media_signals: Arc::clone(&media_signals),
            storage: storage.clone(),
            age_tracker,
            activity_tracker,
            proof_of_live,
            hosts: Arc::clone(&hosts),
            scores: Arc::clone(&scores),
            rates: Arc::clone(&rates),
            trust_graph: Some(Arc::clone(&trust_graph)),
            groups: Arc::clone(&groups),
            trust_metrics: Arc::clone(&trust_metrics),
            oracle: Arc::clone(&oracle),
            address_refresh: Arc::clone(&address_refresh),
            hole_puncher: Arc::clone(&hole_puncher),
            signaling_strategy: Arc::clone(&signaling_strategy),
            relay_tx: Arc::clone(&relay_tx_slot),
            relay_tracker,
            relay_metrics,
            relay_nonce_cache: RuntimeContext::default_relay_nonce_cache(),
            peer_directory,
            observable: RuntimeContext::default_observable(),
            prekey_cache,
            local_prekey_store,
            session_store,
            biometric_gate,
            invite_registry,
            degradation: Arc::clone(&degradation),
            stigma_cache: Arc::clone(&stigma_cache),
            inbound_observations_tx: RuntimeContext::default_inbound_observations(),
            badge_store: Arc::clone(&badge_store),
            badge_metrics: Arc::clone(&badge_metrics),
            badge_fetch_shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cold_contact_tracker,
            auto_badge_queue,
            abuse_metrics,
            identity_id: identity_id.clone(),
            public_key: public_key.clone(),
            identity_signing_key: Some(Arc::new(signing_key.clone())),
            jury_commitment_publisher,
            jury_plaintext_cache: RuntimeContext::default_jury_plaintext_cache(),
            invite_redemption_transport,
            pending_invite_redemptions: RuntimeContext::default_pending_invite_redemptions(),
            sas_pairing: RuntimeContext::default_sas_pairing(),
            integrity: integrity.clone(),
        });
        let (lan_discovery, lan_discovery_task, lan_discovery_shutdown) = match transport
            .local_address
            .rsplit_once(':')
            .and_then(|(_, port)| {
                port.parse::<u16>()
                    .ok()
                    .filter(|port| *port == crate::lan_discovery::TCP_PEER_PORT)
            }) {
            Some(port) => match crate::lan_discovery::LanDiscovery::bind(
                identity_id.clone(),
                &public_key,
                signing_key.clone(),
                Arc::clone(&ctx.home_state),
                port,
                Arc::clone(&ctx.peer_directory),
                storage.clone(),
            )
            .await
            {
                Ok(discovery) => {
                    let (shutdown, receiver) = oneshot::channel();
                    let task = tokio::spawn(discovery.clone().run(receiver));
                    (Some(discovery), Some(task), Some(shutdown))
                }
                Err(error) => {
                    log::warn!("lan_discovery: unable to start UDP listener: {error:#}");
                    (None, None, None)
                }
            },
            None => (None, None, None),
        };
        *ctx.inbound_observations_tx.lock().await = Some(inbound_obs_tx.clone());
        let relay_service = Arc::new(RelayService::new(
            Arc::clone(&ctx),
            signing_key.clone(),
            identity_id.clone(),
            public_key.clone(),
            dht_local_id,
            Arc::clone(&dht_routing),
            Arc::clone(&dht_cache),
            Arc::clone(&hosts),
            trust_policy.clone(),
        ));
        let (relay_tx, relay_rx) = mpsc::channel::<RelayWork>(RELAY_QUEUE_CAPACITY);
        *relay_tx_slot.lock().await = Some(relay_tx);
        let (relay_shutdown, relay_shutdown_rx) = oneshot::channel();
        let relay_task = tokio::spawn(
            RelayWorkerTask::new(Arc::clone(&relay_service)).run(relay_rx, relay_shutdown_rx),
        );
        let (incoming_shutdown, incoming_task) =
            Self::spawn_incoming_task(incoming, Arc::clone(&ctx));
        let (quic_incoming_shutdown, quic_incoming_task) = if transport.has_quic() {
            match (transport.quic_channel(), transport.incoming_tx()) {
                (Some(channel), Some(sender)) => {
                    let (shutdown, task) = Self::spawn_quic_incoming_task(
                        channel,
                        sender,
                        Arc::clone(&ctx.hosts),
                        Arc::clone(&ctx.abuse_metrics),
                    );
                    (Some(shutdown), Some(task))
                }
                _ => (None, None),
            }
        } else {
            (None, None)
        };
        let (quic_listener_shutdown, quic_listener_task) =
            match (quic_listener_endpoint.as_ref(), transport.incoming_tx()) {
                (Some(endpoint), Some(sender)) => {
                    let (shutdown, task) = Self::spawn_quic_endpoint_listener(
                        Arc::clone(endpoint),
                        signing_key.clone(),
                        sender,
                        Arc::clone(&ctx.hosts),
                        Arc::clone(&ctx.abuse_metrics),
                    );
                    (Some(shutdown), Some(task))
                }
                _ => (None, None),
            };
        let transport_addresses = advertised_transport_addresses(&transport.local_address);
        let public_tcp_port = transport
            .local_address
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .filter(|port| *port != 0);
        let public_endpoint = Arc::new(std::sync::RwLock::new(None));
        let (refresh_shutdown, refresh_task) = {
            let task = AddressRefreshTask::new(
                Arc::clone(&ctx.address_refresh),
                identity_id.clone(),
                public_key.clone(),
                signing_key.clone(),
                dht_local_id,
                ctx.proof_of_live.clone(),
                Arc::clone(&dht_routing),
                Arc::clone(&dht_cache),
                Arc::clone(&hosts),
                trust_policy.clone(),
                transport_addresses,
            )
            .with_public_endpoint_state(Arc::clone(&public_endpoint))
            .with_public_udp_endpoint(Arc::clone(&public_quic_endpoint));
            let task = match public_tcp_port {
                Some(port) => task.with_public_tcp_port(port),
                None => task,
            };
            let task =
                task.with_trust_graph(Arc::clone(&trust_graph), Arc::clone(&ctx.abuse_metrics));
            let (shutdown, receiver) = oneshot::channel();
            (shutdown, tokio::spawn(task.run(receiver)))
        };
        let (punch_fetch_shutdown, punch_fetch_task) = {
            let task = PunchFetchTask::new(
                Arc::clone(&ctx),
                PunchFetchConfig::default(),
                signing_key.clone(),
                dht_local_id,
                Arc::clone(&dht_routing),
                Arc::clone(&dht_cache),
                Arc::clone(&hosts),
                trust_policy.clone(),
            );
            let (shutdown, receiver) = oneshot::channel();
            (shutdown, tokio::spawn(task.run(receiver)))
        };
        let (badge_fetch_shutdown, badge_fetch_shutdown_rx) = oneshot::channel();
        let badge_fetch_task = tokio::spawn(
            BadgeFetchTask::new(
                Arc::clone(&ctx),
                BadgeFetchConfig::default(),
                signing_key.clone(),
                dht_local_id,
                Arc::clone(&dht_routing),
                Arc::clone(&dht_cache),
                trust_policy.clone(),
            )
            .run(badge_fetch_shutdown_rx),
        );
        let (retention_prune_shutdown, retention_prune_task) = if ctx.activity_tracker.is_some() {
            let (shutdown, shutdown_rx) = oneshot::channel();
            let task = tokio::spawn(
                RetentionPruneTask::new(
                    Arc::clone(
                        ctx.activity_tracker
                            .as_ref()
                            .expect("activity tracker configured"),
                    ),
                    Arc::clone(&ctx),
                )
                .run(shutdown_rx),
            );
            (Some(shutdown), Some(task))
        } else {
            (None, None)
        };
        let (auto_badge_shutdown, auto_badge_shutdown_rx) = oneshot::channel();
        let auto_badge_task = tokio::spawn(
            AutoBadgeWorker::new(
                Arc::clone(&ctx),
                signing_key.clone(),
                identity_id.clone(),
                public_key.clone(),
                dht_local_id,
                Arc::clone(&dht_routing),
                Arc::clone(&dht_cache),
                Arc::clone(&hosts),
                trust_policy.clone(),
            )
            .run(auto_badge_shutdown_rx),
        );
        let peer_address_state = Arc::new(Mutex::new(PeerAddressState::default()));
        let (inbound_obs_shutdown, inbound_obs_shutdown_rx) = oneshot::channel();
        let inbound_obs_task = tokio::spawn(
            InboundObserverTask::with_observable(
                Arc::clone(&ctx.peer_directory),
                Arc::clone(&ctx.observable),
            )
            .with_peer_address_state(Arc::clone(&peer_address_state))
            .run(inbound_obs_rx, inbound_obs_shutdown_rx),
        );
        let (stigma_refresh_shutdown, stigma_refresh_rx) = oneshot::channel();
        let stigma_refresh_task = tokio::spawn(
            StigmaRefreshTask::default_config(Arc::clone(&ctx)).run(stigma_refresh_rx),
        );
        let (prekey_rotation_shutdown, prekey_rotation_task) =
            if let Some(local_prekey_store) = ctx.local_prekey_store.as_ref() {
                let task = PrekeyRotationTask::new(
                    Arc::clone(local_prekey_store),
                    Arc::clone(&ctx.abuse_metrics),
                    signing_key.clone(),
                    dht_local_id,
                    Arc::clone(&dht_routing),
                    Arc::clone(&hosts),
                    trust_policy.clone(),
                    Arc::clone(&ctx.prekey_cache),
                );
                let (shutdown, receiver) = oneshot::channel();
                (Some(shutdown), Some(tokio::spawn(task.run(receiver))))
            } else {
                (None, None)
            };
        let (journal_commit_shutdown, journal_commit_task) =
            if let Some(storage) = ctx.storage.as_ref() {
                let publisher = Arc::new(JournalCommitPublisher::new(
                    Arc::clone(storage),
                    signing_key.clone(),
                    dht_publish_transport(
                        dht_local_id,
                        signing_key.clone(),
                        Arc::clone(&dht_routing),
                        Arc::clone(&hosts),
                        trust_policy.clone(),
                    ),
                ));
                let (shutdown, receiver) = oneshot::channel();
                (Some(shutdown), Some(tokio::spawn(publisher.run(receiver))))
            } else {
                (None, None)
            };
        let (jury_assembly_shutdown, jury_assembly_task) = if ctx.storage.is_some() {
            let (shutdown, receiver) = oneshot::channel();
            let task = Arc::new(crate::jury_assembly::JuryAssemblyTask::new(Arc::clone(
                &ctx,
            )));
            (Some(shutdown), Some(tokio::spawn(task.run(receiver))))
        } else {
            (None, None)
        };
        let (jury_outbox_shutdown, jury_outbox_task) = if ctx.storage.is_some() {
            let task = Arc::new(JuryOutboxTask::new(
                Arc::clone(&ctx),
                signing_key.clone(),
                dht_local_id,
                Arc::clone(&hosts),
                Arc::clone(&dht_routing),
                Arc::clone(&dht_cache),
                trust_policy.clone(),
            ));
            let (shutdown, receiver) = oneshot::channel();
            (
                Some(shutdown),
                Some(tokio::spawn(JuryOutboxTask::run(task, receiver))),
            )
        } else {
            (None, None)
        };
        let (complainant_orchestrator_shutdown, complainant_orchestrator_task) =
            if ctx.storage.is_some() {
                let verdicts: Arc<dyn crate::arbitrator_pool::JuryVerdictProvider> =
                    Arc::new(crate::arbitrator_pool::NoVerdictsProvider);
                let task = Arc::new(ComplainantOrchestratorTask::new(
                    Arc::clone(&ctx),
                    signing_key.clone(),
                    verdicts,
                ));
                let (shutdown, receiver) = oneshot::channel();
                (Some(shutdown), Some(tokio::spawn(task.run(receiver))))
            } else {
                (None, None)
            };
        let (juror_orchestrator_shutdown, juror_orchestrator_task) = if ctx.storage.is_some() {
            let task = JurorOrchestratorTask::new(
                Arc::clone(&ctx),
                signing_key.clone(),
                dht_local_id,
                Arc::clone(&hosts),
                Arc::clone(&dht_routing),
                trust_policy.clone(),
            );
            let (shutdown, receiver) = oneshot::channel();
            (Some(shutdown), Some(tokio::spawn(task.run(receiver))))
        } else {
            (None, None)
        };

        let cover_state = Arc::new(Mutex::new(CoverTrafficState::Idle));
        let last_message_time = Arc::new(Mutex::new(Instant::now()));
        let cover_identity = identity_id.clone();
        let cover_public_key = public_key.clone();
        let cover_transport_address = transport_address.clone();
        let cover_private_key = signing_key.clone();
        let cover_hosts = Arc::clone(&hosts);
        let cover_trust_policy = trust_policy.clone();
        let (cover_traffic_shutdown, cover_traffic_task) = if cfg!(target_os = "android")
            || std::env::var("HAL_COVER_TRAFFIC_ENABLED")
                .map(|value| {
                    matches!(
                        value.trim().to_ascii_lowercase().as_str(),
                        "1" | "true" | "yes" | "on"
                    )
                })
                .unwrap_or(false)
        {
            let (shutdown, mut shutdown_rx) = oneshot::channel();
            let state = Arc::clone(&cover_state);
            let last = Arc::clone(&last_message_time);
            let transport_address = cover_transport_address.clone();
            let private_key = cover_private_key.clone();
            let hosts = Arc::clone(&cover_hosts);
            let trust_policy = cover_trust_policy.clone();
            (
                Some(shutdown),
                Some(tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = &mut shutdown_rx => break,
                            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
                        }
                        let now = Instant::now();
                        let last_message_time = *last.lock().await;
                        let current_state = CoverTrafficState::evaluate(
                            last_message_time,
                            false,
                            false,
                            false,
                            now,
                        );
                        let cover_state = *state.lock().await;
                        let effective_state = if cover_state == CoverTrafficState::Idle {
                            current_state
                        } else {
                            cover_state
                        };
                        match effective_state {
                            CoverTrafficState::Idle => continue,
                            CoverTrafficState::Burst => {
                                let envelope = SyncEnvelope::new_cover(
                                    cover_identity.clone(),
                                    cover_public_key.clone(),
                                );
                                log::info!(target: "HAL_DHT", "CoverTraffic: generated Burst packet");
                                if let Err(error) = crate::transport::send_envelope_secure(
                                    &transport_address,
                                    &envelope,
                                    &private_key,
                                    Arc::clone(&hosts),
                                    trust_policy.clone(),
                                )
                                .await
                                {
                                    log::warn!(target: "HAL_DHT", "CoverTraffic: failed to send Burst packet: {error}");
                                }
                            }
                            CoverTrafficState::Chaos => {
                                let envelope = SyncEnvelope::new_cover(
                                    cover_identity.clone(),
                                    cover_public_key.clone(),
                                );
                                log::info!(target: "HAL_DHT", "CoverTraffic: generated Chaos packet");
                                if let Err(error) = crate::transport::send_envelope_secure(
                                    &transport_address,
                                    &envelope,
                                    &private_key,
                                    Arc::clone(&hosts),
                                    trust_policy.clone(),
                                )
                                .await
                                {
                                    log::warn!(target: "HAL_DHT", "CoverTraffic: failed to send Chaos packet: {error}");
                                }
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                })),
            )
        } else {
            (None, None)
        };
        let mut runtime = Self {
            identity_id,
            public_key,
            transport_address,
            private_key: signing_key,
            transport,
            incoming_task: Some(incoming_task),
            incoming_shutdown: Some(incoming_shutdown),
            quic_incoming_task,
            quic_incoming_shutdown,
            quic_listener_endpoint: Arc::new(tokio::sync::RwLock::new(quic_listener_endpoint)),
            quic_listener_task: tokio::sync::Mutex::new(quic_listener_task),
            quic_listener_shutdown: tokio::sync::Mutex::new(quic_listener_shutdown),
            quic_punch_task: None,
            quic_punch_shutdown: None,
            relay_task: Some(relay_task),
            relay_shutdown: Some(relay_shutdown),
            relay_service: Some(relay_service),
            refresh_task: Some(refresh_task),
            refresh_shutdown: Some(refresh_shutdown),
            endpoint_heartbeat_task: None,
            endpoint_heartbeat_shutdown: None,
            punch_fetch_task: Some(punch_fetch_task),
            punch_fetch_shutdown: Some(punch_fetch_shutdown),
            badge_fetch_task: Some(badge_fetch_task),
            badge_fetch_shutdown: Some(badge_fetch_shutdown),
            prekey_rotation_task,
            prekey_rotation_shutdown,
            journal_commit_task,
            journal_commit_shutdown,
            jury_assembly_task,
            jury_assembly_shutdown,
            jury_outbox_task,
            jury_outbox_shutdown,
            complainant_orchestrator_task,
            complainant_orchestrator_shutdown,
            juror_orchestrator_task,
            juror_orchestrator_shutdown,
            retention_prune_task,
            retention_prune_shutdown,
            auto_badge_task: Some(auto_badge_task),
            auto_badge_shutdown: Some(auto_badge_shutdown),
            inbound_obs_task: Some(inbound_obs_task),
            inbound_obs_shutdown: Some(inbound_obs_shutdown),
            stigma_refresh_task: Some(stigma_refresh_task),
            stigma_refresh_shutdown: Some(stigma_refresh_shutdown),
            polling: Some(polling),
            poll_actions,
            peers,
            dispatcher_task: None,
            dispatcher_shutdown: None,
            discovery: None,
            discovery_task: None,
            discovery_shutdown: None,
            lan_discovery,
            lan_discovery_task,
            lan_discovery_shutdown,
            public_endpoint,
            public_quic_endpoint,
            software_measurement,
            ctx,
            presence_policy,
            trust_policy,
            relay_mode_enabled: Arc::new(AtomicBool::new(false)),
            force_wss_relay: AtomicBool::new(
                std::env::var("HAL_FORCE_WSS_RELAY")
                    .is_ok_and(|value| value.eq_ignore_ascii_case("true")),
            ),
            activity: Arc::new(Mutex::new(ActivityController::default())),
            dispatch_notify,
            dht_local_id,
            dht_routing,
            dht_cache,
            dht_handler,
            dht_metrics,
            dht_config,
            dht_priority,
            dht_activity_state,
            dht_stream_tx: Some(dht_stream_tx),
            dht_worker_task: Some(dht_worker_task),
            active_sessions: Mutex::new(HashMap::new()),
            wss_sessions: Mutex::new(HashMap::new()),
            wss_url: Arc::new(Mutex::new(
                std::env::var("HAL_WSS_URL")
                    .ok()
                    .filter(|url| !url.trim().is_empty()),
            )),
            recent_send_failures: Mutex::new(HashMap::new()),
            peer_address_state,
            cover_state,
            last_message_time,
            cover_traffic_task,
            cover_traffic_shutdown,
            home_sync_task: None,
            home_sync_shutdown: None,
        };
        runtime.start_quic_punch_rendezvous();
        runtime.start_home_sync_worker();
        let public_dht_port = runtime
            .transport
            .local_address
            .parse::<std::net::SocketAddr>()
            .map(|address| address.port())
            .unwrap_or(Self::DEFAULT_PEER_PORT);
        let public_dht_node_id = runtime.dht_local_id;
        tokio::spawn(async move {
            loop {
                if let Err(error) =
                    crate::dht::bootstrap::announce_public_hal_node(public_dht_port).await
                {
                    log::warn!("DHT Bootstrap: public announce failed: {error:#}");
                }
                if let Err(error) = crate::dht::endpoint_lookup::announce_public_tcp_endpoint(
                    &public_dht_node_id,
                    public_dht_port,
                )
                .await
                {
                    log::warn!("DHT Bootstrap: public TCP endpoint announce failed: {error:#}");
                }
                let peers = crate::dht::bootstrap::discover_public_hal_peers().await;
                let now = unix_now();
                if !peers.is_empty() {
                    let mut nodes = crate::dht::bootstrap::load_bootstrap_nodes();
                    for peer in peers {
                        let address = peer.to_string();
                        if !nodes.iter().any(|node| node.address == address) {
                            nodes.push(crate::dht::BootstrapNode::new(address, now));
                        }
                    }
                    if let Err(error) = crate::dht::bootstrap::save_bootstrap_nodes(&nodes) {
                        log::warn!("DHT Bootstrap: failed to cache public peers: {error}");
                    }
                }
                tokio::time::sleep(Duration::from_secs(5 * 60)).await;
            }
        });
        let resolver = crate::dht::DnsSeedResolver::with_defaults();
        let bootstrap_result =
            crate::dht::BootstrapConfig::from_dns_resolver(&resolver, Vec::new()).await;
        match bootstrap_result {
            Ok(config) => {
                log::info!(
                    "DHT bootstrap resolved {} DNS seed endpoint(s)",
                    config.dns_addresses.len()
                );
                match runtime.dht_bootstrap(config.clone(), unix_now()).await {
                    Ok(report) => {
                        log::info!(
                            target: "HAL_DHT",
                            "DHT bootstrap complete: seeds={}, responded={}, peers_discovered={}, inserted={}",
                            report.seeds_contacted,
                            report.seeds_responded,
                            report.peers_discovered,
                            report.peers_inserted
                        );
                        for (node_id, error) in &report.failures {
                            log::warn!(
                                target: "HAL_DHT",
                                "DHT bootstrap peer {} failed: {error}",
                                node_id.to_hex()
                            );
                        }
                        if report.seeds_responded == 0 && report.failures.is_empty() {
                            log::warn!(
                                target: "HAL_DHT",
                                "DHT bootstrap returned no seed responses and no peer-level failure details"
                            );
                        }
                        if report.seeds_responded > 0 {
                            let now = unix_now();
                            let mut verified = Vec::new();
                            for seed in config.static_addresses.iter().take(5) {
                                let mut nodes = crate::dht::bootstrap::load_bootstrap_nodes();
                                let address = seed.address.to_string();
                                match nodes.iter_mut().find(|node| node.address == address) {
                                    Some(node) => {
                                        node.score = node.score.saturating_add(10);
                                        node.last_seen = now;
                                    }
                                    None => nodes
                                        .push(crate::dht::BootstrapNode::new(address.clone(), now)),
                                }
                                verified.push(address);
                                let _ = crate::dht::bootstrap::save_bootstrap_nodes(&nodes);
                            }
                            for address in verified {
                                log::info!(
                                    target: "HAL_DHT",
                                    "DHT Bootstrap: verified {address}, score=10"
                                );
                            }
                        }
                    }
                    Err(error) => log::warn!("DHT bootstrap failed: {error:#}"),
                }
            }
            Err(error) => log::warn!("DHT bootstrap DNS resolution failed: {error}"),
        }
        if let Err(error) = runtime.publish_endpoints(unix_now()).await {
            log::warn!("initial endpoint publication failed: {error:#}");
        }
        #[cfg(not(test))]
        runtime.start_public_endpoint_heartbeat();
        Ok(runtime)
    }

    pub fn presence_policy(&self) -> &PresencePolicy {
        &self.presence_policy
    }

    pub fn runtime_context(&self) -> Arc<RuntimeContext> {
        Arc::clone(&self.ctx)
    }

    fn start_home_sync_worker(&mut self) {
        let context = Arc::clone(&self.ctx);
        let identity_id = self.identity_id.clone();
        let public_key = self.public_key.clone();
        let private_key = self.private_key.clone();
        let hosts = Arc::clone(&self.ctx.hosts);
        let trust_policy = self.trust_policy.clone();
        let (shutdown, shutdown_rx) = oneshot::channel();
        self.home_sync_shutdown = Some(shutdown);
        self.home_sync_task = Some(tokio::spawn(home_sync_worker_loop(
            context,
            identity_id,
            public_key,
            private_key,
            hosts,
            trust_policy,
            shutdown_rx,
        )));
    }

    #[cfg(not(test))]
    fn start_public_endpoint_heartbeat(&mut self) {
        let identity_id = self.identity_id.clone();
        let public_key = self.public_key.clone();
        let signing_key = self.private_key.clone();
        let storage = self.ctx.storage.clone();
        let relay_mode_enabled = Arc::clone(&self.relay_mode_enabled);
        let wss_url = Arc::clone(&self.wss_url);
        let (shutdown, mut shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let interval = PUBLIC_ENDPOINT_HEARTBEAT_INTERVAL;
            let mut ticker =
                tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    _ = ticker.tick() => {}
                }

                let display_name = match read_profile_display_name(storage.as_ref()) {
                    Ok(display_name) => display_name,
                    Err(error) => {
                        log::warn!(target: "HAL_DHT", "profile heartbeat could not read local nickname: {error:#}");
                        continue;
                    }
                };
                let relay_mode = relay_mode_enabled.load(Ordering::Relaxed);
                if display_name.is_none() && !relay_mode {
                    continue;
                }
                let wss_url = wss_url
                    .lock()
                    .await
                    .clone()
                    .or_else(|| std::env::var("HAL_WSS_URL").ok())
                    .map(|url| url.trim().to_owned())
                    .filter(|url| !url.is_empty());

                match publish_public_profile_record(
                    &identity_id,
                    &public_key,
                    &signing_key,
                    display_name,
                    relay_mode,
                    wss_url,
                    unix_now(),
                )
                .await
                {
                    Ok(()) => {
                        log::info!(target: "HAL_DHT", "public EndpointRecord heartbeat published")
                    }
                    Err(error) => {
                        log::warn!(target: "HAL_DHT", "public EndpointRecord heartbeat failed: {error:#}")
                    }
                }
            }
        });
        self.endpoint_heartbeat_shutdown = Some(shutdown);
        self.endpoint_heartbeat_task = Some(task);
    }

    pub async fn broadcast_lan_address(&self) -> Result<usize> {
        let discovery = self
            .lan_discovery
            .as_ref()
            .ok_or_else(|| anyhow!("LAN discovery is not active"))?;
        discovery.broadcast_my_address().await
    }

    pub async fn discovered_lan_peers(&self) -> Vec<crate::lan_discovery::DiscoveredLanPeer> {
        match self.lan_discovery.as_ref() {
            Some(discovery) => discovery.discovered_peers().await,
            None => Vec::new(),
        }
    }

    pub async fn refresh_quic_endpoint(&self) -> Result<Option<SocketAddr>> {
        if let Some(shutdown) = self.quic_listener_shutdown.lock().await.take() {
            let _ = shutdown.send(());
        }
        if let Some(endpoint) = self.quic_listener_endpoint.write().await.take() {
            endpoint.close(0u32.into(), b"network changed");
        }
        if let Some(task) = self.quic_listener_task.lock().await.take() {
            match tokio::time::timeout(Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("old QUIC listener stopped with error: {error}"),
                Err(_) => {
                    log::warn!("old QUIC listener did not stop within 5 seconds");
                }
            }
        }

        let (endpoint, public_address) = bind_runtime_quic_endpoint(&self.private_key).await;
        let endpoint = endpoint.ok_or_else(|| anyhow!("unable to restart QUIC UDP listener"))?;
        let sender = self
            .transport
            .incoming_tx()
            .ok_or_else(|| anyhow!("peer transport has no incoming channel"))?;
        let (shutdown, task) = Self::spawn_quic_endpoint_listener(
            Arc::clone(&endpoint),
            self.private_key.clone(),
            sender,
            Arc::clone(&self.ctx.hosts),
            Arc::clone(&self.ctx.abuse_metrics),
        );
        *self.quic_listener_endpoint.write().await = Some(endpoint);
        *self.quic_listener_shutdown.lock().await = Some(shutdown);
        *self.quic_listener_task.lock().await = Some(task);
        *self
            .public_quic_endpoint
            .write()
            .map_err(|error| anyhow!("public QUIC endpoint state lock poisoned: {error}"))? =
            public_address;

        self.publish_endpoints(unix_now()).await?;
        Ok(public_address)
    }

    pub fn relay_service(&self) -> Option<Arc<RelayService>> {
        self.relay_service.as_ref().map(Arc::clone)
    }

    pub async fn request_activity(&self, trigger: ActivityTrigger, now: u64) -> ActivityPlan {
        let mut activity = self.activity.lock().await;
        activity.tick(now);
        activity.request(trigger, now);
        activity.plan()
    }

    pub async fn activity_plan(&self, now: u64) -> ActivityPlan {
        let mut activity = self.activity.lock().await;
        activity.tick(now);
        activity.plan()
    }

    pub async fn activity_mode(&self, now: u64) -> ActivityMode {
        self.activity_plan(now).await.mode
    }

    pub async fn release_activity(&self) {
        self.activity.lock().await.release();
    }

    pub async fn set_dht_config(&self, config: DhtPollerConfig) -> Result<()> {
        config.validate().map_err(anyhow::Error::msg)?;
        *self.dht_config.lock().await = config;
        Ok(())
    }

    pub async fn dht_config(&self) -> DhtPollerConfig {
        self.dht_config.lock().await.clone()
    }

    pub async fn set_contact_priority(&self, contact_id: &str, level: PriorityLevel) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.dht_priority
            .lock()
            .await
            .set_manual(contact_id, level, now);
        Ok(())
    }

    pub async fn clear_contact_priority(&self, contact_id: &str) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.dht_priority.lock().await.clear_manual(contact_id, now);
        Ok(())
    }

    pub async fn contact_priority(&self, contact_id: &str) -> PriorityLevel {
        self.dht_priority.lock().await.level_of(contact_id)
    }

    pub async fn refresh_auto_priorities(&self, now: u64) {
        self.dht_priority.lock().await.recompute_auto(now);
    }

    pub fn availability_state(&self, last_seen: Option<u64>, now: u64) -> AvailabilityState {
        self.presence_policy.state_at(last_seen, now)
    }

    pub async fn activate_listener(
        &mut self,
        storage: Option<Arc<StdMutex<ClientStorage>>>,
        integrity: Option<IntegrityWave>,
    ) -> Result<()> {
        if self.incoming_task.is_some() {
            return Ok(());
        }
        let inbound_obs_tx = self.ctx.inbound_observations_tx.lock().await.clone();
        let storage = storage.or_else(|| self.ctx.storage.clone());
        let current_port = self
            .transport
            .local_address
            .parse::<SocketAddr>()
            .map_err(|error| anyhow!("invalid existing peer bind address: {error}"))?
            .port();
        let bind_address = format!("0.0.0.0:{current_port}");
        let age_tracker = self
            .ctx
            .age_tracker
            .clone()
            .or_else(|| RuntimeContext::default_age_tracker(storage.clone()));
        let activity_tracker = self
            .ctx
            .activity_tracker
            .clone()
            .or_else(|| RuntimeContext::default_activity_tracker(storage.clone()));
        let local_prekey_store = self.ctx.local_prekey_store.clone().or_else(|| {
            RuntimeContext::default_local_prekey_store(
                storage.clone(),
                Arc::clone(&self.ctx.abuse_metrics),
            )
        });
        let (transport, incoming) = PeerTransport::bind_secure_on_demand_with_stigma_cache(
            &bind_address,
            self.private_key.clone(),
            Arc::clone(&self.ctx.hosts),
            self.trust_policy.clone(),
            crate::TransportKind::TlsMux,
            self.dht_stream_tx.clone(),
            Some(Arc::clone(&self.dht_metrics)),
            inbound_obs_tx,
            Some(Arc::clone(&self.ctx.abuse_metrics)),
            Some(Arc::clone(&self.ctx.stigma_cache)),
            Some(Arc::clone(&self.ctx.degradation)),
        )
        .await
        .map_err(|error| anyhow!("failed to rebind peer runtime on {bind_address}: {error}"))?;
        self.transport = transport;
        self.transport_address = advertised_transport_address(&self.transport.local_address);
        let ctx = Arc::new(RuntimeContext {
            sync: Arc::clone(&self.ctx.sync),
            home_state: Arc::clone(&self.ctx.home_state),
            media_signals: Arc::clone(&self.ctx.media_signals),
            storage,
            age_tracker: age_tracker.clone(),
            activity_tracker: activity_tracker.clone(),
            proof_of_live: RuntimeContext::default_proof_of_live(
                age_tracker.clone(),
                activity_tracker.clone(),
            ),
            hosts: Arc::clone(&self.ctx.hosts),
            scores: Arc::clone(&self.ctx.scores),
            rates: Arc::clone(&self.ctx.rates),
            trust_graph: self.ctx.trust_graph.clone(),
            groups: Arc::clone(&self.ctx.groups),
            trust_metrics: Arc::clone(&self.ctx.trust_metrics),
            oracle: Arc::clone(&self.ctx.oracle),
            address_refresh: Arc::clone(&self.ctx.address_refresh),
            hole_puncher: Arc::clone(&self.ctx.hole_puncher),
            signaling_strategy: Arc::clone(&self.ctx.signaling_strategy),
            relay_tx: Arc::clone(&self.ctx.relay_tx),
            relay_tracker: Arc::clone(&self.ctx.relay_tracker),
            relay_metrics: Arc::clone(&self.ctx.relay_metrics),
            relay_nonce_cache: Arc::clone(&self.ctx.relay_nonce_cache),
            peer_directory: Arc::clone(&self.ctx.peer_directory),
            observable: Arc::clone(&self.ctx.observable),
            prekey_cache: Arc::clone(&self.ctx.prekey_cache),
            local_prekey_store,
            session_store: Arc::clone(&self.ctx.session_store),
            biometric_gate: Arc::clone(&self.ctx.biometric_gate),
            invite_registry: Arc::clone(&self.ctx.invite_registry),
            degradation: Arc::clone(&self.ctx.degradation),
            stigma_cache: Arc::clone(&self.ctx.stigma_cache),
            inbound_observations_tx: Arc::clone(&self.ctx.inbound_observations_tx),
            badge_store: Arc::clone(&self.ctx.badge_store),
            badge_metrics: Arc::clone(&self.ctx.badge_metrics),
            badge_fetch_shutdown: Arc::clone(&self.ctx.badge_fetch_shutdown),
            cold_contact_tracker: Arc::clone(&self.ctx.cold_contact_tracker),
            auto_badge_queue: Arc::clone(&self.ctx.auto_badge_queue),
            abuse_metrics: Arc::clone(&self.ctx.abuse_metrics),
            identity_id: self.identity_id.clone(),
            public_key: self.public_key.clone(),
            identity_signing_key: self.ctx.identity_signing_key.clone(),
            jury_commitment_publisher: self.ctx.jury_commitment_publisher.clone(),
            jury_plaintext_cache: Arc::clone(&self.ctx.jury_plaintext_cache),
            invite_redemption_transport: self.ctx.invite_redemption_transport.clone(),
            pending_invite_redemptions: Arc::clone(&self.ctx.pending_invite_redemptions),
            sas_pairing: Arc::clone(&self.ctx.sas_pairing),
            integrity: integrity.or_else(|| self.ctx.integrity.clone()),
        });
        self.ctx = Arc::clone(&ctx);
        let (incoming_shutdown, incoming_task) =
            Self::spawn_incoming_task(incoming, Arc::clone(&ctx));
        self.incoming_shutdown = Some(incoming_shutdown);
        self.incoming_task = Some(incoming_task);
        let (quic_incoming_shutdown, quic_incoming_task) = if self.transport.has_quic() {
            match (self.transport.quic_channel(), self.transport.incoming_tx()) {
                (Some(channel), Some(sender)) => {
                    let (shutdown, task) = Self::spawn_quic_incoming_task(
                        channel,
                        sender,
                        Arc::clone(&ctx.hosts),
                        Arc::clone(&ctx.abuse_metrics),
                    );
                    (Some(shutdown), Some(task))
                }
                _ => (None, None),
            }
        } else {
            (None, None)
        };
        self.quic_incoming_shutdown = quic_incoming_shutdown;
        self.quic_incoming_task = quic_incoming_task;
        Ok(())
    }

    fn spawn_quic_incoming_task(
        channel: Arc<crate::quic_transport::QuicChannel>,
        sender: mpsc::Sender<(SyncEnvelope, EnvelopeMeta)>,
        hosts: Arc<std::sync::Mutex<KnownHosts>>,
        abuse_metrics: Arc<AbuseMetrics>,
    ) -> (oneshot::Sender<()>, JoinHandle<()>) {
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(crate::transport::quic_incoming_loop(
            channel,
            sender,
            hosts,
            abuse_metrics,
            shutdown_rx,
        ));
        (shutdown, task)
    }

    fn start_quic_punch_rendezvous(&mut self) {
        let local_identity_id = self.identity_id.clone();
        let signing_key = self.private_key.clone();
        let endpoint_state = Arc::clone(&self.quic_listener_endpoint);
        let hosts = Arc::clone(&self.ctx.hosts);
        let metrics = Arc::clone(&self.ctx.abuse_metrics);
        log::info!(
            target: "HAL_DHT",
            "QUIC rendezvous poller started for {}",
            self.identity_id
        );
        let (shutdown, mut shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut attempted = HashMap::<String, Instant>::new();
            let mut reported_peer_count = false;

            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    _ = interval.tick() => {}
                }

                let mut peers = match hosts.lock() {
                    Ok(hosts) => hosts
                        .identities()
                        .into_iter()
                        .filter(|(identity_id, _)| identity_id != &local_identity_id)
                        .collect::<Vec<_>>(),
                    Err(error) => {
                        log::error!("QUIC rendezvous: known-hosts lock poisoned: {error}");
                        continue;
                    }
                };
                peers.sort_by(|left, right| left.0.cmp(&right.0));
                if !reported_peer_count {
                    log::info!(
                        target: "HAL_DHT",
                        "QUIC rendezvous poller has {} pinned peer(s)",
                        peers.len()
                    );
                    reported_peer_count = true;
                }

                let lookups = futures::stream::iter(peers.into_iter().map(|(peer_id, key_hex)| {
                    let local_identity_id = local_identity_id.clone();
                    async move {
                        let topic = quic_punch_dht_topic(&peer_id, &local_identity_id);
                        let result = PublicDhtProvider::new(&topic)
                            .with_timeout(Duration::from_secs(4))
                            .discover()
                            .await;
                        (peer_id, key_hex, topic, result)
                    }
                }))
                .buffer_unordered(4);
                tokio::pin!(lookups);

                while let Some((peer_id, key_hex, topic, result)) = lookups.next().await {
                    let addresses = match result {
                        Ok(addresses) => addresses,
                        Err(error) => {
                            log::debug!(
                                target: "HAL_DHT",
                                "QUIC rendezvous lookup failed for {peer_id} on {topic}: {error}"
                            );
                            continue;
                        }
                    };
                    if !addresses.is_empty() {
                        log::info!(
                            target: "HAL_DHT",
                            "QUIC rendezvous found {} endpoint(s) for pinned peer {peer_id}",
                            addresses.len()
                        );
                    }
                    let public_key_bytes: [u8; 32] = match hex::decode(&key_hex).and_then(|bytes| {
                        bytes
                            .try_into()
                            .map_err(|_| hex::FromHexError::InvalidStringLength)
                    }) {
                        Ok(bytes) => bytes,
                        Err(error) => {
                            log::warn!(
                                "QUIC rendezvous skipped invalid pinned key for {peer_id}: {error}"
                            );
                            continue;
                        }
                    };
                    let expected_peer_key = match VerifyingKey::from_bytes(&public_key_bytes) {
                        Ok(key) if NodeId::from_public_key(&key).to_hex() == peer_id => key,
                        Ok(_) => {
                            log::warn!(
                                "QUIC rendezvous skipped mismatched pinned identity {peer_id}"
                            );
                            continue;
                        }
                        Err(error) => {
                            log::warn!(
                                "QUIC rendezvous skipped invalid pinned key for {peer_id}: {error}"
                            );
                            continue;
                        }
                    };

                    for address in addresses.into_iter().filter(|address| {
                        !address.ip().is_loopback()
                            && !address.ip().is_unspecified()
                            && address.port() != 0
                    }) {
                        let attempt_key = format!("{peer_id}@{address}");
                        if attempted.get(&attempt_key).is_some_and(|last_attempt| {
                            last_attempt.elapsed() < Duration::from_secs(60)
                        }) {
                            continue;
                        }
                        attempted.insert(attempt_key, Instant::now());
                        let Some(endpoint) = endpoint_state.read().await.clone() else {
                            break;
                        };
                        let result = tokio::time::timeout(
                            Duration::from_secs(5),
                            QuicChannel::connect_on_endpoint(
                                endpoint,
                                address,
                                "hal-sync",
                                &signing_key,
                                Some(expected_peer_key.clone()),
                                Arc::clone(&hosts),
                                Arc::clone(&metrics),
                            ),
                        )
                        .await;
                        match result {
                            Ok(Ok(channel)) => {
                                log::info!(
                                    target: "HAL_DHT",
                                    "QUIC rendezvous punch connected to {peer_id} at {address}"
                                );
                                tokio::time::sleep(Duration::from_secs(3)).await;
                                drop(channel);
                            }
                            Ok(Err(error)) => log::debug!(
                                target: "HAL_DHT",
                                "QUIC rendezvous connect to {peer_id} at {address} failed: {error}"
                            ),
                            Err(_) => log::debug!(
                                target: "HAL_DHT",
                                "QUIC rendezvous connect to {peer_id} at {address} timed out"
                            ),
                        }
                    }
                }

                attempted
                    .retain(|_, last_attempt| last_attempt.elapsed() < Duration::from_secs(300));
            }
        });
        self.quic_punch_shutdown = Some(shutdown);
        self.quic_punch_task = Some(task);
    }

    fn spawn_quic_endpoint_listener(
        endpoint: Arc<quinn::Endpoint>,
        signing_key: SigningKey,
        sender: mpsc::Sender<(SyncEnvelope, EnvelopeMeta)>,
        hosts: Arc<std::sync::Mutex<KnownHosts>>,
        abuse_metrics: Arc<AbuseMetrics>,
    ) -> (oneshot::Sender<()>, JoinHandle<()>) {
        let (shutdown, mut shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                let incoming = tokio::select! {
                    _ = &mut shutdown_rx => break,
                    incoming = endpoint.accept() => incoming,
                };
                let Some(incoming) = incoming else {
                    break;
                };
                let endpoint = endpoint.as_ref().clone();
                let signing_key = signing_key.clone();
                let sender = sender.clone();
                let hosts = Arc::clone(&hosts);
                let abuse_metrics = Arc::clone(&abuse_metrics);
                tokio::spawn(async move {
                    match QuicChannel::accept_incoming(
                        endpoint,
                        incoming,
                        &signing_key,
                        None,
                        Arc::clone(&hosts),
                        Arc::clone(&abuse_metrics),
                    )
                    .await
                    {
                        Ok(channel) => {
                            let channel = Arc::new(channel);
                            let (_shutdown, shutdown_rx) = oneshot::channel();
                            crate::transport::quic_incoming_loop(
                                channel,
                                sender,
                                hosts,
                                abuse_metrics,
                                shutdown_rx,
                            )
                            .await;
                        }
                        Err(error) => {
                            log::warn!("QUIC incoming connection rejected: {error}");
                        }
                    }
                });
            }
            endpoint.close(0u32.into(), b"runtime stopped");
        });
        (shutdown, task)
    }

    fn spawn_incoming_task(
        mut incoming: mpsc::Receiver<(SyncEnvelope, EnvelopeMeta)>,
        ctx: Arc<RuntimeContext>,
    ) -> (oneshot::Sender<()>, JoinHandle<()>) {
        let (shutdown, mut shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                let Some((envelope, meta)) = (tokio::select! {
                    _ = &mut shutdown_rx => break,
                    envelope = incoming.recv() => envelope,
                }) else {
                    break;
                };
                Self::process_incoming_envelope_with_meta(envelope, meta, Arc::clone(&ctx)).await;
            }
        });
        (shutdown, task)
    }

    #[cfg(test)]
    async fn process_incoming_envelope(envelope: SyncEnvelope, ctx: Arc<RuntimeContext>) {
        Self::process_incoming_envelope_with_meta(envelope, EnvelopeMeta::default(), ctx).await;
    }

    async fn process_incoming_envelope_with_meta(
        envelope: SyncEnvelope,
        meta: EnvelopeMeta,
        ctx: Arc<RuntimeContext>,
    ) {
        if meta.was_cold {
            ctx.trust_metrics.inc_envelope_cold_received();
            log::debug!(
                "cold envelope received from {} at {:?} (binding {:?})",
                envelope.identity_id,
                meta.remote_addr,
                meta.binding_before_learn
            );
        } else {
            ctx.trust_metrics.inc_envelope_warm_received();
            log::debug!(
                "warm envelope received from {} at {:?} (binding {:?})",
                envelope.identity_id,
                meta.remote_addr,
                meta.binding_before_learn
            );
        }
        Self::process_incoming_envelope_inner(envelope, ctx, 0, meta).await;
    }

    async fn process_incoming_envelope_inner(
        envelope: SyncEnvelope,
        ctx: Arc<RuntimeContext>,
        depth: u8,
        meta: EnvelopeMeta,
    ) {
        if let Err(error) = envelope.verify() {
            log::warn!("incoming envelope signature rejected: {error}");
            return;
        }
        Self::process_incoming_envelope_verified(envelope, ctx, depth, meta).await;
    }

    async fn process_incoming_envelope_verified(
        envelope: SyncEnvelope,
        ctx: Arc<RuntimeContext>,
        depth: u8,
        meta: EnvelopeMeta,
    ) {
        if envelope.is_cover {
            log::debug!(target: "HAL_DHT", "CoverTraffic: dropped cover envelope from {}", envelope.identity_id);
            return;
        }
        if envelope.identity_id == ctx.identity_id || envelope.public_key == ctx.public_key {
            return;
        }

        if let Some(transport_id) = meta.transport_peer_identity.as_ref() {
            if transport_id != &envelope.identity_id {
                ctx.abuse_metrics
                    .envelope_transport_identity_mismatch_total
                    .fetch_add(1, Ordering::Relaxed);
                log::warn!(
                    "transport identity mismatch: envelope {} != transport {}",
                    envelope.identity_id,
                    transport_id
                );
                return;
            }
            ctx.abuse_metrics
                .envelope_transport_identity_verified_total
                .fetch_add(1, Ordering::Relaxed);
        }

        let contains_sas_pairing = envelope
            .events
            .iter()
            .any(|event| event.event_type == SyncEventType::SasPairing);
        if contains_sas_pairing {
            if let Err(error) = handle_sas_pairing_envelope(envelope, meta, ctx).await {
                log::warn!("SAS pairing control event rejected: {error}");
            }
            return;
        }
        let contains_peer_presence = envelope
            .events
            .iter()
            .any(|event| event.event_type == SyncEventType::PeerPresence);
        if contains_peer_presence {
            if let Err(error) = handle_home_presence_envelope(envelope, meta, ctx).await {
                log::warn!("Home Presence event rejected: {error}");
            }
            return;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if !ctx
            .admit_peer(&envelope.identity_id, Some(&envelope.public_key), now)
            .await
        {
            log::debug!(
                "incoming envelope rejected by degraded admission gate: {}",
                envelope.identity_id
            );
            return;
        }

        if let Some(wave) = ctx.integrity.as_ref() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if envelope.verify_with_integrity(wave, now).is_err() {
                log::warn!("Rejected peer envelope with invalid integrity proof");
                return;
            }
        }

        let is_stranger = match ctx.hosts.lock() {
            Ok(hosts) => match hosts.check(&envelope.identity_id, &envelope.public_key) {
                crate::pinning::BindingCheck::Trusted => false,
                crate::pinning::BindingCheck::Unknown => true,
                crate::pinning::BindingCheck::Conflicted { .. } => {
                    ctx.trust_metrics.inc_conflicted();
                    log::warn!("host pinning conflict from {}", envelope.identity_id);
                    return;
                }
            },
            Err(_) => {
                log::warn!("known hosts mutex poisoned");
                return;
            }
        };

        let pubkey_bytes: [u8; 32] = match hex::decode(&envelope.public_key)
            .ok()
            .and_then(|value| value.try_into().ok())
        {
            Some(bytes) => bytes,
            None => {
                log::warn!("invalid public_key hex from {}", envelope.identity_id);
                return;
            }
        };

        let verifying_key = match VerifyingKey::from_bytes(&pubkey_bytes) {
            Ok(vk) => vk,
            Err(_) => {
                log::warn!("invalid ed25519 public_key from {}", envelope.identity_id);
                return;
            }
        };
        let node_id = NodeId::from_public_key(&verifying_key);
        if ctx.oracle.is_banned(&node_id, now) {
            ctx.trust_metrics.inc_denies_banned();
            log::debug!("dropped envelope from banned node {}", envelope.identity_id);
            return;
        }
        let now_gate = unix_now();
        if meta.was_cold {
            let mut tracker = ctx.cold_contact_tracker.lock().await;
            let evicted_before = tracker.metrics().evicted_total.load(Ordering::Relaxed);
            let verdict = tracker.record(&node_id, now_gate);
            let evicted_after = tracker.metrics().evicted_total.load(Ordering::Relaxed);
            if evicted_after > evicted_before {
                ctx.abuse_metrics
                    .cold_tracker_evicted_total
                    .fetch_add(evicted_after - evicted_before, Ordering::Relaxed);
            }

            if let ColdContactVerdict::Exceeded { count } = verdict {
                ctx.abuse_metrics
                    .incoming_cold_exceeded_total
                    .fetch_add(1, Ordering::Relaxed);
                let message_ids = envelope
                    .events
                    .iter()
                    .take(64)
                    .map(|event| event.id.clone())
                    .collect::<Vec<_>>();
                if message_ids.is_empty() {
                    ctx.abuse_metrics
                        .auto_badge_skipped_no_evidence_total
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    ctx.auto_badge_queue.lock().await.push(PendingBadge {
                        subject_id: node_id,
                        message_ids,
                        reason: format!(
                            "cold-contact flood: {count}/{COLD_CONTACT_LIMIT} in {COLD_CONTACT_WINDOW_SECS}s"
                        ),
                        observed_at: now_gate,
                    });
                    ctx.abuse_metrics
                        .auto_badge_queued_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                log::debug!(
                    "incoming cold-contact threshold exceeded for {}",
                    envelope.identity_id
                );
            }
        }
        if ctx.trust_graph.is_some() && ctx.rate_exceeded(&node_id, now).await {
            log::debug!(
                "dropped envelope from tier-rate-limited node {}",
                envelope.identity_id
            );
            return;
        }
        if is_stranger
            && !cfg!(all(debug_assertions, not(test)))
            && !ctx.oracle.allows_message_to_stranger(&node_id, now)
        {
            ctx.trust_metrics.inc_denies_stranger_rate();
            log::debug!(
                "dropped envelope from rate-limited stranger {}",
                envelope.identity_id
            );
            return;
        }

        match ctx
            .peer_admission(&envelope.identity_id, Some(&envelope.public_key), now_gate)
            .await
        {
            crate::runtime_context::PeerAdmission::StigmaRejected => {
                ctx.abuse_metrics
                    .incoming_stigma_rejected_total
                    .fetch_add(1, Ordering::Relaxed);
                log::debug!(
                    "incoming rejected: sender {} under stigma",
                    envelope.identity_id
                );
                return;
            }
            crate::runtime_context::PeerAdmission::DegradedUnknownRejected => {
                log::debug!(
                    "incoming rejected: sender {} by degraded admission gate",
                    envelope.identity_id
                );
                return;
            }
            crate::runtime_context::PeerAdmission::Allowed { .. } => {}
        }

        if !is_stranger && ctx.trust_graph.is_some() && !ctx.record_rate_acceptance(&node_id, now) {
            log::debug!(
                "dropped envelope after rate window reservation failed for {}",
                envelope.identity_id
            );
            return;
        }

        if let Some(storage) = &ctx.storage {
            match storage.lock() {
                Ok(storage) => {
                    let registry = storage.peer_registry();
                    if let Err(error) = registry.upsert_identity_key(
                        &envelope.identity_id,
                        &envelope.public_key,
                        now_gate,
                    ) {
                        log::warn!(
                            "failed to persist authenticated peer key for {}: {error}",
                            envelope.identity_id
                        );
                    }
                    if let Some(remote_addr) = meta
                        .remote_addr
                        .and_then(crate::transport::inferred_lan_peer_listener_address)
                    {
                        let peer = hal_storage::StoredPeer {
                            peer_id: envelope.identity_id.clone(),
                            identity_id: envelope.identity_id.clone(),
                            public_key: envelope.public_key.clone(),
                            transport_address: remote_addr.to_string(),
                            last_seen: now_gate,
                            expires_at: now_gate.saturating_add(5 * 60),
                            latency_ms: None,
                            failure_count: 0,
                        };
                        if let Err(error) = registry.upsert(&peer) {
                            log::warn!(
                                "failed to persist authenticated peer address for {}: {error}",
                                envelope.identity_id
                            );
                        }
                    } else if meta.remote_addr.is_some() {
                        log::debug!(
                            "not persisting non-LAN inbound source as a direct peer address for {}",
                            envelope.identity_id
                        );
                    }
                }
                Err(_) => log::warn!("storage lock poisoned while recording authenticated peer"),
            }
        }

        if let Err(error) = load_session_on_demand(&ctx, &node_id).await {
            log::warn!(
                "failed loading persisted session for incoming peer {}: {error}",
                envelope.identity_id
            );
        }

        if let Some(age_tracker) = ctx.age_tracker.as_ref() {
            if let Err(error) = age_tracker.lock().await.observe(node_id, now_gate) {
                log::debug!("age_tracker observe failed: {error}");
            }
        }
        if let Some(activity_tracker) = ctx.activity_tracker.as_ref() {
            for event in &envelope.events {
                if let Err(error) = activity_tracker
                    .lock()
                    .await
                    .record(node_id, event.id.clone(), now_gate)
                    .await
                {
                    log::debug!("activity_tracker record failed: {error}");
                    break;
                }
            }
        }

        if let Some(signal) = envelope.media_signal.clone() {
            let mut signals = ctx.media_signals.lock().await;
            if signals.len() >= MAX_MEDIA_SIGNALS {
                signals.remove(0);
                log::warn!(
                    "dropping oldest media signal after queue reached {}",
                    MAX_MEDIA_SIGNALS
                );
            }
            signals.push((envelope.identity_id.clone(), signal));
        }

        let sender_identity_id = envelope.identity_id.clone();
        let mut merged_events = Vec::with_capacity(envelope.events.len());
        let mut relay_forwards = Vec::new();
        for event in envelope.events {
            if event.event_type == SyncEventType::HomeLinkRequest {
                log::info!(
                    "received HomeLinkRequest event {} from {}",
                    event.id,
                    sender_identity_id
                );
            }
            #[cfg(not(target_os = "android"))]
            if event.event_type == SyncEventType::MessageAdded {
                log::info!(
                    "Desktop: received message from peer, storing... sender={} event_id={}",
                    sender_identity_id,
                    event.id
                );
            }
            let message_read = if event.event_type == SyncEventType::MessageRead {
                let payload = match serde_json::from_str::<crate::MessageReadPayload>(&event.data) {
                    Ok(payload) => payload,
                    Err(error) => {
                        log::warn!(
                            "rejecting malformed MessageRead event {}: {error}",
                            event.id
                        );
                        continue;
                    }
                };
                let valid = if payload.recipient_id != ctx.identity_id
                    || payload.reader_id != sender_identity_id
                {
                    false
                } else if let Some(storage) = ctx.storage.as_ref() {
                    let target = storage.lock().ok().and_then(|storage| {
                        storage
                            .get_message_read_target(&payload.message_id)
                            .ok()
                            .flatten()
                    });
                    target.is_some_and(|target| {
                        if target.sender_id != "android-local" {
                            return false;
                        }
                        if let Some(group_id) = target.group_id {
                            storage
                                .lock()
                                .ok()
                                .and_then(|storage| storage.get_group(&group_id).ok().flatten())
                                .is_some_and(|group| {
                                    group.member_peer_ids.iter().any(|member| {
                                        parse_group_member_key(member).is_ok_and(|key| {
                                            NodeId::from_public_key(&key).to_hex()
                                                == payload.reader_id
                                        })
                                    })
                                })
                        } else {
                            hex::decode(target.chat_id)
                                .ok()
                                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                                .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
                                .is_some_and(|key| {
                                    NodeId::from_public_key(&key).to_hex() == payload.reader_id
                                })
                        }
                    })
                } else {
                    false
                };
                if !valid {
                    log::warn!(
                        "rejecting unauthorized or misaddressed MessageRead event {}",
                        event.id
                    );
                    continue;
                }
                Some(payload)
            } else {
                None
            };
            let profile_update = if event.event_type == SyncEventType::ProfileUpdate {
                let payload = match serde_json::from_str::<crate::ProfileUpdatePayload>(&event.data)
                {
                    Ok(payload) => payload,
                    Err(error) => {
                        log::warn!(
                            "rejecting malformed ProfileUpdate event {}: {error}",
                            event.id
                        );
                        continue;
                    }
                };
                let avatar_is_valid = payload.avatar_b64.as_ref().is_none_or(|avatar| {
                    use base64::Engine as _;
                    base64::engine::general_purpose::STANDARD
                        .decode(avatar)
                        .is_ok_and(|bytes| bytes.len() <= 256 * 1024)
                });
                if payload.recipient_id != ctx.identity_id
                    || payload.display_name.trim().is_empty()
                    || payload.display_name.chars().count() > 64
                    || payload.display_name.chars().any(char::is_control)
                    || !avatar_is_valid
                {
                    log::warn!(
                        "rejecting invalid or misaddressed ProfileUpdate event {}",
                        event.id
                    );
                    continue;
                }
                Some(payload)
            } else {
                None
            };
            let group_create = if event.event_type == SyncEventType::GroupCreate {
                let payload = match serde_json::from_str::<crate::GroupCreatePayload>(&event.data) {
                    Ok(payload) => payload,
                    Err(error) => {
                        log::warn!(
                            "rejecting malformed GroupCreate event {}: {error}",
                            event.id
                        );
                        continue;
                    }
                };
                let mut member_keys = Vec::with_capacity(payload.members.len());
                let mut member_key_bytes = HashSet::with_capacity(payload.members.len());
                let mut valid = uuid::Uuid::parse_str(&payload.group_id).is_ok()
                    && !payload.name.trim().is_empty()
                    && payload.name.len() <= 64
                    && payload.recipient_id == ctx.identity_id
                    && !payload.members.is_empty()
                    && payload.members.len() <= 500
                    && payload
                        .avatar_b64
                        .as_ref()
                        .is_none_or(|avatar| avatar.len() <= 350_000);
                for member in &payload.members {
                    match parse_group_member_key(member) {
                        Ok(key) if member_key_bytes.insert(key.to_bytes()) => {
                            member_keys.push(key);
                        }
                        _ => {
                            valid = false;
                            break;
                        }
                    }
                }
                let sender_is_member = member_keys
                    .iter()
                    .any(|key| key.to_bytes() == verifying_key.to_bytes());
                let local_key_bytes = hex::decode(&ctx.public_key)
                    .ok()
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());
                let local_is_member = local_key_bytes.is_some_and(|local_key_bytes| {
                    member_keys
                        .iter()
                        .any(|key| key.to_bytes() == local_key_bytes)
                });
                if !valid || !sender_is_member || !local_is_member {
                    log::warn!(
                        "rejecting invalid or misaddressed GroupCreate event {}",
                        event.id
                    );
                    continue;
                }
                Some(payload)
            } else {
                None
            };
            if let (Some(storage), Some(payload)) = (&ctx.storage, group_create.as_ref()) {
                match storage.lock() {
                    Ok(mut storage) => {
                        if let Err(error) = storage.store_group_invite(
                            &payload.group_id,
                            &payload.name,
                            payload.avatar_b64.as_deref(),
                            &payload.members,
                        ) {
                            log::warn!("failed to persist received group invite: {error}");
                            continue;
                        }
                    }
                    Err(_) => {
                        log::error!("storage lock poisoned while applying group invite");
                        continue;
                    }
                }
            }
            let group_key_distribution = if event.event_type == SyncEventType::GroupKeyDistribution
            {
                let payload =
                    match serde_json::from_str::<crate::GroupKeyDistributionPayload>(&event.data) {
                        Ok(payload) => payload,
                        Err(error) => {
                            log::warn!("rejecting malformed group key event {}: {error}", event.id);
                            continue;
                        }
                    };
                let Ok(key) = hex::decode(&payload.group_key) else {
                    log::warn!("rejecting invalid group key event {}", event.id);
                    continue;
                };
                let sender_key = hex::encode(verifying_key.to_bytes());
                let is_member = ctx
                    .storage
                    .as_ref()
                    .and_then(|storage| storage.lock().ok())
                    .and_then(|storage| storage.get_group(&payload.group_id).ok().flatten())
                    .is_some_and(|group| {
                        group.member_peer_ids.contains(&sender_key)
                            && group.member_peer_ids.contains(&ctx.public_key)
                    });
                if uuid::Uuid::parse_str(&payload.group_id).is_err()
                    || payload.recipient_id != ctx.identity_id
                    || key.len() != 32
                    || !is_member
                {
                    log::warn!(
                        "rejecting invalid or misaddressed group key event {}",
                        event.id
                    );
                    continue;
                }
                Some(payload)
            } else {
                None
            };
            let decrypted_group_message = if event.event_type == SyncEventType::GroupMessage {
                let payload = match serde_json::from_str::<crate::GroupMessagePayload>(&event.data)
                {
                    Ok(payload) => payload,
                    Err(error) => {
                        log::warn!(
                            "rejecting malformed group message event {}: {error}",
                            event.id
                        );
                        continue;
                    }
                };
                let member_key = hex::encode(verifying_key.to_bytes());
                let group_and_key = ctx
                    .storage
                    .as_ref()
                    .and_then(|storage| storage.lock().ok())
                    .and_then(|storage| {
                        let group = storage.get_group(&payload.group_id).ok().flatten()?;
                        if !group.member_peer_ids.contains(&member_key)
                            || !group.member_peer_ids.contains(&ctx.public_key)
                        {
                            return None;
                        }
                        let key = storage.get_group_key(&payload.group_id).ok().flatten()?;
                        Some(key)
                    });
                let Some(group_key_hex) = group_and_key else {
                    log::warn!(
                        "rejecting group message from non-member or without a sender key {}",
                        event.id
                    );
                    continue;
                };
                let Ok(key) = hex::decode(group_key_hex) else {
                    log::warn!(
                        "stored group key is malformed for group message {}",
                        event.id
                    );
                    continue;
                };
                let Ok(key): Result<[u8; 32], _> = key.try_into() else {
                    log::warn!("stored group key length is invalid for event {}", event.id);
                    continue;
                };
                let Ok(nonce) = base64::engine::general_purpose::STANDARD.decode(&payload.nonce)
                else {
                    log::warn!("group message nonce is malformed for event {}", event.id);
                    continue;
                };
                let Ok(ciphertext) =
                    base64::engine::general_purpose::STANDARD.decode(&payload.ciphertext)
                else {
                    log::warn!(
                        "group message ciphertext is malformed for event {}",
                        event.id
                    );
                    continue;
                };
                let Ok(nonce): Result<[u8; 12], _> = nonce.try_into() else {
                    log::warn!(
                        "group message nonce length is invalid for event {}",
                        event.id
                    );
                    continue;
                };
                let Ok(cipher) = ChaCha20Poly1305::new_from_slice(&key) else {
                    log::warn!("group sender key is invalid for event {}", event.id);
                    continue;
                };
                let aad =
                    group_message_aad(&payload.group_id, &payload.sender_id, &payload.message_id);
                let Ok(plaintext) = cipher.decrypt(
                    Nonce::from_slice(&nonce),
                    chacha20poly1305::aead::Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                ) else {
                    log::warn!("group message decryption failed for event {}", event.id);
                    continue;
                };
                let Ok(plaintext) = serde_json::from_slice::<serde_json::Value>(&plaintext) else {
                    log::warn!(
                        "decrypted group message is malformed for event {}",
                        event.id
                    );
                    continue;
                };
                let Some(text) = plaintext.get("text").and_then(|value| value.as_str()) else {
                    log::warn!("decrypted group message has no text for event {}", event.id);
                    continue;
                };
                if payload.recipient_id != ctx.identity_id
                    || payload.sender_id != sender_identity_id
                    || NodeId::from_public_key(&verifying_key).to_hex() != payload.sender_id
                    || uuid::Uuid::parse_str(&payload.group_id).is_err()
                    || uuid::Uuid::parse_str(&payload.message_id).is_err()
                    || text.is_empty()
                    || text.len() > 4096
                {
                    log::warn!("rejecting invalid group message event {}", event.id);
                    continue;
                }
                let reply_to_id = plaintext
                    .get("reply_to_id")
                    .and_then(|value| value.as_str())
                    .map(str::to_string);
                if reply_to_id
                    .as_ref()
                    .is_some_and(|reply_id| reply_id.is_empty() || reply_id.len() > 128)
                {
                    log::warn!("rejecting invalid group reply metadata {}", event.id);
                    continue;
                }
                Some((payload, text.to_string(), reply_to_id))
            } else {
                None
            };
            let mut pending_ratchet_receive = None;
            let mut _receive_guard = None;
            let mut contact_policy_after_verify = None;
            let decrypted_message = if event.event_type == SyncEventType::MessageAdded {
                match serde_json::from_str::<serde_json::Value>(&event.data) {
                    Ok(value)
                        if value.get("chat_id").is_some()
                            && value.get("sender_id").is_some()
                            && (value.get("ciphertext").is_some()
                                || value.get("version").is_some()
                                || (value.get("text").is_some()
                                    && value.get("recipient_id").is_some())) =>
                    {
                        let payload = match serde_json::from_value::<crate::MessageAddedPayload>(
                            value,
                        ) {
                            Ok(payload) => payload,
                            Err(error) => {
                                ctx.abuse_metrics
                                    .messages_decrypt_failed_total
                                    .fetch_add(1, Ordering::Relaxed);
                                ctx.abuse_metrics
                                    .ratchet_parse_failed_total
                                    .fetch_add(1, Ordering::Relaxed);
                                log::warn!(
                                    "rejecting malformed versioned MessageAdded payload {}: {error}",
                                    event.id
                                );
                                continue;
                            }
                        };
                        if let Err(error) = payload.validate() {
                            ctx.abuse_metrics
                                .messages_decrypt_failed_total
                                .fetch_add(1, Ordering::Relaxed);
                            if matches!(payload.version, 3 | 4) {
                                ctx.abuse_metrics
                                    .ratchet_parse_failed_total
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            log::warn!(
                                "rejecting invalid encrypted MessageAdded payload {}: {error}",
                                event.id
                            );
                            continue;
                        }
                        if !matches!(payload.version, 1..=4) {
                            ctx.abuse_metrics
                                .messages_decrypt_failed_total
                                .fetch_add(1, Ordering::Relaxed);
                            log::warn!(
                                "rejecting unsupported MessageAdded version {} for event {}",
                                payload.version,
                                event.id
                            );
                            continue;
                        }
                        if payload.sender_id != sender_identity_id {
                            ctx.abuse_metrics
                                .messages_decrypt_failed_total
                                .fetch_add(1, Ordering::Relaxed);
                            if matches!(payload.version, 3 | 4) {
                                ctx.abuse_metrics
                                    .ratchet_sender_mismatch_total
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            log::warn!(
                                "rejecting encrypted MessageAdded sender mismatch for event {}",
                                event.id
                            );
                            continue;
                        }
                        if payload.version <= 2 {
                            if let Some(storage) = ctx.storage.as_ref() {
                                let has_event = match storage.lock() {
                                    Ok(storage) => storage.sync_storage().has_event(&event.id),
                                    Err(_) => {
                                        log::error!(
                                            "storage lock poisoned during event replay precheck {}",
                                            event.id
                                        );
                                        continue;
                                    }
                                };
                                match has_event {
                                    Ok(true) => {
                                        ctx.abuse_metrics
                                            .replay_precheck_total
                                            .fetch_add(1, Ordering::Relaxed);
                                        log::debug!(
                                            "event replay precheck rejected {} from {}",
                                            event.id,
                                            envelope.identity_id
                                        );
                                        continue;
                                    }
                                    Ok(false) => {}
                                    Err(error) => {
                                        log::error!(
                                            "event replay precheck failed for {}: {error}",
                                            event.id
                                        );
                                        continue;
                                    }
                                }
                            }
                        }
                        if payload.version != 1
                            && payload.recipient_id() == Some(ctx.identity_id.as_str())
                        {
                            let policy = ctx
                                .session_store
                                .lock()
                                .await
                                .get(&node_id)
                                .map(|session| session.contact_policy);
                            if let Some(policy) = policy {
                                match ensure_biometric_if_required(
                                    ctx.biometric_gate.as_ref(),
                                    &policy,
                                    &ctx.abuse_metrics,
                                    "Confirm receiving a message",
                                )
                                .await
                                {
                                    Ok(updated) => {
                                        if updated != policy {
                                            contact_policy_after_verify = Some(updated);
                                        }
                                    }
                                    Err(error) => {
                                        log::warn!(
                                            "biometric rejected for receive event {}; deferring decrypt: {error}",
                                            event.id
                                        );
                                        continue;
                                    }
                                }
                            }
                        }
                        if payload.version == 1 {
                            let sender_has_confirmed_session = ctx
                                .session_store
                                .lock()
                                .await
                                .get_view(&node_id)
                                .is_some_and(|view| view.responded);
                            if sender_has_confirmed_session {
                                ctx.abuse_metrics
                                    .ratchet_unexpected_v1_total
                                    .fetch_add(1, Ordering::Relaxed);
                                log::warn!(
                                    "rejecting plaintext V1 message from confirmed ratchet peer {}",
                                    sender_identity_id
                                );
                                continue;
                            }
                            None
                        } else if payload.recipient_id() != Some(ctx.identity_id.as_str()) {
                            if matches!(payload.version, 3 | 4) {
                                ctx.abuse_metrics
                                    .ratchet_recipient_mismatch_total
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            None
                        } else if payload.version == 2 {
                            let sender_has_confirmed_session = ctx
                                .session_store
                                .lock()
                                .await
                                .get_view(&node_id)
                                .is_some_and(|view| view.responded && !view.needs_resync);
                            if sender_has_confirmed_session {
                                ctx.abuse_metrics
                                    .ratchet_unexpected_v2_total
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            let Some(identity_key) = ctx.identity_signing_key.as_ref() else {
                                ctx.abuse_metrics
                                    .messages_decrypt_failed_total
                                    .fetch_add(1, Ordering::Relaxed);
                                log::error!(
                                    "cannot decrypt addressed MessageAdded event {}: local identity key unavailable",
                                    event.id
                                );
                                continue;
                            };
                            match payload.decrypt(identity_key, &event.id) {
                                Ok(plaintext) => {
                                    ctx.abuse_metrics
                                        .messages_decrypted_total
                                        .fetch_add(1, Ordering::Relaxed);
                                    Some((payload, plaintext))
                                }
                                Err(error) => {
                                    ctx.abuse_metrics
                                        .messages_decrypt_failed_total
                                        .fetch_add(1, Ordering::Relaxed);
                                    log::warn!(
                                        "encrypted MessageAdded decryption failed for event {}: {error}",
                                        event.id
                                    );
                                    continue;
                                }
                            }
                        } else if payload.version == 3 {
                            let Some(counter) = payload.ratchet_counter() else {
                                ctx.abuse_metrics
                                    .ratchet_decrypt_failed_total
                                    .fetch_add(1, Ordering::Relaxed);
                                ctx.abuse_metrics
                                    .messages_decrypt_failed_total
                                    .fetch_add(1, Ordering::Relaxed);
                                log::warn!(
                                    "V3 MessageAdded event {} is missing its ratchet counter",
                                    event.id
                                );
                                continue;
                            };
                            if counter == u64::MAX {
                                ctx.abuse_metrics
                                    .ratchet_counter_overflow_total
                                    .fetch_add(1, Ordering::Relaxed);
                                ctx.abuse_metrics
                                    .ratchet_decrypt_failed_total
                                    .fetch_add(1, Ordering::Relaxed);
                                log::warn!("rejecting V3 counter overflow in event {}", event.id);
                                continue;
                            }
                            let lock = {
                                let store = ctx.session_store.lock().await;
                                store.receive_lock(&node_id)
                            };
                            let (lock, expected_generation) = match lock {
                                Ok(lock) => lock,
                                Err(error) => {
                                    match error {
                                        crate::SessionError::MissingSession
                                        | crate::SessionError::SessionNotReady => {
                                            ctx.abuse_metrics
                                                .ratchet_no_session_total
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        crate::SessionError::NeedsResync => {
                                            ctx.abuse_metrics
                                                .ratchet_needs_resync_received_total
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        crate::SessionError::CounterOverflow => {
                                            ctx.abuse_metrics
                                                .ratchet_counter_overflow_total
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        _ => {}
                                    }
                                    ctx.abuse_metrics
                                        .ratchet_decrypt_failed_total
                                        .fetch_add(1, Ordering::Relaxed);
                                    ctx.abuse_metrics
                                        .messages_decrypt_failed_total
                                        .fetch_add(1, Ordering::Relaxed);
                                    log::warn!(
                                        "V3 ratchet receive unavailable for event {}: {error}",
                                        event.id
                                    );
                                    continue;
                                }
                            };
                            _receive_guard = Some(lock.lock_owned().await);
                            let receive_preview = {
                                let mut store = ctx.session_store.lock().await;
                                store.prepare_receive_with_skipped_at(
                                    &node_id,
                                    counter,
                                    expected_generation,
                                    unix_now(),
                                )
                            };
                            match receive_preview {
                                Ok(preview) => {
                                    let out_of_order = preview.is_out_of_order();
                                    match payload.decrypt_v3(&preview.target_key, &event.id) {
                                        Ok(plaintext) => {
                                            pending_ratchet_receive = Some(PendingRatchetReceive {
                                                peer: node_id.clone(),
                                                preview: Some(preview),
                                                out_of_order,
                                                v4_transition: None,
                                                v4_counter: counter,
                                                generation: expected_generation,
                                                prune_previous_chain: None,
                                            });
                                            ctx.abuse_metrics
                                                .ratchet_decrypt_total
                                                .fetch_add(1, Ordering::Relaxed);
                                            ctx.abuse_metrics
                                                .messages_decrypted_total
                                                .fetch_add(1, Ordering::Relaxed);
                                            Some((payload, plaintext))
                                        }
                                        Err(error) => {
                                            let mut pending = Some(PendingRatchetReceive {
                                                peer: node_id.clone(),
                                                preview: Some(preview),
                                                out_of_order,
                                                v4_transition: None,
                                                v4_counter: counter,
                                                generation: expected_generation,
                                                prune_previous_chain: None,
                                            });
                                            abort_pending_ratchet_receive(
                                                ctx.as_ref(),
                                                &mut pending,
                                                &event.id,
                                            )
                                            .await;
                                            ctx.abuse_metrics
                                                .ratchet_decrypt_failed_total
                                                .fetch_add(1, Ordering::Relaxed);
                                            ctx.abuse_metrics
                                                .messages_decrypt_failed_total
                                                .fetch_add(1, Ordering::Relaxed);
                                            log::warn!(
                                            "V3 MessageAdded decryption failed for event {}: {error}",
                                            event.id
                                        );
                                            continue;
                                        }
                                    }
                                }
                                Err(error) => {
                                    match error {
                                        crate::SessionError::SkippedKeyUnavailable(_) => {
                                            ctx.abuse_metrics
                                                .ratchet_replay_total
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        crate::SessionError::CounterAhead { .. } => {
                                            ctx.abuse_metrics
                                                .ratchet_out_of_order_total
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        crate::SessionError::GapTooLarge { .. } => {
                                            ctx.abuse_metrics
                                                .ratchet_gap_too_large_total
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        crate::SessionError::MissingSession
                                        | crate::SessionError::SessionNotReady => {
                                            ctx.abuse_metrics
                                                .ratchet_no_session_total
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        crate::SessionError::NeedsResync => {
                                            ctx.abuse_metrics
                                                .ratchet_needs_resync_received_total
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        crate::SessionError::SessionReplaced => {
                                            ctx.abuse_metrics
                                                .ratchet_session_replaced_total
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        crate::SessionError::CounterOverflow => {
                                            ctx.abuse_metrics
                                                .ratchet_counter_overflow_total
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        _ => {}
                                    }
                                    ctx.abuse_metrics
                                        .ratchet_decrypt_failed_total
                                        .fetch_add(1, Ordering::Relaxed);
                                    ctx.abuse_metrics
                                        .messages_decrypt_failed_total
                                        .fetch_add(1, Ordering::Relaxed);
                                    log::warn!(
                                        "V3 ratchet receive preparation failed for event {}: {error}",
                                        event.id
                                    );
                                    continue;
                                }
                            }
                        } else if payload.version == crate::journal::MESSAGE_VERSION_V4 {
                            let Some(counter) = payload.ratchet_counter() else {
                                ctx.abuse_metrics
                                    .ratchet_decrypt_failed_total
                                    .fetch_add(1, Ordering::Relaxed);
                                ctx.abuse_metrics
                                    .messages_decrypt_failed_total
                                    .fetch_add(1, Ordering::Relaxed);
                                continue;
                            };
                            let Some(chain_id) = payload.chain_id else {
                                ctx.abuse_metrics
                                    .ratchet_parse_failed_total
                                    .fetch_add(1, Ordering::Relaxed);
                                continue;
                            };
                            if counter == u64::MAX {
                                ctx.abuse_metrics
                                    .ratchet_counter_overflow_total
                                    .fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            let lock = {
                                let store = ctx.session_store.lock().await;
                                store.receive_lock(&node_id)
                            };
                            let (lock, expected_generation) = match lock {
                                Ok(lock) => lock,
                                Err(error) => {
                                    if matches!(
                                        error,
                                        crate::SessionError::MissingSession
                                            | crate::SessionError::SessionNotReady
                                    ) {
                                        ctx.abuse_metrics
                                            .v4_no_session_total
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                    ctx.abuse_metrics
                                        .ratchet_decrypt_failed_total
                                        .fetch_add(1, Ordering::Relaxed);
                                    log::warn!(
                                        "V4 ratchet receive unavailable for event {}: {error}",
                                        event.id
                                    );
                                    continue;
                                }
                            };
                            _receive_guard = Some(lock.lock_owned().await);

                            let route = {
                                let store = ctx.session_store.lock().await;
                                store.get(&node_id).map(|session| {
                                    (
                                        session.is_v4_active(),
                                        session.chain_epoch,
                                        session.has_pending_dh_ratchet(),
                                    )
                                })
                            };
                            let Some((true, chain_epoch, pending)) = route else {
                                ctx.abuse_metrics
                                    .v4_no_session_total
                                    .fetch_add(1, Ordering::Relaxed);
                                continue;
                            };
                            let header_allows_next = pending || payload.dh_pubkey.is_some();
                            let max_epoch = chain_epoch
                                .checked_add(u64::from(header_allows_next))
                                .unwrap_or(u64::MAX);
                            if u64::from(chain_id) > max_epoch {
                                ctx.abuse_metrics
                                    .v4_future_chain_rejected_total
                                    .fetch_add(1, Ordering::Relaxed);
                                log::warn!(
                                    "rejecting future V4 chain {} for event {} (current epoch {})",
                                    chain_id,
                                    event.id,
                                    chain_epoch
                                );
                                continue;
                            }

                            let now = unix_now();
                            if u64::from(chain_id) < chain_epoch {
                                let preview = {
                                    let mut store = ctx.session_store.lock().await;
                                    match store.prepare_v4_skipped_receive(
                                        &node_id,
                                        u64::from(chain_id),
                                        counter,
                                        expected_generation,
                                        now,
                                    ) {
                                        Err(crate::SessionError::SkippedKeyUnavailable(_)) => store
                                            .prepare_v4_retired_receive(
                                                &node_id,
                                                u64::from(chain_id),
                                                counter,
                                                expected_generation,
                                                now,
                                            ),
                                        result => result,
                                    }
                                };
                                match preview {
                                    Ok(preview) => match payload
                                        .decrypt_v4(&preview.target_key, &event.id)
                                    {
                                        Ok(plaintext) => {
                                            pending_ratchet_receive = Some(PendingRatchetReceive {
                                                peer: node_id.clone(),
                                                preview: Some(preview),
                                                out_of_order: true,
                                                v4_transition: None,
                                                v4_counter: counter,
                                                generation: expected_generation,
                                                prune_previous_chain: None,
                                            });
                                            ctx.abuse_metrics
                                                .ratchet_decrypt_total
                                                .fetch_add(1, Ordering::Relaxed);
                                            ctx.abuse_metrics
                                                .messages_decrypted_total
                                                .fetch_add(1, Ordering::Relaxed);
                                            ctx.abuse_metrics
                                                .v4_messages_received_total
                                                .fetch_add(1, Ordering::Relaxed);
                                            Some((payload, plaintext))
                                        }
                                        Err(error) => {
                                            let mut pending = Some(PendingRatchetReceive {
                                                peer: node_id.clone(),
                                                preview: Some(preview),
                                                out_of_order: true,
                                                v4_transition: None,
                                                v4_counter: counter,
                                                generation: expected_generation,
                                                prune_previous_chain: None,
                                            });
                                            abort_pending_ratchet_receive(
                                                ctx.as_ref(),
                                                &mut pending,
                                                &event.id,
                                            )
                                            .await;
                                            ctx.abuse_metrics
                                                .ratchet_decrypt_failed_total
                                                .fetch_add(1, Ordering::Relaxed);
                                            log::warn!(
                                                "V4 skipped-chain decryption failed for event {}: {error}",
                                                event.id
                                            );
                                            continue;
                                        }
                                    },
                                    Err(error) => {
                                        if matches!(
                                            &error,
                                            crate::SessionError::SkippedKeyUnavailable(_)
                                        ) {
                                            ctx.abuse_metrics
                                                .v4_missing_chain_total
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        ctx.abuse_metrics
                                            .ratchet_decrypt_failed_total
                                            .fetch_add(1, Ordering::Relaxed);
                                        log::warn!(
                                            "V4 skipped-chain receive failed for event {}: {error}",
                                            event.id
                                        );
                                        continue;
                                    }
                                }
                            } else if payload.dh_pubkey.is_some()
                                || u64::from(chain_id) > chain_epoch
                            {
                                let candidate = {
                                    let store = ctx.session_store.lock().await;
                                    store
                                        .get(&node_id)
                                        .ok_or(crate::SessionError::MissingSession)
                                        .and_then(|session| {
                                            session.v4_receive_key(
                                                chain_id,
                                                counter,
                                                payload.dh_pubkey,
                                            )
                                        })
                                };
                                let (message_key, action) = match candidate {
                                    Ok(candidate) => candidate,
                                    Err(error) => {
                                        ctx.abuse_metrics
                                            .ratchet_decrypt_failed_total
                                            .fetch_add(1, Ordering::Relaxed);
                                        log::warn!(
                                            "V4 ratchet transition preview failed for event {}: {error}",
                                            event.id
                                        );
                                        continue;
                                    }
                                };
                                if action
                                    == crate::session_store::V4RatchetAction::DuplicateAdvertise
                                {
                                    ctx.abuse_metrics
                                        .v4_duplicate_advertise_total
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                                let is_transition = !matches!(
                                    action,
                                    crate::session_store::V4RatchetAction::None
                                        | crate::session_store::V4RatchetAction::DuplicateAdvertise
                                );
                                if is_transition {
                                    match payload.decrypt_v4(&message_key, &event.id) {
                                        Ok(plaintext) => {
                                            let prune_previous_chain =
                                                payload.prev_chain_length.map(|length| {
                                                    (u64::from(chain_id).saturating_sub(1), length)
                                                });
                                            pending_ratchet_receive = Some(PendingRatchetReceive {
                                                peer: node_id.clone(),
                                                preview: None,
                                                out_of_order: false,
                                                v4_transition: Some(action),
                                                v4_counter: counter,
                                                generation: expected_generation,
                                                prune_previous_chain,
                                            });
                                            ctx.abuse_metrics
                                                .ratchet_decrypt_total
                                                .fetch_add(1, Ordering::Relaxed);
                                            ctx.abuse_metrics
                                                .messages_decrypted_total
                                                .fetch_add(1, Ordering::Relaxed);
                                            ctx.abuse_metrics
                                                .v4_messages_received_total
                                                .fetch_add(1, Ordering::Relaxed);
                                            Some((payload, plaintext))
                                        }
                                        Err(error) => {
                                            ctx.abuse_metrics
                                                .ratchet_decrypt_failed_total
                                                .fetch_add(1, Ordering::Relaxed);
                                            log::warn!(
                                                "V4 transition candidate did not authenticate event {}: {error}",
                                                event.id
                                            );
                                            continue;
                                        }
                                    }
                                } else {
                                    let preview = ctx
                                        .session_store
                                        .lock()
                                        .await
                                        .prepare_receive_with_skipped_at(
                                            &node_id,
                                            counter,
                                            expected_generation,
                                            now,
                                        );
                                    match preview {
                                        Ok(preview) => {
                                            let out_of_order = preview.is_out_of_order();
                                            match payload.decrypt_v4(&preview.target_key, &event.id)
                                            {
                                                Ok(plaintext) => {
                                                    pending_ratchet_receive =
                                                        Some(PendingRatchetReceive {
                                                            peer: node_id.clone(),
                                                            preview: Some(preview),
                                                            out_of_order,
                                                            v4_transition: None,
                                                            v4_counter: counter,
                                                            generation: expected_generation,
                                                            prune_previous_chain: None,
                                                        });
                                                    ctx.abuse_metrics
                                                        .ratchet_decrypt_total
                                                        .fetch_add(1, Ordering::Relaxed);
                                                    ctx.abuse_metrics
                                                        .messages_decrypted_total
                                                        .fetch_add(1, Ordering::Relaxed);
                                                    ctx.abuse_metrics
                                                        .v4_messages_received_total
                                                        .fetch_add(1, Ordering::Relaxed);
                                                    Some((payload, plaintext))
                                                }
                                                Err(error) => {
                                                    let mut pending = Some(PendingRatchetReceive {
                                                        peer: node_id.clone(),
                                                        preview: Some(preview),
                                                        out_of_order,
                                                        v4_transition: None,
                                                        v4_counter: counter,
                                                        generation: expected_generation,
                                                        prune_previous_chain: None,
                                                    });
                                                    abort_pending_ratchet_receive(
                                                        ctx.as_ref(),
                                                        &mut pending,
                                                        &event.id,
                                                    )
                                                    .await;
                                                    ctx.abuse_metrics
                                                        .ratchet_decrypt_failed_total
                                                        .fetch_add(1, Ordering::Relaxed);
                                                    log::warn!(
                                                        "V4 MessageAdded decryption failed for event {}: {error}",
                                                        event.id
                                                    );
                                                    continue;
                                                }
                                            }
                                        }
                                        Err(error) => {
                                            ctx.abuse_metrics
                                                .ratchet_decrypt_failed_total
                                                .fetch_add(1, Ordering::Relaxed);
                                            log::warn!(
                                                "V4 ratchet receive preparation failed for event {}: {error}",
                                                event.id
                                            );
                                            continue;
                                        }
                                    }
                                }
                            } else {
                                let preview = ctx
                                    .session_store
                                    .lock()
                                    .await
                                    .prepare_receive_with_skipped_at(
                                        &node_id,
                                        counter,
                                        expected_generation,
                                        now,
                                    );
                                match preview {
                                    Ok(preview) => {
                                        let out_of_order = preview.is_out_of_order();
                                        match payload.decrypt_v4(&preview.target_key, &event.id) {
                                            Ok(plaintext) => {
                                                pending_ratchet_receive =
                                                    Some(PendingRatchetReceive {
                                                        peer: node_id.clone(),
                                                        preview: Some(preview),
                                                        out_of_order,
                                                        v4_transition: None,
                                                        v4_counter: counter,
                                                        generation: expected_generation,
                                                        prune_previous_chain: None,
                                                    });
                                                ctx.abuse_metrics
                                                    .ratchet_decrypt_total
                                                    .fetch_add(1, Ordering::Relaxed);
                                                ctx.abuse_metrics
                                                    .messages_decrypted_total
                                                    .fetch_add(1, Ordering::Relaxed);
                                                ctx.abuse_metrics
                                                    .v4_messages_received_total
                                                    .fetch_add(1, Ordering::Relaxed);
                                                Some((payload, plaintext))
                                            }
                                            Err(error) => {
                                                let mut pending = Some(PendingRatchetReceive {
                                                    peer: node_id.clone(),
                                                    preview: Some(preview),
                                                    out_of_order,
                                                    v4_transition: None,
                                                    v4_counter: counter,
                                                    generation: expected_generation,
                                                    prune_previous_chain: None,
                                                });
                                                abort_pending_ratchet_receive(
                                                    ctx.as_ref(),
                                                    &mut pending,
                                                    &event.id,
                                                )
                                                .await;
                                                ctx.abuse_metrics
                                                    .ratchet_decrypt_failed_total
                                                    .fetch_add(1, Ordering::Relaxed);
                                                continue;
                                            }
                                        }
                                    }
                                    Err(error) => {
                                        ctx.abuse_metrics
                                            .ratchet_decrypt_failed_total
                                            .fetch_add(1, Ordering::Relaxed);
                                        log::warn!(
                                            "V4 current-chain receive failed for event {}: {error}",
                                            event.id
                                        );
                                        continue;
                                    }
                                }
                            }
                        } else {
                            None
                        }
                    }
                    Ok(value)
                        if matches!(
                            value.get("version").and_then(|value| value.as_u64()),
                            Some(3 | 4)
                        ) =>
                    {
                        ctx.abuse_metrics
                            .ratchet_parse_failed_total
                            .fetch_add(1, Ordering::Relaxed);
                        ctx.abuse_metrics
                            .ratchet_decrypt_failed_total
                            .fetch_add(1, Ordering::Relaxed);
                        log::warn!(
                            "rejecting malformed ratchet MessageAdded event {}",
                            event.id
                        );
                        continue;
                    }
                    Ok(_) => None,
                    Err(error) => {
                        ctx.abuse_metrics
                            .ratchet_parse_failed_total
                            .fetch_add(1, Ordering::Relaxed);
                        log::warn!("invalid MessageAdded JSON for event {}: {error}", event.id);
                        continue;
                    }
                }
            } else {
                None
            };
            if decrypted_message.is_some() {
                if let Some(policy) = contact_policy_after_verify {
                    update_contact_policy(&ctx, &node_id, policy).await;
                }
            }
            if let Some(storage) = &ctx.storage {
                let storage_result = (|| -> Result<bool> {
                    let mut storage = storage
                        .lock()
                        .map_err(|_| anyhow!("storage lock poisoned"))?;
                    if let Some(payload) = group_create.as_ref() {
                        storage.store_group_invite(
                            &payload.group_id,
                            &payload.name,
                            payload.avatar_b64.as_deref(),
                            &payload.members,
                        )?;
                    }
                    if let Some(payload) = group_key_distribution.as_ref() {
                        storage.set_group_key(&payload.group_id, &payload.group_key)?;
                    }
                    let sync_storage = storage.sync_storage();
                    let event_type = format!("{:?}", event.event_type);
                    let is_new = if let Some((payload, plaintext, reply_to_id)) =
                        decrypted_group_message.as_ref()
                    {
                        sync_storage.record_decrypted_message_event_with_reply(
                            &event.id,
                            &payload.message_id,
                            &event_type,
                            &event.data,
                            event.timestamp,
                            &event.signature,
                            &payload.group_id,
                            &payload.sender_id,
                            plaintext,
                            Some(&payload.group_id),
                            reply_to_id.as_deref(),
                        )?
                    } else if let (Some(_), Some((payload, plaintext))) =
                        (pending_ratchet_receive.as_ref(), decrypted_message.as_ref())
                    {
                        let sender_public_key = (envelope.identity_id == payload.sender_id())
                            .then_some(envelope.public_key.as_str());
                        let chat_id = incoming_message_chat_id(
                            payload.chat_id(),
                            payload.group_id.as_deref(),
                            sender_public_key,
                        );
                        if payload.group_id.is_none() && sender_public_key.is_some() {
                            log::info!(
                                target: "HAL_DHT",
                                "incoming direct message routed to authenticated sender chat key (chat_id_len={})",
                                chat_id.len()
                            );
                        }
                        sync_storage.record_decrypted_message_event_with_sender_key(
                            &event.id,
                            &event.id,
                            &event_type,
                            &event.data,
                            event.timestamp,
                            &event.signature,
                            chat_id,
                            payload.sender_id(),
                            plaintext,
                            payload.group_id.as_deref(),
                            payload.reply_to_id.as_deref(),
                            sender_public_key,
                        )?
                    } else {
                        sync_storage.record_event(
                            &event.id,
                            &event_type,
                            &event.data,
                            event.timestamp,
                            &event.signature,
                        )?
                    };
                    if !is_new {
                        return Ok(false);
                    }
                    match event.event_type {
                        crate::SyncEventType::ContactAdded
                        | crate::SyncEventType::ContactUpdated => {
                            let _ = sync_storage.apply_contact_added(&event.data);
                        }
                        crate::SyncEventType::ContactDeleted => {
                            let _ = sync_storage.apply_contact_deleted(&event.data);
                        }
                        crate::SyncEventType::MessageAdded => {
                            if let Some((payload, plaintext)) = decrypted_message.as_ref() {
                                if pending_ratchet_receive.is_none() {
                                    let sender_public_key = (envelope.identity_id
                                        == payload.sender_id())
                                    .then_some(envelope.public_key.as_str());
                                    let chat_id = incoming_message_chat_id(
                                        payload.chat_id(),
                                        payload.group_id.as_deref(),
                                        sender_public_key,
                                    );
                                    if payload.group_id.is_none() && sender_public_key.is_some() {
                                        log::info!(
                                            target: "HAL_DHT",
                                            "applying incoming direct message under authenticated sender chat key (chat_id_len={})",
                                            chat_id.len()
                                        );
                                    }
                                    if let Err(error) = sync_storage
                                        .apply_decrypted_message_added_with_sender_key(
                                            &event.id,
                                            chat_id,
                                            payload.sender_id(),
                                            plaintext,
                                            event.timestamp,
                                            payload.group_id.as_deref(),
                                            payload.reply_to_id.as_deref(),
                                            sender_public_key,
                                        )
                                    {
                                        log::error!(
                                            "failed storing decrypted message {}: {error}",
                                            event.id
                                        );
                                    } else if payload.group_id.is_none()
                                        && sender_public_key.is_some()
                                    {
                                        log::info!(
                                            target: "HAL_DHT",
                                            "incoming direct message stored under authenticated sender chat key"
                                        );
                                    }
                                }
                            } else if let Ok(value) =
                                serde_json::from_str::<serde_json::Value>(&event.data)
                            {
                                let encrypted_version =
                                    value.get("version").and_then(|v| v.as_u64());
                                let recipient_is_local =
                                    value.get("recipient_id").and_then(|v| v.as_str())
                                        == Some(ctx.identity_id.as_str());
                                if !matches!(encrypted_version, Some(2 | 3 | 4))
                                    || recipient_is_local
                                {
                                    if let Err(error) = sync_storage.apply_message_added(
                                        &event.id,
                                        &event.data,
                                        event.timestamp,
                                    ) {
                                        log::error!(
                                            "failed applying MessageAdded {}: {error}",
                                            event.id
                                        );
                                    }
                                }
                            }
                        }
                        crate::SyncEventType::SettingsUpdated => {
                            if let Err(error) =
                                sync_storage.apply_settings_updated(&event.data, event.timestamp)
                            {
                                log::error!(
                                    "failed applying SettingsUpdated {}: {error}",
                                    event.id
                                );
                            }
                        }
                        crate::SyncEventType::MessageRead => {
                            if let Some(payload) = message_read.as_ref() {
                                if let Err(error) = storage.mark_message_read(&payload.message_id) {
                                    log::error!(
                                        "failed applying MessageRead {}: {error}",
                                        event.id
                                    );
                                }
                            }
                        }
                        crate::SyncEventType::ProfileUpdate => {
                            if let Some(payload) = profile_update.as_ref() {
                                if let Err(error) = sync_storage.apply_contact_profile_update(
                                    &envelope.public_key,
                                    &payload.display_name,
                                    payload.avatar_b64.as_deref(),
                                ) {
                                    log::error!(
                                        "failed applying ProfileUpdate {}: {error}",
                                        event.id
                                    );
                                }
                            }
                        }
                        crate::SyncEventType::FileTransferInit
                        | crate::SyncEventType::FileTransferChunk
                        | crate::SyncEventType::FileTransferComplete
                        | crate::SyncEventType::FileTransferCancel => {
                            if let Err(error) = apply_incoming_file_transfer_event(
                                &mut storage,
                                &ctx.identity_id,
                                &event,
                                &sender_identity_id,
                                &envelope.public_key,
                            ) {
                                log::warn!(
                                    "failed applying file-transfer event {}: {error}",
                                    event.id
                                );
                            }
                        }
                        crate::SyncEventType::GroupCreate
                        | crate::SyncEventType::GroupKeyDistribution
                        | crate::SyncEventType::GroupMessage => {}
                        crate::SyncEventType::HomeLinkRequest
                        | crate::SyncEventType::HomeLinkResponse
                        | crate::SyncEventType::HomeLinkConfirm
                        | crate::SyncEventType::HomeSyncChunk
                        | crate::SyncEventType::HomeSyncAck
                        | crate::SyncEventType::DraftUpdate
                        | crate::SyncEventType::SasPairing
                        | crate::SyncEventType::RelayRequest
                        | crate::SyncEventType::RelayResponse
                        | crate::SyncEventType::RelayForward
                        | crate::SyncEventType::X3dhInit
                        | crate::SyncEventType::X3dhRespond
                        | crate::SyncEventType::JuryInvitation
                        | crate::SyncEventType::JuryInvitationResponse
                        | crate::SyncEventType::JuryShareDelivery
                        | crate::SyncEventType::JuryShareAck
                        | crate::SyncEventType::JuryEvidenceDelivery
                        | crate::SyncEventType::JuryVerdictPrivate
                        | crate::SyncEventType::InviteRedemptionRequest
                        | crate::SyncEventType::InviteRedemptionResponse
                        | crate::SyncEventType::PeerPresence => {}
                    }
                    Ok(true)
                })();
                match storage_result {
                    #[cfg(not(target_os = "android"))]
                    Ok(true) if event.event_type == SyncEventType::MessageAdded => {
                        log::info!(
                            "Desktop: message stored event_id={} sender={}",
                            event.id,
                            sender_identity_id
                        );
                    }
                    Ok(true) => {}
                    Ok(false) => {
                        abort_pending_ratchet_receive(
                            ctx.as_ref(),
                            &mut pending_ratchet_receive,
                            &event.id,
                        )
                        .await;
                        continue;
                    }
                    Err(error) => {
                        if pending_ratchet_receive.is_some() {
                            ctx.abuse_metrics
                                .ratchet_persist_failed_total
                                .fetch_add(1, Ordering::Relaxed);
                            abort_pending_ratchet_receive(
                                ctx.as_ref(),
                                &mut pending_ratchet_receive,
                                &event.id,
                            )
                            .await;
                        }
                        log::error!("failed applying sync event {}: {error}", event.id);
                        continue;
                    }
                }
                if pending_ratchet_receive.is_some() {
                    let committed = commit_pending_ratchet_receive(
                        ctx.as_ref(),
                        &mut pending_ratchet_receive,
                        unix_now(),
                        &event.id,
                    )
                    .await;
                    drop(_receive_guard.take());
                    if !committed {
                        continue;
                    }
                    persist_session_nonfatal(ctx.as_ref(), &node_id, "receive commit").await;
                }
            }
            match event.event_type {
                SyncEventType::JuryInvitation
                | SyncEventType::JuryInvitationResponse
                | SyncEventType::JuryShareDelivery
                | SyncEventType::JuryShareAck
                | SyncEventType::JuryEvidenceDelivery
                | SyncEventType::JuryVerdictPrivate => {
                    match NodeId::from_hex(&sender_identity_id) {
                        Ok(sender_node_id) => {
                            let result = match event.event_type {
                                SyncEventType::JuryInvitation => {
                                    crate::jury_delivery::handle_jury_invitation(
                                        &ctx,
                                        &event,
                                        sender_node_id.as_bytes(),
                                        now,
                                    )
                                    .await
                                }
                                SyncEventType::JuryInvitationResponse => {
                                    crate::jury_delivery::handle_jury_invitation_response(
                                        &ctx,
                                        &event,
                                        sender_node_id.as_bytes(),
                                        now,
                                    )
                                    .await
                                }
                                SyncEventType::JuryShareDelivery => {
                                    crate::jury_delivery::handle_jury_share_delivery(
                                        &ctx,
                                        &event,
                                        sender_node_id.as_bytes(),
                                        now,
                                    )
                                    .await
                                }
                                SyncEventType::JuryShareAck => {
                                    crate::jury_delivery::handle_jury_share_ack(
                                        &ctx,
                                        &event,
                                        sender_node_id.as_bytes(),
                                        now,
                                    )
                                    .await
                                }
                                SyncEventType::JuryEvidenceDelivery => {
                                    crate::jury_evidence_delivery::handle_jury_evidence_delivery(
                                        &ctx,
                                        &event,
                                        sender_node_id.as_bytes(),
                                        &verifying_key,
                                        now,
                                    )
                                    .await
                                }
                                SyncEventType::JuryVerdictPrivate => {
                                    crate::jury_verdict_private::handle_jury_verdict_private(
                                        &ctx,
                                        &event,
                                        sender_node_id.as_bytes(),
                                        &verifying_key,
                                        now,
                                    )
                                    .await
                                }
                                _ => continue,
                            };
                            if let Err(error) = result {
                                log::warn!(
                                    "invalid jury delivery event {} from {}: {error}",
                                    event.id,
                                    sender_identity_id
                                );
                            }
                        }
                        Err(error) => log::warn!(
                            "invalid sender identity for jury delivery event {}: {error}",
                            event.id
                        ),
                    }
                }
                SyncEventType::InviteRedemptionRequest
                | SyncEventType::InviteRedemptionResponse => {
                    match NodeId::from_hex(&sender_identity_id) {
                        Ok(sender_node_id) => {
                            let result = match event.event_type {
                                SyncEventType::InviteRedemptionRequest => {
                                    crate::invite_redemption::handle_invite_redemption_request(
                                        &ctx,
                                        &event,
                                        sender_node_id.as_bytes(),
                                        &verifying_key,
                                        now,
                                    )
                                    .await
                                }
                                SyncEventType::InviteRedemptionResponse => {
                                    crate::invite_redemption::handle_invite_redemption_response(
                                        &ctx,
                                        &event,
                                        sender_node_id.as_bytes(),
                                        &verifying_key,
                                        now,
                                    )
                                    .await
                                }
                                _ => continue,
                            };
                            if let Err(error) = result {
                                log::warn!(
                                    "invalid invite redemption event {} from {}: {error}",
                                    event.id,
                                    sender_identity_id
                                );
                            }
                        }
                        Err(error) => log::warn!(
                            "invalid sender identity for invite redemption event {}: {error}",
                            event.id
                        ),
                    }
                }
                SyncEventType::HomeLinkRequest => {
                    match serde_json::from_str::<LinkRequest>(&event.data) {
                        Err(error) => log::warn!(
                            "invalid HomeLinkRequest JSON in event {} from {}: {error}",
                            event.id,
                            sender_identity_id
                        ),
                        Ok(request) => match request.verify() {
                            Err(error) => log::warn!(
                                "invalid HomeLinkRequest signature/data in event {} from {}: {error}",
                                event.id,
                                sender_identity_id
                            ),
                            Ok(()) => {
                                let remote_addr = meta.remote_addr.map(|address| {
                                    crate::transport::inferred_lan_peer_listener_address(address)
                                        .unwrap_or(address)
                                });
                                ctx.home_state
                                    .lock()
                                    .await
                                    .pending_requests
                                    .insert(
                                        request.nonce.clone(),
                                        PendingLinkRequest {
                                            request,
                                            remote_addr,
                                        },
                                    );
                                log::info!(
                                    "accepted HomeLinkRequest event {} from {}",
                                    event.id,
                                    sender_identity_id
                                );
                            }
                        }
                    }
                }
                SyncEventType::HomeLinkResponse => {
                    if let Ok(response) = serde_json::from_str::<LinkResponse>(&event.data) {
                        if response.verify().is_ok() {
                            ctx.home_state
                                .lock()
                                .await
                                .pending_responses
                                .insert(response.link_nonce.clone(), response);
                        }
                    }
                }
                SyncEventType::HomeLinkConfirm => {
                    if let Ok(confirm) = serde_json::from_str::<LinkConfirm>(&event.data) {
                        ctx.home_state
                            .lock()
                            .await
                            .pending_confirms
                            .insert(confirm.link_nonce.clone(), confirm);
                    }
                }
                SyncEventType::HomeSyncAck => {
                    let ack = serde_json::from_str::<HomeSyncAck>(&event.data);
                    match ack {
                        Ok(ack) if ack.transfer_id.len() <= 64 && ack.digest.len() == 64 => {
                            let peer_public_key = hex::encode(&pubkey_bytes);
                            let linked_device = ctx
                                .home_state
                                .lock()
                                .await
                                .linked_device_pubkeys
                                .contains(&peer_public_key);
                            if !linked_device {
                                log::warn!(
                                    "ignored Home sync acknowledgement from unlinked device {}",
                                    sender_identity_id
                                );
                                continue;
                            }
                            let Some(storage) = ctx.storage.as_ref() else {
                                log::warn!(
                                    "ignored Home sync acknowledgement without client storage"
                                );
                                continue;
                            };
                            match storage
                                .lock()
                                .map_err(|_| anyhow!("client storage lock poisoned"))
                                .and_then(|storage| {
                                    storage.acknowledge_home_sync_snapshot(
                                        &peer_public_key,
                                        &ack.transfer_id,
                                        &ack.digest,
                                    )
                                }) {
                                Ok(true) => log::info!(
                                    "Home sync snapshot {} acknowledged by {}",
                                    ack.transfer_id,
                                    sender_identity_id
                                ),
                                Ok(false) => log::debug!(
                                    "ignored stale Home sync acknowledgement {}",
                                    ack.transfer_id
                                ),
                                Err(error) => {
                                    log::error!("failed to acknowledge Home sync snapshot: {error}")
                                }
                            }
                        }
                        Ok(_) => log::warn!("rejected malformed Home sync acknowledgement"),
                        Err(error) => {
                            log::warn!("rejected invalid Home sync acknowledgement: {error}")
                        }
                    }
                }
                SyncEventType::DraftUpdate => {
                    let update = serde_json::from_str::<HomeDraftUpdate>(&event.data);
                    match update {
                        Ok(update)
                            if !update.chat_id.is_empty()
                                && update.chat_id.len() <= 128
                                && update.text.len() <= 16 * 1024
                                && update.updated_at > 0 =>
                        {
                            let source_public_key = hex::encode(&pubkey_bytes);
                            let linked_device = ctx
                                .home_state
                                .lock()
                                .await
                                .linked_device_pubkeys
                                .contains(&source_public_key);
                            if !linked_device {
                                log::warn!(
                                    "ignored DraftUpdate from unlinked device {}",
                                    sender_identity_id
                                );
                                continue;
                            }
                            let Some(storage) = ctx.storage.as_ref() else {
                                log::warn!("ignored DraftUpdate without client storage");
                                continue;
                            };
                            match storage
                                .lock()
                                .map_err(|_| anyhow!("client storage lock poisoned"))
                                .and_then(|storage| {
                                    storage.upsert_home_sync_draft(
                                        &update.chat_id,
                                        &update.text,
                                        update.updated_at,
                                    )
                                }) {
                                Ok(true) => log::info!(
                                    "DraftUpdate received chat={} from {}",
                                    update.chat_id,
                                    sender_identity_id
                                ),
                                Ok(false) => log::debug!(
                                    "ignored stale DraftUpdate for chat={}",
                                    update.chat_id
                                ),
                                Err(error) => {
                                    log::error!("failed to store DraftUpdate: {error:#}")
                                }
                            }
                        }
                        Ok(_) => log::warn!("rejected malformed DraftUpdate"),
                        Err(error) => log::warn!("rejected invalid DraftUpdate: {error}"),
                    }
                }
                SyncEventType::HomeSyncChunk => {
                    let chunk = serde_json::from_str::<HomeSyncChunk>(&event.data);
                    match chunk {
                        Ok(chunk)
                            if chunk.version == 1
                                && chunk.total > 0
                                && chunk.total <= 4096
                                && chunk.index < chunk.total
                                && chunk.transfer_id.len() <= 64
                                && chunk.encrypted.ciphertext.len()
                                    <= crate::home::sync::HOME_SYNC_CHUNK_BYTES + 16 =>
                        {
                            let mut state = ctx.home_state.lock().await;
                            let source_public_key = hex::encode(&pubkey_bytes);
                            let linked_device =
                                state.linked_device_pubkeys.contains(&source_public_key);
                            let approved_link_primary = state
                                .pending_responses
                                .values()
                                .any(|response| response.primary_pubkey == source_public_key);
                            if !linked_device && !approved_link_primary {
                                log::warn!(
                                    "ignored Home sync chunk from unlinked device {}",
                                    sender_identity_id
                                );
                                continue;
                            }
                            if !state
                                .pending_sync_transfers
                                .contains_key(&chunk.transfer_id)
                                && state.pending_sync_transfers.len() >= 2
                            {
                                log::warn!(
                                    "rejected Home sync transfer {}: pending transfer limit reached",
                                    chunk.transfer_id
                                );
                                continue;
                            }
                            let transfer_id = chunk.transfer_id.clone();
                            let transfer_ready = {
                                let transfer = state
                                    .pending_sync_transfers
                                    .entry(transfer_id.clone())
                                    .or_insert_with(|| PendingHomeSyncTransfer {
                                        source_public_key: source_public_key.clone(),
                                        chunks: Vec::new(),
                                    });
                                if transfer.source_public_key != source_public_key {
                                    log::warn!(
                                        "rejected Home sync transfer {} from a conflicting source",
                                        transfer_id
                                    );
                                    continue;
                                }
                                if !transfer
                                    .chunks
                                    .iter()
                                    .any(|existing| existing.index == chunk.index)
                                {
                                    transfer.chunks.push(chunk);
                                }
                                transfer.chunks.first().is_some_and(|first| {
                                    transfer.chunks.len() == first.total as usize
                                })
                            };
                            let complete = transfer_ready
                                && state.home_secret.is_some()
                                && state.linked_device_pubkeys.contains(&source_public_key);
                            drop(state);
                            if complete {
                                if let Err(error) =
                                    apply_complete_home_sync_transfer(&ctx, &transfer_id).await
                                {
                                    log::error!(
                                        "failed applying Home sync transfer {transfer_id}: {error}"
                                    );
                                }
                            }
                        }
                        Ok(chunk) => log::warn!(
                            "rejected malformed Home sync chunk for transfer {}",
                            chunk.transfer_id
                        ),
                        Err(error) => {
                            log::warn!("rejected invalid Home sync chunk: {error}");
                        }
                    }
                }
                SyncEventType::X3dhInit => {
                    let decoded = base64::engine::general_purpose::STANDARD
                        .decode(&event.data)
                        .map_err(|error| anyhow!("invalid X3DH init base64: {error}"))
                        .and_then(|bytes| {
                            serde_json::from_slice::<X3dhInitMessage>(&bytes)
                                .map_err(|error| anyhow!("invalid X3DH init JSON: {error}"))
                        });
                    match decoded {
                        Ok(message) => {
                            if let Err(error) = handle_session_init_in_context(
                                &ctx,
                                message,
                                now,
                                Some(pubkey_bytes),
                            )
                            .await
                            {
                                log::warn!("X3DH init failed: {error}");
                            }
                        }
                        Err(error) => {
                            ctx.abuse_metrics
                                .x3dh_session_failed_total
                                .fetch_add(1, Ordering::Relaxed);
                            log::warn!("X3DH init decode failed: {error}");
                        }
                    }
                    continue;
                }
                SyncEventType::X3dhRespond => {
                    let decoded = base64::engine::general_purpose::STANDARD
                        .decode(&event.data)
                        .map_err(|error| anyhow!("invalid X3DH respond base64: {error}"))
                        .and_then(|bytes| {
                            serde_json::from_slice::<X3dhRespondMessage>(&bytes)
                                .map_err(|error| anyhow!("invalid X3DH respond JSON: {error}"))
                        });
                    match decoded {
                        Ok(message) => {
                            if let Err(error) = handle_session_respond_in_context(
                                &ctx,
                                message,
                                now,
                                Some(pubkey_bytes),
                            )
                            .await
                            {
                                log::warn!("X3DH respond failed: {error}");
                            }
                        }
                        Err(error) => {
                            ctx.abuse_metrics
                                .x3dh_session_failed_total
                                .fetch_add(1, Ordering::Relaxed);
                            log::warn!("X3DH respond decode failed: {error}");
                        }
                    }
                    continue;
                }
                SyncEventType::RelayRequest => {
                    match crate::relay::RelayRequest::from_base64(&event.data) {
                        Ok(request) => {
                            log::info!(
                                target: "HAL_DHT",
                                "RelayRequest received from {} for target {}, forwarding...",
                                request.requester_id.to_hex(),
                                request.target_id.to_hex()
                            );
                            let tx_opt = ctx.relay_tx.lock().await.clone();
                            match tx_opt {
                                Some(tx) => {
                                    let work = RelayWork {
                                        from_identity: sender_identity_id.clone(),
                                        request,
                                        received_at: event.timestamp,
                                        response_sender: meta.session_sender.clone(),
                                    };
                                    if tx.capacity() == 0 {
                                        ctx.relay_metrics
                                            .queue_full_total
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                    if tx.send(work).await.is_ok() {
                                        ctx.relay_metrics
                                            .received_total
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    } else {
                                        ctx.relay_metrics
                                            .queue_closed_total
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                }
                                None => {
                                    ctx.relay_metrics
                                        .queue_closed_total
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                        }
                        Err(error) => {
                            log::warn!("invalid RelayRequest from {}: {error}", sender_identity_id)
                        }
                    }
                }
                SyncEventType::RelayResponse => {
                    match crate::relay::RelayResponse::from_base64(&event.data) {
                        Ok(response) => {
                            if let Ok(nonce_bytes) = hex::decode(&event.id) {
                                if let Ok(nonce) = <[u8; 16]>::try_from(nonce_bytes.as_slice()) {
                                    let mut tracker = ctx.relay_tracker.lock().await;
                                    if let Some(tx) = tracker.remove(&nonce) {
                                        let _ = tx.send(response);
                                    } else {
                                        ctx.relay_metrics
                                            .tracker_orphan_total
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                        Err(error) => log::warn!("invalid RelayResponse: {error}"),
                    }
                }
                SyncEventType::RelayForward => {
                    if depth >= MAX_RELAY_FORWARD_DEPTH {
                        log::warn!("relay forward depth exceeded, dropping");
                        ctx.relay_metrics
                            .forward_rejected_depth
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        continue;
                    }
                    let forward_bytes =
                        match base64::engine::general_purpose::STANDARD.decode(&event.data) {
                            Ok(bytes) => bytes,
                            Err(error) => {
                                log::warn!("invalid RelayForward base64: {error}");
                                continue;
                            }
                        };
                    let forward_value: serde_json::Value =
                        match serde_json::from_slice(&forward_bytes) {
                            Ok(value) => value,
                            Err(error) => {
                                log::warn!("invalid RelayForward JSON: {error}");
                                continue;
                            }
                        };
                    if forward_value
                        .get("requester_consent")
                        .and_then(serde_json::Value::as_str)
                        .is_none()
                    {
                        ctx.abuse_metrics
                            .relay_consent_missing_total
                            .fetch_add(1, Ordering::Relaxed);
                        log::warn!("RelayForward missing requester consent");
                        continue;
                    }
                    let forward: crate::relay::RelayForwardEvent =
                        match serde_json::from_value(forward_value) {
                            Ok(forward) => forward,
                            Err(error) => {
                                log::warn!("invalid RelayForward payload: {error}");
                                continue;
                            }
                        };
                    let inner_bytes = match base64::engine::general_purpose::STANDARD
                        .decode(&forward.inner_envelope_base64)
                    {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            log::warn!("invalid inner envelope base64");
                            continue;
                        }
                    };
                    let inner: SyncEnvelope = match serde_json::from_slice(&inner_bytes) {
                        Ok(inner) => inner,
                        Err(_) => {
                            log::warn!("invalid inner envelope json");
                            continue;
                        }
                    };
                    let inner_pk_bytes: [u8; 32] = match hex::decode(&inner.public_key)
                        .ok()
                        .and_then(|bytes| bytes.try_into().ok())
                    {
                        Some(bytes) => bytes,
                        None => {
                            log::warn!("invalid RelayForward inner public key");
                            ctx.relay_metrics
                                .forward_rejected_binding
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            continue;
                        }
                    };
                    let inner_vk = match VerifyingKey::from_bytes(&inner_pk_bytes) {
                        Ok(key) => key,
                        Err(_) => {
                            log::warn!("invalid RelayForward inner Ed25519 key");
                            ctx.relay_metrics
                                .forward_rejected_binding
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            continue;
                        }
                    };
                    let inner_id = NodeId::from_public_key(&inner_vk);
                    if inner_id != forward.requester_id
                        || inner.public_key != forward.requester_public_key_hex
                        || inner.identity_id != forward.requester_identity_id
                        || inner.identity_id != forward.requester_id.to_hex()
                        || event.id != hex::encode(forward.relay_nonce)
                    {
                        log::warn!("RelayForward requester binding mismatch");
                        ctx.relay_metrics
                            .forward_rejected_binding
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        continue;
                    }
                    if let Err(error) = inner.verify() {
                        ctx.abuse_metrics
                            .relay_inner_verify_failed_total
                            .fetch_add(1, Ordering::Relaxed);
                        log::warn!(
                            "relay inner envelope signature invalid from relay {}: {error}",
                            envelope.identity_id
                        );
                        continue;
                    }
                    ctx.abuse_metrics
                        .relay_inner_verify_ok_total
                        .fetch_add(1, Ordering::Relaxed);

                    let consent =
                        match crate::relay::RelayRequest::from_base64(&forward.requester_consent) {
                            Ok(consent) => consent,
                            Err(error) => {
                                ctx.abuse_metrics
                                    .relay_consent_signature_failed_total
                                    .fetch_add(1, Ordering::Relaxed);
                                log::warn!("invalid requester consent: {error:?}");
                                continue;
                            }
                        };
                    let now = unix_now();
                    let local_id = match NodeId::from_hex(&ctx.identity_id) {
                        Ok(local_id) => local_id,
                        Err(error) => {
                            ctx.abuse_metrics
                                .relay_consent_signature_failed_total
                                .fetch_add(1, Ordering::Relaxed);
                            log::error!("invalid local identity for relay consent: {error}");
                            continue;
                        }
                    };
                    if consent.expires_at <= now {
                        ctx.abuse_metrics
                            .relay_consent_expired_total
                            .fetch_add(1, Ordering::Relaxed);
                        log::warn!("RelayForward requester consent expired");
                        continue;
                    }
                    if consent.target_id != local_id {
                        ctx.abuse_metrics
                            .relay_consent_target_mismatch_total
                            .fetch_add(1, Ordering::Relaxed);
                        log::warn!("RelayForward requester consent targets another node");
                        continue;
                    }
                    if consent.requester_id != forward.requester_id
                        || consent.nonce != forward.relay_nonce
                        || consent.verify(&inner_vk, local_id, now).is_err()
                    {
                        ctx.abuse_metrics
                            .relay_consent_signature_failed_total
                            .fetch_add(1, Ordering::Relaxed);
                        log::warn!("RelayForward requester consent signature or identity invalid");
                        continue;
                    }
                    if consent.envelope_bytes != inner_bytes {
                        ctx.abuse_metrics
                            .relay_consent_content_mismatch_total
                            .fetch_add(1, Ordering::Relaxed);
                        log::warn!(
                            "RelayForward consent does not bind the forwarded envelope bytes"
                        );
                        continue;
                    }
                    {
                        let mut nonce_cache = ctx.relay_nonce_cache.lock().await;
                        nonce_cache.cleanup_expired(now);
                        if nonce_cache.contains(&consent.nonce) {
                            ctx.abuse_metrics
                                .relay_consent_replay_total
                                .fetch_add(1, Ordering::Relaxed);
                            log::warn!("RelayForward requester consent nonce replayed");
                            continue;
                        }
                        if !nonce_cache.insert(consent.nonce, consent.expires_at) {
                            log::error!("RelayForward nonce cache full; rejecting consent");
                            continue;
                        }
                    }
                    ctx.abuse_metrics
                        .relay_consent_verified_total
                        .fetch_add(1, Ordering::Relaxed);
                    ctx.relay_metrics
                        .forward_received_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    relay_forwards.push(inner);
                    continue;
                }
                _ => {}
            }
            let received_event_id = event.id.clone();
            merged_events.push(event);
            if ctx.storage.is_none() {
                if pending_ratchet_receive.is_some()
                    && !commit_pending_ratchet_receive(
                        ctx.as_ref(),
                        &mut pending_ratchet_receive,
                        unix_now(),
                        &received_event_id,
                    )
                    .await
                {
                    merged_events.pop();
                }
            }
        }
        for inner in relay_forwards {
            let next_ctx = Arc::clone(&ctx);
            Box::pin(Self::process_incoming_envelope_verified(
                inner,
                next_ctx,
                depth + 1,
                EnvelopeMeta::default(),
            ))
            .await;
        }
        if !merged_events.is_empty() {
            let mut manager = ctx.sync.lock().await;
            let _ = manager.merge_events(merged_events);
        }
        ctx.oracle.record_message(&node_id, is_stranger, now);
        ctx.trust_metrics.inc_recorded_messages();
    }

    pub async fn add_contact(&self, pubkey: String, name: String) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let node_id =
            pubkey_to_node_id(&pubkey).ok_or_else(|| anyhow!("invalid public key for contact"))?;

        if !self.ctx.oracle.allows_contact_add(&node_id, now) {
            self.ctx.trust_metrics.inc_denies_contact_rate();
            return Err(anyhow!("contact add denied by trust policy"));
        }

        self.ctx.sync.lock().await.sync_contact(pubkey, name)?;

        self.ctx.oracle.record_contact_add(&node_id, now);
        self.ctx.trust_metrics.inc_recorded_contacts();
        Ok(())
    }

    pub async fn add_message(
        &self,
        chat_id: String,
        sender_id: String,
        recipient_id: Option<String>,
        text: String,
    ) -> Result<()> {
        self.add_message_with_reply(chat_id, sender_id, recipient_id, text, None)
            .await
    }

    pub async fn add_message_with_reply(
        &self,
        chat_id: String,
        sender_id: String,
        recipient_id: Option<String>,
        text: String,
        reply_to_id: Option<String>,
    ) -> Result<()> {
        self.add_message_with_reply_and_id(
            chat_id,
            sender_id,
            recipient_id,
            text,
            reply_to_id,
            uuid::Uuid::new_v4().to_string(),
        )
        .await
    }

    pub async fn add_message_with_reply_and_id(
        &self,
        chat_id: String,
        sender_id: String,
        recipient_id: Option<String>,
        text: String,
        reply_to_id: Option<String>,
        message_id: String,
    ) -> Result<()> {
        let recipient_id = recipient_id
            .filter(|identity| !identity.is_empty())
            .ok_or_else(|| anyhow!("direct message requires a recipient identity"))?;
        let recipient_pubkey = self.resolve_recipient_pubkey(&recipient_id).await?;
        self.add_message_with_reply_and_id_for_public_key(
            chat_id,
            sender_id,
            Some(recipient_id),
            recipient_pubkey,
            text,
            reply_to_id,
            message_id,
        )
        .await
    }

    pub async fn add_message_with_reply_and_id_for_public_key(
        &self,
        chat_id: String,
        sender_id: String,
        recipient_id: Option<String>,
        recipient_pubkey: VerifyingKey,
        text: String,
        reply_to_id: Option<String>,
        message_id: String,
    ) -> Result<()> {
        let recipient_id = recipient_id
            .filter(|identity| !identity.is_empty())
            .ok_or_else(|| anyhow!("direct message requires a recipient identity"))?;
        if uuid::Uuid::parse_str(&message_id).is_err() {
            return Err(anyhow!("invalid direct message identifier"));
        }
        self.add_message_encrypted_with_reply(
            chat_id,
            sender_id,
            recipient_id,
            &recipient_pubkey,
            text,
            reply_to_id,
            message_id,
        )
        .await
    }

    async fn resolve_recipient_pubkey(&self, recipient_id: &str) -> Result<VerifyingKey> {
        let now = unix_now();
        let peer_key = self
            .ctx
            .peer_directory
            .lock()
            .await
            .lookup_by_identity(recipient_id, now)
            .map(|entry| entry.public_key_hex.clone());
        let host_key = self
            .ctx
            .hosts
            .lock()
            .map_err(|_| anyhow!("known-hosts lock poisoned"))?
            .record_of(recipient_id)
            .map(|record| record.public_key_hex.clone());
        if peer_key.is_some() && host_key.is_some() && peer_key != host_key {
            return Err(anyhow!(
                "recipient identity has conflicting pinned public keys"
            ));
        }
        let public_key_hex = peer_key.or(host_key).ok_or_else(|| {
            anyhow!("recipient public key is unknown; refusing plaintext fallback")
        })?;
        let public_key_bytes: [u8; 32] = hex::decode(&public_key_hex)
            .map_err(|error| anyhow!("invalid recipient public key encoding: {error}"))?
            .try_into()
            .map_err(|_| anyhow!("recipient public key must be 32 bytes"))?;
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|error| anyhow!("invalid recipient identity key: {error}"))?;
        if NodeId::from_public_key(&verifying_key).to_hex() != recipient_id {
            return Err(anyhow!(
                "recipient public key does not match recipient identity"
            ));
        }
        Ok(verifying_key)
    }

    async fn trigger_ratchet_resync(&self, peer: &NodeId, peer_identity: &str) -> Result<()> {
        self.ctx
            .abuse_metrics
            .ratchet_resync_triggered_total
            .fetch_add(1, Ordering::Relaxed);
        if let Err(error) = self
            .establish_session_as_initiator_for_resync(peer.clone(), unix_now())
            .await
        {
            log::warn!("ratchet session resynchronization failed for {peer_identity}: {error}");
            return Err(anyhow!(
                "ratchet session requires resynchronization; retry after recovery: {error}"
            ));
        }
        log::info!(
            "ratchet session resynchronization started for {peer_identity}; waiting for X3DH response"
        );
        Ok(())
    }

    pub async fn add_message_encrypted(
        &self,
        chat_id: String,
        sender_id: String,
        recipient_id: String,
        recipient_pubkey: &VerifyingKey,
        text: String,
    ) -> Result<()> {
        self.add_message_encrypted_with_reply(
            chat_id,
            sender_id,
            recipient_id,
            recipient_pubkey,
            text,
            None,
            uuid::Uuid::new_v4().to_string(),
        )
        .await
    }

    async fn add_message_encrypted_with_reply(
        &self,
        chat_id: String,
        sender_id: String,
        recipient_id: String,
        recipient_pubkey: &VerifyingKey,
        text: String,
        reply_to_id: Option<String>,
        message_id: String,
    ) -> Result<()> {
        self.add_message_encrypted_with_group(
            chat_id,
            sender_id,
            recipient_id,
            recipient_pubkey,
            text,
            None,
            reply_to_id,
            message_id,
        )
        .await
    }

    async fn add_message_encrypted_with_group(
        &self,
        chat_id: String,
        sender_id: String,
        recipient_id: String,
        recipient_pubkey: &VerifyingKey,
        text: String,
        group_id: Option<String>,
        reply_to_id: Option<String>,
        message_id: String,
    ) -> Result<()> {
        if sender_id != self.identity_id {
            return Err(anyhow!(
                "direct message sender identity does not match local runtime"
            ));
        }
        if NodeId::from_public_key(recipient_pubkey).to_hex() != recipient_id {
            return Err(anyhow!(
                "recipient public key does not match recipient identity"
            ));
        }
        let recipient_node_id = NodeId::from_hex(&recipient_id)
            .map_err(|error| anyhow!("invalid recipient identity: {error}"))?;
        let timestamp = unix_now();
        let session_view = load_session_on_demand(&self.ctx, &recipient_node_id).await?;
        if let Some(view) = session_view.filter(|view| view.needs_resync) {
            self.ctx
                .abuse_metrics
                .ratchet_send_blocked_resync_total
                .fetch_add(1, Ordering::Relaxed);
            if view.responded {
                self.trigger_ratchet_resync(&recipient_node_id, &recipient_id)
                    .await?;
            } else {
                log::info!(
                    "ratchet session resynchronization is pending for {}; waiting for X3DH response",
                    recipient_id
                );
            }
            return Err(crate::SessionError::NeedsResync.into());
        }
        let event_id = message_id;
        let send_lock = {
            let store = self.ctx.session_store.lock().await;
            store
                .get_view(&recipient_node_id)
                .filter(|view| view.responded)
                .map(|_| store.send_lock_with_generation(&recipient_node_id))
                .transpose()
                .map_err(|error| anyhow!("failed to get ratchet send lock: {error}"))?
        };
        let (mut send_guard, send_generation) = match send_lock {
            Some((lock, generation)) => (Some(lock.lock_owned().await), Some(generation)),
            None => (None, None),
        };
        let use_ratchet = send_guard.is_some();
        let contact_policy = self
            .ctx
            .session_store
            .lock()
            .await
            .get(&recipient_node_id)
            .map(|session| session.contact_policy);
        if let Some(policy) = contact_policy {
            let updated = ensure_biometric_if_required(
                self.ctx.biometric_gate.as_ref(),
                &policy,
                &self.ctx.abuse_metrics,
                "Confirm sending a message",
            )
            .await?;
            if updated != policy {
                if let Some(session) = self
                    .ctx
                    .session_store
                    .lock()
                    .await
                    .get_mut(&recipient_node_id)
                {
                    session.contact_policy = updated;
                }
                persist_session_nonfatal(&self.ctx, &recipient_node_id, "contact policy update")
                    .await;
            }
        }
        let mut v4_send_rollback = None;
        let mut v4_advertised = false;
        let (mut payload, ratchet_counter) = if use_ratchet {
            let expected_generation =
                send_generation.ok_or_else(|| anyhow!("ratchet send generation is unavailable"))?;
            let (message_key, counter, v4_fields) = {
                let mut store = self.ctx.session_store.lock().await;
                let session = store
                    .get_mut(&recipient_node_id)
                    .ok_or(crate::SessionError::MissingSession)?;
                let v4_active = is_v4_active(session);
                let initiated =
                    v4_active && session.needs_dh_ratchet() && !session.has_pending_dh_ratchet();
                if v4_active {
                    // Once V4 is negotiated, every ratchet message stays V4 (R3).
                    // The chain id is the current epoch, or the next epoch while a DH
                    // initiation is pending; ordinary V4 messages omit DH fields.
                    if initiated {
                        if let Err(error) = session.dh_ratchet_initiate() {
                            if matches!(error, crate::SessionError::ChainEpochOverflow) {
                                self.ctx
                                    .abuse_metrics
                                    .v4_chain_id_overflow_total
                                    .fetch_add(1, Ordering::Relaxed);
                                log::error!("chain_epoch at u32::MAX, cannot initiate further");
                            } else {
                                self.ctx
                                    .abuse_metrics
                                    .dh_ratchet_failures_total
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            return Err(anyhow!("failed to initiate DH ratchet: {error}"));
                        }
                        self.ctx
                            .abuse_metrics
                            .dh_ratchet_initiations_total
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    let pending = session.has_pending_dh_ratchet();
                    let chain_epoch = if pending {
                        session.chain_epoch.checked_add(1)
                    } else {
                        Some(session.chain_epoch)
                    };
                    let chain_id = chain_epoch
                        .and_then(|epoch| u32::try_from(epoch).ok())
                        .ok_or_else(|| anyhow!("V4 chain_id is outside the wire range"))?;
                    let (sending_chain_key, sending_index) = session.sending_chain.serialize();
                    v4_send_rollback = Some(V4SendRollback {
                        sending_chain_key,
                        sending_index,
                        messages_since_ratchet: session.messages_since_ratchet,
                        prev_chain_length: session.prev_chain_length,
                        last_used_at: session.last_used_at,
                    });
                    let advertisement = session.prev_chain_length.map(|_| session.dh_our_pubkey);
                    let prev_chain_length = advertisement.and_then(|_| session.prev_chain_length);
                    v4_advertised = advertisement.is_some();
                    let message_key = session.sending_chain.peek_next()?;
                    (
                        message_key,
                        session.sending_chain.next_index(),
                        Some((chain_id, advertisement, prev_chain_length)),
                    )
                } else {
                    let message_key = session.sending_chain.peek_next()?;
                    (message_key, session.sending_chain.next_index(), None)
                }
            };
            let payload = if let Some((chain_id, dh_pubkey, prev_chain_length)) = v4_fields {
                crate::MessageAddedPayload::new_ratchet_v4_encrypted(
                    chat_id.clone(),
                    sender_id.clone(),
                    recipient_id.clone(),
                    &text,
                    &message_key,
                    counter,
                    &event_id,
                    timestamp,
                    chain_id,
                    dh_pubkey,
                    prev_chain_length,
                )
            } else {
                crate::MessageAddedPayload::new_ratchet_encrypted(
                    chat_id.clone(),
                    sender_id.clone(),
                    recipient_id.clone(),
                    &text,
                    &message_key,
                    counter,
                    &event_id,
                    timestamp,
                )
            }
            .map_err(|error| {
                self.ctx
                    .abuse_metrics
                    .ratchet_encrypt_failed_total
                    .fetch_add(1, Ordering::Relaxed);
                anyhow!("failed to encrypt ratchet message: {error}")
            })?;
            (payload, Some(counter))
        } else {
            (
                crate::MessageAddedPayload::new_encrypted(
                    chat_id,
                    sender_id.clone(),
                    recipient_id.clone(),
                    recipient_pubkey,
                    &text,
                    timestamp,
                    &event_id,
                )
                .map_err(|error| anyhow!("failed to create encrypted message payload: {error}"))?,
                None,
            )
        };
        payload.group_id = group_id.clone();
        payload.reply_to_id = reply_to_id;
        payload
            .validate()
            .map_err(|error| anyhow!("invalid group message payload: {error}"))?;
        if let Some(storage) = self.ctx.storage.as_ref() {
            let storage = storage
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            storage.sync_storage().record_local_outbound(
                &event_id,
                &sender_id,
                &recipient_id,
                timestamp,
            )?;
        }

        if let Some(counter) = ratchet_counter {
            let is_v4_message = payload.version == crate::journal::MESSAGE_VERSION_V4;
            let persist_result = {
                let mut sync = self.ctx.sync.lock().await;
                sync.add_message_payload_with_id(event_id.clone(), timestamp, payload)
            };
            if let Err(error) = persist_result {
                self.ctx
                    .abuse_metrics
                    .ratchet_encrypt_failed_total
                    .fetch_add(1, Ordering::Relaxed);
                return Err(error);
            }
            let commit_result = self
                .ctx
                .session_store
                .lock()
                .await
                .commit_sending_for_generation(
                    &recipient_node_id,
                    counter,
                    send_generation,
                    timestamp,
                );
            match commit_result {
                Ok(()) => {
                    if is_v4_message {
                        if v4_advertised {
                            if let Some(session) = self
                                .ctx
                                .session_store
                                .lock()
                                .await
                                .get_mut(&recipient_node_id)
                            {
                                session.prev_chain_length = None;
                            }
                        }
                        if let Err(error) =
                            persist_session_required(&self.ctx, &recipient_node_id).await
                        {
                            self.ctx
                                .abuse_metrics
                                .session_persist_failed_total
                                .fetch_add(1, Ordering::Relaxed);
                            if let Some(rollback) = v4_send_rollback.take() {
                                let rollback_result = {
                                    let mut store = self.ctx.session_store.lock().await;
                                    match store.get_mut(&recipient_node_id) {
                                        Some(session) => {
                                            session.sending_chain =
                                                hal_crypto::SymmetricRatchet::from_persisted(
                                                    *rollback.sending_chain_key,
                                                    rollback.sending_index,
                                                );
                                            session.messages_since_ratchet =
                                                rollback.messages_since_ratchet;
                                            session.prev_chain_length = rollback.prev_chain_length;
                                            session.last_used_at = rollback.last_used_at;
                                            Ok(())
                                        }
                                        None => Err(crate::SessionError::MissingSession),
                                    }
                                };
                                if let Err(rollback_error) = rollback_result {
                                    log::error!(
                                        "failed to roll back V4 send after persistence failure: {rollback_error}"
                                    );
                                }
                            }
                            self.ctx.sync.lock().await.remove_unsent_event(&event_id);
                            drop(send_guard.take());
                            return Err(error);
                        }
                        self.ctx
                            .abuse_metrics
                            .v4_messages_sent_total
                            .fetch_add(1, Ordering::Relaxed);
                    } else {
                        persist_session_nonfatal(&self.ctx, &recipient_node_id, "send commit")
                            .await;
                    }
                    drop(send_guard.take());
                    self.ctx
                        .abuse_metrics
                        .ratchet_encrypt_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(error) => {
                    if matches!(error, crate::SessionError::SessionReplaced) {
                        self.ctx
                            .abuse_metrics
                            .ratchet_session_replaced_total
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    if matches!(
                        error,
                        crate::SessionError::CounterMismatch { .. }
                            | crate::SessionError::CounterOverflow
                    ) {
                        self.ctx
                            .abuse_metrics
                            .ratchet_commit_mismatch_total
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    self.ctx
                        .abuse_metrics
                        .ratchet_commit_failed_total
                        .fetch_add(1, Ordering::Relaxed);
                    let marked = self
                        .ctx
                        .session_store
                        .lock()
                        .await
                        .mark_needs_resync(&recipient_node_id);
                    match marked {
                        Ok(true) => {
                            self.ctx
                                .abuse_metrics
                                .ratchet_needs_resync_total
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(false) => {}
                        Err(mark_error) => log::error!(
                            "failed to mark peer session as needing resync: {mark_error}"
                        ),
                    }
                    log::error!("ratchet send commit failed after message persistence: {error}");
                    drop(send_guard.take());
                    match self
                        .trigger_ratchet_resync(&recipient_node_id, &recipient_id)
                        .await
                    {
                        Ok(()) => return Err(crate::SessionError::NeedsResync.into()),
                        Err(resync_error) => {
                            return Err(anyhow!(
                                "message persisted; ratchet send commit failed ({error}); resynchronization failed: {resync_error}"
                            ));
                        }
                    }
                }
            }
        } else {
            let mut sync = self.ctx.sync.lock().await;
            sync.add_message_payload_with_id(event_id, timestamp, payload)?;
            self.ctx
                .abuse_metrics
                .ecies_fallback_total
                .fetch_add(1, Ordering::Relaxed);
        }
        drop(send_guard);
        self.ctx
            .abuse_metrics
            .messages_encrypted_total
            .fetch_add(1, Ordering::Relaxed);
        if group_id.is_none() {
            let peer = self.peers.lock().await.first().cloned();
            if let Some(peer) = peer {
                let _ = self.send_pending(&peer).await;
            }
        }
        Ok(())
    }

    pub async fn create_group_and_invite_members(
        &self,
        group_id: String,
        name: String,
        avatar: Option<String>,
        mut members: Vec<String>,
    ) -> Result<()> {
        let local_public_key = self.public_key.clone();
        members = members
            .iter()
            .map(|member| parse_group_member_key(member).map(|key| hex::encode(key.to_bytes())))
            .collect::<Result<Vec<_>>>()?;
        members.push(local_public_key.clone());
        members.sort();
        members.dedup();
        if members.len() < 2 {
            return Err(anyhow!(
                "a network group must include at least one other member"
            ));
        }
        if members.len() > 500 {
            return Err(anyhow!("group member count exceeds limit"));
        }
        let storage = self
            .ctx
            .storage
            .as_ref()
            .ok_or_else(|| anyhow!("client storage is not initialized"))?;
        storage
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?
            .store_group_invite(&group_id, &name, avatar.as_deref(), &members)?;
        let mut group_key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut group_key[..]);
        let group_key_hex = hex::encode(&group_key[..]);
        storage
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?
            .set_group_key(&group_id, &group_key_hex)?;

        for member in members
            .iter()
            .filter(|member| member.as_str() != local_public_key)
        {
            let public_key = parse_group_member_key(member)?;
            let recipient_id = NodeId::from_public_key(&public_key).to_hex();
            let payload = crate::GroupCreatePayload {
                group_id: group_id.clone(),
                name: name.clone(),
                avatar_b64: avatar.clone(),
                members: members.clone(),
                recipient_id: recipient_id.clone(),
            };
            self.ctx.sync.lock().await.add_group_create_event(payload)?;
            self.ctx
                .sync
                .lock()
                .await
                .add_group_key_distribution_event(crate::GroupKeyDistributionPayload {
                    group_id: group_id.clone(),
                    group_key: group_key_hex.clone(),
                    recipient_id: recipient_id.clone(),
                })?;

            let addresses = self.peer_addresses_of(&recipient_id).await;
            if addresses.is_empty() {
                log::warn!("GroupCreate queued for {recipient_id}; no active address is known yet");
                continue;
            }
            let mut sent = false;
            for address in addresses {
                match self.send_pending_verified(&address, member).await {
                    Ok(()) => {
                        sent = true;
                        break;
                    }
                    Err(error) => log::warn!(
                        "GroupCreate send to {recipient_id} via {address} failed: {error}"
                    ),
                }
            }
            if sent {
                log::info!("GroupCreate delivered to group member {recipient_id}");
            }
        }
        log::info!("generated and stored sender key for group {group_id}");
        Ok(())
    }

    pub async fn send_group_message(&self, group_id: &str, text: &str) -> Result<()> {
        self.send_group_message_with_reply(group_id, text, None, &uuid::Uuid::new_v4().to_string())
            .await
    }

    pub async fn mark_message_read(&self, message_id: &str) -> Result<()> {
        log::info!(
            target: "HAL_READ_RECEIPT",
            "PeerRuntime::mark_message_read entered for message {message_id}"
        );
        let storage = self
            .ctx
            .storage
            .as_ref()
            .ok_or_else(|| anyhow!("client storage is not initialized"))?;
        let target = storage
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?
            .get_message_read_target(message_id)?
            .ok_or_else(|| anyhow!("message to mark read was not found"))?;
        log::info!(
            "mark_message_read message_id={message_id}: sender_id={}, group_id={:?}, chat_id={}",
            target.sender_id,
            target.group_id,
            target.chat_id
        );
        if target.sender_id == "android-local" {
            return Ok(());
        }
        {
            let storage = storage
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            storage.mark_incoming_message_read(message_id)?;
            storage.queue_pending_read_receipt(message_id, &target.sender_id)?;
        }

        let mut discovered_endpoints = Vec::new();
        let (recipient_id, recipient_public_key) = if let Some(group_id) =
            target.group_id.as_deref()
        {
            let group = storage
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?
                .get_group(group_id)?
                .ok_or_else(|| anyhow!("group for read receipt was not found"))?;
            group
                .member_peer_ids
                .iter()
                .find_map(|member| {
                    let public_key = parse_group_member_key(member).ok()?;
                    let identity_id = NodeId::from_public_key(&public_key).to_hex();
                    (identity_id == target.sender_id)
                        .then(|| (identity_id, hex::encode(public_key.to_bytes())))
                })
                .ok_or_else(|| anyhow!("group sender is not a stored member"))?
        } else {
            let stored_public_key = target
                .sender_public_key
                .as_deref()
                .map(|public_key_hex| {
                    let bytes: [u8; 32] = hex::decode(public_key_hex)
                        .map_err(|error| anyhow!("invalid stored sender public key: {error}"))?
                        .try_into()
                        .map_err(|_| anyhow!("stored sender public key must be 32 bytes"))?;
                    let public_key = VerifyingKey::from_bytes(&bytes)
                        .map_err(|error| anyhow!("invalid stored sender public key: {error}"))?;
                    if NodeId::from_public_key(&public_key).to_hex() != target.sender_id {
                        return Err(anyhow!(
                            "stored sender public key does not match {}",
                            target.sender_id
                        ));
                    }
                    Ok(public_key)
                })
                .transpose()?;
            let public_key = match stored_public_key {
                Some(public_key) => public_key,
                None => {
                    let registry_key = storage
                        .lock()
                        .map_err(|_| anyhow!("storage lock poisoned"))?
                        .peer_registry()
                        .public_key_for_identity(&target.sender_id, unix_now())?;
                    let registry_public_key = registry_key
                        .map(|public_key_hex| {
                            let bytes: [u8; 32] = hex::decode(&public_key_hex)
                                .map_err(|error| {
                                    anyhow!("invalid peer registry public key: {error}")
                                })?
                                .try_into()
                                .map_err(|_| {
                                    anyhow!("peer registry public key must be 32 bytes")
                                })?;
                            let public_key = VerifyingKey::from_bytes(&bytes).map_err(|error| {
                                anyhow!("invalid peer registry public key: {error}")
                            })?;
                            if NodeId::from_public_key(&public_key).to_hex() != target.sender_id {
                                return Err(anyhow!(
                                    "peer registry public key does not match {}",
                                    target.sender_id
                                ));
                            }
                            Ok(public_key)
                        })
                        .transpose()?;
                    if let Some(public_key) = registry_public_key {
                        public_key
                    } else {
                        match self.resolve_recipient_pubkey(&target.sender_id).await {
                            Ok(public_key) => public_key,
                            Err(resolve_error) => {
                                log::warn!(
                                    "stored peer key unavailable for read receipt sender {}; trying signed DHT identity record: {resolve_error}",
                                    target.sender_id
                                );
                                let record = match tokio::time::timeout(
                                    Duration::from_secs(3),
                                    self.lookup_endpoints(&target.sender_id, unix_now()),
                                )
                                .await
                                {
                                    Err(_) => {
                                        log::error!(
                                            "Missing pubkey for sender_id: {}",
                                            target.sender_id
                                        );
                                        return Err(anyhow!(
                                            "sender public key lookup timed out for read receipt {}",
                                            target.sender_id
                                        ));
                                    }
                                    Ok(Err(error)) => {
                                        log::error!(
                                            "Missing pubkey for sender_id: {}",
                                            target.sender_id
                                        );
                                        return Err(error);
                                    }
                                    Ok(Ok(None)) => {
                                        log::error!(
                                            "Missing pubkey for sender_id: {}",
                                            target.sender_id
                                        );
                                        return Err(anyhow!(
                                            "sender public key is unknown and no DHT identity record exists for {}",
                                            target.sender_id
                                        ));
                                    }
                                    Ok(Ok(Some(record))) => record,
                                };
                                let public_key_bytes: [u8; 32] = hex::decode(&record.public_key)
                                    .map_err(|error| anyhow!("invalid DHT public key: {error}"))?
                                    .try_into()
                                    .map_err(|_| anyhow!("DHT public key must contain 32 bytes"))?;
                                let public_key = VerifyingKey::from_bytes(&public_key_bytes)
                                    .map_err(|error| anyhow!("invalid DHT public key: {error}"))?;
                                if record.identity_id != target.sender_id
                                    || NodeId::from_public_key(&public_key).to_hex()
                                        != target.sender_id
                                {
                                    return Err(anyhow!(
                                        "DHT identity key did not match read receipt sender {}",
                                        target.sender_id
                                    ));
                                }
                                discovered_endpoints = record.endpoints;
                                public_key
                            }
                        }
                    }
                }
            };
            (target.sender_id.clone(), hex::encode(public_key.to_bytes()))
        };

        let read_event_is_pending =
            self.ctx
                .sync
                .lock()
                .await
                .get_pending_events()
                .iter()
                .any(|event| {
                    event.event_type == crate::SyncEventType::MessageRead
                        && serde_json::from_str::<crate::MessageReadPayload>(&event.data).is_ok_and(
                            |payload| {
                                payload.message_id == message_id
                                    && payload.reader_id == self.identity_id
                                    && payload.recipient_id == recipient_id
                            },
                        )
                });
        if !read_event_is_pending {
            self.ctx
                .sync
                .lock()
                .await
                .add_message_read_event(crate::MessageReadPayload {
                    message_id: message_id.to_owned(),
                    reader_id: self.identity_id.clone(),
                    recipient_id: recipient_id.clone(),
                })?;
        }

        let mut addresses = self.peer_addresses_of(&recipient_id).await;
        if addresses.is_empty() {
            if let Some(address) = self.last_known_peer_address(&recipient_id).await? {
                log::info!(
                    "using persisted peer address for read receipt recipient {recipient_id}"
                );
                addresses.push(address);
            }
        }
        if addresses.is_empty() {
            addresses = std::mem::take(&mut discovered_endpoints);
        }
        if addresses.is_empty() {
            log::info!(
                "no active peer address for read receipt recipient {recipient_id}; trying DHT lookup"
            );
            match tokio::time::timeout(
                Duration::from_secs(3),
                self.lookup_endpoints(&recipient_id, unix_now()),
            )
            .await
            {
                Ok(Ok(Some(record))) => {
                    let lookup_key = hex::decode(&record.public_key)
                        .ok()
                        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                        .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok());
                    let record_identity = lookup_key
                        .as_ref()
                        .map(|key| NodeId::from_public_key(key).to_hex());
                    if record.identity_id != recipient_id
                        || record_identity.as_deref() != Some(recipient_id.as_str())
                    {
                        return Err(anyhow!(
                            "DHT endpoint identity did not match read receipt recipient {recipient_id}"
                        ));
                    }
                    addresses = record.endpoints;
                    log::info!(
                        "DHT lookup found {} endpoint(s) for read receipt recipient {recipient_id}",
                        addresses.len()
                    );
                }
                Ok(Ok(None)) => log::warn!(
                    "DHT lookup found no endpoint record for read receipt recipient {recipient_id}"
                ),
                Ok(Err(error)) => log::warn!(
                    "DHT lookup failed for read receipt recipient {recipient_id}: {error}"
                ),
                Err(_) => {
                    log::warn!("DHT lookup timed out for read receipt recipient {recipient_id}")
                }
            }
        }
        addresses.sort_by_key(|address| {
            address
                .parse::<std::net::SocketAddr>()
                .map(|address| !crate::transport::is_lan_address(&address))
                .unwrap_or(true)
        });
        log::info!(
            target: "HAL_READ_RECEIPT",
            "read receipt recipient {recipient_id} candidate addresses: {}",
            addresses.join(", ")
        );
        if addresses.is_empty() {
            return Err(anyhow!(
                "no active or DHT endpoint is available for read receipt recipient {recipient_id}"
            ));
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut last_error = None;
        for address in addresses {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                last_error = Some(anyhow!("5-second address budget expired"));
                break;
            }
            match tokio::time::timeout(
                remaining,
                self.send_pending_verified(&address, &recipient_public_key),
            )
            .await
            {
                Ok(Ok(())) => {
                    log::info!("MessageRead sent for message {message_id} to {recipient_id}");
                    storage
                        .lock()
                        .map_err(|_| anyhow!("storage lock poisoned"))?
                        .remove_pending_read_receipt(message_id)?;
                    return Ok(());
                }
                Ok(Err(error)) => {
                    log::warn!(
                        target: "HAL_READ_RECEIPT",
                        "read receipt send to {address} failed: {error}"
                    );
                    last_error = Some(error);
                }
                Err(_) => {
                    last_error = Some(anyhow!("send timed out after the 5-second address budget"));
                    break;
                }
            }
        }
        if let Some(error) = last_error {
            log::warn!("MessageRead remains queued for {recipient_id}: {error}");
            return Err(anyhow!("{error}"));
        }
        Err(anyhow!(
            "no address attempt was made for read receipt recipient {recipient_id}"
        ))
    }

    pub async fn retry_pending_read_receipts(&self) -> Result<usize> {
        let storage = self
            .ctx
            .storage
            .as_ref()
            .ok_or_else(|| anyhow!("client storage is not initialized"))?;
        let pending = storage
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?
            .pending_read_receipts(3)?;
        let mut sent = 0;
        for receipt in pending {
            match self.mark_message_read(&receipt.message_id).await {
                Ok(()) => sent += 1,
                Err(error) => log::warn!(
                    "pending read receipt for {} remains queued: {error}",
                    receipt.message_id
                ),
            }
        }
        Ok(sent)
    }

    pub async fn send_group_message_with_reply(
        &self,
        group_id: &str,
        text: &str,
        reply_to_id: Option<&str>,
        message_id: &str,
    ) -> Result<()> {
        if text.trim().is_empty() || text.len() > 4096 {
            return Err(anyhow!("group message is empty or exceeds the size limit"));
        }
        if uuid::Uuid::parse_str(message_id).is_err()
            || reply_to_id.is_some_and(|reply_id| reply_id.is_empty() || reply_id.len() > 128)
        {
            return Err(anyhow!("invalid group message or reply identifier"));
        }
        let storage = self
            .ctx
            .storage
            .as_ref()
            .ok_or_else(|| anyhow!("client storage is not initialized"))?;
        let group = storage
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?
            .get_group(group_id)?
            .ok_or_else(|| anyhow!("group does not exist"))?;
        let group_key_hex = storage
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?
            .get_group_key(group_id)?
            .ok_or_else(|| anyhow!("group sender key is not available"))?;
        let key = hex::decode(&group_key_hex)
            .map_err(|error| anyhow!("stored group key encoding is invalid: {error}"))?;
        let key: Zeroizing<[u8; 32]> = Zeroizing::new(
            key.try_into()
                .map_err(|_| anyhow!("stored group key has an invalid length"))?,
        );
        let local_public_key = self.public_key.clone();
        let recipient_count = group
            .member_peer_ids
            .iter()
            .filter(|member| member.as_str() != local_public_key)
            .count();
        if recipient_count == 0 {
            return Err(anyhow!("group has no remote members"));
        }
        let plaintext = serde_json::to_vec(&serde_json::json!({
            "text": text,
            "reply_to_id": reply_to_id,
        }))?;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let cipher = ChaCha20Poly1305::new_from_slice(&key[..])
            .map_err(|_| anyhow!("invalid group sender key"))?;
        let aad = group_message_aad(group_id, &self.identity_id, message_id);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                chacha20poly1305::aead::Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow!("group message encryption failed"))?;
        let nonce = base64::engine::general_purpose::STANDARD.encode(nonce_bytes);
        let ciphertext = base64::engine::general_purpose::STANDARD.encode(ciphertext);
        log::info!(
            "encrypted group message once for group {group_id}; fan-out to {recipient_count} member(s)"
        );
        storage
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?
            .save_group_text_message_with_id(
                message_id,
                group_id,
                "android-local",
                text,
                reply_to_id,
            )?;
        let mut delivered_members = 0usize;
        let mut failures = Vec::new();
        for member in group
            .member_peer_ids
            .iter()
            .filter(|member| member.as_str() != local_public_key)
        {
            let public_key = match parse_group_member_key(member) {
                Ok(key) => key,
                Err(error) => {
                    failures.push(error.to_string());
                    continue;
                }
            };
            let recipient_id = NodeId::from_public_key(&public_key).to_hex();
            let addresses = self.peer_addresses_of(&recipient_id).await;
            if addresses.is_empty() {
                failures.push(format!("no known address for group member {recipient_id}"));
                continue;
            }
            self.ctx
                .sync
                .lock()
                .await
                .add_group_message_event(crate::GroupMessagePayload {
                    message_id: message_id.to_string(),
                    group_id: group_id.to_string(),
                    sender_id: self.identity_id.clone(),
                    recipient_id: recipient_id.clone(),
                    timestamp: unix_now(),
                    nonce: nonce.clone(),
                    ciphertext: ciphertext.clone(),
                })?;
            let mut sent = false;
            for address in addresses {
                match self.send_pending_verified(&address, member).await {
                    Ok(()) => {
                        sent = true;
                        break;
                    }
                    Err(error) => log::warn!(
                        "group message send to {recipient_id} via {address} failed: {error}"
                    ),
                }
            }
            if sent {
                delivered_members += 1;
            } else {
                failures.push(format!("message delivery failed for {recipient_id}"));
            }
        }
        if delivered_members != recipient_count {
            return Err(anyhow!(
                "group message delivered to {delivered_members}/{recipient_count} members; {}",
                failures.join("; "),
            ));
        }
        Ok(())
    }

    pub async fn update_settings(&self, settings: crate::SyncSettings) -> Result<()> {
        self.ctx.sync.lock().await.sync_settings(settings)
    }

    pub fn channel_handler(&self, source: Arc<dyn ChannelSource>) -> ChannelPollHandler {
        ChannelPollHandler::new(source, Arc::clone(&self.ctx.sync))
    }

    pub async fn pending_events(&self) -> Vec<SyncEvent> {
        self.ctx.sync.lock().await.get_pending_events()
    }

    pub async fn has_pending_events_for_peer(&self, peer_public_key_hex: &str) -> Result<bool> {
        let identity_id = pubkey_to_node_id(peer_public_key_hex)
            .ok_or_else(|| anyhow!("invalid peer public key"))?
            .to_hex();
        Ok(!pending_events_for_recipient(self.pending_events().await, &identity_id).is_empty())
    }

    pub async fn pending_message_ids_for_peer(
        &self,
        peer_public_key_hex: &str,
    ) -> Result<Vec<String>> {
        let identity_id = pubkey_to_node_id(peer_public_key_hex)
            .ok_or_else(|| anyhow!("invalid peer public key"))?
            .to_hex();
        Ok(
            pending_events_for_recipient(self.pending_events().await, &identity_id)
                .into_iter()
                .filter(|event| event.event_type == SyncEventType::MessageAdded)
                .map(|event| event.id)
                .collect(),
        )
    }

    async fn send_home_event(
        &self,
        peer_address: &str,
        event_type: SyncEventType,
        data: String,
    ) -> Result<()> {
        if !matches!(
            event_type,
            SyncEventType::HomeLinkRequest
                | SyncEventType::HomeLinkResponse
                | SyncEventType::HomeLinkConfirm
                | SyncEventType::HomeSyncChunk
                | SyncEventType::HomeSyncAck
                | SyncEventType::DraftUpdate
        ) {
            return Err(anyhow!("event type is not a Home event"));
        }
        let mut event = SyncEvent::new(uuid::Uuid::new_v4().to_string(), event_type, data);
        event.sign(&self.private_key.to_bytes())?;
        let envelope = SyncEnvelope::new(
            self.identity_id.clone(),
            self.public_key.clone(),
            vec![event],
        );
        if serde_json::to_vec(&envelope)?.len() > crate::tls_transport::MAX_TLS_ENVELOPE_SIZE {
            return Err(anyhow!("Home event exceeds the TLS envelope size limit"));
        }
        send_envelope_secure_with_stream_kind_and_metrics(
            peer_address,
            &envelope,
            &self.private_key,
            Arc::clone(&self.ctx.hosts),
            None,
            self.trust_policy.clone(),
            crate::mux::StreamKind::Control,
            Arc::clone(&self.ctx.abuse_metrics),
        )
        .await
    }

    pub async fn register_home_stack(
        &self,
        stack: &HomeStack,
        home_secret: HomeSecret,
    ) -> Result<()> {
        if stack.stack_id.trim().is_empty() {
            return Err(anyhow!("Home Stack id cannot be empty"));
        }
        let current_public_key = hex::encode(self.private_key.verifying_key().to_bytes());
        let mut linked_device_pubkeys = HashSet::new();
        for device in stack.devices.values() {
            if device.stack_id != stack.stack_id {
                return Err(anyhow!(
                    "Home Stack contains a device assigned to another stack"
                ));
            }
            let key_bytes: [u8; 32] = hex::decode(&device.device_pubkey)
                .map_err(|error| anyhow!("invalid linked device public key: {error}"))?
                .try_into()
                .map_err(|_| anyhow!("linked device public key must be 32 bytes"))?;
            VerifyingKey::from_bytes(&key_bytes)
                .map_err(|error| anyhow!("invalid linked device public key: {error}"))?;
            linked_device_pubkeys.insert(hex::encode(key_bytes));
        }
        let primary = stack
            .devices
            .get(&stack.primary_device_id)
            .ok_or_else(|| anyhow!("Home Stack is missing its primary device"))?;
        if primary.role != crate::DeviceRole::Primary
            || !linked_device_pubkeys.contains(&current_public_key)
        {
            return Err(anyhow!(
                "Home Stack does not contain this runtime and a valid primary device"
            ));
        }
        let mut state = self.ctx.home_state.lock().await;
        state.home_stack_id = Some(stack.stack_id.clone());
        state
            .pending_sync_transfers
            .retain(|_, transfer| linked_device_pubkeys.contains(&transfer.source_public_key));
        state.linked_device_pubkeys = linked_device_pubkeys;
        let members = state.linked_device_pubkeys.clone();
        state
            .active_presence
            .retain(|_, entry| members.contains(&entry.record.public_key));
        state
            .cached_presence
            .retain(|_, entry| members.contains(&entry.public_key));
        state.home_secret = Some(home_secret);
        let complete_transfers = state
            .pending_sync_transfers
            .values()
            .filter(|transfer| {
                transfer
                    .chunks
                    .first()
                    .is_some_and(|chunk| transfer.chunks.len() == chunk.total as usize)
            })
            .cloned()
            .collect::<Vec<_>>();
        drop(state);
        for transfer in complete_transfers {
            let Some(chunk) = transfer.chunks.first() else {
                continue;
            };
            if let Err(error) =
                apply_complete_home_sync_transfer(&self.ctx, &chunk.transfer_id).await
            {
                log::warn!("could not apply pending Home sync snapshot: {error}");
            }
        }
        Ok(())
    }

    pub async fn send_home_sync_snapshot(
        &self,
        peer_public_key: &str,
        peer_address: &str,
        home_secret: &HomeSecret,
    ) -> Result<usize> {
        let peer_key: [u8; 32] = hex::decode(peer_public_key)
            .map_err(|error| anyhow!("invalid Home device public key: {error}"))?
            .try_into()
            .map_err(|_| anyhow!("Home device public key must be 32 bytes"))?;
        VerifyingKey::from_bytes(&peer_key)
            .map_err(|error| anyhow!("invalid Home device public key: {error}"))?;
        if !self
            .ctx
            .home_state
            .lock()
            .await
            .linked_device_pubkeys
            .contains(&hex::encode(peer_key))
        {
            return Err(anyhow!("target device is not linked to this Home Stack"));
        }

        let storage = self
            .ctx
            .storage
            .as_ref()
            .ok_or_else(|| anyhow!("client storage is not configured"))?;
        let snapshot = storage
            .lock()
            .map_err(|_| anyhow!("client storage lock poisoned"))?
            .export_home_sync_snapshot()?;
        let chunks = seal_home_sync_snapshot(&snapshot, home_secret)?;
        let chunk_count = chunks.len();
        let first = chunks
            .first()
            .ok_or_else(|| anyhow!("Home sync snapshot produced no chunks"))?;
        let peer_public_key = hex::encode(peer_key);
        storage
            .lock()
            .map_err(|_| anyhow!("client storage lock poisoned"))?
            .queue_home_sync_snapshot(
                &peer_public_key,
                &first.transfer_id,
                &first.snapshot_sha256,
                &serde_json::to_string(&chunks)?,
            )?;
        for chunk in &chunks {
            self.send_home_event(
                peer_address,
                SyncEventType::HomeSyncChunk,
                serde_json::to_string(&chunk)?,
            )
            .await?;
        }
        storage
            .lock()
            .map_err(|_| anyhow!("client storage lock poisoned"))?
            .mark_home_sync_outbox_attempt(&peer_public_key, &first.transfer_id, unix_now())?;
        Ok(chunk_count)
    }

    pub async fn update_home_sync_draft(&self, chat_id: &str, text: &str) -> Result<usize> {
        if chat_id.is_empty() || chat_id.len() > 128 || text.len() > 16 * 1024 {
            return Err(anyhow!("invalid Home sync draft"));
        }
        let storage = self
            .ctx
            .storage
            .as_ref()
            .ok_or_else(|| anyhow!("client storage is not configured"))?;
        let draft = storage
            .lock()
            .map_err(|_| anyhow!("client storage lock poisoned"))?
            .set_home_sync_draft(chat_id, text)?;
        let (home_secret, linked_devices) = {
            let state = self.ctx.home_state.lock().await;
            (
                state.home_secret.clone(),
                state.linked_device_pubkeys.clone(),
            )
        };
        if home_secret.is_none() {
            return Ok(0);
        }

        let local_public_key = hex::encode(self.private_key.verifying_key().to_bytes());
        let update = serde_json::to_string(&HomeDraftUpdate {
            chat_id: draft.chat_id,
            text: draft.text,
            updated_at: draft.updated_at,
        })?;
        let mut sent = 0;
        for peer_public_key in linked_devices {
            if peer_public_key == local_public_key {
                continue;
            }
            let addresses = home_sync_peer_addresses(&self.ctx, &peer_public_key).await?;
            let mut last_error = None;
            for address in addresses {
                match self
                    .send_home_event(&address, SyncEventType::DraftUpdate, update.clone())
                    .await
                {
                    Ok(()) => {
                        sent += 1;
                        last_error = None;
                        break;
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            if let Some(error) = last_error {
                log::warn!(
                    "DraftUpdate delivery to linked device {} failed: {error:#}",
                    &peer_public_key[..8.min(peer_public_key.len())]
                );
            }
        }
        if sent > 0 {
            log::info!("DraftUpdate sent chat={} devices={sent}", chat_id);
        }
        Ok(sent)
    }

    pub async fn take_pending_home_sync_transfers(&self) -> Vec<PendingHomeSyncTransfer> {
        let mut state = self.ctx.home_state.lock().await;
        std::mem::take(&mut state.pending_sync_transfers)
            .into_values()
            .collect()
    }

    pub async fn apply_home_sync_transfer(
        &self,
        transfer: &PendingHomeSyncTransfer,
        home_secret: &HomeSecret,
    ) -> Result<()> {
        let peer_key: [u8; 32] = hex::decode(&transfer.source_public_key)
            .map_err(|error| anyhow!("invalid Home sync source public key: {error}"))?
            .try_into()
            .map_err(|_| anyhow!("Home sync source public key must be 32 bytes"))?;
        if !self
            .ctx
            .home_state
            .lock()
            .await
            .linked_device_pubkeys
            .contains(&hex::encode(peer_key))
        {
            return Err(anyhow!("Home sync source device is no longer linked"));
        }
        let snapshot = open_home_sync_snapshot(&transfer.chunks, home_secret)?;
        let storage = self
            .ctx
            .storage
            .as_ref()
            .ok_or_else(|| anyhow!("client storage is not configured"))?;
        storage
            .lock()
            .map_err(|_| anyhow!("client storage lock poisoned"))?
            .apply_home_sync_snapshot(&snapshot)?;
        if let Some(chunk) = transfer.chunks.first() {
            self.ctx
                .home_state
                .lock()
                .await
                .pending_sync_transfers
                .remove(&chunk.transfer_id);
        }
        Ok(())
    }

    pub async fn pending_link_requests(&self) -> Vec<PendingLinkRequest> {
        self.ctx
            .home_state
            .lock()
            .await
            .pending_requests
            .values()
            .cloned()
            .collect()
    }

    pub async fn initiate_home_link(&self, qr_link: &str) -> Result<String> {
        let qr = LinkingQr::from_link(qr_link)?;
        log::info!("HomeLink: QR validated; preparing signed request");
        let mut request = LinkRequest::new(
            self.public_key.clone(),
            crate::DeviceRole::Secondary,
            crate::DeviceCapabilities::default(),
            qr.linking_token.clone(),
        );
        request.sign(&self.private_key);
        let nonce = request.nonce.clone();
        self.ctx
            .home_state
            .lock()
            .await
            .pending_link_targets
            .insert(nonce.clone(), qr.clone());
        println!("HomeLink: sending signed request to {}", qr.primary_addr);
        if let Err(error) = self.initiate_linking(&qr.primary_addr, request).await {
            self.ctx
                .home_state
                .lock()
                .await
                .pending_link_targets
                .remove(&nonce);
            return Err(error);
        }
        Ok(nonce)
    }

    pub async fn has_pending_home_link_response(&self, link_nonce: &str) -> bool {
        self.ctx
            .home_state
            .lock()
            .await
            .pending_responses
            .contains_key(link_nonce)
    }

    pub async fn finish_home_link(&self, link_nonce: &str) -> Result<(HomeSecret, HomeStack)> {
        let (response, qr) = {
            let state = self.ctx.home_state.lock().await;
            let response = state
                .pending_responses
                .get(link_nonce)
                .cloned()
                .ok_or_else(|| anyhow!("Home link response is not available yet"))?;
            let qr = state
                .pending_link_targets
                .get(link_nonce)
                .cloned()
                .ok_or_else(|| anyhow!("Home link QR context has expired"))?;
            (response, qr)
        };
        if response.primary_pubkey != qr.primary_pubkey
            || response.primary_device_id != qr.primary_device_id
        {
            return Err(anyhow!(
                "Home link response does not match the scanned QR identity"
            ));
        }
        let (home_secret, home_stack, _self_info) = crate::handle_link_response(
            &response,
            &self.private_key,
            crate::DeviceRole::Secondary,
            crate::DeviceCapabilities::default(),
        )?;
        self.register_home_stack(&home_stack, home_secret.clone())
            .await?;
        let confirm = LinkConfirm::create(
            &self.private_key,
            response.primary_device_id.clone(),
            &home_secret,
            response.link_nonce.clone(),
        )?;
        self.send_link_confirm(&qr.primary_addr, confirm).await?;

        let mut state = self.ctx.home_state.lock().await;
        state.pending_responses.remove(link_nonce);
        state.pending_link_targets.remove(link_nonce);
        Ok((home_secret, home_stack))
    }

    pub async fn approve_link_request(
        &self,
        link_nonce: &str,
        peer_address: &str,
        home_secret: HomeSecret,
        home_stack: HomeStack,
        all_devices: Vec<DeviceInfo>,
    ) -> Result<HomeStack> {
        let pending = self
            .ctx
            .home_state
            .lock()
            .await
            .pending_requests
            .get(link_nonce)
            .cloned()
            .ok_or_else(|| anyhow!("link request not found"))?;
        let request = pending.request;

        let mut updated_stack = home_stack.clone();
        let response = crate::handle_link_request(
            &request,
            &request.linking_token,
            &mut updated_stack,
            &self.private_key,
            &home_secret,
            all_devices,
        )?;
        let now = unix_now();
        use sha2::Digest;
        let current_device_id = hex::encode(sha2::Sha256::digest(
            self.private_key.verifying_key().to_bytes(),
        ));
        if updated_stack.primary_device_id != current_device_id {
            return Err(anyhow!(
                "Home Stack primary identity does not match this runtime"
            ));
        }
        if !updated_stack.is_linked(&current_device_id) {
            updated_stack.add_device(DeviceInfo {
                device_id: current_device_id.clone(),
                device_pubkey: self.public_key.clone(),
                stack_id: updated_stack.stack_id.clone(),
                added_at: now,
                added_by: current_device_id.clone(),
                role: crate::DeviceRole::Primary,
                last_seen: now,
                capabilities: crate::DeviceCapabilities::default(),
            })?;
        }
        if let Some(existing) = updated_stack.devices.get_mut(&request.new_device_id) {
            let existing_public_key = hex::decode(&existing.device_pubkey)
                .map_err(|_| anyhow!("Identity Mismatch: stored public key is invalid"))?;
            let requested_public_key = hex::decode(&request.new_device_pubkey)
                .map_err(|_| anyhow!("Identity Mismatch: requested public key is invalid"))?;
            if existing_public_key != requested_public_key {
                return Err(anyhow!(
                    "Identity Mismatch: device public key does not match"
                ));
            }
            existing.last_seen = now;
            existing.role = request.requested_role;
            existing.capabilities = request.capabilities.clone();
        } else {
            updated_stack.add_device(DeviceInfo {
                device_id: request.new_device_id.clone(),
                device_pubkey: request.new_device_pubkey.clone(),
                stack_id: updated_stack.stack_id.clone(),
                added_at: now,
                added_by: updated_stack.primary_device_id.clone(),
                role: request.requested_role,
                last_seen: now,
                capabilities: request.capabilities.clone(),
            })?;
        }
        self.send_home_event(
            peer_address,
            SyncEventType::HomeLinkResponse,
            serde_json::to_string(&response)?,
        )
        .await?;
        self.register_home_stack(&updated_stack, home_secret.clone())
            .await?;
        self.send_home_sync_snapshot(&request.new_device_pubkey, peer_address, &home_secret)
            .await?;

        let mut state = self.ctx.home_state.lock().await;
        state.pending_requests.remove(link_nonce);
        state.approved_tokens.insert(request.linking_token);
        Ok(updated_stack)
    }

    pub async fn reject_link_request(&self, link_nonce: &str) -> Result<()> {
        self.ctx
            .home_state
            .lock()
            .await
            .pending_requests
            .remove(link_nonce)
            .ok_or_else(|| anyhow!("link request not found"))?;
        Ok(())
    }

    pub async fn initiate_linking(
        &self,
        primary_address: &str,
        request: LinkRequest,
    ) -> Result<()> {
        println!("HomeLink: recording request before network send");
        self.ctx.sync.lock().await.add_home_event(
            SyncEventType::HomeLinkRequest,
            serde_json::to_string(&request)?,
        )?;
        println!("HomeLink: sending pending events to {primary_address}");
        self.send_pending(primary_address).await
    }

    pub async fn take_link_responses(&self) -> Vec<LinkResponse> {
        let responses = {
            let mut state = self.ctx.home_state.lock().await;
            std::mem::take(&mut state.pending_responses)
        };
        responses.into_values().collect()
    }

    pub async fn send_link_confirm(
        &self,
        primary_address: &str,
        confirm: LinkConfirm,
    ) -> Result<()> {
        self.send_home_event(
            primary_address,
            SyncEventType::HomeLinkConfirm,
            serde_json::to_string(&confirm)?,
        )
        .await
    }

    pub async fn publish_endpoints(&self, now: u64) -> Result<PublishReport> {
        let transport = MuxDhtTransport::new(
            self.private_key.clone(),
            Arc::clone(&self.ctx.hosts),
            self.trust_policy.clone(),
        );
        let mut endpoints = self.transport_addresses();
        let public_tcp_endpoint = *self
            .public_endpoint
            .read()
            .map_err(|error| anyhow!("public TCP endpoint state lock poisoned: {error}"))?;
        if let Some(address) = public_tcp_endpoint {
            if !endpoints.contains(&address.to_string()) {
                endpoints.push(address.to_string());
            }
        }
        let public_udp_endpoint = *self
            .public_quic_endpoint
            .read()
            .map_err(|error| anyhow!("public QUIC endpoint state lock poisoned: {error}"))?;
        if let Some(address) = public_udp_endpoint {
            endpoints.push(format!("udp://{address}"));
        }
        crate::address_refresh::retain_routable_endpoints(&mut endpoints);
        let relay_mode = self.relay_mode_enabled.load(Ordering::Relaxed);
        let wss_url = self
            .wss_url
            .lock()
            .await
            .clone()
            .or_else(|| std::env::var("HAL_WSS_URL").ok())
            .map(|url| url.trim().to_string())
            .filter(|url| !url.is_empty());
        let display_name = read_profile_display_name(self.ctx.storage.as_ref())?;
        if endpoints.is_empty() && !(relay_mode && wss_url.is_some()) && display_name.is_none() {
            log::warn!("DHT announce skipped: no endpoint or profile is available");
            return Ok(PublishReport {
                peers_contacted: 0,
                peers_stored: 0,
                failures: Vec::new(),
            });
        }
        let dht_identity_id = self.dht_local_id.to_hex();
        if self.identity_id != dht_identity_id {
            return Err(anyhow!(
                "runtime identity {} does not match DHT identity {dht_identity_id}",
                self.identity_id
            ));
        }
        let announced_endpoints = endpoints.join(", ");
        let record = EndpointRecord::create(
            dht_identity_id,
            self.public_key.clone(),
            endpoints,
            &self.private_key,
            now,
            crate::dht::ENDPOINT_TTL_SECONDS,
        )?
        .with_relay(relay_mode, &self.private_key)
        .with_wss_url(
            if relay_mode { wss_url.clone() } else { None },
            &self.private_key,
        )?
        .with_display_name(display_name.clone(), &self.private_key)?;
        let mut routing = self.dht_routing.lock().await;
        let mut cache = self.dht_cache.lock().await;
        let mut store = EndpointStore::new(self.dht_local_id, &transport, &mut routing, &mut cache);
        let report = store
            .publish(record, now)
            .await
            .map_err(|error| anyhow!(error.to_string()))?;
        log::info!(target: "HAL_DHT", "DHT announce: {announced_endpoints}");
        drop(store);
        drop(cache);
        drop(routing);
        #[cfg(not(test))]
        if display_name.is_some() || relay_mode {
            match publish_public_profile_record(
                &self.identity_id,
                &self.public_key,
                &self.private_key,
                display_name.clone(),
                relay_mode,
                wss_url.clone(),
                now,
            )
            .await
            {
                Ok(()) => log::info!(
                    target: "HAL_DHT",
                    "signed EndpointRecord published to public Mainline DHT for {}",
                    self.identity_id
                ),
                Err(error) => log::warn!(
                    target: "HAL_DHT",
                    "signed EndpointRecord publish failed for {}: {error:#}",
                    self.identity_id
                ),
            }
        }
        if let Some(address) = public_udp_endpoint {
            if !address.ip().is_loopback() && !address.ip().is_unspecified() {
                let topic = quic_dht_topic(&self.identity_id);
                let provider = PublicDhtProvider::new(&topic).with_timeout(Duration::from_secs(8));
                match provider.announce(address.port()).await {
                    Ok(()) => log::info!(
                        target: "HAL_DHT",
                        "QUIC endpoint announced to public DHT topic {topic}: {address}"
                    ),
                    Err(error) => log::warn!(
                        target: "HAL_DHT",
                        "public DHT QUIC announce failed for {topic} at {address}: {error}"
                    ),
                }
            }
        }
        Ok(report)
    }

    pub async fn configure_wss_relay(&self, url: &str, force: bool) -> Result<()> {
        let url = url.trim();
        if force && url.is_empty() {
            return Err(anyhow!("forced WSS relay requires a configured URL"));
        }
        if !url.is_empty() && !(url.starts_with("https://") || url.starts_with("wss://")) {
            return Err(anyhow!("WSS relay URL must use https:// or wss://"));
        }
        if url.is_empty() {
            std::env::remove_var("HAL_WSS_URL");
        } else {
            std::env::set_var("HAL_WSS_URL", url);
        }
        std::env::set_var("HAL_FORCE_WSS_RELAY", force.to_string());
        *self.wss_url.lock().await = (!url.is_empty()).then(|| url.to_string());
        self.force_wss_relay.store(force, Ordering::Release);
        log::info!(
            target: "HAL_DHT",
            "WSS relay settings updated: configured={}, forced={force}",
            !url.is_empty()
        );
        Ok(())
    }

    pub async fn enable_relay_mode(&self) -> Result<()> {
        self.relay_mode_enabled.store(true, Ordering::Relaxed);
        let report = self.publish_endpoints(unix_now()).await?;
        log::info!(
            target: "HAL_DHT",
            "Relay capability published in DHT: is_relay=true, stored={}, peers={}",
            report.peers_stored,
            report.peers_contacted
        );
        Ok(())
    }

    /// Publish this identity's signed prekey bundle to the DHT.
    pub async fn publish_prekey_bundle(&self, bundle: PrekeyBundle) -> Result<PublishReport> {
        let now = unix_now();
        let transport = MuxDhtTransport::new(
            self.private_key.clone(),
            Arc::clone(&self.ctx.hosts),
            self.trust_policy.clone(),
        );
        let mut routing = self.dht_routing.lock().await;
        let mut cache = self.ctx.prekey_cache.lock().await;
        let mut store = PrekeyStore::new(
            self.dht_local_id,
            &transport,
            &mut routing,
            &mut cache,
            &self.ctx.abuse_metrics,
        );
        store.publish(bundle, now).await
    }

    /// Fetch and verify a peer's signed prekey bundle from the DHT.
    pub async fn fetch_prekey_bundle(
        &self,
        identity_id: &NodeId,
        now: u64,
    ) -> Result<Option<PrekeyBundle>> {
        let transport = MuxDhtTransport::new(
            self.private_key.clone(),
            Arc::clone(&self.ctx.hosts),
            self.trust_policy.clone(),
        );
        let mut routing = self.dht_routing.lock().await;
        let mut cache = self.ctx.prekey_cache.lock().await;
        let mut store = PrekeyStore::new(
            self.dht_local_id,
            &transport,
            &mut routing,
            &mut cache,
            &self.ctx.abuse_metrics,
        );
        store.fetch(identity_id, now).await
    }

    pub async fn establish_session_as_initiator(
        &self,
        peer_identity: NodeId,
        now: u64,
    ) -> Result<()> {
        self.establish_session_as_initiator_inner(peer_identity, now, false)
            .await
    }

    async fn establish_session_as_initiator_for_resync(
        &self,
        peer_identity: NodeId,
        now: u64,
    ) -> Result<()> {
        self.establish_session_as_initiator_inner(peer_identity, now, true)
            .await
    }

    async fn establish_session_as_initiator_inner(
        &self,
        peer_identity: NodeId,
        now: u64,
        resync: bool,
    ) -> Result<()> {
        let bundle = match self.fetch_prekey_bundle(&peer_identity, now).await {
            Ok(Some(bundle)) => bundle,
            Ok(None) => {
                self.ctx
                    .abuse_metrics
                    .x3dh_bundle_fetch_failed_total
                    .fetch_add(1, Ordering::Relaxed);
                self.ctx
                    .abuse_metrics
                    .x3dh_session_failed_total
                    .fetch_add(1, Ordering::Relaxed);
                return Err(anyhow!("peer prekey bundle is unavailable"));
            }
            Err(error) => {
                self.ctx
                    .abuse_metrics
                    .x3dh_bundle_fetch_failed_total
                    .fetch_add(1, Ordering::Relaxed);
                self.ctx
                    .abuse_metrics
                    .x3dh_session_failed_total
                    .fetch_add(1, Ordering::Relaxed);
                return Err(anyhow!("failed to fetch peer prekey bundle: {error}"));
            }
        };
        if let Err(error) = bundle.verify(now) {
            self.ctx
                .abuse_metrics
                .x3dh_bundle_verify_failed_total
                .fetch_add(1, Ordering::Relaxed);
            self.ctx
                .abuse_metrics
                .x3dh_session_failed_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(anyhow!("invalid peer prekey bundle: {error}"));
        }
        let responder_identity =
            VerifyingKey::from_bytes(&bundle.identity_key).map_err(|error| {
                self.ctx
                    .abuse_metrics
                    .x3dh_bundle_verify_failed_total
                    .fetch_add(1, Ordering::Relaxed);
                self.ctx
                    .abuse_metrics
                    .x3dh_session_failed_total
                    .fetch_add(1, Ordering::Relaxed);
                anyhow!("invalid peer identity in prekey bundle: {error}")
            })?;
        if NodeId::from_public_key(&responder_identity) != peer_identity {
            self.ctx
                .abuse_metrics
                .x3dh_bundle_verify_failed_total
                .fetch_add(1, Ordering::Relaxed);
            self.ctx
                .abuse_metrics
                .x3dh_session_failed_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(anyhow!(
                "prekey bundle identity does not match requested peer"
            ));
        }

        let keys = X3DHKeys::from_identity(&self.private_key).map_err(|error| {
            self.ctx
                .abuse_metrics
                .x3dh_session_failed_total
                .fetch_add(1, Ordering::Relaxed);
            anyhow!("failed to create initiator X3DH keys: {error}")
        })?;
        let selected_opk = match bundle.one_time_prekeys.first() {
            Some(opk) => Some(opk),
            None => {
                self.ctx
                    .abuse_metrics
                    .x3dh_session_failed_total
                    .fetch_add(1, Ordering::Relaxed);
                return Err(anyhow!("peer bundle has no one-time prekey"));
            }
        };
        let (result, init_message) = X3DH::initiate_with_bundle_and_capabilities(
            &keys,
            &bundle,
            selected_opk,
            now,
            Some(true),
            Some(true),
        )
        .map_err(|error| {
            self.ctx
                .abuse_metrics
                .x3dh_session_failed_total
                .fetch_add(1, Ordering::Relaxed);
            anyhow!("X3DH initiation failed: {error}")
        })?;
        let root_key = session_root_key(&result).map_err(|error| {
            self.ctx
                .abuse_metrics
                .x3dh_session_failed_total
                .fetch_add(1, Ordering::Relaxed);
            error
        })?;
        let encoded = serde_json::to_vec(&init_message)
            .map(|json| base64::engine::general_purpose::STANDARD.encode(json))
            .map_err(|error| {
                self.ctx
                    .abuse_metrics
                    .x3dh_session_failed_total
                    .fetch_add(1, Ordering::Relaxed);
                anyhow!("failed to serialize X3DH init message: {error}")
            })?;
        self.ctx
            .sync
            .lock()
            .await
            .add_protocol_event(SyncEventType::X3dhInit, encoded)
            .map_err(|error| {
                self.ctx
                    .abuse_metrics
                    .x3dh_session_failed_total
                    .fetch_add(1, Ordering::Relaxed);
                error
            })?;
        let local_identity = NodeId::from_public_key(&self.private_key.verifying_key());
        {
            let mut session_store = self.ctx.session_store.lock().await;
            if resync {
                session_store.insert_pending_resync_with_chains(
                    peer_identity,
                    root_key,
                    &local_identity,
                    now,
                    init_message.ephemeral_public,
                    init_message.signed_prekey_used,
                    init_message.one_time_prekey_id,
                )?;
            } else {
                session_store.insert_pending_with_chains(
                    peer_identity,
                    root_key,
                    &local_identity,
                    now,
                    init_message.ephemeral_public,
                    init_message.signed_prekey_used,
                    init_message.one_time_prekey_id,
                )?;
            }
        }
        persist_session_nonfatal(&self.ctx, &peer_identity, "X3DH session creation").await;
        self.ctx
            .abuse_metrics
            .x3dh_session_established_total
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub async fn handle_session_init(&self, init_message: X3dhInitMessage, now: u64) -> Result<()> {
        handle_session_init_in_context(&self.ctx, init_message, now, None).await
    }

    pub async fn handle_session_respond(
        &self,
        respond_message: X3dhRespondMessage,
        now: u64,
    ) -> Result<()> {
        handle_session_respond_in_context(&self.ctx, respond_message, now, None).await
    }

    pub async fn get_session(&self, peer: &NodeId) -> Option<SessionView> {
        match load_session_on_demand(&self.ctx, peer).await {
            Ok(session) => session,
            Err(error) => {
                log::warn!("failed loading session for {peer:?}: {error}");
                None
            }
        }
    }

    pub async fn has_session(&self, peer: &NodeId) -> bool {
        self.get_session(peer).await.is_some()
    }

    pub async fn forget_session(&self, peer: &NodeId) -> Result<()> {
        forget_session(&self.ctx, peer).await
    }

    pub async fn lookup_endpoints(
        &self,
        identity_id: &str,
        now: u64,
    ) -> Result<Option<EndpointRecord>> {
        let transport = MuxDhtTransport::new(
            self.private_key.clone(),
            Arc::clone(&self.ctx.hosts),
            self.trust_policy.clone(),
        );
        let mut routing = self.dht_routing.lock().await;
        let mut cache = self.dht_cache.lock().await;
        let mut store = EndpointStore::new(self.dht_local_id, &transport, &mut routing, &mut cache);
        store
            .lookup(identity_id, now)
            .await
            .map_err(|error| anyhow!(error.to_string()))
    }

    /// Publish a signed badge locally and propagate the subject slot to DHT peers.
    pub async fn publish_badge(&self, badge: Badge) -> Result<()> {
        let subject = badge.subject_id;
        publish_badge_impl(
            &self.ctx,
            &self.private_key,
            &self.identity_id,
            &self.public_key,
            self.dht_local_id,
            &self.dht_routing,
            &self.dht_cache,
            &self.ctx.hosts,
            &self.trust_policy,
            badge,
        )
        .await?;
        let level = self.ctx.stigma_gate(&subject, unix_now()).await;
        self.ctx.stigma_cache.update(subject, level);
        Ok(())
    }

    /// Fetch, verify and merge the public DHT badge slot for a subject.
    pub async fn fetch_badges(&self, subject: &NodeId) -> Result<usize> {
        crate::badge_fetch_task::fetch_badges_from_dht(
            &self.ctx,
            &self.private_key,
            self.dht_local_id,
            &self.dht_routing,
            &self.dht_cache,
            &self.trust_policy,
            subject,
        )
        .await
    }

    /// Query only the local BadgeStore; never performs DHT I/O or enforcement side effects.
    pub async fn stigma_gate(&self, subject: &NodeId, now: u64) -> StigmaLevel {
        self.ctx.stigma_gate(subject, now).await
    }

    pub async fn dht_bootstrap(
        &self,
        config: BootstrapConfig,
        _now: u64,
    ) -> Result<BootstrapReport> {
        let transport = MuxDhtTransport::new(
            self.private_key.clone(),
            Arc::clone(&self.ctx.hosts),
            self.trust_policy.clone(),
        );
        let mut routing = self.dht_routing.lock().await;
        let mut bootstrap =
            crate::dht::Bootstrapper::new(self.dht_local_id, config, &transport, &mut routing);
        bootstrap
            .bootstrap_once()
            .await
            .map_err(|error| anyhow!(error.to_string()))
    }

    pub fn dht_handler(&self) -> Arc<DhtRequestHandler> {
        Arc::clone(&self.dht_handler)
    }

    pub fn dht_metrics(&self) -> Arc<crate::dht::DhtMetrics> {
        Arc::clone(&self.dht_metrics)
    }

    pub fn trust_metrics(&self) -> Arc<TrustMetrics> {
        Arc::clone(&self.ctx.trust_metrics)
    }

    /// Snapshot both DHT and trust metrics.
    pub async fn metrics_snapshot(&self) -> RuntimeMetricsSnapshot {
        RuntimeMetricsSnapshot {
            dht: self.dht_metrics.snapshot(),
            trust: self.ctx.trust_metrics.snapshot(),
            relay: self.ctx.relay_metrics.snapshot(),
            peer_directory: self.ctx.peer_directory.lock().await.metrics_snapshot(),
            badge: self.ctx.badge_metrics.snapshot(),
            abuse: self.ctx.abuse_metrics.snapshot(),
        }
    }

    /// Log both metrics once. Periodic logging belongs to an external loop.
    pub async fn log_metrics(&self) {
        let snapshot = self.metrics_snapshot().await;
        log::info!(
            "dht_metrics: received={} processed={} dropped={} timeouts={} errors={} responses={}",
            snapshot.dht.streams_received,
            snapshot.dht.streams_processed,
            snapshot.dht.streams_dropped,
            snapshot.dht.rpc_timeouts,
            snapshot.dht.rpc_errors,
            snapshot.dht.responses_sent,
        );
        log::info!(
            "trust_metrics: denies_banned={} denies_stranger_rate={} denies_contact_rate={} conflicted={} recorded_messages={} recorded_contacts={} send_stigma_blocked={} send_watching_seen={} envelope_cold_received={} envelope_warm_received={}",
            snapshot.trust.denies_banned,
            snapshot.trust.denies_stranger_rate,
            snapshot.trust.denies_contact_rate,
            snapshot.trust.conflicted,
            snapshot.trust.recorded_messages,
            snapshot.trust.recorded_contacts,
            snapshot.trust.send_stigma_blocked_total,
            snapshot.trust.send_watching_seen_total,
            snapshot.trust.envelope_cold_received_total,
            snapshot.trust.envelope_warm_received_total,
        );
        log::info!(
            "relay_metrics: received={} forwarded={} rejected={} error={} queue_full={} queue_closed={} response_sent={} response_failed={} avg_latency_micros={} tracker_orphan={} forward_received={} forward_rejected_depth={} forward_rejected_binding={} stigma_rejected={} watching_seen={}",
            snapshot.relay.received_total,
            snapshot.relay.forwarded_total,
            snapshot.relay.rejected_total,
            snapshot.relay.error_total,
            snapshot.relay.queue_full_total,
            snapshot.relay.queue_closed_total,
            snapshot.relay.response_sent_total,
            snapshot.relay.response_failed_total,
            snapshot.relay.avg_latency_micros,
            snapshot.relay.tracker_orphan_total,
            snapshot.relay.forward_received_total,
            snapshot.relay.forward_rejected_depth,
            snapshot.relay.forward_rejected_binding,
            snapshot.relay.stigma_rejected_total,
            snapshot.relay.watching_seen_total,
        );
        log::info!(
            "badge_metrics: published={} fetched={} verify_failed={} stigma_active={} watching={} fetch_rounds={} fetch_subjects={} fetch_badges_merged={} fetch_failed={} store_stale={}",
            snapshot.badge.badge_published_total,
            snapshot.badge.badge_fetched_total,
            snapshot.badge.badge_verify_failed_total,
            snapshot.badge.badge_stigma_active_current,
            snapshot.badge.badge_watching_current,
            snapshot.badge.fetch_rounds_total,
            snapshot.badge.fetch_subjects_total,
            snapshot.badge.fetch_badges_merged_total,
            snapshot.badge.fetch_failed_total,
            snapshot.badge.store_stale_current,
        );
        log::info!(
            "prekey_bundle_metrics: published={} stored={} fetched={} fetch_ok={} fetch_failed={} verify_failed={} rotations={} refills={} generated={} rotation_failed={} rotation_publish={} opk_consumed={} opk_replay={} opk_not_found={}",
            snapshot.abuse.prekey_bundle_published_total,
            snapshot.abuse.prekey_bundle_stored_total,
            snapshot.abuse.prekey_bundle_fetched_total,
            snapshot.abuse.prekey_bundle_fetch_ok_total,
            snapshot.abuse.prekey_bundle_fetch_failed_total,
            snapshot.abuse.prekey_bundle_verify_failed_total,
            snapshot.abuse.prekey_rotation_total,
            snapshot.abuse.prekey_opk_refill_total,
            snapshot.abuse.prekey_opk_generated_total,
            snapshot.abuse.prekey_rotation_failed_total,
            snapshot.abuse.prekey_publish_from_rotation_total,
            snapshot.abuse.prekey_opk_consumed_total,
            snapshot.abuse.prekey_opk_consume_replay_total,
            snapshot.abuse.prekey_opk_consume_not_found_total,
        );
        log::info!(
            "x3dh_session_metrics: established={} accepted={} failed={} bundle_fetch_failed={} bundle_verify_failed={}",
            snapshot.abuse.x3dh_session_established_total,
            snapshot.abuse.x3dh_session_accepted_total,
            snapshot.abuse.x3dh_session_failed_total,
            snapshot.abuse.x3dh_bundle_fetch_failed_total,
            snapshot.abuse.x3dh_bundle_verify_failed_total,
        );
        log::info!(
            "ratchet_metrics: encrypt={} encrypt_failed={} commit_failed={} decrypt={} decrypt_failed={} replay={} out_of_order={} out_of_order_accepted={} skipped_keys_current={} skipped_keys_inserted={} skipped_keys_expired={} skipped_keys_evicted={} persist_failed={} session_persist_failed={} needs_resync={} no_session={} needs_resync_received={} session_replaced={} resync_triggered={} send_blocked_resync={} gap_too_large={} parse_failed={} unexpected_v2={} unexpected_v1={} recipient_mismatch={} sender_mismatch={} counter_overflow={} commit_mismatch={} ecies_fallback={}",
            snapshot.abuse.ratchet_encrypt_total,
            snapshot.abuse.ratchet_encrypt_failed_total,
            snapshot.abuse.ratchet_commit_failed_total,
            snapshot.abuse.ratchet_decrypt_total,
            snapshot.abuse.ratchet_decrypt_failed_total,
            snapshot.abuse.ratchet_replay_total,
            snapshot.abuse.ratchet_out_of_order_total,
            snapshot.abuse.ratchet_out_of_order_accepted_total,
            snapshot.abuse.ratchet_skipped_keys_current,
            snapshot.abuse.ratchet_skipped_keys_inserted_total,
            snapshot.abuse.ratchet_skipped_keys_expired_total,
            snapshot.abuse.ratchet_skipped_keys_evicted_total,
            snapshot.abuse.ratchet_persist_failed_total,
            snapshot.abuse.session_persist_failed_total,
            snapshot.abuse.ratchet_needs_resync_total,
            snapshot.abuse.ratchet_no_session_total,
            snapshot.abuse.ratchet_needs_resync_received_total,
            snapshot.abuse.ratchet_session_replaced_total,
            snapshot.abuse.ratchet_resync_triggered_total,
            snapshot.abuse.ratchet_send_blocked_resync_total,
            snapshot.abuse.ratchet_gap_too_large_total,
            snapshot.abuse.ratchet_parse_failed_total,
            snapshot.abuse.ratchet_unexpected_v2_total,
            snapshot.abuse.ratchet_unexpected_v1_total,
            snapshot.abuse.ratchet_recipient_mismatch_total,
            snapshot.abuse.ratchet_sender_mismatch_total,
            snapshot.abuse.ratchet_counter_overflow_total,
            snapshot.abuse.ratchet_commit_mismatch_total,
            snapshot.abuse.ecies_fallback_total,
        );
        log::info!(
            "biometric_metrics: verified={} rejected={} unavailable={}",
            snapshot.abuse.biometric_verified_total,
            snapshot.abuse.biometric_rejected_total,
            snapshot.abuse.biometric_unavailable_total,
        );
        log::info!(
            "abuse_metrics: incoming_stigma_rejected={} incoming_cold_exceeded={} auto_badge_queued={} auto_badge_published={} auto_badge_skipped_reply={} auto_badge_skipped_no_storage={} auto_badge_skipped_vouch={} auto_badge_skipped_no_evidence={} quic_identity_verified={} quic_identity_rejected={} quic_identity_tofu={} relay_inner_verify_failed={} relay_inner_verify_ok={} relay_consent_verified={} relay_consent_missing={} relay_consent_signature_failed={} relay_consent_target_mismatch={} relay_consent_expired={} relay_consent_replay={} relay_consent_content_mismatch={} envelope_size_exceeded={} envelope_send_size_exceeded={} envelope_transport_identity_verified={} envelope_transport_identity_mismatch={} cold_tracker_evicted={} inbound_observation_dropped={} stigma_refresh_rounds={} transport_stigma_rejected={} rate_tier_throttled={} rate_tier_warning={} rate_tier_blocked={} trust_gate_blocked={} rate_blocked={} rate_limiter_worker_failed={} rate_throttled_warning={} rate_throttled_watching={}",
            snapshot.abuse.incoming_stigma_rejected_total,
            snapshot.abuse.incoming_cold_exceeded_total,
            snapshot.abuse.auto_badge_queued_total,
            snapshot.abuse.auto_badge_published_total,
            snapshot.abuse.auto_badge_skipped_reply_total,
            snapshot.abuse.auto_badge_skipped_no_storage_total,
            snapshot.abuse.auto_badge_skipped_vouch_total,
            snapshot.abuse.auto_badge_skipped_no_evidence_total,
            snapshot.abuse.quic_identity_verified_total,
            snapshot.abuse.quic_identity_rejected_total,
            snapshot.abuse.quic_identity_tofu_total,
            snapshot.abuse.relay_inner_verify_failed_total,
            snapshot.abuse.relay_inner_verify_ok_total,
            snapshot.abuse.relay_consent_verified_total,
            snapshot.abuse.relay_consent_missing_total,
            snapshot.abuse.relay_consent_signature_failed_total,
            snapshot.abuse.relay_consent_target_mismatch_total,
            snapshot.abuse.relay_consent_expired_total,
            snapshot.abuse.relay_consent_replay_total,
            snapshot.abuse.relay_consent_content_mismatch_total,
            snapshot.abuse.envelope_size_exceeded_total,
            snapshot.abuse.envelope_send_size_exceeded_total,
            snapshot.abuse.envelope_transport_identity_verified_total,
            snapshot.abuse.envelope_transport_identity_mismatch_total,
            snapshot.abuse.cold_tracker_evicted_total,
            snapshot.abuse.inbound_observation_dropped_total,
            snapshot.abuse.stigma_refresh_rounds_total,
            snapshot.abuse.transport_stigma_rejected_total,
            snapshot.abuse.rate_tier_throttled_total,
            snapshot.abuse.rate_tier_warning_total,
            snapshot.abuse.rate_tier_blocked_total,
            snapshot.abuse.trust_gate_blocked_total,
            snapshot.abuse.rate_blocked_total,
            snapshot.abuse.rate_limiter_worker_failed_total,
            snapshot.abuse.rate_throttled_by_warning_total,
            snapshot.abuse.rate_throttled_by_watching_total,
        );
        log::info!(
            "peer_directory_metrics: inbound={} outbound={} invite={} refreshed={} invalid_identity={} conflicts={} evicted_lru={} evicted_per_identity={} expired={} entries_current={}",
            snapshot.peer_directory.recorded_inbound_total,
            snapshot.peer_directory.recorded_outbound_total,
            snapshot.peer_directory.recorded_invite_total,
            snapshot.peer_directory.refreshed_total,
            snapshot.peer_directory.rejected_invalid_identity_total,
            snapshot.peer_directory.rejected_conflict_total,
            snapshot.peer_directory.evicted_lru_total,
            snapshot.peer_directory.evicted_per_identity_total,
            snapshot.peer_directory.expired_total,
            snapshot.peer_directory.entries_current,
        );
    }

    pub fn address_refresh(&self) -> Arc<AddressRefresh> {
        Arc::clone(&self.ctx.address_refresh)
    }

    /// Punch peer через signaling strategy.
    ///
    /// Создаёт DhtEndpointLookup локально, использует настройки из ctx.
    /// Интеграция в send_pending запланирована следующим шагом.
    pub async fn punch_peer(&self, target_id: NodeId, seed: u64) -> PunchOutcome {
        let lookup = DhtEndpointLookup::new(
            self.dht_local_id,
            self.private_key.clone(),
            Arc::clone(&self.ctx.hosts),
            self.trust_policy.clone(),
            Arc::clone(&self.dht_routing),
            Arc::clone(&self.dht_cache),
        );
        punch_hole_with_strategy(
            &self.ctx.hole_puncher,
            SocketAddr::from(([0, 0, 0, 0], 0)),
            target_id,
            &self.ctx.signaling_strategy,
            Some(Arc::new(lookup)),
            seed,
        )
        .await
    }

    /// Опубликовать PunchRequest в DHT.
    ///
    /// Endpoint берётся из первого адреса, объявляемого runtime.
    pub async fn publish_punch_request(&self, target_id: NodeId, ttl_secs: u64) -> Result<()> {
        use crate::signaling::{PunchRequest, PunchRequestStore};

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let endpoint_address = self
            .transport_addresses()
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("no transport address available"))?;
        let endpoint: SocketAddr = endpoint_address
            .parse()
            .map_err(|error| anyhow!("invalid transport address: {error}"))?;

        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let request = PunchRequest::create(
            self.dht_local_id,
            target_id,
            endpoint,
            Duration::from_secs(ttl_secs),
            now,
            &self.private_key,
            nonce,
        )
        .map_err(|error| anyhow!("create punch request: {error}"))?;

        let transport = MuxDhtTransport::new(
            self.private_key.clone(),
            Arc::clone(&self.ctx.hosts),
            self.trust_policy.clone(),
        );
        let mut routing = self.dht_routing.lock().await;
        let mut store = PunchRequestStore::new(self.dht_local_id, &transport, &mut routing);
        let format = select_punch_request_format(&self.ctx.signaling_strategy, target_id, now);
        store
            .publish_masked(&request, format, now)
            .await
            .map_err(|error| anyhow!("publish punch request: {error}"))
    }

    /// Прочитать PunchRequest из слота своего NodeId.
    pub async fn fetch_punch_requests(
        &self,
        my_id: NodeId,
    ) -> Result<Vec<crate::signaling::PunchRequest>> {
        use crate::signaling::PunchRequestStore;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let transport = MuxDhtTransport::new(
            self.private_key.clone(),
            Arc::clone(&self.ctx.hosts),
            self.trust_policy.clone(),
        );
        let mut routing = self.dht_routing.lock().await;
        let mut store = PunchRequestStore::new(self.dht_local_id, &transport, &mut routing);
        store
            .fetch(&my_id, now)
            .await
            .map_err(|error| anyhow!("fetch punch requests: {error}"))
    }

    /// Получить запросы адресата и начать punch по выбранному target identity.
    pub async fn punch_from_requests(&self, target_id: NodeId, seed: u64) -> PunchOutcome {
        match self.fetch_punch_requests(self.dht_local_id).await {
            Ok(requests) => {
                if !requests
                    .iter()
                    .any(|request| request.requester_id == target_id)
                {
                    log::debug!("no punch request from target, punching anyway");
                }
            }
            Err(error) => {
                log::warn!("fetch_punch_requests failed: {error}");
            }
        }
        self.punch_peer(target_id, seed).await
    }

    /// Internal-only send path without the public trust-policy checks.
    pub(crate) async fn send_pending(&self, peer_address: &str) -> Result<()> {
        let mut events = self.pending_events().await;
        if events.is_empty() {
            return Ok(());
        }
        for event in &mut events {
            event.sign(&self.private_key.to_bytes())?;
        }
        let envelope = self.envelope_with_integrity(SyncEnvelope::new(
            self.identity_id.clone(),
            self.public_key.clone(),
            events,
        ))?;
        let mut last_error = None;
        for candidate in peer_address_candidates(peer_address) {
            if classify_candidate(&candidate) == TransportTier::Relay
                && !self.trust_policy.allows_relay(&candidate)
            {
                continue;
            }
            // TODO(Post-MVP): mux cache by identity_id
            //
            // Текущая polling-модель переоткрывает mux на каждый
            // send_pending. Session resumption делает это дешёвым
            // (~5ms vs ~30ms full handshake), но кеш ускорил бы
            // ещё в 3-5 раз.
            //
            // Кеш требует решения модели peer_id ↔ address.
            // Текущий API передаёт только address в send_pending.
            // Нужен контракт: где хранится identity для каждого
            // peer, что делать при смене address.
            match send_envelope_secure_with_stream_kind_and_metrics(
                &candidate,
                &envelope,
                &self.private_key,
                Arc::clone(&self.ctx.hosts),
                None,
                self.trust_policy.clone(),
                crate::mux::StreamKind::Sync,
                Arc::clone(&self.ctx.abuse_metrics),
            )
            .await
            {
                Ok(()) => return Ok(()),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("all peer transports failed")))
    }

    /// Отправить pending events с trust-проверками.
    ///
    /// В отличие от send_pending (без node_id), этот метод
    /// проверяет trust через oracle.
    pub async fn send_pending_trusted(&self, node_id: NodeId, peer_address: &str) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.enforce_cold_contact_stigma(&node_id, now).await?;

        if self.ctx.oracle.is_banned(&node_id, now) {
            self.ctx.trust_metrics.inc_denies_banned();
            return Err(anyhow!("peer is banned"));
        }
        if !self.ctx.oracle.allows_message_to_stranger(&node_id, now) {
            self.ctx.trust_metrics.inc_denies_stranger_rate();
            return Err(anyhow!("message denied by trust policy"));
        }

        let mut events = self.pending_events().await;
        if events.is_empty() {
            return Ok(());
        }
        for event in &mut events {
            event.sign(&self.private_key.to_bytes())?;
        }
        let envelope = self.envelope_with_integrity(SyncEnvelope::new(
            self.identity_id.clone(),
            self.public_key.clone(),
            events,
        ))?;
        let mut last_error = None;
        for candidate in peer_address_candidates(peer_address) {
            if classify_candidate(&candidate) == TransportTier::Relay
                && !self.trust_policy.allows_relay(&candidate)
            {
                continue;
            }
            match send_envelope_secure_with_stream_kind_and_metrics(
                &candidate,
                &envelope,
                &self.private_key,
                Arc::clone(&self.ctx.hosts),
                None,
                self.trust_policy.clone(),
                crate::mux::StreamKind::Sync,
                Arc::clone(&self.ctx.abuse_metrics),
            )
            .await
            {
                Ok(()) => {
                    let is_stranger = matches!(
                        self.ctx.oracle.relationship(&node_id),
                        Relationship::Unknown
                    );
                    self.ctx.oracle.record_message(&node_id, is_stranger, now);
                    self.ctx.trust_metrics.inc_recorded_messages();
                    return Ok(());
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("all peer transports failed")))
    }

    pub async fn send_pending_verified(
        &self,
        peer_address: &str,
        peer_public_key_hex: &str,
    ) -> Result<()> {
        let identity_id = pubkey_to_node_id(peer_public_key_hex).map(|node_id| node_id.to_hex());
        log::info!(
            target: "HAL_DHT",
            "send_pending_verified ENTER: peer={}, address={}",
            identity_id.as_deref().unwrap_or("unknown"),
            peer_address
        );
        log::info!(
            target: "HAL_DHT",
            "send_pending_verified: LAN address used: {} (address={peer_address})",
            peer_address
                .parse::<std::net::SocketAddr>()
                .is_ok_and(|address| crate::transport::is_lan_address(&address))
        );
        let result = if let Some(identity_id) = identity_id.as_deref() {
            let verifying_key = VerifyingKey::from_bytes(
                &hex::decode(peer_public_key_hex)?
                    .try_into()
                    .map_err(|_| anyhow!("peer public key must be 32 bytes"))?,
            )?;
            if let Err(error) = self
                .validate_outbound_peer(
                    &NodeId::from_public_key(&verifying_key),
                    peer_public_key_hex,
                )
                .await
            {
                Err(error)
            } else if self.force_wss_relay.load(Ordering::Acquire) {
                log::info!(
                    target: "HAL_DHT",
                    "forced WSS relay enabled; skipping LAN and direct DHT routes for {identity_id}"
                );
                self.send_pending_verified_inner("", peer_public_key_hex)
                    .await
            } else {
                let mut candidates = self
                    .peer_addresses_for_send(
                        identity_id,
                        &verifying_key,
                        Some(peer_address),
                        "peer send",
                    )
                    .await?;
                let mut attempted = HashSet::new();
                let mut last_error = None;
                let mut refreshed_after_connect_failure = false;
                if candidates.is_empty() {
                    log::info!(
                        target: "HAL_DHT",
                        "No direct endpoint is available for {identity_id}; trying QUIC and trusted relay routes"
                    );
                    self.send_pending_verified_inner("", peer_public_key_hex)
                        .await
                } else {
                    loop {
                        let Some(index) = candidates
                            .iter()
                            .position(|address| !attempted.contains(address))
                        else {
                            break Err(last_error.unwrap_or_else(|| {
                                anyhow!("no known or discoverable address for peer {identity_id}")
                            }));
                        };
                        let address = candidates.remove(index);
                        attempted.insert(address.clone());
                        let attempt = match tokio::time::timeout(
                            Duration::from_secs(30),
                            self.send_pending_verified_inner(&address, peer_public_key_hex),
                        )
                        .await
                        {
                            Ok(result) => result,
                            Err(_) => Err(anyhow!("send timed out after 30s")),
                        };
                        match attempt {
                            Ok(()) => {
                                self.peer_address_state
                                    .lock()
                                    .await
                                    .confirm_address(identity_id, &address);
                                break Ok(());
                            }
                            Err(error) => {
                                let error_message = error.to_string();
                                if error_message.contains("TLS handshake timed out with") {
                                    self.mark_peer_address_stale(identity_id, &address).await;
                                    candidates.extend(
                                        self.peer_addresses_for_send(
                                            identity_id,
                                            &verifying_key,
                                            None,
                                            "peer send",
                                        )
                                        .await?,
                                    );
                                } else if is_connection_establishment_failure(&error)
                                    && !refreshed_after_connect_failure
                                {
                                    refreshed_after_connect_failure = true;
                                    candidates.extend(
                                        self.peer_addresses_for_send(
                                            identity_id,
                                            &verifying_key,
                                            None,
                                            "peer send",
                                        )
                                        .await?,
                                    );
                                }
                                if is_connection_establishment_failure(&error)
                                    && candidates
                                        .iter()
                                        .any(|candidate| !attempted.contains(candidate))
                                {
                                    log::warn!(
                                        target: "HAL_DHT",
                                        "connect failed for {address}, trying next peer address"
                                    );
                                }
                                last_error = Some(error);
                            }
                        }
                    }
                }
            }
        } else {
            match tokio::time::timeout(
                Duration::from_secs(30),
                self.send_pending_verified_inner(peer_address, peer_public_key_hex),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(anyhow!("send timed out after 30s")),
            }
        };
        log::info!(
            target: "HAL_DHT",
            "send_pending done: peer={}, success={}",
            identity_id.as_deref().unwrap_or("unknown"),
            result.is_ok()
        );
        log::info!(target: "HAL_DHT", "send_pending_verified EXIT: success={}", result.is_ok());
        if let Some(identity_id) = identity_id {
            if result.is_ok() {
                self.recent_send_failures.lock().await.remove(&identity_id);
            } else {
                self.mark_peer_offline(&identity_id).await;
            }
        }
        result
    }

    async fn validate_outbound_peer(
        &self,
        node_id: &NodeId,
        peer_public_key_hex: &str,
    ) -> Result<()> {
        if *node_id == self.dht_local_id {
            return Err(anyhow!("resolved message target is the local identity"));
        }
        let now = unix_now();
        let debug_bypass_active = cfg!(all(debug_assertions, not(test)));
        if self.ctx.rate_exceeded(&self.dht_local_id, now).await {
            return Err(anyhow!("tier-aware rate exceeded"));
        }
        if !self
            .ctx
            .admit_peer(&node_id.to_hex(), Some(peer_public_key_hex), now)
            .await
        {
            return Err(anyhow!("peer rejected by degraded admission gate"));
        }
        let is_cold_contact = !self.is_existing_contact(&node_id.to_hex());
        self.enforce_cold_contact_stigma(node_id, now).await?;
        if is_cold_contact && !debug_bypass_active {
            if let Some(status) = self.self_proof_of_live(now).await {
                if !status.can_cold_contact() {
                    self.ctx
                        .abuse_metrics
                        .proof_of_live_cold_rejected_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Err(anyhow!("cold contact forbidden: {:?}", status));
                }
            }
        }
        if self.ctx.oracle.is_banned(node_id, now) {
            self.ctx.trust_metrics.inc_denies_banned();
            return Err(anyhow!("peer is banned"));
        }
        if !debug_bypass_active && !self.ctx.oracle.allows_message_to_stranger(node_id, now) {
            self.ctx.trust_metrics.inc_denies_stranger_rate();
            return Err(anyhow!("message denied by trust policy"));
        }
        if !debug_bypass_active {
            if let Some(trust_graph) = &self.ctx.trust_graph {
                match trust_graph
                    .gate_with_public_key(node_id, peer_public_key_hex, now)
                    .await
                {
                    TrustGateDecision::Allow => {}
                    TrustGateDecision::Throttle { .. } | TrustGateDecision::Block { .. } => {
                        self.ctx
                            .abuse_metrics
                            .trust_gate_blocked_total
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return Err(anyhow!("cold-contact blocked by trust gate"));
                    }
                }
            }
        }
        Ok(())
    }

    async fn mark_peer_address_stale(&self, identity_id: &str, address: &str) {
        self.peer_address_state
            .lock()
            .await
            .mark_stale(identity_id, address.to_string());
        log::warn!(
            target: "HAL_DHT",
            "peer address marked stale: {identity_id} {address} after handshake timeout"
        );
    }

    pub async fn invalidate_peer_addresses(&self) -> Result<usize> {
        let peers = self
            .ctx
            .peer_directory
            .lock()
            .await
            .entries(&[], unix_now());
        let count = self.peer_address_state.lock().await.invalidate_all(&peers);
        let persisted_count = if let Some(storage) = self.ctx.storage.as_ref() {
            storage
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned while clearing LAN peer addresses"))?
                .peer_registry()
                .remove_lan_addresses()
                .map_err(|error| anyhow!("failed clearing persisted LAN peer addresses: {error}"))?
        } else {
            0
        };
        log::info!(
            target: "HAL_DHT",
            "invalidate_peer_addresses: marked {count} runtime addresses stale and removed {persisted_count} persisted LAN addresses"
        );
        Ok(count + persisted_count)
    }

    async fn peer_addresses_for_send(
        &self,
        identity_id: &str,
        verifying_key: &VerifyingKey,
        fallback_address: Option<&str>,
        operation: &str,
    ) -> Result<Vec<String>> {
        let mut cached_addresses = self
            .active_sessions
            .lock()
            .await
            .get(identity_id)
            .map(|session| session.address.to_string())
            .into_iter()
            .collect::<Vec<_>>();
        cached_addresses.extend(self.peer_addresses_of(identity_id).await);
        if let Some(address) = self.last_known_peer_address(identity_id).await? {
            cached_addresses.push(address);
        }
        cached_addresses.sort_by_key(|address| {
            address
                .parse::<SocketAddr>()
                .map(|address| !crate::transport::is_lan_address(&address))
                .unwrap_or(true)
        });
        cached_addresses.dedup();

        let mut fallback_addresses = fallback_address
            .map(peer_address_candidates)
            .unwrap_or_default();

        let stale_addresses = self
            .peer_address_state
            .lock()
            .await
            .stale_addresses(identity_id);
        let stale_count = cached_addresses
            .iter()
            .chain(fallback_addresses.iter())
            .filter(|address| stale_addresses.contains(*address))
            .count();
        if stale_count > 0 {
            log::info!(
                target: "HAL_DHT",
                "{operation} skipped {stale_count} stale address(es) for {identity_id}"
            );
            cached_addresses.retain(|address| !stale_addresses.contains(address));
            fallback_addresses.retain(|address| !stale_addresses.contains(address));
            let stale_active_session = self
                .active_sessions
                .lock()
                .await
                .get(identity_id)
                .is_some_and(|session| stale_addresses.contains(&session.address.to_string()));
            if stale_active_session {
                self.active_sessions.lock().await.remove(identity_id);
            }
        }
        let has_cached_address = !cached_addresses.is_empty();
        let mut addresses = cached_addresses;
        addresses.append(&mut fallback_addresses);
        addresses.sort_by_key(|address| {
            address
                .parse::<SocketAddr>()
                .map(|address| !crate::transport::is_lan_address(&address))
                .unwrap_or(true)
        });
        addresses.dedup();
        if has_cached_address {
            return Ok(addresses);
        }

        if !stale_addresses.is_empty()
            && !self
                .peer_address_state
                .lock()
                .await
                .begin_refresh(identity_id)
        {
            return Ok(addresses);
        }
        log::info!(
            target: "HAL_DHT",
            "{operation} has no usable cached address for {identity_id}; looking up DHT endpoints"
        );
        let node_id = NodeId::from_public_key(verifying_key);
        let (record_result, public_candidates_result) = tokio::join!(
            tokio::time::timeout(
                Duration::from_secs(3),
                self.lookup_endpoints(identity_id, unix_now())
            ),
            tokio::time::timeout(
                Duration::from_secs(2),
                crate::dht::endpoint_lookup::discover_public_tcp_endpoints(&node_id)
            )
        );
        match public_candidates_result {
            Ok(Ok(candidates)) => {
                for candidate in candidates {
                    let candidate = candidate.to_string();
                    if !addresses.contains(&candidate) {
                        addresses.push(candidate);
                    }
                }
            }
            Ok(Err(error)) => {
                log::debug!(
                    target: "HAL_DHT",
                    "public DHT TCP lookup failed for {identity_id}: {error:#}"
                );
            }
            Err(_) => {
                log::debug!(
                    target: "HAL_DHT",
                    "public DHT TCP lookup timed out for {identity_id}"
                );
            }
        }
        let record = match record_result {
            Ok(Ok(Some(record))) => record,
            Ok(Ok(None)) => {
                log::warn!(target: "HAL_DHT", "DHT lookup found no endpoint record for {identity_id}");
                return Ok(addresses);
            }
            Ok(Err(error)) => {
                log::warn!(target: "HAL_DHT", "DHT lookup failed for {identity_id}: {error}");
                return Ok(addresses);
            }
            Err(_) => {
                log::warn!(target: "HAL_DHT", "DHT lookup timed out for {identity_id}");
                return Ok(addresses);
            }
        };
        record.verify(unix_now())?;
        if record.identity_id != identity_id
            || record.public_key != hex::encode(verifying_key.to_bytes())
        {
            return Err(anyhow!(
                "DHT endpoint identity or public key does not match send peer"
            ));
        }
        if !stale_addresses.is_empty() {
            if let Some(new_address) = record
                .endpoints
                .iter()
                .find(|address| !stale_addresses.contains(*address))
            {
                for old_address in &stale_addresses {
                    log::info!(
                        target: "HAL_DHT",
                        "peer address refreshed: {identity_id} {old_address} -> {new_address}"
                    );
                }
            }
        }
        let mut endpoints = record.endpoints;
        endpoints.extend(addresses);
        endpoints.retain(|address| !stale_addresses.contains(address));
        endpoints.sort_by_key(|address| {
            address
                .parse::<SocketAddr>()
                .map(|address| !crate::transport::is_lan_address(&address))
                .unwrap_or(true)
        });
        endpoints.dedup();
        Ok(endpoints)
    }

    pub async fn send_file_transfer_event(
        &self,
        peer_public_key_hex: &str,
        event_type: SyncEventType,
        data: String,
    ) -> Result<()> {
        self.send_file_transfer_events(peer_public_key_hex, vec![(event_type, data)])
            .await
    }

    pub async fn send_file_transfer_events(
        &self,
        peer_public_key_hex: &str,
        events: Vec<(SyncEventType, String)>,
    ) -> Result<()> {
        if events.is_empty() {
            return Err(anyhow!("file-transfer event batch is empty"));
        }
        let peer_key_bytes: [u8; 32] = hex::decode(peer_public_key_hex)?
            .try_into()
            .map_err(|_| anyhow!("peer public key must be 32 bytes"))?;
        let verifying_key = VerifyingKey::from_bytes(&peer_key_bytes)?;
        let recipient_id = NodeId::from_public_key(&verifying_key).to_hex();
        let mut addresses = self
            .peer_addresses_for_send(&recipient_id, &verifying_key, None, "file transfer")
            .await?;
        if addresses.is_empty() {
            return Err(anyhow!(
                "no known or discoverable address for file-transfer peer {recipient_id}"
            ));
        }

        let mut signed_events = Vec::with_capacity(events.len());
        for (event_type, data) in events {
            if !matches!(
                event_type,
                SyncEventType::FileTransferInit
                    | SyncEventType::FileTransferChunk
                    | SyncEventType::FileTransferComplete
                    | SyncEventType::FileTransferCancel
            ) {
                return Err(anyhow!("event is not a file-transfer event"));
            }
            let payload: serde_json::Value = serde_json::from_str(&data)?;
            if payload
                .get("recipient_id")
                .and_then(serde_json::Value::as_str)
                != Some(recipient_id.as_str())
            {
                return Err(anyhow!(
                    "file-transfer event recipient does not match peer key"
                ));
            }
            let mut event = SyncEvent::new(uuid::Uuid::new_v4().to_string(), event_type, data);
            event.sign(&self.private_key.to_bytes())?;
            signed_events.push(event);
        }
        let envelope = self.envelope_with_integrity(SyncEnvelope::new(
            self.identity_id.clone(),
            self.public_key.clone(),
            signed_events,
        ))?;
        let envelope_size = serde_json::to_vec(&envelope)?.len();
        if envelope_size > crate::tls_transport::MAX_TLS_ENVELOPE_SIZE {
            return Err(anyhow!(
                "file-transfer event exceeds TLS envelope limit: {envelope_size} bytes"
            ));
        }

        if let Some(session) = self
            .active_sessions
            .lock()
            .await
            .get(&recipient_id)
            .map(|session| (session.address, Arc::clone(&session.mux)))
            .filter(|(address, _)| addresses.contains(&address.to_string()))
        {
            let mut mux = session.1.lock().await;
            log::info!(
                target: "HAL_DHT",
                "send_file_transfer_events: active session at {}, alive={}",
                session.0,
                mux.is_alive()
            );
            if mux.is_alive() {
                match crate::transport::send_envelope_over_mux(
                    &mut mux,
                    &envelope,
                    Some(&self.ctx.abuse_metrics),
                )
                .await
                {
                    Ok(()) => {
                        log_file_transfer_events_sent(&envelope.events, &session.0.to_string());
                        return Ok(());
                    }
                    Err(error) => {
                        log::warn!(
                            target: "HAL_DHT",
                            "send_file_transfer_events: active session send failed: {error}"
                        );
                    }
                }
            }
            drop(mux);
            self.active_sessions.lock().await.remove(&recipient_id);
        }

        let mut last_error = None;
        let mut attempted = HashSet::new();
        let mut refreshed_after_connect_failure = false;
        while let Some(index) = addresses
            .iter()
            .position(|address| !attempted.contains(address))
        {
            let Some(address) = addresses.get(index).cloned() else {
                break;
            };
            attempted.insert(address.clone());
            log::info!(
                target: "HAL_DHT",
                "send_file_transfer_events: using address {address} for peer {recipient_id}"
            );
            match send_envelope_secure_with_stream_kind_and_metrics(
                &address,
                &envelope,
                &self.private_key,
                Arc::clone(&self.ctx.hosts),
                Some(verifying_key.clone()),
                self.trust_policy.clone(),
                crate::mux::StreamKind::Sync,
                Arc::clone(&self.ctx.abuse_metrics),
            )
            .await
            {
                Ok(()) => {
                    self.add_peer_address(address.clone()).await;
                    self.peer_address_state
                        .lock()
                        .await
                        .confirm_address(&recipient_id, &address);
                    if let Err(error) = self.ctx.peer_directory.lock().await.record_outbound(
                        address.clone(),
                        recipient_id.clone(),
                        hex::encode(verifying_key.to_bytes()),
                        unix_now(),
                    ) {
                        log::debug!("peer_directory record_outbound failed: {error:?}");
                    }
                    log_file_transfer_events_sent(&envelope.events, &address);
                    return Ok(());
                }
                Err(error) => {
                    log::warn!(
                        target: "HAL_DHT",
                        "send_file_transfer_events: send to {address} failed: {error}"
                    );
                    let error_message = error.to_string();
                    if error_message.contains("TLS handshake timed out with") {
                        self.mark_peer_address_stale(&recipient_id, &address).await;
                        addresses.extend(
                            self.peer_addresses_for_send(
                                &recipient_id,
                                &verifying_key,
                                None,
                                "file transfer",
                            )
                            .await?,
                        );
                    } else if is_connection_establishment_failure(&error)
                        && !refreshed_after_connect_failure
                    {
                        refreshed_after_connect_failure = true;
                        addresses.extend(
                            self.peer_addresses_for_send(
                                &recipient_id,
                                &verifying_key,
                                None,
                                "file transfer",
                            )
                            .await?,
                        );
                    }
                    if is_connection_establishment_failure(&error)
                        && addresses
                            .iter()
                            .any(|candidate| !attempted.contains(candidate))
                    {
                        log::warn!(
                            target: "HAL_DHT",
                            "connect failed for {address}, trying next peer address"
                        );
                    }
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("all file-transfer addresses failed")))
    }

    async fn send_pending_verified_inner(
        &self,
        peer_address: &str,
        peer_public_key_hex: &str,
    ) -> Result<()> {
        let peer = pubkey_to_node_id(peer_public_key_hex)
            .map(|node_id| node_id.to_hex())
            .unwrap_or_else(|| "invalid".to_string());
        log::info!(target: "HAL_DHT", "send_pending start: peer={peer}");
        let now = unix_now();

        let node_id = pubkey_to_node_id(peer_public_key_hex)
            .ok_or_else(|| anyhow!("invalid peer public key"))?;
        if node_id == self.dht_local_id {
            log::error!(
                target: "HAL_DHT",
                "Refusing send to local identity {} (peer_public_key={})",
                self.dht_local_id.to_hex(),
                peer_public_key_hex
            );
            return Err(anyhow!("resolved message target is the local identity"));
        }

        let target_identity = node_id.to_hex();
        log::info!(target: "HAL_DHT", "send_pending: session lookup for peer={target_identity}");
        let mut events =
            pending_events_for_recipient(self.pending_events().await, &target_identity);
        if events.is_empty() {
            log::info!("send_pending_verified: no pending events for peer={target_identity}");
            return Ok(());
        }
        if events.iter().any(|event| {
            event.event_type == SyncEventType::MessageAdded
                || event.event_type == SyncEventType::GroupMessage
        }) {
            self.note_message_activity().await;
        }
        if self.ctx.trust_graph.is_some()
            && !self.ctx.record_rate_acceptance(&self.dht_local_id, now)
        {
            return Err(anyhow!(
                "rate limit reached while reserving outbound message"
            ));
        }
        for event in &mut events {
            event.sign(&self.private_key.to_bytes())?;
        }
        let peer_public_key: [u8; 32] = hex::decode(peer_public_key_hex)?
            .try_into()
            .map_err(|_| anyhow!("peer public key must be 32 bytes"))?;
        let verifying_key = VerifyingKey::from_bytes(&peer_public_key)?;
        let verifying_key_hex = hex::encode(verifying_key.to_bytes());
        let envelope = self.envelope_with_integrity(SyncEnvelope::new(
            self.identity_id.clone(),
            self.public_key.clone(),
            events,
        ))?;
        let outcome = self
            .race_pending_transports(&node_id, &envelope, &verifying_key, peer_address, now)
            .await?;
        match outcome {
            DynamicProbeSuccess::Relay(address) => Err(anyhow!(
                "RELAY_REQUIRED: relay {address} accepted the request envelope; awaiting recipient delivery confirmation"
            )),
            DynamicProbeSuccess::Tcp(address) => {
                log::info!(
                    target: "HAL_DHT",
                    "Dynamic probe: TCP won; send accepted by {address}"
                );
                self.record_successful_peer_send(
                    &node_id,
                    &address,
                    &verifying_key_hex,
                    now,
                )
                .await
            }
            DynamicProbeSuccess::Quic(address) => {
                log::info!(
                    target: "HAL_DHT",
                    "Dynamic probe: QUIC won; send accepted by {address}"
                );
                let address = address.to_string();
                self.record_successful_peer_send(
                    &node_id,
                    &address,
                    &verifying_key_hex,
                    now,
                )
                .await
            }
        }
    }

    async fn record_successful_peer_send(
        &self,
        node_id: &NodeId,
        address: &str,
        verifying_key_hex: &str,
        now: u64,
    ) -> Result<()> {
        let is_stranger = matches!(self.ctx.oracle.relationship(node_id), Relationship::Unknown);
        self.ctx.oracle.record_message(node_id, is_stranger, now);
        self.ctx.trust_metrics.inc_recorded_messages();
        self.add_peer_address(address.to_string()).await;
        if let Err(error) = self.ctx.peer_directory.lock().await.record_outbound(
            address.to_string(),
            node_id.to_hex(),
            verifying_key_hex.to_string(),
            unix_now(),
        ) {
            log::debug!("peer_directory record_outbound failed: {error:?}");
        }
        Ok(())
    }

    async fn race_pending_transports(
        &self,
        node_id: &NodeId,
        envelope: &SyncEnvelope,
        verifying_key: &VerifyingKey,
        peer_address: &str,
        now: u64,
    ) -> Result<DynamicProbeSuccess> {
        if self.force_wss_relay.load(Ordering::Acquire) {
            let url = self
                .wss_url
                .lock()
                .await
                .clone()
                .or_else(|| std::env::var("HAL_WSS_URL").ok())
                .map(|url| url.trim().to_string())
                .filter(|url| !url.is_empty())
                .ok_or_else(|| anyhow!("forced WSS relay has no configured URL"))?;
            log::info!(
                target: "HAL_DHT",
                "WSS Transport: dialing configured relay {url}; skipping TCP, QUIC, LAN, and DHT"
            );
            return self
                .submit_relay_request(node_id, envelope, now)
                .await
                .map(DynamicProbeSuccess::Relay);
        }
        log::info!(
            target: "HAL_DHT",
            "Dynamic probe: racing TCP, QUIC, and Relay..."
        );
        let started = Instant::now();
        let has_trusted_pinned_relay = self
            .ctx
            .hosts
            .lock()
            .map_err(|_| anyhow!("known hosts mutex poisoned"))?
            .identities()
            .into_iter()
            .any(|(identity_id, _)| {
                if identity_id == self.identity_id || identity_id == node_id.to_hex() {
                    return false;
                }
                NodeId::from_hex(&identity_id).is_ok_and(|relay_id| {
                    crate::relay::RelayPolicy::default_trusted().allows(
                        self.ctx.oracle.as_ref(),
                        &relay_id,
                        now,
                    )
                })
            });
        let wss_configured = self
            .wss_url
            .lock()
            .await
            .as_ref()
            .is_some_and(|url| !url.trim().is_empty())
            || std::env::var("HAL_WSS_URL").is_ok_and(|url| !url.trim().is_empty())
            || has_trusted_pinned_relay;
        let probe_timeout = if wss_configured {
            WSS_DYNAMIC_PROBE_TIMEOUT
        } else {
            DYNAMIC_PROBE_TIMEOUT
        };
        let deadline = tokio::time::Instant::now() + probe_timeout;
        let identity_id = node_id.to_hex();
        let envelope_for_tcp = envelope.clone();
        let address_for_tcp = peer_address.to_string();
        let key_for_tcp = verifying_key.clone();
        let tcp_probe = async {
            let active_session = self
                .active_sessions
                .lock()
                .await
                .get(&identity_id)
                .map(|session| (session.address, Arc::clone(&session.mux)));
            if let Some((address, mux)) = active_session {
                let mut mux = mux.lock().await;
                if mux.is_alive() {
                    match crate::transport::send_envelope_over_mux(
                        &mut mux,
                        &envelope_for_tcp,
                        Some(&self.ctx.abuse_metrics),
                    )
                    .await
                    {
                        Ok(()) => return Ok(DynamicProbeSuccess::Tcp(address.to_string())),
                        Err(error) => {
                            log::warn!(
                                target: "HAL_DHT",
                                "Dynamic probe: active TCP session failed: {error}"
                            );
                            self.active_sessions.lock().await.remove(&identity_id);
                        }
                    }
                }
            }
            let candidates = peer_address_candidates(&address_for_tcp);
            crate::transport::send_envelope_secure_with_tcp_candidates(
                &candidates,
                &envelope_for_tcp,
                &self.private_key,
                Arc::clone(&self.ctx.hosts),
                key_for_tcp,
                self.trust_policy.clone(),
                Arc::clone(&self.ctx.abuse_metrics),
            )
            .await
            .map(DynamicProbeSuccess::Tcp)
        };

        let envelope_for_quic = envelope.clone();
        let key_for_quic = verifying_key.clone();
        let quic_probe = async {
            if let Err(error) = self.publish_punch_request(*node_id, 300).await {
                log::warn!("publish_punch_request failed: {error}");
            }
            let endpoint = self
                .quic_listener_endpoint
                .read()
                .await
                .clone()
                .ok_or_else(|| anyhow!("QUIC UDP listener is unavailable"))?;
            let rendezvous_address = *self
                .public_quic_endpoint
                .read()
                .map_err(|error| anyhow!("public QUIC endpoint state lock poisoned: {error}"))?;
            if let Some(address) = rendezvous_address {
                if !address.ip().is_loopback()
                    && !address.ip().is_unspecified()
                    && address.port() != 0
                {
                    let topic = quic_punch_dht_topic(&self.identity_id, &identity_id);
                    tokio::spawn(async move {
                        match PublicDhtProvider::new(&topic)
                            .with_timeout(Duration::from_secs(5))
                            .announce(address.port())
                            .await
                        {
                            Ok(()) => log::info!(
                                target: "HAL_DHT",
                                "QUIC punch rendezvous announced to {topic}: {address}"
                            ),
                            Err(error) => log::warn!(
                                target: "HAL_DHT",
                                "QUIC punch rendezvous announce failed for {topic}: {error}"
                            ),
                        }
                    });
                }
            }
            let lookup = DhtEndpointLookup::new(
                self.dht_local_id,
                self.private_key.clone(),
                Arc::clone(&self.ctx.hosts),
                self.trust_policy.clone(),
                Arc::clone(&self.dht_routing),
                Arc::clone(&self.dht_cache),
            );
            let candidates = lookup.lookup_quic(node_id, now).await?;
            if candidates.is_empty() {
                log::warn!(
                    target: "HAL_DHT",
                    "HolePunch: failed (no authenticated UDP endpoint); relay fallback remains active"
                );
                return Err(anyhow!("peer has no published QUIC UDP endpoint"));
            }
            let mut last_error = None;
            for remote_addr in candidates {
                log::info!(target: "HAL_DHT", "WAN endpoint detected: {remote_addr}");
                log::info!(
                    target: "HAL_DHT",
                    "HolePunch: sent probe to {remote_addr}"
                );
                let channel = QuicChannel::connect_on_endpoint(
                    Arc::clone(&endpoint),
                    remote_addr,
                    "hal-sync",
                    &self.private_key,
                    Some(key_for_quic.clone()),
                    Arc::clone(&self.ctx.hosts),
                    Arc::clone(&self.ctx.abuse_metrics),
                )
                .await;
                match channel {
                    Ok(channel) => {
                        log::info!(
                            target: "HAL_DHT",
                            "HolePunch: received probe response from {remote_addr}"
                        );
                        send_envelope_quic(
                            &channel,
                            &envelope_for_quic,
                            Some(&self.ctx.abuse_metrics),
                        )
                        .await?;
                        log::info!(
                            target: "HAL_DHT",
                            "HolePunch: tunnel established to {remote_addr}"
                        );
                        return Ok(DynamicProbeSuccess::Quic(remote_addr));
                    }
                    Err(error) => {
                        log::warn!(
                            target: "HAL_DHT",
                            "HolePunch: failed for {remote_addr}: {error}"
                        );
                        last_error = Some(error.to_string());
                    }
                }
            }
            Err(anyhow!(
                "all QUIC endpoints failed: {}",
                last_error.unwrap_or_else(|| "no reachable UDP endpoint".to_string())
            ))
        };

        let envelope_for_relay = envelope.clone();
        let relay_probe = async {
            self.submit_relay_request(node_id, &envelope_for_relay, now)
                .await
                .map(DynamicProbeSuccess::Relay)
        };

        tokio::pin!(tcp_probe);
        tokio::pin!(quic_probe);
        tokio::pin!(relay_probe);
        let mut tcp_done = false;
        let mut quic_done = false;
        let mut relay_done = false;
        let mut errors = Vec::new();
        let winner = loop {
            if tcp_done && quic_done && relay_done {
                break None;
            }
            tokio::select! {
                result = &mut tcp_probe, if !tcp_done => {
                    tcp_done = true;
                    match result {
                        Ok(success) => break Some(success),
                        Err(error) => {
                            log::warn!(target: "HAL_DHT", "Dynamic probe: TCP failed: {error}");
                            errors.push(format!("TCP: {error}"));
                        }
                    }
                }
                result = &mut quic_probe, if !quic_done => {
                    quic_done = true;
                    match result {
                        Ok(success) => break Some(success),
                        Err(error) => {
                            log::warn!(target: "HAL_DHT", "Dynamic probe: QUIC failed: {error}");
                            errors.push(format!("QUIC: {error}"));
                        }
                    }
                }
                result = &mut relay_probe, if !relay_done => {
                    relay_done = true;
                    match result {
                        Ok(success) => break Some(success),
                        Err(error) => {
                            log::warn!(target: "HAL_DHT", "Dynamic probe: Relay failed: {error}");
                            errors.push(format!("Relay: {error}"));
                        }
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    log::warn!(
                        target: "HAL_DHT",
                        "Dynamic probe: all probes timed out after {}ms",
                        started.elapsed().as_millis()
                    );
                    break None;
                }
            }
        };
        match winner {
            Some(success @ DynamicProbeSuccess::Tcp(_)) => {
                log::info!(
                    target: "HAL_DHT",
                    "Dynamic probe: TCP won after {}ms",
                    started.elapsed().as_millis()
                );
                Ok(success)
            }
            Some(success @ DynamicProbeSuccess::Quic(_)) => {
                log::info!(
                    target: "HAL_DHT",
                    "Dynamic probe: QUIC won after {}ms",
                    started.elapsed().as_millis()
                );
                Ok(success)
            }
            Some(success @ DynamicProbeSuccess::Relay(_)) => {
                log::info!(
                    target: "HAL_DHT",
                    "Dynamic probe: Relay request accepted after {}ms; recipient ACK is still required",
                    started.elapsed().as_millis()
                );
                Ok(success)
            }
            None => {
                log::warn!(
                    target: "HAL_DHT",
                    "Dynamic probe: all probes failed within {}ms: {}",
                    started.elapsed().as_millis(),
                    errors.join("; ")
                );
                Err(anyhow!("ERROR:timeout:all_probes_failed"))
            }
        }
    }

    #[cfg(test)]
    async fn relay_fallback_after_direct_failure(
        &self,
        target_id: &NodeId,
        envelope: &SyncEnvelope,
        now: u64,
        direct_error: String,
    ) -> Result<()> {
        match self.submit_relay_request(target_id, envelope, now).await {
            Ok(relay_address) => {
                log::warn!(
                    target: "HAL_DHT",
                    "RELAY_REQUIRED: relay {relay_address} acknowledged the request envelope; recipient delivery is not yet confirmed"
                );
                Err(anyhow!(
                    "{direct_error}; RELAY_REQUIRED: relay {relay_address} acknowledged the request envelope, awaiting recipient delivery confirmation"
                ))
            }
            Err(relay_error) => {
                log::warn!(
                    target: "HAL_DHT",
                    "RELAY_REQUIRED: relay fallback unavailable for {}: {relay_error}",
                    target_id.to_hex()
                );
                Err(anyhow!("{direct_error}; RELAY_REQUIRED: {relay_error}"))
            }
        }
    }

    async fn submit_relay_request(
        &self,
        target_id: &NodeId,
        envelope: &SyncEnvelope,
        now: u64,
    ) -> Result<String> {
        if *target_id == self.dht_local_id {
            log::warn!(
                target: "HAL_DHT",
                "Relay target resolved to local requester {}; refusing self-relay",
                target_id.to_hex()
            );
            return Err(anyhow!("relay target resolved to local requester"));
        }
        let wss_url = self
            .wss_url
            .lock()
            .await
            .clone()
            .or_else(|| std::env::var("HAL_WSS_URL").ok())
            .map(|url| url.trim().to_string())
            .filter(|url| !url.is_empty());
        let force_wss_relay = self.force_wss_relay.load(Ordering::Acquire);
        let mut relay_candidates = if force_wss_relay {
            Vec::new()
        } else {
            self.ctx
                .peer_directory
                .lock()
                .await
                .entries(&[], now)
                .into_iter()
                .filter(|entry| {
                    entry.identity_id != self.identity_id && entry.identity_id != target_id.to_hex()
                })
                .filter(|entry| entry.address.parse::<SocketAddr>().is_ok())
                .filter(|entry| self.trust_policy.allows_relay(&entry.address))
                .filter(|entry| {
                    let Ok(relay_id) = NodeId::from_hex(&entry.identity_id) else {
                        return false;
                    };
                    crate::relay::RelayPolicy::default_trusted().allows(
                        self.ctx.oracle.as_ref(),
                        &relay_id,
                        now,
                    )
                })
                .collect::<Vec<_>>()
        };
        relay_candidates.sort_by_key(|entry| std::cmp::Reverse(entry.last_seen));
        let mut seen_candidates = HashSet::new();
        relay_candidates.retain(|entry| seen_candidates.insert(entry.identity_id.clone()));

        let mut candidates = Vec::new();
        for relay_candidate in relay_candidates {
            let relay_is_relay = match tokio::time::timeout(
                Duration::from_secs(3),
                self.lookup_endpoints(&relay_candidate.identity_id, now),
            )
            .await
            {
                Ok(Ok(Some(record))) => record.is_relay,
                Ok(Ok(None)) => false,
                Ok(Err(error)) => {
                    log::warn!(
                        target: "HAL_DHT",
                        "Relay Selection: DHT lookup failed for candidate {}: {error}",
                        relay_candidate.identity_id
                    );
                    false
                }
                Err(_) => false,
            };
            log::info!(
                target: "HAL_DHT",
                "Relay Selection: found candidate {}, is_relay={}",
                relay_candidate.identity_id,
                relay_is_relay
            );
            if relay_is_relay {
                candidates.push((
                    relay_candidate.identity_id,
                    relay_candidate.address,
                    relay_candidate.public_key_hex,
                    false,
                ));
            }
        }
        candidates.truncate(3);

        let pinned_identities = self
            .ctx
            .hosts
            .lock()
            .map_err(|_| anyhow!("known hosts mutex poisoned"))?
            .identities();
        let trusted_pins = pinned_identities
            .into_iter()
            .filter(|(identity_id, _)| {
                identity_id != &self.identity_id && identity_id != &target_id.to_hex()
            })
            .filter_map(|(identity_id, public_key_hex)| {
                let relay_id = NodeId::from_hex(&identity_id).ok()?;
                let key_bytes: [u8; 32] = hex::decode(&public_key_hex).ok()?.try_into().ok()?;
                let relay_key = VerifyingKey::from_bytes(&key_bytes).ok()?;
                if NodeId::from_public_key(&relay_key) != relay_id
                    || !crate::relay::RelayPolicy::default_trusted().allows(
                        self.ctx.oracle.as_ref(),
                        &relay_id,
                        now,
                    )
                {
                    return None;
                }
                Some((identity_id, public_key_hex))
            })
            .collect::<Vec<_>>();
        if let Some(url) = wss_url.as_ref() {
            for (identity_id, public_key_hex) in &trusted_pins {
                candidates.push((
                    identity_id.clone(),
                    url.clone(),
                    public_key_hex.clone(),
                    true,
                ));
            }
        }
        if !force_wss_relay {
            let public_records = futures::future::join_all(trusted_pins.iter().map(
                |(identity_id, public_key_hex)| async move {
                    (
                        identity_id,
                        public_key_hex,
                        crate::dht::endpoint_lookup::discover_public_endpoint_record(
                            public_key_hex,
                            now,
                        )
                        .await,
                    )
                },
            ))
            .await;
            for (identity_id, public_key_hex, record_result) in public_records {
                match record_result {
                    Ok(Some(record)) if record.is_relay => {
                        if let Some(url) = record.wss_url {
                            candidates.push((
                                identity_id.clone(),
                                url,
                                public_key_hex.clone(),
                                true,
                            ));
                        }
                    }
                    Ok(_) => {}
                    Err(error) => log::debug!(
                        target: "HAL_DHT",
                        "Mainline DHT relay lookup failed for trusted identity {identity_id}: {error:#}"
                    ),
                }
            }
        }
        candidates.sort_by_key(|(_, _, _, use_wss)| !*use_wss);

        if candidates.is_empty() {
            return Err(anyhow!("no reachable trusted relay candidate is known"));
        }

        let envelope_bytes = serde_json::to_vec(envelope)
            .map_err(|error| anyhow!("serialize inner relay envelope: {error}"))?;
        let mut last_error = None;
        for (relay_identity_id, relay_address, relay_public_key_hex, use_wss) in candidates {
            let relay_key_bytes: [u8; 32] = match hex::decode(&relay_public_key_hex)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
            {
                Some(bytes) => bytes,
                None => {
                    last_error = Some(format!(
                        "relay {} has an invalid public key",
                        relay_identity_id
                    ));
                    continue;
                }
            };
            let relay_key = match VerifyingKey::from_bytes(&relay_key_bytes) {
                Ok(key) if NodeId::from_public_key(&key).to_hex() == relay_identity_id => key,
                Ok(_) => {
                    last_error = Some(format!(
                        "relay {} public key does not match its identity",
                        relay_identity_id
                    ));
                    continue;
                }
                Err(error) => {
                    last_error = Some(format!(
                        "relay {} public key is invalid: {error}",
                        relay_identity_id
                    ));
                    continue;
                }
            };
            let mut nonce = [0u8; 16];
            OsRng.fill_bytes(&mut nonce);
            let request = match crate::relay::RelayRequest::create(
                self.dht_local_id,
                *target_id,
                envelope_bytes.clone(),
                crate::relay::RELAY_DEFAULT_TTL_SECS,
                now,
                Vec::new(),
                &self.private_key,
                nonce,
            ) {
                Ok(request) => request,
                Err(error) => return Err(anyhow!("create signed relay request: {error}")),
            };
            let mut request_event = SyncEvent::new(
                hex::encode(nonce),
                SyncEventType::RelayRequest,
                request
                    .to_base64()
                    .map_err(|error| anyhow!("encode signed relay request: {error}"))?,
            );
            request_event.sign(&self.private_key.to_bytes())?;
            let relay_envelope = SyncEnvelope::new(
                self.identity_id.clone(),
                self.public_key.clone(),
                vec![request_event],
            );
            let (response_tx, response_rx) = oneshot::channel();
            self.ctx
                .relay_tracker
                .lock()
                .await
                .insert(nonce, response_tx);
            log::info!(
                target: "HAL_DHT",
                "RELAY_REQUIRED: trying relay {} at {} for target {}",
                relay_identity_id,
                relay_address,
                target_id.to_hex()
            );
            log::info!(
                target: "HAL_DHT",
                "Sending RelayRequest: target={}, via relay={}",
                target_id.to_hex(),
                relay_identity_id
            );
            let attempt_timeout = if use_wss {
                WSS_RELAY_ATTEMPT_TIMEOUT
            } else {
                Duration::from_secs(8)
            };
            match tokio::time::timeout(attempt_timeout, async {
                if use_wss {
                    log::info!(
                        target: "HAL_DHT",
                        "WSS Transport: dialing {relay_address} with pinned relay identity {relay_identity_id}"
                    );
                    log::info!(
                        target: "HAL_DHT",
                        "WSS Transport: sending signed RelayRequest for {} via {}",
                        target_id.to_hex(),
                        relay_address
                    );
                    self.open_wss_client_session(&relay_address, Some(relay_key))
                        .await?
                        .send_envelope(relay_envelope)
                        .await
                } else {
                    send_envelope_secure_with_stream_kind_and_metrics(
                        &relay_address,
                        &relay_envelope,
                        &self.private_key,
                        Arc::clone(&self.ctx.hosts),
                        Some(relay_key),
                        self.trust_policy.clone(),
                        crate::mux::StreamKind::Sync,
                        Arc::clone(&self.ctx.abuse_metrics),
                    )
                    .await
                }
            })
            .await
            {
                Ok(Ok(())) => {
                    log::info!(
                        target: "HAL_DHT",
                        "RelayRequest sent for {} via relay {}",
                        target_id.to_hex(),
                        relay_identity_id
                    );
                    log::info!(
                        target: "HAL_DHT",
                        "relay endpoint acknowledged request envelope at {} for target {}; relay policy and end-to-end delivery are not yet confirmed",
                        relay_address,
                        target_id.to_hex()
                    );
                    match tokio::time::timeout(Duration::from_secs(10), response_rx).await {
                        Ok(Ok(crate::relay::RelayResponse::Forwarded)) => {
                            log::info!(
                                target: "HAL_DHT",
                                "RelayResponse received: Forwarded for target {} via {}",
                                target_id.to_hex(),
                                relay_identity_id
                            );
                            return Ok(relay_address);
                        }
                        Ok(Ok(response)) => {
                            self.ctx.relay_tracker.lock().await.remove(&nonce);
                            last_error =
                                Some(format!("relay rejected or deferred request: {response:?}"));
                        }
                        Ok(Err(_)) => {
                            self.ctx.relay_tracker.lock().await.remove(&nonce);
                            last_error = Some("relay response channel closed".to_string());
                        }
                        Err(_) => {
                            self.ctx.relay_tracker.lock().await.remove(&nonce);
                            last_error = Some("timed out waiting for RelayResponse".to_string());
                        }
                    }
                }
                Ok(Err(error)) => {
                    self.ctx.relay_tracker.lock().await.remove(&nonce);
                    if use_wss {
                        self.wss_sessions.lock().await.remove(&relay_identity_id);
                        log::debug!(
                            target: "HAL_DHT",
                            "WSS Transport: failed, falling back to TCP/LAN: {error}"
                        );
                    } else {
                        log::warn!(
                            target: "HAL_DHT",
                            "relay connect/send failed for {} at {}: {error}",
                            relay_identity_id,
                            relay_address
                        );
                    }
                    last_error = Some(error.to_string());
                }
                Err(_) => {
                    self.ctx.relay_tracker.lock().await.remove(&nonce);
                    if use_wss {
                        self.wss_sessions.lock().await.remove(&relay_identity_id);
                        log::debug!(
                            target: "HAL_DHT",
                            "WSS Transport: failed, falling back to TCP/LAN: relay connect/send timed out"
                        );
                    } else {
                        log::warn!(
                            target: "HAL_DHT",
                            "relay connect/send timed out for {} at {}",
                            relay_identity_id,
                            relay_address
                        );
                    }
                    last_error = Some("relay connect/send timed out".to_string());
                }
            }
        }
        Err(anyhow!(
            "all trusted relay candidates failed: {}",
            last_error.unwrap_or_else(|| "no candidate accepted the request".to_string())
        ))
    }

    fn is_existing_contact(&self, recipient_identity_hex: &str) -> bool {
        self.ctx
            .hosts
            .lock()
            .map(|hosts| hosts.record_of(recipient_identity_hex).is_some())
            .unwrap_or(false)
    }

    async fn enforce_cold_contact_stigma(&self, recipient: &NodeId, now: u64) -> Result<()> {
        if self.is_existing_contact(&recipient.to_hex()) {
            return Ok(());
        }
        match self.ctx.stigma_gate(&self.dht_local_id, now).await {
            StigmaLevel::Stigma { .. } => {
                self.ctx.trust_metrics.inc_send_stigma_blocked();
                Err(anyhow!("cold contact forbidden: sender under stigma"))
            }
            StigmaLevel::Watching { .. } => {
                self.ctx.trust_metrics.inc_send_watching_seen();
                Ok(())
            }
            StigmaLevel::Clean | StigmaLevel::Cleared { .. } => Ok(()),
        }
    }

    pub async fn send_media_signal(&self, peer_address: &str, signal: Vec<u8>) -> Result<()> {
        if !peer_address_candidates(peer_address)
            .iter()
            .any(|candidate| self.trust_policy.allows_media(candidate))
        {
            return Err(anyhow!(
                "media signaling requires a higher network trust level"
            ));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.request_activity(ActivityTrigger::Call, now).await;
        let envelope = self.envelope_with_integrity(SyncEnvelope::new_media_signal(
            self.identity_id.clone(),
            self.public_key.clone(),
            signal,
        ))?;
        let mut last_error = None;
        for candidate in peer_address_candidates(peer_address) {
            if classify_candidate(&candidate) == TransportTier::Relay
                && !self.trust_policy.allows_relay(&candidate)
            {
                continue;
            }
            match send_envelope_secure_with_stream_kind_and_metrics(
                &candidate,
                &envelope,
                &self.private_key,
                Arc::clone(&self.ctx.hosts),
                None,
                self.trust_policy.clone(),
                crate::mux::StreamKind::MediaSignal,
                Arc::clone(&self.ctx.abuse_metrics),
            )
            .await
            {
                Ok(()) => return Ok(()),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("all media transport paths failed")))
    }

    pub async fn take_media_signals(&self) -> Vec<(String, Vec<u8>)> {
        std::mem::take(&mut *self.ctx.media_signals.lock().await)
    }

    fn envelope_with_integrity(&self, envelope: SyncEnvelope) -> Result<SyncEnvelope> {
        let Some(wave) = &self.ctx.integrity else {
            return Ok(envelope);
        };
        let measurement = self
            .software_measurement
            .clone()
            .ok_or_else(|| anyhow!("integrity runtime has no software measurement"))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut response = IntegrityResponse::new(wave, self.public_key.clone(), measurement, now)?;
        response.sign(&self.private_key.to_bytes());
        Ok(envelope.with_integrity_response(response))
    }

    pub async fn contact_count(&self) -> usize {
        self.ctx.sync.lock().await.get_contact_count()
    }

    pub async fn take_poll_actions(&self) -> Vec<PollRequest> {
        std::mem::take(&mut *self.poll_actions.lock().await)
    }

    pub async fn dispatch_poll_actions(&self, dispatcher: &PollDispatcher) -> Result<usize> {
        let actions = self.take_poll_actions().await;
        let mut handled = 0;
        for action in actions {
            if dispatcher.dispatch(action).await? {
                handled += 1;
            }
        }
        Ok(handled)
    }

    pub async fn peer_addresses(&self) -> Vec<String> {
        self.peers.lock().await.clone()
    }

    /// List runtime-known peers that have a live identity binding.
    pub async fn peer_entries(&self) -> Vec<PeerEntry> {
        let now = unix_now();
        let hint = self.peers.lock().await.clone();
        let directory = self.ctx.peer_directory.lock().await;
        directory.entries(&hint, now)
    }

    /// Look up the live identity binding for an address.
    pub async fn peer_lookup_by_address(&self, addr: &str) -> Option<PeerEntry> {
        let now = unix_now();
        self.ctx
            .peer_directory
            .lock()
            .await
            .lookup_by_address(addr, now)
            .cloned()
    }

    /// Return all live addresses associated with an identity.
    pub async fn peer_addresses_of(&self, identity_id: &str) -> Vec<String> {
        let now = unix_now();
        self.ctx
            .peer_directory
            .lock()
            .await
            .addresses_of(identity_id, now)
    }

    pub async fn last_known_peer_address(&self, identity_id: &str) -> Result<Option<String>> {
        let Some(storage) = self.ctx.storage.as_ref() else {
            return Ok(None);
        };
        storage
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?
            .peer_registry()
            .latest_address(identity_id)
            .map_err(|error| anyhow!("failed loading last peer address: {error}"))
    }

    pub async fn send_profile_update_to_peer(
        &self,
        identity_id: &str,
        peer_public_key_hex: &str,
        display_name: &str,
        avatar_b64: Option<&str>,
    ) -> Result<()> {
        let public_key_bytes: [u8; 32] = hex::decode(peer_public_key_hex)?
            .try_into()
            .map_err(|_| anyhow!("peer public key must be 32 bytes"))?;
        let public_key = VerifyingKey::from_bytes(&public_key_bytes)?;
        if NodeId::from_public_key(&public_key).to_hex() != identity_id {
            return Err(anyhow!("peer public key does not match profile recipient"));
        }
        self.ctx
            .sync
            .lock()
            .await
            .add_profile_update_event(crate::ProfileUpdatePayload {
                display_name: display_name.to_owned(),
                avatar_b64: avatar_b64.map(str::to_owned),
                recipient_id: identity_id.to_owned(),
            })?;

        let mut addresses = self.peer_addresses_of(identity_id).await;
        if addresses.is_empty() {
            if let Some(address) = self.last_known_peer_address(identity_id).await? {
                addresses.push(address);
            }
        }
        if addresses.is_empty() {
            return Err(anyhow!("no known address for ProfileUpdate recipient"));
        }
        let mut last_error = None;
        for address in addresses {
            match self
                .send_pending_verified(&address, peer_public_key_hex)
                .await
            {
                Ok(()) => {
                    log::info!("sent ProfileUpdate to invited peer {identity_id}");
                    return Ok(());
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("no address accepted ProfileUpdate")))
    }

    pub async fn is_peer_online(&self, identity_id: &str) -> bool {
        let is_present = self
            .ctx
            .home_state
            .lock()
            .await
            .cached_presence
            .get(identity_id)
            .is_some_and(|peer| {
                peer.last_seen
                    .saturating_add(crate::peer_presence::PRESENCE_TTL_SECS)
                    > unix_now()
            });
        if is_present {
            return true;
        }
        let has_recent_send_failure = {
            let mut failures = self.recent_send_failures.lock().await;
            match failures.get(identity_id) {
                Some(failed_at) if failed_at.elapsed() < RECENT_SEND_FAILURE_WINDOW => true,
                Some(_) => {
                    failures.remove(identity_id);
                    false
                }
                None => false,
            }
        };
        if has_recent_send_failure {
            return false;
        }

        let session = self
            .active_sessions
            .lock()
            .await
            .get(identity_id)
            .map(|session| Arc::clone(&session.mux));
        let Some(session) = session else {
            return false;
        };
        let is_alive = session.lock().await.is_alive();
        is_alive
    }

    pub async fn request_home_presence(
        &self,
    ) -> Result<Vec<crate::peer_presence::PeerPresenceRecord>> {
        let home_stack_id = self
            .ctx
            .home_state
            .lock()
            .await
            .home_stack_id
            .clone()
            .ok_or_else(|| anyhow!("local Home Stack is not registered"))?;
        let relay_url = self
            .wss_url
            .lock()
            .await
            .clone()
            .filter(|url| !url.trim().is_empty())
            .ok_or_else(|| anyhow!("WSS relay URL is not configured"))?;
        let session = self.open_wss_client_session(&relay_url, None).await?;
        let peer_identity_id = session.peer_identity_id().to_string();
        let peer_public_key = session.peer_public_key_hex().to_string();
        if !matches!(
            self.ctx
                .hosts
                .lock()
                .map_err(|_| anyhow!("known hosts mutex poisoned"))?
                .check(&peer_identity_id, &peer_public_key),
            crate::pinning::BindingCheck::Trusted
        ) {
            return Err(anyhow!(
                "WSS relay must be paired and pinned before requesting Home Presence"
            ));
        }

        let request_id = uuid::Uuid::new_v4().to_string();
        let (response_tx, response_rx) = oneshot::channel();
        self.ctx
            .home_state
            .lock()
            .await
            .pending_presence_requests
            .insert(request_id.clone(), response_tx);
        let mut endpoints = self.transport_addresses();
        endpoints.truncate(crate::peer_presence::PRESENCE_MAX_ENDPOINTS);
        let request = crate::peer_presence::PeerPresenceMessage::Request {
            request_id: request_id.clone(),
            home_stack_id,
            endpoints,
            wss_url: Some(relay_url),
        };
        let envelope = match home_presence_envelope(&self.ctx, request) {
            Ok(envelope) => envelope,
            Err(error) => {
                self.ctx
                    .home_state
                    .lock()
                    .await
                    .pending_presence_requests
                    .remove(&request_id);
                return Err(error);
            }
        };
        if let Err(error) = session.send_envelope(envelope).await {
            self.ctx
                .home_state
                .lock()
                .await
                .pending_presence_requests
                .remove(&request_id);
            return Err(anyhow!("failed to send Home Presence request: {error}"));
        }
        let response = match tokio::time::timeout(Duration::from_secs(12), response_rx).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                self.ctx
                    .home_state
                    .lock()
                    .await
                    .pending_presence_requests
                    .remove(&request_id);
                return Err(anyhow!("Home Presence response channel closed"));
            }
            Err(_) => {
                self.ctx
                    .home_state
                    .lock()
                    .await
                    .pending_presence_requests
                    .remove(&request_id);
                return Err(anyhow!("Home Presence request timed out"));
            }
        };
        match response {
            crate::peer_presence::PeerPresenceMessage::Response { peers, .. } => Ok(peers),
            crate::peer_presence::PeerPresenceMessage::Error { reason, .. } => {
                Err(anyhow!("Home Presence request rejected: {reason}"))
            }
            crate::peer_presence::PeerPresenceMessage::Request { .. } => {
                Err(anyhow!("unexpected Home Presence request response"))
            }
        }
    }

    pub async fn cached_home_presence(&self) -> Vec<crate::peer_presence::PeerPresenceRecord> {
        let now = unix_now();
        let mut state = self.ctx.home_state.lock().await;
        state.cached_presence.retain(|_, peer| {
            peer.last_seen
                .saturating_add(crate::peer_presence::PRESENCE_TTL_SECS)
                > now
        });
        let mut peers = state.cached_presence.values().cloned().collect::<Vec<_>>();
        peers.sort_by(|left, right| left.identity_id.cmp(&right.identity_id));
        peers
    }

    pub async fn mark_peer_offline(&self, identity_id: &str) {
        self.active_sessions.lock().await.remove(identity_id);
        let mut failures = self.recent_send_failures.lock().await;
        failures.retain(|_, failed_at| failed_at.elapsed() < RECENT_SEND_FAILURE_WINDOW);
        failures.insert(identity_id.to_string(), Instant::now());
    }

    pub async fn add_peer_address(&self, address: String) {
        let mut peers = self.peers.lock().await;
        if !peers.contains(&address) {
            peers.push(address);
        }
    }

    /// Explicitly anchor a peer identity after invite/QR/SAS verification.
    /// Unknown peers are never pinned implicitly by transport traffic.
    pub async fn pin_peer(&self, identity_id: &str, public_key_hex: &str) -> Result<()> {
        pin_identity_in_context(&self.ctx, identity_id, public_key_hex)
    }

    async fn open_wss_client_session(
        &self,
        url: &str,
        expected_peer_key: Option<VerifyingKey>,
    ) -> Result<crate::transport::WssClientSessionHandle> {
        let (handle, mut incoming) =
            crate::transport::connect_wss_client_session(url, &self.private_key, expected_peer_key)
                .await?;
        let peer_identity_id = handle.peer_identity_id().to_string();
        let peer_public_key_hex = handle.peer_public_key_hex().to_string();
        match self
            .ctx
            .hosts
            .lock()
            .map_err(|_| anyhow!("known hosts mutex poisoned"))?
            .check(&peer_identity_id, &peer_public_key_hex)
        {
            crate::pinning::BindingCheck::Conflicted { .. } => {
                return Err(anyhow!(
                    "WSS peer identity conflicts with an existing trust pin"
                ));
            }
            crate::pinning::BindingCheck::Trusted | crate::pinning::BindingCheck::Unknown => {}
        }

        {
            let mut sessions = self.wss_sessions.lock().await;
            if let Some(existing) = sessions
                .get(&peer_identity_id)
                .filter(|session| session.is_alive())
            {
                return Ok(existing.clone());
            }
            sessions.insert(peer_identity_id.clone(), handle.clone());
        }
        let ctx = Arc::clone(&self.ctx);
        tokio::spawn(async move {
            while let Some((envelope, meta)) = incoming.recv().await {
                PeerRuntime::process_incoming_envelope_with_meta(envelope, meta, Arc::clone(&ctx))
                    .await;
            }
            log::debug!("WSS incoming envelope processor stopped for {peer_identity_id}");
        });
        Ok(handle)
    }

    pub async fn begin_wss_sas_pairing(&self, url: &str) -> Result<String> {
        *self.wss_url.lock().await = Some(url.trim().to_string());
        let handle = self.open_wss_client_session(url, None).await?;
        let peer_identity_id = handle.peer_identity_id().to_string();
        let peer_public_key_hex = handle.peer_public_key_hex().to_string();
        match self
            .ctx
            .hosts
            .lock()
            .map_err(|_| anyhow!("known hosts mutex poisoned"))?
            .check(&peer_identity_id, &peer_public_key_hex)
        {
            crate::pinning::BindingCheck::Trusted => {
                return Err(anyhow!("WSS peer is already trusted"));
            }
            crate::pinning::BindingCheck::Conflicted { .. } => {
                return Err(anyhow!(
                    "WSS peer identity conflicts with an existing trust pin"
                ));
            }
            crate::pinning::BindingCheck::Unknown => {}
        }
        let mut session_id_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut session_id_bytes);
        let contribution = crate::pairing_sas::SasContribution::create(
            session_id_bytes,
            crate::pairing_sas::SasRole::Initiator,
            self.identity_id.clone(),
            self.public_key.clone(),
            peer_identity_id.clone(),
        )?;
        let session_id = contribution.commitment().session_id.clone();
        let mut session = crate::pairing_sas::SasPairingSession::new(
            contribution,
            peer_identity_id,
            peer_public_key_hex,
        );
        session.local_commitment_sent = true;
        let message = crate::pairing_sas::SasPairingMessage::Commitment {
            commitment: session.contribution.commitment(),
        };
        prune_expired_sas_pairings(&self.ctx).await;
        let mut sessions = self.ctx.sas_pairing.sessions.lock().await;
        if sessions.len() >= crate::pairing_sas::SAS_PAIRING_MAX_SESSIONS {
            return Err(anyhow!("too many active SAS pairing sessions"));
        }
        sessions.insert(session_id.clone(), session);
        drop(sessions);
        let envelope = sas_pairing_envelope(&self.ctx, message)?;
        if let Err(error) = handle.send_envelope(envelope).await {
            self.ctx
                .sas_pairing
                .sessions
                .lock()
                .await
                .remove(&session_id);
            return Err(anyhow!("failed to send SAS commitment: {error}"));
        }
        Ok(session_id)
    }

    #[cfg(debug_assertions)]
    pub async fn reset_wss_peer_pin_and_begin_sas_pairing(&self, url: &str) -> Result<String> {
        let handle = self.open_wss_client_session(url, None).await?;
        let peer_identity_id = handle.peer_identity_id().to_string();
        let peer_public_key_hex = handle.peer_public_key_hex().to_string();
        let mut hosts = self
            .ctx
            .hosts
            .lock()
            .map_err(|_| anyhow!("known hosts mutex poisoned"))?;

        match hosts.check(&peer_identity_id, &peer_public_key_hex) {
            crate::pinning::BindingCheck::Trusted => {}
            crate::pinning::BindingCheck::Unknown => {
                drop(hosts);
                return self.begin_wss_sas_pairing(url).await;
            }
            crate::pinning::BindingCheck::Conflicted { .. } => {
                return Err(anyhow!(
                    "WSS peer identity conflicts with an existing trust pin"
                ));
            }
        }

        let storage =
            self.ctx.storage.as_ref().ok_or_else(|| {
                anyhow!("persistent storage is unavailable; WSS pin was not removed")
            })?;
        let removed = storage
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?
            .peer_registry()
            .remove_trust_pin(&peer_identity_id, &peer_public_key_hex)
            .map_err(|error| anyhow!("failed to remove WSS trust pin: {error}"))?;
        if !removed {
            return Err(anyhow!(
                "matching persistent WSS trust pin was not found; in-memory pin was preserved"
            ));
        }
        if !hosts.remove_if_matches(&peer_identity_id, &peer_public_key_hex) {
            return Err(anyhow!(
                "in-memory WSS trust pin changed while it was being removed"
            ));
        }
        drop(hosts);

        log::warn!(
            target: "HAL_DHT",
            "Debug SAS retry removed stale WSS trust pin for peer {}",
            peer_identity_id
        );
        self.begin_wss_sas_pairing(url).await
    }

    pub async fn pending_sas_pairing_prompts(&self) -> Vec<crate::pairing_sas::SasPairingPrompt> {
        prune_expired_sas_pairings(&self.ctx).await;
        let mut prompts = self
            .ctx
            .sas_pairing
            .prompts
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        prompts.sort_by(|left, right| left.session_id.cmp(&right.session_id));
        prompts
    }

    pub async fn confirm_sas_pairing(&self, session_id: &str, accepted: bool) -> Result<()> {
        prune_expired_sas_pairings(&self.ctx).await;
        let (peer_identity_id, peer_public_key_hex, mux_sender, message, should_complete) = {
            let mut sessions = self.ctx.sas_pairing.sessions.lock().await;
            let session = sessions
                .get_mut(session_id)
                .ok_or_else(|| anyhow!("SAS pairing session was not found"))?;
            if session.code.is_none() {
                return Err(anyhow!("SAS code has not been verified yet"));
            }
            if !accepted {
                (
                    session.peer_identity_id.clone(),
                    session.peer_public_key_hex.clone(),
                    session.mux_sender.clone(),
                    crate::pairing_sas::SasPairingMessage::Confirm {
                        session_id: session_id.to_string(),
                        accepted: false,
                    },
                    false,
                )
            } else {
                let should_complete = session.record_local_confirmation()?;
                (
                    session.peer_identity_id.clone(),
                    session.peer_public_key_hex.clone(),
                    session.mux_sender.clone(),
                    crate::pairing_sas::SasPairingMessage::Confirm {
                        session_id: session_id.to_string(),
                        accepted: true,
                    },
                    should_complete,
                )
            }
        };
        self.send_sas_pairing_message(&peer_identity_id, mux_sender.clone(), message)
            .await?;

        if !accepted {
            self.ctx
                .sas_pairing
                .sessions
                .lock()
                .await
                .remove(session_id);
            self.ctx.sas_pairing.prompts.lock().await.remove(session_id);
            return Ok(());
        }
        if should_complete {
            pin_identity_in_context(&self.ctx, &peer_identity_id, &peer_public_key_hex)?;
            self.send_sas_pairing_message(
                &peer_identity_id,
                mux_sender,
                crate::pairing_sas::SasPairingMessage::Complete {
                    session_id: session_id.to_string(),
                },
            )
            .await?;
            let remote_completion_received = self
                .ctx
                .sas_pairing
                .sessions
                .lock()
                .await
                .get(session_id)
                .is_some_and(crate::pairing_sas::SasPairingSession::is_complete);
            if remote_completion_received {
                self.ctx
                    .sas_pairing
                    .sessions
                    .lock()
                    .await
                    .remove(session_id);
                log::info!("SAS pairing completed with peer {peer_identity_id}");
            }
        }
        self.ctx.sas_pairing.prompts.lock().await.remove(session_id);
        Ok(())
    }

    async fn send_sas_pairing_message(
        &self,
        peer_identity_id: &str,
        mux_sender: Option<crate::mux::MuxSender>,
        message: crate::pairing_sas::SasPairingMessage,
    ) -> Result<()> {
        let envelope = sas_pairing_envelope(&self.ctx, message)?;
        let client_session = self
            .wss_sessions
            .lock()
            .await
            .get(peer_identity_id)
            .filter(|session| session.is_alive())
            .cloned();
        match select_sas_pairing_send_route(client_session, mux_sender)? {
            SasPairingSendRoute::Wss(session) => session.send_envelope(envelope).await,
            SasPairingSendRoute::IncomingMux(sender) => {
                crate::transport::send_envelope_over_mux_sender(
                    &sender,
                    &envelope,
                    Some(&self.ctx.abuse_metrics),
                )
                .await
            }
        }
    }

    pub async fn record_invite_peer(
        &self,
        address: String,
        identity_id: &str,
        public_key_hex: &str,
    ) -> Result<()> {
        let node_id = pubkey_to_node_id(public_key_hex)
            .ok_or_else(|| anyhow!("invalid invite peer public key"))?;
        if node_id.to_hex() != identity_id {
            return Err(anyhow!("invite identity does not match public key"));
        }

        self.pin_peer(identity_id, public_key_hex).await?;
        let now = unix_now();
        self.ctx
            .peer_directory
            .lock()
            .await
            .record_invite(
                address.clone(),
                identity_id.to_string(),
                public_key_hex.to_string(),
                now,
            )
            .map_err(|error| anyhow!("failed to record invite peer: {error:?}"))?;
        if let Some(storage) = self.ctx.storage.as_ref() {
            storage
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?
                .peer_registry()
                .upsert(&StoredPeer {
                    peer_id: identity_id.to_string(),
                    identity_id: identity_id.to_string(),
                    public_key: public_key_hex.to_string(),
                    transport_address: address.clone(),
                    last_seen: now,
                    expires_at: now + crate::peer_directory::TTL_INVITE_SECS,
                    latency_ms: None,
                    failure_count: 0,
                })
                .map_err(|error| anyhow!("failed to persist Invite peer address: {error}"))?;
        }
        self.add_peer_address(address).await;
        Ok(())
    }

    pub async fn connect_invited_peer(
        &self,
        candidate_addresses: &[SocketAddr],
        identity_id: &str,
        public_key_hex: &str,
    ) -> Result<SocketAddr> {
        let public_key_bytes: [u8; 32] = hex::decode(public_key_hex)?
            .try_into()
            .map_err(|_| anyhow!("invite peer public key must be 32 bytes"))?;
        let expected_key = VerifyingKey::from_bytes(&public_key_bytes)?;
        let expected_identity = NodeId::from_public_key(&expected_key);
        if expected_identity.to_hex() != identity_id {
            return Err(anyhow!(
                "invite identity does not match its public key during connection"
            ));
        }

        let active_session = self
            .active_sessions
            .lock()
            .await
            .get(identity_id)
            .map(|session| (session.address, Arc::clone(&session.mux)));
        if let Some((address, mux)) = active_session {
            if mux.lock().await.is_alive() {
                return Ok(address);
            }
            log::warn!("Removing stale peer session for {identity_id} at {address}");
            self.active_sessions.lock().await.remove(identity_id);
        }

        let mut seen = HashSet::new();
        let mut ordered_candidates = candidate_addresses
            .iter()
            .copied()
            .filter(|address| seen.insert(*address))
            .collect::<Vec<_>>();
        ordered_candidates.sort_by_key(|address| !crate::transport::is_lan_address(address));
        let dial_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut last_error = None;
        for (candidate_index, address) in ordered_candidates.into_iter().take(6).enumerate() {
            let remaining = dial_deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                log::warn!(
                    "Stopping peer dial attempts for {identity_id}: 5-second budget expired"
                );
                break;
            }
            let is_lan = crate::transport::is_lan_address(&address);
            if candidate_index == 0 && crate::transport::is_lan_address(&address) {
                log::info!("Dialing Invite LAN address {address}");
            } else if candidate_index == 0 {
                log::info!("Dialing Invite address {address}");
            } else if is_lan {
                log::info!("Dialing DHT LAN address {address}");
            } else {
                log::info!("Dialing DHT WAN address {address}");
            }
            let connect_timeout = if is_lan {
                remaining.min(Duration::from_secs(2))
            } else {
                remaining
            };
            let connected = tokio::time::timeout(
                connect_timeout,
                TlsTransport::connect(address, &self.private_key, Some(expected_key)),
            )
            .await;
            match connected {
                Ok(Ok(transport)) if transport.peer_identity() == Some(expected_key) => {
                    let mux = Arc::new(Mutex::new(crate::Mux::new(
                        transport.into_stream(),
                        crate::mux::MuxConfig::default(),
                        crate::mux::Mode::Client,
                    )));
                    let hello = self.envelope_with_integrity(SyncEnvelope::new(
                        self.identity_id.clone(),
                        self.public_key.clone(),
                        Vec::new(),
                    ))?;
                    let handshake_timeout =
                        dial_deadline.saturating_duration_since(tokio::time::Instant::now());
                    let hello_result = match tokio::time::timeout(handshake_timeout, async {
                        let mut mux_guard = mux.lock().await;
                        crate::transport::send_envelope_over_mux(
                            &mut mux_guard,
                            &hello,
                            Some(&self.ctx.abuse_metrics),
                        )
                        .await?;
                        if mux_guard.is_alive() {
                            Ok::<(), anyhow::Error>(())
                        } else {
                            Err(anyhow!("peer mux closed during invite handshake"))
                        }
                    })
                    .await
                    {
                        Ok(result) => result,
                        Err(_) => Err(anyhow!(
                            "invite sync handshake exceeded the 5-second dial budget"
                        )),
                    };
                    if let Err(error) = hello_result {
                        if candidate_index == 0 {
                            log::warn!(
                                "Invite address {address} handshake failed; trying DHT candidates: {error}"
                            );
                        }
                        last_error = Some(error);
                        continue;
                    }
                    self.add_peer_address(address.to_string()).await;
                    self.ctx
                        .peer_directory
                        .lock()
                        .await
                        .record_outbound(
                            address.to_string(),
                            identity_id.to_string(),
                            hex::encode(expected_key.to_bytes()),
                            unix_now(),
                        )
                        .map_err(|error| {
                            anyhow!("failed to record verified invite peer address: {error:?}")
                        })?;
                    self.active_sessions
                        .lock()
                        .await
                        .insert(identity_id.to_string(), ActivePeerSession { address, mux });
                    self.recent_send_failures.lock().await.remove(identity_id);
                    return Ok(address);
                }
                Ok(Ok(_)) => {
                    let error = anyhow!("peer identity handshake returned an unexpected identity");
                    if candidate_index == 0 {
                        log::warn!(
                            "Invite address {address} identity verification failed; trying DHT candidates"
                        );
                    }
                    last_error = Some(error);
                }
                Ok(Err(error)) => {
                    log::error!("Dial failed to {address}: {error:?}");
                    if candidate_index == 0 {
                        log::warn!("Invite address {address} failed; trying DHT candidates");
                    }
                    last_error = Some(error);
                }
                Err(_) => {
                    let error = anyhow!(
                        "dial timed out after {}ms during TCP/TLS identity handshake",
                        connect_timeout.as_millis()
                    );
                    log::error!("Dial failed to {address}: {error:?}");
                    if candidate_index == 0 {
                        log::warn!("Invite address {address} timed out; trying DHT candidates");
                    }
                    last_error = Some(error);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            anyhow!("no valid direct or DHT address was found for the invited peer")
        }))
    }

    pub async fn accept_peer_announcement(
        &self,
        announcement: PeerAnnouncement,
        _now: u64,
    ) -> Result<()> {
        announcement.verify()?;
        if announcement.identity_id == self.identity_id {
            return Err(anyhow!("self peer announcement rejected"));
        }
        self.add_peer_address(announcement.transport_address.clone())
            .await;
        Ok(())
    }

    pub fn persist_peer_announcement(
        &self,
        storage: &Arc<StdMutex<ClientStorage>>,
        announcement: &PeerAnnouncement,
        now: u64,
        ttl_seconds: u64,
    ) -> Result<()> {
        announcement.verify()?;
        let peer = StoredPeer {
            peer_id: announcement.identity_id.clone(),
            identity_id: announcement.identity_id.clone(),
            public_key: announcement.public_key.clone(),
            transport_address: announcement.transport_address.clone(),
            last_seen: now,
            expires_at: now.saturating_add(ttl_seconds),
            latency_ms: None,
            failure_count: 0,
        };
        storage
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?
            .peer_registry()
            .upsert(&peer)
            .map_err(|error| anyhow!("failed to persist peer announcement: {error}"))
    }

    pub async fn start_dispatch_loop(&mut self, dispatcher: Arc<PollDispatcher>) -> Result<()> {
        if self.dispatcher_task.is_some() {
            return Ok(());
        }
        let actions = Arc::clone(&self.poll_actions);
        let peers = Arc::clone(&self.peers);
        let sync = Arc::clone(&self.ctx.sync);
        let identity = self.identity_id.clone();
        let public_key = self.public_key.clone();
        let private_key = self.private_key.to_bytes();
        let hosts = Arc::clone(&self.ctx.hosts);
        let abuse_metrics = Arc::clone(&self.ctx.abuse_metrics);
        let trust_policy = self.trust_policy.clone();
        let dispatch_notify = Arc::clone(&self.dispatch_notify);
        let integrity = self.ctx.integrity.clone();
        let software_measurement = self.software_measurement.clone();
        let (dispatcher_shutdown, mut dispatcher_shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                if dispatcher_shutdown_rx.try_recv().is_ok() {
                    break;
                }
                let notified = dispatch_notify.notified();
                let pending = std::mem::take(&mut *actions.lock().await);
                for action in pending {
                    let _ = dispatcher.dispatch(action).await;
                }
                let mut events = sync.lock().await.get_pending_events();
                if events.is_empty() {
                    tokio::select! {
                        _ = &mut dispatcher_shutdown_rx => break,
                        _ = notified => {}
                        _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
                    }
                    continue;
                }
                events.retain_mut(|event| event.sign(&private_key).is_ok());
                if events.is_empty() {
                    continue;
                }
                let mut envelope = SyncEnvelope::new(identity.clone(), public_key.clone(), events);
                if let (Some(wave), Some(measurement)) = (&integrity, &software_measurement) {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let Ok(mut response) =
                        IntegrityResponse::new(wave, public_key.clone(), measurement.clone(), now)
                    else {
                        log::warn!(
                            "Skipping sync dispatch: integrity response could not be created"
                        );
                        continue;
                    };
                    response.sign(&private_key);
                    envelope = envelope.with_integrity_response(response);
                }
                let peers_snapshot = peers.lock().await.clone();
                for peer in peers_snapshot {
                    if dispatcher_shutdown_rx.try_recv().is_ok() {
                        return;
                    }
                    if classify_candidate(&peer) == TransportTier::Relay
                        && !trust_policy.allows_relay(&peer)
                    {
                        continue;
                    }
                    let signing_key = SigningKey::from_bytes(&private_key);
                    let _ = send_envelope_secure_with_stream_kind_and_metrics(
                        &peer,
                        &envelope,
                        &signing_key,
                        Arc::clone(&hosts),
                        None,
                        trust_policy.clone(),
                        crate::mux::StreamKind::Sync,
                        Arc::clone(&abuse_metrics),
                    )
                    .await;
                }
            }
        });
        self.dispatcher_shutdown = Some(dispatcher_shutdown);
        self.dispatcher_task = Some(task);
        Ok(())
    }

    pub async fn start_discovery(
        &mut self,
        storage: Option<Arc<StdMutex<ClientStorage>>>,
        ttl_seconds: u64,
    ) -> Result<()> {
        if self.discovery.is_some() {
            return Ok(());
        }
        let (discovery, mut announcements) = PeerDiscovery::start(
            self.identity_id.clone(),
            self.public_key.clone(),
            self.private_key.to_bytes(),
            self.transport_address.clone(),
        )
        .await?;
        let peers = Arc::clone(&self.peers);
        let local_identity = self.identity_id.clone();
        let (discovery_shutdown, mut discovery_shutdown_rx) = oneshot::channel();
        let discovery_task = tokio::spawn(async move {
            loop {
                let Some(announcement) = (tokio::select! {
                    _ = &mut discovery_shutdown_rx => break,
                    announcement = announcements.recv() => announcement,
                }) else {
                    break;
                };
                if announcement.identity_id == local_identity {
                    continue;
                }
                if announcement.verify().is_err() {
                    continue;
                }
                let address = announcement.transport_address.clone();
                let mut known = peers.lock().await;
                if !known.contains(&address) {
                    known.push(address);
                }
                drop(known);
                if let Some(storage) = &storage {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let peer = StoredPeer {
                        peer_id: announcement.identity_id.clone(),
                        identity_id: announcement.identity_id.clone(),
                        public_key: announcement.public_key.clone(),
                        transport_address: announcement.transport_address.clone(),
                        last_seen: now,
                        expires_at: now.saturating_add(ttl_seconds),
                        latency_ms: None,
                        failure_count: 0,
                    };
                    if let Ok(guard) = storage.lock() {
                        let _ = guard.peer_registry().upsert(&peer);
                    }
                }
            }
        });
        self.discovery_shutdown = Some(discovery_shutdown);
        self.discovery = Some(discovery);
        self.discovery_task = Some(discovery_task);
        Ok(())
    }

    pub async fn stop(mut self) -> Result<()> {
        self.active_sessions.lock().await.clear();
        self.wss_sessions.lock().await.clear();
        self.ctx.sas_pairing.sessions.lock().await.clear();
        self.ctx.sas_pairing.prompts.lock().await.clear();
        self.ctx.relay_tx.lock().await.take();
        if let Some(shutdown) = self.relay_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(shutdown) = self.discovery_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(shutdown) = self.lan_discovery_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(shutdown) = self.dispatcher_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(shutdown) = self.cover_traffic_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(shutdown) = self.home_sync_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(shutdown) = self.incoming_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(shutdown) = self.quic_incoming_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(shutdown) = self.quic_listener_shutdown.lock().await.take() {
            let _ = shutdown.send(());
        }
        if let Some(endpoint) = self.quic_listener_endpoint.read().await.as_ref() {
            endpoint.close(0u32.into(), b"runtime stopped");
        }
        if let Some(shutdown) = self.refresh_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(shutdown) = self.endpoint_heartbeat_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(shutdown) = self.punch_fetch_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(shutdown) = self.quic_punch_shutdown.take() {
            let _ = shutdown.send(());
        }
        self.ctx
            .badge_fetch_shutdown
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(shutdown) = self.badge_fetch_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(shutdown) = self.retention_prune_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(shutdown) = self.auto_badge_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(shutdown) = self.stigma_refresh_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(shutdown) = self.prekey_rotation_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(shutdown) = self.journal_commit_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(shutdown) = self.jury_assembly_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(shutdown) = self.jury_outbox_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(shutdown) = self.complainant_orchestrator_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(shutdown) = self.juror_orchestrator_shutdown.take() {
            let _ = shutdown.send(());
        }

        if let Some(task) = self.discovery_task.take() {
            match tokio::time::timeout(std::time::Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("discovery task stopped with error: {error}"),
                Err(_) => log::warn!("discovery task did not stop within 5 seconds"),
            }
        }
        if let Some(task) = self.lan_discovery_task.take() {
            match tokio::time::timeout(std::time::Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("LAN discovery task stopped with error: {error}"),
                Err(_) => log::warn!("LAN discovery task did not stop within 5 seconds"),
            }
        }
        if let Some(task) = self.quic_punch_task.take() {
            match tokio::time::timeout(Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("QUIC rendezvous task stopped with error: {error}"),
                Err(_) => log::warn!("QUIC rendezvous task did not stop within 5 seconds"),
            }
        }
        if let Some(discovery) = self.discovery.take() {
            discovery.stop().await?;
        }
        if let Some(task) = self.dispatcher_task.take() {
            match tokio::time::timeout(std::time::Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("dispatcher task stopped with error: {error}"),
                Err(_) => log::warn!("dispatcher task did not stop within 5 seconds"),
            }
        }
        if let Some(task) = self.cover_traffic_task.take() {
            match tokio::time::timeout(std::time::Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("cover traffic task stopped with error: {error}"),
                Err(_) => log::warn!("cover traffic task did not stop within 5 seconds"),
            }
        }
        if let Some(task) = self.home_sync_task.take() {
            match tokio::time::timeout(Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("Home sync worker stopped with error: {error}"),
                Err(_) => log::warn!("Home sync worker did not stop within 5 seconds"),
            }
        }
        if let Some(task) = self.incoming_task.take() {
            match tokio::time::timeout(std::time::Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("incoming task stopped with error: {error}"),
                Err(_) => log::warn!("incoming task did not stop within 5 seconds"),
            }
        }
        if let Some(task) = self.quic_incoming_task.take() {
            match tokio::time::timeout(Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("quic incoming task stopped with error: {error}"),
                Err(_) => log::warn!("quic incoming task did not stop within 5 seconds"),
            }
        }
        if let Some(task) = self.quic_listener_task.lock().await.take() {
            match tokio::time::timeout(Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("QUIC listener task stopped with error: {error}"),
                Err(_) => log::warn!("QUIC listener task did not stop within 5 seconds"),
            }
        }
        if let Some(task) = self.refresh_task.take() {
            match tokio::time::timeout(std::time::Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("refresh task stopped with error: {error}"),
                Err(_) => log::warn!("refresh task did not stop within 5 seconds"),
            }
        }
        if let Some(task) = self.endpoint_heartbeat_task.take() {
            match tokio::time::timeout(Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    log::warn!("public endpoint heartbeat stopped with error: {error}")
                }
                Err(_) => log::warn!("public endpoint heartbeat did not stop within 5 seconds"),
            }
        }
        if let Some(task) = self.punch_fetch_task.take() {
            match tokio::time::timeout(std::time::Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("punch fetch task stopped with error: {error}"),
                Err(_) => log::warn!("punch fetch task did not stop within 5 seconds"),
            }
        }
        if let Some(task) = self.badge_fetch_task.take() {
            match tokio::time::timeout(Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("badge fetch task stopped with error: {error}"),
                Err(_) => log::warn!("badge fetch task did not stop within 5 seconds"),
            }
        }
        if let Some(task) = self.prekey_rotation_task.take() {
            match tokio::time::timeout(Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("prekey rotation task stopped with error: {error}"),
                Err(_) => log::warn!("prekey rotation task did not stop within 5 seconds"),
            }
        }
        if let Some(task) = self.journal_commit_task.take() {
            match tokio::time::timeout(Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    log::warn!("journal commit publisher stopped with error: {error}")
                }
                Err(_) => log::warn!("journal commit publisher did not stop within 5 seconds"),
            }
        }
        if let Some(task) = self.jury_assembly_task.take() {
            match tokio::time::timeout(Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("jury assembly task stopped with error: {error}"),
                Err(_) => log::warn!("jury assembly task did not stop within 5 seconds"),
            }
        }
        if let Some(task) = self.jury_outbox_task.take() {
            match tokio::time::timeout(Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("jury outbox task stopped with error: {error}"),
                Err(_) => log::warn!("jury outbox task did not stop within 5 seconds"),
            }
        }
        if let Some(task) = self.complainant_orchestrator_task.take() {
            match tokio::time::timeout(Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    log::warn!("complainant orchestrator stopped with error: {error}")
                }
                Err(_) => {
                    log::warn!("complainant orchestrator did not stop within 5 seconds")
                }
            }
        }
        if let Some(task) = self.juror_orchestrator_task.take() {
            match tokio::time::timeout(Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("juror orchestrator stopped with error: {error}"),
                Err(_) => log::warn!("juror orchestrator did not stop within 5 seconds"),
            }
        }
        if let Some(task) = self.auto_badge_task.take() {
            match tokio::time::timeout(Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("auto-badge worker stopped with error: {error}"),
                Err(_) => log::warn!("auto-badge worker did not stop within 5 seconds"),
            }
        }
        if let Some(task) = self.relay_task.take() {
            match tokio::time::timeout(Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("relay worker stopped with error: {error}"),
                Err(_) => log::warn!("relay worker did not stop within 5 seconds"),
            }
        }
        *self.ctx.home_state.lock().await = HomeRuntimeState::default();
        if let Some(polling) = self.polling.take() {
            polling.stop().await?;
        }
        if let Some(tx) = self.dht_stream_tx.take() {
            drop(tx);
        }
        let transport_result = self.transport.stop().await;
        if let Some(shutdown) = self.inbound_obs_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.inbound_obs_task.take() {
            match tokio::time::timeout(Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("inbound observer task stopped with error: {error}"),
                Err(_) => log::warn!("inbound observer task did not stop within 5 seconds"),
            }
        }
        if let Some(task) = self.stigma_refresh_task.take() {
            match tokio::time::timeout(Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::warn!("stigma refresh task stopped with error: {error}"),
                Err(_) => log::warn!("stigma refresh task did not stop within 5 seconds"),
            }
        }
        if let Some(task) = self.dht_worker_task.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        }
        transport_result
    }
}

async fn dht_worker_loop(
    mut rx: mpsc::Receiver<(crate::Mux<crate::tls_transport::TlsConn>, crate::MuxStream)>,
    handler: Arc<DhtRequestHandler>,
    metrics: Arc<crate::dht::DhtMetrics>,
    config: Arc<Mutex<DhtPollerConfig>>,
) {
    let max_parallel = { config.lock().await.max_parallel };
    let timeout = Duration::from_secs(config.lock().await.rpc_timeout_secs);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_parallel));
    while let Some((mux, stream)) = rx.recv().await {
        let Ok(permit) = Arc::clone(&semaphore).acquire_owned().await else {
            break;
        };
        let handler = Arc::clone(&handler);
        let metrics = Arc::clone(&metrics);
        let timeout = timeout;
        tokio::spawn(async move {
            let _permit = permit;
            let _ =
                tokio::time::timeout(timeout, handle_dht_stream((mux, stream), handler, metrics))
                    .await;
        });
    }
}

async fn handle_dht_stream(
    (mux, mut stream): (crate::Mux<crate::tls_transport::TlsConn>, crate::MuxStream),
    handler: Arc<DhtRequestHandler>,
    metrics: Arc<crate::dht::DhtMetrics>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    metrics.inc_processed();
    let mut length_buf = [0u8; crate::dht::DHT_FRAME_PREFIX_BYTES];
    let request_len_result = stream.read_exact(&mut length_buf).await;
    if request_len_result.is_err() {
        let _ = stream.shutdown().await;
        let _ = mux.close().await;
        return;
    }
    let request_len = u32::from_be_bytes(length_buf) as usize;
    if request_len == 0 || request_len > crate::dht::MAX_DHT_REQUEST_BYTES {
        let _ = stream.shutdown().await;
        let _ = mux.close().await;
        return;
    }
    let mut request_bytes = vec![0u8; request_len];
    if stream.read_exact(&mut request_bytes).await.is_err() {
        let _ = stream.shutdown().await;
        let _ = mux.close().await;
        return;
    }
    let framed_request = [length_buf.as_slice(), request_bytes.as_slice()].concat();
    let request = match crate::dht::decode_request_framed(&framed_request) {
        Ok(request) => request,
        Err(error) => {
            eprintln!(
                "[SERVER] decode_request failed: {error}; raw_len={} first32={:02x?}",
                request_bytes.len(),
                &request_bytes[..request_bytes.len().min(32)]
            );
            let _ = stream.shutdown().await;
            let _ = mux.close().await;
            return;
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let response = if request.validate(now).is_err() {
        crate::DhtResponse {
            version: crate::dht::DHT_PROTOCOL_VERSION,
            request_id: request.request_id,
            responder_node_id: handler.local_id(),
            timestamp: now,
            payload: crate::dht::DhtResponsePayload::Error {
                code: crate::dht::ERR_INVALID_REQUEST,
                message: "validation failed".into(),
            },
        }
    } else {
        handler.handle(request, now).await
    };
    if let Ok(response_frame) = crate::dht::encode_response_framed(&response) {
        let _ = stream.write_all(&response_frame).await;
        let _ = stream.flush().await;
        metrics.inc_responses();
    }
    let _ = stream.shutdown().await;
    let _ = mux.close().await;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TransportTier {
    ExternalIpv6,
    ExternalIpv4,
    LocalLan,
    Relay,
    LocalLoopback,
}

fn classify_candidate(address: &str) -> TransportTier {
    let host = address.trim();
    if host.is_empty() {
        return TransportTier::Relay;
    }

    let host = host
        .strip_prefix('[')
        .and_then(|inner| inner.split_once(']').map(|(head, _)| head))
        .unwrap_or_else(|| host.rsplit_once(':').map(|(head, _)| head).unwrap_or(host));

    let host = host.trim();
    if host.is_empty() || host == "localhost" || host == "127.0.0.1" || host == "::1" {
        return TransportTier::LocalLoopback;
    }

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                if v4.is_loopback() || v4 == std::net::Ipv4Addr::LOCALHOST {
                    return TransportTier::LocalLoopback;
                }
                if v4.is_private() || v4.is_link_local() || v4.is_unspecified() {
                    return TransportTier::LocalLan;
                }
                return TransportTier::ExternalIpv4;
            }
            std::net::IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    return TransportTier::LocalLoopback;
                }
                if v6.is_unique_local() || v6.is_unspecified() || v6.is_unicast_link_local() {
                    return TransportTier::LocalLan;
                }
                return TransportTier::ExternalIpv6;
            }
        }
    }

    let lower = host.to_ascii_lowercase();
    if lower.contains("relay")
        || lower.contains("turn")
        || lower.contains("stun")
        || lower.contains("ice")
    {
        return TransportTier::Relay;
    }

    if host.contains('.') || host.contains(':') || host.contains("-") {
        return TransportTier::ExternalIpv4;
    }

    TransportTier::Relay
}

fn peer_address_candidates(peer_address: &str) -> Vec<String> {
    let raw = peer_address.trim();
    if raw.is_empty() {
        return Vec::new();
    }

    let mut candidates = raw
        .split([',', ';'])
        .filter_map(|candidate| {
            let candidate = candidate.trim();
            if candidate.is_empty() {
                None
            } else {
                Some(candidate.to_string())
            }
        })
        .collect::<Vec<_>>();

    candidates.sort_by_key(|candidate| classify_candidate(candidate));
    candidates.dedup();
    candidates
}

fn is_connection_establishment_failure(error: &anyhow::Error) -> bool {
    let message = error.to_string();
    message.contains("TCP connect failed")
        || message.contains("TCP connect FAILED")
        || message.contains("TCP connect timed out")
        || message.contains("Happy Eyeballs connection timed out")
        || message.contains("connection failed:")
}

fn candidate_transport_addresses(port: &str) -> Vec<String> {
    let mut addresses = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    let ipv6 = std::net::UdpSocket::bind("[::]:0").ok().and_then(|socket| {
        socket.connect("[2001:4860:4860::8888]:443").ok()?;
        let addr = socket.local_addr().ok()?;
        let ip = addr.ip().to_string();
        let candidate = if ip.contains(':') {
            format!("[{ip}]:{port}")
        } else {
            format!("{ip}:{port}")
        };
        Some(candidate)
    });
    if let Some(address) = ipv6 {
        if seen.insert(address.clone()) {
            addresses.push(address);
        }
    }

    let ipv4 = std::net::UdpSocket::bind("0.0.0.0:0")
        .ok()
        .and_then(|socket| {
            socket.connect("8.8.8.8:80").ok()?;
            let addr = socket.local_addr().ok()?;
            let ip = addr.ip().to_string();
            let candidate = if ip.contains(':') {
                format!("[{ip}]:{port}")
            } else {
                format!("{ip}:{port}")
            };
            Some(candidate)
        });
    if let Some(address) = ipv4 {
        if seen.insert(address.clone()) {
            addresses.push(address);
        }
    }

    addresses.sort_by_key(|address| classify_candidate(address));
    addresses.dedup();
    for interface in if_addrs::get_if_addrs().unwrap_or_default() {
        let ip = match interface.addr {
            if_addrs::IfAddr::V4(address) => std::net::IpAddr::V4(address.ip),
            if_addrs::IfAddr::V6(address) => std::net::IpAddr::V6(address.ip),
        };
        if ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_multicast()
            || matches!(ip, std::net::IpAddr::V6(address) if address.is_unicast_link_local())
        {
            continue;
        }
        let address = match ip {
            std::net::IpAddr::V4(address) => format!("{address}:{port}"),
            std::net::IpAddr::V6(address) => format!("[{address}]:{port}"),
        };
        if seen.insert(address.clone()) {
            addresses.push(address);
        }
    }
    addresses
}

fn advertised_transport_address(bound_address: &str) -> String {
    let port = bound_address
        .rsplit_once(':')
        .map(|(_, port)| port)
        .unwrap_or("0");
    let candidates = candidate_transport_addresses(port);
    candidates
        .iter()
        .find(|address| {
            address
                .parse::<std::net::SocketAddr>()
                .is_ok_and(|socket| socket.is_ipv4())
        })
        .cloned()
        .or_else(|| candidates.into_iter().next())
        .unwrap_or_default()
}

fn advertised_transport_addresses(bound_address: &str) -> Vec<String> {
    let port = bound_address
        .rsplit_once(':')
        .map(|(_, port)| port)
        .unwrap_or("0");
    candidate_transport_addresses(port)
}

fn select_lan_invite_address(addresses: &[String]) -> Result<String> {
    let interfaces = if_addrs::get_if_addrs().unwrap_or_default();
    let preferred = addresses
        .iter()
        .filter_map(|address| {
            let socket = address.parse::<SocketAddr>().ok()?;
            if !crate::transport::is_lan_address(&socket) || socket.ip().is_loopback() {
                return None;
            }
            let rank = interfaces
                .iter()
                .find_map(|interface| match &interface.addr {
                    if_addrs::IfAddr::V4(address)
                        if socket.ip() == std::net::IpAddr::V4(address.ip) =>
                    {
                        Some(lan_interface_rank(&interface.name))
                    }
                    if_addrs::IfAddr::V6(address)
                        if socket.ip() == std::net::IpAddr::V6(address.ip) =>
                    {
                        Some(lan_interface_rank(&interface.name))
                    }
                    _ => None,
                })
                .unwrap_or(3);
            Some((rank, address))
        })
        .min_by_key(|(rank, _)| *rank)
        .map(|(_, address)| address.clone());
    if let Some(address) = preferred {
        return Ok(address);
    }

    addresses
        .iter()
        .find(|address| {
            address.parse::<SocketAddr>().is_ok_and(|socket| {
                crate::transport::is_lan_address(&socket) && !socket.ip().is_loopback()
            })
        })
        .cloned()
        .ok_or_else(|| {
            anyhow!("NoLANAddressAvailable: проверьте подключение к Wi-Fi и попробуйте снова")
        })
}

fn lan_interface_rank(name: &str) -> u8 {
    let name = name.to_ascii_lowercase();
    if name.starts_with("wl")
        || name.starts_with("wlan")
        || name.starts_with("wifi")
        || name.starts_with("en")
        || name.starts_with("eth")
    {
        return 0;
    }
    if [
        "tun",
        "tap",
        "wg",
        "warp",
        "vpn",
        "tailscale",
        "docker",
        "veth",
        "br-",
        "virbr",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
    {
        return 2;
    }
    1
}

fn pubkey_to_node_id(pubkey_hex: &str) -> Option<NodeId> {
    let bytes: [u8; 32] = hex::decode(pubkey_hex).ok()?.try_into().ok()?;
    let verifying_key = VerifyingKey::from_bytes(&bytes).ok()?;
    Some(NodeId::from_public_key(&verifying_key))
}

fn parse_group_member_key(public_key_hex: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(public_key_hex)
        .map_err(|error| anyhow!("invalid group member public key: {error}"))?
        .try_into()
        .map_err(|_| anyhow!("group member public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|error| anyhow!("invalid group member identity key: {error}"))
}

fn apply_incoming_file_transfer_event(
    storage: &mut ClientStorage,
    local_identity_id: &str,
    event: &SyncEvent,
    sender_identity_id: &str,
    sender_public_key: &str,
) -> Result<()> {
    match event.event_type {
        SyncEventType::FileTransferInit => {
            let payload: crate::journal::FileTransferInitPayload =
                serde_json::from_str(&event.data)?;
            let expected_chunks = payload
                .file_size
                .div_ceil(crate::journal::FILE_TRANSFER_CHUNK_SIZE as u64);
            if payload.recipient_id != local_identity_id
                || payload.sender_id != sender_identity_id
                || pubkey_to_node_id(&payload.chat_id)
                    .is_none_or(|peer_id| peer_id.to_hex() != local_identity_id)
                || uuid::Uuid::parse_str(&payload.file_id).is_err()
                || payload.file_size > crate::journal::MAX_FILE_TRANSFER_SIZE
                || u64::from(payload.total_chunks) != expected_chunks
                || payload.file_name.trim().is_empty()
                || payload.file_name.len() > 255
                || payload
                    .file_name
                    .chars()
                    .any(|c| c == '/' || c == '\\' || c.is_control())
                || payload.mime_type.is_empty()
                || payload.mime_type.len() > 255
                || payload.chat_id.is_empty()
            {
                return Err(anyhow!("invalid or misaddressed file-transfer init"));
            }
            if let Some(existing) = storage.get_file_transfer(&payload.file_id)? {
                if existing.sender_id == sender_identity_id
                    && existing.file_size == payload.file_size
                    && existing.total_chunks == payload.total_chunks
                {
                    if existing.local_path.as_deref().is_some_and(|path| {
                        std::fs::metadata(path).is_ok_and(|metadata| {
                            metadata.is_file() && metadata.len() == payload.file_size
                        })
                    }) {
                        return Ok(());
                    }
                    let transfer_dir = storage
                        .path()
                        .parent()
                        .ok_or_else(|| anyhow!("client database has no parent directory"))?
                        .join("transfers");
                    let local_path = transfer_dir.join(&payload.file_id);
                    storage.initialize_incoming_file(&payload.file_id, &local_path)?;
                    return Ok(());
                }
                return Err(anyhow!("file-transfer id conflicts with existing transfer"));
            }
            storage.create_file_transfer(
                &payload.file_id,
                sender_public_key,
                sender_identity_id,
                "incoming",
                &payload.file_name,
                payload.file_size,
                &payload.mime_type,
                payload.total_chunks,
            )?;
            let transfer_dir = storage
                .path()
                .parent()
                .ok_or_else(|| anyhow!("client database has no parent directory"))?
                .join("transfers");
            let local_path = transfer_dir.join(&payload.file_id);
            storage.initialize_incoming_file(&payload.file_id, &local_path)?;
            if payload.total_chunks == 0 {
                storage.update_file_transfer_progress(&payload.file_id, 0, "completed")?;
            }
            log::info!(
                target: "HAL_DHT",
                "apply_incoming_file_transfer_event: FileTransferInit received, file_id={}, total_chunks={}",
                payload.file_id,
                payload.total_chunks
            );
        }
        SyncEventType::FileTransferChunk => {
            let payload: crate::journal::FileTransferChunkPayload =
                serde_json::from_str(&event.data)?;
            if payload.recipient_id != local_identity_id
                || uuid::Uuid::parse_str(&payload.file_id).is_err()
            {
                return Err(anyhow!("invalid or misaddressed file-transfer chunk"));
            }
            let transfer = storage
                .get_file_transfer(&payload.file_id)?
                .ok_or_else(|| anyhow!("file-transfer init was not received"))?;
            if transfer.sender_id != sender_identity_id
                || payload.data.len() > crate::journal::FILE_TRANSFER_CHUNK_SIZE
            {
                return Err(anyhow!("file-transfer chunk sender or size is invalid"));
            }
            let offset = u64::from(payload.chunk_index)
                .checked_mul(crate::journal::FILE_TRANSFER_CHUNK_SIZE as u64)
                .ok_or_else(|| anyhow!("file-transfer chunk offset overflow"))?;
            let expected_size = usize::try_from(
                transfer
                    .file_size
                    .saturating_sub(offset)
                    .min(crate::journal::FILE_TRANSFER_CHUNK_SIZE as u64),
            )
            .map_err(|_| anyhow!("file-transfer chunk size overflow"))?;
            if payload.data.len() != expected_size {
                return Err(anyhow!(
                    "file-transfer chunk length does not match metadata"
                ));
            }
            storage.write_file_transfer_chunk(
                &payload.file_id,
                payload.chunk_index,
                crate::journal::FILE_TRANSFER_CHUNK_SIZE as u32,
                &payload.data,
            )?;
            log::info!(
                target: "HAL_DHT",
                "apply_incoming_file_transfer_event: chunk {}/{} received, file_id={}, wrote {} bytes",
                payload.chunk_index + 1,
                transfer.total_chunks,
                payload.file_id,
                payload.data.len()
            );
        }
        SyncEventType::FileTransferComplete => {
            let payload: crate::journal::FileTransferCompletePayload =
                serde_json::from_str(&event.data)?;
            if payload.recipient_id != local_identity_id
                || uuid::Uuid::parse_str(&payload.file_id).is_err()
            {
                return Err(anyhow!("invalid or misaddressed file-transfer completion"));
            }
            let transfer = storage
                .get_file_transfer(&payload.file_id)?
                .ok_or_else(|| anyhow!("file-transfer init was not received"))?;
            if transfer.sender_id != sender_identity_id
                || transfer.received_chunks != transfer.total_chunks
            {
                return Err(anyhow!(
                    "file-transfer completion arrived before all chunks"
                ));
            }
            storage.update_file_transfer_progress(
                &payload.file_id,
                transfer.total_chunks,
                "completed",
            )?;
            log::info!(
                target: "HAL_DHT",
                "apply_incoming_file_transfer_event: file complete, file_id={}, chunks={}",
                payload.file_id,
                transfer.total_chunks
            );
        }
        SyncEventType::FileTransferCancel => {
            let payload: crate::journal::FileTransferCancelPayload =
                serde_json::from_str(&event.data)?;
            if payload.recipient_id != local_identity_id
                || uuid::Uuid::parse_str(&payload.file_id).is_err()
                || payload.reason.len() > 256
            {
                return Err(anyhow!(
                    "invalid or misaddressed file-transfer cancellation"
                ));
            }
            let transfer = storage
                .get_file_transfer(&payload.file_id)?
                .ok_or_else(|| anyhow!("file-transfer init was not received"))?;
            if transfer.sender_id != sender_identity_id {
                return Err(anyhow!("file-transfer cancellation sender mismatch"));
            }
            storage.update_file_transfer_progress(
                &payload.file_id,
                transfer.received_chunks,
                "cancelled",
            )?;
        }
        _ => return Err(anyhow!("not a file-transfer event")),
    }
    Ok(())
}

fn log_file_transfer_events_sent(events: &[SyncEvent], address: &str) {
    for event in events {
        let file_id = serde_json::from_str::<serde_json::Value>(&event.data)
            .ok()
            .and_then(|payload| {
                payload
                    .get("file_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "unknown".to_string());
        match event.event_type {
            SyncEventType::FileTransferInit => log::info!(
                target: "HAL_DHT",
                "send_file_transfer_events: FileTransferInit sent to {address}, file_id={file_id}"
            ),
            SyncEventType::FileTransferChunk => {
                let chunk_index =
                    serde_json::from_str::<crate::journal::FileTransferChunkPayload>(&event.data)
                        .map(|payload| payload.chunk_index.saturating_add(1))
                        .unwrap_or_default();
                log::info!(
                    target: "HAL_DHT",
                    "send_file_transfer_events: chunk {chunk_index} sent to {address}, file_id={file_id}"
                );
            }
            SyncEventType::FileTransferComplete => log::info!(
                target: "HAL_DHT",
                "send_file_transfer_events: FileTransferComplete sent to {address}, file_id={file_id}"
            ),
            SyncEventType::FileTransferCancel => log::info!(
                target: "HAL_DHT",
                "send_file_transfer_events: FileTransferCancel sent to {address}, file_id={file_id}"
            ),
            _ => {}
        }
    }
}

fn incoming_message_chat_id<'a>(
    payload_chat_id: &'a str,
    group_id: Option<&str>,
    authenticated_sender_public_key: Option<&'a str>,
) -> &'a str {
    if group_id.is_none() {
        authenticated_sender_public_key.unwrap_or(payload_chat_id)
    } else {
        payload_chat_id
    }
}

fn pending_events_for_recipient(events: Vec<SyncEvent>, recipient_id: &str) -> Vec<SyncEvent> {
    events
        .into_iter()
        .filter(|event| match event.event_type {
            SyncEventType::GroupCreate
            | SyncEventType::GroupKeyDistribution
            | SyncEventType::GroupMessage
            | SyncEventType::ProfileUpdate => {
                match serde_json::from_str::<serde_json::Value>(&event.data) {
                    Ok(payload) => {
                        payload.get("recipient_id").and_then(|value| value.as_str())
                            == Some(recipient_id)
                    }
                    Err(error) => {
                        log::warn!(
                            "dropping malformed pending addressed event {}: {error}",
                            event.id
                        );
                        false
                    }
                }
            }
            SyncEventType::MessageAdded => {
                match serde_json::from_str::<serde_json::Value>(&event.data) {
                    Ok(payload) => {
                        payload.get("recipient_id").and_then(|value| value.as_str())
                            == Some(recipient_id)
                    }
                    Err(error) => {
                        log::warn!(
                            "dropping malformed pending message event {}: {error}",
                            event.id
                        );
                        false
                    }
                }
            }
            _ => true,
        })
        .collect()
}

fn group_message_aad(group_id: &str, sender_id: &str, message_id: &str) -> Vec<u8> {
    let mut aad = b"hal-group-message-v1\0".to_vec();
    aad.extend_from_slice(group_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(sender_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(message_id.as_bytes());
    aad
}

fn select_punch_request_format(
    strategy: &SignalingStrategy,
    target_id: NodeId,
    now: u64,
) -> crate::signaling::SignalingFormat {
    let seed = now ^ u64::from_le_bytes(target_id.as_bytes()[..8].try_into().unwrap_or_default());
    strategy
        .pick_format(seed)
        .unwrap_or(crate::signaling::SignalingFormat::Explicit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::biometric_gate::{MockBiometricGate, MockResponse};
    use crate::PollHandler;
    use crate::TransportKind;
    use crate::{send_envelope_secure_with_kind, SyncSettings};
    use crate::{EventKind, ObservableEvents};
    use hal_protocol::invite::InviteWire;
    use sha2::Digest;
    use std::sync::atomic::Ordering;

    fn identity_for(key: &[u8; 32]) -> String {
        let signing = SigningKey::from_bytes(key);
        let mut hash = sha2::Sha256::new();
        hash.update(signing.verifying_key().to_bytes());
        hex::encode(hash.finalize())
    }

    fn test_pubkey(seed: u8) -> String {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        hex::encode(signing_key.verifying_key().to_bytes())
    }

    #[test]
    fn incoming_direct_message_uses_authenticated_sender_chat_key() {
        let payload_chat_id = "recipient-public-key";
        let sender_public_key = "sender-public-key";

        assert_eq!(
            incoming_message_chat_id(payload_chat_id, None, Some(sender_public_key)),
            sender_public_key
        );
        assert_eq!(
            incoming_message_chat_id(payload_chat_id, Some("group-id"), Some(sender_public_key)),
            payload_chat_id
        );
        assert_eq!(
            incoming_message_chat_id(payload_chat_id, None, None),
            payload_chat_id
        );
    }

    async fn wait_until<F, Fut>(mut check: F, timeout: Duration) -> bool
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        tokio::time::timeout(timeout, async {
            loop {
                if check().await {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or(false)
    }

    async fn await_event<F, Fut>(
        events: &ObservableEvents,
        kind: EventKind,
        mut condition: F,
        deadline: Duration,
    ) -> Result<(), &'static str>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let wait = async {
            loop {
                let notified = events.notifier(kind).notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if condition().await {
                    return Ok(());
                }
                notified.as_mut().await;
                if condition().await {
                    return Ok(());
                }
            }
        };

        tokio::time::timeout(deadline, wait)
            .await
            .map_err(|_| "observable event deadline exceeded")?
    }

    #[tokio::test]
    async fn create_invite_v2_rejects_non_genesis_without_proof() {
        let private_key = [228; 32];
        let signing_key = SigningKey::from_bytes(&private_key);
        let issuer = NodeId::from_public_key(&signing_key.verifying_key());
        let storage_path = std::env::temp_dir().join(format!(
            "hal-runtime-invite-v2-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&storage_path, &[0x65; 32]).expect("open storage"),
        ));
        storage
            .lock()
            .expect("storage lock")
            .upsert_invite_first_seen(issuer.as_bytes(), 1)
            .expect("seed first-seen");
        seed_local_proof_of_live_full(&storage, issuer);
        let runtime = PeerRuntime::start_with_policy(
            identity_for(&private_key),
            private_key,
            "invite-v2-durable".into(),
            Some(Arc::clone(&storage)),
            trusted_local_policy(),
        )
        .await
        .expect("runtime");
        assert_local_proof_of_live_full(&runtime).await;
        runtime
            .ctx
            .hosts
            .lock()
            .expect("hosts lock")
            .pin_manual(&issuer.to_hex(), &runtime.public_key, unix_now())
            .expect("pin local issuer");

        let link = runtime.create_invite_v2(3600).await;
        let error = link.expect_err("non-genesis issuance requires a stored proof");
        assert!(
            error
                .to_string()
                .contains("verified invite proof for non-genesis issuer is missing"),
            "unexpected invite error: {error:#}"
        );
        let stored_count: i64 = storage
            .lock()
            .expect("storage lock")
            .connection()
            .query_row("SELECT COUNT(*) FROM invites", [], |row| row.get(0))
            .expect("query durable invite");
        assert_eq!(stored_count, 0);

        runtime.stop().await.expect("stop runtime");
        std::fs::remove_file(storage_path).expect("remove test database");
    }

    #[tokio::test]
    async fn create_invite_v1_still_works() {
        let private_key = [229; 32];
        let signing_key = SigningKey::from_bytes(&private_key);
        let issuer = NodeId::from_public_key(&signing_key.verifying_key());
        let storage_path = std::env::temp_dir().join(format!(
            "hal-runtime-invite-v1-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&storage_path, &[0x66; 32]).expect("open storage"),
        ));
        storage
            .lock()
            .expect("storage lock")
            .upsert_invite_first_seen(issuer.as_bytes(), 1)
            .expect("seed first-seen");
        seed_local_proof_of_live_full(&storage, issuer);
        let runtime = PeerRuntime::start_with_storage(
            identity_for(&private_key),
            private_key,
            "invite-v1-legacy".into(),
            storage,
        )
        .await
        .expect("runtime");
        assert_local_proof_of_live_full(&runtime).await;
        runtime
            .ctx
            .hosts
            .lock()
            .expect("hosts lock")
            .pin_manual(&runtime.identity_id, &runtime.public_key, unix_now())
            .expect("pin local issuer");

        let link = runtime.create_invite(3600).await;
        let link = link.expect("create legacy invite");
        let InviteWire::V1(invite) = InviteWire::from_link(&link).expect("parse legacy link")
        else {
            panic!("legacy link decoded as v2");
        };
        assert_eq!(invite.v, 1);
        invite.verify(unix_now()).expect("verify legacy invite");

        runtime.stop().await.expect("stop runtime");
        std::fs::remove_file(storage_path).expect("remove test database");
    }

    #[tokio::test]
    async fn cold_contact_send_blocked_by_trust_gate() {
        let local_key = [226; 32];
        let peer_key = SigningKey::from_bytes(&[227; 32]);
        let runtime = PeerRuntime::start(
            identity_for(&local_key),
            local_key,
            "trust-gate-cold-block".into(),
        )
        .await
        .expect("runtime");

        let blocked_before = runtime
            .ctx
            .abuse_metrics
            .snapshot()
            .trust_gate_blocked_total;
        let result = runtime
            .send_pending_verified(
                "127.0.0.1:1",
                &hex::encode(peer_key.verifying_key().to_bytes()),
            )
            .await;

        assert!(result
            .expect_err("unknown peer must be blocked by trust gate")
            .to_string()
            .contains("blocked by trust gate"));
        assert_eq!(
            runtime
                .ctx
                .abuse_metrics
                .snapshot()
                .trust_gate_blocked_total,
            blocked_before + 1
        );
        runtime.stop().await.expect("stop runtime");
    }

    #[tokio::test]
    async fn cold_contact_send_allowed_for_ingraph_peer() {
        let local_key = [228; 32];
        let peer_key = SigningKey::from_bytes(&[229; 32]);
        let peer_id = NodeId::from_public_key(&peer_key.verifying_key());
        let runtime = PeerRuntime::start(
            identity_for(&local_key),
            local_key,
            "trust-gate-known-peer".into(),
        )
        .await
        .expect("runtime");
        runtime
            .ctx
            .hosts
            .lock()
            .expect("hosts lock")
            .pin_manual(
                &peer_id.to_hex(),
                &hex::encode(peer_key.verifying_key().to_bytes()),
                unix_now(),
            )
            .expect("pin known peer");

        let blocked_before = runtime
            .ctx
            .abuse_metrics
            .snapshot()
            .trust_gate_blocked_total;
        runtime
            .send_pending_verified(
                "127.0.0.1:1",
                &hex::encode(peer_key.verifying_key().to_bytes()),
            )
            .await
            .expect("known peer allowed by trust gate");
        assert_eq!(
            runtime
                .ctx
                .abuse_metrics
                .snapshot()
                .trust_gate_blocked_total,
            blocked_before
        );
        runtime.stop().await.expect("stop runtime");
    }

    #[tokio::test]
    async fn create_invite_blocked_for_unknown_issuer() {
        let private_key = [230; 32];
        let runtime = PeerRuntime::start(
            identity_for(&private_key),
            private_key,
            "trust-gate-unknown-issuer".into(),
        )
        .await
        .expect("runtime");

        let blocked_before = runtime
            .ctx
            .abuse_metrics
            .snapshot()
            .trust_gate_blocked_total;
        let result = runtime.create_invite(3600).await;
        #[cfg(debug_assertions)]
        {
            assert!(result.is_ok(), "debug builds bypass invite trust gating");
            assert_eq!(
                runtime
                    .ctx
                    .abuse_metrics
                    .snapshot()
                    .trust_gate_blocked_total,
                blocked_before
            );
        }
        #[cfg(not(debug_assertions))]
        {
            let error = result.expect_err("unknown issuer must be blocked");
            assert!(error.to_string().contains("blocked by trust gate"));
            assert_eq!(
                runtime
                    .ctx
                    .abuse_metrics
                    .snapshot()
                    .trust_gate_blocked_total,
                blocked_before + 1
            );
        }
        runtime.stop().await.expect("stop runtime");
    }

    #[tokio::test]
    async fn prekey_rotation_task_is_enabled_only_with_storage() {
        let local_key = [220; 32];
        let without_storage = PeerRuntime::start(
            identity_for(&local_key),
            local_key,
            "prekey-no-storage".into(),
        )
        .await
        .expect("runtime without storage");
        assert!(without_storage.prekey_rotation_task.is_none());
        assert!(without_storage.journal_commit_task.is_none());
        assert!(without_storage.ctx.local_prekey_store.is_none());
        without_storage.stop().await.expect("stop runtime");

        let path = std::env::temp_dir().join(format!(
            "hal-runtime-prekey-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[0x64; 32]).expect("open storage"),
        ));
        let with_storage = PeerRuntime::start_with_storage(
            identity_for(&local_key),
            local_key,
            "prekey-with-storage".into(),
            storage,
        )
        .await
        .expect("runtime with storage");
        assert!(with_storage.prekey_rotation_task.is_some());
        assert!(with_storage.journal_commit_task.is_some());
        assert!(with_storage.ctx.local_prekey_store.is_some());
        with_storage.stop().await.expect("stop runtime");
        std::fs::remove_file(path).expect("remove test database");
    }

    #[tokio::test]
    async fn incoming_envelope_records_age_tracker() {
        let local_key = [221; 32];
        let sender_key = [222; 32];
        let storage_path =
            std::env::temp_dir().join(format!("hal-runtime-age-{}.sqlite3", uuid::Uuid::new_v4()));
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&storage_path, &[0x61; 32]).expect("open storage"),
        ));
        let runtime = PeerRuntime::start_with_storage(
            identity_for(&local_key),
            local_key,
            "age-tracker-inbound".into(),
            storage,
        )
        .await
        .expect("runtime");
        let sender_id =
            NodeId::from_public_key(&SigningKey::from_bytes(&sender_key).verifying_key());
        let envelope = SyncEnvelope::new(
            identity_for(&sender_key),
            test_pubkey(sender_key[0]),
            Vec::new(),
        );

        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&runtime.ctx)).await;

        let first_seen = runtime
            .ctx
            .age_tracker
            .as_ref()
            .expect("age tracker configured")
            .lock()
            .await
            .first_seen(&sender_id)
            .expect("read first-seen");
        assert!(first_seen.is_some());
        runtime.stop().await.expect("stop runtime");
        std::fs::remove_file(storage_path).expect("remove test database");
    }

    #[tokio::test]
    async fn incoming_envelope_second_time_does_not_update() {
        let local_key = [223; 32];
        let sender_key = [224; 32];
        let storage_path = std::env::temp_dir().join(format!(
            "hal-runtime-age-idempotent-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        let storage = ClientStorage::open(&storage_path, &[0x62; 32]).expect("open storage");
        let sender_id =
            NodeId::from_public_key(&SigningKey::from_bytes(&sender_key).verifying_key());
        storage
            .identity_history()
            .observe_first_seen(&sender_id.to_hex(), 123)
            .expect("seed first-seen");
        let storage = Arc::new(StdMutex::new(storage));
        let runtime = PeerRuntime::start_with_storage(
            identity_for(&local_key),
            local_key,
            "age-tracker-repeat".into(),
            storage,
        )
        .await
        .expect("runtime");

        for _ in 0..2 {
            let envelope = SyncEnvelope::new(
                identity_for(&sender_key),
                test_pubkey(sender_key[0]),
                Vec::new(),
            );
            PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&runtime.ctx)).await;
        }

        let first_seen = runtime
            .ctx
            .age_tracker
            .as_ref()
            .expect("age tracker configured")
            .lock()
            .await
            .first_seen(&sender_id)
            .expect("read first-seen");
        assert_eq!(first_seen, Some(123));
        runtime.stop().await.expect("stop runtime");
        std::fs::remove_file(storage_path).expect("remove test database");
    }

    #[tokio::test]
    async fn incoming_envelope_records_activity() {
        let local_key = [225; 32];
        let sender_key = [226; 32];
        let storage_path = std::env::temp_dir().join(format!(
            "hal-runtime-activity-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&storage_path, &[0x63; 32]).expect("open storage"),
        ));
        let runtime = PeerRuntime::start_with_storage(
            identity_for(&local_key),
            local_key,
            "activity-tracker-inbound".into(),
            storage,
        )
        .await
        .expect("runtime");
        let sender_id =
            NodeId::from_public_key(&SigningKey::from_bytes(&sender_key).verifying_key());
        let mut event_a = SyncEvent::new(
            "event-a".into(),
            SyncEventType::SettingsUpdated,
            "{}".into(),
        );
        let mut event_b = SyncEvent::new(
            "event-b".into(),
            SyncEventType::SettingsUpdated,
            "{}".into(),
        );
        event_a.sign(&sender_key).expect("sign event a");
        event_b.sign(&sender_key).expect("sign event b");
        let envelope = SyncEnvelope::new(
            identity_for(&sender_key),
            test_pubkey(sender_key[0]),
            vec![event_a, event_b],
        );

        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&runtime.ctx)).await;

        let last = runtime
            .ctx
            .activity_tracker
            .as_ref()
            .expect("activity tracker configured")
            .lock()
            .await
            .last_activity(&sender_id)
            .await
            .expect("read activity");
        assert!(last.is_some());
        runtime.stop().await.expect("stop runtime");
        std::fs::remove_file(storage_path).expect("remove test database");
    }

    async fn successful_peer_directory_send(label: &str) -> (PeerRuntime, PeerRuntime) {
        let key_a = [121; 32];
        let key_b = [122; 32];
        let mut a = PeerRuntime::start(identity_for(&key_a), key_a, format!("{label}-a"))
            .await
            .expect("runtime a");
        let mut b = PeerRuntime::start(identity_for(&key_b), key_b, format!("{label}-b"))
            .await
            .expect("runtime b");
        a.activate_listener(None, None)
            .await
            .expect("activate a listener");
        b.activate_listener(None, None)
            .await
            .expect("activate b listener");
        a.pin_peer(&b.identity_id, &b.public_key)
            .await
            .expect("pin b for a");
        b.pin_peer(&a.identity_id, &a.public_key)
            .await
            .expect("pin a for b");
        let address = b.transport_address.clone();
        let public_key = b.public_key.clone();
        a.add_message(
            format!("{label}-chat"),
            a.identity_id.clone(),
            Some(b.identity_id.clone()),
            "pending".into(),
        )
        .await
        .expect("add pending message");
        a.send_pending_verified(&address, &public_key)
            .await
            .expect("send pending message");
        (a, b)
    }

    fn e2ee_test_storage(seed: u8) -> (Arc<StdMutex<ClientStorage>>, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "hal-e2ee-2d-{seed}-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[seed; 32]).expect("open E2EE test storage"),
        ));
        (storage, path)
    }

    fn x3dh_test_context(
        signing_key: &SigningKey,
        storage: Option<Arc<StdMutex<ClientStorage>>>,
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
        let identity_id = NodeId::from_public_key(&signing_key.verifying_key()).to_hex();
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());
        Arc::new(RuntimeContext {
            sync: Arc::new(Mutex::new(SyncManager::new(identity_id.clone()))),
            home_state: Arc::new(Mutex::new(HomeRuntimeState::default())),
            media_signals: Arc::new(Mutex::new(Vec::new())),
            age_tracker: RuntimeContext::default_age_tracker(storage.clone()),
            activity_tracker: RuntimeContext::default_activity_tracker(storage.clone()),
            proof_of_live: None,
            storage: storage.clone(),
            hosts,
            scores,
            rates,
            trust_graph: None,
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
            local_prekey_store: RuntimeContext::default_local_prekey_store(
                storage.clone(),
                Arc::clone(&abuse_metrics),
            ),
            session_store: match storage.as_ref() {
                Some(storage) => RuntimeContext::session_store_with_storage(
                    Arc::clone(storage),
                    Arc::clone(&abuse_metrics),
                ),
                None => RuntimeContext::session_store_with_metrics(Arc::clone(&abuse_metrics)),
            },
            biometric_gate: Arc::new(NoopBiometricGate),
            invite_registry: RuntimeContext::default_invite_registry(),
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
            public_key,
            identity_signing_key: Some(Arc::new(signing_key.clone())),
            jury_commitment_publisher: None,
            jury_plaintext_cache: RuntimeContext::default_jury_plaintext_cache(),
            invite_redemption_transport: None,
            pending_invite_redemptions: RuntimeContext::default_pending_invite_redemptions(),
            sas_pairing: RuntimeContext::default_sas_pairing(),
            integrity: None,
        })
    }

    async fn x3dh_test_bundle(
        ctx: &RuntimeContext,
        signing_key: &SigningKey,
        now: u64,
        include_opk: bool,
    ) -> PrekeyBundle {
        let store = ctx
            .local_prekey_store
            .as_ref()
            .expect("test local prekey store");
        let mut store = store.lock().await;
        store.ensure_signed_prekey(now).await.expect("ensure SPK");
        if include_opk {
            store.refill_opk_pool(now).await.expect("refill OPK");
        }
        let signed_prekey = store
            .current_signed_prekey()
            .await
            .expect("read SPK")
            .expect("current SPK");
        let mut opks = if include_opk {
            store.opk_list().await.expect("read OPKs")
        } else {
            Vec::new()
        };
        opks.truncate(1);
        PrekeyBundle::create(
            signing_key,
            signed_prekey.public_key,
            opks,
            1,
            now,
            now.saturating_add(3_600),
        )
        .expect("create prekey bundle")
    }

    async fn establish_test_ratchet_session(
        initiator: &PeerRuntime,
        responder: &PeerRuntime,
    ) -> NodeId {
        let now = unix_now();
        let peer = NodeId::from_hex(&responder.identity_id).expect("responder identity");
        let bundle = x3dh_test_bundle(&responder.ctx, &responder.private_key, now, true).await;
        initiator
            .ctx
            .prekey_cache
            .lock()
            .await
            .insert(peer, bundle.clone(), bundle.expires_at, now)
            .expect("cache responder bundle");
        initiator
            .establish_session_as_initiator(peer, now)
            .await
            .expect("establish pending initiator session");

        let init_event = initiator
            .pending_events()
            .await
            .into_iter()
            .rev()
            .find(|event| event.event_type == SyncEventType::X3dhInit)
            .expect("initiator X3DH init event");
        let init_bytes = base64::engine::general_purpose::STANDARD
            .decode(init_event.data)
            .expect("decode X3DH init event");
        let init: X3dhInitMessage =
            serde_json::from_slice(&init_bytes).expect("parse X3DH init message");
        responder
            .handle_session_init(init.clone(), now)
            .await
            .expect("handle X3DH init");
        initiator
            .handle_session_respond(
                X3dhRespondMessage::for_init_with_capability(
                    &init,
                    &responder.private_key,
                    Some(true),
                ),
                now,
            )
            .await
            .expect("handle X3DH response");

        assert!(
            initiator
                .get_session(&peer)
                .await
                .expect("initiator session")
                .responded
        );
        let initiator_id = NodeId::from_hex(&initiator.identity_id).expect("initiator identity");
        assert!(
            responder
                .get_session(&initiator_id)
                .await
                .expect("responder session")
                .responded
        );
        peer
    }

    async fn biometric_test_pair(
        label: &str,
        gate_on_initiator: bool,
        gate: Arc<MockBiometricGate>,
    ) -> (PeerRuntime, PeerRuntime, NodeId, tempfile::TempDir) {
        let initiator_key = [201; 32];
        let responder_key = [202; 32];
        let (responder_storage, storage_dir) = runtime_storage(203);
        let gate: Arc<dyn BiometricGate> = gate;
        let initiator = if gate_on_initiator {
            PeerRuntime::start_with_biometric_gate(
                identity_for(&initiator_key),
                initiator_key,
                format!("{label}-a"),
                None,
                Arc::clone(&gate),
            )
            .await
        } else {
            PeerRuntime::start(
                identity_for(&initiator_key),
                initiator_key,
                format!("{label}-a"),
            )
            .await
        }
        .expect("start biometric test initiator");
        let responder = if gate_on_initiator {
            PeerRuntime::start_with_storage(
                identity_for(&responder_key),
                responder_key,
                format!("{label}-b"),
                responder_storage,
            )
            .await
        } else {
            PeerRuntime::start_with_biometric_gate(
                identity_for(&responder_key),
                responder_key,
                format!("{label}-b"),
                Some(responder_storage),
                gate,
            )
            .await
        }
        .expect("start biometric test responder");
        let peer = establish_test_ratchet_session(&initiator, &responder).await;
        initiator
            .pin_peer(&responder.identity_id, &responder.public_key)
            .await
            .expect("pin responder");
        responder
            .pin_peer(&initiator.identity_id, &initiator.public_key)
            .await
            .expect("pin initiator");
        (initiator, responder, peer, storage_dir)
    }

    async fn set_contact_policy(runtime: &PeerRuntime, peer: NodeId, policy: ContactPolicy) {
        runtime
            .ctx
            .session_store
            .lock()
            .await
            .get_mut(&peer)
            .expect("test session")
            .contact_policy = policy;
    }

    async fn send_biometric_test_message(
        sender: &PeerRuntime,
        recipient: &PeerRuntime,
        text: &str,
    ) -> Result<()> {
        let recipient_key = recipient.private_key.verifying_key();
        sender
            .add_message_encrypted(
                "biometric-test".into(),
                sender.identity_id.clone(),
                recipient.identity_id.clone(),
                &recipient_key,
                text.into(),
            )
            .await
    }

    async fn receive_biometric_test_message(sender: &PeerRuntime, recipient: &PeerRuntime) {
        let mut event = sender
            .pending_events()
            .await
            .into_iter()
            .rev()
            .find(|event| event.event_type == SyncEventType::MessageAdded)
            .expect("outbound MessageAdded event");
        event
            .sign(&sender.private_key.to_bytes())
            .expect("sign outbound event");
        let envelope = SyncEnvelope::new(
            sender.identity_id.clone(),
            sender.public_key.clone(),
            vec![event],
        );
        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&recipient.ctx)).await;
    }

    #[tokio::test]
    async fn age_proof_send_does_not_prompt() {
        let gate = Arc::new(MockBiometricGate::new(true));
        gate.set_response(MockResponse::Rejected);
        let (a, b, b_id, _storage_dir) =
            biometric_test_pair("biometric-age-send", true, gate).await;
        set_contact_policy(&a, b_id, ContactPolicy::AgeProof).await;

        assert!(send_biometric_test_message(&a, &b, "age proof")
            .await
            .is_ok());
        assert_eq!(
            a.ctx
                .abuse_metrics
                .biometric_rejected_total
                .load(Ordering::Relaxed),
            0
        );

        a.stop().await.expect("stop initiator");
        b.stop().await.expect("stop responder");
    }

    #[tokio::test]
    async fn paranoid_send_requires_and_records_biometric() {
        let gate = Arc::new(MockBiometricGate::new(true));
        let (a, b, b_id, _storage_dir) =
            biometric_test_pair("biometric-paranoid-send", true, gate).await;
        set_contact_policy(&a, b_id, ContactPolicy::Paranoid).await;

        assert!(send_biometric_test_message(&a, &b, "approved")
            .await
            .is_ok());
        assert_eq!(
            a.ctx
                .abuse_metrics
                .biometric_verified_total
                .load(Ordering::Relaxed),
            1
        );

        a.stop().await.expect("stop initiator");
        b.stop().await.expect("stop responder");
    }

    #[tokio::test]
    async fn paranoid_send_rejection_prevents_message_creation() {
        let gate = Arc::new(MockBiometricGate::new(true));
        gate.set_response(MockResponse::Rejected);
        let (a, b, b_id, _storage_dir) =
            biometric_test_pair("biometric-reject-send", true, gate).await;
        set_contact_policy(&a, b_id, ContactPolicy::Paranoid).await;

        assert!(send_biometric_test_message(&a, &b, "rejected")
            .await
            .is_err());
        assert_eq!(
            a.pending_events()
                .await
                .iter()
                .filter(|event| event.event_type == SyncEventType::MessageAdded)
                .count(),
            0
        );
        assert_eq!(
            a.ctx
                .abuse_metrics
                .biometric_rejected_total
                .load(Ordering::Relaxed),
            1
        );

        a.stop().await.expect("stop initiator");
        b.stop().await.expect("stop responder");
    }

    #[tokio::test]
    async fn fresh_biometric_interval_send_does_not_prompt() {
        let gate = Arc::new(MockBiometricGate::new(true));
        gate.set_response(MockResponse::Rejected);
        let (a, b, b_id, _storage_dir) =
            biometric_test_pair("biometric-interval-fresh-send", true, gate).await;
        set_contact_policy(
            &a,
            b_id,
            ContactPolicy::BiometricInterval {
                interval_secs: 900,
                last_verified: unix_now(),
            },
        )
        .await;

        assert!(send_biometric_test_message(&a, &b, "fresh").await.is_ok());
        assert_eq!(
            a.ctx
                .abuse_metrics
                .biometric_verified_total
                .load(Ordering::Relaxed),
            0
        );

        a.stop().await.expect("stop initiator");
        b.stop().await.expect("stop responder");
    }

    #[tokio::test]
    async fn expired_biometric_interval_send_refreshes_verification() {
        let gate = Arc::new(MockBiometricGate::new(true));
        let (a, b, b_id, _storage_dir) =
            biometric_test_pair("biometric-interval-expired-send", true, gate).await;
        set_contact_policy(
            &a,
            b_id,
            ContactPolicy::BiometricInterval {
                interval_secs: 1,
                last_verified: 0,
            },
        )
        .await;

        assert!(send_biometric_test_message(&a, &b, "refresh").await.is_ok());
        assert_eq!(
            a.ctx
                .session_store
                .lock()
                .await
                .get(&b_id)
                .expect("session")
                .contact_policy,
            ContactPolicy::BiometricInterval {
                interval_secs: 1,
                last_verified: unix_now(),
            }
        );

        a.stop().await.expect("stop initiator");
        b.stop().await.expect("stop responder");
    }

    #[tokio::test]
    async fn unavailable_biometric_send_downgrades_to_age_proof() {
        let gate = Arc::new(MockBiometricGate::new(false));
        let (a, b, b_id, _storage_dir) =
            biometric_test_pair("biometric-unavailable-send", true, gate).await;
        set_contact_policy(&a, b_id, ContactPolicy::Paranoid).await;

        assert!(send_biometric_test_message(&a, &b, "degraded")
            .await
            .is_ok());
        assert_eq!(
            a.ctx
                .session_store
                .lock()
                .await
                .get(&b_id)
                .expect("session")
                .contact_policy,
            ContactPolicy::AgeProof
        );
        assert_eq!(
            a.ctx
                .abuse_metrics
                .biometric_unavailable_total
                .load(Ordering::Relaxed),
            1
        );

        a.stop().await.expect("stop initiator");
        b.stop().await.expect("stop responder");
    }

    #[tokio::test]
    async fn paranoid_receive_rejection_prevents_decryption() {
        let gate = Arc::new(MockBiometricGate::new(true));
        gate.set_response(MockResponse::Rejected);
        let (a, b, _b_id, _storage_dir) =
            biometric_test_pair("biometric-reject-receive", false, gate).await;
        let a_id = NodeId::from_hex(&a.identity_id).expect("initiator identity");
        set_contact_policy(&b, a_id, ContactPolicy::Paranoid).await;
        assert!(send_biometric_test_message(&a, &b, "blocked receive")
            .await
            .is_ok());

        receive_biometric_test_message(&a, &b).await;
        assert_eq!(
            b.ctx
                .abuse_metrics
                .ratchet_decrypt_total
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            b.ctx
                .abuse_metrics
                .biometric_rejected_total
                .load(Ordering::Relaxed),
            1
        );

        a.stop().await.expect("stop initiator");
        b.stop().await.expect("stop responder");
    }

    #[tokio::test]
    async fn paranoid_receive_approval_allows_decryption() {
        let gate = Arc::new(MockBiometricGate::new(true));
        let (a, b, _b_id, _storage_dir) =
            biometric_test_pair("biometric-approve-receive", false, gate).await;
        let a_id = NodeId::from_hex(&a.identity_id).expect("initiator identity");
        set_contact_policy(&b, a_id, ContactPolicy::Paranoid).await;
        assert!(send_biometric_test_message(&a, &b, "approved receive")
            .await
            .is_ok());

        receive_biometric_test_message(&a, &b).await;
        assert_eq!(
            b.ctx
                .abuse_metrics
                .ratchet_decrypt_total
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            b.ctx
                .abuse_metrics
                .biometric_verified_total
                .load(Ordering::Relaxed),
            1
        );

        a.stop().await.expect("stop initiator");
        b.stop().await.expect("stop responder");
    }

    #[tokio::test]
    async fn interval_receive_rejection_defers_decrypt() {
        let gate = Arc::new(MockBiometricGate::new(true));
        gate.set_response(MockResponse::Rejected);
        let (a, b, _b_id, _storage_dir) = biometric_test_pair(
            "biometric-interval-reject-receive",
            false,
            Arc::clone(&gate),
        )
        .await;
        let a_id = NodeId::from_hex(&a.identity_id).expect("initiator identity");
        set_contact_policy(
            &b,
            a_id,
            ContactPolicy::BiometricInterval {
                interval_secs: 1,
                last_verified: 0,
            },
        )
        .await;
        assert!(
            send_biometric_test_message(&a, &b, "deferred until approval")
                .await
                .is_ok()
        );
        let event_id = a
            .pending_events()
            .await
            .into_iter()
            .rev()
            .find(|event| event.event_type == SyncEventType::MessageAdded)
            .expect("outbound message event")
            .id;

        let journal_before = b
            .ctx
            .storage
            .as_ref()
            .expect("responder storage")
            .lock()
            .expect("storage lock")
            .messages_json(&a.public_key)
            .expect("read message journal");
        receive_biometric_test_message(&a, &b).await;
        assert_eq!(
            b.ctx
                .abuse_metrics
                .ratchet_decrypt_total
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            b.ctx
                .abuse_metrics
                .biometric_rejected_total
                .load(Ordering::Relaxed),
            1
        );
        let journal_after_rejection = b
            .ctx
            .storage
            .as_ref()
            .expect("responder storage")
            .lock()
            .expect("storage lock")
            .messages_json(&a.public_key)
            .expect("read message journal");
        assert_eq!(journal_after_rejection, journal_before);
        assert!(!journal_after_rejection.contains(&event_id));

        gate.set_response(MockResponse::Ok);
        receive_biometric_test_message(&a, &b).await;
        assert_eq!(
            b.ctx
                .abuse_metrics
                .ratchet_decrypt_total
                .load(Ordering::Relaxed),
            1
        );
        let journal_after_retry = b
            .ctx
            .storage
            .as_ref()
            .expect("responder storage")
            .lock()
            .expect("storage lock")
            .messages_json(&a.public_key)
            .expect("read message journal");
        assert!(journal_after_retry.contains(&event_id));

        a.stop().await.expect("stop initiator");
        b.stop().await.expect("stop responder");
    }

    #[tokio::test]
    async fn unavailable_biometric_receive_downgrades_policy() {
        let gate = Arc::new(MockBiometricGate::new(false));
        let (a, b, _b_id, _storage_dir) =
            biometric_test_pair("biometric-unavailable-receive", false, gate).await;
        let a_id = NodeId::from_hex(&a.identity_id).expect("initiator identity");
        set_contact_policy(&b, a_id, ContactPolicy::Paranoid).await;
        assert!(send_biometric_test_message(&a, &b, "degraded receive")
            .await
            .is_ok());

        receive_biometric_test_message(&a, &b).await;
        assert_eq!(
            b.ctx
                .session_store
                .lock()
                .await
                .get(&a_id)
                .expect("session")
                .contact_policy,
            ContactPolicy::AgeProof
        );
        assert_eq!(
            b.ctx
                .abuse_metrics
                .biometric_unavailable_total
                .load(Ordering::Relaxed),
            1
        );

        a.stop().await.expect("stop initiator");
        b.stop().await.expect("stop responder");
    }

    async fn establish_test_session_with_capability(
        initiator: &PeerRuntime,
        responder: &PeerRuntime,
        capability: Option<bool>,
    ) -> NodeId {
        let now = unix_now();
        let bundle = x3dh_test_bundle(&responder.ctx, &responder.private_key, now, true).await;
        let initiator_keys =
            X3DHKeys::from_identity(&initiator.private_key).expect("initiator X3DH keys");
        let opk = bundle.one_time_prekeys.first();
        let (result, init) = X3DH::initiate_with_bundle_and_capability(
            &initiator_keys,
            &bundle,
            opk,
            now,
            capability,
        )
        .expect("create capability-specific X3DH init");
        let root_key = session_root_key(&result).expect("derive X3DH root");
        responder
            .handle_session_init(init, now)
            .await
            .expect("handle capability-specific X3DH init");

        let peer = NodeId::from_hex(&responder.identity_id).expect("responder identity");
        let local = NodeId::from_hex(&initiator.identity_id).expect("initiator identity");
        let mut store = initiator.ctx.session_store.lock().await;
        store
            .insert_with_chains(peer, root_key, &local, now)
            .expect("install initiator session from X3DH root");
        store
            .set_peer_supports_v4(&peer, capability)
            .expect("set negotiated test capability");
        peer
    }

    async fn start_mutual_ratchet_pair(
        seed: u8,
    ) -> (PeerRuntime, PeerRuntime, NodeId, tempfile::TempDir) {
        let sender_key = [seed; 32];
        let recipient_key = [seed.wrapping_add(1); 32];
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            format!("v4-mutual-sender-{seed}"),
        )
        .await
        .expect("start sender");
        let (storage, storage_dir) = runtime_storage(seed);
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            format!("v4-mutual-recipient-{seed}"),
            Some(storage),
            trusted_local_policy(),
        )
        .await
        .expect("start recipient");
        let peer = establish_test_ratchet_session(&sender, &recipient).await;
        sender
            .ctx
            .session_store
            .lock()
            .await
            .set_peer_supports_v4(&peer, Some(true))
            .expect("set negotiated test capability");
        (sender, recipient, peer, storage_dir)
    }

    async fn start_mutual_ratchet_pair_with_established_rate_peer(
        seed: u8,
    ) -> (PeerRuntime, PeerRuntime, NodeId, tempfile::TempDir) {
        let sender_key = [seed; 32];
        let recipient_key = [seed.wrapping_add(1); 32];
        let sender_id =
            NodeId::from_public_key(&SigningKey::from_bytes(&sender_key).verifying_key());
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            format!("v4-established-sender-{seed}"),
        )
        .await
        .expect("start sender");
        let (storage, storage_dir) = runtime_storage(seed);
        storage
            .lock()
            .expect("storage lock")
            .identity_history()
            .observe_first_seen(&sender_id.to_hex(), 1)
            .expect("seed established first-seen timestamp");
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            format!("v4-established-recipient-{seed}"),
            Some(storage),
            trusted_local_policy(),
        )
        .await
        .expect("start recipient");
        let peer = establish_test_ratchet_session(&sender, &recipient).await;
        sender
            .ctx
            .session_store
            .lock()
            .await
            .set_peer_supports_v4(&peer, Some(true))
            .expect("set negotiated test capability");

        let accepted_start = unix_now()
            .saturating_sub(crate::dht::rate_limit::FIRST_CONTACT_ACCEPTED_THRESHOLD as u64 * 31);
        for index in 0..crate::dht::rate_limit::FIRST_CONTACT_ACCEPTED_THRESHOLD as u64 {
            assert!(recipient
                .ctx
                .record_rate_acceptance(&sender_id, accepted_start + index * 31));
        }
        (sender, recipient, peer, storage_dir)
    }

    async fn start_persistent_mutual_ratchet_pair(
        seed: u8,
    ) -> (
        PeerRuntime,
        PeerRuntime,
        NodeId,
        Arc<StdMutex<ClientStorage>>,
        tempfile::TempDir,
        tempfile::TempDir,
    ) {
        let sender_key = [seed; 32];
        let recipient_key = [seed.wrapping_add(1); 32];
        let (sender_storage, sender_dir) = runtime_storage(seed);
        let (recipient_storage, recipient_dir) = runtime_storage(seed.wrapping_add(1));
        let sender = PeerRuntime::start_with_storage(
            identity_for(&sender_key),
            sender_key,
            format!("v4-persistent-sender-{seed}"),
            Arc::clone(&sender_storage),
        )
        .await
        .expect("start persistent sender");
        let recipient = PeerRuntime::start_with_storage(
            identity_for(&recipient_key),
            recipient_key,
            format!("v4-persistent-recipient-{seed}"),
            recipient_storage,
        )
        .await
        .expect("start persistent recipient");
        let peer = establish_test_ratchet_session(&sender, &recipient).await;
        prime_test_dh_peers(&sender, &recipient).await;
        (
            sender,
            recipient,
            peer,
            sender_storage,
            sender_dir,
            recipient_dir,
        )
    }

    async fn x3dh_init_with_capability(
        initiator_key: [u8; 32],
        responder: &PeerRuntime,
        capability: Option<bool>,
    ) -> X3dhInitMessage {
        let now = unix_now();
        let bundle = x3dh_test_bundle(&responder.ctx, &responder.private_key, now, true).await;
        let initiator_keys = X3DHKeys::from_identity(&SigningKey::from_bytes(&initiator_key))
            .expect("initiator X3DH keys");
        let opk = bundle.one_time_prekeys.first().cloned();
        let (_, init) = X3DH::initiate_with_bundle_and_capability(
            &initiator_keys,
            &bundle,
            opk.as_ref(),
            now,
            capability,
        )
        .expect("create X3DH init");
        init
    }

    async fn prime_test_dh_peers(a: &PeerRuntime, b: &PeerRuntime) {
        let a_id = NodeId::from_hex(&a.identity_id).expect("a identity");
        let b_id = NodeId::from_hex(&b.identity_id).expect("b identity");
        let a_pub = a
            .ctx
            .session_store
            .lock()
            .await
            .get(&b_id)
            .expect("a session")
            .dh_our_pubkey;
        let b_pub = b
            .ctx
            .session_store
            .lock()
            .await
            .get(&a_id)
            .expect("b session")
            .dh_our_pubkey;
        a.ctx
            .session_store
            .lock()
            .await
            .get_mut(&b_id)
            .expect("a mutable session")
            .dh_peer_pubkey = Some(b_pub);
        b.ctx
            .session_store
            .lock()
            .await
            .get_mut(&a_id)
            .expect("b mutable session")
            .dh_peer_pubkey = Some(a_pub);
    }

    #[tokio::test]
    async fn x3dh_outbound_init_carries_capability_true() {
        let (sender, recipient, _, _storage_dir) = start_mutual_ratchet_pair(141).await;
        let init = sender
            .pending_events()
            .await
            .into_iter()
            .find(|event| event.event_type == SyncEventType::X3dhInit)
            .map(|event| {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(event.data)
                    .expect("decode init");
                serde_json::from_slice::<X3dhInitMessage>(&bytes).expect("parse init")
            })
            .expect("outbound init event");
        assert_eq!(init.capability_v4_dh_ratchet, Some(true));
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
    }

    #[tokio::test]
    async fn responder_stores_peer_v4_capability() {
        let (sender, recipient, _, _storage_dir) = start_mutual_ratchet_pair(143).await;
        let peer = NodeId::from_hex(&sender.identity_id).expect("sender id");
        assert_eq!(
            recipient
                .ctx
                .session_store
                .lock()
                .await
                .get(&peer)
                .expect("responder session")
                .peer_supports_v4,
            Some(true)
        );
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
    }

    #[tokio::test]
    async fn responder_stores_legacy_peer() {
        let sender_key = [145; 32];
        let recipient_key = [146; 32];
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "v4-legacy-sender".into(),
        )
        .await
        .expect("start sender");
        let (storage, _storage_dir) = runtime_storage(183);
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            "v4-legacy-recipient".into(),
            Some(storage),
            trusted_local_policy(),
        )
        .await
        .expect("start recipient");
        let init = x3dh_init_with_capability(sender_key, &recipient, None).await;
        recipient
            .handle_session_init(init, unix_now())
            .await
            .expect("handle legacy init");
        let peer = NodeId::from_hex(&sender.identity_id).expect("sender id");
        assert_eq!(
            recipient
                .ctx
                .session_store
                .lock()
                .await
                .get(&peer)
                .expect("responder session")
                .peer_supports_v4,
            None
        );
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
    }

    #[tokio::test]
    async fn responder_stores_declined_peer() {
        let sender_key = [147; 32];
        let recipient_key = [148; 32];
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "v4-declined-sender".into(),
        )
        .await
        .expect("start sender");
        let (storage, _storage_dir) = runtime_storage(185);
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            "v4-declined-recipient".into(),
            Some(storage),
            trusted_local_policy(),
        )
        .await
        .expect("start recipient");
        let init = x3dh_init_with_capability(sender_key, &recipient, Some(false)).await;
        recipient
            .handle_session_init(init, unix_now())
            .await
            .expect("handle declined init");
        let peer = NodeId::from_hex(&sender.identity_id).expect("sender id");
        assert_eq!(
            recipient
                .ctx
                .session_store
                .lock()
                .await
                .get(&peer)
                .expect("responder session")
                .peer_supports_v4,
            Some(false)
        );
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
    }

    #[tokio::test]
    async fn initiator_stores_response_capability() {
        let sender_key = [149; 32];
        let recipient_key = [150; 32];
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "v4-response-capability-sender".into(),
        )
        .await
        .expect("start sender");
        let (storage, _storage_dir) = runtime_storage(187);
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            "v4-response-capability-recipient".into(),
            Some(storage),
            trusted_local_policy(),
        )
        .await
        .expect("start recipient");
        let now = unix_now();
        let peer = NodeId::from_hex(&recipient.identity_id).expect("recipient id");
        let bundle = x3dh_test_bundle(&recipient.ctx, &recipient.private_key, now, true).await;
        sender
            .ctx
            .prekey_cache
            .lock()
            .await
            .insert(peer, bundle.clone(), bundle.expires_at, now)
            .expect("cache responder bundle");
        sender
            .establish_session_as_initiator(peer, now)
            .await
            .expect("establish pending session");
        let init = sender
            .pending_events()
            .await
            .into_iter()
            .find(|event| event.event_type == SyncEventType::X3dhInit)
            .map(|event| {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(event.data)
                    .expect("decode init");
                serde_json::from_slice::<X3dhInitMessage>(&bytes).expect("parse init")
            })
            .expect("outbound init");
        sender
            .handle_session_respond(
                X3dhRespondMessage::for_init_with_capability(
                    &init,
                    &recipient.private_key,
                    Some(true),
                ),
                now,
            )
            .await
            .expect("handle capable response");
        assert_eq!(
            sender
                .ctx
                .session_store
                .lock()
                .await
                .get(&peer)
                .expect("initiator session")
                .peer_supports_v4,
            Some(true)
        );
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
    }

    #[tokio::test]
    async fn v4_sent_when_mutual_capability() {
        let (sender, recipient, _, _storage_dir) = start_mutual_ratchet_pair(151).await;
        let envelope =
            send_ratchet_envelope(&sender, &recipient, "v4-first", "first mutual message").await;
        let payload: crate::MessageAddedPayload =
            serde_json::from_str(&envelope.events[0].data).expect("parse payload");
        assert_eq!(payload.version, crate::journal::MESSAGE_VERSION_V4);
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
    }

    #[tokio::test]
    async fn v3_sent_when_peer_legacy() {
        let (sender, recipient, peer, _storage_dir) = start_mutual_ratchet_pair(153).await;
        sender
            .ctx
            .session_store
            .lock()
            .await
            .get_mut(&peer)
            .expect("sender session")
            .peer_supports_v4 = None;
        let envelope =
            send_ratchet_envelope(&sender, &recipient, "v3-legacy", "legacy message").await;
        let payload: crate::MessageAddedPayload =
            serde_json::from_str(&envelope.events[0].data).expect("parse payload");
        assert_eq!(payload.version, 3);
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
    }

    #[tokio::test]
    async fn v4_first_message_has_chain_id_zero() {
        let (sender, recipient, _, _storage_dir) = start_mutual_ratchet_pair(155).await;
        let envelope =
            send_ratchet_envelope(&sender, &recipient, "v4-chain-zero", "epoch zero").await;
        let payload: crate::MessageAddedPayload =
            serde_json::from_str(&envelope.events[0].data).expect("parse payload");
        assert_eq!(payload.chain_id, Some(0));
        assert_eq!(payload.dh_pubkey, None);
        assert_eq!(payload.prev_chain_length, None);
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
    }

    #[tokio::test]
    async fn v4_dh_trigger_at_threshold_50() {
        let (sender, recipient, peer, _storage_dir) = start_mutual_ratchet_pair(157).await;
        prime_test_dh_peers(&sender, &recipient).await;
        sender
            .ctx
            .session_store
            .lock()
            .await
            .get_mut(&peer)
            .expect("sender session")
            .messages_since_ratchet = 49;
        let before_threshold =
            send_ratchet_envelope(&sender, &recipient, "v4-threshold", "below threshold").await;
        let before_payload: crate::MessageAddedPayload =
            serde_json::from_str(&before_threshold.events[0].data).expect("parse pre-threshold");
        assert_eq!(before_payload.version, crate::journal::MESSAGE_VERSION_V4);
        assert_eq!(before_payload.chain_id, Some(0));
        assert_eq!(before_payload.dh_pubkey, None);
        assert_eq!(
            sender
                .ctx
                .abuse_metrics
                .snapshot()
                .dh_ratchet_initiations_total,
            0
        );
        let envelope =
            send_ratchet_envelope(&sender, &recipient, "v4-threshold", "threshold").await;
        let payload: crate::MessageAddedPayload =
            serde_json::from_str(&envelope.events[0].data).expect("parse payload");
        assert_eq!(payload.version, crate::journal::MESSAGE_VERSION_V4);
        assert_eq!(payload.chain_id, Some(1));
        assert!(payload.dh_pubkey.is_some());
        assert_eq!(payload.prev_chain_length, Some(50));
        assert_eq!(
            sender
                .ctx
                .abuse_metrics
                .snapshot()
                .dh_ratchet_initiations_total,
            1
        );
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
    }

    #[tokio::test]
    async fn v4_initiate_refuses_when_chain_epoch_at_u32_max() {
        let (sender, recipient, peer, _storage_dir) = start_mutual_ratchet_pair(159).await;
        let (root_before, sending_chain_before) = {
            let mut store = sender.ctx.session_store.lock().await;
            let session = store.get_mut(&peer).expect("sender session");
            session.messages_since_ratchet = 50;
            let root_before = session.root_key;
            let sending_chain_before = session.sending_chain.serialize();
            session.chain_epoch = u64::from(u32::MAX);
            (root_before, sending_chain_before)
        };
        let result = sender
            .add_message_encrypted(
                "v4-overflow".into(),
                sender.identity_id.clone(),
                recipient.identity_id.clone(),
                &recipient.private_key.verifying_key(),
                "must refuse overflow".into(),
            )
            .await;
        assert!(result.is_err());
        assert_eq!(
            sender
                .ctx
                .abuse_metrics
                .snapshot()
                .v4_chain_id_overflow_total,
            1
        );
        {
            let store = sender.ctx.session_store.lock().await;
            let session = store.get(&peer).expect("sender session");
            assert_eq!(session.root_key, root_before);
            assert_eq!(session.sending_chain.serialize(), sending_chain_before);
            assert!(!session.has_pending_dh_ratchet());
        }
        assert_eq!(
            sender
                .pending_events()
                .await
                .iter()
                .filter(|event| event.event_type == SyncEventType::MessageAdded)
                .count(),
            0
        );
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
    }

    #[tokio::test]
    async fn v4_dh_pubkey_only_on_first_v4_after_initiate() {
        let (sender, recipient, peer, _storage_dir) = start_mutual_ratchet_pair(161).await;
        prime_test_dh_peers(&sender, &recipient).await;
        sender
            .ctx
            .session_store
            .lock()
            .await
            .get_mut(&peer)
            .expect("sender session")
            .messages_since_ratchet = 50;
        let first = send_ratchet_envelope(&sender, &recipient, "v4-advertise", "advertise").await;
        let second = send_ratchet_envelope(&sender, &recipient, "v4-advertise", "no repeat").await;
        let first_payload: crate::MessageAddedPayload =
            serde_json::from_str(&first.events[0].data).expect("parse first payload");
        let second_payload: crate::MessageAddedPayload =
            serde_json::from_str(&second.events[0].data).expect("parse second payload");
        assert!(first_payload.dh_pubkey.is_some());
        assert_eq!(first_payload.prev_chain_length, Some(50));
        assert_eq!(second_payload.version, crate::journal::MESSAGE_VERSION_V4);
        assert_eq!(second_payload.chain_id, Some(1));
        assert_eq!(second_payload.dh_pubkey, None);
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
    }

    #[tokio::test]
    async fn v4_prev_chain_length_cleared_after_send() {
        let (sender, recipient, peer, _storage_dir) = start_mutual_ratchet_pair(163).await;
        prime_test_dh_peers(&sender, &recipient).await;
        sender
            .ctx
            .session_store
            .lock()
            .await
            .get_mut(&peer)
            .expect("sender session")
            .messages_since_ratchet = 50;
        let envelope = send_ratchet_envelope(&sender, &recipient, "v4-clear", "advertised").await;
        let payload: crate::MessageAddedPayload =
            serde_json::from_str(&envelope.events[0].data).expect("parse payload");
        assert!(payload.dh_pubkey.is_some());
        assert_eq!(
            sender
                .ctx
                .session_store
                .lock()
                .await
                .get(&peer)
                .expect("sender session")
                .prev_chain_length,
            None
        );
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
    }

    #[tokio::test]
    async fn v4_prev_chain_length_remains_if_persist_fails() {
        let sender_key = [165; 32];
        let recipient_key = [166; 32];
        let (sender_storage, _sender_dir) = runtime_storage(165);
        let sender = PeerRuntime::start_with_storage(
            identity_for(&sender_key),
            sender_key,
            "v4-persist-failure-sender".into(),
            Arc::clone(&sender_storage),
        )
        .await
        .expect("start sender");
        let (recipient_storage, _recipient_dir) = runtime_storage(166);
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            "v4-persist-failure-recipient".into(),
            Some(recipient_storage),
            trusted_local_policy(),
        )
        .await
        .expect("start recipient");
        let peer = establish_test_ratchet_session(&sender, &recipient).await;
        sender
            .ctx
            .session_store
            .lock()
            .await
            .set_peer_supports_v4(&peer, Some(true))
            .expect("set negotiated test capability");
        prime_test_dh_peers(&sender, &recipient).await;
        sender
            .ctx
            .session_store
            .lock()
            .await
            .get_mut(&peer)
            .expect("session")
            .messages_since_ratchet = 50;
        sender
            .ctx
            .session_store
            .lock()
            .await
            .fail_next_session_persist();
        let failed_send = sender
            .add_message_encrypted(
                "v4-persist-failure".into(),
                sender.identity_id.clone(),
                recipient.identity_id.clone(),
                &recipient.private_key.verifying_key(),
                "retry ratchet advertisement".into(),
            )
            .await;
        let error = failed_send.expect_err("injected write error must abort send");
        assert!(
            error
                .to_string()
                .contains("injected session persistence failure"),
            "expected the injected persistence Err, got: {error}"
        );
        assert_eq!(
            sender
                .ctx
                .session_store
                .lock()
                .await
                .get(&peer)
                .expect("session")
                .prev_chain_length,
            Some(50)
        );
        sender
            .add_message_encrypted(
                "v4-persist-retry".into(),
                sender.identity_id.clone(),
                recipient.identity_id.clone(),
                &recipient.private_key.verifying_key(),
                "retry ratchet advertisement".into(),
            )
            .await
            .expect("retry should advertise pending ratchet");
        let retried_event = sender
            .pending_events()
            .await
            .into_iter()
            .rev()
            .find(|event| event.event_type == SyncEventType::MessageAdded)
            .expect("retry MessageAdded event");
        let retried_payload: crate::MessageAddedPayload =
            serde_json::from_str(&retried_event.data).expect("parse retry payload");
        assert!(retried_payload.dh_pubkey.is_some());
        assert_eq!(retried_payload.prev_chain_length, Some(50));
        assert_eq!(
            sender
                .ctx
                .session_store
                .lock()
                .await
                .get(&peer)
                .expect("session")
                .prev_chain_length,
            None
        );
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
    }

    #[tokio::test]
    async fn v3_only_legacy_peer_no_dh_ratchet() {
        let sender_key = [191; 32];
        let recipient_key = [192; 32];
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "v3-only-sender".into(),
        )
        .await
        .expect("start sender");
        let (recipient_storage, _recipient_dir) = runtime_storage(192);
        let recipient = PeerRuntime::start_with_storage(
            identity_for(&recipient_key),
            recipient_key,
            "v3-only-recipient".into(),
            recipient_storage,
        )
        .await
        .expect("start recipient");
        let peer = establish_test_session_with_capability(&sender, &recipient, None).await;

        for index in 0..200 {
            let envelope = send_ratchet_envelope(
                &sender,
                &recipient,
                "v3-only",
                &format!("legacy message {index}"),
            )
            .await;
            let payload: crate::MessageAddedPayload =
                serde_json::from_str(&envelope.events[0].data).expect("parse legacy payload");
            assert_eq!(payload.version, 3);
        }

        assert_eq!(
            sender
                .ctx
                .session_store
                .lock()
                .await
                .get(&peer)
                .expect("sender session")
                .peer_supports_v4,
            None
        );
        assert_eq!(
            sender
                .ctx
                .abuse_metrics
                .snapshot()
                .dh_ratchet_initiations_total,
            0
        );
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
    }

    #[tokio::test]
    async fn v3_to_v4_upgrade_on_new_session() {
        let sender_key = [193; 32];
        let recipient_key = [194; 32];
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "v3-v4-upgrade-sender".into(),
        )
        .await
        .expect("start sender");
        let (recipient_storage, _recipient_dir) = runtime_storage(194);
        let recipient = PeerRuntime::start_with_storage(
            identity_for(&recipient_key),
            recipient_key,
            "v3-v4-upgrade-recipient".into(),
            Arc::clone(&recipient_storage),
        )
        .await
        .expect("start recipient");
        let old_peer = establish_test_session_with_capability(&sender, &recipient, None).await;

        let old_envelope =
            send_ratchet_envelope(&sender, &recipient, "v3-v4-upgrade", "old chain zero").await;
        let old_payload: crate::MessageAddedPayload =
            serde_json::from_str(&old_envelope.events[0].data).expect("parse old V3 payload");
        assert_eq!(old_payload.version, 3);
        PeerRuntime::process_incoming_envelope(old_envelope, Arc::clone(&recipient.ctx)).await;
        assert!(recipient_storage
            .lock()
            .expect("recipient storage lock")
            .messages_json(&sender.public_key)
            .expect("read old V3 message")
            .contains("old chain zero"));

        sender
            .forget_session(&old_peer)
            .await
            .expect("forget old initiator session");
        let sender_peer = NodeId::from_hex(&sender.identity_id).expect("sender identity");
        recipient
            .forget_session(&sender_peer)
            .await
            .expect("forget old responder session");
        let new_peer =
            establish_test_session_with_capability(&sender, &recipient, Some(true)).await;
        assert_eq!(new_peer, old_peer);

        let new_envelope =
            send_ratchet_envelope(&sender, &recipient, "v3-v4-upgrade", "new V4 chain zero").await;
        let new_payload: crate::MessageAddedPayload =
            serde_json::from_str(&new_envelope.events[0].data).expect("parse new V4 payload");
        assert_eq!(new_payload.version, crate::journal::MESSAGE_VERSION_V4);
        assert_eq!(new_payload.chain_id, Some(0));
        PeerRuntime::process_incoming_envelope(new_envelope, Arc::clone(&recipient.ctx)).await;
        let stored_messages = recipient_storage
            .lock()
            .expect("recipient storage lock")
            .messages_json(&sender.public_key)
            .expect("read upgraded messages");
        assert!(stored_messages.contains("old chain zero"));
        assert!(stored_messages.contains("new V4 chain zero"));

        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
    }

    #[tokio::test]
    async fn restart_before_advertise_resumes_pending() {
        let seed = 195;
        let (sender, recipient, peer, sender_storage, sender_dir, _recipient_dir) =
            start_persistent_mutual_ratchet_pair(seed).await;
        {
            let mut store = sender.ctx.session_store.lock().await;
            let session = store.get_mut(&peer).expect("sender session");
            session.messages_since_ratchet = 17;
            session.dh_ratchet_initiate().expect("initiate DH ratchet");
        }
        persist_session_required(&sender.ctx, &peer)
            .await
            .expect("persist pending initiation before send");
        sender.stop().await.expect("stop sender before restart");

        let restarted = PeerRuntime::start_with_storage(
            identity_for(&[seed; 32]),
            [seed; 32],
            "v4-restart-before-advertise".into(),
            Arc::clone(&sender_storage),
        )
        .await
        .expect("restart sender");
        load_session_on_demand(&restarted.ctx, &peer)
            .await
            .expect("load restarted session")
            .expect("restored session");
        {
            let store = restarted.ctx.session_store.lock().await;
            let session = store.get(&peer).expect("restored session");
            assert_eq!(session.prev_chain_length, Some(17));
            assert!(session.has_pending_dh_ratchet());
        }
        let envelope = send_ratchet_envelope(
            &restarted,
            &recipient,
            "restart-before-advertise",
            "resumed advertisement",
        )
        .await;
        let payload: crate::MessageAddedPayload =
            serde_json::from_str(&envelope.events[0].data).expect("parse resumed payload");
        assert_eq!(payload.version, crate::journal::MESSAGE_VERSION_V4);
        assert!(payload.dh_pubkey.is_some());
        assert_eq!(payload.prev_chain_length, Some(17));

        restarted.stop().await.expect("stop restarted sender");
        recipient.stop().await.expect("stop recipient");
        drop((sender_storage, sender_dir));
    }

    #[tokio::test]
    async fn restart_after_advertise_no_duplicate_advertise() {
        let seed = 197;
        let (sender, recipient, peer, sender_storage, sender_dir, _recipient_dir) =
            start_persistent_mutual_ratchet_pair(seed).await;
        sender
            .ctx
            .session_store
            .lock()
            .await
            .get_mut(&peer)
            .expect("sender session")
            .messages_since_ratchet = 17;
        sender
            .ctx
            .session_store
            .lock()
            .await
            .get_mut(&peer)
            .expect("sender session")
            .dh_ratchet_initiate()
            .expect("initiate DH ratchet");
        persist_session_required(&sender.ctx, &peer)
            .await
            .expect("persist initiation");
        let first = send_ratchet_envelope(
            &sender,
            &recipient,
            "restart-after-advertise",
            "first advertisement",
        )
        .await;
        let first_payload: crate::MessageAddedPayload =
            serde_json::from_str(&first.events[0].data).expect("parse first payload");
        assert!(first_payload.dh_pubkey.is_some());
        sender
            .stop()
            .await
            .expect("stop sender after advertisement");

        let restarted = PeerRuntime::start_with_storage(
            identity_for(&[seed; 32]),
            [seed; 32],
            "v4-restart-after-advertise".into(),
            Arc::clone(&sender_storage),
        )
        .await
        .expect("restart sender");
        load_session_on_demand(&restarted.ctx, &peer)
            .await
            .expect("load restarted session")
            .expect("restored session");
        {
            let store = restarted.ctx.session_store.lock().await;
            let session = store.get(&peer).expect("restored session");
            assert_eq!(session.prev_chain_length, None);
            assert!(session.has_pending_dh_ratchet());
        }
        let next = send_ratchet_envelope(
            &restarted,
            &recipient,
            "restart-after-advertise",
            "no duplicate advertisement",
        )
        .await;
        let next_payload: crate::MessageAddedPayload =
            serde_json::from_str(&next.events[0].data).expect("parse next payload");
        assert_eq!(next_payload.version, crate::journal::MESSAGE_VERSION_V4);
        assert_eq!(next_payload.chain_id, Some(1));
        assert_eq!(next_payload.dh_pubkey, None);

        restarted.stop().await.expect("stop restarted sender");
        recipient.stop().await.expect("stop recipient");
        drop((sender_storage, sender_dir));
    }

    #[tokio::test]
    async fn out_of_order_across_epochs() {
        let (sender, recipient, sender_peer, _storage_dir) =
            start_mutual_ratchet_pair_with_established_rate_peer(199).await;
        prime_test_dh_peers(&sender, &recipient).await;
        let sender_node = NodeId::from_hex(&sender.identity_id).expect("sender identity");
        let old_epoch = send_ratchet_envelope_batch(
            &sender,
            &recipient,
            "out-of-order-epochs",
            &[
                "epoch-zero-0",
                "epoch-zero-1",
                "epoch-zero-2",
                "epoch-zero-3",
                "epoch-zero-4",
                "epoch-zero-5",
                "epoch-zero-6",
                "epoch-zero-7",
                "epoch-zero-8",
                "epoch-zero-9",
            ],
        )
        .await;
        sender
            .ctx
            .session_store
            .lock()
            .await
            .get_mut(&sender_peer)
            .expect("sender session")
            .dh_ratchet_initiate()
            .expect("initiate epoch one");
        let new_epoch = send_ratchet_envelope_batch(
            &sender,
            &recipient,
            "out-of-order-epochs",
            &[
                "epoch-one-0",
                "epoch-one-1",
                "epoch-one-2",
                "epoch-one-3",
                "epoch-one-4",
                "epoch-one-5",
                "epoch-one-6",
                "epoch-one-7",
                "epoch-one-8",
                "epoch-one-9",
            ],
        )
        .await;

        let transition: crate::MessageAddedPayload =
            serde_json::from_str(&new_epoch.events[0].data).expect("parse epoch-one transition");
        assert_eq!(transition.chain_id, Some(1));
        assert!(transition.dh_pubkey.is_some());
        PeerRuntime::process_incoming_envelope(
            SyncEnvelope::new(
                sender.identity_id.clone(),
                sender.public_key.clone(),
                vec![new_epoch.events[0].clone()],
            ),
            Arc::clone(&recipient.ctx),
        )
        .await;
        for index in (1..10).rev() {
            PeerRuntime::process_incoming_envelope(
                SyncEnvelope::new(
                    sender.identity_id.clone(),
                    sender.public_key.clone(),
                    vec![new_epoch.events[index].clone()],
                ),
                Arc::clone(&recipient.ctx),
            )
            .await;
        }
        tokio::time::sleep(std::time::Duration::from_secs(31)).await;
        for index in (0..10).rev() {
            PeerRuntime::process_incoming_envelope(
                SyncEnvelope::new(
                    sender.identity_id.clone(),
                    sender.public_key.clone(),
                    vec![old_epoch.events[index].clone()],
                ),
                Arc::clone(&recipient.ctx),
            )
            .await;
        }

        let storage = recipient.ctx.storage.as_ref().expect("recipient storage");
        let stored = storage
            .lock()
            .expect("recipient storage lock")
            .messages_json(&sender.public_key)
            .expect("read delivered messages");
        for epoch in ["epoch-zero", "epoch-one"] {
            for counter in 0..10 {
                assert!(
                    stored.contains(&format!("{epoch}-{counter}")),
                    "missing {epoch}-{counter}"
                );
            }
        }
        assert_eq!(
            recipient
                .ctx
                .session_store
                .lock()
                .await
                .get(&sender_node)
                .expect("recipient session")
                .chain_epoch,
            1
        );
        assert_eq!(
            recipient.ctx.abuse_metrics.snapshot().ratchet_decrypt_total,
            20
        );

        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
    }

    #[tokio::test]
    async fn compromise_recovery_forward_secrecy() {
        // Empirical check for forward secrecy, not a formal proof.
        //
        // This test demonstrates that a session copy holding only the
        // compromised root_key(N) and pre-initiate DH material cannot
        // derive root_key(N+1) via dh_ratchet_step — the resulting root
        // differs from the true post-transition root. A formal reduction
        // to X25519 / HKDF security is out of scope for e2e tests.
        //
        // What this test does NOT cover:
        //  - Attacker with additional side-channel material (e.g., one of
        //    the DH private keys from a future epoch).
        //  - Cryptographic weaknesses in HKDF-SHA256 or X25519.
        // Both are covered by crypto-primitive tests, not this layer.
        let (a, b, b_node, _storage_dir) = start_mutual_ratchet_pair(201).await;
        prime_test_dh_peers(&a, &b).await;
        let a_node = NodeId::from_hex(&a.identity_id).expect("A identity");
        let (root_n, compromised_a_private, old_b_public) = {
            let store = a.ctx.session_store.lock().await;
            let session = store.get(&b_node).expect("A session");
            (
                session.root_key,
                session.dh_our_privkey,
                session.dh_peer_pubkey.expect("old B DH public key"),
            )
        };

        let a_new_public = a
            .ctx
            .session_store
            .lock()
            .await
            .get_mut(&b_node)
            .expect("A session")
            .dh_ratchet_initiate()
            .expect("A initiates new DH key");
        let b_new_public = {
            let mut store = b.ctx.session_store.lock().await;
            let session = store.get_mut(&a_node).expect("B session");
            session
                .dh_ratchet_step(a_new_public)
                .expect("B applies new A DH key");
            session.dh_our_pubkey
        };
        {
            let mut store = a.ctx.session_store.lock().await;
            store
                .get_mut(&b_node)
                .expect("A session")
                .dh_ratchet_complete(b_new_public)
                .expect("A completes DH cycle");
        }
        let actual_root_n_plus_1 = a
            .ctx
            .session_store
            .lock()
            .await
            .get(&b_node)
            .expect("A session")
            .root_key;
        assert_ne!(actual_root_n_plus_1, root_n);
        assert_eq!(
            actual_root_n_plus_1,
            b.ctx
                .session_store
                .lock()
                .await
                .get(&a_node)
                .expect("B session")
                .root_key
        );

        let mut attacker_copy = crate::session_store::SessionStore::new();
        attacker_copy
            .insert_with_chains(b_node, root_n, &a_node, unix_now())
            .expect("create attacker copy with compromised root");
        {
            let mut store = attacker_copy;
            let attacker_session = store.get_mut(&b_node).expect("attacker copy");
            attacker_session.root_key = root_n;
            attacker_session.dh_our_privkey = compromised_a_private;
            attacker_session.dh_our_pubkey = x25519_dalek::PublicKey::from(
                &x25519_dalek::StaticSecret::from(compromised_a_private),
            )
            .to_bytes();
            attacker_session.dh_peer_pubkey = Some(old_b_public);
            attacker_session
                .dh_ratchet_step(b_new_public)
                .expect("attempt DH step with only compromised old material");
            assert_ne!(attacker_session.root_key, actual_root_n_plus_1);
        }

        a.stop().await.expect("stop A");
        b.stop().await.expect("stop B");
    }

    #[tokio::test]
    async fn collision_reordered_dh_advertise_after_response_is_dropped() {
        let (a, b, b_node, _storage_dir) = start_mutual_ratchet_pair(207).await;
        prime_test_dh_peers(&a, &b).await;
        let a_node = NodeId::from_hex(&a.identity_id).expect("A identity");
        for runtime_peer in [(&a, b_node), (&b, a_node)] {
            runtime_peer
                .0
                .ctx
                .session_store
                .lock()
                .await
                .get_mut(&runtime_peer.1)
                .expect("session")
                .messages_since_ratchet = 50;
        }

        let a_init = send_ratchet_envelope(&a, &b, "collision-reordered", "A initiate").await;
        let b_init = send_ratchet_envelope(&b, &a, "collision-reordered", "B initiate").await;
        let a_payload: crate::MessageAddedPayload =
            serde_json::from_str(&a_init.events[0].data).expect("parse A init");
        let b_payload: crate::MessageAddedPayload =
            serde_json::from_str(&b_init.events[0].data).expect("parse B init");
        let a_dh = a_payload.dh_pubkey.expect("A advertise");
        let b_dh = b_payload.dh_pubkey.expect("B advertise");
        let (smaller, larger, smaller_peer, larger_peer, smaller_init, larger_init) = if a_dh < b_dh
        {
            (&a, &b, b_node, a_node, a_init, b_init)
        } else {
            (&b, &a, a_node, b_node, b_init, a_init)
        };

        PeerRuntime::process_incoming_envelope(smaller_init, Arc::clone(&larger.ctx)).await;
        let response =
            send_ratchet_envelope(larger, smaller, "collision-reordered", "B response").await;
        let response_payload: crate::MessageAddedPayload =
            serde_json::from_str(&response.events[0].data).expect("parse collision response");
        assert_eq!(response_payload.dh_pubkey, Some(b_dh.max(a_dh)));
        assert_eq!(response_payload.chain_id, Some(1));

        PeerRuntime::process_incoming_envelope(response, Arc::clone(&smaller.ctx)).await;
        let state_before_late_advertise = {
            let store = smaller.ctx.session_store.lock().await;
            let session = store.get(&smaller_peer).expect("smaller session");
            let (sending_key, sending_index) = session.sending_chain.serialize();
            let (receiving_key, receiving_index) = session.receiving_chain.serialize();
            (
                session.root_key,
                session.chain_epoch,
                (*sending_key, sending_index),
                (*receiving_key, receiving_index),
            )
        };
        let metrics_before_late_advertise = smaller.ctx.abuse_metrics.snapshot();

        PeerRuntime::process_incoming_envelope(larger_init, Arc::clone(&smaller.ctx)).await;

        let state_after_late_advertise = {
            let store = smaller.ctx.session_store.lock().await;
            let session = store.get(&smaller_peer).expect("smaller session");
            let (sending_key, sending_index) = session.sending_chain.serialize();
            let (receiving_key, receiving_index) = session.receiving_chain.serialize();
            (
                session.root_key,
                session.chain_epoch,
                (*sending_key, sending_index),
                (*receiving_key, receiving_index),
            )
        };
        let metrics_after_late_advertise = smaller.ctx.abuse_metrics.snapshot();
        assert_eq!(
            metrics_after_late_advertise.v4_duplicate_advertise_total,
            metrics_before_late_advertise.v4_duplicate_advertise_total + 1
        );
        assert_eq!(
            metrics_after_late_advertise.ratchet_decrypt_total,
            metrics_before_late_advertise.ratchet_decrypt_total,
            "the late duplicate advertise must be dropped"
        );
        assert_eq!(
            state_after_late_advertise, state_before_late_advertise,
            "the late duplicate advertise must not mutate the session"
        );

        let larger_follow_up =
            send_ratchet_envelope(larger, smaller, "collision-reordered", "larger follow-up").await;
        PeerRuntime::process_incoming_envelope(larger_follow_up, Arc::clone(&smaller.ctx)).await;
        let smaller_follow_up =
            send_ratchet_envelope(smaller, larger, "collision-reordered", "smaller follow-up")
                .await;
        PeerRuntime::process_incoming_envelope(smaller_follow_up, Arc::clone(&larger.ctx)).await;

        let larger_state = {
            let store = larger.ctx.session_store.lock().await;
            let session = store.get(&larger_peer).expect("larger session");
            (
                session.chain_epoch,
                session.sending_chain.serialize(),
                session.receiving_chain.serialize(),
            )
        };
        let smaller_state = {
            let store = smaller.ctx.session_store.lock().await;
            let session = store.get(&smaller_peer).expect("smaller session");
            (
                session.chain_epoch,
                session.sending_chain.serialize(),
                session.receiving_chain.serialize(),
            )
        };
        assert_eq!(larger_state.0, smaller_state.0);
        assert_eq!(larger_state.1, smaller_state.2);
        assert_eq!(larger_state.2, smaller_state.1);

        a.stop().await.expect("stop A");
        b.stop().await.expect("stop B");
    }

    #[tokio::test]
    async fn compromise_recovery_post_compromise_healing() {
        let (a, b, b_node, _storage_dir) = start_mutual_ratchet_pair(203).await;
        prime_test_dh_peers(&a, &b).await;
        let a_node = NodeId::from_hex(&a.identity_id).expect("A identity");
        let (root_n, compromised_a_private) = {
            let store = a.ctx.session_store.lock().await;
            let session = store.get(&b_node).expect("A session");
            (session.root_key, session.dh_our_privkey)
        };
        let a_new_public = a
            .ctx
            .session_store
            .lock()
            .await
            .get_mut(&b_node)
            .expect("A session")
            .dh_ratchet_initiate()
            .expect("A initiates fresh DH key");
        let b_new_public = {
            let mut store = b.ctx.session_store.lock().await;
            let session = store.get_mut(&a_node).expect("B session");
            session
                .dh_ratchet_step(a_new_public)
                .expect("B applies fresh A DH key");
            session.dh_our_pubkey
        };
        a.ctx
            .session_store
            .lock()
            .await
            .get_mut(&b_node)
            .expect("A session")
            .dh_ratchet_complete(b_new_public)
            .expect("A completes DH cycle");
        let (new_a_private, new_a_public) = {
            let store = a.ctx.session_store.lock().await;
            let session = store.get(&b_node).expect("A session");
            (session.dh_our_privkey, session.dh_our_pubkey)
        };
        assert_ne!(new_a_private, compromised_a_private);
        assert_eq!(new_a_public, a_new_public);

        let mut attacker_copy = crate::session_store::SessionStore::new();
        attacker_copy
            .insert_with_chains(b_node, root_n, &a_node, unix_now())
            .expect("create compromised attacker session");
        {
            let attacker = attacker_copy.get_mut(&b_node).expect("attacker session");
            attacker.root_key = root_n;
            attacker.dh_our_privkey = compromised_a_private;
            attacker.dh_our_pubkey = x25519_dalek::PublicKey::from(
                &x25519_dalek::StaticSecret::from(compromised_a_private),
            )
            .to_bytes();
            attacker
                .dh_ratchet_step(a_new_public)
                .expect("derive attacker-only candidate chain");
        }
        let (attacker_key, _) = attacker_copy
            .peek_sending(&b_node)
            .expect("attacker candidate message key");
        let envelope =
            send_ratchet_envelope(&a, &b, "compromise-healing", "post-compromise secret").await;
        let event = &envelope.events[0];
        let payload: crate::MessageAddedPayload =
            serde_json::from_str(&event.data).expect("parse post-compromise payload");
        assert_eq!(payload.version, crate::journal::MESSAGE_VERSION_V4);
        let encrypted = hal_crypto::EncryptedMessage {
            nonce: base64::engine::general_purpose::STANDARD
                .decode(payload.ratchet_nonce.as_deref().expect("ratchet nonce"))
                .expect("decode nonce"),
            ciphertext: base64::engine::general_purpose::STANDARD
                .decode(payload.ciphertext.as_deref().expect("ciphertext"))
                .expect("decode ciphertext"),
        };
        let counter = payload.ratchet_counter().expect("ratchet counter");
        let mut aad = b"hal-msg-v3:".to_vec();
        aad.extend_from_slice(payload.chat_id.as_bytes());
        aad.extend_from_slice(payload.sender_id.as_bytes());
        aad.extend_from_slice(
            payload
                .recipient_id
                .as_deref()
                .expect("recipient")
                .as_bytes(),
        );
        aad.extend_from_slice(&counter.to_be_bytes());
        aad.extend_from_slice(event.id.as_bytes());
        let attacker_decrypt = hal_crypto::XChaCha20Poly1305Cipher::decrypt(
            &attacker_key.key[..],
            &encrypted,
            Some(&aad),
        );
        assert!(
            attacker_decrypt.is_err(),
            "pre-compromise DH private key and root must not decrypt the healed V4 message"
        );

        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&b.ctx)).await;
        let stored = b
            .ctx
            .storage
            .as_ref()
            .expect("B storage")
            .lock()
            .expect("B storage lock")
            .messages_json(&a.public_key)
            .expect("read decrypted message");
        assert!(stored.contains("post-compromise secret"));
        a.stop().await.expect("stop A");
        b.stop().await.expect("stop B");
    }

    #[tokio::test]
    async fn collision_recovery_full_convergence() {
        let (a, b, b_node, _storage_dir) = start_mutual_ratchet_pair(205).await;
        prime_test_dh_peers(&a, &b).await;
        let a_node = NodeId::from_hex(&a.identity_id).expect("A identity");
        for runtime_peer in [(&a, b_node), (&b, a_node)] {
            runtime_peer
                .0
                .ctx
                .session_store
                .lock()
                .await
                .get_mut(&runtime_peer.1)
                .expect("session")
                .messages_since_ratchet = 50;
        }
        let a_message =
            send_ratchet_envelope(&a, &b, "collision-recovery", "A simultaneous init").await;
        let b_message =
            send_ratchet_envelope(&b, &a, "collision-recovery", "B simultaneous init").await;
        let a_payload: crate::MessageAddedPayload =
            serde_json::from_str(&a_message.events[0].data).expect("parse A init");
        let b_payload: crate::MessageAddedPayload =
            serde_json::from_str(&b_message.events[0].data).expect("parse B init");
        assert!(a_payload.dh_pubkey.is_some());
        assert!(b_payload.dh_pubkey.is_some());

        PeerRuntime::process_incoming_envelope(a_message, Arc::clone(&b.ctx)).await;
        PeerRuntime::process_incoming_envelope(b_message, Arc::clone(&a.ctx)).await;
        let a_epoch_after_first_exchange = a
            .ctx
            .session_store
            .lock()
            .await
            .get(&b_node)
            .expect("A collision session")
            .chain_epoch;
        let b_epoch_after_first_exchange = b
            .ctx
            .session_store
            .lock()
            .await
            .get(&a_node)
            .expect("B collision session")
            .chain_epoch;
        if a_epoch_after_first_exchange > b_epoch_after_first_exchange {
            let response =
                send_ratchet_envelope(&a, &b, "collision-recovery", "collision response").await;
            let response_payload: crate::MessageAddedPayload =
                serde_json::from_str(&response.events[0].data).expect("parse collision response");
            assert!(response_payload.dh_pubkey.is_some());
            assert_eq!(response_payload.chain_id, Some(1));
            assert!(response_payload.prev_chain_length.is_some());
            PeerRuntime::process_incoming_envelope(response, Arc::clone(&b.ctx)).await;
        } else {
            assert!(
                b_epoch_after_first_exchange > a_epoch_after_first_exchange,
                "simultaneous initiation must choose one collision responder"
            );
            let response =
                send_ratchet_envelope(&b, &a, "collision-recovery", "collision response").await;
            let response_payload: crate::MessageAddedPayload =
                serde_json::from_str(&response.events[0].data).expect("parse collision response");
            assert!(response_payload.dh_pubkey.is_some());
            assert_eq!(response_payload.chain_id, Some(1));
            assert!(response_payload.prev_chain_length.is_some());
            PeerRuntime::process_incoming_envelope(response, Arc::clone(&a.ctx)).await;
        }
        let (a_root, a_epoch, a_sending, a_receiving) = {
            let store = a.ctx.session_store.lock().await;
            let session = store.get(&b_node).expect("A collision session");
            let (sending_key, sending_index) = session.sending_chain.serialize();
            let (receiving_key, receiving_index) = session.receiving_chain.serialize();
            (
                session.root_key,
                session.chain_epoch,
                (*sending_key, sending_index),
                (*receiving_key, receiving_index),
            )
        };
        let (b_root, b_epoch, b_sending, b_receiving) = {
            let store = b.ctx.session_store.lock().await;
            let session = store.get(&a_node).expect("B collision session");
            let (sending_key, sending_index) = session.sending_chain.serialize();
            let (receiving_key, receiving_index) = session.receiving_chain.serialize();
            (
                session.root_key,
                session.chain_epoch,
                (*sending_key, sending_index),
                (*receiving_key, receiving_index),
            )
        };
        assert!(a_root == b_root, "collision root keys diverged");
        assert_eq!(a_epoch, b_epoch, "collision epochs diverged");
        assert!(
            a_sending == b_receiving,
            "collision sending/receiving chain mismatch"
        );
        assert!(
            a_receiving == b_sending,
            "collision receiving/sending chain mismatch"
        );
        let larger_collisions = a
            .ctx
            .abuse_metrics
            .dh_ratchet_collisions_case3_larger_total
            .load(Ordering::Relaxed)
            + b.ctx
                .abuse_metrics
                .dh_ratchet_collisions_case3_larger_total
                .load(Ordering::Relaxed);
        let smaller_collisions = a
            .ctx
            .abuse_metrics
            .dh_ratchet_collisions_case3_smaller_total
            .load(Ordering::Relaxed)
            + b.ctx
                .abuse_metrics
                .dh_ratchet_collisions_case3_smaller_total
                .load(Ordering::Relaxed);
        assert_eq!(larger_collisions, 1);
        assert_eq!(smaller_collisions, 1);

        let next_a = send_ratchet_envelope(&a, &b, "collision-recovery", "converged A").await;
        PeerRuntime::process_incoming_envelope(next_a, Arc::clone(&b.ctx)).await;
        let next_b = send_ratchet_envelope(&b, &a, "collision-recovery", "converged B").await;
        PeerRuntime::process_incoming_envelope(next_b, Arc::clone(&a.ctx)).await;
        let a_chains = {
            let store = a.ctx.session_store.lock().await;
            let session = store.get(&b_node).expect("A converged session");
            (
                session.chain_epoch,
                session.sending_chain.serialize(),
                session.receiving_chain.serialize(),
            )
        };
        let b_chains = {
            let store = b.ctx.session_store.lock().await;
            let session = store.get(&a_node).expect("B converged session");
            (
                session.chain_epoch,
                session.sending_chain.serialize(),
                session.receiving_chain.serialize(),
            )
        };
        assert_eq!(
            a_chains.0, b_chains.0,
            "epochs diverged after follow-up messages"
        );
        assert!(
            a_chains.1 == b_chains.2,
            "A follow-up V4 message was not received by B"
        );
        assert!(
            a_chains.2 == b_chains.1,
            "B follow-up V4 message was not received by A"
        );
        a.stop().await.expect("stop A");
        b.stop().await.expect("stop B");
    }

    #[tokio::test]
    async fn v4_received_on_current_chain() {
        let (sender, recipient, _, _storage_dir) = start_mutual_ratchet_pair(167).await;
        let peer = NodeId::from_hex(&sender.identity_id).expect("sender id");
        let envelope =
            send_ratchet_envelope(&sender, &recipient, "v4-current", "current chain").await;
        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&recipient.ctx)).await;
        assert_eq!(
            recipient
                .ctx
                .session_store
                .lock()
                .await
                .get_view(&peer)
                .expect("recipient session")
                .recv_counter,
            1
        );
        assert_eq!(
            recipient
                .ctx
                .abuse_metrics
                .snapshot()
                .v4_messages_received_total,
            1
        );
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
    }

    #[tokio::test]
    async fn v4_received_triggers_responder_step() {
        let (sender, recipient, sender_peer, _storage_dir) = start_mutual_ratchet_pair(169).await;
        let sender_node = NodeId::from_hex(&sender.identity_id).expect("sender id");
        prime_test_dh_peers(&sender, &recipient).await;
        sender
            .ctx
            .session_store
            .lock()
            .await
            .get_mut(&sender_peer)
            .expect("sender session")
            .messages_since_ratchet = 50;
        let envelope = send_ratchet_envelope(&sender, &recipient, "v4-step", "ratchet step").await;
        let payload: crate::MessageAddedPayload =
            serde_json::from_str(&envelope.events[0].data).expect("parse payload");
        let advertised = payload.dh_pubkey.expect("sender advertise");
        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&recipient.ctx)).await;
        let store = recipient.ctx.session_store.lock().await;
        let recipient_session = store.get(&sender_node).expect("recipient session");
        assert_eq!(recipient_session.chain_epoch, 1);
        assert_eq!(recipient_session.dh_peer_pubkey, Some(advertised));
        drop(store);
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
    }

    #[tokio::test]
    async fn v4_future_chain_rejected() {
        let (sender, recipient, _, _storage_dir) = start_mutual_ratchet_pair(173).await;
        let peer = NodeId::from_hex(&sender.identity_id).expect("sender id");
        let envelope =
            send_ratchet_envelope(&sender, &recipient, "v4-future", "future chain").await;
        let mut payload: crate::MessageAddedPayload =
            serde_json::from_str(&envelope.events[0].data).expect("parse payload");
        payload.chain_id = Some(100);
        let event_id = envelope.events[0].id.clone();
        let mut event = SyncEvent::new(
            event_id,
            SyncEventType::MessageAdded,
            serde_json::to_string(&payload).expect("serialize payload"),
        );
        event
            .sign(&sender.private_key.to_bytes())
            .expect("sign event");
        let future = SyncEnvelope::new(
            sender.identity_id.clone(),
            sender.public_key.clone(),
            vec![event],
        );
        PeerRuntime::process_incoming_envelope(future, Arc::clone(&recipient.ctx)).await;
        assert_eq!(
            recipient
                .ctx
                .session_store
                .lock()
                .await
                .get_view(&peer)
                .expect("recipient session")
                .recv_counter,
            0
        );
        assert_eq!(
            recipient
                .ctx
                .abuse_metrics
                .snapshot()
                .v4_future_chain_rejected_total,
            1
        );
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
    }

    #[tokio::test]
    async fn v4_skipped_keys_pruned_by_prev_chain_length() {
        let (sender, recipient, sender_peer, _storage_dir) = start_mutual_ratchet_pair(175).await;
        let sender_node = NodeId::from_hex(&sender.identity_id).expect("sender id");
        let batch = send_ratchet_envelope_batch(
            &sender,
            &recipient,
            "v4-prune",
            &["old-zero", "old-one", "old-two"],
        )
        .await;
        for index in [0usize, 2] {
            PeerRuntime::process_incoming_envelope(
                SyncEnvelope::new(
                    sender.identity_id.clone(),
                    sender.public_key.clone(),
                    vec![batch.events[index].clone()],
                ),
                Arc::clone(&recipient.ctx),
            )
            .await;
        }
        assert_eq!(
            recipient
                .ctx
                .session_store
                .lock()
                .await
                .get_view(&sender_node)
                .expect("recipient session")
                .skipped_keys_count,
            1
        );
        sender
            .ctx
            .session_store
            .lock()
            .await
            .get_mut(&sender_peer)
            .expect("sender session")
            .messages_since_ratchet = 1;
        prime_test_dh_peers(&sender, &recipient).await;
        sender
            .ctx
            .session_store
            .lock()
            .await
            .get_mut(&sender_peer)
            .expect("sender session")
            .dh_ratchet_initiate()
            .expect("initiate V4 transition");
        let transition = send_ratchet_envelope(&sender, &recipient, "v4-prune", "transition").await;
        let transition_payload: crate::MessageAddedPayload =
            serde_json::from_str(&transition.events[0].data).expect("parse transition");
        assert_eq!(transition_payload.prev_chain_length, Some(1));
        PeerRuntime::process_incoming_envelope(transition, Arc::clone(&recipient.ctx)).await;
        assert_eq!(
            recipient
                .ctx
                .session_store
                .lock()
                .await
                .get(&sender_node)
                .expect("recipient session")
                .chain_epoch,
            1
        );
        assert_eq!(
            recipient
                .ctx
                .session_store
                .lock()
                .await
                .get_view(&sender_node)
                .expect("recipient session")
                .skipped_keys_count,
            0
        );
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
    }

    #[tokio::test]
    async fn peer_supports_v4_and_prev_chain_length_survive_save_load() {
        let (storage, _dir) = runtime_storage(177);
        let local_key = SigningKey::from_bytes(&[177; 32]);
        let local = NodeId::from_public_key(&local_key.verifying_key());
        let peer = NodeId::from_bytes([178; 32]);
        let ctx = x3dh_test_context(&local_key, Some(Arc::clone(&storage)));
        ctx.session_store
            .lock()
            .await
            .insert_with_chains(peer, [179; 32], &local, 1)
            .expect("insert session");
        {
            let mut store = ctx.session_store.lock().await;
            let session = store.get_mut(&peer).expect("session");
            session.peer_supports_v4 = Some(true);
            session.prev_chain_length = Some(24);
        }
        persist_session_required(&ctx, &peer)
            .await
            .expect("persist session");
        drop(ctx);
        let restored = x3dh_test_context(&local_key, Some(storage));
        load_session_on_demand(&restored, &peer)
            .await
            .expect("load session")
            .expect("restored session");
        let store = restored.session_store.lock().await;
        let session = store.get(&peer).expect("restored session");
        assert_eq!(session.peer_supports_v4, Some(true));
        assert_eq!(session.prev_chain_length, Some(24));
    }

    #[tokio::test]
    async fn migration_idempotent_on_existing_db() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("migration.sqlite3");
        for _ in 0..3 {
            drop(ClientStorage::open(&path, &[181; 32]).expect("open migrated database"));
        }
    }

    async fn insert_runtime_test_session(ctx: &RuntimeContext, peer: NodeId, key: u8) {
        let local = NodeId::from_public_key(
            &ctx.identity_signing_key
                .as_ref()
                .expect("test identity signing key")
                .verifying_key(),
        );
        ctx.session_store
            .lock()
            .await
            .insert_with_chains(peer, [key; 32], &local, 1)
            .expect("insert test session");
    }

    fn runtime_storage(seed: u8) -> (Arc<StdMutex<ClientStorage>>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("create session storage directory");
        let path = dir.path().join("sessions.sqlite3");
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[seed; 32]).expect("open session storage"),
        ));
        (storage, dir)
    }

    #[tokio::test]
    async fn runtime_restores_invite_peer_address_after_restart() {
        let local_key = SigningKey::from_bytes(&[33; 32]);
        let peer_key = SigningKey::from_bytes(&[34; 32]);
        let peer_identity = identity_for(&peer_key.to_bytes());
        let peer_public_key = hex::encode(peer_key.verifying_key().to_bytes());
        let address = "192.168.0.234:4001".to_string();
        let (storage, _dir) = runtime_storage(33);

        let runtime = PeerRuntime::start_with_storage(
            identity_for(&local_key.to_bytes()),
            local_key.to_bytes(),
            "invite-address-first".into(),
            Arc::clone(&storage),
        )
        .await
        .expect("start initial runtime");
        runtime
            .record_invite_peer(address.clone(), &peer_identity, &peer_public_key)
            .await
            .expect("persist Invite peer address");
        runtime.stop().await.expect("stop initial runtime");

        let restarted = PeerRuntime::start_with_storage(
            identity_for(&local_key.to_bytes()),
            local_key.to_bytes(),
            "invite-address-restarted".into(),
            storage,
        )
        .await
        .expect("start restarted runtime");

        assert_eq!(
            restarted.peer_addresses_of(&peer_identity).await,
            vec![address]
        );
        restarted.stop().await.expect("stop restarted runtime");
    }

    #[tokio::test]
    async fn runtime_persists_session_on_first_message() {
        let key = SigningKey::from_bytes(&[31; 32]);
        let (storage, _dir) = runtime_storage(31);
        let recipient_key = SigningKey::from_bytes(&[32; 32]);
        let recipient_id = identity_for(&recipient_key.to_bytes());
        let peer = NodeId::from_public_key(&recipient_key.verifying_key());
        let first = PeerRuntime::start_with_storage(
            identity_for(&key.to_bytes()),
            key.to_bytes(),
            "session-persist-first".into(),
            Arc::clone(&storage),
        )
        .await
        .expect("start initial runtime");
        insert_runtime_test_session(&first.ctx, peer, 9).await;
        first
            .add_message_encrypted(
                "session-persist-chat".into(),
                first.identity_id.clone(),
                recipient_id.clone(),
                &recipient_key.verifying_key(),
                "persist this send".into(),
            )
            .await
            .expect("send encrypted message");
        first.stop().await.expect("stop initial runtime");

        let restarted = PeerRuntime::start_with_storage(
            identity_for(&key.to_bytes()),
            key.to_bytes(),
            "session-persist-restarted".into(),
            storage,
        )
        .await
        .expect("start restarted runtime");
        let restored = restarted
            .get_session(&peer)
            .await
            .expect("restored session");
        assert_eq!(restored.send_counter, 1);
        restarted.stop().await.expect("stop restarted runtime");
    }

    #[tokio::test]
    async fn runtime_persists_skipped_keys_on_commit() {
        let key = SigningKey::from_bytes(&[33; 32]);
        let (storage, _dir) = runtime_storage(33);
        let peer = NodeId::from_bytes([34; 32]);
        let first = x3dh_test_context(&key, Some(Arc::clone(&storage)));
        insert_runtime_test_session(&first, peer, 10).await;
        persist_session_nonfatal(&first, &peer, "test session creation").await;
        let generation = first
            .session_store
            .lock()
            .await
            .receive_lock(&peer)
            .expect("receive lock")
            .1;
        let preview = first
            .session_store
            .lock()
            .await
            .prepare_receive_with_skipped_at(&peer, 3, generation, 10)
            .expect("prepare out-of-order receive");
        first
            .session_store
            .lock()
            .await
            .commit_receive_preview(&peer, preview, 10)
            .expect("commit out-of-order receive");
        persist_session_nonfatal(&first, &peer, "test receive commit").await;
        drop(first);

        let restarted = x3dh_test_context(&key, Some(storage));
        load_session_on_demand(&restarted, &peer)
            .await
            .expect("lazy restore")
            .expect("restored session");
        let store = restarted.session_store.lock().await;
        assert_eq!(
            store
                .get_view(&peer)
                .expect("session view")
                .skipped_keys_count,
            3
        );
    }

    #[tokio::test]
    async fn runtime_abort_does_not_persist() {
        let key = SigningKey::from_bytes(&[35; 32]);
        let (storage, _dir) = runtime_storage(35);
        let peer = NodeId::from_bytes([36; 32]);
        let ctx = x3dh_test_context(&key, Some(Arc::clone(&storage)));
        insert_runtime_test_session(&ctx, peer, 11).await;
        persist_session_nonfatal(&ctx, &peer, "test session creation").await;
        let before = {
            let storage = storage.lock().expect("storage lock");
            let row = storage
                .load_session(&peer.to_hex())
                .expect("load persisted row")
                .expect("persisted session");
            (
                row.receiving_index,
                storage
                    .load_skipped_keys(&peer.to_hex())
                    .expect("load skipped")
                    .len(),
            )
        };
        let generation = ctx
            .session_store
            .lock()
            .await
            .receive_lock(&peer)
            .expect("receive lock")
            .1;
        let preview = ctx
            .session_store
            .lock()
            .await
            .prepare_receive_with_skipped_at(&peer, 3, generation, 10)
            .expect("prepare preview");
        ctx.session_store
            .lock()
            .await
            .abort_receive_preview(&peer, preview)
            .expect("abort preview");
        let after = {
            let storage = storage.lock().expect("storage lock");
            let row = storage
                .load_session(&peer.to_hex())
                .expect("load persisted row")
                .expect("persisted session");
            (
                row.receiving_index,
                storage
                    .load_skipped_keys(&peer.to_hex())
                    .expect("load skipped")
                    .len(),
            )
        };
        assert_eq!(after, before);
        drop(ctx);
        let restarted = x3dh_test_context(&key, Some(storage));
        let restored = load_session_on_demand(&restarted, &peer)
            .await
            .expect("restore after abort")
            .expect("persisted session after abort");
        assert_eq!(restored.recv_counter, before.0);
        assert_eq!(restored.skipped_keys_count, before.1);
    }

    #[tokio::test]
    async fn runtime_in_memory_mode_unchanged() {
        let key = SigningKey::from_bytes(&[37; 32]);
        let ctx = x3dh_test_context(&key, None);
        let peer = NodeId::from_bytes([38; 32]);
        assert!(load_session_on_demand(&ctx, &peer)
            .await
            .expect("initial lookup")
            .is_none());
        insert_runtime_test_session(&ctx, peer, 12).await;
        {
            let mut store = ctx.session_store.lock().await;
            store.commit_sending(&peer, 0, 3).expect("commit send");
        }
        persist_session_nonfatal(&ctx, &peer, "in-memory test").await;
        assert_eq!(
            ctx.session_store
                .lock()
                .await
                .get_view(&peer)
                .unwrap()
                .send_counter,
            1
        );
        assert_eq!(
            ctx.abuse_metrics
                .session_persist_failed_total
                .load(Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn runtime_persist_failure_does_not_break_send() {
        let key = SigningKey::from_bytes(&[39; 32]);
        let (storage, _dir) = runtime_storage(39);
        let ctx = x3dh_test_context(&key, Some(Arc::clone(&storage)));
        let peer = NodeId::from_bytes([40; 32]);
        insert_runtime_test_session(&ctx, peer, 13).await;
        let poison_storage = Arc::clone(&storage);
        // Deliberately poison the mutex to exercise the separate PoisonError path.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = poison_storage.lock().expect("unpoisoned storage");
            panic!("poison storage for persistence failure test");
        }));

        {
            let mut store = ctx.session_store.lock().await;
            store
                .commit_sending(&peer, 0, 4)
                .expect("send commit survives persistence failure");
        }
        persist_session_nonfatal(&ctx, &peer, "test send").await;
        assert_eq!(
            ctx.session_store
                .lock()
                .await
                .get_view(&peer)
                .unwrap()
                .send_counter,
            1
        );
        assert_eq!(
            ctx.abuse_metrics
                .session_persist_failed_total
                .load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn runtime_lazy_load_only_on_demand() {
        let key = SigningKey::from_bytes(&[41; 32]);
        let (storage, _dir) = runtime_storage(41);
        let local = NodeId::from_public_key(&key.verifying_key());
        let peers = [
            NodeId::from_bytes([42; 32]),
            NodeId::from_bytes([43; 32]),
            NodeId::from_bytes([44; 32]),
        ];
        {
            let mut store =
                crate::session_store::SessionStore::with_storage(Arc::clone(&storage), None);
            for (index, peer) in peers.iter().enumerate() {
                store
                    .insert_with_chains(*peer, [index as u8 + 1; 32], &local, 5)
                    .expect("insert storage session");
                let snapshot = store.persistence_snapshot(peer).expect("snapshot").unwrap();
                snapshot.persist(&storage).expect("persist session");
            }
        }
        let ctx = x3dh_test_context(&key, Some(storage));
        load_session_on_demand(&ctx, &peers[1])
            .await
            .expect("lazy load")
            .expect("requested session");
        assert_eq!(ctx.session_store.lock().await.len(), 1);
        assert!(ctx.session_store.lock().await.get_view(&peers[0]).is_none());
        assert!(ctx.session_store.lock().await.get_view(&peers[2]).is_none());
    }

    #[tokio::test]
    async fn runtime_forget_removes_from_both() {
        let key = SigningKey::from_bytes(&[45; 32]);
        let (storage, _dir) = runtime_storage(45);
        let peer = NodeId::from_bytes([46; 32]);
        let ctx = x3dh_test_context(&key, Some(Arc::clone(&storage)));
        insert_runtime_test_session(&ctx, peer, 14).await;
        persist_session_nonfatal(&ctx, &peer, "test session creation").await;
        forget_session(&ctx, &peer).await.expect("forget session");
        assert!(ctx.session_store.lock().await.get_view(&peer).is_none());
        assert!(storage
            .lock()
            .expect("storage lock")
            .load_session(&peer.to_hex())
            .expect("load deleted session")
            .is_none());
    }

    #[tokio::test]
    async fn runtime_lock_ordering_no_deadlock() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        use std::sync::Arc as StdArc;

        let key = SigningKey::from_bytes(&[47; 32]);
        let (storage, _dir) = runtime_storage(47);
        let ctx = x3dh_test_context(&key, Some(storage));
        let send_peer = NodeId::from_bytes([48; 32]);
        let receive_peer = NodeId::from_bytes([49; 32]);
        insert_runtime_test_session(&ctx, send_peer, 15).await;
        insert_runtime_test_session(&ctx, receive_peer, 16).await;
        persist_session_nonfatal(&ctx, &send_peer, "test session creation").await;
        persist_session_nonfatal(&ctx, &receive_peer, "test session creation").await;

        // Progress counters: if a task hangs, they reveal at which iteration
        // it stopped. A real deadlock freezes at some iteration; slow-under-load
        // still progresses.
        let send_progress = StdArc::new(AtomicUsize::new(0));
        let receive_progress = StdArc::new(AtomicUsize::new(0));

        let send_ctx = Arc::clone(&ctx);
        let send_progress_task = StdArc::clone(&send_progress);
        let send_task = tokio::spawn(async move {
            for counter in 0..100 {
                {
                    let mut store = send_ctx.session_store.lock().await;
                    store
                        .commit_sending(&send_peer, counter, counter + 1)
                        .expect("send commit");
                }
                persist_session_nonfatal(&send_ctx, &send_peer, "stress send").await;
                send_progress_task.fetch_add(1, AtomicOrdering::Relaxed);
            }
        });

        let receive_ctx = Arc::clone(&ctx);
        let receive_progress_task = StdArc::clone(&receive_progress);
        let receive_task = tokio::spawn(async move {
            let (receive_lock, generation) = receive_ctx
                .session_store
                .lock()
                .await
                .receive_lock(&receive_peer)
                .expect("receive lock");
            for counter in 0..100 {
                let receive_guard = Arc::clone(&receive_lock).lock_owned().await;
                {
                    let mut store = receive_ctx.session_store.lock().await;
                    let preview = store
                        .prepare_receive_with_skipped_at(
                            &receive_peer,
                            counter,
                            generation,
                            counter + 1,
                        )
                        .expect("prepare receive");
                    store
                        .commit_receive_preview(&receive_peer, preview, counter + 1)
                        .expect("receive commit");
                }
                drop(receive_guard);
                persist_session_nonfatal(&receive_ctx, &receive_peer, "stress receive").await;
                receive_progress_task.fetch_add(1, AtomicOrdering::Relaxed);
            }
        });

        // Per-task timeout: a real deadlock freezes a task indefinitely.
        // 60s per task gives ~20x headroom over the isolated baseline (~2.8s
        // total for both tasks) while remaining a clear signal of an actual hang.
        let send_deadline = Duration::from_secs(60);
        let receive_deadline = Duration::from_secs(60);

        let send_result = tokio::time::timeout(send_deadline, send_task).await;
        let receive_result = tokio::time::timeout(receive_deadline, receive_task).await;

        let send_iter = send_progress.load(AtomicOrdering::Relaxed);
        let receive_iter = receive_progress.load(AtomicOrdering::Relaxed);

        match send_result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => panic!("send task panicked: {error:?}"),
            Err(_) => panic!(
                "send task did not complete within {send_deadline:?} \
                 (deadlock suspected; progress={send_iter}/100)"
            ),
        }
        match receive_result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => panic!("receive task panicked: {error:?}"),
            Err(_) => panic!(
                "receive task did not complete within {receive_deadline:?} \
                 (deadlock suspected; progress={receive_iter}/100)"
            ),
        }
    }

    async fn send_ratchet_envelope(
        sender: &PeerRuntime,
        recipient: &PeerRuntime,
        chat_id: &str,
        plaintext: &str,
    ) -> SyncEnvelope {
        let existing_event_ids = sender
            .pending_events()
            .await
            .into_iter()
            .map(|event| event.id)
            .collect::<std::collections::HashSet<_>>();
        sender
            .add_message_encrypted(
                chat_id.to_string(),
                sender.identity_id.clone(),
                recipient.identity_id.clone(),
                &recipient.private_key.verifying_key(),
                plaintext.to_string(),
            )
            .await
            .expect("queue encrypted ratchet message");
        let mut event = sender
            .pending_events()
            .await
            .into_iter()
            .rev()
            .find(|event| {
                event.event_type == SyncEventType::MessageAdded
                    && !existing_event_ids.contains(&event.id)
            })
            .expect("queued MessageAdded event");
        event
            .sign(&sender.private_key.to_bytes())
            .expect("sign MessageAdded event");
        SyncEnvelope::new(
            sender.identity_id.clone(),
            sender.public_key.clone(),
            vec![event],
        )
    }

    async fn send_ratchet_envelope_batch(
        sender: &PeerRuntime,
        recipient: &PeerRuntime,
        chat_id: &str,
        plaintexts: &[&str],
    ) -> SyncEnvelope {
        for plaintext in plaintexts {
            sender
                .add_message_encrypted(
                    chat_id.to_string(),
                    sender.identity_id.clone(),
                    recipient.identity_id.clone(),
                    &recipient.private_key.verifying_key(),
                    (*plaintext).to_string(),
                )
                .await
                .expect("queue batch ratchet message");
        }
        let mut events = sender
            .pending_events()
            .await
            .into_iter()
            .filter(|event| event.event_type == SyncEventType::MessageAdded)
            .collect::<Vec<_>>();
        let first_new = events.len().saturating_sub(plaintexts.len());
        events.drain(..first_new);
        for event in &mut events {
            event
                .sign(&sender.private_key.to_bytes())
                .expect("sign batch ratchet event");
        }
        SyncEnvelope::new(
            sender.identity_id.clone(),
            sender.public_key.clone(),
            events,
        )
    }

    #[tokio::test]
    async fn add_message_falls_back_to_ecies_without_session() {
        let sender_key = [41; 32];
        let recipient_key = [42; 32];
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "ratchet-no-session-sender".into(),
        )
        .await
        .expect("sender runtime");
        let recipient = PeerRuntime::start(
            identity_for(&recipient_key),
            recipient_key,
            "ratchet-no-session-recipient".into(),
        )
        .await
        .expect("recipient runtime");

        let envelope =
            send_ratchet_envelope(&sender, &recipient, "ratchet-fallback", "fallback").await;
        let payload: crate::MessageAddedPayload =
            serde_json::from_str(&envelope.events[0].data).expect("parse payload");
        assert_eq!(payload.version, 2);
        let metrics = sender.ctx.abuse_metrics.snapshot();
        assert_eq!(metrics.ecies_fallback_total, 1);
        assert_eq!(metrics.ratchet_encrypt_total, 0);

        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
    }

    #[tokio::test]
    async fn add_message_falls_back_when_session_pending() {
        let sender_key = [43; 32];
        let recipient_key = [44; 32];
        let (recipient_storage, recipient_path) = e2ee_test_storage(60);
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "ratchet-pending-sender".into(),
        )
        .await
        .expect("sender runtime");
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            "ratchet-pending-recipient".into(),
            Some(Arc::clone(&recipient_storage)),
            trusted_local_policy(),
        )
        .await
        .expect("recipient runtime");
        let now = unix_now();
        let peer = NodeId::from_hex(&recipient.identity_id).expect("recipient identity");
        let bundle = x3dh_test_bundle(&recipient.ctx, &recipient.private_key, now, true).await;
        sender
            .ctx
            .prekey_cache
            .lock()
            .await
            .insert(peer, bundle.clone(), bundle.expires_at, now)
            .expect("cache recipient bundle");
        sender
            .establish_session_as_initiator(peer, now)
            .await
            .expect("create pending session");
        assert!(
            !sender
                .get_session(&peer)
                .await
                .expect("pending session")
                .responded
        );

        let envelope =
            send_ratchet_envelope(&sender, &recipient, "ratchet-pending", "pending").await;
        let payload: crate::MessageAddedPayload =
            serde_json::from_str(&envelope.events[0].data).expect("parse payload");
        assert_eq!(payload.version, 2);
        assert_eq!(sender.ctx.abuse_metrics.snapshot().ecies_fallback_total, 1);

        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
        drop(recipient_storage);
        let _ = std::fs::remove_file(recipient_path);
    }

    #[tokio::test]
    async fn send_lock_released_after_success() {
        let sender_key = [45; 32];
        let recipient_key = [46; 32];
        let (recipient_storage, recipient_path) = e2ee_test_storage(61);
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "ratchet-confirmed-sender".into(),
        )
        .await
        .expect("sender runtime");
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            "ratchet-confirmed-recipient".into(),
            Some(Arc::clone(&recipient_storage)),
            trusted_local_policy(),
        )
        .await
        .expect("recipient runtime");
        establish_test_ratchet_session(&sender, &recipient).await;

        let envelope =
            send_ratchet_envelope(&sender, &recipient, "ratchet-confirmed", "ratchet").await;
        let payload: crate::MessageAddedPayload =
            serde_json::from_str(&envelope.events[0].data).expect("parse payload");
        assert!(matches!(payload.version, 3 | 4));
        assert_eq!(payload.ratchet_counter(), Some(0));
        assert_eq!(sender.ctx.abuse_metrics.snapshot().ratchet_encrypt_total, 1);
        let peer = NodeId::from_hex(&recipient.identity_id).expect("recipient identity");
        assert_eq!(
            sender
                .get_session(&peer)
                .await
                .expect("sender session")
                .send_counter,
            1
        );
        sender
            .add_message_encrypted(
                "ratchet-confirmed".into(),
                sender.identity_id.clone(),
                recipient.identity_id.clone(),
                &recipient.private_key.verifying_key(),
                "second ratchet message".into(),
            )
            .await
            .expect("send after successful commit");
        assert_eq!(
            sender
                .get_session(&peer)
                .await
                .expect("sender session after second send")
                .send_counter,
            2
        );

        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
        drop(recipient_storage);
        let _ = std::fs::remove_file(recipient_path);
    }

    #[tokio::test]
    async fn ratchet_send_does_not_advance_and_send_lock_releases_after_persist_failure() {
        let sender_key = [62; 32];
        let recipient_key = [63; 32];
        let (recipient_storage, recipient_path) = e2ee_test_storage(64);
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "ratchet-persist-failure-sender".into(),
        )
        .await
        .expect("sender runtime");
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            "ratchet-persist-failure-recipient".into(),
            Some(Arc::clone(&recipient_storage)),
            trusted_local_policy(),
        )
        .await
        .expect("recipient runtime");
        let peer = establish_test_ratchet_session(&sender, &recipient).await;
        sender.ctx.sync.lock().await.fail_next_message_persist();

        let send_result = sender
            .add_message_encrypted(
                "ratchet-persist-failure".into(),
                sender.identity_id.clone(),
                recipient.identity_id.clone(),
                &recipient.private_key.verifying_key(),
                "retry with same counter".into(),
            )
            .await;
        assert!(send_result.is_err());
        assert_eq!(
            sender
                .get_session(&peer)
                .await
                .expect("sender session")
                .send_counter,
            0
        );
        assert!(!sender
            .pending_events()
            .await
            .iter()
            .any(|event| event.event_type == SyncEventType::MessageAdded));
        assert_eq!(
            sender
                .ctx
                .abuse_metrics
                .snapshot()
                .ratchet_encrypt_failed_total,
            1
        );

        sender
            .add_message_encrypted(
                "ratchet-persist-failure".into(),
                sender.identity_id.clone(),
                recipient.identity_id.clone(),
                &recipient.private_key.verifying_key(),
                "retry with same counter".into(),
            )
            .await
            .expect("retry message");
        let payload: crate::MessageAddedPayload = serde_json::from_str(
            &sender
                .pending_events()
                .await
                .into_iter()
                .rev()
                .find(|event| event.event_type == SyncEventType::MessageAdded)
                .expect("persisted retry event")
                .data,
        )
        .expect("parse retry payload");
        assert!(matches!(payload.version, 3 | 4));
        assert_eq!(payload.ratchet_counter(), Some(0));
        assert_eq!(
            sender
                .get_session(&peer)
                .await
                .expect("sender session after retry")
                .send_counter,
            1
        );

        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
        drop(recipient_storage);
        let _ = std::fs::remove_file(recipient_path);
    }

    #[tokio::test]
    async fn send_lock_serializes_concurrent_sends_no_deadlock() {
        let sender_key = [65; 32];
        let recipient_key = [66; 32];
        let (recipient_storage, recipient_path) = e2ee_test_storage(67);
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "ratchet-concurrent-sender".into(),
        )
        .await
        .expect("sender runtime");
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            "ratchet-concurrent-recipient".into(),
            Some(Arc::clone(&recipient_storage)),
            trusted_local_policy(),
        )
        .await
        .expect("recipient runtime");
        let peer = establish_test_ratchet_session(&sender, &recipient).await;
        let recipient_pubkey = recipient.private_key.verifying_key();

        let concurrent_sends = futures::future::join_all((0..10).map(|index| {
            sender.add_message_encrypted(
                "ratchet-concurrent".into(),
                sender.identity_id.clone(),
                recipient.identity_id.clone(),
                &recipient_pubkey,
                format!("concurrent message {index}"),
            )
        }));
        let results = tokio::time::timeout(Duration::from_secs(5), concurrent_sends)
            .await
            .expect("concurrent sends must not deadlock");
        for result in results {
            result.expect("concurrent send");
        }
        let mut counters = sender
            .pending_events()
            .await
            .into_iter()
            .filter(|event| event.event_type == SyncEventType::MessageAdded)
            .map(|event| {
                serde_json::from_str::<crate::MessageAddedPayload>(&event.data)
                    .expect("parse concurrent payload")
                    .ratchet_counter()
                    .expect("ratchet counter")
            })
            .collect::<Vec<_>>();
        counters.sort_unstable();
        assert_eq!(counters, (0..10).collect::<Vec<_>>());
        assert_eq!(
            sender
                .get_session(&peer)
                .await
                .expect("sender session")
                .send_counter,
            10
        );
        let mut events = sender
            .pending_events()
            .await
            .into_iter()
            .filter(|event| event.event_type == SyncEventType::MessageAdded)
            .collect::<Vec<_>>();
        for event in &mut events {
            event
                .sign(&sender.private_key.to_bytes())
                .expect("sign concurrent event");
        }
        let envelope = SyncEnvelope::new(
            sender.identity_id.clone(),
            sender.public_key.clone(),
            events,
        );
        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&recipient.ctx)).await;
        let recipient_messages = recipient_storage
            .lock()
            .expect("recipient storage lock")
            .messages_json(&sender.public_key)
            .expect("read concurrent messages");
        for index in 0..10 {
            assert!(recipient_messages.contains(&format!("concurrent message {index}")));
        }

        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
        drop(recipient_storage);
        let _ = std::fs::remove_file(recipient_path);
    }

    #[tokio::test]
    async fn incoming_v3_fails_without_session() {
        let sender_key = [47; 32];
        let recipient_key = [48; 32];
        let (storage, storage_path) = e2ee_test_storage(49);
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "ratchet-missing-session-sender".into(),
        )
        .await
        .expect("sender runtime");
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            "ratchet-missing-session-recipient".into(),
            Some(Arc::clone(&storage)),
            trusted_local_policy(),
        )
        .await
        .expect("recipient runtime");
        let mut chain = hal_crypto::SymmetricRatchet::new(&[50; 32]);
        let message_key = chain.advance().expect("derive message key");
        let event_id = "ratchet-without-session";
        let payload = crate::MessageAddedPayload::new_ratchet_encrypted(
            "ratchet-no-session-chat".into(),
            sender.identity_id.clone(),
            recipient.identity_id.clone(),
            "must not decrypt",
            &message_key,
            0,
            event_id,
            unix_now(),
        )
        .expect("create V3 payload");
        let mut event = SyncEvent::new(
            event_id.into(),
            SyncEventType::MessageAdded,
            serde_json::to_string(&payload).expect("serialize V3 payload"),
        );
        event
            .sign(&sender.private_key.to_bytes())
            .expect("sign V3 event");
        let envelope = SyncEnvelope::new(
            sender.identity_id.clone(),
            sender.public_key.clone(),
            vec![event],
        );

        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&recipient.ctx)).await;

        let metrics = recipient.ctx.abuse_metrics.snapshot();
        assert_eq!(metrics.ratchet_decrypt_failed_total, 1);
        assert_eq!(metrics.ratchet_decrypt_total, 0);
        assert_eq!(metrics.ratchet_no_session_total, 1);
        assert!(!storage
            .lock()
            .expect("storage lock")
            .messages_json("ratchet-no-session-chat")
            .expect("read messages")
            .contains("must not decrypt"));
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
        drop(storage);
        let _ = std::fs::remove_file(storage_path);
    }

    #[tokio::test]
    async fn v3_authentication_metadata_is_bound_to_local_peer() {
        let sender_key = [70; 32];
        let recipient_key = [71; 32];
        let (storage, storage_path) = e2ee_test_storage(72);
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "ratchet-auth-sender".into(),
        )
        .await
        .expect("sender runtime");
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            "ratchet-auth-recipient".into(),
            Some(Arc::clone(&storage)),
            trusted_local_policy(),
        )
        .await
        .expect("recipient runtime");
        establish_test_ratchet_session(&sender, &recipient).await;
        let sender_node = NodeId::from_hex(&sender.identity_id).expect("sender identity");

        let source =
            send_ratchet_envelope(&sender, &recipient, "ratchet-auth", "authenticated").await;
        let mut recipient_mismatch: crate::MessageAddedPayload =
            serde_json::from_str(&source.events[0].data).expect("parse original payload");
        recipient_mismatch.recipient_id = Some(sender.identity_id.clone());
        let mut event = SyncEvent::new(
            source.events[0].id.clone(),
            SyncEventType::MessageAdded,
            serde_json::to_string(&recipient_mismatch).expect("serialize recipient mismatch"),
        );
        event
            .sign(&sender.private_key.to_bytes())
            .expect("sign recipient mismatch");
        PeerRuntime::process_incoming_envelope(
            SyncEnvelope::new(
                sender.identity_id.clone(),
                sender.public_key.clone(),
                vec![event],
            ),
            Arc::clone(&recipient.ctx),
        )
        .await;
        assert_eq!(
            recipient
                .ctx
                .abuse_metrics
                .snapshot()
                .ratchet_recipient_mismatch_total,
            1
        );
        assert_eq!(
            recipient
                .ctx
                .session_store
                .lock()
                .await
                .get_view(&sender_node)
                .expect("receiver session")
                .recv_counter,
            0
        );

        let mut sender_mismatch: crate::MessageAddedPayload =
            serde_json::from_str(&source.events[0].data).expect("parse original payload");
        sender_mismatch.sender_id = "forged-sender".into();
        let mut event = SyncEvent::new(
            "ratchet-auth-sender-mismatch".into(),
            SyncEventType::MessageAdded,
            serde_json::to_string(&sender_mismatch).expect("serialize sender mismatch"),
        );
        event
            .sign(&sender.private_key.to_bytes())
            .expect("sign sender mismatch");
        PeerRuntime::process_incoming_envelope(
            SyncEnvelope::new(
                sender.identity_id.clone(),
                sender.public_key.clone(),
                vec![event],
            ),
            Arc::clone(&recipient.ctx),
        )
        .await;
        assert_eq!(
            recipient
                .ctx
                .abuse_metrics
                .snapshot()
                .ratchet_sender_mismatch_total,
            1
        );
        assert_eq!(
            recipient
                .ctx
                .session_store
                .lock()
                .await
                .get_view(&sender_node)
                .expect("receiver session")
                .recv_counter,
            0
        );

        let mut overflow_payload: crate::MessageAddedPayload =
            serde_json::from_str(&source.events[0].data).expect("parse original payload");
        overflow_payload.ratchet_counter = Some(u64::MAX);
        let mut event = SyncEvent::new(
            "ratchet-auth-counter-overflow".into(),
            SyncEventType::MessageAdded,
            serde_json::to_string(&overflow_payload).expect("serialize overflow payload"),
        );
        event
            .sign(&sender.private_key.to_bytes())
            .expect("sign overflow payload");
        PeerRuntime::process_incoming_envelope(
            SyncEnvelope::new(
                sender.identity_id.clone(),
                sender.public_key.clone(),
                vec![event],
            ),
            Arc::clone(&recipient.ctx),
        )
        .await;
        assert_eq!(
            recipient
                .ctx
                .abuse_metrics
                .snapshot()
                .ratchet_counter_overflow_total,
            1
        );
        assert_eq!(
            recipient
                .ctx
                .session_store
                .lock()
                .await
                .get_view(&sender_node)
                .expect("receiver session")
                .recv_counter,
            0
        );

        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
        drop(storage);
        let _ = std::fs::remove_file(storage_path);
    }

    #[tokio::test]
    async fn v3_in_needs_resync_session_and_malformed_payload_are_counted() {
        let sender_key = [73; 32];
        let recipient_key = [74; 32];
        let (storage, storage_path) = e2ee_test_storage(72);
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "ratchet-resync-receiver-sender".into(),
        )
        .await
        .expect("sender runtime");
        let recipient = PeerRuntime::start_with_storage(
            identity_for(&recipient_key),
            recipient_key,
            "ratchet-resync-receiver-recipient".into(),
            Arc::clone(&storage),
        )
        .await
        .expect("recipient runtime");
        establish_test_ratchet_session(&sender, &recipient).await;
        let sender_node = NodeId::from_hex(&sender.identity_id).expect("sender identity");
        sender
            .ctx
            .session_store
            .lock()
            .await
            .set_peer_supports_v4(
                &NodeId::from_hex(&recipient.identity_id).expect("recipient identity"),
                None,
            )
            .expect("use legacy peer for V3-specific test");
        recipient
            .ctx
            .session_store
            .lock()
            .await
            .mark_needs_resync(&sender_node)
            .expect("mark receiver session for resync");

        let envelope =
            send_ratchet_envelope(&sender, &recipient, "ratchet-resync-receiver", "blocked").await;
        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&recipient.ctx)).await;
        assert_eq!(
            recipient
                .ctx
                .abuse_metrics
                .snapshot()
                .ratchet_needs_resync_received_total,
            1
        );

        let mut malformed = SyncEvent::new(
            "ratchet-malformed-v3".into(),
            SyncEventType::MessageAdded,
            r#"{"version":3"#.into(),
        );
        malformed
            .sign(&sender.private_key.to_bytes())
            .expect("sign malformed event");
        PeerRuntime::process_incoming_envelope(
            SyncEnvelope::new(
                sender.identity_id.clone(),
                sender.public_key.clone(),
                vec![malformed],
            ),
            Arc::clone(&recipient.ctx),
        )
        .await;
        assert_eq!(
            recipient
                .ctx
                .abuse_metrics
                .snapshot()
                .ratchet_parse_failed_total,
            1
        );

        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
        drop(storage);
        let _ = std::fs::remove_file(storage_path);
    }

    #[tokio::test]
    async fn version_coexistence_rejects_v1_and_accepts_v2_with_confirmed_session() {
        let sender_key = [75; 32];
        let recipient_key = [76; 32];
        let (storage, storage_path) = e2ee_test_storage(77);
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "ratchet-version-policy-sender".into(),
        )
        .await
        .expect("sender runtime");
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            "ratchet-version-policy-recipient".into(),
            Some(Arc::clone(&storage)),
            trusted_local_policy(),
        )
        .await
        .expect("recipient runtime");
        establish_test_ratchet_session(&sender, &recipient).await;
        let recipient_key = recipient.private_key.verifying_key();

        let plaintext = crate::MessageAddedPayload::new_legacy(
            "ratchet-version-policy".into(),
            sender.identity_id.clone(),
            Some(recipient.identity_id.clone()),
            "plaintext downgrade".into(),
            unix_now(),
        );
        let mut v1_event = SyncEvent::new(
            "ratchet-unexpected-v1".into(),
            SyncEventType::MessageAdded,
            serde_json::to_string(&plaintext).expect("serialize V1 payload"),
        );
        v1_event
            .sign(&sender.private_key.to_bytes())
            .expect("sign V1 payload");
        PeerRuntime::process_incoming_envelope(
            SyncEnvelope::new(
                sender.identity_id.clone(),
                sender.public_key.clone(),
                vec![v1_event],
            ),
            Arc::clone(&recipient.ctx),
        )
        .await;
        assert_eq!(
            recipient
                .ctx
                .abuse_metrics
                .snapshot()
                .ratchet_unexpected_v1_total,
            1
        );

        let encrypted = crate::MessageAddedPayload::new_encrypted(
            "ratchet-version-policy".into(),
            sender.identity_id.clone(),
            recipient.identity_id.clone(),
            &recipient_key,
            "allowed ECIES fallback",
            unix_now(),
            "ratchet-unexpected-v2",
        )
        .expect("create V2 payload");
        let mut v2_event = SyncEvent::new(
            "ratchet-unexpected-v2".into(),
            SyncEventType::MessageAdded,
            serde_json::to_string(&encrypted).expect("serialize V2 payload"),
        );
        v2_event
            .sign(&sender.private_key.to_bytes())
            .expect("sign V2 payload");
        PeerRuntime::process_incoming_envelope(
            SyncEnvelope::new(
                sender.identity_id.clone(),
                sender.public_key.clone(),
                vec![v2_event],
            ),
            Arc::clone(&recipient.ctx),
        )
        .await;
        let metrics = recipient.ctx.abuse_metrics.snapshot();
        assert_eq!(metrics.ratchet_unexpected_v2_total, 1);
        assert_eq!(metrics.messages_decrypted_total, 1);

        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
        drop(storage);
        let _ = std::fs::remove_file(storage_path);
    }

    #[tokio::test]
    async fn v3_envelope_order_duplicate_gap_and_concurrent_replay_are_guarded() {
        let sender_key = [67; 32];
        let recipient_key = [68; 32];
        let sender_node =
            NodeId::from_public_key(&SigningKey::from_bytes(&sender_key).verifying_key());
        let (storage, storage_path) = e2ee_test_storage(69);
        storage
            .lock()
            .expect("storage lock")
            .identity_history()
            .observe_first_seen(&sender_node.to_hex(), 1)
            .expect("seed established first-seen timestamp");
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "ratchet-envelope-order-sender".into(),
        )
        .await
        .expect("sender runtime");
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            "ratchet-envelope-order-recipient".into(),
            Some(Arc::clone(&storage)),
            trusted_local_policy(),
        )
        .await
        .expect("recipient runtime");
        establish_test_ratchet_session(&sender, &recipient).await;
        let recipient_node = NodeId::from_hex(&recipient.identity_id).expect("recipient identity");
        sender
            .ctx
            .session_store
            .lock()
            .await
            .set_peer_supports_v4(&recipient_node, None)
            .expect("use legacy peer for V3-specific test");
        let accepted_start = unix_now()
            .saturating_sub(crate::dht::rate_limit::FIRST_CONTACT_ACCEPTED_THRESHOLD as u64 * 31);
        for index in 0..crate::dht::rate_limit::FIRST_CONTACT_ACCEPTED_THRESHOLD as u64 {
            assert!(recipient
                .ctx
                .record_rate_acceptance(&sender_node, accepted_start + index * 31));
        }

        let first_batch = send_ratchet_envelope_batch(
            &sender,
            &recipient,
            "ratchet-envelope-order",
            &["ordered zero", "ordered one"],
        )
        .await;
        PeerRuntime::process_incoming_envelope(first_batch, Arc::clone(&recipient.ctx)).await;
        assert_eq!(
            recipient
                .ctx
                .session_store
                .lock()
                .await
                .get_view(&sender_node)
                .expect("receiver session")
                .recv_counter,
            2
        );

        let duplicate_source =
            send_ratchet_envelope(&sender, &recipient, "ratchet-envelope-order", "once").await;
        let duplicate_event = duplicate_source.events[0].clone();
        let duplicated = SyncEnvelope::new(
            sender.identity_id.clone(),
            sender.public_key.clone(),
            vec![duplicate_event.clone(), duplicate_event],
        );
        PeerRuntime::process_incoming_envelope(duplicated, Arc::clone(&recipient.ctx)).await;
        assert_eq!(
            recipient
                .ctx
                .session_store
                .lock()
                .await
                .get_view(&sender_node)
                .expect("receiver session")
                .recv_counter,
            3
        );
        assert_eq!(
            recipient.ctx.abuse_metrics.snapshot().ratchet_replay_total,
            1
        );

        let gap_batch = send_ratchet_envelope_batch(
            &sender,
            &recipient,
            "ratchet-envelope-order",
            &["gap zero", "gap one", "gap two"],
        )
        .await;
        let gap_events = vec![gap_batch.events[0].clone(), gap_batch.events[2].clone()];
        PeerRuntime::process_incoming_envelope(
            SyncEnvelope::new(
                sender.identity_id.clone(),
                sender.public_key.clone(),
                gap_events,
            ),
            Arc::clone(&recipient.ctx),
        )
        .await;
        assert_eq!(
            recipient
                .ctx
                .session_store
                .lock()
                .await
                .get_view(&sender_node)
                .expect("receiver session")
                .recv_counter,
            6
        );
        assert_eq!(
            recipient
                .ctx
                .abuse_metrics
                .snapshot()
                .ratchet_out_of_order_total,
            0
        );
        assert_eq!(
            recipient
                .ctx
                .abuse_metrics
                .snapshot()
                .ratchet_out_of_order_accepted_total,
            1
        );
        PeerRuntime::process_incoming_envelope(
            SyncEnvelope::new(
                sender.identity_id.clone(),
                sender.public_key.clone(),
                vec![gap_batch.events[1].clone()],
            ),
            Arc::clone(&recipient.ctx),
        )
        .await;
        assert_eq!(
            recipient
                .ctx
                .session_store
                .lock()
                .await
                .get_view(&sender_node)
                .expect("receiver session")
                .recv_counter,
            6
        );
        PeerRuntime::process_incoming_envelope(
            SyncEnvelope::new(
                sender.identity_id.clone(),
                sender.public_key.clone(),
                vec![gap_batch.events[2].clone()],
            ),
            Arc::clone(&recipient.ctx),
        )
        .await;
        assert_eq!(
            recipient
                .ctx
                .session_store
                .lock()
                .await
                .get_view(&sender_node)
                .expect("receiver session")
                .recv_counter,
            6
        );

        let concurrent_source = send_ratchet_envelope(
            &sender,
            &recipient,
            "ratchet-envelope-order",
            "concurrent once",
        )
        .await;
        let concurrent_a = concurrent_source.clone();
        let concurrent_b = concurrent_source;
        tokio::join!(
            PeerRuntime::process_incoming_envelope(concurrent_a, Arc::clone(&recipient.ctx)),
            PeerRuntime::process_incoming_envelope(concurrent_b, Arc::clone(&recipient.ctx)),
        );
        assert_eq!(
            recipient
                .ctx
                .session_store
                .lock()
                .await
                .get_view(&sender_node)
                .expect("receiver session")
                .recv_counter,
            7
        );
        assert_eq!(
            recipient.ctx.abuse_metrics.snapshot().ratchet_replay_total,
            3
        );

        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
        drop(storage);
        let _ = std::fs::remove_file(storage_path);
    }

    #[tokio::test]
    async fn v3_messages_delivered_out_of_order_use_skipped_keys() {
        let sender_key = [91; 32];
        let recipient_key = [92; 32];
        let (storage, storage_path) = e2ee_test_storage(93);
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "ratchet-out-of-order-sender".into(),
        )
        .await
        .expect("sender runtime");
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            "ratchet-out-of-order-recipient".into(),
            Some(Arc::clone(&storage)),
            trusted_local_policy(),
        )
        .await
        .expect("recipient runtime");
        establish_test_ratchet_session(&sender, &recipient).await;
        let sender_node = NodeId::from_hex(&sender.identity_id).expect("sender identity");
        let batch = send_ratchet_envelope_batch(
            &sender,
            &recipient,
            "ratchet-out-of-order",
            &[
                "out of order zero",
                "out of order one",
                "out of order two",
                "out of order three",
                "out of order four",
            ],
        )
        .await;

        for counter in [0, 2, 1, 4, 3] {
            PeerRuntime::process_incoming_envelope(
                SyncEnvelope::new(
                    sender.identity_id.clone(),
                    sender.public_key.clone(),
                    vec![batch.events[counter].clone()],
                ),
                Arc::clone(&recipient.ctx),
            )
            .await;
        }

        assert_eq!(
            recipient
                .ctx
                .session_store
                .lock()
                .await
                .get_view(&sender_node)
                .expect("receiver session")
                .recv_counter,
            5
        );
        let metrics = recipient.ctx.abuse_metrics.snapshot();
        assert_eq!(metrics.ratchet_decrypt_total, 5);
        assert_eq!(metrics.ratchet_out_of_order_accepted_total, 4);
        assert_eq!(metrics.ratchet_replay_total, 0);
        let messages = storage
            .lock()
            .expect("storage lock")
            .messages_json(&sender.public_key)
            .expect("read received messages");
        for plaintext in [
            "out of order zero",
            "out of order one",
            "out of order two",
            "out of order three",
            "out of order four",
        ] {
            assert!(
                messages.contains(plaintext),
                "missing plaintext: {plaintext}"
            );
        }

        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
        drop(storage);
        let _ = std::fs::remove_file(storage_path);
    }

    #[tokio::test]
    async fn incoming_v3_bad_counter_does_not_advance_receive_chain() {
        let sender_key = [51; 32];
        let recipient_key = [52; 32];
        let (storage, storage_path) = e2ee_test_storage(53);
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "ratchet-counter-sender".into(),
        )
        .await
        .expect("sender runtime");
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            "ratchet-counter-recipient".into(),
            Some(Arc::clone(&storage)),
            trusted_local_policy(),
        )
        .await
        .expect("recipient runtime");
        establish_test_ratchet_session(&sender, &recipient).await;
        let sender_node = NodeId::from_hex(&sender.identity_id).expect("sender identity");
        let envelope =
            send_ratchet_envelope(&sender, &recipient, "ratchet-counter", "valid message").await;
        let mut bad_payload: crate::MessageAddedPayload =
            serde_json::from_str(&envelope.events[0].data).expect("parse V3 payload");
        bad_payload.ratchet_counter = Some(1);
        let event_id = envelope.events[0].id.clone();
        let mut bad_event = SyncEvent::new(
            event_id.clone(),
            SyncEventType::MessageAdded,
            serde_json::to_string(&bad_payload).expect("serialize modified payload"),
        );
        bad_event
            .sign(&sender.private_key.to_bytes())
            .expect("sign modified event");
        let bad_envelope = SyncEnvelope::new(
            sender.identity_id.clone(),
            sender.public_key.clone(),
            vec![bad_event],
        );

        PeerRuntime::process_incoming_envelope(bad_envelope, Arc::clone(&recipient.ctx)).await;
        assert_eq!(
            recipient
                .ctx
                .session_store
                .lock()
                .await
                .get_view(&sender_node)
                .expect("receiver session")
                .recv_counter,
            0
        );
        assert_eq!(
            recipient
                .ctx
                .abuse_metrics
                .snapshot()
                .ratchet_decrypt_failed_total,
            1
        );

        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&recipient.ctx)).await;
        assert_eq!(
            recipient
                .ctx
                .session_store
                .lock()
                .await
                .get_view(&sender_node)
                .expect("receiver session")
                .recv_counter,
            1
        );
        assert_eq!(
            recipient.ctx.abuse_metrics.snapshot().ratchet_decrypt_total,
            1
        );
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
        drop(storage);
        let _ = std::fs::remove_file(storage_path);
    }

    #[tokio::test]
    async fn incoming_v3_storage_failure_does_not_commit_and_can_retry() {
        let sender_key = [61; 32];
        let recipient_key = [62; 32];
        let (storage, storage_path) = e2ee_test_storage(63);
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "ratchet-receive-persist-sender".into(),
        )
        .await
        .expect("sender runtime");
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            "ratchet-receive-persist-recipient".into(),
            Some(Arc::clone(&storage)),
            trusted_local_policy(),
        )
        .await
        .expect("recipient runtime");
        establish_test_ratchet_session(&sender, &recipient).await;
        let sender_node = NodeId::from_hex(&sender.identity_id).expect("sender identity");
        let envelope =
            send_ratchet_envelope(&sender, &recipient, "ratchet-persist-retry", "retry me").await;

        let poisoned_storage = Arc::clone(&storage);
        let _ = std::thread::spawn(move || {
            let _guard = poisoned_storage
                .lock()
                .expect("take storage lock before poisoning");
            panic!("test storage lock poison");
        })
        .join();
        PeerRuntime::process_incoming_envelope(envelope.clone(), Arc::clone(&recipient.ctx)).await;
        assert_eq!(
            recipient
                .ctx
                .session_store
                .lock()
                .await
                .get_view(&sender_node)
                .expect("receiver session")
                .recv_counter,
            0
        );
        assert_eq!(
            recipient
                .ctx
                .abuse_metrics
                .snapshot()
                .ratchet_persist_failed_total,
            1
        );

        storage.clear_poison();
        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&recipient.ctx)).await;
        assert_eq!(
            recipient
                .ctx
                .session_store
                .lock()
                .await
                .get_view(&sender_node)
                .expect("receiver session")
                .recv_counter,
            1
        );
        assert!(storage
            .lock()
            .expect("storage lock after clearing poison")
            .messages_json(&sender.public_key)
            .expect("read stored messages")
            .contains("retry me"));

        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
        drop(storage);
        let _ = std::fs::remove_file(storage_path);
    }

    #[tokio::test]
    async fn send_commit_failure_marks_session_needs_resync() {
        let sender_key = [64; 32];
        let recipient_key = [65; 32];
        let (storage, storage_path) = e2ee_test_storage(66);
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "ratchet-send-commit-failure-sender".into(),
        )
        .await
        .expect("sender runtime");
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            "ratchet-send-commit-failure-recipient".into(),
            Some(Arc::clone(&storage)),
            trusted_local_policy(),
        )
        .await
        .expect("recipient runtime");
        let peer = establish_test_ratchet_session(&sender, &recipient).await;
        sender
            .ctx
            .session_store
            .lock()
            .await
            .fail_next_send_commit();

        let first_send = sender
            .add_message_encrypted(
                "ratchet-needs-resync".into(),
                sender.identity_id.clone(),
                recipient.identity_id.clone(),
                &recipient.private_key.verifying_key(),
                "persisted before commit failure".into(),
            )
            .await;
        assert!(first_send.is_err());
        let view = sender
            .ctx
            .session_store
            .lock()
            .await
            .get_view(&peer)
            .expect("sender session");
        assert!(view.needs_resync);
        assert!(!view.responded);
        assert_eq!(view.send_counter, 0);
        let metrics = sender.ctx.abuse_metrics.snapshot();
        assert_eq!(metrics.ratchet_commit_failed_total, 1);
        assert_eq!(metrics.ratchet_needs_resync_total, 1);
        assert_eq!(metrics.ratchet_resync_triggered_total, 1);
        assert_eq!(metrics.ratchet_send_blocked_resync_total, 0);
        assert!(sender
            .pending_events()
            .await
            .iter()
            .any(|event| event.event_type == SyncEventType::X3dhInit));

        let second_send = sender
            .add_message_encrypted(
                "ratchet-needs-resync".into(),
                sender.identity_id.clone(),
                recipient.identity_id.clone(),
                &recipient.private_key.verifying_key(),
                "must be blocked".into(),
            )
            .await;
        assert!(second_send.is_err());
        assert_eq!(sender.ctx.abuse_metrics.snapshot().ecies_fallback_total, 0);
        assert_eq!(
            sender
                .ctx
                .abuse_metrics
                .snapshot()
                .ratchet_resync_triggered_total,
            1
        );
        assert_eq!(
            sender
                .ctx
                .abuse_metrics
                .snapshot()
                .ratchet_send_blocked_resync_total,
            1
        );

        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
        drop(storage);
        let _ = std::fs::remove_file(storage_path);
    }

    #[tokio::test]
    async fn two_node_ratchet_roundtrip_and_relay_cannot_decrypt() {
        let key_a = [54; 32];
        let key_b = [55; 32];
        let relay_key = [56; 32];
        let (storage_a, path_a) = e2ee_test_storage(57);
        let (storage_b, path_b) = e2ee_test_storage(58);
        let (relay_storage, relay_path) = e2ee_test_storage(59);
        let a = PeerRuntime::start_with_policy(
            identity_for(&key_a),
            key_a,
            "ratchet-roundtrip-a".into(),
            Some(Arc::clone(&storage_a)),
            trusted_local_policy(),
        )
        .await
        .expect("runtime a");
        let b = PeerRuntime::start_with_policy(
            identity_for(&key_b),
            key_b,
            "ratchet-roundtrip-b".into(),
            Some(Arc::clone(&storage_b)),
            trusted_local_policy(),
        )
        .await
        .expect("runtime b");
        let relay = PeerRuntime::start_with_policy(
            identity_for(&relay_key),
            relay_key,
            "ratchet-roundtrip-relay".into(),
            Some(Arc::clone(&relay_storage)),
            trusted_local_policy(),
        )
        .await
        .expect("runtime relay");
        establish_test_ratchet_session(&a, &b).await;

        let mut sent_a_to_b = 0;
        let mut sent_b_to_a = 0;
        for index in 0..10 {
            let (sender, recipient, expected_counter) = if index % 2 == 0 {
                let counter = sent_a_to_b;
                sent_a_to_b += 1;
                (&a, &b, counter)
            } else {
                let counter = sent_b_to_a;
                sent_b_to_a += 1;
                (&b, &a, counter)
            };
            let plaintext = format!("ratchet body {index}");
            let envelope =
                send_ratchet_envelope(sender, recipient, "ratchet-roundtrip", &plaintext).await;
            let payload: crate::MessageAddedPayload =
                serde_json::from_str(&envelope.events[0].data).expect("parse ratchet payload");
            assert!(matches!(payload.version, 3 | 4));
            assert_eq!(payload.ratchet_counter(), Some(expected_counter));

            PeerRuntime::process_incoming_envelope(envelope.clone(), Arc::clone(&relay.ctx)).await;
            assert_eq!(relay.ctx.abuse_metrics.snapshot().ratchet_decrypt_total, 0);
            PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&recipient.ctx)).await;

            let (storage, peer) = if std::ptr::eq(recipient, &a) {
                (&storage_a, &b)
            } else {
                (&storage_b, &a)
            };
            assert!(storage
                .lock()
                .expect("recipient storage lock")
                .messages_json(&peer.public_key)
                .expect("read recipient messages")
                .contains(&plaintext));
            let peer_id = NodeId::from_hex(&peer.identity_id).expect("peer identity");
            assert_eq!(
                recipient
                    .get_session(&peer_id)
                    .await
                    .expect("recipient ratchet session")
                    .recv_counter,
                expected_counter + 1
            );
        }

        assert_eq!(sent_a_to_b, 5);
        assert_eq!(sent_b_to_a, 5);
        assert_eq!(a.ctx.abuse_metrics.snapshot().ratchet_encrypt_total, 5);
        assert_eq!(b.ctx.abuse_metrics.snapshot().ratchet_encrypt_total, 5);
        assert_eq!(a.ctx.abuse_metrics.snapshot().ratchet_decrypt_total, 5);
        assert_eq!(b.ctx.abuse_metrics.snapshot().ratchet_decrypt_total, 5);
        assert_eq!(relay.ctx.abuse_metrics.snapshot().ratchet_decrypt_total, 0);
        let relay_messages = relay_storage
            .lock()
            .expect("relay storage lock")
            .messages_json("ratchet-roundtrip")
            .expect("read relay message projection");
        assert!(!relay_messages.contains("ratchet body"));

        a.stop().await.expect("stop runtime a");
        b.stop().await.expect("stop runtime b");
        relay.stop().await.expect("stop relay");
        drop((storage_a, storage_b, relay_storage));
        let _ = std::fs::remove_file(path_a);
        let _ = std::fs::remove_file(path_b);
        let _ = std::fs::remove_file(relay_path);
    }

    #[tokio::test]
    async fn x3dh_session_establish_session_fetches_bundle_and_saves() {
        let now = unix_now();
        let local_key = [231; 32];
        let remote_key = SigningKey::from_bytes(&[232; 32]);
        let remote_x3dh = X3DHKeys::from_identity(&remote_key).expect("remote X3DH keys");
        let bundle = PrekeyBundle::create(
            &remote_key,
            remote_x3dh.prekey.to_bytes(),
            {
                let (_, public) = hal_crypto::generate_x25519_keypair();
                vec![hal_crypto::OneTimePrekey {
                    id: 1,
                    public_key: public.to_bytes(),
                }]
            },
            1,
            now,
            now.saturating_add(3_600),
        )
        .expect("remote bundle");
        let peer = NodeId::from_public_key(&remote_key.verifying_key());
        let runtime = PeerRuntime::start(identity_for(&local_key), local_key, "x3dh-init".into())
            .await
            .expect("runtime");
        runtime
            .ctx
            .prekey_cache
            .lock()
            .await
            .insert(peer, bundle.clone(), bundle.expires_at, now)
            .expect("cache bundle");

        runtime
            .establish_session_as_initiator(peer, now)
            .await
            .expect("establish initiator session");
        let session = runtime.get_session(&peer).await.expect("session stored");
        assert!(!session.responded);
        assert_eq!(
            runtime
                .pending_events()
                .await
                .iter()
                .filter(|event| event.event_type == SyncEventType::X3dhInit)
                .count(),
            1
        );
        assert_eq!(
            runtime
                .metrics_snapshot()
                .await
                .abuse
                .x3dh_session_established_total,
            1
        );
        runtime.stop().await.expect("stop runtime");
    }

    #[tokio::test]
    async fn x3dh_session_establish_session_fails_without_bundle() {
        let local_key = [233; 32];
        let missing_peer =
            NodeId::from_public_key(&SigningKey::from_bytes(&[234; 32]).verifying_key());
        let runtime =
            PeerRuntime::start(identity_for(&local_key), local_key, "x3dh-no-bundle".into())
                .await
                .expect("runtime");

        assert!(runtime
            .establish_session_as_initiator(missing_peer, unix_now())
            .await
            .is_err());
        assert!(!runtime.has_session(&missing_peer).await);
        assert_eq!(
            runtime
                .metrics_snapshot()
                .await
                .abuse
                .x3dh_bundle_fetch_failed_total,
            1
        );
        runtime.stop().await.expect("stop runtime");
    }

    #[tokio::test]
    async fn x3dh_session_establish_session_fails_on_invalid_bundle_signature() {
        let now = unix_now();
        let local_key = [235; 32];
        let remote_key = SigningKey::from_bytes(&[236; 32]);
        let remote_x3dh = X3DHKeys::from_identity(&remote_key).expect("remote X3DH keys");
        let mut bundle = PrekeyBundle::create(
            &remote_key,
            remote_x3dh.prekey.to_bytes(),
            Vec::new(),
            1,
            now,
            now.saturating_add(3_600),
        )
        .expect("remote bundle");
        bundle.bundle_signature[0] ^= 1;
        let peer = NodeId::from_public_key(&remote_key.verifying_key());
        let runtime = PeerRuntime::start(
            identity_for(&local_key),
            local_key,
            "x3dh-bad-bundle".into(),
        )
        .await
        .expect("runtime");
        runtime.ctx.prekey_cache.lock().await.insert_unchecked(
            peer,
            bundle.clone(),
            bundle.expires_at,
        );

        assert!(runtime
            .establish_session_as_initiator(peer, now)
            .await
            .is_err());
        assert!(!runtime.has_session(&peer).await);
        assert_eq!(
            runtime
                .metrics_snapshot()
                .await
                .abuse
                .x3dh_bundle_verify_failed_total,
            1
        );
        runtime.stop().await.expect("stop runtime");
    }

    #[tokio::test]
    async fn x3dh_session_handle_init_creates_session() {
        let now = unix_now();
        let alice_key = SigningKey::from_bytes(&[237; 32]);
        let bob_key = SigningKey::from_bytes(&[238; 32]);
        let (storage, path) = e2ee_test_storage(238);
        let bob = x3dh_test_context(&bob_key, Some(Arc::clone(&storage)));
        let bundle = x3dh_test_bundle(&bob, &bob_key, now, true).await;
        let alice_x3dh = X3DHKeys::from_identity(&alice_key).expect("alice X3DH keys");
        let (_, init) =
            X3DH::initiate_with_bundle(&alice_x3dh, &bundle, bundle.one_time_prekeys.first(), now)
                .expect("initiate");

        handle_session_init_in_context(&bob, init, now, None)
            .await
            .expect("handle init");
        let alice_id = NodeId::from_public_key(&alice_key.verifying_key());
        let session = bob.session_store.lock().await.get_view(&alice_id);
        assert_eq!(session.expect("responder session").recv_counter, 0);
        drop(bob);
        drop(storage);
        std::fs::remove_file(path).expect("remove test database");
    }

    #[tokio::test]
    async fn x3dh_session_handle_init_fails_without_opk() {
        let now = unix_now();
        let alice_key = SigningKey::from_bytes(&[239; 32]);
        let bob_key = SigningKey::from_bytes(&[240; 32]);
        let (storage, path) = e2ee_test_storage(240);
        let bob = x3dh_test_context(&bob_key, Some(Arc::clone(&storage)));
        let bundle = x3dh_test_bundle(&bob, &bob_key, now, false).await;
        let alice_x3dh = X3DHKeys::from_identity(&alice_key).expect("alice X3DH keys");
        let (_, init) =
            X3DH::initiate_with_bundle(&alice_x3dh, &bundle, None, now).expect("initiate");

        assert!(handle_session_init_in_context(&bob, init, now, None)
            .await
            .is_err());
        let alice_id = NodeId::from_public_key(&alice_key.verifying_key());
        assert!(bob.session_store.lock().await.get_view(&alice_id).is_none());
        drop(bob);
        drop(storage);
        std::fs::remove_file(path).expect("remove test database");
    }

    #[tokio::test]
    async fn x3dh_session_handle_init_fails_with_consumed_opk() {
        let now = unix_now();
        let alice_key = SigningKey::from_bytes(&[241; 32]);
        let bob_key = SigningKey::from_bytes(&[242; 32]);
        let (storage, path) = e2ee_test_storage(242);
        let bob = x3dh_test_context(&bob_key, Some(Arc::clone(&storage)));
        let bundle = x3dh_test_bundle(&bob, &bob_key, now, true).await;
        let opk = bundle.one_time_prekeys.first().expect("published OPK");
        let alice_x3dh = X3DHKeys::from_identity(&alice_key).expect("alice X3DH keys");
        let (_, init) =
            X3DH::initiate_with_bundle(&alice_x3dh, &bundle, Some(opk), now).expect("initiate");
        bob.local_prekey_store
            .as_ref()
            .expect("prekey store")
            .lock()
            .await
            .consume_opk(opk.id, now)
            .await
            .expect("consume OPK first");

        assert!(handle_session_init_in_context(&bob, init, now, None)
            .await
            .is_err());
        let alice_id = NodeId::from_public_key(&alice_key.verifying_key());
        assert!(bob.session_store.lock().await.get_view(&alice_id).is_none());
        drop(bob);
        drop(storage);
        std::fs::remove_file(path).expect("remove test database");
    }

    #[tokio::test]
    async fn two_node_chains_match_after_establish() {
        let now = unix_now();
        let alice_key = SigningKey::from_bytes(&[243; 32]);
        let bob_key = SigningKey::from_bytes(&[244; 32]);
        let (storage, path) = e2ee_test_storage(244);
        let alice = x3dh_test_context(&alice_key, None);
        let bob = x3dh_test_context(&bob_key, Some(Arc::clone(&storage)));
        let bundle = x3dh_test_bundle(&bob, &bob_key, now, true).await;
        let alice_x3dh = X3DHKeys::from_identity(&alice_key).expect("alice X3DH keys");
        let (initiated, init) =
            X3DH::initiate_with_bundle(&alice_x3dh, &bundle, bundle.one_time_prekeys.first(), now)
                .expect("initiate");
        let alice_id = NodeId::from_public_key(&alice_key.verifying_key());
        let bob_id = NodeId::from_public_key(&bob_key.verifying_key());
        let root_key = session_root_key(&initiated).expect("root key");
        alice
            .session_store
            .lock()
            .await
            .insert_pending_with_chains(
                bob_id,
                root_key,
                &alice_id,
                now,
                init.ephemeral_public,
                init.signed_prekey_used,
                init.one_time_prekey_id,
            )
            .expect("create initiator ratchet session");
        let mut init_event = SyncEvent::new(
            uuid::Uuid::new_v4().to_string(),
            SyncEventType::X3dhInit,
            base64::engine::general_purpose::STANDARD
                .encode(serde_json::to_vec(&init).expect("serialize init")),
        );
        init_event
            .sign(&alice_key.to_bytes())
            .expect("sign init event");
        let init_envelope = SyncEnvelope::new(
            alice.identity_id.clone(),
            alice.public_key.clone(),
            vec![init_event],
        );
        PeerRuntime::process_incoming_envelope_inner(
            init_envelope,
            Arc::clone(&bob),
            0,
            EnvelopeMeta::default(),
        )
        .await;
        let response_event = bob
            .sync
            .lock()
            .await
            .get_pending_events()
            .into_iter()
            .find(|event| event.event_type == SyncEventType::X3dhRespond)
            .expect("respond event");
        let mut response_event = response_event;
        response_event
            .sign(&bob_key.to_bytes())
            .expect("sign response event");
        let response_envelope = SyncEnvelope::new(
            bob.identity_id.clone(),
            bob.public_key.clone(),
            vec![response_event],
        );
        PeerRuntime::process_incoming_envelope_inner(
            response_envelope,
            Arc::clone(&alice),
            0,
            EnvelopeMeta::default(),
        )
        .await;
        let alice_session = alice.session_store.lock().await.get_view(&bob_id);
        assert_eq!(
            alice_session.as_ref().expect("initiator session").direction,
            if alice_id.as_bytes() < bob_id.as_bytes() {
                crate::session_store::Direction::LowToHigh
            } else {
                crate::session_store::Direction::HighToLow
            }
        );
        assert!(alice_session.as_ref().expect("initiator session").responded);
        let (alice_message_key, alice_counter) = alice
            .session_store
            .lock()
            .await
            .advance_sending(&bob_id, now + 1)
            .expect("advance initiator send chain");
        let (bob_message_key, bob_counter) = bob
            .session_store
            .lock()
            .await
            .advance_receiving(&alice_id, alice_counter, now + 1)
            .expect("advance responder receive chain");
        assert_eq!(alice_counter, bob_counter);
        assert_eq!(*alice_message_key.key, *bob_message_key.key);
        drop(alice);
        drop(bob);
        drop(storage);
        std::fs::remove_file(path).expect("remove test database");
    }

    #[tokio::test]
    async fn x3dh_session_not_established_on_tampered_init() {
        let now = unix_now();
        let alice_key = SigningKey::from_bytes(&[245; 32]);
        let bob_key = SigningKey::from_bytes(&[246; 32]);
        let (storage, path) = e2ee_test_storage(246);
        let bob = x3dh_test_context(&bob_key, Some(Arc::clone(&storage)));
        let bundle = x3dh_test_bundle(&bob, &bob_key, now, true).await;
        let alice_x3dh = X3DHKeys::from_identity(&alice_key).expect("alice X3DH keys");
        let (_, mut init) =
            X3DH::initiate_with_bundle(&alice_x3dh, &bundle, bundle.one_time_prekeys.first(), now)
                .expect("initiate");
        init.signature[0] ^= 1;

        assert!(handle_session_init_in_context(&bob, init, now, None)
            .await
            .is_err());
        let alice_id = NodeId::from_public_key(&alice_key.verifying_key());
        assert!(bob.session_store.lock().await.get_view(&alice_id).is_none());
        drop(bob);
        drop(storage);
        std::fs::remove_file(path).expect("remove test database");
    }

    async fn queue_encrypted_direct_message(
        sender: &PeerRuntime,
        recipient: &PeerRuntime,
        chat_id: &str,
        plaintext: &str,
    ) -> SyncEnvelope {
        sender
            .pin_peer(&recipient.identity_id, &recipient.public_key)
            .await
            .expect("pin direct-message recipient");
        sender
            .add_message(
                chat_id.to_string(),
                sender.identity_id.clone(),
                Some(recipient.identity_id.clone()),
                plaintext.to_string(),
            )
            .await
            .expect("queue encrypted direct message");
        let mut event = sender
            .pending_events()
            .await
            .into_iter()
            .rev()
            .find(|event| event.event_type == SyncEventType::MessageAdded)
            .expect("queued MessageAdded event");
        event
            .sign(&sender.private_key.to_bytes())
            .expect("sign outgoing direct-message event");
        SyncEnvelope::new(
            sender.identity_id.clone(),
            sender.public_key.clone(),
            vec![event],
        )
    }

    #[tokio::test]
    async fn e2ee_two_node_via_real_relay_roundtrip_and_relay_state_is_ciphertext_only() {
        let requester_key = [216; 32];
        let relay_key = [217; 32];
        let target_key = [218; 32];
        let requester = PeerRuntime::start(
            identity_for(&requester_key),
            requester_key,
            "e2ee-2d-requester".into(),
        )
        .await
        .expect("requester runtime");
        let relay = PeerRuntime::start(identity_for(&relay_key), relay_key, "e2ee-2d-relay".into())
            .await
            .expect("relay runtime");
        let target = PeerRuntime::start(
            identity_for(&target_key),
            target_key,
            "e2ee-2d-target".into(),
        )
        .await
        .expect("target runtime");

        requester
            .pin_peer(&relay.identity_id, &relay.public_key)
            .await
            .expect("pin relay at requester");
        relay
            .pin_peer(&requester.identity_id, &requester.public_key)
            .await
            .expect("pin requester at relay");
        relay
            .pin_peer(&target.identity_id, &target.public_key)
            .await
            .expect("pin target at relay");
        target
            .pin_peer(&relay.identity_id, &relay.public_key)
            .await
            .expect("pin relay at target");
        target
            .pin_peer(&requester.identity_id, &requester.public_key)
            .await
            .expect("pin requester at target");

        let now = current_unix_time();
        for peer in [&requester, &target] {
            let endpoint = EndpointRecord::create(
                peer.identity_id.clone(),
                peer.public_key.clone(),
                vec![peer.transport_address.clone()],
                &peer.private_key,
                now,
                crate::dht::ENDPOINT_TTL_SECONDS,
            )
            .expect("create endpoint record");
            relay
                .dht_cache
                .lock()
                .await
                .insert(endpoint)
                .expect("cache relay endpoint");
        }
        let (relay_work_tx, mut relay_work_rx) =
            mpsc::channel(crate::relay_service::RELAY_QUEUE_CAPACITY);
        *relay.ctx.relay_tx.lock().await = Some(relay_work_tx);

        let plaintext = "crypto2d secret hello";
        let inner_envelope =
            queue_encrypted_direct_message(&requester, &target, "crypto2d-chat", plaintext).await;
        let encrypted_event = &inner_envelope.events[0];
        let encrypted_payload: crate::MessageAddedPayload =
            serde_json::from_str(&encrypted_event.data).expect("parse V2 payload");
        assert_eq!(encrypted_payload.version, 2);
        assert!(encrypted_payload.text.is_none());

        let nonce = [221; 16];
        let (response_tx, response_rx) = oneshot::channel();
        requester
            .ctx
            .relay_tracker
            .lock()
            .await
            .insert(nonce, response_tx);
        let request = crate::relay::RelayRequest::create(
            requester.dht_local_id,
            target.dht_local_id,
            serde_json::to_vec(&inner_envelope).expect("serialize encrypted inner envelope"),
            crate::relay::RELAY_DEFAULT_TTL_SECS,
            now,
            Vec::new(),
            &requester.private_key,
            nonce,
        )
        .expect("create relay request");
        let mut request_event = SyncEvent::new(
            hex::encode(nonce),
            SyncEventType::RelayRequest,
            request.to_base64().expect("encode relay request"),
        );
        request_event
            .sign(&requester.private_key.to_bytes())
            .expect("sign relay request event");
        let request_envelope = SyncEnvelope::new(
            requester.identity_id.clone(),
            requester.public_key.clone(),
            vec![request_event],
        );
        crate::transport::send_envelope_secure_with_stream_kind(
            &relay.transport_address,
            &request_envelope,
            &requester.private_key,
            Arc::clone(&requester.ctx.hosts),
            None,
            requester.trust_policy.clone(),
            crate::mux::StreamKind::Sync,
        )
        .await
        .expect("send encrypted request to real relay runtime");

        let relay_work = tokio::time::timeout(Duration::from_secs(5), relay_work_rx.recv())
            .await
            .expect("relay work queue timeout")
            .expect("relay work sender closed");
        let relay_observed_bytes = relay_work.request.envelope_bytes.clone();
        let relay_observed_state = String::from_utf8_lossy(&relay_observed_bytes);
        assert!(
            !relay_observed_state.contains(plaintext),
            "P0 REGRESSION: relay work queue contains direct-message plaintext"
        );
        let relay_observed_envelope: SyncEnvelope =
            serde_json::from_slice(&relay_observed_bytes).expect("parse relay-observed envelope");
        let relay_observed_payload: crate::MessageAddedPayload =
            serde_json::from_str(&relay_observed_envelope.events[0].data)
                .expect("parse relay-observed ciphertext");
        assert_eq!(
            relay_observed_payload.ciphertext,
            encrypted_payload.ciphertext
        );
        assert!(
            relay_observed_payload
                .decrypt(&relay.private_key, &encrypted_event.id)
                .is_err(),
            "relay identity must not decrypt recipient ciphertext"
        );
        let relay_service = relay.relay_service().expect("real relay service");
        assert_eq!(
            relay_service.handle(relay_work, current_unix_time()).await,
            crate::relay::RelayResponse::Forwarded
        );

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), response_rx)
                .await
                .expect("relay response timeout")
                .expect("relay response sender dropped"),
            crate::relay::RelayResponse::Forwarded
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while target
                .ctx
                .relay_metrics
                .snapshot()
                .forward_received_total
                == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "target did not process real relay forward; relay={:?}, target_relay={:?}, target_abuse={:?}",
                relay.ctx.relay_metrics.snapshot(),
                target.ctx.relay_metrics.snapshot(),
                target.ctx.abuse_metrics.snapshot()
            )
        });
        assert_eq!(
            target.ctx.abuse_metrics.snapshot().messages_decrypted_total,
            1,
            "target must decrypt the addressed message"
        );

        assert!(!encrypted_event.data.contains(plaintext));
        assert_eq!(
            encrypted_payload
                .decrypt(&target.private_key, &encrypted_event.id)
                .expect("recipient decrypts forwarded message"),
            plaintext
        );

        let relay_state_dump = format!("{relay_observed_state:?}");
        assert!(
            !relay_state_dump.contains(plaintext),
            "P0 REGRESSION: relay runtime state contains direct-message plaintext"
        );
        let ciphertext_bytes = base64::engine::general_purpose::STANDARD
            .decode(encrypted_payload.ciphertext.as_deref().expect("ciphertext"))
            .expect("decode ciphertext");
        let ciphertext_as_text = String::from_utf8_lossy(&ciphertext_bytes);
        assert!(
            !relay_state_dump.contains(ciphertext_as_text.as_ref()),
            "relay message projection must not store ciphertext as display plaintext"
        );
        let metrics = target.ctx.abuse_metrics.snapshot();
        assert_eq!(metrics.messages_decrypted_total, 1);
        assert_eq!(metrics.messages_decrypt_failed_total, 0);
        assert_eq!(
            relay.ctx.abuse_metrics.snapshot().messages_decrypted_total,
            0
        );

        requester.stop().await.expect("stop requester");
        relay.stop().await.expect("stop relay");
        target.stop().await.expect("stop target");
    }

    #[tokio::test]
    async fn e2ee_third_party_cannot_decrypt_or_store_direct_message_text() {
        let sender_key = [222; 32];
        let recipient_key = [223; 32];
        let third_party_key = [224; 32];
        let (third_storage, third_path) = e2ee_test_storage(225);
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "e2ee-2d-third-sender".into(),
        )
        .await
        .expect("sender runtime");
        let recipient = PeerRuntime::start(
            identity_for(&recipient_key),
            recipient_key,
            "e2ee-2d-third-recipient".into(),
        )
        .await
        .expect("recipient runtime");
        let third_party = PeerRuntime::start_with_policy(
            identity_for(&third_party_key),
            third_party_key,
            "e2ee-2d-third-party".into(),
            Some(Arc::clone(&third_storage)),
            trusted_local_policy(),
        )
        .await
        .expect("third-party runtime");
        let plaintext = "third party must not read";
        let envelope =
            queue_encrypted_direct_message(&sender, &recipient, "third-party-chat", plaintext)
                .await;
        let event = envelope.events[0].clone();
        let payload: crate::MessageAddedPayload =
            serde_json::from_str(&event.data).expect("parse encrypted payload");
        assert!(payload
            .decrypt(&SigningKey::from_bytes(&third_party_key), &event.id)
            .is_err());

        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&third_party.ctx)).await;

        let third_party_messages = third_storage
            .lock()
            .expect("third-party storage lock")
            .messages_json("third-party-chat")
            .expect("read third-party messages");
        assert!(!third_party_messages.contains(plaintext));
        assert!(!third_party_messages.contains("ciphertext"));
        assert_eq!(
            third_party
                .ctx
                .abuse_metrics
                .snapshot()
                .messages_decrypted_total,
            0
        );
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
        third_party.stop().await.expect("stop third party");
        drop(third_storage);
        let _ = std::fs::remove_file(third_path);
    }

    #[tokio::test]
    async fn e2ee_v1_legacy_plaintext_remains_readable() {
        let sender_key = [226; 32];
        let recipient_key = [227; 32];
        let (recipient_storage, recipient_path) = e2ee_test_storage(228);
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            "e2ee-2d-v1-recipient".into(),
            Some(Arc::clone(&recipient_storage)),
            trusted_local_policy(),
        )
        .await
        .expect("recipient runtime");
        let payload = crate::MessageAddedPayload::new_legacy(
            "legacy-chat".into(),
            identity_for(&sender_key),
            Some(recipient.identity_id.clone()),
            "legacy hello".into(),
            current_unix_time(),
        );
        let mut event = SyncEvent::new(
            "e2ee-2d-legacy".into(),
            SyncEventType::MessageAdded,
            serde_json::to_string(&payload).expect("serialize V1 payload"),
        );
        event.sign(&sender_key).expect("sign legacy event");
        let envelope = SyncEnvelope::new(
            identity_for(&sender_key),
            test_pubkey(sender_key[0]),
            vec![event],
        );

        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&recipient.ctx)).await;

        let messages = recipient_storage
            .lock()
            .expect("recipient storage lock")
            .messages_json("legacy-chat")
            .expect("read legacy messages");
        assert!(messages.contains("legacy hello"));
        recipient.stop().await.expect("stop recipient");
        drop(recipient_storage);
        let _ = std::fs::remove_file(recipient_path);
    }

    #[tokio::test]
    async fn v2_first_event_replay_precheck_passes() {
        let sender_key = [250; 32];
        let recipient_key = [251; 32];
        let (storage, path) = e2ee_test_storage(252);
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "v2-precheck-first-sender".into(),
        )
        .await
        .expect("sender runtime");
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            "v2-precheck-first-recipient".into(),
            Some(Arc::clone(&storage)),
            trusted_local_policy(),
        )
        .await
        .expect("recipient runtime");
        let envelope =
            queue_encrypted_direct_message(&sender, &recipient, "precheck-first", "first").await;

        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&recipient.ctx)).await;

        let metrics = recipient.ctx.abuse_metrics.snapshot();
        assert_eq!(metrics.messages_decrypted_total, 1);
        assert_eq!(metrics.replay_precheck_total, 0);
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
        drop(storage);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn v2_duplicate_event_replay_precheck_rejected() {
        let sender_key = [253; 32];
        let recipient_key = [254; 32];
        let (storage, path) = e2ee_test_storage(255);
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "v2-precheck-duplicate-sender".into(),
        )
        .await
        .expect("sender runtime");
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            "v2-precheck-duplicate-recipient".into(),
            Some(Arc::clone(&storage)),
            trusted_local_policy(),
        )
        .await
        .expect("recipient runtime");
        let envelope = queue_encrypted_direct_message(
            &sender,
            &recipient,
            "precheck-duplicate",
            "decrypt once",
        )
        .await;

        PeerRuntime::process_incoming_envelope(envelope.clone(), Arc::clone(&recipient.ctx)).await;
        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&recipient.ctx)).await;

        let metrics = recipient.ctx.abuse_metrics.snapshot();
        assert_eq!(metrics.messages_decrypted_total, 1);
        assert_eq!(metrics.replay_precheck_total, 1);
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
        drop(storage);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn replay_precheck_no_storage_skips() {
        let sender_key = [1; 32];
        let recipient_key = [2; 32];
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "v2-precheck-memory-sender".into(),
        )
        .await
        .expect("sender runtime");
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            "v2-precheck-memory-recipient".into(),
            None,
            trusted_local_policy(),
        )
        .await
        .expect("recipient runtime");
        let envelope = queue_encrypted_direct_message(
            &sender,
            &recipient,
            "precheck-memory",
            "memory fallback",
        )
        .await;

        PeerRuntime::process_incoming_envelope(envelope.clone(), Arc::clone(&recipient.ctx)).await;
        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&recipient.ctx)).await;

        let metrics = recipient.ctx.abuse_metrics.snapshot();
        assert_eq!(metrics.messages_decrypted_total, 2);
        assert_eq!(metrics.replay_precheck_total, 0);
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
    }

    #[tokio::test]
    async fn e2ee_v2_wrong_recipient_is_rejected() {
        let sender_key = [229; 32];
        let recipient_key = [230; 32];
        let third_party_key = [231; 32];
        let (recipient_storage, recipient_path) = e2ee_test_storage(232);
        let (third_storage, third_path) = e2ee_test_storage(233);
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            "e2ee-2d-mismatch-recipient".into(),
            Some(Arc::clone(&recipient_storage)),
            trusted_local_policy(),
        )
        .await
        .expect("recipient runtime");
        let third_party = PeerRuntime::start_with_policy(
            identity_for(&third_party_key),
            third_party_key,
            "e2ee-2d-mismatch-third".into(),
            Some(Arc::clone(&third_storage)),
            trusted_local_policy(),
        )
        .await
        .expect("third-party runtime");
        let event_id = "e2ee-2d-mismatch";
        let mut payload = crate::MessageAddedPayload::new_encrypted(
            "mismatch-chat".into(),
            identity_for(&sender_key),
            recipient.identity_id.clone(),
            &SigningKey::from_bytes(&recipient_key).verifying_key(),
            "mismatch secret",
            current_unix_time(),
            event_id,
        )
        .expect("encrypt for recipient");
        payload.recipient_id = Some(third_party.identity_id.clone());
        let mut event = SyncEvent::new(
            event_id.into(),
            SyncEventType::MessageAdded,
            serde_json::to_string(&payload).expect("serialize mismatched payload"),
        );
        event.sign(&sender_key).expect("sign mismatched event");
        let envelope = SyncEnvelope::new(
            identity_for(&sender_key),
            test_pubkey(sender_key[0]),
            vec![event],
        );
        let third_envelope = envelope.clone();
        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&recipient.ctx)).await;
        PeerRuntime::process_incoming_envelope(third_envelope, Arc::clone(&third_party.ctx)).await;

        assert_eq!(
            third_party
                .ctx
                .abuse_metrics
                .snapshot()
                .messages_decrypt_failed_total,
            1
        );
        assert!(!recipient_storage
            .lock()
            .expect("recipient storage lock")
            .messages_json("mismatch-chat")
            .expect("read recipient messages")
            .contains("mismatch secret"));
        assert!(!third_storage
            .lock()
            .expect("third-party storage lock")
            .messages_json("mismatch-chat")
            .expect("read third-party messages")
            .contains("mismatch secret"));
        recipient.stop().await.expect("stop recipient");
        third_party.stop().await.expect("stop third party");
        drop(recipient_storage);
        drop(third_storage);
        let _ = std::fs::remove_file(recipient_path);
        let _ = std::fs::remove_file(third_path);
    }

    #[tokio::test]
    async fn e2ee_tampered_ciphertext_is_rejected_and_counted() {
        use base64::Engine;

        let sender_key = [234; 32];
        let recipient_key = [235; 32];
        let (recipient_storage, recipient_path) = e2ee_test_storage(236);
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "e2ee-2d-tamper-sender".into(),
        )
        .await
        .expect("sender runtime");
        let recipient = PeerRuntime::start_with_policy(
            identity_for(&recipient_key),
            recipient_key,
            "e2ee-2d-tamper-recipient".into(),
            Some(Arc::clone(&recipient_storage)),
            trusted_local_policy(),
        )
        .await
        .expect("recipient runtime");
        let mut envelope =
            queue_encrypted_direct_message(&sender, &recipient, "tampered-chat", "tamper secret")
                .await;
        let tampered_event = &mut envelope.events[0];
        let mut payload: crate::MessageAddedPayload =
            serde_json::from_str(&tampered_event.data).expect("parse encrypted payload");
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(payload.ciphertext.as_deref().expect("ciphertext"))
            .expect("decode ciphertext");
        let mut corrupted = ciphertext;
        let last = corrupted.last_mut().expect("non-empty ciphertext");
        *last ^= 1;
        payload.ciphertext = Some(base64::engine::general_purpose::STANDARD.encode(corrupted));
        tampered_event.data = serde_json::to_string(&payload).expect("serialize tampered payload");
        tampered_event
            .sign(&sender_key)
            .expect("sign tampered event for authenticated test input");

        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&recipient.ctx)).await;

        assert_eq!(
            recipient
                .ctx
                .abuse_metrics
                .snapshot()
                .messages_decrypt_failed_total,
            1
        );
        assert!(!recipient_storage
            .lock()
            .expect("recipient storage lock")
            .messages_json("tampered-chat")
            .expect("read recipient messages")
            .contains("tamper secret"));
        sender.stop().await.expect("stop sender");
        recipient.stop().await.expect("stop recipient");
        drop(recipient_storage);
        let _ = std::fs::remove_file(recipient_path);
    }

    #[tokio::test]
    async fn add_message_encrypts_payload_and_relay_forward_hides_plaintext() {
        let sender_key = [211; 32];
        let recipient_key = [212; 32];
        let sender = PeerRuntime::start(
            identity_for(&sender_key),
            sender_key,
            "encrypted-message-wire".into(),
        )
        .await
        .expect("start sender");
        let recipient_id = identity_for(&recipient_key);
        sender
            .pin_peer(&recipient_id, &test_pubkey(recipient_key[0]))
            .await
            .expect("pin recipient");
        let plaintext = "sensitive direct message";
        sender
            .add_message(
                "encrypted-chat".into(),
                sender.identity_id.clone(),
                Some(recipient_id),
                plaintext.into(),
            )
            .await
            .expect("queue encrypted message");

        let events = sender.pending_events().await;
        let message = events
            .iter()
            .find(|event| event.event_type == SyncEventType::MessageAdded)
            .expect("queued MessageAdded event");
        let message_json: serde_json::Value =
            serde_json::from_str(&message.data).expect("message payload JSON");
        assert_eq!(message_json["version"], 2);
        assert!(message_json["ciphertext"]
            .as_str()
            .is_some_and(|v| !v.is_empty()));
        assert!(message_json.get("text").is_none());
        assert!(!message.data.contains(plaintext));

        let inner = SyncEnvelope::new(
            sender.identity_id.clone(),
            sender.public_key.clone(),
            events,
        );
        let relay = relay_forward_envelope(
            &SigningKey::from_bytes(&[213; 32]),
            &inner,
            [214; 16],
            "test-consent".into(),
        );
        let relay_state = serde_json::to_string(&relay).expect("serialize relay envelope");
        assert!(!relay_state.contains(plaintext));
        let forward_bytes = base64::engine::general_purpose::STANDARD
            .decode(&relay.events[0].data)
            .expect("decode relay forward");
        let forward: serde_json::Value =
            serde_json::from_slice(&forward_bytes).expect("parse relay forward");
        let inner_bytes = base64::engine::general_purpose::STANDARD
            .decode(
                forward["inner_envelope_base64"]
                    .as_str()
                    .expect("inner envelope"),
            )
            .expect("decode inner envelope");
        let inner_state = String::from_utf8(inner_bytes).expect("inner envelope UTF-8");
        assert!(!inner_state.contains(plaintext));
        assert!(inner_state.contains("ciphertext"));
        assert_eq!(
            sender.ctx.abuse_metrics.snapshot().messages_encrypted_total,
            1
        );
        assert_eq!(
            sender
                .ctx
                .abuse_metrics
                .snapshot()
                .messages_sent_plaintext_total,
            0
        );

        let unknown_id = identity_for(&[215; 32]);
        let queued_before = sender.pending_events().await.len();
        let error = sender
            .add_message(
                "encrypted-chat".into(),
                sender.identity_id.clone(),
                Some(unknown_id),
                plaintext.into(),
            )
            .await
            .expect_err("unknown recipient must not fall back to plaintext");
        assert!(error.to_string().contains("public key is unknown"));
        assert_eq!(sender.pending_events().await.len(), queued_before);
        sender.stop().await.expect("stop sender");
    }

    fn test_relay_service(runtime: &PeerRuntime) -> Arc<RelayService> {
        runtime.relay_service().expect("relay service")
    }

    fn trusted_local_policy() -> NetworkScanPolicy {
        NetworkScanPolicy {
            trust: NetworkTrustPolicy {
                local_level: 100,
                external_level: 0,
            },
            ..NetworkScanPolicy::default()
        }
    }

    #[test]
    fn peer_address_candidates_support_multi_route_lists() {
        let addresses =
            peer_address_candidates("[2001:db8::1]:9000, 192.168.1.10:9000; relay.example.com:443");
        assert_eq!(
            addresses,
            vec![
                "[2001:db8::1]:9000",
                "192.168.1.10:9000",
                "relay.example.com:443"
            ]
        );
    }

    #[test]
    fn candidate_transport_addresses_prefer_ipv6_then_ipv4() {
        let candidates = candidate_transport_addresses("9000");
        assert!(candidates
            .iter()
            .all(|address| address.ends_with(":9000") || address.ends_with("]:9000")));
        assert!(candidates.iter().all(|address| address
            .parse::<SocketAddr>()
            .is_ok_and(|socket| !socket.ip().is_loopback() && !socket.ip().is_unspecified())));

        if !candidates.is_empty() {
            let has_ipv6 = candidates.iter().any(|address| address.starts_with('['));
            if has_ipv6 {
                assert!(
                    candidates[0].starts_with('[')
                        && candidates[0].contains("]:")
                        && candidates[0].ends_with(":9000")
                );
            } else {
                assert!(candidates[0]
                    .parse::<SocketAddr>()
                    .is_ok_and(|socket| socket.is_ipv4()));
            }
        }
    }

    #[test]
    fn invite_address_selects_lan_and_rejects_wan_or_loopback_only() {
        let candidates = vec![
            "188.163.83.204:4001".to_string(),
            "192.168.0.234:4001".to_string(),
        ];
        assert_eq!(
            select_lan_invite_address(&candidates).expect("LAN address"),
            "192.168.0.234:4001"
        );
        assert!(select_lan_invite_address(&["188.163.83.204:4001".to_string()]).is_err());
        assert!(select_lan_invite_address(&["127.0.0.1:4001".to_string()]).is_err());
    }

    #[test]
    fn invite_address_prefers_physical_interfaces_over_tunnels() {
        assert!(lan_interface_rank("wlp0s20f3") < lan_interface_rank("CloudflareWARP"));
        assert!(lan_interface_rank("enp1s0") < lan_interface_rank("wg0"));
    }

    #[test]
    fn link_request_roundtrip_via_event() {
        let key = [41; 32];
        let signing_key = SigningKey::from_bytes(&key);
        let mut request = crate::LinkRequest::new(
            hex::encode(signing_key.verifying_key().to_bytes()),
            crate::DeviceRole::Mobile,
            crate::DeviceCapabilities::default(),
            "runtime-token".into(),
        );
        request.sign(&signing_key);
        let event = crate::SyncEvent::new(
            uuid::Uuid::new_v4().to_string(),
            crate::SyncEventType::HomeLinkRequest,
            serde_json::to_string(&request).expect("request json"),
        );
        let decoded: crate::LinkRequest =
            serde_json::from_str(&event.data).expect("decode request");
        assert!(decoded.verify().is_ok());
    }

    #[tokio::test]
    async fn approve_link_request_produces_valid_response() {
        let primary_key = [42; 32];
        let new_key = [43; 32];
        let (storage, storage_path) = open_auto_badge_storage();
        let primary = PeerRuntime::start_with_policy(
            identity_for(&primary_key),
            primary_key,
            "primary-approve".into(),
            Some(Arc::clone(&storage)),
            trusted_local_policy(),
        )
        .await
        .expect("primary");
        let mut new_device = PeerRuntime::start_with_policy(
            identity_for(&new_key),
            new_key,
            "new-approve".into(),
            None,
            trusted_local_policy(),
        )
        .await
        .expect("new device");
        new_device
            .activate_listener(None, None)
            .await
            .expect("new listener");
        primary
            .pin_peer(&new_device.identity_id, &new_device.public_key)
            .await
            .expect("pin new");
        new_device
            .pin_peer(&primary.identity_id, &primary.public_key)
            .await
            .expect("pin primary");

        let new_signing_key = SigningKey::from_bytes(&new_key);
        let mut request = crate::LinkRequest::new(
            hex::encode(new_signing_key.verifying_key().to_bytes()),
            crate::DeviceRole::Mobile,
            crate::DeviceCapabilities::default(),
            "approve-token".into(),
        );
        request.sign(&new_signing_key);
        let nonce = request.nonce.clone();
        primary.ctx.home_state.lock().await.pending_requests.insert(
            nonce.clone(),
            PendingLinkRequest {
                request,
                remote_addr: Some(
                    new_device
                        .transport_address
                        .parse()
                        .expect("new device transport address"),
                ),
            },
        );
        let secret = crate::HomeSecret::generate();
        let stack = crate::HomeStack::new("approve-stack".into(), primary.identity_id.clone());

        let updated = primary
            .approve_link_request(
                &nonce,
                &new_device.transport_address,
                secret.clone(),
                stack,
                vec![],
            )
            .await
            .expect("approve");
        assert!(updated.has_link_nonce(&nonce));
        tokio::time::sleep(Duration::from_millis(30)).await;
        let responses = new_device.take_link_responses().await;
        assert_eq!(responses.len(), 1);
        let opened = responses[0]
            .open_secret(&new_signing_key)
            .expect("open response");
        assert_eq!(opened.as_bytes(), secret.as_bytes());
        assert!(primary.pending_link_requests().await.is_empty());

        let mut relink_request = crate::LinkRequest::new(
            hex::encode(new_signing_key.verifying_key().to_bytes()),
            crate::DeviceRole::Mobile,
            crate::DeviceCapabilities::default(),
            "approve-token-relink".into(),
        );
        relink_request.sign(&new_signing_key);
        let relink_nonce = relink_request.nonce.clone();
        primary.ctx.home_state.lock().await.pending_requests.insert(
            relink_nonce.clone(),
            PendingLinkRequest {
                request: relink_request,
                remote_addr: Some(
                    new_device
                        .transport_address
                        .parse()
                        .expect("new device transport address"),
                ),
            },
        );
        let relinked = primary
            .approve_link_request(
                &relink_nonce,
                &new_device.transport_address,
                secret.clone(),
                updated.clone(),
                updated.devices.values().cloned().collect(),
            )
            .await
            .expect("relink already-linked device");
        assert!(relinked.has_link_nonce(&relink_nonce));
        assert_eq!(
            relinked
                .devices
                .values()
                .filter(|device| device.device_pubkey
                    == hex::encode(new_signing_key.verifying_key().to_bytes()))
                .count(),
            1
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(new_device.take_link_responses().await.len(), 1);

        primary.stop().await.expect("stop primary");
        new_device.stop().await.expect("stop new");
        drop(storage);
        let _ = std::fs::remove_file(storage_path);
    }

    #[tokio::test]
    async fn home_sync_worker_replicates_new_messages_both_directions_and_acks() {
        let (primary_storage, primary_path) = open_auto_badge_storage();
        let (secondary_storage, secondary_path) = open_auto_badge_storage();
        let primary_key = [52; 32];
        let secondary_key = [53; 32];
        let mut primary = PeerRuntime::start_with_policy(
            identity_for(&primary_key),
            primary_key,
            "home-sync-primary".into(),
            Some(Arc::clone(&primary_storage)),
            trusted_local_policy(),
        )
        .await
        .expect("primary runtime");
        let mut secondary = PeerRuntime::start_with_policy(
            identity_for(&secondary_key),
            secondary_key,
            "home-sync-secondary".into(),
            Some(Arc::clone(&secondary_storage)),
            trusted_local_policy(),
        )
        .await
        .expect("secondary runtime");
        primary
            .activate_listener(None, None)
            .await
            .expect("activate primary listener");
        secondary
            .activate_listener(None, None)
            .await
            .expect("activate secondary listener");
        primary
            .pin_peer(&secondary.identity_id, &secondary.public_key)
            .await
            .expect("pin secondary");
        secondary
            .pin_peer(&primary.identity_id, &primary.public_key)
            .await
            .expect("pin primary");

        let now = unix_now();
        primary
            .ctx
            .peer_directory
            .lock()
            .await
            .record_invite(
                secondary.transport_address.clone(),
                secondary.identity_id.clone(),
                secondary.public_key.clone(),
                now,
            )
            .expect("record secondary address");
        secondary
            .ctx
            .peer_directory
            .lock()
            .await
            .record_invite(
                primary.transport_address.clone(),
                primary.identity_id.clone(),
                primary.public_key.clone(),
                now,
            )
            .expect("record primary address");

        let stack_id = "home-sync-stack".to_string();
        let mut stack = HomeStack::new(stack_id.clone(), primary.identity_id.clone());
        stack
            .add_device(DeviceInfo {
                device_id: primary.identity_id.clone(),
                device_pubkey: primary.public_key.clone(),
                stack_id: stack_id.clone(),
                added_at: now,
                added_by: primary.identity_id.clone(),
                role: crate::DeviceRole::Primary,
                last_seen: now,
                capabilities: crate::DeviceCapabilities::default(),
            })
            .expect("add primary device");
        stack
            .add_device(DeviceInfo {
                device_id: secondary.identity_id.clone(),
                device_pubkey: secondary.public_key.clone(),
                stack_id,
                added_at: now,
                added_by: primary.identity_id.clone(),
                role: crate::DeviceRole::Secondary,
                last_seen: now,
                capabilities: crate::DeviceCapabilities::default(),
            })
            .expect("add secondary device");
        let home_secret = HomeSecret::generate();
        primary
            .register_home_stack(&stack, home_secret.clone())
            .await
            .expect("register primary Home Stack");
        secondary
            .register_home_stack(&stack, home_secret)
            .await
            .expect("register secondary Home Stack");

        assert_eq!(
            primary
                .update_home_sync_draft("shared-chat", "draft from primary")
                .await
                .expect("send draft update"),
            1
        );
        let mut received_draft = None;
        for _ in 0..20 {
            received_draft = secondary_storage
                .lock()
                .expect("secondary storage lock")
                .home_sync_draft("shared-chat")
                .expect("read replicated draft");
            if received_draft
                .as_ref()
                .is_some_and(|draft| draft.text == "draft from primary")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            received_draft.expect("draft received").text,
            "draft from primary"
        );

        primary_storage
            .lock()
            .expect("primary storage lock")
            .save_text_message_with_id(
                "message-from-primary",
                "shared-chat",
                "primary",
                "first message",
                None,
            )
            .expect("save primary message");
        let mut primary_revision = None;
        let mut primary_chunks = Vec::new();
        home_sync_worker_tick(
            &primary.ctx,
            &primary.identity_id,
            &primary.public_key,
            &primary.private_key,
            &primary.ctx.hosts,
            &primary.trust_policy,
            &mut primary_revision,
            &mut primary_chunks,
        )
        .await
        .expect("push primary snapshot");
        tokio::time::sleep(Duration::from_millis(150)).await;

        let imported_primary_message: String = secondary_storage
            .lock()
            .expect("secondary storage lock")
            .connection()
            .query_row(
                "SELECT content FROM messages WHERE id = 'message-from-primary'",
                [],
                |row| row.get(0),
            )
            .expect("primary message imported");
        assert_eq!(imported_primary_message, "first message");

        let mut secondary_revision = None;
        let mut secondary_chunks = Vec::new();
        home_sync_worker_tick(
            &secondary.ctx,
            &secondary.identity_id,
            &secondary.public_key,
            &secondary.private_key,
            &secondary.ctx.hosts,
            &secondary.trust_policy,
            &mut secondary_revision,
            &mut secondary_chunks,
        )
        .await
        .expect("ack primary snapshot");
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(primary_storage
            .lock()
            .expect("primary storage lock")
            .pending_home_sync_outbox(unix_now())
            .expect("read primary outbox")
            .is_empty());

        secondary_storage
            .lock()
            .expect("secondary storage lock")
            .save_text_message_with_id(
                "message-from-secondary",
                "shared-chat",
                "secondary",
                "second message",
                None,
            )
            .expect("save secondary message");
        home_sync_worker_tick(
            &secondary.ctx,
            &secondary.identity_id,
            &secondary.public_key,
            &secondary.private_key,
            &secondary.ctx.hosts,
            &secondary.trust_policy,
            &mut secondary_revision,
            &mut secondary_chunks,
        )
        .await
        .expect("push secondary delta snapshot");
        tokio::time::sleep(Duration::from_millis(150)).await;
        let imported_secondary_message: String = primary_storage
            .lock()
            .expect("primary storage lock")
            .connection()
            .query_row(
                "SELECT content FROM messages WHERE id = 'message-from-secondary'",
                [],
                |row| row.get(0),
            )
            .expect("secondary message imported");
        assert_eq!(imported_secondary_message, "second message");

        home_sync_worker_tick(
            &primary.ctx,
            &primary.identity_id,
            &primary.public_key,
            &primary.private_key,
            &primary.ctx.hosts,
            &primary.trust_policy,
            &mut primary_revision,
            &mut primary_chunks,
        )
        .await
        .expect("ack secondary snapshot");
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(secondary_storage
            .lock()
            .expect("secondary storage lock")
            .pending_home_sync_outbox(unix_now())
            .expect("read secondary outbox")
            .is_empty());

        primary.stop().await.expect("stop primary");
        secondary.stop().await.expect("stop secondary");
        drop(primary_storage);
        drop(secondary_storage);
        let _ = std::fs::remove_file(primary_path);
        let _ = std::fs::remove_file(secondary_path);
    }

    #[tokio::test]
    async fn reject_link_request_removes_from_pending() {
        let key = [44; 32];
        let runtime = PeerRuntime::start(identity_for(&key), key, "reject-home".into())
            .await
            .expect("runtime");
        let signing_key = SigningKey::from_bytes(&key);
        let mut request = crate::LinkRequest::new(
            hex::encode(signing_key.verifying_key().to_bytes()),
            crate::DeviceRole::Mobile,
            crate::DeviceCapabilities::default(),
            "reject-token".into(),
        );
        request.sign(&signing_key);
        let nonce = request.nonce.clone();
        runtime.ctx.home_state.lock().await.pending_requests.insert(
            nonce.clone(),
            PendingLinkRequest {
                request,
                remote_addr: None,
            },
        );
        runtime.reject_link_request(&nonce).await.expect("reject");
        assert!(runtime.pending_link_requests().await.is_empty());
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn initiate_linking_sends_event() {
        let sender_key = [45; 32];
        let primary_key = [46; 32];
        let mut sender = PeerRuntime::start_with_policy(
            identity_for(&sender_key),
            sender_key,
            "sender-home".into(),
            None,
            trusted_local_policy(),
        )
        .await
        .expect("sender");
        let mut primary = PeerRuntime::start_with_policy(
            identity_for(&primary_key),
            primary_key,
            "primary-home".into(),
            None,
            trusted_local_policy(),
        )
        .await
        .expect("primary");
        sender
            .activate_listener(None, None)
            .await
            .expect("sender listener");
        primary
            .activate_listener(None, None)
            .await
            .expect("primary listener");
        primary
            .pin_peer(&sender.identity_id, &sender.public_key)
            .await
            .expect("pin sender");
        let signing_key = SigningKey::from_bytes(&sender_key);
        let mut request = crate::LinkRequest::new(
            hex::encode(signing_key.verifying_key().to_bytes()),
            crate::DeviceRole::Mobile,
            crate::DeviceCapabilities::default(),
            "initiate-token".into(),
        );
        request.sign(&signing_key);
        let nonce = request.nonce.clone();
        sender
            .initiate_linking(&primary.transport_address, request)
            .await
            .expect("initiate");
        let received = wait_until(
            || async {
                primary
                    .pending_link_requests()
                    .await
                    .iter()
                    .any(|request| request.nonce == nonce)
            },
            Duration::from_secs(2),
        )
        .await;
        assert!(received, "link request did not arrive within 2s");
        let requests = primary.pending_link_requests().await;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].nonce, nonce);
        assert!(requests[0].remote_addr.is_some());
        sender.stop().await.expect("stop sender");
        primary.stop().await.expect("stop primary");
    }
    #[tokio::test]
    async fn transport_stigma_gate_rejects_under_stigma() {
        let local_key = [203; 32];
        let peer_key = [204; 32];
        let local = PeerRuntime::start(
            identity_for(&local_key),
            local_key,
            "stigma-gate-local".into(),
        )
        .await
        .expect("local runtime");
        let peer = PeerRuntime::start(identity_for(&peer_key), peer_key, "stigma-gate-peer".into())
            .await
            .expect("peer runtime");
        local
            .pin_peer(&peer.identity_id, &peer.public_key)
            .await
            .expect("pin peer");
        peer.pin_peer(&local.identity_id, &local.public_key)
            .await
            .expect("pin local");
        let peer_id = NodeId::from_public_key(&SigningKey::from_bytes(&peer_key).verifying_key());
        local.ctx.stigma_cache.update(
            peer_id,
            StigmaLevel::Stigma {
                weight: 2.0,
                badge_count: 3,
                since: unix_now(),
            },
        );
        peer.add_message(
            "stigma-gate-chat".into(),
            peer.identity_id.clone(),
            Some(local.identity_id.clone()),
            "blocked".into(),
        )
        .await
        .expect("add pending message");
        let _ = peer
            .send_pending_verified(&local.transport_address, &local.public_key)
            .await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while local
                .ctx
                .abuse_metrics
                .snapshot()
                .transport_stigma_rejected_total
                == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("transport rejection metric timeout");
        assert_eq!(
            local
                .ctx
                .abuse_metrics
                .snapshot()
                .transport_stigma_rejected_total,
            1
        );
        assert_eq!(
            local
                .ctx
                .trust_metrics
                .snapshot()
                .envelope_warm_received_total,
            0
        );
        local.stop().await.expect("stop local");
        peer.stop().await.expect("stop peer");
    }

    #[tokio::test]
    async fn transport_stigma_gate_allows_clean() {
        let local_key = [205; 32];
        let peer_key = [206; 32];
        let local = PeerRuntime::start(
            identity_for(&local_key),
            local_key,
            "stigma-clean-local".into(),
        )
        .await
        .expect("local runtime");
        let peer = PeerRuntime::start(
            identity_for(&peer_key),
            peer_key,
            "stigma-clean-peer".into(),
        )
        .await
        .expect("peer runtime");
        local
            .pin_peer(&peer.identity_id, &peer.public_key)
            .await
            .expect("pin peer");
        peer.pin_peer(&local.identity_id, &local.public_key)
            .await
            .expect("pin local");
        peer.add_message(
            "stigma-clean-chat".into(),
            peer.identity_id.clone(),
            Some(local.identity_id.clone()),
            "accepted".into(),
        )
        .await
        .expect("add pending message");
        peer.send_pending_verified(&local.transport_address, &local.public_key)
            .await
            .expect("clean peer should be accepted");
        tokio::time::timeout(Duration::from_secs(1), async {
            while local
                .ctx
                .trust_metrics
                .snapshot()
                .envelope_warm_received_total
                == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("clean envelope receive timeout");
        assert_eq!(
            local
                .ctx
                .abuse_metrics
                .snapshot()
                .transport_stigma_rejected_total,
            0
        );
        local.stop().await.expect("stop local");
        peer.stop().await.expect("stop peer");
    }

    #[tokio::test]
    async fn publish_badge_updates_stigma_cache() {
        use crate::dht::badge::{Badge, BadgeContext, BadgeKind, BADGE_REFLECTION_PERIOD_SECS};

        let local_seed = [207; 32];
        let local_key = SigningKey::from_bytes(&local_seed);
        let local_id = NodeId::from_public_key(&local_key.verifying_key());
        let runtime =
            PeerRuntime::start(local_id.to_hex(), local_seed, "stigma-publish-cache".into())
                .await
                .expect("runtime");
        runtime
            .pin_peer(
                &local_id.to_hex(),
                &hex::encode(local_key.verifying_key().to_bytes()),
            )
            .await
            .expect("pin issuer");
        let subject_key = SigningKey::from_bytes(&[208; 32]);
        let subject = NodeId::from_public_key(&subject_key.verifying_key());
        let now = unix_now();
        let badge = Badge::create(
            9201,
            subject,
            None,
            BadgeKind::Spammer,
            vec!["publish-cache-evidence".into()],
            BadgeContext::ColdContact,
            "publish cache test".into(),
            local_id,
            now.saturating_sub(BADGE_REFLECTION_PERIOD_SECS + 1),
            None,
            &local_key,
        )
        .expect("create badge");
        runtime.publish_badge(badge).await.expect("publish badge");
        assert!(runtime.ctx.stigma_cache.is_stigmatized(&subject));
        runtime.stop().await.expect("stop runtime");
    }

    #[tokio::test]
    async fn two_independent_runtimes_exchange_sync_events() {
        let key_a = [31; 32];
        let key_b = [32; 32];
        let mut a = PeerRuntime::start(identity_for(&key_a), key_a, "android".into())
            .await
            .expect("runtime a");
        let mut b = PeerRuntime::start(identity_for(&key_b), key_b, "desktop".into())
            .await
            .expect("runtime b");
        a.activate_listener(None, None)
            .await
            .expect("activate a listener");
        b.activate_listener(None, None)
            .await
            .expect("activate b listener");
        b.pin_peer(&a.identity_id, &a.public_key)
            .await
            .expect("pin peer");
        a.pin_peer(&b.identity_id, &b.public_key)
            .await
            .expect("pin peer");
        a.add_contact(test_pubkey(1), "A".into())
            .await
            .expect("contact");
        a.send_pending_verified(&b.transport_address, &b.public_key)
            .await
            .expect("sync");
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while b.contact_count().await != 1 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("contact delivery timeout");
        assert_eq!(b.contact_count().await, 1);
        a.stop().await.expect("stop a");
        b.stop().await.expect("stop b");
    }

    #[tokio::test]
    async fn set_dht_config_validates() {
        let runtime = PeerRuntime::start(identity_for(&[39; 32]), [39; 32], "dht-config".into())
            .await
            .expect("runtime");
        let invalid = DhtPollerConfig {
            max_parallel: 0,
            ..DhtPollerConfig::default()
        };
        assert!(runtime.set_dht_config(invalid).await.is_err());

        let valid = DhtPollerConfig::aggressive();
        assert!(runtime.set_dht_config(valid).await.is_ok());
        assert_eq!(
            runtime.dht_config().await.profile,
            crate::dht::DhtProfile::Aggressive
        );
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn worker_uses_config_max_parallel() {
        let runtime = PeerRuntime::start(identity_for(&[40; 32]), [40; 32], "dht-worker".into())
            .await
            .expect("runtime");
        let config = DhtPollerConfig {
            max_parallel: 12,
            ..DhtPollerConfig::default()
        };
        runtime
            .set_dht_config(config.clone())
            .await
            .expect("config");
        assert_eq!(runtime.dht_config().await.max_parallel, 12);
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn banned_envelope_increments_metric() {
        let sender_key = [70; 32];
        let sender_signing = SigningKey::from_bytes(&sender_key);
        let sender_pubkey = hex::encode(sender_signing.verifying_key().to_bytes());
        let node_id = NodeId::from_public_key(&sender_signing.verifying_key());
        let scores = Arc::new(StdMutex::new(TrustScoreManager::new()));
        let rates = Arc::new(StdMutex::new(RateLimiter::new()));
        let hosts = Arc::new(std::sync::Mutex::new(KnownHosts::new()));
        let groups: Arc<dyn GroupGraph> = Arc::new(GroupRegistry::new());
        let oracle: Arc<dyn TrustOracle> = Arc::new(BasicTrustOracle::new(
            Arc::clone(&scores),
            Arc::clone(&rates),
            Arc::clone(&hosts),
            Arc::clone(&groups),
        ));
        let sync = Arc::new(Mutex::new(SyncManager::new("ban-check".into())));
        let home_state = Arc::new(Mutex::new(HomeRuntimeState::default()));
        let media_signals = Arc::new(Mutex::new(Vec::new()));
        let (relay_tx, relay_tracker, relay_metrics) = RuntimeContext::default_relay_channels();
        let (badge_store, badge_metrics) = RuntimeContext::default_badge_components();
        let (cold_contact_tracker, auto_badge_queue, abuse_metrics) =
            RuntimeContext::default_abuse_channels();
        let ctx = Arc::new(RuntimeContext {
            sync: Arc::clone(&sync),
            home_state: Arc::clone(&home_state),
            media_signals: Arc::clone(&media_signals),
            storage: None,
            age_tracker: None,
            activity_tracker: None,
            proof_of_live: None,
            hosts: Arc::clone(&hosts),
            scores: Arc::clone(&scores),
            rates: Arc::clone(&rates),
            trust_graph: None,
            groups: Arc::clone(&groups),
            trust_metrics: Arc::new(TrustMetrics::new()),
            oracle: Arc::clone(&oracle),
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
            invite_registry: RuntimeContext::default_invite_registry(),
            degradation: RuntimeContext::default_degradation(),
            stigma_cache: RuntimeContext::default_stigma_cache(),
            inbound_observations_tx: RuntimeContext::default_inbound_observations(),
            badge_store,
            badge_metrics,
            badge_fetch_shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cold_contact_tracker,
            auto_badge_queue,
            abuse_metrics,
            identity_id: "local-id".to_string(),
            public_key: "local-pub".to_string(),
            identity_signing_key: None,
            jury_commitment_publisher: None,
            jury_plaintext_cache: RuntimeContext::default_jury_plaintext_cache(),
            invite_redemption_transport: None,
            pending_invite_redemptions: RuntimeContext::default_pending_invite_redemptions(),
            sas_pairing: RuntimeContext::default_sas_pairing(),
            integrity: None,
        });

        scores.lock().unwrap().penalize(&node_id, 100, "bad", 1000);
        let envelope = SyncEnvelope::new(identity_for(&sender_key), sender_pubkey, Vec::new());
        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&ctx)).await;

        assert!(ctx.oracle.is_banned(&node_id, 1000));
        assert_eq!(ctx.trust_metrics.snapshot().denies_banned, 1);
        assert_eq!(sync.lock().await.get_pending_events().len(), 0);
    }

    #[tokio::test]
    async fn conflicted_envelope_increments_metric() {
        let pinned_key = SigningKey::from_bytes(&[73; 32]);
        let conflicting_key = SigningKey::from_bytes(&[74; 32]);
        let identity_id = identity_for(&[74; 32]);
        let hosts = Arc::new(std::sync::Mutex::new(KnownHosts::new()));
        hosts
            .lock()
            .unwrap()
            .pin_manual(
                &identity_id,
                &hex::encode(pinned_key.verifying_key().to_bytes()),
                1_000,
            )
            .expect("pin host");
        let scores = Arc::new(StdMutex::new(TrustScoreManager::new()));
        let rates = Arc::new(StdMutex::new(RateLimiter::new()));
        let groups: Arc<dyn GroupGraph> = Arc::new(GroupRegistry::new());
        let oracle: Arc<dyn TrustOracle> = Arc::new(BasicTrustOracle::new(
            Arc::clone(&scores),
            Arc::clone(&rates),
            Arc::clone(&hosts),
            Arc::clone(&groups),
        ));
        let trust_metrics = Arc::new(TrustMetrics::new());
        let (relay_tx, relay_tracker, relay_metrics) = RuntimeContext::default_relay_channels();
        let (badge_store, badge_metrics) = RuntimeContext::default_badge_components();
        let (cold_contact_tracker, auto_badge_queue, abuse_metrics) =
            RuntimeContext::default_abuse_channels();
        let ctx = Arc::new(RuntimeContext {
            sync: Arc::new(Mutex::new(SyncManager::new("conflict-check".into()))),
            home_state: Arc::new(Mutex::new(HomeRuntimeState::default())),
            media_signals: Arc::new(Mutex::new(Vec::new())),
            storage: None,
            age_tracker: None,
            activity_tracker: None,
            proof_of_live: None,
            hosts: Arc::clone(&hosts),
            scores,
            rates,
            trust_graph: None,
            groups,
            trust_metrics: Arc::clone(&trust_metrics),
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
            invite_registry: RuntimeContext::default_invite_registry(),
            degradation: RuntimeContext::default_degradation(),
            stigma_cache: RuntimeContext::default_stigma_cache(),
            inbound_observations_tx: RuntimeContext::default_inbound_observations(),
            badge_store,
            badge_metrics,
            badge_fetch_shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cold_contact_tracker,
            auto_badge_queue,
            abuse_metrics,
            identity_id: "local-id".to_string(),
            public_key: "local-pub".to_string(),
            identity_signing_key: None,
            jury_commitment_publisher: None,
            jury_plaintext_cache: RuntimeContext::default_jury_plaintext_cache(),
            invite_redemption_transport: None,
            pending_invite_redemptions: RuntimeContext::default_pending_invite_redemptions(),
            sas_pairing: RuntimeContext::default_sas_pairing(),
            integrity: None,
        });

        let envelope = SyncEnvelope::new(
            identity_id,
            hex::encode(conflicting_key.verifying_key().to_bytes()),
            Vec::new(),
        );
        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&ctx)).await;

        assert_eq!(trust_metrics.snapshot().conflicted, 1);
    }

    #[tokio::test]
    async fn runtime_ctx_oracle_blocks_stranger_rate_limited() {
        let sender_key = [71; 32];
        let sender_signing = SigningKey::from_bytes(&sender_key);
        let sender_pubkey = hex::encode(sender_signing.verifying_key().to_bytes());
        let node_id = NodeId::from_public_key(&sender_signing.verifying_key());
        let scores = Arc::new(StdMutex::new(TrustScoreManager::new()));
        let rates = Arc::new(StdMutex::new(RateLimiter::new()));
        let hosts = Arc::new(std::sync::Mutex::new(KnownHosts::new()));
        let groups: Arc<dyn GroupGraph> = Arc::new(GroupRegistry::new());
        let oracle: Arc<dyn TrustOracle> = Arc::new(BasicTrustOracle::new(
            Arc::clone(&scores),
            Arc::clone(&rates),
            Arc::clone(&hosts),
            Arc::clone(&groups),
        ));
        let now = 2_000;
        {
            let mut limiter = rates.lock().unwrap();
            for t in 0..crate::dht::rate_limit::RATE_MESSAGES_PER_HOUR as u64 {
                let _ = limiter.check_message(&node_id, now + t);
            }
        }
        assert!(!oracle.allows_message_to_stranger(&node_id, now));

        let (relay_tx, relay_tracker, relay_metrics) = RuntimeContext::default_relay_channels();
        let (badge_store, badge_metrics) = RuntimeContext::default_badge_components();
        let (cold_contact_tracker, auto_badge_queue, abuse_metrics) =
            RuntimeContext::default_abuse_channels();
        let ctx = Arc::new(RuntimeContext {
            sync: Arc::new(Mutex::new(SyncManager::new("rate-check".into()))),
            home_state: Arc::new(Mutex::new(HomeRuntimeState::default())),
            media_signals: Arc::new(Mutex::new(Vec::new())),
            storage: None,
            age_tracker: None,
            activity_tracker: None,
            proof_of_live: None,
            hosts: Arc::clone(&hosts),
            scores: Arc::clone(&scores),
            rates: Arc::clone(&rates),
            trust_graph: None,
            groups: Arc::clone(&groups),
            trust_metrics: Arc::new(TrustMetrics::new()),
            oracle: Arc::clone(&oracle),
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
            invite_registry: RuntimeContext::default_invite_registry(),
            degradation: RuntimeContext::default_degradation(),
            stigma_cache: RuntimeContext::default_stigma_cache(),
            inbound_observations_tx: RuntimeContext::default_inbound_observations(),
            badge_store,
            badge_metrics,
            badge_fetch_shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cold_contact_tracker,
            auto_badge_queue,
            abuse_metrics,
            identity_id: "local-id".to_string(),
            public_key: sender_pubkey.clone(),
            identity_signing_key: None,
            jury_commitment_publisher: None,
            jury_plaintext_cache: RuntimeContext::default_jury_plaintext_cache(),
            invite_redemption_transport: None,
            pending_invite_redemptions: RuntimeContext::default_pending_invite_redemptions(),
            sas_pairing: RuntimeContext::default_sas_pairing(),
            integrity: None,
        });
        let envelope = SyncEnvelope::new("remote-unknown".to_string(), sender_pubkey, Vec::new());
        PeerRuntime::process_incoming_envelope(envelope, ctx).await;
    }

    #[tokio::test]
    async fn runtime_ctx_oracle_allows_known_node() {
        let sender_key = [72; 32];
        let sender_signing = SigningKey::from_bytes(&sender_key);
        let sender_pubkey = hex::encode(sender_signing.verifying_key().to_bytes());
        let node_id = NodeId::from_public_key(&sender_signing.verifying_key());
        let scores = Arc::new(StdMutex::new(TrustScoreManager::new()));
        let rates = Arc::new(StdMutex::new(RateLimiter::new()));
        let hosts = Arc::new(std::sync::Mutex::new(KnownHosts::new()));
        let groups: Arc<dyn GroupGraph> = Arc::new(GroupRegistry::new());
        {
            let mut hosts_guard = hosts.lock().unwrap();
            hosts_guard
                .pin_manual(&node_id.to_hex(), &sender_pubkey, 1_000)
                .expect("pin host");
        }
        let oracle: Arc<dyn TrustOracle> = Arc::new(BasicTrustOracle::new(
            Arc::clone(&scores),
            Arc::clone(&rates),
            Arc::clone(&hosts),
            Arc::clone(&groups),
        ));
        let now = 2_000;
        {
            let mut limiter = rates.lock().unwrap();
            for t in 0..crate::dht::rate_limit::RATE_MESSAGES_PER_HOUR as u64 {
                let _ = limiter.check_message(&node_id, now + t);
            }
        }

        assert!(oracle.allows_message_to_stranger(&node_id, now));
    }

    #[tokio::test]
    async fn runtime_refresh_starts_task() {
        let runtime = PeerRuntime::start(identity_for(&[90; 32]), [90; 32], "refresh-start".into())
            .await
            .expect("runtime");
        assert_eq!(
            runtime.address_refresh().config().interval,
            crate::ADDRESS_REFRESH_DEFAULT_INTERVAL
        );
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn incoming_rejected_when_warning_tier() {
        let runtime =
            PeerRuntime::start(identity_for(&[72; 32]), [72; 32], "incoming-warning".into())
                .await
                .expect("runtime");
        let sender_key = SigningKey::from_bytes(&[73; 32]);
        let sender_id = NodeId::from_public_key(&sender_key.verifying_key());
        let now = unix_now();
        {
            let mut rates = runtime.ctx.rates.lock().unwrap();
            let start = now.saturating_sub(200);
            for timestamp in start..start + crate::dht::rate_limit::RATE_MESSAGES_PER_HOUR as u64 {
                assert!(rates.check_message(&sender_id, timestamp).is_allowed());
            }
            let reject_start = start + crate::dht::rate_limit::RATE_MESSAGES_PER_HOUR as u64;
            for timestamp in reject_start..reject_start + 10 {
                assert!(rates.check_message(&sender_id, timestamp).is_rejected());
            }
        }
        let envelope = SyncEnvelope::new(
            identity_for(&sender_key.to_bytes()),
            hex::encode(sender_key.verifying_key().to_bytes()),
            Vec::new(),
        );

        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&runtime.ctx)).await;

        assert_eq!(
            runtime
                .ctx
                .abuse_metrics
                .rate_throttled_by_warning_total
                .load(Ordering::Relaxed),
            1
        );
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn incoming_allowed_when_normal_tier() {
        let runtime =
            PeerRuntime::start(identity_for(&[74; 32]), [74; 32], "incoming-normal".into())
                .await
                .expect("runtime");
        let sender_key = SigningKey::from_bytes(&[75; 32]);
        let envelope = SyncEnvelope::new(
            identity_for(&sender_key.to_bytes()),
            hex::encode(sender_key.verifying_key().to_bytes()),
            Vec::new(),
        );

        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&runtime.ctx)).await;

        assert_eq!(
            runtime
                .ctx
                .abuse_metrics
                .rate_throttled_by_warning_total
                .load(Ordering::Relaxed),
            0
        );
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn incoming_rejected_when_blocked_tier() {
        let runtime =
            PeerRuntime::start(identity_for(&[76; 32]), [76; 32], "incoming-blocked".into())
                .await
                .expect("runtime");
        let sender_key = SigningKey::from_bytes(&[77; 32]);
        let sender_id = NodeId::from_public_key(&sender_key.verifying_key());
        let now = unix_now();
        {
            let mut rates = runtime.ctx.rates.lock().unwrap();
            let start = now.saturating_sub(200);
            for timestamp in start..start + crate::dht::rate_limit::RATE_MESSAGES_PER_HOUR as u64 {
                assert!(rates.check_message(&sender_id, timestamp).is_allowed());
            }
            let reject_start = start + crate::dht::rate_limit::RATE_MESSAGES_PER_HOUR as u64;
            for timestamp in reject_start..reject_start + 50 {
                assert!(rates.check_message(&sender_id, timestamp).is_rejected());
            }
        }
        let envelope = SyncEnvelope::new(
            identity_for(&sender_key.to_bytes()),
            hex::encode(sender_key.verifying_key().to_bytes()),
            Vec::new(),
        );

        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&runtime.ctx)).await;

        assert_eq!(
            runtime
                .ctx
                .abuse_metrics
                .rate_blocked_total
                .load(Ordering::Relaxed),
            1
        );
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn runtime_refresh_stops_task() {
        let runtime = PeerRuntime::start(identity_for(&[91; 32]), [91; 32], "refresh-stop".into())
            .await
            .expect("runtime");
        tokio::time::timeout(std::time::Duration::from_secs(10), runtime.stop())
            .await
            .expect("runtime stop timeout")
            .expect("stop");
    }

    #[tokio::test]
    async fn add_contact_denied_when_rate_limited() {
        let runtime = PeerRuntime::start(identity_for(&[77; 32]), [77; 32], "rate-limit".into())
            .await
            .expect("runtime");
        let pubkey = test_pubkey(50);
        let node_id = pubkey_to_node_id(&pubkey).expect("valid key");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        {
            let mut limiter = runtime.ctx.rates.lock().unwrap();
            for t in 0..crate::dht::rate_limit::RATE_NEW_CONTACTS_PER_DAY as u64 {
                let _ = limiter.check_contact_add(&node_id, now + t);
            }
        }

        let err = runtime
            .add_contact(pubkey, "Blocked".into())
            .await
            .expect_err("denied");
        assert!(err.to_string().contains("denied"));
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn send_pending_verified_denied_for_banned() {
        let runtime = PeerRuntime::start(identity_for(&[78; 32]), [78; 32], "banned".into())
            .await
            .expect("runtime");
        let pubkey = test_pubkey(51);
        let node_id = pubkey_to_node_id(&pubkey).expect("valid key");
        runtime
            .ctx
            .scores
            .lock()
            .unwrap()
            .penalize(&node_id, 100, "bad", 1000);

        let err = runtime
            .send_pending_verified("127.0.0.1:1", &pubkey)
            .await
            .expect_err("banned");
        assert!(err.to_string().contains("banned"));
        assert_eq!(runtime.trust_metrics().snapshot().denies_banned, 1);
        runtime.stop().await.expect("stop");
    }

    #[test]
    fn runtime_send_pending_trusted_banned_denied() {
        let executor = tokio::runtime::Runtime::new().expect("create runtime");
        executor.block_on(async {
            let runtime =
                PeerRuntime::start(identity_for(&[94; 32]), [94; 32], "trusted-banned".into())
                    .await
                    .expect("runtime");
            let node_id = pubkey_to_node_id(&test_pubkey(95)).expect("valid key");
            runtime
                .ctx
                .scores
                .lock()
                .unwrap()
                .penalize(&node_id, 100, "bad", 1000);

            let err = runtime
                .send_pending_trusted(node_id, "127.0.0.1:1")
                .await
                .expect_err("banned");
            assert!(err.to_string().contains("banned"));
            runtime.stop().await.expect("stop");
        });
    }

    #[test]
    fn runtime_send_pending_trusted_known_bypasses_rate() {
        let executor = tokio::runtime::Runtime::new().expect("create runtime");
        executor.block_on(async {
            let key = [96; 32];
            let peer_key = [97; 32];
            let runtime = PeerRuntime::start(identity_for(&key), key, "trusted-known".into())
                .await
                .expect("runtime");
            let peer_public_key = test_pubkey(peer_key[0]);
            let node_id = pubkey_to_node_id(&peer_public_key).expect("valid key");
            {
                let mut hosts = runtime.ctx.hosts.lock().unwrap();
                hosts
                    .pin_manual(&node_id.to_hex(), &peer_public_key, 1_000)
                    .expect("pin known host");
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            {
                let mut rates = runtime.ctx.rates.lock().unwrap();
                for offset in 0..crate::dht::rate_limit::RATE_MESSAGES_PER_HOUR as u64 {
                    let _ = rates.check_message(&node_id, now + offset);
                }
            }

            runtime
                .send_pending_trusted(node_id, "127.0.0.1:1")
                .await
                .expect("empty pending events should bypass stranger rate for known peer");
            runtime.stop().await.expect("stop");
        });
    }

    #[tokio::test]
    async fn send_pending_verified_rate_deny_increments_metric() {
        let runtime = PeerRuntime::start(identity_for(&[81; 32]), [81; 32], "rate-deny".into())
            .await
            .expect("runtime");
        let pubkey = test_pubkey(52);
        let node_id = pubkey_to_node_id(&pubkey).expect("valid key");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        {
            let mut rates = runtime.ctx.rates.lock().unwrap();
            for offset in 0..crate::dht::rate_limit::RATE_MESSAGES_PER_HOUR as u64 {
                let _ = rates.check_message(&node_id, now + offset);
            }
        }

        let err = runtime
            .send_pending_verified("127.0.0.1:1", &pubkey)
            .await
            .expect_err("rate limited");
        assert!(err.to_string().contains("denied"));
        assert_eq!(runtime.trust_metrics().snapshot().denies_stranger_rate, 1);
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn send_rejected_when_self_warning() {
        let local_key = [82; 32];
        let runtime =
            PeerRuntime::start(identity_for(&local_key), local_key, "send-warning".into())
                .await
                .expect("runtime");
        let now = unix_now();
        let start = now.saturating_sub(200);
        {
            let mut rates = runtime.ctx.rates.lock().unwrap();
            for timestamp in start..start + crate::dht::rate_limit::RATE_MESSAGES_PER_HOUR as u64 {
                assert!(rates
                    .check_message(&runtime.dht_local_id, timestamp)
                    .is_allowed());
            }
            let reject_start = start + crate::dht::rate_limit::RATE_MESSAGES_PER_HOUR as u64;
            for timestamp in reject_start..reject_start + 10 {
                assert!(rates
                    .check_message(&runtime.dht_local_id, timestamp)
                    .is_rejected());
            }
        }

        let error = runtime
            .send_pending_verified("127.0.0.1:1", &test_pubkey(83))
            .await
            .expect_err("self warning tier must constrain outgoing sends");

        assert_eq!(error.to_string(), "tier-aware rate exceeded");
        assert_eq!(
            runtime
                .ctx
                .abuse_metrics
                .rate_throttled_by_warning_total
                .load(Ordering::Relaxed),
            1
        );
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn send_pending_verified_allowed_for_known() {
        let key_a = [79; 32];
        let key_b = [80; 32];
        let sender = PeerRuntime::start(identity_for(&key_a), key_a, "known-sender".into())
            .await
            .expect("runtime");
        let mut receiver = PeerRuntime::start(identity_for(&key_b), key_b, "known-receiver".into())
            .await
            .expect("runtime");
        receiver
            .activate_listener(None, None)
            .await
            .expect("receiver listener");
        let pubkey = receiver.public_key.clone();
        let node_id = pubkey_to_node_id(&pubkey).expect("valid key");
        {
            let mut hosts = sender.ctx.hosts.lock().unwrap();
            hosts
                .pin_manual(&node_id.to_hex(), &pubkey, 1_000)
                .expect("pin known host");
        }

        sender
            .send_pending_verified(&receiver.transport_address, &pubkey)
            .await
            .expect("known peer should not be denied by trust");

        sender.stop().await.expect("stop sender");
        receiver.stop().await.expect("stop receiver");
    }

    #[tokio::test]
    async fn connect_invited_peer_uses_only_identity_verified_addresses() {
        let key_a = [197; 32];
        let key_b = [198; 32];
        let sender = PeerRuntime::start(identity_for(&key_a), key_a, "invite-dial-sender".into())
            .await
            .expect("sender runtime");
        let (receiver_storage, _receiver_storage_dir) = runtime_storage(key_b[0]);
        let mut receiver = PeerRuntime::start_with_storage(
            identity_for(&key_b),
            key_b,
            "invite-dial-receiver".into(),
            Arc::clone(&receiver_storage),
        )
        .await
        .expect("receiver runtime");
        receiver
            .activate_listener(None, None)
            .await
            .expect("receiver listener");

        let address = receiver
            .transport_address
            .parse::<SocketAddr>()
            .expect("receiver socket address");
        sender
            .record_invite_peer(
                address.to_string(),
                &receiver.identity_id,
                &receiver.public_key,
            )
            .await
            .expect("record verified invite");
        let candidates = [
            "127.0.0.1:1".parse().expect("unreachable test address"),
            address,
        ];
        let connected = sender
            .connect_invited_peer(&candidates, &receiver.identity_id, &receiver.public_key)
            .await
            .expect("authenticated invite connection");

        assert_eq!(connected, address);
        assert!(sender.is_peer_online(&receiver.identity_id).await);
        assert!(sender.peer_entries().await.iter().any(|entry| {
            entry.address == address.to_string()
                && entry.identity_id == receiver.identity_id
                && entry.source == crate::peer_directory::PeerEntrySource::OutboundVerified
        }));

        sender
            .add_message(
                "persistent-invite-chat".into(),
                sender.identity_id.clone(),
                Some(receiver.identity_id.clone()),
                "message over persistent invite session".into(),
            )
            .await
            .expect("queue encrypted message");
        sender
            .send_pending_verified(&address.to_string(), &receiver.public_key)
            .await
            .expect("send over persistent invite session");
        assert!(sender.is_peer_online(&receiver.identity_id).await);
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let messages = receiver_storage
                    .lock()
                    .expect("receiver storage lock")
                    .messages_json(&sender.public_key)
                    .expect("read received messages");
                if messages.contains("message over persistent invite session") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("receiver should process message over the persistent session");

        sender.mark_peer_offline(&receiver.identity_id).await;
        assert!(!sender.is_peer_online(&receiver.identity_id).await);

        let receiver_identity = receiver.identity_id.clone();
        let receiver_public_key = receiver.public_key.clone();
        receiver.stop().await.expect("stop receiver");
        tokio::time::timeout(Duration::from_secs(3), async {
            while sender.is_peer_online(&receiver_identity).await {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("closed peer transport should clear live status");
        assert!(sender
            .connect_invited_peer(&[address], &receiver_identity, &receiver_public_key)
            .await
            .is_err());
        assert!(!sender.is_peer_online(&receiver_identity).await);
        sender.stop().await.expect("stop sender");
    }

    #[tokio::test]
    async fn peer_entries_empty_when_no_directory_records() {
        let key = [123; 32];
        let runtime = PeerRuntime::start(identity_for(&key), key, "peer-entries-empty".into())
            .await
            .expect("runtime");
        assert!(runtime.peer_entries().await.is_empty());
        runtime.stop().await.expect("stop runtime");
    }

    #[tokio::test]
    async fn record_outbound_via_send_pending_verified() {
        let (a, b) = successful_peer_directory_send("peer-record").await;
        let entries = a.peer_entries().await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].address, b.transport_address);
        assert_eq!(entries[0].identity_id, b.identity_id);
        assert_eq!(entries[0].public_key_hex, b.public_key);
        a.stop().await.expect("stop a");
        b.stop().await.expect("stop b");
    }

    #[tokio::test]
    async fn two_node_tls_handshake_records_inbound() {
        let key_a = [121; 32];
        let key_b = [122; 32];
        let mut a = PeerRuntime::start(identity_for(&key_a), key_a, "inbound-handshake-a".into())
            .await
            .expect("runtime a");
        let mut b = PeerRuntime::start(identity_for(&key_b), key_b, "inbound-handshake-b".into())
            .await
            .expect("runtime b");
        a.activate_listener(None, None)
            .await
            .expect("activate a listener");
        b.activate_listener(None, None)
            .await
            .expect("activate b listener");
        a.pin_peer(&b.identity_id, &b.public_key)
            .await
            .expect("pin b for a");
        b.pin_peer(&a.identity_id, &a.public_key)
            .await
            .expect("pin a for b");
        let address = b.transport_address.clone();
        let public_key = b.public_key.clone();
        a.add_message(
            "inbound-handshake-chat".into(),
            a.identity_id.clone(),
            Some(b.identity_id.clone()),
            "pending".into(),
        )
        .await
        .expect("add pending message");

        let target_id = a.identity_id.clone();
        let directory = Arc::clone(&b.ctx.peer_directory);
        let (observation_result, send_result) = tokio::join!(
            await_event(
                &b.ctx.observable,
                EventKind::InboundObservationRecorded,
                || {
                    let directory = Arc::clone(&directory);
                    let target_id = target_id.clone();
                    async move {
                        directory
                            .lock()
                            .await
                            .lookup_by_identity(&target_id, unix_now())
                            .is_some()
                    }
                },
                Duration::from_secs(60),
            ),
            a.send_pending_verified(&address, &public_key)
        );
        observation_result.expect("inbound observation event timeout");
        send_result.expect("send pending message");
        let addresses = b.peer_addresses_of(&a.identity_id).await;
        assert!(
            !addresses.is_empty(),
            "addresses empty after observation recorded"
        );
        let entry = b
            .ctx
            .peer_directory
            .lock()
            .await
            .lookup_by_address(&addresses[0], unix_now())
            .cloned()
            .expect("inbound directory entry");
        assert_eq!(entry.identity_id, a.identity_id);
        assert_eq!(entry.public_key_hex, a.public_key);
        assert_eq!(
            entry.source,
            crate::peer_directory::PeerEntrySource::InboundTls
        );
        a.stop().await.expect("stop a");
        b.stop().await.expect("stop b");
    }

    #[tokio::test]
    async fn peer_lookup_by_address_returns_entry() {
        let (a, b) = successful_peer_directory_send("peer-lookup").await;
        let entry = a
            .peer_lookup_by_address(&b.transport_address)
            .await
            .expect("directory entry");
        assert_eq!(entry.identity_id, b.identity_id);
        assert_eq!(entry.public_key_hex, b.public_key);
        a.stop().await.expect("stop a");
        b.stop().await.expect("stop b");
    }

    #[tokio::test]
    async fn peer_entries_respects_hint_filter() {
        let key = [124; 32];
        let runtime = PeerRuntime::start(identity_for(&key), key, "peer-hint-filter".into())
            .await
            .expect("runtime");
        let first_key = test_pubkey(125);
        let second_key = test_pubkey(126);
        let first_identity = pubkey_to_node_id(&first_key)
            .expect("first identity")
            .to_hex();
        let second_identity = pubkey_to_node_id(&second_key)
            .expect("second identity")
            .to_hex();
        let first_address = "peer-hint-first:9000";
        let second_address = "peer-hint-second:9000";
        {
            let mut directory = runtime.ctx.peer_directory.lock().await;
            directory
                .record_outbound(
                    first_address.to_string(),
                    first_identity,
                    first_key,
                    unix_now(),
                )
                .expect("record first peer");
            directory
                .record_outbound(
                    second_address.to_string(),
                    second_identity,
                    second_key,
                    unix_now(),
                )
                .expect("record second peer");
        }
        runtime.peers.lock().await.push(first_address.to_string());
        let entries = runtime.peer_entries().await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].address, first_address);
        runtime.stop().await.expect("stop runtime");
    }

    #[tokio::test]
    async fn record_outbound_does_not_overwrite_conflict() {
        let (a, b) = successful_peer_directory_send("peer-conflict").await;
        let conflicting_key = test_pubkey(127);
        let conflicting_identity = pubkey_to_node_id(&conflicting_key)
            .expect("conflicting identity")
            .to_hex();
        let result = a.ctx.peer_directory.lock().await.record_outbound(
            b.transport_address.clone(),
            conflicting_identity,
            conflicting_key,
            unix_now(),
        );
        assert_eq!(
            result,
            Err(crate::peer_directory::PeerDirectoryError::AddressConflict)
        );
        let entry = a
            .peer_lookup_by_address(&b.transport_address)
            .await
            .expect("original directory entry");
        assert_eq!(entry.identity_id, b.identity_id);
        assert_eq!(entry.public_key_hex, b.public_key);
        a.stop().await.expect("stop a");
        b.stop().await.expect("stop b");
    }

    #[tokio::test]
    async fn peer_directory_metrics_visible_in_snapshot() {
        let (a, b) = successful_peer_directory_send("peer-metrics").await;
        let snapshot = a.metrics_snapshot().await;
        assert_eq!(snapshot.peer_directory.recorded_outbound_total, 1);
        a.stop().await.expect("stop a");
        b.stop().await.expect("stop b");
    }

    #[test]
    fn runtime_send_pending_verified_tcp_fail_punch_fallback() {
        let executor = tokio::runtime::Runtime::new().expect("create runtime");
        executor.block_on(async {
            let local_key = [92; 32];
            let remote_key = [93; 32];
            let runtime = PeerRuntime::start_with_policy(
                identity_for(&local_key),
                local_key,
                "verified-punch-fallback".into(),
                None,
                trusted_local_policy(),
            )
            .await
            .expect("start runtime");
            let remote_public_key = test_pubkey(remote_key[0]);
            let remote_identity = identity_for(&remote_key);
            runtime
                .pin_peer(&remote_identity, &remote_public_key)
                .await
                .expect("pin recipient");
            runtime
                .add_message(
                    "chat-punch".into(),
                    runtime.identity_id.clone(),
                    Some(remote_identity),
                    "pending".into(),
                )
                .await
                .expect("add pending message");

            let error = runtime
                .send_pending_verified("127.0.0.1:1", &remote_public_key)
                .await
                .expect_err("TCP and punch should fail without known DHT peers");
            assert_eq!(error.to_string(), "ERROR:timeout:all_probes_failed");
            assert!(runtime
                .has_pending_events_for_peer(&remote_public_key)
                .await
                .expect("check queued message"));
            runtime.stop().await.expect("stop runtime");
        });
    }

    #[test]
    fn runtime_send_pending_verified_tcp_fail_no_dht_peers() {
        let executor = tokio::runtime::Runtime::new().expect("create runtime");
        executor.block_on(async {
            let runtime = PeerRuntime::start(
                identity_for(&[96; 32]),
                [96; 32],
                "verified-tcp-fallback-no-dht".into(),
            )
            .await
            .expect("start runtime");
            let pubkey = test_pubkey(97);
            let recipient_id = identity_for(&[97; 32]);
            runtime
                .pin_peer(&recipient_id, &pubkey)
                .await
                .expect("pin recipient");
            runtime
                .add_message(
                    "fallback-chat".into(),
                    runtime.identity_id.clone(),
                    Some(recipient_id),
                    "tcp fail".into(),
                )
                .await
                .expect("queue message");

            let started = Instant::now();
            let err = runtime
                .send_pending_verified("127.0.0.1:1", &pubkey)
                .await
                .expect_err("fallback should fail without remote");
            assert_eq!(err.to_string(), "ERROR:timeout:all_probes_failed");
            assert!(started.elapsed() < Duration::from_secs(15));
            assert!(runtime
                .has_pending_events_for_peer(&pubkey)
                .await
                .expect("check queued message"));
            runtime.stop().await.expect("stop runtime");
        });
    }

    #[tokio::test]
    async fn runtime_start_opens_real_listener() {
        let runtime =
            PeerRuntime::start(identity_for(&[39; 32]), [39; 32], "listener-start".into())
                .await
                .expect("runtime");
        let address: std::net::SocketAddr =
            runtime.transport_address.parse().expect("socket address");
        assert!(
            !address.ip().is_loopback(),
            "listener should advertise a non-loopback address: {address}"
        );
        assert_ne!(
            address.port(),
            0,
            "listener should advertise a bound port: {address}"
        );
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn dht_stream_isolated_from_sync() {
        let server_key = SigningKey::from_bytes(&[90; 32]);
        let client_key = SigningKey::from_bytes(&[91; 32]);
        let hosts = Arc::new(std::sync::Mutex::new(crate::pinning::KnownHosts::new()));
        let dht_metrics = Arc::new(crate::dht::DhtMetrics::new());
        let (transport, mut incoming) = PeerTransport::bind_secure_on_demand_with_kind(
            "127.0.0.1:0",
            server_key.clone(),
            hosts,
            NetworkTrustPolicy::default(),
            TransportKind::TlsMux,
            None,
            Some(Arc::clone(&dht_metrics)),
        )
        .await
        .expect("bind dht listener");
        let envelope = SyncEnvelope::new(
            identity_for(&[91; 32]),
            hex::encode(client_key.verifying_key().to_bytes()),
            Vec::new(),
        );
        send_envelope_secure_with_kind(
            &transport.local_address,
            &envelope,
            &client_key,
            Arc::new(std::sync::Mutex::new(crate::pinning::KnownHosts::new())),
            server_key.verifying_key(),
            NetworkTrustPolicy::default(),
            TransportKind::TlsMux,
        )
        .await
        .expect("send sync through mux");
        let received = tokio::time::timeout(std::time::Duration::from_secs(2), incoming.recv())
            .await
            .expect("incoming envelope timeout")
            .expect("incoming channel closed");
        assert_eq!(received.0.identity_id, envelope.identity_id);
        assert_eq!(dht_metrics.snapshot().streams_received, 0);
        transport.stop().await.expect("stop listener");
    }

    #[tokio::test]
    async fn dht_metrics_record_increments() {
        let metrics = Arc::new(crate::dht::DhtMetrics::new());
        metrics.inc_received();
        metrics.inc_dropped();
        metrics.inc_processed();
        metrics.inc_timeouts();
        metrics.inc_errors();
        metrics.inc_responses();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.streams_received, 1);
        assert_eq!(snapshot.streams_dropped, 1);
        assert_eq!(snapshot.streams_processed, 1);
        assert_eq!(snapshot.rpc_timeouts, 1);
        assert_eq!(snapshot.rpc_errors, 1);
        assert_eq!(snapshot.responses_sent, 1);
    }

    #[tokio::test]
    async fn runtime_metrics_snapshot_initial_zero() {
        let runtime =
            PeerRuntime::start(identity_for(&[103; 32]), [103; 32], "metrics-zero".into())
                .await
                .expect("runtime");
        let snapshot = runtime.metrics_snapshot().await;
        assert_eq!(snapshot.dht.streams_received, 0);
        assert_eq!(snapshot.dht.streams_processed, 0);
        assert_eq!(snapshot.dht.streams_dropped, 0);
        assert_eq!(snapshot.dht.rpc_timeouts, 0);
        assert_eq!(snapshot.dht.rpc_errors, 0);
        assert_eq!(snapshot.dht.responses_sent, 0);
        assert_eq!(snapshot.trust.denies_banned, 0);
        assert_eq!(snapshot.trust.denies_stranger_rate, 0);
        assert_eq!(snapshot.trust.denies_contact_rate, 0);
        assert_eq!(snapshot.trust.conflicted, 0);
        assert_eq!(snapshot.trust.recorded_messages, 0);
        assert_eq!(snapshot.trust.recorded_contacts, 0);
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn runtime_metrics_snapshot_reflects_trust() {
        let runtime =
            PeerRuntime::start(identity_for(&[104; 32]), [104; 32], "metrics-trust".into())
                .await
                .expect("runtime");
        runtime.ctx.trust_metrics.inc_denies_banned();
        assert_eq!(runtime.metrics_snapshot().await.trust.denies_banned, 1);
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn runtime_log_metrics_does_not_panic() {
        let runtime = PeerRuntime::start(identity_for(&[105; 32]), [105; 32], "metrics-log".into())
            .await
            .expect("runtime");
        runtime.log_metrics().await;
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn runtime_exposes_configured_poll_actions() {
        let mut policy = NetworkScanPolicy::default();
        policy.channels.schedule = hal_settings::ScanSchedule::Continuous;
        policy.channels.interval_seconds = 1;
        let runtime = PeerRuntime::start_with_policy(
            identity_for(&[35; 32]),
            [35; 32],
            "polling".into(),
            None,
            policy,
        )
        .await
        .expect("runtime");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(runtime
            .take_poll_actions()
            .await
            .iter()
            .any(|action| action.branch == crate::PollBranch::Channels));
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn stop_returns_within_timeout() {
        let runtime = PeerRuntime::start(identity_for(&[38; 32]), [38; 32], "graceful-stop".into())
            .await
            .expect("runtime");
        tokio::time::timeout(std::time::Duration::from_secs(6), runtime.stop())
            .await
            .expect("stop timeout")
            .expect("graceful stop");
    }

    #[test]
    fn runtime_hole_puncher_default_works() {
        let puncher = HolePuncher::with_defaults();
        assert_eq!(puncher.config().magic, *crate::PUNCH_MAGIC);
    }

    #[test]
    fn runtime_signaling_strategy_default_hybrid() {
        assert_eq!(SignalingStrategy::default_hybrid().validate(), Ok(()));
    }

    fn test_badge_for_requester(
        subject: NodeId,
        issuer: NodeId,
        assigned_at: u64,
        signer: &SigningKey,
    ) -> Badge {
        Badge::create(
            assigned_at,
            subject,
            None,
            crate::dht::BadgeKind::Spammer,
            vec!["relay-stigma-test-message".to_string()],
            crate::dht::BadgeContext::KnownContact,
            "relay stigma test".to_string(),
            issuer,
            assigned_at,
            None,
            signer,
        )
        .expect("valid stigma badge")
    }

    #[tokio::test]
    async fn envelope_meta_cold_marks_unknown_sender() {
        let local_key = [153; 32];
        let sender_key = SigningKey::from_bytes(&[154; 32]);
        let sender_identity = identity_for(&[154; 32]);
        let runtime = PeerRuntime::start(
            identity_for(&local_key),
            local_key,
            "envelope-cold-meta".into(),
        )
        .await
        .expect("runtime");
        let envelope = SyncEnvelope::new(
            sender_identity,
            hex::encode(sender_key.verifying_key().to_bytes()),
            Vec::new(),
        );
        let meta = EnvelopeMeta {
            binding_before_learn: crate::pinning::BindingCheck::Unknown,
            was_cold: true,
            remote_addr: Some("127.0.0.1:12345".parse().expect("remote address")),
            transport_peer_identity: None,
            session_sender: None,
        };

        PeerRuntime::process_incoming_envelope_with_meta(envelope, meta, Arc::clone(&runtime.ctx))
            .await;
        let metrics = runtime.trust_metrics().snapshot();
        assert_eq!(metrics.envelope_cold_received_total, 1);
        assert_eq!(metrics.envelope_warm_received_total, 0);
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn envelope_meta_warm_marks_trusted_sender() {
        let local_key = [155; 32];
        let sender_key = SigningKey::from_bytes(&[156; 32]);
        let sender_public_key = hex::encode(sender_key.verifying_key().to_bytes());
        let sender_identity = identity_for(&[156; 32]);
        let runtime = PeerRuntime::start(
            identity_for(&local_key),
            local_key,
            "envelope-warm-meta".into(),
        )
        .await
        .expect("runtime");
        runtime
            .ctx
            .hosts
            .lock()
            .unwrap()
            .pin_manual(&sender_identity, &sender_public_key, 1)
            .expect("pin sender");
        let envelope = SyncEnvelope::new(sender_identity, sender_public_key, Vec::new());
        let meta = EnvelopeMeta {
            binding_before_learn: crate::pinning::BindingCheck::Trusted,
            was_cold: false,
            remote_addr: None,
            transport_peer_identity: None,
            session_sender: None,
        };

        PeerRuntime::process_incoming_envelope_with_meta(envelope, meta, Arc::clone(&runtime.ctx))
            .await;
        let metrics = runtime.trust_metrics().snapshot();
        assert_eq!(metrics.envelope_cold_received_total, 0);
        assert_eq!(metrics.envelope_warm_received_total, 1);
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn cold_contact_exceeded_queues_pending_badge() {
        let local_key = [157; 32];
        let sender_key = SigningKey::from_bytes(&[158; 32]);
        let sender_id = NodeId::from_public_key(&sender_key.verifying_key());
        let (runtime, _storage_dir) = start_runtime_with_established_rate_peer(
            local_key,
            sender_key.to_bytes(),
            "cold-contact-queue".into(),
            157,
        )
        .await;
        let sender_identity = identity_for(&[158; 32]);
        let sender_public_key = hex::encode(sender_key.verifying_key().to_bytes());

        for index in 0..11 {
            let event = SyncEvent::new(
                format!("cold-contact-message-{index}"),
                SyncEventType::MessageAdded,
                serde_json::json!({
                    "chat_id": "cold-contact-chat",
                    "sender_id": sender_identity,
                    "text": format!("message {index}")
                })
                .to_string(),
            );
            let mut event = event;
            event
                .sign(&sender_key.to_bytes())
                .expect("sign message event");
            let envelope = SyncEnvelope::new(
                sender_identity.clone(),
                sender_public_key.clone(),
                vec![event],
            );
            let meta = EnvelopeMeta {
                binding_before_learn: crate::pinning::BindingCheck::Unknown,
                was_cold: true,
                remote_addr: None,
                transport_peer_identity: None,
                session_sender: None,
            };
            PeerRuntime::process_incoming_envelope_with_meta(
                envelope,
                meta,
                Arc::clone(&runtime.ctx),
            )
            .await;
        }

        let mut queue = runtime.ctx.auto_badge_queue.lock().await;
        assert_eq!(queue.len(), 1);
        let pending_badges = queue.drain();
        let pending = pending_badges.first().expect("queued pending badge");
        assert_eq!(pending.subject_id, sender_id);
        assert_eq!(pending.message_ids, vec!["cold-contact-message-10"]);
        assert!(pending.reason.contains("11/10 in 3600s"));
        drop(queue);
        assert_eq!(
            runtime
                .ctx
                .abuse_metrics
                .snapshot()
                .incoming_cold_exceeded_total,
            1
        );
        assert_eq!(
            runtime.ctx.abuse_metrics.snapshot().auto_badge_queued_total,
            1
        );
        runtime.stop().await.expect("stop");
    }

    async fn start_runtime_with_established_rate_peer(
        local_key: [u8; 32],
        sender_key: [u8; 32],
        device_id: String,
        storage_seed: u8,
    ) -> (PeerRuntime, tempfile::TempDir) {
        let sender = SigningKey::from_bytes(&sender_key);
        let sender_id = NodeId::from_public_key(&sender.verifying_key());
        let (storage, storage_dir) = runtime_storage(storage_seed);
        storage
            .lock()
            .expect("storage lock")
            .identity_history()
            .observe_first_seen(&sender_id.to_hex(), 1)
            .expect("seed established first-seen timestamp");

        let runtime = PeerRuntime::start_with_storage(
            identity_for(&local_key),
            local_key,
            device_id,
            storage,
        )
        .await
        .expect("runtime");
        let accepted_start = unix_now()
            .saturating_sub(crate::dht::rate_limit::FIRST_CONTACT_ACCEPTED_THRESHOLD as u64 * 31);
        for index in 0..crate::dht::rate_limit::FIRST_CONTACT_ACCEPTED_THRESHOLD as u64 {
            assert!(runtime
                .ctx
                .record_rate_acceptance(&sender_id, accepted_start + index * 31));
        }
        (runtime, storage_dir)
    }

    #[tokio::test]
    async fn cold_contact_empty_events_skips_queue() {
        let local_key = [159; 32];
        let sender_key = SigningKey::from_bytes(&[160; 32]);
        let (runtime, _storage_dir) = start_runtime_with_established_rate_peer(
            local_key,
            sender_key.to_bytes(),
            "cold-contact-no-evidence".into(),
            159,
        )
        .await;
        let sender_identity = identity_for(&[160; 32]);
        let sender_public_key = hex::encode(sender_key.verifying_key().to_bytes());

        for _ in 0..11 {
            let envelope = SyncEnvelope::new(
                sender_identity.clone(),
                sender_public_key.clone(),
                Vec::new(),
            );
            PeerRuntime::process_incoming_envelope_with_meta(
                envelope,
                EnvelopeMeta {
                    binding_before_learn: crate::pinning::BindingCheck::Unknown,
                    was_cold: true,
                    remote_addr: None,
                    transport_peer_identity: None,
                    session_sender: None,
                },
                Arc::clone(&runtime.ctx),
            )
            .await;
        }

        assert_eq!(runtime.ctx.auto_badge_queue.lock().await.len(), 0);
        let metrics = runtime.ctx.abuse_metrics.snapshot();
        assert_eq!(metrics.incoming_cold_exceeded_total, 1);
        assert_eq!(metrics.auto_badge_queued_total, 0);
        assert_eq!(metrics.auto_badge_skipped_no_evidence_total, 1);
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn cold_contact_flood_badge_fires_at_11th_for_established_peer() {
        let local_key = [163; 32];
        let sender_key = SigningKey::from_bytes(&[164; 32]);
        let sender_id = NodeId::from_public_key(&sender_key.verifying_key());
        let (runtime, _storage_dir) = start_runtime_with_established_rate_peer(
            local_key,
            sender_key.to_bytes(),
            "cold-contact-established-flood".into(),
            163,
        )
        .await;
        let sender_identity = identity_for(&[164; 32]);
        let sender_public_key = hex::encode(sender_key.verifying_key().to_bytes());

        for index in 0..11 {
            let event = SyncEvent::new(
                format!("established-cold-contact-message-{index}"),
                SyncEventType::MessageAdded,
                serde_json::json!({
                    "chat_id": "established-cold-contact-chat",
                    "sender_id": sender_identity,
                    "text": format!("message {index}")
                })
                .to_string(),
            );
            let mut event = event;
            event
                .sign(&sender_key.to_bytes())
                .expect("sign message event");
            let envelope = SyncEnvelope::new(
                sender_identity.clone(),
                sender_public_key.clone(),
                vec![event],
            );
            PeerRuntime::process_incoming_envelope_with_meta(
                envelope,
                EnvelopeMeta {
                    binding_before_learn: crate::pinning::BindingCheck::Unknown,
                    was_cold: true,
                    remote_addr: None,
                    transport_peer_identity: None,
                    session_sender: None,
                },
                Arc::clone(&runtime.ctx),
            )
            .await;
        }

        let mut queue = runtime.ctx.auto_badge_queue.lock().await;
        let pending = queue.drain();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].subject_id, sender_id);
        assert_eq!(
            pending[0].message_ids,
            vec!["established-cold-contact-message-10"]
        );
        assert!(pending[0].reason.contains("11/10 in 3600s"));
        drop(queue);
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn warm_sender_not_tracked() {
        let local_key = [161; 32];
        let sender_key = SigningKey::from_bytes(&[162; 32]);
        let sender_identity = identity_for(&[162; 32]);
        let sender_public_key = hex::encode(sender_key.verifying_key().to_bytes());
        let runtime = PeerRuntime::start(
            identity_for(&local_key),
            local_key,
            "warm-sender-untracked".into(),
        )
        .await
        .expect("runtime");
        runtime
            .ctx
            .hosts
            .lock()
            .unwrap()
            .pin_manual(&sender_identity, &sender_public_key, current_unix_time())
            .expect("pin warm sender");
        let envelope = SyncEnvelope::new(sender_identity, sender_public_key, Vec::new());
        PeerRuntime::process_incoming_envelope_with_meta(
            envelope,
            EnvelopeMeta {
                binding_before_learn: crate::pinning::BindingCheck::Trusted,
                was_cold: false,
                remote_addr: None,
                transport_peer_identity: None,
                session_sender: None,
            },
            Arc::clone(&runtime.ctx),
        )
        .await;

        assert_eq!(runtime.ctx.cold_contact_tracker.lock().await.len(), 0);
        runtime.stop().await.expect("stop");
    }

    async fn set_runtime_stigma(
        runtime: &PeerRuntime,
        issuer_key: &SigningKey,
        pin_issuer_as_contact: bool,
        assigned_at: u64,
    ) {
        let issuer_id = NodeId::from_public_key(&issuer_key.verifying_key());
        if pin_issuer_as_contact {
            runtime
                .ctx
                .hosts
                .lock()
                .unwrap()
                .pin_manual(
                    &issuer_id.to_hex(),
                    &hex::encode(issuer_key.verifying_key().to_bytes()),
                    assigned_at,
                )
                .expect("pin badge issuer");
        }
        runtime
            .ctx
            .badge_store
            .lock()
            .await
            .publish(test_badge_for_requester(
                runtime.dht_local_id,
                issuer_id,
                assigned_at,
                issuer_key,
            ))
            .expect("publish self badge");
    }

    fn current_unix_time() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn seed_local_proof_of_live_full(storage: &Arc<StdMutex<ClientStorage>>, identity: NodeId) {
        let now = current_unix_time();
        let identity_hex = identity.to_hex();
        {
            let storage = storage.lock().expect("storage lock");
            let history = storage.identity_history();
            history
                .observe_first_seen(
                    &identity_hex,
                    now.saturating_sub(crate::proof_of_live::AGE_MIN_SECS),
                )
                .expect("record first-seen time");
            let start = now.saturating_sub(crate::proof_of_live::UPTIME_WINDOW_SECS);
            for (index, observed_at) in (start..=now)
                .step_by(crate::proof_of_live::GRACE_SECS as usize)
                .enumerate()
            {
                history
                    .record_activity(&identity_hex, observed_at, &format!("f1-pol-full-{index}"))
                    .expect("record proof-of-live activity");
            }
        }
    }

    async fn assert_local_proof_of_live_full(runtime: &PeerRuntime) {
        let now = current_unix_time();
        let status = runtime
            .self_proof_of_live(now)
            .await
            .expect("configured proof-of-live tracker");
        assert!(status.is_full(), "expected full PoL status, got {status:?}");
    }

    fn open_auto_badge_storage() -> (Arc<StdMutex<ClientStorage>>, std::path::PathBuf) {
        let path =
            std::env::temp_dir().join(format!("hal-auto-badge-{}.sqlite3", uuid::Uuid::new_v4()));
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[0x51u8; 32]).expect("storage"),
        ));
        (storage, path)
    }

    async fn start_auto_badge_runtime(
        seed: u8,
        storage: Option<Arc<StdMutex<ClientStorage>>>,
    ) -> PeerRuntime {
        let key = [seed; 32];
        PeerRuntime::start_with_policy(
            identity_for(&key),
            key,
            format!("auto-badge-reply-{seed}"),
            storage,
            trusted_local_policy(),
        )
        .await
        .expect("runtime")
    }

    async fn enqueue_auto_badge(runtime: &PeerRuntime, subject_id: NodeId, observed_at: u64) {
        runtime
            .ctx
            .auto_badge_queue
            .lock()
            .await
            .push(crate::auto_badge_queue::PendingBadge {
                subject_id,
                message_ids: vec!["cold-message".into()],
                reason: "cold-contact flood".into(),
                observed_at,
            });
    }

    fn auto_badge_worker_for(runtime: &PeerRuntime) -> AutoBadgeWorker {
        AutoBadgeWorker::new(
            Arc::clone(&runtime.ctx),
            runtime.private_key.clone(),
            runtime.identity_id.clone(),
            runtime.public_key.clone(),
            runtime.dht_local_id,
            Arc::clone(&runtime.dht_routing),
            Arc::clone(&runtime.dht_cache),
            Arc::clone(&runtime.ctx.hosts),
            runtime.trust_policy.clone(),
        )
    }

    #[tokio::test]
    async fn auto_badge_worker_uses_flooder_kind() {
        let runtime = PeerRuntime::start(
            identity_for(&[200; 32]),
            [200; 32],
            "auto-badge-worker-flooder".into(),
        )
        .await
        .expect("runtime");

        let subject = NodeId::from_bytes([201; 32]);
        runtime
            .ctx
            .auto_badge_queue
            .lock()
            .await
            .push(crate::auto_badge_queue::PendingBadge {
                subject_id: subject,
                message_ids: vec!["m-1".to_string()],
                reason: "cold-contact flood".to_string(),
                observed_at: 1,
            });

        let worker = AutoBadgeWorker::new(
            Arc::clone(&runtime.ctx),
            runtime.private_key.clone(),
            runtime.identity_id.clone(),
            runtime.public_key.clone(),
            runtime.dht_local_id,
            Arc::clone(&runtime.dht_routing),
            Arc::clone(&runtime.dht_cache),
            Arc::clone(&runtime.ctx.hosts),
            runtime.trust_policy.clone(),
        );

        worker.drain_once().await.expect("drain once");

        let published = runtime
            .ctx
            .badge_store
            .lock()
            .await
            .badges_for_subject(&subject);
        assert_eq!(published.len(), 1);
        assert!(matches!(published[0].kind, crate::dht::BadgeKind::Flooder));
        assert!(!runtime.ctx.stigma_cache.is_empty());
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn auto_badge_skipped_when_local_replied() {
        let (storage, path) = open_auto_badge_storage();
        let runtime = start_auto_badge_runtime(210, Some(Arc::clone(&storage))).await;
        let subject_key = SigningKey::from_bytes(&[211; 32]);
        let subject = NodeId::from_public_key(&subject_key.verifying_key());
        let now = current_unix_time();
        storage
            .lock()
            .expect("storage lock")
            .sync_storage()
            .record_local_outbound(
                "reply-in-window",
                &runtime.identity_id,
                &subject.to_hex(),
                now.saturating_sub(60),
            )
            .expect("record reply");
        enqueue_auto_badge(&runtime, subject, now).await;

        auto_badge_worker_for(&runtime)
            .drain_once()
            .await
            .expect("drain");

        assert!(runtime
            .ctx
            .badge_store
            .lock()
            .await
            .badges_for_subject(&subject)
            .is_empty());
        assert_eq!(
            runtime
                .ctx
                .abuse_metrics
                .snapshot()
                .auto_badge_skipped_reply_total,
            1
        );
        runtime.stop().await.expect("stop runtime");
        drop(storage);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn auto_badge_published_when_no_reply() {
        let (storage, path) = open_auto_badge_storage();
        let runtime = start_auto_badge_runtime(212, Some(Arc::clone(&storage))).await;
        let subject = NodeId::from_bytes([213; 32]);
        enqueue_auto_badge(&runtime, subject, current_unix_time()).await;

        auto_badge_worker_for(&runtime)
            .drain_once()
            .await
            .expect("drain");

        assert_eq!(
            runtime
                .ctx
                .badge_store
                .lock()
                .await
                .badges_for_subject(&subject)
                .len(),
            1
        );
        assert_eq!(
            runtime
                .ctx
                .abuse_metrics
                .snapshot()
                .auto_badge_published_total,
            1
        );
        assert_eq!(
            runtime
                .ctx
                .abuse_metrics
                .snapshot()
                .auto_badge_skipped_reply_total,
            0
        );
        runtime.stop().await.expect("stop runtime");
        drop(storage);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn auto_badge_published_when_reply_outside_window() {
        let (storage, path) = open_auto_badge_storage();
        let runtime = start_auto_badge_runtime(214, Some(Arc::clone(&storage))).await;
        let subject = NodeId::from_bytes([215; 32]);
        let now = current_unix_time();
        storage
            .lock()
            .expect("storage lock")
            .sync_storage()
            .record_local_outbound(
                "reply-outside-window",
                &runtime.identity_id,
                &subject.to_hex(),
                now.saturating_sub(25 * 60 * 60),
            )
            .expect("record old reply");
        enqueue_auto_badge(&runtime, subject, now).await;

        auto_badge_worker_for(&runtime)
            .drain_once()
            .await
            .expect("drain");

        assert_eq!(
            runtime
                .ctx
                .badge_store
                .lock()
                .await
                .badges_for_subject(&subject)
                .len(),
            1
        );
        assert_eq!(
            runtime
                .ctx
                .abuse_metrics
                .snapshot()
                .auto_badge_published_total,
            1
        );
        runtime.stop().await.expect("stop runtime");
        drop(storage);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn auto_badge_published_when_storage_unavailable() {
        let runtime = start_auto_badge_runtime(216, None).await;
        let subject = NodeId::from_bytes([217; 32]);
        enqueue_auto_badge(&runtime, subject, current_unix_time()).await;

        auto_badge_worker_for(&runtime)
            .drain_once()
            .await
            .expect("drain");

        assert_eq!(
            runtime
                .ctx
                .badge_store
                .lock()
                .await
                .badges_for_subject(&subject)
                .len(),
            1
        );
        let metrics = runtime.ctx.abuse_metrics.snapshot();
        assert_eq!(metrics.auto_badge_published_total, 1);
        assert_eq!(metrics.auto_badge_skipped_no_storage_total, 1);
        runtime.stop().await.expect("stop runtime");
    }

    #[tokio::test]
    async fn auto_badge_reply_guard_uses_canonical_ids() {
        let (storage, path) = open_auto_badge_storage();
        let runtime = start_auto_badge_runtime(218, Some(Arc::clone(&storage))).await;
        let subject_key = SigningKey::from_bytes(&[219; 32]);
        let subject = NodeId::from_public_key(&subject_key.verifying_key());
        let raw_public_key = hex::encode(subject_key.verifying_key().to_bytes());
        assert_ne!(raw_public_key, subject.to_hex());
        storage
            .lock()
            .expect("storage lock")
            .sync_storage()
            .record_local_outbound(
                "reply-with-raw-pubkey",
                &runtime.identity_id,
                &raw_public_key,
                current_unix_time(),
            )
            .expect("record noncanonical recipient");
        enqueue_auto_badge(&runtime, subject, current_unix_time()).await;

        auto_badge_worker_for(&runtime)
            .drain_once()
            .await
            .expect("drain");

        assert_eq!(
            runtime
                .ctx
                .badge_store
                .lock()
                .await
                .badges_for_subject(&subject)
                .len(),
            1
        );
        assert_eq!(
            runtime
                .ctx
                .abuse_metrics
                .snapshot()
                .auto_badge_skipped_reply_total,
            0
        );
        runtime.stop().await.expect("stop runtime");
        drop(storage);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn cold_contact_send_requires_pol_full() {
        let local_key = [135; 32];
        let stranger_key = SigningKey::from_bytes(&[136; 32]);
        let (storage, _storage_dir) = runtime_storage(135);
        let runtime = PeerRuntime::start_with_storage(
            identity_for(&local_key),
            local_key,
            "cold-contact-pol-partial".into(),
            storage,
        )
        .await
        .expect("runtime with proof-of-live");
        let status = runtime
            .self_proof_of_live(current_unix_time())
            .await
            .expect("proof-of-live tracker");
        assert!(!status.is_full());

        let error = runtime
            .send_pending_verified(
                "127.0.0.1:1",
                &hex::encode(stranger_key.verifying_key().to_bytes()),
            )
            .await
            .expect_err("cold-contact send requires full proof-of-live");
        assert!(error.to_string().starts_with("cold contact forbidden:"));
        assert_eq!(
            runtime
                .ctx
                .abuse_metrics
                .snapshot()
                .proof_of_live_cold_rejected_total,
            1
        );
        runtime.stop().await.expect("stop runtime");
    }

    #[tokio::test]
    async fn cold_contact_send_with_pol_full_is_blocked_by_unknown_trust_gate() {
        let local_key = [137; 32];
        let stranger_key = SigningKey::from_bytes(&[138; 32]);
        let (storage, _storage_dir) = runtime_storage(137);
        let local_identity =
            NodeId::from_public_key(&SigningKey::from_bytes(&local_key).verifying_key());
        seed_local_proof_of_live_full(&storage, local_identity);
        let runtime = PeerRuntime::start_with_storage(
            identity_for(&local_key),
            local_key,
            "cold-contact-pol-full".into(),
            storage,
        )
        .await
        .expect("runtime with proof-of-live");
        assert_local_proof_of_live_full(&runtime).await;

        let blocked_before = runtime
            .ctx
            .abuse_metrics
            .snapshot()
            .trust_gate_blocked_total;
        let error = runtime
            .send_pending_verified(
                "127.0.0.1:1",
                &hex::encode(stranger_key.verifying_key().to_bytes()),
            )
            .await
            .expect_err("unknown peer is blocked by trust gate");
        assert!(error.to_string().contains("blocked by trust gate"));
        assert_eq!(
            runtime
                .ctx
                .abuse_metrics
                .snapshot()
                .proof_of_live_cold_rejected_total,
            0
        );
        assert_eq!(
            runtime
                .ctx
                .abuse_metrics
                .snapshot()
                .trust_gate_blocked_total,
            blocked_before + 1
        );
        runtime.stop().await.expect("stop runtime");
    }

    #[tokio::test]
    async fn existing_contact_send_allowed_without_pol_full() {
        let local_key = [139; 32];
        let recipient_key = SigningKey::from_bytes(&[140; 32]);
        let (storage, _storage_dir) = runtime_storage(139);
        let runtime = PeerRuntime::start_with_storage(
            identity_for(&local_key),
            local_key,
            "existing-contact-pol-partial".into(),
            storage,
        )
        .await
        .expect("runtime with proof-of-live");
        let recipient_id = NodeId::from_public_key(&recipient_key.verifying_key());
        runtime
            .ctx
            .hosts
            .lock()
            .expect("hosts lock")
            .pin_manual(
                &recipient_id.to_hex(),
                &hex::encode(recipient_key.verifying_key().to_bytes()),
                current_unix_time(),
            )
            .expect("pin existing recipient");
        let status = runtime
            .self_proof_of_live(current_unix_time())
            .await
            .expect("proof-of-live tracker");
        assert!(!status.is_full());

        runtime
            .send_pending_verified(
                "127.0.0.1:1",
                &hex::encode(recipient_key.verifying_key().to_bytes()),
            )
            .await
            .expect("existing contact does not require full PoL");
        assert_eq!(
            runtime
                .ctx
                .abuse_metrics
                .snapshot()
                .proof_of_live_cold_rejected_total,
            0
        );
        runtime.stop().await.expect("stop runtime");
    }

    #[tokio::test]
    async fn existing_contact_send_allowed_with_no_tracker() {
        let local_key = [141; 32];
        let recipient_key = SigningKey::from_bytes(&[142; 32]);
        let runtime = PeerRuntime::start(
            identity_for(&local_key),
            local_key,
            "existing-contact-no-pol-tracker".into(),
        )
        .await
        .expect("runtime without storage");
        assert!(runtime.ctx.proof_of_live.is_none());
        let recipient_id = NodeId::from_public_key(&recipient_key.verifying_key());
        runtime
            .ctx
            .hosts
            .lock()
            .expect("hosts lock")
            .pin_manual(
                &recipient_id.to_hex(),
                &hex::encode(recipient_key.verifying_key().to_bytes()),
                current_unix_time(),
            )
            .expect("pin existing recipient");

        runtime
            .send_pending_verified(
                "127.0.0.1:1",
                &hex::encode(recipient_key.verifying_key().to_bytes()),
            )
            .await
            .expect("existing contact with no tracker is allowed");
        runtime.stop().await.expect("stop runtime");
    }

    #[tokio::test]
    async fn send_pending_verified_blocks_cold_contact_under_stigma() {
        let local_key = [139; 32];
        let issuer_key = SigningKey::from_bytes(&[140; 32]);
        let stranger_key = SigningKey::from_bytes(&[141; 32]);
        let runtime = PeerRuntime::start(
            identity_for(&local_key),
            local_key,
            "send-stigma-blocked".into(),
        )
        .await
        .expect("runtime");
        let now = current_unix_time();
        set_runtime_stigma(
            &runtime,
            &issuer_key,
            true,
            now - crate::dht::BADGE_REFLECTION_PERIOD_SECS - 60,
        )
        .await;
        assert!(matches!(
            runtime.ctx.stigma_gate(&runtime.dht_local_id, now).await,
            StigmaLevel::Stigma { .. }
        ));

        let error = runtime
            .send_pending_verified(
                "127.0.0.1:1",
                &hex::encode(stranger_key.verifying_key().to_bytes()),
            )
            .await
            .expect_err("cold contact blocked under stigma");
        assert_eq!(
            error.to_string(),
            "cold contact forbidden: sender under stigma"
        );
        assert_eq!(
            runtime.trust_metrics().snapshot().send_stigma_blocked_total,
            1
        );
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn send_pending_verified_allows_existing_contact_under_stigma() {
        let local_key = [142; 32];
        let issuer_key = SigningKey::from_bytes(&[143; 32]);
        let recipient_key = SigningKey::from_bytes(&[144; 32]);
        let runtime = PeerRuntime::start(
            identity_for(&local_key),
            local_key,
            "send-stigma-known".into(),
        )
        .await
        .expect("runtime");
        let now = current_unix_time();
        set_runtime_stigma(
            &runtime,
            &issuer_key,
            true,
            now - crate::dht::BADGE_REFLECTION_PERIOD_SECS - 60,
        )
        .await;
        let recipient_id = NodeId::from_public_key(&recipient_key.verifying_key());
        runtime
            .ctx
            .hosts
            .lock()
            .unwrap()
            .pin_manual(
                &recipient_id.to_hex(),
                &hex::encode(recipient_key.verifying_key().to_bytes()),
                now,
            )
            .expect("pin existing recipient");

        runtime
            .send_pending_verified(
                "127.0.0.1:1",
                &hex::encode(recipient_key.verifying_key().to_bytes()),
            )
            .await
            .expect("existing contact is exempt from stigma gate");
        assert_eq!(
            runtime.trust_metrics().snapshot().send_stigma_blocked_total,
            0
        );
        assert_eq!(
            runtime.trust_metrics().snapshot().send_watching_seen_total,
            0
        );
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn send_pending_verified_blocks_clean_unknown_cold_contact() {
        let local_key = [145; 32];
        let stranger_key = SigningKey::from_bytes(&[146; 32]);
        let runtime = PeerRuntime::start(
            identity_for(&local_key),
            local_key,
            "send-stigma-clean".into(),
        )
        .await
        .expect("runtime");

        let blocked_before = runtime
            .ctx
            .abuse_metrics
            .snapshot()
            .trust_gate_blocked_total;
        let error = runtime
            .send_pending_verified(
                "127.0.0.1:1",
                &hex::encode(stranger_key.verifying_key().to_bytes()),
            )
            .await
            .expect_err("unknown peer is blocked by trust gate");
        assert!(error.to_string().contains("blocked by trust gate"));
        assert_eq!(
            runtime.trust_metrics().snapshot().send_stigma_blocked_total,
            0
        );
        assert_eq!(
            runtime.trust_metrics().snapshot().send_watching_seen_total,
            0
        );
        assert_eq!(
            runtime
                .ctx
                .abuse_metrics
                .snapshot()
                .trust_gate_blocked_total,
            blocked_before + 1
        );
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn send_pending_verified_throttled_by_watching_gate() {
        let local_key = [147; 32];
        let issuer_key = SigningKey::from_bytes(&[148; 32]);
        let stranger_key = SigningKey::from_bytes(&[149; 32]);
        let runtime = PeerRuntime::start(
            identity_for(&local_key),
            local_key,
            "send-stigma-watching".into(),
        )
        .await
        .expect("runtime");
        let now = current_unix_time();
        set_runtime_stigma(&runtime, &issuer_key, false, now - 60).await;
        assert!(matches!(
            runtime.ctx.stigma_gate(&runtime.dht_local_id, now).await,
            StigmaLevel::Watching { .. }
        ));

        let blocked_before = runtime
            .ctx
            .abuse_metrics
            .snapshot()
            .trust_gate_blocked_total;
        let error = runtime
            .send_pending_verified(
                "127.0.0.1:1",
                &hex::encode(stranger_key.verifying_key().to_bytes()),
            )
            .await
            .expect_err("Watching tier is throttled by trust gate");
        assert!(error.to_string().contains("blocked by trust gate"));
        assert_eq!(
            runtime.trust_metrics().snapshot().send_stigma_blocked_total,
            0
        );
        assert_eq!(
            runtime.trust_metrics().snapshot().send_watching_seen_total,
            1
        );
        assert_eq!(
            runtime
                .ctx
                .abuse_metrics
                .snapshot()
                .trust_gate_blocked_total,
            blocked_before + 1
        );
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn send_pending_trusted_blocks_cold_contact_under_stigma() {
        let local_key = [150; 32];
        let issuer_key = SigningKey::from_bytes(&[151; 32]);
        let stranger_key = SigningKey::from_bytes(&[152; 32]);
        let runtime = PeerRuntime::start(
            identity_for(&local_key),
            local_key,
            "send-trusted-stigma".into(),
        )
        .await
        .expect("runtime");
        let now = current_unix_time();
        set_runtime_stigma(
            &runtime,
            &issuer_key,
            true,
            now - crate::dht::BADGE_REFLECTION_PERIOD_SECS - 60,
        )
        .await;
        let recipient = NodeId::from_public_key(&stranger_key.verifying_key());

        let error = runtime
            .send_pending_trusted(recipient, "127.0.0.1:1")
            .await
            .expect_err("trusted API also blocks cold contact under stigma");
        assert_eq!(
            error.to_string(),
            "cold contact forbidden: sender under stigma"
        );
        assert_eq!(
            runtime.trust_metrics().snapshot().send_stigma_blocked_total,
            1
        );
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn relay_rejects_requester_under_stigma() {
        let local_key = [125; 32];
        let requester_key = SigningKey::from_bytes(&[126; 32]);
        let requester_id = NodeId::from_public_key(&requester_key.verifying_key());
        let requester_pubkey = hex::encode(requester_key.verifying_key().to_bytes());
        let target_id = NodeId::from_bytes([127; 32]);
        let issuer_key = SigningKey::from_bytes(&[128; 32]);
        let issuer_id = NodeId::from_public_key(&issuer_key.verifying_key());
        let runtime = PeerRuntime::start(
            identity_for(&local_key),
            local_key,
            "relay-stigma-reject".into(),
        )
        .await
        .expect("runtime");

        {
            let mut hosts = runtime.ctx.hosts.lock().unwrap();
            hosts
                .pin_manual(&requester_id.to_hex(), &requester_pubkey, 1_000)
                .expect("pin requester as known host");
            hosts
                .pin_manual(
                    &issuer_id.to_hex(),
                    &hex::encode(issuer_key.verifying_key().to_bytes()),
                    1_000,
                )
                .expect("pin issuer as known host");
        }
        let now = 1_700_000_000;
        {
            let mut store = runtime.ctx.badge_store.lock().await;
            store
                .publish(test_badge_for_requester(
                    requester_id,
                    issuer_id,
                    now - crate::dht::BADGE_REFLECTION_PERIOD_SECS - 60,
                    &issuer_key,
                ))
                .expect("publish badge");
        }

        let envelope = SyncEnvelope::new(
            requester_id.to_hex(),
            hex::encode(requester_key.verifying_key().to_bytes()),
            Vec::new(),
        );
        let request = crate::relay::RelayRequest::create(
            requester_id,
            target_id,
            serde_json::to_vec(&envelope).expect("serialize envelope"),
            crate::relay::RELAY_DEFAULT_TTL_SECS,
            now,
            Vec::new(),
            &requester_key,
            [129; 16],
        )
        .expect("relay request");

        let response = test_relay_service(&runtime)
            .do_handle(&request, now + 1)
            .await;
        assert!(matches!(
            response,
            crate::relay::RelayResponse::Rejected { reason } if reason == "requester under stigma"
        ));
        assert_eq!(
            test_relay_service(&runtime)
                .metrics()
                .stigma_rejected_total
                .load(Ordering::Relaxed),
            1
        );

        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn relay_rejected_when_requester_warning() {
        let local_key = [140; 32];
        let requester_key = SigningKey::from_bytes(&[141; 32]);
        let requester_id = NodeId::from_public_key(&requester_key.verifying_key());
        let runtime =
            PeerRuntime::start(identity_for(&local_key), local_key, "relay-warning".into())
                .await
                .expect("runtime");
        let now = unix_now();
        let start = now.saturating_sub(200);
        {
            let mut rates = runtime.ctx.rates.lock().unwrap();
            for timestamp in start..start + crate::dht::rate_limit::RATE_MESSAGES_PER_HOUR as u64 {
                assert!(rates.check_message(&requester_id, timestamp).is_allowed());
            }
            let reject_start = start + crate::dht::rate_limit::RATE_MESSAGES_PER_HOUR as u64;
            for timestamp in reject_start..reject_start + 10 {
                assert!(rates.check_message(&requester_id, timestamp).is_rejected());
            }
        }
        let envelope = SyncEnvelope::new(
            requester_id.to_hex(),
            hex::encode(requester_key.verifying_key().to_bytes()),
            Vec::new(),
        );
        let request = crate::relay::RelayRequest::create(
            requester_id,
            NodeId::from_bytes([142; 32]),
            serde_json::to_vec(&envelope).expect("serialize envelope"),
            crate::relay::RELAY_DEFAULT_TTL_SECS,
            now,
            Vec::new(),
            &requester_key,
            [143; 16],
        )
        .expect("relay request");

        let response = test_relay_service(&runtime)
            .do_handle(&request, now + 1)
            .await;

        assert!(matches!(
            response,
            crate::relay::RelayResponse::Rejected { reason }
                if reason == "tier-aware rate exceeded"
        ));
        assert_eq!(
            runtime
                .ctx
                .abuse_metrics
                .rate_throttled_by_warning_total
                .load(Ordering::Relaxed),
            1
        );
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn relay_allows_requester_under_watching() {
        let local_key = [130; 32];
        let requester_key = SigningKey::from_bytes(&[131; 32]);
        let requester_id = NodeId::from_public_key(&requester_key.verifying_key());
        let requester_pubkey = hex::encode(requester_key.verifying_key().to_bytes());
        let target_id = NodeId::from_bytes([132; 32]);
        let issuer_key = SigningKey::from_bytes(&[133; 32]);
        let issuer_id = NodeId::from_public_key(&issuer_key.verifying_key());
        let runtime = PeerRuntime::start(
            identity_for(&local_key),
            local_key,
            "relay-stigma-watching".into(),
        )
        .await
        .expect("runtime");

        {
            let mut hosts = runtime.ctx.hosts.lock().unwrap();
            hosts
                .pin_manual(&requester_id.to_hex(), &requester_pubkey, 1_000)
                .expect("pin requester as known host");
            hosts
                .pin_manual(
                    &issuer_id.to_hex(),
                    &hex::encode(issuer_key.verifying_key().to_bytes()),
                    1_000,
                )
                .expect("pin issuer as known host");
        }

        let now = 1_700_000_100;
        {
            let mut store = runtime.ctx.badge_store.lock().await;
            store
                .publish(test_badge_for_requester(
                    requester_id,
                    issuer_id,
                    now - 60,
                    &issuer_key,
                ))
                .expect("publish single badge");
        }

        let envelope = SyncEnvelope::new(
            requester_id.to_hex(),
            hex::encode(requester_key.verifying_key().to_bytes()),
            Vec::new(),
        );
        let request = crate::relay::RelayRequest::create(
            requester_id,
            target_id,
            serde_json::to_vec(&envelope).expect("serialize envelope"),
            crate::relay::RELAY_DEFAULT_TTL_SECS,
            now,
            Vec::new(),
            &requester_key,
            [134; 16],
        )
        .expect("relay request");

        let response = test_relay_service(&runtime)
            .do_handle(&request, now + 1)
            .await;
        assert!(
            matches!(&response, crate::relay::RelayResponse::Rejected { reason } if reason == "target endpoint not found")
                || matches!(response, crate::relay::RelayResponse::Error { .. })
        );
        assert_eq!(
            test_relay_service(&runtime)
                .metrics()
                .watching_seen_total
                .load(Ordering::Relaxed),
            1
        );

        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn relay_allows_clean_requester() {
        let local_key = [135; 32];
        let requester_key = SigningKey::from_bytes(&[136; 32]);
        let requester_id = NodeId::from_public_key(&requester_key.verifying_key());
        let requester_pubkey = hex::encode(requester_key.verifying_key().to_bytes());
        let target_id = NodeId::from_bytes([137; 32]);
        let runtime = PeerRuntime::start(identity_for(&local_key), local_key, "relay-clean".into())
            .await
            .expect("runtime");

        {
            let mut hosts = runtime.ctx.hosts.lock().unwrap();
            hosts
                .pin_manual(&requester_id.to_hex(), &requester_pubkey, 1_000)
                .expect("pin requester as known host");
        }

        let now = 1_700_000_200;
        let envelope = SyncEnvelope::new(
            requester_id.to_hex(),
            hex::encode(requester_key.verifying_key().to_bytes()),
            Vec::new(),
        );
        let request = crate::relay::RelayRequest::create(
            requester_id,
            target_id,
            serde_json::to_vec(&envelope).expect("serialize envelope"),
            crate::relay::RELAY_DEFAULT_TTL_SECS,
            now,
            Vec::new(),
            &requester_key,
            [138; 16],
        )
        .expect("relay request");

        let response = test_relay_service(&runtime)
            .do_handle(&request, now + 1)
            .await;
        assert!(
            matches!(&response, crate::relay::RelayResponse::Rejected { reason } if reason == "target endpoint not found")
                || matches!(response, crate::relay::RelayResponse::Error { .. })
        );
        assert_eq!(
            test_relay_service(&runtime)
                .metrics()
                .watching_seen_total
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            test_relay_service(&runtime)
                .metrics()
                .stigma_rejected_total
                .load(Ordering::Relaxed),
            0
        );

        runtime.stop().await.expect("stop");
    }

    #[test]
    fn relay_request_malformed_envelope_rejected() {
        let executor = tokio::runtime::Runtime::new().expect("create runtime");
        executor.block_on(async {
            let key = [111; 32];
            let signing_key = SigningKey::from_bytes(&key);
            let requester_id = NodeId::from_public_key(&signing_key.verifying_key());
            let request = crate::relay::RelayRequest::create(
                requester_id,
                NodeId::from_bytes([112; 32]),
                b"not json".to_vec(),
                crate::relay::RELAY_DEFAULT_TTL_SECS,
                1_700_000_000,
                Vec::new(),
                &signing_key,
                [113; 16],
            )
            .expect("relay request");
            let runtime = PeerRuntime::start(identity_for(&key), key, "relay-malformed".into())
                .await
                .expect("runtime");

            let response = test_relay_service(&runtime)
                .do_handle(&request, 1_700_000_001)
                .await;
            assert!(matches!(
                response,
                crate::relay::RelayResponse::Rejected { reason }
                    if reason.starts_with("malformed envelope:")
            ));
            runtime.stop().await.expect("stop");
        });
    }

    #[test]
    fn relay_request_invalid_pubkey_rejected() {
        let executor = tokio::runtime::Runtime::new().expect("create runtime");
        executor.block_on(async {
            let key = [114; 32];
            let signing_key = SigningKey::from_bytes(&key);
            let requester_id = NodeId::from_public_key(&signing_key.verifying_key());
            let envelope = SyncEnvelope::new("requester".into(), "not hex".into(), Vec::new());
            let request = crate::relay::RelayRequest::create(
                requester_id,
                NodeId::from_bytes([115; 32]),
                serde_json::to_vec(&envelope).expect("serialize envelope"),
                crate::relay::RELAY_DEFAULT_TTL_SECS,
                1_700_000_000,
                Vec::new(),
                &signing_key,
                [116; 16],
            )
            .expect("relay request");
            let runtime = PeerRuntime::start(identity_for(&key), key, "relay-bad-key".into())
                .await
                .expect("runtime");

            let response = test_relay_service(&runtime)
                .do_handle(&request, 1_700_000_001)
                .await;
            assert_eq!(
                response,
                crate::relay::RelayResponse::Rejected {
                    reason: "invalid envelope public_key".into()
                }
            );
            runtime.stop().await.expect("stop");
        });
    }

    #[test]
    fn relay_request_self_relay_rejected() {
        let executor = tokio::runtime::Runtime::new().expect("create runtime");
        executor.block_on(async {
            let key = [117; 32];
            let signing_key = SigningKey::from_bytes(&key);
            let requester_id = NodeId::from_public_key(&signing_key.verifying_key());
            let envelope = SyncEnvelope::new(
                "requester".into(),
                hex::encode(signing_key.verifying_key().to_bytes()),
                Vec::new(),
            );
            let request = crate::relay::RelayRequest {
                requester_id,
                target_id: requester_id,
                envelope_bytes: serde_json::to_vec(&envelope).expect("serialize envelope"),
                nonce: [118; 16],
                created_at: 1_700_000_000,
                expires_at: 1_700_000_060,
                relay_chain: Vec::new(),
                signature: [0; 64],
            };
            let runtime = PeerRuntime::start(identity_for(&key), key, "relay-self".into())
                .await
                .expect("runtime");

            let response = test_relay_service(&runtime)
                .do_handle(&request, 1_700_000_001)
                .await;
            assert!(matches!(
                response,
                crate::relay::RelayResponse::Rejected { reason }
                    if reason.contains("requester and target are the same")
            ));
            runtime.stop().await.expect("stop");
        });
    }

    #[tokio::test]
    async fn relay_request_through_envelope_is_processed() {
        let local_key = [119; 32];
        let remote_key = SigningKey::from_bytes(&[120; 32]);
        let remote_id = NodeId::from_public_key(&remote_key.verifying_key());
        let runtime =
            PeerRuntime::start(identity_for(&local_key), local_key, "relay-ingress".into())
                .await
                .expect("runtime");
        let (tx, mut rx) = mpsc::channel(crate::relay_service::RELAY_QUEUE_CAPACITY);
        *runtime.ctx.relay_tx.lock().await = Some(tx);
        let request = crate::relay::RelayRequest::create(
            remote_id,
            NodeId::from_bytes([121; 32]),
            b"opaque envelope".to_vec(),
            crate::relay::RELAY_DEFAULT_TTL_SECS,
            1_700_000_000,
            Vec::new(),
            &remote_key,
            [122; 16],
        )
        .expect("relay request");
        let mut event = SyncEvent::new(
            "relay-request-test".into(),
            SyncEventType::RelayRequest,
            request.to_base64().expect("encode relay request"),
        );
        event.sign(&remote_key.to_bytes()).expect("sign event");
        let envelope = SyncEnvelope::new(
            hex::encode(remote_id.as_bytes()),
            hex::encode(remote_key.verifying_key().to_bytes()),
            vec![event],
        );

        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&runtime.ctx)).await;
        let work = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("relay work timeout")
            .expect("relay channel closed");
        assert_eq!(work.from_identity, hex::encode(remote_id.as_bytes()));
        assert_eq!(work.request.target_id, NodeId::from_bytes([121; 32]));
        assert_eq!(work.request.nonce, [122; 16]);
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn relay_queue_backpressure_no_drop() {
        let (tx, mut rx) = mpsc::channel::<usize>(crate::relay_service::RELAY_QUEUE_CAPACITY);
        let producer = tokio::spawn(async move {
            for item in 0..200 {
                tx.send(item).await.expect("queue receiver");
            }
        });
        for expected in 0..200 {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), rx.recv())
                    .await
                    .expect("queue receive timeout"),
                Some(expected)
            );
        }
        producer.await.expect("producer task");
    }

    #[tokio::test]
    async fn relay_worker_shutdown_clean() {
        let key = [123; 32];
        let runtime = PeerRuntime::start(identity_for(&key), key, "relay-shutdown".into())
            .await
            .expect("runtime");
        let service = test_relay_service(&runtime);
        let (_tx, rx) = mpsc::channel(crate::relay_service::RELAY_QUEUE_CAPACITY);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let worker = tokio::spawn(RelayWorkerTask::new(service).run(rx, shutdown_rx));
        shutdown_tx.send(()).expect("worker shutdown channel");
        tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .expect("worker shutdown timeout")
            .expect("worker join");
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn relay_response_correlates_by_nonce() {
        let key = [124; 32];
        let runtime = PeerRuntime::start(identity_for(&key), key, "relay-tracker".into())
            .await
            .expect("runtime");
        let service = test_relay_service(&runtime);
        let nonce = [125; 16];
        let (tx, rx) = oneshot::channel();
        service.tracker().lock().await.insert(nonce, tx);
        service
            .deliver_to_tracker(nonce, crate::relay::RelayResponse::Forwarded)
            .await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), rx)
                .await
                .expect("tracker response timeout")
                .expect("tracker sender dropped"),
            crate::relay::RelayResponse::Forwarded
        );
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn relay_consent_valid_request_accepted() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let requester_key = [126; 32];
        let relay_key = [127; 32];
        let target_key = [128; 32];
        let requester = PeerRuntime::start(
            identity_for(&requester_key),
            requester_key,
            "relay-e2e-requester".into(),
        )
        .await
        .expect("requester runtime");
        let relay = PeerRuntime::start(
            identity_for(&relay_key),
            relay_key,
            "relay-e2e-relay".into(),
        )
        .await
        .expect("relay runtime");
        let target = PeerRuntime::start(
            identity_for(&target_key),
            target_key,
            "relay-e2e-target".into(),
        )
        .await
        .expect("target runtime");
        requester
            .pin_peer(&relay.identity_id, &relay.public_key)
            .await
            .expect("pin relay at requester");
        relay
            .pin_peer(&requester.identity_id, &requester.public_key)
            .await
            .expect("pin requester at relay");
        relay
            .pin_peer(&target.identity_id, &target.public_key)
            .await
            .expect("pin target at relay");
        target
            .pin_peer(&relay.identity_id, &relay.public_key)
            .await
            .expect("pin relay at target");
        target
            .pin_peer(&requester.identity_id, &requester.public_key)
            .await
            .expect("pin requester at target");
        for peer in [&requester] {
            let record = EndpointRecord::create(
                peer.identity_id.clone(),
                peer.public_key.clone(),
                vec![peer.transport_address.clone()],
                &peer.private_key,
                now,
                crate::dht::ENDPOINT_TTL_SECONDS,
            )
            .expect("create signed endpoint record");
            relay
                .dht_cache
                .lock()
                .await
                .insert(record)
                .expect("cache endpoint record");
        }
        relay
            .ctx
            .peer_directory
            .lock()
            .await
            .record_outbound(
                target.transport_address.clone(),
                target.identity_id.clone(),
                target.public_key.clone(),
                now,
            )
            .expect("record authenticated target endpoint");

        let nonce = [129; 16];
        let (response_tx, response_rx) = oneshot::channel();
        requester
            .ctx
            .relay_tracker
            .lock()
            .await
            .insert(nonce, response_tx);
        let contact_pubkey = test_pubkey(131);
        let mut inner_event = SyncEvent::new(
            "relay-e2e-payload".into(),
            SyncEventType::ContactAdded,
            serde_json::json!({"pubkey": contact_pubkey, "name": "Relayed contact"}).to_string(),
        );
        inner_event
            .sign(&requester.private_key.to_bytes())
            .expect("sign payload");
        let inner_envelope = SyncEnvelope::new(
            requester.identity_id.clone(),
            requester.public_key.clone(),
            vec![inner_event],
        );
        let request = crate::relay::RelayRequest::create(
            requester.dht_local_id,
            target.dht_local_id,
            serde_json::to_vec(&inner_envelope).expect("serialize inner envelope"),
            crate::relay::RELAY_DEFAULT_TTL_SECS,
            now,
            Vec::new(),
            &requester.private_key,
            nonce,
        )
        .expect("create relay request");
        let mut outer_event = SyncEvent::new(
            hex::encode(nonce),
            SyncEventType::RelayRequest,
            request.to_base64().expect("encode relay request"),
        );
        outer_event
            .sign(&requester.private_key.to_bytes())
            .expect("sign relay event");
        let outer_envelope = SyncEnvelope::new(
            requester.identity_id.clone(),
            requester.public_key.clone(),
            vec![outer_event],
        );
        crate::transport::send_envelope_secure_with_stream_kind(
            &relay.transport_address,
            &outer_envelope,
            &requester.private_key,
            Arc::clone(&requester.ctx.hosts),
            None,
            requester.trust_policy.clone(),
            crate::mux::StreamKind::Sync,
        )
        .await
        .expect("send relay request to relay node");

        let relay_response = tokio::time::timeout(Duration::from_secs(5), response_rx)
            .await
            .expect("relay response timeout")
            .expect("relay response sender dropped");
        assert_eq!(relay_response, crate::relay::RelayResponse::Forwarded);
        tokio::time::timeout(Duration::from_secs(5), async {
            while target.ctx.relay_metrics.snapshot().forward_received_total == 0
                || target
                    .ctx
                    .abuse_metrics
                    .snapshot()
                    .relay_consent_verified_total
                    == 0
                || relay.ctx.relay_metrics.snapshot().response_sent_total == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("target relay dispatcher did not process inner envelope");
        assert_eq!(target.contact_count().await, 1);
        assert_eq!(relay.ctx.relay_metrics.snapshot().forwarded_total, 1);
        assert_eq!(relay.ctx.relay_metrics.snapshot().response_sent_total, 1);
        let target_metrics = target.ctx.relay_metrics.snapshot();
        assert_eq!(target_metrics.forward_received_total, 1);
        assert_eq!(target_metrics.forward_rejected_depth, 0);
        assert_eq!(target_metrics.forward_rejected_binding, 0);
        assert_eq!(
            target
                .ctx
                .abuse_metrics
                .snapshot()
                .relay_consent_verified_total,
            1
        );

        requester.stop().await.expect("stop requester");
        relay.stop().await.expect("stop relay");
        target.stop().await.expect("stop target");
    }

    #[tokio::test]
    async fn relay_fallback_stays_pending_until_recipient_ack() {
        let requester_key = [132; 32];
        let relay_key = [133; 32];
        let target_key = SigningKey::from_bytes(&[134; 32]);
        let requester = PeerRuntime::start(
            identity_for(&requester_key),
            requester_key,
            "relay-fallback-requester".into(),
        )
        .await
        .expect("requester runtime");
        let target = PeerRuntime::start(
            NodeId::from_public_key(&target_key.verifying_key()).to_hex(),
            target_key.to_bytes(),
            "relay-fallback-target".into(),
        )
        .await
        .expect("target runtime");
        let relay = PeerRuntime::start(
            identity_for(&relay_key),
            relay_key,
            "relay-fallback-relay".into(),
        )
        .await
        .expect("relay runtime");
        requester
            .record_invite_peer(
                relay.transport_address.clone(),
                &relay.identity_id,
                &relay.public_key,
            )
            .await
            .expect("record trusted relay");
        relay
            .pin_peer(&requester.identity_id, &requester.public_key)
            .await
            .expect("pin requester at relay");
        relay
            .pin_peer(&target.identity_id, &target.public_key)
            .await
            .expect("pin target at relay");
        target
            .pin_peer(&relay.identity_id, &relay.public_key)
            .await
            .expect("pin relay at target");
        target
            .pin_peer(&requester.identity_id, &requester.public_key)
            .await
            .expect("pin requester at target");
        relay
            .ctx
            .peer_directory
            .lock()
            .await
            .record_outbound(
                target.transport_address.clone(),
                target.identity_id.clone(),
                target.public_key.clone(),
                unix_now(),
            )
            .expect("record authenticated target endpoint");
        let target_endpoint = EndpointRecord::create(
            target.identity_id.clone(),
            target.public_key.clone(),
            vec![target.transport_address.clone()],
            &target.private_key,
            unix_now(),
            crate::dht::ENDPOINT_TTL_SECONDS,
        )
        .expect("create target endpoint record");
        relay
            .dht_cache
            .lock()
            .await
            .insert(target_endpoint)
            .expect("publish target endpoint to relay cache");
        let relay_endpoint = EndpointRecord::create(
            relay.identity_id.clone(),
            relay.public_key.clone(),
            vec![relay.transport_address.clone()],
            &relay.private_key,
            unix_now(),
            crate::dht::ENDPOINT_TTL_SECONDS,
        )
        .expect("create relay endpoint")
        .with_relay(true, &relay.private_key);
        requester
            .dht_cache
            .lock()
            .await
            .insert(relay_endpoint)
            .expect("publish relay endpoint to requester cache");

        let mut event = SyncEvent::new(
            "relay-fallback-payload".into(),
            SyncEventType::ContactAdded,
            serde_json::json!({"pubkey": test_pubkey(135), "name": "Relay fallback test"})
                .to_string(),
        );
        event
            .sign(&requester.private_key.to_bytes())
            .expect("sign inner event");
        let envelope = SyncEnvelope::new(
            requester.identity_id.clone(),
            requester.public_key.clone(),
            vec![event],
        );
        let target_id = NodeId::from_public_key(&target_key.verifying_key());
        let now = unix_now();
        let error = requester
            .relay_fallback_after_direct_failure(
                &target_id,
                &envelope,
                now,
                "TCP connect failed; QUIC connect failed".into(),
            )
            .await
            .expect_err("relay transport acceptance must not confirm delivery");
        assert!(
            error
                .to_string()
                .contains("timed out waiting for RelayResponse"),
            "unexpected relay fallback result: {error}"
        );

        tokio::time::timeout(Duration::from_secs(5), async {
            while relay.ctx.relay_metrics.snapshot().forwarded_total == 0
                || target.ctx.relay_metrics.snapshot().forward_received_total == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("relay did not forward fallback request to the target");
        requester.stop().await.expect("stop requester");
        relay.stop().await.expect("stop relay");
        target.stop().await.expect("stop target");
    }

    fn relay_request_for_inner(
        requester_key: &SigningKey,
        inner: &SyncEnvelope,
        target_id: NodeId,
        nonce: [u8; 16],
        now: u64,
        ttl_secs: u64,
    ) -> crate::relay::RelayRequest {
        crate::relay::RelayRequest::create(
            NodeId::from_public_key(&requester_key.verifying_key()),
            target_id,
            serde_json::to_vec(inner).expect("serialize consent envelope"),
            ttl_secs,
            now,
            Vec::new(),
            requester_key,
            nonce,
        )
        .expect("create requester consent")
    }

    fn relay_forward_envelope(
        relay_key: &SigningKey,
        inner: &SyncEnvelope,
        nonce: [u8; 16],
        requester_consent: String,
    ) -> SyncEnvelope {
        let inner_public_key: [u8; 32] = hex::decode(&inner.public_key)
            .expect("inner public key hex")
            .try_into()
            .expect("inner public key length");
        let inner_verifying_key = VerifyingKey::from_bytes(&inner_public_key).expect("inner key");
        let requester_id = NodeId::from_public_key(&inner_verifying_key);
        let forward = crate::relay::RelayForwardEvent {
            requester_id,
            requester_identity_id: inner.identity_id.clone(),
            requester_public_key_hex: inner.public_key.clone(),
            relay_nonce: nonce,
            requester_consent,
            inner_envelope_base64: base64::engine::general_purpose::STANDARD
                .encode(serde_json::to_vec(inner).expect("serialize inner envelope")),
            forwarded_at: current_unix_time(),
        };
        relay_forward_envelope_data(
            relay_key,
            nonce,
            forward.to_base64().expect("encode relay forward"),
        )
    }

    fn relay_forward_envelope_without_consent(
        relay_key: &SigningKey,
        inner: &SyncEnvelope,
        nonce: [u8; 16],
    ) -> SyncEnvelope {
        let inner_public_key: [u8; 32] = hex::decode(&inner.public_key)
            .expect("inner public key hex")
            .try_into()
            .expect("inner public key length");
        let inner_verifying_key = VerifyingKey::from_bytes(&inner_public_key).expect("inner key");
        let requester_id = NodeId::from_public_key(&inner_verifying_key);
        let forward_without_consent = serde_json::json!({
            "requester_id": requester_id,
            "requester_identity_id": inner.identity_id,
            "requester_public_key_hex": inner.public_key,
            "relay_nonce": nonce,
            "inner_envelope_base64": base64::engine::general_purpose::STANDARD
                .encode(serde_json::to_vec(inner).expect("serialize inner envelope")),
            "forwarded_at": current_unix_time(),
        });
        let encoded = base64::engine::general_purpose::STANDARD.encode(
            serde_json::to_vec(&forward_without_consent)
                .expect("serialize forward without consent"),
        );
        relay_forward_envelope_data(relay_key, nonce, encoded)
    }

    fn relay_forward_envelope_data(
        relay_key: &SigningKey,
        nonce: [u8; 16],
        forward_data: String,
    ) -> SyncEnvelope {
        let mut event = SyncEvent::new(
            hex::encode(nonce),
            SyncEventType::RelayForward,
            forward_data,
        );
        event
            .sign(&relay_key.to_bytes())
            .expect("sign relay wrapper");
        let relay_verifying_key = relay_key.verifying_key();
        SyncEnvelope::new(
            NodeId::from_public_key(&relay_verifying_key).to_hex(),
            hex::encode(relay_verifying_key.to_bytes()),
            vec![event],
        )
    }

    async fn start_relay_inner_verification_receiver(
        seed: u8,
        relay_key: &SigningKey,
    ) -> PeerRuntime {
        let key = [seed; 32];
        let receiver = PeerRuntime::start(
            identity_for(&key),
            key,
            format!("relay-inner-verify-{seed}"),
        )
        .await
        .expect("receiver runtime");
        let relay_id = NodeId::from_public_key(&relay_key.verifying_key());
        receiver
            .pin_peer(
                &relay_id.to_hex(),
                &hex::encode(relay_key.verifying_key().to_bytes()),
            )
            .await
            .expect("pin relay");
        receiver
    }

    fn contact_added_envelope(
        sender_key: &SigningKey,
        event_signing_key: &SigningKey,
        event_id: &str,
        contact: &str,
    ) -> SyncEnvelope {
        let mut event = SyncEvent::new(
            event_id.into(),
            SyncEventType::ContactAdded,
            serde_json::json!({"pubkey": contact, "name": "Relay proof contact"}).to_string(),
        );
        event
            .sign(&event_signing_key.to_bytes())
            .expect("sign contact event");
        let verifying_key = sender_key.verifying_key();
        SyncEnvelope::new(
            NodeId::from_public_key(&verifying_key).to_hex(),
            hex::encode(verifying_key.to_bytes()),
            vec![event],
        )
    }

    #[tokio::test]
    async fn relay_inner_valid_signature_accepted() {
        let relay_key = SigningKey::from_bytes(&[220; 32]);
        let sender_key = SigningKey::from_bytes(&[221; 32]);
        let receiver = start_relay_inner_verification_receiver(222, &relay_key).await;
        let inner =
            contact_added_envelope(&sender_key, &sender_key, "valid-inner", "contact-valid");
        let nonce = [223; 16];
        let consent = relay_request_for_inner(
            &sender_key,
            &inner,
            receiver.dht_local_id,
            nonce,
            current_unix_time(),
            crate::relay::RELAY_DEFAULT_TTL_SECS,
        )
        .to_base64()
        .expect("encode requester consent");
        let outer = relay_forward_envelope(&relay_key, &inner, nonce, consent);

        PeerRuntime::process_incoming_envelope(outer, Arc::clone(&receiver.ctx)).await;

        assert_eq!(receiver.contact_count().await, 1);
        assert_eq!(
            receiver
                .ctx
                .abuse_metrics
                .snapshot()
                .relay_inner_verify_ok_total,
            1
        );
        assert_eq!(
            receiver
                .ctx
                .abuse_metrics
                .snapshot()
                .relay_inner_verify_failed_total,
            0
        );
        receiver.stop().await.expect("stop receiver");
    }

    #[tokio::test]
    async fn relay_inner_tampered_envelope_rejected() {
        let relay_key = SigningKey::from_bytes(&[224; 32]);
        let sender_key = SigningKey::from_bytes(&[225; 32]);
        let receiver = start_relay_inner_verification_receiver(226, &relay_key).await;
        let mut inner = contact_added_envelope(
            &sender_key,
            &sender_key,
            "tampered-inner",
            "contact-tampered",
        );
        inner.events[0].data = serde_json::json!({
            "pubkey": "contact-tampered",
            "name": "forged after signing"
        })
        .to_string();
        let nonce = [227; 16];
        let consent = relay_request_for_inner(
            &sender_key,
            &inner,
            receiver.dht_local_id,
            nonce,
            current_unix_time(),
            crate::relay::RELAY_DEFAULT_TTL_SECS,
        )
        .to_base64()
        .expect("encode requester consent");
        let outer = relay_forward_envelope(&relay_key, &inner, nonce, consent);

        PeerRuntime::process_incoming_envelope(outer, Arc::clone(&receiver.ctx)).await;

        assert_eq!(receiver.contact_count().await, 0);
        let metrics = receiver.ctx.abuse_metrics.snapshot();
        assert_eq!(metrics.relay_inner_verify_failed_total, 1);
        assert_eq!(metrics.relay_inner_verify_ok_total, 0);
        assert_eq!(
            receiver.ctx.relay_metrics.snapshot().forward_received_total,
            0
        );
        receiver.stop().await.expect("stop receiver");
    }

    #[tokio::test]
    async fn relay_inner_forged_pubkey_rejected() {
        let relay_key = SigningKey::from_bytes(&[228; 32]);
        let attacker_key = SigningKey::from_bytes(&[230; 32]);
        let receiver = start_relay_inner_verification_receiver(231, &relay_key).await;
        let victim_identity = identity_for(&[229; 32]);
        let inner = SyncEnvelope::new(
            victim_identity,
            hex::encode(attacker_key.verifying_key().to_bytes()),
            Vec::new(),
        );
        let nonce = [232; 16];
        let consent = relay_request_for_inner(
            &attacker_key,
            &inner,
            receiver.dht_local_id,
            nonce,
            current_unix_time(),
            crate::relay::RELAY_DEFAULT_TTL_SECS,
        )
        .to_base64()
        .expect("encode requester consent");
        let outer = relay_forward_envelope(&relay_key, &inner, nonce, consent);

        PeerRuntime::process_incoming_envelope(outer, Arc::clone(&receiver.ctx)).await;

        assert_eq!(receiver.contact_count().await, 0);
        assert_eq!(
            receiver
                .ctx
                .relay_metrics
                .snapshot()
                .forward_rejected_binding,
            1
        );
        assert_eq!(
            receiver
                .ctx
                .abuse_metrics
                .snapshot()
                .relay_inner_verify_ok_total,
            0
        );
        receiver.stop().await.expect("stop receiver");
    }

    #[tokio::test]
    async fn relay_inner_wrong_signature_rejected() {
        let relay_key = SigningKey::from_bytes(&[233; 32]);
        let sender_key = SigningKey::from_bytes(&[234; 32]);
        let attacker_key = SigningKey::from_bytes(&[235; 32]);
        let receiver = start_relay_inner_verification_receiver(236, &relay_key).await;
        let inner = contact_added_envelope(
            &sender_key,
            &attacker_key,
            "wrong-inner-sig",
            "contact-wrong-sig",
        );
        let nonce = [237; 16];
        let consent = relay_request_for_inner(
            &sender_key,
            &inner,
            receiver.dht_local_id,
            nonce,
            current_unix_time(),
            crate::relay::RELAY_DEFAULT_TTL_SECS,
        )
        .to_base64()
        .expect("encode requester consent");
        let outer = relay_forward_envelope(&relay_key, &inner, nonce, consent);

        PeerRuntime::process_incoming_envelope(outer, Arc::clone(&receiver.ctx)).await;

        assert_eq!(receiver.contact_count().await, 0);
        assert_eq!(
            receiver
                .ctx
                .abuse_metrics
                .snapshot()
                .relay_inner_verify_failed_total,
            1
        );
        receiver.stop().await.expect("stop receiver");
    }

    #[tokio::test]
    async fn direct_path_also_verifies_signature() {
        let sender_key = SigningKey::from_bytes(&[238; 32]);
        let attacker_key = SigningKey::from_bytes(&[239; 32]);
        let receiver_key = [240; 32];
        let receiver = PeerRuntime::start(
            identity_for(&receiver_key),
            receiver_key,
            "direct-signature-guard".into(),
        )
        .await
        .expect("receiver runtime");
        let inner = contact_added_envelope(
            &sender_key,
            &attacker_key,
            "direct-wrong-sig",
            "contact-direct-wrong-sig",
        );

        PeerRuntime::process_incoming_envelope(inner, Arc::clone(&receiver.ctx)).await;

        assert_eq!(receiver.contact_count().await, 0);
        assert_eq!(
            receiver.ctx.relay_metrics.snapshot().forward_received_total,
            0
        );
        receiver.stop().await.expect("stop receiver");
    }

    #[test]
    fn relay_forward_depth_exceeded_is_rejected() {
        let executor = tokio::runtime::Runtime::new().expect("create runtime");
        executor.block_on(async {
            let receiver_key = [132; 32];
            let relay_key = SigningKey::from_bytes(&[133; 32]);
            let relay_id = NodeId::from_public_key(&relay_key.verifying_key());
            let receiver = PeerRuntime::start(
                identity_for(&receiver_key),
                receiver_key,
                "relay-depth-guard".into(),
            )
            .await
            .expect("receiver runtime");
            receiver
                .pin_peer(
                    &hex::encode(relay_id.as_bytes()),
                    &hex::encode(relay_key.verifying_key().to_bytes()),
                )
                .await
                .expect("pin relay sender");
            let mut event = SyncEvent::new(
                "depth-guard".into(),
                SyncEventType::RelayForward,
                "not decoded at depth limit".into(),
            );
            event
                .sign(&relay_key.to_bytes())
                .expect("sign relay wrapper");
            let envelope = SyncEnvelope::new(
                hex::encode(relay_id.as_bytes()),
                hex::encode(relay_key.verifying_key().to_bytes()),
                vec![event],
            );
            PeerRuntime::process_incoming_envelope_inner(
                envelope,
                Arc::clone(&receiver.ctx),
                MAX_RELAY_FORWARD_DEPTH,
                EnvelopeMeta::default(),
            )
            .await;
            assert_eq!(
                receiver.ctx.relay_metrics.snapshot().forward_rejected_depth,
                1
            );
            assert_eq!(
                receiver.ctx.relay_metrics.snapshot().forward_received_total,
                0
            );
            receiver.stop().await.expect("stop");
        });
    }

    #[test]
    fn relay_forward_binding_mismatch_is_rejected() {
        let executor = tokio::runtime::Runtime::new().expect("create runtime");
        executor.block_on(async {
            let receiver_key = [134; 32];
            let relay_key = SigningKey::from_bytes(&[135; 32]);
            let requester_key = SigningKey::from_bytes(&[136; 32]);
            let relay_id = NodeId::from_public_key(&relay_key.verifying_key());
            let requester_id = NodeId::from_public_key(&requester_key.verifying_key());
            let receiver = PeerRuntime::start(
                identity_for(&receiver_key),
                receiver_key,
                "relay-binding-guard".into(),
            )
            .await
            .expect("receiver runtime");
            receiver
                .pin_peer(
                    &hex::encode(relay_id.as_bytes()),
                    &hex::encode(relay_key.verifying_key().to_bytes()),
                )
                .await
                .expect("pin relay sender");
            let inner = SyncEnvelope::new(
                hex::encode(requester_id.as_bytes()),
                hex::encode(requester_key.verifying_key().to_bytes()),
                Vec::new(),
            );
            let forward = crate::relay::RelayForwardEvent {
                requester_id: NodeId::from_bytes([137; 32]),
                requester_identity_id: inner.identity_id.clone(),
                requester_public_key_hex: inner.public_key.clone(),
                relay_nonce: [138; 16],
                requester_consent: "unused-for-binding-mismatch".into(),
                inner_envelope_base64: base64::engine::general_purpose::STANDARD
                    .encode(serde_json::to_vec(&inner).expect("serialize inner")),
                forwarded_at: 1_700_000_000,
            };
            let mut event = SyncEvent::new(
                hex::encode(forward.relay_nonce),
                SyncEventType::RelayForward,
                forward.to_base64().expect("encode forward"),
            );
            event
                .sign(&relay_key.to_bytes())
                .expect("sign relay wrapper");
            let envelope = SyncEnvelope::new(
                hex::encode(relay_id.as_bytes()),
                hex::encode(relay_key.verifying_key().to_bytes()),
                vec![event],
            );
            PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&receiver.ctx)).await;
            assert_eq!(
                receiver
                    .ctx
                    .relay_metrics
                    .snapshot()
                    .forward_rejected_binding,
                1
            );
            assert_eq!(
                receiver.ctx.relay_metrics.snapshot().forward_received_total,
                0
            );
            receiver.stop().await.expect("stop");
        });
    }

    #[test]
    fn runtime_publish_punch_request_format_picked() {
        let strategy = SignalingStrategy::explicit_only();
        let target_id = NodeId::from_bytes([101; 32]);
        assert_eq!(
            select_punch_request_format(&strategy, target_id, 1_700_000_000),
            crate::signaling::SignalingFormat::Explicit
        );
    }

    #[test]
    fn runtime_publish_punch_request_format_falls_back_to_explicit() {
        let mut strategy = SignalingStrategy::default_hybrid();
        strategy.formats.clear();
        assert_eq!(
            select_punch_request_format(&strategy, NodeId::from_bytes([102; 32]), 1_700_000_001),
            crate::signaling::SignalingFormat::Explicit
        );
    }

    #[test]
    fn runtime_publish_punch_request_without_dht_peers_fails_cleanly() {
        let executor = tokio::runtime::Runtime::new().expect("create runtime");
        executor.block_on(async {
            let runtime = PeerRuntime::start(
                identity_for(&[81; 32]),
                [81; 32],
                "publish-punch-request".into(),
            )
            .await
            .expect("start runtime");
            let result = runtime
                .publish_punch_request(NodeId::from_bytes([82; 32]), 300)
                .await;
            assert!(result.is_err());
            runtime.stop().await.expect("stop runtime");
        });
    }

    #[test]
    fn runtime_fetch_punch_requests_returns_empty_without_dht_peers() {
        let executor = tokio::runtime::Runtime::new().expect("create runtime");
        executor.block_on(async {
            let runtime = PeerRuntime::start(
                identity_for(&[83; 32]),
                [83; 32],
                "fetch-punch-requests".into(),
            )
            .await
            .expect("start runtime");
            let requests = runtime
                .fetch_punch_requests(runtime.dht_local_id)
                .await
                .expect("fetch from empty DHT route table");
            assert!(requests.is_empty());
            runtime.stop().await.expect("stop runtime");
        });
    }

    #[test]
    fn runtime_punch_from_requests_falls_back() {
        let executor = tokio::runtime::Runtime::new().expect("create runtime");
        executor.block_on(async {
            let runtime = PeerRuntime::start(
                identity_for(&[84; 32]),
                [84; 32],
                "punch-from-requests".into(),
            )
            .await
            .expect("start runtime");
            let outcome = runtime
                .punch_from_requests(NodeId::from_bytes([85; 32]), 0)
                .await;
            assert!(matches!(
                outcome,
                crate::PunchOutcome::Failed {
                    error: crate::PunchError::NoRemote
                }
            ));
            runtime.stop().await.expect("stop runtime");
        });
    }

    #[test]
    fn runtime_starts_punch_fetch_task() {
        let executor = tokio::runtime::Runtime::new().expect("create runtime");
        executor.block_on(async {
            let runtime = PeerRuntime::start(
                identity_for(&[86; 32]),
                [86; 32],
                "punch-fetch-start".into(),
            )
            .await
            .expect("start runtime");
            assert!(runtime.punch_fetch_task.is_some());
            assert!(runtime.punch_fetch_shutdown.is_some());
            runtime.stop().await.expect("stop runtime");
        });
    }

    #[test]
    fn runtime_stops_punch_fetch_task() {
        let executor = tokio::runtime::Runtime::new().expect("create runtime");
        executor.block_on(async {
            let runtime =
                PeerRuntime::start(identity_for(&[87; 32]), [87; 32], "punch-fetch-stop".into())
                    .await
                    .expect("start runtime");
            tokio::time::timeout(Duration::from_secs(10), runtime.stop())
                .await
                .expect("runtime shutdown timeout")
                .expect("stop runtime");
        });
    }

    #[tokio::test]
    async fn runtime_starts_and_stops_badge_fetch_task() {
        let runtime = PeerRuntime::start(
            identity_for(&[88; 32]),
            [88; 32],
            "badge-fetch-lifecycle".into(),
        )
        .await
        .expect("start runtime");
        let ctx = runtime.runtime_context();
        assert!(runtime.badge_fetch_task.is_some());
        assert!(runtime.badge_fetch_shutdown.is_some());
        assert!(!ctx
            .badge_fetch_shutdown
            .load(std::sync::atomic::Ordering::Relaxed));

        runtime.stop().await.expect("stop runtime");
        assert!(ctx
            .badge_fetch_shutdown
            .load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn runtime_quic_incoming_not_started_without_quic() {
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("create runtime executor");
        executor.block_on(async {
            let runtime =
                PeerRuntime::start(identity_for(&[61; 32]), [61; 32], "without-quic".into())
                    .await
                    .expect("runtime");
            assert!(!runtime.transport.has_quic());
            assert!(runtime.quic_incoming_task.is_none());
            runtime.stop().await.expect("stop runtime");
        });
    }

    #[test]
    fn runtime_quic_incoming_shutdown_none_by_default() {
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("create runtime executor");
        executor.block_on(async {
            let runtime =
                PeerRuntime::start(identity_for(&[62; 32]), [62; 32], "quic-shutdown".into())
                    .await
                    .expect("runtime");
            assert!(runtime.transport.incoming_tx().is_some());
            assert!(runtime.quic_incoming_shutdown.is_none());
            runtime.stop().await.expect("stop runtime");
        });
    }

    #[tokio::test]
    async fn received_contact_is_persisted_in_peer_storage() {
        let key_a = [33; 32];
        let key_b = [34; 32];
        let path = std::env::temp_dir().join(format!("hal-sync-{}.sqlite3", uuid::Uuid::new_v4()));
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[0x42u8; 32]).expect("storage"),
        ));
        let mut a = PeerRuntime::start_with_policy(
            identity_for(&key_a),
            key_a,
            "android".into(),
            None,
            trusted_local_policy(),
        )
        .await
        .expect("runtime a");
        let mut b = PeerRuntime::start_with_policy(
            identity_for(&key_b),
            key_b,
            "desktop".into(),
            Some(Arc::clone(&storage)),
            trusted_local_policy(),
        )
        .await
        .expect("runtime b");
        a.activate_listener(None, None)
            .await
            .expect("activate a listener");
        b.activate_listener(None, None)
            .await
            .expect("activate b listener");
        b.pin_peer(&a.identity_id, &a.public_key)
            .await
            .expect("pin peer");
        a.pin_peer(&b.identity_id, &b.public_key)
            .await
            .expect("pin recipient");
        a.add_contact(test_pubkey(2), "Persisted Peer".into())
            .await
            .expect("contact");
        a.add_message(
            "chat-1".into(),
            a.identity_id.clone(),
            Some(b.identity_id.clone()),
            "hello from peer".into(),
        )
        .await
        .expect("message");
        a.update_settings(SyncSettings {
            language: "en".into(),
            ..SyncSettings::default()
        })
        .await
        .expect("settings");
        a.send_pending_verified(&b.transport_address, &b.public_key)
            .await
            .expect("sync");
        let peer_contact = test_pubkey(2);
        let persisted = wait_until(
            || async {
                let guard = storage.lock().expect("storage lock");
                let contacts = guard.contacts_json().expect("contacts");
                contacts.contains("Persisted Peer") || contacts.contains(&peer_contact)
            },
            Duration::from_secs(2),
        )
        .await;
        assert!(persisted, "contact was not persisted within 2s");
        let (message_persisted, settings_persisted) = {
            let storage_guard = storage.lock().expect("storage lock");
            (
                storage_guard
                    .messages_json(&a.public_key)
                    .expect("messages")
                    .contains("hello from peer"),
                storage_guard
                    .sync_storage()
                    .setting_json("settings")
                    .expect("setting")
                    .is_some(),
            )
        };
        assert!(message_persisted);
        assert_eq!(b.ctx.abuse_metrics.snapshot().messages_decrypted_total, 1);
        assert!(settings_persisted);
        a.stop().await.expect("stop a");
        b.stop().await.expect("stop b");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn create_invite_persists_first_seen() {
        let key = [0x61; 32];
        let path = std::env::temp_dir().join(format!("hal-sync-{}.sqlite3", uuid::Uuid::new_v4()));
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[0x62; 32]).expect("storage"),
        ));
        let issuer = NodeId::from_public_key(&SigningKey::from_bytes(&key).verifying_key());
        let now = unix_now();
        let first_seen = now - crate::dht::invite::NEW_IDENTITY_COOLDOWN_SECS - 60;
        {
            let storage_guard = storage.lock().expect("storage lock");
            storage_guard
                .upsert_invite_first_seen(issuer.as_bytes(), first_seen)
                .expect("seed persisted first-seen timestamp");
            let identity_history = storage_guard.identity_history();
            identity_history
                .observe_first_seen(
                    &issuer.to_hex(),
                    now - crate::proof_of_live::AGE_MIN_SECS - 1,
                )
                .expect("seed age proof");
            let required_uptime = (crate::proof_of_live::UPTIME_WINDOW_SECS as f64
                * crate::proof_of_live::UPTIME_MIN_RATIO as f64)
                .ceil() as u64;
            let mut observed_at = now - required_uptime;
            let mut event_index = 0u64;
            while observed_at <= now {
                identity_history
                    .record_activity(
                        &issuer.to_hex(),
                        observed_at,
                        &format!("invite-proof-{event_index}"),
                    )
                    .expect("seed activity proof");
                observed_at += 299;
                event_index += 1;
            }
        }

        let runtime = PeerRuntime::start_with_storage(
            identity_for(&key),
            key,
            "invite-first-seen".into(),
            Arc::clone(&storage),
        )
        .await
        .expect("runtime");
        runtime
            .ctx
            .hosts
            .lock()
            .expect("hosts lock")
            .pin_manual(&runtime.identity_id, &runtime.public_key, unix_now())
            .expect("pin local issuer");
        for offset in 1..=crate::dht::rate_limit::FIRST_CONTACT_ACCEPTED_THRESHOLD as u64 {
            assert!(runtime
                .ctx
                .record_rate_acceptance(&issuer, now - 31 * offset));
        }

        storage
            .lock()
            .expect("storage lock")
            .connection()
            .execute(
                "DELETE FROM invite_registry_first_seen WHERE node_id_hex = ?1",
                [issuer.to_hex()],
            )
            .expect("remove persisted timestamp before invite");

        let invite_link = runtime.create_invite(3600).await.expect("create invite");

        assert!(invite_link.starts_with("hal://connect#"));
        assert_eq!(
            storage
                .lock()
                .expect("storage lock")
                .read_invite_first_seen(issuer.as_bytes())
                .expect("read first-seen timestamp"),
            Some(first_seen)
        );

        runtime.stop().await.expect("stop runtime");
        let _ = std::fs::remove_file(path);
    }

    async fn invite_cutover_test_runtime(
        seed: u8,
    ) -> (
        PeerRuntime,
        Arc<StdMutex<ClientStorage>>,
        std::path::PathBuf,
    ) {
        let key = [seed; 32];
        let path = std::env::temp_dir().join(format!(
            "hal-invite-cutover-{}-{}.sqlite3",
            seed,
            uuid::Uuid::new_v4()
        ));
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[seed.wrapping_add(1); 32]).expect("open storage"),
        ));
        let runtime = PeerRuntime::start_with_storage(
            identity_for(&key),
            key,
            format!("invite-cutover-{seed}"),
            Arc::clone(&storage),
        )
        .await
        .expect("start runtime");
        (runtime, storage, path)
    }

    fn seed_cutover_peer(storage: &Arc<StdMutex<ClientStorage>>, peer: &NodeId) {
        storage
            .lock()
            .expect("storage lock")
            .identity_history()
            .observe_first_seen(&peer.to_hex(), 100)
            .expect("seed grandfather candidate");
    }

    #[tokio::test]
    async fn invite_cutover_emits_notification_for_peers_without_proof() {
        let (runtime, storage, path) = invite_cutover_test_runtime(0x63).await;
        let peer = NodeId::from_bytes([0x64; 32]);
        seed_cutover_peer(&storage, &peer);

        runtime
            .activate_invite_cutover(200)
            .await
            .expect("activate invite cutover");

        let home_state = runtime.ctx.home_state.lock().await;
        let pending = home_state.notifications.pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].kind,
            crate::dht::notifier::NotificationKind::InviteRedemptionRequired
        );
        assert_eq!(pending[0].from, peer);
        assert_eq!(pending[0].subject, runtime.dht_local_id);
        drop(home_state);

        runtime.stop().await.expect("stop runtime");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn invite_cutover_does_not_emit_for_peers_with_proof() {
        let (runtime, storage, path) = invite_cutover_test_runtime(0x65).await;
        let peer = NodeId::from_bytes([0x66; 32]);
        seed_cutover_peer(&storage, &peer);
        hal_storage::invite_storage::upsert_invite_proof(
            storage.lock().expect("storage lock").connection(),
            &peer.to_hex(),
            b"proof",
            150,
        )
        .expect("seed invite proof");

        runtime
            .activate_invite_cutover(200)
            .await
            .expect("activate invite cutover");

        assert!(runtime
            .ctx
            .home_state
            .lock()
            .await
            .notifications
            .pending()
            .is_empty());

        runtime.stop().await.expect("stop runtime");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn invite_cutover_second_activation_does_not_duplicate_notifications() {
        let (runtime, storage, path) = invite_cutover_test_runtime(0x67).await;
        let peer = NodeId::from_bytes([0x68; 32]);
        seed_cutover_peer(&storage, &peer);

        runtime
            .activate_invite_cutover(200)
            .await
            .expect("activate invite cutover");
        runtime
            .activate_invite_cutover(300)
            .await
            .expect("repeat invite cutover activation");

        assert_eq!(
            runtime
                .ctx
                .home_state
                .lock()
                .await
                .notifications
                .pending()
                .len(),
            1
        );

        runtime.stop().await.expect("stop runtime");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn local_outbound_message_is_persisted_for_reply_lookup() {
        let key = [35; 32];
        let path =
            std::env::temp_dir().join(format!("hal-outbound-{}.sqlite3", uuid::Uuid::new_v4()));
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[0x43u8; 32]).expect("storage"),
        ));
        let runtime = PeerRuntime::start_with_policy(
            identity_for(&key),
            key,
            "outbound-persistence".into(),
            Some(Arc::clone(&storage)),
            trusted_local_policy(),
        )
        .await
        .expect("runtime");
        let sender_id = runtime.identity_id.clone();
        let recipient_key = [36; 32];
        let recipient_id = identity_for(&recipient_key);
        runtime
            .pin_peer(&recipient_id, &test_pubkey(recipient_key[0]))
            .await
            .expect("pin recipient");

        runtime
            .add_message(
                "reply-chat".into(),
                sender_id.clone(),
                Some(recipient_id.clone()),
                "reply".into(),
            )
            .await
            .expect("add outbound reply");

        let storage_guard = storage.lock().expect("storage lock");
        let message_ids = storage_guard
            .sync_storage()
            .outgoing_to(&sender_id, &recipient_id, unix_now().saturating_sub(30))
            .expect("outgoing query");
        assert_eq!(message_ids.len(), 1);
        let pending_events = runtime.pending_events().await;
        assert_eq!(message_ids[0], pending_events[0].id);
        drop(storage_guard);
        runtime.stop().await.expect("stop runtime");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn channel_poll_events_use_runtime_sync_and_reach_peer_storage() {
        struct Source {
            payload: String,
        }
        impl crate::ChannelSource for Source {
            fn poll(&self, cursor: crate::ChannelCursor, _limit: usize) -> crate::PollFutureResult {
                let payload = self.payload.clone();
                Box::pin(async move {
                    Ok(vec![crate::ChannelChange {
                        channel_id: cursor.channel_id,
                        item_id: "channel-item".into(),
                        revision: cursor.revision + 1,
                        kind: "new".into(),
                        payload,
                        next_cursor: Some("next".into()),
                    }])
                })
            }
        }

        let key_a = [36; 32];
        let key_b = [37; 32];
        let path =
            std::env::temp_dir().join(format!("hal-channel-{}.sqlite3", uuid::Uuid::new_v4()));
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[0x42u8; 32]).expect("storage"),
        ));
        let mut a = PeerRuntime::start_with_policy(
            identity_for(&key_a),
            key_a,
            "source".into(),
            None,
            trusted_local_policy(),
        )
        .await
        .expect("source runtime");
        let mut b = PeerRuntime::start_with_policy(
            identity_for(&key_b),
            key_b,
            "receiver".into(),
            Some(Arc::clone(&storage)),
            trusted_local_policy(),
        )
        .await
        .expect("receiver runtime");
        a.activate_listener(None, None)
            .await
            .expect("activate source listener");
        b.activate_listener(None, None)
            .await
            .expect("activate receiver listener");
        b.pin_peer(&a.identity_id, &a.public_key)
            .await
            .expect("pin peer");
        a.pin_peer(&b.identity_id, &b.public_key)
            .await
            .expect("pin peer");
        let payload = crate::MessageAddedPayload::new_legacy(
            "news".into(),
            a.identity_id.clone(),
            Some(b.identity_id.clone()),
            "from channel".into(),
            unix_now(),
        );
        let handler = a.channel_handler(Arc::new(Source {
            payload: serde_json::to_string(&payload).expect("serialize channel message"),
        }));
        handler
            .set_cursor(crate::ChannelCursor {
                channel_id: "news".into(),
                value: None,
                revision: 0,
            })
            .await;
        handler
            .handle(crate::PollRequest {
                branch: crate::PollBranch::Channels,
                max_items: 8,
            })
            .await
            .expect("channel poll");
        assert!(a
            .has_pending_events_for_peer(&b.public_key)
            .await
            .expect("check pending channel event"));
        a.send_pending_verified(&b.transport_address, &b.public_key)
            .await
            .expect("send channel event");
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let stored = storage
                    .lock()
                    .expect("storage lock")
                    .messages_json("news")
                    .expect("messages");
                if stored.contains("from channel") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("receiver should persist the channel message");
        a.stop().await.expect("stop source");
        b.stop().await.expect("stop receiver");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn integrity_runtime_accepts_approved_peer_and_rejects_changed_measurement() {
        let authority = SigningKey::from_bytes(&[38; 32]);
        let authority_public_key = hex::encode(authority.verifying_key().to_bytes());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut wave = crate::IntegrityWave::new(
            "runtime-wave".into(),
            1,
            now.saturating_sub(1),
            now + 300,
            "approved-build".into(),
            authority_public_key,
        );
        wave.sign(&authority.to_bytes());

        let key_a = [39; 32];
        let key_b = [40; 32];
        let mut receiver = PeerRuntime::start_with_integrity(
            identity_for(&key_b),
            key_b,
            "receiver".into(),
            None,
            trusted_local_policy(),
            wave.clone(),
            "approved-build".into(),
        )
        .await
        .expect("receiver");
        let mut approved = PeerRuntime::start_with_integrity(
            identity_for(&key_a),
            key_a,
            "approved".into(),
            None,
            trusted_local_policy(),
            wave.clone(),
            "approved-build".into(),
        )
        .await
        .expect("approved sender");
        receiver
            .activate_listener(None, None)
            .await
            .expect("activate receiver listener");
        approved
            .activate_listener(None, None)
            .await
            .expect("activate approved listener");
        receiver
            .pin_peer(&approved.identity_id, &approved.public_key)
            .await
            .expect("pin peer");
        approved
            .pin_peer(&receiver.identity_id, &receiver.public_key)
            .await
            .expect("pin receiver");
        approved
            .add_contact(test_pubkey(3), "Approved".into())
            .await
            .expect("contact");
        approved
            .send_pending_verified(&receiver.transport_address, &receiver.public_key)
            .await
            .expect("approved sync");
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(receiver.contact_count().await, 1);
        approved.stop().await.expect("stop approved");
        receiver.stop().await.expect("stop receiver");

        let mut receiver = PeerRuntime::start_with_integrity(
            identity_for(&key_b),
            key_b,
            "receiver-reject".into(),
            None,
            trusted_local_policy(),
            wave.clone(),
            "approved-build".into(),
        )
        .await
        .expect("receiver reject");
        let mut changed = PeerRuntime::start_with_integrity(
            identity_for(&key_a),
            key_a,
            "changed".into(),
            None,
            trusted_local_policy(),
            wave,
            "fork-build".into(),
        )
        .await
        .expect("changed sender");
        receiver
            .activate_listener(None, None)
            .await
            .expect("activate receiver reject listener");
        changed
            .activate_listener(None, None)
            .await
            .expect("activate changed listener");
        receiver
            .pin_peer(&changed.identity_id, &changed.public_key)
            .await
            .expect("pin peer");
        changed
            .pin_peer(&receiver.identity_id, &receiver.public_key)
            .await
            .expect("pin receiver");
        changed
            .add_contact(test_pubkey(4), "Rejected".into())
            .await
            .expect("contact");
        changed
            .send_pending_verified(&receiver.transport_address, &receiver.public_key)
            .await
            .expect("changed sync transport");
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(receiver.contact_count().await, 0);
        changed.stop().await.expect("stop changed");
        receiver.stop().await.expect("stop receiver reject");
    }

    #[tokio::test]
    async fn relay_consent_missing_rejected() {
        let relay_key = SigningKey::from_bytes(&[241; 32]);
        let requester_key = SigningKey::from_bytes(&[242; 32]);
        let receiver = start_relay_inner_verification_receiver(243, &relay_key).await;
        let inner = contact_added_envelope(
            &requester_key,
            &requester_key,
            "missing-consent-inner",
            "contact-missing-consent",
        );
        let outer = relay_forward_envelope_without_consent(&relay_key, &inner, [244; 16]);

        PeerRuntime::process_incoming_envelope(outer, Arc::clone(&receiver.ctx)).await;

        assert_eq!(receiver.contact_count().await, 0);
        assert_eq!(
            receiver
                .ctx
                .abuse_metrics
                .snapshot()
                .relay_consent_missing_total,
            1
        );
        receiver.stop().await.expect("stop receiver");
    }

    #[tokio::test]
    async fn relay_consent_wrong_target_rejected() {
        let relay_key = SigningKey::from_bytes(&[245; 32]);
        let requester_key = SigningKey::from_bytes(&[246; 32]);
        let receiver = start_relay_inner_verification_receiver(247, &relay_key).await;
        let inner = contact_added_envelope(
            &requester_key,
            &requester_key,
            "wrong-target-inner",
            "contact-wrong-target",
        );
        let nonce = [248; 16];
        let consent = relay_request_for_inner(
            &requester_key,
            &inner,
            NodeId::from_bytes([249; 32]),
            nonce,
            current_unix_time(),
            crate::relay::RELAY_DEFAULT_TTL_SECS,
        )
        .to_base64()
        .expect("encode requester consent");
        let outer = relay_forward_envelope(&relay_key, &inner, nonce, consent);

        PeerRuntime::process_incoming_envelope(outer, Arc::clone(&receiver.ctx)).await;

        assert_eq!(receiver.contact_count().await, 0);
        assert_eq!(
            receiver
                .ctx
                .abuse_metrics
                .snapshot()
                .relay_consent_target_mismatch_total,
            1
        );
        receiver.stop().await.expect("stop receiver");
    }

    #[tokio::test]
    async fn relay_consent_expired_rejected() {
        let relay_key = SigningKey::from_bytes(&[250; 32]);
        let requester_key = SigningKey::from_bytes(&[251; 32]);
        let receiver = start_relay_inner_verification_receiver(252, &relay_key).await;
        let inner = contact_added_envelope(
            &requester_key,
            &requester_key,
            "expired-consent-inner",
            "contact-expired-consent",
        );
        let nonce = [253; 16];
        let consent = relay_request_for_inner(
            &requester_key,
            &inner,
            receiver.dht_local_id,
            nonce,
            current_unix_time().saturating_sub(600),
            60,
        )
        .to_base64()
        .expect("encode requester consent");
        let outer = relay_forward_envelope(&relay_key, &inner, nonce, consent);

        PeerRuntime::process_incoming_envelope(outer, Arc::clone(&receiver.ctx)).await;

        assert_eq!(receiver.contact_count().await, 0);
        assert_eq!(
            receiver
                .ctx
                .abuse_metrics
                .snapshot()
                .relay_consent_expired_total,
            1
        );
        receiver.stop().await.expect("stop receiver");
    }

    #[tokio::test]
    async fn relay_consent_replay_rejected() {
        let relay_key = SigningKey::from_bytes(&[254; 32]);
        let requester_key = SigningKey::from_bytes(&[1; 32]);
        let receiver = start_relay_inner_verification_receiver(2, &relay_key).await;
        let inner = contact_added_envelope(
            &requester_key,
            &requester_key,
            "replay-consent-inner",
            "contact-replay-consent",
        );
        let nonce = [3; 16];
        let consent = relay_request_for_inner(
            &requester_key,
            &inner,
            receiver.dht_local_id,
            nonce,
            current_unix_time(),
            crate::relay::RELAY_DEFAULT_TTL_SECS,
        )
        .to_base64()
        .expect("encode requester consent");
        let outer = relay_forward_envelope(&relay_key, &inner, nonce, consent);

        PeerRuntime::process_incoming_envelope(outer.clone(), Arc::clone(&receiver.ctx)).await;
        PeerRuntime::process_incoming_envelope(outer, Arc::clone(&receiver.ctx)).await;

        assert_eq!(receiver.contact_count().await, 1);
        let metrics = receiver.ctx.abuse_metrics.snapshot();
        assert_eq!(metrics.relay_consent_verified_total, 1);
        assert_eq!(metrics.relay_consent_replay_total, 1);
        receiver.stop().await.expect("stop receiver");
    }

    #[tokio::test]
    async fn relay_consent_content_mismatch_rejected() {
        let relay_key = SigningKey::from_bytes(&[4; 32]);
        let requester_key = SigningKey::from_bytes(&[5; 32]);
        let receiver = start_relay_inner_verification_receiver(6, &relay_key).await;
        let inner = contact_added_envelope(
            &requester_key,
            &requester_key,
            "actual-envelope",
            "contact-actual",
        );
        let consented_inner = contact_added_envelope(
            &requester_key,
            &requester_key,
            "different-envelope",
            "contact-consented",
        );
        let nonce = [7; 16];
        let consent = relay_request_for_inner(
            &requester_key,
            &consented_inner,
            receiver.dht_local_id,
            nonce,
            current_unix_time(),
            crate::relay::RELAY_DEFAULT_TTL_SECS,
        )
        .to_base64()
        .expect("encode requester consent");
        let outer = relay_forward_envelope(&relay_key, &inner, nonce, consent);

        PeerRuntime::process_incoming_envelope(outer, Arc::clone(&receiver.ctx)).await;

        assert_eq!(receiver.contact_count().await, 0);
        assert_eq!(
            receiver
                .ctx
                .abuse_metrics
                .snapshot()
                .relay_consent_content_mismatch_total,
            1
        );
        receiver.stop().await.expect("stop receiver");
    }

    #[tokio::test]
    async fn relay_consent_forged_signature_rejected() {
        let relay_key = SigningKey::from_bytes(&[8; 32]);
        let requester_key = SigningKey::from_bytes(&[9; 32]);
        let attacker_key = SigningKey::from_bytes(&[10; 32]);
        let receiver = start_relay_inner_verification_receiver(11, &relay_key).await;
        let inner = contact_added_envelope(
            &requester_key,
            &requester_key,
            "forged-consent-inner",
            "contact-forged-consent",
        );
        let nonce = [12; 16];
        let forged_request = crate::relay::RelayRequest::create(
            NodeId::from_public_key(&requester_key.verifying_key()),
            receiver.dht_local_id,
            serde_json::to_vec(&inner).expect("serialize inner"),
            crate::relay::RELAY_DEFAULT_TTL_SECS,
            current_unix_time(),
            Vec::new(),
            &attacker_key,
            nonce,
        )
        .expect("create forged consent");
        let outer = relay_forward_envelope(
            &relay_key,
            &inner,
            nonce,
            forged_request.to_base64().expect("encode forged consent"),
        );

        PeerRuntime::process_incoming_envelope(outer, Arc::clone(&receiver.ctx)).await;

        assert_eq!(receiver.contact_count().await, 0);
        assert_eq!(
            receiver
                .ctx
                .abuse_metrics
                .snapshot()
                .relay_consent_signature_failed_total,
            1
        );
        receiver.stop().await.expect("stop receiver");
    }

    #[test]
    fn pending_addressed_events_are_filtered_to_the_recipient() {
        let group_id = "1d9d3a51-32c7-4909-901a-19e2f12ac7e3";
        let events = vec![
            SyncEvent::new(
                "invite-a".into(),
                SyncEventType::GroupCreate,
                serde_json::to_string(&crate::GroupCreatePayload {
                    group_id: group_id.into(),
                    name: "Group".into(),
                    avatar_b64: None,
                    members: Vec::new(),
                    recipient_id: "peer-a".into(),
                })
                .expect("serialize group invite"),
            ),
            SyncEvent::new(
                "invite-b".into(),
                SyncEventType::GroupCreate,
                serde_json::to_string(&crate::GroupCreatePayload {
                    group_id: group_id.into(),
                    name: "Group".into(),
                    avatar_b64: None,
                    members: Vec::new(),
                    recipient_id: "peer-b".into(),
                })
                .expect("serialize group invite"),
            ),
            SyncEvent::new(
                "key-a".into(),
                SyncEventType::GroupKeyDistribution,
                serde_json::to_string(&crate::GroupKeyDistributionPayload {
                    group_id: group_id.into(),
                    group_key: "ab".repeat(32),
                    recipient_id: "peer-a".into(),
                })
                .expect("serialize group key"),
            ),
            SyncEvent::new(
                "key-b".into(),
                SyncEventType::GroupKeyDistribution,
                serde_json::to_string(&crate::GroupKeyDistributionPayload {
                    group_id: group_id.into(),
                    group_key: "cd".repeat(32),
                    recipient_id: "peer-b".into(),
                })
                .expect("serialize group key"),
            ),
            SyncEvent::new(
                "group-message-a".into(),
                SyncEventType::GroupMessage,
                serde_json::to_string(&crate::GroupMessagePayload {
                    message_id: "e1136b7e-c583-4c36-bcdb-e6ab0c7b0fea".into(),
                    group_id: group_id.into(),
                    sender_id: "sender".into(),
                    recipient_id: "peer-a".into(),
                    timestamp: 1,
                    nonce: "AQ==".into(),
                    ciphertext: "AQ==".into(),
                })
                .expect("serialize group message"),
            ),
            SyncEvent::new(
                "profile-a".into(),
                SyncEventType::ProfileUpdate,
                serde_json::to_string(&crate::ProfileUpdatePayload {
                    display_name: "Alice".into(),
                    avatar_b64: None,
                    recipient_id: "peer-a".into(),
                })
                .expect("serialize profile update"),
            ),
            SyncEvent::new(
                "profile-b".into(),
                SyncEventType::ProfileUpdate,
                serde_json::to_string(&crate::ProfileUpdatePayload {
                    display_name: "Bob".into(),
                    avatar_b64: None,
                    recipient_id: "peer-b".into(),
                })
                .expect("serialize profile update"),
            ),
            SyncEvent::new(
                "message-a".into(),
                SyncEventType::MessageAdded,
                serde_json::json!({
                    "group_id": group_id,
                    "recipient_id": "peer-a"
                })
                .to_string(),
            ),
            SyncEvent::new(
                "direct-message-a".into(),
                SyncEventType::MessageAdded,
                serde_json::json!({
                    "recipient_id": "peer-a"
                })
                .to_string(),
            ),
            SyncEvent::new(
                "direct-message-b".into(),
                SyncEventType::MessageAdded,
                serde_json::json!({
                    "recipient_id": "peer-b"
                })
                .to_string(),
            ),
            SyncEvent::new("contact".into(), SyncEventType::ContactAdded, "{}".into()),
        ];

        let filtered = pending_events_for_recipient(events, "peer-a");
        let event_ids: Vec<&str> = filtered.iter().map(|event| event.id.as_str()).collect();
        assert_eq!(
            event_ids,
            vec![
                "invite-a",
                "key-a",
                "group-message-a",
                "profile-a",
                "message-a",
                "direct-message-a",
                "contact"
            ]
        );
    }

    #[tokio::test]
    async fn addressed_group_create_event_is_persisted_for_members() {
        let sender_key = [221; 32];
        let receiver_key = [222; 32];
        let sender_signing_key = SigningKey::from_bytes(&sender_key);
        let sender_public_key = hex::encode(sender_signing_key.verifying_key().to_bytes());
        let receiver_signing_key = SigningKey::from_bytes(&receiver_key);
        let receiver_public_key = hex::encode(receiver_signing_key.verifying_key().to_bytes());
        let sender_identity = identity_for(&sender_key);
        let receiver_identity = identity_for(&receiver_key);
        let path =
            std::env::temp_dir().join(format!("hal-group-create-{}.sqlite3", uuid::Uuid::new_v4()));
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[223; 32]).expect("open storage"),
        ));
        let receiver = PeerRuntime::start_with_storage(
            receiver_identity.clone(),
            receiver_key,
            "group-create-receiver".into(),
            Arc::clone(&storage),
        )
        .await
        .expect("start receiver");
        receiver
            .ctx
            .hosts
            .lock()
            .expect("known hosts lock")
            .pin_manual(&sender_identity, &sender_public_key, current_unix_time())
            .expect("pin sender");

        let group_id = "b58f9c5f-8a2b-4a77-957c-498e44cae340";
        let payload = crate::GroupCreatePayload {
            group_id: group_id.into(),
            name: "Network Group".into(),
            avatar_b64: None,
            members: vec![sender_public_key.clone(), receiver_public_key],
            recipient_id: receiver_identity.clone(),
        };
        let group_key = [0x77; 32];
        let mut group_create_event = SyncEvent::new(
            "group-create-event".into(),
            SyncEventType::GroupCreate,
            serde_json::to_string(&payload).expect("serialize group invite"),
        );
        let mut group_key_event = SyncEvent::new(
            "group-key-event".into(),
            SyncEventType::GroupKeyDistribution,
            serde_json::to_string(&crate::GroupKeyDistributionPayload {
                group_id: group_id.into(),
                group_key: hex::encode(group_key),
                recipient_id: receiver_identity.clone(),
            })
            .expect("serialize group key"),
        );
        let message_id = "e1136b7e-c583-4c36-bcdb-e6ab0c7b0fea";
        let nonce = [0x55; 12];
        let message_aad = group_message_aad(group_id, &sender_identity, message_id);
        let cipher = ChaCha20Poly1305::new_from_slice(&group_key).expect("valid test key");
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: br#"{"text":"encrypted group hello","reply_to_id":"previous-message"}"#,
                    aad: &message_aad,
                },
            )
            .expect("encrypt group message");
        let mut group_message_event = SyncEvent::new(
            "group-message-event".into(),
            SyncEventType::GroupMessage,
            serde_json::to_string(&crate::GroupMessagePayload {
                message_id: message_id.into(),
                group_id: group_id.into(),
                sender_id: sender_identity.clone(),
                recipient_id: receiver_identity.clone(),
                timestamp: 456,
                nonce: base64::engine::general_purpose::STANDARD.encode(nonce),
                ciphertext: base64::engine::general_purpose::STANDARD.encode(ciphertext),
            })
            .expect("serialize encrypted group message"),
        );
        group_create_event
            .sign(&sender_signing_key.to_bytes())
            .expect("sign group create event");
        group_key_event
            .sign(&sender_signing_key.to_bytes())
            .expect("sign group key event");
        group_message_event
            .sign(&sender_signing_key.to_bytes())
            .expect("sign group message event");
        let envelope = SyncEnvelope::new(
            sender_identity,
            sender_public_key,
            vec![group_create_event, group_key_event, group_message_event],
        );

        PeerRuntime::process_incoming_envelope(envelope, Arc::clone(&receiver.ctx)).await;

        let group = storage
            .lock()
            .expect("storage lock")
            .get_group(group_id)
            .expect("load group")
            .expect("group persisted");
        assert_eq!(group.name, "Network Group");
        assert_eq!(group.member_peer_ids.len(), 2);
        assert_eq!(
            storage
                .lock()
                .expect("storage lock")
                .get_group_key(group_id)
                .expect("load group key"),
            Some(hex::encode(group_key))
        );
        let messages: serde_json::Value = serde_json::from_str(
            &storage
                .lock()
                .expect("storage lock")
                .get_group_messages(group_id)
                .expect("load group messages"),
        )
        .expect("valid stored messages");
        assert_eq!(messages[0]["text"], "encrypted group hello");
        assert_eq!(messages[0]["reply_to_id"], "previous-message");
        receiver.stop().await.expect("stop receiver");
        let _ = std::fs::remove_file(path);
    }
}
