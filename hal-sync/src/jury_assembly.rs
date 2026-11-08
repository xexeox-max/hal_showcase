//! Persisted complainant and juror jury-assembly state machine.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::sync::oneshot;
use tokio::time::{interval_at, Instant, MissedTickBehavior};

use crate::dht::jury_dkg_commitment::JURY_PARTICIPANTS;
use crate::dht::notifier::{NotificationKind, NOTIFICATION_DEFAULT_TTL_SECS};
use crate::dht::NodeId;
use crate::runtime_context::RuntimeContext;
use hal_storage::jury_acceptances::list_jury_acceptances_for_complaint_from_storage;
use hal_storage::jury_aggregated_shares::read_aggregated_share;
use hal_storage::jury_assembly_state::{
    insert_complainant_state_if_missing_for_storage, insert_juror_state_if_missing_for_storage,
    list_complainant_states_active_from_storage, list_juror_states_active_for_storage,
    read_complainant_state_from_storage, read_juror_state_from_storage,
    upsert_complainant_state_for_storage, upsert_juror_state_for_storage, ComplainantPhase,
    ComplainantState, JurorPhase, JurorState,
};
use hal_storage::jury_commitments::list_jury_commitments_for_complaint_from_storage;
use hal_storage::jury_dkg_storage::{list_received_shares, read_own_share};
use hal_storage::jury_evidence_responses::list_evidence_responses;
use hal_storage::jury_verdicts::read_verdict;
use hal_storage::ClientStorage;

pub const DEFAULT_JURY_ASSEMBLY_TICK_SECS: u64 = 60;
pub const ACCEPTANCE_DEADLINE_SECS: u64 = 48 * 3600;
pub const COMMITMENT_DEADLINE_SECS: u64 = 24 * 3600;
pub const EVIDENCE_RESPONSE_WINDOW_SECS: u64 = 7 * 86400;
pub const JURY_STATE_TTL_SECS: u64 = 180 * 86400;

pub fn register_complainant_state(
    ctx: &RuntimeContext,
    complaint_id: [u8; 32],
    now: u64,
) -> Result<()> {
    let storage_arc = ctx
        .storage
        .as_ref()
        .context("storage is required for jury assembly")?;
    let mut storage = storage_arc
        .lock()
        .map_err(|_| anyhow!("storage lock poisoned"))?;
    let state = ComplainantState {
        complaint_id,
        phase: ComplainantPhase::CollectingAcceptances,
        deadline: now
            .checked_add(ACCEPTANCE_DEADLINE_SECS)
            .ok_or_else(|| anyhow!("jury acceptance deadline overflow"))?,
        updated_at: now,
    };
    insert_complainant_state_if_missing_for_storage(&mut storage, &state)
}

pub fn register_juror_state(
    ctx: &RuntimeContext,
    complaint_id: [u8; 32],
    juror_node_id: [u8; 32],
    now: u64,
) -> Result<()> {
    let storage_arc = ctx
        .storage
        .as_ref()
        .context("storage is required for jury assembly")?;
    let mut storage = storage_arc
        .lock()
        .map_err(|_| anyhow!("storage lock poisoned"))?;
    insert_juror_state_if_missing_for_storage(
        &mut storage,
        &JurorState {
            complaint_id,
            juror_node_id,
            phase: JurorPhase::Accepted,
            updated_at: now,
        },
    )
}

pub fn advance_complainant(
    ctx: &RuntimeContext,
    complaint_id: &[u8; 32],
    now: u64,
) -> Result<Option<ComplainantPhase>> {
    let storage_arc = ctx
        .storage
        .as_ref()
        .context("storage is required for jury assembly")?;
    let mut storage = storage_arc
        .lock()
        .map_err(|_| anyhow!("storage lock poisoned"))?;
    advance_complainant_in_storage(&mut storage, complaint_id, now)
}

fn advance_complainant_in_storage(
    storage: &mut ClientStorage,
    complaint_id: &[u8; 32],
    now: u64,
) -> Result<Option<ComplainantPhase>> {
    let Some(mut state) = read_complainant_state_from_storage(storage, complaint_id)? else {
        return Ok(None);
    };
    if matches!(
        state.phase,
        ComplainantPhase::Expired | ComplainantPhase::ReadyForEvidenceExchange
    ) {
        return Ok(Some(state.phase));
    }

    if now > state.deadline {
        state.phase = ComplainantPhase::Expired;
        state.updated_at = now;
        upsert_complainant_state_for_storage(storage, &state)?;
        return Ok(Some(state.phase));
    }

    match state.phase {
        ComplainantPhase::CollectingAcceptances => {
            let acceptances =
                list_jury_acceptances_for_complaint_from_storage(storage, complaint_id)?;
            if acceptances.len() >= JURY_PARTICIPANTS as usize {
                state.phase = ComplainantPhase::WaitingCommitments;
                state.deadline = now
                    .checked_add(COMMITMENT_DEADLINE_SECS)
                    .ok_or_else(|| anyhow!("jury commitment deadline overflow"))?;
                state.updated_at = now;
                upsert_complainant_state_for_storage(storage, &state)?;
            }
        }
        ComplainantPhase::WaitingCommitments => {
            if has_complete_commitment_set(storage, complaint_id)? {
                state.phase = ComplainantPhase::ReadyForEvidenceExchange;
                state.updated_at = now;
                upsert_complainant_state_for_storage(storage, &state)?;
            }
        }
        ComplainantPhase::ReadyForEvidenceExchange | ComplainantPhase::Expired => {}
    }
    Ok(Some(state.phase))
}

pub fn advance_juror(
    ctx: &RuntimeContext,
    complaint_id: &[u8; 32],
    juror_node_id: &[u8; 32],
    now: u64,
) -> Result<Option<JurorPhase>> {
    let storage_arc = ctx
        .storage
        .as_ref()
        .context("storage is required for jury assembly")?;
    let mut storage = storage_arc
        .lock()
        .map_err(|_| anyhow!("storage lock poisoned"))?;
    advance_juror_in_storage(&mut storage, complaint_id, juror_node_id, now)
}

fn advance_juror_in_storage(
    storage: &mut ClientStorage,
    complaint_id: &[u8; 32],
    juror_node_id: &[u8; 32],
    now: u64,
) -> Result<Option<JurorPhase>> {
    let Some(mut state) = read_juror_state_from_storage(storage, complaint_id, juror_node_id)?
    else {
        return Ok(None);
    };
    if matches!(
        state.phase,
        JurorPhase::Expired | JurorPhase::VerdictFinalized
    ) {
        return Ok(Some(state.phase));
    }

    if now > state.updated_at.saturating_add(JURY_STATE_TTL_SECS) {
        state.phase = JurorPhase::Expired;
        state.updated_at = now;
        upsert_juror_state_for_storage(storage, &state)?;
        return Ok(Some(state.phase));
    }

    if state.phase == JurorPhase::ReadyForDecryption {
        return Ok(Some(state.phase));
    }

    if matches!(
        state.phase,
        JurorPhase::Accepted | JurorPhase::PublishedCommitments
    ) && now > state.updated_at.saturating_add(COMMITMENT_DEADLINE_SECS)
    {
        state.phase = JurorPhase::Expired;
        state.updated_at = now;
        upsert_juror_state_for_storage(storage, &state)?;
        return Ok(Some(state.phase));
    }

    match state.phase {
        JurorPhase::Accepted => {
            let commitments =
                list_jury_commitments_for_complaint_from_storage(storage, complaint_id)?;
            if commitments
                .iter()
                .any(|record| &record.dealer_node_id == juror_node_id)
            {
                state.phase = JurorPhase::PublishedCommitments;
                state.updated_at = now;
                upsert_juror_state_for_storage(storage, &state)?;
            }
        }
        JurorPhase::PublishedCommitments => {
            if has_complete_commitment_set(storage, complaint_id)? {
                state.phase = JurorPhase::AwaitingShares;
                state.updated_at = now;
                upsert_juror_state_for_storage(storage, &state)?;
            }
        }
        JurorPhase::AwaitingShares => {
            let verified_count = list_received_shares(storage.connection(), complaint_id)?
                .into_iter()
                .filter(|share| share.verified)
                .count();
            let own = read_own_share(storage.connection(), complaint_id, juror_node_id)?;
            let aggregated =
                read_aggregated_share(storage.connection(), complaint_id, juror_node_id)?;
            if verified_count >= 6 && own.is_some() && aggregated.is_some() {
                state.phase = JurorPhase::ReadyForDecryption;
                state.updated_at = now;
                upsert_juror_state_for_storage(storage, &state)?;
            }
        }
        JurorPhase::AwaitingVotes => {
            let responses = list_evidence_responses(storage.connection(), complaint_id)?;
            let mut all_finalized = !responses.is_empty();
            for response in responses {
                if read_verdict(storage.connection(), complaint_id, &response.evidence_hash)?
                    .is_none()
                {
                    all_finalized = false;
                    break;
                }
            }
            if all_finalized {
                state.phase = JurorPhase::VerdictFinalized;
                state.updated_at = now;
                upsert_juror_state_for_storage(storage, &state)?;
            }
        }
        JurorPhase::ReadyForDecryption | JurorPhase::Expired | JurorPhase::VerdictFinalized => {}
    }
    Ok(Some(state.phase))
}

pub(crate) async fn notify_verdict_ready_once(
    ctx: &RuntimeContext,
    complaint_id: &[u8; 32],
    juror_node_id: &[u8; 32],
    now: u64,
) {
    let mut home = ctx.home_state.lock().await;
    if home.notifications.pending().iter().any(|notification| {
        notification.kind == NotificationKind::JuryVerdictReady
            && notification.from == NodeId::from_bytes(*juror_node_id)
            && notification.subject == NodeId::from_bytes(*complaint_id)
    }) {
        return;
    }
    home.notifications.create(
        NotificationKind::JuryVerdictReady,
        NodeId::from_bytes(*juror_node_id),
        NodeId::from_bytes(*complaint_id),
        None,
        now,
        NOTIFICATION_DEFAULT_TTL_SECS,
    );
}

fn has_complete_commitment_set(storage: &ClientStorage, complaint_id: &[u8; 32]) -> Result<bool> {
    let acceptances = list_jury_acceptances_for_complaint_from_storage(storage, complaint_id)?;
    let commitments = list_jury_commitments_for_complaint_from_storage(storage, complaint_id)?;
    if acceptances.len() != JURY_PARTICIPANTS as usize
        || commitments.len() != JURY_PARTICIPANTS as usize
    {
        return Ok(false);
    }
    Ok(acceptances.iter().all(|acceptance| {
        commitments
            .iter()
            .any(|commitment| commitment.dealer_node_id == acceptance.juror_node_id)
    }))
}

pub struct JuryAssemblyTask {
    ctx: Arc<RuntimeContext>,
    tick_secs: u64,
}

impl JuryAssemblyTask {
    pub fn new(ctx: Arc<RuntimeContext>) -> Self {
        Self {
            ctx,
            tick_secs: DEFAULT_JURY_ASSEMBLY_TICK_SECS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::jury_dkg_commitment::JURY_THRESHOLD;
    use crate::dht::{
        BasicTrustOracle, GroupGraph, GroupRegistry, RateLimiter, TrustMetrics, TrustScoreManager,
    };
    use crate::runtime::HomeRuntimeState;
    use crate::runtime_context::{NoopBiometricGate, RuntimeContext};
    use crate::signaling::SignalingStrategy;
    use crate::trust_graph::TrustGraph;
    use crate::SyncManager;
    use ed25519_dalek::SigningKey;
    use hal_storage::jury_acceptances::{persist_jury_acceptance, JuryAcceptanceRow};
    use hal_storage::jury_commitments::{persist_jury_commitment, JuryCommitmentRecord};
    use hal_storage::jury_evidence_responses::{upsert_evidence_response, EvidenceResponseRow};
    use hal_storage::jury_verdicts::{upsert_verdict, JuryVerdictRow};
    use hal_storage::ClientStorage;
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::sync::Mutex as TokioMutex;

    fn context() -> (Arc<RuntimeContext>, tempfile::TempDir) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let storage = ClientStorage::open(directory.path().join("jury.sqlite3"), &[101; 32])
            .expect("open storage");
        let storage = Arc::new(StdMutex::new(storage));
        let hosts = Arc::new(StdMutex::new(crate::pinning::KnownHosts::new()));
        let scores = Arc::new(StdMutex::new(TrustScoreManager::new()));
        let rates = Arc::new(StdMutex::new(RateLimiter::new()));
        let groups: Arc<dyn GroupGraph> = Arc::new(GroupRegistry::new());
        let oracle: Arc<dyn crate::dht::TrustOracle> = Arc::new(BasicTrustOracle::new(
            Arc::clone(&scores),
            Arc::clone(&rates),
            Arc::clone(&hosts),
            Arc::clone(&groups),
        ));
        let invite_registry = RuntimeContext::default_invite_registry();
        let (relay_tx, relay_tracker, relay_metrics) = RuntimeContext::default_relay_channels();
        let (badge_store, badge_metrics) = RuntimeContext::default_badge_components();
        let (cold_contact_tracker, auto_badge_queue, abuse_metrics) =
            RuntimeContext::default_abuse_channels();
        let trust_graph = Arc::new(TrustGraph::new(
            Arc::clone(&hosts),
            Arc::clone(&invite_registry),
            Arc::clone(&badge_store),
            Arc::clone(&oracle),
            Arc::clone(&scores),
            Arc::clone(&rates),
            Arc::clone(&abuse_metrics),
        ));
        let signing_key = SigningKey::from_bytes(&[102; 32]);
        let identity_id = NodeId::from_public_key(&signing_key.verifying_key()).to_hex();
        let ctx = RuntimeContext {
            sync: Arc::new(TokioMutex::new(SyncManager::new("jury-test".into()))),
            home_state: Arc::new(TokioMutex::new(HomeRuntimeState::default())),
            media_signals: Arc::new(TokioMutex::new(Vec::new())),
            storage: Some(storage),
            age_tracker: None,
            activity_tracker: None,
            proof_of_live: None,
            hosts,
            scores,
            rates,
            trust_graph: Some(trust_graph),
            groups,
            trust_metrics: Arc::new(TrustMetrics::new()),
            oracle,
            address_refresh: Arc::new(crate::address_refresh::AddressRefresh::with_defaults()),
            hole_puncher: Arc::new(crate::hole_punch::HolePuncher::with_defaults()),
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
            invite_registry,
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
            public_key: hex::encode(signing_key.verifying_key().to_bytes()),
            identity_signing_key: Some(Arc::new(signing_key)),
            jury_commitment_publisher: None,
            jury_plaintext_cache: RuntimeContext::default_jury_plaintext_cache(),
            invite_redemption_transport: None,
            pending_invite_redemptions: RuntimeContext::default_pending_invite_redemptions(),
            sas_pairing: RuntimeContext::default_sas_pairing(),
            integrity: None,
        };
        (Arc::new(ctx), directory)
    }

    fn insert_acceptances(ctx: &RuntimeContext, complaint_id: [u8; 32], count: u8) {
        let storage = ctx.storage.as_ref().expect("test storage");
        let mut storage = storage.lock().expect("storage lock");
        for index in 1..=count {
            persist_jury_acceptance(
                &mut storage,
                &JuryAcceptanceRow {
                    complaint_id,
                    juror_node_id: [index; 32],
                    juror_public_key: [index; 32],
                    share_index: u32::from(index),
                    accepted_at: 100,
                    record_blob: vec![index],
                },
                100 + crate::dht::jury_acceptance::ACCEPTANCE_TTL_SECS,
            )
            .expect("insert acceptance");
        }
    }

    fn insert_commitments(ctx: &RuntimeContext, complaint_id: [u8; 32], count: u8) {
        for dealer in 1..=count {
            insert_commitment(ctx, complaint_id, [dealer; 32]);
        }
    }

    fn insert_commitment(ctx: &RuntimeContext, complaint_id: [u8; 32], dealer_node_id: [u8; 32]) {
        let storage = ctx.storage.as_ref().expect("test storage");
        let mut storage = storage.lock().expect("storage lock");
        persist_jury_commitment(
            &mut storage,
            &JuryCommitmentRecord {
                complaint_id,
                dealer_node_id,
                dealer_public_key: dealer_node_id,
                commitments: vec![dealer_node_id; JURY_THRESHOLD as usize],
                threshold: JURY_THRESHOLD,
                participant_count: JURY_PARTICIPANTS,
                published_at: 100,
                signature: dealer_node_id
                    .as_slice()
                    .repeat(2)
                    .try_into()
                    .expect("signature"),
                expires_at: 100 + crate::dht::jury_dkg_commitment::JURY_DKG_COMMITMENT_TTL_SECS,
            },
        )
        .expect("insert DKG commitment");
    }

    fn read_complainant(ctx: &RuntimeContext, complaint_id: &[u8; 32]) -> Option<ComplainantState> {
        let storage = ctx.storage.as_ref().expect("test storage");
        let storage = storage.lock().expect("storage lock");
        read_complainant_state_from_storage(&storage, complaint_id).expect("read complainant state")
    }

    fn read_juror(
        ctx: &RuntimeContext,
        complaint_id: &[u8; 32],
        juror_node_id: &[u8; 32],
    ) -> Option<JurorState> {
        let storage = ctx.storage.as_ref().expect("test storage");
        let storage = storage.lock().expect("storage lock");
        read_juror_state_from_storage(&storage, complaint_id, juror_node_id)
            .expect("read juror state")
    }

    fn insert_juror_state(
        ctx: &RuntimeContext,
        complaint_id: [u8; 32],
        juror_node_id: [u8; 32],
        phase: JurorPhase,
        updated_at: u64,
    ) {
        let storage = ctx.storage.as_ref().expect("test storage");
        let mut storage = storage.lock().expect("storage lock");
        upsert_juror_state_for_storage(
            &mut storage,
            &JurorState {
                complaint_id,
                juror_node_id,
                phase,
                updated_at,
            },
        )
        .expect("insert juror state");
    }

    #[test]
    fn register_complainant_state_persists_initial_phase() {
        let (ctx, _directory) = context();
        register_complainant_state(&ctx, [1; 32], 100).expect("register complainant");
        assert_eq!(
            read_complainant(&ctx, &[1; 32]),
            Some(ComplainantState {
                complaint_id: [1; 32],
                phase: ComplainantPhase::CollectingAcceptances,
                deadline: 100 + ACCEPTANCE_DEADLINE_SECS,
                updated_at: 100,
            })
        );
    }

    #[test]
    fn registering_existing_juror_does_not_reset_progress() {
        let (ctx, _directory) = context();
        register_juror_state(&ctx, [14; 32], [3; 32], 100).expect("register juror");
        insert_juror_state(
            &ctx,
            [14; 32],
            [3; 32],
            JurorPhase::PublishedCommitments,
            200,
        );
        register_juror_state(&ctx, [14; 32], [3; 32], 300).expect("register idempotently");
        assert_eq!(
            read_juror(&ctx, &[14; 32], &[3; 32])
                .expect("state exists")
                .phase,
            JurorPhase::PublishedCommitments
        );
    }

    #[test]
    fn register_juror_state_persists_initial_phase() {
        let (ctx, _directory) = context();
        register_juror_state(&ctx, [2; 32], [3; 32], 100).expect("register juror");
        assert_eq!(
            read_juror(&ctx, &[2; 32], &[3; 32]),
            Some(JurorState {
                complaint_id: [2; 32],
                juror_node_id: [3; 32],
                phase: JurorPhase::Accepted,
                updated_at: 100,
            })
        );
    }

    #[test]
    fn advance_complainant_expires_past_deadline() {
        let (ctx, _directory) = context();
        register_complainant_state(&ctx, [4; 32], 100).expect("register complainant");
        assert_eq!(
            advance_complainant(&ctx, &[4; 32], 100 + ACCEPTANCE_DEADLINE_SECS + 1)
                .expect("advance"),
            Some(ComplainantPhase::Expired)
        );
    }

    #[test]
    fn advance_complainant_transitions_to_waiting_commitments_at_7_acceptances() {
        let (ctx, _directory) = context();
        register_complainant_state(&ctx, [5; 32], 100).expect("register complainant");
        insert_acceptances(&ctx, [5; 32], JURY_PARTICIPANTS as u8);
        assert_eq!(
            advance_complainant(&ctx, &[5; 32], 200).expect("advance"),
            Some(ComplainantPhase::WaitingCommitments)
        );
        let state = read_complainant(&ctx, &[5; 32]).expect("state exists");
        assert_eq!(state.deadline, 200 + COMMITMENT_DEADLINE_SECS);
    }

    #[test]
    fn registering_existing_complainant_does_not_reset_progress() {
        let (ctx, _directory) = context();
        register_complainant_state(&ctx, [13; 32], 100).expect("register complainant");
        insert_acceptances(&ctx, [13; 32], JURY_PARTICIPANTS as u8);
        advance_complainant(&ctx, &[13; 32], 200).expect("advance to commitments");
        register_complainant_state(&ctx, [13; 32], 300).expect("register idempotently");
        assert_eq!(
            read_complainant(&ctx, &[13; 32])
                .expect("state exists")
                .phase,
            ComplainantPhase::WaitingCommitments
        );
    }

    #[test]
    fn advance_complainant_transitions_to_ready_at_7_commitments() {
        let (ctx, _directory) = context();
        let mut state = ComplainantState {
            complaint_id: [6; 32],
            phase: ComplainantPhase::WaitingCommitments,
            deadline: 1_000,
            updated_at: 100,
        };
        let storage = ctx.storage.as_ref().expect("test storage");
        {
            let mut storage = storage.lock().expect("storage lock");
            upsert_complainant_state_for_storage(&mut storage, &state).expect("insert state");
        }
        insert_acceptances(&ctx, [6; 32], JURY_PARTICIPANTS as u8);
        insert_commitments(&ctx, [6; 32], JURY_PARTICIPANTS as u8);
        assert_eq!(
            advance_complainant(&ctx, &[6; 32], 200).expect("advance"),
            Some(ComplainantPhase::ReadyForEvidenceExchange)
        );
        state.phase = ComplainantPhase::ReadyForEvidenceExchange;
        state.updated_at = 200;
        assert_eq!(read_complainant(&ctx, &[6; 32]), Some(state));
    }

    #[test]
    fn advance_complainant_noop_for_terminal_state() {
        let (ctx, _directory) = context();
        let state = ComplainantState {
            complaint_id: [7; 32],
            phase: ComplainantPhase::ReadyForEvidenceExchange,
            deadline: 100,
            updated_at: 90,
        };
        let storage = ctx.storage.as_ref().expect("test storage");
        {
            let mut storage = storage.lock().expect("storage lock");
            upsert_complainant_state_for_storage(&mut storage, &state).expect("insert state");
        }
        assert_eq!(
            advance_complainant(&ctx, &[7; 32], 10_000).expect("advance"),
            Some(ComplainantPhase::ReadyForEvidenceExchange)
        );
        assert_eq!(read_complainant(&ctx, &[7; 32]), Some(state));
    }

    #[test]
    fn advance_juror_transitions_accepted_to_published_when_own_commitment_exists() {
        let (ctx, _directory) = context();
        insert_juror_state(&ctx, [8; 32], [1; 32], JurorPhase::Accepted, 100);
        insert_commitments(&ctx, [8; 32], 1);
        assert_eq!(
            advance_juror(&ctx, &[8; 32], &[1; 32], 200).expect("advance"),
            Some(JurorPhase::PublishedCommitments)
        );
    }

    #[test]
    fn advance_juror_transitions_published_to_awaiting_shares_at_7_commitments() {
        let (ctx, _directory) = context();
        insert_juror_state(
            &ctx,
            [9; 32],
            [1; 32],
            JurorPhase::PublishedCommitments,
            100,
        );
        insert_acceptances(&ctx, [9; 32], JURY_PARTICIPANTS as u8);
        insert_commitments(&ctx, [9; 32], JURY_PARTICIPANTS as u8);
        assert_eq!(
            advance_juror(&ctx, &[9; 32], &[1; 32], 200).expect("advance"),
            Some(JurorPhase::AwaitingShares)
        );
    }

    #[test]
    fn commitment_from_nonaccepted_dealer_does_not_complete_jury() {
        let (ctx, _directory) = context();
        let state = ComplainantState {
            complaint_id: [16; 32],
            phase: ComplainantPhase::WaitingCommitments,
            deadline: 1_000,
            updated_at: 100,
        };
        let storage = ctx.storage.as_ref().expect("test storage");
        {
            let mut storage = storage.lock().expect("storage lock");
            upsert_complainant_state_for_storage(&mut storage, &state).expect("insert state");
        }
        insert_acceptances(&ctx, [16; 32], JURY_PARTICIPANTS as u8);
        insert_commitments(&ctx, [16; 32], JURY_PARTICIPANTS as u8 - 1);
        insert_commitment(&ctx, [16; 32], [99; 32]);
        assert_eq!(
            advance_complainant(&ctx, &[16; 32], 200).expect("advance"),
            Some(ComplainantPhase::WaitingCommitments)
        );
    }

    #[test]
    fn advance_juror_noop_for_terminal_state() {
        let (ctx, _directory) = context();
        insert_juror_state(&ctx, [10; 32], [1; 32], JurorPhase::ReadyForDecryption, 100);
        assert_eq!(
            advance_juror(&ctx, &[10; 32], &[1; 32], 200).expect("advance"),
            Some(JurorPhase::ReadyForDecryption)
        );
        assert_eq!(
            read_juror(&ctx, &[10; 32], &[1; 32])
                .expect("state exists")
                .updated_at,
            100
        );
    }

    #[tokio::test]
    async fn tick_advances_active_local_juror_states() {
        let (ctx, _directory) = context();
        let local_id = NodeId::from_hex(&ctx.identity_id).expect("valid local identity");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_secs();
        insert_juror_state(
            &ctx,
            [11; 32],
            *local_id.as_bytes(),
            JurorPhase::Accepted,
            now,
        );
        insert_commitment(&ctx, [11; 32], *local_id.as_bytes());
        JuryAssemblyTask::new(Arc::clone(&ctx))
            .tick()
            .await
            .expect("run task tick");
        assert_eq!(
            read_juror(&ctx, &[11; 32], local_id.as_bytes())
                .expect("juror state exists")
                .phase,
            JurorPhase::PublishedCommitments
        );
    }

    #[test]
    fn advance_juror_expires_after_inactivity_deadline() {
        let (ctx, _directory) = context();
        insert_juror_state(&ctx, [12; 32], [1; 32], JurorPhase::Accepted, 100);
        assert_eq!(
            advance_juror(
                &ctx,
                &[12; 32],
                &[1; 32],
                100 + COMMITMENT_DEADLINE_SECS + 1,
            )
            .expect("advance"),
            Some(JurorPhase::Expired)
        );
    }

    #[test]
    fn advance_expires_stale_awaiting_votes_state() {
        let (ctx, _directory) = context();
        insert_juror_state(&ctx, [13; 32], [1; 32], JurorPhase::AwaitingVotes, 100);

        assert_eq!(
            advance_juror(&ctx, &[13; 32], &[1; 32], 100 + JURY_STATE_TTL_SECS + 1,)
                .expect("advance stale juror"),
            Some(JurorPhase::Expired)
        );
        assert_eq!(
            read_juror(&ctx, &[13; 32], &[1; 32])
                .expect("read expired state")
                .phase,
            JurorPhase::Expired
        );
    }

    #[test]
    fn advance_does_not_expire_verdict_finalized() {
        let (ctx, _directory) = context();
        insert_juror_state(&ctx, [14; 32], [1; 32], JurorPhase::VerdictFinalized, 100);

        assert_eq!(
            advance_juror(&ctx, &[14; 32], &[1; 32], 100 + JURY_STATE_TTL_SECS + 1,)
                .expect("advance finalized juror"),
            Some(JurorPhase::VerdictFinalized)
        );
    }

    #[test]
    fn advance_does_not_expire_fresh_state() {
        let (ctx, _directory) = context();
        insert_juror_state(&ctx, [17; 32], [1; 32], JurorPhase::AwaitingVotes, 100);

        assert_eq!(
            advance_juror(&ctx, &[17; 32], &[1; 32], 100 + JURY_STATE_TTL_SECS)
                .expect("advance fresh juror"),
            Some(JurorPhase::AwaitingVotes)
        );
    }

    #[test]
    fn advance_juror_keeps_awaiting_shares_for_share_delivery_stage() {
        let (ctx, _directory) = context();
        insert_juror_state(&ctx, [15; 32], [1; 32], JurorPhase::AwaitingShares, 100);
        assert_eq!(
            advance_juror(
                &ctx,
                &[15; 32],
                &[1; 32],
                100 + COMMITMENT_DEADLINE_SECS + 1,
            )
            .expect("advance"),
            Some(JurorPhase::AwaitingShares)
        );
    }

    #[test]
    fn advance_waits_for_all_evidence_hashes_to_have_verdicts() {
        let (ctx, _directory) = context();
        let complaint_id = [71; 32];
        let juror_node_id = [72; 32];
        insert_juror_state(
            &ctx,
            complaint_id,
            juror_node_id,
            JurorPhase::AwaitingVotes,
            100,
        );
        {
            let storage_arc = ctx.storage.as_ref().expect("test storage");
            let storage = storage_arc.lock().expect("storage lock");
            for (respondent, evidence_hash) in [(73, [74; 32]), (75, [76; 32])] {
                upsert_evidence_response(
                    storage.connection(),
                    &EvidenceResponseRow {
                        complaint_id,
                        respondent_node_id: [respondent; 32],
                        jury_pubkey: [77; 32],
                        evidence_hash,
                        encapsulation: [78; 32],
                        nonce: [79; 12],
                        ciphertext: vec![80],
                        signature: [81; 64],
                        issued_at: 100,
                    },
                )
                .expect("insert evidence response");
            }
            upsert_verdict(
                storage.connection(),
                &JuryVerdictRow {
                    complaint_id,
                    evidence_hash: [74; 32],
                    verdict: crate::jury_vote::JuryDecision::Guilty.as_u8(),
                    juror_signatures: b"[]".to_vec(),
                    issued_at: 200,
                },
            )
            .expect("insert first verdict");
        }
        assert_eq!(
            advance_juror(&ctx, &complaint_id, &juror_node_id, 210).expect("advance partially"),
            Some(JurorPhase::AwaitingVotes)
        );
        {
            let storage_arc = ctx.storage.as_ref().expect("test storage");
            let storage = storage_arc.lock().expect("storage lock");
            upsert_verdict(
                storage.connection(),
                &JuryVerdictRow {
                    complaint_id,
                    evidence_hash: [76; 32],
                    verdict: crate::jury_vote::JuryDecision::Inconclusive.as_u8(),
                    juror_signatures: b"[]".to_vec(),
                    issued_at: 220,
                },
            )
            .expect("insert second verdict");
        }
        assert_eq!(
            advance_juror(&ctx, &complaint_id, &juror_node_id, 230).expect("advance finalized"),
            Some(JurorPhase::VerdictFinalized)
        );
    }
}

impl JuryAssemblyTask {
    pub fn with_tick_secs(mut self, secs: u64) -> Self {
        self.tick_secs = secs;
        self
    }

    pub async fn run(self: Arc<Self>, mut shutdown: oneshot::Receiver<()>) {
        let period = Duration::from_secs(self.tick_secs.max(1));
        let mut ticker = interval_at(Instant::now() + period, period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    log::debug!("jury assembly task stopped");
                    break;
                }
                _ = ticker.tick() => {
                    if let Err(error) = self.tick().await {
                        log::warn!("jury assembly tick failed: {error}");
                    }
                }
            }
        }
    }

    async fn tick(&self) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock precedes Unix epoch")?
            .as_secs();
        let Some(storage_arc) = self.ctx.storage.as_ref() else {
            return Ok(());
        };
        let active_complainants = {
            let storage = storage_arc
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            list_complainant_states_active_from_storage(&storage)?
        };
        for state in active_complainants {
            advance_complainant(&self.ctx, &state.complaint_id, now)?;
        }

        let local_node_id = NodeId::from_hex(&self.ctx.identity_id)
            .context("parse local identity ID for juror assembly")?;
        let active_jurors = {
            let storage = storage_arc
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            list_juror_states_active_for_storage(&storage, local_node_id.as_bytes())?
        };
        for state in active_jurors {
            let phase = advance_juror(
                &self.ctx,
                &state.complaint_id,
                local_node_id.as_bytes(),
                now,
            )?;
            if state.phase == JurorPhase::AwaitingVotes
                && phase == Some(JurorPhase::VerdictFinalized)
            {
                notify_verdict_ready_once(
                    &self.ctx,
                    &state.complaint_id,
                    local_node_id.as_bytes(),
                    now,
                )
                .await;
            }
        }
        Ok(())
    }
}
