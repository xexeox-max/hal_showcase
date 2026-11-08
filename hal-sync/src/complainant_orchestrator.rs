//! Complainant-side jury roster orchestration.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use tokio::sync::oneshot;
use tokio::time::{interval_at, Instant, MissedTickBehavior};

use crate::arbitrator_pool::{
    build_candidate_list, sort_candidates, Candidate, JuryVerdictProvider,
};
use crate::dht::jury_acceptance::assign_share_indices;
use crate::dht::NodeId;
use crate::journal::{
    compute_invitation_id_v2, compute_roster_hash, JuryInvitationPayload, RosterEntry, SyncEvent,
};
use crate::jury_assembly::{advance_complainant, register_complainant_state};
use crate::jury_delivery_outbox::enqueue_invitation;
use crate::runtime_context::RuntimeContext;
use hal_storage::complaints::{list_active_complaints_by_complainant, ComplaintRow};
use hal_storage::jury_assembly_state::{
    read_complainant_state_from_storage, upsert_complainant_state_for_storage, ComplainantPhase,
};
use hal_storage::jury_rosters::{
    insert_roster, insert_roster_assignment, list_assignments_for_generation, read_assignment,
    read_latest_roster, RosterAssignmentResponse, RosterAssignmentRow, RosterRow,
};

pub const ORCHESTRATOR_TICK_SECS: u64 = 30;
pub const ROSTER_SIZE: usize = 7;
pub const RESPONSE_DEADLINE_SECS: u64 = 48 * 3600;
pub const MAX_ROSTER_GENERATION: u32 = 5;

pub struct ComplainantOrchestratorTask {
    ctx: Arc<RuntimeContext>,
    _signing_key: SigningKey,
    verdicts: Arc<dyn JuryVerdictProvider>,
    phone_verified_set: HashSet<NodeId>,
    governance_gate_active: bool,
    tick_secs: u64,
    dispatched_generations: std::sync::Mutex<HashSet<([u8; 32], u32)>>,
    notified_ready: std::sync::Mutex<HashSet<[u8; 32]>>,
    notified_expired: std::sync::Mutex<HashSet<[u8; 32]>>,
}

impl ComplainantOrchestratorTask {
    pub fn new(
        ctx: Arc<RuntimeContext>,
        signing_key: SigningKey,
        verdicts: Arc<dyn JuryVerdictProvider>,
    ) -> Self {
        Self {
            ctx,
            _signing_key: signing_key,
            verdicts,
            phone_verified_set: HashSet::new(),
            governance_gate_active: false,
            tick_secs: ORCHESTRATOR_TICK_SECS,
            dispatched_generations: std::sync::Mutex::new(HashSet::new()),
            notified_ready: std::sync::Mutex::new(HashSet::new()),
            notified_expired: std::sync::Mutex::new(HashSet::new()),
        }
    }

    pub fn with_tick_secs(mut self, secs: u64) -> Self {
        self.tick_secs = secs;
        self
    }

    pub fn with_phone_verified_set(mut self, set: HashSet<NodeId>) -> Self {
        self.phone_verified_set = set;
        self
    }

    pub fn with_governance_gate(mut self, active: bool) -> Self {
        self.governance_gate_active = active;
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
                    log::debug!("complainant orchestrator stopped");
                    break;
                }
                _ = ticker.tick() => {
                    if let Err(error) = self.tick().await {
                        log::warn!("complainant orchestrator tick failed: {error}");
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
        let local_id = local_node_id(&self.ctx)?;
        let Some(storage_arc) = self.ctx.storage.as_ref() else {
            return Ok(());
        };

        let complaints = {
            let storage = storage_arc
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            list_active_complaints_by_complainant(storage.connection(), &local_id, now)?
        };

        for complaint in complaints {
            if let Err(error) = self.process_complaint(&complaint, now).await {
                log::warn!(
                    "complainant orchestrator failed for complaint {}: {error}",
                    hex::encode(complaint.complaint_id)
                );
            }
        }
        Ok(())
    }

    async fn process_complaint(&self, complaint: &ComplaintRow, now: u64) -> Result<()> {
        let storage_arc = self
            .ctx
            .storage
            .as_ref()
            .context("storage required for orchestrator")?;

        let state = {
            let storage = storage_arc
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            read_complainant_state_from_storage(&storage, &complaint.complaint_id)?
        };
        let state = match state {
            Some(state) => state,
            None => {
                register_complainant_state(&self.ctx, complaint.complaint_id, now)?;
                let storage = storage_arc
                    .lock()
                    .map_err(|_| anyhow!("storage lock poisoned"))?;
                read_complainant_state_from_storage(&storage, &complaint.complaint_id)?
                    .context("complainant state missing after registration")?
            }
        };
        if state.phase == ComplainantPhase::Expired {
            self.notify_expired(&complaint.complaint_id, now).await?;
            return Ok(());
        }
        if state.phase == ComplainantPhase::ReadyForEvidenceExchange {
            self.notify_ready_for_evidence(&complaint.complaint_id, now)
                .await?;
            return Ok(());
        }
        if state.phase == ComplainantPhase::WaitingCommitments && now > state.deadline {
            if advance_complainant(&self.ctx, &complaint.complaint_id, now)?
                == Some(ComplainantPhase::Expired)
            {
                self.notify_expired(&complaint.complaint_id, now).await?;
            }
            return Ok(());
        }

        let latest = {
            let storage = storage_arc
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            read_latest_roster(storage.connection(), &complaint.complaint_id)?
        };

        match latest {
            None => self.create_roster(complaint, 0, now).await?,
            Some(roster) => {
                self.enqueue_roster_invitations(
                    complaint,
                    &roster,
                    now,
                    now <= roster.created_at.saturating_add(RESPONSE_DEADLINE_SECS),
                )?;
                self.advance_or_complete(&roster, complaint, now).await?;
            }
        }
        Ok(())
    }

    async fn create_roster(
        &self,
        complaint: &ComplaintRow,
        generation: u32,
        now: u64,
    ) -> Result<()> {
        if generation >= MAX_ROSTER_GENERATION {
            self.mark_expired(&complaint.complaint_id, now).await?;
            return Ok(());
        }

        let all_candidates = build_candidate_list(
            &self.ctx,
            self.verdicts.as_ref(),
            &complaint.complaint_id,
            complaint.submitted_at,
            generation,
            now,
            self.governance_gate_active,
            &self.phone_verified_set,
        )
        .await;
        let failed = self.collect_failed_candidates(&complaint.complaint_id, generation, now)?;
        let selected = select_roster_candidates(all_candidates, &failed);
        if selected.len() != ROSTER_SIZE {
            log::warn!(
                "complainant orchestrator: not enough candidates for complaint {} ({} < {})",
                hex::encode(complaint.complaint_id),
                selected.len(),
                ROSTER_SIZE
            );
            self.mark_expired(&complaint.complaint_id, now).await?;
            return Ok(());
        }

        let index_map = assign_share_indices(&selected)
            .map_err(|error| anyhow!("assign share indices: {error}"))?;
        let mut roster_entries: Vec<RosterEntry> = index_map
            .iter()
            .map(|(node, share_index)| RosterEntry {
                share_index: *share_index,
                node_id: *node.as_bytes(),
            })
            .collect();
        roster_entries.sort_by_key(|entry| entry.share_index);

        let roster_hash = compute_roster_hash(&complaint.complaint_id, &roster_entries)
            .map_err(|error| anyhow!("compute roster hash: {error}"))?;
        let roster = RosterRow {
            complaint_id: complaint.complaint_id,
            roster_generation: generation,
            roster_hash,
            roster_blob: serde_json::to_vec(&roster_entries).context("serialize roster")?,
            created_at: now,
        };

        let storage_arc = self.ctx.storage.as_ref().context("storage required")?;
        {
            let storage = storage_arc
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            insert_roster(storage.connection(), &roster)?;
        }
        self.extend_acceptance_deadline(&complaint.complaint_id, now)?;
        self.enqueue_roster_invitations(complaint, &roster, now, true)
    }

    fn extend_acceptance_deadline(&self, complaint_id: &[u8; 32], now: u64) -> Result<()> {
        let deadline = now
            .checked_add(RESPONSE_DEADLINE_SECS)
            .context("acceptance deadline overflow")?;
        let storage_arc = self.ctx.storage.as_ref().context("storage required")?;
        let mut storage = storage_arc
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        let Some(mut state) = read_complainant_state_from_storage(&storage, complaint_id)? else {
            return Err(anyhow!("complainant assembly state is missing"));
        };
        if state.phase == ComplainantPhase::CollectingAcceptances {
            state.deadline = deadline;
            state.updated_at = now;
            upsert_complainant_state_for_storage(&mut storage, &state)?;
        }
        Ok(())
    }

    fn enqueue_roster_invitations(
        &self,
        complaint: &ComplaintRow,
        roster: &RosterRow,
        now: u64,
        should_enqueue: bool,
    ) -> Result<()> {
        let generation_key = (complaint.complaint_id, roster.roster_generation);
        if should_enqueue
            && self
                .dispatched_generations
                .lock()
                .map_err(|_| anyhow!("dispatch lock poisoned"))?
                .contains(&generation_key)
        {
            return Ok(());
        }

        let entries: Vec<RosterEntry> =
            serde_json::from_slice(&roster.roster_blob).context("deserialize persisted roster")?;
        let computed_hash = compute_roster_hash(&complaint.complaint_id, &entries)
            .map_err(|error| anyhow!("validate persisted roster: {error}"))?;
        if computed_hash != roster.roster_hash {
            return Err(anyhow!("persisted roster hash mismatch"));
        }

        let local_id = local_node_id(&self.ctx)?;
        let storage_arc = self.ctx.storage.as_ref().context("storage required")?;
        let assignments = {
            let storage = storage_arc
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            for entry in &entries {
                let invitation_id = compute_invitation_id_v2(
                    &complaint.complaint_id,
                    &local_id,
                    &entry.node_id,
                    roster.roster_generation,
                );
                let expected = RosterAssignmentRow {
                    complaint_id: complaint.complaint_id,
                    roster_generation: roster.roster_generation,
                    share_index: entry.share_index,
                    candidate_node_id: entry.node_id,
                    invitation_id,
                    invited_at: roster.created_at,
                    response: None,
                };
                match read_assignment(
                    storage.connection(),
                    &complaint.complaint_id,
                    roster.roster_generation,
                    entry.share_index,
                )? {
                    Some(existing)
                        if existing.complaint_id == expected.complaint_id
                            && existing.roster_generation == expected.roster_generation
                            && existing.share_index == expected.share_index
                            && existing.candidate_node_id == expected.candidate_node_id
                            && existing.invitation_id == expected.invitation_id
                            && existing.invited_at == expected.invited_at => {}
                    Some(_) => return Err(anyhow!("persisted roster assignment mismatch")),
                    None => insert_roster_assignment(storage.connection(), &expected)?,
                }
            }
            list_assignments_for_generation(
                storage.connection(),
                &complaint.complaint_id,
                roster.roster_generation,
            )?
        };
        if assignments.len() != ROSTER_SIZE || entries.len() != ROSTER_SIZE {
            return Err(anyhow!(
                "persisted roster contains {} entries and {} assignments; expected {ROSTER_SIZE}",
                entries.len(),
                assignments.len()
            ));
        }

        if should_enqueue {
            for assignment in assignments {
                if assignment.response.is_some() {
                    continue;
                }
                let entry = entries
                    .iter()
                    .find(|entry| entry.share_index == assignment.share_index)
                    .context("roster assignment has no matching entry")?;
                if entry.node_id != assignment.candidate_node_id {
                    return Err(anyhow!("roster candidate does not match assignment"));
                }
                let expected_invitation_id = compute_invitation_id_v2(
                    &complaint.complaint_id,
                    &local_id,
                    &entry.node_id,
                    roster.roster_generation,
                );
                if expected_invitation_id != assignment.invitation_id {
                    return Err(anyhow!("roster invitation ID does not match assignment"));
                }
                let payload = JuryInvitationPayload {
                    complaint_id: complaint.complaint_id,
                    complainant_node_id: local_id,
                    candidate_node_id: entry.node_id,
                    share_index: entry.share_index,
                    roster: entries.clone(),
                    roster_hash: roster.roster_hash,
                    roster_generation: roster.roster_generation,
                    invitation_id: assignment.invitation_id,
                    issued_at: roster.created_at,
                    response_deadline: roster.created_at.saturating_add(RESPONSE_DEADLINE_SECS),
                };
                let event =
                    SyncEvent::jury_invitation(&payload).context("build jury invitation event")?;
                enqueue_invitation(
                    &self.ctx,
                    event,
                    complaint.complaint_id,
                    entry.node_id,
                    assignment.invitation_id,
                    now,
                )?;
            }
            self.dispatched_generations
                .lock()
                .map_err(|_| anyhow!("dispatch lock poisoned"))?
                .insert(generation_key);
        }
        Ok(())
    }

    fn collect_failed_candidates(
        &self,
        complaint_id: &[u8; 32],
        current_generation: u32,
        now: u64,
    ) -> Result<HashSet<NodeId>> {
        let storage_arc = self.ctx.storage.as_ref().context("storage required")?;
        let storage = storage_arc
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        let mut failed = HashSet::new();
        for generation in 0..current_generation {
            let assignments =
                list_assignments_for_generation(storage.connection(), complaint_id, generation)?;
            for assignment in assignments {
                let is_failed = match assignment.response {
                    Some(RosterAssignmentResponse::Rejected) => true,
                    Some(RosterAssignmentResponse::Accepted) => false,
                    None => now > assignment.invited_at.saturating_add(RESPONSE_DEADLINE_SECS),
                };
                if is_failed {
                    failed.insert(NodeId::from_bytes(assignment.candidate_node_id));
                }
            }
        }
        Ok(failed)
    }

    async fn advance_or_complete(
        &self,
        roster: &RosterRow,
        complaint: &ComplaintRow,
        now: u64,
    ) -> Result<()> {
        let storage_arc = self.ctx.storage.as_ref().context("storage required")?;
        let assignments = {
            let storage = storage_arc
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            list_assignments_for_generation(
                storage.connection(),
                &complaint.complaint_id,
                roster.roster_generation,
            )?
        };
        if assignments.len() != ROSTER_SIZE {
            return Err(anyhow!(
                "roster has {} assignments, expected {ROSTER_SIZE}",
                assignments.len()
            ));
        }

        let accepted = assignments
            .iter()
            .filter(|assignment| {
                matches!(
                    assignment.response,
                    Some(RosterAssignmentResponse::Accepted)
                )
            })
            .count();
        let pending = assignments
            .iter()
            .filter(|assignment| assignment.response.is_none())
            .count();
        let expired = now > roster.created_at.saturating_add(RESPONSE_DEADLINE_SECS);

        match response_outcome(accepted, pending, expired) {
            ResponseOutcome::Accepted => {
                let phase = advance_complainant(&self.ctx, &complaint.complaint_id, now)?;
                if phase == Some(ComplainantPhase::ReadyForEvidenceExchange) {
                    self.notify_ready_for_evidence(&complaint.complaint_id, now)
                        .await?;
                } else if phase == Some(ComplainantPhase::Expired) {
                    self.notify_expired(&complaint.complaint_id, now).await?;
                }
            }
            ResponseOutcome::Retry => {
                let next_generation = roster
                    .roster_generation
                    .checked_add(1)
                    .context("roster generation overflow")?;
                if next_generation >= MAX_ROSTER_GENERATION {
                    self.mark_expired(&complaint.complaint_id, now).await?;
                } else {
                    self.create_roster(complaint, next_generation, now).await?;
                }
            }
            ResponseOutcome::Wait => {}
        }
        Ok(())
    }

    async fn mark_expired(&self, complaint_id: &[u8; 32], now: u64) -> Result<()> {
        let storage_arc = self.ctx.storage.as_ref().context("storage required")?;
        let transitioned = {
            let mut storage = storage_arc
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            match read_complainant_state_from_storage(&storage, complaint_id)? {
                Some(mut state)
                    if !matches!(
                        state.phase,
                        ComplainantPhase::Expired | ComplainantPhase::ReadyForEvidenceExchange
                    ) =>
                {
                    state.phase = ComplainantPhase::Expired;
                    state.updated_at = now;
                    upsert_complainant_state_for_storage(&mut storage, &state)?;
                    true
                }
                Some(_) => false,
                None => return Err(anyhow!("complainant assembly state is missing")),
            }
        };
        if transitioned {
            self.notify_expired(complaint_id, now).await?;
        }
        Ok(())
    }

    async fn notify_ready_for_evidence(&self, complaint_id: &[u8; 32], now: u64) -> Result<()> {
        {
            let mut notified = self
                .notified_ready
                .lock()
                .map_err(|_| anyhow!("notification lock poisoned"))?;
            if !notified.insert(*complaint_id) {
                return Ok(());
            }
        }
        let local_id = local_node_id(&self.ctx)?;
        self.ctx.home_state.lock().await.notifications.create(
            crate::dht::notifier::NotificationKind::JuryReadyForEvidence,
            NodeId::from_bytes(local_id),
            NodeId::from_bytes(*complaint_id),
            None,
            now,
            crate::dht::notifier::NOTIFICATION_DEFAULT_TTL_SECS,
        );
        Ok(())
    }

    async fn notify_expired(&self, complaint_id: &[u8; 32], now: u64) -> Result<()> {
        {
            let mut notified = self
                .notified_expired
                .lock()
                .map_err(|_| anyhow!("notification lock poisoned"))?;
            if !notified.insert(*complaint_id) {
                return Ok(());
            }
        }
        let local_id = local_node_id(&self.ctx)?;
        self.ctx.home_state.lock().await.notifications.create(
            crate::dht::notifier::NotificationKind::JuryAssemblyExpired,
            NodeId::from_bytes(local_id),
            NodeId::from_bytes(*complaint_id),
            None,
            now,
            crate::dht::notifier::NOTIFICATION_DEFAULT_TTL_SECS,
        );
        Ok(())
    }
}

fn select_roster_candidates(
    candidates: Vec<Candidate>,
    failed_candidates: &HashSet<NodeId>,
) -> Vec<Candidate> {
    let mut candidates: Vec<_> = candidates
        .into_iter()
        .filter(|candidate| !failed_candidates.contains(&candidate.node_id))
        .collect();
    candidates = sort_candidates(candidates);
    candidates.truncate(ROSTER_SIZE);
    candidates
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseOutcome {
    Accepted,
    Retry,
    Wait,
}

fn response_outcome(accepted: usize, pending: usize, expired: bool) -> ResponseOutcome {
    if accepted == ROSTER_SIZE {
        ResponseOutcome::Accepted
    } else if pending == 0 || expired {
        ResponseOutcome::Retry
    } else {
        ResponseOutcome::Wait
    }
}

fn local_node_id(ctx: &RuntimeContext) -> Result<[u8; 32]> {
    let node = NodeId::from_hex(&ctx.identity_id).context("parse local identity")?;
    Ok(*node.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::{
        BasicTrustOracle, GroupGraph, GroupRegistry, RateLimiter, TrustMetrics, TrustScoreManager,
    };
    use crate::runtime::HomeRuntimeState;
    use crate::runtime_context::NoopBiometricGate;
    use ed25519_dalek::SigningKey;
    use hal_storage::jury_rosters::record_assignment_response;
    use hal_storage::ClientStorage;
    use std::sync::Mutex as StdMutex;
    use tokio::sync::Mutex as TokioMutex;

    fn test_context(with_storage: bool) -> (Arc<RuntimeContext>, tempfile::TempDir) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let storage = with_storage.then(|| {
            Arc::new(StdMutex::new(
                ClientStorage::open(directory.path().join("orchestrator.sqlite3"), &[71; 32])
                    .expect("open test storage"),
            ))
        });
        let signing_key = SigningKey::from_bytes(&[72; 32]);
        let identity_id = NodeId::from_public_key(&signing_key.verifying_key()).to_hex();
        let hosts = Arc::new(StdMutex::new(crate::pinning::KnownHosts::new()));
        let scores = Arc::new(StdMutex::new(TrustScoreManager::new()));
        let rates = Arc::new(StdMutex::new(RateLimiter::new()));
        let groups: Arc<dyn GroupGraph> = Arc::new(GroupRegistry::new());
        let oracle = Arc::new(BasicTrustOracle::new(
            Arc::clone(&scores),
            Arc::clone(&rates),
            Arc::clone(&hosts),
            Arc::clone(&groups),
        ));
        let (relay_tx, relay_tracker, relay_metrics) = RuntimeContext::default_relay_channels();
        let (badge_store, badge_metrics) = RuntimeContext::default_badge_components();
        let (cold_contact_tracker, auto_badge_queue, abuse_metrics) =
            RuntimeContext::default_abuse_channels();
        let context = RuntimeContext {
            sync: Arc::new(TokioMutex::new(crate::SyncManager::new(
                "orchestrator-test".into(),
            ))),
            home_state: Arc::new(TokioMutex::new(HomeRuntimeState::default())),
            media_signals: Arc::new(TokioMutex::new(Vec::new())),
            storage,
            age_tracker: None,
            activity_tracker: None,
            proof_of_live: None,
            hosts,
            scores,
            rates,
            trust_graph: None,
            groups,
            trust_metrics: Arc::new(TrustMetrics::new()),
            oracle,
            address_refresh: Arc::new(crate::address_refresh::AddressRefresh::with_defaults()),
            hole_puncher: Arc::new(crate::hole_punch::HolePuncher::with_defaults()),
            signaling_strategy: Arc::new(crate::signaling::SignalingStrategy::default_hybrid()),
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
        (Arc::new(context), directory)
    }

    fn task(ctx: Arc<RuntimeContext>) -> ComplainantOrchestratorTask {
        ComplainantOrchestratorTask::new(
            ctx,
            SigningKey::from_bytes(&[73; 32]),
            Arc::new(crate::arbitrator_pool::NoVerdictsProvider),
        )
    }

    fn candidate(id: u8, weight: u32) -> Candidate {
        Candidate {
            node_id: NodeId::from_bytes([id; 32]),
            weight,
            criteria: crate::arbitrator_pool::ArbitratorCriteria {
                pol_full_ok: true,
                score_ok: true,
                no_active_guilty: true,
                governance_ok: true,
                phone_verified: false,
            },
            tie_breaker: [id; 32],
        }
    }

    #[test]
    fn select_roster_excludes_failed_candidates_before_truncation() {
        let candidates = (1..=8).map(|id| candidate(id, 1)).collect();
        let failed = HashSet::from([NodeId::from_bytes([1; 32])]);

        let selected = select_roster_candidates(candidates, &failed);

        assert_eq!(selected.len(), ROSTER_SIZE);
        assert!(!selected
            .iter()
            .any(|candidate| candidate.node_id == NodeId::from_bytes([1; 32])));
        assert!(selected
            .iter()
            .any(|candidate| candidate.node_id == NodeId::from_bytes([8; 32])));
    }

    #[test]
    fn select_roster_sorts_by_weight_and_limits_size() {
        let candidates = (1..=9).map(|id| candidate(id, u32::from(id))).collect();
        let selected = select_roster_candidates(candidates, &HashSet::new());

        assert_eq!(selected.len(), ROSTER_SIZE);
        assert_eq!(selected[0].weight, 9);
        assert_eq!(selected[6].weight, 3);
    }

    #[test]
    fn select_roster_returns_fewer_than_seven_when_pool_is_small() {
        let candidates = (1..=6).map(|id| candidate(id, 1)).collect();
        assert_eq!(
            select_roster_candidates(candidates, &HashSet::new()).len(),
            6
        );
    }

    #[tokio::test]
    async fn tick_noop_without_storage() {
        let (ctx, _directory) = test_context(false);

        task(ctx).tick().await.expect("tick without storage");
    }

    #[tokio::test]
    async fn tick_noop_with_no_active_complaints() {
        let (ctx, _directory) = test_context(true);

        task(ctx).tick().await.expect("tick without complaints");
    }

    #[test]
    fn collect_failed_candidates_includes_rejections_and_timeouts() {
        let (ctx, _directory) = test_context(true);
        let complaint_id = [74; 32];
        let storage = ctx.storage.as_ref().expect("test storage");
        let storage = storage.lock().expect("storage lock");
        insert_roster(
            storage.connection(),
            &RosterRow {
                complaint_id,
                roster_generation: 0,
                roster_hash: [75; 32],
                roster_blob: Vec::new(),
                created_at: 100,
            },
        )
        .expect("insert prior roster");
        for share_index in 1..=3 {
            let candidate_node_id = [share_index as u8; 32];
            let invitation_id = [share_index as u8 + 80; 32];
            insert_roster_assignment(
                storage.connection(),
                &RosterAssignmentRow {
                    complaint_id,
                    roster_generation: 0,
                    share_index,
                    candidate_node_id,
                    invitation_id,
                    invited_at: 100,
                    response: None,
                },
            )
            .expect("insert prior assignment");
            if share_index != 2 {
                record_assignment_response(
                    storage.connection(),
                    &complaint_id,
                    0,
                    &invitation_id,
                    if share_index == 1 {
                        RosterAssignmentResponse::Rejected
                    } else {
                        RosterAssignmentResponse::Accepted
                    },
                    101,
                )
                .expect("record prior response");
            }
        }
        drop(storage);

        let failed = task(ctx)
            .collect_failed_candidates(&complaint_id, 1, 100 + RESPONSE_DEADLINE_SECS + 1)
            .expect("collect failed candidates");

        assert!(failed.contains(&NodeId::from_bytes([1; 32])));
        assert!(failed.contains(&NodeId::from_bytes([2; 32])));
        assert!(!failed.contains(&NodeId::from_bytes([3; 32])));
    }

    #[test]
    fn response_outcome_accepts_only_full_roster() {
        assert_eq!(
            response_outcome(ROSTER_SIZE, 0, false),
            ResponseOutcome::Accepted
        );
    }

    #[test]
    fn response_outcome_waits_when_responses_are_pending_before_deadline() {
        assert_eq!(response_outcome(1, 2, false), ResponseOutcome::Wait);
    }

    #[test]
    fn response_outcome_retries_after_every_candidate_responded() {
        assert_eq!(response_outcome(6, 0, false), ResponseOutcome::Retry);
    }

    #[test]
    fn response_outcome_retries_after_response_timeout() {
        assert_eq!(response_outcome(1, 6, true), ResponseOutcome::Retry);
    }
}
