//! Periodically fetch remote commitments for active local juror sessions.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use hal_settings::NetworkTrustPolicy;
use hal_storage::complaints::read_complaint;
use hal_storage::jury_aggregated_shares::{
    read_aggregated_share, upsert_aggregated_share, AggregatedShareRow,
};
use hal_storage::jury_assembly_state::{
    list_juror_states_active_for_storage, transition_juror_phase, JurorPhase, JurorState,
};
use hal_storage::jury_dkg_storage::{list_received_shares, read_own_share};
use hal_storage::jury_evidence_responses::list_evidence_responses;
use hal_storage::jury_partial_decryptions::read_partial_decryption;
use hal_storage::jury_rosters::{list_assignments_for_generation, read_latest_roster};
use hal_storage::jury_verdicts::{read_verdict, upsert_verdict, JuryVerdictRow};
use hal_storage::jury_votes::{list_votes, read_vote, JuryVoteRow};
use tokio::sync::{oneshot, Mutex};
use tokio::time::{interval_at, Instant, MissedTickBehavior};

use crate::dht::notifier::{NotificationKind, NOTIFICATION_DEFAULT_TTL_SECS};
use crate::dht::routing::RoutingTable;
use crate::dht::NodeId;
use crate::journal::{JuryShareDeliveryPayload, SyncEvent};
use crate::journal_commit_publisher::{dht_publish_transport, PublishTransport};
use crate::juror_commitment_fetcher::JurorCommitmentFetcher;
use crate::jury_assembly::{advance_juror, notify_verdict_ready_once};
use crate::jury_delivery_outbox::enqueue_share_delivery;
use crate::jury_evidence_decryptor::try_decrypt_evidence;
use crate::jury_partial_fetcher::{partial_decryption_from_row, JuryPartialFetcher};
use crate::jury_partial_publisher::publish_partial_to_dht;
use crate::jury_verdict_aggregator::aggregate_verdict;
use crate::jury_verdict_publisher::{
    publish_private_verdict, publish_verdict, PrivateVerdictTransport,
};
use crate::jury_vote::{JuryDecision, JuryVerdict, JuryVote};
use crate::jury_vote_fetcher::JuryVoteFetcher;
use crate::jury_vote_publisher::publish_vote_to_dht;
use crate::pinning::KnownHosts;
use crate::runtime_context::RuntimeContext;
use crate::transport::SyncEnvelope;

pub const ORCHESTRATOR_TICK_SECS: u64 = 30;

pub fn compute_share_message_id(
    complaint_id: &[u8; 32],
    dealer_node_id: &[u8; 32],
    recipient_share_index: u32,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"HAL-JURY-SHARE-v1\0");
    h.update(complaint_id);
    h.update(dealer_node_id);
    h.update(recipient_share_index.to_be_bytes());
    h.finalize().into()
}

pub struct JurorOrchestratorTask {
    ctx: Arc<RuntimeContext>,
    fetcher: JurorCommitmentFetcher,
    partial_fetcher: JuryPartialFetcher,
    partial_publisher: Arc<dyn PublishTransport>,
    vote_fetcher: JuryVoteFetcher,
    vote_publisher: Arc<dyn PublishTransport>,
    private_verdict_transport: Arc<dyn PrivateVerdictTransport>,
    tick_secs: u64,
}

struct DirectPrivateVerdictTransport {
    ctx: Arc<RuntimeContext>,
    signing_key: SigningKey,
    routing: Arc<Mutex<RoutingTable>>,
    hosts: Arc<std::sync::Mutex<KnownHosts>>,
    trust_policy: NetworkTrustPolicy,
}

#[async_trait::async_trait]
impl PrivateVerdictTransport for DirectPrivateVerdictTransport {
    async fn send_private_event(
        &self,
        recipient_node_id: &[u8; 32],
        event: &SyncEvent,
    ) -> Result<()> {
        let peer = self
            .routing
            .lock()
            .await
            .all_peers()
            .into_iter()
            .find(|peer| peer.node_id.as_bytes() == recipient_node_id)
            .cloned()
            .context("recipient is not currently in the routing table")?;
        let endpoint = peer
            .best_endpoint()
            .context("recipient has no known online endpoint")?
            .address
            .clone();
        let peer_key: [u8; 32] = hex::decode(&peer.public_key)
            .context("decode private-verdict recipient public key")?
            .try_into()
            .map_err(|_| anyhow!("private-verdict recipient public key must be 32 bytes"))?;
        let mut signed_event = event.clone();
        signed_event.timestamp = crate::dht::prekey_cache::unix_now();
        signed_event.sign(&self.signing_key.to_bytes())?;
        let envelope = SyncEnvelope::new(
            self.ctx.identity_id.clone(),
            self.ctx.public_key.clone(),
            vec![signed_event],
        );
        crate::transport::send_envelope_secure_with_stream_kind_and_metrics(
            &endpoint,
            &envelope,
            &self.signing_key,
            Arc::clone(&self.hosts),
            Some(ed25519_dalek::VerifyingKey::from_bytes(&peer_key)?),
            self.trust_policy.clone(),
            crate::mux::StreamKind::Sync,
            Arc::clone(&self.ctx.abuse_metrics),
        )
        .await
    }
}

impl JurorOrchestratorTask {
    pub fn new(
        ctx: Arc<RuntimeContext>,
        signing_key: SigningKey,
        local_id: NodeId,
        hosts: Arc<std::sync::Mutex<KnownHosts>>,
        routing: Arc<Mutex<RoutingTable>>,
        trust_policy: NetworkTrustPolicy,
    ) -> Self {
        let partial_fetcher = JuryPartialFetcher::new(
            local_id,
            signing_key.clone(),
            Arc::clone(&hosts),
            Arc::clone(&routing),
            trust_policy.clone(),
        );
        let partial_publisher = dht_publish_transport(
            local_id,
            signing_key.clone(),
            Arc::clone(&routing),
            Arc::clone(&hosts),
            trust_policy.clone(),
        );
        let vote_publisher = Arc::clone(&partial_publisher);
        let private_verdict_transport: Arc<dyn PrivateVerdictTransport> =
            Arc::new(DirectPrivateVerdictTransport {
                ctx: Arc::clone(&ctx),
                signing_key: signing_key.clone(),
                routing: Arc::clone(&routing),
                hosts: Arc::clone(&hosts),
                trust_policy: trust_policy.clone(),
            });
        Self {
            ctx,
            vote_fetcher: JuryVoteFetcher::new(
                local_id,
                signing_key.clone(),
                Arc::clone(&hosts),
                Arc::clone(&routing),
                trust_policy.clone(),
            ),
            vote_publisher,
            private_verdict_transport,
            fetcher: JurorCommitmentFetcher::new(
                local_id,
                signing_key,
                hosts,
                routing,
                trust_policy,
            ),
            partial_fetcher,
            partial_publisher,
            tick_secs: ORCHESTRATOR_TICK_SECS,
        }
    }

    pub fn with_tick_secs(mut self, tick_secs: u64) -> Self {
        self.tick_secs = tick_secs;
        self
    }

    pub async fn run(self, mut shutdown: oneshot::Receiver<()>) {
        let period = Duration::from_secs(self.tick_secs.max(1));
        let mut ticker = interval_at(Instant::now() + period, period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    log::debug!("juror orchestrator stopped");
                    break;
                }
                _ = ticker.tick() => {
                    if let Err(error) = self.tick().await {
                        log::warn!("juror orchestrator tick failed: {error}");
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
        self.tick_at(now).await
    }

    pub(crate) async fn tick_at(&self, now: u64) -> Result<()> {
        let Some(storage_arc) = self.ctx.storage.as_ref() else {
            return Ok(());
        };
        let local_node = NodeId::from_hex(&self.ctx.identity_id)
            .context("parse local identity for juror orchestrator")?;
        let local_bytes = *local_node.as_bytes();
        let active_states = {
            let storage = storage_arc
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            list_juror_states_active_for_storage(&storage, &local_bytes)?
        };

        for state in active_states {
            if !matches!(
                state.phase,
                JurorPhase::Expired | JurorPhase::VerdictFinalized
            ) && now
                > state
                    .updated_at
                    .saturating_add(crate::jury_assembly::JURY_STATE_TTL_SECS)
            {
                match advance_juror(&self.ctx, &state.complaint_id, &local_bytes, now) {
                    Ok(Some(JurorPhase::Expired)) | Ok(None) => continue,
                    Ok(Some(_)) => {}
                    Err(error) => {
                        log::warn!(
                            "juror state advancement failed for complaint {}: {error}",
                            hex::encode(state.complaint_id)
                        );
                        continue;
                    }
                }
            }
            if let Err(error) = self.process_juror_state(&state, &local_bytes, now).await {
                log::warn!(
                    "juror orchestrator failed for complaint {}: {error}",
                    hex::encode(state.complaint_id)
                );
            }
        }
        Ok(())
    }

    async fn process_juror_state(
        &self,
        state: &JurorState,
        local_bytes: &[u8; 32],
        now: u64,
    ) -> Result<()> {
        match state.phase {
            JurorPhase::Accepted | JurorPhase::PublishedCommitments => {
                let storage_arc = self
                    .ctx
                    .storage
                    .as_ref()
                    .context("storage required for juror orchestrator")?;
                let assignments = {
                    let storage = storage_arc
                        .lock()
                        .map_err(|_| anyhow!("storage lock poisoned"))?;
                    let Some(roster) =
                        read_latest_roster(storage.connection(), &state.complaint_id)?
                    else {
                        return Ok(());
                    };
                    list_assignments_for_generation(
                        storage.connection(),
                        &state.complaint_id,
                        roster.roster_generation,
                    )?
                };
                if assignments.len() != crate::dht::jury_dkg_commitment::JURY_PARTICIPANTS as usize
                {
                    return Ok(());
                }

                for assignment in assignments {
                    if assignment.candidate_node_id == *local_bytes {
                        continue;
                    }
                    if let Err(error) = self
                        .fetcher
                        .fetch_commitment(
                            storage_arc,
                            &state.complaint_id,
                            &assignment.candidate_node_id,
                            now,
                        )
                        .await
                    {
                        log::debug!(
                            "fetch commitment failed for dealer {}: {error}",
                            hex::encode(assignment.candidate_node_id)
                        );
                    }
                }

                let phase = advance_juror(&self.ctx, &state.complaint_id, local_bytes, now)?;
                if state.phase == JurorPhase::PublishedCommitments
                    && phase == Some(JurorPhase::AwaitingShares)
                {
                    self.notify_shares_needed(&state.complaint_id, local_bytes, now)
                        .await;
                    self.dispatch_shares(&state.complaint_id, local_bytes, now)
                        .await?;
                }
            }
            JurorPhase::AwaitingShares => {
                self.dispatch_shares(&state.complaint_id, local_bytes, now)
                    .await?;
                self.maybe_aggregate_x_j(state, local_bytes, now).await?;
            }
            JurorPhase::ReadyForDecryption => {
                self.pull_partials(&state.complaint_id, local_bytes, now)
                    .await?;
                let responses = {
                    let storage = self
                        .ctx
                        .storage
                        .as_ref()
                        .context("storage required for jury evidence decryption")?
                        .lock()
                        .map_err(|_| anyhow!("storage lock poisoned"))?;
                    list_evidence_responses(storage.connection(), &state.complaint_id)?
                };
                for response in responses {
                    match try_decrypt_evidence(
                        &self.ctx,
                        &state.complaint_id,
                        &response.evidence_hash,
                        now,
                    )
                    .await
                    {
                        Ok(Some(_)) => {
                            log::info!(
                                "jury evidence decrypted for complaint {}",
                                hex::encode(state.complaint_id)
                            );
                            transition_to_vote_needed(
                                &self.ctx,
                                &state.complaint_id,
                                local_bytes,
                                &response.evidence_hash,
                                now,
                            )
                            .await?;
                        }
                        Ok(None) => {}
                        Err(error) => log::warn!(
                            "jury evidence decryption failed for complaint {}: {error}",
                            hex::encode(state.complaint_id)
                        ),
                    }
                }
            }
            JurorPhase::AwaitingVotes => {
                let storage_arc = self
                    .ctx
                    .storage
                    .as_ref()
                    .context("storage required for jury vote collection")?;
                let responses = {
                    let storage = storage_arc
                        .lock()
                        .map_err(|_| anyhow!("storage lock poisoned"))?;
                    list_evidence_responses(storage.connection(), &state.complaint_id)?
                };
                for response in responses {
                    let existing_verdict = {
                        let storage = storage_arc
                            .lock()
                            .map_err(|_| anyhow!("storage lock poisoned"))?;
                        read_verdict(
                            storage.connection(),
                            &state.complaint_id,
                            &response.evidence_hash,
                        )?
                    };
                    if let Some(row) = existing_verdict {
                        let verdict = Self::jury_verdict_from_row(row)?;
                        if let Err(error) =
                            publish_verdict(self.vote_publisher.as_ref(), &verdict, now).await
                        {
                            log::warn!(
                                "jury verdict publication retry failed for complaint {}: {error}",
                                hex::encode(state.complaint_id)
                            );
                        }
                        self.deliver_private_verdict(&verdict).await?;
                        self.ctx
                            .jury_plaintext_cache
                            .remove(&state.complaint_id, &response.evidence_hash)
                            .context("evict cached plaintext for persisted verdict")?;
                        continue;
                    }
                    if self
                        .ctx
                        .jury_plaintext_cache
                        .get(&state.complaint_id, &response.evidence_hash)
                        .context("check cached jury plaintext while awaiting votes")?
                        .is_none()
                    {
                        self.pull_partials(&state.complaint_id, local_bytes, now)
                            .await?;
                        match try_decrypt_evidence(
                            &self.ctx,
                            &state.complaint_id,
                            &response.evidence_hash,
                            now,
                        )
                        .await
                        {
                            Ok(Some(_)) => {}
                            Ok(None) => continue,
                            Err(error) => {
                                log::warn!(
                                    "jury evidence cache recovery failed for complaint {}: {error}",
                                    hex::encode(state.complaint_id)
                                );
                                continue;
                            }
                        }
                    }
                    if let Err(error) = self
                        .vote_fetcher
                        .fetch_remote_votes(
                            &self.ctx,
                            &state.complaint_id,
                            &response.evidence_hash,
                            now,
                        )
                        .await
                    {
                        log::warn!(
                            "jury vote fetch failed for complaint {}: {error}",
                            hex::encode(state.complaint_id)
                        );
                    }
                    let local_vote = {
                        let storage = storage_arc
                            .lock()
                            .map_err(|_| anyhow!("storage lock poisoned"))?;
                        read_vote(
                            storage.connection(),
                            &state.complaint_id,
                            &response.evidence_hash,
                            local_bytes,
                        )?
                    };
                    if let Some(row) = local_vote {
                        let vote = Self::jury_vote_from_row(row)?;
                        if let Err(error) =
                            publish_vote_to_dht(self.vote_publisher.as_ref(), &vote, now).await
                        {
                            log::warn!(
                                "jury vote republish failed for complaint {}: {error}",
                                hex::encode(state.complaint_id)
                            );
                        }
                    }
                    let vote_rows = {
                        let storage = storage_arc
                            .lock()
                            .map_err(|_| anyhow!("storage lock poisoned"))?;
                        list_votes(
                            storage.connection(),
                            &state.complaint_id,
                            &response.evidence_hash,
                        )?
                    };
                    let votes = vote_rows
                        .into_iter()
                        .map(Self::jury_vote_from_row)
                        .collect::<Result<Vec<_>>>()?;
                    let verdict = match aggregate_verdict(
                        &state.complaint_id,
                        &response.evidence_hash,
                        &votes,
                        now,
                    ) {
                        Ok(verdict) => verdict,
                        Err(error) => {
                            log::warn!(
                                "jury verdict aggregation failed for complaint {}: {error}",
                                hex::encode(state.complaint_id)
                            );
                            None
                        }
                    };
                    if verdict.is_none() {
                        ensure_vote_needed_notification(
                            &self.ctx,
                            &state.complaint_id,
                            local_bytes,
                            &response.evidence_hash,
                            now,
                        )
                        .await?;
                    }
                    if let Some(verdict) = verdict {
                        let juror_signatures = serde_json::to_vec(&verdict.juror_signatures)
                            .context("serialize jury verdict vote references")?;
                        {
                            let storage = storage_arc
                                .lock()
                                .map_err(|_| anyhow!("storage lock poisoned"))?;
                            upsert_verdict(
                                storage.connection(),
                                &JuryVerdictRow {
                                    complaint_id: verdict.complaint_id,
                                    evidence_hash: verdict.evidence_hash,
                                    verdict: verdict.verdict.as_u8(),
                                    juror_signatures,
                                    issued_at: verdict.issued_at,
                                },
                            )?;
                        }
                        if let Err(error) =
                            publish_verdict(self.vote_publisher.as_ref(), &verdict, now).await
                        {
                            log::warn!(
                                "jury verdict publication failed for complaint {}: {error}",
                                hex::encode(state.complaint_id)
                            );
                        }
                        self.deliver_private_verdict(&verdict).await?;
                        self.ctx
                            .jury_plaintext_cache
                            .remove(&state.complaint_id, &response.evidence_hash)
                            .context("evict jury plaintext after verdict persistence")?;
                    }
                }
                let phase = advance_juror(&self.ctx, &state.complaint_id, local_bytes, now)?;
                if phase == Some(JurorPhase::VerdictFinalized) {
                    notify_verdict_ready_once(&self.ctx, &state.complaint_id, local_bytes, now)
                        .await;
                }
            }
            JurorPhase::Expired => {}
            JurorPhase::VerdictFinalized => {}
        }
        Ok(())
    }

    async fn deliver_private_verdict(&self, verdict: &JuryVerdict) -> Result<()> {
        if verdict.verdict == JuryDecision::Guilty {
            return Ok(());
        }
        let storage_arc = self
            .ctx
            .storage
            .as_ref()
            .context("storage required for private jury verdict delivery")?;
        let complaint = {
            let storage = storage_arc
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            read_complaint(storage.connection(), &verdict.complaint_id)?
        };
        let Some(complaint) = complaint else {
            log::warn!(
                "private verdict delivery skipped because complaint {} is unavailable",
                hex::encode(verdict.complaint_id)
            );
            return Ok(());
        };
        publish_private_verdict(
            self.private_verdict_transport.as_ref(),
            verdict,
            &[complaint.complainant_node_id, complaint.subject_node_id],
        )
        .await
    }

    fn jury_vote_from_row(row: JuryVoteRow) -> Result<JuryVote> {
        Ok(JuryVote {
            complaint_id: row.complaint_id,
            evidence_hash: row.evidence_hash,
            juror_node_id: row.juror_node_id,
            juror_public_key: row.juror_public_key,
            decision: JuryDecision::from_u8(row.decision)
                .context("decode stored jury vote decision")?,
            issued_at: row.issued_at,
            signature: row.signature,
        })
    }

    fn jury_verdict_from_row(row: JuryVerdictRow) -> Result<JuryVerdict> {
        Ok(JuryVerdict {
            complaint_id: row.complaint_id,
            evidence_hash: row.evidence_hash,
            verdict: JuryDecision::from_u8(row.verdict)
                .context("decode stored jury verdict decision")?,
            juror_signatures: serde_json::from_slice(&row.juror_signatures)
                .context("decode stored jury verdict vote references")?,
            issued_at: row.issued_at,
        })
    }

    async fn pull_partials(
        &self,
        complaint_id: &[u8; 32],
        local_bytes: &[u8; 32],
        now: u64,
    ) -> Result<()> {
        let storage_arc = self
            .ctx
            .storage
            .as_ref()
            .context("storage required for jury partial collection")?;
        let responses = {
            let storage = storage_arc
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            list_evidence_responses(storage.connection(), complaint_id)?
        };
        for response in responses {
            let local_partial = {
                let storage = storage_arc
                    .lock()
                    .map_err(|_| anyhow!("storage lock poisoned"))?;
                read_partial_decryption(
                    storage.connection(),
                    complaint_id,
                    local_bytes,
                    &response.evidence_hash,
                )?
            };
            if let Some(row) = local_partial {
                match partial_decryption_from_row(&row) {
                    Ok(partial) => {
                        if let Err(error) =
                            publish_partial_to_dht(self.partial_publisher.as_ref(), &partial, now)
                                .await
                        {
                            log::warn!(
                                "publish local jury partial failed for complaint {}: {error}",
                                hex::encode(complaint_id)
                            );
                        }
                    }
                    Err(error) => {
                        log::warn!(
                            "decode local jury partial failed for complaint {}: {error}",
                            hex::encode(complaint_id)
                        );
                    }
                }
            }
            if let Err(error) = self
                .partial_fetcher
                .fetch_remote_partials(&self.ctx, complaint_id, &response.evidence_hash, now)
                .await
            {
                log::warn!(
                    "fetch remote jury partials failed for complaint {}: {error}",
                    hex::encode(complaint_id)
                );
            }
        }
        Ok(())
    }

    async fn dispatch_shares(
        &self,
        complaint_id: &[u8; 32],
        local_bytes: &[u8; 32],
        now: u64,
    ) -> Result<()> {
        let storage_arc = self
            .ctx
            .storage
            .as_ref()
            .context("storage required for share dispatch")?;
        let (shares, assignments) = {
            let storage = storage_arc
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            let Some(roster) = read_latest_roster(storage.connection(), complaint_id)? else {
                return Ok(());
            };
            let assignments = list_assignments_for_generation(
                storage.connection(),
                complaint_id,
                roster.roster_generation,
            )?;
            let shares = hal_storage::jury_outgoing_shares::list_outgoing_shares_for_complaint(
                storage.connection(),
                complaint_id,
            )?
            .into_iter()
            .filter(|share| share.dealer_node_id == *local_bytes)
            .collect::<Vec<_>>();
            (shares, assignments)
        };
        if shares.is_empty() {
            return Ok(());
        }
        if assignments.len() != crate::dht::jury_dkg_commitment::JURY_PARTICIPANTS as usize
            || shares.len() != crate::dht::jury_dkg_commitment::JURY_PARTICIPANTS as usize - 1
        {
            return Err(anyhow!(
                "share dispatch requires seven roster assignments and six outgoing shares"
            ));
        }
        let dealer_share_index = assignments
            .iter()
            .find(|assignment| assignment.candidate_node_id == *local_bytes)
            .map(|assignment| assignment.share_index)
            .context("local juror is missing from the roster assignments")?;
        let dealer_public_key = self
            .ctx
            .identity_signing_key
            .as_ref()
            .context("local identity signing key required for share dispatch")?
            .verifying_key()
            .to_bytes();
        if NodeId::from_public_key(
            &ed25519_dalek::VerifyingKey::from_bytes(&dealer_public_key)
                .context("parse local share dealer public key")?,
        )
        .as_bytes()
            != local_bytes
        {
            return Err(anyhow!(
                "local identity public key does not match juror node ID"
            ));
        }
        let expected_recipient_indexes = assignments
            .iter()
            .filter(|assignment| assignment.candidate_node_id != *local_bytes)
            .map(|assignment| assignment.share_index)
            .collect::<Vec<_>>();
        let actual_recipient_indexes = shares
            .iter()
            .map(|share| share.recipient_share_index)
            .collect::<Vec<_>>();
        if expected_recipient_indexes != actual_recipient_indexes {
            return Err(anyhow!(
                "outgoing shares do not match roster recipient indexes"
            ));
        }
        for share in &shares {
            let recipient = assignments
                .iter()
                .find(|assignment| assignment.share_index == share.recipient_share_index)
                .context("outgoing share recipient is missing from roster assignments")?;
            if recipient.candidate_node_id == *local_bytes {
                return Err(anyhow!("outgoing share is addressed to the local juror"));
            }
        }

        for share in shares {
            let recipient = assignments
                .iter()
                .find(|assignment| assignment.share_index == share.recipient_share_index)
                .context("outgoing share recipient is missing from roster assignments")?;
            let message_id =
                compute_share_message_id(complaint_id, local_bytes, share.recipient_share_index);
            let payload = JuryShareDeliveryPayload {
                message_id,
                complaint_id: *complaint_id,
                dealer_node_id: *local_bytes,
                dealer_public_key,
                dealer_share_index,
                recipient_share_index: share.recipient_share_index,
                share_value: share.share_value,
                issued_at: now,
            };
            let event = SyncEvent::jury_share_delivery(&payload)
                .context("create jury share delivery event")?;
            enqueue_share_delivery(
                &self.ctx,
                event,
                *complaint_id,
                recipient.candidate_node_id,
                message_id,
                now,
            )
            .context("enqueue jury share delivery")?;
        }
        Ok(())
    }

    async fn maybe_aggregate_x_j(
        &self,
        state: &JurorState,
        local_bytes: &[u8; 32],
        now: u64,
    ) -> Result<()> {
        let was_awaiting = state.phase == JurorPhase::AwaitingShares;
        let storage_arc = self
            .ctx
            .storage
            .as_ref()
            .context("storage required for share aggregation")?;
        let already_aggregated = {
            let storage = storage_arc
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            read_aggregated_share(storage.connection(), &state.complaint_id, local_bytes)?.is_some()
        };
        if !already_aggregated {
            let maybe_row = {
                let storage = storage_arc
                    .lock()
                    .map_err(|_| anyhow!("storage lock poisoned"))?;
                let Some(own_share) =
                    read_own_share(storage.connection(), &state.complaint_id, local_bytes)?
                else {
                    log::warn!(
                        "jury share aggregation skipped: no local own share for complaint {}",
                        hex::encode(state.complaint_id)
                    );
                    return Ok(());
                };
                let verified_shares =
                    list_received_shares(storage.connection(), &state.complaint_id)?
                        .into_iter()
                        .filter(|share| share.verified)
                        .collect::<Vec<_>>();
                if verified_shares.len()
                    != crate::dht::jury_dkg_commitment::JURY_PARTICIPANTS as usize - 1
                {
                    return Ok(());
                }
                let mut seen = std::collections::HashSet::new();
                for share in &verified_shares {
                    if !seen.insert(share.dealer_node_id) {
                        return Ok(());
                    }
                }
                let mut sum = Scalar::ZERO;
                let local_bytes_array: [u8; 32] = own_share
                    .share_value
                    .as_ref()
                    .try_into()
                    .context("decode local share value")?;
                let local_scalar = {
                    let maybe_scalar: Option<Scalar> =
                        Option::from(Scalar::from_canonical_bytes(local_bytes_array));
                    if let Some(scalar) = maybe_scalar {
                        scalar
                    } else {
                        return Err(anyhow!("local share value is not a canonical scalar"));
                    }
                };
                sum += local_scalar;
                for share in &verified_shares {
                    let share_bytes: [u8; 32] = share
                        .share_value
                        .as_ref()
                        .try_into()
                        .context("decode verified share value")?;
                    let scalar = {
                        let maybe_scalar: Option<Scalar> =
                            Option::from(Scalar::from_canonical_bytes(share_bytes));
                        if let Some(scalar) = maybe_scalar {
                            scalar
                        } else {
                            return Err(anyhow!("verified share value is not a canonical scalar"));
                        }
                    };
                    sum += scalar;
                }
                Some(AggregatedShareRow {
                    complaint_id: state.complaint_id,
                    juror_node_id: *local_bytes,
                    share_index: own_share.share_index,
                    aggregated_value: sum.to_bytes(),
                    threshold: 5,
                    participant_count: 7,
                    computed_at: now,
                })
            };
            let Some(row) = maybe_row else {
                return Ok(());
            };
            let storage = storage_arc
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            upsert_aggregated_share(storage.connection(), &row)?;
        }
        let phase = if was_awaiting {
            advance_juror(&self.ctx, &state.complaint_id, local_bytes, now)?
        } else {
            None
        };
        if was_awaiting && phase == Some(JurorPhase::ReadyForDecryption) {
            self.ctx.home_state.lock().await.notifications.create(
                NotificationKind::JuryReadyForDecryption,
                NodeId::from_bytes(*local_bytes),
                NodeId::from_bytes(state.complaint_id),
                None,
                now,
                NOTIFICATION_DEFAULT_TTL_SECS,
            );
        }
        Ok(())
    }

    async fn notify_shares_needed(
        &self,
        complaint_id: &[u8; 32],
        local_bytes: &[u8; 32],
        now: u64,
    ) {
        self.ctx.home_state.lock().await.notifications.create(
            NotificationKind::JurySharesNeeded,
            NodeId::from_bytes(*local_bytes),
            NodeId::from_bytes(*complaint_id),
            None,
            now,
            NOTIFICATION_DEFAULT_TTL_SECS,
        );
    }
}

async fn transition_to_vote_needed(
    ctx: &Arc<RuntimeContext>,
    complaint_id: &[u8; 32],
    local_bytes: &[u8; 32],
    evidence_hash: &[u8; 32],
    now: u64,
) -> Result<bool> {
    if ctx
        .jury_plaintext_cache
        .get(complaint_id, evidence_hash)
        .context("check jury plaintext before voting transition")?
        .is_none()
    {
        return Ok(false);
    }
    let storage_arc = ctx
        .storage
        .as_ref()
        .context("storage required to enter jury voting phase")?;
    let transitioned = {
        let storage = storage_arc
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        transition_juror_phase(
            storage.connection(),
            complaint_id,
            local_bytes,
            JurorPhase::ReadyForDecryption,
            JurorPhase::AwaitingVotes,
            now,
        )?
    };
    ensure_vote_needed_notification(ctx, complaint_id, local_bytes, evidence_hash, now).await?;
    Ok(transitioned)
}

async fn ensure_vote_needed_notification(
    ctx: &Arc<RuntimeContext>,
    complaint_id: &[u8; 32],
    local_bytes: &[u8; 32],
    evidence_hash: &[u8; 32],
    now: u64,
) -> Result<bool> {
    let storage_arc = ctx
        .storage
        .as_ref()
        .context("storage required to check local jury vote")?;
    let has_vote = {
        let storage = storage_arc
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        read_vote(
            storage.connection(),
            complaint_id,
            evidence_hash,
            local_bytes,
        )?
        .is_some()
    };
    if has_vote
        || ctx
            .jury_plaintext_cache
            .get(complaint_id, evidence_hash)
            .context("check jury plaintext before vote notification")?
            .is_none()
    {
        return Ok(false);
    }
    let mut home = ctx.home_state.lock().await;
    if home.notifications.pending().iter().any(|notification| {
        notification.kind == NotificationKind::JuryVoteNeeded
            && notification.from == NodeId::from_bytes(*local_bytes)
            && notification.subject == NodeId::from_bytes(*complaint_id)
            && notification.expires_at > now
    }) {
        return Ok(false);
    }
    home.notifications.create(
        NotificationKind::JuryVoteNeeded,
        NodeId::from_bytes(*local_bytes),
        NodeId::from_bytes(*complaint_id),
        None,
        now,
        NOTIFICATION_DEFAULT_TTL_SECS,
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::group::{GroupGraph, GroupRegistry};
    use crate::dht::trust_oracle::BasicTrustOracle;
    use crate::journal::RosterEntry;
    use crate::runtime::HomeRuntimeState;
    use crate::runtime_context::{NoopBiometricGate, RuntimeContext};
    use hal_storage::jury_aggregated_shares::{
        read_aggregated_share, upsert_aggregated_share, AggregatedShareRow,
    };
    use hal_storage::jury_assembly_state::{
        read_juror_state, upsert_juror_state, JurorPhase, JurorState,
    };
    use hal_storage::jury_dkg_storage::{
        mark_received_share_verified, read_own_share, upsert_own_share, upsert_received_share,
        OwnShareRow, ReceivedShareRow,
    };
    use hal_storage::jury_evidence_responses::{upsert_evidence_response, EvidenceResponseRow};
    use hal_storage::jury_outbox::{read_outbox_entry, OutboxKind};
    use hal_storage::jury_outgoing_shares::{insert_outgoing_share, OutgoingShareRow};
    use hal_storage::jury_rosters::{
        insert_roster, insert_roster_assignment, RosterAssignmentRow, RosterRow,
    };
    use hal_storage::jury_verdicts::read_verdict;
    use hal_storage::jury_votes::{insert_vote_if_missing, JuryVoteRow};
    use hal_storage::ClientStorage;
    use std::sync::{Arc, Mutex};

    fn context(with_storage: bool) -> (Arc<RuntimeContext>, SigningKey, tempfile::TempDir) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let storage = with_storage.then(|| {
            Arc::new(Mutex::new(
                ClientStorage::open(directory.path().join("juror-orchestrator.db"), &[7; 32])
                    .expect("open storage"),
            ))
        });
        let signing_key = SigningKey::from_bytes(&[41; 32]);
        let hosts = Arc::new(Mutex::new(crate::pinning::KnownHosts::new()));
        let scores = Arc::new(Mutex::new(crate::dht::trust::TrustScoreManager::new()));
        let rates = Arc::new(Mutex::new(crate::dht::rate_limit::RateLimiter::new()));
        let groups: Arc<dyn GroupGraph> = Arc::new(GroupRegistry::new());
        let oracle: Arc<dyn crate::dht::trust_oracle::TrustOracle> =
            Arc::new(BasicTrustOracle::new(
                Arc::clone(&scores),
                Arc::clone(&rates),
                Arc::clone(&hosts),
                Arc::clone(&groups),
            ));
        let (relay_tx, relay_tracker, relay_metrics) = RuntimeContext::default_relay_channels();
        let (badge_store, badge_metrics) = RuntimeContext::default_badge_components();
        let (cold_contact_tracker, auto_badge_queue, abuse_metrics) =
            RuntimeContext::default_abuse_channels();
        let ctx = Arc::new(RuntimeContext {
            sync: Arc::new(tokio::sync::Mutex::new(crate::SyncManager::new(
                "juror-orchestrator-test".into(),
            ))),
            home_state: Arc::new(tokio::sync::Mutex::new(HomeRuntimeState::default())),
            media_signals: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            storage,
            age_tracker: None,
            activity_tracker: None,
            proof_of_live: None,
            hosts,
            scores,
            rates,
            trust_graph: None,
            groups,
            trust_metrics: Arc::new(crate::dht::trust_metrics::TrustMetrics::new()),
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
            identity_id: NodeId::from_public_key(&signing_key.verifying_key()).to_hex(),
            public_key: hex::encode(signing_key.verifying_key().to_bytes()),
            identity_signing_key: Some(Arc::new(signing_key.clone())),
            jury_commitment_publisher: None,
            jury_plaintext_cache: RuntimeContext::default_jury_plaintext_cache(),
            invite_redemption_transport: None,
            pending_invite_redemptions: RuntimeContext::default_pending_invite_redemptions(),
            sas_pairing: RuntimeContext::default_sas_pairing(),
            integrity: None,
        });
        (ctx, signing_key, directory)
    }

    fn task(ctx: Arc<RuntimeContext>, signing_key: SigningKey) -> JurorOrchestratorTask {
        let local_id = NodeId::from_public_key(&signing_key.verifying_key());
        JurorOrchestratorTask::new(
            ctx,
            signing_key,
            local_id,
            Arc::new(Mutex::new(crate::pinning::KnownHosts::new())),
            Arc::new(tokio::sync::Mutex::new(RoutingTable::new(local_id))),
            NetworkTrustPolicy::default(),
        )
    }

    fn insert_state(ctx: &RuntimeContext, state: JurorState) {
        let storage = ctx.storage.as_ref().expect("test storage");
        upsert_juror_state(&storage.lock().expect("storage lock").connection(), &state)
            .expect("insert juror state");
    }

    fn seed_vote_evidence(
        ctx: &RuntimeContext,
        complaint_id: [u8; 32],
        evidence_hash: [u8; 32],
        decisions: &[JuryDecision],
        issued_at: u64,
    ) {
        let storage = ctx.storage.as_ref().expect("test storage");
        let storage = storage.lock().expect("storage lock");
        upsert_evidence_response(
            storage.connection(),
            &EvidenceResponseRow {
                complaint_id,
                respondent_node_id: [91; 32],
                jury_pubkey: [92; 32],
                evidence_hash,
                encapsulation: [93; 32],
                nonce: [94; 12],
                ciphertext: vec![95],
                signature: [96; 64],
                issued_at,
            },
        )
        .expect("insert test evidence response");
        for (index, decision) in decisions.iter().copied().enumerate() {
            let key = SigningKey::from_bytes(&[(101 + index) as u8; 32]);
            let mut vote = JuryVote {
                complaint_id,
                evidence_hash,
                juror_node_id: *NodeId::from_public_key(&key.verifying_key()).as_bytes(),
                juror_public_key: [0; 32],
                decision,
                issued_at,
                signature: [0; 64],
            };
            crate::jury_vote::sign_vote(&key, &mut vote).expect("sign test vote");
            assert!(insert_vote_if_missing(
                storage.connection(),
                &JuryVoteRow {
                    complaint_id,
                    evidence_hash,
                    juror_node_id: vote.juror_node_id,
                    juror_public_key: vote.juror_public_key,
                    decision: vote.decision.as_u8(),
                    issued_at: vote.issued_at,
                    signature: vote.signature,
                },
            )
            .expect("persist test vote"));
        }
    }

    fn seed_awaiting_shares(
        ctx: &RuntimeContext,
        signing_key: &SigningKey,
        complaint_id: [u8; 32],
        with_shares: bool,
    ) -> Vec<RosterEntry> {
        let local_node = NodeId::from_public_key(&signing_key.verifying_key());
        let mut roster = vec![RosterEntry {
            share_index: 1,
            node_id: *local_node.as_bytes(),
        }];
        for share_index in 2..=7 {
            let recipient_key = SigningKey::from_bytes(&[share_index as u8 + 100; 32]);
            roster.push(RosterEntry {
                share_index,
                node_id: *NodeId::from_public_key(&recipient_key.verifying_key()).as_bytes(),
            });
        }

        let storage_arc = ctx.storage.as_ref().expect("test storage");
        let storage = storage_arc.lock().expect("storage lock");
        let connection = storage.connection();
        insert_roster(
            connection,
            &RosterRow {
                complaint_id,
                roster_generation: 1,
                roster_hash: [71; 32],
                roster_blob: serde_json::to_vec(&roster).expect("serialize roster"),
                created_at: 1,
            },
        )
        .expect("insert roster");
        for entry in &roster {
            insert_roster_assignment(
                connection,
                &RosterAssignmentRow {
                    complaint_id,
                    roster_generation: 1,
                    share_index: entry.share_index,
                    candidate_node_id: entry.node_id,
                    invitation_id: [entry.share_index as u8; 32],
                    invited_at: 1,
                    response: None,
                },
            )
            .expect("insert roster assignment");
            if with_shares && entry.node_id != *local_node.as_bytes() {
                insert_outgoing_share(
                    connection,
                    &OutgoingShareRow {
                        complaint_id,
                        dealer_node_id: *local_node.as_bytes(),
                        recipient_share_index: entry.share_index,
                        share_value: [entry.share_index as u8 + 10; 32],
                        created_at: 1,
                    },
                )
                .expect("insert outgoing share");
            }
        }
        upsert_juror_state(
            connection,
            &JurorState {
                complaint_id,
                juror_node_id: *local_node.as_bytes(),
                phase: JurorPhase::AwaitingShares,
                updated_at: 1,
            },
        )
        .expect("insert awaiting-shares state");
        roster
    }

    fn seed_aggregation_inputs(
        ctx: &RuntimeContext,
        signing_key: &SigningKey,
        complaint_id: [u8; 32],
        verified_count: u8,
        include_own_share: bool,
    ) -> ([u8; 32], Scalar) {
        seed_awaiting_shares(ctx, signing_key, complaint_id, false);
        let local_bytes = *NodeId::from_public_key(&signing_key.verifying_key()).as_bytes();
        let own_scalar = Scalar::from(10u64);
        let storage = ctx.storage.as_ref().expect("test storage");
        let storage = storage.lock().expect("storage lock");
        let connection = storage.connection();
        if include_own_share {
            upsert_own_share(
                connection,
                &OwnShareRow {
                    complaint_id,
                    juror_node_id: local_bytes,
                    share_index: 1,
                    share_value: zeroize::Zeroizing::new(own_scalar.to_bytes()),
                    threshold: 5,
                    participant_count: 7,
                    computed_at: 1,
                },
            )
            .expect("insert local own share");
        }
        for index in 1..=verified_count {
            let dealer_node_id = [index.saturating_add(20); 32];
            upsert_received_share(
                connection,
                &ReceivedShareRow {
                    complaint_id,
                    dealer_node_id,
                    dealer_public_key: [index.saturating_add(40); 32],
                    dealer_share_index: u32::from(index) + 1,
                    recipient_share_index: 1,
                    share_value: zeroize::Zeroizing::new(Scalar::from(u64::from(index)).to_bytes()),
                    received_at: 2,
                    verified: false,
                    message_id: [index.saturating_add(60); 32],
                },
            )
            .expect("insert received share");
            assert!(
                mark_received_share_verified(connection, &complaint_id, &dealer_node_id)
                    .expect("mark test share verified")
            );
        }
        (local_bytes, own_scalar)
    }

    #[test]
    fn compute_share_message_id_deterministic() {
        let complaint_id = [1; 32];
        let dealer_node_id = [2; 32];
        assert_eq!(
            compute_share_message_id(&complaint_id, &dealer_node_id, 3),
            compute_share_message_id(&complaint_id, &dealer_node_id, 3)
        );
    }

    #[test]
    fn compute_share_message_id_differs_by_recipient() {
        let complaint_id = [1; 32];
        let dealer_node_id = [2; 32];
        assert_ne!(
            compute_share_message_id(&complaint_id, &dealer_node_id, 3),
            compute_share_message_id(&complaint_id, &dealer_node_id, 4)
        );
    }

    #[tokio::test]
    async fn tick_skips_awaiting_shares_when_no_outgoing_shares() {
        let (ctx, signing_key, _directory) = context(true);
        let complaint_id = [33; 32];
        seed_awaiting_shares(&ctx, &signing_key, complaint_id, false);

        task(Arc::clone(&ctx), signing_key.clone())
            .tick()
            .await
            .expect("tick with no outgoing shares");

        let storage = ctx.storage.as_ref().expect("test storage");
        for recipient_share_index in 2..=7 {
            let message_id = compute_share_message_id(
                &complaint_id,
                NodeId::from_public_key(&signing_key.verifying_key()).as_bytes(),
                recipient_share_index,
            );
            assert!(read_outbox_entry(
                &storage.lock().expect("storage lock").connection(),
                &message_id
            )
            .expect("read outbox")
            .is_none());
        }
    }

    #[tokio::test]
    async fn tick_dispatches_six_shares_on_awaiting_shares() {
        let (ctx, signing_key, _directory) = context(true);
        let complaint_id = [34; 32];
        let roster = seed_awaiting_shares(&ctx, &signing_key, complaint_id, true);
        let local_bytes = *NodeId::from_public_key(&signing_key.verifying_key()).as_bytes();
        let storage = ctx.storage.as_ref().expect("test storage");

        task(Arc::clone(&ctx), signing_key.clone())
            .tick_at(200)
            .await
            .expect("dispatch outgoing shares");

        let storage = storage.lock().expect("storage lock");
        for recipient_share_index in 2..=7 {
            let message_id =
                compute_share_message_id(&complaint_id, &local_bytes, recipient_share_index);
            let entry = read_outbox_entry(storage.connection(), &message_id)
                .expect("read outbox")
                .expect("share delivery enqueued");
            let recipient = roster
                .iter()
                .find(|entry| entry.share_index == recipient_share_index)
                .expect("recipient roster entry");
            assert_eq!(entry.kind, OutboxKind::ShareDelivery);
            assert_eq!(entry.recipient_node_id, recipient.node_id);
            let event: SyncEvent =
                serde_json::from_slice(&entry.event_blob).expect("decode outbox event");
            let payload: JuryShareDeliveryPayload =
                serde_json::from_str(&event.data).expect("decode share payload");
            assert_eq!(payload.message_id, message_id);
            assert_eq!(payload.complaint_id, complaint_id);
            assert_eq!(payload.dealer_node_id, local_bytes);
            assert_eq!(
                payload.dealer_public_key,
                signing_key.verifying_key().to_bytes()
            );
            assert_eq!(payload.dealer_share_index, 1);
            assert_eq!(payload.recipient_share_index, recipient_share_index);
            assert_eq!(payload.share_value, [recipient_share_index as u8 + 10; 32]);
        }
    }

    #[tokio::test]
    async fn tick_dispatch_idempotent_on_second_call() {
        let (ctx, signing_key, _directory) = context(true);
        let complaint_id = [35; 32];
        seed_awaiting_shares(&ctx, &signing_key, complaint_id, true);
        let local_bytes = *NodeId::from_public_key(&signing_key.verifying_key()).as_bytes();
        let orchestrator = task(Arc::clone(&ctx), signing_key);

        orchestrator
            .tick_at(200)
            .await
            .expect("first dispatch tick");
        orchestrator
            .tick_at(201)
            .await
            .expect("second dispatch tick");

        let storage = ctx.storage.as_ref().expect("test storage");
        let storage = storage.lock().expect("storage lock");
        for recipient_share_index in 2..=7 {
            let message_id =
                compute_share_message_id(&complaint_id, &local_bytes, recipient_share_index);
            assert!(read_outbox_entry(storage.connection(), &message_id)
                .expect("read outbox")
                .is_some());
        }
    }

    #[tokio::test]
    async fn tick_noop_without_storage() {
        let (ctx, signing_key, _directory) = context(false);
        task(ctx, signing_key)
            .tick()
            .await
            .expect("tick without storage");
    }

    #[tokio::test]
    async fn tick_noop_with_no_active_juror_states() {
        let (ctx, signing_key, _directory) = context(true);
        task(ctx, signing_key)
            .tick()
            .await
            .expect("tick with no active jurors");
    }

    #[tokio::test]
    async fn tick_transitions_ready_to_awaiting_votes_and_emits_notification() {
        let (ctx, signing_key, _directory) = context(true);
        let complaint_id = [68; 32];
        let evidence_hash = [69; 32];
        let local_bytes = *NodeId::from_public_key(&signing_key.verifying_key()).as_bytes();
        insert_state(
            &ctx,
            JurorState {
                complaint_id,
                juror_node_id: local_bytes,
                phase: JurorPhase::ReadyForDecryption,
                updated_at: 100,
            },
        );
        ctx.jury_plaintext_cache
            .insert(
                complaint_id,
                evidence_hash,
                zeroize::Zeroizing::new(b"{\"evidence\":true}".to_vec()),
            )
            .expect("cache plaintext");

        assert!(
            transition_to_vote_needed(&ctx, &complaint_id, &local_bytes, &evidence_hash, 200,)
                .await
                .expect("first transition")
        );
        assert!(
            !transition_to_vote_needed(&ctx, &complaint_id, &local_bytes, &evidence_hash, 201,)
                .await
                .expect("duplicate transition")
        );

        let storage = ctx.storage.as_ref().expect("test storage");
        let state = read_juror_state(
            &storage.lock().expect("storage lock").connection(),
            &complaint_id,
            &local_bytes,
        )
        .expect("read state")
        .expect("state exists");
        assert_eq!(state.phase, JurorPhase::AwaitingVotes);
        let home = ctx.home_state.lock().await;
        let notifications = home.notifications.pending();
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].kind, NotificationKind::JuryVoteNeeded);
    }

    #[tokio::test]
    async fn tick_finalizes_verdict_and_evicts_plaintext() {
        let (ctx, signing_key, _directory) = context(true);
        let complaint_id = [84; 32];
        let evidence_hash = [85; 32];
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_secs();
        let local_bytes = *NodeId::from_public_key(&signing_key.verifying_key()).as_bytes();
        insert_state(
            &ctx,
            JurorState {
                complaint_id,
                juror_node_id: local_bytes,
                phase: JurorPhase::AwaitingVotes,
                updated_at: now.saturating_sub(1),
            },
        );
        seed_vote_evidence(
            &ctx,
            complaint_id,
            evidence_hash,
            &[JuryDecision::Guilty; 5],
            now.saturating_sub(1),
        );
        ctx.jury_plaintext_cache
            .insert(
                complaint_id,
                evidence_hash,
                zeroize::Zeroizing::new(b"{\"evidence\":true}".to_vec()),
            )
            .expect("cache plaintext");

        task(Arc::clone(&ctx), signing_key)
            .tick()
            .await
            .expect("finalize guilty verdict");

        let storage = ctx.storage.as_ref().expect("test storage");
        let storage = storage.lock().expect("storage lock");
        let verdict = read_verdict(storage.connection(), &complaint_id, &evidence_hash)
            .expect("read verdict")
            .expect("verdict persisted");
        assert_eq!(verdict.verdict, JuryDecision::Guilty.as_u8());
        let state = read_juror_state(storage.connection(), &complaint_id, &local_bytes)
            .expect("read juror state")
            .expect("juror state exists");
        assert_eq!(state.phase, JurorPhase::VerdictFinalized);
        drop(storage);
        assert!(ctx
            .jury_plaintext_cache
            .get(&complaint_id, &evidence_hash)
            .expect("read evicted cache")
            .is_none());
        let home = ctx.home_state.lock().await;
        assert_eq!(
            home.notifications
                .pending()
                .iter()
                .filter(|notification| notification.kind == NotificationKind::JuryVerdictReady)
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn tick_finalizes_inconclusive_with_mixed_votes() {
        let (ctx, signing_key, _directory) = context(true);
        let complaint_id = [86; 32];
        let evidence_hash = [87; 32];
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_secs();
        let local_bytes = *NodeId::from_public_key(&signing_key.verifying_key()).as_bytes();
        insert_state(
            &ctx,
            JurorState {
                complaint_id,
                juror_node_id: local_bytes,
                phase: JurorPhase::AwaitingVotes,
                updated_at: now.saturating_sub(1),
            },
        );
        seed_vote_evidence(
            &ctx,
            complaint_id,
            evidence_hash,
            &[
                JuryDecision::Guilty,
                JuryDecision::Guilty,
                JuryDecision::Guilty,
                JuryDecision::NotGuilty,
                JuryDecision::NotGuilty,
                JuryDecision::Inconclusive,
                JuryDecision::Inconclusive,
            ],
            now.saturating_sub(1),
        );
        ctx.jury_plaintext_cache
            .insert(
                complaint_id,
                evidence_hash,
                zeroize::Zeroizing::new(b"{\"evidence\":true}".to_vec()),
            )
            .expect("cache plaintext");

        task(Arc::clone(&ctx), signing_key)
            .tick()
            .await
            .expect("finalize inconclusive verdict");

        let storage = ctx.storage.as_ref().expect("test storage");
        let verdict = read_verdict(
            &storage.lock().expect("storage lock").connection(),
            &complaint_id,
            &evidence_hash,
        )
        .expect("read verdict")
        .expect("verdict persisted");
        assert_eq!(verdict.verdict, JuryDecision::Inconclusive.as_u8());
        assert!(ctx
            .jury_plaintext_cache
            .get(&complaint_id, &evidence_hash)
            .expect("read evicted cache")
            .is_none());
    }

    #[tokio::test]
    async fn tick_stays_awaiting_votes_when_insufficient() {
        let (ctx, signing_key, _directory) = context(true);
        let complaint_id = [88; 32];
        let evidence_hash = [89; 32];
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_secs();
        let local_bytes = *NodeId::from_public_key(&signing_key.verifying_key()).as_bytes();
        insert_state(
            &ctx,
            JurorState {
                complaint_id,
                juror_node_id: local_bytes,
                phase: JurorPhase::AwaitingVotes,
                updated_at: now.saturating_sub(1),
            },
        );
        seed_vote_evidence(
            &ctx,
            complaint_id,
            evidence_hash,
            &[JuryDecision::Guilty; 4],
            now.saturating_sub(1),
        );
        ctx.jury_plaintext_cache
            .insert(
                complaint_id,
                evidence_hash,
                zeroize::Zeroizing::new(b"{\"evidence\":true}".to_vec()),
            )
            .expect("cache plaintext");

        task(Arc::clone(&ctx), signing_key)
            .tick()
            .await
            .expect("tick with insufficient votes");

        let storage = ctx.storage.as_ref().expect("test storage");
        {
            let storage = storage.lock().expect("storage lock");
            let state = read_juror_state(storage.connection(), &complaint_id, &local_bytes)
                .expect("read juror state")
                .expect("juror state exists");
            assert_eq!(state.phase, JurorPhase::AwaitingVotes);
            assert!(
                read_verdict(storage.connection(), &complaint_id, &evidence_hash)
                    .expect("read verdict")
                    .is_none()
            );
        }
        assert!(ctx
            .jury_plaintext_cache
            .get(&complaint_id, &evidence_hash)
            .expect("read retained cache")
            .is_some());
    }

    #[tokio::test]
    async fn tick_processes_ready_phase_and_leaves_expired_state() {
        let (ctx, signing_key, _directory) = context(true);
        let local_bytes = *NodeId::from_public_key(&signing_key.verifying_key()).as_bytes();
        for phase in [JurorPhase::ReadyForDecryption, JurorPhase::Expired] {
            insert_state(
                &ctx,
                JurorState {
                    complaint_id: [phase as u8; 32],
                    juror_node_id: local_bytes,
                    phase,
                    updated_at: 100,
                },
            );
        }

        task(Arc::clone(&ctx), signing_key.clone())
            .tick_at(200)
            .await
            .expect("tick terminal states");

        let storage = ctx.storage.as_ref().expect("test storage");
        let storage = storage.lock().expect("storage lock");
        for phase in [JurorPhase::ReadyForDecryption, JurorPhase::Expired] {
            let state = read_juror_state(storage.connection(), &[phase as u8; 32], &local_bytes)
                .expect("read state")
                .expect("state exists");
            assert_eq!(state.phase, phase);
        }
    }

    #[tokio::test]
    async fn tick_skips_when_no_roster() {
        let (ctx, signing_key, _directory) = context(true);
        let local_bytes = *NodeId::from_public_key(&signing_key.verifying_key()).as_bytes();
        let complaint_id = [19; 32];
        insert_state(
            &ctx,
            JurorState {
                complaint_id,
                juror_node_id: local_bytes,
                phase: JurorPhase::Accepted,
                updated_at: 100,
            },
        );

        task(Arc::clone(&ctx), signing_key)
            .tick_at(200)
            .await
            .expect("tick without roster");

        let storage = ctx.storage.as_ref().expect("test storage");
        let state = read_juror_state(
            &storage.lock().expect("storage lock").connection(),
            &complaint_id,
            &local_bytes,
        )
        .expect("read state")
        .expect("state exists");
        assert_eq!(state.phase, JurorPhase::Accepted);
    }

    #[tokio::test]
    async fn aggregate_waits_when_not_all_verified() {
        let (ctx, signing_key, _directory) = context(true);
        let complaint_id = [81; 32];
        let (local_bytes, _) = seed_aggregation_inputs(&ctx, &signing_key, complaint_id, 5, true);

        task(Arc::clone(&ctx), signing_key.clone())
            .tick_at(200)
            .await
            .expect("tick with only five verified shares");

        let storage = ctx.storage.as_ref().expect("test storage");
        let storage = storage.lock().expect("storage lock");
        assert!(
            read_aggregated_share(storage.connection(), &complaint_id, &local_bytes)
                .expect("read aggregated share")
                .is_none()
        );
        let state = read_juror_state(storage.connection(), &complaint_id, &local_bytes)
            .expect("read juror state")
            .expect("juror state exists");
        assert_eq!(state.phase, JurorPhase::AwaitingShares);
    }

    #[tokio::test]
    async fn aggregate_computes_x_j_when_all_verified() {
        let (ctx, signing_key, _directory) = context(true);
        let complaint_id = [82; 32];
        let (local_bytes, own_scalar) =
            seed_aggregation_inputs(&ctx, &signing_key, complaint_id, 6, true);

        task(Arc::clone(&ctx), signing_key.clone())
            .tick_at(200)
            .await
            .expect("aggregate all verified shares");

        let expected = own_scalar + (1u64..=6).map(Scalar::from).sum::<Scalar>();
        let storage = ctx.storage.as_ref().expect("test storage");
        let storage = storage.lock().expect("storage lock");
        let aggregated = read_aggregated_share(storage.connection(), &complaint_id, &local_bytes)
            .expect("read aggregated share")
            .expect("aggregated share exists");
        assert_eq!(aggregated.aggregated_value, expected.to_bytes());
        let state = read_juror_state(storage.connection(), &complaint_id, &local_bytes)
            .expect("read juror state")
            .expect("juror state exists");
        assert_eq!(state.phase, JurorPhase::ReadyForDecryption);
        drop(storage);
        let home_state = ctx.home_state.lock().await;
        let ready_notifications = home_state
            .notifications
            .pending()
            .into_iter()
            .filter(|notification| notification.kind == NotificationKind::JuryReadyForDecryption)
            .count();
        assert_eq!(ready_notifications, 1);
    }

    #[tokio::test]
    async fn aggregate_is_idempotent_on_second_tick() {
        let (ctx, signing_key, _directory) = context(true);
        let complaint_id = [83; 32];
        let (local_bytes, _) = seed_aggregation_inputs(&ctx, &signing_key, complaint_id, 6, true);
        let existing = AggregatedShareRow {
            complaint_id,
            juror_node_id: local_bytes,
            share_index: 1,
            aggregated_value: Scalar::from(88u64).to_bytes(),
            threshold: 5,
            participant_count: 7,
            computed_at: 77,
        };
        {
            let storage = ctx.storage.as_ref().expect("test storage");
            upsert_aggregated_share(
                &storage.lock().expect("storage lock").connection(),
                &existing,
            )
            .expect("seed aggregate persisted before phase transition");
        }
        let orchestrator = task(Arc::clone(&ctx), signing_key);

        orchestrator
            .tick_at(200)
            .await
            .expect("recover phase transition");
        orchestrator
            .tick_at(201)
            .await
            .expect("second idempotent tick");

        let storage = ctx.storage.as_ref().expect("test storage");
        let storage = storage.lock().expect("storage lock");
        let aggregated = read_aggregated_share(storage.connection(), &complaint_id, &local_bytes)
            .expect("read aggregated share")
            .expect("aggregated share remains");
        assert_eq!(aggregated.computed_at, existing.computed_at);
        assert_eq!(aggregated.aggregated_value, existing.aggregated_value);
        let state = read_juror_state(storage.connection(), &complaint_id, &local_bytes)
            .expect("read juror state")
            .expect("juror state exists");
        assert_eq!(state.phase, JurorPhase::ReadyForDecryption);
        drop(storage);
        let home_state = ctx.home_state.lock().await;
        let ready_notifications = home_state
            .notifications
            .pending()
            .into_iter()
            .filter(|notification| notification.kind == NotificationKind::JuryReadyForDecryption)
            .count();
        assert_eq!(ready_notifications, 1);
    }

    #[tokio::test]
    async fn aggregate_skips_when_own_share_missing() {
        let (ctx, signing_key, _directory) = context(true);
        let complaint_id = [84; 32];
        let (local_bytes, _) = seed_aggregation_inputs(&ctx, &signing_key, complaint_id, 6, false);

        task(Arc::clone(&ctx), signing_key.clone())
            .tick()
            .await
            .expect("tick without local own share");

        let storage = ctx.storage.as_ref().expect("test storage");
        let storage = storage.lock().expect("storage lock");
        assert!(
            read_own_share(storage.connection(), &complaint_id, &local_bytes)
                .expect("read own share")
                .is_none()
        );
        assert!(
            read_aggregated_share(storage.connection(), &complaint_id, &local_bytes)
                .expect("read aggregated share")
                .is_none()
        );
    }
}
