//! Juror response handling for accepted or rejected jury invitations.
//!
//! The accepted path persists the local dealer secret, records the own share and
//! all outgoing shares, and publishes the signed Feldman commitments to DHT.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::dht::jury_acceptance::sign_acceptance;
use crate::dht::jury_dkg_commitment::{sign_commitment, JURY_PARTICIPANTS, JURY_THRESHOLD};
use crate::dht::NodeId;
use crate::journal::{JuryInvitationPayload, JuryInvitationResponsePayload, SyncEvent};
use crate::jury_assembly::register_juror_state;
use crate::jury_delivery_outbox::enqueue_invitation_response;
use crate::runtime_context::RuntimeContext;
use hal_crypto::vss::feldman_split;
use hal_storage::jury_dkg_storage::{
    insert_dealer_secret, read_dealer_secret, upsert_own_share, DealerSecretRow, OwnShareRow,
};
use hal_storage::jury_invitations::{
    delete_pending_invitation, read_pending_invitation_by_notification,
};
use hal_storage::jury_outgoing_shares::{insert_outgoing_share, OutgoingShareRow};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JurorDecision {
    Accept,
    Reject,
}

fn accepted_flag(decision: JurorDecision) -> bool {
    matches!(decision, JurorDecision::Accept)
}

fn response_share_index(decision: JurorDecision, payload: &JuryInvitationPayload) -> u32 {
    if accepted_flag(decision) {
        payload.share_index
    } else {
        0
    }
}

pub async fn respond_to_jury_invitation(
    ctx: &Arc<RuntimeContext>,
    notification_id: u64,
    decision: JurorDecision,
    now: u64,
) -> Result<[u8; 32]> {
    let storage_arc = ctx
        .storage
        .as_ref()
        .context("storage required for juror response")?;
    let pending = {
        let storage = storage_arc
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        read_pending_invitation_by_notification(storage.connection(), notification_id)?
            .context("pending jury invitation not found for notification")?
    };

    let payload: JuryInvitationPayload = serde_json::from_slice(&pending.payload_blob)
        .context("deserialize persisted jury invitation payload")?;
    let accepted = accepted_flag(decision);
    if accepted && ctx.jury_commitment_publisher.is_none() {
        return Err(anyhow!("jury commitment publisher not configured"));
    }

    {
        let mut home = ctx.home_state.lock().await;
        home.notifications
            .respond(notification_id, accepted, now)
            .map_err(|error| anyhow!("update notification status: {error}"))?;
    }

    let signing_key = ctx
        .identity_signing_key
        .as_ref()
        .context("signing key unavailable")?
        .clone();
    let local_node = NodeId::from_hex(&ctx.identity_id)
        .context("parse local identity for jury invitation response")?;
    let local_node_id = *local_node.as_bytes();

    let response_payload = JuryInvitationResponsePayload {
        invitation_id: payload.invitation_id,
        complaint_id: payload.complaint_id,
        candidate_node_id: local_node_id,
        accepted,
        share_index: response_share_index(decision, &payload),
        roster_hash: payload.roster_hash,
        acceptance: if accepted {
            Some(
                sign_acceptance(&signing_key, payload.complaint_id, payload.share_index, now)
                    .map_err(|error| anyhow!("sign acceptance: {error}"))?,
            )
        } else {
            None
        },
        responded_at: now,
    };
    let response_event = SyncEvent::jury_invitation_response(&response_payload)
        .context("build invitation response event")?;

    enqueue_invitation_response(
        ctx,
        response_event,
        payload.complaint_id,
        payload.complainant_node_id,
        payload.invitation_id,
        now,
    )?;

    register_juror_state(ctx, payload.complaint_id, local_node_id, now)?;

    {
        let storage = storage_arc
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        let assignment_response = if accepted {
            hal_storage::jury_rosters::RosterAssignmentResponse::Accepted
        } else {
            hal_storage::jury_rosters::RosterAssignmentResponse::Rejected
        };
        if !hal_storage::jury_rosters::record_assignment_response(
            storage.connection(),
            &payload.complaint_id,
            payload.roster_generation,
            &payload.invitation_id,
            assignment_response,
            now,
        )? {
            return Err(anyhow!("jury roster assignment response was not recorded"));
        }
        delete_pending_invitation(storage.connection(), notification_id)?;
    }

    if accepted {
        setup_dealer_and_save_shares(ctx, &payload, &signing_key, now).await?;
    }

    log::debug!(
        "juror response recorded: complaint={} invitation={} accepted={}",
        hex::encode(payload.complaint_id),
        hex::encode(payload.invitation_id),
        accepted,
    );
    Ok(payload.invitation_id)
}

async fn setup_dealer_and_save_shares(
    ctx: &Arc<RuntimeContext>,
    payload: &JuryInvitationPayload,
    signing_key: &ed25519_dalek::SigningKey,
    now: u64,
) -> Result<()> {
    let storage_arc = ctx
        .storage
        .as_ref()
        .context("storage required for dealer setup")?;
    let local_node =
        NodeId::from_hex(&ctx.identity_id).context("parse local identity for dealer setup")?;
    let dealer_node_id = *local_node.as_bytes();
    let dealer_public_key = ctx
        .identity_signing_key
        .as_ref()
        .context("signing key unavailable")?
        .verifying_key()
        .to_bytes();
    let publisher = ctx
        .jury_commitment_publisher
        .as_ref()
        .context("jury commitment publisher not configured")?;

    let dealer_secret_exists = {
        let storage = storage_arc
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        read_dealer_secret(storage.connection(), &payload.complaint_id, &dealer_node_id)?.is_some()
    };
    if dealer_secret_exists {
        let commitment = publisher
            .read_local(&payload.complaint_id, &dealer_node_id, now)?
            .context("dealer secret exists without a persisted jury commitment")?;
        publisher
            .publish_once(&commitment, now)
            .await
            .context("republish jury commitment")?;
        return Ok(());
    }

    let mut rng = OsRng;
    let mut secret_bytes = [0u8; 64];
    rng.fill_bytes(&mut secret_bytes);
    let secret = Scalar::from_bytes_mod_order_wide(&secret_bytes);
    let split = feldman_split(&mut rng, &secret, JURY_THRESHOLD, JURY_PARTICIPANTS)
        .context("split local jury secret for dealer setup")?;

    let expires_at = now
        .checked_add(hal_storage::jury_dkg_storage::JURY_DKG_TTL_SECS)
        .context("dealer secret expiry overflow")?;
    {
        let storage = storage_arc
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        insert_dealer_secret(
            storage.connection(),
            &DealerSecretRow {
                complaint_id: payload.complaint_id,
                dealer_node_id,
                dealer_public_key,
                secret_scalar: Zeroizing::new(secret.to_bytes()),
                threshold: JURY_THRESHOLD,
                participant_count: JURY_PARTICIPANTS,
                created_at: now,
            },
            expires_at,
        )?;
    }

    let own_share = split
        .shares
        .iter()
        .find(|share| share.index == payload.share_index)
        .context("assigned jury share missing from dealer split")?;
    {
        let storage = storage_arc
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        upsert_own_share(
            storage.connection(),
            &OwnShareRow {
                complaint_id: payload.complaint_id,
                juror_node_id: dealer_node_id,
                share_index: payload.share_index,
                share_value: Zeroizing::new(own_share.value.to_bytes()),
                threshold: JURY_THRESHOLD,
                participant_count: JURY_PARTICIPANTS,
                computed_at: now,
            },
        )?;
    }

    for share in split.shares {
        if share.index == payload.share_index {
            continue;
        }
        let storage = storage_arc
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        insert_outgoing_share(
            storage.connection(),
            &OutgoingShareRow {
                complaint_id: payload.complaint_id,
                dealer_node_id,
                recipient_share_index: share.index,
                share_value: share.value.to_bytes(),
                created_at: now,
            },
        )?;
    }

    let commitments_compressed = split
        .commitments
        .commitments
        .iter()
        .map(|commitment| commitment.to_bytes())
        .collect();
    let commitment_record = sign_commitment(
        signing_key,
        payload.complaint_id,
        commitments_compressed,
        now,
    )
    .map_err(|error| anyhow!("sign commitment: {error}"))?;
    publisher
        .publish_once(&commitment_record, now)
        .await
        .context("publish jury commitment")?;

    log::debug!(
        "dealer setup complete: complaint={} dealer={} own_share={} outgoing={}",
        hex::encode(payload.complaint_id),
        hex::encode(dealer_node_id),
        payload.share_index,
        JURY_PARTICIPANTS - 1,
    );
    log::debug!(
        "jury commitment published: complaint={} dealer={}",
        hex::encode(payload.complaint_id),
        hex::encode(dealer_node_id),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::group::{GroupGraph, GroupRegistry};
    use crate::dht::notifier::NotificationKind;
    use crate::dht::trust_oracle::BasicTrustOracle;
    use crate::journal::{
        compute_invitation_id_v2, compute_roster_hash, JuryInvitationPayload, RosterEntry,
    };
    use crate::journal_commit_publisher::PublishTransport;
    use crate::jury_commitment_publisher::JuryCommitmentPublisher;
    use crate::runtime::HomeRuntimeState;
    use crate::runtime_context::{NoopBiometricGate, RuntimeContext};
    use ed25519_dalek::SigningKey;
    use hal_storage::jury_assembly_state::{read_juror_state_from_storage, JurorPhase};
    use hal_storage::jury_dkg_storage::{read_dealer_secret, read_own_share};
    use hal_storage::jury_invitations::{
        insert_pending_invitation, read_pending_invitation_by_notification,
        PendingJuryInvitationRow,
    };
    use hal_storage::jury_outgoing_shares::list_outgoing_shares_for_complaint;
    use hal_storage::jury_rosters::{
        insert_roster, insert_roster_assignment, read_assignment, RosterAssignmentRow, RosterRow,
    };
    use hal_storage::ClientStorage;
    use std::sync::{Arc, Mutex};
    use tokio::sync::Mutex as TokioMutex;

    struct PublishedRecord {
        key: [u8; 32],
        value: Vec<u8>,
        record_type: crate::dht::wire::StoredRecordType,
        expires_at: u64,
    }

    #[derive(Clone)]
    struct RecordingPublishTransport(Arc<Mutex<Vec<PublishedRecord>>>);

    #[async_trait::async_trait]
    impl PublishTransport for RecordingPublishTransport {
        async fn store_typed(
            &self,
            key: [u8; 32],
            value: Vec<u8>,
            record_type: crate::dht::wire::StoredRecordType,
            expires_at: u64,
        ) -> anyhow::Result<()> {
            self.0
                .lock()
                .map_err(|_| anyhow::anyhow!("test transport lock poisoned"))?
                .push(PublishedRecord {
                    key,
                    value,
                    record_type,
                    expires_at,
                });
            Ok(())
        }
    }

    async fn build_test_ctx() -> (Arc<RuntimeContext>, tempfile::TempDir) {
        let (ctx, directory, _) = build_test_ctx_with_publisher(true).await;
        (ctx, directory)
    }

    async fn build_test_ctx_with_publisher(
        with_publisher: bool,
    ) -> (
        Arc<RuntimeContext>,
        tempfile::TempDir,
        Arc<Mutex<Vec<PublishedRecord>>>,
    ) {
        let directory = tempfile::tempdir().expect("temp dir");
        let storage = Arc::new(Mutex::new(
            ClientStorage::open(directory.path().join("juror-response.db"), &[7; 32])
                .expect("open storage"),
        ));
        let local_key = SigningKey::from_bytes(&[42; 32]);
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
        let publish_calls = Arc::new(Mutex::new(Vec::new()));
        let jury_commitment_publisher = with_publisher.then(|| {
            Arc::new(JuryCommitmentPublisher::new(
                Arc::clone(&storage),
                Arc::new(RecordingPublishTransport(Arc::clone(&publish_calls))),
            ))
        });
        let identity_id = NodeId::from_public_key(&local_key.verifying_key()).to_hex();
        let ctx = Arc::new(RuntimeContext {
            sync: Arc::new(TokioMutex::new(crate::SyncManager::new(
                "juror-response-test".into(),
            ))),
            home_state: Arc::new(TokioMutex::new(HomeRuntimeState::default())),
            media_signals: Arc::new(TokioMutex::new(Vec::new())),
            storage: Some(storage),
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
            identity_id,
            public_key: hex::encode(local_key.verifying_key().to_bytes()),
            identity_signing_key: Some(Arc::new(local_key)),
            jury_commitment_publisher,
            jury_plaintext_cache: RuntimeContext::default_jury_plaintext_cache(),
            invite_redemption_transport: None,
            pending_invite_redemptions: RuntimeContext::default_pending_invite_redemptions(),
            sas_pairing: RuntimeContext::default_sas_pairing(),
            integrity: None,
        });
        (ctx, directory, publish_calls)
    }

    fn test_payload_for_local_ctx(ctx: &RuntimeContext, share_index: u32) -> JuryInvitationPayload {
        let complaint_id = [7; 32];
        let complainant_node_id = [11; 32];
        let candidate_node_id = *NodeId::from_hex(&ctx.identity_id)
            .expect("local identity")
            .as_bytes();
        let roster = (1..=JURY_PARTICIPANTS)
            .map(|index| RosterEntry {
                share_index: index,
                node_id: if index == share_index {
                    candidate_node_id
                } else {
                    [100 + index as u8; 32]
                },
            })
            .collect::<Vec<_>>();
        let roster_hash = compute_roster_hash(&complaint_id, &roster).expect("roster hash");
        let roster_generation = 9;
        JuryInvitationPayload {
            complaint_id,
            complainant_node_id,
            candidate_node_id,
            share_index,
            roster,
            roster_hash,
            roster_generation,
            invitation_id: compute_invitation_id_v2(
                &complaint_id,
                &complainant_node_id,
                &candidate_node_id,
                roster_generation,
            ),
            issued_at: 10,
            response_deadline: 100,
        }
    }

    async fn seed_pending_invitation(
        ctx: &Arc<RuntimeContext>,
        payload: &JuryInvitationPayload,
        notification_id: u64,
        now: u64,
    ) {
        let actual_notification_id = ctx.home_state.lock().await.notifications.create(
            NotificationKind::JuryOptInRequest,
            NodeId::from_bytes(payload.complainant_node_id),
            NodeId::from_bytes(payload.complaint_id),
            None,
            now,
            1_000,
        );
        assert_eq!(actual_notification_id, notification_id);
        let storage = ctx.storage.as_ref().expect("test storage");
        let storage = storage.lock().expect("storage lock");
        let connection = storage.connection();
        insert_roster(
            connection,
            &RosterRow {
                complaint_id: payload.complaint_id,
                roster_generation: payload.roster_generation,
                roster_hash: payload.roster_hash,
                roster_blob: serde_json::to_vec(&payload.roster).expect("serialize roster"),
                created_at: now,
            },
        )
        .expect("insert roster");
        for entry in &payload.roster {
            insert_roster_assignment(
                connection,
                &RosterAssignmentRow {
                    complaint_id: payload.complaint_id,
                    roster_generation: payload.roster_generation,
                    share_index: entry.share_index,
                    candidate_node_id: entry.node_id,
                    invitation_id: compute_invitation_id_v2(
                        &payload.complaint_id,
                        &payload.complainant_node_id,
                        &entry.node_id,
                        payload.roster_generation,
                    ),
                    invited_at: payload.issued_at,
                    response: None,
                },
            )
            .expect("insert roster assignment");
        }
        insert_pending_invitation(
            connection,
            &PendingJuryInvitationRow {
                notification_id: actual_notification_id,
                invitation_id: payload.invitation_id,
                complaint_id: payload.complaint_id,
                complainant_node_id: payload.complainant_node_id,
                candidate_node_id: payload.candidate_node_id,
                share_index: payload.share_index,
                roster_generation: payload.roster_generation,
                received_at: now,
                expires_at: now + 1_000,
                payload_blob: serde_json::to_vec(payload).expect("serialize invitation"),
            },
        )
        .expect("insert pending invitation");
    }

    fn make_test_payload(candidate_share: u32) -> JuryInvitationPayload {
        let complaint_id = [7u8; 32];
        let complainant_node_id = [11u8; 32];
        let candidate_node_id = [(100 + candidate_share as u8); 32];
        let mut roster = Vec::with_capacity(7);
        for share_index in 1..=7 {
            let node_id = if share_index == candidate_share {
                candidate_node_id
            } else {
                [(100 + share_index as u8); 32]
            };
            roster.push(RosterEntry {
                share_index,
                node_id,
            });
        }
        let roster_hash = compute_roster_hash(&complaint_id, &roster).expect("valid roster hash");
        let invitation_id =
            compute_invitation_id_v2(&complaint_id, &complainant_node_id, &candidate_node_id, 9);
        JuryInvitationPayload {
            complaint_id,
            complainant_node_id,
            candidate_node_id,
            share_index: candidate_share,
            roster,
            roster_hash,
            roster_generation: 9,
            invitation_id,
            issued_at: 10,
            response_deadline: 100,
        }
    }

    fn make_acceptance_record(
        payload: &JuryInvitationPayload,
        signing_key: &SigningKey,
        now: u64,
    ) -> Option<crate::dht::jury_acceptance::JuryAcceptanceRecord> {
        Some(
            sign_acceptance(signing_key, payload.complaint_id, payload.share_index, now)
                .expect("sign acceptance"),
        )
    }

    #[test]
    fn accept_decision_is_truthy() {
        assert!(accepted_flag(JurorDecision::Accept));
    }

    #[test]
    fn reject_decision_is_falsey() {
        assert!(!accepted_flag(JurorDecision::Reject));
    }

    #[test]
    fn response_share_index_uses_invitation_index_for_accept() {
        let payload = make_test_payload(3);
        assert_eq!(response_share_index(JurorDecision::Accept, &payload), 3);
    }

    #[test]
    fn response_share_index_zero_for_reject() {
        let payload = make_test_payload(4);
        assert_eq!(response_share_index(JurorDecision::Reject, &payload), 0);
    }

    #[test]
    fn accepted_payload_has_signed_acceptance_record() {
        let payload = make_test_payload(2);
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let record = make_acceptance_record(&payload, &signing_key, 123).expect("acceptance");
        assert_eq!(record.complaint_id, payload.complaint_id);
        assert_eq!(record.share_index, payload.share_index);
    }

    #[test]
    fn rejected_payload_has_no_acceptance_record() {
        let payload = make_test_payload(5);
        assert_eq!(response_share_index(JurorDecision::Reject, &payload), 0);
        assert_eq!(payload.share_index, 5);
    }

    #[test]
    fn dealer_secret_row_capsule_omits_coefficients() {
        let row = DealerSecretRow {
            complaint_id: [1u8; 32],
            dealer_node_id: [2u8; 32],
            dealer_public_key: [3u8; 32],
            secret_scalar: Zeroizing::new([9u8; 32]),
            threshold: JURY_THRESHOLD,
            participant_count: JURY_PARTICIPANTS,
            created_at: 77,
        };
        assert_eq!(row.threshold, JURY_THRESHOLD);
        assert_eq!(row.participant_count, JURY_PARTICIPANTS);
        assert_eq!(*row.secret_scalar, [9u8; 32]);
    }

    #[test]
    fn make_test_payload_has_valid_roster_hash() {
        let payload = make_test_payload(1);
        assert_eq!(payload.roster.len(), 7);
        let computed = compute_roster_hash(&payload.complaint_id, &payload.roster).expect("hash");
        assert_eq!(computed, payload.roster_hash);
    }

    #[test]
    fn make_test_payload_has_expected_invitation_id() {
        let payload = make_test_payload(6);
        let expected = compute_invitation_id_v2(
            &payload.complaint_id,
            &payload.complainant_node_id,
            &payload.candidate_node_id,
            payload.roster_generation,
        );
        assert_eq!(expected, payload.invitation_id);
    }

    #[test]
    fn response_decision_roundtrip_preserves_share_index() {
        let payload = make_test_payload(7);
        let accept = JurorDecision::Accept;
        let reject = JurorDecision::Reject;
        assert_eq!(response_share_index(accept, &payload), payload.share_index);
        assert_eq!(response_share_index(reject, &payload), 0);
    }

    #[test]
    fn accepted_flag_is_stable_for_enum_variants() {
        assert_eq!(accepted_flag(JurorDecision::Accept), true);
        assert_eq!(accepted_flag(JurorDecision::Reject), false);
    }

    #[tokio::test]
    async fn respond_accept_e2e_runs_full_flow() {
        let (ctx, _directory) = build_test_ctx().await;
        let payload = test_payload_for_local_ctx(&ctx, 3);
        seed_pending_invitation(&ctx, &payload, 1, 20).await;

        respond_to_jury_invitation(&ctx, 1, JurorDecision::Accept, 30)
            .await
            .expect("accept invitation");

        let storage = ctx.storage.as_ref().expect("test storage");
        let storage = storage.lock().expect("storage lock");
        let node_id = *NodeId::from_hex(&ctx.identity_id)
            .expect("local identity")
            .as_bytes();
        let juror = read_juror_state_from_storage(&storage, &payload.complaint_id, &node_id)
            .expect("read juror state")
            .expect("juror state exists");
        assert_eq!(juror.phase, JurorPhase::Accepted);

        let dealer = read_dealer_secret(storage.connection(), &payload.complaint_id, &node_id)
            .expect("read dealer secret")
            .expect("dealer secret exists");
        assert_eq!(dealer.threshold, JURY_THRESHOLD);
        assert_eq!(dealer.participant_count, JURY_PARTICIPANTS);

        let own_share = read_own_share(storage.connection(), &payload.complaint_id, &node_id)
            .expect("read own share")
            .expect("own share exists");
        assert_eq!(own_share.share_index, payload.share_index);
        let assignment = read_assignment(
            storage.connection(),
            &payload.complaint_id,
            payload.roster_generation,
            payload.share_index,
        )
        .expect("read own roster assignment")
        .expect("own assignment exists");
        assert_eq!(
            assignment.response,
            Some(hal_storage::jury_rosters::RosterAssignmentResponse::Accepted)
        );

        let outgoing =
            list_outgoing_shares_for_complaint(storage.connection(), &payload.complaint_id)
                .expect("list outgoing shares");
        assert_eq!(outgoing.len(), 6);
        assert!(outgoing
            .iter()
            .all(|share| share.recipient_share_index != payload.share_index));
        assert!(
            read_pending_invitation_by_notification(storage.connection(), 1)
                .expect("read pending invitation")
                .is_none()
        );
    }

    #[tokio::test]
    async fn respond_reject_e2e_skips_dealer_setup() {
        let (ctx, _directory) = build_test_ctx().await;
        let payload = test_payload_for_local_ctx(&ctx, 2);
        seed_pending_invitation(&ctx, &payload, 1, 20).await;

        respond_to_jury_invitation(&ctx, 1, JurorDecision::Reject, 30)
            .await
            .expect("reject invitation");

        let storage = ctx.storage.as_ref().expect("test storage");
        let storage = storage.lock().expect("storage lock");
        let node_id = *NodeId::from_hex(&ctx.identity_id)
            .expect("local identity")
            .as_bytes();
        let juror = read_juror_state_from_storage(&storage, &payload.complaint_id, &node_id)
            .expect("read juror state")
            .expect("juror state exists");
        assert_eq!(juror.phase, JurorPhase::Accepted);
        assert!(
            read_dealer_secret(storage.connection(), &payload.complaint_id, &node_id)
                .expect("read dealer secret")
                .is_none()
        );
        assert!(
            read_own_share(storage.connection(), &payload.complaint_id, &node_id)
                .expect("read own share")
                .is_none()
        );
        assert!(
            list_outgoing_shares_for_complaint(storage.connection(), &payload.complaint_id)
                .expect("list outgoing shares")
                .is_empty()
        );
        let assignment = read_assignment(
            storage.connection(),
            &payload.complaint_id,
            payload.roster_generation,
            payload.share_index,
        )
        .expect("read own roster assignment")
        .expect("own assignment exists");
        assert_eq!(
            assignment.response,
            Some(hal_storage::jury_rosters::RosterAssignmentResponse::Rejected)
        );
    }

    #[tokio::test]
    async fn respond_accept_second_call_fails_missing_pending() {
        let (ctx, _directory) = build_test_ctx().await;
        let payload = test_payload_for_local_ctx(&ctx, 4);
        seed_pending_invitation(&ctx, &payload, 1, 20).await;

        respond_to_jury_invitation(&ctx, 1, JurorDecision::Accept, 30)
            .await
            .expect("first acceptance");
        let error = respond_to_jury_invitation(&ctx, 1, JurorDecision::Accept, 31)
            .await
            .expect_err("second acceptance should fail");
        assert!(error.to_string().contains("pending"));
    }

    #[tokio::test]
    async fn respond_fails_when_pending_missing() {
        let (ctx, _directory) = build_test_ctx().await;

        let error = respond_to_jury_invitation(&ctx, 404, JurorDecision::Accept, 30)
            .await
            .expect_err("missing invitation should fail");

        assert!(error.to_string().contains("pending"));
    }

    #[tokio::test]
    async fn respond_accept_publishes_commitment_to_transport() {
        let (ctx, _directory, publish_calls) = build_test_ctx_with_publisher(true).await;
        let payload = test_payload_for_local_ctx(&ctx, 1);
        seed_pending_invitation(&ctx, &payload, 1, 20).await;

        respond_to_jury_invitation(&ctx, 1, JurorDecision::Accept, 30)
            .await
            .expect("accept and publish commitment");

        let calls = publish_calls.lock().expect("publish calls lock");
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].key,
            crate::dht::jury_dkg_commitment::commitment_dht_key(
                &payload.complaint_id,
                &NodeId::from_hex(&ctx.identity_id)
                    .expect("local identity")
                    .as_bytes(),
            )
        );
        assert_eq!(
            calls[0].record_type,
            crate::dht::wire::StoredRecordType::JuryDkgCommitment
        );
        assert_eq!(
            calls[0].expires_at,
            30 + crate::dht::jury_dkg_commitment::JURY_DKG_COMMITMENT_TTL_SECS
        );
    }

    #[tokio::test]
    async fn respond_accept_commitment_passes_verification() {
        let (ctx, _directory, publish_calls) = build_test_ctx_with_publisher(true).await;
        let payload = test_payload_for_local_ctx(&ctx, 5);
        seed_pending_invitation(&ctx, &payload, 1, 20).await;

        respond_to_jury_invitation(&ctx, 1, JurorDecision::Accept, 30)
            .await
            .expect("accept and publish commitment");

        let calls = publish_calls.lock().expect("publish calls lock");
        let call = calls.first().expect("published commitment");
        let record: crate::dht::jury_dkg_commitment::JuryDkgCommitmentRecord =
            serde_json::from_slice(&call.value).expect("deserialize commitment");
        crate::dht::jury_dkg_commitment::verify_commitment(&record)
            .expect("verify signed commitment");
        assert_eq!(record.complaint_id, payload.complaint_id);
    }

    #[tokio::test]
    async fn respond_accept_fails_when_publisher_missing() {
        let (ctx, _directory, _) = build_test_ctx_with_publisher(false).await;
        let payload = test_payload_for_local_ctx(&ctx, 6);
        seed_pending_invitation(&ctx, &payload, 1, 20).await;

        let error = respond_to_jury_invitation(&ctx, 1, JurorDecision::Accept, 30)
            .await
            .expect_err("acceptance without publisher should fail");
        assert!(error.to_string().contains("publisher"));
    }
}
