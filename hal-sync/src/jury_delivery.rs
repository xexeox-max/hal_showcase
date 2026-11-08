//! Handlers for jury invitation and DKG share delivery events.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::VerifyingKey;
use hal_storage::jury_delivery_inbox::{
    try_insert_delivery_for_storage, DeliveryKind, DeliveryRecord,
};
use sha2::{Digest, Sha256};

use crate::dht::jury_acceptance::{verify_acceptance, ACCEPTANCE_TTL_SECS};
use crate::dht::notifier::{NotificationKind, NOTIFICATION_DEFAULT_TTL_SECS};
use crate::dht::NodeId;
use crate::journal::{
    compute_invitation_id_v2, JuryInvitationPayload, JuryInvitationResponsePayload,
    JuryShareAckPayload, JuryShareDeliveryPayload, SyncEvent, SyncEventType,
};
use crate::runtime_context::RuntimeContext;
use hal_storage::jury_rosters::{
    insert_roster, insert_roster_assignment, read_assignment, read_roster, RosterAssignmentRow,
    RosterRow,
};

pub const JURY_DELIVERY_TTL_SECS: u64 = 30 * 24 * 3600;

fn remove_matching_outbox(
    storage: &hal_storage::ClientStorage,
    message_id: &[u8; 32],
    kind: hal_storage::jury_outbox::OutboxKind,
    complaint_id: &[u8; 32],
    recipient_node_id: &[u8; 32],
) -> Result<bool> {
    let Some(entry) =
        hal_storage::jury_outbox::read_outbox_entry(storage.connection(), message_id)?
    else {
        return Ok(false);
    };
    if entry.kind != kind
        || entry.complaint_id != *complaint_id
        || entry.recipient_node_id != *recipient_node_id
    {
        return Ok(false);
    }
    hal_storage::jury_outbox::remove_outbox(storage.connection(), message_id)
}

pub async fn handle_jury_invitation(
    ctx: &Arc<RuntimeContext>,
    event: &SyncEvent,
    sender_node_id: &[u8; 32],
    now: u64,
) -> Result<()> {
    let payload: JuryInvitationPayload =
        serde_json::from_str(&event.data).context("parse JuryInvitation payload")?;
    if payload.complainant_node_id != *sender_node_id {
        return Err(anyhow!("jury invitation sender does not match complainant"));
    }
    payload
        .verify()
        .map_err(|error| anyhow!("jury invitation payload invalid: {error}"))?;
    if payload.issued_at > now || payload.response_deadline < now {
        return Err(anyhow!("jury invitation is not currently valid"));
    }

    let local_node_id =
        NodeId::from_hex(&ctx.identity_id).context("parse local identity for jury invitation")?;
    if payload.candidate_node_id != *local_node_id.as_bytes() {
        return Ok(());
    }

    let storage_arc = ctx
        .storage
        .as_ref()
        .context("storage required for jury delivery")?;
    {
        let storage = storage_arc
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        persist_received_roster(&storage, &payload, now)?;
    }
    let inserted = {
        let mut storage = storage_arc
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        try_insert_delivery_for_storage(
            &mut storage,
            &DeliveryRecord {
                message_id: payload.invitation_id,
                kind: DeliveryKind::Invitation,
                complaint_id: payload.complaint_id,
                from_node_id: payload.complainant_node_id,
                payload_blob: event.data.as_bytes().to_vec(),
                received_at: now,
            },
            now.saturating_add(JURY_DELIVERY_TTL_SECS),
        )?
    };
    if !inserted {
        return Ok(());
    }

    fn persist_received_roster(
        storage: &hal_storage::ClientStorage,
        payload: &JuryInvitationPayload,
        now: u64,
    ) -> Result<()> {
        let connection = storage.connection();
        let roster_blob = serde_json::to_vec(&payload.roster).context("serialize jury roster")?;
        match read_roster(connection, &payload.complaint_id, payload.roster_generation)? {
            Some(existing)
                if existing.roster_hash == payload.roster_hash
                    && existing.roster_blob == roster_blob => {}
            Some(_) => return Err(anyhow!("received jury roster conflicts with stored roster")),
            None => insert_roster(
                connection,
                &RosterRow {
                    complaint_id: payload.complaint_id,
                    roster_generation: payload.roster_generation,
                    roster_hash: payload.roster_hash,
                    roster_blob,
                    created_at: now,
                },
            )?,
        }

        for entry in &payload.roster {
            let invitation_id = compute_invitation_id_v2(
                &payload.complaint_id,
                &payload.complainant_node_id,
                &entry.node_id,
                payload.roster_generation,
            );
            match read_assignment(
                connection,
                &payload.complaint_id,
                payload.roster_generation,
                entry.share_index,
            )? {
                Some(existing)
                    if existing.candidate_node_id == entry.node_id
                        && existing.invitation_id == invitation_id
                        && existing.invited_at == payload.issued_at => {}
                Some(_) => {
                    return Err(anyhow!(
                        "received jury roster assignment conflicts with stored assignment"
                    ))
                }
                None => insert_roster_assignment(
                    connection,
                    &RosterAssignmentRow {
                        complaint_id: payload.complaint_id,
                        roster_generation: payload.roster_generation,
                        share_index: entry.share_index,
                        candidate_node_id: entry.node_id,
                        invitation_id,
                        invited_at: payload.issued_at,
                        response: None,
                    },
                )?,
            }
        }
        Ok(())
    }

    let ttl = payload
        .response_deadline
        .saturating_sub(now)
        .min(NOTIFICATION_DEFAULT_TTL_SECS);
    let notification_id = ctx.home_state.lock().await.notifications.create(
        NotificationKind::JuryOptInRequest,
        NodeId::from_bytes(payload.complainant_node_id),
        // The existing notifier has no opaque payload field; use subject to key the complaint.
        NodeId::from_bytes(payload.complaint_id),
        None,
        now,
        ttl,
    );
    {
        let storage = storage_arc
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        hal_storage::jury_invitations::insert_pending_invitation(
            storage.connection(),
            &hal_storage::jury_invitations::PendingJuryInvitationRow {
                notification_id,
                invitation_id: payload.invitation_id,
                complaint_id: payload.complaint_id,
                complainant_node_id: payload.complainant_node_id,
                candidate_node_id: payload.candidate_node_id,
                share_index: payload.share_index,
                roster_generation: payload.roster_generation,
                received_at: now,
                expires_at: now.saturating_add(ttl),
                payload_blob: event.data.as_bytes().to_vec(),
            },
        )?;
    }
    log::debug!(
        "jury invitation received: complaint={} share_index={} generation={}",
        hex::encode(payload.complaint_id),
        payload.share_index,
        payload.roster_generation,
    );
    Ok(())
}

pub async fn handle_jury_invitation_response(
    ctx: &Arc<RuntimeContext>,
    event: &SyncEvent,
    sender_node_id: &[u8; 32],
    now: u64,
) -> Result<()> {
    let payload: JuryInvitationResponsePayload =
        serde_json::from_str(&event.data).context("parse JuryInvitationResponse payload")?;
    if payload.candidate_node_id != *sender_node_id {
        return Err(anyhow!(
            "jury invitation response sender does not match candidate"
        ));
    }
    if payload.responded_at > now
        || (payload.accepted && !(1..=7).contains(&payload.share_index))
        || (!payload.accepted && payload.share_index != 0)
    {
        return Err(anyhow!("jury invitation response fields are invalid"));
    }

    if payload.accepted {
        let acceptance = payload
            .acceptance
            .as_ref()
            .context("accepted response must carry signed acceptance")?;
        verify_acceptance(acceptance)
            .map_err(|error| anyhow!("invalid acceptance in response: {error}"))?;
        if acceptance.complaint_id != payload.complaint_id
            || acceptance.juror_node_id != payload.candidate_node_id
            || acceptance.share_index != payload.share_index
            || acceptance.accepted_at > payload.responded_at
        {
            return Err(anyhow!(
                "acceptance fields do not match invitation response"
            ));
        }
    } else if payload.acceptance.is_some() {
        return Err(anyhow!("rejected response must not carry acceptance"));
    }

    let storage_arc = ctx
        .storage
        .as_ref()
        .context("storage required for jury delivery")?;
    let mut storage = storage_arc
        .lock()
        .map_err(|_| anyhow!("storage lock poisoned"))?;
    let local_id = local_node_id(ctx)?;
    let complainant =
        hal_storage::complaints::read_complaint_for_storage(&storage, &payload.complaint_id)?
            .context("jury invitation response references an unknown complaint")?;
    if complainant.complainant_node_id != local_id {
        return Err(anyhow!(
            "jury invitation response is not for the local complainant"
        ));
    }

    let response_event_blob = event.data.as_bytes();
    let matching_invitation =
        hal_storage::jury_outbox::read_outbox_entry(&storage.connection(), &payload.invitation_id)?;
    if let Some(entry) = matching_invitation {
        if entry.kind != hal_storage::jury_outbox::OutboxKind::Invitation
            || entry.complaint_id != payload.complaint_id
            || entry.recipient_node_id != payload.candidate_node_id
        {
            return Err(anyhow!(
                "jury invitation response does not match the outbox invitation"
            ));
        }
        let invitation_event: SyncEvent = serde_json::from_slice(&entry.event_blob)
            .context("parse invitation event from outbox")?;
        if invitation_event.event_type != SyncEventType::JuryInvitation {
            return Err(anyhow!("jury outbox entry is not an invitation event"));
        }
        let invitation: JuryInvitationPayload = serde_json::from_str(&invitation_event.data)
            .context("parse invitation payload from outbox")?;
        invitation
            .verify()
            .map_err(|error| anyhow!("outbox invitation payload invalid: {error}"))?;
        if invitation.invitation_id != payload.invitation_id
            || invitation.complaint_id != payload.complaint_id
            || invitation.complainant_node_id != local_id
            || invitation.candidate_node_id != payload.candidate_node_id
            || invitation.roster_hash != payload.roster_hash
            || (payload.accepted && invitation.share_index != payload.share_index)
            || payload.responded_at < invitation.issued_at
            || payload.responded_at > invitation.response_deadline
        {
            return Err(anyhow!(
                "jury invitation response does not match the issued invitation"
            ));
        }
    } else {
        match hal_storage::jury_delivery_inbox::read_delivery(
            &storage.connection(),
            &payload.invitation_id,
        )? {
            Some(existing)
                if existing.kind == DeliveryKind::InvitationResponse
                    && existing.complaint_id == payload.complaint_id
                    && existing.from_node_id == payload.candidate_node_id
                    && existing.payload_blob == response_event_blob => {}
            Some(_) => {
                return Err(anyhow!(
                    "jury invitation response ID conflicts with an existing inbox record"
                ));
            }
            None => return Ok(()),
        }
    }

    if payload.accepted {
        let acceptance = payload
            .acceptance
            .as_ref()
            .context("accepted response must carry signed acceptance")?;
        let row = hal_storage::jury_acceptances::JuryAcceptanceRow {
            complaint_id: acceptance.complaint_id,
            juror_node_id: acceptance.juror_node_id,
            juror_public_key: acceptance.juror_public_key,
            share_index: acceptance.share_index,
            accepted_at: acceptance.accepted_at,
            record_blob: serde_json::to_vec(acceptance)
                .context("serialize acceptance for storage")?,
        };
        hal_storage::jury_acceptances::insert_jury_acceptance(
            &storage.connection(),
            &row,
            acceptance.accepted_at.saturating_add(ACCEPTANCE_TTL_SECS),
        )
        .map_err(|error| {
            log::warn!(
                "acceptance insert failed for complaint {}: {error}",
                hex::encode(payload.complaint_id)
            );
            anyhow!("acceptance storage conflict: {error}")
        })?;
    }

    let inserted = try_insert_delivery_for_storage(
        &mut storage,
        &DeliveryRecord {
            message_id: payload.invitation_id,
            kind: DeliveryKind::InvitationResponse,
            complaint_id: payload.complaint_id,
            from_node_id: payload.candidate_node_id,
            payload_blob: response_event_blob.to_vec(),
            received_at: now,
        },
        now.saturating_add(JURY_DELIVERY_TTL_SECS),
    )?;
    if inserted && payload.accepted {
        log::debug!(
            "jury invitation accepted: complaint={} candidate={} share_index={}",
            hex::encode(payload.complaint_id),
            hex::encode(payload.candidate_node_id),
            payload.share_index,
        );
    }
    let removed = remove_matching_outbox(
        &storage,
        &payload.invitation_id,
        hal_storage::jury_outbox::OutboxKind::Invitation,
        &payload.complaint_id,
        &payload.candidate_node_id,
    )?;
    if removed {
        log::debug!(
            "jury invitation {} removed from outbox after response",
            hex::encode(payload.invitation_id)
        );
    }
    Ok(())
}

pub async fn handle_jury_share_delivery(
    ctx: &Arc<RuntimeContext>,
    event: &SyncEvent,
    sender_node_id: &[u8; 32],
    now: u64,
) -> Result<()> {
    let payload: JuryShareDeliveryPayload =
        serde_json::from_str(&event.data).context("parse JuryShareDelivery payload")?;
    if payload.dealer_node_id != *sender_node_id {
        return Err(anyhow!("jury share sender does not match dealer"));
    }
    let dealer_key = VerifyingKey::from_bytes(&payload.dealer_public_key)
        .context("parse jury share dealer public key")?;
    if NodeId::from_public_key(&dealer_key).as_bytes() != sender_node_id {
        return Err(anyhow!(
            "jury share dealer public key does not match envelope identity"
        ));
    }
    if !(1..=7).contains(&payload.dealer_share_index)
        || !(1..=7).contains(&payload.recipient_share_index)
        || payload.issued_at > now
    {
        return Err(anyhow!("jury share delivery fields are invalid"));
    }
    let local_id = local_node_id(ctx)?;
    if local_id == *sender_node_id {
        return Err(anyhow!("jury share delivery cannot be self-addressed"));
    }

    let storage_arc = ctx
        .storage
        .as_ref()
        .context("storage required for jury delivery")?;
    let mut storage = storage_arc
        .lock()
        .map_err(|_| anyhow!("storage lock poisoned"))?;
    let acceptance = hal_storage::jury_acceptances::read_jury_acceptance_for_storage(
        &storage,
        &payload.complaint_id,
        &local_id,
    )?
    .context("jury share delivery is for a non-accepted juror")?;
    if acceptance.share_index != payload.recipient_share_index {
        return Err(anyhow!(
            "jury share delivery recipient index does not match local acceptance"
        ));
    }

    let commitment_row = hal_storage::jury_commitments::read_jury_commitment(
        storage.connection(),
        &payload.complaint_id,
        &payload.dealer_node_id,
    )?;
    let share_valid = match commitment_row {
        Some(commitment_row) => {
            if commitment_row.dealer_public_key != payload.dealer_public_key {
                log::warn!(
                    "jury share rejected: dealer public key mismatch for complaint {}",
                    hex::encode(payload.complaint_id)
                );
                false
            } else {
                let commitments = hal_crypto::vss::FeldmanCommitments {
                    commitments: commitment_row
                        .commitments
                        .iter()
                        .map(|bytes| curve25519_dalek::ristretto::CompressedRistretto(*bytes))
                        .collect(),
                    threshold: commitment_row.threshold,
                    participant_count: commitment_row.participant_count,
                };
                let maybe_scalar: Option<curve25519_dalek::scalar::Scalar> = Option::from(
                    curve25519_dalek::scalar::Scalar::from_canonical_bytes(payload.share_value),
                );
                if let Some(scalar) = maybe_scalar {
                    let share = hal_crypto::vss::Share {
                        index: payload.recipient_share_index,
                        value: zeroize::Zeroizing::new(scalar),
                        threshold: commitment_row.threshold,
                        participant_count: commitment_row.participant_count,
                    };
                    match hal_crypto::vss::verify_share(&commitments, &share) {
                        Ok(()) => {
                            let row = hal_storage::jury_dkg_storage::ReceivedShareRow {
                                complaint_id: payload.complaint_id,
                                dealer_node_id: payload.dealer_node_id,
                                dealer_public_key: payload.dealer_public_key,
                                dealer_share_index: payload.dealer_share_index,
                                recipient_share_index: payload.recipient_share_index,
                                share_value: zeroize::Zeroizing::new(payload.share_value),
                                received_at: now,
                                verified: false,
                                message_id: payload.message_id,
                            };
                            hal_storage::jury_dkg_storage::upsert_received_share(
                                storage.connection(),
                                &row,
                            )?;
                            hal_storage::jury_dkg_storage::mark_received_share_verified(
                                storage.connection(),
                                &payload.complaint_id,
                                &payload.dealer_node_id,
                            )?;
                            true
                        }
                        Err(error) => {
                            log::warn!(
                                "jury share rejected: invalid Feldman share for complaint {}: {error}",
                                hex::encode(payload.complaint_id)
                            );
                            false
                        }
                    }
                } else {
                    log::warn!(
                        "jury share rejected: invalid scalar encoding for complaint {}",
                        hex::encode(payload.complaint_id)
                    );
                    false
                }
            }
        }
        None => {
            log::debug!(
                "jury share rejected: no commitment for complaint {} dealer {}",
                hex::encode(payload.complaint_id),
                hex::encode(payload.dealer_node_id)
            );
            false
        }
    };

    let inserted = try_insert_delivery_for_storage(
        &mut storage,
        &DeliveryRecord {
            message_id: payload.message_id,
            kind: DeliveryKind::ShareDelivery,
            complaint_id: payload.complaint_id,
            from_node_id: payload.dealer_node_id,
            payload_blob: event.data.as_bytes().to_vec(),
            received_at: now,
        },
        now.saturating_add(JURY_DELIVERY_TTL_SECS),
    )?;
    drop(storage);
    if inserted {
        log::debug!(
            "jury share received: complaint={} dealer={} recipient_index={}",
            hex::encode(payload.complaint_id),
            hex::encode(payload.dealer_node_id),
            payload.recipient_share_index,
        );
    }
    let mut ack_hasher = Sha256::new();
    ack_hasher.update(b"HAL-JURY-ACK-v1\0");
    ack_hasher.update(payload.message_id);
    let ack_message_id: [u8; 32] = ack_hasher.finalize().into();
    let ack_payload = crate::journal::JuryShareAckPayload {
        message_id: ack_message_id,
        shared_message_id: payload.message_id,
        complaint_id: payload.complaint_id,
        dealer_node_id: payload.dealer_node_id,
        recipient_node_id: local_id,
        share_valid: share_valid,
        acked_at: now,
    };
    let ack_event = SyncEvent::jury_share_ack(&ack_payload)?;
    crate::jury_delivery_outbox::enqueue_share_ack(
        ctx,
        ack_event,
        payload.complaint_id,
        payload.dealer_node_id,
        ack_message_id,
        now,
    )?;
    Ok(())
}

pub async fn handle_jury_share_ack(
    ctx: &Arc<RuntimeContext>,
    event: &SyncEvent,
    sender_node_id: &[u8; 32],
    now: u64,
) -> Result<()> {
    let payload: JuryShareAckPayload =
        serde_json::from_str(&event.data).context("parse JuryShareAck payload")?;
    if payload.recipient_node_id != *sender_node_id
        || payload.dealer_node_id != local_node_id(ctx)?
        || payload.acked_at > now
    {
        return Err(anyhow!("jury share ACK sender or fields are invalid"));
    }

    let storage_arc = ctx
        .storage
        .as_ref()
        .context("storage required for jury delivery")?;
    let mut storage = storage_arc
        .lock()
        .map_err(|_| anyhow!("storage lock poisoned"))?;
    let inserted = try_insert_delivery_for_storage(
        &mut storage,
        &DeliveryRecord {
            message_id: payload.message_id,
            kind: DeliveryKind::ShareAck,
            complaint_id: payload.complaint_id,
            from_node_id: payload.recipient_node_id,
            payload_blob: event.data.as_bytes().to_vec(),
            received_at: now,
        },
        now.saturating_add(JURY_DELIVERY_TTL_SECS),
    )?;
    let removed = if payload.share_valid {
        remove_matching_outbox(
            &storage,
            &payload.shared_message_id,
            hal_storage::jury_outbox::OutboxKind::ShareDelivery,
            &payload.complaint_id,
            &payload.recipient_node_id,
        )?
    } else {
        false
    };
    if inserted {
        log::debug!(
            "jury share ack received: complaint={} dealer={} share_valid={}",
            hex::encode(payload.complaint_id),
            hex::encode(payload.dealer_node_id),
            payload.share_valid,
        );
    }
    if removed {
        log::debug!(
            "jury share delivery {} removed from outbox after valid ACK",
            hex::encode(payload.shared_message_id)
        );
    }
    Ok(())
}

fn local_node_id(ctx: &RuntimeContext) -> Result<[u8; 32]> {
    Ok(*NodeId::from_hex(&ctx.identity_id)
        .context("parse local identity for jury delivery")?
        .as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::group::{GroupGraph, GroupRegistry};
    use crate::dht::jury_acceptance::sign_acceptance;
    use crate::dht::trust_oracle::BasicTrustOracle;
    use crate::journal::{
        compute_invitation_id_v2, compute_roster_hash, JuryInvitationPayload,
        JuryInvitationResponsePayload, JuryShareAckPayload, JuryShareDeliveryPayload, RosterEntry,
        SyncEventType,
    };
    use crate::runtime::HomeRuntimeState;
    use crate::runtime_context::{NoopBiometricGate, RuntimeContext};
    use curve25519_dalek::scalar::Scalar;
    use ed25519_dalek::SigningKey;
    use hal_storage::complaints::ComplaintRow;
    use hal_storage::jury_acceptances::{persist_jury_acceptance, JuryAcceptanceRow};
    use hal_storage::jury_commitments::{persist_jury_commitment, JuryCommitmentRecord};
    use hal_storage::jury_rosters::{
        list_assignments_for_generation, read_latest_roster, record_assignment_response,
        RosterAssignmentResponse,
    };
    use hal_storage::ClientStorage;
    use rand::rngs::OsRng;
    use std::sync::{Arc, Mutex};
    use tokio::sync::Mutex as TokioMutex;

    fn test_context(local_key: &SigningKey) -> (Arc<RuntimeContext>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let database_path = dir.path().join("jury-delivery.db");
        let storage = Arc::new(Mutex::new(
            ClientStorage::open(database_path, &[7; 32]).expect("open storage"),
        ));
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
        let invite_registry = RuntimeContext::default_invite_registry();
        let ctx = Arc::new(RuntimeContext {
            sync: Arc::new(TokioMutex::new(crate::SyncManager::new(
                "jury-delivery".into(),
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
            identity_id: NodeId::from_public_key(&local_key.verifying_key()).to_hex(),
            public_key: hex::encode(local_key.verifying_key().to_bytes()),
            identity_signing_key: Some(Arc::new(local_key.clone())),
            jury_commitment_publisher: None,
            jury_plaintext_cache: RuntimeContext::default_jury_plaintext_cache(),
            invite_redemption_transport: None,
            pending_invite_redemptions: RuntimeContext::default_pending_invite_redemptions(),
            sas_pairing: RuntimeContext::default_sas_pairing(),
            integrity: None,
        });
        (ctx, dir)
    }

    fn setup_commitment_and_share(
        ctx: &Arc<RuntimeContext>,
        dealer_key: &SigningKey,
        complaint_id: [u8; 32],
        recipient_share_index: u32,
        now: u64,
    ) -> (
        crate::dht::jury_dkg_commitment::JuryDkgCommitmentRecord,
        [u8; 32],
    ) {
        let mut rng = OsRng;
        let secret = Scalar::from(23u64);
        let split =
            hal_crypto::vss::feldman_split(&mut rng, &secret, 5, 7).expect("split dealer secret");
        let commitment_bytes = split
            .commitments
            .commitments
            .iter()
            .map(|commitment| commitment.to_bytes())
            .collect();
        let record = crate::dht::jury_dkg_commitment::sign_commitment(
            dealer_key,
            complaint_id,
            commitment_bytes,
            now,
        )
        .expect("sign dealer commitment");
        let storage_record = JuryCommitmentRecord {
            complaint_id: record.complaint_id,
            dealer_node_id: record.dealer_node_id,
            dealer_public_key: record.dealer_public_key,
            commitments: record.commitments.clone(),
            threshold: record.threshold,
            participant_count: record.participant_count,
            published_at: record.published_at,
            signature: record.signature,
            expires_at: now
                .saturating_add(crate::dht::jury_dkg_commitment::JURY_DKG_COMMITMENT_TTL_SECS),
        };
        let storage = ctx.storage.as_ref().expect("test storage");
        persist_jury_commitment(&mut storage.lock().expect("storage lock"), &storage_record)
            .expect("persist dealer commitment");
        let share = split
            .shares
            .iter()
            .find(|share| share.index == recipient_share_index)
            .expect("recipient share");
        (record, share.value.to_bytes())
    }

    fn store_share_acceptance(
        ctx: &Arc<RuntimeContext>,
        local_key: &SigningKey,
        complaint_id: [u8; 32],
        share_index: u32,
    ) {
        let local_id = *NodeId::from_public_key(&local_key.verifying_key()).as_bytes();
        let storage = ctx.storage.as_ref().expect("test storage");
        persist_jury_acceptance(
            &mut storage.lock().expect("storage lock"),
            &JuryAcceptanceRow {
                complaint_id,
                juror_node_id: local_id,
                juror_public_key: local_key.verifying_key().to_bytes(),
                share_index,
                accepted_at: 1,
                record_blob: vec![1],
            },
            1000,
        )
        .expect("store acceptance");
    }

    fn read_share_ack(
        ctx: &Arc<RuntimeContext>,
        payload: &JuryShareDeliveryPayload,
    ) -> JuryShareAckPayload {
        let mut hasher = Sha256::new();
        hasher.update(b"HAL-JURY-ACK-v1\0");
        hasher.update(payload.message_id);
        let ack_message_id: [u8; 32] = hasher.finalize().into();
        let storage = ctx.storage.as_ref().expect("test storage");
        let storage = storage.lock().expect("storage lock");
        let entry =
            hal_storage::jury_outbox::read_outbox_entry(storage.connection(), &ack_message_id)
                .expect("read ACK outbox")
                .expect("ACK queued");
        assert_eq!(entry.kind, hal_storage::jury_outbox::OutboxKind::ShareAck);
        let event: SyncEvent = serde_json::from_slice(&entry.event_blob).expect("decode ACK event");
        serde_json::from_str(&event.data).expect("decode ACK payload")
    }

    fn invitation(
        complaint_id: [u8; 32],
        complainant_node_id: [u8; 32],
        candidate_node_id: [u8; 32],
    ) -> JuryInvitationPayload {
        let mut roster: Vec<_> = (1..=7u32)
            .map(|share_index| RosterEntry {
                share_index,
                node_id: [share_index as u8; 32],
            })
            .collect();
        if !roster
            .iter()
            .any(|entry| entry.node_id == candidate_node_id)
        {
            roster[0].node_id = candidate_node_id;
        }
        let roster_hash = compute_roster_hash(&complaint_id, &roster).expect("roster hash");
        let roster_generation = 0;
        JuryInvitationPayload {
            complaint_id,
            complainant_node_id,
            candidate_node_id,
            share_index: roster
                .iter()
                .find(|entry| entry.node_id == candidate_node_id)
                .expect("candidate in roster")
                .share_index,
            roster,
            roster_hash,
            roster_generation,
            invitation_id: compute_invitation_id_v2(
                &complaint_id,
                &complainant_node_id,
                &candidate_node_id,
                roster_generation,
            ),
            issued_at: 1,
            response_deadline: 100,
        }
    }

    fn invitation_response(
        candidate_key: &SigningKey,
        invitation_id: [u8; 32],
        complaint_id: [u8; 32],
        share_index: u32,
        responded_at: u64,
    ) -> JuryInvitationResponsePayload {
        let candidate_node_id = *NodeId::from_public_key(&candidate_key.verifying_key()).as_bytes();
        let acceptance = sign_acceptance(candidate_key, complaint_id, share_index, responded_at)
            .expect("sign acceptance");
        let roster_hash = invitation(complaint_id, [0; 32], candidate_node_id).roster_hash;
        JuryInvitationResponsePayload {
            invitation_id,
            complaint_id,
            candidate_node_id,
            accepted: true,
            share_index,
            roster_hash,
            acceptance: Some(acceptance),
            responded_at,
        }
    }

    fn store_complaint(ctx: &RuntimeContext, complaint_id: [u8; 32], complainant: [u8; 32]) {
        let storage = ctx.storage.as_ref().expect("test storage");
        hal_storage::complaints::insert_complaint_for_storage(
            &mut storage.lock().expect("storage lock"),
            &ComplaintRow {
                complaint_id,
                complainant_node_id: complainant,
                subject_node_id: [9; 32],
                kind_tag: 1,
                period_start: 1,
                period_end: 2,
                submitted_at: 1,
                record_blob: vec![1],
            },
            1000,
        )
        .expect("store complaint");
    }

    fn store_outbox_entry(
        ctx: &RuntimeContext,
        kind: hal_storage::jury_outbox::OutboxKind,
        message_id: [u8; 32],
        complaint_id: [u8; 32],
        recipient_node_id: [u8; 32],
    ) {
        let storage = ctx.storage.as_ref().expect("test storage");
        let (event_blob, event_id) = if kind == hal_storage::jury_outbox::OutboxKind::Invitation {
            let complainant_node_id = local_node_id(ctx).expect("local node ID");
            let payload = invitation(complaint_id, complainant_node_id, recipient_node_id);
            assert_eq!(payload.invitation_id, message_id);
            let event = SyncEvent::jury_invitation(&payload).expect("create invitation event");
            (
                serde_json::to_vec(&event).expect("serialize invitation event"),
                event.id,
            )
        } else {
            (b"event".to_vec(), "event-1".to_string())
        };
        hal_storage::jury_outbox::enqueue_outbox(
            storage.lock().expect("storage lock").connection(),
            &hal_storage::jury_outbox::OutboxEntry {
                message_id,
                kind,
                complaint_id,
                recipient_node_id,
                event_blob,
                event_id,
                created_at: 1,
                next_attempt_at: 2,
                attempts: 0,
                deadline: 1000,
                last_error: None,
            },
        )
        .expect("store outbox entry");
    }

    #[test]
    fn event_helpers_use_the_jury_event_types() {
        let payload = JuryShareDeliveryPayload {
            message_id: [1; 32],
            complaint_id: [2; 32],
            dealer_node_id: [3; 32],
            dealer_public_key: [4; 32],
            dealer_share_index: 1,
            recipient_share_index: 2,
            share_value: [5; 32],
            issued_at: 10,
        };
        let event = SyncEvent::jury_share_delivery(&payload).expect("create event");
        assert_eq!(event.event_type, SyncEventType::JuryShareDelivery);
        assert_eq!(
            serde_json::from_str::<JuryShareDeliveryPayload>(&event.data).expect("decode"),
            payload
        );

        let response = JuryInvitationResponsePayload {
            invitation_id: [6; 32],
            complaint_id: [2; 32],
            candidate_node_id: [3; 32],
            accepted: true,
            share_index: 1,
            roster_hash: [0; 32],
            acceptance: None,
            responded_at: 10,
        };
        assert_eq!(
            SyncEvent::jury_invitation_response(&response)
                .expect("create response")
                .event_type,
            SyncEventType::JuryInvitationResponse
        );
        let ack = JuryShareAckPayload {
            message_id: [1; 32],
            shared_message_id: [7; 32],
            complaint_id: [2; 32],
            dealer_node_id: [3; 32],
            recipient_node_id: [4; 32],
            share_valid: true,
            acked_at: 10,
        };
        assert_eq!(
            SyncEvent::jury_share_ack(&ack)
                .expect("create ack")
                .event_type,
            SyncEventType::JuryShareAck
        );
    }

    #[tokio::test]
    async fn handle_invitation_for_other_candidate_noop() {
        let local_key = SigningKey::from_bytes(&[1; 32]);
        let sender_key = SigningKey::from_bytes(&[2; 32]);
        let (ctx, _dir) = test_context(&local_key);
        let sender_id = *NodeId::from_public_key(&sender_key.verifying_key()).as_bytes();
        let payload = invitation([3; 32], sender_id, [4; 32]);
        let event = SyncEvent::jury_invitation(&payload).expect("create event");
        handle_jury_invitation(&ctx, &event, &sender_id, 10)
            .await
            .expect("handle invitation");
        assert!(ctx
            .home_state
            .lock()
            .await
            .notifications
            .pending()
            .is_empty());
    }

    #[tokio::test]
    async fn handle_invitation_creates_notification() {
        let local_key = SigningKey::from_bytes(&[1; 32]);
        let sender_key = SigningKey::from_bytes(&[2; 32]);
        let (ctx, _dir) = test_context(&local_key);
        let sender_id = *NodeId::from_public_key(&sender_key.verifying_key()).as_bytes();
        let local_id = *NodeId::from_public_key(&local_key.verifying_key()).as_bytes();
        let payload = invitation([3; 32], sender_id, local_id);
        let event = SyncEvent::jury_invitation(&payload).expect("create event");
        handle_jury_invitation(&ctx, &event, &sender_id, 10)
            .await
            .expect("handle invitation");
        let home_state = ctx.home_state.lock().await;
        let pending = home_state.notifications.pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].kind, NotificationKind::JuryOptInRequest);
        assert_eq!(pending[0].from.as_bytes(), &sender_id);
        assert_eq!(pending[0].subject.as_bytes(), &[3; 32]);
    }

    #[tokio::test]
    async fn handle_invitation_persists_roster_and_all_assignments() {
        let local_key = SigningKey::from_bytes(&[1; 32]);
        let sender_key = SigningKey::from_bytes(&[2; 32]);
        let (ctx, _dir) = test_context(&local_key);
        let sender_id = *NodeId::from_public_key(&sender_key.verifying_key()).as_bytes();
        let local_id = *NodeId::from_public_key(&local_key.verifying_key()).as_bytes();
        let payload = invitation([3; 32], sender_id, local_id);
        let event = SyncEvent::jury_invitation(&payload).expect("create event");

        handle_jury_invitation(&ctx, &event, &sender_id, 10)
            .await
            .expect("handle invitation");

        let storage = ctx.storage.as_ref().expect("test storage");
        let storage = storage.lock().expect("storage lock");
        let roster = read_latest_roster(storage.connection(), &payload.complaint_id)
            .expect("read roster")
            .expect("roster exists");
        assert_eq!(roster.roster_generation, payload.roster_generation);
        assert_eq!(roster.roster_hash, payload.roster_hash);
        let assignments = list_assignments_for_generation(
            storage.connection(),
            &payload.complaint_id,
            payload.roster_generation,
        )
        .expect("list assignments");
        assert_eq!(assignments.len(), 7);
        for (assignment, entry) in assignments.iter().zip(&payload.roster) {
            assert_eq!(assignment.share_index, entry.share_index);
            assert_eq!(assignment.candidate_node_id, entry.node_id);
            assert_eq!(
                assignment.invitation_id,
                compute_invitation_id_v2(
                    &payload.complaint_id,
                    &payload.complainant_node_id,
                    &entry.node_id,
                    payload.roster_generation,
                )
            );
            assert_eq!(assignment.response, None);
        }
    }

    #[tokio::test]
    async fn handle_invitation_idempotent() {
        let local_key = SigningKey::from_bytes(&[1; 32]);
        let sender_key = SigningKey::from_bytes(&[2; 32]);
        let (ctx, _dir) = test_context(&local_key);
        let sender_id = *NodeId::from_public_key(&sender_key.verifying_key()).as_bytes();
        let local_id = *NodeId::from_public_key(&local_key.verifying_key()).as_bytes();
        let payload = invitation([3; 32], sender_id, local_id);
        let event = SyncEvent::jury_invitation(&payload).expect("create event");
        handle_jury_invitation(&ctx, &event, &sender_id, 10)
            .await
            .expect("first delivery");
        let storage = ctx.storage.as_ref().expect("test storage");
        assert!(record_assignment_response(
            &storage.lock().expect("storage lock").connection(),
            &payload.complaint_id,
            payload.roster_generation,
            &payload.invitation_id,
            RosterAssignmentResponse::Accepted,
            10,
        )
        .expect("record assignment response"));
        handle_jury_invitation(&ctx, &event, &sender_id, 11)
            .await
            .expect("duplicate delivery");
        assert_eq!(ctx.home_state.lock().await.notifications.pending().len(), 1);
        let assignments = list_assignments_for_generation(
            &storage.lock().expect("storage lock").connection(),
            &payload.complaint_id,
            payload.roster_generation,
        )
        .expect("list assignments");
        assert_eq!(
            assignments
                .iter()
                .find(|assignment| assignment.candidate_node_id == local_id)
                .and_then(|assignment| assignment.response),
            Some(RosterAssignmentResponse::Accepted)
        );
    }

    #[tokio::test]
    async fn handle_invitation_rejects_invalid_roster_hash() {
        let local_key = SigningKey::from_bytes(&[1; 32]);
        let sender_key = SigningKey::from_bytes(&[2; 32]);
        let (ctx, _dir) = test_context(&local_key);
        let sender_id = *NodeId::from_public_key(&sender_key.verifying_key()).as_bytes();
        let local_id = *NodeId::from_public_key(&local_key.verifying_key()).as_bytes();
        let mut payload = invitation([3; 32], sender_id, local_id);
        payload.roster_hash[0] ^= 1;
        let event = SyncEvent::jury_invitation(&payload).expect("create event");

        assert!(handle_jury_invitation(&ctx, &event, &sender_id, 10)
            .await
            .is_err());
        assert!(ctx
            .home_state
            .lock()
            .await
            .notifications
            .pending()
            .is_empty());
    }

    #[tokio::test]
    async fn handle_share_delivery_persists_inbox() {
        let local_key = SigningKey::from_bytes(&[1; 32]);
        let dealer_key = SigningKey::from_bytes(&[2; 32]);
        let (ctx, _dir) = test_context(&local_key);
        let local_id = *NodeId::from_public_key(&local_key.verifying_key()).as_bytes();
        let dealer_id = *NodeId::from_public_key(&dealer_key.verifying_key()).as_bytes();
        let storage = ctx.storage.as_ref().expect("test storage");
        persist_jury_acceptance(
            &mut storage.lock().expect("storage lock"),
            &JuryAcceptanceRow {
                complaint_id: [3; 32],
                juror_node_id: local_id,
                juror_public_key: local_key.verifying_key().to_bytes(),
                share_index: 2,
                accepted_at: 1,
                record_blob: vec![1],
            },
            1000,
        )
        .expect("store acceptance");
        let payload = JuryShareDeliveryPayload {
            message_id: [4; 32],
            complaint_id: [3; 32],
            dealer_node_id: dealer_id,
            dealer_public_key: dealer_key.verifying_key().to_bytes(),
            dealer_share_index: 1,
            recipient_share_index: 2,
            share_value: [5; 32],
            issued_at: 2,
        };
        let event = SyncEvent::jury_share_delivery(&payload).expect("create event");
        handle_jury_share_delivery(&ctx, &event, &dealer_id, 10)
            .await
            .expect("handle share");
        let records = hal_storage::jury_delivery_inbox::list_deliveries_for_complaint_from_storage(
            &storage.lock().expect("storage lock"),
            &[3; 32],
        )
        .expect("list deliveries");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, DeliveryKind::ShareDelivery);
    }

    #[tokio::test]
    async fn handle_share_delivery_accepts_deterministic_message_id() {
        let local_key = SigningKey::from_bytes(&[1; 32]);
        let dealer_key = SigningKey::from_bytes(&[2; 32]);
        let (ctx, _dir) = test_context(&local_key);
        let local_id = *NodeId::from_public_key(&local_key.verifying_key()).as_bytes();
        let dealer_id = *NodeId::from_public_key(&dealer_key.verifying_key()).as_bytes();
        let storage = ctx.storage.as_ref().expect("test storage");
        persist_jury_acceptance(
            &mut storage.lock().expect("storage lock"),
            &JuryAcceptanceRow {
                complaint_id: [3; 32],
                juror_node_id: local_id,
                juror_public_key: local_key.verifying_key().to_bytes(),
                share_index: 2,
                accepted_at: 1,
                record_blob: vec![1],
            },
            1000,
        )
        .expect("store acceptance");
        let payload = JuryShareDeliveryPayload {
            message_id: crate::juror_orchestrator::compute_share_message_id(
                &[3; 32], &dealer_id, 2,
            ),
            complaint_id: [3; 32],
            dealer_node_id: dealer_id,
            dealer_public_key: dealer_key.verifying_key().to_bytes(),
            dealer_share_index: 1,
            recipient_share_index: 2,
            share_value: [5; 32],
            issued_at: 2,
        };
        let event = SyncEvent::jury_share_delivery(&payload).expect("create event");

        handle_jury_share_delivery(&ctx, &event, &dealer_id, 10)
            .await
            .expect("handle deterministic share");
        handle_jury_share_delivery(&ctx, &event, &dealer_id, 11)
            .await
            .expect("deduplicate deterministic share");

        let records = hal_storage::jury_delivery_inbox::list_deliveries_for_complaint_from_storage(
            &storage.lock().expect("storage lock"),
            &[3; 32],
        )
        .expect("list deliveries");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].message_id, payload.message_id);
    }

    #[tokio::test]
    async fn handle_share_delivery_without_commitment_emits_invalid_ack() {
        let local_key = SigningKey::from_bytes(&[1; 32]);
        let dealer_key = SigningKey::from_bytes(&[2; 32]);
        let (ctx, _dir) = test_context(&local_key);
        let local_id = *NodeId::from_public_key(&local_key.verifying_key()).as_bytes();
        let dealer_id = *NodeId::from_public_key(&dealer_key.verifying_key()).as_bytes();
        let storage = ctx.storage.as_ref().expect("test storage");
        persist_jury_acceptance(
            &mut storage.lock().expect("storage lock"),
            &JuryAcceptanceRow {
                complaint_id: [3; 32],
                juror_node_id: local_id,
                juror_public_key: local_key.verifying_key().to_bytes(),
                share_index: 2,
                accepted_at: 1,
                record_blob: vec![1],
            },
            1000,
        )
        .expect("store acceptance");
        let payload = JuryShareDeliveryPayload {
            message_id: [4; 32],
            complaint_id: [3; 32],
            dealer_node_id: dealer_id,
            dealer_public_key: dealer_key.verifying_key().to_bytes(),
            dealer_share_index: 1,
            recipient_share_index: 2,
            share_value: [5; 32],
            issued_at: 2,
        };
        let event = SyncEvent::jury_share_delivery(&payload).expect("create event");

        handle_jury_share_delivery(&ctx, &event, &dealer_id, 10)
            .await
            .expect("handle share");

        let mut ack_hasher = Sha256::new();
        ack_hasher.update(b"HAL-JURY-ACK-v1\0");
        ack_hasher.update(payload.message_id);
        let ack_message_id: [u8; 32] = ack_hasher.finalize().into();
        let ack_entry = hal_storage::jury_outbox::read_outbox_entry(
            storage.lock().expect("storage lock").connection(),
            &ack_message_id,
        )
        .expect("read ACK outbox entry")
        .expect("ACK must be queued");
        let ack_event: SyncEvent =
            serde_json::from_slice(&ack_entry.event_blob).expect("decode ACK event");
        let ack_payload: JuryShareAckPayload =
            serde_json::from_str(&ack_event.data).expect("decode ACK payload");
        assert!(
            !ack_payload.share_valid,
            "ACK must reject a share without commitment"
        );
    }

    #[tokio::test]
    async fn handle_duplicate_share_delivery_requeues_ack() {
        let local_key = SigningKey::from_bytes(&[1; 32]);
        let dealer_key = SigningKey::from_bytes(&[2; 32]);
        let (ctx, _dir) = test_context(&local_key);
        let local_id = *NodeId::from_public_key(&local_key.verifying_key()).as_bytes();
        let dealer_id = *NodeId::from_public_key(&dealer_key.verifying_key()).as_bytes();
        let storage = ctx.storage.as_ref().expect("test storage");
        persist_jury_acceptance(
            &mut storage.lock().expect("storage lock"),
            &JuryAcceptanceRow {
                complaint_id: [3; 32],
                juror_node_id: local_id,
                juror_public_key: local_key.verifying_key().to_bytes(),
                share_index: 2,
                accepted_at: 1,
                record_blob: vec![1],
            },
            1000,
        )
        .expect("store acceptance");
        let payload = JuryShareDeliveryPayload {
            message_id: [4; 32],
            complaint_id: [3; 32],
            dealer_node_id: dealer_id,
            dealer_public_key: dealer_key.verifying_key().to_bytes(),
            dealer_share_index: 1,
            recipient_share_index: 2,
            share_value: [5; 32],
            issued_at: 2,
        };
        let event = SyncEvent::jury_share_delivery(&payload).expect("create event");
        let mut ack_hasher = Sha256::new();
        ack_hasher.update(b"HAL-JURY-ACK-v1\0");
        ack_hasher.update(payload.message_id);
        let ack_message_id: [u8; 32] = ack_hasher.finalize().into();

        handle_jury_share_delivery(&ctx, &event, &dealer_id, 10)
            .await
            .expect("first share delivery");
        hal_storage::jury_outbox::remove_outbox(
            storage.lock().expect("storage lock").connection(),
            &ack_message_id,
        )
        .expect("simulate ACK already sent");

        handle_jury_share_delivery(&ctx, &event, &dealer_id, 11)
            .await
            .expect("retry share delivery");

        assert!(hal_storage::jury_outbox::read_outbox_entry(
            storage.lock().expect("storage lock").connection(),
            &ack_message_id
        )
        .expect("read requeued ACK")
        .is_some());
    }

    #[tokio::test]
    async fn handle_share_ack_persists_inbox() {
        let local_key = SigningKey::from_bytes(&[1; 32]);
        let recipient_key = SigningKey::from_bytes(&[2; 32]);
        let (ctx, _dir) = test_context(&local_key);
        let local_id = *NodeId::from_public_key(&local_key.verifying_key()).as_bytes();
        let recipient_id = *NodeId::from_public_key(&recipient_key.verifying_key()).as_bytes();
        let payload = JuryShareAckPayload {
            message_id: [3; 32],
            shared_message_id: [5; 32],
            complaint_id: [4; 32],
            dealer_node_id: local_id,
            recipient_node_id: recipient_id,
            share_valid: true,
            acked_at: 9,
        };
        let event = SyncEvent::jury_share_ack(&payload).expect("create event");
        handle_jury_share_ack(&ctx, &event, &recipient_id, 10)
            .await
            .expect("handle ACK");
        let storage = ctx.storage.as_ref().expect("test storage");
        let record = hal_storage::jury_delivery_inbox::read_delivery_for_storage(
            &storage.lock().expect("storage lock"),
            &payload.message_id,
        )
        .expect("read ACK");
        assert_eq!(record.expect("stored ACK").kind, DeliveryKind::ShareAck);
    }

    #[tokio::test]
    async fn handle_share_ack_removes_share_delivery_from_outbox() {
        let local_key = SigningKey::from_bytes(&[1; 32]);
        let recipient_key = SigningKey::from_bytes(&[2; 32]);
        let (ctx, _dir) = test_context(&local_key);
        let local_id = *NodeId::from_public_key(&local_key.verifying_key()).as_bytes();
        let recipient_id = *NodeId::from_public_key(&recipient_key.verifying_key()).as_bytes();
        let complaint_id = [4; 32];
        let shared_message_id = [5; 32];
        store_outbox_entry(
            &ctx,
            hal_storage::jury_outbox::OutboxKind::ShareDelivery,
            shared_message_id,
            complaint_id,
            recipient_id,
        );
        let payload = JuryShareAckPayload {
            message_id: [6; 32],
            shared_message_id,
            complaint_id,
            dealer_node_id: local_id,
            recipient_node_id: recipient_id,
            share_valid: true,
            acked_at: 9,
        };
        let event = SyncEvent::jury_share_ack(&payload).expect("create ACK");

        handle_jury_share_ack(&ctx, &event, &recipient_id, 10)
            .await
            .expect("handle ACK");

        let storage = ctx.storage.as_ref().expect("test storage");
        assert!(hal_storage::jury_outbox::read_outbox_entry(
            storage.lock().expect("storage lock").connection(),
            &shared_message_id
        )
        .expect("read outbox")
        .is_none());
    }

    #[tokio::test]
    async fn handle_share_ack_ignores_unknown_shared_message_id() {
        let local_key = SigningKey::from_bytes(&[1; 32]);
        let recipient_key = SigningKey::from_bytes(&[2; 32]);
        let (ctx, _dir) = test_context(&local_key);
        let local_id = *NodeId::from_public_key(&local_key.verifying_key()).as_bytes();
        let recipient_id = *NodeId::from_public_key(&recipient_key.verifying_key()).as_bytes();
        let payload = JuryShareAckPayload {
            message_id: [3; 32],
            shared_message_id: [5; 32],
            complaint_id: [4; 32],
            dealer_node_id: local_id,
            recipient_node_id: recipient_id,
            share_valid: true,
            acked_at: 9,
        };
        let event = SyncEvent::jury_share_ack(&payload).expect("create ACK");

        handle_jury_share_ack(&ctx, &event, &recipient_id, 10)
            .await
            .expect("unknown share ACK is harmless");
    }

    #[tokio::test]
    async fn handle_invitation_response_persists_inbox() {
        let local_key = SigningKey::from_bytes(&[1; 32]);
        let candidate_key = SigningKey::from_bytes(&[2; 32]);
        let (ctx, _dir) = test_context(&local_key);
        let local_id = *NodeId::from_public_key(&local_key.verifying_key()).as_bytes();
        let candidate_id = *NodeId::from_public_key(&candidate_key.verifying_key()).as_bytes();
        let complaint_id = [3; 32];
        store_complaint(&ctx, complaint_id, local_id);
        let issued_invitation = invitation(complaint_id, local_id, candidate_id);
        store_outbox_entry(
            &ctx,
            hal_storage::jury_outbox::OutboxKind::Invitation,
            issued_invitation.invitation_id,
            complaint_id,
            candidate_id,
        );
        let invitation_id = issued_invitation.invitation_id;
        let payload = invitation_response(&candidate_key, invitation_id, complaint_id, 1, 9);
        let event = SyncEvent::jury_invitation_response(&payload).expect("create event");
        handle_jury_invitation_response(&ctx, &event, &candidate_id, 10)
            .await
            .expect("handle response");
        let storage = ctx.storage.as_ref().expect("test storage");
        let record = hal_storage::jury_delivery_inbox::read_delivery_for_storage(
            &storage.lock().expect("storage lock"),
            &payload.invitation_id,
        )
        .expect("read response");
        assert_eq!(
            record.expect("stored response").kind,
            DeliveryKind::InvitationResponse
        );
        let acceptance = hal_storage::jury_acceptances::read_jury_acceptance(
            &storage.lock().expect("storage lock").connection(),
            &complaint_id,
            &candidate_id,
        )
        .expect("read acceptance")
        .expect("acceptance persisted");
        assert_eq!(acceptance.share_index, 1);
    }

    #[tokio::test]
    async fn handle_invitation_response_rejects_invalid_acceptance_signature() {
        let local_key = SigningKey::from_bytes(&[1; 32]);
        let candidate_key = SigningKey::from_bytes(&[2; 32]);
        let (ctx, _dir) = test_context(&local_key);
        let local_id = *NodeId::from_public_key(&local_key.verifying_key()).as_bytes();
        let candidate_id = *NodeId::from_public_key(&candidate_key.verifying_key()).as_bytes();
        let complaint_id = [3; 32];
        store_complaint(&ctx, complaint_id, local_id);
        let invitation_id = compute_invitation_id_v2(&complaint_id, &local_id, &candidate_id, 0);
        let mut payload = invitation_response(&candidate_key, invitation_id, complaint_id, 1, 9);
        payload
            .acceptance
            .as_mut()
            .expect("signed acceptance")
            .signature[0] ^= 1;
        let event = SyncEvent::jury_invitation_response(&payload).expect("create event");

        assert!(
            handle_jury_invitation_response(&ctx, &event, &candidate_id, 10)
                .await
                .is_err()
        );
        let storage = ctx.storage.as_ref().expect("test storage");
        assert!(hal_storage::jury_acceptances::read_jury_acceptance(
            &storage.lock().expect("storage lock").connection(),
            &complaint_id,
            &candidate_id,
        )
        .expect("read acceptance")
        .is_none());
    }

    #[tokio::test]
    async fn handle_invitation_response_rejects_mismatched_roster_hash() {
        let local_key = SigningKey::from_bytes(&[1; 32]);
        let candidate_key = SigningKey::from_bytes(&[2; 32]);
        let (ctx, _dir) = test_context(&local_key);
        let local_id = *NodeId::from_public_key(&local_key.verifying_key()).as_bytes();
        let candidate_id = *NodeId::from_public_key(&candidate_key.verifying_key()).as_bytes();
        let complaint_id = [3; 32];
        store_complaint(&ctx, complaint_id, local_id);
        let invitation = invitation(complaint_id, local_id, candidate_id);
        store_outbox_entry(
            &ctx,
            hal_storage::jury_outbox::OutboxKind::Invitation,
            invitation.invitation_id,
            complaint_id,
            candidate_id,
        );
        let mut payload = invitation_response(
            &candidate_key,
            invitation.invitation_id,
            complaint_id,
            invitation.share_index,
            9,
        );
        payload.roster_hash[0] ^= 1;
        let event = SyncEvent::jury_invitation_response(&payload).expect("create event");

        assert!(
            handle_jury_invitation_response(&ctx, &event, &candidate_id, 10)
                .await
                .is_err()
        );
        let storage = ctx.storage.as_ref().expect("test storage");
        assert!(hal_storage::jury_acceptances::read_jury_acceptance(
            &storage.lock().expect("storage lock").connection(),
            &complaint_id,
            &candidate_id,
        )
        .expect("read acceptance")
        .is_none());
    }

    #[tokio::test]
    async fn handle_invitation_response_removes_invitation_from_outbox() {
        let local_key = SigningKey::from_bytes(&[1; 32]);
        let candidate_key = SigningKey::from_bytes(&[2; 32]);
        let (ctx, _dir) = test_context(&local_key);
        let local_id = *NodeId::from_public_key(&local_key.verifying_key()).as_bytes();
        let candidate_id = *NodeId::from_public_key(&candidate_key.verifying_key()).as_bytes();
        let complaint_id = [3; 32];
        store_complaint(&ctx, complaint_id, local_id);
        let invitation_id = compute_invitation_id_v2(&complaint_id, &local_id, &candidate_id, 0);
        store_outbox_entry(
            &ctx,
            hal_storage::jury_outbox::OutboxKind::Invitation,
            invitation_id,
            complaint_id,
            candidate_id,
        );
        let payload = invitation_response(&candidate_key, invitation_id, complaint_id, 1, 9);
        let event = SyncEvent::jury_invitation_response(&payload).expect("create response");

        handle_jury_invitation_response(&ctx, &event, &candidate_id, 10)
            .await
            .expect("handle response");

        let storage = ctx.storage.as_ref().expect("test storage");
        assert!(hal_storage::jury_outbox::read_outbox_entry(
            storage.lock().expect("storage lock").connection(),
            &invitation_id
        )
        .expect("read outbox")
        .is_none());
    }

    #[tokio::test]
    async fn handle_invitation_response_unknown_invitation_ok() {
        let local_key = SigningKey::from_bytes(&[1; 32]);
        let candidate_key = SigningKey::from_bytes(&[2; 32]);
        let (ctx, _dir) = test_context(&local_key);
        let local_id = *NodeId::from_public_key(&local_key.verifying_key()).as_bytes();
        let candidate_id = *NodeId::from_public_key(&candidate_key.verifying_key()).as_bytes();
        let complaint_id = [3; 32];
        store_complaint(&ctx, complaint_id, local_id);
        let invitation_id = compute_invitation_id_v2(&complaint_id, &local_id, &candidate_id, 0);
        let payload = invitation_response(&candidate_key, invitation_id, complaint_id, 1, 9);
        let event = SyncEvent::jury_invitation_response(&payload).expect("create response");

        handle_jury_invitation_response(&ctx, &event, &candidate_id, 10)
            .await
            .expect("unknown invitation response is harmless");
    }

    #[tokio::test]
    async fn handle_share_delivery_with_valid_share_marks_verified_and_acks_true() {
        let local_key = SigningKey::from_bytes(&[1; 32]);
        let dealer_key = SigningKey::from_bytes(&[2; 32]);
        let (ctx, _dir) = test_context(&local_key);
        let complaint_id = [51; 32];
        let local_id = *NodeId::from_public_key(&local_key.verifying_key()).as_bytes();
        let dealer_id = *NodeId::from_public_key(&dealer_key.verifying_key()).as_bytes();
        store_share_acceptance(&ctx, &local_key, complaint_id, 2);
        let (record, share_value) =
            setup_commitment_and_share(&ctx, &dealer_key, complaint_id, 2, 10);
        let payload = JuryShareDeliveryPayload {
            message_id: [52; 32],
            complaint_id,
            dealer_node_id: dealer_id,
            dealer_public_key: record.dealer_public_key,
            dealer_share_index: 1,
            recipient_share_index: 2,
            share_value,
            issued_at: 11,
        };
        let event = SyncEvent::jury_share_delivery(&payload).expect("create event");

        handle_jury_share_delivery(&ctx, &event, &dealer_id, 12)
            .await
            .expect("handle valid share");

        let storage = ctx.storage.as_ref().expect("test storage");
        let received = hal_storage::jury_dkg_storage::read_received_share(
            &storage.lock().expect("storage lock").connection(),
            &complaint_id,
            &dealer_id,
        )
        .expect("read received share")
        .expect("valid share persisted");
        assert!(received.verified);
        assert_eq!(received.recipient_share_index, 2);
        assert_eq!(*received.share_value, share_value);
        let ack = read_share_ack(&ctx, &payload);
        assert!(ack.share_valid);
        assert_eq!(ack.recipient_node_id, local_id);
    }

    #[tokio::test]
    async fn handle_share_delivery_with_invalid_share_acks_false() {
        let local_key = SigningKey::from_bytes(&[1; 32]);
        let dealer_key = SigningKey::from_bytes(&[2; 32]);
        let (ctx, _dir) = test_context(&local_key);
        let complaint_id = [53; 32];
        let dealer_id = *NodeId::from_public_key(&dealer_key.verifying_key()).as_bytes();
        store_share_acceptance(&ctx, &local_key, complaint_id, 2);
        let (record, valid_share) =
            setup_commitment_and_share(&ctx, &dealer_key, complaint_id, 2, 10);
        let valid_scalar: Option<Scalar> = Option::from(Scalar::from_canonical_bytes(valid_share));
        let invalid_share =
            (valid_scalar.expect("valid generated scalar") + Scalar::ONE).to_bytes();
        let payload = JuryShareDeliveryPayload {
            message_id: [54; 32],
            complaint_id,
            dealer_node_id: dealer_id,
            dealer_public_key: record.dealer_public_key,
            dealer_share_index: 1,
            recipient_share_index: 2,
            share_value: invalid_share,
            issued_at: 11,
        };
        let event = SyncEvent::jury_share_delivery(&payload).expect("create event");

        handle_jury_share_delivery(&ctx, &event, &dealer_id, 12)
            .await
            .expect("handle invalid share");

        let storage = ctx.storage.as_ref().expect("test storage");
        assert!(hal_storage::jury_dkg_storage::read_received_share(
            &storage.lock().expect("storage lock").connection(),
            &complaint_id,
            &dealer_id,
        )
        .expect("read received share")
        .is_none());
        assert!(!read_share_ack(&ctx, &payload).share_valid);
    }

    #[tokio::test]
    async fn handle_share_delivery_without_commitment_acks_false() {
        let local_key = SigningKey::from_bytes(&[1; 32]);
        let dealer_key = SigningKey::from_bytes(&[2; 32]);
        let (ctx, _dir) = test_context(&local_key);
        let complaint_id = [55; 32];
        let dealer_id = *NodeId::from_public_key(&dealer_key.verifying_key()).as_bytes();
        store_share_acceptance(&ctx, &local_key, complaint_id, 2);
        let payload = JuryShareDeliveryPayload {
            message_id: [56; 32],
            complaint_id,
            dealer_node_id: dealer_id,
            dealer_public_key: dealer_key.verifying_key().to_bytes(),
            dealer_share_index: 1,
            recipient_share_index: 2,
            share_value: Scalar::from(3u64).to_bytes(),
            issued_at: 11,
        };
        let event = SyncEvent::jury_share_delivery(&payload).expect("create event");

        handle_jury_share_delivery(&ctx, &event, &dealer_id, 12)
            .await
            .expect("handle share without commitment");

        let storage = ctx.storage.as_ref().expect("test storage");
        assert!(hal_storage::jury_dkg_storage::read_received_share(
            &storage.lock().expect("storage lock").connection(),
            &complaint_id,
            &dealer_id,
        )
        .expect("read received share")
        .is_none());
        assert!(!read_share_ack(&ctx, &payload).share_valid);
    }

    #[tokio::test]
    async fn handle_share_delivery_rejects_mismatched_dealer_public_key() {
        let local_key = SigningKey::from_bytes(&[1; 32]);
        let dealer_key = SigningKey::from_bytes(&[2; 32]);
        let other_key = SigningKey::from_bytes(&[3; 32]);
        let (ctx, _dir) = test_context(&local_key);
        let complaint_id = [57; 32];
        let dealer_id = *NodeId::from_public_key(&dealer_key.verifying_key()).as_bytes();
        store_share_acceptance(&ctx, &local_key, complaint_id, 2);
        let (record, share_value) =
            setup_commitment_and_share(&ctx, &dealer_key, complaint_id, 2, 10);
        let other_public_key = other_key.verifying_key().to_bytes();
        {
            let storage = ctx.storage.as_ref().expect("test storage");
            storage
                .lock()
                .expect("storage lock")
                .connection()
                .execute(
                    "UPDATE jury_commitments SET dealer_public_key = ?1
                     WHERE complaint_id = ?2 AND dealer_node_id = ?3",
                    (
                        other_public_key.as_slice(),
                        complaint_id.as_slice(),
                        record.dealer_node_id.as_slice(),
                    ),
                )
                .expect("corrupt stored dealer-key binding for test");
        }
        let payload = JuryShareDeliveryPayload {
            message_id: [58; 32],
            complaint_id,
            dealer_node_id: dealer_id,
            dealer_public_key: dealer_key.verifying_key().to_bytes(),
            dealer_share_index: 1,
            recipient_share_index: 2,
            share_value,
            issued_at: 11,
        };
        let event = SyncEvent::jury_share_delivery(&payload).expect("create event");

        handle_jury_share_delivery(&ctx, &event, &dealer_id, 12)
            .await
            .expect("handle mismatched stored dealer key");

        let storage = ctx.storage.as_ref().expect("test storage");
        assert!(hal_storage::jury_dkg_storage::read_received_share(
            &storage.lock().expect("storage lock").connection(),
            &complaint_id,
            &dealer_id,
        )
        .expect("read received share")
        .is_none());
        assert!(!read_share_ack(&ctx, &payload).share_valid);
    }
}
