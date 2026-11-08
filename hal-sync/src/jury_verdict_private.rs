use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::VerifyingKey;
use hal_storage::ClientStorage;
use hal_storage::{
    complaints::read_complaint,
    jury_rosters::{list_assignments_for_generation, read_latest_roster},
    jury_verdicts::{upsert_verdict, JuryVerdictRow},
};

use crate::{
    dht::{notifier::NotificationKind, NodeId},
    journal::{JuryVerdictPrivatePayload, SyncEvent},
    jury_verdict_aggregator::verify_verdict,
    runtime_context::RuntimeContext,
};

pub async fn handle_jury_verdict_private(
    ctx: &Arc<RuntimeContext>,
    event: &SyncEvent,
    sender_node_id: &[u8; 32],
    sender_key: &VerifyingKey,
    now: u64,
) -> Result<()> {
    let payload: JuryVerdictPrivatePayload =
        serde_json::from_str(&event.data).context("parse JuryVerdictPrivate payload")?;
    let verdict = &payload.verdict;
    if NodeId::from_public_key(sender_key).as_bytes() != sender_node_id {
        return Err(anyhow!(
            "private verdict sender key does not match sender node id"
        ));
    }
    if !verdict
        .juror_signatures
        .iter()
        .any(|vote_ref| &vote_ref.juror_node_id == sender_node_id)
    {
        return Err(anyhow!(
            "private verdict sender is not one of its aggregating jurors"
        ));
    }

    let local_node_id = *NodeId::from_hex(&ctx.identity_id)
        .context("parse local identity for private verdict")?
        .as_bytes();
    let storage_arc = ctx
        .storage
        .as_ref()
        .context("storage required for private jury verdict")?;
    let stored = {
        let storage = storage_arc
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        persist_private_verdict(&storage, &payload, &local_node_id, now)?
    };
    if !stored {
        return Ok(());
    }

    let mut home = ctx.home_state.lock().await;
    let complaint_node = NodeId::from_bytes(verdict.complaint_id);
    let sender = NodeId::from_bytes(*sender_node_id);
    if !home.notifications.pending().iter().any(|notification| {
        notification.kind == NotificationKind::JuryVerdictReceived
            && notification.from == sender
            && notification.subject == complaint_node
    }) {
        home.notifications.create(
            NotificationKind::JuryVerdictReceived,
            sender,
            complaint_node,
            None,
            now,
            crate::dht::notifier::NOTIFICATION_DEFAULT_TTL_SECS,
        );
    }
    Ok(())
}

fn persist_private_verdict(
    storage: &ClientStorage,
    payload: &JuryVerdictPrivatePayload,
    local_node_id: &[u8; 32],
    now: u64,
) -> Result<bool> {
    let verdict = &payload.verdict;
    if verdict.verdict == crate::jury_vote::JuryDecision::Guilty {
        return Err(anyhow!("guilty verdict must not use private delivery"));
    }
    if verdict.issued_at > now {
        return Err(anyhow!("private jury verdict issue time is in the future"));
    }
    verify_verdict(verdict).context("verify private jury verdict")?;
    let Some(complaint) = read_complaint(storage.connection(), &verdict.complaint_id)? else {
        return Ok(false);
    };
    if local_node_id != &complaint.complainant_node_id
        && local_node_id != &complaint.subject_node_id
    {
        return Ok(false);
    }
    let roster = read_latest_roster(storage.connection(), &verdict.complaint_id)?
        .context("jury roster is required to verify private verdict")?;
    let roster_nodes = list_assignments_for_generation(
        storage.connection(),
        &verdict.complaint_id,
        roster.roster_generation,
    )?
    .into_iter()
    .map(|assignment| assignment.candidate_node_id)
    .collect::<std::collections::HashSet<_>>();
    if verdict
        .juror_signatures
        .iter()
        .any(|vote_ref| !roster_nodes.contains(&vote_ref.juror_node_id))
    {
        return Err(anyhow!(
            "private jury verdict contains a signer outside the complaint roster"
        ));
    }

    let juror_signatures =
        serde_json::to_vec(&verdict.juror_signatures).context("serialize jury vote references")?;
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
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use hal_storage::{
        complaints::{insert_complaint, ComplaintRow},
        jury_rosters::{insert_roster, insert_roster_assignment, RosterAssignmentRow, RosterRow},
        jury_verdicts::read_verdict,
        ClientStorage,
    };
    use std::sync::{Arc, Mutex};
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn handler_persists_private_verdict_after_verification() {
        let db_file = NamedTempFile::new().expect("create test database file");
        let storage = Arc::new(Mutex::new(
            ClientStorage::open(db_file.path(), &[21; 32]).expect("open test storage"),
        ));
        let complaint_id = [1; 32];
        let local_key = SigningKey::from_bytes(&[31; 32]);
        let local_node_id = *NodeId::from_public_key(&local_key.verifying_key()).as_bytes();
        let juror_keys = (1..=5)
            .map(|index| SigningKey::from_bytes(&[index; 32]))
            .collect::<Vec<_>>();
        let sender_key = juror_keys[0].clone();
        {
            let storage = storage.lock().expect("storage lock");
            insert_complaint(
                storage.connection(),
                &ComplaintRow {
                    complaint_id,
                    complainant_node_id: local_node_id,
                    subject_node_id: [2; 32],
                    kind_tag: 1,
                    period_start: 1,
                    period_end: 2,
                    submitted_at: 1,
                    record_blob: vec![1],
                },
                10_000,
            )
            .expect("insert complaint");
            insert_roster(
                storage.connection(),
                &RosterRow {
                    complaint_id,
                    roster_generation: 1,
                    roster_hash: [4; 32],
                    roster_blob: Vec::new(),
                    created_at: 5,
                },
            )
            .expect("insert jury roster");
            for (index, key) in juror_keys.iter().enumerate() {
                insert_roster_assignment(
                    storage.connection(),
                    &RosterAssignmentRow {
                        complaint_id,
                        roster_generation: 1,
                        share_index: index as u32 + 1,
                        candidate_node_id: *NodeId::from_public_key(&key.verifying_key())
                            .as_bytes(),
                        invitation_id: [index as u8 + 10; 32],
                        invited_at: 6,
                        response: None,
                    },
                )
                .expect("insert roster assignment");
            }
        }
        let refs = juror_keys
            .into_iter()
            .map(|key| {
                let mut vote = crate::jury_vote::JuryVote {
                    complaint_id,
                    evidence_hash: [3; 32],
                    juror_node_id: *NodeId::from_public_key(&key.verifying_key()).as_bytes(),
                    juror_public_key: [0; 32],
                    decision: crate::jury_vote::JuryDecision::NotGuilty,
                    issued_at: 10,
                    signature: [0; 64],
                };
                crate::jury_vote::sign_vote(&key, &mut vote).expect("sign vote");
                crate::jury_vote::JurorVoteRef {
                    juror_node_id: vote.juror_node_id,
                    juror_public_key: vote.juror_public_key,
                    decision: vote.decision,
                    issued_at: vote.issued_at,
                    signature: vote.signature,
                }
            })
            .collect();
        let payload = JuryVerdictPrivatePayload {
            verdict: crate::jury_vote::JuryVerdict {
                complaint_id,
                evidence_hash: [3; 32],
                verdict: crate::jury_vote::JuryDecision::NotGuilty,
                juror_signatures: refs,
                issued_at: 11,
            },
        };
        let ctx = crate::runtime_context::tests::test_runtime_context_with_storage(
            Some(Arc::clone(&storage)),
            NodeId::from_bytes(local_node_id).to_hex(),
        );
        let sender_node_id = *NodeId::from_public_key(&sender_key.verifying_key()).as_bytes();
        let mut event = SyncEvent::jury_verdict_private(&payload).expect("create private event");
        event.timestamp = 12;
        event
            .sign(&sender_key.to_bytes())
            .expect("sign private event");

        handle_jury_verdict_private(
            &ctx,
            &event,
            &sender_node_id,
            &sender_key.verifying_key(),
            12,
        )
        .await
        .expect("handle verified private verdict");
        let storage = storage.lock().expect("storage lock");
        assert_eq!(
            read_verdict(storage.connection(), &complaint_id, &[3; 32])
                .expect("read verdict")
                .expect("verdict persisted")
                .verdict,
            crate::jury_vote::JuryDecision::NotGuilty.as_u8()
        );
        drop(storage);
        let home = ctx.home_state.lock().await;
        assert!(home
            .notifications
            .pending()
            .iter()
            .any(|notification| notification.kind == NotificationKind::JuryVerdictReceived));
    }
}
