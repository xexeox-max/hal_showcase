use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use hal_storage::{
    jury_assembly_state::{read_juror_state, JurorPhase},
    jury_votes::{insert_vote_if_missing, read_vote, JuryVoteRow},
};

use crate::{
    dht::NodeId,
    journal_commit_publisher::PublishTransport,
    jury_vote::{sign_vote, JuryDecision, JuryVote},
    jury_vote_publisher::publish_vote_to_dht,
    runtime_context::RuntimeContext,
};

pub async fn submit_vote(
    ctx: &Arc<RuntimeContext>,
    transport: &dyn PublishTransport,
    complaint_id: &[u8; 32],
    evidence_hash: &[u8; 32],
    decision: JuryDecision,
    now: u64,
) -> Result<()> {
    let local_node_id = *NodeId::from_hex(&ctx.identity_id)
        .context("parse local juror identity for vote submission")?
        .as_bytes();
    let storage_arc = ctx
        .storage
        .as_ref()
        .context("storage required to submit jury vote")?;
    {
        let storage = storage_arc
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        let state = read_juror_state(storage.connection(), complaint_id, &local_node_id)?
            .ok_or_else(|| anyhow!("local juror state not found"))?;
        validate_vote_window(state.phase, state.updated_at, now)?;
        if read_vote(
            storage.connection(),
            complaint_id,
            evidence_hash,
            &local_node_id,
        )?
        .is_some()
        {
            return Err(anyhow!("local jury vote already exists for this evidence"));
        }
    }

    if ctx
        .jury_plaintext_cache
        .get(complaint_id, evidence_hash)
        .context("check jury plaintext before vote submission")?
        .is_none()
    {
        return Err(anyhow!(
            "cannot submit jury vote before evidence is decrypted"
        ));
    }
    let signing_key = ctx
        .identity_signing_key
        .as_ref()
        .context("identity signing key required to submit jury vote")?;
    let mut vote = JuryVote {
        complaint_id: *complaint_id,
        evidence_hash: *evidence_hash,
        juror_node_id: local_node_id,
        juror_public_key: [0; 32],
        decision,
        issued_at: now,
        signature: [0; 64],
    };
    sign_vote(signing_key, &mut vote).context("sign jury vote")?;
    let row = JuryVoteRow {
        complaint_id: vote.complaint_id,
        evidence_hash: vote.evidence_hash,
        juror_node_id: vote.juror_node_id,
        juror_public_key: vote.juror_public_key,
        decision: vote.decision.as_u8(),
        issued_at: vote.issued_at,
        signature: vote.signature,
    };
    {
        let storage = storage_arc
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        if !insert_vote_if_missing(storage.connection(), &row)? {
            return Err(anyhow!(
                "local jury vote was submitted concurrently for this evidence"
            ));
        }
    }
    publish_vote_to_dht(transport, &vote, now)
        .await
        .context("publish submitted jury vote")
}

fn validate_vote_window(phase: JurorPhase, phase_updated_at: u64, now: u64) -> Result<()> {
    if phase != JurorPhase::AwaitingVotes {
        return Err(anyhow!("cannot submit jury vote in phase {phase:?}"));
    }
    if now < phase_updated_at
        || now.saturating_sub(phase_updated_at) > crate::jury_vote::JURY_VOTE_WINDOW_SECS
    {
        return Err(anyhow!("jury vote is outside the three-day voting window"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vote_window_requires_awaiting_phase_and_is_inclusive_at_deadline() {
        assert!(validate_vote_window(JurorPhase::ReadyForDecryption, 100, 100).is_err());
        assert!(validate_vote_window(JurorPhase::AwaitingVotes, 100, 99).is_err());
        assert!(validate_vote_window(
            JurorPhase::AwaitingVotes,
            100,
            100 + crate::jury_vote::JURY_VOTE_WINDOW_SECS
        )
        .is_ok());
        assert!(validate_vote_window(
            JurorPhase::AwaitingVotes,
            100,
            101 + crate::jury_vote::JURY_VOTE_WINDOW_SECS
        )
        .is_err());
    }
}
