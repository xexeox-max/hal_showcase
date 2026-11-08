use std::collections::HashSet;

use ed25519_dalek::VerifyingKey;
use thiserror::Error;

use crate::jury_vote::{
    node_id_from_public_key, verify_vote, vote_from_ref, JurorVoteRef, JuryDecision, JuryVerdict,
    JuryVote, VoteError,
};

#[derive(Debug, Error)]
pub enum VerdictError {
    #[error("vote verification failed: {0}")]
    Vote(#[from] VoteError),
    #[error("fewer than five verified votes")]
    InsufficientVotes,
    #[error("public key does not match juror_node_id")]
    KeyMismatch,
    #[error("duplicate juror vote reference")]
    DuplicateJuror,
    #[error("declared verdict does not match the verified votes")]
    VerdictMismatch,
}

pub fn derive_verdict(refs: &[JurorVoteRef]) -> Result<JuryDecision, VerdictError> {
    let guilty = refs
        .iter()
        .filter(|vote| vote.decision == JuryDecision::Guilty)
        .count();
    let not_guilty = refs
        .iter()
        .filter(|vote| vote.decision == JuryDecision::NotGuilty)
        .count();
    let inconclusive = refs
        .iter()
        .filter(|vote| vote.decision == JuryDecision::Inconclusive)
        .count();

    if guilty >= 5 {
        Ok(JuryDecision::Guilty)
    } else if not_guilty >= 5 {
        Ok(JuryDecision::NotGuilty)
    } else if guilty + not_guilty + inconclusive >= 5 {
        Ok(JuryDecision::Inconclusive)
    } else {
        Err(VerdictError::InsufficientVotes)
    }
}

pub fn verify_verdict(verdict: &JuryVerdict) -> Result<(), VerdictError> {
    if verdict.juror_signatures.len() < 5 {
        return Err(VerdictError::InsufficientVotes);
    }
    let mut seen = HashSet::with_capacity(verdict.juror_signatures.len());
    for vote_ref in &verdict.juror_signatures {
        if !seen.insert(vote_ref.juror_node_id) {
            return Err(VerdictError::DuplicateJuror);
        }
        let public_key = VerifyingKey::from_bytes(&vote_ref.juror_public_key)
            .map_err(|_| VerdictError::KeyMismatch)?;
        if node_id_from_public_key(&public_key) != vote_ref.juror_node_id {
            return Err(VerdictError::KeyMismatch);
        }
        verify_vote(
            &public_key,
            &vote_from_ref(verdict.complaint_id, verdict.evidence_hash, vote_ref),
        )?;
    }
    if derive_verdict(&verdict.juror_signatures)? != verdict.verdict {
        return Err(VerdictError::VerdictMismatch);
    }
    Ok(())
}

pub fn aggregate_verdict(
    complaint_id: &[u8; 32],
    evidence_hash: &[u8; 32],
    votes: &[JuryVote],
    now: u64,
) -> Result<Option<JuryVerdict>, VerdictError> {
    let mut verified = Vec::new();
    for vote in votes {
        if vote.complaint_id != *complaint_id || vote.evidence_hash != *evidence_hash {
            continue;
        }
        let public_key = match VerifyingKey::from_bytes(&vote.juror_public_key) {
            Ok(public_key) if node_id_from_public_key(&public_key) == vote.juror_node_id => {
                public_key
            }
            _ => continue,
        };
        if verify_vote(&public_key, vote).is_ok() {
            verified.push(vote);
        }
    }

    verified.sort_by_key(|vote| (vote.issued_at, vote.juror_node_id));
    let mut seen = HashSet::with_capacity(verified.len());
    let refs = verified
        .into_iter()
        .filter(|vote| seen.insert(vote.juror_node_id))
        .map(|vote| JurorVoteRef {
            juror_node_id: vote.juror_node_id,
            juror_public_key: vote.juror_public_key,
            decision: vote.decision,
            issued_at: vote.issued_at,
            signature: vote.signature,
        })
        .collect::<Vec<_>>();
    if refs.len() < 5 {
        return Ok(None);
    }

    let verdict = derive_verdict(&refs)?;
    Ok(Some(JuryVerdict {
        complaint_id: *complaint_id,
        evidence_hash: *evidence_hash,
        verdict,
        juror_signatures: refs,
        issued_at: now,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jury_vote::{node_id_from_public_key, sign_vote};
    use ed25519_dalek::SigningKey;

    fn signed_vote(index: u8, decision: JuryDecision, issued_at: u64) -> JuryVote {
        let key = SigningKey::from_bytes(&[index; 32]);
        let mut vote = JuryVote {
            complaint_id: [1; 32],
            evidence_hash: [2; 32],
            juror_node_id: node_id_from_public_key(&key.verifying_key()),
            juror_public_key: [0; 32],
            decision,
            issued_at,
            signature: [0; 64],
        };
        sign_vote(&key, &mut vote).expect("sign test vote");
        vote
    }

    #[test]
    fn aggregate_returns_none_with_fewer_than_five_votes() {
        let votes = (1..5)
            .map(|index| signed_vote(index, JuryDecision::Guilty, u64::from(index)))
            .collect::<Vec<_>>();
        assert!(aggregate_verdict(&[1; 32], &[2; 32], &votes, 10)
            .expect("aggregate four votes")
            .is_none());
    }

    #[test]
    fn aggregate_returns_guilty_with_five_guilty() {
        let votes = (1..=5)
            .map(|index| signed_vote(index, JuryDecision::Guilty, u64::from(index)))
            .collect::<Vec<_>>();
        let verdict = aggregate_verdict(&[1; 32], &[2; 32], &votes, 10)
            .expect("aggregate guilty votes")
            .expect("five votes");
        assert_eq!(verdict.verdict, JuryDecision::Guilty);
        assert_eq!(verdict.juror_signatures.len(), 5);
        assert_eq!(verdict.issued_at, 10);
    }

    #[test]
    fn aggregate_returns_not_guilty_with_five_not_guilty() {
        let votes = (1..=5)
            .map(|index| signed_vote(index, JuryDecision::NotGuilty, u64::from(index)))
            .collect::<Vec<_>>();
        let verdict = aggregate_verdict(&[1; 32], &[2; 32], &votes, 10)
            .expect("aggregate not-guilty votes")
            .expect("five votes");
        assert_eq!(verdict.verdict, JuryDecision::NotGuilty);
    }

    #[test]
    fn aggregate_returns_inconclusive_with_mixed_decisions() {
        let votes = [
            signed_vote(1, JuryDecision::Guilty, 1),
            signed_vote(2, JuryDecision::Guilty, 2),
            signed_vote(3, JuryDecision::Guilty, 3),
            signed_vote(4, JuryDecision::NotGuilty, 4),
            signed_vote(5, JuryDecision::NotGuilty, 5),
        ];
        let verdict = aggregate_verdict(&[1; 32], &[2; 32], &votes, 10)
            .expect("aggregate mixed votes")
            .expect("five votes");
        assert_eq!(verdict.verdict, JuryDecision::Inconclusive);
    }

    #[test]
    fn aggregate_dedupes_votes_by_juror_node_id() {
        let earliest = signed_vote(1, JuryDecision::NotGuilty, 1);
        let later = signed_vote(1, JuryDecision::Guilty, 2);
        let mut votes = vec![later, earliest.clone()];
        votes.extend(
            (2..=5).map(|index| signed_vote(index, JuryDecision::NotGuilty, u64::from(index))),
        );
        let verdict = aggregate_verdict(&[1; 32], &[2; 32], &votes, 10)
            .expect("aggregate deduplicated votes")
            .expect("five unique votes");
        assert_eq!(verdict.verdict, JuryDecision::NotGuilty);
        assert_eq!(
            verdict
                .juror_signatures
                .iter()
                .find(|vote| vote.juror_node_id == earliest.juror_node_id)
                .map(|vote| vote.issued_at),
            Some(1)
        );
    }
}
