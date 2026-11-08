use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const VOTE_SIGNING_DOMAIN: &[u8] = b"hal.jury.vote.sign.v1";
pub const VOTE_DOMAIN: &[u8] = b"hal.jury.vote.v1";
pub const VERDICT_DOMAIN: &[u8] = b"hal.jury.verdict.v1";
pub const JURY_VOTE_TTL_SECS: u64 = 14 * 86400;
pub const JURY_VOTE_WINDOW_SECS: u64 = 3 * 86400;
pub const JURY_VERDICT_TTL_SECS: u64 = 365 * 86400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum JuryDecision {
    Guilty = 1,
    NotGuilty = 2,
    Inconclusive = 3,
}

impl JuryDecision {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(value: u8) -> Result<Self, VoteError> {
        match value {
            1 => Ok(Self::Guilty),
            2 => Ok(Self::NotGuilty),
            3 => Ok(Self::Inconclusive),
            _ => Err(VoteError::InvalidDecision(value)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JuryVote {
    pub complaint_id: [u8; 32],
    pub evidence_hash: [u8; 32],
    pub juror_node_id: [u8; 32],
    pub juror_public_key: [u8; 32],
    pub decision: JuryDecision,
    pub issued_at: u64,
    #[serde(with = "bytes64_serde")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JurorVoteRef {
    pub juror_node_id: [u8; 32],
    pub juror_public_key: [u8; 32],
    pub decision: JuryDecision,
    pub issued_at: u64,
    #[serde(with = "bytes64_serde")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JuryVerdict {
    pub complaint_id: [u8; 32],
    pub evidence_hash: [u8; 32],
    pub verdict: JuryDecision,
    pub juror_signatures: Vec<JurorVoteRef>,
    pub issued_at: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VoteError {
    #[error("invalid decision value: {0}")]
    InvalidDecision(u8),
    #[error("signature verification failed")]
    SignatureInvalid,
}

pub fn vote_signing_bytes(vote: &JuryVote) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(VOTE_SIGNING_DOMAIN.len() + 32 * 4 + 1 + 8);
    bytes.extend_from_slice(VOTE_SIGNING_DOMAIN);
    bytes.extend_from_slice(&vote.complaint_id);
    bytes.extend_from_slice(&vote.evidence_hash);
    bytes.extend_from_slice(&vote.juror_node_id);
    bytes.extend_from_slice(&vote.juror_public_key);
    bytes.push(vote.decision.as_u8());
    bytes.extend_from_slice(&vote.issued_at.to_be_bytes());
    bytes
}

pub fn sign_vote(key: &SigningKey, vote: &mut JuryVote) -> Result<(), VoteError> {
    let public_key = key.verifying_key();
    if node_id_from_public_key(&public_key) != vote.juror_node_id {
        return Err(VoteError::SignatureInvalid);
    }
    vote.juror_public_key = public_key.to_bytes();
    vote.signature = key.sign(&vote_signing_bytes(vote)).to_bytes();
    Ok(())
}

pub fn verify_vote(public_key: &VerifyingKey, vote: &JuryVote) -> Result<(), VoteError> {
    if node_id_from_public_key(public_key) != vote.juror_node_id
        || public_key.to_bytes() != vote.juror_public_key
        || JuryDecision::from_u8(vote.decision.as_u8()).is_err()
    {
        return Err(VoteError::SignatureInvalid);
    }
    public_key
        .verify_strict(
            &vote_signing_bytes(vote),
            &Signature::from_bytes(&vote.signature),
        )
        .map_err(|_| VoteError::SignatureInvalid)
}

pub fn vote_from_ref(
    complaint_id: [u8; 32],
    evidence_hash: [u8; 32],
    vote_ref: &JurorVoteRef,
) -> JuryVote {
    JuryVote {
        complaint_id,
        evidence_hash,
        juror_node_id: vote_ref.juror_node_id,
        juror_public_key: vote_ref.juror_public_key,
        decision: vote_ref.decision,
        issued_at: vote_ref.issued_at,
        signature: vote_ref.signature,
    }
}

pub fn vote_dht_key(
    complaint_id: &[u8; 32],
    evidence_hash: &[u8; 32],
    juror_node_id: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(VOTE_DOMAIN);
    hasher.update(complaint_id);
    hasher.update(evidence_hash);
    hasher.update(juror_node_id);
    hasher.finalize().into()
}

pub fn verdict_dht_key(complaint_id: &[u8; 32], evidence_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(VERDICT_DOMAIN);
    hasher.update(complaint_id);
    hasher.update(evidence_hash);
    hasher.finalize().into()
}

pub fn node_id_from_public_key(public_key: &VerifyingKey) -> [u8; 32] {
    Sha256::digest(public_key.as_bytes()).into()
}

mod bytes64_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        value.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|bytes: Vec<u8>| serde::de::Error::invalid_length(bytes.len(), &"64 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::jury_dkg_commitment::{commitment_dht_key, partial_dht_key};

    #[test]
    fn decision_roundtrip_u8() {
        for (value, decision) in [
            (1, JuryDecision::Guilty),
            (2, JuryDecision::NotGuilty),
            (3, JuryDecision::Inconclusive),
        ] {
            assert_eq!(JuryDecision::from_u8(value), Ok(decision));
            assert_eq!(decision.as_u8(), value);
        }
        assert_eq!(JuryDecision::from_u8(4), Err(VoteError::InvalidDecision(4)));
    }

    #[test]
    fn vote_sign_verify_roundtrip() {
        let key = SigningKey::from_bytes(&[17; 32]);
        let verifying_key = key.verifying_key();
        let mut vote = JuryVote {
            complaint_id: [1; 32],
            evidence_hash: [2; 32],
            juror_node_id: node_id_from_public_key(&verifying_key),
            juror_public_key: [0; 32],
            decision: JuryDecision::NotGuilty,
            issued_at: 100,
            signature: [0; 64],
        };
        sign_vote(&key, &mut vote).expect("sign vote");
        verify_vote(&verifying_key, &vote).expect("verify vote");
    }

    #[test]
    fn verify_rejects_tampered_decision() {
        let key = SigningKey::from_bytes(&[18; 32]);
        let verifying_key = key.verifying_key();
        let mut vote = JuryVote {
            complaint_id: [1; 32],
            evidence_hash: [2; 32],
            juror_node_id: node_id_from_public_key(&verifying_key),
            juror_public_key: [0; 32],
            decision: JuryDecision::Guilty,
            issued_at: 100,
            signature: [0; 64],
        };
        sign_vote(&key, &mut vote).expect("sign vote");
        vote.decision = JuryDecision::Inconclusive;
        assert_eq!(
            verify_vote(&verifying_key, &vote),
            Err(VoteError::SignatureInvalid)
        );
    }

    #[test]
    fn vote_dht_key_is_domain_separated() {
        let complaint_id = [1; 32];
        let evidence_hash = [2; 32];
        let juror_node_id = [3; 32];
        let vote_key = vote_dht_key(&complaint_id, &evidence_hash, &juror_node_id);
        assert_ne!(
            vote_key,
            partial_dht_key(&complaint_id, &evidence_hash, &juror_node_id)
        );
        assert_ne!(vote_key, commitment_dht_key(&complaint_id, &juror_node_id));
    }
}
