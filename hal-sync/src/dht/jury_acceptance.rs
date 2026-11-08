//! Signed opt-in and deterministic DKG share-index assignment for jury members.

use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::arbitrator_pool::Candidate;
use crate::dht::jury_dkg_commitment::JURY_PARTICIPANTS;
use crate::dht::NodeId;

pub const ACCEPTANCE_DOMAIN: &[u8] = b"HAL-JURY-ACCEPTANCE-v1\0";
pub const ACCEPTANCE_TTL_SECS: u64 = 90 * 24 * 3600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JuryAcceptanceRecord {
    #[serde(with = "bytes32_serde")]
    pub complaint_id: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub juror_node_id: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub juror_public_key: [u8; 32],
    pub share_index: u32,
    pub accepted_at: u64,
    #[serde(with = "bytes64_serde")]
    pub signature: [u8; 64],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AcceptanceError {
    #[error("share index must be in 1..=7")]
    InvalidShareIndex,
    #[error("juror binding mismatch")]
    JurorBindingMismatch,
    #[error("invalid juror public key")]
    InvalidPublicKey,
    #[error("signature invalid")]
    InvalidSignature,
    #[error("wrong jury size")]
    WrongJurySize,
    #[error("duplicate juror in jury candidate set")]
    DuplicateJuror,
}

fn canonical_bytes(record: &JuryAcceptanceRecord) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ACCEPTANCE_DOMAIN.len() + 32 + 32 + 32 + 4 + 8);
    bytes.extend_from_slice(ACCEPTANCE_DOMAIN);
    bytes.extend_from_slice(&record.complaint_id);
    bytes.extend_from_slice(&record.juror_node_id);
    bytes.extend_from_slice(&record.juror_public_key);
    bytes.extend_from_slice(&record.share_index.to_be_bytes());
    bytes.extend_from_slice(&record.accepted_at.to_be_bytes());
    bytes
}

pub fn sign_acceptance(
    signing_key: &SigningKey,
    complaint_id: [u8; 32],
    share_index: u32,
    accepted_at: u64,
) -> Result<JuryAcceptanceRecord, AcceptanceError> {
    if share_index == 0 || share_index > JURY_PARTICIPANTS {
        return Err(AcceptanceError::InvalidShareIndex);
    }
    let juror_public_key = signing_key.verifying_key().to_bytes();
    let juror_node_id: [u8; 32] = Sha256::digest(juror_public_key).into();
    let mut record = JuryAcceptanceRecord {
        complaint_id,
        juror_node_id,
        juror_public_key,
        share_index,
        accepted_at,
        signature: [0; 64],
    };
    record.signature = signing_key.sign(&canonical_bytes(&record)).to_bytes();
    Ok(record)
}

pub fn verify_acceptance(record: &JuryAcceptanceRecord) -> Result<(), AcceptanceError> {
    if record.share_index == 0 || record.share_index > JURY_PARTICIPANTS {
        return Err(AcceptanceError::InvalidShareIndex);
    }
    let computed: [u8; 32] = Sha256::digest(record.juror_public_key).into();
    if computed != record.juror_node_id {
        return Err(AcceptanceError::JurorBindingMismatch);
    }
    let verifying_key = VerifyingKey::from_bytes(&record.juror_public_key)
        .map_err(|_| AcceptanceError::InvalidPublicKey)?;
    verifying_key
        .verify_strict(
            &canonical_bytes(record),
            &Signature::from_bytes(&record.signature),
        )
        .map_err(|_| AcceptanceError::InvalidSignature)
}

pub fn acceptance_dht_key(complaint_id: &[u8; 32], juror_node_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ACCEPTANCE_DOMAIN);
    hasher.update(complaint_id);
    hasher.update(juror_node_id);
    hasher.finalize().into()
}

pub fn verify_share_index_against_pool(
    record: &JuryAcceptanceRecord,
    pool_tie_breakers: &[(NodeId, [u8; 32])],
) -> Result<(), AcceptanceError> {
    if pool_tie_breakers.len() != JURY_PARTICIPANTS as usize {
        return Err(AcceptanceError::WrongJurySize);
    }
    let mut sorted = pool_tie_breakers.to_vec();
    sorted.sort_by(|left, right| {
        left.1
            .cmp(&right.1)
            .then_with(|| left.0.as_bytes().cmp(right.0.as_bytes()))
    });
    let mut unique_nodes = HashSet::with_capacity(sorted.len());
    if sorted
        .iter()
        .any(|(node_id, _)| !unique_nodes.insert(*node_id))
    {
        return Err(AcceptanceError::DuplicateJuror);
    }
    let juror = NodeId::from_bytes(record.juror_node_id);
    match sorted.iter().position(|(node_id, _)| *node_id == juror) {
        Some(position) if record.share_index == position as u32 + 1 => Ok(()),
        _ => Err(AcceptanceError::InvalidShareIndex),
    }
}

/// Assign share indices 1..=7 by ascending tie-breaker, then ascending node ID.
pub fn assign_share_indices(
    candidates: &[Candidate],
) -> Result<HashMap<NodeId, u32>, AcceptanceError> {
    if candidates.len() != JURY_PARTICIPANTS as usize {
        return Err(AcceptanceError::WrongJurySize);
    }
    let mut sorted = candidates.to_vec();
    sorted.sort_by(|left, right| {
        left.tie_breaker
            .cmp(&right.tie_breaker)
            .then_with(|| left.node_id.as_bytes().cmp(right.node_id.as_bytes()))
    });
    let mut out = HashMap::with_capacity(sorted.len());
    for (index, candidate) in sorted.iter().enumerate() {
        if out.insert(candidate.node_id, index as u32 + 1).is_some() {
            return Err(AcceptanceError::DuplicateJuror);
        }
    }
    Ok(out)
}

mod bytes32_serde {
    use super::*;

    pub fn serialize<S: Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        value.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|bytes: Vec<u8>| serde::de::Error::invalid_length(bytes.len(), &"32 bytes"))
    }
}

mod bytes64_serde {
    use super::*;

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
    use crate::arbitrator_pool::ArbitratorCriteria;

    fn acceptance(index: u32) -> JuryAcceptanceRecord {
        sign_acceptance(&SigningKey::from_bytes(&[61; 32]), [62; 32], index, 100)
            .expect("sign acceptance")
    }

    fn candidates(seed: &[u8; 32]) -> (Vec<Candidate>, HashMap<NodeId, SigningKey>) {
        let criteria = ArbitratorCriteria {
            pol_full_ok: true,
            score_ok: true,
            no_active_guilty: true,
            governance_ok: true,
            phone_verified: false,
        };
        let mut keys = HashMap::with_capacity(7);
        let candidates = (1..=7)
            .map(|node| {
                let signing_key = SigningKey::from_bytes(&[node; 32]);
                let public_key = signing_key.verifying_key().to_bytes();
                let node_id = NodeId::from_bytes(Sha256::digest(public_key).into());
                keys.insert(node_id, signing_key);
                Candidate::new(node_id, criteria, seed)
            })
            .collect();
        (candidates, keys)
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        verify_acceptance(&acceptance(1)).expect("verify acceptance");
    }

    #[test]
    fn sign_rejects_index_zero() {
        assert_eq!(
            sign_acceptance(&SigningKey::from_bytes(&[1; 32]), [2; 32], 0, 10),
            Err(AcceptanceError::InvalidShareIndex)
        );
    }

    #[test]
    fn sign_rejects_index_eight() {
        assert_eq!(
            sign_acceptance(&SigningKey::from_bytes(&[1; 32]), [2; 32], 8, 10),
            Err(AcceptanceError::InvalidShareIndex)
        );
    }

    #[test]
    fn verify_rejects_juror_binding_mismatch() {
        let mut record = acceptance(1);
        record.juror_node_id[0] ^= 1;
        assert_eq!(
            verify_acceptance(&record),
            Err(AcceptanceError::JurorBindingMismatch)
        );
    }

    #[test]
    fn verify_rejects_tampered_complaint_id() {
        let mut record = acceptance(1);
        record.complaint_id[0] ^= 1;
        assert_eq!(
            verify_acceptance(&record),
            Err(AcceptanceError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_tampered_share_index() {
        let mut record = acceptance(1);
        record.share_index = 2;
        assert_eq!(
            verify_acceptance(&record),
            Err(AcceptanceError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let mut record = acceptance(1);
        record.signature[0] ^= 1;
        assert_eq!(
            verify_acceptance(&record),
            Err(AcceptanceError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_wrong_signing_key() {
        let mut record = acceptance(1);
        record.signature = SigningKey::from_bytes(&[63; 32])
            .sign(&canonical_bytes(&record))
            .to_bytes();
        assert_eq!(
            verify_acceptance(&record),
            Err(AcceptanceError::InvalidSignature)
        );
    }

    #[test]
    fn acceptance_dht_key_is_domain_separated() {
        let key = acceptance_dht_key(&[64; 32], &[65; 32]);
        let expected: [u8; 32] =
            Sha256::digest([ACCEPTANCE_DOMAIN, &[64; 32], &[65; 32]].concat()).into();
        assert_eq!(key, expected);
        let undomained: [u8; 32] = Sha256::digest([[64; 32], [65; 32]].concat()).into();
        assert_ne!(key, undomained);
    }

    #[test]
    fn acceptance_dht_key_deterministic() {
        assert_eq!(
            acceptance_dht_key(&[66; 32], &[67; 32]),
            acceptance_dht_key(&[66; 32], &[67; 32])
        );
    }

    #[test]
    fn verify_share_index_against_pool_correct() {
        let (pool, signing_keys) = candidates(&[68; 32]);
        let indices = assign_share_indices(&pool).expect("assign indices");
        let (juror, share_index) = indices.iter().next().expect("assigned juror");
        let record = sign_acceptance(
            signing_keys.get(juror).expect("juror signing key"),
            [69; 32],
            *share_index,
            100,
        )
        .expect("sign acceptance");
        let tie_breakers = pool
            .iter()
            .map(|candidate| (candidate.node_id, candidate.tie_breaker))
            .collect::<Vec<_>>();
        verify_share_index_against_pool(&record, &tie_breakers).expect("verify index");
    }

    #[test]
    fn verify_share_index_against_pool_rejects_wrong() {
        let (pool, signing_keys) = candidates(&[70; 32]);
        let indices = assign_share_indices(&pool).expect("assign indices");
        let (juror, share_index) = indices.iter().next().expect("assigned juror");
        let wrong_index = if *share_index == 1 { 2 } else { 1 };
        let record = sign_acceptance(
            signing_keys.get(juror).expect("juror signing key"),
            [71; 32],
            wrong_index,
            100,
        )
        .expect("sign acceptance");
        let tie_breakers = pool
            .iter()
            .map(|candidate| (candidate.node_id, candidate.tie_breaker))
            .collect::<Vec<_>>();
        assert_eq!(
            verify_share_index_against_pool(&record, &tie_breakers),
            Err(AcceptanceError::InvalidShareIndex)
        );
    }

    #[test]
    fn verify_share_index_against_pool_wrong_size() {
        assert_eq!(
            verify_share_index_against_pool(&acceptance(1), &[]),
            Err(AcceptanceError::WrongJurySize)
        );
    }

    #[test]
    fn assign_share_indices_deterministic() {
        let (pool, _) = candidates(&[72; 32]);
        assert_eq!(
            assign_share_indices(&pool).expect("first assignment"),
            assign_share_indices(&pool).expect("second assignment")
        );
    }

    #[test]
    fn canonical_bytes_layout_stable() {
        let record = acceptance(5);
        let bytes = canonical_bytes(&record);
        let prefix = ACCEPTANCE_DOMAIN.len();
        assert_eq!(bytes.len(), prefix + 32 + 32 + 32 + 4 + 8);
        assert_eq!(&bytes[..prefix], ACCEPTANCE_DOMAIN);
        assert_eq!(&bytes[prefix..prefix + 32], &record.complaint_id);
        assert_eq!(&bytes[prefix + 32..prefix + 64], &record.juror_node_id);
        assert_eq!(&bytes[prefix + 64..prefix + 96], &record.juror_public_key);
        assert_eq!(
            &bytes[prefix + 96..prefix + 100],
            &record.share_index.to_be_bytes()
        );
        assert_eq!(&bytes[prefix + 100..], &record.accepted_at.to_be_bytes());
    }
}
