//! Signed public Feldman commitments for the jury DKG.
//!
//! Round 1 commitments are published in DHT. Round 2 shares use the direct
//! channel and must never be published here.

use curve25519_dalek::ristretto::CompressedRistretto;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

pub const COMMIT_DOMAIN: &[u8] = b"HAL-JURY-DKG-COMMIT-v1\0";
pub const PARTIAL_DOMAIN: &[u8] = b"hal.jury.partial.v1";
pub const JURY_THRESHOLD: u32 = 5;
pub const JURY_PARTICIPANTS: u32 = 7;
pub const JURY_DKG_COMMITMENT_TTL_SECS: u64 = 90 * 24 * 3600;
pub const JURY_PARTIAL_TTL_SECS: u64 = 7 * 86400;

/// Signed public Feldman commitments for one dealer and complaint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JuryDkgCommitmentRecord {
    #[serde(with = "bytes32_serde")]
    pub complaint_id: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub dealer_node_id: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub dealer_public_key: [u8; 32],
    pub commitments: Vec<[u8; 32]>,
    pub threshold: u32,
    pub participant_count: u32,
    pub published_at: u64,
    #[serde(with = "bytes64_serde")]
    pub signature: [u8; 64],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JuryDkgCommitmentError {
    #[error("commitment count must equal threshold")]
    InvalidCommitmentCount,
    #[error("threshold must be {JURY_THRESHOLD}")]
    InvalidThreshold,
    #[error("participant_count must be {JURY_PARTICIPANTS}")]
    InvalidParticipantCount,
    #[error("dealer binding mismatch")]
    DealerBindingMismatch,
    #[error("invalid dealer public key")]
    InvalidPublicKey,
    #[error("invalid compressed Ristretto commitment")]
    InvalidCommitmentPoint,
    #[error("signature invalid")]
    InvalidSignature,
}

fn canonical_bytes(record: &JuryDkgCommitmentRecord) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        COMMIT_DOMAIN.len() + 32 + 32 + 32 + 4 + 4 + 8 + 4 + 32 * JURY_THRESHOLD as usize,
    );
    bytes.extend_from_slice(COMMIT_DOMAIN);
    bytes.extend_from_slice(&record.complaint_id);
    bytes.extend_from_slice(&record.dealer_node_id);
    bytes.extend_from_slice(&record.dealer_public_key);
    bytes.extend_from_slice(&record.threshold.to_be_bytes());
    bytes.extend_from_slice(&record.participant_count.to_be_bytes());
    bytes.extend_from_slice(&record.published_at.to_be_bytes());
    let commitment_count = u32::try_from(record.commitments.len()).unwrap_or(u32::MAX);
    bytes.extend_from_slice(&commitment_count.to_be_bytes());
    for commitment in &record.commitments {
        bytes.extend_from_slice(commitment);
    }
    bytes
}

/// Sign a record containing exactly five valid compressed Ristretto points.
pub fn sign_commitment(
    signing_key: &SigningKey,
    complaint_id: [u8; 32],
    commitments: Vec<[u8; 32]>,
    published_at: u64,
) -> Result<JuryDkgCommitmentRecord, JuryDkgCommitmentError> {
    if commitments.len() != JURY_THRESHOLD as usize {
        return Err(JuryDkgCommitmentError::InvalidCommitmentCount);
    }
    if commitments
        .iter()
        .any(|bytes| CompressedRistretto(*bytes).decompress().is_none())
    {
        return Err(JuryDkgCommitmentError::InvalidCommitmentPoint);
    }

    let dealer_public_key = signing_key.verifying_key().to_bytes();
    let dealer_node_id: [u8; 32] = Sha256::digest(dealer_public_key).into();
    let mut record = JuryDkgCommitmentRecord {
        complaint_id,
        dealer_node_id,
        dealer_public_key,
        commitments,
        threshold: JURY_THRESHOLD,
        participant_count: JURY_PARTICIPANTS,
        published_at,
        signature: [0; 64],
    };
    record.signature = signing_key.sign(&canonical_bytes(&record)).to_bytes();
    Ok(record)
}

/// Validate fixed jury parameters, point encodings, dealer binding, and signature.
pub fn verify_commitment(record: &JuryDkgCommitmentRecord) -> Result<(), JuryDkgCommitmentError> {
    if record.threshold != JURY_THRESHOLD {
        return Err(JuryDkgCommitmentError::InvalidThreshold);
    }
    if record.participant_count != JURY_PARTICIPANTS {
        return Err(JuryDkgCommitmentError::InvalidParticipantCount);
    }
    if record.commitments.len() != record.threshold as usize {
        return Err(JuryDkgCommitmentError::InvalidCommitmentCount);
    }
    if record
        .commitments
        .iter()
        .any(|bytes| CompressedRistretto(*bytes).decompress().is_none())
    {
        return Err(JuryDkgCommitmentError::InvalidCommitmentPoint);
    }

    let computed_node_id: [u8; 32] = Sha256::digest(record.dealer_public_key).into();
    if computed_node_id != record.dealer_node_id {
        return Err(JuryDkgCommitmentError::DealerBindingMismatch);
    }
    let verifying_key = VerifyingKey::from_bytes(&record.dealer_public_key)
        .map_err(|_| JuryDkgCommitmentError::InvalidPublicKey)?;
    verifying_key
        .verify_strict(
            &canonical_bytes(record),
            &Signature::from_bytes(&record.signature),
        )
        .map_err(|_| JuryDkgCommitmentError::InvalidSignature)
}

/// DHT key = SHA256(COMMIT_DOMAIN || complaint_id || dealer_node_id).
pub fn commitment_dht_key(complaint_id: &[u8; 32], dealer_node_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(COMMIT_DOMAIN);
    hasher.update(complaint_id);
    hasher.update(dealer_node_id);
    hasher.finalize().into()
}

pub fn partial_dht_key(
    complaint_id: &[u8; 32],
    evidence_hash: &[u8; 32],
    juror_node_id: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PARTIAL_DOMAIN);
    hasher.update(complaint_id);
    hasher.update(evidence_hash);
    hasher.update(juror_node_id);
    hasher.finalize().into()
}

mod bytes32_serde {
    use super::*;

    pub fn serialize<S: Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        value.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        bytes.try_into().map_err(|bytes: Vec<u8>| {
            serde::de::Error::invalid_length(bytes.len(), &"32-byte array")
        })
    }
}

mod bytes64_serde {
    use super::*;

    pub fn serialize<S: Serializer>(value: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        value.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        bytes.try_into().map_err(|bytes: Vec<u8>| {
            serde::de::Error::invalid_length(bytes.len(), &"64-byte array")
        })
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};

    use super::{
        canonical_bytes, commitment_dht_key, partial_dht_key, sign_commitment, verify_commitment,
        JuryDkgCommitmentError, JuryDkgCommitmentRecord, COMMIT_DOMAIN, JURY_PARTICIPANTS,
        JURY_THRESHOLD, PARTIAL_DOMAIN,
    };

    fn signed_record() -> JuryDkgCommitmentRecord {
        let key = SigningKey::from_bytes(&[41; 32]);
        let commitment = RISTRETTO_BASEPOINT_POINT.compress().to_bytes();
        sign_commitment(
            &key,
            [17; 32],
            vec![commitment; JURY_THRESHOLD as usize],
            100,
        )
        .expect("sign record")
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        verify_commitment(&signed_record()).expect("verify");
    }

    #[test]
    fn verify_rejects_wrong_commitment_count() {
        let mut record = signed_record();
        record.commitments.push(record.commitments[0]);
        assert_eq!(
            verify_commitment(&record),
            Err(JuryDkgCommitmentError::InvalidCommitmentCount)
        );
    }

    #[test]
    fn verify_rejects_wrong_threshold() {
        let mut record = signed_record();
        record.threshold = 4;
        assert_eq!(
            verify_commitment(&record),
            Err(JuryDkgCommitmentError::InvalidThreshold)
        );
    }

    #[test]
    fn verify_rejects_wrong_participant_count() {
        let mut record = signed_record();
        record.participant_count = 8;
        assert_eq!(
            verify_commitment(&record),
            Err(JuryDkgCommitmentError::InvalidParticipantCount)
        );
    }

    #[test]
    fn verify_rejects_dealer_binding_mismatch() {
        let mut record = signed_record();
        record.dealer_node_id[0] ^= 1;
        assert_eq!(
            verify_commitment(&record),
            Err(JuryDkgCommitmentError::DealerBindingMismatch)
        );
    }

    #[test]
    fn verify_rejects_tampered_complaint_id() {
        let mut record = signed_record();
        record.complaint_id[0] ^= 1;
        assert_eq!(
            verify_commitment(&record),
            Err(JuryDkgCommitmentError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_tampered_commitments() {
        let mut record = signed_record();
        record.commitments[0][0] ^= 1;
        assert!(verify_commitment(&record).is_err());
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let mut record = signed_record();
        record.signature[0] ^= 1;
        assert_eq!(
            verify_commitment(&record),
            Err(JuryDkgCommitmentError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_invalid_compressed_commitment() {
        let mut record = signed_record();
        record.commitments[0] = [0xff; 32];
        assert_eq!(
            verify_commitment(&record),
            Err(JuryDkgCommitmentError::InvalidCommitmentPoint)
        );
    }

    #[test]
    fn sign_rejects_wrong_commitment_count() {
        let key = SigningKey::from_bytes(&[42; 32]);
        assert_eq!(
            sign_commitment(&key, [1; 32], vec![], 100).err(),
            Some(JuryDkgCommitmentError::InvalidCommitmentCount)
        );
    }

    #[test]
    fn commitment_dht_key_is_domain_separated() {
        assert_ne!(commitment_dht_key(&[1; 32], &[2; 32]), [1; 32]);
        assert_ne!(
            commitment_dht_key(&[1; 32], &[2; 32]),
            commitment_dht_key(&[1; 32], &[3; 32])
        );
        assert_ne!(
            commitment_dht_key(&[1; 32], &[2; 32]),
            commitment_dht_key(&[3; 32], &[2; 32])
        );
    }

    #[test]
    fn commitment_dht_key_deterministic() {
        assert_eq!(
            commitment_dht_key(&[4; 32], &[5; 32]),
            commitment_dht_key(&[4; 32], &[5; 32])
        );
    }

    #[test]
    fn canonical_bytes_layout_is_stable() {
        let record = signed_record();
        let bytes = canonical_bytes(&record);
        let count_offset = COMMIT_DOMAIN.len() + 32 * 3 + 4 + 4 + 8;
        let commitments_offset = count_offset + 4;
        let expected_len = commitments_offset + 32 * JURY_THRESHOLD as usize;
        assert_eq!(bytes.len(), expected_len);
        assert_eq!(&bytes[..COMMIT_DOMAIN.len()], COMMIT_DOMAIN);
        assert_eq!(
            &bytes[COMMIT_DOMAIN.len()..COMMIT_DOMAIN.len() + 32],
            &record.complaint_id
        );
        assert_eq!(
            &bytes[COMMIT_DOMAIN.len() + 32..COMMIT_DOMAIN.len() + 64],
            &record.dealer_node_id
        );
        assert_eq!(
            &bytes[COMMIT_DOMAIN.len() + 64..COMMIT_DOMAIN.len() + 96],
            &record.dealer_public_key
        );
        let threshold_offset = COMMIT_DOMAIN.len() + 32 * 3;
        let participants_offset = threshold_offset + 4;
        let published_at_offset = participants_offset + 4;
        assert_eq!(
            &bytes[threshold_offset..participants_offset],
            &record.threshold.to_be_bytes()
        );
        assert_eq!(
            &bytes[participants_offset..published_at_offset],
            &record.participant_count.to_be_bytes()
        );
        assert_eq!(
            &bytes[published_at_offset..count_offset],
            &record.published_at.to_be_bytes()
        );
        assert_eq!(
            &bytes[count_offset..commitments_offset],
            &(JURY_THRESHOLD as u32).to_be_bytes()
        );
        for (index, commitment) in record.commitments.iter().enumerate() {
            let start = commitments_offset + index * 32;
            assert_eq!(&bytes[start..start + 32], commitment);
        }
    }

    #[test]
    fn record_serialization_roundtrip() {
        let record = signed_record();
        let encoded = serde_json::to_vec(&record).expect("serialize");
        let decoded: JuryDkgCommitmentRecord =
            serde_json::from_slice(&encoded).expect("deserialize");
        assert_eq!(decoded, record);
    }

    #[test]
    fn key_depends_on_domain_prefix() {
        let expected: [u8; 32] =
            Sha256::digest([COMMIT_DOMAIN, &[6; 32], &[7; 32]].concat()).into();
        assert_eq!(commitment_dht_key(&[6; 32], &[7; 32]), expected);
        assert_eq!(JURY_THRESHOLD, 5);
        assert_eq!(JURY_PARTICIPANTS, 7);
    }

    #[test]
    fn partial_dht_key_is_domain_separated() {
        let key = partial_dht_key(&[1; 32], &[2; 32], &[3; 32]);
        let commitment_key = commitment_dht_key(&[1; 32], &[2; 32]);
        let unprefixed: [u8; 32] = Sha256::digest([[1; 32], [2; 32], [3; 32]].concat()).into();
        let expected: [u8; 32] =
            Sha256::digest([PARTIAL_DOMAIN, &[1; 32], &[2; 32], &[3; 32]].concat()).into();
        assert_eq!(key, expected);
        assert_ne!(key, commitment_key);
        assert_ne!(key, unprefixed);
    }
}
