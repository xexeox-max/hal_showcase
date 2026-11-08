//! ComplaintRecord — public complaint metadata.
//!
//! Schema: docs/EVIDENCE_AND_JURY.md §5. Public metadata only; evidence is not
//! included in the record.

use curve25519_dalek::ristretto::CompressedRistretto;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

pub const COMPLAINT_DOMAIN: &[u8] = b"HAL-COMPLAINT-v1\0";
pub const COMPLAINT_TTL_SECS: u64 = 365 * 24 * 3600;
pub const MAX_COMPLAINT_PERIOD_SECS: u64 = 180 * 24 * 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComplaintKind {
    Csam,
    Terror,
    Fraud,
    Abuse,
}

impl ComplaintKind {
    pub fn tag(self) -> u8 {
        match self {
            Self::Csam => 1,
            Self::Terror => 2,
            Self::Fraud => 3,
            Self::Abuse => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplaintRecord {
    #[serde(with = "bytes32_serde")]
    pub complaint_id: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub complainant_node_id: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub complainant_public_key: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub subject_node_id: [u8; 32],
    pub kind: ComplaintKind,
    pub period_start: u64,
    pub period_end: u64,
    pub submitted_at: u64,
    #[serde(with = "bytes64_serde")]
    pub signature: [u8; 64],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ComplaintError {
    #[error("complaint complainant binding mismatch")]
    ComplainantBindingMismatch,
    #[error("invalid complainant public key")]
    InvalidPublicKey,
    #[error("period_start must be <= period_end")]
    InvalidPeriod,
    #[error("period too large (max 180 days)")]
    PeriodTooLong,
    #[error("complaint_id does not match canonical payload")]
    ComplaintIdMismatch,
    #[error("signature invalid")]
    InvalidSignature,
    #[error("insufficient DKG commitments to compute jury pubkey")]
    InsufficientCommitments,
    #[error("DKG commitments invalid")]
    InvalidCommitments,
}

fn canonical_bytes_unsigned(record: &ComplaintRecord) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(COMPLAINT_DOMAIN.len() + 32 * 3 + 1 + 8 + 8 + 8);
    bytes.extend_from_slice(COMPLAINT_DOMAIN);
    bytes.extend_from_slice(&record.complainant_node_id);
    bytes.extend_from_slice(&record.complainant_public_key);
    bytes.extend_from_slice(&record.subject_node_id);
    bytes.push(record.kind.tag());
    bytes.extend_from_slice(&record.period_start.to_be_bytes());
    bytes.extend_from_slice(&record.period_end.to_be_bytes());
    bytes.extend_from_slice(&record.submitted_at.to_be_bytes());
    bytes
}

fn compute_complaint_id(unsigned_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"HAL-COMPLAINT-ID-v1\0");
    hasher.update(unsigned_bytes);
    hasher.finalize().into()
}

pub fn create_complaint(
    signing_key: &SigningKey,
    subject_node_id: [u8; 32],
    kind: ComplaintKind,
    period_start: u64,
    period_end: u64,
    submitted_at: u64,
) -> Result<ComplaintRecord, ComplaintError> {
    if period_start > period_end {
        return Err(ComplaintError::InvalidPeriod);
    }
    if period_end - period_start > MAX_COMPLAINT_PERIOD_SECS {
        return Err(ComplaintError::PeriodTooLong);
    }

    let complainant_public_key = signing_key.verifying_key().to_bytes();
    let complainant_node_id: [u8; 32] = Sha256::digest(complainant_public_key).into();
    let mut record = ComplaintRecord {
        complaint_id: [0; 32],
        complainant_node_id,
        complainant_public_key,
        subject_node_id,
        kind,
        period_start,
        period_end,
        submitted_at,
        signature: [0; 64],
    };
    let unsigned = canonical_bytes_unsigned(&record);
    record.complaint_id = compute_complaint_id(&unsigned);
    record.signature = signing_key.sign(&unsigned).to_bytes();
    Ok(record)
}

pub fn verify_complaint(record: &ComplaintRecord) -> Result<(), ComplaintError> {
    if record.period_start > record.period_end {
        return Err(ComplaintError::InvalidPeriod);
    }
    if record.period_end - record.period_start > MAX_COMPLAINT_PERIOD_SECS {
        return Err(ComplaintError::PeriodTooLong);
    }
    let computed_node: [u8; 32] = Sha256::digest(record.complainant_public_key).into();
    if computed_node != record.complainant_node_id {
        return Err(ComplaintError::ComplainantBindingMismatch);
    }
    let unsigned = canonical_bytes_unsigned(record);
    if compute_complaint_id(&unsigned) != record.complaint_id {
        return Err(ComplaintError::ComplaintIdMismatch);
    }
    let verifying_key = VerifyingKey::from_bytes(&record.complainant_public_key)
        .map_err(|_| ComplaintError::InvalidPublicKey)?;
    verifying_key
        .verify_strict(&unsigned, &Signature::from_bytes(&record.signature))
        .map_err(|_| ComplaintError::InvalidSignature)
}

pub fn complaint_dht_key(complaint_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(COMPLAINT_DOMAIN);
    hasher.update(complaint_id);
    hasher.finalize().into()
}

/// Compute the jury public key by summing the constant commitments of all seven dealers.
pub fn compute_jury_pubkey_from_commitments(
    commitments: &[crate::dht::jury_dkg_commitment::JuryDkgCommitmentRecord],
) -> Result<CompressedRistretto, ComplaintError> {
    use crate::dht::jury_dkg_commitment::JURY_PARTICIPANTS;
    use std::collections::HashSet;

    if commitments.len() != JURY_PARTICIPANTS as usize {
        return Err(ComplaintError::InsufficientCommitments);
    }
    let first = &commitments[0];
    let mut dealers = HashSet::with_capacity(commitments.len());
    for record in commitments {
        if record.complaint_id != first.complaint_id {
            return Err(ComplaintError::ComplaintIdMismatch);
        }
        if !dealers.insert(record.dealer_node_id)
            || crate::dht::jury_dkg_commitment::verify_commitment(record).is_err()
        {
            return Err(ComplaintError::InvalidCommitments);
        }
    }
    let feldman: Vec<hal_crypto::vss::FeldmanCommitments> = commitments
        .iter()
        .map(|record| hal_crypto::vss::FeldmanCommitments {
            commitments: record
                .commitments
                .iter()
                .map(|bytes| CompressedRistretto(*bytes))
                .collect(),
            threshold: record.threshold,
            participant_count: record.participant_count,
        })
        .collect();
    hal_crypto::vss::combine_commitments_to_public_key(&feldman)
        .map_err(|_| ComplaintError::InvalidCommitments)
}

#[async_trait::async_trait]
pub trait DepositHook: Send + Sync {
    async fn reserve(
        &self,
        complainant_node_id: &[u8; 32],
        complaint_id: &[u8; 32],
    ) -> anyhow::Result<()>;
    async fn release(&self, complaint_id: &[u8; 32]) -> anyhow::Result<()>;
}

pub struct NoOpDepositHook;

#[async_trait::async_trait]
impl DepositHook for NoOpDepositHook {
    async fn reserve(
        &self,
        _complainant_node_id: &[u8; 32],
        _complaint_id: &[u8; 32],
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn release(&self, _complaint_id: &[u8; 32]) -> anyhow::Result<()> {
        Ok(())
    }
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
    use ed25519_dalek::Signer;

    fn test_record(key: &SigningKey, subject: [u8; 32], kind: ComplaintKind) -> ComplaintRecord {
        create_complaint(key, subject, kind, 100, 200, 300).expect("create complaint")
    }

    #[test]
    fn create_and_verify_roundtrip() {
        let record = test_record(
            &SigningKey::from_bytes(&[1; 32]),
            [2; 32],
            ComplaintKind::Fraud,
        );
        verify_complaint(&record).expect("verify complaint");
    }

    #[test]
    fn complaint_id_deterministic() {
        let key = SigningKey::from_bytes(&[3; 32]);
        assert_eq!(
            test_record(&key, [4; 32], ComplaintKind::Abuse).complaint_id,
            test_record(&key, [4; 32], ComplaintKind::Abuse).complaint_id
        );
    }

    #[test]
    fn complaint_id_differs_on_subject() {
        let key = SigningKey::from_bytes(&[5; 32]);
        assert_ne!(
            test_record(&key, [6; 32], ComplaintKind::Fraud).complaint_id,
            test_record(&key, [7; 32], ComplaintKind::Fraud).complaint_id
        );
    }

    #[test]
    fn create_rejects_invalid_period() {
        assert_eq!(
            create_complaint(
                &SigningKey::from_bytes(&[8; 32]),
                [9; 32],
                ComplaintKind::Fraud,
                101,
                100,
                200
            ),
            Err(ComplaintError::InvalidPeriod)
        );
    }

    #[test]
    fn create_rejects_period_too_long() {
        assert_eq!(
            create_complaint(
                &SigningKey::from_bytes(&[10; 32]),
                [11; 32],
                ComplaintKind::Fraud,
                0,
                MAX_COMPLAINT_PERIOD_SECS + 1,
                200
            ),
            Err(ComplaintError::PeriodTooLong)
        );
    }

    #[test]
    fn verify_rejects_complainant_binding_mismatch() {
        let mut record = test_record(
            &SigningKey::from_bytes(&[12; 32]),
            [13; 32],
            ComplaintKind::Fraud,
        );
        record.complainant_node_id[0] ^= 1;
        assert_eq!(
            verify_complaint(&record),
            Err(ComplaintError::ComplainantBindingMismatch)
        );
    }

    #[test]
    fn verify_rejects_complaint_id_mismatch() {
        let mut record = test_record(
            &SigningKey::from_bytes(&[14; 32]),
            [15; 32],
            ComplaintKind::Fraud,
        );
        record.complaint_id[0] ^= 1;
        assert_eq!(
            verify_complaint(&record),
            Err(ComplaintError::ComplaintIdMismatch)
        );
    }

    #[test]
    fn verify_rejects_tampered_subject() {
        let mut record = test_record(
            &SigningKey::from_bytes(&[16; 32]),
            [17; 32],
            ComplaintKind::Fraud,
        );
        record.subject_node_id[0] ^= 1;
        assert_eq!(
            verify_complaint(&record),
            Err(ComplaintError::ComplaintIdMismatch)
        );
    }

    #[test]
    fn verify_rejects_tampered_kind() {
        let mut record = test_record(
            &SigningKey::from_bytes(&[18; 32]),
            [19; 32],
            ComplaintKind::Fraud,
        );
        record.kind = ComplaintKind::Abuse;
        assert_eq!(
            verify_complaint(&record),
            Err(ComplaintError::ComplaintIdMismatch)
        );
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let mut record = test_record(
            &SigningKey::from_bytes(&[20; 32]),
            [21; 32],
            ComplaintKind::Fraud,
        );
        record.signature[0] ^= 1;
        assert_eq!(
            verify_complaint(&record),
            Err(ComplaintError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_wrong_signing_key() {
        let mut record = test_record(
            &SigningKey::from_bytes(&[22; 32]),
            [23; 32],
            ComplaintKind::Fraud,
        );
        let other_key = SigningKey::from_bytes(&[24; 32]);
        record.signature = other_key
            .sign(&canonical_bytes_unsigned(&record))
            .to_bytes();
        assert_eq!(
            verify_complaint(&record),
            Err(ComplaintError::InvalidSignature)
        );
    }

    #[test]
    fn complaint_dht_key_is_domain_separated() {
        let complaint_id = [25; 32];
        let key = complaint_dht_key(&complaint_id);
        let expected: [u8; 32] =
            Sha256::digest([COMPLAINT_DOMAIN, complaint_id.as_slice()].concat()).into();
        let unscoped: [u8; 32] = Sha256::digest(complaint_id).into();
        assert_eq!(key, expected);
        assert_ne!(key, unscoped);
    }

    #[tokio::test]
    async fn no_op_deposit_hook_always_succeeds() {
        let hook = NoOpDepositHook;
        assert!(hook.reserve(&[1; 32], &[2; 32]).await.is_ok());
        assert!(hook.release(&[2; 32]).await.is_ok());
    }

    #[test]
    fn canonical_bytes_unsigned_has_no_id_or_signature() {
        let record = test_record(
            &SigningKey::from_bytes(&[26; 32]),
            [27; 32],
            ComplaintKind::Terror,
        );
        let bytes = canonical_bytes_unsigned(&record);
        let offsets = [
            0,
            COMPLAINT_DOMAIN.len(),
            COMPLAINT_DOMAIN.len() + 32,
            COMPLAINT_DOMAIN.len() + 64,
            COMPLAINT_DOMAIN.len() + 96,
            COMPLAINT_DOMAIN.len() + 97,
            COMPLAINT_DOMAIN.len() + 105,
            COMPLAINT_DOMAIN.len() + 113,
            COMPLAINT_DOMAIN.len() + 121,
        ];
        let expected_length = COMPLAINT_DOMAIN.len() + 121;
        assert_eq!(bytes.len(), expected_length);
        assert_eq!(&bytes[offsets[0]..offsets[1]], COMPLAINT_DOMAIN);
        assert_eq!(&bytes[offsets[1]..offsets[2]], &record.complainant_node_id);
        assert_eq!(
            &bytes[offsets[2]..offsets[3]],
            &record.complainant_public_key
        );
        assert_eq!(&bytes[offsets[3]..offsets[4]], &record.subject_node_id);
        assert_eq!(bytes[offsets[4]], record.kind.tag());
        assert_eq!(
            &bytes[offsets[5]..offsets[6]],
            &record.period_start.to_be_bytes()
        );
        assert_eq!(
            &bytes[offsets[6]..offsets[7]],
            &record.period_end.to_be_bytes()
        );
        assert_eq!(
            &bytes[offsets[7]..offsets[8]],
            &record.submitted_at.to_be_bytes()
        );
    }

    #[test]
    fn compute_jury_pubkey_from_commitments_full_set() {
        use crate::dht::jury_dkg_commitment::{sign_commitment, JURY_THRESHOLD};
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

        let point = RISTRETTO_BASEPOINT_POINT.compress().to_bytes();
        let commitments: Vec<_> = (0..7)
            .map(|seed| {
                sign_commitment(
                    &SigningKey::from_bytes(&[seed + 40; 32]),
                    [77; 32],
                    vec![point; JURY_THRESHOLD as usize],
                    100,
                )
                .expect("sign commitment")
            })
            .collect();
        let first = compute_jury_pubkey_from_commitments(&commitments).expect("compute Y");
        let second = compute_jury_pubkey_from_commitments(&commitments).expect("compute Y again");
        assert_eq!(first, second);
        assert_eq!(
            first,
            (RISTRETTO_BASEPOINT_POINT * curve25519_dalek::scalar::Scalar::from(7u64)).compress()
        );
    }

    #[test]
    fn compute_jury_pubkey_rejects_insufficient() {
        use crate::dht::jury_dkg_commitment::{sign_commitment, JURY_THRESHOLD};
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

        let point = RISTRETTO_BASEPOINT_POINT.compress().to_bytes();
        let commitments: Vec<_> = (0..6)
            .map(|seed| {
                sign_commitment(
                    &SigningKey::from_bytes(&[seed + 50; 32]),
                    [78; 32],
                    vec![point; JURY_THRESHOLD as usize],
                    100,
                )
                .expect("sign commitment")
            })
            .collect();
        assert_eq!(
            compute_jury_pubkey_from_commitments(&commitments),
            Err(ComplaintError::InsufficientCommitments)
        );
    }
}
