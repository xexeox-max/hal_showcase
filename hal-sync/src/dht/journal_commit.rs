//! Signed Merkle-root commitments for the local journal.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

pub const COMMIT_DOMAIN: &[u8] = b"HAL-JOURNAL-COMMIT-v1\0";
pub const POINTER_DOMAIN: &[u8] = b"HAL-JOURNAL-POINTER-v1\0";
pub const JOURNAL_COMMIT_TTL_SECS: u64 = 90 * 24 * 3600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalCommit {
    pub sequence: u64,
    #[serde(with = "bytes32_serde")]
    pub root: [u8; 32],
    pub leaf_count: u64,
    pub published_at: u64,
    #[serde(with = "bytes32_serde")]
    pub issuer_node_id: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub issuer_public_key: [u8; 32],
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalCommitPointer {
    #[serde(with = "bytes32_serde")]
    pub issuer_node_id: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub issuer_public_key: [u8; 32],
    pub latest_sequence: u64,
    pub published_at: u64,
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JournalCommitError {
    #[error("journal commit sequence must be > 0")]
    InvalidSequence,
    #[error("journal commit issuer binding mismatch")]
    IssuerBindingMismatch,
    #[error("invalid issuer public key")]
    InvalidPublicKey,
    #[error("journal commit signature invalid")]
    InvalidSignature,
}

fn canonical_bytes(commit: &JournalCommit) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(COMMIT_DOMAIN.len() + 8 + 32 + 8 + 8 + 32);
    bytes.extend_from_slice(COMMIT_DOMAIN);
    bytes.extend_from_slice(&commit.sequence.to_be_bytes());
    bytes.extend_from_slice(&commit.root);
    bytes.extend_from_slice(&commit.leaf_count.to_be_bytes());
    bytes.extend_from_slice(&commit.published_at.to_be_bytes());
    bytes.extend_from_slice(&commit.issuer_node_id);
    bytes
}

fn canonical_pointer_bytes(pointer: &JournalCommitPointer) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(POINTER_DOMAIN.len() + 32 + 8 + 8);
    bytes.extend_from_slice(POINTER_DOMAIN);
    bytes.extend_from_slice(&pointer.issuer_node_id);
    bytes.extend_from_slice(&pointer.latest_sequence.to_be_bytes());
    bytes.extend_from_slice(&pointer.published_at.to_be_bytes());
    bytes
}

pub fn sign_commit(
    signing_key: &SigningKey,
    sequence: u64,
    root: [u8; 32],
    leaf_count: u64,
    published_at: u64,
) -> JournalCommit {
    let issuer_public_key = signing_key.verifying_key().to_bytes();
    let issuer_node_id: [u8; 32] = Sha256::digest(issuer_public_key).into();
    let mut commit = JournalCommit {
        sequence,
        root,
        leaf_count,
        published_at,
        issuer_node_id,
        issuer_public_key,
        signature: [0; 64],
    };
    commit.signature = signing_key.sign(&canonical_bytes(&commit)).to_bytes();
    commit
}

pub fn verify_commit(commit: &JournalCommit) -> Result<(), JournalCommitError> {
    if commit.sequence == 0 {
        return Err(JournalCommitError::InvalidSequence);
    }
    let computed: [u8; 32] = Sha256::digest(commit.issuer_public_key).into();
    if computed != commit.issuer_node_id {
        return Err(JournalCommitError::IssuerBindingMismatch);
    }
    let verifying_key = VerifyingKey::from_bytes(&commit.issuer_public_key)
        .map_err(|_| JournalCommitError::InvalidPublicKey)?;
    verifying_key
        .verify_strict(
            &canonical_bytes(commit),
            &Signature::from_bytes(&commit.signature),
        )
        .map_err(|_| JournalCommitError::InvalidSignature)
}

pub fn sign_pointer(
    signing_key: &SigningKey,
    latest_sequence: u64,
    published_at: u64,
) -> JournalCommitPointer {
    let issuer_public_key = signing_key.verifying_key().to_bytes();
    let issuer_node_id: [u8; 32] = Sha256::digest(issuer_public_key).into();
    let mut pointer = JournalCommitPointer {
        issuer_node_id,
        issuer_public_key,
        latest_sequence,
        published_at,
        signature: [0; 64],
    };
    pointer.signature = signing_key
        .sign(&canonical_pointer_bytes(&pointer))
        .to_bytes();
    pointer
}

pub fn verify_pointer(pointer: &JournalCommitPointer) -> Result<(), JournalCommitError> {
    if pointer.latest_sequence == 0 {
        return Err(JournalCommitError::InvalidSequence);
    }
    let computed: [u8; 32] = Sha256::digest(pointer.issuer_public_key).into();
    if computed != pointer.issuer_node_id {
        return Err(JournalCommitError::IssuerBindingMismatch);
    }
    let verifying_key = VerifyingKey::from_bytes(&pointer.issuer_public_key)
        .map_err(|_| JournalCommitError::InvalidPublicKey)?;
    verifying_key
        .verify_strict(
            &canonical_pointer_bytes(pointer),
            &Signature::from_bytes(&pointer.signature),
        )
        .map_err(|_| JournalCommitError::InvalidSignature)
}

pub fn commit_dht_key(issuer_node_id: &[u8; 32], sequence: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(COMMIT_DOMAIN);
    hasher.update(issuer_node_id);
    hasher.update(sequence.to_be_bytes());
    hasher.finalize().into()
}

pub fn latest_dht_key(issuer_node_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(POINTER_DOMAIN);
    hasher.update(issuer_node_id);
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

mod signature_serde {
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
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn valid_commit() -> JournalCommit {
        sign_commit(&key(1), 1, [2; 32], 3, 4)
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        assert_eq!(verify_commit(&valid_commit()), Ok(()));
    }

    #[test]
    fn sign_binds_issuer_node_id_to_pubkey() {
        let commit = valid_commit();
        let expected: [u8; 32] = Sha256::digest(commit.issuer_public_key).into();
        assert_eq!(commit.issuer_node_id, expected);
    }

    #[test]
    fn verify_rejects_zero_sequence() {
        let mut commit = sign_commit(&key(1), 0, [2; 32], 3, 4);
        commit.sequence = 0;
        assert_eq!(
            verify_commit(&commit),
            Err(JournalCommitError::InvalidSequence)
        );
    }

    #[test]
    fn verify_rejects_pubkey_binding_mismatch() {
        let mut commit = valid_commit();
        commit.issuer_node_id[0] ^= 1;
        assert_eq!(
            verify_commit(&commit),
            Err(JournalCommitError::IssuerBindingMismatch)
        );
    }

    #[test]
    fn verify_rejects_tampered_root() {
        let mut commit = valid_commit();
        commit.root[0] ^= 1;
        assert_eq!(
            verify_commit(&commit),
            Err(JournalCommitError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_tampered_sequence() {
        let mut commit = valid_commit();
        commit.sequence += 1;
        assert_eq!(
            verify_commit(&commit),
            Err(JournalCommitError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_tampered_leaf_count() {
        let mut commit = valid_commit();
        commit.leaf_count += 1;
        assert_eq!(
            verify_commit(&commit),
            Err(JournalCommitError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_tampered_published_at() {
        let mut commit = valid_commit();
        commit.published_at += 1;
        assert_eq!(
            verify_commit(&commit),
            Err(JournalCommitError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let mut commit = valid_commit();
        commit.signature[0] ^= 1;
        assert_eq!(
            verify_commit(&commit),
            Err(JournalCommitError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_wrong_signing_key() {
        let mut commit = valid_commit();
        commit.signature = key(9).sign(&canonical_bytes(&commit)).to_bytes();
        assert_eq!(
            verify_commit(&commit),
            Err(JournalCommitError::InvalidSignature)
        );
    }

    #[test]
    fn canonical_payload_matches_spec() {
        let commit = valid_commit();
        let mut expected = COMMIT_DOMAIN.to_vec();
        expected.extend_from_slice(&commit.sequence.to_be_bytes());
        expected.extend_from_slice(&commit.root);
        expected.extend_from_slice(&commit.leaf_count.to_be_bytes());
        expected.extend_from_slice(&commit.published_at.to_be_bytes());
        expected.extend_from_slice(&commit.issuer_node_id);
        assert_eq!(canonical_bytes(&commit), expected);
    }

    #[test]
    fn commit_dht_key_is_domain_separated() {
        assert_ne!(commit_dht_key(&[1; 32], 1), commit_dht_key(&[2; 32], 1));
        assert_ne!(commit_dht_key(&[1; 32], 1), commit_dht_key(&[1; 32], 2));
    }

    #[test]
    fn commit_serde_roundtrip() {
        let commit = valid_commit();
        let encoded = serde_json::to_vec(&commit).expect("serialize commit");
        assert_eq!(
            serde_json::from_slice::<JournalCommit>(&encoded).expect("deserialize commit"),
            commit
        );
    }

    #[test]
    fn sign_pointer_and_verify_roundtrip() {
        let pointer = sign_pointer(&key(7), 1, 100);
        assert_eq!(verify_pointer(&pointer), Ok(()));
    }

    #[test]
    fn verify_pointer_rejects_zero_sequence() {
        let pointer = sign_pointer(&key(7), 0, 100);
        assert_eq!(
            verify_pointer(&pointer),
            Err(JournalCommitError::InvalidSequence)
        );
    }

    #[test]
    fn verify_pointer_rejects_binding_mismatch() {
        let mut pointer = sign_pointer(&key(7), 1, 100);
        pointer.issuer_node_id[0] ^= 1;
        assert_eq!(
            verify_pointer(&pointer),
            Err(JournalCommitError::IssuerBindingMismatch)
        );
    }

    #[test]
    fn verify_pointer_rejects_tampered_latest_sequence() {
        let mut pointer = sign_pointer(&key(7), 1, 100);
        pointer.latest_sequence += 1;
        assert_eq!(
            verify_pointer(&pointer),
            Err(JournalCommitError::InvalidSignature)
        );
    }

    #[test]
    fn verify_pointer_rejects_tampered_signature() {
        let mut pointer = sign_pointer(&key(7), 1, 100);
        pointer.signature[0] ^= 1;
        assert_eq!(
            verify_pointer(&pointer),
            Err(JournalCommitError::InvalidSignature)
        );
    }

    #[test]
    fn latest_dht_key_differs_from_sequence_key() {
        let issuer = [8; 32];
        assert_ne!(latest_dht_key(&issuer), commit_dht_key(&issuer, 1));
    }
}
