use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

pub const REVOKE_DOMAIN: &[u8] = b"HAL-INV-REVOKE-v1\0";
pub const REVOCATION_RETRY_WINDOW_SECS: u64 = 60;
pub const REVOCATION_DHT_RECORD_TTL_SECS: u64 = 30 * 24 * 3600;
pub const NEGATIVE_CACHE_TTL_SECS: u64 = 300;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RevocationLookupError {
    #[error("DHT transport error: {0}")]
    Transport(String),
    #[error("DHT returned invalid record bytes: {0}")]
    InvalidRecord(String),
    #[error("DHT lookup timed out")]
    Timeout,
    #[error("revocation record signature invalid: {0}")]
    InvalidSignature(String),
}

#[async_trait::async_trait]
pub trait RevocationOracle: Send + Sync {
    /// Returns `Ok(true)` when revoked, `Ok(false)` when positively not revoked,
    /// and an error when revocation status cannot be determined.
    async fn is_revoked(&self, token_hash: &[u8; 32]) -> Result<bool, RevocationLookupError>;
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RevocationError {
    #[error("issuer_hex is not 64 lowercase hex")]
    InvalidIssuerHex,
    #[error("SHA256(issuer_public_key) != issuer_hex")]
    PubkeyBindingMismatch,
    #[error("invalid issuer_public_key bytes")]
    InvalidPublicKey,
    #[error("revocation_signature invalid")]
    InvalidSignature,
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("deserialization failed: {0}")]
    Deserialization(String),
    #[error("signature must be 64 bytes")]
    InvalidSignatureLength,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationRecord {
    pub token_hash: [u8; 32],
    pub issuer_hex: String,
    pub issuer_public_key: [u8; 32],
    pub revoked_at: u64,
    #[serde(with = "signature_serde")]
    pub revocation_signature: [u8; 64],
}

fn canonical_revocation_bytes(
    token_hash: &[u8; 32],
    issuer_node_id: &[u8; 32],
    revoked_at: u64,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(REVOKE_DOMAIN.len() + 32 + 32 + 8);
    bytes.extend_from_slice(REVOKE_DOMAIN);
    bytes.extend_from_slice(token_hash);
    bytes.extend_from_slice(issuer_node_id);
    bytes.extend_from_slice(&revoked_at.to_be_bytes());
    bytes
}

fn parse_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    let mut output = [0u8; 32];
    hex::decode_to_slice(value, &mut output).ok()?;
    Some(output)
}

/// Sign an invite revocation with the issuer's Ed25519 key.
///
/// `issuer_node_id` is SHA256(public_key), matching the project's
/// `NodeId::from_public_key` convention.
pub fn sign_revocation(
    signing_key: &SigningKey,
    token_hash: [u8; 32],
    revoked_at: u64,
) -> RevocationRecord {
    let issuer_public_key = signing_key.verifying_key().to_bytes();
    let issuer_node_id: [u8; 32] = Sha256::digest(issuer_public_key).into();
    let issuer_hex = hex::encode(issuer_node_id);
    let payload = canonical_revocation_bytes(&token_hash, &issuer_node_id, revoked_at);
    let revocation_signature = signing_key.sign(&payload).to_bytes();

    RevocationRecord {
        token_hash,
        issuer_hex,
        issuer_public_key,
        revoked_at,
        revocation_signature,
    }
}

pub fn verify_revocation(record: &RevocationRecord) -> Result<(), RevocationError> {
    let issuer_bytes = parse_hex_32(&record.issuer_hex).ok_or(RevocationError::InvalidIssuerHex)?;
    let computed: [u8; 32] = Sha256::digest(record.issuer_public_key).into();
    if computed != issuer_bytes {
        return Err(RevocationError::PubkeyBindingMismatch);
    }
    let verifying_key = VerifyingKey::from_bytes(&record.issuer_public_key)
        .map_err(|_| RevocationError::InvalidPublicKey)?;
    let payload = canonical_revocation_bytes(&record.token_hash, &issuer_bytes, record.revoked_at);
    verifying_key
        .verify_strict(
            &payload,
            &Signature::from_bytes(&record.revocation_signature),
        )
        .map_err(|_| RevocationError::InvalidSignature)
}

pub fn revocation_dht_key(token_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REVOKE_DOMAIN);
    hasher.update(token_hash);
    hasher.finalize().into()
}

pub fn serialize_revocation(record: &RevocationRecord) -> Result<Vec<u8>, RevocationError> {
    serde_json::to_vec(record).map_err(|error| RevocationError::Serialization(error.to_string()))
}

pub fn deserialize_revocation(bytes: &[u8]) -> Result<RevocationRecord, RevocationError> {
    #[derive(Deserialize)]
    struct SerializedRevocationRecord {
        token_hash: [u8; 32],
        issuer_hex: String,
        issuer_public_key: [u8; 32],
        revoked_at: u64,
        revocation_signature: Vec<u8>,
    }

    let record: SerializedRevocationRecord = serde_json::from_slice(bytes)
        .map_err(|error| RevocationError::Deserialization(error.to_string()))?;
    let revocation_signature: [u8; 64] = record
        .revocation_signature
        .try_into()
        .map_err(|_| RevocationError::InvalidSignatureLength)?;
    Ok(RevocationRecord {
        token_hash: record.token_hash,
        issuer_hex: record.issuer_hex,
        issuer_public_key: record.issuer_public_key,
        revoked_at: record.revoked_at,
        revocation_signature,
    })
}

mod signature_serde {
    use super::*;

    pub fn serialize<S>(signature: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(signature)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        bytes.try_into().map_err(|bytes: Vec<u8>| {
            serde::de::Error::custom(format!(
                "revocation_signature must be 64 bytes, got {}",
                bytes.len()
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::Signer;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn token(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let record = sign_revocation(&key(1), token(2), 1_700_000_000);
        assert_eq!(verify_revocation(&record), Ok(()));
    }

    #[test]
    fn sign_sets_issuer_hex_from_pubkey_hash() {
        let record = sign_revocation(&key(3), token(4), 123);
        let expected: [u8; 32] = Sha256::digest(record.issuer_public_key).into();
        assert_eq!(record.issuer_hex, hex::encode(expected));
    }

    #[test]
    fn sign_is_deterministic() {
        let signing_key = key(5);
        let first = sign_revocation(&signing_key, token(6), 456);
        let second = sign_revocation(&signing_key, token(6), 456);
        assert_eq!(first, second);
    }

    #[test]
    fn verify_rejects_uppercase_issuer_hex() {
        let mut record = sign_revocation(&key(7), token(8), 789);
        record.issuer_hex.make_ascii_uppercase();
        assert_eq!(
            verify_revocation(&record),
            Err(RevocationError::InvalidIssuerHex)
        );
    }

    #[test]
    fn verify_rejects_short_issuer_hex() {
        let mut record = sign_revocation(&key(9), token(10), 987);
        record.issuer_hex.pop();
        assert_eq!(
            verify_revocation(&record),
            Err(RevocationError::InvalidIssuerHex)
        );
    }

    #[test]
    fn verify_rejects_non_hex_issuer_hex() {
        let mut record = sign_revocation(&key(11), token(12), 654);
        record.issuer_hex.replace_range(0..2, "zz");
        assert_eq!(
            verify_revocation(&record),
            Err(RevocationError::InvalidIssuerHex)
        );
    }

    #[test]
    fn verify_rejects_pubkey_binding_mismatch() {
        let mut record = sign_revocation(&key(13), token(14), 321);
        record.issuer_public_key = key(15).verifying_key().to_bytes();
        assert_eq!(
            verify_revocation(&record),
            Err(RevocationError::PubkeyBindingMismatch)
        );
    }

    #[test]
    fn verify_rejects_invalid_public_key() {
        let mut record = sign_revocation(&key(16), token(17), 159);
        let invalid_public_key = (0..=u16::MAX)
            .find_map(|candidate| {
                let mut bytes = [0; 32];
                bytes[0] = candidate as u8;
                bytes[1] = (candidate >> 8) as u8;
                VerifyingKey::from_bytes(&bytes).is_err().then_some(bytes)
            })
            .expect("find an invalid compressed Ed25519 public key");
        record.issuer_public_key = invalid_public_key;
        record.issuer_hex = hex::encode(Sha256::digest(record.issuer_public_key));
        assert_eq!(
            verify_revocation(&record),
            Err(RevocationError::InvalidPublicKey)
        );
    }

    #[test]
    fn verify_rejects_tampered_token_hash() {
        let mut record = sign_revocation(&key(18), token(19), 753);
        record.token_hash[0] ^= 1;
        assert_eq!(
            verify_revocation(&record),
            Err(RevocationError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_tampered_revoked_at() {
        let mut record = sign_revocation(&key(20), token(21), 852);
        record.revoked_at += 1;
        assert_eq!(
            verify_revocation(&record),
            Err(RevocationError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let mut record = sign_revocation(&key(22), token(23), 951);
        record.revocation_signature[0] ^= 1;
        assert_eq!(
            verify_revocation(&record),
            Err(RevocationError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_wrong_signing_key() {
        let mut record = sign_revocation(&key(24), token(25), 1_234);
        let issuer_node_id: [u8; 32] = Sha256::digest(record.issuer_public_key).into();
        let payload =
            canonical_revocation_bytes(&record.token_hash, &issuer_node_id, record.revoked_at);
        record.revocation_signature = key(26).sign(&payload).to_bytes();
        assert_eq!(
            verify_revocation(&record),
            Err(RevocationError::InvalidSignature)
        );
    }

    #[test]
    fn canonical_payload_matches_spec() {
        let token_hash = token(27);
        let issuer_node_id = token(28);
        let revoked_at: u64 = 0x0102_0304_0506_0708;
        let mut expected = Vec::new();
        expected.extend_from_slice(b"HAL-INV-REVOKE-v1\0");
        expected.extend_from_slice(&token_hash);
        expected.extend_from_slice(&issuer_node_id);
        expected.extend_from_slice(&revoked_at.to_be_bytes());

        assert_eq!(
            canonical_revocation_bytes(&token_hash, &issuer_node_id, revoked_at),
            expected
        );
    }
}
