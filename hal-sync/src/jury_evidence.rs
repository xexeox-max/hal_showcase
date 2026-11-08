use curve25519_dalek::ristretto::CompressedRistretto;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hal_crypto::threshold_encrypt::{DleqProof, PartialDecryption};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::canonical_json::{self, CanonicalJsonError};

pub const EVIDENCE_HASH_DOMAIN: &[u8] = b"hal.jury.evidence.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JuryEvidenceResponse {
    pub complaint_id: [u8; 32],
    pub respondent_node_id: [u8; 32],
    pub jury_pubkey: CompressedRistretto,
    pub evidence_hash: [u8; 32],
    pub encapsulation: CompressedRistretto,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub signature: [u8; 64],
    pub issued_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JuryPartialDecryption {
    pub complaint_id: [u8; 32],
    pub juror_node_id: [u8; 32],
    pub juror_public_key: [u8; 32],
    pub juror_share_index: u32,
    pub evidence_hash: [u8; 32],
    pub partial: PartialDecryption,
    pub signature: [u8; 64],
    pub issued_at: u64,
}

#[derive(Serialize, Deserialize)]
struct JuryPartialDecryptionWire {
    complaint_id: [u8; 32],
    juror_node_id: [u8; 32],
    juror_public_key: [u8; 32],
    juror_share_index: u32,
    evidence_hash: [u8; 32],
    partial: PartialDecryptionWire,
    signature: Vec<u8>,
    issued_at: u64,
}

#[derive(Serialize, Deserialize)]
struct PartialDecryptionWire {
    share_index: u32,
    threshold: u32,
    participant_count: u32,
    partial: [u8; 32],
    proof: DleqProofWire,
}

#[derive(Serialize, Deserialize)]
struct DleqProofWire {
    challenge: [u8; 32],
    response: [u8; 32],
    share_public: [u8; 32],
}

impl Serialize for JuryPartialDecryption {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        JuryPartialDecryptionWire {
            complaint_id: self.complaint_id,
            juror_node_id: self.juror_node_id,
            juror_public_key: self.juror_public_key,
            juror_share_index: self.juror_share_index,
            evidence_hash: self.evidence_hash,
            partial: PartialDecryptionWire {
                share_index: self.partial.share_index,
                threshold: self.partial.threshold,
                participant_count: self.partial.participant_count,
                partial: *self.partial.partial.as_bytes(),
                proof: DleqProofWire {
                    challenge: self.partial.proof.challenge.to_bytes(),
                    response: self.partial.proof.response.to_bytes(),
                    share_public: *self.partial.proof.share_public.as_bytes(),
                },
            },
            signature: self.signature.to_vec(),
            issued_at: self.issued_at,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for JuryPartialDecryption {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = JuryPartialDecryptionWire::deserialize(deserializer)?;
        let challenge = Option::<curve25519_dalek::scalar::Scalar>::from(
            curve25519_dalek::scalar::Scalar::from_canonical_bytes(wire.partial.proof.challenge),
        )
        .ok_or_else(|| serde::de::Error::custom("non-canonical DLEQ challenge"))?;
        let response = Option::<curve25519_dalek::scalar::Scalar>::from(
            curve25519_dalek::scalar::Scalar::from_canonical_bytes(wire.partial.proof.response),
        )
        .ok_or_else(|| serde::de::Error::custom("non-canonical DLEQ response"))?;
        let signature = wire.signature.try_into().map_err(|signature: Vec<u8>| {
            serde::de::Error::invalid_length(signature.len(), &"64-byte signature")
        })?;
        Ok(Self {
            complaint_id: wire.complaint_id,
            juror_node_id: wire.juror_node_id,
            juror_public_key: wire.juror_public_key,
            juror_share_index: wire.juror_share_index,
            evidence_hash: wire.evidence_hash,
            partial: PartialDecryption {
                share_index: wire.partial.share_index,
                threshold: wire.partial.threshold,
                participant_count: wire.partial.participant_count,
                partial: CompressedRistretto(wire.partial.partial),
                proof: DleqProof {
                    challenge,
                    response,
                    share_public: CompressedRistretto(wire.partial.proof.share_public),
                },
            },
            signature,
            issued_at: wire.issued_at,
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EvidenceError {
    #[error("canonicalization failed: {0}")]
    Canonical(#[from] CanonicalJsonError),
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("signature encoding failed: {0}")]
    SignatureEncode(String),
}

pub fn compute_evidence_hash(
    complaint_id: &[u8; 32],
    plaintext_json: &serde_json::Value,
) -> Result<[u8; 32], CanonicalJsonError> {
    let canonical = Zeroizing::new(canonical_json::canonicalize_json(plaintext_json)?);
    let mut hasher = Sha256::new();
    hasher.update(EVIDENCE_HASH_DOMAIN);
    hasher.update(complaint_id);
    hasher.update(canonical.as_bytes());
    Ok(hasher.finalize().into())
}

pub fn sign_evidence_response(
    key: &SigningKey,
    response: &mut JuryEvidenceResponse,
) -> Result<(), EvidenceError> {
    if node_id_from_public_key(&key.verifying_key()) != response.respondent_node_id {
        return Err(EvidenceError::SignatureInvalid);
    }
    response.signature = key
        .sign(&evidence_response_signing_bytes(response))
        .to_bytes();
    Ok(())
}

pub fn verify_evidence_response(
    public_key: &VerifyingKey,
    response: &JuryEvidenceResponse,
) -> Result<(), EvidenceError> {
    if node_id_from_public_key(public_key) != response.respondent_node_id {
        return Err(EvidenceError::SignatureInvalid);
    }
    public_key
        .verify_strict(
            &evidence_response_signing_bytes(response),
            &Signature::from_bytes(&response.signature),
        )
        .map_err(|_| EvidenceError::SignatureInvalid)
}

pub fn sign_partial_decryption(
    key: &SigningKey,
    partial: &mut JuryPartialDecryption,
) -> Result<(), EvidenceError> {
    let public_key = key.verifying_key();
    if node_id_from_public_key(&public_key) != partial.juror_node_id
        || partial.juror_share_index != partial.partial.share_index
    {
        return Err(EvidenceError::SignatureInvalid);
    }
    partial.juror_public_key = public_key.to_bytes();
    partial.signature = key
        .sign(&partial_decryption_signing_bytes(partial))
        .to_bytes();
    Ok(())
}

pub fn verify_partial_decryption_signature(
    public_key: &VerifyingKey,
    partial: &JuryPartialDecryption,
) -> Result<(), EvidenceError> {
    if node_id_from_public_key(public_key) != partial.juror_node_id
        || partial.juror_public_key != public_key.to_bytes()
        || partial.juror_share_index != partial.partial.share_index
    {
        return Err(EvidenceError::SignatureInvalid);
    }
    public_key
        .verify_strict(
            &partial_decryption_signing_bytes(partial),
            &Signature::from_bytes(&partial.signature),
        )
        .map_err(|_| EvidenceError::SignatureInvalid)
}

fn evidence_response_signing_bytes(response: &JuryEvidenceResponse) -> Vec<u8> {
    let ciphertext_hash = Sha256::digest(&response.ciphertext);
    let mut bytes = Vec::with_capacity(32 * 6 + 12 + 8);
    bytes.extend_from_slice(&response.complaint_id);
    bytes.extend_from_slice(&response.respondent_node_id);
    bytes.extend_from_slice(response.jury_pubkey.as_bytes());
    bytes.extend_from_slice(&response.evidence_hash);
    bytes.extend_from_slice(response.encapsulation.as_bytes());
    bytes.extend_from_slice(&response.nonce);
    bytes.extend_from_slice(&ciphertext_hash);
    bytes.extend_from_slice(&response.issued_at.to_be_bytes());
    bytes
}

fn partial_decryption_signing_bytes(partial: &JuryPartialDecryption) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 * 9 + 4 * 4 + 8);
    bytes.extend_from_slice(&partial.complaint_id);
    bytes.extend_from_slice(&partial.juror_node_id);
    bytes.extend_from_slice(&partial.juror_public_key);
    bytes.extend_from_slice(&partial.juror_share_index.to_be_bytes());
    bytes.extend_from_slice(&partial.evidence_hash);
    bytes.extend_from_slice(&partial.partial.share_index.to_be_bytes());
    bytes.extend_from_slice(&partial.partial.threshold.to_be_bytes());
    bytes.extend_from_slice(&partial.partial.participant_count.to_be_bytes());
    bytes.extend_from_slice(partial.partial.partial.as_bytes());
    bytes.extend_from_slice(&partial.partial.proof.challenge.to_bytes());
    bytes.extend_from_slice(&partial.partial.proof.response.to_bytes());
    bytes.extend_from_slice(partial.partial.proof.share_public.as_bytes());
    bytes.extend_from_slice(&partial.issued_at.to_be_bytes());
    bytes
}

fn node_id_from_public_key(public_key: &VerifyingKey) -> [u8; 32] {
    Sha256::digest(public_key.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_COMPRESSED, scalar::Scalar};
    use hal_crypto::threshold_encrypt::DleqProof;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    fn response(key: &SigningKey) -> JuryEvidenceResponse {
        JuryEvidenceResponse {
            complaint_id: [1; 32],
            respondent_node_id: node_id_from_public_key(&key.verifying_key()),
            jury_pubkey: RISTRETTO_BASEPOINT_COMPRESSED,
            evidence_hash: [2; 32],
            encapsulation: RISTRETTO_BASEPOINT_COMPRESSED,
            nonce: [3; 12],
            ciphertext: vec![4, 5, 6],
            signature: [0; 64],
            issued_at: 123,
        }
    }

    fn partial(key: &SigningKey) -> JuryPartialDecryption {
        let public_key = key.verifying_key();
        JuryPartialDecryption {
            complaint_id: [1; 32],
            juror_node_id: node_id_from_public_key(&public_key),
            juror_public_key: [0; 32],
            juror_share_index: 1,
            evidence_hash: [2; 32],
            partial: PartialDecryption {
                share_index: 1,
                threshold: 5,
                participant_count: 7,
                partial: RISTRETTO_BASEPOINT_COMPRESSED,
                proof: DleqProof {
                    challenge: Scalar::ZERO,
                    response: Scalar::ZERO,
                    share_public: RISTRETTO_BASEPOINT_COMPRESSED,
                },
            },
            signature: [0; 64],
            issued_at: 3,
        }
    }

    #[test]
    fn evidence_hash_is_deterministic() {
        let complaint_id = [8; 32];
        let value = serde_json::json!({"message": "evidence", "time": 1});
        assert_eq!(
            compute_evidence_hash(&complaint_id, &value).expect("hash"),
            compute_evidence_hash(&complaint_id, &value).expect("hash")
        );
    }

    #[test]
    fn evidence_hash_changes_on_complaint_id() {
        let value = serde_json::json!({"message": "evidence"});
        assert_ne!(
            compute_evidence_hash(&[1; 32], &value).expect("hash"),
            compute_evidence_hash(&[2; 32], &value).expect("hash")
        );
    }

    #[test]
    fn evidence_hash_domain_separated() {
        let complaint_id = [9; 32];
        let value = serde_json::json!({"message": "evidence"});
        let canonical = canonical_json::canonical_bytes_of(&value).expect("canonical JSON");
        let bare_hash: [u8; 32] = Sha256::digest(canonical).into();
        assert_ne!(
            compute_evidence_hash(&complaint_id, &value).expect("hash"),
            bare_hash
        );
    }

    #[test]
    fn sign_verify_evidence_response_roundtrip() {
        let key = signing_key();
        let mut response = response(&key);
        sign_evidence_response(&key, &mut response).expect("sign response");
        verify_evidence_response(&key.verifying_key(), &response).expect("verify response");
    }

    #[test]
    fn verify_rejects_tampered_response() {
        let key = signing_key();
        let mut response = response(&key);
        sign_evidence_response(&key, &mut response).expect("sign response");
        response.issued_at += 1;
        assert_eq!(
            verify_evidence_response(&key.verifying_key(), &response),
            Err(EvidenceError::SignatureInvalid)
        );
    }

    #[test]
    fn partial_decryption_roundtrip_with_juror_public_key() {
        let key = signing_key();
        let mut partial = partial(&key);
        sign_partial_decryption(&key, &mut partial).expect("sign partial");
        assert_eq!(partial.juror_public_key, key.verifying_key().to_bytes());
        verify_partial_decryption_signature(&key.verifying_key(), &partial)
            .expect("verify partial");
    }

    #[test]
    fn partial_decryption_rejects_wrong_juror_public_key() {
        let key = signing_key();
        let mut partial = partial(&key);
        sign_partial_decryption(&key, &mut partial).expect("sign partial");
        partial.juror_public_key = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        assert_eq!(
            verify_partial_decryption_signature(&key.verifying_key(), &partial),
            Err(EvidenceError::SignatureInvalid)
        );
    }
}
