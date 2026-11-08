//! Publish signed jury partial decryptions to the key-addressed DHT.

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::VerifyingKey;

use crate::dht::jury_dkg_commitment::{partial_dht_key, JURY_PARTIAL_TTL_SECS};
use crate::dht::wire::StoredRecordType;
use crate::journal_commit_publisher::PublishTransport;
use crate::jury_evidence::{verify_partial_decryption_signature, JuryPartialDecryption};

pub async fn publish_partial_to_dht(
    transport: &dyn PublishTransport,
    partial: &JuryPartialDecryption,
    now: u64,
) -> Result<()> {
    if partial.issued_at > now {
        return Err(anyhow!("jury partial issue time is in the future"));
    }
    let expires_at = partial
        .issued_at
        .checked_add(JURY_PARTIAL_TTL_SECS)
        .context("jury partial expiry overflow")?;
    if expires_at <= now {
        return Err(anyhow!("jury partial has expired"));
    }
    let public_key = VerifyingKey::from_bytes(&partial.juror_public_key)
        .context("decode jury partial public key")?;
    verify_partial_decryption_signature(&public_key, partial)
        .context("verify jury partial before publication")?;
    let key = partial_dht_key(
        &partial.complaint_id,
        &partial.evidence_hash,
        &partial.juror_node_id,
    );
    let value = serde_json::to_vec(partial).context("serialize jury partial")?;
    transport
        .store_typed(key, value, StoredRecordType::JuryPartial, expires_at)
        .await
        .context("publish jury partial to DHT")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::jury_dkg_commitment::partial_dht_key;
    use crate::journal_commit_publisher::PublishTransport;
    use crate::jury_evidence::sign_partial_decryption;
    use async_trait::async_trait;
    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_COMPRESSED, scalar::Scalar};
    use hal_crypto::threshold_encrypt::{DleqProof, PartialDecryption};
    use std::sync::Mutex;

    #[derive(Default)]
    struct MockTransport {
        stored: Mutex<Vec<([u8; 32], Vec<u8>, StoredRecordType, u64)>>,
    }

    #[async_trait]
    impl PublishTransport for MockTransport {
        async fn store_typed(
            &self,
            key: [u8; 32],
            value: Vec<u8>,
            record_type: StoredRecordType,
            expires_at: u64,
        ) -> Result<()> {
            self.stored
                .lock()
                .map_err(|_| anyhow!("mock transport lock poisoned"))?
                .push((key, value, record_type, expires_at));
            Ok(())
        }
    }

    fn signed_partial() -> JuryPartialDecryption {
        let key = ed25519_dalek::SigningKey::from_bytes(&[41; 32]);
        let juror_node_id = *crate::dht::NodeId::from_public_key(&key.verifying_key()).as_bytes();
        let mut partial = JuryPartialDecryption {
            complaint_id: [1; 32],
            juror_node_id,
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
            issued_at: 100,
        };
        sign_partial_decryption(&key, &mut partial).expect("sign partial");
        partial
    }

    #[tokio::test]
    async fn publish_partial_uses_expected_key_and_ttl() {
        let transport = MockTransport::default();
        let partial = signed_partial();
        publish_partial_to_dht(&transport, &partial, 101)
            .await
            .expect("publish partial");
        let stored = transport.stored.lock().expect("stored records");
        assert_eq!(stored.len(), 1);
        assert_eq!(
            stored[0].0,
            partial_dht_key(
                &partial.complaint_id,
                &partial.evidence_hash,
                &partial.juror_node_id,
            )
        );
        assert_eq!(stored[0].2, StoredRecordType::JuryPartial);
        assert_eq!(stored[0].3, 100 + JURY_PARTIAL_TTL_SECS);
    }
}
