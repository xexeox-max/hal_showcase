use anyhow::{anyhow, Context, Result};
use ed25519_dalek::VerifyingKey;

use crate::dht::wire::StoredRecordType;
use crate::journal_commit_publisher::PublishTransport;
use crate::jury_vote::{verify_vote, vote_dht_key, JuryVote, JURY_VOTE_TTL_SECS};

pub async fn publish_vote_to_dht(
    transport: &dyn PublishTransport,
    vote: &JuryVote,
    now: u64,
) -> Result<()> {
    if vote.issued_at > now {
        return Err(anyhow!("jury vote issue time is in the future"));
    }
    let expires_at = vote
        .issued_at
        .checked_add(JURY_VOTE_TTL_SECS)
        .context("jury vote expiry overflow")?;
    if expires_at <= now {
        return Err(anyhow!("jury vote has expired"));
    }
    let public_key =
        VerifyingKey::from_bytes(&vote.juror_public_key).context("decode jury vote public key")?;
    verify_vote(&public_key, vote).context("verify jury vote before publication")?;
    let key = vote_dht_key(&vote.complaint_id, &vote.evidence_hash, &vote.juror_node_id);
    let value = serde_json::to_vec(vote).context("serialize jury vote")?;
    transport
        .store_typed(key, value, StoredRecordType::JuryVote, expires_at)
        .await
        .context("publish jury vote to DHT")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jury_vote::{node_id_from_public_key, sign_vote, JuryDecision};
    use async_trait::async_trait;
    use ed25519_dalek::SigningKey;
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

    fn signed_vote() -> JuryVote {
        let key = SigningKey::from_bytes(&[41; 32]);
        let mut vote = JuryVote {
            complaint_id: [1; 32],
            evidence_hash: [2; 32],
            juror_node_id: node_id_from_public_key(&key.verifying_key()),
            juror_public_key: [0; 32],
            decision: JuryDecision::Guilty,
            issued_at: 100,
            signature: [0; 64],
        };
        sign_vote(&key, &mut vote).expect("sign vote");
        vote
    }

    #[tokio::test]
    async fn publish_vote_uses_expected_key_and_ttl() {
        let transport = MockTransport::default();
        let vote = signed_vote();
        publish_vote_to_dht(&transport, &vote, 101)
            .await
            .expect("publish vote");
        let stored = transport.stored.lock().expect("stored records");
        assert_eq!(stored.len(), 1);
        assert_eq!(
            stored[0].0,
            vote_dht_key(&vote.complaint_id, &vote.evidence_hash, &vote.juror_node_id)
        );
        assert_eq!(stored[0].2, StoredRecordType::JuryVote);
        assert_eq!(stored[0].3, 100 + JURY_VOTE_TTL_SECS);
        assert_eq!(
            serde_json::from_slice::<JuryVote>(&stored[0].1).expect("decode published vote"),
            vote
        );
    }
}
