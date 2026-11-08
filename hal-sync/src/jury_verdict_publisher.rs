use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;

use crate::dht::wire::StoredRecordType;
use crate::journal::{JuryVerdictPrivatePayload, SyncEvent};
use crate::journal_commit_publisher::PublishTransport;
use crate::jury_vote::{verdict_dht_key, JuryDecision, JuryVerdict, JURY_VERDICT_TTL_SECS};

#[async_trait]
pub trait PrivateVerdictTransport: Send + Sync {
    async fn send_private_event(
        &self,
        recipient_node_id: &[u8; 32],
        event: &SyncEvent,
    ) -> Result<()>;
}

pub async fn publish_private_verdict(
    transport: &dyn PrivateVerdictTransport,
    verdict: &JuryVerdict,
    recipients: &[[u8; 32]],
) -> Result<()> {
    if verdict.verdict == JuryDecision::Guilty {
        return Ok(());
    }
    let event = SyncEvent::jury_verdict_private(&JuryVerdictPrivatePayload {
        verdict: verdict.clone(),
    })
    .context("build private jury verdict event")?;
    let mut delivered = std::collections::HashSet::new();
    for recipient in recipients {
        if !delivered.insert(*recipient) {
            continue;
        }
        if let Err(error) = transport.send_private_event(recipient, &event).await {
            log::warn!(
                "private jury verdict delivery to {} skipped: {error}",
                hex::encode(recipient)
            );
        }
    }
    Ok(())
}

pub async fn publish_verdict(
    transport: &dyn PublishTransport,
    verdict: &JuryVerdict,
    now: u64,
) -> Result<()> {
    if verdict.verdict != JuryDecision::Guilty {
        log::debug!(
            "verdict {:?} for complaint {} is private; no DHT publication",
            verdict.verdict,
            hex::encode(verdict.complaint_id)
        );
        return Ok(());
    }
    if verdict.issued_at > now {
        return Err(anyhow!("jury verdict issue time is in the future"));
    }
    let expires_at = verdict
        .issued_at
        .checked_add(JURY_VERDICT_TTL_SECS)
        .context("jury verdict expiry overflow")?;
    if expires_at <= now {
        return Err(anyhow!("jury verdict has expired"));
    }
    let key = verdict_dht_key(&verdict.complaint_id, &verdict.evidence_hash);
    let value = serde_json::to_vec(verdict).context("serialize jury verdict")?;
    transport
        .store_typed(key, value, StoredRecordType::JuryVerdict, expires_at)
        .await
        .context("publish guilty verdict to DHT")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jury_vote::{node_id_from_public_key, sign_vote, JurorVoteRef};
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
                .map_err(|_| anyhow::anyhow!("mock transport lock poisoned"))?
                .push((key, value, record_type, expires_at));
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockPrivateTransport {
        sent: Mutex<Vec<([u8; 32], SyncEvent)>>,
    }

    #[async_trait]
    impl PrivateVerdictTransport for MockPrivateTransport {
        async fn send_private_event(
            &self,
            recipient_node_id: &[u8; 32],
            event: &SyncEvent,
        ) -> Result<()> {
            self.sent
                .lock()
                .map_err(|_| anyhow::anyhow!("mock private transport lock poisoned"))?
                .push((*recipient_node_id, event.clone()));
            Ok(())
        }
    }

    fn verdict(decision: JuryDecision) -> JuryVerdict {
        let refs = (1..=5)
            .map(|index| {
                let key = SigningKey::from_bytes(&[index; 32]);
                let mut vote = crate::jury_vote::JuryVote {
                    complaint_id: [1; 32],
                    evidence_hash: [2; 32],
                    juror_node_id: node_id_from_public_key(&key.verifying_key()),
                    juror_public_key: [0; 32],
                    decision,
                    issued_at: 100,
                    signature: [0; 64],
                };
                sign_vote(&key, &mut vote).expect("sign vote");
                JurorVoteRef {
                    juror_node_id: vote.juror_node_id,
                    juror_public_key: vote.juror_public_key,
                    decision: vote.decision,
                    issued_at: vote.issued_at,
                    signature: vote.signature,
                }
            })
            .collect();
        JuryVerdict {
            complaint_id: [1; 32],
            evidence_hash: [2; 32],
            verdict: decision,
            juror_signatures: refs,
            issued_at: 100,
        }
    }

    #[tokio::test]
    async fn publisher_skips_dht_for_not_guilty_and_inconclusive() {
        let transport = MockTransport::default();
        for decision in [JuryDecision::NotGuilty, JuryDecision::Inconclusive] {
            publish_verdict(&transport, &verdict(decision), 101)
                .await
                .expect("private verdict is not published");
        }
        assert!(transport.stored.lock().expect("stored records").is_empty());
    }

    #[tokio::test]
    async fn publisher_writes_guilty_to_dht_with_expected_key_and_ttl() {
        let transport = MockTransport::default();
        let verdict = verdict(JuryDecision::Guilty);
        publish_verdict(&transport, &verdict, 101)
            .await
            .expect("publish guilty verdict");
        let stored = transport.stored.lock().expect("stored records");
        assert_eq!(stored.len(), 1);
        assert_eq!(
            stored[0].0,
            verdict_dht_key(&verdict.complaint_id, &verdict.evidence_hash)
        );
        assert_eq!(stored[0].2, StoredRecordType::JuryVerdict);
        assert_eq!(stored[0].3, 100 + JURY_VERDICT_TTL_SECS);
        assert_eq!(
            serde_json::from_slice::<JuryVerdict>(&stored[0].1).expect("decode verdict"),
            verdict
        );
    }

    #[tokio::test]
    async fn publisher_emits_private_sync_event_for_not_guilty() {
        let transport = MockPrivateTransport::default();
        let verdict = verdict(JuryDecision::NotGuilty);
        let recipients = [[3; 32], [4; 32]];

        publish_private_verdict(&transport, &verdict, &recipients)
            .await
            .expect("publish private verdict");

        let sent = transport.sent.lock().expect("sent private events");
        assert_eq!(sent.len(), 2);
        assert!(sent.iter().all(|(_, event)| {
            event.event_type == crate::journal::SyncEventType::JuryVerdictPrivate
                && serde_json::from_str::<JuryVerdictPrivatePayload>(&event.data)
                    .is_ok_and(|payload| payload.verdict == verdict)
        }));
        assert_eq!(sent[0].0, recipients[0]);
        assert_eq!(sent[1].0, recipients[1]);
    }

    #[tokio::test]
    async fn publisher_does_not_emit_private_event_for_guilty() {
        let transport = MockPrivateTransport::default();
        publish_private_verdict(
            &transport,
            &verdict(JuryDecision::Guilty),
            &[[3; 32], [4; 32]],
        )
        .await
        .expect("guilty verdict is not privately delivered");
        assert!(transport
            .sent
            .lock()
            .expect("sent private events")
            .is_empty());
    }

    #[test]
    fn private_verdict_payload_roundtrips_sync_event() {
        let verdict = verdict(JuryDecision::Inconclusive);
        let event = SyncEvent::jury_verdict_private(&JuryVerdictPrivatePayload {
            verdict: verdict.clone(),
        })
        .expect("construct private verdict event");
        let decoded: JuryVerdictPrivatePayload =
            serde_json::from_str(&event.data).expect("decode private verdict payload");
        assert_eq!(
            event.event_type,
            crate::journal::SyncEventType::JuryVerdictPrivate
        );
        assert_eq!(decoded.verdict, verdict);
    }
}
