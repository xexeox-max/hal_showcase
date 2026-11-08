//! Local persistence, DHT publication, and verified reads for jury DKG commitments.

use std::sync::{Arc, Mutex as StdMutex};

use anyhow::{anyhow, Context, Result};
use hal_storage::jury_commitments::{
    list_jury_commitments_for_storage, persist_jury_commitment, read_jury_commitment_for_storage,
    JuryCommitmentRecord,
};
use hal_storage::ClientStorage;

use crate::dht::jury_dkg_commitment::{
    commitment_dht_key, verify_commitment, JuryDkgCommitmentRecord, JURY_DKG_COMMITMENT_TTL_SECS,
};
use crate::dht::wire::StoredRecordType;
use crate::journal_commit_publisher::PublishTransport;

pub struct JuryCommitmentPublisher {
    storage: Arc<StdMutex<ClientStorage>>,
    dht_transport: Arc<dyn PublishTransport>,
}

impl JuryCommitmentPublisher {
    pub fn new(
        storage: Arc<StdMutex<ClientStorage>>,
        dht_transport: Arc<dyn PublishTransport>,
    ) -> Self {
        Self {
            storage,
            dht_transport,
        }
    }

    /// Persist a signed commitment before publishing it to DHT.
    pub async fn publish_once(
        &self,
        record: &JuryDkgCommitmentRecord,
        now: u64,
    ) -> Result<[u8; 32]> {
        verify_commitment(record).context("verify jury DKG commitment before publication")?;
        if record.published_at > now {
            return Err(anyhow!(
                "jury DKG commitment publication time is in the future"
            ));
        }
        let expires_at = record
            .published_at
            .checked_add(JURY_DKG_COMMITMENT_TTL_SECS)
            .ok_or_else(|| anyhow!("jury DKG commitment expiry overflow"))?;
        if expires_at <= now {
            return Err(anyhow!("jury DKG commitment has expired"));
        }
        let key = commitment_dht_key(&record.complaint_id, &record.dealer_node_id);
        let value = serde_json::to_vec(record).context("serialize jury DKG commitment")?;
        {
            let mut storage = self
                .storage
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            persist_jury_commitment(&mut storage, &to_storage_record(record, expires_at))
                .context("persist jury DKG commitment before publication")?;
        }

        self.dht_transport
            .store_typed(key, value, StoredRecordType::JuryDkgCommitment, expires_at)
            .await
            .context("publish jury DKG commitment")?;
        Ok(key)
    }

    /// Return a locally stored, unexpired commitment after verifying its signature and points.
    pub fn read_local(
        &self,
        complaint_id: &[u8; 32],
        dealer_node_id: &[u8; 32],
        now: u64,
    ) -> Result<Option<JuryDkgCommitmentRecord>> {
        let storage = self
            .storage
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        let Some(stored) =
            read_jury_commitment_for_storage(&storage, complaint_id, dealer_node_id)?
        else {
            return Ok(None);
        };
        verified_unexpired_record(stored, now)
    }

    /// Return all locally stored, unexpired commitments in stable storage order.
    pub fn list_local(&self, now: u64) -> Result<Vec<JuryDkgCommitmentRecord>> {
        let storage = self
            .storage
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        list_jury_commitments_for_storage(&storage)?
            .into_iter()
            .map(|stored| verified_unexpired_record(stored, now))
            .filter_map(|result| match result {
                Ok(Some(record)) => Some(Ok(record)),
                Ok(None) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
    }
}

fn to_storage_record(record: &JuryDkgCommitmentRecord, expires_at: u64) -> JuryCommitmentRecord {
    JuryCommitmentRecord {
        complaint_id: record.complaint_id,
        dealer_node_id: record.dealer_node_id,
        dealer_public_key: record.dealer_public_key,
        commitments: record.commitments.clone(),
        threshold: record.threshold,
        participant_count: record.participant_count,
        published_at: record.published_at,
        signature: record.signature,
        expires_at,
    }
}

fn verified_unexpired_record(
    stored: JuryCommitmentRecord,
    now: u64,
) -> Result<Option<JuryDkgCommitmentRecord>> {
    if stored.expires_at <= now {
        return Ok(None);
    }
    if stored.published_at > now {
        return Err(anyhow!(
            "stored jury DKG commitment publication time is in the future"
        ));
    }
    let expected_expiry = stored
        .published_at
        .checked_add(JURY_DKG_COMMITMENT_TTL_SECS)
        .ok_or_else(|| anyhow!("stored jury DKG commitment expiry overflow"))?;
    if stored.expires_at != expected_expiry {
        return Err(anyhow!(
            "stored jury DKG commitment expiry does not match its TTL"
        ));
    }
    let record = JuryDkgCommitmentRecord {
        complaint_id: stored.complaint_id,
        dealer_node_id: stored.dealer_node_id,
        dealer_public_key: stored.dealer_public_key,
        commitments: stored.commitments,
        threshold: stored.threshold,
        participant_count: stored.participant_count,
        published_at: stored.published_at,
        signature: stored.signature,
    };
    verify_commitment(&record).context("verify locally stored jury DKG commitment")?;
    Ok(Some(record))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use ed25519_dalek::SigningKey;
    use hal_storage::jury_commitments::list_jury_commitments_for_storage;
    use std::sync::Mutex;

    use crate::dht::jury_dkg_commitment::{sign_commitment, JURY_THRESHOLD};

    #[derive(Default)]
    struct MockTransport {
        calls: Mutex<Vec<([u8; 32], Vec<u8>, StoredRecordType, u64)>>,
        fail: bool,
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
            self.calls
                .lock()
                .map_err(|_| anyhow!("mock transport lock poisoned"))?
                .push((key, value, record_type, expires_at));
            if self.fail {
                return Err(anyhow!("mock DHT failure"));
            }
            Ok(())
        }
    }

    fn setup(
        fail: bool,
    ) -> (
        JuryCommitmentPublisher,
        Arc<MockTransport>,
        tempfile::TempDir,
    ) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let storage = ClientStorage::open(directory.path().join("jury.sqlite3"), &[11; 32])
            .expect("open storage");
        let transport = Arc::new(MockTransport {
            fail,
            ..MockTransport::default()
        });
        (
            JuryCommitmentPublisher::new(Arc::new(StdMutex::new(storage)), transport.clone()),
            transport,
            directory,
        )
    }

    fn commitment(published_at: u64) -> JuryDkgCommitmentRecord {
        sign_commitment(
            &SigningKey::from_bytes(&[12; 32]),
            [13; 32],
            vec![RISTRETTO_BASEPOINT_POINT.compress().to_bytes(); JURY_THRESHOLD as usize],
            published_at,
        )
        .expect("sign commitment")
    }

    #[tokio::test]
    async fn publishes_typed_commitment_with_derived_key_and_ttl() {
        let (publisher, transport, _directory) = setup(false);
        let record = commitment(100);
        let key = publisher.publish_once(&record, 101).await.expect("publish");
        let calls = transport.calls.lock().expect("calls");
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].0,
            commitment_dht_key(&record.complaint_id, &record.dealer_node_id)
        );
        assert_eq!(key, calls[0].0);
        assert_eq!(calls[0].2, StoredRecordType::JuryDkgCommitment);
        assert_eq!(calls[0].3, 100 + JURY_DKG_COMMITMENT_TTL_SECS);
        assert_eq!(
            serde_json::from_slice::<JuryDkgCommitmentRecord>(&calls[0].1).expect("decode"),
            record
        );
    }

    #[tokio::test]
    async fn publish_persists_locally_and_reader_verifies_record() {
        let (publisher, _, _directory) = setup(false);
        let record = commitment(100);
        publisher.publish_once(&record, 101).await.expect("publish");
        assert_eq!(
            publisher
                .read_local(&record.complaint_id, &record.dealer_node_id, 101)
                .expect("read"),
            Some(record.clone())
        );
        assert_eq!(publisher.list_local(101).expect("list"), vec![record]);
        assert!(publisher
            .read_local(&[14; 32], &[15; 32], 101)
            .expect("read missing")
            .is_none());
    }

    #[tokio::test]
    async fn expired_commitment_is_not_published_or_persisted() {
        let (publisher, transport, _directory) = setup(false);
        let record = commitment(100);
        let expired_at = 100 + JURY_DKG_COMMITMENT_TTL_SECS;
        assert!(publisher.publish_once(&record, expired_at).await.is_err());
        assert!(transport.calls.lock().expect("calls").is_empty());
        let storage = publisher.storage.lock().expect("storage");
        assert!(list_jury_commitments_for_storage(&storage)
            .expect("list")
            .is_empty());
    }

    #[tokio::test]
    async fn invalid_commitment_is_not_published_or_persisted() {
        let (publisher, transport, _directory) = setup(false);
        let mut record = commitment(100);
        record.commitments.pop();
        assert!(publisher.publish_once(&record, 101).await.is_err());
        assert!(transport.calls.lock().expect("calls").is_empty());
        let storage = publisher.storage.lock().expect("storage");
        assert!(list_jury_commitments_for_storage(&storage)
            .expect("list")
            .is_empty());
    }

    #[tokio::test]
    async fn dht_failure_keeps_persisted_commitment_for_retry() {
        let (publisher, transport, _directory) = setup(true);
        let record = commitment(100);
        assert!(publisher.publish_once(&record, 101).await.is_err());
        assert_eq!(transport.calls.lock().expect("calls").len(), 1);
        assert_eq!(publisher.list_local(101).expect("list"), vec![record]);
    }
}
