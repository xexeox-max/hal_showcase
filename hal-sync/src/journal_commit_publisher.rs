//! Periodic publication of signed journal Merkle roots and latest pointers.

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use hal_settings::NetworkTrustPolicy;
use hal_storage::journal_roots::{
    journal_commit_snapshot, persist_journal_commit, JournalCommitRecord,
};
use hal_storage::ClientStorage;
use tokio::sync::{oneshot, Mutex};
use tokio::time::{interval_at, Instant, MissedTickBehavior};

use crate::dht::journal_commit::{
    commit_dht_key, latest_dht_key, sign_commit, sign_pointer, JOURNAL_COMMIT_TTL_SECS,
};
use crate::dht::mux_transport::MuxDhtTransport;
use crate::dht::routing::{RoutingTable, K};
use crate::dht::transport::DhtTransport;
use crate::dht::wire::{DhtRequest, DhtRequestPayload, DhtResponsePayload, StoredRecordType};
use crate::dht::NodeId;
use crate::journal_merkle::{leaf_hash, merkle_root_from_leaves, JournalLeaf};
use crate::pinning::KnownHosts;

pub const DEFAULT_PUBLISH_INTERVAL_SECS: u64 = 24 * 3600;

#[async_trait]
pub trait PublishTransport: Send + Sync {
    async fn store_typed(
        &self,
        key: [u8; 32],
        value: Vec<u8>,
        record_type: StoredRecordType,
        expires_at: u64,
    ) -> Result<()>;
}

pub struct DhtPublishTransport {
    local_id: NodeId,
    routing: Arc<Mutex<RoutingTable>>,
    transport: Arc<dyn DhtTransport>,
}

impl DhtPublishTransport {
    pub fn new(
        local_id: NodeId,
        routing: Arc<Mutex<RoutingTable>>,
        transport: Arc<dyn DhtTransport>,
    ) -> Self {
        Self {
            local_id,
            routing,
            transport,
        }
    }
}

#[async_trait]
impl PublishTransport for DhtPublishTransport {
    async fn store_typed(
        &self,
        key: [u8; 32],
        value: Vec<u8>,
        record_type: StoredRecordType,
        expires_at: u64,
    ) -> Result<()> {
        let target = NodeId::from_bytes(key);
        let peers = self.routing.lock().await.closest(&target, K);
        if peers.is_empty() {
            return Err(anyhow!(
                "no DHT peers available for typed record publication"
            ));
        }

        let now = crate::dht::prekey_cache::unix_now();
        let signature = typed_record_signature(record_type, &value)?;
        let mut errors = Vec::new();
        let mut stored = false;
        for peer in peers {
            let request = DhtRequest::new(
                DhtRequestPayload::StoreTyped {
                    key,
                    value: value.clone(),
                    signature: signature.clone(),
                    expires_at,
                    record_type: Some(record_type),
                },
                self.local_id,
                now,
            );
            let request_id = request.request_id;
            match self.transport.send_request(&peer, request).await {
                Ok(response) => {
                    if let Err(error) =
                        response.validate(&request_id, crate::dht::prekey_cache::unix_now())
                    {
                        errors.push(format!(
                            "peer {:?} returned invalid response: {error}",
                            peer.node_id
                        ));
                        continue;
                    }
                    match response.payload {
                        DhtResponsePayload::Stored { key: stored_key } if stored_key == key => {
                            stored = true;
                        }
                        DhtResponsePayload::Error { code, message } => {
                            errors.push(format!(
                                "peer {:?} rejected store ({code}): {message}",
                                peer.node_id
                            ));
                        }
                        _ => errors.push(format!(
                            "peer {:?} returned unexpected store response",
                            peer.node_id
                        )),
                    }
                }
                Err(error) => errors.push(format!("peer {:?}: {error}", peer.node_id)),
            }
        }
        if stored {
            Ok(())
        } else {
            Err(anyhow!(
                "typed record publication failed on all candidate peers: {}",
                errors.join("; ")
            ))
        }
    }
}

fn typed_record_signature(record_type: StoredRecordType, value: &[u8]) -> Result<Vec<u8>> {
    match record_type {
        StoredRecordType::JournalCommit => {
            let commit: crate::dht::journal_commit::JournalCommit =
                serde_json::from_slice(value).context("decode signed journal commit")?;
            Ok(commit.signature.to_vec())
        }
        StoredRecordType::JournalCommitPointer => {
            let pointer: crate::dht::journal_commit::JournalCommitPointer =
                serde_json::from_slice(value).context("decode signed journal pointer")?;
            Ok(pointer.signature.to_vec())
        }
        StoredRecordType::JuryDkgCommitment => {
            let commitment: crate::dht::jury_dkg_commitment::JuryDkgCommitmentRecord =
                serde_json::from_slice(value).context("decode signed jury DKG commitment")?;
            Ok(commitment.signature.to_vec())
        }
        StoredRecordType::JuryPartial => {
            let partial: crate::jury_evidence::JuryPartialDecryption =
                serde_json::from_slice(value).context("decode signed jury partial")?;
            Ok(partial.signature.to_vec())
        }
        StoredRecordType::JuryVote => {
            let vote: crate::jury_vote::JuryVote =
                serde_json::from_slice(value).context("decode signed jury vote")?;
            Ok(vote.signature.to_vec())
        }
        StoredRecordType::JuryVerdict => {
            let verdict: crate::jury_vote::JuryVerdict =
                serde_json::from_slice(value).context("decode jury verdict")?;
            verdict
                .juror_signatures
                .first()
                .map(|vote| vote.signature.to_vec())
                .ok_or_else(|| anyhow!("jury verdict has no juror vote signatures"))
        }
        _ => Err(anyhow!(
            "unsupported record type for typed publication: {record_type:?}"
        )),
    }
}

pub struct JournalCommitPublisher {
    storage: Arc<StdMutex<ClientStorage>>,
    signing_key: SigningKey,
    dht_transport: Arc<dyn PublishTransport>,
    interval_secs: u64,
    publish_lock: Mutex<()>,
}

impl JournalCommitPublisher {
    pub fn new(
        storage: Arc<StdMutex<ClientStorage>>,
        signing_key: SigningKey,
        dht_transport: Arc<dyn PublishTransport>,
    ) -> Self {
        Self {
            storage,
            signing_key,
            dht_transport,
            interval_secs: DEFAULT_PUBLISH_INTERVAL_SECS,
            publish_lock: Mutex::new(()),
        }
    }

    pub fn with_interval(mut self, secs: u64) -> Self {
        self.interval_secs = secs.max(1);
        self
    }

    /// Build, persist, sign, and publish one cumulative journal commitment.
    pub async fn publish_once(&self, now: u64) -> Result<u64> {
        let _publish_guard = self.publish_lock.lock().await;

        let (events, sequence) = {
            let mut storage = self
                .storage
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            journal_commit_snapshot(&mut storage).context("read journal snapshot")?
        };

        let mut leaves = Vec::with_capacity(events.len());
        for event in &events {
            leaves.push(
                leaf_hash(&JournalLeaf {
                    event_id: &event.event_id,
                    event_timestamp: event.event_timestamp,
                    event_type_kind: &event.event_type,
                    event_data: &event.event_data,
                    signature: &event.signature,
                })
                .context("hash journal event")?,
            );
        }
        let root = merkle_root_from_leaves(&leaves);
        let leaf_count = u64::try_from(leaves.len()).context("journal leaf count overflow")?;
        let expires_at = now
            .checked_add(JOURNAL_COMMIT_TTL_SECS)
            .ok_or_else(|| anyhow!("journal commit expiry overflow"))?;
        let commit = sign_commit(&self.signing_key, sequence, root, leaf_count, now);
        let commit_bytes = serde_json::to_vec(&commit).context("serialize journal commit")?;
        let sequence_key = commit_dht_key(&commit.issuer_node_id, sequence);

        {
            let mut storage = self
                .storage
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            persist_journal_commit(
                &mut storage,
                &JournalCommitRecord {
                    sequence,
                    root,
                    leaf_count,
                    published_at: now,
                },
                &sequence_key,
            )
            .context("persist journal commitment before publication")?;
        }

        self.dht_transport
            .store_typed(
                sequence_key,
                commit_bytes,
                StoredRecordType::JournalCommit,
                expires_at,
            )
            .await
            .context("publish journal commit by sequence key")?;

        let pointer = sign_pointer(&self.signing_key, sequence, now);
        let pointer_bytes =
            serde_json::to_vec(&pointer).context("serialize journal commit pointer")?;
        self.dht_transport
            .store_typed(
                latest_dht_key(&pointer.issuer_node_id),
                pointer_bytes,
                StoredRecordType::JournalCommitPointer,
                expires_at,
            )
            .await
            .context("publish journal commit pointer")?;

        Ok(sequence)
    }

    /// Publish once per interval until shutdown; initial publication waits one interval.
    pub async fn run(self: Arc<Self>, mut shutdown: oneshot::Receiver<()>) {
        let period = Duration::from_secs(self.interval_secs);
        let mut ticker = interval_at(Instant::now() + period, period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    log::debug!("journal commit publisher stopped");
                    break;
                }
                _ = ticker.tick() => {
                    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                        Ok(duration) => {
                            if let Err(error) = self.publish_once(duration.as_secs()).await {
                                log::warn!("journal commit publish failed: {error}");
                            }
                        }
                        Err(error) => log::warn!("system clock precedes Unix epoch; journal publish skipped: {error}"),
                    }
                }
            }
        }
    }
}

pub fn dht_publish_transport(
    local_id: NodeId,
    signing_key: SigningKey,
    routing: Arc<Mutex<RoutingTable>>,
    hosts: Arc<StdMutex<KnownHosts>>,
    trust_policy: NetworkTrustPolicy,
) -> Arc<dyn PublishTransport> {
    let transport = Arc::new(MuxDhtTransport::new(signing_key, hosts, trust_policy));
    Arc::new(DhtPublishTransport::new(local_id, routing, transport))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::journal_commit::{
        commit_dht_key, latest_dht_key, verify_commit, verify_pointer, JournalCommit,
        JournalCommitPointer,
    };
    use crate::dht::jury_dkg_commitment::{sign_commitment, JURY_THRESHOLD};
    use crate::journal_merkle::empty_root;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use hal_storage::journal_roots::latest_journal_commit_for_storage;

    #[derive(Default)]
    struct MockTransport {
        calls: StdMutex<Vec<([u8; 32], Vec<u8>, StoredRecordType, u64)>>,
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
            Ok(())
        }
    }

    fn publisher() -> (
        JournalCommitPublisher,
        Arc<MockTransport>,
        tempfile::TempDir,
    ) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let storage = ClientStorage::open(directory.path().join("journal.sqlite3"), &[91; 32])
            .expect("open test storage");
        let storage = Arc::new(StdMutex::new(storage));
        let transport = Arc::new(MockTransport::default());
        let publisher = JournalCommitPublisher::new(
            storage,
            SigningKey::from_bytes(&[92; 32]),
            transport.clone(),
        );
        (publisher, transport, directory)
    }

    #[tokio::test]
    async fn publish_once_publishes_both_keys() {
        let (publisher, transport, _directory) = publisher();
        assert_eq!(publisher.publish_once(100).await.expect("publish"), 1);
        let calls = transport.calls.lock().expect("calls");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].2, StoredRecordType::JournalCommit);
        assert_eq!(calls[1].2, StoredRecordType::JournalCommitPointer);
        let commit: JournalCommit =
            serde_json::from_slice(&calls[0].1).expect("deserialize commit");
        let pointer: JournalCommitPointer =
            serde_json::from_slice(&calls[1].1).expect("deserialize pointer");
        assert_eq!(
            calls[0].0,
            commit_dht_key(&commit.issuer_node_id, commit.sequence)
        );
        assert_eq!(calls[1].0, latest_dht_key(&pointer.issuer_node_id));
        assert_eq!(verify_pointer(&pointer), Ok(()));
    }

    #[tokio::test]
    async fn publish_once_increments_sequence() {
        let (publisher, _, _directory) = publisher();
        assert_eq!(publisher.publish_once(100).await.expect("first publish"), 1);
        assert_eq!(
            publisher.publish_once(200).await.expect("second publish"),
            2
        );
    }

    #[tokio::test]
    async fn publish_once_persists_local_record() {
        let (publisher, _, _directory) = publisher();
        publisher.publish_once(100).await.expect("publish");
        let storage = publisher.storage.lock().expect("storage lock");
        let latest = latest_journal_commit_for_storage(&storage).expect("read commit");
        assert_eq!(latest.map(|record| record.sequence), Some(1));
    }

    #[tokio::test]
    async fn publish_once_serializes_valid_commit() {
        let (publisher, transport, _directory) = publisher();
        publisher.publish_once(100).await.expect("publish");
        let calls = transport.calls.lock().expect("calls");
        let commit: JournalCommit =
            serde_json::from_slice(&calls[0].1).expect("deserialize commit");
        assert_eq!(verify_commit(&commit), Ok(()));
    }

    #[tokio::test]
    async fn publish_once_empty_journal_publishes_empty_root() {
        let (publisher, transport, _directory) = publisher();
        publisher.publish_once(100).await.expect("publish");
        let calls = transport.calls.lock().expect("calls");
        let commit: JournalCommit =
            serde_json::from_slice(&calls[0].1).expect("deserialize commit");
        assert_eq!(commit.root, empty_root());
        assert_eq!(commit.leaf_count, 0);
    }

    #[test]
    fn publish_interval_uses_default_24h() {
        assert_eq!(DEFAULT_PUBLISH_INTERVAL_SECS, 86_400);
    }

    #[test]
    fn typed_signature_extractor_supports_jury_commitments() {
        let key = SigningKey::from_bytes(&[93; 32]);
        let record = sign_commitment(
            &key,
            [94; 32],
            vec![RISTRETTO_BASEPOINT_POINT.compress().to_bytes(); JURY_THRESHOLD as usize],
            100,
        )
        .expect("sign commitment");
        let value = serde_json::to_vec(&record).expect("serialize commitment");
        assert_eq!(
            typed_record_signature(StoredRecordType::JuryDkgCommitment, &value)
                .expect("extract signature"),
            record.signature
        );
    }
}
