//! Fetch and persist remote jury DKG commitments through the DHT.

use std::sync::{Arc, Mutex as StdMutex};

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use hal_settings::NetworkTrustPolicy;
use hal_storage::jury_commitments::{
    persist_jury_commitment, read_jury_commitment, JuryCommitmentRecord,
};
use hal_storage::ClientStorage;
use tokio::sync::Mutex;

use crate::dht::jury_dkg_commitment::{
    commitment_dht_key, verify_commitment, JuryDkgCommitmentRecord, JURY_DKG_COMMITMENT_TTL_SECS,
};
use crate::dht::lookup::{Lookup, LookupConfig};
use crate::dht::mux_transport::MuxDhtTransport;
use crate::dht::routing::RoutingTable;
use crate::dht::NodeId;
use crate::pinning::KnownHosts;

pub struct JurorCommitmentFetcher {
    local_id: NodeId,
    signing_key: SigningKey,
    hosts: Arc<StdMutex<KnownHosts>>,
    routing: Arc<Mutex<RoutingTable>>,
    trust_policy: NetworkTrustPolicy,
}

impl JurorCommitmentFetcher {
    pub fn new(
        local_id: NodeId,
        signing_key: SigningKey,
        hosts: Arc<StdMutex<KnownHosts>>,
        routing: Arc<Mutex<RoutingTable>>,
        trust_policy: NetworkTrustPolicy,
    ) -> Self {
        Self {
            local_id,
            signing_key,
            hosts,
            routing,
            trust_policy,
        }
    }

    /// Fetch, verify, and persist one dealer commitment; return `None` when absent or expired.
    pub async fn fetch_commitment(
        &self,
        storage: &Arc<StdMutex<ClientStorage>>,
        complaint_id: &[u8; 32],
        dealer_node_id: &[u8; 32],
        now: u64,
    ) -> Result<Option<()>> {
        {
            let storage = storage
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            if let Some(existing) =
                read_jury_commitment(storage.connection(), complaint_id, dealer_node_id)?
            {
                if existing.expires_at > now {
                    let record = dht_record_from_storage(existing);
                    verify_commitment(&record).context("verify locally stored jury commitment")?;
                    validate_record_binding(&record, complaint_id, dealer_node_id)?;
                    return Ok(Some(()));
                }
            }
        }

        let key = commitment_dht_key(complaint_id, dealer_node_id);
        let transport = MuxDhtTransport::new(
            self.signing_key.clone(),
            Arc::clone(&self.hosts),
            self.trust_policy.clone(),
        );
        let mut routing = self.routing.lock().await;
        let mut lookup = Lookup::new(
            self.local_id,
            NodeId::from_bytes(key),
            LookupConfig::default(),
            &transport,
            &mut routing,
        );
        let result = lookup
            .find_value(key)
            .await
            .context("DHT find_value for jury commitment")?;
        drop(lookup);
        drop(routing);

        let Some(value) = result.value else {
            return Ok(None);
        };
        if value.expires_at <= now {
            return Ok(None);
        }
        let record: JuryDkgCommitmentRecord = serde_json::from_slice(&value.value)
            .context("deserialize fetched jury commitment record")?;
        verify_commitment(&record).context("verify fetched jury commitment")?;
        validate_record_binding(&record, complaint_id, dealer_node_id)?;
        if value.signature.as_slice() != record.signature {
            return Err(anyhow!(
                "fetched commitment DHT signature does not match signed record"
            ));
        }
        let expected_expiry = record
            .published_at
            .checked_add(JURY_DKG_COMMITMENT_TTL_SECS)
            .context("fetched commitment expiry overflow")?;
        if value.expires_at != expected_expiry {
            return Err(anyhow!("fetched commitment expiry does not match its TTL"));
        }
        if record.published_at > now {
            return Err(anyhow!(
                "fetched commitment publication time is in the future"
            ));
        }

        let storage_record = JuryCommitmentRecord {
            complaint_id: record.complaint_id,
            dealer_node_id: record.dealer_node_id,
            dealer_public_key: record.dealer_public_key,
            commitments: record.commitments,
            threshold: record.threshold,
            participant_count: record.participant_count,
            published_at: record.published_at,
            signature: record.signature,
            expires_at: value.expires_at,
        };
        let mut storage = storage
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        persist_jury_commitment(&mut storage, &storage_record)
            .context("persist fetched jury commitment")?;
        Ok(Some(()))
    }
}

fn validate_record_binding(
    record: &JuryDkgCommitmentRecord,
    complaint_id: &[u8; 32],
    dealer_node_id: &[u8; 32],
) -> Result<()> {
    if &record.complaint_id != complaint_id {
        return Err(anyhow!("fetched commitment has wrong complaint_id"));
    }
    if &record.dealer_node_id != dealer_node_id {
        return Err(anyhow!("fetched commitment has wrong dealer_node_id"));
    }
    Ok(())
}

fn dht_record_from_storage(record: JuryCommitmentRecord) -> JuryDkgCommitmentRecord {
    JuryDkgCommitmentRecord {
        complaint_id: record.complaint_id,
        dealer_node_id: record.dealer_node_id,
        dealer_public_key: record.dealer_public_key,
        commitments: record.commitments,
        threshold: record.threshold,
        participant_count: record.participant_count,
        published_at: record.published_at,
        signature: record.signature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use hal_storage::jury_commitments::persist_jury_commitment;

    fn setup() -> (
        JurorCommitmentFetcher,
        Arc<StdMutex<ClientStorage>>,
        SigningKey,
        tempfile::TempDir,
    ) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(directory.path().join("commitment-fetcher.db"), &[7; 32])
                .expect("open storage"),
        ));
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let local_id = NodeId::from_public_key(&signing_key.verifying_key());
        let fetcher = JurorCommitmentFetcher::new(
            local_id,
            signing_key.clone(),
            Arc::new(StdMutex::new(KnownHosts::new())),
            Arc::new(Mutex::new(RoutingTable::new(local_id))),
            NetworkTrustPolicy::default(),
        );
        (fetcher, storage, signing_key, directory)
    }

    #[tokio::test]
    async fn fetch_returns_some_when_local_exists() {
        let (fetcher, storage, dealer_key, _directory) = setup();
        let complaint_id = [3; 32];
        let record = crate::dht::jury_dkg_commitment::sign_commitment(
            &dealer_key,
            complaint_id,
            vec![RISTRETTO_BASEPOINT_POINT.compress().to_bytes(); 5],
            100,
        )
        .expect("sign commitment");
        let storage_record = JuryCommitmentRecord {
            complaint_id,
            dealer_node_id: record.dealer_node_id,
            dealer_public_key: record.dealer_public_key,
            commitments: record.commitments,
            threshold: record.threshold,
            participant_count: record.participant_count,
            published_at: record.published_at,
            signature: record.signature,
            expires_at: 100 + JURY_DKG_COMMITMENT_TTL_SECS,
        };
        persist_jury_commitment(&mut storage.lock().expect("storage lock"), &storage_record)
            .expect("persist local commitment");

        let result = fetcher
            .fetch_commitment(&storage, &complaint_id, &storage_record.dealer_node_id, 200)
            .await
            .expect("fetch local commitment");

        assert_eq!(result, Some(()));
    }

    #[tokio::test]
    async fn fetch_returns_none_when_no_value() {
        let (fetcher, storage, _signing_key, _directory) = setup();
        let result = fetcher
            .fetch_commitment(&storage, &[4; 32], &[5; 32], 200)
            .await
            .expect("lookup with empty routing table");
        assert_eq!(result, None);
    }
}
