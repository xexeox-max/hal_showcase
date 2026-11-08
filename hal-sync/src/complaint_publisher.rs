//! Local persistence and DHT publication for signed complaints.

use std::sync::{Arc, Mutex as StdMutex};

use anyhow::{anyhow, Context, Result};
use hal_storage::complaints::{persist_complaint, ComplaintRow};
use hal_storage::ClientStorage;
use tokio::sync::Mutex;

use crate::dht::complaint::{
    complaint_dht_key, verify_complaint, ComplaintRecord, DepositHook, NoOpDepositHook,
    COMPLAINT_TTL_SECS,
};
use crate::dht::node_id::NodeId;
use crate::dht::routing::{RoutingTable, K};
use crate::dht::transport::DhtTransport;
use crate::dht::wire::{DhtRequest, DhtRequestPayload, DhtResponsePayload, StoredRecordType};
use crate::runtime_context::RuntimeContext;

pub struct ComplaintPublisher {
    local_id: NodeId,
    routing: Arc<Mutex<RoutingTable>>,
    transport: Arc<dyn DhtTransport>,
    storage: Arc<StdMutex<ClientStorage>>,
    deposit_hook: Arc<dyn DepositHook>,
}

impl ComplaintPublisher {
    pub fn new(
        local_id: NodeId,
        routing: Arc<Mutex<RoutingTable>>,
        transport: Arc<dyn DhtTransport>,
        storage: Arc<StdMutex<ClientStorage>>,
        deposit_hook: Arc<dyn DepositHook>,
    ) -> Self {
        Self {
            local_id,
            routing,
            transport,
            storage,
            deposit_hook,
        }
    }

    pub fn new_with_noop_deposit(
        local_id: NodeId,
        routing: Arc<Mutex<RoutingTable>>,
        transport: Arc<dyn DhtTransport>,
        storage: Arc<StdMutex<ClientStorage>>,
    ) -> Self {
        Self::new(
            local_id,
            routing,
            transport,
            storage,
            Arc::new(NoOpDepositHook),
        )
    }

    /// Reserve the complainant's deposit, persist the signed record, then publish it.
    pub async fn submit(&self, record: &ComplaintRecord, now: u64) -> Result<[u8; 32]> {
        verify_complaint(record).context("verify complaint before submission")?;
        if record.complainant_node_id != self.local_id.0 {
            return Err(anyhow!(
                "complaint signer does not match local DHT identity"
            ));
        }
        if record.submitted_at > now {
            return Err(anyhow!("complaint submission time is in the future"));
        }
        let expires_at = record
            .submitted_at
            .checked_add(COMPLAINT_TTL_SECS)
            .ok_or_else(|| anyhow!("complaint expiry overflow"))?;
        if expires_at <= now {
            return Err(anyhow!("complaint has expired"));
        }

        let value = serde_json::to_vec(record).context("serialize complaint record")?;
        let row = to_complaint_row(record, value.clone());
        self.deposit_hook
            .reserve(&record.complainant_node_id, &record.complaint_id)
            .await
            .context("reserve complaint deposit")?;
        let persist_result = match self.storage.lock() {
            Ok(mut storage) => persist_complaint(&mut storage, &row, expires_at)
                .context("persist complaint before DHT publication"),
            Err(_) => Err(anyhow!("storage lock poisoned")),
        };
        if let Err(error) = persist_result {
            if let Err(release_error) = self.deposit_hook.release(&record.complaint_id).await {
                return Err(error.context(format!(
                    "also failed to release complaint deposit: {release_error}"
                )));
            }
            return Err(error);
        }

        let key = complaint_dht_key(&record.complaint_id);
        self.publish_typed(key, value, record.signature.to_vec(), expires_at)
            .await
            .context("publish complaint record")?;
        Ok(key)
    }

    /// Submit a complaint and register its complainant assembly state.
    pub async fn submit_with_ctx(
        &self,
        ctx: &Arc<RuntimeContext>,
        record: &ComplaintRecord,
        now: u64,
    ) -> Result<[u8; 32]> {
        let dht_key = self.submit(record, now).await?;
        crate::jury_assembly::register_complainant_state(ctx, record.complaint_id, now)?;
        Ok(dht_key)
    }

    async fn publish_typed(
        &self,
        key: [u8; 32],
        value: Vec<u8>,
        signature: Vec<u8>,
        expires_at: u64,
    ) -> Result<()> {
        let target = NodeId::from_bytes(key);
        let peers = self.routing.lock().await.closest(&target, K);
        if peers.is_empty() {
            return Err(anyhow!("no DHT peers available for complaint publication"));
        }

        let mut errors = Vec::new();
        let mut stored = false;
        for peer in peers {
            let request = DhtRequest::new(
                DhtRequestPayload::StoreTyped {
                    key,
                    value: value.clone(),
                    signature: signature.clone(),
                    expires_at,
                    record_type: Some(StoredRecordType::ComplaintRecord),
                },
                self.local_id,
                now_unix()?,
            );
            let request_id = request.request_id;
            match self.transport.send_request(&peer, request).await {
                Ok(response) => {
                    if let Err(error) = response.validate(
                        &request_id,
                        now_unix().context("read clock while validating DHT response")?,
                    ) {
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
                        DhtResponsePayload::Error { code, message } => errors.push(format!(
                            "peer {:?} rejected store ({code}): {message}",
                            peer.node_id
                        )),
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
                "complaint publication failed on all candidate peers: {}",
                errors.join("; ")
            ))
        }
    }
}

fn to_complaint_row(record: &ComplaintRecord, record_blob: Vec<u8>) -> ComplaintRow {
    ComplaintRow {
        complaint_id: record.complaint_id,
        complainant_node_id: record.complainant_node_id,
        subject_node_id: record.subject_node_id,
        kind_tag: record.kind.tag(),
        period_start: record.period_start,
        period_end: record.period_end,
        submitted_at: record.submitted_at,
        record_blob,
    }
}

fn now_unix() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock precedes Unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::complaint::{create_complaint, ComplaintKind};
    use crate::dht::peer_info::PeerInfo;
    use crate::dht::routing::RoutingTable;
    use crate::dht::wire::{DhtResponse, DHT_PROTOCOL_VERSION};
    use crate::dht::{
        BasicTrustOracle, GroupGraph, GroupRegistry, RateLimiter, TrustMetrics, TrustScoreManager,
    };
    use crate::runtime::HomeRuntimeState;
    use crate::runtime_context::{NoopBiometricGate, RuntimeContext};
    use async_trait::async_trait;
    use ed25519_dalek::SigningKey;
    use hal_storage::ClientStorage;
    use sha2::{Digest, Sha256};
    use tokio::sync::Mutex as TokioMutex;

    struct MockTransport;

    #[async_trait]
    impl DhtTransport for MockTransport {
        async fn send_request(
            &self,
            _peer: &PeerInfo,
            request: DhtRequest,
        ) -> std::result::Result<DhtResponse, crate::dht::wire::DhtError> {
            let DhtRequestPayload::StoreTyped {
                key,
                record_type: Some(StoredRecordType::ComplaintRecord),
                ..
            } = request.payload
            else {
                return Err(crate::dht::wire::DhtError::InvalidRequest(
                    "expected complaint typed store".into(),
                ));
            };
            Ok(DhtResponse {
                version: DHT_PROTOCOL_VERSION,
                request_id: request.request_id,
                responder_node_id: NodeId::from_bytes([44; 32]),
                timestamp: now_unix().map_err(|_| {
                    crate::dht::wire::DhtError::InvalidRequest("clock error".into())
                })?,
                payload: DhtResponsePayload::Stored { key },
            })
        }
    }

    #[derive(Default)]
    struct RecordingDepositHook {
        reserved: StdMutex<Vec<[u8; 32]>>,
        released: StdMutex<Vec<[u8; 32]>>,
    }

    #[async_trait]
    impl DepositHook for RecordingDepositHook {
        async fn reserve(
            &self,
            _complainant_node_id: &[u8; 32],
            complaint_id: &[u8; 32],
        ) -> Result<()> {
            self.reserved
                .lock()
                .map_err(|_| anyhow!("deposit test lock poisoned"))?
                .push(*complaint_id);
            Ok(())
        }

        async fn release(&self, complaint_id: &[u8; 32]) -> Result<()> {
            self.released
                .lock()
                .map_err(|_| anyhow!("deposit test lock poisoned"))?
                .push(*complaint_id);
            Ok(())
        }
    }

    fn setup() -> (
        ComplaintPublisher,
        Arc<RecordingDepositHook>,
        Arc<StdMutex<ClientStorage>>,
        tempfile::TempDir,
    ) {
        let hook = Arc::new(RecordingDepositHook::default());
        let (publisher, storage, directory) = setup_with_hook(Some(hook.clone()));
        (publisher, hook, storage, directory)
    }

    fn setup_with_hook(
        hook: Option<Arc<dyn DepositHook>>,
    ) -> (
        ComplaintPublisher,
        Arc<StdMutex<ClientStorage>>,
        tempfile::TempDir,
    ) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(directory.path().join("complaints.sqlite3"), &[41; 32])
                .expect("open storage"),
        ));
        let key = SigningKey::from_bytes(&[42; 32]);
        let local_id = NodeId::from_bytes(Sha256::digest(key.verifying_key().to_bytes()).into());
        let peer_id = NodeId::from_bytes([43; 32]);
        let mut peer = PeerInfo::new(peer_id, "test-peer".into());
        peer.add_endpoint("127.0.0.1:9001".into(), 100);
        let mut routing = RoutingTable::new(local_id);
        routing.insert(peer, 100);
        let publisher = match hook {
            Some(hook) => ComplaintPublisher::new(
                local_id,
                Arc::new(Mutex::new(routing)),
                Arc::new(MockTransport),
                Arc::clone(&storage),
                hook,
            ),
            None => ComplaintPublisher::new_with_noop_deposit(
                local_id,
                Arc::new(Mutex::new(routing)),
                Arc::new(MockTransport),
                Arc::clone(&storage),
            ),
        };
        (publisher, storage, directory)
    }

    fn runtime_context(
        storage: Arc<StdMutex<ClientStorage>>,
        key: &SigningKey,
    ) -> Arc<RuntimeContext> {
        let hosts = Arc::new(StdMutex::new(crate::pinning::KnownHosts::new()));
        let scores = Arc::new(StdMutex::new(TrustScoreManager::new()));
        let rates = Arc::new(StdMutex::new(RateLimiter::new()));
        let groups: Arc<dyn GroupGraph> = Arc::new(GroupRegistry::new());
        let oracle: Arc<dyn crate::dht::TrustOracle> = Arc::new(BasicTrustOracle::new(
            Arc::clone(&scores),
            Arc::clone(&rates),
            Arc::clone(&hosts),
            Arc::clone(&groups),
        ));
        let (relay_tx, relay_tracker, relay_metrics) = RuntimeContext::default_relay_channels();
        let (badge_store, badge_metrics) = RuntimeContext::default_badge_components();
        let (cold_contact_tracker, auto_badge_queue, abuse_metrics) =
            RuntimeContext::default_abuse_channels();
        let invite_registry = RuntimeContext::default_invite_registry();
        Arc::new(RuntimeContext {
            sync: Arc::new(TokioMutex::new(crate::SyncManager::new(
                "complaint-test".into(),
            ))),
            home_state: Arc::new(TokioMutex::new(HomeRuntimeState::default())),
            media_signals: Arc::new(TokioMutex::new(Vec::new())),
            storage: Some(storage),
            age_tracker: None,
            activity_tracker: None,
            proof_of_live: None,
            hosts,
            scores,
            rates,
            trust_graph: None,
            groups,
            trust_metrics: Arc::new(TrustMetrics::new()),
            oracle,
            address_refresh: Arc::new(crate::address_refresh::AddressRefresh::with_defaults()),
            hole_puncher: Arc::new(crate::hole_punch::HolePuncher::with_defaults()),
            signaling_strategy: Arc::new(crate::signaling::SignalingStrategy::default_hybrid()),
            relay_tx,
            relay_tracker,
            relay_metrics,
            relay_nonce_cache: RuntimeContext::default_relay_nonce_cache(),
            peer_directory: RuntimeContext::default_peer_directory(),
            observable: RuntimeContext::default_observable(),
            prekey_cache: RuntimeContext::default_prekey_cache(),
            local_prekey_store: None,
            session_store: RuntimeContext::session_store_with_metrics(Arc::clone(&abuse_metrics)),
            biometric_gate: Arc::new(NoopBiometricGate),
            invite_registry,
            degradation: RuntimeContext::default_degradation(),
            stigma_cache: RuntimeContext::default_stigma_cache(),
            inbound_observations_tx: RuntimeContext::default_inbound_observations(),
            badge_store,
            badge_metrics,
            badge_fetch_shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cold_contact_tracker,
            auto_badge_queue,
            abuse_metrics,
            identity_id: NodeId::from_public_key(&key.verifying_key()).to_hex(),
            public_key: hex::encode(key.verifying_key().to_bytes()),
            identity_signing_key: Some(Arc::new(key.clone())),
            jury_commitment_publisher: None,
            jury_plaintext_cache: RuntimeContext::default_jury_plaintext_cache(),
            invite_redemption_transport: None,
            pending_invite_redemptions: RuntimeContext::default_pending_invite_redemptions(),
            sas_pairing: RuntimeContext::default_sas_pairing(),
            integrity: None,
        })
    }

    fn valid_complaint() -> ComplaintRecord {
        create_complaint(
            &SigningKey::from_bytes(&[42; 32]),
            [45; 32],
            ComplaintKind::Fraud,
            100,
            200,
            now_unix().expect("clock"),
        )
        .expect("create complaint")
    }

    #[tokio::test]
    async fn submit_reserves_persists_and_publishes() {
        let (publisher, hook, _storage, _directory) = setup();
        let record = valid_complaint();
        let key = publisher
            .submit(&record, now_unix().expect("clock"))
            .await
            .expect("submit");
        assert_eq!(key, complaint_dht_key(&record.complaint_id));
        assert_eq!(
            hook.reserved.lock().expect("reserved").as_slice(),
            &[record.complaint_id]
        );
        let storage = publisher.storage.lock().expect("storage");
        let stored =
            hal_storage::complaints::read_complaint_for_storage(&storage, &record.complaint_id)
                .expect("read stored complaint")
                .expect("complaint exists");
        assert_eq!(
            serde_json::from_slice::<ComplaintRecord>(&stored.record_blob).expect("decode"),
            record
        );
        assert!(hook.released.lock().expect("released").is_empty());
    }

    #[tokio::test]
    async fn submit_with_ctx_registers_complainant_state() {
        let (publisher, storage, _directory) = setup_with_hook(None);
        let key = SigningKey::from_bytes(&[42; 32]);
        let ctx = runtime_context(Arc::clone(&storage), &key);
        let record = valid_complaint();
        let now = now_unix().expect("clock");

        publisher
            .submit_with_ctx(&ctx, &record, now)
            .await
            .expect("submit and register");

        let state = hal_storage::jury_assembly_state::read_complainant_state(
            &storage.lock().expect("storage").connection(),
            &record.complaint_id,
        )
        .expect("read complainant state")
        .expect("state registered");
        assert_eq!(
            state.phase,
            hal_storage::jury_assembly_state::ComplainantPhase::CollectingAcceptances
        );
    }

    #[tokio::test]
    async fn submit_rejects_complaint_signed_by_different_node() {
        let (publisher, hook, _storage, _directory) = setup();
        let record = create_complaint(
            &SigningKey::from_bytes(&[46; 32]),
            [45; 32],
            ComplaintKind::Fraud,
            100,
            200,
            now_unix().expect("clock"),
        )
        .expect("create complaint");
        assert!(publisher
            .submit(&record, now_unix().expect("clock"))
            .await
            .is_err());
        assert!(hook.reserved.lock().expect("reserved").is_empty());
    }

    #[tokio::test]
    async fn noop_hook_is_accepted_as_default_dependency() {
        let (publisher, _storage, _directory) = setup_with_hook(None);
        let record = valid_complaint();
        publisher
            .submit(&record, now_unix().expect("clock"))
            .await
            .expect("submit with no-op hook");
    }
}
