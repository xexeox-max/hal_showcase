use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use hal_settings::NetworkTrustPolicy;
use tokio::sync::oneshot;
use tokio::time::{interval_at, Instant, MissedTickBehavior};

use crate::dht::endpoint::EndpointCache;
use crate::dht::endpoint_lookup::{DhtEndpointLookup, EndpointLookup};
use crate::dht::routing::RoutingTable;
use crate::dht::NodeId;
use crate::journal::SyncEvent;
use crate::pinning::KnownHosts;
use crate::runtime_context::RuntimeContext;
use crate::transport::{send_envelope_secure, SyncEnvelope};
use hal_storage::jury_outbox::{
    list_due_outbox, prune_expired_outbox, record_attempt_failure, remove_outbox, OutboxEntry,
    OutboxKind,
};

pub const OUTBOX_TICK_SECS: u64 = 30;
pub const OUTBOX_BATCH_LIMIT: u32 = 32;
pub const OUTBOX_BASE_BACKOFF_SECS: u64 = 60;
pub const OUTBOX_MAX_BACKOFF_SECS: u64 = 3600;

pub const INVITATION_DEADLINE_SECS: u64 = 48 * 3600;
pub const SHARE_DEADLINE_SECS: u64 = 24 * 3600;
pub const ACK_DEADLINE_SECS: u64 = 24 * 3600;
pub const RESPONSE_DEADLINE_SECS: u64 = 48 * 3600;

pub fn compute_backoff(attempts: u32) -> u64 {
    let shift = attempts.min(6);
    let base = OUTBOX_BASE_BACKOFF_SECS.saturating_mul(1u64 << shift);
    base.min(OUTBOX_MAX_BACKOFF_SECS)
}

pub fn enqueue_invitation(
    ctx: &Arc<RuntimeContext>,
    event: SyncEvent,
    complaint_id: [u8; 32],
    candidate_node_id: [u8; 32],
    message_id: [u8; 32],
    now: u64,
) -> Result<()> {
    enqueue_impl(
        ctx,
        event,
        OutboxKind::Invitation,
        complaint_id,
        candidate_node_id,
        message_id,
        now.saturating_add(INVITATION_DEADLINE_SECS),
        now,
    )
}

pub fn enqueue_invitation_response(
    ctx: &Arc<RuntimeContext>,
    event: SyncEvent,
    complaint_id: [u8; 32],
    complainant_node_id: [u8; 32],
    message_id: [u8; 32],
    now: u64,
) -> Result<()> {
    enqueue_impl(
        ctx,
        event,
        OutboxKind::InvitationResponse,
        complaint_id,
        complainant_node_id,
        message_id,
        now.saturating_add(RESPONSE_DEADLINE_SECS),
        now,
    )
}

pub fn enqueue_share_delivery(
    ctx: &Arc<RuntimeContext>,
    event: SyncEvent,
    complaint_id: [u8; 32],
    recipient_node_id: [u8; 32],
    message_id: [u8; 32],
    now: u64,
) -> Result<()> {
    enqueue_impl(
        ctx,
        event,
        OutboxKind::ShareDelivery,
        complaint_id,
        recipient_node_id,
        message_id,
        now.saturating_add(SHARE_DEADLINE_SECS),
        now,
    )
}

pub fn enqueue_share_ack(
    ctx: &Arc<RuntimeContext>,
    event: SyncEvent,
    complaint_id: [u8; 32],
    dealer_node_id: [u8; 32],
    message_id: [u8; 32],
    now: u64,
) -> Result<()> {
    enqueue_impl(
        ctx,
        event,
        OutboxKind::ShareAck,
        complaint_id,
        dealer_node_id,
        message_id,
        now.saturating_add(ACK_DEADLINE_SECS),
        now,
    )
}

fn enqueue_impl(
    ctx: &Arc<RuntimeContext>,
    event: SyncEvent,
    kind: OutboxKind,
    complaint_id: [u8; 32],
    recipient_node_id: [u8; 32],
    message_id: [u8; 32],
    deadline: u64,
    now: u64,
) -> Result<()> {
    let storage_arc = ctx
        .storage
        .as_ref()
        .context("storage required for jury outbox")?;
    let event_blob = serde_json::to_vec(&event).context("serialize sync event for outbox")?;
    let storage = storage_arc
        .lock()
        .map_err(|_| anyhow!("storage lock poisoned"))?;
    let entry = OutboxEntry {
        message_id,
        kind,
        complaint_id,
        recipient_node_id,
        event_blob,
        event_id: event.id.clone(),
        created_at: now,
        next_attempt_at: now.saturating_add(OUTBOX_BASE_BACKOFF_SECS),
        attempts: 0,
        deadline,
        last_error: None,
    };
    hal_storage::jury_outbox::enqueue_outbox(storage.connection(), &entry)
}

fn complete_successful_send(
    storage: &hal_storage::ClientStorage,
    entry: &OutboxEntry,
    now: u64,
) -> Result<()> {
    match entry.kind {
        OutboxKind::ShareAck | OutboxKind::InvitationResponse => {
            remove_outbox(storage.connection(), &entry.message_id)?;
            log::debug!(
                "jury outbox delivered+removed {} to {}",
                hex::encode(entry.message_id),
                hex::encode(entry.recipient_node_id)
            );
        }
        OutboxKind::Invitation | OutboxKind::ShareDelivery => {
            let next_attempt = now.saturating_add(compute_backoff(entry.attempts));
            record_attempt_failure(
                storage.connection(),
                &entry.message_id,
                next_attempt,
                "awaiting protocol response",
            )?;
            log::debug!(
                "jury outbox sent {} to {}, awaiting protocol response",
                hex::encode(entry.message_id),
                hex::encode(entry.recipient_node_id)
            );
        }
    }
    Ok(())
}

pub struct JuryOutboxTask {
    ctx: Arc<RuntimeContext>,
    signing_key: SigningKey,
    dht_local_id: NodeId,
    hosts: Arc<std::sync::Mutex<KnownHosts>>,
    dht_routing: Arc<tokio::sync::Mutex<RoutingTable>>,
    dht_cache: Arc<tokio::sync::Mutex<EndpointCache>>,
    trust_policy: NetworkTrustPolicy,
    tick_secs: u64,
}

impl JuryOutboxTask {
    pub fn new(
        ctx: Arc<RuntimeContext>,
        signing_key: SigningKey,
        dht_local_id: NodeId,
        hosts: Arc<std::sync::Mutex<KnownHosts>>,
        dht_routing: Arc<tokio::sync::Mutex<RoutingTable>>,
        dht_cache: Arc<tokio::sync::Mutex<EndpointCache>>,
        trust_policy: NetworkTrustPolicy,
    ) -> Self {
        Self {
            ctx,
            signing_key,
            dht_local_id,
            hosts,
            dht_routing,
            dht_cache,
            trust_policy,
            tick_secs: OUTBOX_TICK_SECS,
        }
    }

    pub fn with_tick_secs(mut self, secs: u64) -> Self {
        self.tick_secs = secs;
        self
    }

    pub async fn run(task: Arc<Self>, mut shutdown: oneshot::Receiver<()>) {
        let period = Duration::from_secs(task.tick_secs.max(1));
        let mut ticker = interval_at(Instant::now() + period, period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    log::debug!("jury outbox task stopped");
                    break;
                }
                _ = ticker.tick() => {
                    if let Err(error) = task.tick().await {
                        log::warn!("jury outbox tick failed: {error}");
                    }
                }
            }
        }
    }

    async fn tick(&self) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock precedes Unix epoch")?
            .as_secs();

        let due = {
            let storage_arc = self
                .ctx
                .storage
                .as_ref()
                .context("storage required for outbox tick")?;
            let storage = storage_arc
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            let connection = storage.connection();
            let pruned = prune_expired_outbox(connection, now)?;
            if pruned > 0 {
                log::debug!("jury outbox pruned {} expired entries", pruned);
            }
            list_due_outbox(connection, now, OUTBOX_BATCH_LIMIT)?
        };

        for entry in due {
            if let Err(error) = self.attempt_delivery(entry, now).await {
                log::warn!("jury outbox delivery failed: {error}");
            }
        }
        Ok(())
    }

    async fn attempt_delivery(&self, entry: OutboxEntry, now: u64) -> Result<()> {
        let event: SyncEvent =
            serde_json::from_slice(&entry.event_blob).context("deserialize outbox event")?;
        let endpoint_lookup: Arc<dyn EndpointLookup> = Arc::new(DhtEndpointLookup::new(
            self.dht_local_id,
            self.signing_key.clone(),
            Arc::clone(&self.hosts),
            self.trust_policy.clone(),
            Arc::clone(&self.dht_routing),
            Arc::clone(&self.dht_cache),
        ));
        let addresses = endpoint_lookup
            .lookup(&NodeId::from_bytes(entry.recipient_node_id), now)
            .await;
        if addresses.is_empty() {
            let next_attempt = now.saturating_add(compute_backoff(entry.attempts));
            {
                let storage_arc = self
                    .ctx
                    .storage
                    .as_ref()
                    .context("storage required for outbox failure")?;
                let storage = storage_arc
                    .lock()
                    .map_err(|_| anyhow!("storage lock poisoned"))?;
                record_attempt_failure(
                    storage.connection(),
                    &entry.message_id,
                    next_attempt,
                    "no endpoint for recipient",
                )?;
            }
            return Ok(());
        }

        let envelope = SyncEnvelope::new(
            self.ctx.identity_id.clone(),
            self.ctx.public_key.clone(),
            vec![event],
        );

        let mut last_error = None;
        for address in addresses {
            let hosts = Arc::clone(&self.ctx.hosts);
            let policy = self.trust_policy.clone();
            match send_envelope_secure(
                &address.to_string(),
                &envelope,
                &self.signing_key,
                hosts,
                policy,
            )
            .await
            {
                Ok(()) => {
                    {
                        let storage_arc = self
                            .ctx
                            .storage
                            .as_ref()
                            .context("storage required for outbox success")?;
                        let storage = storage_arc
                            .lock()
                            .map_err(|_| anyhow!("storage lock poisoned"))?;
                        complete_successful_send(&storage, &entry, now)?;
                    }
                    return Ok(());
                }
                Err(error) => {
                    last_error = Some(error.to_string());
                    log::warn!("jury outbox send failed to {}: {error}", address);
                }
            }
        }

        let next_attempt = now.saturating_add(compute_backoff(entry.attempts));
        {
            let storage_arc = self
                .ctx
                .storage
                .as_ref()
                .context("storage required for outbox failure")?;
            let storage = storage_arc
                .lock()
                .map_err(|_| anyhow!("storage lock poisoned"))?;
            record_attempt_failure(
                storage.connection(),
                &entry.message_id,
                next_attempt,
                last_error.as_deref().unwrap_or("send failed"),
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hal_storage::ClientStorage;
    use std::path::PathBuf;

    fn assert_send_sync<T: Send + Sync>() {}

    fn test_storage() -> (tempfile::TempDir, ClientStorage) {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path: PathBuf = dir.path().join("jury-outbox.db");
        let storage = ClientStorage::open(path, &[17; 32]).expect("open test storage");
        (dir, storage)
    }

    fn outbox_entry(kind: OutboxKind, message_id: [u8; 32]) -> OutboxEntry {
        OutboxEntry {
            message_id,
            kind,
            complaint_id: [2; 32],
            recipient_node_id: [3; 32],
            event_blob: b"event".to_vec(),
            event_id: "event-1".to_string(),
            created_at: 10,
            next_attempt_at: 20,
            attempts: 0,
            deadline: 1000,
            last_error: None,
        }
    }

    fn insert_entry(storage: &ClientStorage, entry: &OutboxEntry) {
        hal_storage::jury_outbox::enqueue_outbox(storage.connection(), entry)
            .expect("insert outbox entry");
    }

    #[test]
    fn jury_outbox_task_is_send_sync() {
        assert_send_sync::<JuryOutboxTask>();
    }

    #[test]
    fn attempt_delivery_removes_share_ack_after_send() {
        let (_dir, storage) = test_storage();
        let entry = outbox_entry(OutboxKind::ShareAck, [1; 32]);
        insert_entry(&storage, &entry);

        complete_successful_send(&storage, &entry, 30).expect("complete send");

        assert!(hal_storage::jury_outbox::read_outbox_entry(
            storage.connection(),
            &entry.message_id
        )
        .expect("read entry")
        .is_none());
    }

    #[test]
    fn attempt_delivery_keeps_share_delivery_awaiting_ack() {
        let (_dir, storage) = test_storage();
        let entry = outbox_entry(OutboxKind::ShareDelivery, [2; 32]);
        insert_entry(&storage, &entry);

        complete_successful_send(&storage, &entry, 30).expect("complete send");

        let stored =
            hal_storage::jury_outbox::read_outbox_entry(storage.connection(), &entry.message_id)
                .expect("read entry")
                .expect("entry remains until ACK");
        assert_eq!(stored.next_attempt_at, 30 + OUTBOX_BASE_BACKOFF_SECS);
        assert_eq!(stored.attempts, 1);
        assert_eq!(
            stored.last_error.as_deref(),
            Some("awaiting protocol response")
        );
    }

    #[test]
    fn attempt_delivery_keeps_invitation_awaiting_response() {
        let (_dir, storage) = test_storage();
        let entry = outbox_entry(OutboxKind::Invitation, [3; 32]);
        insert_entry(&storage, &entry);

        complete_successful_send(&storage, &entry, 30).expect("complete send");

        let stored =
            hal_storage::jury_outbox::read_outbox_entry(storage.connection(), &entry.message_id)
                .expect("read entry")
                .expect("entry remains until response");
        assert_eq!(stored.next_attempt_at, 30 + OUTBOX_BASE_BACKOFF_SECS);
        assert_eq!(stored.attempts, 1);
    }

    #[test]
    fn attempt_delivery_removes_invitation_response_after_send() {
        let (_dir, storage) = test_storage();
        let entry = outbox_entry(OutboxKind::InvitationResponse, [4; 32]);
        insert_entry(&storage, &entry);

        complete_successful_send(&storage, &entry, 30).expect("complete send");

        assert!(hal_storage::jury_outbox::read_outbox_entry(
            storage.connection(),
            &entry.message_id
        )
        .expect("read entry")
        .is_none());
    }

    #[test]
    fn compute_backoff_starts_at_base() {
        assert_eq!(compute_backoff(0), OUTBOX_BASE_BACKOFF_SECS);
    }

    #[test]
    fn compute_backoff_grows_and_caps() {
        assert_eq!(compute_backoff(1), OUTBOX_BASE_BACKOFF_SECS * 2);
        assert_eq!(compute_backoff(6), OUTBOX_MAX_BACKOFF_SECS);
        assert_eq!(compute_backoff(20), OUTBOX_MAX_BACKOFF_SECS);
    }
}
