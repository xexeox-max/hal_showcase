use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use hal_crypto::{OneTimePrekey, PrekeyBundle};
use hal_settings::NetworkTrustPolicy;
use tokio::sync::{oneshot, Mutex};
use tokio::time::{interval, Interval};

use crate::abuse_metrics::AbuseMetrics;
use crate::dht::endpoint::PublishReport;
use crate::dht::mux_transport::MuxDhtTransport;
use crate::dht::prekey_cache::{unix_now, PrekeyCache, PrekeyStore};
use crate::dht::routing::RoutingTable;
use crate::dht::NodeId;
use crate::local_prekey_store::LocalPrekeyStore;
use crate::pinning::KnownHosts;
use hal_storage::OPK_RETENTION_SECS;

/// Signed prekeys rotate every seven days.
pub const SIGNED_PREKEY_ROTATION_SECS: u64 = 7 * 86_400;

/// The previous signed prekey remains valid for one day after rotation.
pub const SIGNED_PREKEY_OVERLAP_SECS: u64 = 86_400;

/// Maximum number of unconsumed one-time prekeys.
pub const OPK_POOL_SIZE: usize = 100;

/// Refill the OPK pool when it falls below this count.
pub const OPK_REFILL_THRESHOLD: usize = 20;

/// Background rotation and refill check interval.
pub const ROTATION_CHECK_INTERVAL_SECS: u64 = 3_600;

const PREKEY_BUNDLE_TTL_SECS: u64 = 86_400;

#[async_trait]
trait PrekeyBundlePublisher: Send + Sync {
    async fn publish(&self, bundle: PrekeyBundle, now: u64) -> Result<PublishReport>;
}

struct DhtPrekeyBundlePublisher {
    local_id: NodeId,
    signing_key: SigningKey,
    routing: Arc<Mutex<RoutingTable>>,
    hosts: Arc<StdMutex<KnownHosts>>,
    trust_policy: NetworkTrustPolicy,
    cache: Arc<Mutex<PrekeyCache>>,
    metrics: Arc<AbuseMetrics>,
}

#[async_trait]
impl PrekeyBundlePublisher for DhtPrekeyBundlePublisher {
    async fn publish(&self, bundle: PrekeyBundle, now: u64) -> Result<PublishReport> {
        let transport = MuxDhtTransport::new(
            self.signing_key.clone(),
            Arc::clone(&self.hosts),
            self.trust_policy.clone(),
        );
        let mut routing = self.routing.lock().await;
        let mut cache = self.cache.lock().await;
        let mut store = PrekeyStore::new(
            self.local_id,
            &transport,
            &mut routing,
            &mut cache,
            &self.metrics,
        );
        store.publish(bundle, now).await
    }
}

pub struct PrekeyRotationTask {
    store: Arc<Mutex<LocalPrekeyStore>>,
    metrics: Arc<AbuseMetrics>,
    identity_signing_key: SigningKey,
    publisher: Arc<dyn PrekeyBundlePublisher>,
    check_interval: Duration,
}

impl PrekeyRotationTask {
    pub fn new(
        store: Arc<Mutex<LocalPrekeyStore>>,
        metrics: Arc<AbuseMetrics>,
        identity_signing_key: SigningKey,
        local_id: NodeId,
        routing: Arc<Mutex<RoutingTable>>,
        hosts: Arc<StdMutex<KnownHosts>>,
        trust_policy: NetworkTrustPolicy,
        prekey_cache: Arc<Mutex<PrekeyCache>>,
    ) -> Self {
        let publisher = Arc::new(DhtPrekeyBundlePublisher {
            local_id,
            signing_key: identity_signing_key.clone(),
            routing,
            hosts,
            trust_policy,
            cache: prekey_cache,
            metrics: Arc::clone(&metrics),
        });
        Self {
            store,
            metrics,
            identity_signing_key,
            publisher,
            check_interval: Duration::from_secs(ROTATION_CHECK_INTERVAL_SECS),
        }
    }

    #[cfg(test)]
    fn with_publisher(
        store: Arc<Mutex<LocalPrekeyStore>>,
        metrics: Arc<AbuseMetrics>,
        identity_signing_key: SigningKey,
        publisher: Arc<dyn PrekeyBundlePublisher>,
    ) -> Self {
        Self {
            store,
            metrics,
            identity_signing_key,
            publisher,
            check_interval: Duration::from_secs(ROTATION_CHECK_INTERVAL_SECS),
        }
    }

    pub async fn run(self, mut shutdown: oneshot::Receiver<()>) {
        let mut ticker: Interval = interval(self.check_interval);
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    log::info!("prekey rotation: shutdown");
                    break;
                }
                _ = ticker.tick() => {
                    if let Err(error) = self.run_once(unix_now()).await {
                        log::warn!("prekey rotation failed: {error}");
                    }
                }
            }
        }
    }

    pub(crate) async fn run_once(&self, now: u64) -> Result<()> {
        let result = self.run_once_inner(now).await;
        if result.is_err() {
            self.metrics
                .prekey_rotation_failed_total
                .fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    async fn run_once_inner(&self, now: u64) -> Result<()> {
        let (revision, bundle) = {
            let mut store = self.store.lock().await;
            if let Err(error) = store.prune_consumed_opks(OPK_RETENTION_SECS).await {
                log::warn!("failed pruning consumed one-time prekeys: {error}");
            }
            store.ensure_signed_prekey(now).await?;
            let current = store
                .current_signed_prekey()
                .await?
                .ok_or_else(|| anyhow!("signed prekey missing after initialization"))?;
            if current.expires_at <= now
                || now.saturating_sub(current.created_at) >= SIGNED_PREKEY_ROTATION_SECS
            {
                store.rotate_signed_prekey(now).await?;
                self.metrics
                    .prekey_rotation_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            store.valid_signed_prekeys(now).await?;

            let count = store.opk_count().await?;
            if count < OPK_REFILL_THRESHOLD {
                let generated = store.refill_opk_pool(now).await?;
                if generated > 0 {
                    self.metrics
                        .prekey_opk_refill_total
                        .fetch_add(1, Ordering::Relaxed);
                    self.metrics
                        .prekey_opk_generated_total
                        .fetch_add(generated as u64, Ordering::Relaxed);
                }
            }

            let (revision, published_revision) = store.revision_state().await?;
            if revision <= published_revision {
                (revision, None)
            } else {
                let current = store
                    .current_signed_prekey()
                    .await?
                    .ok_or_else(|| anyhow!("current signed prekey disappeared"))?;
                let opks: Vec<OneTimePrekey> = store.opk_list().await?;
                let expires_at = current
                    .expires_at
                    .min(now.saturating_add(PREKEY_BUNDLE_TTL_SECS));
                if expires_at <= now {
                    return Err(anyhow!("current signed prekey is expired"));
                }
                let bundle = PrekeyBundle::create(
                    &self.identity_signing_key,
                    current.public_key,
                    opks,
                    revision,
                    now,
                    expires_at,
                )?;
                (revision, Some(bundle))
            }
        };

        if let Some(bundle) = bundle {
            let report = self.publisher.publish(bundle, now).await?;
            if report.peers_stored > 0 {
                self.store
                    .lock()
                    .await
                    .mark_revision_published(revision)
                    .await?;
                self.metrics
                    .prekey_publish_from_rotation_total
                    .fetch_add(1, Ordering::Relaxed);
            } else {
                log::warn!(
                    "prekey bundle revision {revision} was not stored by any DHT peer; will retry"
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hal_storage::ClientStorage;
    use std::path::PathBuf;
    const NOW: u64 = 1_800_000_000;

    struct MockPublisher {
        bundles: Mutex<Vec<PrekeyBundle>>,
        stored_peers: Option<usize>,
    }

    impl Default for MockPublisher {
        fn default() -> Self {
            Self {
                bundles: Mutex::new(Vec::new()),
                stored_peers: None,
            }
        }
    }

    #[async_trait]
    impl PrekeyBundlePublisher for MockPublisher {
        async fn publish(&self, bundle: PrekeyBundle, _now: u64) -> Result<PublishReport> {
            self.bundles.lock().await.push(bundle);
            Ok(PublishReport {
                peers_contacted: 1,
                peers_stored: self.stored_peers.unwrap_or(1),
                failures: Vec::new(),
            })
        }
    }

    fn local_store() -> (Arc<Mutex<LocalPrekeyStore>>, PathBuf) {
        let path =
            std::env::temp_dir().join(format!("hal-prekey-task-{}.sqlite3", uuid::Uuid::new_v4()));
        let storage = ClientStorage::open(&path, &[0x70; 32]).expect("encrypted storage");
        (
            Arc::new(Mutex::new(LocalPrekeyStore::new(Arc::new(StdMutex::new(
                storage,
            ))))),
            path,
        )
    }

    fn task(
        store: Arc<Mutex<LocalPrekeyStore>>,
        metrics: Arc<AbuseMetrics>,
        identity: SigningKey,
        publisher: Arc<dyn PrekeyBundlePublisher>,
    ) -> PrekeyRotationTask {
        PrekeyRotationTask::with_publisher(store, metrics, identity, publisher)
    }

    async fn seeded_store() -> (Arc<Mutex<LocalPrekeyStore>>, PathBuf) {
        let (store, path) = local_store();
        {
            let mut locked = store.lock().await;
            locked.ensure_signed_prekey(NOW).await.expect("ensure SPK");
            locked.refill_opk_pool(NOW).await.expect("fill OPKs");
            let (revision, _) = locked.revision_state().await.expect("revision");
            locked
                .mark_revision_published(revision)
                .await
                .expect("mark published");
        }
        (store, path)
    }

    #[tokio::test]
    async fn rotation_fires_when_signed_prekey_old() {
        let (store, path) = local_store();
        let identity = SigningKey::from_bytes(&[81; 32]);
        let metrics = Arc::new(AbuseMetrics::new());
        let publisher = Arc::new(MockPublisher::default());
        let task = task(store.clone(), metrics.clone(), identity, publisher.clone());
        task.run_once(NOW).await.expect("initialization");
        task.run_once(NOW + SIGNED_PREKEY_ROTATION_SECS)
            .await
            .expect("rotation");
        assert_eq!(metrics.snapshot().prekey_rotation_total, 1);
        assert_eq!(publisher.bundles.lock().await.len(), 2);
        drop(task);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn rotation_skipped_when_fresh() {
        let (store, path) = seeded_store().await;
        let identity = SigningKey::from_bytes(&[82; 32]);
        let metrics = Arc::new(AbuseMetrics::new());
        let publisher = Arc::new(MockPublisher::default());
        let task = task(store, metrics.clone(), identity, publisher.clone());
        task.run_once(NOW + 100).await.expect("fresh check");
        assert_eq!(metrics.snapshot().prekey_rotation_total, 0);
        assert!(publisher.bundles.lock().await.is_empty());
        drop(task);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn refill_fires_when_below_threshold() {
        let (store, path) = local_store();
        let identity = SigningKey::from_bytes(&[83; 32]);
        let metrics = Arc::new(AbuseMetrics::new());
        let task = task(
            store.clone(),
            metrics.clone(),
            identity,
            Arc::new(MockPublisher::default()),
        );
        task.run_once(NOW).await.expect("initial refill");
        let count = store.lock().await.opk_count().await.expect("count");
        assert_eq!(count, OPK_POOL_SIZE);
        assert_eq!(metrics.snapshot().prekey_opk_refill_total, 1);
        assert_eq!(
            metrics.snapshot().prekey_opk_generated_total,
            OPK_POOL_SIZE as u64
        );
        drop(task);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn refill_skipped_when_above_threshold() {
        let (store, path) = seeded_store().await;
        let identity = SigningKey::from_bytes(&[84; 32]);
        let metrics = Arc::new(AbuseMetrics::new());
        let task = task(
            store,
            metrics.clone(),
            identity,
            Arc::new(MockPublisher::default()),
        );
        task.run_once(NOW + 100).await.expect("full pool check");
        assert_eq!(metrics.snapshot().prekey_opk_refill_total, 0);
        drop(task);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn publishes_bundle_after_rotation() {
        let (store, path) = local_store();
        let identity = SigningKey::from_bytes(&[85; 32]);
        let metrics = Arc::new(AbuseMetrics::new());
        let publisher = Arc::new(MockPublisher::default());
        let task = task(store, metrics.clone(), identity, publisher.clone());
        task.run_once(NOW).await.expect("initial publish");
        task.run_once(NOW + SIGNED_PREKEY_ROTATION_SECS)
            .await
            .expect("rotated publish");
        let bundles = publisher.bundles.lock().await;
        assert_eq!(bundles.len(), 2);
        assert_eq!(bundles[1].issued_at, NOW + SIGNED_PREKEY_ROTATION_SECS);
        assert_eq!(metrics.snapshot().prekey_publish_from_rotation_total, 2);
        drop(bundles);
        drop(task);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn shutdown_clean() {
        let (store, path) = local_store();
        let identity = SigningKey::from_bytes(&[86; 32]);
        let task = task(
            store,
            Arc::new(AbuseMetrics::new()),
            identity,
            Arc::new(MockPublisher::default()),
        );
        let (shutdown, receiver) = oneshot::channel();
        let join = tokio::spawn(task.run(receiver));
        shutdown.send(()).expect("send shutdown");
        tokio::time::timeout(Duration::from_secs(1), join)
            .await
            .expect("task shutdown timeout")
            .expect("task join");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn does_not_republish_unchanged_state_after_restart() {
        let (store, path) = seeded_store().await;
        let identity = SigningKey::from_bytes(&[87; 32]);
        let metrics = Arc::new(AbuseMetrics::new());
        let publisher = Arc::new(MockPublisher::default());
        let task = task(store, metrics, identity, publisher.clone());
        task.run_once(NOW + 1).await.expect("unchanged state");
        assert!(publisher.bundles.lock().await.is_empty());
        drop(task);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn retries_unpublished_revision() {
        let (store, path) = local_store();
        let identity = SigningKey::from_bytes(&[88; 32]);
        let metrics = Arc::new(AbuseMetrics::new());
        let publisher = Arc::new(MockPublisher {
            bundles: Mutex::new(Vec::new()),
            stored_peers: Some(0),
        });
        let task = task(store, metrics, identity, publisher.clone());
        task.run_once(NOW).await.expect("first publication attempt");
        task.run_once(NOW + 1).await.expect("publication retry");
        assert_eq!(publisher.bundles.lock().await.len(), 2);
        drop(task);
        let _ = std::fs::remove_file(path);
    }
}
