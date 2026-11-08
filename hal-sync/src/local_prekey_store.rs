use std::sync::{Arc, Mutex as StdMutex};

use crate::prekey_rotation_task::{
    OPK_POOL_SIZE, SIGNED_PREKEY_OVERLAP_SECS, SIGNED_PREKEY_ROTATION_SECS,
};
use anyhow::{anyhow, Result};
use hal_crypto::OneTimePrekey;
use hal_storage::{
    ClientStorage, ConsumedOneTimePrekey, PrekeyOpkConsumption, StoredOneTimePrekey,
    StoredSignedPrekey, StoredSignedPrekeyWithPrivate,
};
use thiserror::Error;
use zeroize::Zeroize;

use crate::abuse_metrics::AbuseMetrics;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalPrekeyError {
    #[error("opk {0} not found")]
    OpkNotFound(u32),
    #[error("opk {0} already consumed at {1}")]
    OpkAlreadyConsumed(u32, u64),
    #[error("storage error: {0}")]
    Storage(String),
}

pub struct ConsumedOpk {
    pub id: u32,
    pub privkey: [u8; 32],
    pub pubkey: [u8; 32],
}

impl std::fmt::Debug for ConsumedOpk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConsumedOpk")
            .field("id", &self.id)
            .field("privkey", &"[REDACTED]")
            .field("pubkey", &self.pubkey)
            .finish()
    }
}

impl Drop for ConsumedOpk {
    fn drop(&mut self) {
        self.privkey.zeroize();
    }
}

pub struct SignedPrekeyWithPrivate {
    pub id: i64,
    pub pubkey: [u8; 32],
    pub privkey: [u8; 32],
    pub created_at: u64,
    pub expires_at: u64,
    pub is_current: bool,
}

impl std::fmt::Debug for SignedPrekeyWithPrivate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignedPrekeyWithPrivate")
            .field("id", &self.id)
            .field("pubkey", &self.pubkey)
            .field("privkey", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("is_current", &self.is_current)
            .finish()
    }
}

impl SignedPrekeyWithPrivate {
    fn zeroize_private_key(&mut self) {
        self.privkey.zeroize();
    }
}

impl Drop for SignedPrekeyWithPrivate {
    fn drop(&mut self) {
        self.zeroize_private_key();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPrekey {
    pub id: i64,
    pub public_key: [u8; 32],
    pub created_at: u64,
    pub expires_at: u64,
}

pub struct LocalPrekeyStore {
    storage: Arc<StdMutex<ClientStorage>>,
    metrics: Option<Arc<AbuseMetrics>>,
}

impl LocalPrekeyStore {
    pub fn new(storage: Arc<StdMutex<ClientStorage>>) -> Self {
        Self {
            storage,
            metrics: None,
        }
    }

    pub fn with_metrics(storage: Arc<StdMutex<ClientStorage>>, metrics: Arc<AbuseMetrics>) -> Self {
        Self {
            storage,
            metrics: Some(metrics),
        }
    }

    pub async fn ensure_signed_prekey(&mut self, now: u64) -> Result<bool> {
        if self.current_signed_prekey().await?.is_some() {
            return Ok(false);
        }
        let (mut private_key, public_key) = generate_keypair();
        let expires_at = now
            .saturating_add(SIGNED_PREKEY_ROTATION_SECS.saturating_add(SIGNED_PREKEY_OVERLAP_SECS));
        let result = self.with_storage(|storage| {
            storage.prekey_insert_signed_if_missing(&private_key, &public_key, now, expires_at)
        });
        private_key.zeroize();
        result
    }

    pub async fn rotate_signed_prekey(&mut self, now: u64) -> Result<()> {
        let previous_expires_at = self.current_signed_prekey().await?.map_or(
            now.saturating_add(SIGNED_PREKEY_OVERLAP_SECS),
            |current| {
                current
                    .expires_at
                    .min(now.saturating_add(SIGNED_PREKEY_OVERLAP_SECS))
            },
        );
        let (mut private_key, public_key) = generate_keypair();
        let expires_at = now
            .saturating_add(SIGNED_PREKEY_ROTATION_SECS.saturating_add(SIGNED_PREKEY_OVERLAP_SECS));
        let result = self.with_storage(|storage| {
            storage.prekey_rotate_signed(
                &private_key,
                &public_key,
                now,
                expires_at,
                previous_expires_at,
            )
        });
        private_key.zeroize();
        result
    }

    pub async fn current_signed_prekey(&self) -> Result<Option<SignedPrekey>> {
        self.with_storage(|storage| Ok(storage.prekey_current_signed()?.map(public_signed_prekey)))
    }

    pub async fn current_signed_prekey_with_private(
        &self,
        now: u64,
    ) -> Result<Option<SignedPrekeyWithPrivate>> {
        Ok(self
            .valid_signed_prekeys_with_private(now)
            .await?
            .into_iter()
            .find(|prekey| prekey.is_current))
    }

    pub async fn signed_prekey_with_private(
        &self,
        id: i64,
        now: u64,
    ) -> Result<Option<SignedPrekeyWithPrivate>> {
        Ok(self
            .valid_signed_prekeys_with_private(now)
            .await?
            .into_iter()
            .find(|prekey| prekey.id == id))
    }

    pub async fn signed_prekey_by_public_key_with_private(
        &self,
        pubkey: &[u8; 32],
        now: u64,
    ) -> Result<Option<SignedPrekeyWithPrivate>> {
        Ok(self
            .valid_signed_prekeys_with_private(now)
            .await?
            .into_iter()
            .find(|prekey| &prekey.pubkey == pubkey))
    }

    pub async fn valid_signed_prekeys_with_private(
        &self,
        now: u64,
    ) -> Result<Vec<SignedPrekeyWithPrivate>> {
        self.with_storage(|storage| {
            Ok(storage
                .prekey_valid_signed_with_private(now)?
                .into_iter()
                .map(signed_prekey_with_private)
                .collect())
        })
    }

    pub async fn valid_signed_prekeys(&self, now: u64) -> Result<Vec<SignedPrekey>> {
        self.with_storage(|storage| {
            Ok(storage
                .prekey_valid_signed(now)?
                .into_iter()
                .map(public_signed_prekey)
                .collect())
        })
    }

    pub async fn opk_list(&self) -> Result<Vec<OneTimePrekey>> {
        self.with_storage(|storage| {
            Ok(storage
                .prekey_opk_list()?
                .into_iter()
                .map(public_opk)
                .collect())
        })
    }

    pub async fn refill_opk_pool(&mut self, now: u64) -> Result<usize> {
        let count = self.opk_count().await?;
        if count >= OPK_POOL_SIZE {
            return Ok(0);
        }
        let missing = OPK_POOL_SIZE - count;
        let mut generated = (0..missing).map(|_| generate_keypair()).collect::<Vec<_>>();
        let result = self.with_storage(|storage| {
            storage.prekey_insert_opks(&generated, now)?;
            Ok(generated.len())
        });
        for (private_key, _) in &mut generated {
            private_key.zeroize();
        }
        result
    }

    pub async fn opk_count(&self) -> Result<usize> {
        self.with_storage(|storage| storage.prekey_opk_count())
    }

    pub async fn prune_consumed_opks(&self, older_than_secs: u64) -> Result<usize> {
        self.with_storage(|storage| storage.prune_consumed_opks(older_than_secs))
    }

    pub async fn consume_opk(
        &mut self,
        opk_id: u32,
        now: u64,
    ) -> Result<ConsumedOpk, LocalPrekeyError> {
        let result = self
            .storage
            .lock()
            .map_err(|_| LocalPrekeyError::Storage("client storage lock poisoned".into()))?
            .prekey_consume_opk(opk_id, now)
            .map_err(|error| LocalPrekeyError::Storage(error.to_string()))?;
        match result {
            PrekeyOpkConsumption::Consumed(prekey) => {
                self.increment_metric(|metrics| &metrics.prekey_opk_consumed_total);
                Ok(consumed_opk(prekey))
            }
            PrekeyOpkConsumption::AlreadyConsumed(consumed_at) => {
                self.increment_metric(|metrics| &metrics.prekey_opk_consume_replay_total);
                Err(LocalPrekeyError::OpkAlreadyConsumed(opk_id, consumed_at))
            }
            PrekeyOpkConsumption::NotFound => {
                self.increment_metric(|metrics| &metrics.prekey_opk_consume_not_found_total);
                Err(LocalPrekeyError::OpkNotFound(opk_id))
            }
        }
    }

    pub async fn revision_state(&self) -> Result<(u64, u64)> {
        self.with_storage(|storage| storage.prekey_revision_state())
    }

    pub async fn mark_revision_published(&self, revision: u64) -> Result<()> {
        self.with_storage(|storage| storage.prekey_mark_revision_published(revision))
    }

    fn with_storage<T>(
        &self,
        operation: impl FnOnce(&mut ClientStorage) -> Result<T>,
    ) -> Result<T> {
        let mut storage = self
            .storage
            .lock()
            .map_err(|_| anyhow!("client storage lock poisoned"))?;
        operation(&mut storage)
    }

    fn increment_metric(
        &self,
        counter: impl FnOnce(&AbuseMetrics) -> &std::sync::atomic::AtomicU64,
    ) {
        if let Some(metrics) = &self.metrics {
            counter(metrics).fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

fn consumed_opk(prekey: ConsumedOneTimePrekey) -> ConsumedOpk {
    let (id, privkey, pubkey) = prekey.into_parts();
    ConsumedOpk {
        id,
        privkey,
        pubkey,
    }
}

fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let (secret, public) = hal_crypto::generate_x25519_keypair();
    (secret.to_bytes(), public.to_bytes())
}

fn public_signed_prekey(prekey: StoredSignedPrekey) -> SignedPrekey {
    SignedPrekey {
        id: prekey.id,
        public_key: prekey.public_key,
        created_at: prekey.created_at,
        expires_at: prekey.expires_at,
    }
}

fn signed_prekey_with_private(prekey: StoredSignedPrekeyWithPrivate) -> SignedPrekeyWithPrivate {
    let (id, privkey, pubkey, created_at, expires_at, is_current) = prekey.into_parts();
    SignedPrekeyWithPrivate {
        id,
        pubkey,
        privkey,
        created_at,
        expires_at,
        is_current,
    }
}

fn public_opk(prekey: StoredOneTimePrekey) -> OneTimePrekey {
    OneTimePrekey {
        id: prekey.id,
        public_key: prekey.public_key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hal_storage::PrekeyOpkConsumption;
    use std::path::PathBuf;
    use std::sync::Barrier;
    use x25519_dalek::{PublicKey, StaticSecret};

    const NOW: u64 = 1_800_000_000;

    fn store() -> (LocalPrekeyStore, PathBuf) {
        let path =
            std::env::temp_dir().join(format!("hal-prekey-{}.sqlite3", uuid::Uuid::new_v4()));
        let storage = ClientStorage::open(&path, &[0x6d; 32]).expect("encrypted storage");
        (
            LocalPrekeyStore::new(Arc::new(StdMutex::new(storage))),
            path,
        )
    }

    fn cleanup(path: PathBuf) {
        let _ = std::fs::remove_file(path);
    }

    fn seed_opk(store: &mut LocalPrekeyStore, private: [u8; 32], now: u64) -> u32 {
        let public = PublicKey::from(&StaticSecret::from(private)).to_bytes();
        store
            .with_storage(|storage| {
                let ids = storage.prekey_insert_opks(&[(private, public)], now)?;
                ids.into_iter()
                    .next()
                    .ok_or_else(|| anyhow!("test OPK insertion returned no ID"))
            })
            .expect("seed test OPK")
    }

    #[tokio::test]
    async fn ensure_signed_prekey_creates_if_missing() {
        let (mut store, path) = store();
        assert!(store.ensure_signed_prekey(NOW).await.expect("ensure"));
        let current = store
            .current_signed_prekey()
            .await
            .expect("current")
            .unwrap();
        assert_eq!(current.created_at, NOW);
        assert_eq!(
            current.expires_at,
            NOW + SIGNED_PREKEY_ROTATION_SECS + SIGNED_PREKEY_OVERLAP_SECS
        );
        cleanup(path);
    }

    #[tokio::test]
    async fn ensure_signed_prekey_idempotent() {
        let (mut store, path) = store();
        assert!(store.ensure_signed_prekey(NOW).await.expect("first ensure"));
        let first = store
            .current_signed_prekey()
            .await
            .expect("first key")
            .unwrap();
        assert!(!store
            .ensure_signed_prekey(NOW + 1)
            .await
            .expect("second ensure"));
        assert_eq!(
            store
                .current_signed_prekey()
                .await
                .expect("current")
                .unwrap(),
            first
        );
        cleanup(path);
    }

    #[tokio::test]
    async fn rotate_signed_prekey_moves_old_to_previous() {
        let (mut store, path) = store();
        store.ensure_signed_prekey(NOW).await.expect("ensure");
        let old = store.current_signed_prekey().await.expect("old").unwrap();
        store
            .rotate_signed_prekey(NOW + SIGNED_PREKEY_ROTATION_SECS)
            .await
            .expect("rotate");
        let new = store.current_signed_prekey().await.expect("new").unwrap();
        let previous = store
            .valid_signed_prekeys(NOW + SIGNED_PREKEY_ROTATION_SECS)
            .await
            .expect("valid keys");
        assert_ne!(new.public_key, old.public_key);
        assert!(previous.contains(&old));
        cleanup(path);
    }

    #[tokio::test]
    async fn valid_signed_prekeys_returns_current_and_previous_in_overlap() {
        let (mut store, path) = store();
        store.ensure_signed_prekey(NOW).await.expect("ensure");
        store
            .rotate_signed_prekey(NOW + SIGNED_PREKEY_ROTATION_SECS)
            .await
            .expect("rotate");
        let valid = store
            .valid_signed_prekeys(NOW + SIGNED_PREKEY_ROTATION_SECS)
            .await
            .expect("valid keys");
        assert_eq!(valid.len(), 2);
        assert!(valid.iter().any(|key| key.created_at == NOW));
        assert!(valid
            .iter()
            .any(|key| key.created_at == NOW + SIGNED_PREKEY_ROTATION_SECS));
        cleanup(path);
    }

    #[tokio::test]
    async fn valid_signed_prekeys_excludes_expired_previous() {
        let (mut store, path) = store();
        store.ensure_signed_prekey(NOW).await.expect("ensure");
        store
            .rotate_signed_prekey(NOW + SIGNED_PREKEY_ROTATION_SECS)
            .await
            .expect("rotate");
        let now = NOW + SIGNED_PREKEY_ROTATION_SECS + SIGNED_PREKEY_OVERLAP_SECS;
        let valid = store.valid_signed_prekeys(now).await.expect("valid keys");
        assert_eq!(valid.len(), 1);
        cleanup(path);
    }

    #[tokio::test]
    async fn delayed_rotation_does_not_extend_expired_previous_key() {
        let (mut store, path) = store();
        store.ensure_signed_prekey(NOW).await.expect("ensure");
        let delayed_rotation = NOW + SIGNED_PREKEY_ROTATION_SECS + SIGNED_PREKEY_OVERLAP_SECS;
        store
            .rotate_signed_prekey(delayed_rotation)
            .await
            .expect("delayed rotation");
        let valid = store
            .valid_signed_prekeys(delayed_rotation)
            .await
            .expect("valid keys");
        assert_eq!(valid.len(), 1);
        assert_eq!(valid[0].created_at, delayed_rotation);
        cleanup(path);
    }

    #[tokio::test]
    async fn current_signed_prekey_with_private_returns_private_key() {
        let (mut store, path) = store();
        store.ensure_signed_prekey(NOW).await.expect("ensure");
        let signed = store
            .current_signed_prekey_with_private(NOW)
            .await
            .expect("private current")
            .expect("current SPK");
        assert_eq!(
            PublicKey::from(&StaticSecret::from(signed.privkey)).to_bytes(),
            signed.pubkey
        );
        assert!(signed.is_current);
        drop(signed);
        cleanup(path);
    }

    #[tokio::test]
    async fn current_signed_prekey_with_private_includes_overlap() {
        let (mut store, path) = store();
        store.ensure_signed_prekey(NOW).await.expect("ensure");
        let old = store.current_signed_prekey().await.expect("old").unwrap();
        let rotation = NOW + SIGNED_PREKEY_ROTATION_SECS;
        store.rotate_signed_prekey(rotation).await.expect("rotate");
        let valid = store
            .valid_signed_prekeys_with_private(rotation)
            .await
            .expect("valid private keys");
        assert_eq!(valid.len(), 2);
        let previous = valid
            .iter()
            .find(|prekey| prekey.pubkey == old.public_key)
            .expect("previous SPK retained during overlap");
        assert!(!previous.is_current);
        assert_eq!(
            PublicKey::from(&StaticSecret::from(previous.privkey)).to_bytes(),
            previous.pubkey
        );
        let selected = store
            .signed_prekey_by_public_key_with_private(&old.public_key, rotation)
            .await
            .expect("lookup SPK from init message")
            .expect("matching overlap SPK");
        assert_eq!(selected.id, previous.id);
        cleanup(path);
    }

    #[tokio::test]
    async fn current_signed_prekey_with_private_returns_none_when_empty() {
        let (store, path) = store();
        assert!(store
            .current_signed_prekey_with_private(NOW)
            .await
            .expect("empty current SPK")
            .is_none());
        cleanup(path);
    }

    #[test]
    fn signed_prekey_with_private_zeroizes_on_drop() {
        assert!(std::mem::needs_drop::<SignedPrekeyWithPrivate>());
        let mut prekey = SignedPrekeyWithPrivate {
            id: 1,
            pubkey: [2; 32],
            privkey: [3; 32],
            created_at: NOW,
            expires_at: NOW + 1,
            is_current: true,
        };
        prekey.zeroize_private_key();
        assert_eq!(prekey.privkey, [0; 32]);
        assert!(!format!("{prekey:?}").contains("[3, 3"));
        assert!(format!("{prekey:?}").contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn refill_opk_pool_to_target() {
        let (mut store, path) = store();
        assert_eq!(
            store.refill_opk_pool(NOW).await.expect("refill"),
            OPK_POOL_SIZE
        );
        assert_eq!(store.opk_count().await.expect("count"), OPK_POOL_SIZE);
        cleanup(path);
    }

    #[tokio::test]
    async fn refill_opk_pool_noop_if_full() {
        let (mut store, path) = store();
        store.refill_opk_pool(NOW).await.expect("initial refill");
        assert_eq!(store.refill_opk_pool(NOW + 1).await.expect("noop"), 0);
        cleanup(path);
    }

    #[tokio::test]
    async fn opk_list_returns_all_unconsumed() {
        let (mut store, path) = store();
        store.refill_opk_pool(NOW).await.expect("refill");
        let opks = store.opk_list().await.expect("OPKs");
        assert_eq!(opks.len(), OPK_POOL_SIZE);
        assert!(opks.windows(2).all(|pair| pair[0].id < pair[1].id));
        cleanup(path);
    }

    #[tokio::test]
    async fn prekeys_and_revision_survive_store_reopen() {
        let (mut store, path) = store();
        store.ensure_signed_prekey(NOW).await.expect("ensure");
        store.refill_opk_pool(NOW).await.expect("refill");
        let expected_spk = store
            .current_signed_prekey()
            .await
            .expect("current")
            .unwrap();
        let expected_revision = store.revision_state().await.expect("revision");
        drop(store);

        let storage = ClientStorage::open(&path, &[0x6d; 32]).expect("reopen encrypted storage");
        let reopened = LocalPrekeyStore::new(Arc::new(StdMutex::new(storage)));
        assert_eq!(
            reopened
                .current_signed_prekey()
                .await
                .expect("reopened current"),
            Some(expected_spk)
        );
        assert_eq!(
            reopened.opk_count().await.expect("reopened OPK count"),
            OPK_POOL_SIZE
        );
        assert_eq!(
            reopened.revision_state().await.expect("reopened revision"),
            expected_revision
        );
        drop(reopened);
        cleanup(path);
    }

    #[tokio::test]
    async fn consume_opk_marks_consumed() {
        let (store, path) = store();
        let metrics = Arc::new(AbuseMetrics::new());
        let mut store = LocalPrekeyStore::with_metrics(store.storage.clone(), metrics.clone());
        let id = seed_opk(&mut store, [0x91; 32], NOW);
        store.consume_opk(id, NOW + 10).await.expect("consume");
        assert_eq!(
            store
                .with_storage(|storage| storage.prekey_opk_consumed_at(id))
                .expect("audit timestamp"),
            Some(NOW + 10)
        );
        assert_eq!(metrics.snapshot().prekey_opk_consumed_total, 1);
        cleanup(path);
    }

    #[tokio::test]
    async fn consume_opk_returns_stored_private_and_public_keys() {
        let (store, path) = store();
        let private_key = [0x92; 32];
        let expected_public = PublicKey::from(&StaticSecret::from(private_key)).to_bytes();
        let mut store = store;
        let id = seed_opk(&mut store, private_key, NOW);
        let consumed = store.consume_opk(id, NOW + 1).await.expect("consume");
        assert_eq!(consumed.id, id);
        assert_eq!(consumed.privkey, private_key);
        assert_eq!(consumed.pubkey, expected_public);
        cleanup(path);
    }

    #[tokio::test]
    async fn consume_opk_twice_fails_and_counts_replay() {
        let (store, path) = store();
        let metrics = Arc::new(AbuseMetrics::new());
        let mut store = LocalPrekeyStore::with_metrics(store.storage.clone(), metrics.clone());
        let id = seed_opk(&mut store, [0x93; 32], NOW);
        store.consume_opk(id, NOW + 1).await.expect("first consume");
        assert_eq!(
            store.consume_opk(id, NOW + 2).await.unwrap_err(),
            LocalPrekeyError::OpkAlreadyConsumed(id, NOW + 1)
        );
        assert_eq!(metrics.snapshot().prekey_opk_consume_replay_total, 1);
        cleanup(path);
    }

    #[tokio::test]
    async fn consume_nonexistent_opk_fails_and_counts_not_found() {
        let (store, path) = store();
        let metrics = Arc::new(AbuseMetrics::new());
        let mut store = LocalPrekeyStore::with_metrics(store.storage.clone(), metrics.clone());
        assert_eq!(
            store.consume_opk(404, NOW).await.unwrap_err(),
            LocalPrekeyError::OpkNotFound(404)
        );
        assert_eq!(metrics.snapshot().prekey_opk_consume_not_found_total, 1);
        cleanup(path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn consume_opk_is_atomic_under_concurrent_race() {
        let (initial_store, path) = store();
        let mut initial_store = initial_store;
        let id = seed_opk(&mut initial_store, [0x94; 32], NOW);
        let storage_path = path.clone();
        drop(initial_store);

        let storage_a = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[0x6d; 32]).expect("open connection A"),
        ));
        let storage_b = Arc::new(StdMutex::new(
            ClientStorage::open(&storage_path, &[0x6d; 32]).expect("open connection B"),
        ));
        let barrier = Arc::new(Barrier::new(2));
        let run_consume = |storage: Arc<StdMutex<ClientStorage>>, barrier: Arc<Barrier>| {
            tokio::task::spawn_blocking(move || {
                barrier.wait();
                storage
                    .lock()
                    .map_err(|_| anyhow!("storage A lock poisoned"))?
                    .prekey_consume_opk(id, NOW + 5)
            })
        };
        let (first, second) = tokio::join!(
            run_consume(Arc::clone(&storage_a), Arc::clone(&barrier)),
            run_consume(Arc::clone(&storage_b), Arc::clone(&barrier))
        );
        let first = first
            .expect("first consume task")
            .expect("first DB operation");
        let second = second
            .expect("second consume task")
            .expect("second DB operation");
        let outcomes = [first, second];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, PrekeyOpkConsumption::Consumed(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, PrekeyOpkConsumption::AlreadyConsumed(_)))
                .count(),
            1
        );
        drop(outcomes);
        drop(storage_a);
        drop(storage_b);
        cleanup(path);
    }

    #[tokio::test]
    async fn consume_opk_retains_audit_row() {
        let (store, path) = store();
        let mut store = store;
        let id = seed_opk(&mut store, [0x95; 32], NOW);
        store.consume_opk(id, NOW + 15).await.expect("consume");
        assert_eq!(
            store
                .with_storage(|storage| storage.prekey_opk_consumed_at(id))
                .expect("audit row"),
            Some(NOW + 15)
        );
        assert_eq!(store.opk_count().await.expect("unconsumed count"), 0);
        cleanup(path);
    }

    #[tokio::test]
    async fn opk_list_excludes_consumed_prekey() {
        let (store, path) = store();
        let mut store = store;
        let consumed_id = seed_opk(&mut store, [0x96; 32], NOW);
        let available_id = seed_opk(&mut store, [0x97; 32], NOW);
        store
            .consume_opk(consumed_id, NOW + 1)
            .await
            .expect("consume");
        let available = store.opk_list().await.expect("list");
        assert_eq!(available.len(), 1);
        assert_eq!(available[0].id, available_id);
        cleanup(path);
    }

    #[tokio::test]
    async fn consume_opk_updates_bundle_revision() {
        let (store, path) = store();
        let mut store = store;
        let id = seed_opk(&mut store, [0x98; 32], NOW);
        let (before, _) = store.revision_state().await.expect("revision before");
        store.consume_opk(id, NOW + 1).await.expect("consume");
        let (after, published) = store.revision_state().await.expect("revision after");
        assert_eq!(after, before + 1);
        assert!(published < after);
        cleanup(path);
    }
}
