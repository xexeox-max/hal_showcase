//! PR-B7.0a: persisted first-observation times for remote identities.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

use anyhow::{anyhow, Result};
use hal_storage::ClientStorage;

use crate::dht::NodeId;

pub struct AgeTracker {
    store: Arc<StdMutex<ClientStorage>>,
    cache: HashMap<NodeId, u64>,
}

impl AgeTracker {
    pub fn new(store: Arc<StdMutex<ClientStorage>>) -> Self {
        Self {
            store,
            cache: HashMap::new(),
        }
    }

    /// Persist only on this process's first observation of an identity.
    pub fn observe(&mut self, identity: NodeId, now: u64) -> Result<()> {
        if self.cache.contains_key(&identity) {
            return Ok(());
        }

        let identity_hex = identity.to_hex();
        let storage = self
            .store
            .lock()
            .map_err(|_| anyhow!("client storage mutex poisoned"))?;
        let history = storage.identity_history();
        history.observe_first_seen(&identity_hex, now)?;
        let first_seen = history
            .first_seen(&identity_hex)?
            .ok_or_else(|| anyhow!("first-seen row missing after observation"))?;
        self.cache.insert(identity, first_seen);
        Ok(())
    }

    pub fn first_seen(&self, identity: &NodeId) -> Result<Option<u64>> {
        if let Some(first_seen) = self.cache.get(identity) {
            return Ok(Some(*first_seen));
        }

        let storage = self
            .store
            .lock()
            .map_err(|_| anyhow!("client storage mutex poisoned"))?;
        storage.identity_history().first_seen(&identity.to_hex())
    }

    pub fn age_secs(&self, identity: &NodeId, now: u64) -> Result<Option<u64>> {
        Ok(self
            .first_seen(identity)?
            .map(|first_seen| now.saturating_sub(first_seen)))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use hal_storage::ClientStorage;

    use super::AgeTracker;
    use crate::dht::NodeId;

    fn tracker() -> (PathBuf, AgeTracker) {
        let path =
            std::env::temp_dir().join(format!("hal-age-tracker-{}.sqlite3", uuid::Uuid::new_v4()));
        let storage = ClientStorage::open(&path, &[0x37; 32]).expect("open storage");
        (path, AgeTracker::new(Arc::new(Mutex::new(storage))))
    }

    fn remove_db(path: PathBuf) {
        std::fs::remove_file(path).expect("remove temporary database");
    }

    fn node(seed: u8) -> NodeId {
        NodeId::from_bytes([seed; 32])
    }

    #[test]
    fn observe_then_first_seen() {
        let (path, mut tracker) = tracker();
        let identity = node(1);

        tracker.observe(identity, 100).expect("observe");

        assert_eq!(tracker.first_seen(&identity).expect("read"), Some(100));
        drop(tracker);
        remove_db(path);
    }

    #[test]
    fn age_secs_correct() {
        let (path, mut tracker) = tracker();
        let identity = node(2);
        tracker.observe(identity, 100).expect("observe");

        assert_eq!(tracker.age_secs(&identity, 200).expect("age"), Some(100));
        drop(tracker);
        remove_db(path);
    }

    #[test]
    fn age_secs_none_for_unknown() {
        let (path, tracker) = tracker();

        assert_eq!(tracker.age_secs(&node(3), 200).expect("age"), None);
        drop(tracker);
        remove_db(path);
    }

    #[test]
    fn observe_idempotent_keeps_first_cached_value() {
        let (path, mut tracker) = tracker();
        let identity = node(4);

        tracker.observe(identity, 100).expect("first observation");
        tracker.observe(identity, 200).expect("repeat observation");

        assert_eq!(tracker.first_seen(&identity).expect("read"), Some(100));
        drop(tracker);
        remove_db(path);
    }

    #[test]
    fn first_seen_survives_storage_reopen() {
        let path = std::env::temp_dir().join(format!(
            "hal-age-tracker-reopen-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        let identity = node(5);
        {
            let storage = ClientStorage::open(&path, &[0x37; 32]).expect("open storage");
            let mut tracker = AgeTracker::new(Arc::new(Mutex::new(storage)));
            tracker.observe(identity, 100).expect("observe");
        }

        let storage = ClientStorage::open(&path, &[0x37; 32]).expect("reopen storage");
        let tracker = AgeTracker::new(Arc::new(Mutex::new(storage)));
        assert_eq!(
            tracker.first_seen(&identity).expect("read after restart"),
            Some(100)
        );
        assert_eq!(
            tracker.age_secs(&identity, 200).expect("age after restart"),
            Some(100)
        );
        drop(tracker);
        remove_db(path);
    }
}
