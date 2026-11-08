//! PR-B5: synchronous cache of the BadgeStore-derived stigma gate.
//!
//! Transport reads this cache without awaiting the async BadgeStore lock. A
//! missing or poisoned entry fails open; runtime-level enforcement remains
//! authoritative.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use crate::dht::badge::StigmaLevel;
use crate::dht::NodeId;

pub const STIGMA_CACHE_MAX_AGE_SECS: u64 =
    2 * crate::stigma_refresh_task::STIGMA_REFRESH_DEFAULT_INTERVAL.as_secs();

pub struct StigmaCache {
    inner: StdMutex<HashMap<NodeId, StigmaLevel>>,
    refreshed_at: AtomicU64,
}

impl StigmaCache {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: StdMutex::new(HashMap::new()),
            refreshed_at: AtomicU64::new(0),
        })
    }

    pub fn is_stigmatized(&self, id: &NodeId) -> bool {
        let refreshed_at = self.refreshed_at.load(Ordering::Relaxed);
        if refreshed_at == 0 || unix_now().saturating_sub(refreshed_at) > STIGMA_CACHE_MAX_AGE_SECS
        {
            return false;
        }
        match self.inner.lock() {
            Ok(entries) => matches!(entries.get(id), Some(StigmaLevel::Stigma { .. })),
            Err(_) => false,
        }
    }

    pub fn update(&self, id: NodeId, level: StigmaLevel) {
        if let Ok(mut entries) = self.inner.lock() {
            if matches!(level, StigmaLevel::Clean | StigmaLevel::Cleared { .. }) {
                entries.remove(&id);
            } else {
                entries.insert(id, level);
            }
            self.refreshed_at.store(unix_now(), Ordering::Relaxed);
        }
    }

    pub fn bulk_replace(&self, new_map: HashMap<NodeId, StigmaLevel>) {
        if let Ok(mut entries) = self.inner.lock() {
            *entries = new_map
                .into_iter()
                .filter(|(_, level)| {
                    !matches!(level, StigmaLevel::Clean | StigmaLevel::Cleared { .. })
                })
                .collect();
            self.refreshed_at.store(unix_now(), Ordering::Relaxed);
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|entries| entries.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(seed: u8) -> NodeId {
        NodeId::from_bytes([seed; 32])
    }

    fn stigma() -> StigmaLevel {
        StigmaLevel::Stigma {
            weight: 2.0,
            badge_count: 3,
            since: 10,
        }
    }

    #[test]
    fn is_stigmatized_false_for_empty() {
        let cache = StigmaCache::new();
        assert!(!cache.is_stigmatized(&node(1)));
    }

    #[test]
    fn update_stores_stigma() {
        let cache = StigmaCache::new();
        let id = node(2);
        cache.update(id, stigma());
        assert!(cache.is_stigmatized(&id));
    }

    #[test]
    fn update_removes_clean() {
        let cache = StigmaCache::new();
        let id = node(3);
        cache.update(id, stigma());
        cache.update(id, StigmaLevel::Clean);
        assert!(!cache.is_stigmatized(&id));
        assert!(cache.is_empty());
    }

    #[test]
    fn bulk_replace_filters_clean() {
        let cache = StigmaCache::new();
        let clean_id = node(4);
        let stigma_id = node(5);
        cache.bulk_replace(HashMap::from([
            (clean_id, StigmaLevel::Clean),
            (stigma_id, stigma()),
        ]));
        assert_eq!(cache.len(), 1);
        assert!(!cache.is_stigmatized(&clean_id));
        assert!(cache.is_stigmatized(&stigma_id));
    }

    #[test]
    fn is_stigmatized_fail_open_on_poison() {
        let cache = StigmaCache::new();
        let poisoned = Arc::clone(&cache);
        let _ = std::thread::spawn(move || {
            let _guard = poisoned.inner.lock().expect("cache lock");
            panic!("poison cache mutex for test");
        })
        .join();
        assert!(!cache.is_stigmatized(&node(6)));
    }

    #[test]
    fn is_stigmatized_fails_open_when_stale() {
        let cache = StigmaCache::new();
        let id = node(7);
        cache.update(id, stigma());
        cache.refreshed_at.store(1, Ordering::Relaxed);
        assert!(!cache.is_stigmatized(&id));
    }
}
