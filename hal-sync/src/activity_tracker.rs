//! PR-B7.0b: ActivityTracker — per-identity accepted observations over time.
//!
//! Uptime is derived from the stored observations using a grace interval:
//! online_time(identity, window) = union([t_i, t_i + GRACE_SECS])
//! for each accepted event observation within the window.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex as StdMutex};

use anyhow::{anyhow, Result};
use hal_storage::ClientStorage;

use crate::dht::NodeId;

pub const RETENTION_SECS: u64 = 30 * 86_400;
pub const FLUSH_INTERVAL_SECS: u64 = 30;
pub const MAX_CACHE_ENTRIES: usize = 1_000;
pub const GRACE_SECS: u64 = 300;

pub struct ActivityTracker {
    store: Arc<StdMutex<ClientStorage>>,
    pending: HashMap<NodeId, VecDeque<(u64, String)>>,
    recent_cache: HashMap<NodeId, Vec<(u64, String)>>,
    last_flush: u64,
}

impl ActivityTracker {
    pub fn new(store: Arc<StdMutex<ClientStorage>>) -> Self {
        Self {
            store,
            pending: HashMap::new(),
            recent_cache: HashMap::new(),
            last_flush: 0,
        }
    }

    pub async fn record(&mut self, identity: NodeId, event_id: String, now: u64) -> Result<()> {
        let queue = self.pending.entry(identity).or_default();
        queue.push_back((now, event_id));
        if queue.len() > MAX_CACHE_ENTRIES {
            queue.pop_front();
        }
        if now.saturating_sub(self.last_flush) >= FLUSH_INTERVAL_SECS {
            self.flush().await?;
        }
        Ok(())
    }

    pub async fn observations_since(
        &mut self,
        identity: &NodeId,
        since: u64,
        now: u64,
    ) -> Result<Vec<(u64, String)>> {
        let mut combined = self.recent_cache.get(identity).cloned().unwrap_or_default();
        let pending = self.pending.get(identity).cloned().unwrap_or_default();
        combined.extend(pending);

        let storage = self
            .store
            .lock()
            .map_err(|_| anyhow!("client storage mutex poisoned"))?;
        let persisted = storage
            .identity_history()
            .observations_since(&identity.to_hex(), since)?;
        combined.extend(persisted.into_iter());

        combined.sort_by_key(|(ts, _)| *ts);
        combined.dedup_by(|a, b| a.1 == b.1);
        combined.retain(|(ts, _)| *ts >= since && *ts <= now);
        self.recent_cache.insert(*identity, combined.clone());
        Ok(combined)
    }

    pub async fn last_activity(&mut self, identity: &NodeId) -> Result<Option<u64>> {
        if let Some(rows) = self.recent_cache.get(identity) {
            if let Some((ts, _)) = rows.iter().max_by_key(|(ts, _)| *ts) {
                return Ok(Some(*ts));
            }
        }
        let mut max_pending = None;
        if let Some(rows) = self.pending.get(identity) {
            max_pending = rows.iter().map(|(ts, _)| *ts).max();
        }

        let storage = self
            .store
            .lock()
            .map_err(|_| anyhow!("client storage mutex poisoned"))?;
        let persisted = storage
            .identity_history()
            .last_activity(&identity.to_hex())?;
        Ok(max_pending.max(persisted))
    }

    pub async fn flush(&mut self) -> Result<usize> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut total = 0usize;
        let ids: Vec<NodeId> = self.pending.keys().copied().collect();
        for identity in ids {
            let Some(entries) = self.pending.get(&identity).cloned() else {
                continue;
            };
            if entries.is_empty() {
                continue;
            }
            let storage = self
                .store
                .lock()
                .map_err(|_| anyhow!("client storage mutex poisoned"))?;
            for (ts, event_id) in entries {
                let inserted = storage.identity_history().record_activity(
                    &identity.to_hex(),
                    ts,
                    &event_id,
                )?;
                if inserted {
                    total += 1;
                }
            }
            self.pending.remove(&identity);
        }
        self.last_flush = now;
        Ok(total)
    }

    pub async fn prune(&mut self, now: u64) -> Result<usize> {
        let cutoff = now.saturating_sub(RETENTION_SECS);
        let storage = self
            .store
            .lock()
            .map_err(|_| anyhow!("client storage mutex poisoned"))?;
        let removed = storage.identity_history().prune_activity_before(cutoff)?;
        for identity in self.pending.keys().copied().collect::<Vec<_>>() {
            let queue = self.pending.get_mut(&identity).unwrap();
            queue.retain(|(ts, _)| *ts >= cutoff);
            if queue.is_empty() {
                self.pending.remove(&identity);
            }
        }
        Ok(removed)
    }

    pub async fn uptime_ratio(
        &mut self,
        identity: &NodeId,
        window_secs: u64,
        grace_secs: u64,
        now: u64,
    ) -> Result<f32> {
        if window_secs == 0 {
            return Ok(0.0);
        }
        let since = now.saturating_sub(window_secs);
        let observations = self.observations_since(identity, since, now).await?;
        if observations.is_empty() {
            return Ok(0.0);
        }

        let mut intervals: Vec<(u64, u64)> = observations
            .into_iter()
            .map(|(ts, _)| (ts, ts.saturating_add(grace_secs)))
            .collect();
        intervals.sort_by_key(|(start, _)| *start);

        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (start, end) in intervals {
            if let Some(last) = merged.last_mut() {
                if start <= last.1 {
                    last.1 = last.1.max(end);
                    continue;
                }
            }
            merged.push((start, end));
        }

        let online = merged
            .into_iter()
            .map(|(start, end)| end.saturating_sub(start))
            .sum::<u64>();

        let ratio = (online as f32) / (window_secs as f32);
        Ok(ratio.min(1.0))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use hal_storage::ClientStorage;

    use super::{ActivityTracker, GRACE_SECS, MAX_CACHE_ENTRIES};
    use crate::dht::NodeId;

    fn tracker() -> (PathBuf, ActivityTracker) {
        let path = std::env::temp_dir().join(format!(
            "hal-activity-tracker-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        let storage = ClientStorage::open(&path, &[0x44; 32]).expect("open storage");
        (path, ActivityTracker::new(Arc::new(Mutex::new(storage))))
    }

    fn cleanup(path: PathBuf) {
        let _ = std::fs::remove_file(path);
    }

    fn node(seed: u8) -> NodeId {
        NodeId::from_bytes([seed; 32])
    }

    #[tokio::test]
    async fn record_stores_in_memory() {
        let (path, mut tracker) = tracker();
        let identity = node(1);

        tracker
            .record(identity, "event-1".into(), 0)
            .await
            .expect("record");
        assert_eq!(tracker.pending.get(&identity).unwrap().len(), 1);
        cleanup(path);
    }

    #[tokio::test]
    async fn flush_persists_to_storage() {
        let (path, mut tracker) = tracker();
        let identity = node(2);
        tracker
            .record(identity, "event-2".into(), 200)
            .await
            .expect("record");
        tracker.flush().await.expect("flush");
        assert!(tracker.pending.get(&identity).is_none());
        assert_eq!(
            tracker.last_activity(&identity).await.expect("last"),
            Some(200)
        );
        cleanup(path);
    }

    #[tokio::test]
    async fn uptime_ratio_union_intervals() {
        let (path, mut tracker) = tracker();
        let identity = node(3);
        for ts in [0, 100, 200] {
            tracker
                .record(identity, format!("event-{ts}"), ts)
                .await
                .expect("record");
        }
        let ratio = tracker
            .uptime_ratio(&identity, 300, GRACE_SECS, 300)
            .await
            .expect("ratio");
        assert!(ratio > 0.0);
        cleanup(path);
    }

    #[tokio::test]
    async fn uptime_ratio_zero_for_no_observations() {
        let (path, mut tracker) = tracker();
        let identity = node(4);
        let ratio = tracker
            .uptime_ratio(&identity, 300, GRACE_SECS, 300)
            .await
            .expect("ratio");
        assert_eq!(ratio, 0.0);
        cleanup(path);
    }

    #[tokio::test]
    async fn uptime_ratio_clamped_to_one() {
        let (path, mut tracker) = tracker();
        let identity = node(5);
        for ts in [0, 10, 20, 30, 40, 50, 60, 70, 80, 90] {
            tracker
                .record(identity, format!("event-{ts}"), ts)
                .await
                .expect("record");
        }
        let ratio = tracker
            .uptime_ratio(&identity, 100, 10, 100)
            .await
            .expect("ratio");
        assert!(ratio <= 1.0);
        cleanup(path);
    }

    #[tokio::test]
    async fn record_caps_pending_per_identity() {
        let (path, mut tracker) = tracker();
        let identity = node(6);
        for i in 0..(MAX_CACHE_ENTRIES + 50) {
            tracker
                .record(identity, format!("event-{i}"), i as u64)
                .await
                .expect("record");
        }
        assert!(tracker.pending.get(&identity).unwrap().len() <= MAX_CACHE_ENTRIES);
        cleanup(path);
    }
}
