//! PR-B4.2: per-sender cold-contact rate tracker.
//!
//! Records cold-contact timestamps in a sliding window. Enforcement is deferred
//! to PR-B4.3.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::dht::NodeId;

pub const COLD_CONTACT_LIMIT: usize = 10;
pub const COLD_CONTACT_WINDOW_SECS: u64 = 3600;
pub const COLD_TRACKER_MAX_ENTRIES: usize = 10_000;

#[derive(Debug)]
pub struct ColdContactTracker {
    state: HashMap<NodeId, Vec<u64>>,
    limit: usize,
    window_secs: u64,
    max_entries: usize,
    metrics: ColdContactTrackerMetrics,
}

#[derive(Debug, Default)]
pub struct ColdContactTrackerMetrics {
    pub recorded_total: AtomicU64,
    pub exceeded_total: AtomicU64,
    pub evicted_total: AtomicU64,
    pub rejected_non_cold_total: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColdContactVerdict {
    Within { count: usize },
    Exceeded { count: usize },
}

impl ColdContactTracker {
    pub fn new(limit: usize, window_secs: u64, max_entries: usize) -> Self {
        Self {
            state: HashMap::new(),
            limit,
            window_secs,
            max_entries: max_entries.max(1),
            metrics: ColdContactTrackerMetrics::default(),
        }
    }

    pub fn default_config() -> Self {
        Self::new(
            COLD_CONTACT_LIMIT,
            COLD_CONTACT_WINDOW_SECS,
            COLD_TRACKER_MAX_ENTRIES,
        )
    }

    /// Record one cold contact and return the resulting count verdict.
    pub fn record(&mut self, sender: &NodeId, now: u64) -> ColdContactVerdict {
        self.gc_sender(sender, now);
        if !self.state.contains_key(sender) && self.state.len() >= self.max_entries {
            self.evict_lru_if_needed();
        }

        let timestamps = self.state.entry(*sender).or_default();
        timestamps.push(now);
        let count = timestamps.len();
        self.metrics.recorded_total.fetch_add(1, Ordering::Relaxed);
        if count > self.limit {
            self.metrics.exceeded_total.fetch_add(1, Ordering::Relaxed);
            ColdContactVerdict::Exceeded { count }
        } else {
            ColdContactVerdict::Within { count }
        }
    }

    /// Record a warm observation passed to the cold-only API (sanity metric).
    pub fn record_warm(&self) {
        self.metrics
            .rejected_non_cold_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Remove expired timestamps and empty entries from all senders.
    /// Runtime ingestion prunes the current sender inline on `record`.
    pub fn gc(&mut self, now: u64) {
        let window_secs = self.window_secs;
        self.state.retain(|_, timestamps| {
            timestamps.retain(|timestamp| now.saturating_sub(*timestamp) < window_secs);
            !timestamps.is_empty()
        });
    }

    pub fn len(&self) -> usize {
        self.state.len()
    }

    pub fn metrics(&self) -> &ColdContactTrackerMetrics {
        &self.metrics
    }

    fn gc_sender(&mut self, sender: &NodeId, now: u64) {
        let Some(timestamps) = self.state.get_mut(sender) else {
            return;
        };
        timestamps.retain(|timestamp| now.saturating_sub(*timestamp) < self.window_secs);
        if timestamps.is_empty() {
            self.state.remove(sender);
        }
    }

    fn evict_lru_if_needed(&mut self) {
        let oldest = self
            .state
            .iter()
            .min_by_key(|(_, timestamps)| timestamps.last().copied().unwrap_or_default())
            .map(|(sender, _)| *sender);
        if oldest.is_some_and(|sender| self.state.remove(&sender).is_some()) {
            self.metrics.evicted_total.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Default for ColdContactTracker {
    fn default() -> Self {
        Self::default_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(seed: u8) -> NodeId {
        NodeId::from_bytes([seed; 32])
    }

    #[test]
    fn record_within_limit() {
        let mut tracker = ColdContactTracker::new(10, 3600, 100);
        for timestamp in 0..5 {
            assert_eq!(
                tracker.record(&node(1), timestamp),
                ColdContactVerdict::Within {
                    count: timestamp as usize + 1
                }
            );
        }
    }

    #[test]
    fn record_exceeds_limit() {
        let mut tracker = ColdContactTracker::new(10, 3600, 100);
        for timestamp in 0..10 {
            assert!(matches!(
                tracker.record(&node(2), timestamp),
                ColdContactVerdict::Within { .. }
            ));
        }
        assert_eq!(
            tracker.record(&node(2), 10),
            ColdContactVerdict::Exceeded { count: 11 }
        );
        assert_eq!(tracker.metrics().exceeded_total.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn window_expires_old_entries() {
        let mut tracker = ColdContactTracker::new(10, 60, 100);
        assert_eq!(
            tracker.record(&node(3), 10),
            ColdContactVerdict::Within { count: 1 }
        );
        assert_eq!(
            tracker.record(&node(3), 71),
            ColdContactVerdict::Within { count: 1 }
        );
    }

    #[test]
    fn lru_eviction_on_max_entries() {
        let mut tracker = ColdContactTracker::new(10, 3600, 3);
        tracker.record(&node(4), 1);
        tracker.record(&node(4), 2);
        tracker.record(&node(5), 3);
        tracker.record(&node(6), 4);
        tracker.record(&node(7), 5);

        assert_eq!(tracker.len(), 3);
        assert!(!tracker.state.contains_key(&node(4)));
        assert_eq!(tracker.metrics().evicted_total.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn record_warm_increments_counter() {
        let tracker = ColdContactTracker::new(10, 3600, 10);
        tracker.record_warm();
        assert_eq!(
            tracker
                .metrics()
                .rejected_non_cold_total
                .load(Ordering::Relaxed),
            1
        );
    }
}
