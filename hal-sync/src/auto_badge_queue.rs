//! PR-B4.2: bounded queue for future auto-badge publication.
//!
//! Enqueued work is drained by a publisher in PR-B4.3; this module does not
//! publish badges.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::dht::NodeId;

pub const AUTO_BADGE_QUEUE_CAPACITY: usize = 128;

#[derive(Debug, Clone)]
pub struct PendingBadge {
    pub subject_id: NodeId,
    pub message_ids: Vec<String>,
    pub reason: String,
    pub observed_at: u64,
}

#[derive(Debug, Default)]
pub struct AutoBadgeQueueMetrics {
    pub queued_total: AtomicU64,
    pub overflow_dropped_total: AtomicU64,
    pub drained_total: AtomicU64,
}

#[derive(Debug)]
pub struct AutoBadgeQueue {
    inner: VecDeque<PendingBadge>,
    capacity: usize,
    metrics: AutoBadgeQueueMetrics,
}

impl AutoBadgeQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: VecDeque::new(),
            capacity: capacity.max(1),
            metrics: AutoBadgeQueueMetrics::default(),
        }
    }

    pub fn default_config() -> Self {
        Self::new(AUTO_BADGE_QUEUE_CAPACITY)
    }

    /// Append work, dropping the oldest pending item when the queue is full.
    pub fn push(&mut self, badge: PendingBadge) {
        if self.inner.len() >= self.capacity {
            self.inner.pop_front();
            self.metrics
                .overflow_dropped_total
                .fetch_add(1, Ordering::Relaxed);
        }
        self.inner.push_back(badge);
        self.metrics.queued_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn drain(&mut self) -> Vec<PendingBadge> {
        let drained = self.inner.len() as u64;
        let badges = self.inner.drain(..).collect();
        self.metrics
            .drained_total
            .fetch_add(drained, Ordering::Relaxed);
        badges
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn metrics(&self) -> &AutoBadgeQueueMetrics {
        &self.metrics
    }
}

impl Default for AutoBadgeQueue {
    fn default() -> Self {
        Self::default_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(seed: u8) -> PendingBadge {
        PendingBadge {
            subject_id: NodeId::from_bytes([seed; 32]),
            message_ids: vec![format!("message-{seed}")],
            reason: "test pending badge".to_string(),
            observed_at: u64::from(seed),
        }
    }

    #[test]
    fn push_and_drain() {
        let mut queue = AutoBadgeQueue::new(4);
        queue.push(pending(1));
        queue.push(pending(2));
        queue.push(pending(3));
        let drained = queue.drain();
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].subject_id, NodeId::from_bytes([1; 32]));
        assert_eq!(queue.metrics().drained_total.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn overflow_drops_oldest() {
        let mut queue = AutoBadgeQueue::new(2);
        queue.push(pending(1));
        queue.push(pending(2));
        queue.push(pending(3));
        assert_eq!(queue.len(), 2);
        assert_eq!(
            queue
                .metrics()
                .overflow_dropped_total
                .load(Ordering::Relaxed),
            1
        );
        let drained = queue.drain();
        assert_eq!(drained[0].subject_id, NodeId::from_bytes([2; 32]));
        assert_eq!(drained[1].subject_id, NodeId::from_bytes([3; 32]));
    }

    #[test]
    fn drain_empties_queue() {
        let mut queue = AutoBadgeQueue::new(2);
        queue.push(pending(1));
        let _ = queue.drain();
        assert_eq!(queue.len(), 0);
        assert!(queue.drain().is_empty());
    }
}
