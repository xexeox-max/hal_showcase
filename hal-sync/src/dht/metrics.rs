use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct DhtMetrics {
    pub streams_received: AtomicU64,
    pub streams_dropped: AtomicU64,
    pub streams_processed: AtomicU64,
    pub rpc_timeouts: AtomicU64,
    pub rpc_errors: AtomicU64,
    pub responses_sent: AtomicU64,
}

impl DhtMetrics {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn inc_received(&self) {
        self.streams_received.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_dropped(&self) {
        self.streams_dropped.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_processed(&self) {
        self.streams_processed.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_timeouts(&self) {
        self.rpc_timeouts.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_errors(&self) {
        self.rpc_errors.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_responses(&self) {
        self.responses_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> DhtMetricsSnapshot {
        DhtMetricsSnapshot {
            streams_received: self.streams_received.load(Ordering::Relaxed),
            streams_dropped: self.streams_dropped.load(Ordering::Relaxed),
            streams_processed: self.streams_processed.load(Ordering::Relaxed),
            rpc_timeouts: self.rpc_timeouts.load(Ordering::Relaxed),
            rpc_errors: self.rpc_errors.load(Ordering::Relaxed),
            responses_sent: self.responses_sent.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct DhtMetricsSnapshot {
    pub streams_received: u64,
    pub streams_dropped: u64,
    pub streams_processed: u64,
    pub rpc_timeouts: u64,
    pub rpc_errors: u64,
    pub responses_sent: u64,
}
