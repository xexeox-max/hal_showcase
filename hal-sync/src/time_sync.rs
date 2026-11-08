use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockDelta {
    pub node_id: String,
    pub local_epoch_ms: u64,
    pub cluster_offset_ms: i64,
    pub drift_ms: i64,
    pub last_sync_epoch: u64,
    pub skew_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSyncState {
    pub node_id: String,
    pub local_epoch_ms: u64,
    pub offset_ms: i64,
    pub corrected_epoch_ms: u64,
    pub is_healthy: bool,
}

impl TimeSyncState {
    pub fn new(node_id: String, local_epoch_ms: u64) -> Self {
        Self {
            node_id,
            local_epoch_ms,
            offset_ms: 0,
            corrected_epoch_ms: local_epoch_ms,
            is_healthy: true,
        }
    }

    pub fn update(&mut self, cluster_offset_ms: i64) {
        self.offset_ms = cluster_offset_ms;
        self.corrected_epoch_ms = self.local_epoch_ms.saturating_sub(cluster_offset_ms as u64);
        self.is_healthy = cluster_offset_ms.abs() <= 5000;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterClock {
    pub nodes: Vec<ClockDelta>,
}

impl ClusterClock {
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    pub fn add(&mut self, delta: ClockDelta) {
        self.nodes.push(delta);
    }

    pub fn mean_offset_ms(&self) -> i64 {
        let mut offsets: Vec<i64> = self
            .nodes
            .iter()
            .filter(|node| node.skew_status != "invalid")
            .map(|node| node.cluster_offset_ms)
            .collect();
        if offsets.is_empty() {
            return 0;
        }

        offsets.sort_unstable();
        let middle = offsets.len() / 2;
        if offsets.len() % 2 == 0 {
            (offsets[middle - 1] + offsets[middle]) / 2
        } else {
            offsets[middle]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delta(offset: i64) -> ClockDelta {
        ClockDelta {
            node_id: offset.to_string(),
            local_epoch_ms: 0,
            cluster_offset_ms: offset,
            drift_ms: 0,
            last_sync_epoch: 1,
            skew_status: "healthy".into(),
        }
    }

    #[test]
    fn cluster_clock_uses_median_to_ignore_outlier() {
        let mut clock = ClusterClock::default();
        clock.add(delta(10));
        clock.add(delta(12));
        clock.add(delta(11_000));

        assert_eq!(clock.mean_offset_ms(), 12);
    }
}

impl Default for ClusterClock {
    fn default() -> Self {
        Self::new()
    }
}
