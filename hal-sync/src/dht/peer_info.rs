use serde::{Deserialize, Serialize};

use super::node_id::NodeId;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerEndpoint {
    pub address: String,
    pub last_seen: u64,
    pub latency_ms: Option<u32>,
    pub failure_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerInfo {
    pub node_id: NodeId,
    pub public_key: String,
    pub endpoints: Vec<PeerEndpoint>,
    pub last_seen: u64,
    pub added_at: u64,
}

impl PeerInfo {
    pub fn new(node_id: NodeId, public_key: String) -> Self {
        Self {
            node_id,
            public_key,
            endpoints: Vec::new(),
            last_seen: 0,
            added_at: 0,
        }
    }

    pub fn add_endpoint(&mut self, address: String, now: u64) {
        if let Some(endpoint) = self
            .endpoints
            .iter_mut()
            .find(|endpoint| endpoint.address == address)
        {
            endpoint.last_seen = now;
        } else {
            self.endpoints.push(PeerEndpoint {
                address,
                last_seen: now,
                latency_ms: None,
                failure_count: 0,
            });
        }
        self.last_seen = self.last_seen.max(now);
        if self.added_at == 0 {
            self.added_at = now;
        }
    }

    pub fn remove_endpoint(&mut self, address: &str) {
        self.endpoints
            .retain(|endpoint| endpoint.address != address);
    }

    pub fn best_endpoint(&self) -> Option<&PeerEndpoint> {
        self.endpoints.iter().min_by_key(|endpoint| {
            (
                endpoint.latency_ms.unwrap_or(u32::MAX),
                endpoint.failure_count,
                std::cmp::Reverse(endpoint.last_seen),
            )
        })
    }

    pub fn record_failure(&mut self, address: &str) {
        if let Some(endpoint) = self
            .endpoints
            .iter_mut()
            .find(|endpoint| endpoint.address == address)
        {
            endpoint.failure_count = endpoint.failure_count.saturating_add(1);
        }
    }

    pub fn record_success(&mut self, address: &str, latency_ms: u32) {
        if let Some(endpoint) = self
            .endpoints
            .iter_mut()
            .find(|endpoint| endpoint.address == address)
        {
            endpoint.failure_count = 0;
            endpoint.latency_ms = Some(latency_ms);
        }
    }

    pub fn is_stale(&self, now: u64, ttl_secs: u64) -> bool {
        now.saturating_sub(self.last_seen) > ttl_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerInfo {
        PeerInfo::new(NodeId::from_bytes([1u8; 32]), "pubkey".into())
    }

    #[test]
    fn add_endpoint_dedup() {
        let mut peer = peer();
        peer.add_endpoint("127.0.0.1:1000".into(), 10);
        peer.add_endpoint("127.0.0.1:1000".into(), 20);
        assert_eq!(peer.endpoints.len(), 1);
        assert_eq!(peer.endpoints[0].last_seen, 20);
    }

    #[test]
    fn best_endpoint_prefers_low_latency() {
        let mut peer = peer();
        peer.add_endpoint("slow:1".into(), 10);
        peer.add_endpoint("fast:1".into(), 10);
        peer.record_success("slow:1", 100);
        peer.record_success("fast:1", 20);
        assert_eq!(peer.best_endpoint().expect("endpoint").address, "fast:1");
    }

    #[test]
    fn failure_count_increments() {
        let mut peer = peer();
        peer.add_endpoint("peer:1".into(), 10);
        peer.record_failure("peer:1");
        peer.record_failure("peer:1");
        assert_eq!(peer.endpoints[0].failure_count, 2);
    }

    #[test]
    fn stale_after_ttl() {
        let mut peer = peer();
        peer.add_endpoint("peer:1".into(), 100);
        assert!(!peer.is_stale(199, 100));
        assert!(peer.is_stale(201, 100));
    }
}
