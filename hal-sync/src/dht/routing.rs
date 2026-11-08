use std::collections::VecDeque;

use super::distance::closest_k;
use super::node_id::NodeId;
use super::peer_info::PeerInfo;

pub const K: usize = 20;
pub const NUM_BUCKETS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BucketInsertResult {
    Inserted,
    Updated,
    Full,
}

#[derive(Debug, Clone)]
pub struct KBucket {
    peers: VecDeque<PeerInfo>,
    last_refresh: u64,
}

impl KBucket {
    pub fn new() -> Self {
        Self {
            peers: VecDeque::with_capacity(K),
            last_refresh: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_full(&self) -> bool {
        self.len() >= K
    }

    pub fn contains(&self, node_id: &NodeId) -> bool {
        self.peers.iter().any(|peer| &peer.node_id == node_id)
    }

    pub fn insert_or_update(&mut self, peer: PeerInfo, now: u64) -> BucketInsertResult {
        if let Some(position) = self
            .peers
            .iter()
            .position(|current| current.node_id == peer.node_id)
        {
            self.peers.remove(position);
            self.peers.push_back(peer);
            self.last_refresh = now;
            return BucketInsertResult::Updated;
        }
        if self.is_full() {
            return BucketInsertResult::Full;
        }
        self.peers.push_back(peer);
        self.last_refresh = now;
        BucketInsertResult::Inserted
    }

    pub fn remove(&mut self, node_id: &NodeId) -> bool {
        let Some(position) = self.peers.iter().position(|peer| &peer.node_id == node_id) else {
            return false;
        };
        self.peers.remove(position).is_some()
    }

    pub fn iter(&self) -> impl Iterator<Item = &PeerInfo> {
        self.peers.iter()
    }

    pub fn oldest(&self) -> Option<&PeerInfo> {
        self.peers.front()
    }

    pub fn needs_refresh(&self, now: u64, interval_secs: u64) -> bool {
        now.saturating_sub(self.last_refresh) >= interval_secs
    }
}

impl Default for KBucket {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RoutingTable {
    local_id: NodeId,
    buckets: Box<[KBucket; NUM_BUCKETS]>,
}

impl RoutingTable {
    pub fn new(local_id: NodeId) -> Self {
        Self {
            local_id,
            buckets: Box::new(std::array::from_fn(|_| KBucket::new())),
        }
    }

    pub fn local_id(&self) -> &NodeId {
        &self.local_id
    }

    pub fn len(&self) -> usize {
        self.buckets.iter().map(KBucket::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn insert(&mut self, peer: PeerInfo, now: u64) -> BucketInsertResult {
        let Some(bucket_index) = self.local_id.bucket_index(&peer.node_id) else {
            return BucketInsertResult::Full;
        };
        self.buckets[bucket_index as usize].insert_or_update(peer, now)
    }

    pub fn remove(&mut self, node_id: &NodeId) -> bool {
        let Some(bucket_index) = self.local_id.bucket_index(node_id) else {
            return false;
        };
        self.buckets[bucket_index as usize].remove(node_id)
    }

    pub fn contains(&self, node_id: &NodeId) -> bool {
        let Some(bucket_index) = self.local_id.bucket_index(node_id) else {
            return false;
        };
        self.buckets[bucket_index as usize].contains(node_id)
    }

    pub fn closest(&self, target: &NodeId, k: usize) -> Vec<PeerInfo> {
        let peers = self.all_peers().into_iter().cloned().collect::<Vec<_>>();
        closest_k(target, &peers, k)
    }

    pub fn bucket_for(&self, node_id: &NodeId) -> Option<&KBucket> {
        self.local_id
            .bucket_index(node_id)
            .map(|index| &self.buckets[index as usize])
    }

    pub fn bucket_for_mut(&mut self, node_id: &NodeId) -> Option<&mut KBucket> {
        self.local_id
            .bucket_index(node_id)
            .map(|index| &mut self.buckets[index as usize])
    }

    pub fn buckets_needing_refresh(&self, now: u64, interval_secs: u64) -> Vec<u8> {
        self.buckets
            .iter()
            .enumerate()
            .filter(|(_, bucket)| bucket.needs_refresh(now, interval_secs))
            .map(|(index, _)| index as u8)
            .collect()
    }

    pub fn all_peers(&self) -> Vec<&PeerInfo> {
        self.buckets.iter().flat_map(KBucket::iter).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(value: u8) -> PeerInfo {
        PeerInfo::new(NodeId::from_bytes([value; 32]), format!("key-{value}"))
    }

    fn bucket_peer(second_byte: u8) -> PeerInfo {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x80;
        bytes[1] = second_byte;
        PeerInfo::new(
            NodeId::from_bytes(bytes),
            format!("bucket-key-{second_byte}"),
        )
    }

    #[test]
    fn insert_into_empty_bucket() {
        let local = NodeId::from_bytes([0u8; 32]);
        let mut table = RoutingTable::new(local);
        assert_eq!(table.insert(peer(1), 10), BucketInsertResult::Inserted);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn insert_self_ignored() {
        let local = NodeId::from_bytes([1u8; 32]);
        let mut table = RoutingTable::new(local);
        assert_eq!(table.insert(peer(1), 10), BucketInsertResult::Full);
        assert!(!table.contains(&local));
    }

    #[test]
    fn insert_updates_existing_moves_to_tail() {
        let local = NodeId::from_bytes([0u8; 32]);
        let mut table = RoutingTable::new(local);
        table.insert(bucket_peer(1), 10);
        table.insert(bucket_peer(2), 10);
        assert_eq!(
            table.insert(bucket_peer(1), 20),
            BucketInsertResult::Updated
        );
        let bucket = table.bucket_for(&bucket_peer(1).node_id).expect("bucket");
        assert_eq!(
            bucket
                .iter()
                .map(|peer| peer.node_id.0[1])
                .collect::<Vec<_>>(),
            vec![2, 1]
        );
    }

    #[test]
    fn bucket_full_rejects_new() {
        let local = NodeId::from_bytes([0u8; 32]);
        let mut table = RoutingTable::new(local);
        for value in 1..=K as u8 {
            assert_eq!(
                table.insert(bucket_peer(value), 10),
                BucketInsertResult::Inserted
            );
        }
        assert_eq!(table.insert(bucket_peer(21), 10), BucketInsertResult::Full);
        assert_eq!(table.len(), K);
    }

    #[test]
    fn remove_peer() {
        let local = NodeId::from_bytes([0u8; 32]);
        let mut table = RoutingTable::new(local);
        let node = NodeId::from_bytes([1u8; 32]);
        table.insert(peer(1), 10);
        assert!(table.remove(&node));
        assert!(!table.contains(&node));
        assert!(!table.remove(&node));
    }

    #[test]
    fn closest_returns_k_sorted() {
        let local = NodeId::from_bytes([0u8; 32]);
        let mut table = RoutingTable::new(local);
        for value in [9, 2, 4, 1] {
            table.insert(peer(value), 10);
        }
        let closest = table.closest(&NodeId::from_bytes([0u8; 32]), 3);
        assert_eq!(
            closest
                .iter()
                .map(|peer| peer.node_id.0[0])
                .collect::<Vec<_>>(),
            vec![1, 2, 4]
        );
    }

    #[test]
    fn bucket_index_correct() {
        let local = NodeId::from_bytes([0u8; 32]);
        let table = RoutingTable::new(local);
        assert!(table.bucket_for(&NodeId::from_bytes([0x80; 32])).is_some());
        assert!(table.bucket_for(&NodeId::from_bytes([0x00; 32])).is_none());
    }

    #[test]
    fn all_peers_count() {
        let local = NodeId::from_bytes([0u8; 32]);
        let mut table = RoutingTable::new(local);
        for value in 1..=3 {
            table.insert(peer(value), 10);
        }
        assert_eq!(table.all_peers().len(), 3);
        assert_eq!(table.len(), 3);
        assert!(!table.is_empty());
    }
}
