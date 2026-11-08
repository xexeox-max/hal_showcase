use std::cmp::Ordering;

use super::node_id::NodeId;
use super::peer_info::PeerInfo;

pub fn closer_to(target: &NodeId, a: &NodeId, b: &NodeId) -> Ordering {
    target.distance(a).cmp(&target.distance(b))
}

pub fn sort_by_distance(target: &NodeId, peers: &mut [PeerInfo]) {
    peers.sort_by(|left, right| closer_to(target, &left.node_id, &right.node_id));
}

pub fn closest_k(target: &NodeId, peers: &[PeerInfo], k: usize) -> Vec<PeerInfo> {
    let mut closest = peers.to_vec();
    sort_by_distance(target, &mut closest);
    closest.truncate(k);
    closest
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(value: u8) -> PeerInfo {
        PeerInfo::new(NodeId::from_bytes([value; 32]), format!("key-{value}"))
    }

    #[test]
    fn closer_to_basic() {
        let target = NodeId::from_bytes([0u8; 32]);
        let close = NodeId::from_bytes([1u8; 32]);
        let far = NodeId::from_bytes([0x80u8; 32]);
        assert_eq!(closer_to(&target, &close, &far), Ordering::Less);
    }

    #[test]
    fn sort_by_distance_stable() {
        let target = NodeId::from_bytes([0u8; 32]);
        let mut peers = vec![peer(2), peer(1), peer(2)];
        sort_by_distance(&target, &mut peers);
        assert_eq!(
            peers
                .iter()
                .map(|peer| peer.public_key.as_str())
                .collect::<Vec<_>>(),
            vec!["key-1", "key-2", "key-2"]
        );
    }

    #[test]
    fn closest_k_returns_sorted() {
        let target = NodeId::from_bytes([0u8; 32]);
        let peers = vec![peer(9), peer(2), peer(4), peer(1)];
        let closest = closest_k(&target, &peers, 3);
        assert_eq!(
            closest
                .iter()
                .map(|peer| peer.node_id.0[0])
                .collect::<Vec<_>>(),
            vec![1, 2, 4]
        );
    }

    #[test]
    fn closest_k_handles_fewer_than_k() {
        let target = NodeId::from_bytes([0u8; 32]);
        let peers = vec![peer(1), peer(2)];
        assert_eq!(closest_k(&target, &peers, 10).len(), 2);
    }
}
