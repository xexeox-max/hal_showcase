//! Merkle tree for journal entries.
//!
//! Canonical encoding: docs/EVIDENCE_AND_JURY.md §12.1–12.2.
//! This is separate from the cluster-specific tree in `cluster.rs`.

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};

pub const LEAF_DOMAIN: &[u8] = b"HAL-JOURNAL-LEAF-v1\0";
pub const NODE_DOMAIN: &[u8] = b"HAL-JOURNAL-NODE-v1\0";
pub const EMPTY_DOMAIN: &[u8] = b"HAL-JOURNAL-EMPTY-v1\0";

/// Stable tag for the persisted `SyncEventType` debug names.
/// Assign new tags without changing any existing assignment.
pub fn event_type_tag(kind: &str) -> u8 {
    match kind {
        "ContactAdded" => 1,
        "ContactUpdated" => 2,
        "ContactDeleted" => 3,
        "SettingsUpdated" => 4,
        "MessageAdded" => 5,
        "HomeLinkRequest" => 6,
        "HomeLinkResponse" => 7,
        "HomeLinkConfirm" => 8,
        "HomeSyncChunk" => 14,
        "HomeSyncAck" => 15,
        "DraftUpdate" => 16,
        "RelayRequest" => 9,
        "RelayResponse" => 10,
        "RelayForward" => 11,
        "X3dhInit" => 12,
        "X3dhRespond" => 13,
        _ => 255,
    }
}

pub struct JournalLeaf<'a> {
    pub event_id: &'a str,
    pub event_timestamp: u64,
    pub event_type_kind: &'a str,
    pub event_data: &'a [u8],
    pub signature: &'a [u8],
}

pub fn leaf_hash(leaf: &JournalLeaf<'_>) -> Result<[u8; 32]> {
    let event_id_len = u32::try_from(leaf.event_id.len())
        .map_err(|_| anyhow!("journal event id exceeds canonical encoding limit"))?;
    let event_data_len = u32::try_from(leaf.event_data.len())
        .map_err(|_| anyhow!("journal event data exceeds canonical encoding limit"))?;
    let signature_len = u32::try_from(leaf.signature.len())
        .map_err(|_| anyhow!("journal signature exceeds canonical encoding limit"))?;

    let mut hash = Sha256::new();
    hash.update(LEAF_DOMAIN);
    hash.update(event_id_len.to_be_bytes());
    hash.update(leaf.event_id.as_bytes());
    hash.update(leaf.event_timestamp.to_be_bytes());
    hash.update([event_type_tag(leaf.event_type_kind)]);
    hash.update(event_data_len.to_be_bytes());
    hash.update(leaf.event_data);
    hash.update(signature_len.to_be_bytes());
    hash.update(leaf.signature);
    Ok(hash.finalize().into())
}

pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(NODE_DOMAIN);
    hash.update(left);
    hash.update(right);
    hash.finalize().into()
}

pub fn empty_root() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(EMPTY_DOMAIN);
    hash.finalize().into()
}

/// Build a Merkle root from leaves pre-sorted by `(event_timestamp, event_id)`.
/// An odd final node is promoted unchanged to the next level.
pub fn merkle_root_from_leaves(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return empty_root();
    }

    let mut current = leaves.to_vec();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        for pair in current.chunks(2) {
            if let [left, right] = pair {
                next.push(node_hash(left, right));
            } else if let Some(only) = pair.first() {
                next.push(*only);
            }
        }
        current = next;
    }
    match current.as_slice() {
        [root] => *root,
        _ => empty_root(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf<'a>(kind: &'a str, data: &'a [u8], signature: &'a [u8]) -> JournalLeaf<'a> {
        JournalLeaf {
            event_id: "event-1",
            event_timestamp: 42,
            event_type_kind: kind,
            event_data: data,
            signature,
        }
    }

    #[test]
    fn empty_root_is_deterministic() {
        assert_eq!(empty_root(), empty_root());
    }

    #[test]
    fn single_leaf_root_equals_leaf() {
        let hashes = [[7; 32]];
        assert_eq!(merkle_root_from_leaves(&hashes), hashes[0]);
    }

    #[test]
    fn two_leaf_root_is_node_hash() {
        let leaves = [[1; 32], [2; 32]];
        assert_eq!(
            merkle_root_from_leaves(&leaves),
            node_hash(&leaves[0], &leaves[1])
        );
    }

    #[test]
    fn odd_leaf_promoted_without_hash() {
        let leaves = [[1; 32], [2; 32], [3; 32]];
        let expected = node_hash(&node_hash(&leaves[0], &leaves[1]), &leaves[2]);
        assert_eq!(merkle_root_from_leaves(&leaves), expected);
    }

    #[test]
    fn leaf_hash_is_domain_separated() {
        let contact =
            leaf_hash(&leaf("ContactAdded", b"data", b"sig")).expect("valid canonical leaf");
        let message =
            leaf_hash(&leaf("MessageAdded", b"data", b"sig")).expect("valid canonical leaf");
        assert_ne!(contact, message);
    }

    #[test]
    fn leaf_hash_changes_with_signature() {
        let first =
            leaf_hash(&leaf("MessageAdded", b"data", b"sig-1")).expect("valid canonical leaf");
        let second =
            leaf_hash(&leaf("MessageAdded", b"data", b"sig-2")).expect("valid canonical leaf");
        assert_ne!(first, second);
    }

    #[test]
    fn leaf_hash_changes_with_event_data() {
        let first =
            leaf_hash(&leaf("MessageAdded", b"data-1", b"sig")).expect("valid canonical leaf");
        let second =
            leaf_hash(&leaf("MessageAdded", b"data-2", b"sig")).expect("valid canonical leaf");
        assert_ne!(first, second);
    }

    #[test]
    fn unknown_event_type_uses_tag_255() {
        assert_eq!(event_type_tag("FutureSyncEvent"), 255);
    }
}
