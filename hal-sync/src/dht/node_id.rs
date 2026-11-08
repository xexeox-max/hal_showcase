use anyhow::{anyhow, Result};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    pub fn from_public_key(pubkey: &VerifyingKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(pubkey.to_bytes());
        Self(hasher.finalize().into())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(value: &str) -> Result<Self> {
        let bytes = hex::decode(value).map_err(|error| anyhow!("invalid NodeId hex: {error}"))?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow!("NodeId must contain exactly 32 bytes"))?;
        Ok(Self(bytes))
    }

    pub fn distance(&self, other: &NodeId) -> [u8; 32] {
        let mut distance = [0u8; 32];
        for (index, byte) in distance.iter_mut().enumerate() {
            *byte = self.0[index] ^ other.0[index];
        }
        distance
    }

    pub fn bucket_index(&self, other: &NodeId) -> Option<u8> {
        self.distance(other)
            .iter()
            .enumerate()
            .find_map(|(byte_index, byte)| {
                if *byte == 0 {
                    None
                } else {
                    Some((byte_index * 8 + byte.leading_zeros() as usize) as u8)
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn from_public_key_deterministic() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        assert_eq!(
            NodeId::from_public_key(&key.verifying_key()),
            NodeId::from_public_key(&key.verifying_key())
        );
    }

    #[test]
    fn distance_symmetric() {
        let first = NodeId::from_bytes([0x10; 32]);
        let second = NodeId::from_bytes([0x20; 32]);
        assert_eq!(first.distance(&second), second.distance(&first));
    }

    #[test]
    fn distance_zero_for_self() {
        let node = NodeId::from_bytes([0xabu8; 32]);
        assert_eq!(node.distance(&node), [0u8; 32]);
        assert_eq!(node.bucket_index(&node), None);
    }

    #[test]
    fn bucket_index_basic() {
        let local = NodeId::from_bytes([0u8; 32]);
        let first_bit = NodeId::from_bytes([0x80; 32]);
        let mut ninth_bit = [0u8; 32];
        ninth_bit[1] = 0x80;
        let ninth_bit = NodeId::from_bytes(ninth_bit);
        assert_eq!(local.bucket_index(&first_bit), Some(0));
        assert_eq!(local.bucket_index(&ninth_bit), Some(8));
    }

    #[test]
    fn hex_roundtrip() {
        let node = NodeId::from_bytes([0x5au8; 32]);
        assert_eq!(NodeId::from_hex(&node.to_hex()).expect("NodeId hex"), node);
        assert!(NodeId::from_hex("00").is_err());
    }
}
