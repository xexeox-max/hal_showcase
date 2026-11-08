use anyhow::{anyhow, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterDelta {
    Joined(String),
    Left(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterStateRecord {
    pub cluster_id: String,
    pub epoch: u64,
    pub sequence: u64,
    pub observed_at: u64,
    pub previous_hash: String,
    pub active_root: String,
    pub active_count: u32,
    pub delta: Vec<ClusterDelta>,
    pub authority_public_key: String,
    pub signature: String,
}

impl ClusterStateRecord {
    pub fn new(
        cluster_id: String,
        epoch: u64,
        sequence: u64,
        observed_at: u64,
        previous_hash: String,
        active_ids: &[String],
        delta: Vec<ClusterDelta>,
        authority_public_key: String,
    ) -> Self {
        Self {
            cluster_id,
            epoch,
            sequence,
            observed_at,
            previous_hash,
            active_root: merkle_root(active_ids),
            active_count: active_ids.len() as u32,
            delta,
            authority_public_key,
            signature: String::new(),
        }
    }

    fn signing_payload(&self) -> Vec<u8> {
        // own-struct serde cannot fail in practice; policy forbids expect
        let bytes = serde_json::to_vec(&(
            &self.cluster_id,
            self.epoch,
            self.sequence,
            self.observed_at,
            &self.previous_hash,
            &self.active_root,
            self.active_count,
            &self.delta,
            &self.authority_public_key,
        ))
        .unwrap_or_default();
        bytes
    }

    pub fn sign(&mut self, private_key: &[u8; 32]) {
        self.signature = hex::encode(
            SigningKey::from_bytes(private_key)
                .sign(&self.signing_payload())
                .to_bytes(),
        );
    }

    pub fn verify(&self) -> Result<()> {
        let public_key: [u8; 32] = hex::decode(&self.authority_public_key)
            .map_err(|_| anyhow!("invalid cluster authority public key"))?
            .try_into()
            .map_err(|_| anyhow!("cluster authority public key must be 32 bytes"))?;
        let signature: [u8; 64] = hex::decode(&self.signature)
            .map_err(|_| anyhow!("invalid cluster record signature"))?
            .try_into()
            .map_err(|_| anyhow!("cluster record signature must be 64 bytes"))?;
        VerifyingKey::from_bytes(&public_key)?
            .verify(&self.signing_payload(), &Signature::from_bytes(&signature))?;
        Ok(())
    }

    pub fn record_hash(&self) -> String {
        let mut hash = Sha256::new();
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        hash.update(&bytes);
        hex::encode(hash.finalize())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipProof {
    pub node_id: String,
    pub leaf_index: usize,
    pub siblings: Vec<String>,
    pub root: String,
}

impl MembershipProof {
    pub fn verify(&self) -> bool {
        let mut current = leaf_hash(&self.node_id);
        let mut index = self.leaf_index;
        for sibling in &self.siblings {
            let Ok(sibling_bytes) = hex::decode(sibling) else {
                return false;
            };
            let mut hash = Sha256::new();
            if index % 2 == 0 {
                hash.update(&current);
                hash.update(sibling_bytes);
            } else {
                hash.update(sibling_bytes);
                hash.update(&current);
            }
            current = hash.finalize().to_vec();
            index /= 2;
        }
        hex::encode(current) == self.root
    }
}

pub fn membership_proof(active_ids: &[String], node_id: &str) -> Option<MembershipProof> {
    let mut leaves = active_ids.to_vec();
    leaves.sort();
    let mut index = leaves.iter().position(|id| id == node_id)?;
    let original_index = index;
    let mut level = leaves.iter().map(|id| leaf_hash(id)).collect::<Vec<_>>();
    let mut siblings = Vec::new();
    while level.len() > 1 {
        let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
        let sibling = level
            .get(sibling_index)
            .cloned()
            .unwrap_or_else(|| level[index].clone());
        siblings.push(hex::encode(sibling));
        let mut next = Vec::new();
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            let mut hash = Sha256::new();
            hash.update(&pair[0]);
            hash.update(right);
            next.push(hash.finalize().to_vec());
        }
        level = next;
        index /= 2;
    }
    Some(MembershipProof {
        node_id: node_id.to_string(),
        leaf_index: original_index,
        siblings,
        root: hex::encode(level.first()?),
    })
}

pub fn merkle_root(active_ids: &[String]) -> String {
    if active_ids.is_empty() {
        return hex::encode(leaf_hash(""));
    }
    let mut leaves = active_ids.to_vec();
    leaves.sort();
    let mut level = leaves.iter().map(|id| leaf_hash(id)).collect::<Vec<_>>();
    while level.len() > 1 {
        let mut next = Vec::new();
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            let mut hash = Sha256::new();
            hash.update(&pair[0]);
            hash.update(right);
            next.push(hash.finalize().to_vec());
        }
        level = next;
    }
    hex::encode(level[0].clone())
}

fn leaf_hash(node_id: &str) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"hal-infinity:cluster-leaf:v1");
    hash.update((node_id.len() as u64).to_be_bytes());
    hash.update(node_id.as_bytes());
    hash.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> Vec<String> {
        vec!["node-c".into(), "node-a".into(), "node-b".into()]
    }

    #[test]
    fn membership_proof_verifies_against_cluster_root() {
        let active = ids();
        let proof = membership_proof(&active, "node-b").unwrap();
        assert_eq!(proof.root, merkle_root(&active));
        assert!(proof.verify());
    }

    #[test]
    fn membership_proof_rejects_wrong_node() {
        let active = ids();
        let mut proof = membership_proof(&active, "node-b").unwrap();
        proof.node_id = "node-x".into();
        assert!(!proof.verify());
    }

    #[test]
    fn signed_record_rejects_tampering() {
        let private_key = [41; 32];
        let public_key = hex::encode(
            SigningKey::from_bytes(&private_key)
                .verifying_key()
                .to_bytes(),
        );
        let mut record = ClusterStateRecord::new(
            "cluster-1".into(),
            1,
            1,
            100,
            "root-0".into(),
            &ids(),
            vec![],
            public_key,
        );
        record.sign(&private_key);
        assert!(record.verify().is_ok());
        record.active_count += 1;
        assert!(record.verify().is_err());
    }
}
