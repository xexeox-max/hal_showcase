use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use thiserror::Error;
use zeroize::Zeroizing;

type EvidenceKey = ([u8; 32], [u8; 32]);

#[derive(Default)]
pub struct JuryPlaintextCache {
    entries: Mutex<HashMap<EvidenceKey, Zeroizing<Vec<u8>>>>,
    attempted: Mutex<HashSet<EvidenceKey>>,
}

impl JuryPlaintextCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &self,
        complaint_id: [u8; 32],
        evidence_hash: [u8; 32],
        plaintext: Zeroizing<Vec<u8>>,
    ) -> Result<(), JuryPlaintextError> {
        self.entries
            .lock()
            .map_err(|_| JuryPlaintextError::Poisoned)?
            .insert((complaint_id, evidence_hash), plaintext);
        Ok(())
    }

    pub fn get(
        &self,
        complaint_id: &[u8; 32],
        evidence_hash: &[u8; 32],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, JuryPlaintextError> {
        self.entries
            .lock()
            .map_err(|_| JuryPlaintextError::Poisoned)
            .map(|entries| {
                entries
                    .get(&(*complaint_id, *evidence_hash))
                    .map(|plaintext| Zeroizing::new(plaintext.to_vec()))
            })
    }

    pub fn remove(
        &self,
        complaint_id: &[u8; 32],
        evidence_hash: &[u8; 32],
    ) -> Result<(), JuryPlaintextError> {
        self.entries
            .lock()
            .map_err(|_| JuryPlaintextError::Poisoned)?
            .remove(&(*complaint_id, *evidence_hash));
        Ok(())
    }

    pub fn len(&self) -> Result<usize, JuryPlaintextError> {
        self.entries
            .lock()
            .map_err(|_| JuryPlaintextError::Poisoned)
            .map(|entries| entries.len())
    }

    pub(crate) fn mark_attempted(
        &self,
        complaint_id: [u8; 32],
        evidence_hash: [u8; 32],
    ) -> Result<bool, JuryPlaintextError> {
        self.attempted
            .lock()
            .map_err(|_| JuryPlaintextError::Poisoned)
            .map(|mut attempted| attempted.insert((complaint_id, evidence_hash)))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum JuryPlaintextError {
    #[error("plaintext cache mutex poisoned")]
    Poisoned,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_get_roundtrip() {
        let cache = JuryPlaintextCache::new();
        cache
            .insert([1; 32], [2; 32], Zeroizing::new(vec![3, 4, 5]))
            .expect("insert plaintext");
        assert_eq!(
            cache
                .get(&[1; 32], &[2; 32])
                .expect("read cache")
                .map(|bytes| bytes.to_vec()),
            Some(vec![3, 4, 5])
        );
    }

    #[test]
    fn get_returns_none_when_missing() {
        assert!(JuryPlaintextCache::new()
            .get(&[1; 32], &[2; 32])
            .expect("read cache")
            .is_none());
    }

    #[test]
    fn remove_clears_entry() {
        let cache = JuryPlaintextCache::new();
        cache
            .insert([1; 32], [2; 32], Zeroizing::new(vec![3]))
            .expect("insert plaintext");
        cache.remove(&[1; 32], &[2; 32]).expect("remove plaintext");
        assert!(cache.get(&[1; 32], &[2; 32]).expect("read cache").is_none());
        assert_eq!(cache.len().expect("cache length"), 0);
    }

    #[test]
    fn insert_overwrites_existing() {
        let cache = JuryPlaintextCache::new();
        cache
            .insert([1; 32], [2; 32], Zeroizing::new(vec![3]))
            .expect("insert initial plaintext");
        cache
            .insert([1; 32], [2; 32], Zeroizing::new(vec![4]))
            .expect("overwrite plaintext");
        assert_eq!(
            cache
                .get(&[1; 32], &[2; 32])
                .expect("read cache")
                .map(|bytes| bytes.to_vec()),
            Some(vec![4])
        );
    }

    #[test]
    fn decryption_attempt_is_claimed_once() {
        let cache = JuryPlaintextCache::new();
        assert!(cache
            .mark_attempted([1; 32], [2; 32])
            .expect("claim attempt"));
        assert!(!cache.mark_attempted([1; 32], [2; 32]).expect("claim again"));
    }
}
