use std::collections::HashMap;

pub const DEFAULT_RELAY_NONCE_CACHE_SIZE: usize = 10_000;

#[derive(Debug)]
pub struct RelayNonceCache {
    entries: HashMap<[u8; 16], u64>,
    max_size: usize,
}

impl Default for RelayNonceCache {
    fn default() -> Self {
        Self::new(DEFAULT_RELAY_NONCE_CACHE_SIZE)
    }
}

impl RelayNonceCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_size,
        }
    }

    pub fn contains(&self, nonce: &[u8; 16]) -> bool {
        self.entries.contains_key(nonce)
    }

    /// Inserts a new nonce unless it was seen or the bounded cache is full.
    /// Live entries are never evicted: saturation fails closed until cleanup.
    pub fn insert(&mut self, nonce: [u8; 16], expires_at: u64) -> bool {
        if self.entries.contains_key(&nonce) || self.entries.len() >= self.max_size {
            return false;
        }
        self.entries.insert(nonce, expires_at);
        true
    }

    pub fn cleanup_expired(&mut self, now: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, expires_at| *expires_at > now);
        before - self.entries.len()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::RelayNonceCache;

    #[test]
    fn nonce_is_retained_until_expiry() {
        let mut cache = RelayNonceCache::new(2);
        assert!(cache.insert([1; 16], 20));
        assert_eq!(cache.cleanup_expired(19), 0);
        assert!(cache.contains(&[1; 16]));
        assert_eq!(cache.cleanup_expired(20), 1);
        assert!(!cache.contains(&[1; 16]));
    }

    #[test]
    fn duplicate_nonce_is_rejected() {
        let mut cache = RelayNonceCache::new(2);
        assert!(cache.insert([1; 16], 20));
        assert!(!cache.insert([1; 16], 30));
    }

    #[test]
    fn full_cache_fails_closed_without_evicting_live_nonce() {
        let mut cache = RelayNonceCache::new(1);
        assert!(cache.insert([1; 16], 20));
        assert!(!cache.insert([2; 16], 30));
        assert!(cache.contains(&[1; 16]));
        assert!(!cache.contains(&[2; 16]));
    }
}
