use std::collections::HashMap;

use crate::dht::wire::DhtError;
use crate::dht::NodeId;
use crate::signaling::{PunchRequest, PUNCH_REQUEST_KEY_PREFIX};

/// Максимум запросов на один ключ (слот).
pub const PUNCH_REQUEST_MAX_PER_KEY: usize = 100;

/// TTL для кэша на сервере: min(expires_at, now + 10min).
pub const PUNCH_REQUEST_SERVER_TTL_SECS: u64 = 10 * 60;

/// Отдельный кэш PunchRequest на сервере.
///
/// Не смешивается с EndpointCache. Signature verification needs the requester's
/// public key, which is not part of the request record, and remains the target's
/// responsibility.
pub struct PunchRequestCache {
    cache: HashMap<[u8; 32], Vec<PunchRequest>>,
    server_expiries: HashMap<([u8; 32], NodeId, [u8; 16]), u64>,
    max_per_key: usize,
}

impl PunchRequestCache {
    pub fn new(max_per_key: usize) -> Self {
        Self {
            cache: HashMap::new(),
            server_expiries: HashMap::new(),
            max_per_key,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(PUNCH_REQUEST_MAX_PER_KEY)
    }

    /// Вставить запрос. Возвращает true, если принят.
    pub fn insert(
        &mut self,
        key: [u8; 32],
        request: PunchRequest,
        now: u64,
    ) -> Result<bool, DhtError> {
        if request.expires_at <= now {
            return Err(DhtError::InvalidRequest("punch request expired".into()));
        }
        if key != punch_request_key(&request.target_id) {
            return Err(DhtError::InvalidRequest(
                "punch request key mismatch".into(),
            ));
        }
        if self.max_per_key == 0 {
            return Ok(false);
        }

        let expired = self
            .cache
            .get(&key)
            .map(|slot| {
                slot.iter()
                    .filter(|existing| {
                        existing.expires_at <= now
                            || self
                                .server_expiries
                                .get(&(key, existing.requester_id, existing.nonce))
                                .is_none_or(|expires_at| *expires_at <= now)
                    })
                    .map(|existing| (existing.requester_id, existing.nonce))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if !expired.is_empty() {
            if let Some(slot) = self.cache.get_mut(&key) {
                slot.retain(|existing| {
                    existing.expires_at > now
                        && self
                            .server_expiries
                            .get(&(key, existing.requester_id, existing.nonce))
                            .is_some_and(|expires_at| *expires_at > now)
                });
            }
            for (requester_id, nonce) in expired {
                self.server_expiries.remove(&(key, requester_id, nonce));
            }
            self.cache.retain(|_, slot| !slot.is_empty());
        }

        let slot = self.cache.entry(key).or_default();
        if slot.iter().any(|existing| {
            existing.requester_id == request.requester_id && existing.nonce == request.nonce
        }) {
            return Ok(false);
        }

        let request_key = (key, request.requester_id, request.nonce);
        let server_expires_at = request
            .expires_at
            .min(now.saturating_add(PUNCH_REQUEST_SERVER_TTL_SECS));
        slot.push(request);
        self.server_expiries.insert(request_key, server_expires_at);

        while slot.len() > self.max_per_key {
            let oldest = slot.remove(0);
            self.server_expiries
                .remove(&(key, oldest.requester_id, oldest.nonce));
        }

        Ok(true)
    }

    /// Получить все запросы по ключу (фильтрует истёкшие).
    pub fn get(&self, key: &[u8; 32], now: u64) -> Vec<&PunchRequest> {
        self.cache
            .get(key)
            .map(|slot| {
                slot.iter()
                    .filter(|request| {
                        request.expires_at > now
                            && self
                                .server_expiries
                                .get(&(*key, request.requester_id, request.nonce))
                                .is_some_and(|expires_at| *expires_at > now)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Удалить истёкшие. Возвращает количество удалённых.
    pub fn cleanup_expired(&mut self, now: u64) -> usize {
        let expiries = &self.server_expiries;
        let mut removed = 0;
        self.cache.retain(|key, slot| {
            let before = slot.len();
            slot.retain(|request| {
                request.expires_at > now
                    && expiries
                        .get(&(*key, request.requester_id, request.nonce))
                        .is_some_and(|expires_at| *expires_at > now)
            });
            removed += before - slot.len();
            !slot.is_empty()
        });
        self.server_expiries
            .retain(|(key, requester_id, nonce), expires_at| {
                *expires_at > now
                    && self.cache.get(key).is_some_and(|slot| {
                        slot.iter().any(|request| {
                            request.requester_id == *requester_id && request.nonce == *nonce
                        })
                    })
            });
        removed
    }

    pub fn len(&self) -> usize {
        self.cache.values().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    pub fn tracked_keys(&self) -> usize {
        self.cache.len()
    }
}

fn punch_request_key(target_id: &NodeId) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(PUNCH_REQUEST_KEY_PREFIX.as_bytes());
    hasher.update(target_id.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::node_id::NodeId;
    use ed25519_dalek::SigningKey;
    use std::time::Duration;

    fn node(seed: u8) -> NodeId {
        NodeId::from_bytes([seed; 32])
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn nonce(seed: u8) -> [u8; 16] {
        [seed; 16]
    }

    fn request(seed: u8, now: u64, ttl_secs: u64) -> PunchRequest {
        let signing_key = key(seed);
        let requester_id = NodeId::from_public_key(&signing_key.verifying_key());
        PunchRequest::create(
            requester_id,
            node(99),
            "127.0.0.1:9000".parse().expect("socket address"),
            Duration::from_secs(ttl_secs),
            now,
            &signing_key,
            nonce(seed),
        )
        .expect("create request")
    }

    #[test]
    fn new_cache_empty() {
        let cache = PunchRequestCache::with_defaults();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.tracked_keys(), 0);
    }

    #[test]
    fn insert_valid_request() {
        let mut cache = PunchRequestCache::with_defaults();
        let request = request(1, 1_000, 20 * 60);
        let key = punch_request_key(&request.target_id);
        assert!(cache.insert(key, request, 1_000).expect("insert request"));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.tracked_keys(), 1);
        assert_eq!(cache.get(&key, 1_001).len(), 1);
        assert!(cache
            .get(&key, 1_000 + PUNCH_REQUEST_SERVER_TTL_SECS + 1)
            .is_empty());
    }

    #[test]
    fn insert_expired_rejected() {
        let mut cache = PunchRequestCache::with_defaults();
        let request = request(2, 1_000, 60);
        let key = punch_request_key(&request.target_id);
        assert!(matches!(
            cache.insert(key, request, 2_000),
            Err(DhtError::InvalidRequest(_))
        ));
        assert!(cache.is_empty());
    }

    #[test]
    fn insert_duplicate_returns_false() {
        let mut cache = PunchRequestCache::new(1);
        let first_request = request(3, 1_000, 300);
        let key = punch_request_key(&first_request.target_id);
        assert!(cache
            .insert(key, first_request.clone(), 1_000)
            .expect("insert first request"));
        assert!(!cache
            .insert(key, first_request, 1_000)
            .expect("deduplicate request"));
        assert_eq!(cache.len(), 1);

        let refreshed = request(3, 1_301, 300);
        assert!(cache
            .insert(key, refreshed, 1_301)
            .expect("accept request after prior entry expires"));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cleanup_expired_removes_stale() {
        let mut cache = PunchRequestCache::with_defaults();
        let request_a = request(4, 1_000, 60);
        let request_b = request(5, 1_000, 300);
        let key = punch_request_key(&request_a.target_id);
        cache
            .insert(key, request_a, 1_000)
            .expect("insert first request");
        cache
            .insert(key, request_b, 1_000)
            .expect("insert second request");

        let removed = cache.cleanup_expired(1_100);
        assert_eq!(removed, 1);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.tracked_keys(), 1);
    }
}
