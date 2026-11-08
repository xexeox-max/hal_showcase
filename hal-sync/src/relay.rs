use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::dht::trust_oracle::{Relationship, TrustOracle};
use crate::dht::NodeId;

/// Срок жизни relay-запроса: 60 секунд (relay быстрый).
pub const RELAY_DEFAULT_TTL_SECS: u64 = 60;

/// Максимальный срок: 5 минут.
pub const RELAY_MAX_TTL_SECS: u64 = 300;

/// Максимум relay-узлов в цепочке (multi-hop).
pub const RELAY_MAX_CHAIN_DEPTH: usize = 3;

/// Роль relay-узла.
///
/// Temp (N5a): только TrustedDesktop (Known/Circle).
/// TODO(N5d): TrustedDesktopWithCrossSign (TrustedNodes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayRole {
    /// Десктоп-узел без trust-подтверждения (не используется в temp).
    Desktop,
    /// Trusted desktop (Known или Circle в TrustOracle). Temp.
    TrustedDesktop,
}

/// Подписанный запрос на релей.
///
/// requester_id → relay (этот узел) → target_id.
/// relay_chain — путь (для multi-hop). Пусто = single relay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayRequest {
    pub requester_id: NodeId,
    pub target_id: NodeId,
    /// Сериализованный SyncEnvelope (opaque для relay).
    pub envelope_bytes: Vec<u8>,
    pub nonce: [u8; 16],
    pub created_at: u64,
    pub expires_at: u64,
    /// Путь relay-узлов. Пусто = single relay (direct).
    pub relay_chain: Vec<NodeId>,
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
}

/// Событие доставки inner envelope от requester'а к target'у через relay.
/// Подписывается relay'ем; inner envelope проверяется отдельно.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayForwardEvent {
    pub requester_id: NodeId,
    pub requester_identity_id: String,
    pub requester_public_key_hex: String,
    pub relay_nonce: [u8; 16],
    /// Original requester-signed RelayRequest, encoded as base64 JSON.
    pub requester_consent: String,
    /// base64(serde_json::to_vec(inner SyncEnvelope)).
    pub inner_envelope_base64: String,
    pub forwarded_at: u64,
}

impl RelayForwardEvent {
    pub fn to_base64(&self) -> Result<String, RelayError> {
        let bytes = serde_json::to_vec(self).map_err(|_| RelayError::Malformed)?;
        use base64::{engine::general_purpose::STANDARD, Engine};
        Ok(STANDARD.encode(bytes))
    }

    pub fn from_base64(encoded: &str) -> Result<Self, RelayError> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|_| RelayError::Malformed)?;
        serde_json::from_slice(&bytes).map_err(|_| RelayError::Malformed)
    }
}

mod signature_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(signature: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(signature)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        bytes.try_into().map_err(|bytes: Vec<u8>| {
            serde::de::Error::custom(format!("signature must be 64 bytes, got {}", bytes.len()))
        })
    }
}

#[derive(Serialize)]
struct RelayRequestPayload<'a> {
    requester_id: &'a NodeId,
    target_id: &'a NodeId,
    envelope_bytes: &'a [u8],
    nonce: &'a [u8; 16],
    created_at: u64,
    expires_at: u64,
    relay_chain: &'a [NodeId],
}

/// Ответ relay-узла.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelayResponse {
    /// Relay принял запрос, будет пересылать. forward_token — для трекинга.
    Accepted { forward_token: [u8; 16] },
    /// Уже переслано target'у.
    Forwarded,
    /// Отклонено с причиной.
    Rejected { reason: String },
    /// Ошибка.
    Error { code: u16, message: String },
}

/// Ошибки relay-протокола.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    InvalidSignature,
    Expired,
    FromFuture,
    Malformed,
    ChainTooDeep,
    /// requester_id == target_id.
    SelfRelay,
    /// requester_id == relay (этот узел).
    RequesterIsRelay,
    /// relay_chain содержит этот узел (loop).
    ChainLoop,
    /// Отклонено RelayPolicy.
    PolicyDenied,
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "invalid relay request signature"),
            Self::Expired => write!(f, "relay request expired"),
            Self::FromFuture => write!(f, "relay request from future"),
            Self::Malformed => write!(f, "malformed relay request"),
            Self::ChainTooDeep => write!(f, "relay chain too deep"),
            Self::SelfRelay => write!(f, "requester and target are the same"),
            Self::RequesterIsRelay => write!(f, "requester is the relay"),
            Self::ChainLoop => write!(f, "relay chain contains loop"),
            Self::PolicyDenied => write!(f, "relay denied by policy"),
        }
    }
}

impl std::error::Error for RelayError {}

impl RelayRequest {
    /// Создать подписанный relay-запрос.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        requester_id: NodeId,
        target_id: NodeId,
        envelope_bytes: Vec<u8>,
        ttl_secs: u64,
        now: u64,
        relay_chain: Vec<NodeId>,
        signing_key: &SigningKey,
        nonce: [u8; 16],
    ) -> Result<Self, RelayError> {
        if requester_id == target_id {
            return Err(RelayError::SelfRelay);
        }
        if ttl_secs > RELAY_MAX_TTL_SECS {
            return Err(RelayError::Malformed);
        }
        if relay_chain.len() > RELAY_MAX_CHAIN_DEPTH {
            return Err(RelayError::ChainTooDeep);
        }
        let expires_at = now.saturating_add(ttl_secs);
        let payload = RelayRequestPayload {
            requester_id: &requester_id,
            target_id: &target_id,
            envelope_bytes: &envelope_bytes,
            nonce: &nonce,
            created_at: now,
            expires_at,
            relay_chain: &relay_chain,
        };
        let bytes = serde_json::to_vec(&payload).map_err(|_| RelayError::Malformed)?;
        let signature = signing_key.sign(&bytes).to_bytes();

        Ok(Self {
            requester_id,
            target_id,
            envelope_bytes,
            nonce,
            created_at: now,
            expires_at,
            relay_chain,
            signature,
        })
    }

    /// Проверить подпись, ttl, chain.
    ///
    /// relay_id — идентификатор узла, который обрабатывает запрос.
    pub fn verify(
        &self,
        requester_pubkey: &VerifyingKey,
        relay_id: NodeId,
        now: u64,
    ) -> Result<(), RelayError> {
        if self.requester_id == self.target_id {
            return Err(RelayError::SelfRelay);
        }
        if self.requester_id == relay_id {
            return Err(RelayError::RequesterIsRelay);
        }
        if self.relay_chain.contains(&relay_id) {
            return Err(RelayError::ChainLoop);
        }
        if self.relay_chain.len() > RELAY_MAX_CHAIN_DEPTH {
            return Err(RelayError::ChainTooDeep);
        }
        if self.expires_at < self.created_at
            || self.expires_at.saturating_sub(self.created_at) > RELAY_MAX_TTL_SECS
        {
            return Err(RelayError::Malformed);
        }
        if now < self.created_at {
            return Err(RelayError::FromFuture);
        }
        if now > self.expires_at {
            return Err(RelayError::Expired);
        }
        let payload = RelayRequestPayload {
            requester_id: &self.requester_id,
            target_id: &self.target_id,
            envelope_bytes: &self.envelope_bytes,
            nonce: &self.nonce,
            created_at: self.created_at,
            expires_at: self.expires_at,
            relay_chain: &self.relay_chain,
        };
        let bytes = serde_json::to_vec(&payload).map_err(|_| RelayError::Malformed)?;
        let signature = Signature::from_bytes(&self.signature);
        requester_pubkey
            .verify(&bytes, &signature)
            .map_err(|_| RelayError::InvalidSignature)
    }

    pub fn to_base64(&self) -> Result<String, RelayError> {
        let bytes = serde_json::to_vec(self).map_err(|_| RelayError::Malformed)?;
        use base64::{engine::general_purpose::STANDARD, Engine};
        Ok(STANDARD.encode(&bytes))
    }

    pub fn from_base64(s: &str) -> Result<Self, RelayError> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let bytes = STANDARD.decode(s).map_err(|_| RelayError::Malformed)?;
        serde_json::from_slice(&bytes).map_err(|_| RelayError::Malformed)
    }
}

impl RelayResponse {
    pub fn to_base64(&self) -> Result<String, RelayError> {
        let bytes = serde_json::to_vec(self).map_err(|_| RelayError::Malformed)?;
        use base64::{engine::general_purpose::STANDARD, Engine};
        Ok(STANDARD.encode(&bytes))
    }

    pub fn from_base64(s: &str) -> Result<Self, RelayError> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let bytes = STANDARD.decode(s).map_err(|_| RelayError::Malformed)?;
        serde_json::from_slice(&bytes).map_err(|_| RelayError::Malformed)
    }
}

/// Политика relay-узла.
///
/// Temp (N5a): только Known/Circle.
/// TODO(N5d): TrustedDesktopWithCrossSign через TrustedNodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayPolicy {
    pub max_chain_depth: usize,
    /// Temp: требовать Known/Circle. TODO(N5d): убрать в пользу cross-sign.
    pub require_trusted: bool,
}

impl Default for RelayPolicy {
    fn default() -> Self {
        Self {
            max_chain_depth: RELAY_MAX_CHAIN_DEPTH,
            require_trusted: true,
        }
    }
}

impl RelayPolicy {
    pub fn default_trusted() -> Self {
        Self::default()
    }

    pub fn permissive() -> Self {
        Self {
            max_chain_depth: RELAY_MAX_CHAIN_DEPTH,
            require_trusted: false,
        }
    }

    /// Разрешён ли узел как relay-кандидат.
    ///
    /// Если require_trusted: только Known/Circle.
    /// Иначе: Known/Circle/Unknown (не Banned).
    pub fn allows(&self, oracle: &dyn TrustOracle, node_id: &NodeId, _now: u64) -> bool {
        let relationship = oracle.relationship(node_id);
        if relationship == Relationship::Banned {
            return false;
        }
        if self.require_trusted {
            matches!(relationship, Relationship::Circle | Relationship::Known)
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::group::{GroupGraph, GroupRegistry};
    use crate::dht::rate_limit::RateLimiter;
    use crate::dht::trust::TrustScoreManager;
    use crate::dht::trust_oracle::BasicTrustOracle;
    use crate::pinning::KnownHosts;
    use std::sync::{Arc, Mutex as StdMutex};

    fn node(seed: u8) -> NodeId {
        NodeId::from_bytes([seed; 32])
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn nonce(seed: u8) -> [u8; 16] {
        [seed; 16]
    }

    fn oracle_with_hosts(hosts: Arc<StdMutex<KnownHosts>>) -> Arc<dyn TrustOracle> {
        let scores = Arc::new(StdMutex::new(TrustScoreManager::new()));
        let rates = Arc::new(StdMutex::new(RateLimiter::new()));
        let groups: Arc<dyn GroupGraph> = Arc::new(GroupRegistry::new());
        Arc::new(BasicTrustOracle::new(scores, rates, hosts, groups))
    }

    #[test]
    fn relay_request_create_and_verify() {
        let sk = key(1);
        let vk = sk.verifying_key();
        let requester = NodeId::from_public_key(&vk);
        let target = node(2);
        let relay = node(3);

        let request = RelayRequest::create(
            requester,
            target,
            b"envelope".to_vec(),
            RELAY_DEFAULT_TTL_SECS,
            1000,
            vec![],
            &sk,
            nonce(1),
        )
        .expect("create");
        assert!(request.verify(&vk, relay, 1010).is_ok());
    }

    #[test]
    fn relay_request_expired_rejected() {
        let sk = key(2);
        let vk = sk.verifying_key();
        let requester = NodeId::from_public_key(&vk);

        let request = RelayRequest::create(
            requester,
            node(2),
            b"envelope".to_vec(),
            RELAY_DEFAULT_TTL_SECS,
            1000,
            vec![],
            &sk,
            nonce(2),
        )
        .expect("create");
        assert_eq!(
            request.verify(&vk, node(3), 1000 + RELAY_DEFAULT_TTL_SECS + 1),
            Err(RelayError::Expired)
        );
    }

    #[test]
    fn relay_request_self_relay_rejected() {
        let sk = key(3);
        let same = NodeId::from_public_key(&sk.verifying_key());

        let result = RelayRequest::create(
            same,
            same,
            b"x".to_vec(),
            RELAY_DEFAULT_TTL_SECS,
            1000,
            vec![],
            &sk,
            nonce(3),
        );
        assert_eq!(result, Err(RelayError::SelfRelay));
    }

    #[test]
    fn relay_request_chain_too_deep_rejected() {
        let sk = key(4);
        let requester = NodeId::from_public_key(&sk.verifying_key());
        let chain: Vec<NodeId> = (0..RELAY_MAX_CHAIN_DEPTH + 1)
            .map(|i| node(100 + i as u8))
            .collect();

        let result = RelayRequest::create(
            requester,
            node(2),
            b"x".to_vec(),
            RELAY_DEFAULT_TTL_SECS,
            1000,
            chain,
            &sk,
            nonce(4),
        );
        assert_eq!(result, Err(RelayError::ChainTooDeep));
    }

    #[test]
    fn relay_response_base64_roundtrip() {
        let response = RelayResponse::Accepted {
            forward_token: [7u8; 16],
        };
        let encoded = response.to_base64().expect("encode");
        let decoded = RelayResponse::from_base64(&encoded).expect("decode");
        assert_eq!(decoded, response);
    }

    #[test]
    fn relay_policy_trusted_allows_known() {
        let sk = key(5);
        let vk = sk.verifying_key();
        let known_id = NodeId::from_public_key(&vk);
        let key_hex = hex::encode(vk.to_bytes());

        let hosts = Arc::new(StdMutex::new(KnownHosts::new()));
        {
            let mut h = hosts.lock().unwrap();
            h.pin_manual(&known_id.to_hex(), &key_hex, 100).unwrap();
        }
        let oracle = oracle_with_hosts(hosts);
        let policy = RelayPolicy::default_trusted();
        assert!(policy.allows(oracle.as_ref(), &known_id, 1000));
    }

    #[test]
    fn relay_policy_trusted_denies_unknown() {
        let hosts = Arc::new(StdMutex::new(KnownHosts::new()));
        let oracle = oracle_with_hosts(hosts);
        let policy = RelayPolicy::default_trusted();
        assert!(!policy.allows(oracle.as_ref(), &node(99), 1000));
    }
}
