use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::dht::group::GroupId;
use crate::dht::routing::RoutingTable;
use crate::dht::routing::K;
use crate::dht::transport::DhtTransport;
use crate::dht::wire::{
    DhtError, DhtRequest, DhtRequestPayload, DhtResponsePayload, StoredRecordType,
};
use crate::dht::NodeId;

pub const PUNCH_REQUEST_DEFAULT_TTL: Duration = Duration::from_secs(5 * 60);
pub const PUNCH_REQUEST_MAX_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PunchRequest {
    pub requester_id: NodeId,
    pub target_id: NodeId,
    pub requester_endpoint: String,
    pub nonce: [u8; 16],
    pub created_at: u64,
    pub expires_at: u64,
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
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
struct PunchRequestPayload<'a> {
    requester_id: &'a NodeId,
    target_id: &'a NodeId,
    requester_endpoint: &'a str,
    nonce: &'a [u8; 16],
    created_at: u64,
    expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignalingError {
    InvalidSignature,
    Expired,
    FromFuture,
    Malformed,
    SelfPunch,
    TargetMismatch,
    TtlTooLong,
}

impl fmt::Display for SignalingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "invalid punch request signature"),
            Self::Expired => write!(f, "punch request expired"),
            Self::FromFuture => write!(f, "punch request is from the future"),
            Self::Malformed => write!(f, "malformed punch request"),
            Self::SelfPunch => write!(f, "punch request targets the requester"),
            Self::TargetMismatch => write!(f, "punch request target does not match"),
            Self::TtlTooLong => write!(f, "punch request TTL is too long"),
        }
    }
}

impl std::error::Error for SignalingError {}

impl PunchRequest {
    pub fn create(
        requester_id: NodeId,
        target_id: NodeId,
        requester_endpoint: SocketAddr,
        ttl: Duration,
        now: u64,
        signing_key: &SigningKey,
        nonce: [u8; 16],
    ) -> Result<Self, SignalingError> {
        if requester_id == target_id {
            return Err(SignalingError::SelfPunch);
        }
        if ttl > PUNCH_REQUEST_MAX_TTL {
            return Err(SignalingError::TtlTooLong);
        }
        let ttl_seconds = u64::try_from(ttl.as_secs()).map_err(|_| SignalingError::Malformed)?;
        let expires_at = now
            .checked_add(ttl_seconds)
            .ok_or(SignalingError::Malformed)?;
        let requester_endpoint = requester_endpoint.to_string();
        let payload = PunchRequestPayload {
            requester_id: &requester_id,
            target_id: &target_id,
            requester_endpoint: &requester_endpoint,
            nonce: &nonce,
            created_at: now,
            expires_at,
        };
        let bytes = serde_json::to_vec(&payload).map_err(|_| SignalingError::Malformed)?;
        let signature = signing_key.sign(&bytes).to_bytes();

        Ok(Self {
            requester_id,
            target_id,
            requester_endpoint,
            nonce,
            created_at: now,
            expires_at,
            signature,
        })
    }

    pub fn verify(
        &self,
        requester_pubkey: &VerifyingKey,
        my_id: NodeId,
        now: u64,
    ) -> Result<(), SignalingError> {
        if self.requester_id == self.target_id {
            return Err(SignalingError::SelfPunch);
        }
        if self.target_id != my_id {
            return Err(SignalingError::TargetMismatch);
        }
        if now < self.created_at {
            return Err(SignalingError::FromFuture);
        }
        if now > self.expires_at {
            return Err(SignalingError::Expired);
        }
        let payload = PunchRequestPayload {
            requester_id: &self.requester_id,
            target_id: &self.target_id,
            requester_endpoint: &self.requester_endpoint,
            nonce: &self.nonce,
            created_at: self.created_at,
            expires_at: self.expires_at,
        };
        let bytes = serde_json::to_vec(&payload).map_err(|_| SignalingError::Malformed)?;
        let signature = Signature::from_bytes(&self.signature);
        requester_pubkey
            .verify(&bytes, &signature)
            .map_err(|_| SignalingError::InvalidSignature)
    }

    pub fn to_base64(&self) -> Result<String, SignalingError> {
        let bytes = serde_json::to_vec(self).map_err(|_| SignalingError::Malformed)?;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn from_base64(s: &str) -> Result<Self, SignalingError> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let bytes = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| SignalingError::Malformed)?;
        serde_json::from_slice(&bytes).map_err(|_| SignalingError::Malformed)
    }

    pub fn endpoint(&self) -> Result<SocketAddr, SignalingError> {
        self.requester_endpoint
            .parse()
            .map_err(|_| SignalingError::Malformed)
    }
}

/// Замаскировать PunchRequest в указанный формат.
pub fn mask_punch_request(
    request: &PunchRequest,
    format: SignalingFormat,
) -> Result<Vec<u8>, SignalingError> {
    match format {
        SignalingFormat::Explicit => {
            serde_json::to_vec(request).map_err(|_| SignalingError::Malformed)
        }
        SignalingFormat::AsSync => {
            let b64 = request.to_base64()?;
            let event = crate::journal::SyncEvent::new(
                String::new(),
                crate::journal::SyncEventType::MessageAdded,
                b64,
            );
            let envelope =
                crate::transport::SyncEnvelope::new(String::new(), String::new(), vec![event]);
            serde_json::to_vec(&envelope).map_err(|_| SignalingError::Malformed)
        }
        SignalingFormat::AsMessage => {
            let b64 = request.to_base64()?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0);
            let payload = serde_json::json!({
                "text": b64,
                "timestamp": now,
            });
            serde_json::to_vec(&payload).map_err(|_| SignalingError::Malformed)
        }
        SignalingFormat::AsHeartbeat | SignalingFormat::AsEndpoint => {
            Err(SignalingError::Malformed)
        }
    }
}

/// Демаскировать PunchRequest из Explicit, AsSync или AsMessage JSON.
pub fn unmask_punch_request(
    bytes: &[u8],
) -> Result<(PunchRequest, SignalingFormat), SignalingError> {
    if let Ok(request) = serde_json::from_slice::<PunchRequest>(bytes) {
        return Ok((request, SignalingFormat::Explicit));
    }
    if let Ok(envelope) = serde_json::from_slice::<crate::transport::SyncEnvelope>(bytes) {
        if let Some(event) = envelope.events.first() {
            if let Ok(request) = PunchRequest::from_base64(&event.data) {
                return Ok((request, SignalingFormat::AsSync));
            }
        }
    }
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) {
        if let Some(text) = value.get("text").and_then(serde_json::Value::as_str) {
            if let Ok(request) = PunchRequest::from_base64(text) {
                return Ok((request, SignalingFormat::AsMessage));
            }
        }
    }
    Err(SignalingError::Malformed)
}

/// Замаскировать весь слот (Vec<PunchRequest>) в указанный формат.
///
/// Explicit — JSON Vec<PunchRequest>.
/// AsSync — SyncEnvelope с event.data = base64(JSON).
/// AsMessage — JSON { text: base64(JSON), timestamp }.
pub fn mask_punch_slot(
    slot: &[PunchRequest],
    format: SignalingFormat,
) -> Result<Vec<u8>, SignalingError> {
    let inner = serde_json::to_vec(slot).map_err(|_| SignalingError::Malformed)?;
    match format {
        SignalingFormat::Explicit => Ok(inner),
        SignalingFormat::AsSync => {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine;
            let b64 = URL_SAFE_NO_PAD.encode(&inner);
            let event = crate::journal::SyncEvent::new(
                String::new(),
                crate::journal::SyncEventType::MessageAdded,
                b64,
            );
            let envelope =
                crate::transport::SyncEnvelope::new(String::new(), String::new(), vec![event]);
            serde_json::to_vec(&envelope).map_err(|_| SignalingError::Malformed)
        }
        SignalingFormat::AsMessage => {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine;
            let b64 = URL_SAFE_NO_PAD.encode(&inner);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0);
            let payload = serde_json::json!({
                "text": b64,
                "timestamp": now,
            });
            serde_json::to_vec(&payload).map_err(|_| SignalingError::Malformed)
        }
        SignalingFormat::AsHeartbeat | SignalingFormat::AsEndpoint => {
            Err(SignalingError::Malformed)
        }
    }
}

/// Демаскировать слот (Vec<PunchRequest>) в порядке Explicit → AsSync → AsMessage.
pub fn unmask_punch_slot(
    bytes: &[u8],
) -> Result<(Vec<PunchRequest>, SignalingFormat), SignalingError> {
    if let Ok(slot) = serde_json::from_slice::<Vec<PunchRequest>>(bytes) {
        return Ok((slot, SignalingFormat::Explicit));
    }
    if let Ok(single) = serde_json::from_slice::<PunchRequest>(bytes) {
        return Ok((vec![single], SignalingFormat::Explicit));
    }
    if let Ok(envelope) = serde_json::from_slice::<crate::transport::SyncEnvelope>(bytes) {
        if let Some(event) = envelope.events.first() {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine;
            if let Ok(decoded) = URL_SAFE_NO_PAD.decode(&event.data) {
                if let Ok(slot) = serde_json::from_slice::<Vec<PunchRequest>>(&decoded) {
                    return Ok((slot, SignalingFormat::AsSync));
                }
            }
        }
    }
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) {
        if let Some(text) = value.get("text").and_then(serde_json::Value::as_str) {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine;
            if let Ok(decoded) = URL_SAFE_NO_PAD.decode(text) {
                if let Ok(slot) = serde_json::from_slice::<Vec<PunchRequest>>(&decoded) {
                    return Ok((slot, SignalingFormat::AsMessage));
                }
            }
        }
    }
    Err(SignalingError::Malformed)
}

pub const PUNCH_REQUEST_KEY_PREFIX: &str = "punch:";
pub const PUNCH_REQUEST_MAX_PER_SLOT: usize = 100;

/// Ключ DHT для слотов PunchRequest адресата.
fn punch_request_key(target_id: &NodeId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PUNCH_REQUEST_KEY_PREFIX.as_bytes());
    hasher.update(target_id.as_bytes());
    hasher.finalize().into()
}

/// Хранилище PunchRequest в DHT.
///
/// Локальный кэш отделён от EndpointCache, так как это другой тип записи.
pub struct PunchRequestStore<'a> {
    local_id: NodeId,
    transport: &'a dyn DhtTransport,
    routing: &'a mut RoutingTable,
    local_cache: HashMap<NodeId, Vec<PunchRequest>>,
}

impl<'a> PunchRequestStore<'a> {
    pub fn new(
        local_id: NodeId,
        transport: &'a dyn DhtTransport,
        routing: &'a mut RoutingTable,
    ) -> Self {
        Self {
            local_id,
            transport,
            routing,
            local_cache: HashMap::new(),
        }
    }

    /// Опубликовать с маскировкой в указанный формат.
    pub async fn publish_masked(
        &mut self,
        request: &PunchRequest,
        format: SignalingFormat,
        now: u64,
    ) -> Result<(), DhtError> {
        self.publish_with_format(request, format, now).await
    }

    /// Опубликовать PunchRequest в слот target_id.
    pub async fn publish(&mut self, request: &PunchRequest, now: u64) -> Result<(), DhtError> {
        self.publish_with_format(request, SignalingFormat::Explicit, now)
            .await
    }

    /// Внутренний: publish с указанным форматом маскировки.
    async fn publish_with_format(
        &mut self,
        request: &PunchRequest,
        format: SignalingFormat,
        now: u64,
    ) -> Result<(), DhtError> {
        if request.expires_at <= now {
            return Err(DhtError::InvalidRequest(
                "punch request already expired".into(),
            ));
        }

        let key = punch_request_key(&request.target_id);
        let closest = self.routing.closest(&NodeId::from_bytes(key), K);
        if closest.is_empty() {
            return Err(DhtError::Internal(
                "no peers for punch request store (routing empty)".into(),
            ));
        }

        let mut slot = self
            .local_cache
            .get(&request.target_id)
            .cloned()
            .unwrap_or_default();
        slot.retain(|existing| existing.expires_at > now);

        for peer in closest.iter().take(3) {
            let lookup_request =
                DhtRequest::new(DhtRequestPayload::FindValue { key }, self.local_id, now);
            if let Ok(response) = self.transport.send_request(peer, lookup_request).await {
                if let DhtResponsePayload::Value {
                    key: response_key,
                    value,
                    expires_at,
                    ..
                } = response.payload
                {
                    if response_key == key && expires_at > now {
                        if let Ok((mut stored, _format)) = unmask_punch_slot(&value) {
                            slot.append(&mut stored);
                        }
                    }
                }
            }
        }

        slot.retain(|existing| existing.expires_at > now);
        if !slot.iter().any(|existing| same_request(existing, request)) {
            slot.push(request.clone());
        }
        deduplicate_requests(&mut slot);
        trim_request_slot(&mut slot);
        let value = mask_punch_slot(&slot, format)
            .map_err(|error| DhtError::Internal(format!("mask failed: {error:?}")))?;
        let expires_at = slot
            .iter()
            .map(|stored| stored.expires_at)
            .max()
            .unwrap_or(request.expires_at);

        let mut stored_count = 0;
        for peer in closest.iter().take(3) {
            let store_request = DhtRequest::new(
                DhtRequestPayload::StoreTyped {
                    key,
                    value: value.clone(),
                    signature: request.signature.to_vec(),
                    expires_at,
                    record_type: Some(StoredRecordType::PunchRequest),
                },
                self.local_id,
                now,
            );
            if let Ok(response) = self.transport.send_request(peer, store_request).await {
                if matches!(response.payload, DhtResponsePayload::Stored { key: stored_key } if stored_key == key)
                {
                    stored_count += 1;
                }
            }
        }

        if stored_count == 0 {
            return Err(DhtError::Internal(
                "punch request was not stored by any DHT peer".into(),
            ));
        }

        self.local_cache.insert(request.target_id, slot);
        Ok(())
    }

    /// Получить все PunchRequest для target_id.
    pub async fn fetch(
        &mut self,
        target_id: &NodeId,
        now: u64,
    ) -> Result<Vec<PunchRequest>, DhtError> {
        let key = punch_request_key(target_id);
        let mut requests = self.local_cache.get(target_id).cloned().unwrap_or_default();
        let closest = self.routing.closest(&NodeId::from_bytes(key), K);

        for peer in closest.iter().take(3) {
            let request = DhtRequest::new(DhtRequestPayload::FindValue { key }, self.local_id, now);
            let Ok(response) = self.transport.send_request(peer, request).await else {
                continue;
            };
            if let DhtResponsePayload::Value {
                key: response_key,
                value,
                expires_at,
                ..
            } = response.payload
            {
                if response_key != key || expires_at <= now {
                    continue;
                }
                if let Ok((mut stored, _format)) = unmask_punch_slot(&value) {
                    requests.append(&mut stored);
                }
            }
        }

        requests.retain(|request| request.target_id == *target_id && request.expires_at > now);
        deduplicate_requests(&mut requests);
        Ok(requests)
    }

    /// Удалить истёкшие запросы из локального кэша.
    pub fn cleanup_expired(&mut self, now: u64) -> usize {
        let mut removed = 0;
        self.local_cache.retain(|_, requests| {
            let old_len = requests.len();
            requests.retain(|request| request.expires_at > now);
            removed += old_len - requests.len();
            !requests.is_empty()
        });
        removed
    }
}

fn same_request(first: &PunchRequest, second: &PunchRequest) -> bool {
    first.requester_id == second.requester_id && first.nonce == second.nonce
}

fn deduplicate_requests(requests: &mut Vec<PunchRequest>) {
    let mut seen = std::collections::HashSet::new();
    requests.retain(|request| seen.insert((request.requester_id, request.nonce)));
}

fn trim_request_slot(requests: &mut Vec<PunchRequest>) {
    if requests.len() > PUNCH_REQUEST_MAX_PER_SLOT {
        let remove_count = requests.len() - PUNCH_REQUEST_MAX_PER_SLOT;
        requests.drain(..remove_count);
    }
}

/// Канал координации punch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordinationChannel {
    /// Через DHT (публикация endpoint).
    Dht,
    /// Через existing TCP-канал.
    ExistingTcp,
    /// Через группу.
    Group(GroupId),
    /// Через referral (общий знакомый).
    Referral(NodeId),
    /// Через relay-узел.
    Relay(SocketAddr),
    /// Через invite.
    Invite,
}

/// Формат запроса.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalingFormat {
    /// Явный PunchRequest.
    Explicit,
    /// Как sync envelope.
    AsSync,
    /// Как сообщение.
    AsMessage,
    /// Как heartbeat.
    AsHeartbeat,
    /// Как endpoint record.
    AsEndpoint,
}

/// Стратегия выбора канала и формата.
///
/// Веса — относительные. Чем больше вес, тем чаще выбирается.
/// Выбор детерминирован seed; randomize управляет выбором по весам.
#[derive(Debug, Clone)]
pub struct SignalingStrategy {
    pub channels: Vec<(CoordinationChannel, u8)>,
    pub formats: Vec<(SignalingFormat, u8)>,
    pub randomize: bool,
    pub rotate_on_retry: bool,
}

impl SignalingStrategy {
    /// Гибридный дефолт: DHT + TCP + Group.
    pub fn default_hybrid() -> Self {
        Self {
            channels: vec![
                (CoordinationChannel::Dht, 3),
                (CoordinationChannel::ExistingTcp, 2),
                (CoordinationChannel::Group(0), 1),
            ],
            formats: vec![
                (SignalingFormat::Explicit, 2),
                (SignalingFormat::AsSync, 2),
                (SignalingFormat::AsMessage, 1),
            ],
            randomize: true,
            rotate_on_retry: true,
        }
    }

    /// Только DHT.
    pub fn only_dht() -> Self {
        Self {
            channels: vec![(CoordinationChannel::Dht, 1)],
            formats: vec![
                (SignalingFormat::Explicit, 2),
                (SignalingFormat::AsEndpoint, 1),
            ],
            randomize: false,
            rotate_on_retry: false,
        }
    }

    /// Только явный формат.
    pub fn explicit_only() -> Self {
        Self {
            channels: vec![
                (CoordinationChannel::Dht, 1),
                (CoordinationChannel::ExistingTcp, 1),
            ],
            formats: vec![(SignalingFormat::Explicit, 1)],
            randomize: false,
            rotate_on_retry: false,
        }
    }

    /// Проверить, что есть хотя бы один канал и формат, веса > 0.
    pub fn validate(&self) -> Result<(), SignalingStrategyError> {
        if self.channels.is_empty() {
            return Err(SignalingStrategyError::NoChannels);
        }
        if self.formats.is_empty() {
            return Err(SignalingStrategyError::NoFormats);
        }
        if self.channels.iter().any(|(_, weight)| *weight == 0)
            || self.formats.iter().any(|(_, weight)| *weight == 0)
        {
            return Err(SignalingStrategyError::InvalidWeight);
        }
        Ok(())
    }

    /// Выбрать канал детерминированно по seed и настроенным весам.
    pub fn pick_channel(&self, seed: u64) -> Option<CoordinationChannel> {
        if self.channels.is_empty() {
            return None;
        }
        if !self.randomize {
            return self
                .channels
                .iter()
                .max_by_key(|(_, weight)| *weight)
                .map(|(channel, _)| channel.clone());
        }

        let total: u64 = self
            .channels
            .iter()
            .map(|(_, weight)| u64::from(*weight))
            .sum();
        if total == 0 {
            return None;
        }
        let target = seed % total;
        let mut accumulated = 0u64;
        for (channel, weight) in &self.channels {
            accumulated += u64::from(*weight);
            if target < accumulated {
                return Some(channel.clone());
            }
        }
        self.channels.last().map(|(channel, _)| channel.clone())
    }

    /// Выбрать формат детерминированно по seed и настроенным весам.
    pub fn pick_format(&self, seed: u64) -> Option<SignalingFormat> {
        if self.formats.is_empty() {
            return None;
        }
        if !self.randomize {
            return self
                .formats
                .iter()
                .max_by_key(|(_, weight)| *weight)
                .map(|(format, _)| *format);
        }

        let total: u64 = self
            .formats
            .iter()
            .map(|(_, weight)| u64::from(*weight))
            .sum();
        if total == 0 {
            return None;
        }
        let target = seed % total;
        let mut accumulated = 0u64;
        for (format, weight) in &self.formats {
            accumulated += u64::from(*weight);
            if target < accumulated {
                return Some(*format);
            }
        }
        self.formats.last().map(|(format, _)| *format)
    }
}

/// Ошибки стратегии.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignalingStrategyError {
    NoChannels,
    NoFormats,
    InvalidWeight,
}

impl fmt::Display for SignalingStrategyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoChannels => write!(formatter, "no coordination channels configured"),
            Self::NoFormats => write!(formatter, "no signaling formats configured"),
            Self::InvalidWeight => write!(formatter, "channel or format weight is zero"),
        }
    }
}

impl std::error::Error for SignalingStrategyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::peer_info::PeerInfo;
    use crate::dht::wire::{DhtRequest, DhtResponse};
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    fn node(seed: u8) -> NodeId {
        NodeId::from_bytes([seed; 32])
    }

    fn request(key: &SigningKey, now: u64) -> PunchRequest {
        PunchRequest::create(
            NodeId::from_public_key(&key.verifying_key()),
            node(2),
            "127.0.0.1:9000".parse().expect("socket address"),
            PUNCH_REQUEST_DEFAULT_TTL,
            now,
            key,
            [7; 16],
        )
        .expect("create punch request")
    }

    fn publish_masked_value(
        format: SignalingFormat,
        request_seed: u8,
        local_seed: u8,
    ) -> (PunchRequest, Vec<u8>) {
        let key = SigningKey::from_bytes(&[request_seed; 32]);
        let original = request(&key, 100);
        let local_id = node(local_seed);
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let transport = EmptyDhtTransport {
            requests: Some(Arc::clone(&recorded)),
        };
        let mut routing = RoutingTable::new(local_id);
        routing.insert(
            PeerInfo::new(node(local_seed.wrapping_add(1)), "peer".into()),
            100,
        );
        let mut store = PunchRequestStore::new(local_id, &transport, &mut routing);
        let executor = tokio::runtime::Runtime::new().expect("create runtime");
        executor
            .block_on(store.publish_masked(&original, format, 101))
            .expect("publish masked request");

        let value = recorded
            .lock()
            .expect("recorded requests")
            .iter()
            .find_map(|sent_request| match &sent_request.payload {
                DhtRequestPayload::StoreTyped { value, .. } => Some(value.clone()),
                _ => None,
            })
            .expect("stored slot value");
        (original, value)
    }

    #[derive(Default)]
    struct EmptyDhtTransport {
        requests: Option<Arc<Mutex<Vec<DhtRequest>>>>,
    }

    #[async_trait]
    impl DhtTransport for EmptyDhtTransport {
        async fn send_request(
            &self,
            peer: &PeerInfo,
            request: DhtRequest,
        ) -> Result<DhtResponse, DhtError> {
            if let Some(requests) = &self.requests {
                if let Ok(mut requests) = requests.lock() {
                    requests.push(request.clone());
                }
            }
            let payload = match request.payload {
                DhtRequestPayload::FindValue { key } => DhtResponsePayload::NotFound { key },
                DhtRequestPayload::Store { key, .. }
                | DhtRequestPayload::StoreTyped { key, .. } => DhtResponsePayload::Stored { key },
                _ => return Err(DhtError::Internal("unexpected test request".into())),
            };
            Ok(DhtResponse {
                version: request.version,
                request_id: request.request_id,
                responder_node_id: peer.node_id,
                timestamp: request.timestamp,
                payload,
            })
        }
    }

    #[test]
    fn create_and_verify() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let target = node(2);
        let request = PunchRequest::create(
            NodeId::from_public_key(&key.verifying_key()),
            target,
            "127.0.0.1:9000".parse().expect("socket address"),
            PUNCH_REQUEST_DEFAULT_TTL,
            1_000,
            &key,
            [1; 16],
        )
        .expect("create request");
        assert_eq!(request.verify(&key.verifying_key(), target, 1_100), Ok(()));
        assert_eq!(request.endpoint().expect("request endpoint").port(), 9000);
    }

    #[test]
    fn expired_rejected() {
        let key = SigningKey::from_bytes(&[2; 32]);
        let request = request(&key, 100);
        assert_eq!(
            request.verify(&key.verifying_key(), node(2), request.expires_at + 1),
            Err(SignalingError::Expired)
        );
    }

    #[test]
    fn from_future_rejected() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let request = request(&key, 101);
        assert_eq!(
            request.verify(&key.verifying_key(), node(2), 100),
            Err(SignalingError::FromFuture)
        );
    }

    #[test]
    fn invalid_signature_rejected() {
        let key = SigningKey::from_bytes(&[4; 32]);
        let mut request = request(&key, 100);
        request.signature[0] ^= 1;
        assert_eq!(
            request.verify(&key.verifying_key(), node(2), 101),
            Err(SignalingError::InvalidSignature)
        );
    }

    #[test]
    fn self_punch_rejected() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let id = NodeId::from_public_key(&key.verifying_key());
        assert_eq!(
            PunchRequest::create(
                id,
                id,
                "127.0.0.1:9000".parse().expect("socket address"),
                PUNCH_REQUEST_DEFAULT_TTL,
                100,
                &key,
                [5; 16],
            ),
            Err(SignalingError::SelfPunch)
        );
    }

    #[test]
    fn target_mismatch_rejected() {
        let key = SigningKey::from_bytes(&[6; 32]);
        let request = request(&key, 100);
        assert_eq!(
            request.verify(&key.verifying_key(), node(3), 101),
            Err(SignalingError::TargetMismatch)
        );
    }

    #[test]
    fn base64_roundtrip() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let request = request(&key, 100);
        let encoded = request.to_base64().expect("encode request");
        let decoded = PunchRequest::from_base64(&encoded).expect("decode request");
        assert_eq!(decoded, request);
    }

    #[test]
    fn mask_explicit_roundtrip() {
        let key = SigningKey::from_bytes(&[17; 32]);
        let original = request(&key, 100);
        let bytes = mask_punch_request(&original, SignalingFormat::Explicit).expect("mask");
        let (restored, format) = unmask_punch_request(&bytes).expect("unmask");
        assert_eq!(restored, original);
        assert_eq!(format, SignalingFormat::Explicit);
    }

    #[test]
    fn mask_as_sync_roundtrip() {
        let key = SigningKey::from_bytes(&[18; 32]);
        let original = request(&key, 100);
        let bytes = mask_punch_request(&original, SignalingFormat::AsSync).expect("mask");
        let (restored, format) = unmask_punch_request(&bytes).expect("unmask");
        assert_eq!(restored, original);
        assert_eq!(format, SignalingFormat::AsSync);
    }

    #[test]
    fn mask_as_message_roundtrip() {
        let key = SigningKey::from_bytes(&[19; 32]);
        let original = request(&key, 100);
        let bytes = mask_punch_request(&original, SignalingFormat::AsMessage).expect("mask");
        let (restored, format) = unmask_punch_request(&bytes).expect("unmask");
        assert_eq!(restored, original);
        assert_eq!(format, SignalingFormat::AsMessage);
    }

    #[test]
    fn unmask_invalid_bytes_fails() {
        assert_eq!(
            unmask_punch_request(b"not json"),
            Err(SignalingError::Malformed)
        );
    }

    #[test]
    fn unmask_empty_bytes_fails() {
        assert_eq!(unmask_punch_request(b""), Err(SignalingError::Malformed));
    }

    #[test]
    fn mask_as_heartbeat_not_supported() {
        let key = SigningKey::from_bytes(&[20; 32]);
        let original = request(&key, 100);
        assert_eq!(
            mask_punch_request(&original, SignalingFormat::AsHeartbeat),
            Err(SignalingError::Malformed)
        );
    }

    #[test]
    fn mask_slot_explicit_roundtrip() {
        let first_key = SigningKey::from_bytes(&[21; 32]);
        let second_key = SigningKey::from_bytes(&[22; 32]);
        let original = vec![request(&first_key, 100), request(&second_key, 101)];
        let bytes = mask_punch_slot(&original, SignalingFormat::Explicit).expect("mask slot");
        let (restored, format) = unmask_punch_slot(&bytes).expect("unmask slot");
        assert_eq!(restored, original);
        assert_eq!(format, SignalingFormat::Explicit);
    }

    #[test]
    fn mask_slot_as_sync_roundtrip() {
        let first_key = SigningKey::from_bytes(&[23; 32]);
        let second_key = SigningKey::from_bytes(&[24; 32]);
        let original = vec![request(&first_key, 100), request(&second_key, 101)];
        let bytes = mask_punch_slot(&original, SignalingFormat::AsSync).expect("mask slot");
        let (restored, format) = unmask_punch_slot(&bytes).expect("unmask slot");
        assert_eq!(restored, original);
        assert_eq!(format, SignalingFormat::AsSync);
    }

    #[test]
    fn mask_slot_as_message_roundtrip() {
        let first_key = SigningKey::from_bytes(&[25; 32]);
        let second_key = SigningKey::from_bytes(&[26; 32]);
        let original = vec![request(&first_key, 100), request(&second_key, 101)];
        let bytes = mask_punch_slot(&original, SignalingFormat::AsMessage).expect("mask slot");
        let (restored, format) = unmask_punch_slot(&bytes).expect("unmask slot");
        assert_eq!(restored, original);
        assert_eq!(format, SignalingFormat::AsMessage);
    }

    #[test]
    fn unmask_slot_single_punch_request_works() {
        let key = SigningKey::from_bytes(&[27; 32]);
        let original = request(&key, 100);
        let bytes = serde_json::to_vec(&original).expect("serialize request");
        let (restored, format) = unmask_punch_slot(&bytes).expect("unmask request");
        assert_eq!(restored, vec![original]);
        assert_eq!(format, SignalingFormat::Explicit);
    }

    #[test]
    fn unmask_slot_empty_bytes_fails() {
        assert_eq!(unmask_punch_slot(b""), Err(SignalingError::Malformed));
    }

    #[test]
    fn mask_slot_as_heartbeat_not_supported() {
        let key = SigningKey::from_bytes(&[28; 32]);
        let slot = vec![request(&key, 100)];
        assert_eq!(
            mask_punch_slot(&slot, SignalingFormat::AsHeartbeat),
            Err(SignalingError::Malformed)
        );
    }

    #[test]
    fn publish_masked_explicit_equivalent_to_publish() {
        let (original, value) = publish_masked_value(SignalingFormat::Explicit, 29, 40);
        let (restored, format) = unmask_punch_slot(&value).expect("unmask stored slot");
        assert_eq!(restored, vec![original]);
        assert_eq!(format, SignalingFormat::Explicit);
    }

    #[test]
    fn publish_masked_as_sync_roundtrip() {
        let (original, value) = publish_masked_value(SignalingFormat::AsSync, 30, 42);
        assert!(serde_json::from_slice::<crate::transport::SyncEnvelope>(&value).is_ok());
        let (restored, format) = unmask_punch_slot(&value).expect("unmask stored slot");
        assert_eq!(restored, vec![original]);
        assert_eq!(format, SignalingFormat::AsSync);
    }

    #[test]
    fn publish_masked_as_message_roundtrip() {
        let (original, value) = publish_masked_value(SignalingFormat::AsMessage, 31, 44);
        let payload: serde_json::Value = serde_json::from_slice(&value).expect("message JSON");
        assert!(payload
            .get("text")
            .and_then(serde_json::Value::as_str)
            .is_some());
        let (restored, format) = unmask_punch_slot(&value).expect("unmask stored slot");
        assert_eq!(restored, vec![original]);
        assert_eq!(format, SignalingFormat::AsMessage);
    }

    #[test]
    fn strategy_default_hybrid_valid() {
        assert_eq!(SignalingStrategy::default_hybrid().validate(), Ok(()));
    }

    #[test]
    fn strategy_only_dht_valid() {
        assert_eq!(SignalingStrategy::only_dht().validate(), Ok(()));
    }

    #[test]
    fn strategy_empty_channels_invalid() {
        let mut strategy = SignalingStrategy::default_hybrid();
        strategy.channels.clear();
        assert_eq!(strategy.validate(), Err(SignalingStrategyError::NoChannels));
    }

    #[test]
    fn strategy_pick_channel_deterministic() {
        let strategy = SignalingStrategy::default_hybrid();
        assert_eq!(strategy.pick_channel(0), strategy.pick_channel(0));
        assert_ne!(strategy.pick_channel(0), strategy.pick_channel(999));
    }

    #[test]
    fn strategy_pick_format_deterministic() {
        let strategy = SignalingStrategy::default_hybrid();
        assert_eq!(strategy.pick_format(0), strategy.pick_format(0));
        assert_ne!(strategy.pick_format(0), strategy.pick_format(999));
    }

    #[test]
    fn strategy_no_randomize_picks_max_weight() {
        let strategy = SignalingStrategy {
            channels: vec![
                (CoordinationChannel::Dht, 1),
                (CoordinationChannel::ExistingTcp, 5),
            ],
            formats: vec![(SignalingFormat::Explicit, 1)],
            randomize: false,
            rotate_on_retry: false,
        };
        assert_eq!(
            strategy.pick_channel(0),
            Some(CoordinationChannel::ExistingTcp)
        );
    }

    #[test]
    fn punch_request_key_deterministic() {
        assert_eq!(punch_request_key(&node(1)), punch_request_key(&node(1)));
        assert_ne!(punch_request_key(&node(1)), punch_request_key(&node(2)));
    }

    #[test]
    fn punch_request_key_different_from_endpoint_key() {
        assert_ne!(
            punch_request_key(&node(1)),
            crate::dht::endpoint::endpoint_key("identity1")
        );
    }

    #[test]
    fn store_new_constructible() {
        let local_id = node(8);
        let transport = EmptyDhtTransport::default();
        let mut routing = RoutingTable::new(local_id);
        let mut store = PunchRequestStore::new(local_id, &transport, &mut routing);
        assert_eq!(store.cleanup_expired(1_000), 0);
    }

    #[test]
    fn cleanup_expired_returns_zero_on_empty() {
        let local_id = node(9);
        let transport = EmptyDhtTransport::default();
        let mut routing = RoutingTable::new(local_id);
        let mut store = PunchRequestStore::new(local_id, &transport, &mut routing);
        assert_eq!(store.cleanup_expired(1_000), 0);
    }

    #[test]
    fn publish_uses_store_typed() {
        let local_id = node(18);
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let transport = EmptyDhtTransport {
            requests: Some(Arc::clone(&recorded)),
        };
        let mut routing = RoutingTable::new(local_id);
        routing.insert(PeerInfo::new(node(19), "test-peer".into()), 100);
        let request = request(&SigningKey::from_bytes(&[20; 32]), 100);
        let mut store = PunchRequestStore::new(local_id, &transport, &mut routing);
        let executor = tokio::runtime::Runtime::new().expect("create runtime");
        executor
            .block_on(store.publish(&request, 101))
            .expect("publish request");

        let sent = recorded.lock().expect("recorded requests");
        assert!(sent.iter().any(|sent_request| matches!(
            &sent_request.payload,
            DhtRequestPayload::StoreTyped {
                record_type: Some(StoredRecordType::PunchRequest),
                ..
            }
        )));
    }

    #[test]
    fn publish_legacy_store_not_used() {
        let local_id = node(21);
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let transport = EmptyDhtTransport {
            requests: Some(Arc::clone(&recorded)),
        };
        let mut routing = RoutingTable::new(local_id);
        routing.insert(PeerInfo::new(node(22), "test-peer".into()), 100);
        let request = request(&SigningKey::from_bytes(&[23; 32]), 100);
        let mut store = PunchRequestStore::new(local_id, &transport, &mut routing);
        let executor = tokio::runtime::Runtime::new().expect("create runtime");
        executor
            .block_on(store.publish(&request, 101))
            .expect("publish request");

        let sent = recorded.lock().expect("recorded requests");
        assert!(sent
            .iter()
            .all(|sent_request| !matches!(sent_request.payload, DhtRequestPayload::Store { .. })));
    }

    #[test]
    fn request_lifecycle() {
        let key = SigningKey::from_bytes(&[10; 32]);
        let request = request(&key, 100);
        assert_eq!(
            request.expires_at,
            100 + PUNCH_REQUEST_DEFAULT_TTL.as_secs()
        );
        assert_eq!(
            request.verify(&key.verifying_key(), node(2), request.expires_at + 1),
            Err(SignalingError::Expired)
        );
    }

    #[test]
    fn publish_expired_request_rejected() {
        let key = SigningKey::from_bytes(&[11; 32]);
        let expired = request(&key, 100);
        let local_id = node(12);
        let transport = EmptyDhtTransport::default();
        let mut routing = RoutingTable::new(local_id);
        let mut store = PunchRequestStore::new(local_id, &transport, &mut routing);
        let executor = tokio::runtime::Runtime::new().expect("create runtime");
        assert!(matches!(
            executor.block_on(store.publish(&expired, expired.expires_at)),
            Err(DhtError::InvalidRequest(_))
        ));
    }

    #[test]
    fn publish_caches_locally() {
        let key = SigningKey::from_bytes(&[13; 32]);
        let request = request(&key, 100);
        let local_id = node(14);
        let transport = EmptyDhtTransport::default();
        let mut routing = RoutingTable::new(local_id);
        routing.insert(PeerInfo::new(node(15), "test-peer".into()), 100);
        let mut store = PunchRequestStore::new(local_id, &transport, &mut routing);
        let executor = tokio::runtime::Runtime::new().expect("create runtime");
        executor
            .block_on(store.publish(&request, 101))
            .expect("publish request");
        assert_eq!(
            store.local_cache.get(&request.target_id),
            Some(&vec![request])
        );
    }

    #[test]
    fn fetch_filters_expired() {
        let key = SigningKey::from_bytes(&[16; 32]);
        let expired = request(&key, 100);
        let target_id = expired.target_id;
        let local_id = node(17);
        let transport = EmptyDhtTransport::default();
        let mut routing = RoutingTable::new(local_id);
        let mut store = PunchRequestStore::new(local_id, &transport, &mut routing);
        store.local_cache.insert(target_id, vec![expired.clone()]);
        let executor = tokio::runtime::Runtime::new().expect("create runtime");
        assert!(executor
            .block_on(store.fetch(&target_id, expired.expires_at))
            .expect("fetch slot")
            .is_empty());
    }

    #[test]
    fn punch_request_max_per_slot_enforced() {
        assert_eq!(PUNCH_REQUEST_MAX_PER_SLOT, 100);
        let mut slot = (0..=PUNCH_REQUEST_MAX_PER_SLOT)
            .map(|seed| {
                let key = SigningKey::from_bytes(&[(seed % 255) as u8; 32]);
                request(&key, 100)
            })
            .collect::<Vec<_>>();
        trim_request_slot(&mut slot);
        assert_eq!(slot.len(), PUNCH_REQUEST_MAX_PER_SLOT);
    }
}
