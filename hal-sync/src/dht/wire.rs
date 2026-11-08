use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::dht::badge::Badge;
use crate::dht::endpoint::{endpoint_key, EndpointRecord};
use crate::signaling::{PunchRequest, PUNCH_REQUEST_KEY_PREFIX};

use super::node_id::NodeId;
use super::peer_info::PeerInfo;

pub const DHT_PROTOCOL_VERSION: u8 = 1;
pub const MAX_DHT_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_DHT_PEERS_PER_RESPONSE: usize = 20;
pub const DHT_FRAME_PREFIX_BYTES: usize = 4;
const DHT_TIMESTAMP_WINDOW_SECS: u64 = 5 * 60;

pub const ERR_INVALID_REQUEST: u16 = 1;
pub const ERR_VERSION_MISMATCH: u16 = 2;
pub const ERR_TIMESTAMP_OUT_OF_RANGE: u16 = 3;
pub const ERR_STORAGE_FULL: u16 = 4;
pub const ERR_INVALID_SIGNATURE: u16 = 5;
pub const ERR_INTERNAL: u16 = 99;

/// Тип записи в Store запросе.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StoredRecordType {
    Endpoint,
    PunchRequest,
    Badge,
    PrekeyBundle,
    InviteRevocation,
    JournalCommit,
    JournalCommitPointer,
    JuryDkgCommitment,
    JuryPartial,
    JuryVote,
    JuryVerdict,
    JuryAcceptance,
    ComplaintRecord,
    /// Unknown typed records can be rejected gracefully without failing DHT
    /// request deserialization.
    #[serde(other)]
    Unknown,
}

/// Тип записи, хранимой в DHT.
///
/// Endpoint records and punch request slots use distinct key namespaces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StoredRecord {
    Endpoint(EndpointRecord),
    PunchRequest(Vec<PunchRequest>),
    Badge(Vec<Badge>),
}

impl StoredRecord {
    /// Сериализовать в JSON для value.
    pub fn to_value(&self) -> Result<Vec<u8>, DhtError> {
        serde_json::to_vec(self).map_err(|error| DhtError::Internal(error.to_string()))
    }

    /// Десериализовать из value.
    pub fn from_value(bytes: &[u8]) -> Result<Self, DhtError> {
        serde_json::from_slice(bytes).map_err(|error| DhtError::InvalidRequest(error.to_string()))
    }

    /// Проверить, что тип записи соответствует ключу и сроку хранения.
    pub fn validate_for_key(&self, key: &[u8; 32], now: u64) -> Result<(), DhtError> {
        match self {
            Self::Endpoint(record) => {
                if endpoint_key(&record.identity_id) != *key {
                    return Err(DhtError::InvalidRequest("endpoint key mismatch".into()));
                }
                record.verify(now).map_err(|_| DhtError::InvalidSignature)
            }
            Self::PunchRequest(requests) => {
                if requests.is_empty() {
                    return Err(DhtError::InvalidRequest("empty punch request slot".into()));
                }
                let target_id = requests[0].target_id;
                let mut hasher = Sha256::new();
                hasher.update(PUNCH_REQUEST_KEY_PREFIX.as_bytes());
                hasher.update(target_id.as_bytes());
                let expected_key: [u8; 32] = hasher.finalize().into();
                if expected_key != *key
                    || requests
                        .iter()
                        .any(|request| request.target_id != target_id || request.expires_at <= now)
                {
                    return Err(DhtError::InvalidRequest(
                        "punch request slot key mismatch or expired request".into(),
                    ));
                }
                Ok(())
            }
            Self::Badge(badges) => {
                let subject_id = NodeId::from_bytes(*key);
                if badges.is_empty()
                    || badges.iter().any(|badge| {
                        badge.subject_id != subject_id
                            || badge.expires_at.is_some_and(|expires_at| expires_at <= now)
                            || badge.message_ids.is_empty()
                            || badge.message_ids.len() > super::badge::BADGE_MAX_MESSAGE_IDS
                            || badge.message_ids.iter().any(|message_id| {
                                message_id.len() > super::badge::BADGE_MAX_MESSAGE_ID_LEN
                            })
                    })
                {
                    return Err(DhtError::InvalidRequest(
                        "badge slot key mismatch, empty, malformed, or expired".into(),
                    ));
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DhtError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("version mismatch")]
    VersionMismatch,
    #[error("timestamp out of range")]
    TimestampOutOfRange,
    #[error("storage full")]
    StorageFull,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("internal error: {0}")]
    Internal(String),
}

impl DhtError {
    pub fn code(&self) -> u16 {
        match self {
            Self::InvalidRequest(_) => ERR_INVALID_REQUEST,
            Self::VersionMismatch => ERR_VERSION_MISMATCH,
            Self::TimestampOutOfRange => ERR_TIMESTAMP_OUT_OF_RANGE,
            Self::StorageFull => ERR_STORAGE_FULL,
            Self::InvalidSignature => ERR_INVALID_SIGNATURE,
            Self::Internal(_) => ERR_INTERNAL,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DhtRequest {
    pub version: u8,
    pub request_id: [u8; 16],
    pub sender_node_id: NodeId,
    pub timestamp: u64,
    pub payload: DhtRequestPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum DhtRequestPayload {
    Ping,
    FindNode {
        target: NodeId,
    },
    FindValue {
        key: [u8; 32],
    },
    Store {
        key: [u8; 32],
        value: Vec<u8>,
        signature: Vec<u8>,
        expires_at: u64,
    },
    /// Typed Store extension; legacy `Store` remains endpoint-compatible.
    StoreTyped {
        key: [u8; 32],
        value: Vec<u8>,
        signature: Vec<u8>,
        expires_at: u64,
        #[serde(default)]
        record_type: Option<StoredRecordType>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DhtResponse {
    pub version: u8,
    pub request_id: [u8; 16],
    pub responder_node_id: NodeId,
    pub timestamp: u64,
    pub payload: DhtResponsePayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum DhtResponsePayload {
    Pong,
    Nodes {
        peers: Vec<PeerInfo>,
        truncated: bool,
    },
    Value {
        key: [u8; 32],
        value: Vec<u8>,
        signature: Vec<u8>,
        expires_at: u64,
    },
    Stored {
        key: [u8; 32],
    },
    NotFound {
        key: [u8; 32],
    },
    Error {
        code: u16,
        message: String,
    },
}

pub fn generate_request_id() -> [u8; 16] {
    let mut request_id = [0u8; 16];
    OsRng.fill_bytes(&mut request_id);
    request_id
}

fn timestamp_valid(timestamp: u64, now: u64) -> bool {
    timestamp.abs_diff(now) <= DHT_TIMESTAMP_WINDOW_SECS
}

impl DhtRequest {
    pub fn new(payload: DhtRequestPayload, sender: NodeId, now: u64) -> Self {
        Self {
            version: DHT_PROTOCOL_VERSION,
            request_id: generate_request_id(),
            sender_node_id: sender,
            timestamp: now,
            payload,
        }
    }

    pub fn validate(&self, now: u64) -> Result<(), DhtError> {
        if self.version != DHT_PROTOCOL_VERSION {
            return Err(DhtError::VersionMismatch);
        }
        if !timestamp_valid(self.timestamp, now) {
            return Err(DhtError::TimestampOutOfRange);
        }
        let encoded =
            serde_json::to_vec(self).map_err(|error| DhtError::Internal(error.to_string()))?;
        if encoded.len() > MAX_DHT_REQUEST_BYTES {
            return Err(DhtError::InvalidRequest(
                "request exceeds size limit".into(),
            ));
        }
        let store_value = match &self.payload {
            DhtRequestPayload::Store {
                value, expires_at, ..
            }
            | DhtRequestPayload::StoreTyped {
                value, expires_at, ..
            } => Some((value, expires_at)),
            _ => None,
        };
        if let Some((value, expires_at)) = store_value {
            if *expires_at <= now {
                return Err(DhtError::InvalidRequest("store value is expired".into()));
            }
            if value.len() > MAX_DHT_REQUEST_BYTES {
                return Err(DhtError::InvalidRequest(
                    "store value exceeds size limit".into(),
                ));
            }
        }
        Ok(())
    }
}

impl DhtResponse {
    pub fn validate(&self, request_id: &[u8; 16], now: u64) -> Result<(), DhtError> {
        if self.version != DHT_PROTOCOL_VERSION {
            return Err(DhtError::VersionMismatch);
        }
        if &self.request_id != request_id {
            return Err(DhtError::InvalidRequest("request id mismatch".into()));
        }
        if !timestamp_valid(self.timestamp, now) {
            return Err(DhtError::TimestampOutOfRange);
        }
        if let DhtResponsePayload::Nodes { peers, .. } = &self.payload {
            if peers.len() > MAX_DHT_PEERS_PER_RESPONSE {
                return Err(DhtError::InvalidRequest(
                    "too many peers in response".into(),
                ));
            }
        }
        Ok(())
    }
}

pub fn encode_request(request: &DhtRequest) -> Result<Vec<u8>, DhtError> {
    let encoded =
        serde_json::to_vec(request).map_err(|error| DhtError::Internal(error.to_string()))?;
    if encoded.is_empty() || encoded.len() > MAX_DHT_REQUEST_BYTES {
        return Err(DhtError::InvalidRequest(
            "request exceeds size limit".into(),
        ));
    }
    Ok(encoded)
}

pub fn decode_request(bytes: &[u8]) -> Result<DhtRequest, DhtError> {
    check_input_size(bytes)?;
    serde_json::from_slice(bytes).map_err(|error| DhtError::InvalidRequest(error.to_string()))
}

pub fn encode_response(response: &DhtResponse) -> Result<Vec<u8>, DhtError> {
    let encoded =
        serde_json::to_vec(response).map_err(|error| DhtError::Internal(error.to_string()))?;
    if encoded.is_empty() || encoded.len() > MAX_DHT_REQUEST_BYTES {
        return Err(DhtError::InvalidRequest(
            "response exceeds size limit".into(),
        ));
    }
    Ok(encoded)
}

pub fn decode_response(bytes: &[u8]) -> Result<DhtResponse, DhtError> {
    check_input_size(bytes)?;
    serde_json::from_slice(bytes).map_err(|error| DhtError::InvalidRequest(error.to_string()))
}

pub fn frame_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(DHT_FRAME_PREFIX_BYTES + bytes.len());
    framed.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    framed.extend_from_slice(bytes);
    framed
}

pub fn unframe_bytes(bytes: &[u8]) -> Result<(&[u8], &[u8]), DhtError> {
    if bytes.len() < DHT_FRAME_PREFIX_BYTES {
        return Err(DhtError::InvalidRequest("frame too short".into()));
    }
    let len = u32::from_be_bytes(bytes[..DHT_FRAME_PREFIX_BYTES].try_into().unwrap()) as usize;
    if bytes.len() < DHT_FRAME_PREFIX_BYTES + len {
        return Err(DhtError::InvalidRequest("frame truncated".into()));
    }
    let payload = &bytes[DHT_FRAME_PREFIX_BYTES..DHT_FRAME_PREFIX_BYTES + len];
    let rest = &bytes[DHT_FRAME_PREFIX_BYTES + len..];
    Ok((payload, rest))
}

pub fn encode_request_framed(request: &DhtRequest) -> Result<Vec<u8>, DhtError> {
    let bytes = encode_request(request)?;
    Ok(frame_bytes(&bytes))
}

pub fn decode_request_framed(bytes: &[u8]) -> Result<DhtRequest, DhtError> {
    let (payload, _) = unframe_bytes(bytes)?;
    decode_request(payload)
}

pub fn encode_response_framed(response: &DhtResponse) -> Result<Vec<u8>, DhtError> {
    let bytes = encode_response(response)?;
    Ok(frame_bytes(&bytes))
}

pub fn decode_response_framed(bytes: &[u8]) -> Result<DhtResponse, DhtError> {
    let (payload, _) = unframe_bytes(bytes)?;
    decode_response(payload)
}

fn check_input_size(bytes: &[u8]) -> Result<(), DhtError> {
    if bytes.is_empty() {
        return Err(DhtError::InvalidRequest("empty payload".into()));
    }
    if bytes.len() > MAX_DHT_REQUEST_BYTES {
        return Err(DhtError::InvalidRequest(
            "payload exceeds size limit".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000_000;

    fn sender() -> NodeId {
        NodeId::from_bytes([7u8; 32])
    }

    fn request(payload: DhtRequestPayload) -> DhtRequest {
        DhtRequest::new(payload, sender(), NOW)
    }

    fn response(request: &DhtRequest, payload: DhtResponsePayload) -> DhtResponse {
        DhtResponse {
            version: DHT_PROTOCOL_VERSION,
            request_id: request.request_id,
            responder_node_id: NodeId::from_bytes([8u8; 32]),
            timestamp: NOW,
            payload,
        }
    }

    #[test]
    fn ping_request_roundtrip() {
        let value = request(DhtRequestPayload::Ping);
        assert_eq!(
            decode_request(&encode_request(&value).expect("encode")).expect("decode"),
            value
        );
    }

    #[test]
    fn find_node_request_roundtrip() {
        let value = request(DhtRequestPayload::FindNode {
            target: NodeId::from_bytes([1u8; 32]),
        });
        assert_eq!(
            decode_request(&encode_request(&value).expect("encode")).expect("decode"),
            value
        );
    }

    #[test]
    fn find_value_request_roundtrip() {
        let value = request(DhtRequestPayload::FindValue { key: [2u8; 32] });
        assert_eq!(
            decode_request(&encode_request(&value).expect("encode")).expect("decode"),
            value
        );
    }

    #[test]
    fn store_request_roundtrip() {
        let value = request(DhtRequestPayload::Store {
            key: [3u8; 32],
            value: vec![1, 2, 3],
            signature: vec![4; 64],
            expires_at: NOW + 100,
        });
        assert_eq!(
            decode_request(&encode_request(&value).expect("encode")).expect("decode"),
            value
        );
    }

    #[test]
    fn stored_record_type_prekey_bundle_roundtrip() {
        let encoded = serde_json::to_string(&StoredRecordType::PrekeyBundle).expect("serialize");
        assert_eq!(encoded, "\"PrekeyBundle\"");
        assert_eq!(
            serde_json::from_str::<StoredRecordType>(&encoded).expect("deserialize"),
            StoredRecordType::PrekeyBundle
        );
    }

    #[test]
    fn stored_record_type_journal_commit_roundtrip() {
        let encoded = serde_json::to_string(&StoredRecordType::JournalCommit).expect("serialize");
        assert_eq!(encoded, "\"JournalCommit\"");
        assert_eq!(
            serde_json::from_str::<StoredRecordType>(&encoded).expect("deserialize"),
            StoredRecordType::JournalCommit
        );
    }

    #[test]
    fn stored_record_type_journal_commit_pointer_roundtrip() {
        let encoded =
            serde_json::to_string(&StoredRecordType::JournalCommitPointer).expect("serialize");
        assert_eq!(encoded, "\"JournalCommitPointer\"");
        assert_eq!(
            serde_json::from_str::<StoredRecordType>(&encoded).expect("deserialize"),
            StoredRecordType::JournalCommitPointer
        );
    }

    #[test]
    fn stored_record_type_jury_dkg_commitment_roundtrip() {
        let encoded =
            serde_json::to_string(&StoredRecordType::JuryDkgCommitment).expect("serialize");
        assert_eq!(encoded, "\"JuryDkgCommitment\"");
        assert_eq!(
            serde_json::from_str::<StoredRecordType>(&encoded).expect("deserialize"),
            StoredRecordType::JuryDkgCommitment
        );
    }

    #[test]
    fn stored_record_type_jury_partial_roundtrip() {
        let encoded = serde_json::to_string(&StoredRecordType::JuryPartial).expect("serialize");
        assert_eq!(encoded, "\"JuryPartial\"");
        assert_eq!(
            serde_json::from_str::<StoredRecordType>(&encoded).expect("deserialize"),
            StoredRecordType::JuryPartial
        );
    }

    #[test]
    fn unknown_stored_record_type_is_tolerated() {
        assert_eq!(
            serde_json::from_str::<StoredRecordType>("\"FutureRecord\"").expect("unknown type"),
            StoredRecordType::Unknown
        );
    }

    #[test]
    fn nodes_response_roundtrip() {
        let request = request(DhtRequestPayload::Ping);
        let value = response(
            &request,
            DhtResponsePayload::Nodes {
                peers: vec![],
                truncated: false,
            },
        );
        assert_eq!(
            decode_response(&encode_response(&value).expect("encode")).expect("decode"),
            value
        );
    }

    #[test]
    fn value_response_roundtrip() {
        let request = request(DhtRequestPayload::Ping);
        let value = response(
            &request,
            DhtResponsePayload::Value {
                key: [4u8; 32],
                value: vec![5],
                signature: vec![6; 64],
                expires_at: NOW + 100,
            },
        );
        assert_eq!(
            decode_response(&encode_response(&value).expect("encode")).expect("decode"),
            value
        );
    }

    #[test]
    fn stored_response_roundtrip() {
        let request = request(DhtRequestPayload::Ping);
        let value = response(&request, DhtResponsePayload::Stored { key: [7u8; 32] });
        assert_eq!(
            decode_response(&encode_response(&value).expect("encode")).expect("decode"),
            value
        );
    }

    #[test]
    fn error_response_roundtrip() {
        let request = request(DhtRequestPayload::Ping);
        let value = response(
            &request,
            DhtResponsePayload::Error {
                code: ERR_INTERNAL,
                message: "failure".into(),
            },
        );
        assert_eq!(
            decode_response(&encode_response(&value).expect("encode")).expect("decode"),
            value
        );
    }

    #[test]
    fn request_rejects_oversized() {
        assert!(decode_request(&vec![b'x'; MAX_DHT_REQUEST_BYTES + 1]).is_err());
    }

    #[test]
    fn request_rejects_empty() {
        assert!(decode_request(&[]).is_err());
    }

    #[test]
    fn request_rejects_wrong_version() {
        let mut value = request(DhtRequestPayload::Ping);
        value.version = DHT_PROTOCOL_VERSION + 1;
        assert_eq!(value.validate(NOW), Err(DhtError::VersionMismatch));
    }

    #[test]
    fn request_rejects_old_timestamp() {
        let value = request(DhtRequestPayload::Ping);
        assert_eq!(
            value.validate(NOW + DHT_TIMESTAMP_WINDOW_SECS + 1),
            Err(DhtError::TimestampOutOfRange)
        );
    }

    #[test]
    fn request_rejects_future_timestamp() {
        let mut value = request(DhtRequestPayload::Ping);
        value.timestamp = NOW + DHT_TIMESTAMP_WINDOW_SECS + 1;
        assert_eq!(value.validate(NOW), Err(DhtError::TimestampOutOfRange));
    }

    #[test]
    fn store_rejects_oversized_value() {
        let value = request(DhtRequestPayload::Store {
            key: [0; 32],
            value: vec![0; MAX_DHT_REQUEST_BYTES],
            signature: vec![],
            expires_at: NOW + 1,
        });
        assert!(value.validate(NOW).is_err());
    }

    #[test]
    fn store_rejects_expired() {
        let value = request(DhtRequestPayload::Store {
            key: [0; 32],
            value: vec![],
            signature: vec![],
            expires_at: NOW,
        });
        assert!(value.validate(NOW).is_err());
    }

    #[test]
    fn response_rejects_mismatched_request_id() {
        let request = request(DhtRequestPayload::Ping);
        let mut value = response(&request, DhtResponsePayload::Pong);
        value.request_id[0] ^= 1;
        assert!(value.validate(&request.request_id, NOW).is_err());
    }

    #[test]
    fn response_rejects_too_many_peers() {
        let request = request(DhtRequestPayload::Ping);
        let peers = (0..=MAX_DHT_PEERS_PER_RESPONSE)
            .map(|value| PeerInfo::new(NodeId::from_bytes([value as u8; 32]), "key".into()))
            .collect();
        let value = response(
            &request,
            DhtResponsePayload::Nodes {
                peers,
                truncated: false,
            },
        );
        assert!(value.validate(&request.request_id, NOW).is_err());
    }

    #[test]
    fn request_id_unique() {
        assert_ne!(generate_request_id(), generate_request_id());
    }

    #[test]
    fn dht_error_codes_correct() {
        assert_eq!(
            DhtError::InvalidRequest("x".into()).code(),
            ERR_INVALID_REQUEST
        );
        assert_eq!(DhtError::VersionMismatch.code(), ERR_VERSION_MISMATCH);
        assert_eq!(
            DhtError::TimestampOutOfRange.code(),
            ERR_TIMESTAMP_OUT_OF_RANGE
        );
        assert_eq!(DhtError::StorageFull.code(), ERR_STORAGE_FULL);
        assert_eq!(DhtError::InvalidSignature.code(), ERR_INVALID_SIGNATURE);
        assert_eq!(DhtError::Internal("x".into()).code(), ERR_INTERNAL);
    }
}
