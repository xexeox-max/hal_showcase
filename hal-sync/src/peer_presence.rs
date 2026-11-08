use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::SocketAddr};

pub const PRESENCE_HEARTBEAT_SECS: u64 = 45;
pub const PRESENCE_TTL_SECS: u64 = 120;
pub const PRESENCE_MIN_REQUEST_INTERVAL_SECS: u64 = 20;
pub const PRESENCE_MAX_PEERS: usize = 500;
pub const PRESENCE_MAX_ENDPOINTS: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PeerPresenceRecord {
    pub identity_id: String,
    pub public_key: String,
    pub endpoints: Vec<String>,
    pub wss_url: Option<String>,
    pub last_seen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "message", rename_all = "snake_case")]
pub(crate) enum PeerPresenceMessage {
    Request {
        request_id: String,
        home_stack_id: String,
        endpoints: Vec<String>,
        wss_url: Option<String>,
    },
    Response {
        request_id: String,
        home_stack_id: String,
        updated_at: u64,
        peers: Vec<PeerPresenceRecord>,
    },
    Error {
        request_id: String,
        reason: String,
    },
}

#[derive(Clone)]
pub(crate) struct ActivePeerPresence {
    pub record: PeerPresenceRecord,
    pub session_sender: crate::mux::MuxSender,
}

pub(crate) fn validate_record(record: &PeerPresenceRecord) -> Result<()> {
    let bytes: [u8; 32] = hex::decode(&record.public_key)?
        .try_into()
        .map_err(|_| anyhow!("presence public key must be 32 bytes"))?;
    let public_key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)?;
    if crate::dht::NodeId::from_public_key(&public_key).to_hex() != record.identity_id {
        return Err(anyhow!("presence identity does not match public key"));
    }
    if record.endpoints.len() > PRESENCE_MAX_ENDPOINTS
        || record.endpoints.iter().any(|endpoint| {
            endpoint.parse::<SocketAddr>().is_err()
                || endpoint
                    .parse::<SocketAddr>()
                    .is_ok_and(|address| address.port() == 0)
        })
    {
        return Err(anyhow!("presence contains an invalid endpoint"));
    }
    if record.wss_url.as_ref().is_some_and(|url| {
        url.len() > 2048 || !(url.starts_with("https://") || url.starts_with("wss://"))
    }) {
        return Err(anyhow!("presence contains an invalid WSS URL"));
    }
    Ok(())
}

pub(crate) fn filter_home_members<'a>(
    records: impl IntoIterator<Item = &'a PeerPresenceRecord>,
    member_public_keys: &HashSet<String>,
    now: u64,
) -> Vec<PeerPresenceRecord> {
    records
        .into_iter()
        .filter(|record| {
            member_public_keys.contains(&record.public_key)
                && record.last_seen.saturating_add(PRESENCE_TTL_SECS) > now
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn presence_records_require_identity_key_binding_and_valid_candidates() {
        let key = SigningKey::from_bytes(&[41; 32]);
        let public_key = hex::encode(key.verifying_key().to_bytes());
        let identity_id = crate::dht::NodeId::from_public_key(&key.verifying_key()).to_hex();
        let mut record = PeerPresenceRecord {
            identity_id: identity_id.clone(),
            public_key: public_key.clone(),
            endpoints: vec!["203.0.113.8:4001".to_string()],
            wss_url: Some("wss://relay.example.test".to_string()),
            last_seen: 100,
        };
        assert!(validate_record(&record).is_ok());

        record.identity_id = "other-identity".to_string();
        assert!(validate_record(&record).is_err());
        record.identity_id = identity_id;
        record.endpoints = vec!["not-an-endpoint".to_string()];
        assert!(validate_record(&record).is_err());
    }

    #[test]
    fn presence_responses_include_only_live_members_of_the_requested_home() {
        let member = SigningKey::from_bytes(&[41; 32]);
        let outsider = SigningKey::from_bytes(&[42; 32]);
        let member_public_key = hex::encode(member.verifying_key().to_bytes());
        let outsider_public_key = hex::encode(outsider.verifying_key().to_bytes());
        let records = [
            PeerPresenceRecord {
                identity_id: crate::dht::NodeId::from_public_key(&member.verifying_key()).to_hex(),
                public_key: member_public_key.clone(),
                endpoints: vec![],
                wss_url: None,
                last_seen: 100,
            },
            PeerPresenceRecord {
                identity_id: crate::dht::NodeId::from_public_key(&outsider.verifying_key())
                    .to_hex(),
                public_key: outsider_public_key,
                endpoints: vec![],
                wss_url: None,
                last_seen: 100,
            },
            PeerPresenceRecord {
                last_seen: 1,
                ..PeerPresenceRecord {
                    identity_id: crate::dht::NodeId::from_public_key(&member.verifying_key())
                        .to_hex(),
                    public_key: member_public_key.clone(),
                    endpoints: vec![],
                    wss_url: None,
                    last_seen: 100,
                }
            },
        ];
        let members = HashSet::from([member_public_key]);
        let response = filter_home_members(records.iter(), &members, 150);

        assert_eq!(response.len(), 1);
        assert_eq!(response[0].identity_id, records[0].identity_id);
    }
}
