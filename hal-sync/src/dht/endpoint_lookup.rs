use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use hal_settings::NetworkTrustPolicy;
use tokio::sync::Mutex;

use crate::dht::endpoint::{EndpointCache, EndpointStore};
use crate::dht::mux_transport::MuxDhtTransport;
use crate::dht::routing::RoutingTable;
use crate::dht::NodeId;
use crate::pinning::KnownHosts;
use hal_discovery::{DiscoveryProvider, PublicDhtProvider};
use std::time::Duration;

const ENDPOINT_LOOKUP_RETRY_DELAY: Duration = Duration::from_secs(3);

pub fn quic_dht_topic(identity_id: &str) -> String {
    format!("hal.quic.{identity_id}")
}

pub fn tcp_dht_topic(node_id: &NodeId) -> String {
    format!("hal.tcp.{}", node_id.to_hex())
}

const PUBLIC_RECORD_LOOKUP_ATTEMPTS: usize = 2;
const PUBLIC_RECORD_LOOKUP_RETRY_DELAY: Duration = Duration::from_secs(1);

pub async fn discover_public_endpoint_record(
    public_key_hex: &str,
    now: u64,
) -> anyhow::Result<Option<super::endpoint::EndpointRecord>> {
    let public_key: [u8; 32] = hex::decode(public_key_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))?;
    let mut record = None;
    for attempt in 0..PUBLIC_RECORD_LOOKUP_ATTEMPTS {
        let value =
            hal_discovery::discover_mutable_record(&public_key, Duration::from_secs(8)).await?;
        let Some(value) = value else {
            if attempt + 1 < PUBLIC_RECORD_LOOKUP_ATTEMPTS {
                tokio::time::sleep(PUBLIC_RECORD_LOOKUP_RETRY_DELAY).await;
                continue;
            }
            return Ok(None);
        };
        let found: super::endpoint::EndpointRecord = serde_json::from_slice(&value)?;
        if found.is_expired(now) && attempt + 1 < PUBLIC_RECORD_LOOKUP_ATTEMPTS {
            log::debug!(
                target: "HAL_DHT",
                "received an expired public EndpointRecord; retrying lookup once"
            );
            tokio::time::sleep(PUBLIC_RECORD_LOOKUP_RETRY_DELAY).await;
            continue;
        }
        found.verify(now)?;
        record = Some(found);
        break;
    }
    let Some(record) = record else {
        return Ok(None);
    };
    anyhow::ensure!(
        record.public_key == public_key_hex,
        "Mainline DHT endpoint record key does not match the pinned public key"
    );
    Ok(Some(record))
}

pub async fn publish_public_endpoint_record(
    record: &super::endpoint::EndpointRecord,
    signing_key: &SigningKey,
) -> anyhow::Result<()> {
    let value = serde_json::to_vec(record)?;
    anyhow::ensure!(
        record.public_key == hex::encode(signing_key.verifying_key().to_bytes()),
        "signing key does not match endpoint record identity"
    );
    hal_discovery::publish_mutable_record(&signing_key.to_bytes(), &value, Duration::from_secs(8))
        .await
}

pub async fn announce_public_tcp_endpoint(node_id: &NodeId, port: u16) -> anyhow::Result<()> {
    anyhow::ensure!(port != 0, "cannot announce TCP endpoint on port 0");
    #[cfg(test)]
    {
        let _ = node_id;
        return Ok(());
    }
    #[cfg(not(test))]
    {
        let topic = tcp_dht_topic(node_id);
        PublicDhtProvider::new(&topic).announce(port).await?;
        log::info!(
            target: "HAL_DHT",
            "announced TCP endpoint for {} on public DHT topic {topic}",
            node_id.to_hex()
        );
        Ok(())
    }
}

pub async fn discover_public_tcp_endpoints(node_id: &NodeId) -> anyhow::Result<Vec<SocketAddr>> {
    #[cfg(test)]
    {
        let _ = node_id;
        return Ok(Vec::new());
    }
    #[cfg(not(test))]
    {
        let topic = tcp_dht_topic(node_id);
        let provider = PublicDhtProvider::new(&topic).with_timeout(Duration::from_secs(8));
        let mut candidates = provider
            .discover()
            .await?
            .into_iter()
            .filter(|address| is_public_tcp_candidate(*address))
            .collect::<Vec<_>>();
        candidates.sort();
        candidates.dedup();
        log::info!(
            target: "HAL_DHT",
            "public DHT TCP lookup for {} on {topic} returned {} candidate(s)",
            node_id.to_hex(),
            candidates.len()
        );
        Ok(candidates)
    }
}

fn is_public_tcp_candidate(address: SocketAddr) -> bool {
    let SocketAddr::V4(address) = address else {
        return false;
    };
    let ip = address.ip();
    let [a, b, _, _] = ip.octets();
    address.port() != 0
        && !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_broadcast()
        && !ip.is_multicast()
        && !ip.is_unspecified()
        && !(a == 0
            || a >= 240
            || (a == 100 && (64..=127).contains(&b))
            || (a == 192 && (b == 0 || b == 2 || b == 168))
            || (a == 198 && (b == 18 || b == 19 || b == 51))
            || (a == 203 && b == 0))
}

pub fn quic_punch_dht_topic(requester_id: &str, recipient_id: &str) -> String {
    format!("hal.punch.{requester_id}.{recipient_id}")
}

#[async_trait]
pub trait EndpointLookup: Send + Sync {
    /// Найти все endpoint'ы для узла.
    /// Возвращает пустой Vec, если не найдено.
    async fn lookup(&self, node_id: &NodeId, now: u64) -> Vec<SocketAddr>;
}

pub struct DhtEndpointLookup {
    local_id: NodeId,
    signing_key: SigningKey,
    hosts: Arc<std::sync::Mutex<KnownHosts>>,
    trust_policy: NetworkTrustPolicy,
    routing: Arc<Mutex<RoutingTable>>,
    cache: Arc<Mutex<EndpointCache>>,
}

impl DhtEndpointLookup {
    pub fn new(
        local_id: NodeId,
        signing_key: SigningKey,
        hosts: Arc<std::sync::Mutex<KnownHosts>>,
        trust_policy: NetworkTrustPolicy,
        routing: Arc<Mutex<RoutingTable>>,
        cache: Arc<Mutex<EndpointCache>>,
    ) -> Self {
        Self {
            local_id,
            signing_key,
            hosts,
            trust_policy,
            routing,
            cache,
        }
    }

    pub async fn lookup_quic(&self, node_id: &NodeId, now: u64) -> anyhow::Result<Vec<SocketAddr>> {
        let identity_id = node_id.to_hex();
        let transport = MuxDhtTransport::new(
            self.signing_key.clone(),
            Arc::clone(&self.hosts),
            self.trust_policy.clone(),
        );
        let mut record = None;
        for attempt in 0..2 {
            log::info!(target: "HAL_DHT", "DHT lookup: searching for {identity_id}");
            let result = {
                let mut routing = self.routing.lock().await;
                let mut cache = self.cache.lock().await;
                let mut store =
                    EndpointStore::new(self.local_id, &transport, &mut routing, &mut cache);
                store.lookup(&identity_id, now).await
            };
            match result {
                Ok(Some(found)) => {
                    log::info!(target: "HAL_DHT", "DHT lookup: found {found:?}");
                    record = Some(found);
                    break;
                }
                Ok(None) if attempt == 0 => {
                    log::warn!(
                        target: "HAL_DHT",
                        "DHT lookup: not found (retry in 3s)"
                    );
                    tokio::time::sleep(ENDPOINT_LOOKUP_RETRY_DELAY).await;
                }
                Ok(None) => {
                    log::warn!(target: "HAL_DHT", "DHT lookup: not found after retry for {identity_id}");
                }
                Err(error) => {
                    log::warn!(target: "HAL_DHT", "DHT QUIC endpoint lookup failed for {identity_id}: {error}");
                    return Err(error.into());
                }
            }
        }
        let mut candidates = record
            .map(|record| {
                let candidates = record
                    .endpoints
                    .iter()
                    .filter_map(|address| parse_quic_endpoint(address))
                    .collect::<Vec<_>>();
                if candidates.is_empty() {
                    log::warn!(
                        target: "HAL_DHT",
                        "DHT endpoint record for {identity_id} has no valid udp:// candidates"
                    );
                }
                candidates
            })
            .unwrap_or_default();
        if candidates.is_empty() {
            let topic = quic_dht_topic(&identity_id);
            let provider = PublicDhtProvider::new(&topic).with_timeout(Duration::from_secs(8));
            let public_candidates = provider.discover().await?;
            candidates.extend(public_candidates.into_iter().filter(|address| {
                !address.ip().is_loopback() && !address.ip().is_unspecified() && address.port() != 0
            }));
            candidates.sort();
            candidates.dedup();
            log::info!(
                target: "HAL_DHT",
                "public DHT QUIC lookup for {identity_id} on {topic} returned {} endpoint(s)",
                candidates.len()
            );
        }
        if candidates.is_empty() {
            log::warn!(
                target: "HAL_DHT",
                "HolePunch: no UDP endpoint in DHT for {identity_id}"
            );
        }
        Ok(candidates)
    }
}

#[async_trait]
impl EndpointLookup for DhtEndpointLookup {
    async fn lookup(&self, node_id: &NodeId, now: u64) -> Vec<SocketAddr> {
        let identity_id = node_id.to_hex();
        let transport = MuxDhtTransport::new(
            self.signing_key.clone(),
            Arc::clone(&self.hosts),
            self.trust_policy.clone(),
        );
        let mut routing = self.routing.lock().await;
        let mut cache = self.cache.lock().await;
        let mut store = EndpointStore::new(self.local_id, &transport, &mut routing, &mut cache);

        match store.lookup(&identity_id, now).await {
            Ok(Some(record)) => record
                .endpoints
                .iter()
                .filter_map(|address| parse_socket_addr(address))
                .collect(),
            _ => Vec::new(),
        }
    }
}

fn parse_socket_addr(address: &str) -> Option<SocketAddr> {
    address.parse().ok()
}

fn parse_quic_endpoint(address: &str) -> Option<SocketAddr> {
    address.strip_prefix("udp://")?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn lookup() -> DhtEndpointLookup {
        let signing_key = SigningKey::from_bytes(&[1; 32]);
        let local_id = NodeId::from_public_key(&signing_key.verifying_key());
        DhtEndpointLookup::new(
            local_id,
            signing_key,
            Arc::new(std::sync::Mutex::new(KnownHosts::new())),
            NetworkTrustPolicy::default(),
            Arc::new(Mutex::new(RoutingTable::new(local_id))),
            Arc::new(Mutex::new(EndpointCache::new(16))),
        )
    }

    #[test]
    fn trait_object_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DhtEndpointLookup>();
        assert_send_sync::<Arc<dyn EndpointLookup>>();
    }

    #[test]
    fn dht_lookup_new_constructible() {
        let value = lookup();
        assert_eq!(
            value.local_id,
            NodeId::from_public_key(&value.signing_key.verifying_key())
        );
    }

    #[test]
    fn parse_socket_addr_works() {
        assert_eq!(
            parse_socket_addr("127.0.0.1:9000"),
            Some("127.0.0.1:9000".parse().unwrap())
        );
    }

    #[test]
    fn parse_socket_addr_invalid_returns_none() {
        assert_eq!(parse_socket_addr("not-an-endpoint"), None);
        assert_eq!(parse_socket_addr("2001:db8::1"), None);
        assert_eq!(
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
    }

    #[test]
    fn parse_quic_endpoint_requires_udp_candidate_prefix() {
        assert_eq!(
            parse_quic_endpoint("udp://198.51.100.10:4003"),
            Some("198.51.100.10:4003".parse().unwrap())
        );
        assert_eq!(parse_quic_endpoint("198.51.100.10:4003"), None);
        assert_eq!(parse_quic_endpoint("udp://not-an-endpoint"), None);
    }

    #[test]
    fn quic_dht_topic_uses_identity_id() {
        assert_eq!(quic_dht_topic("abc123"), "hal.quic.abc123");
    }

    #[test]
    fn tcp_dht_topic_is_derived_from_peer_identity() {
        let identity = NodeId::from_bytes([0xabu8; 32]);
        assert_eq!(
            tcp_dht_topic(&identity),
            format!("hal.tcp.{}", identity.to_hex())
        );
    }

    #[test]
    fn public_tcp_candidates_reject_private_reserved_and_invalid_addresses() {
        for address in [
            "127.0.0.1:4001",
            "10.0.0.1:4001",
            "192.168.1.1:4001",
            "100.64.0.1:4001",
            "203.0.113.10:4001",
            "224.0.0.1:4001",
            "8.8.8.8:0",
        ] {
            assert!(
                !is_public_tcp_candidate(address.parse().expect("valid address")),
                "candidate should be rejected: {address}"
            );
        }
        assert!(is_public_tcp_candidate(
            "8.8.8.8:4001".parse().expect("public candidate")
        ));
    }

    #[test]
    fn quic_punch_dht_topic_binds_requester_and_recipient() {
        assert_eq!(
            quic_punch_dht_topic("requester", "recipient"),
            "hal.punch.requester.recipient"
        );
    }
}
