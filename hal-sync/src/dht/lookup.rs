use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::future::join_all;
use tokio::time::timeout;

use super::distance::sort_by_distance;
use super::node_id::NodeId;
use super::peer_info::PeerInfo;
use super::routing::{RoutingTable, K};
use super::transport::DhtTransport;
use super::wire::{DhtError, DhtRequest, DhtRequestPayload, DhtResponsePayload};

pub const LOOKUP_ALPHA: usize = 3;
pub const LOOKUP_MAX_ROUNDS: usize = 8;
pub const LOOKUP_TIMEOUT_PER_RPC: Duration = Duration::from_secs(3);
pub const LOOKUP_TOTAL_BUDGET: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupValue {
    pub key: [u8; 32],
    pub value: Vec<u8>,
    pub signature: Vec<u8>,
    pub expires_at: u64,
}

#[derive(Debug, Clone)]
pub struct LookupResult {
    pub peers: Vec<PeerInfo>,
    pub value: Option<LookupValue>,
    pub rounds: usize,
    pub queried_peers: usize,
}

#[derive(Debug, Clone)]
pub struct LookupConfig {
    pub alpha: usize,
    pub max_rounds: usize,
    pub rpc_timeout: Duration,
    pub total_budget: Duration,
}

impl Default for LookupConfig {
    fn default() -> Self {
        Self {
            alpha: LOOKUP_ALPHA,
            max_rounds: LOOKUP_MAX_ROUNDS,
            rpc_timeout: LOOKUP_TIMEOUT_PER_RPC,
            total_budget: LOOKUP_TOTAL_BUDGET,
        }
    }
}

pub struct Lookup<'a> {
    local_id: NodeId,
    target: NodeId,
    config: LookupConfig,
    transport: &'a dyn DhtTransport,
    routing: &'a mut RoutingTable,
}

impl<'a> Lookup<'a> {
    pub fn new(
        local_id: NodeId,
        target: NodeId,
        config: LookupConfig,
        transport: &'a dyn DhtTransport,
        routing: &'a mut RoutingTable,
    ) -> Self {
        Self {
            local_id,
            target,
            config,
            transport,
            routing,
        }
    }

    pub async fn find_node(&mut self) -> Result<LookupResult, DhtError> {
        self.run(None).await
    }

    pub async fn find_value(&mut self, key: [u8; 32]) -> Result<LookupResult, DhtError> {
        self.run(Some(key)).await
    }

    async fn run(&mut self, value_key: Option<[u8; 32]>) -> Result<LookupResult, DhtError> {
        let started = Instant::now();
        let mut candidates = self.routing.closest(&self.target, K);
        let mut known = candidates
            .drain(..)
            .map(|peer| (peer.node_id, peer))
            .collect::<HashMap<_, _>>();
        let mut queried = HashSet::new();
        let mut rounds = 0;
        let mut previous_top = top_ids(
            &self.target,
            known.values().cloned().collect(),
            self.local_id,
        );

        while rounds < self.config.max_rounds && started.elapsed() < self.config.total_budget {
            let mut round_peers = known.values().cloned().collect::<Vec<_>>();
            sort_by_distance(&self.target, &mut round_peers);
            round_peers
                .retain(|peer| peer.node_id != self.local_id && !queried.contains(&peer.node_id));
            round_peers.truncate(self.config.alpha.max(1));
            if round_peers.is_empty() {
                break;
            }

            let now = unix_now();
            let request_payload = value_key
                .map(|key| DhtRequestPayload::FindValue { key })
                .unwrap_or(DhtRequestPayload::FindNode {
                    target: self.target,
                });
            let requests = round_peers
                .iter()
                .map(|peer| {
                    (
                        peer.clone(),
                        DhtRequest::new(request_payload.clone(), self.local_id, now),
                    )
                })
                .collect::<Vec<_>>();
            for peer in &round_peers {
                queried.insert(peer.node_id);
            }

            let remaining = self.config.total_budget.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                break;
            }
            let rpc_timeout = self.config.rpc_timeout.min(remaining);
            let transport = self.transport;
            let responses = join_all(requests.into_iter().map(|(peer, request)| async move {
                let request_id = request.request_id;
                match timeout(rpc_timeout, transport.send_request(&peer, request)).await {
                    Ok(Ok(response)) => response
                        .validate(&request_id, unix_now())
                        .ok()
                        .map(|_| response),
                    _ => None,
                }
            }))
            .await;

            let mut found_value = None;
            for response in responses.into_iter().flatten() {
                match response.payload {
                    DhtResponsePayload::Nodes { peers, .. } => {
                        for peer in peers {
                            if peer.node_id == self.local_id {
                                continue;
                            }
                            self.routing.insert(peer.clone(), unix_now());
                            known.insert(peer.node_id, peer);
                        }
                    }
                    DhtResponsePayload::Value {
                        key,
                        value,
                        signature,
                        expires_at,
                    } => {
                        if value_key == Some(key) {
                            found_value = Some(LookupValue {
                                key,
                                value,
                                signature,
                                expires_at,
                            });
                        }
                    }
                    DhtResponsePayload::NotFound { .. }
                    | DhtResponsePayload::Pong
                    | DhtResponsePayload::Stored { .. }
                    | DhtResponsePayload::Error { .. } => {}
                }
            }
            rounds += 1;
            if found_value.is_some() {
                return Ok(LookupResult {
                    peers: top_peers(&self.target, &known, self.local_id),
                    value: found_value,
                    rounds,
                    queried_peers: queried.len(),
                });
            }

            let current_top = top_ids(
                &self.target,
                known.values().cloned().collect(),
                self.local_id,
            );
            if current_top == previous_top {
                break;
            }
            previous_top = current_top;
        }

        Ok(LookupResult {
            peers: top_peers(&self.target, &known, self.local_id),
            value: None,
            rounds,
            queried_peers: queried.len(),
        })
    }
}

fn top_peers(
    target: &NodeId,
    known: &HashMap<NodeId, PeerInfo>,
    local_id: NodeId,
) -> Vec<PeerInfo> {
    let peers = known
        .values()
        .filter(|peer| peer.node_id != local_id)
        .cloned()
        .collect::<Vec<_>>();
    super::distance::closest_k(target, &peers, K)
}

fn top_ids(target: &NodeId, peers: Vec<PeerInfo>, local_id: NodeId) -> Vec<NodeId> {
    let peers = peers
        .into_iter()
        .filter(|peer| peer.node_id != local_id)
        .collect::<Vec<_>>();
    super::distance::closest_k(target, &peers, K)
        .into_iter()
        .map(|peer| peer.node_id)
        .collect()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::super::wire::DhtResponse;
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::time::sleep;

    #[derive(Clone, Default)]
    struct MockTransport {
        responses: Arc<Mutex<HashMap<NodeId, Vec<DhtResponse>>>>,
        failures: Arc<Mutex<HashSet<NodeId>>>,
        delays: Arc<Mutex<HashMap<NodeId, Duration>>>,
        active: Arc<AtomicUsize>,
        max_active: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl DhtTransport for MockTransport {
        async fn send_request(
            &self,
            peer: &PeerInfo,
            request: DhtRequest,
        ) -> Result<DhtResponse, DhtError> {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(active, Ordering::SeqCst);
            let delay = self
                .delays
                .lock()
                .expect("delays")
                .get(&peer.node_id)
                .copied();
            if let Some(delay) = delay {
                sleep(delay).await;
            }
            let result = if self
                .failures
                .lock()
                .expect("failures")
                .contains(&peer.node_id)
            {
                Err(DhtError::Internal("mock failure".into()))
            } else {
                let response = self
                    .responses
                    .lock()
                    .expect("responses")
                    .get_mut(&peer.node_id)
                    .and_then(|queue| {
                        if queue.is_empty() {
                            None
                        } else {
                            Some(queue.remove(0))
                        }
                    });
                response
                    .map(|mut response| {
                        response.request_id = request.request_id;
                        response.timestamp = unix_now();
                        response
                    })
                    .ok_or_else(|| DhtError::Internal("no mock response".into()))
            };
            self.active.fetch_sub(1, Ordering::SeqCst);
            result
        }
    }

    fn peer(value: u8) -> PeerInfo {
        PeerInfo::new(NodeId::from_bytes([value; 32]), format!("key-{value}"))
    }

    fn nodes_response(peers: Vec<PeerInfo>) -> DhtResponse {
        DhtResponse {
            version: 1,
            request_id: [0; 16],
            responder_node_id: NodeId::from_bytes([9; 32]),
            timestamp: unix_now(),
            payload: DhtResponsePayload::Nodes {
                peers,
                truncated: false,
            },
        }
    }

    fn value_response(key: [u8; 32]) -> DhtResponse {
        DhtResponse {
            version: 1,
            request_id: [0; 16],
            responder_node_id: NodeId::from_bytes([9; 32]),
            timestamp: unix_now(),
            payload: DhtResponsePayload::Value {
                key,
                value: vec![1, 2],
                signature: vec![3],
                expires_at: unix_now() + 100,
            },
        }
    }

    fn table_with(values: &[u8]) -> RoutingTable {
        let mut table = RoutingTable::new(NodeId::from_bytes([0; 32]));
        for value in values {
            table.insert(peer(*value), unix_now());
        }
        table
    }

    fn config() -> LookupConfig {
        LookupConfig {
            alpha: 3,
            max_rounds: 8,
            rpc_timeout: Duration::from_millis(100),
            total_budget: Duration::from_secs(2),
        }
    }

    #[tokio::test]
    async fn lookup_single_round_finds_target() {
        let transport = MockTransport::default();
        transport.responses.lock().unwrap().insert(
            NodeId::from_bytes([1; 32]),
            vec![nodes_response(vec![peer(2)])],
        );
        let mut routing = table_with(&[1]);
        let local = NodeId::from_bytes([0; 32]);
        let mut lookup = Lookup::new(
            local,
            NodeId::from_bytes([2; 32]),
            config(),
            &transport,
            &mut routing,
        );
        let result = lookup.find_node().await.unwrap();
        assert!(result
            .peers
            .iter()
            .any(|peer| peer.node_id == NodeId::from_bytes([2; 32])));
    }

    #[tokio::test]
    async fn lookup_multi_round_converges() {
        let transport = MockTransport::default();
        transport.responses.lock().unwrap().insert(
            NodeId::from_bytes([1; 32]),
            vec![nodes_response(vec![peer(2)])],
        );
        transport.responses.lock().unwrap().insert(
            NodeId::from_bytes([2; 32]),
            vec![nodes_response(vec![peer(3)])],
        );
        let mut routing = table_with(&[1]);
        let mut lookup = Lookup::new(
            NodeId::from_bytes([0; 32]),
            NodeId::from_bytes([3; 32]),
            config(),
            &transport,
            &mut routing,
        );
        let result = lookup.find_node().await.unwrap();
        assert!(result.rounds >= 2);
    }

    #[tokio::test]
    async fn lookup_stops_at_max_rounds() {
        let transport = MockTransport::default();
        transport.responses.lock().unwrap().insert(
            NodeId::from_bytes([1; 32]),
            vec![nodes_response(vec![peer(2)]), nodes_response(vec![peer(2)])],
        );
        let mut routing = table_with(&[1]);
        let mut lookup = Lookup::new(
            NodeId::from_bytes([0; 32]),
            NodeId::from_bytes([9; 32]),
            LookupConfig {
                max_rounds: 1,
                ..config()
            },
            &transport,
            &mut routing,
        );
        assert!(lookup.find_node().await.unwrap().rounds <= 1);
    }

    #[tokio::test]
    async fn lookup_stops_on_convergence() {
        let transport = MockTransport::default();
        transport
            .responses
            .lock()
            .unwrap()
            .insert(NodeId::from_bytes([1; 32]), vec![nodes_response(vec![])]);
        let mut routing = table_with(&[1]);
        let mut lookup = Lookup::new(
            NodeId::from_bytes([0; 32]),
            NodeId::from_bytes([9; 32]),
            config(),
            &transport,
            &mut routing,
        );
        assert_eq!(lookup.find_node().await.unwrap().rounds, 1);
    }

    #[tokio::test]
    async fn lookup_parallel_queries_alpha() {
        let transport = MockTransport::default();
        for value in 1..=5 {
            transport.responses.lock().unwrap().insert(
                NodeId::from_bytes([value; 32]),
                vec![nodes_response(vec![])],
            );
        }
        let mut routing = table_with(&[1, 2, 3, 4, 5]);
        let mut lookup = Lookup::new(
            NodeId::from_bytes([0; 32]),
            NodeId::from_bytes([9; 32]),
            LookupConfig {
                alpha: 2,
                ..config()
            },
            &transport,
            &mut routing,
        );
        lookup.find_node().await.unwrap();
        assert!(transport.max_active.load(Ordering::SeqCst) <= 2);
    }

    #[tokio::test]
    async fn lookup_handles_rpc_timeout() {
        let transport = MockTransport::default();
        transport
            .delays
            .lock()
            .unwrap()
            .insert(NodeId::from_bytes([1; 32]), Duration::from_millis(80));
        transport
            .responses
            .lock()
            .unwrap()
            .insert(NodeId::from_bytes([2; 32]), vec![nodes_response(vec![])]);
        let mut routing = table_with(&[1, 2]);
        let mut lookup = Lookup::new(
            NodeId::from_bytes([0; 32]),
            NodeId::from_bytes([9; 32]),
            LookupConfig {
                rpc_timeout: Duration::from_millis(10),
                ..config()
            },
            &transport,
            &mut routing,
        );
        assert!(lookup.find_node().await.is_ok());
    }

    #[tokio::test]
    async fn lookup_handles_rpc_error() {
        let transport = MockTransport::default();
        transport
            .failures
            .lock()
            .unwrap()
            .insert(NodeId::from_bytes([1; 32]));
        transport
            .responses
            .lock()
            .unwrap()
            .insert(NodeId::from_bytes([2; 32]), vec![nodes_response(vec![])]);
        let mut routing = table_with(&[1, 2]);
        let mut lookup = Lookup::new(
            NodeId::from_bytes([0; 32]),
            NodeId::from_bytes([9; 32]),
            config(),
            &transport,
            &mut routing,
        );
        assert!(lookup.find_node().await.is_ok());
    }

    #[tokio::test]
    async fn lookup_all_peers_fail() {
        let transport = MockTransport::default();
        transport
            .failures
            .lock()
            .unwrap()
            .extend([NodeId::from_bytes([1; 32]), NodeId::from_bytes([2; 32])]);
        let mut routing = table_with(&[1, 2]);
        let mut lookup = Lookup::new(
            NodeId::from_bytes([0; 32]),
            NodeId::from_bytes([9; 32]),
            config(),
            &transport,
            &mut routing,
        );
        let result = lookup.find_node().await.unwrap();
        assert_eq!(result.peers.len(), 2);
    }

    #[tokio::test]
    async fn lookup_updates_routing_table() {
        let transport = MockTransport::default();
        transport.responses.lock().unwrap().insert(
            NodeId::from_bytes([1; 32]),
            vec![nodes_response(vec![peer(2)])],
        );
        let mut routing = table_with(&[1]);
        let mut lookup = Lookup::new(
            NodeId::from_bytes([0; 32]),
            NodeId::from_bytes([9; 32]),
            config(),
            &transport,
            &mut routing,
        );
        lookup.find_node().await.unwrap();
        assert!(routing.contains(&NodeId::from_bytes([2; 32])));
    }

    #[tokio::test]
    async fn lookup_skips_self() {
        let transport = MockTransport::default();
        transport.responses.lock().unwrap().insert(
            NodeId::from_bytes([1; 32]),
            vec![nodes_response(vec![peer(2)])],
        );
        let local = NodeId::from_bytes([2; 32]);
        let mut routing = table_with(&[1, 2]);
        let mut lookup = Lookup::new(
            local,
            NodeId::from_bytes([9; 32]),
            config(),
            &transport,
            &mut routing,
        );
        let result = lookup.find_node().await.unwrap();
        assert!(!result.peers.iter().any(|peer| peer.node_id == local));
    }

    #[tokio::test]
    async fn find_value_returns_value_early() {
        let key = [7; 32];
        let transport = MockTransport::default();
        transport
            .responses
            .lock()
            .unwrap()
            .insert(NodeId::from_bytes([1; 32]), vec![value_response(key)]);
        let mut routing = table_with(&[1]);
        let mut lookup = Lookup::new(
            NodeId::from_bytes([0; 32]),
            NodeId::from_bytes(key),
            config(),
            &transport,
            &mut routing,
        );
        assert!(lookup.find_value(key).await.unwrap().value.is_some());
    }

    #[tokio::test]
    async fn find_value_continues_on_not_found() {
        let key = [7; 32];
        let transport = MockTransport::default();
        transport.responses.lock().unwrap().insert(
            NodeId::from_bytes([1; 32]),
            vec![DhtResponse {
                version: 1,
                request_id: [0; 16],
                responder_node_id: NodeId::from_bytes([9; 32]),
                timestamp: unix_now(),
                payload: DhtResponsePayload::NotFound { key },
            }],
        );
        transport
            .responses
            .lock()
            .unwrap()
            .insert(NodeId::from_bytes([2; 32]), vec![value_response(key)]);
        let mut routing = table_with(&[1, 2]);
        let mut lookup = Lookup::new(
            NodeId::from_bytes([0; 32]),
            NodeId::from_bytes(key),
            config(),
            &transport,
            &mut routing,
        );
        assert!(lookup.find_value(key).await.unwrap().value.is_some());
    }

    #[tokio::test]
    async fn find_value_returns_peers_when_missing() {
        let key = [7; 32];
        let transport = MockTransport::default();
        for value in [1u8, 2] {
            transport.responses.lock().unwrap().insert(
                NodeId::from_bytes([value; 32]),
                vec![DhtResponse {
                    version: 1,
                    request_id: [0; 16],
                    responder_node_id: NodeId::from_bytes([9; 32]),
                    timestamp: unix_now(),
                    payload: DhtResponsePayload::NotFound { key },
                }],
            );
        }
        let mut routing = table_with(&[1, 2]);
        let mut lookup = Lookup::new(
            NodeId::from_bytes([0; 32]),
            NodeId::from_bytes(key),
            config(),
            &transport,
            &mut routing,
        );
        let result = lookup.find_value(key).await.unwrap();
        assert!(result.value.is_none());
        assert_eq!(result.peers.len(), 2);
    }

    #[tokio::test]
    async fn lookup_respects_total_budget() {
        let transport = MockTransport::default();
        transport
            .delays
            .lock()
            .unwrap()
            .insert(NodeId::from_bytes([1; 32]), Duration::from_millis(100));
        let mut routing = table_with(&[1]);
        let mut lookup = Lookup::new(
            NodeId::from_bytes([0; 32]),
            NodeId::from_bytes([9; 32]),
            LookupConfig {
                rpc_timeout: Duration::from_secs(1),
                total_budget: Duration::from_millis(20),
                ..config()
            },
            &transport,
            &mut routing,
        );
        let started = Instant::now();
        lookup.find_node().await.unwrap();
        assert!(started.elapsed() < Duration::from_millis(80));
    }

    #[tokio::test]
    async fn lookup_empty_routing_table() {
        let transport = MockTransport::default();
        let mut routing = RoutingTable::new(NodeId::from_bytes([0; 32]));
        let mut lookup = Lookup::new(
            NodeId::from_bytes([0; 32]),
            NodeId::from_bytes([9; 32]),
            config(),
            &transport,
            &mut routing,
        );
        let result = lookup.find_node().await.unwrap();
        assert!(result.peers.is_empty());
        assert_eq!(result.rounds, 0);
    }
}
