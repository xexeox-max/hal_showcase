use crate::{
    PeerAnnouncement, PollFuture, PollHandler, PollRequest, DISCOVERY_MULTICAST, DISCOVERY_PORT,
};
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::RwLock;
use tokio::time::{timeout, Duration};

pub struct DiscoveryAnnounceHandler {
    identity_id: String,
    public_key: String,
    private_key: [u8; 32],
    transport_address: String,
}

impl DiscoveryAnnounceHandler {
    pub fn new(
        identity_id: String,
        public_key: String,
        private_key: [u8; 32],
        transport_address: String,
    ) -> Self {
        Self {
            identity_id,
            public_key,
            private_key,
            transport_address,
        }
    }
}

impl PollHandler for DiscoveryAnnounceHandler {
    fn handle(&self, _request: PollRequest) -> PollFuture {
        let identity_id = self.identity_id.clone();
        let public_key = self.public_key.clone();
        let private_key = self.private_key;
        let transport_address = self.transport_address.clone();
        Box::pin(async move {
            let mut announcement =
                PeerAnnouncement::new(identity_id, public_key, transport_address);
            announcement.sign(&private_key)?;
            announcement.verify()?;
            let payload = serde_json::to_vec(&announcement)?;
            let socket = UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).await?;
            socket.set_broadcast(true)?;
            socket
                .send_to(&payload, (DISCOVERY_MULTICAST, DISCOVERY_PORT))
                .await?;
            Ok(())
        })
    }
}

pub struct PeerHealthHandler {
    targets: Arc<RwLock<Vec<String>>>,
    timeout: Duration,
    successful_probes: Arc<AtomicUsize>,
}

impl PeerHealthHandler {
    pub fn new(targets: Arc<RwLock<Vec<String>>>, timeout: Duration) -> Self {
        Self {
            targets,
            timeout,
            successful_probes: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn successful_probes(&self) -> usize {
        self.successful_probes.load(Ordering::Relaxed)
    }
}

impl PollHandler for PeerHealthHandler {
    fn handle(&self, _request: PollRequest) -> PollFuture {
        let targets = Arc::clone(&self.targets);
        let timeout_duration = self.timeout;
        let successful = Arc::clone(&self.successful_probes);
        Box::pin(async move {
            let addresses = targets.read().await.clone();
            let mut probes = Vec::with_capacity(addresses.len());
            for address in addresses {
                let Ok(socket_address) = address.parse::<SocketAddr>() else {
                    continue;
                };
                probes.push(async move {
                    timeout(timeout_duration, TcpStream::connect(socket_address))
                        .await
                        .is_ok()
                });
            }
            let results = futures::future::join_all(probes).await;
            successful.fetch_add(
                results.into_iter().filter(|connected| *connected).count(),
                Ordering::Relaxed,
            );
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PollBranch, PollDispatcher};
    use ed25519_dalek::SigningKey;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn health_handler_probes_reachable_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address").to_string();
        let targets = Arc::new(RwLock::new(vec![address]));
        let handler = Arc::new(PeerHealthHandler::new(targets, Duration::from_secs(1)));
        let dispatcher =
            PollDispatcher::new().with_handler(PollBranch::NearbyPeers, handler.clone());
        assert!(dispatcher
            .dispatch(PollRequest {
                branch: PollBranch::NearbyPeers,
                max_items: 1
            })
            .await
            .expect("dispatch"));
        assert_eq!(handler.successful_probes(), 1);
    }

    #[tokio::test]
    async fn discovery_handler_signs_before_sending() {
        let key = SigningKey::from_bytes(&[13; 32]);
        let public = hex::encode(key.verifying_key().to_bytes());
        let mut hash = sha2::Sha256::new();
        use sha2::Digest;
        hash.update(key.verifying_key().to_bytes());
        let identity = hex::encode(hash.finalize());
        let handler = DiscoveryAnnounceHandler::new(
            identity,
            public,
            key.to_bytes(),
            "127.0.0.1:4001".into(),
        );
        handler
            .handle(PollRequest {
                branch: PollBranch::AvailablePeers,
                max_items: 1,
            })
            .await
            .expect("announce");
    }
}
