use anyhow::{anyhow, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use if_addrs::{get_if_addrs, IfAddr};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

pub const DISCOVERY_MULTICAST_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 42, 99);
pub const DISCOVERY_MULTICAST_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x2a99);
pub const DISCOVERY_MULTICAST: Ipv4Addr = DISCOVERY_MULTICAST_V4;
pub const DISCOVERY_PORT: u16 = 39_701;
const MAX_ANNOUNCEMENT_SIZE: usize = 16 * 1024;
const MAX_AGE: u64 = 300;
const MAX_SKEW: u64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerAnnouncement {
    pub identity_id: String,
    pub public_key: String,
    pub transport_address: String,
    pub timestamp: u64,
    pub signature: String,
}

impl PeerAnnouncement {
    pub fn new(identity_id: String, public_key: String, transport_address: String) -> Self {
        Self {
            identity_id,
            public_key,
            transport_address,
            timestamp: now(),
            signature: String::new(),
        }
    }

    fn signing_payload(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            &self.identity_id,
            &self.public_key,
            &self.transport_address,
            self.timestamp,
        ))?)
    }

    pub fn sign(&mut self, private_key: &[u8]) -> Result<()> {
        let bytes: [u8; 32] = private_key
            .try_into()
            .map_err(|_| anyhow!("Ed25519 private key must be 32 bytes"))?;
        self.signature = hex::encode(
            SigningKey::from_bytes(&bytes)
                .sign(&self.signing_payload()?)
                .to_bytes(),
        );
        Ok(())
    }

    pub fn verify(&self) -> Result<()> {
        let current = now();
        if self.timestamp.saturating_add(MAX_AGE) < current {
            return Err(anyhow!("peer announcement is too old"));
        }
        if self.timestamp > current.saturating_add(MAX_SKEW) {
            return Err(anyhow!("peer announcement is from the future"));
        }
        let public_bytes: [u8; 32] = hex::decode(&self.public_key)?
            .try_into()
            .map_err(|_| anyhow!("Ed25519 public key must be 32 bytes"))?;
        let signature_bytes: [u8; 64] = hex::decode(&self.signature)?
            .try_into()
            .map_err(|_| anyhow!("Ed25519 signature must be 64 bytes"))?;
        let mut hasher = Sha256::new();
        hasher.update(public_bytes);
        let expected_identity = hex::encode(hasher.finalize());
        if self.identity_id != expected_identity {
            return Err(anyhow!("announcement identity does not match public key"));
        }
        VerifyingKey::from_bytes(&public_bytes)?.verify(
            &self.signing_payload()?,
            &Signature::from_bytes(&signature_bytes),
        )?;
        Ok(())
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub struct PeerDiscovery {
    pub local_address: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    tasks: Vec<JoinHandle<()>>,
}

fn announcement_key(announcement: &PeerAnnouncement) -> (String, String) {
    (
        announcement.identity_id.clone(),
        announcement.transport_address.clone(),
    )
}

fn forward_announcement(
    announcement: PeerAnnouncement,
    local_identity: &str,
    seen: &mut HashSet<(String, String)>,
    peer_tx: &mpsc::Sender<PeerAnnouncement>,
) {
    if announcement.identity_id == local_identity || announcement.verify().is_err() {
        return;
    }
    if seen.insert(announcement_key(&announcement)) {
        let _ = peer_tx.try_send(announcement);
    }
}

impl PeerDiscovery {
    pub async fn start(
        identity_id: String,
        public_key: String,
        private_key: [u8; 32],
        transport_address: String,
    ) -> Result<(Self, mpsc::Receiver<PeerAnnouncement>)> {
        Self::start_on_port(
            identity_id,
            public_key,
            private_key,
            transport_address,
            DISCOVERY_PORT,
        )
        .await
    }

    async fn start_on_port(
        identity_id: String,
        public_key: String,
        private_key: [u8; 32],
        transport_address: String,
        port: u16,
    ) -> Result<(Self, mpsc::Receiver<PeerAnnouncement>)> {
        let socket_v4 = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).await?;
        socket_v4.join_multicast_v4(DISCOVERY_MULTICAST_V4, Ipv4Addr::UNSPECIFIED)?;
        socket_v4.set_multicast_loop_v4(true)?;
        let local_address = socket_v4.local_addr()?;
        let discovery_port = local_address.port();
        let socket_v6 = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, discovery_port))
            .await
            .ok();
        let v6_interfaces = if socket_v6.is_some() {
            get_if_addrs()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|interface| match interface.addr {
                    IfAddr::V6(_) => interface.index,
                    IfAddr::V4(_) => None,
                })
                .filter(|index| *index != 0)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let socket_v6 = if v6_interfaces.is_empty() {
            None
        } else {
            socket_v6
        };
        let (peer_tx, peer_rx) = mpsc::channel(64);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let announcement = PeerAnnouncement::new(identity_id, public_key, transport_address);
        let local_identity = announcement.identity_id.clone();
        let seen = Arc::new(tokio::sync::Mutex::new(HashSet::new()));
        let (v4_shutdown_tx, mut v4_shutdown_rx) = oneshot::channel();
        let (v6_shutdown_tx, mut v6_shutdown_rx) = oneshot::channel();
        let shutdown_task = tokio::spawn(async move {
            let _ = shutdown_rx.await;
            let _ = v4_shutdown_tx.send(());
            let _ = v6_shutdown_tx.send(());
        });
        let v4_peer_tx = peer_tx.clone();
        let v4_seen = Arc::clone(&seen);
        let v4_local_identity = local_identity.clone();
        let v4_announcement = announcement.clone();
        let v4_task = tokio::spawn(async move {
            let destination = SocketAddr::from((DISCOVERY_MULTICAST_V4, discovery_port));
            let mut buffer = vec![0u8; MAX_ANNOUNCEMENT_SIZE];
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                tokio::select! {
                    _ = &mut v4_shutdown_rx => break,
                    _ = interval.tick() => {
                        let mut current = v4_announcement.clone();
                        current.timestamp = now();
                        if current.sign(&private_key).is_ok() {
                            if let Ok(payload) = serde_json::to_vec(&current) {
                                let _ = socket_v4.send_to(&payload, destination).await;
                            }
                        }
                    }
                    received = socket_v4.recv_from(&mut buffer) => {
                        let Ok((size, _)) = received else { break };
                        if let Ok(peer) = serde_json::from_slice::<PeerAnnouncement>(&buffer[..size]) {
                            forward_announcement(peer, &v4_local_identity, &mut *v4_seen.lock().await, &v4_peer_tx);
                        }
                    }
                }
            }
        });
        let mut tasks = vec![v4_task, shutdown_task];
        if let Some(socket_v6) = socket_v6 {
            let mut joined = false;
            for index in &v6_interfaces {
                if socket_v6
                    .join_multicast_v6(&DISCOVERY_MULTICAST_V6, *index)
                    .is_ok()
                {
                    joined = true;
                }
            }
            if joined && socket_v6.set_multicast_loop_v6(true).is_ok() {
                let v6_peer_tx = peer_tx;
                let v6_seen = Arc::clone(&seen);
                let v6_local_identity = local_identity;
                let v6_announcement = announcement;
                let v6_task = tokio::spawn(async move {
                    let mut buffer = vec![0u8; MAX_ANNOUNCEMENT_SIZE];
                    let mut interval = tokio::time::interval(Duration::from_secs(10));
                    loop {
                        tokio::select! {
                            _ = &mut v6_shutdown_rx => break,
                            _ = interval.tick() => {
                                let mut current = v6_announcement.clone();
                                current.timestamp = now();
                                if current.sign(&private_key).is_ok() {
                                    if let Ok(payload) = serde_json::to_vec(&current) {
                                        for index in &v6_interfaces {
                                            let destination = SocketAddr::V6(SocketAddrV6::new(
                                                DISCOVERY_MULTICAST_V6, discovery_port, 0, *index,
                                            ));
                                            let _ = socket_v6.send_to(&payload, destination).await;
                                        }
                                    }
                                }
                            }
                            received = socket_v6.recv_from(&mut buffer) => {
                                let Ok((size, _)) = received else { break };
                                if let Ok(peer) = serde_json::from_slice::<PeerAnnouncement>(&buffer[..size]) {
                                    forward_announcement(peer, &v6_local_identity, &mut *v6_seen.lock().await, &v6_peer_tx);
                                }
                            }
                        }
                    }
                });
                tasks.push(v6_task);
            }
        }
        Ok((
            Self {
                local_address,
                shutdown: Some(shutdown_tx),
                tasks,
            },
            peer_rx,
        ))
    }

    pub async fn stop(mut self) -> Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        for task in self.tasks.drain(..) {
            task.await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn announcement_requires_matching_identity_and_signature() {
        let key = SigningKey::from_bytes(&[8; 32]);
        let public = hex::encode(key.verifying_key().to_bytes());
        let mut hasher = Sha256::new();
        hasher.update(key.verifying_key().to_bytes());
        let identity = hex::encode(hasher.finalize());
        let mut announcement = PeerAnnouncement::new(identity, public, "127.0.0.1:4001".into());
        announcement.sign(&key.to_bytes()).expect("sign");
        assert!(announcement.verify().is_ok());
        announcement.transport_address = "127.0.0.1:9999".into();
        assert!(announcement.verify().is_err());
    }

    #[test]
    fn old_announcement_rejected() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let public = hex::encode(key.verifying_key().to_bytes());
        let mut hasher = Sha256::new();
        hasher.update(key.verifying_key().to_bytes());
        let identity = hex::encode(hasher.finalize());
        let mut announcement = PeerAnnouncement::new(identity, public, "127.0.0.1:4001".into());
        announcement.timestamp = now().saturating_sub(MAX_AGE + 1);
        announcement.sign(&key.to_bytes()).expect("sign");
        assert!(announcement.verify().is_err());
    }

    #[test]
    fn future_announcement_rejected() {
        let key = SigningKey::from_bytes(&[10; 32]);
        let public = hex::encode(key.verifying_key().to_bytes());
        let mut hasher = Sha256::new();
        hasher.update(key.verifying_key().to_bytes());
        let identity = hex::encode(hasher.finalize());
        let mut announcement = PeerAnnouncement::new(identity, public, "127.0.0.1:4001".into());
        announcement.timestamp = now().saturating_add(MAX_SKEW + 1);
        announcement.sign(&key.to_bytes()).expect("sign");
        assert!(announcement.verify().is_err());
    }

    #[test]
    fn ipv6_multicast_constant_correct() {
        assert_eq!(
            DISCOVERY_MULTICAST_V6,
            "ff02::2a99"
                .parse::<Ipv6Addr>()
                .expect("IPv6 multicast address")
        );
    }

    #[test]
    fn ipv4_discovery_still_works() {
        assert_eq!(DISCOVERY_MULTICAST, DISCOVERY_MULTICAST_V4);
        assert_eq!(DISCOVERY_PORT, 39_701);
    }

    #[tokio::test]
    async fn dual_stack_start_ok() {
        let key = SigningKey::from_bytes(&[11; 32]);
        let public = hex::encode(key.verifying_key().to_bytes());
        let mut hasher = Sha256::new();
        hasher.update(key.verifying_key().to_bytes());
        let identity = hex::encode(hasher.finalize());
        let (discovery, _receiver) = PeerDiscovery::start_on_port(
            identity,
            public,
            key.to_bytes(),
            "127.0.0.1:4001".into(),
            0,
        )
        .await
        .expect("discovery start");
        discovery.stop().await.expect("discovery stop");
    }

    #[tokio::test]
    async fn dedup_by_identity() {
        let key = SigningKey::from_bytes(&[12; 32]);
        let public = hex::encode(key.verifying_key().to_bytes());
        let mut hasher = Sha256::new();
        hasher.update(key.verifying_key().to_bytes());
        let identity = hex::encode(hasher.finalize());
        let mut announcement = PeerAnnouncement::new(identity, public, "127.0.0.1:4002".into());
        announcement.sign(&key.to_bytes()).expect("sign");
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let mut seen = HashSet::new();
        forward_announcement(announcement.clone(), "other-peer", &mut seen, &peer_tx);
        forward_announcement(announcement, "other-peer", &mut seen, &peer_tx);
        assert!(peer_rx.recv().await.is_some());
        assert!(peer_rx.try_recv().is_err());
    }
}
