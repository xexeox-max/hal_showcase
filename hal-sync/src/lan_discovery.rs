use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hal_storage::{ClientStorage, StoredPeer};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex};

use crate::peer_directory::{PeerDirectory, DEFAULT_MAX_ENTRIES};
use crate::runtime::HomeRuntimeState;
use crate::NodeId;

const DISCOVERY_PORT: u16 = 4002;
const MAX_PACKET_LEN: usize = 8192;
const ANNOUNCEMENT_TTL_SECS: u64 = 90;
const MAX_AVATAR_THUMBNAIL_BYTES: usize = 4096;
pub const TCP_PEER_PORT: u16 = 4001;
#[derive(Clone)]
pub struct LanDiscovery {
    socket: Arc<UdpSocket>,
    identity_id: String,
    public_key: [u8; 32],
    signing_key: SigningKey,
    home_state: Arc<Mutex<HomeRuntimeState>>,
    tcp_port: u16,
    peer_directory: Arc<Mutex<PeerDirectory>>,
    storage: Option<Arc<StdMutex<ClientStorage>>>,
    discovered_peers: Arc<Mutex<HashMap<String, DiscoveredLanPeer>>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredLanPeer {
    pub identity_id: String,
    pub public_key: String,
    pub address: String,
    pub last_seen: u64,
    pub nickname: String,
    pub avatar_thumbnail: Option<String>,
    pub matched_circle_ids: Vec<String>,
    pub trust_level: Option<String>,
    pub is_my_device: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LanAnnouncement {
    identity_id: String,
    public_key: String,
    address: String,
    home_id: String,
    issued_at: u64,
    home_proof: String,
    nickname: String,
    avatar_thumbnail: Option<String>,
    circle_ids: Vec<String>,
    circle_proofs: Vec<CircleProof>,
    signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CircleProof {
    circle_id: String,
    hmac: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedAnnouncement<'a> {
    identity_id: &'a str,
    public_key: &'a str,
    address: &'a str,
    home_id: &'a str,
    issued_at: u64,
    home_proof: &'a str,
    nickname: &'a str,
    avatar_thumbnail: &'a Option<String>,
    circle_ids: &'a [String],
    circle_proofs: &'a [CircleProof],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CircleMacInput<'a> {
    identity_id: &'a str,
    public_key: &'a str,
    address: &'a str,
    home_id: &'a str,
    issued_at: u64,
    home_proof: &'a str,
    nickname: &'a str,
    avatar_thumbnail: &'a Option<String>,
    circle_id: &'a str,
}

impl LanDiscovery {
    pub async fn bind(
        identity_id: String,
        public_key_hex: &str,
        signing_key: SigningKey,
        home_state: Arc<Mutex<HomeRuntimeState>>,
        tcp_port: u16,
        peer_directory: Arc<Mutex<PeerDirectory>>,
        storage: Option<Arc<StdMutex<ClientStorage>>>,
    ) -> Result<Self> {
        let public_key: [u8; 32] = hex::decode(public_key_hex)
            .context("invalid LAN discovery public key")?
            .try_into()
            .map_err(|_| anyhow!("LAN discovery public key must be 32 bytes"))?;
        let socket = UdpSocket::bind(("0.0.0.0", DISCOVERY_PORT))
            .await
            .context("failed to bind LAN discovery UDP socket")?;
        socket
            .set_broadcast(true)
            .context("failed to enable UDP broadcast")?;

        Ok(Self {
            socket: Arc::new(socket),
            identity_id,
            public_key,
            signing_key,
            home_state,
            tcp_port,
            peer_directory,
            storage,
            discovered_peers: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn broadcast_my_address(&self) -> Result<usize> {
        let (local_ip, broadcast_ip) = local_ipv4_address()?;
        let address = SocketAddr::new(IpAddr::V4(local_ip), self.tcp_port);
        let (home_id, home_key) = self.local_home_material().await;
        let (nickname, avatar_thumbnail, circles) = self.local_profile_and_circles()?;
        let packet = build_packet(
            &self.identity_id,
            &self.public_key,
            &self.signing_key,
            address,
            home_id,
            home_key,
            unix_now(),
            nickname,
            avatar_thumbnail,
            &circles,
        )?;

        let sent = self
            .socket
            .send_to(
                &packet,
                SocketAddr::new(IpAddr::V4(broadcast_ip), DISCOVERY_PORT),
            )
            .await
            .context("failed to send LAN discovery broadcast")?;
        log::info!(
            "lan_discovery: broadcast sent from {local_ip}:{}",
            self.tcp_port
        );
        Ok(sent)
    }

    pub async fn run(self, mut shutdown: oneshot::Receiver<()>) {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        let mut packet = [0u8; MAX_PACKET_LEN];
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                _ = interval.tick() => {
                    if let Err(error) = self.broadcast_my_address().await {
                        log::warn!("lan_discovery: broadcast failed: {error:#}");
                    }
                }
                received = self.socket.recv_from(&mut packet) => {
                    match received {
                        Ok((length, source)) => {
                            if let Err(error) = self.process_packet(&packet[..length], source).await {
                                log::debug!("lan_discovery: rejected announcement from {source}: {error:#}");
                            }
                        }
                        Err(error) => {
                            log::error!("lan_discovery: UDP receive failed: {error}");
                            break;
                        }
                    }
                }
            }
        }
    }

    async fn process_packet(&self, packet: &[u8], source: SocketAddr) -> Result<()> {
        let announcement = parse_announcement(packet, source, unix_now())?;
        if announcement.identity_id == self.identity_id {
            return Ok(());
        }
        let now = unix_now();
        let local_circles = self
            .storage
            .as_ref()
            .map(|storage| {
                storage
                    .lock()
                    .map_err(|error| anyhow!("client storage lock poisoned: {error}"))?
                    .discovery_circles()
                    .map_err(|error| anyhow!("failed to load local circles: {error}"))
            })
            .transpose()?
            .unwrap_or_default();
        let local_circles_by_id = local_circles
            .iter()
            .map(|circle| (circle.id.as_str(), circle))
            .collect::<std::collections::HashMap<_, _>>();
        let mut matched_circles = Vec::new();
        for proof in &announcement.circle_proofs {
            let Some(circle) = local_circles_by_id.get(proof.circle_id.as_str()) else {
                continue;
            };
            if verify_circle_proof(&announcement, proof, &circle.secret).is_err() {
                log::warn!(
                    "Discovery: invalid HMAC for circle_id {}, possible spoofing",
                    proof.circle_id
                );
                return Ok(());
            }
            matched_circles.push((
                circle.id.clone(),
                circle.trust_level.clone(),
                circle.name.clone(),
            ));
        }
        let mut matched_circle_ids = matched_circles
            .iter()
            .map(|(id, _, _)| id.clone())
            .collect::<Vec<_>>();
        matched_circle_ids.sort();
        let trust_level = matched_circles
            .iter()
            .map(|(_, trust, _)| trust.as_str())
            .min_by_key(|trust| match *trust {
                "AUTO" => 0,
                "ASK" => 1,
                _ => 2,
            })
            .map(str::to_string);
        let has_matching_circle = !matched_circle_ids.is_empty();
        let (local_home_id, local_home_key) = self.local_home_material().await;
        let home_authenticated = announcement.home_id == local_home_id
            && verify_home_proof(&announcement, &local_home_key).is_ok();
        let is_my_device = home_authenticated
            && matched_circles.iter().any(|(_, trust, name)| {
                trust == "AUTO"
                    && matches!(
                        name.trim().to_ascii_lowercase().as_str(),
                        "дом" | "home" | "home circle"
                    )
            });
        if home_authenticated {
            log::info!("LAN Discovery: found matching home_id from {}", source.ip());
        } else {
            log::debug!(
                "LAN Discovery: announcement from {} is not authenticated for this Home",
                source.ip(),
            );
        }
        let discovered = DiscoveredLanPeer {
            identity_id: announcement.identity_id.clone(),
            public_key: announcement.public_key.clone(),
            address: announcement.address.clone(),
            last_seen: now,
            nickname: announcement.nickname.clone(),
            avatar_thumbnail: announcement.avatar_thumbnail.clone(),
            matched_circle_ids,
            trust_level,
            is_my_device,
        };
        self.discovered_peers
            .lock()
            .await
            .insert(announcement.identity_id.clone(), discovered);
        if !has_matching_circle {
            log::info!("Social Discovery: found {}", announcement.nickname);
        }
        log::info!(
            "lan_discovery: received from {} at {source}",
            announcement.identity_id
        );

        let updated = self
            .peer_directory
            .lock()
            .await
            .record_lan_discovery(
                announcement.address.parse()?,
                announcement.identity_id.clone(),
                announcement.public_key.clone(),
                now,
            )
            .map_err(|error| anyhow!("failed to update peer directory: {error:?}"))?;
        if !updated {
            let pinned_public_key = match self.storage.as_ref() {
                Some(storage) => {
                    let storage = storage
                        .lock()
                        .map_err(|error| anyhow!("client storage lock poisoned: {error}"))?;
                    storage
                        .peer_registry()
                        .public_key_for_identity(&announcement.identity_id, now)
                        .context("failed to check pinned peer identity")?
                }
                None => None,
            };
            if pinned_public_key.as_deref() != Some(announcement.public_key.as_str()) {
                log::debug!(
                    "lan_discovery: ignored unpinned peer {}",
                    announcement.identity_id
                );
                return Ok(());
            }
            self.peer_directory
                .lock()
                .await
                .record_pinned_lan_discovery(
                    announcement.address.parse()?,
                    announcement.identity_id.clone(),
                    announcement.public_key.clone(),
                    now,
                )
                .map_err(|error| anyhow!("failed to add pinned LAN peer: {error:?}"))?;
        }

        if is_my_device {
            if let Some(storage) = self.storage.as_ref() {
                if let Err(error) = persist_address(
                    storage,
                    &announcement.identity_id,
                    &announcement.public_key,
                    announcement.address.clone(),
                ) {
                    log::warn!(
                        "lan_discovery: failed to persist updated address for {}: {error:#}",
                        announcement.identity_id
                    );
                }
            }
        }
        log::info!(
            "lan_discovery: updated address for {} to {}",
            announcement.identity_id,
            announcement.address
        );
        Ok(())
    }

    pub async fn discovered_peers(&self) -> Vec<DiscoveredLanPeer> {
        let now = unix_now();
        let mut peers = self.discovered_peers.lock().await;
        peers.retain(|_, peer| now.saturating_sub(peer.last_seen) <= ANNOUNCEMENT_TTL_SECS);
        let mut peers = peers.values().cloned().collect::<Vec<_>>();
        peers.sort_by(|left, right| left.identity_id.cmp(&right.identity_id));
        peers
    }

    #[cfg(debug_assertions)]
    async fn local_home_material(&self) -> (String, [u8; 32]) {
        (
            "test-home".to_string(),
            Sha256::digest(b"HAL debug LAN discovery test-home v1").into(),
        )
    }

    #[cfg(not(debug_assertions))]
    async fn local_home_material(&self) -> (String, [u8; 32]) {
        if let Some(secret) = self.home_state.lock().await.home_secret.as_ref() {
            return (
                format!("home:{}", hex::encode(Sha256::digest(secret.as_bytes()))),
                *secret.as_bytes(),
            );
        }
        let key: [u8; 32] =
            Sha256::digest(format!("HAL unlinked LAN identity:{}", self.identity_id)).into();
        (format!("unlinked:{}", self.identity_id), key)
    }

    fn local_profile_and_circles(
        &self,
    ) -> Result<(String, Option<String>, Vec<(String, [u8; 32])>)> {
        let Some(storage) = self.storage.as_ref() else {
            return Ok(("HAL user".to_string(), None, Vec::new()));
        };
        let storage = storage
            .lock()
            .map_err(|error| anyhow!("client storage lock poisoned: {error}"))?;
        let nickname = storage
            .get_setting("profile_display_name")?
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "HAL user".to_string());
        let nickname = nickname.trim().to_string();
        let nickname = nickname.chars().take(64).collect::<String>();
        let avatar_thumbnail =
            storage
                .get_setting("profile_avatar_thumbnail_b64")?
                .filter(|encoded| {
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
                        .is_ok_and(|bytes| {
                            !bytes.is_empty() && bytes.len() <= MAX_AVATAR_THUMBNAIL_BYTES
                        })
                });
        let circles = storage
            .discovery_circles()?
            .into_iter()
            .map(|circle| (circle.id, circle.secret))
            .collect();
        Ok((nickname, avatar_thumbnail, circles))
    }
}

fn build_packet(
    identity_id: &str,
    public_key: &[u8; 32],
    signing_key: &SigningKey,
    address: SocketAddr,
    home_id: String,
    home_key: [u8; 32],
    issued_at: u64,
    nickname: String,
    avatar_thumbnail: Option<String>,
    circles: &[(String, [u8; 32])],
) -> Result<Vec<u8>> {
    let public_key_hex = hex::encode(public_key);
    let address = address.to_string();
    let home_proof = create_home_proof(
        identity_id,
        &public_key_hex,
        &address,
        &home_id,
        issued_at,
        &home_key,
    )?;
    let mut circle_ids = circles.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>();
    circle_ids.sort();
    circle_ids.dedup();
    let mut circle_proofs = Vec::with_capacity(circle_ids.len());
    for (circle_id, secret) in circles {
        circle_proofs.push(CircleProof {
            circle_id: circle_id.clone(),
            hmac: create_circle_proof(
                identity_id,
                &public_key_hex,
                &address,
                &home_id,
                issued_at,
                &home_proof,
                &nickname,
                &avatar_thumbnail,
                circle_id,
                secret,
            )?,
        });
    }
    circle_proofs.sort_by(|left, right| left.circle_id.cmp(&right.circle_id));
    let payload = signing_payload(
        identity_id,
        &public_key_hex,
        &address,
        &home_id,
        issued_at,
        &home_proof,
        &nickname,
        &avatar_thumbnail,
        &circle_ids,
        &circle_proofs,
    )?;
    let announcement = LanAnnouncement {
        identity_id: identity_id.to_string(),
        public_key: public_key_hex,
        address,
        home_id,
        issued_at,
        home_proof,
        nickname,
        avatar_thumbnail,
        circle_ids,
        circle_proofs,
        signature: hex::encode(signing_key.sign(&payload).to_bytes()),
    };
    serde_json::to_vec(&announcement).context("failed to serialize LAN discovery announcement")
}

fn parse_announcement(packet: &[u8], source: SocketAddr, now: u64) -> Result<LanAnnouncement> {
    if packet.is_empty() || packet.len() > MAX_PACKET_LEN {
        return Err(anyhow!("invalid LAN discovery packet"));
    }
    let announcement: LanAnnouncement =
        serde_json::from_slice(packet).context("invalid LAN discovery announcement JSON")?;
    if announcement.home_id.is_empty() || announcement.home_id.len() > 128 {
        return Err(anyhow!("invalid LAN discovery home_id"));
    }
    if announcement.nickname.trim().is_empty()
        || announcement.nickname.chars().count() > 64
        || announcement.nickname.chars().any(char::is_control)
        || announcement.circle_ids.len() > 32
        || announcement.circle_proofs.len() > 32
        || announcement.circle_ids.len() != announcement.circle_proofs.len()
    {
        return Err(anyhow!("invalid LAN discovery profile metadata"));
    }
    if let Some(avatar) = &announcement.avatar_thumbnail {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(avatar)
            .context("invalid LAN discovery avatar thumbnail encoding")?;
        if bytes.is_empty() || bytes.len() > MAX_AVATAR_THUMBNAIL_BYTES {
            return Err(anyhow!("invalid LAN discovery avatar thumbnail size"));
        }
    }
    let mut circle_ids = announcement.circle_ids.clone();
    circle_ids.sort();
    circle_ids.dedup();
    if circle_ids.len() != announcement.circle_ids.len()
        || announcement
            .circle_proofs
            .iter()
            .map(|proof| proof.circle_id.as_str())
            .collect::<Vec<_>>()
            != announcement
                .circle_ids
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        || announcement.circle_proofs.iter().any(|proof| {
            proof.circle_id.is_empty()
                || proof.circle_id.len() > 128
                || proof.hmac.len() != 64
                || !proof.hmac.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return Err(anyhow!("invalid LAN discovery circle proofs"));
    }
    if now.saturating_sub(announcement.issued_at) > ANNOUNCEMENT_TTL_SECS
        || announcement.issued_at > now.saturating_add(30)
    {
        return Err(anyhow!(
            "LAN discovery announcement is expired or from the future"
        ));
    }
    let public_key_bytes: [u8; 32] = hex::decode(&announcement.public_key)
        .context("invalid LAN discovery public key encoding")?
        .try_into()
        .map_err(|_| anyhow!("LAN discovery public key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
        .context("invalid LAN discovery verifying key")?;
    if NodeId::from_public_key(&verifying_key).to_hex() != announcement.identity_id {
        return Err(anyhow!("LAN discovery identity does not match public key"));
    }
    let address: SocketAddr = announcement
        .address
        .parse()
        .context("invalid LAN discovery transport address")?;
    if source.ip() != address.ip() || !address.is_ipv4() {
        return Err(anyhow!("announced IP does not match packet source"));
    }
    if address.port() == 0 {
        return Err(anyhow!("invalid announced TCP port"));
    }
    let signature_bytes: [u8; 64] = hex::decode(&announcement.signature)
        .context("invalid LAN discovery signature encoding")?
        .try_into()
        .map_err(|_| anyhow!("LAN discovery signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&signature_bytes);
    let payload = signing_payload(
        &announcement.identity_id,
        &announcement.public_key,
        &announcement.address,
        &announcement.home_id,
        announcement.issued_at,
        &announcement.home_proof,
        &announcement.nickname,
        &announcement.avatar_thumbnail,
        &announcement.circle_ids,
        &announcement.circle_proofs,
    )?;
    verifying_key
        .verify(&payload, &signature)
        .context("invalid LAN discovery signature")?;
    Ok(announcement)
}

fn signing_payload(
    identity_id: &str,
    public_key: &str,
    address: &str,
    home_id: &str,
    issued_at: u64,
    home_proof: &str,
    nickname: &str,
    avatar_thumbnail: &Option<String>,
    circle_ids: &[String],
    circle_proofs: &[CircleProof],
) -> Result<Vec<u8>> {
    serde_json::to_vec(&SignedAnnouncement {
        identity_id,
        public_key,
        address,
        home_id,
        issued_at,
        home_proof,
        nickname,
        avatar_thumbnail,
        circle_ids,
        circle_proofs,
    })
    .context("failed to serialize signed LAN discovery payload")
}

fn create_circle_proof(
    identity_id: &str,
    public_key: &str,
    address: &str,
    home_id: &str,
    issued_at: u64,
    home_proof: &str,
    nickname: &str,
    avatar_thumbnail: &Option<String>,
    circle_id: &str,
    secret: &[u8; 32],
) -> Result<String> {
    let payload = serde_json::to_vec(&CircleMacInput {
        identity_id,
        public_key,
        address,
        home_id,
        issued_at,
        home_proof,
        nickname,
        avatar_thumbnail,
        circle_id,
    })?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
        .map_err(|error| anyhow!("invalid circle HMAC secret: {error}"))?;
    mac.update(&payload);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn verify_circle_proof(
    announcement: &LanAnnouncement,
    proof: &CircleProof,
    secret: &[u8; 32],
) -> Result<()> {
    let payload = serde_json::to_vec(&CircleMacInput {
        identity_id: &announcement.identity_id,
        public_key: &announcement.public_key,
        address: &announcement.address,
        home_id: &announcement.home_id,
        issued_at: announcement.issued_at,
        home_proof: &announcement.home_proof,
        nickname: &announcement.nickname,
        avatar_thumbnail: &announcement.avatar_thumbnail,
        circle_id: &proof.circle_id,
    })?;
    let proof_bytes = hex::decode(&proof.hmac).context("invalid circle HMAC encoding")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
        .map_err(|error| anyhow!("invalid circle HMAC secret: {error}"))?;
    mac.update(&payload);
    mac.verify_slice(&proof_bytes)
        .context("circle HMAC does not match local secret")
}

fn create_home_proof(
    identity_id: &str,
    public_key: &str,
    address: &str,
    home_id: &str,
    issued_at: u64,
    home_key: &[u8; 32],
) -> Result<String> {
    let payload = format!(
        "HAL-LAN-HOME-PROOF-v1\n{identity_id}\n{public_key}\n{address}\n{home_id}\n{issued_at}"
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(home_key)
        .map_err(|error| anyhow!("invalid LAN home proof key: {error}"))?;
    mac.update(payload.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn verify_home_proof(announcement: &LanAnnouncement, home_key: &[u8; 32]) -> Result<()> {
    let payload = format!(
        "HAL-LAN-HOME-PROOF-v1\n{}\n{}\n{}\n{}\n{}",
        announcement.identity_id,
        announcement.public_key,
        announcement.address,
        announcement.home_id,
        announcement.issued_at,
    );
    let proof = hex::decode(&announcement.home_proof).context("invalid LAN home proof encoding")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(home_key)
        .map_err(|error| anyhow!("invalid LAN home proof key: {error}"))?;
    mac.update(payload.as_bytes());
    mac.verify_slice(&proof)
        .context("LAN home proof does not match local home")
}

fn local_ipv4_address() -> Result<(Ipv4Addr, Ipv4Addr)> {
    let mut candidates = if_addrs::get_if_addrs()
        .context("failed to enumerate network interfaces")?
        .into_iter()
        .filter(|interface| {
            interface.is_oper_up() && !interface.is_loopback() && !interface.is_p2p()
        })
        .filter_map(|interface| match interface.addr {
            if_addrs::IfAddr::V4(address) => address
                .broadcast
                .filter(|_| !address.ip.is_unspecified())
                .map(|broadcast| (address.ip, broadcast, interface.name)),
            if_addrs::IfAddr::V6(_) => None,
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(address, _, name)| {
        let virtual_interface = name.starts_with("docker")
            || name.starts_with("br-")
            || name.starts_with("virbr")
            || name.starts_with("veth")
            || name.starts_with("podman");
        (
            virtual_interface,
            !address.is_private(),
            address.is_link_local(),
        )
    });
    candidates
        .into_iter()
        .next()
        .map(|(address, broadcast, _)| (address, broadcast))
        .ok_or_else(|| anyhow!("no active IPv4 LAN interface with broadcast support"))
}

fn persist_address(
    storage: &Arc<StdMutex<ClientStorage>>,
    identity_id: &str,
    public_key: &str,
    transport_address: String,
) -> Result<()> {
    let now = unix_now();
    let storage = storage
        .lock()
        .map_err(|error| anyhow!("client storage lock poisoned: {error}"))?;
    let registry = storage.peer_registry();
    let mut matching_peers = registry
        .active_peers(now, DEFAULT_MAX_ENTRIES)
        .context("failed to list known peers")?
        .into_iter()
        .filter(|peer| peer.identity_id == identity_id && peer.public_key == public_key)
        .collect::<Vec<_>>();
    if matching_peers.is_empty() {
        matching_peers.push(StoredPeer {
            peer_id: identity_id.to_string(),
            identity_id: identity_id.to_string(),
            public_key: public_key.to_string(),
            transport_address,
            last_seen: now,
            expires_at: now.saturating_add(5 * 60),
            latency_ms: None,
            failure_count: 0,
        });
    } else {
        for peer in &mut matching_peers {
            peer.transport_address = transport_address.clone();
            peer.last_seen = now;
            peer.expires_at = now.saturating_add(5 * 60);
            peer.failure_count = 0;
        }
    }
    for peer in &matching_peers {
        registry
            .upsert(peer)
            .context("failed to persist LAN discovery address")?;
    }
    Ok(())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn announcement_packet_includes_home_id_and_verifies_signature() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let identity_id = NodeId::from_public_key(&signing_key.verifying_key()).to_hex();
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 55)), 4001);
        let packet = build_packet(
            &identity_id,
            &signing_key.verifying_key().to_bytes(),
            &signing_key,
            address,
            "test-home".to_string(),
            Sha256::digest(b"HAL debug LAN discovery test-home v1").into(),
            100,
            "Test device".to_string(),
            None,
            &[],
        )
        .expect("packet");
        let parsed = parse_announcement(&packet, address, 100).expect("valid announcement");

        assert_eq!(parsed.home_id, "test-home");
        assert_eq!(parsed.address, address.to_string());
    }

    #[test]
    fn rejects_announcement_with_mismatched_source_ip() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 55)), TCP_PEER_PORT);
        let identity_id = NodeId::from_public_key(&signing_key.verifying_key()).to_hex();
        let packet = build_packet(
            &identity_id,
            &signing_key.verifying_key().to_bytes(),
            &signing_key,
            address,
            "test-home".to_string(),
            Sha256::digest(b"HAL debug LAN discovery test-home v1").into(),
            100,
            "Test device".to_string(),
            None,
            &[],
        )
        .expect("packet");
        let result = parse_announcement(
            &packet,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 54)), 12345),
            100,
        );
        assert!(result.is_err());
    }

    #[test]
    fn rejects_tampered_home_id() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 55)), TCP_PEER_PORT);
        let identity_id = NodeId::from_public_key(&signing_key.verifying_key()).to_hex();
        let packet = build_packet(
            &identity_id,
            &signing_key.verifying_key().to_bytes(),
            &signing_key,
            address,
            "test-home".to_string(),
            Sha256::digest(b"HAL debug LAN discovery test-home v1").into(),
            100,
            "Test device".to_string(),
            None,
            &[],
        )
        .expect("packet");
        let mut announcement: LanAnnouncement =
            serde_json::from_slice(&packet).expect("announcement");
        announcement.home_id = "other-home".to_string();
        let tampered_packet = serde_json::to_vec(&announcement).expect("serialize");

        assert!(parse_announcement(&tampered_packet, address, 100).is_err());
    }

    #[test]
    fn circle_hmac_authenticates_profile_and_circle_membership() {
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let identity_id = NodeId::from_public_key(&signing_key.verifying_key()).to_hex();
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 60)), TCP_PEER_PORT);
        let circle_secret = [0x73; 32];
        let packet = build_packet(
            &identity_id,
            &signing_key.verifying_key().to_bytes(),
            &signing_key,
            address,
            "test-home".to_string(),
            Sha256::digest(b"HAL debug LAN discovery test-home v1").into(),
            100,
            "Test device".to_string(),
            None,
            &[("circle-home".to_string(), circle_secret)],
        )
        .expect("packet");
        let parsed = parse_announcement(&packet, address, 100).expect("signed packet");
        let proof = parsed.circle_proofs.first().expect("circle proof");

        assert!(verify_circle_proof(&parsed, proof, &circle_secret).is_ok());
        assert!(verify_circle_proof(&parsed, proof, &[0x74; 32]).is_err());
    }
}
