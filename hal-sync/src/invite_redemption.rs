use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hal_protocol::invite::RedeemableInvite;
use hal_settings::NetworkTrustPolicy;
use hal_storage::invite_storage::{
    read_invite_proof, InviteRecord, RedemptionReceipt, TokenHash, TOKEN_HASH_DOMAIN,
};

use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::sync::{oneshot, Mutex as TokioMutex};
use tokio::time::timeout;

use crate::dht::invite::record_matches_token;
use crate::dht::nested_proof::{
    sign_redemption_receipt, verify_nested_proof, GenesisProvider, NestedProof, ProofHop,
};
use crate::dht::routing::RoutingTable;
use crate::dht::NodeId;
use crate::journal::{InviteRedemptionRequestPayload, InviteRedemptionResponsePayload, SyncEvent};
use crate::pinning::KnownHosts;
use crate::runtime_context::RuntimeContext;
use crate::transport::{send_envelope_secure_with_stream_kind_and_metrics, SyncEnvelope};

const REDEMPTION_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum InviteRedemptionError {
    #[error("invite issuer does not support redemption events")]
    UnsupportedByPeer,
}

#[async_trait]
pub trait InviteRedemptionTransport: Send + Sync {
    async fn send_event(&self, recipient_node_id: &[u8; 32], event: &SyncEvent) -> Result<()>;
}

pub struct PendingInviteRedemption {
    pub issuer_hex: String,
    pub token_hash: [u8; 32],
    pub response_tx: oneshot::Sender<Result<RedemptionReceipt, String>>,
}

pub struct DirectInviteRedemptionTransport {
    signing_key: SigningKey,
    hosts: Arc<StdMutex<KnownHosts>>,
    routing: Arc<TokioMutex<RoutingTable>>,
    trust_policy: NetworkTrustPolicy,
    abuse_metrics: Arc<crate::abuse_metrics::AbuseMetrics>,
}

impl DirectInviteRedemptionTransport {
    pub fn new(
        signing_key: SigningKey,
        hosts: Arc<StdMutex<KnownHosts>>,
        routing: Arc<TokioMutex<RoutingTable>>,
        trust_policy: NetworkTrustPolicy,
        abuse_metrics: Arc<crate::abuse_metrics::AbuseMetrics>,
    ) -> Arc<dyn InviteRedemptionTransport> {
        Arc::new(Self {
            signing_key,
            hosts,
            routing,
            trust_policy,
            abuse_metrics,
        })
    }
}

#[async_trait]
impl InviteRedemptionTransport for DirectInviteRedemptionTransport {
    async fn send_event(&self, recipient_node_id: &[u8; 32], event: &SyncEvent) -> Result<()> {
        let peer = self
            .routing
            .lock()
            .await
            .all_peers()
            .into_iter()
            .find(|peer| peer.node_id.as_bytes() == recipient_node_id)
            .cloned()
            .context("invite redemption recipient is not in the routing table")?;
        let endpoint = peer
            .best_endpoint()
            .context("invite redemption recipient has no known online endpoint")?
            .address
            .clone();
        let peer_key: [u8; 32] = hex::decode(&peer.public_key)
            .context("decode invite redemption recipient public key")?
            .try_into()
            .map_err(|_| anyhow!("invite redemption recipient public key must be 32 bytes"))?;
        let mut signed_event = event.clone();
        signed_event.timestamp = crate::dht::prekey_cache::unix_now();
        signed_event.sign(&self.signing_key.to_bytes())?;
        let envelope = SyncEnvelope::new(
            hex::encode(Sha256::digest(self.signing_key.verifying_key().to_bytes())),
            hex::encode(self.signing_key.verifying_key().to_bytes()),
            vec![signed_event],
        );
        send_envelope_secure_with_stream_kind_and_metrics(
            &endpoint,
            &envelope,
            &self.signing_key,
            Arc::clone(&self.hosts),
            Some(VerifyingKey::from_bytes(&peer_key)?),
            self.trust_policy.clone(),
            crate::mux::StreamKind::Sync,
            Arc::clone(&self.abuse_metrics),
        )
        .await
    }
}

pub struct GenesisProviderImpl;

impl GenesisProvider for GenesisProviderImpl {
    fn is_genesis(&self, node_id_hex: &str) -> bool {
        if node_id_hex.len() != 64 {
            return false;
        }
        let mut node_id = [0; 32];
        if hex::decode_to_slice(node_id_hex, &mut node_id).is_err() {
            return false;
        }
        crate::dht::invite_registry::is_genesis(&node_id)
    }
}

pub async fn request_redemption(
    ctx: &Arc<RuntimeContext>,
    token: &[u8],
    invite: &RedeemableInvite,
) -> Result<RedemptionReceipt> {
    if token.len() != 16 {
        return Err(anyhow!("v2 invite token must be 16 bytes"));
    }
    invite.verify(crate::runtime::unix_now())?;
    let link_token = hex::decode(&invite.token_hex).context("decode v2 invite token")?;
    if link_token != token {
        return Err(anyhow!("supplied token does not match the v2 invite link"));
    }
    let token_hash = hash_token(token);
    let issuer_node_id = NodeId::from_bytes(Sha256::digest(invite.issuer_public_key).into());
    ensure_peer_supports_invite_redemption(ctx, &issuer_node_id, &token_hash).await?;
    let transport = ctx
        .invite_redemption_transport
        .as_ref()
        .context("invite redemption transport is unavailable")?;
    let mut nonce = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let (response_tx, response_rx) = oneshot::channel();
    {
        let mut pending = ctx.pending_invite_redemptions.lock().await;
        if pending.contains_key(&nonce) {
            return Err(anyhow!("invite redemption nonce collision"));
        }
        pending.insert(
            nonce,
            PendingInviteRedemption {
                issuer_hex: invite.issuer_hex.clone(),
                token_hash,
                response_tx,
            },
        );
    }
    let request = InviteRedemptionRequestPayload {
        token_hex: hex::encode(token),
        redeem_request_nonce: nonce,
    };
    let event = SyncEvent::invite_redemption_request(&request)?;
    if let Err(error) = transport
        .send_event(issuer_node_id.as_bytes(), &event)
        .await
    {
        ctx.pending_invite_redemptions.lock().await.remove(&nonce);
        return Err(error).context("send invite redemption request");
    }

    match timeout(REDEMPTION_RESPONSE_TIMEOUT, response_rx).await {
        Ok(Ok(Ok(receipt))) => Ok(receipt),
        Ok(Ok(Err(error))) => Err(anyhow!("invite redemption rejected: {error}")),
        Ok(Err(_)) => Err(anyhow!("invite redemption response channel closed")),
        Err(_) => {
            ctx.pending_invite_redemptions.lock().await.remove(&nonce);
            Err(anyhow!("invite redemption response timed out"))
        }
    }
}

async fn ensure_peer_supports_invite_redemption(
    ctx: &RuntimeContext,
    peer: &NodeId,
    token_hash: &[u8; 32],
) -> std::result::Result<(), InviteRedemptionError> {
    if ctx
        .session_store
        .lock()
        .await
        .peer_supports_invite_redemption(peer)
    {
        return Ok(());
    }
    log::warn!(
        "rejecting invite redemption for token_hash={} from unsupported peer={}",
        hex::encode(token_hash),
        peer.to_hex()
    );
    Err(InviteRedemptionError::UnsupportedByPeer)
}

fn redeem_request_with_cache(
    storage: &mut hal_storage::ClientStorage,
    token_hash: &TokenHash,
    node_id_hex: &str,
    nonce: &[u8],
    now: u64,
    sign_receipt: impl FnOnce() -> [u8; 64],
) -> Result<RedemptionReceipt> {
    if let Some(receipt) = storage
        .read_cached_redemption_atomic(token_hash, nonce)
        .map_err(|error| anyhow!("read cached redemption: {error}"))?
    {
        if receipt.node_id_hex != node_id_hex {
            return Err(hal_storage::invite_storage::RedeemError::NonceReplay.into());
        }
        return Ok(receipt);
    }

    storage
        .redeem_invite_atomic_with_cache_at(token_hash, node_id_hex, nonce, &sign_receipt(), now)
        .map_err(|error| anyhow::Error::new(error).context("atomically redeem invite"))
}

pub async fn handle_invite_redemption_request(
    ctx: &Arc<RuntimeContext>,
    event: &SyncEvent,
    sender_node_id: &[u8; 32],
    sender_key: &VerifyingKey,
    now: u64,
) -> Result<()> {
    let request: InviteRedemptionRequestPayload =
        serde_json::from_str(&event.data).context("parse invite redemption request")?;
    if NodeId::from_public_key(sender_key).as_bytes() != sender_node_id {
        return Err(anyhow!(
            "invite redemption request sender key does not match sender node id"
        ));
    }
    let token = hex::decode(&request.token_hex).context("decode invite redemption token")?;
    if token.len() != 16 {
        return Err(anyhow!("invite redemption token must be 16 bytes"));
    }
    let token_hash = hash_token(&token);
    let storage_arc = ctx
        .storage
        .as_ref()
        .context("durable storage required for invite redemption")?;
    let record = storage_arc
        .lock()
        .map_err(|_| anyhow!("storage lock poisoned"))?
        .read_invite_atomic(&TokenHash::from_bytes(token_hash))?
        .context("invite token is not stored by this issuer")?;
    let local_key = ctx
        .identity_signing_key
        .as_ref()
        .context("local issuer signing key is unavailable")?;
    let local_node_id = NodeId::from_public_key(&local_key.verifying_key());
    if record.issuer_hex != local_node_id.to_hex() {
        return Err(anyhow!("invite record does not belong to the local issuer"));
    }
    if !record_matches_token(&record, &token) {
        return Err(anyhow!("invite token does not match stored token hash"));
    }
    let token_hash_bytes = token_hash;
    let token_hash = TokenHash::from_bytes(token_hash_bytes);
    let redeemer_hex = hex::encode(sender_node_id);
    let cached_receipt = storage_arc
        .lock()
        .map_err(|_| anyhow!("storage lock poisoned"))?
        .read_cached_redemption_atomic(&token_hash, &request.redeem_request_nonce)
        .map_err(|error| anyhow!("read cached redemption: {error}"))?;

    let (receipt, proof) = if let Some(receipt) = cached_receipt {
        if receipt.node_id_hex != redeemer_hex {
            return Err(hal_storage::invite_storage::RedeemError::NonceReplay.into());
        }
        let proof = load_cached_redemption_proof(ctx, &record, &receipt, &local_node_id, now)?;
        (receipt, proof)
    } else {
        let invite = redeemable_from_record(&record, &token)?;
        invite.verify(now).context("verify stored v2 invite")?;
        let issuer_proof = load_issuer_proof(ctx, &local_node_id, now)?;
        let expected_depth = issuer_proof.as_ref().map_or(0, |proof| proof.hops.len());
        if record.chain_depth as usize != expected_depth {
            return Err(anyhow!(
                "invite chain depth does not match issuer proof depth"
            ));
        }
        if let Some(proof) = issuer_proof.as_ref() {
            let expected_parent = proof
                .hops
                .first()
                .map(|hop| TokenHash::from_bytes(hop.token_hash));
            if record.parent_token_hash != expected_parent {
                return Err(anyhow!(
                    "invite parent token does not match issuer's verified proof"
                ));
            }
        } else if !crate::dht::invite_registry::is_genesis(local_node_id.as_bytes()) {
            return Err(anyhow!("non-genesis issuer has no verified invite proof"));
        }

        let mut storage = storage_arc
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        let receipt = redeem_request_with_cache(
            &mut storage,
            &token_hash,
            &redeemer_hex,
            &request.redeem_request_nonce,
            now,
            || sign_redemption_receipt(local_key, token_hash.as_bytes(), sender_node_id, now),
        )?;
        drop(storage);
        let proof = build_redeemer_proof(&record, &receipt, issuer_proof)?;
        (receipt, proof)
    };
    verify_nested_proof(&proof, &GenesisProviderImpl)
        .context("verify assembled redemption proof")?;
    let proof_blob = serde_json::to_vec(&proof).context("serialize redemption proof")?;
    {
        let storage = storage_arc
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        hal_storage::invite_storage::upsert_invite_proof(
            storage.connection(),
            &receipt.node_id_hex,
            &proof_blob,
            receipt.redeemed_at,
        )?;
    }

    ctx.session_store
        .lock()
        .await
        .set_peer_supports_invite_redemption(&NodeId::from_bytes(*sender_node_id), Some(true))
        .context("record invite-redemption capability from authenticated request")?;
    crate::runtime::persist_session_nonfatal(
        ctx,
        &NodeId::from_bytes(*sender_node_id),
        "invite redemption request",
    )
    .await;
    let response_nonce: [u8; 32] = receipt
        .request_nonce
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("stored redemption nonce is not 32 bytes"))?;
    let response = InviteRedemptionResponsePayload {
        token_hash: token_hash_bytes,
        redeem_request_nonce: response_nonce,
        proof,
    };
    let response_event = SyncEvent::invite_redemption_response(&response)?;
    ctx.invite_redemption_transport
        .as_ref()
        .context("invite redemption response transport is unavailable")?
        .send_event(sender_node_id, &response_event)
        .await
        .context("send invite redemption response")
}

pub async fn handle_invite_redemption_response(
    ctx: &Arc<RuntimeContext>,
    event: &SyncEvent,
    sender_node_id: &[u8; 32],
    sender_key: &VerifyingKey,
    now: u64,
) -> Result<()> {
    let response: InviteRedemptionResponsePayload =
        serde_json::from_str(&event.data).context("parse invite redemption response")?;
    if NodeId::from_public_key(sender_key).as_bytes() != sender_node_id {
        return Err(anyhow!(
            "invite redemption response sender key does not match sender node id"
        ));
    }
    let pending = ctx.pending_invite_redemptions.lock().await;
    let expected = pending
        .get(&response.redeem_request_nonce)
        .context("unsolicited invite redemption response")?;
    if expected.token_hash != response.token_hash
        || expected.issuer_hex != hex::encode(sender_node_id)
    {
        return Err(anyhow!(
            "invite redemption response does not match pending request"
        ));
    }
    let local_node_id = NodeId::from_hex(&ctx.identity_id)
        .context("parse local identity for redemption response")?;
    if response.proof.hops.first().map_or(true, |hop| {
        hop.redeemer_node_id_hex != local_node_id.to_hex()
    }) {
        return Err(anyhow!(
            "redemption proof leaf does not identify the local redeemer"
        ));
    }
    let leaf = response
        .proof
        .hops
        .first()
        .context("redemption proof is empty")?;
    if leaf.issuer_hex != hex::encode(sender_node_id) || leaf.token_hash != response.token_hash {
        return Err(anyhow!(
            "redemption proof leaf does not match issuer or token"
        ));
    }
    verify_nested_proof(&response.proof, &GenesisProviderImpl)
        .context("verify invite redemption response proof")?;
    let proof_blob = serde_json::to_vec(&response.proof).context("serialize redemption proof")?;
    let storage_arc = ctx
        .storage
        .as_ref()
        .context("durable storage required to persist redemption proof")?;
    {
        let storage = storage_arc
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        hal_storage::invite_storage::upsert_invite_proof(
            storage.connection(),
            &local_node_id.to_hex(),
            &proof_blob,
            now,
        )?;
    }
    let receipt_nonce = response.redeem_request_nonce.to_vec();
    let receipt = RedemptionReceipt {
        node_id_hex: local_node_id.to_hex(),
        token_hash: TokenHash::from_bytes(response.token_hash),
        issuer_hex: leaf.issuer_hex.clone(),
        redeemed_at: leaf.redeemed_at,
        request_nonce: receipt_nonce,
        signed_receipt: leaf.redemption_signature.to_vec(),
    };
    drop(pending);
    let pending = ctx
        .pending_invite_redemptions
        .lock()
        .await
        .remove(&response.redeem_request_nonce)
        .context("pending invite redemption was cancelled")?;
    pending
        .response_tx
        .send(Ok(receipt))
        .map_err(|_| anyhow!("invite redemption caller is no longer waiting"))?;
    Ok(())
}

pub fn hash_token(token: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TOKEN_HASH_DOMAIN);
    hasher.update(token);
    hasher.finalize().into()
}

fn redeemable_from_record(record: &InviteRecord, token: &[u8]) -> Result<RedeemableInvite> {
    Ok(RedeemableInvite {
        issuer_hex: record.issuer_hex.clone(),
        issuer_public_key: record.issuer_public_key,
        token_hex: hex::encode(token),
        issued_at: record.issued_at,
        expires_at: record.expires_at,
        chain_depth: record.chain_depth,
        parent_token_hash: record
            .parent_token_hash
            .as_ref()
            .map(|hash| *hash.as_bytes()),
        issuance_signature: record.issuance_signature,
    })
}

fn load_issuer_proof(
    ctx: &RuntimeContext,
    issuer: &NodeId,
    now: u64,
) -> Result<Option<NestedProof>> {
    if crate::dht::invite_registry::is_genesis(issuer.as_bytes()) {
        return Ok(None);
    }
    let storage = ctx
        .storage
        .as_ref()
        .context("durable storage required for non-genesis issuer proof")?
        .lock()
        .map_err(|_| anyhow!("storage lock poisoned"))?;
    let proof_blob = read_invite_proof(storage.connection(), &issuer.to_hex())?
        .context("verified invite proof for non-genesis issuer is missing")?;
    let proof: NestedProof =
        serde_json::from_slice(&proof_blob).context("deserialize issuer invite proof")?;
    if proof
        .hops
        .first()
        .map_or(true, |hop| hop.redeemer_node_id_hex != issuer.to_hex())
    {
        return Err(anyhow!("stored issuer proof does not identify its subject"));
    }
    verify_nested_proof(&proof, &GenesisProviderImpl)
        .with_context(|| format!("verify stored issuer proof at {now}"))?;
    Ok(Some(proof))
}

fn load_cached_redemption_proof(
    ctx: &RuntimeContext,
    record: &InviteRecord,
    receipt: &RedemptionReceipt,
    issuer: &NodeId,
    now: u64,
) -> Result<NestedProof> {
    let stored_proof = {
        let storage = ctx
            .storage
            .as_ref()
            .context("durable storage required for cached redemption proof")?
            .lock()
            .map_err(|_| anyhow!("storage lock poisoned"))?;
        read_invite_proof(storage.connection(), &receipt.node_id_hex)?
    };
    let proof = match stored_proof {
        Some(proof_blob) => {
            serde_json::from_slice(&proof_blob).context("deserialize cached redemption proof")?
        }
        None => {
            let issuer_proof = load_issuer_proof(ctx, issuer, now)?;
            build_redeemer_proof(record, receipt, issuer_proof)?
        }
    };
    verify_nested_proof(&proof, &GenesisProviderImpl).context("verify cached redemption proof")?;
    let leaf = proof
        .hops
        .first()
        .context("cached redemption proof is empty")?;
    if leaf.token_hash != *record.token_hash.as_bytes()
        || leaf.issuer_hex != record.issuer_hex
        || leaf.redeemer_node_id_hex != receipt.node_id_hex
        || leaf.redemption_signature.as_slice() != receipt.signed_receipt
    {
        return Err(anyhow!(
            "cached redemption proof does not match its durable receipt"
        ));
    }
    Ok(proof)
}

fn build_redeemer_proof(
    record: &InviteRecord,
    receipt: &RedemptionReceipt,
    issuer_proof: Option<NestedProof>,
) -> Result<NestedProof> {
    let mut proof = NestedProof {
        hops: vec![ProofHop {
            token_hash: *record.token_hash.as_bytes(),
            parent_token_hash: record
                .parent_token_hash
                .as_ref()
                .as_ref()
                .map(|token_hash| *token_hash.as_bytes()),
            issuer_hex: record.issuer_hex.clone(),
            issuer_public_key: record.issuer_public_key,
            issued_at: record.issued_at,
            expires_at: record.expires_at,
            issuance_signature: record.issuance_signature,
            redeemer_node_id_hex: receipt.node_id_hex.clone(),
            redeemed_at: receipt.redeemed_at,
            redemption_signature: receipt
                .signed_receipt
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("stored redemption signature must be 64 bytes"))?,
        }],
    };
    if let Some(issuer_proof) = issuer_proof {
        for hop in issuer_proof.hops {
            proof
                .append_hop(hop)
                .map_err(|error| anyhow!("extend invite proof: {error}"))?;
        }
    }
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_storage() -> (tempfile::TempDir, hal_storage::ClientStorage, TokenHash) {
        let directory = tempdir().expect("create temporary directory");
        let mut storage = hal_storage::ClientStorage::open(
            directory.path().join("invite-redemption.db"),
            &[0x61; 32],
        )
        .expect("open client storage");
        let issuer_public_key = [0x62; 32];
        let token_hash = TokenHash::from_bytes([0x63; 32]);
        let invite = InviteRecord {
            token_hash: token_hash.clone(),
            issuer_hex: hex::encode(Sha256::digest(issuer_public_key)),
            issuer_public_key,
            issuance_signature: [0x64; 64],
            issued_at: 1,
            expires_at: 10_000,
            max_uses: 2,
            current_uses: 0,
            chain_depth: 0,
            parent_token_hash: None,
            revoked_at: None,
        };
        storage
            .insert_invite_atomic(&invite)
            .expect("insert test invite");
        (directory, storage, token_hash)
    }

    #[test]
    fn handle_request_is_idempotent() {
        let (_directory, mut storage, token_hash) = test_storage();
        let nonce = [0x65; 32];
        let redeemer = hex::encode([0x66; 32]);
        let mut sign_calls = 0;

        let first =
            redeem_request_with_cache(&mut storage, &token_hash, &redeemer, &nonce, 100, || {
                sign_calls += 1;
                [0x67; 64]
            })
            .expect("redeem invite");
        let retry =
            redeem_request_with_cache(&mut storage, &token_hash, &redeemer, &nonce, 101, || {
                sign_calls += 1;
                [0x68; 64]
            })
            .expect("return cached redemption");

        assert_eq!(retry, first);
        assert_eq!(sign_calls, 1);
        assert_eq!(
            storage
                .read_invite_atomic(&token_hash)
                .expect("read invite")
                .expect("invite exists")
                .current_uses,
            1
        );
    }

    #[test]
    fn handle_request_rejects_different_nonce_for_redeemed_token() {
        let (_directory, mut storage, token_hash) = test_storage();
        let redeemer = hex::encode([0x69; 32]);
        redeem_request_with_cache(
            &mut storage,
            &token_hash,
            &redeemer,
            &[0x6a; 32],
            100,
            || [0x6b; 64],
        )
        .expect("redeem invite");

        let error = redeem_request_with_cache(
            &mut storage,
            &token_hash,
            &redeemer,
            &[0x6c; 32],
            101,
            || [0x6d; 64],
        )
        .expect_err("different nonce must be rejected");

        assert!(matches!(
            error.downcast_ref::<hal_storage::invite_storage::RedeemError>(),
            Some(hal_storage::invite_storage::RedeemError::NonceReplay)
        ));
    }

    #[tokio::test]
    async fn handle_request_rejects_unsupported_peer() {
        let ctx = crate::runtime_context::tests::test_runtime_context_with_storage(
            None,
            "unsupported-peer-test".to_string(),
        );
        let peer = NodeId::from_bytes([0x6e; 32]);

        let error = ensure_peer_supports_invite_redemption(&ctx, &peer, &[0x6f; 32])
            .await
            .expect_err("unsupported peer must be rejected");

        assert!(matches!(error, InviteRedemptionError::UnsupportedByPeer));
    }
}
