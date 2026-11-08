use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signature, VerifyingKey};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

use crate::dht::invite::MAX_CHAIN_DEPTH;
use crate::dht::revocation::{RevocationOracle, REVOCATION_RETRY_WINDOW_SECS};

pub const ISSUE_DOMAIN: &[u8] = b"HAL-INV-ISSUE-v1\0";
pub const REDEEM_DOMAIN: &[u8] = b"HAL-INV-REDEEM-v1\0";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NestedProof {
    /// Hops ordered from leaf (invitee) to genesis root.
    pub hops: Vec<ProofHop>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProofHop {
    pub token_hash: [u8; 32],
    pub parent_token_hash: Option<[u8; 32]>,
    pub issuer_hex: String,
    pub issuer_public_key: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(with = "signature_bytes_serde")]
    pub issuance_signature: [u8; 64],
    pub redeemer_node_id_hex: String,
    pub redeemed_at: u64,
    #[serde(with = "signature_bytes_serde")]
    pub redemption_signature: [u8; 64],
}

impl NestedProof {
    pub fn append_hop(&mut self, hop: ProofHop) -> Result<(), NestedProofError> {
        let next_depth = self.hops.len() + 1;
        if next_depth > MAX_CHAIN_DEPTH as usize {
            return Err(NestedProofError::DepthExceeded(next_depth, MAX_CHAIN_DEPTH));
        }
        if self
            .hops
            .iter()
            .any(|existing| existing.token_hash == hop.token_hash)
        {
            return Err(NestedProofError::DuplicateTokenHash(self.hops.len()));
        }
        if let Some(last) = self.hops.last() {
            let index = self.hops.len();
            if last.parent_token_hash != Some(hop.token_hash) {
                return Err(NestedProofError::ChainContinuityBroken(index));
            }
            if last.issuer_hex != hop.redeemer_node_id_hex {
                return Err(NestedProofError::ChainOfRedemptionBroken(index - 1));
            }
        }
        self.hops.push(hop);
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NestedProofError {
    #[error("empty proof")]
    Empty,
    #[error("proof depth {0} exceeds MAX_CHAIN_DEPTH {1}")]
    DepthExceeded(usize, u32),
    #[error("duplicate token_hash at hop {0}")]
    DuplicateTokenHash(usize),
    #[error("issuer_hex is not 64 lowercase hex at hop {0}")]
    InvalidIssuerHex(usize),
    #[error("redeemer_node_id_hex is not 64 lowercase hex at hop {0}")]
    InvalidRedeemerHex(usize),
    #[error("SHA256(issuer_public_key) != issuer_hex at hop {0}")]
    PubkeyBindingMismatch(usize),
    #[error("issuance_signature invalid at hop {0}")]
    InvalidIssuanceSignature(usize),
    #[error("redemption_signature invalid at hop {0}")]
    InvalidRedemptionSignature(usize),
    #[error("chain continuity broken at hop {0}")]
    ChainContinuityBroken(usize),
    #[error("invalid v2 chain binding at hop {0}")]
    InvalidChainBinding(usize),
    #[error("chain of redemption broken at hop {0}")]
    ChainOfRedemptionBroken(usize),
    #[error("genesis hop has non-None parent_token_hash")]
    GenesisParentNotNone,
    #[error("genesis issuer not in configured set")]
    GenesisNotTrusted,
    #[error("revocation status unknown at hop {0} (cold-contact fail-closed)")]
    RevocationUnknownColdContact(usize),
    #[error("token at hop {0} is revoked")]
    Revoked(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationPolicy {
    /// Fail-closed: an oracle error rejects the proof.
    ColdContact,
    /// Fail-open with a time-bound retry window.
    Established,
}

pub struct RevocationWindowCache {
    unresolved: Mutex<HashMap<[u8; 32], u64>>,
    now_fn: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl RevocationWindowCache {
    pub fn new() -> Self {
        Self::with_clock(Box::new(unix_now_secs))
    }

    pub fn with_clock(now_fn: Box<dyn Fn() -> u64 + Send + Sync>) -> Self {
        Self {
            unresolved: Mutex::new(HashMap::new()),
            now_fn,
        }
    }

    pub fn record(&self, token_hash: [u8; 32]) -> u64 {
        let now = (self.now_fn)();
        let mut unresolved = self
            .unresolved
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *unresolved.entry(token_hash).or_insert(now)
    }

    pub fn lookup(&self, token_hash: &[u8; 32]) -> Option<u64> {
        self.unresolved
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(token_hash)
            .copied()
    }

    pub fn remove(&self, token_hash: &[u8; 32]) {
        self.unresolved
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(token_hash);
    }

    pub fn prune_expired(&self) -> usize {
        let now = (self.now_fn)();
        let mut unresolved = self
            .unresolved
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = unresolved.len();
        unresolved.retain(|_, inserted_at| {
            now.saturating_sub(*inserted_at) < REVOCATION_RETRY_WINDOW_SECS
        });
        before - unresolved.len()
    }

    fn now(&self) -> u64 {
        (self.now_fn)()
    }

    fn refresh(&self, token_hash: [u8; 32]) -> u64 {
        self.remove(&token_hash);
        self.record(token_hash)
    }
}

impl Default for RevocationWindowCache {
    fn default() -> Self {
        Self::new()
    }
}

pub trait GenesisProvider {
    fn is_genesis(&self, issuer_hex: &str) -> bool;
}

impl GenesisProvider for [&str] {
    fn is_genesis(&self, issuer_hex: &str) -> bool {
        self.iter().any(|hex| *hex == issuer_hex)
    }
}

mod signature_bytes_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(signature: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        signature.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|bytes: Vec<u8>| serde::de::Error::invalid_length(bytes.len(), &"64 bytes"))
    }
}

impl GenesisProvider for HashSet<String> {
    fn is_genesis(&self, issuer_hex: &str) -> bool {
        self.contains(issuer_hex)
    }
}

fn canonical_issuance_bytes(
    token_hash: &[u8; 32],
    parent_token_hash: Option<&[u8; 32]>,
    issued_at: u64,
    expires_at: u64,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ISSUE_DOMAIN.len() + 32 + 32 + 8 + 8);
    bytes.extend_from_slice(ISSUE_DOMAIN);
    bytes.extend_from_slice(token_hash);
    bytes.extend_from_slice(parent_token_hash.unwrap_or(&[0u8; 32]));
    bytes.extend_from_slice(&issued_at.to_be_bytes());
    bytes.extend_from_slice(&expires_at.to_be_bytes());
    bytes
}

fn canonical_redemption_bytes(
    token_hash: &[u8; 32],
    redeemer_node_id: &[u8; 32],
    redeemed_at: u64,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(REDEEM_DOMAIN.len() + 32 + 32 + 8);
    bytes.extend_from_slice(REDEEM_DOMAIN);
    bytes.extend_from_slice(token_hash);
    bytes.extend_from_slice(redeemer_node_id);
    bytes.extend_from_slice(&redeemed_at.to_be_bytes());
    bytes
}

fn parse_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    let mut output = [0u8; 32];
    hex::decode_to_slice(value, &mut output).ok()?;
    Some(output)
}

pub fn verify_nested_proof(
    proof: &NestedProof,
    genesis: &dyn GenesisProvider,
) -> Result<(), NestedProofError> {
    if proof.hops.is_empty() {
        return Err(NestedProofError::Empty);
    }
    if proof.hops.len() > MAX_CHAIN_DEPTH as usize {
        return Err(NestedProofError::DepthExceeded(
            proof.hops.len(),
            MAX_CHAIN_DEPTH,
        ));
    }

    let mut seen = HashMap::with_capacity(proof.hops.len());
    for (index, hop) in proof.hops.iter().enumerate() {
        if seen.insert(hop.token_hash, index).is_some() {
            return Err(NestedProofError::DuplicateTokenHash(index));
        }
    }

    let mut verified_hops = Vec::with_capacity(proof.hops.len());
    for (index, hop) in proof.hops.iter().enumerate() {
        let issuer_bytes =
            parse_hex_32(&hop.issuer_hex).ok_or(NestedProofError::InvalidIssuerHex(index))?;
        let redeemer_bytes = parse_hex_32(&hop.redeemer_node_id_hex)
            .ok_or(NestedProofError::InvalidRedeemerHex(index))?;
        let issuer_hash: [u8; 32] = Sha256::digest(hop.issuer_public_key).into();
        if issuer_hash != issuer_bytes {
            return Err(NestedProofError::PubkeyBindingMismatch(index));
        }
        let verifying_key = VerifyingKey::from_bytes(&hop.issuer_public_key)
            .map_err(|_| NestedProofError::PubkeyBindingMismatch(index))?;
        verified_hops.push((redeemer_bytes, verifying_key));
    }

    for (index, (hop, (redeemer_bytes, verifying_key))) in
        proof.hops.iter().zip(verified_hops.iter()).enumerate()
    {
        let issuance_payload = canonical_issuance_bytes(
            &hop.token_hash,
            hop.parent_token_hash.as_ref(),
            hop.issued_at,
            hop.expires_at,
        );
        if verifying_key
            .verify_strict(
                &issuance_payload,
                &Signature::from_bytes(&hop.issuance_signature),
            )
            .is_err()
        {
            let chain_depth = u32::try_from(proof.hops.len() - index - 1)
                .map_err(|_| NestedProofError::ChainContinuityBroken(index))?;
            if genesis.is_genesis(&hop.issuer_hex) != hop.parent_token_hash.is_none() {
                return Err(NestedProofError::InvalidChainBinding(index));
            }
            let current_signature =
                hal_protocol::invite::RedeemableInvite::verify_issuance_signature_parts(
                    &hop.issuer_hex,
                    &hop.issuer_public_key,
                    &hop.token_hash,
                    hop.issued_at,
                    hop.expires_at,
                    chain_depth,
                    hop.parent_token_hash.as_ref(),
                    &hop.issuance_signature,
                );
            if current_signature.is_err()
                && !(chain_depth == 0
                    && hop.parent_token_hash.is_none()
                    && genesis.is_genesis(&hop.issuer_hex)
                    && hal_protocol::invite::RedeemableInvite::verify_legacy_issuance_signature_parts(
                        &hop.issuer_hex,
                        &hop.issuer_public_key,
                        &hop.token_hash,
                        hop.issued_at,
                        hop.expires_at,
                        chain_depth,
                        &hop.issuance_signature,
                    )
                    .is_ok())
            {
                return Err(NestedProofError::InvalidIssuanceSignature(index));
            }
        }

        let redemption_payload =
            canonical_redemption_bytes(&hop.token_hash, &redeemer_bytes, hop.redeemed_at);
        verifying_key
            .verify_strict(
                &redemption_payload,
                &Signature::from_bytes(&hop.redemption_signature),
            )
            .map_err(|_| NestedProofError::InvalidRedemptionSignature(index))?;
    }

    for index in 1..proof.hops.len() {
        if proof.hops[index - 1].parent_token_hash != Some(proof.hops[index].token_hash) {
            return Err(NestedProofError::ChainContinuityBroken(index));
        }
    }

    for index in 0..proof.hops.len() - 1 {
        if proof.hops[index].issuer_hex != proof.hops[index + 1].redeemer_node_id_hex {
            return Err(NestedProofError::ChainOfRedemptionBroken(index));
        }
    }

    let last = &proof.hops[proof.hops.len() - 1];
    if last.parent_token_hash.is_some() {
        return Err(NestedProofError::GenesisParentNotNone);
    }
    if !genesis.is_genesis(&last.issuer_hex) {
        return Err(NestedProofError::GenesisNotTrusted);
    }

    Ok(())
}

pub fn sign_redemption_receipt(
    signing_key: &SigningKey,
    token_hash: &[u8; 32],
    redeemer_node_id: &[u8; 32],
    redeemed_at: u64,
) -> [u8; 64] {
    signing_key
        .sign(&canonical_redemption_bytes(
            token_hash,
            redeemer_node_id,
            redeemed_at,
        ))
        .to_bytes()
}

/// Convenience wrapper for one-shot verification without a shared
/// retry window. Only valid for `RevocationPolicy::ColdContact`:
/// `Established` requires a long-lived `RevocationWindowCache` to
/// retry unresolved lookups across calls (see §10.7.6). Runtime callers
/// MUST use `verify_nested_proof_with_revocation_cached` with a shared
/// window from `RuntimeContext`.
///
/// # Panics
///
/// Panics if `policy == Established`. This is a programmer error:
/// silently accepting a degraded fail-open would violate §10.7.6.
pub async fn verify_nested_proof_with_revocation(
    proof: &NestedProof,
    genesis: &dyn GenesisProvider,
    revocation: &dyn RevocationOracle,
    policy: RevocationPolicy,
) -> Result<(), NestedProofError> {
    assert_eq!(
        policy,
        RevocationPolicy::ColdContact,
        "verify_nested_proof_with_revocation only supports ColdContact; \
         use verify_nested_proof_with_revocation_cached for Established"
    );
    let window = RevocationWindowCache::new();
    verify_nested_proof_with_revocation_cached(proof, genesis, revocation, policy, &window).await
}

pub async fn verify_nested_proof_with_revocation_cached(
    proof: &NestedProof,
    genesis: &dyn GenesisProvider,
    revocation: &dyn RevocationOracle,
    policy: RevocationPolicy,
    window: &RevocationWindowCache,
) -> Result<(), NestedProofError> {
    verify_nested_proof(proof, genesis)?;

    let mut unresolved = Vec::new();
    for (index, hop) in proof.hops.iter().enumerate() {
        match revocation.is_revoked(&hop.token_hash).await {
            Ok(true) => return Err(NestedProofError::Revoked(index)),
            Ok(false) => window.remove(&hop.token_hash),
            Err(_) if policy == RevocationPolicy::ColdContact => {
                return Err(NestedProofError::RevocationUnknownColdContact(index));
            }
            Err(_) => {
                let inserted_at = window.record(hop.token_hash);
                unresolved.push((index, hop.token_hash, inserted_at));
            }
        }
    }

    if policy == RevocationPolicy::Established {
        for (index, token_hash, inserted_at) in unresolved {
            if window.now().saturating_sub(inserted_at) < REVOCATION_RETRY_WINDOW_SECS {
                continue;
            }
            match revocation.is_revoked(&token_hash).await {
                Ok(true) => return Err(NestedProofError::Revoked(index)),
                Ok(false) => window.remove(&token_hash),
                Err(_) => {
                    window.refresh(token_hash);
                }
            }
        }
    }
    Ok(())
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Build the issuance-side part of a ProofHop from a verified Invite.
/// Caller is responsible for populating redeemer_* and parent_token_hash.
pub fn issuance_side_from_invite(
    invite: &crate::dht::invite::Invite,
    token_hash: [u8; 32],
    parent_token_hash: Option<[u8; 32]>,
) -> (
    [u8; 32],
    Option<[u8; 32]>,
    String,
    [u8; 32],
    u64,
    u64,
    [u8; 64],
) {
    (
        token_hash,
        parent_token_hash,
        hex::encode(invite.issuer_id.as_bytes()),
        invite.issuer_public_key,
        invite.issued_at,
        invite.expires_at,
        invite.signature,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::revocation::RevocationLookupError;
    use ed25519_dalek::{Signer, SigningKey};
    use hal_protocol::invite::RedeemableInvite;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn node_id(key: &SigningKey) -> [u8; 32] {
        Sha256::digest(key.verifying_key().to_bytes()).into()
    }

    fn build_hop(
        issuer_key: &SigningKey,
        redeemer_key: &SigningKey,
        token_hash: [u8; 32],
        parent_token_hash: Option<[u8; 32]>,
        issued_at: u64,
        expires_at: u64,
        redeemed_at: u64,
    ) -> ProofHop {
        let issuer_public_key = issuer_key.verifying_key().to_bytes();
        let issuer_hex = hex::encode(Sha256::digest(issuer_public_key));
        let redeemer_node_id = node_id(redeemer_key);
        let redeemer_node_id_hex = hex::encode(redeemer_node_id);
        let issuance_signature = issuer_key
            .sign(&canonical_issuance_bytes(
                &token_hash,
                parent_token_hash.as_ref(),
                issued_at,
                expires_at,
            ))
            .to_bytes();
        let redemption_signature = issuer_key
            .sign(&canonical_redemption_bytes(
                &token_hash,
                &redeemer_node_id,
                redeemed_at,
            ))
            .to_bytes();

        ProofHop {
            token_hash,
            parent_token_hash,
            issuer_hex,
            issuer_public_key,
            issued_at,
            expires_at,
            issuance_signature,
            redeemer_node_id_hex,
            redeemed_at,
            redemption_signature,
        }
    }

    fn build_v2_hop(
        invite: &RedeemableInvite,
        issuer_key: &SigningKey,
        redeemer_key: &SigningKey,
        redeemed_at: u64,
    ) -> ProofHop {
        let token_hash = invite.token_hash().expect("token hash");
        let redeemer_node_id = node_id(redeemer_key);
        ProofHop {
            token_hash,
            parent_token_hash: invite.parent_token_hash,
            issuer_hex: invite.issuer_hex.clone(),
            issuer_public_key: invite.issuer_public_key,
            issued_at: invite.issued_at,
            expires_at: invite.expires_at,
            issuance_signature: invite.issuance_signature,
            redeemer_node_id_hex: hex::encode(redeemer_node_id),
            redeemed_at,
            redemption_signature: issuer_key
                .sign(&canonical_redemption_bytes(
                    &token_hash,
                    &redeemer_node_id,
                    redeemed_at,
                ))
                .to_bytes(),
        }
    }

    fn build_chain(depth: usize) -> (NestedProof, Vec<String>) {
        let issuers: Vec<_> = (0..depth)
            .map(|index| key(u8::try_from(index + 1).expect("small test depth")))
            .collect();
        let token_hashes: Vec<_> = (0..depth)
            .map(|index| [u8::try_from(index + 40).expect("small test depth"); 32])
            .collect();
        let external_redeemer = key(99);
        let hops = (0..depth)
            .map(|index| {
                let redeemer = if index == 0 {
                    &external_redeemer
                } else {
                    &issuers[index - 1]
                };
                let parent = token_hashes.get(index + 1).copied();
                build_hop(
                    &issuers[index],
                    redeemer,
                    token_hashes[index],
                    parent,
                    100 + index as u64,
                    200 + index as u64,
                    150 + index as u64,
                )
            })
            .collect();
        let root = issuers
            .last()
            .map(|issuer| hex::encode(node_id(issuer)))
            .unwrap_or_default();

        (NestedProof { hops }, vec![root])
    }

    fn trusted(genesis: &[String]) -> HashSet<String> {
        genesis.iter().cloned().collect()
    }

    #[test]
    fn append_hop_extends_chain() {
        let genesis_key = key(111);
        let issuer_key = key(112);
        let redeemer_key = key(113);
        let root_token = [0x22; 32];
        let leaf_token = [0x33; 32];
        let root = build_hop(&genesis_key, &issuer_key, root_token, None, 10, 100, 20);
        let leaf = build_hop(
            &issuer_key,
            &redeemer_key,
            leaf_token,
            Some(root_token),
            11,
            100,
            21,
        );

        let mut proof = NestedProof { hops: vec![leaf] };
        proof.append_hop(root).expect("append issuer proof");
        assert_eq!(proof.hops.len(), 2);
        let trusted = HashSet::from([hex::encode(node_id(&genesis_key))]);
        verify_nested_proof(&proof, &trusted).expect("verify appended chain");
    }

    #[test]
    fn append_hop_rejects_depth_exceed() {
        let signer = key(114);
        let mut proof = NestedProof {
            hops: vec![
                build_hop(&signer, &signer, [1; 32], None, 1, 2, 1);
                MAX_CHAIN_DEPTH as usize
            ],
        };
        let next = build_hop(&signer, &signer, [2; 32], None, 1, 2, 1);
        assert_eq!(
            proof.append_hop(next),
            Err(NestedProofError::DepthExceeded(
                MAX_CHAIN_DEPTH as usize + 1,
                MAX_CHAIN_DEPTH
            ))
        );
    }

    #[test]
    fn nested_proof_serde_roundtrip() {
        let (proof, _) = build_chain(2);
        let encoded = serde_json::to_vec(&proof).expect("serialize proof");
        let decoded: NestedProof = serde_json::from_slice(&encoded).expect("deserialize proof");
        assert_eq!(decoded, proof);
    }

    #[derive(Default)]
    struct MockOracle {
        revoked: Mutex<HashSet<[u8; 32]>>,
        errors_for: Mutex<HashSet<[u8; 32]>>,
        calls: Mutex<Vec<[u8; 32]>>,
        call_count: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl RevocationOracle for MockOracle {
        async fn is_revoked(&self, token_hash: &[u8; 32]) -> Result<bool, RevocationLookupError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            self.calls.lock().expect("calls").push(*token_hash);
            if self.errors_for.lock().expect("errors").contains(token_hash) {
                return Err(RevocationLookupError::Timeout);
            }
            Ok(self.revoked.lock().expect("revoked").contains(token_hash))
        }
    }

    fn test_window(now: Arc<AtomicU64>) -> RevocationWindowCache {
        RevocationWindowCache::with_clock(Box::new(move || now.load(Ordering::SeqCst)))
    }

    async fn verify_with(
        proof: &NestedProof,
        genesis: &[String],
        oracle: &MockOracle,
        policy: RevocationPolicy,
    ) -> Result<(), NestedProofError> {
        let window = RevocationWindowCache::new();
        verify_nested_proof_with_revocation_cached(
            proof,
            &trusted(genesis),
            oracle,
            policy,
            &window,
        )
        .await
    }

    #[test]
    fn verify_accepts_single_hop_chain() {
        let (proof, genesis) = build_chain(1);
        assert_eq!(verify_nested_proof(&proof, &trusted(&genesis)), Ok(()));
    }

    #[test]
    fn verify_accepts_two_hop_chain() {
        let (proof, genesis) = build_chain(2);
        assert_eq!(verify_nested_proof(&proof, &trusted(&genesis)), Ok(()));
    }

    #[test]
    fn verify_rejects_empty_proof() {
        assert_eq!(
            verify_nested_proof(&NestedProof { hops: vec![] }, &HashSet::new()),
            Err(NestedProofError::Empty)
        );
    }

    #[test]
    fn verify_rejects_depth_exceeded() {
        let (proof, genesis) = build_chain(MAX_CHAIN_DEPTH as usize + 1);
        assert_eq!(
            verify_nested_proof(&proof, &trusted(&genesis)),
            Err(NestedProofError::DepthExceeded(
                MAX_CHAIN_DEPTH as usize + 1,
                MAX_CHAIN_DEPTH
            ))
        );
    }

    #[test]
    fn verify_rejects_duplicate_token_hash() {
        let (mut proof, genesis) = build_chain(2);
        proof.hops[1].token_hash = proof.hops[0].token_hash;
        assert_eq!(
            verify_nested_proof(&proof, &trusted(&genesis)),
            Err(NestedProofError::DuplicateTokenHash(1))
        );
    }

    #[test]
    fn verify_rejects_pubkey_binding_mismatch() {
        let (mut proof, genesis) = build_chain(1);
        proof.hops[0].issuer_hex = "00".repeat(32);
        assert_eq!(
            verify_nested_proof(&proof, &trusted(&genesis)),
            Err(NestedProofError::PubkeyBindingMismatch(0))
        );
    }

    #[test]
    fn verify_rejects_invalid_issuer_hex() {
        let (mut proof, genesis) = build_chain(1);
        proof.hops[0].issuer_hex = proof.hops[0].issuer_hex.to_uppercase();
        assert_eq!(
            verify_nested_proof(&proof, &trusted(&genesis)),
            Err(NestedProofError::InvalidIssuerHex(0))
        );
    }

    #[test]
    fn verify_rejects_invalid_redeemer_hex() {
        let (mut proof, genesis) = build_chain(1);
        proof.hops[0].redeemer_node_id_hex = "abcd".to_string();
        assert_eq!(
            verify_nested_proof(&proof, &trusted(&genesis)),
            Err(NestedProofError::InvalidRedeemerHex(0))
        );
    }

    #[test]
    fn verify_rejects_tampered_issuance_signature() {
        let (mut proof, genesis) = build_chain(1);
        proof.hops[0].issuance_signature[0] ^= 1;
        assert_eq!(
            verify_nested_proof(&proof, &trusted(&genesis)),
            Err(NestedProofError::InvalidIssuanceSignature(0))
        );
    }

    #[test]
    fn verify_rejects_tampered_redemption_signature() {
        let (mut proof, genesis) = build_chain(1);
        proof.hops[0].redemption_signature[0] ^= 1;
        assert_eq!(
            verify_nested_proof(&proof, &trusted(&genesis)),
            Err(NestedProofError::InvalidRedemptionSignature(0))
        );
    }

    #[test]
    fn verify_rejects_chain_continuity_broken() {
        let (mut proof, genesis) = build_chain(2);
        let issuer = key(1);
        proof.hops[0].parent_token_hash = Some([0xFE; 32]);
        proof.hops[0].issuance_signature = issuer
            .sign(&canonical_issuance_bytes(
                &proof.hops[0].token_hash,
                proof.hops[0].parent_token_hash.as_ref(),
                proof.hops[0].issued_at,
                proof.hops[0].expires_at,
            ))
            .to_bytes();
        assert_eq!(
            verify_nested_proof(&proof, &trusted(&genesis)),
            Err(NestedProofError::ChainContinuityBroken(1))
        );
    }

    #[test]
    fn verify_rejects_chain_of_redemption_broken() {
        let (mut proof, genesis) = build_chain(2);
        let issuer = key(2);
        let other_redeemer = key(98);
        let token_hash = proof.hops[1].token_hash;
        let parent = proof.hops[1].parent_token_hash;
        let replacement = build_hop(
            &issuer,
            &other_redeemer,
            token_hash,
            parent,
            proof.hops[1].issued_at,
            proof.hops[1].expires_at,
            proof.hops[1].redeemed_at,
        );
        proof.hops[1] = replacement;
        assert_eq!(
            verify_nested_proof(&proof, &trusted(&genesis)),
            Err(NestedProofError::ChainOfRedemptionBroken(0))
        );
    }

    #[test]
    fn verify_rejects_genesis_parent_not_none() {
        let (mut proof, genesis) = build_chain(1);
        let issuer = key(1);
        proof.hops[0].parent_token_hash = Some([0xFD; 32]);
        proof.hops[0].issuance_signature = issuer
            .sign(&canonical_issuance_bytes(
                &proof.hops[0].token_hash,
                proof.hops[0].parent_token_hash.as_ref(),
                proof.hops[0].issued_at,
                proof.hops[0].expires_at,
            ))
            .to_bytes();
        assert_eq!(
            verify_nested_proof(&proof, &trusted(&genesis)),
            Err(NestedProofError::GenesisParentNotNone)
        );
    }

    #[test]
    fn verify_rejects_genesis_not_trusted() {
        let (proof, _) = build_chain(1);
        assert_eq!(
            verify_nested_proof(&proof, &HashSet::new()),
            Err(NestedProofError::GenesisNotTrusted)
        );
    }

    #[test]
    fn nested_proof_rejects_broken_parent_link() {
        let genesis_key = key(121);
        let issuer_key = key(122);
        let redeemer_key = key(123);
        let root_invite =
            RedeemableInvite::create(&genesis_key, [31; 16], 10, 100, 0).expect("root invite");
        let root_hop = build_v2_hop(&root_invite, &genesis_key, &issuer_key, 20);
        let leaf_invite = RedeemableInvite::create_with_parent(
            &issuer_key,
            [32; 16],
            11,
            100,
            1,
            Some([0xFE; 32]),
        )
        .expect("leaf invite");
        let leaf_hop = build_v2_hop(&leaf_invite, &issuer_key, &redeemer_key, 21);
        let proof = NestedProof {
            hops: vec![leaf_hop, root_hop],
        };
        let genesis = HashSet::from([root_invite.issuer_hex]);

        assert_eq!(
            verify_nested_proof(&proof, &genesis),
            Err(NestedProofError::ChainContinuityBroken(1))
        );
    }

    #[test]
    fn nested_proof_accepts_valid_chain_binding() {
        let genesis_key = key(124);
        let issuer_key = key(125);
        let redeemer_key = key(126);
        let root_invite =
            RedeemableInvite::create(&genesis_key, [33; 16], 10, 100, 0).expect("root invite");
        let root_token_hash = root_invite.token_hash().expect("root token hash");
        let root_hop = build_v2_hop(&root_invite, &genesis_key, &issuer_key, 20);
        let leaf_invite = RedeemableInvite::create_with_parent(
            &issuer_key,
            [34; 16],
            11,
            100,
            1,
            Some(root_token_hash),
        )
        .expect("leaf invite");
        let leaf_hop = build_v2_hop(&leaf_invite, &issuer_key, &redeemer_key, 21);
        let proof = NestedProof {
            hops: vec![leaf_hop, root_hop],
        };
        let genesis = HashSet::from([root_invite.issuer_hex]);

        assert_eq!(verify_nested_proof(&proof, &genesis), Ok(()));
    }

    #[tokio::test]
    async fn revocation_accepts_when_no_token_revoked_cold() {
        let (proof, genesis) = build_chain(2);
        assert_eq!(
            verify_with(
                &proof,
                &genesis,
                &MockOracle::default(),
                RevocationPolicy::ColdContact
            )
            .await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn revocation_accepts_when_no_token_revoked_established() {
        let (proof, genesis) = build_chain(2);
        assert_eq!(
            verify_with(
                &proof,
                &genesis,
                &MockOracle::default(),
                RevocationPolicy::Established
            )
            .await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn revocation_rejects_revoked_leaf_cold() {
        let (proof, genesis) = build_chain(2);
        let oracle = MockOracle::default();
        oracle
            .revoked
            .lock()
            .expect("revoked")
            .insert(proof.hops[0].token_hash);
        assert_eq!(
            verify_with(&proof, &genesis, &oracle, RevocationPolicy::ColdContact).await,
            Err(NestedProofError::Revoked(0))
        );
    }

    #[tokio::test]
    async fn revocation_rejects_revoked_intermediate_cold() {
        let (proof, genesis) = build_chain(3);
        let oracle = MockOracle::default();
        oracle
            .revoked
            .lock()
            .expect("revoked")
            .insert(proof.hops[1].token_hash);
        assert_eq!(
            verify_with(&proof, &genesis, &oracle, RevocationPolicy::ColdContact).await,
            Err(NestedProofError::Revoked(1))
        );
    }

    #[tokio::test]
    async fn revocation_rejects_revoked_genesis_cold() {
        let (proof, genesis) = build_chain(2);
        let oracle = MockOracle::default();
        oracle
            .revoked
            .lock()
            .expect("revoked")
            .insert(proof.hops[1].token_hash);
        assert_eq!(
            verify_with(&proof, &genesis, &oracle, RevocationPolicy::ColdContact).await,
            Err(NestedProofError::Revoked(1))
        );
    }

    #[tokio::test]
    async fn revocation_cold_contact_err_rejects() {
        let (proof, genesis) = build_chain(2);
        let oracle = MockOracle::default();
        oracle
            .errors_for
            .lock()
            .expect("errors")
            .insert(proof.hops[1].token_hash);
        assert_eq!(
            verify_with(&proof, &genesis, &oracle, RevocationPolicy::ColdContact).await,
            Err(NestedProofError::RevocationUnknownColdContact(1))
        );
    }

    #[tokio::test]
    async fn revocation_established_err_accepts_within_window() {
        let (proof, genesis) = build_chain(1);
        let oracle = MockOracle::default();
        oracle
            .errors_for
            .lock()
            .expect("errors")
            .insert(proof.hops[0].token_hash);
        let now = Arc::new(AtomicU64::new(500));
        let window = test_window(now);
        assert_eq!(
            verify_nested_proof_with_revocation_cached(
                &proof,
                &trusted(&genesis),
                &oracle,
                RevocationPolicy::Established,
                &window
            )
            .await,
            Ok(())
        );
        assert_eq!(window.lookup(&proof.hops[0].token_hash), Some(500));
    }

    #[tokio::test]
    async fn revocation_established_err_accepts_after_window_if_still_err() {
        let (proof, genesis) = build_chain(1);
        let oracle = MockOracle::default();
        oracle
            .errors_for
            .lock()
            .expect("errors")
            .insert(proof.hops[0].token_hash);
        let now = Arc::new(AtomicU64::new(500));
        let window = test_window(now.clone());
        assert_eq!(
            verify_nested_proof_with_revocation_cached(
                &proof,
                &trusted(&genesis),
                &oracle,
                RevocationPolicy::Established,
                &window
            )
            .await,
            Ok(())
        );
        now.fetch_add(REVOCATION_RETRY_WINDOW_SECS, Ordering::SeqCst);
        assert_eq!(
            verify_nested_proof_with_revocation_cached(
                &proof,
                &trusted(&genesis),
                &oracle,
                RevocationPolicy::Established,
                &window
            )
            .await,
            Ok(())
        );
        assert_eq!(oracle.call_count.load(Ordering::SeqCst), 3);
        assert_eq!(window.lookup(&proof.hops[0].token_hash), Some(560));
    }

    #[tokio::test]
    async fn revocation_established_err_rejects_if_window_expired_and_now_revoked() {
        let (proof, genesis) = build_chain(1);
        let oracle = MockOracle::default();
        let token_hash = proof.hops[0].token_hash;
        oracle.errors_for.lock().expect("errors").insert(token_hash);
        let now = Arc::new(AtomicU64::new(500));
        let window = test_window(now.clone());
        assert_eq!(
            verify_nested_proof_with_revocation_cached(
                &proof,
                &trusted(&genesis),
                &oracle,
                RevocationPolicy::Established,
                &window
            )
            .await,
            Ok(())
        );
        now.fetch_add(REVOCATION_RETRY_WINDOW_SECS, Ordering::SeqCst);
        oracle
            .errors_for
            .lock()
            .expect("errors")
            .remove(&token_hash);
        oracle.revoked.lock().expect("revoked").insert(token_hash);
        assert_eq!(
            verify_nested_proof_with_revocation_cached(
                &proof,
                &trusted(&genesis),
                &oracle,
                RevocationPolicy::Established,
                &window
            )
            .await,
            Err(NestedProofError::Revoked(0))
        );
    }

    #[tokio::test]
    async fn revocation_window_cache_prune_removes_expired() {
        let now = Arc::new(AtomicU64::new(500));
        let window = test_window(now.clone());
        let live = [1; 32];
        let expired = [2; 32];
        window.record(live);
        window.record(expired);
        now.fetch_add(REVOCATION_RETRY_WINDOW_SECS, Ordering::SeqCst);
        assert_eq!(window.prune_expired(), 2);
        assert_eq!(window.lookup(&live), None);
        assert_eq!(window.lookup(&expired), None);
    }

    #[tokio::test]
    async fn revocation_skips_dht_when_structure_invalid() {
        let (mut proof, genesis) = build_chain(1);
        proof.hops[0].issuance_signature[0] ^= 1;
        let oracle = MockOracle::default();
        assert_eq!(
            verify_with(&proof, &genesis, &oracle, RevocationPolicy::ColdContact).await,
            Err(NestedProofError::InvalidIssuanceSignature(0))
        );
        assert_eq!(oracle.call_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn revocation_checks_all_hops_in_order() {
        let (proof, genesis) = build_chain(3);
        let oracle = MockOracle::default();
        assert_eq!(
            verify_with(&proof, &genesis, &oracle, RevocationPolicy::ColdContact).await,
            Ok(())
        );
        assert_eq!(
            *oracle.calls.lock().expect("calls"),
            proof
                .hops
                .iter()
                .map(|hop| hop.token_hash)
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn revocation_established_mixed_ok_and_err() {
        let (proof, genesis) = build_chain(2);
        let oracle = MockOracle::default();
        oracle
            .errors_for
            .lock()
            .expect("errors")
            .insert(proof.hops[0].token_hash);
        oracle
            .revoked
            .lock()
            .expect("revoked")
            .insert(proof.hops[1].token_hash);
        assert_eq!(
            verify_with(&proof, &genesis, &oracle, RevocationPolicy::Established).await,
            Err(NestedProofError::Revoked(1))
        );
    }

    #[tokio::test]
    async fn verify_nested_proof_with_revocation_without_cache_works() {
        let (proof, genesis) = build_chain(1);
        assert_eq!(
            verify_nested_proof_with_revocation(
                &proof,
                &trusted(&genesis),
                &MockOracle::default(),
                RevocationPolicy::ColdContact
            )
            .await,
            Ok(())
        );
    }

    #[tokio::test]
    #[should_panic(expected = "only supports ColdContact")]
    async fn revocation_wrapper_panics_on_established() {
        let (proof, genesis) = build_chain(2);
        let oracle = MockOracle::default();
        let _ = verify_nested_proof_with_revocation(
            &proof,
            &trusted(&genesis),
            &oracle,
            RevocationPolicy::Established,
        )
        .await;
    }
}
