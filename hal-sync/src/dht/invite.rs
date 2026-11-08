use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use hal_protocol::invite::{InviteError as RedeemableInviteError, RedeemableInvite};
use hal_storage::invite_storage::{InviteRecord, TokenHash, TOKEN_HASH_DOMAIN};

use crate::dht::group::{GroupId, GroupRegistry};
use crate::dht::NodeId;

/// Срок жизни invite по умолчанию: 7 дней.
pub const INVITE_DEFAULT_TTL_SECS: u64 = 7 * 24 * 3600;
pub const MAX_INVITES_PER_ISSUER_PER_DAY: usize = 5;
pub const INVITE_WINDOW_SECS: u64 = 86_400;
pub const MAX_CHAIN_DEPTH: u32 = 10;
pub const NEW_IDENTITY_COOLDOWN_SECS: u64 = 7 * 86_400;

/// Префикс URI для QR-кода.
pub const INVITE_QR_SCHEME: &str = "hal://invite/";

/// Префикс URI для шаринга (landing).
pub const INVITE_SHARE_PREFIX: &str = "https://hal.app/i/";
const ISSUE_DOMAIN: &[u8] = b"HAL-INV-ISSUE-v1\0";

/// Подписанное приглашение связаться или вступить в группу.
///
/// group_id == None  -> приглашение на связь (без группы).
/// group_id == Some  -> приглашение в группу.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Invite {
    #[serde(alias = "inviter_id")]
    pub issuer_id: NodeId,
    pub issuer_public_key: [u8; 32],
    pub group_id: Option<GroupId>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: [u8; 16],
    #[serde(default)]
    pub chain_depth: u32,
    #[serde(default)]
    pub parent_invite_id: Option<String>,
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

fn canonical_issuance_bytes(
    token_hash: &[u8; 32],
    parent_token_hash: Option<&[u8; 32]>,
    issued_at: u64,
    expires_at: u64,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ISSUE_DOMAIN.len() + 32 + 32 + 8 + 8);
    bytes.extend_from_slice(ISSUE_DOMAIN);
    bytes.extend_from_slice(token_hash);
    bytes.extend_from_slice(parent_token_hash.unwrap_or(&[0; 32]));
    bytes.extend_from_slice(&issued_at.to_be_bytes());
    bytes.extend_from_slice(&expires_at.to_be_bytes());
    bytes
}

impl Invite {
    pub fn invite_id(&self) -> String {
        hex::encode(self.token_hash())
    }

    // Raw SHA-256 token hash bytes; hal-storage::TokenHash wraps the same 32-byte value.
    fn token_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.issuer_id.as_bytes());
        if let Some(group_id) = self.group_id {
            hasher.update(group_id.to_be_bytes());
        }
        hasher.update(self.expires_at.to_be_bytes());
        hasher.update(self.nonce);
        hasher.update(self.chain_depth.to_be_bytes());
        if let Some(parent) = &self.parent_invite_id {
            hasher.update(parent.as_bytes());
        }
        hasher.finalize().into()
    }

    /// Создать подписанное приглашение.
    pub fn create(
        signing_key: &SigningKey,
        group_id: Option<GroupId>,
        ttl_secs: u64,
        now: u64,
        nonce: [u8; 16],
        chain_depth: u32,
        parent_invite_id: Option<String>,
        parent_token_hash: Option<[u8; 32]>,
    ) -> Self {
        let issuer_public_key = signing_key.verifying_key().to_bytes();
        let issuer_id = NodeId::from_public_key(&signing_key.verifying_key());
        let expires_at = now.saturating_add(ttl_secs);
        let mut invite = Self {
            issuer_id,
            issuer_public_key,
            group_id,
            issued_at: now,
            expires_at,
            nonce,
            chain_depth,
            parent_invite_id,
            signature: [0; 64],
        };
        invite.signature = signing_key
            .sign(&canonical_issuance_bytes(
                &invite.token_hash(),
                parent_token_hash.as_ref(),
                now,
                expires_at,
            ))
            .to_bytes();
        invite
    }

    /// Verifies structural integrity: issuer binding, temporal ordering
    /// (`issued_at <= expires_at`), and canonical signature. Does NOT check
    /// expiration against wall-clock: this verifier is used both for fresh
    /// invites and for historical chain links in NestedProof, where
    /// wall-clock expiration is not applicable. Redeemer-side acceptance
    /// MUST independently check `expires_at > now` before redeeming.
    pub fn verify(
        &self,
        verifying_key: &VerifyingKey,
        parent_token_hash: Option<[u8; 32]>,
    ) -> bool {
        if verifying_key.to_bytes() != self.issuer_public_key
            || NodeId::from_public_key(verifying_key) != self.issuer_id
            || self.issued_at > self.expires_at
        {
            return false;
        }

        let payload = canonical_issuance_bytes(
            &self.token_hash(),
            parent_token_hash.as_ref(),
            self.issued_at,
            self.expires_at,
        );
        verifying_key
            .verify_strict(&payload, &Signature::from_bytes(&self.signature))
            .is_ok()
    }

    /// Сериализация в base64.
    pub fn to_base64(&self) -> Result<String, InviteError> {
        let json = serde_json::to_string(self).map_err(|_| InviteError::Malformed)?;
        Ok(base64_encode(json.as_bytes()))
    }

    /// Десериализация из base64.
    pub fn from_base64(s: &str) -> Result<Self, InviteError> {
        let bytes = base64_decode(s)?;
        serde_json::from_slice(&bytes).map_err(|_| InviteError::Malformed)
    }

    /// URI для QR-кода: hal://invite/<base64>
    pub fn to_qr_uri(&self) -> Result<String, InviteError> {
        Ok(format!("{}{}", INVITE_QR_SCHEME, self.to_base64()?))
    }

    /// URI для шаринга: https://hal.app/i/<base64>
    pub fn to_share_uri(&self) -> Result<String, InviteError> {
        Ok(format!("{}{}", INVITE_SHARE_PREFIX, self.to_base64()?))
    }

    /// Парсинг URI (принимает оба формата).
    pub fn from_uri(uri: &str) -> Result<Self, InviteError> {
        let trimmed = uri.trim();
        let b64 = if let Some(rest) = trimmed.strip_prefix(INVITE_QR_SCHEME) {
            rest
        } else if let Some(rest) = trimmed.strip_prefix(INVITE_SHARE_PREFIX) {
            rest
        } else {
            return Err(InviteError::WrongScheme);
        };
        Self::from_base64(b64)
    }
}

pub fn redeemable_to_record(
    invite: &RedeemableInvite,
    now: u64,
) -> Result<InviteRecord, RedeemableInviteError> {
    invite.verify(now)?;
    let token_hash = TokenHash::from_bytes(invite.token_hash()?);
    Ok(InviteRecord {
        token_hash,
        issuer_hex: invite.issuer_hex.clone(),
        issuer_public_key: invite.issuer_public_key,
        issuance_signature: invite.issuance_signature,
        issued_at: invite.issued_at,
        expires_at: invite.expires_at,
        max_uses: 1,
        current_uses: 0,
        chain_depth: invite.chain_depth,
        parent_token_hash: invite.parent_token_hash.map(TokenHash::from_bytes),
        revoked_at: None,
    })
}

pub fn record_matches_token(record: &InviteRecord, token_bytes: &[u8]) -> bool {
    if token_bytes.len() != 16 {
        return false;
    }
    let mut hasher = Sha256::new();
    hasher.update(TOKEN_HASH_DOMAIN);
    hasher.update(token_bytes);
    record.token_hash.as_bytes() == &<[u8; 32]>::from(hasher.finalize())
}

/// Ошибки invite-протокола.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteError {
    InvalidSignature,
    Expired,
    Malformed,
    WrongScheme,
}

impl std::fmt::Display for InviteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::Expired => write!(f, "invite expired"),
            Self::Malformed => write!(f, "malformed invite"),
            Self::WrongScheme => write!(f, "wrong invite scheme"),
        }
    }
}

impl std::error::Error for InviteError {}

/// Принять приглашение: если group_id == Some, добавить в группу.
/// Если group_id == None — ничего не делать (просто связь).
///
/// МОДУЛЬНОСТЬ: сигнатура может расширяться (добавим KnownHosts,
/// referral, и т.д. в следующих шагах).
pub fn accept_invite(invite: &Invite, groups: &mut GroupRegistry) -> Result<(), InviteError> {
    if let Some(group_id) = invite.group_id {
        groups.add_member(group_id, invite.issuer_id);
    }
    Ok(())
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(bytes)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, InviteError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| InviteError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::group::GroupGraph;
    use ed25519_dalek::SigningKey;
    use hal_protocol::invite::TOKEN_HASH_DOMAIN as PROTOCOL_TOKEN_HASH_DOMAIN;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn nonce(seed: u8) -> [u8; 16] {
        [seed; 16]
    }

    fn redeemable_invite(key: &SigningKey) -> RedeemableInvite {
        RedeemableInvite::create(key, [0x5a; 16], 1000, 3600, 0).expect("create v2 invite")
    }

    #[test]
    fn redeemable_to_record_produces_valid_record() {
        assert_eq!(TOKEN_HASH_DOMAIN, PROTOCOL_TOKEN_HASH_DOMAIN);
        let signing_key = key(21);
        let invite = redeemable_invite(&signing_key);
        let record = redeemable_to_record(&invite, 1001).expect("map record");

        assert_eq!(record.issuer_hex, invite.issuer_hex);
        assert_eq!(record.issuer_public_key, invite.issuer_public_key);
        assert_eq!(record.issuance_signature, invite.issuance_signature);
        assert_eq!(record.issued_at, invite.issued_at);
        assert_eq!(record.expires_at, invite.expires_at);
        assert_eq!(record.max_uses, 1);
        assert_eq!(record.current_uses, 0);
        assert_eq!(record.chain_depth, invite.chain_depth);
        assert!(record.parent_token_hash.is_none());
        assert!(record.revoked_at.is_none());
    }

    #[test]
    fn redeemable_to_record_preserves_parent_token_hash() {
        let signing_key = key(24);
        let invite = RedeemableInvite::create_with_parent(
            &signing_key,
            [0x5c; 16],
            1000,
            3600,
            1,
            Some([0x6d; 32]),
        )
        .expect("create child invite");
        let record = redeemable_to_record(&invite, 1001).expect("map record");

        assert_eq!(
            record
                .parent_token_hash
                .as_ref()
                .map(|hash| *hash.as_bytes()),
            invite.parent_token_hash
        );
    }

    #[test]
    fn record_matches_token_checks_token_hash() {
        let invite = redeemable_invite(&key(22));
        let record = redeemable_to_record(&invite, 1001).expect("map record");
        assert!(record_matches_token(&record, &[0x5a; 16]));
    }

    #[test]
    fn record_matches_token_rejects_wrong_token() {
        let invite = redeemable_invite(&key(23));
        let record = redeemable_to_record(&invite, 1001).expect("map record");
        assert!(!record_matches_token(&record, &[0x5b; 16]));
        assert!(!record_matches_token(&record, &[0x5a; 15]));
    }

    fn create_test_invite(signing_key: &SigningKey, parent_token_hash: Option<[u8; 32]>) -> Invite {
        Invite::create(
            signing_key,
            Some(42),
            3600,
            1000,
            nonce(7),
            1,
            Some("parent-invite".to_string()),
            parent_token_hash,
        )
    }

    #[test]
    fn create_and_verify_roundtrip() {
        let signing_key = key(1);
        let verifying_key = signing_key.verifying_key();
        let issuer = NodeId::from_public_key(&verifying_key);

        let invite = Invite::create(&signing_key, Some(42), 3600, 1000, nonce(7), 0, None, None);
        assert_eq!(invite.issuer_id, issuer);
        assert!(invite.verify(&verifying_key, None));
    }

    #[test]
    fn invalid_signature_rejected() {
        let signing_key = key(3);
        let other_key = key(4);
        let other_verifying_key = other_key.verifying_key();

        let invite = Invite::create(&signing_key, None, 3600, 1000, nonce(9), 0, None, None);
        assert!(!invite.verify(&other_verifying_key, None));
    }

    #[test]
    fn base64_roundtrip() {
        let signing_key = key(5);
        let invite = Invite::create(&signing_key, Some(7), 3600, 1000, nonce(10), 0, None, None);

        let encoded = invite.to_base64().unwrap();
        let restored = Invite::from_base64(&encoded).unwrap();
        assert_eq!(invite, restored);
    }

    #[test]
    fn qr_uri_roundtrip() {
        let signing_key = key(6);
        let invite = Invite::create(&signing_key, None, 3600, 1000, nonce(11), 0, None, None);

        let uri = invite.to_qr_uri().unwrap();
        assert!(uri.starts_with(INVITE_QR_SCHEME));
        let restored = Invite::from_uri(&uri).unwrap();
        assert_eq!(invite, restored);
    }

    #[test]
    fn share_uri_roundtrip() {
        let signing_key = key(7);
        let invite = Invite::create(&signing_key, Some(99), 3600, 1000, nonce(12), 0, None, None);

        let uri = invite.to_share_uri().unwrap();
        assert!(uri.starts_with(INVITE_SHARE_PREFIX));
        let restored = Invite::from_uri(&uri).unwrap();
        assert_eq!(invite, restored);
    }

    #[test]
    fn accept_invite_with_group_adds_to_group() {
        let signing_key = key(8);
        let issuer = NodeId::from_public_key(&signing_key.verifying_key());
        let mut groups = GroupRegistry::new();
        let group_id = groups.create_group(Some("Test".to_string()));
        let invite = Invite::create(
            &signing_key,
            Some(group_id),
            3600,
            1000,
            nonce(13),
            0,
            None,
            None,
        );

        accept_invite(&invite, &mut groups).unwrap();
        assert!(groups.is_in_any_group(&issuer));
    }

    #[test]
    fn accept_invite_without_group_does_nothing() {
        let signing_key = key(9);
        let issuer = NodeId::from_public_key(&signing_key.verifying_key());
        let invite = Invite::create(&signing_key, None, 3600, 1000, nonce(14), 0, None, None);

        let mut groups = GroupRegistry::new();
        accept_invite(&invite, &mut groups).unwrap();
        assert!(!groups.is_in_any_group(&issuer));
    }

    #[test]
    fn from_uri_wrong_scheme_rejected() {
        assert_eq!(
            Invite::from_uri("https://example.com/foo"),
            Err(InviteError::WrongScheme)
        );
    }

    #[test]
    fn invite_registry_blocks_fanout_after_limit() {
        let now = 1_700_000_000;
        let mut registry = crate::dht::invite_registry::InviteRegistry::new();
        let signing_key = key(100);

        for index in 0..MAX_INVITES_PER_ISSUER_PER_DAY {
            let invite = Invite::create(
                &signing_key,
                Some(42),
                3600,
                now + index as u64,
                [index as u8; 16],
                0,
                None,
                None,
            );
            assert!(registry.register(invite, now + index as u64).is_ok());
        }

        let invite = Invite::create(
            &signing_key,
            Some(43),
            3600,
            now + MAX_INVITES_PER_ISSUER_PER_DAY as u64,
            [9; 16],
            0,
            None,
            None,
        );
        assert_eq!(
            registry.register(invite, now + MAX_INVITES_PER_ISSUER_PER_DAY as u64),
            Err(crate::dht::invite_registry::InviteCreationError::FanoutExceeded)
        );
    }

    #[test]
    fn invite_registry_blocks_chain_depth_exceeded() {
        let issuer = NodeId::from_bytes([0x22; 32]);
        let now = 1_800_000_000;
        let registry = crate::dht::invite_registry::InviteRegistry::new();

        assert_eq!(
            registry.can_issue(
                &issuer,
                Some(MAX_CHAIN_DEPTH),
                now - NEW_IDENTITY_COOLDOWN_SECS,
                now
            ),
            Err(crate::dht::invite_registry::InviteCreationError::ChainDepthExceeded)
        );
    }

    #[test]
    fn invite_registry_blocks_cooldown() {
        let issuer = NodeId::from_bytes([0x23; 32]);
        let now = 1_900_000_000;
        let registry = crate::dht::invite_registry::InviteRegistry::new();

        assert_eq!(
            registry.can_issue(&issuer, None, now - 60, now),
            Err(crate::dht::invite_registry::InviteCreationError::CooldownActive)
        );
    }

    #[test]
    fn invite_create_binds_issuer_public_key() {
        let signing_key = key(21);
        let invite = create_test_invite(&signing_key, None);

        assert_eq!(
            invite.issuer_public_key,
            signing_key.verifying_key().to_bytes()
        );
    }

    #[test]
    fn invite_create_signature_verifies_with_canonical_payload() {
        let signing_key = key(22);
        let parent_token_hash = [0x31; 32];
        let invite = create_test_invite(&signing_key, Some(parent_token_hash));
        let payload = canonical_issuance_bytes(
            &invite.token_hash(),
            Some(&parent_token_hash),
            invite.issued_at,
            invite.expires_at,
        );

        assert!(signing_key
            .verifying_key()
            .verify_strict(&payload, &Signature::from_bytes(&invite.signature))
            .is_ok());
    }

    #[test]
    fn invite_verify_rejects_tampered_token_hash() {
        let signing_key = key(23);
        let mut invite = create_test_invite(&signing_key, None);
        invite.nonce[0] ^= 1;

        assert!(!invite.verify(&signing_key.verifying_key(), None));
    }

    #[test]
    fn invite_verify_rejects_tampered_parent_token_hash() {
        let signing_key = key(24);
        let invite = create_test_invite(&signing_key, Some([0x41; 32]));

        assert!(!invite.verify(&signing_key.verifying_key(), Some([0x42; 32])));
    }

    #[test]
    fn invite_verify_rejects_tampered_expires_at() {
        let signing_key = key(25);
        let mut invite = create_test_invite(&signing_key, None);
        invite.expires_at += 1;

        assert!(!invite.verify(&signing_key.verifying_key(), None));
    }

    #[test]
    fn invite_verify_rejects_wrong_verifying_key() {
        let signing_key = key(26);
        let invite = create_test_invite(&signing_key, None);

        assert!(!invite.verify(&key(27).verifying_key(), None));
    }

    #[test]
    fn invite_verify_rejects_mismatched_issuer_public_key() {
        let signing_key = key(28);
        let mut invite = create_test_invite(&signing_key, None);
        invite.issuer_public_key[0] ^= 1;

        assert!(!invite.verify(&signing_key.verifying_key(), None));
    }

    #[test]
    fn invite_verify_rejects_none_parent_vs_some_parent() {
        let signing_key = key(29);
        let invite = create_test_invite(&signing_key, None);

        assert!(!invite.verify(&signing_key.verifying_key(), Some([0x43; 32])));
    }

    #[test]
    fn invite_create_issuer_id_matches_pubkey_hash() {
        let signing_key = key(30);
        let invite = create_test_invite(&signing_key, None);

        assert_eq!(
            invite.issuer_id,
            NodeId::from_public_key(&signing_key.verifying_key())
        );
    }

    #[test]
    fn invite_verify_rejects_bitflipped_signature() {
        let signing_key = key(31);
        let mut invite = create_test_invite(&signing_key, None);
        invite.signature[0] ^= 1;

        assert!(!invite.verify(&signing_key.verifying_key(), None));
    }

    #[test]
    fn invite_verify_rejects_tampered_issued_at() {
        let signing_key = key(32);
        let mut invite = create_test_invite(&signing_key, None);
        invite.issued_at += 1;

        assert!(!invite.verify(&signing_key.verifying_key(), None));
    }

    #[test]
    fn invite_verify_rejects_issued_at_after_expires_at() {
        let signing_key = key(33);
        let mut invite = create_test_invite(&signing_key, None);
        invite.issued_at = invite.expires_at + 1;

        assert!(!invite.verify(&signing_key.verifying_key(), None));
    }

    #[test]
    fn expired_invite_not_checked_by_verify() {
        let signing_key = key(34);
        let invite = Invite::create(&signing_key, None, 1, 1000, nonce(34), 0, None, None);
        let now = invite.expires_at + 1;

        assert!(now > invite.expires_at);
        assert!(invite.verify(&signing_key.verifying_key(), None));
    }
}
