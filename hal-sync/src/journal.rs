use anyhow::Result;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use thiserror::Error;

mod base64_bytes {
    use super::BASE64;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        BASE64.decode(encoded).map_err(serde::de::Error::custom)
    }
}

const LEGACY_MESSAGE_VERSION: u8 = 1;
const ENCRYPTED_MESSAGE_VERSION: u8 = 2;
const RATCHET_MESSAGE_VERSION: u8 = 3;
pub const MESSAGE_VERSION_V4: u8 = 4;
pub const MAX_APPLIED_EVENT_IDS: usize = 50_000;
pub const FILE_TRANSFER_CHUNK_SIZE: usize = 32 * 1024;
pub const MAX_FILE_TRANSFER_SIZE: u64 = 50 * 1024 * 1024;

fn default_message_version() -> u8 {
    LEGACY_MESSAGE_VERSION
}

fn is_legacy_message_version(version: &u8) -> bool {
    *version == LEGACY_MESSAGE_VERSION
}

fn is_zero_timestamp(timestamp: &u64) -> bool {
    *timestamp == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncEventType {
    ContactAdded,
    ContactUpdated,
    ContactDeleted,
    SettingsUpdated,
    MessageAdded,
    MessageRead,
    GroupCreate,
    GroupKeyDistribution,
    GroupMessage,
    HomeLinkRequest,
    HomeLinkResponse,
    HomeLinkConfirm,
    HomeSyncChunk,
    HomeSyncAck,
    DraftUpdate,
    SasPairing,
    PeerPresence,
    RelayRequest,
    RelayResponse,
    RelayForward,
    X3dhInit,
    X3dhRespond,
    /// E1-4d-3a: invitation to join a jury (complainant to candidate).
    JuryInvitation,
    /// E1-4d-3a: candidate response to a jury invitation.
    JuryInvitationResponse,
    /// E1-4d-3a: private DKG share delivery (dealer to juror).
    JuryShareDelivery,
    /// E1-4d-3a: acknowledgement of a received DKG share.
    JuryShareAck,
    /// E1-4d-3d-2: signed evidence response from a complaint party.
    JuryEvidenceDelivery,
    /// E1-4d-3d: private NotGuilty/Inconclusive verdict for complaint parties.
    JuryVerdictPrivate,
    InviteRedemptionRequest,
    InviteRedemptionResponse,
    ProfileUpdate,
    FileTransferInit,
    FileTransferChunk,
    FileTransferComplete,
    FileTransferCancel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncEvent {
    pub id: String,
    pub event_type: SyncEventType,
    pub data: String,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageAddedPayload {
    #[serde(
        default = "default_message_version",
        skip_serializing_if = "is_legacy_message_version"
    )]
    pub version: u8,
    pub chat_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to_id: Option<String>,
    pub sender_id: String,
    #[serde(default)]
    pub recipient_id: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero_timestamp")]
    pub timestamp: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ratchet_counter: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ratchet_nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dh_pubkey: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_chain_length: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupCreatePayload {
    pub group_id: String,
    pub name: String,
    pub avatar_b64: Option<String>,
    pub members: Vec<String>,
    pub recipient_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupKeyDistributionPayload {
    pub group_id: String,
    pub group_key: String,
    pub recipient_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupMessagePayload {
    pub message_id: String,
    pub group_id: String,
    pub sender_id: String,
    pub recipient_id: String,
    pub timestamp: u64,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageReadPayload {
    pub message_id: String,
    pub reader_id: String,
    pub recipient_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileUpdatePayload {
    pub display_name: String,
    pub avatar_b64: Option<String>,
    pub recipient_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileTransferInitPayload {
    pub recipient_id: String,
    pub file_id: String,
    pub chat_id: String,
    pub sender_id: String,
    pub file_name: String,
    pub file_size: u64,
    pub mime_type: String,
    pub total_chunks: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileTransferChunkPayload {
    pub recipient_id: String,
    pub file_id: String,
    pub chunk_index: u32,
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileTransferCompletePayload {
    pub recipient_id: String,
    pub file_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileTransferCancelPayload {
    pub recipient_id: String,
    pub file_id: String,
    pub reason: String,
}

#[derive(Debug, Error)]
pub enum MessagePayloadError {
    #[error("invalid version: {0}")]
    InvalidVersion(u8),
    #[error("invalid payload: {0}")]
    InvalidPayload(&'static str),
    #[error("version {0}: missing required field")]
    MissingField(u8),
    #[error("version {0}: unexpected field")]
    UnexpectedField(u8),
    #[error("invalid direct message metadata")]
    InvalidMetadata,
    #[error("recipient identity does not match the supplied public key")]
    RecipientKeyMismatch,
    #[error("message encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("invalid base64: {0}")]
    InvalidBase64(String),
}

#[derive(Debug, Error)]
pub enum MessageDecryptError {
    #[error("invalid MessageAdded payload for its version")]
    InvalidPayload,
    #[error("recipient identity does not match the supplied private key")]
    RecipientKeyMismatch,
    #[error("encrypted message ciphertext is not valid base64")]
    InvalidCiphertextEncoding,
    #[error("encrypted message could not be decrypted")]
    DecryptionFailed,
    #[error("decrypted message is not valid UTF-8")]
    InvalidPlaintext,
}

impl MessageAddedPayload {
    pub fn new_legacy(
        chat_id: String,
        sender_id: String,
        recipient_id: Option<String>,
        text: String,
        timestamp: u64,
    ) -> Self {
        Self {
            version: LEGACY_MESSAGE_VERSION,
            chat_id,
            group_id: None,
            reply_to_id: None,
            sender_id,
            recipient_id,
            timestamp,
            text: Some(text),
            ciphertext: None,
            ratchet_counter: None,
            ratchet_nonce: None,
            chain_id: None,
            dh_pubkey: None,
            prev_chain_length: None,
        }
    }

    pub fn new_encrypted(
        chat_id: String,
        sender_id: String,
        recipient_id: String,
        recipient_pubkey: &VerifyingKey,
        plaintext: &str,
        timestamp: u64,
        event_id: &str,
    ) -> Result<Self, MessagePayloadError> {
        if chat_id.is_empty()
            || sender_id.is_empty()
            || recipient_id.is_empty()
            || event_id.is_empty()
        {
            return Err(MessagePayloadError::InvalidMetadata);
        }
        if crate::dht::NodeId::from_public_key(recipient_pubkey).to_hex() != recipient_id {
            return Err(MessagePayloadError::RecipientKeyMismatch);
        }
        let encrypted = hal_crypto::encrypt_message(
            recipient_pubkey,
            plaintext.as_bytes(),
            &sender_id,
            event_id,
        )
        .map_err(|_| MessagePayloadError::EncryptionFailed)?;

        Ok(Self {
            version: ENCRYPTED_MESSAGE_VERSION,
            chat_id,
            group_id: None,
            reply_to_id: None,
            sender_id,
            recipient_id: Some(recipient_id),
            timestamp,
            text: None,
            ciphertext: Some(BASE64.encode(encrypted)),
            ratchet_counter: None,
            ratchet_nonce: None,
            chain_id: None,
            dh_pubkey: None,
            prev_chain_length: None,
        })
    }

    pub fn new_ratchet_encrypted(
        chat_id: String,
        sender_id: String,
        recipient_id: String,
        plaintext: &str,
        message_key: &hal_crypto::MessageKey,
        counter: u64,
        event_id: &str,
        timestamp: u64,
    ) -> Result<Self, MessagePayloadError> {
        if chat_id.is_empty()
            || sender_id.is_empty()
            || recipient_id.is_empty()
            || event_id.is_empty()
        {
            return Err(MessagePayloadError::InvalidMetadata);
        }
        if message_key.index != counter {
            return Err(MessagePayloadError::InvalidMetadata);
        }
        let aad = ratchet_message_aad(&chat_id, &sender_id, &recipient_id, counter, event_id);
        let encrypted = hal_crypto::XChaCha20Poly1305Cipher::encrypt(
            &message_key.key[..],
            plaintext.as_bytes(),
            Some(&aad),
        )
        .map_err(|_| MessagePayloadError::EncryptionFailed)?;

        Ok(Self {
            version: RATCHET_MESSAGE_VERSION,
            chat_id,
            group_id: None,
            reply_to_id: None,
            sender_id,
            recipient_id: Some(recipient_id),
            timestamp,
            text: None,
            ciphertext: Some(BASE64.encode(encrypted.ciphertext)),
            ratchet_counter: Some(counter),
            ratchet_nonce: Some(BASE64.encode(encrypted.nonce)),
            chain_id: None,
            dh_pubkey: None,
            prev_chain_length: None,
        })
    }

    pub fn new_ratchet_v4_encrypted(
        chat_id: String,
        sender_id: String,
        recipient_id: String,
        plaintext: &str,
        message_key: &hal_crypto::MessageKey,
        counter: u64,
        event_id: &str,
        timestamp: u64,
        chain_id: u32,
        dh_pubkey: Option<[u8; 32]>,
        prev_chain_length: Option<u32>,
    ) -> Result<Self, MessagePayloadError> {
        if dh_pubkey.is_some() != prev_chain_length.is_some() {
            return Err(MessagePayloadError::InvalidMetadata);
        }
        let mut payload = Self::new_ratchet_encrypted(
            chat_id,
            sender_id,
            recipient_id,
            plaintext,
            message_key,
            counter,
            event_id,
            timestamp,
        )?;
        payload.version = MESSAGE_VERSION_V4;
        payload.chain_id = Some(chain_id);
        payload.dh_pubkey = dh_pubkey;
        payload.prev_chain_length = prev_chain_length;
        payload.validate()?;
        Ok(payload)
    }

    pub fn decrypt_v3(
        &self,
        message_key: &hal_crypto::MessageKey,
        event_id: &str,
    ) -> Result<String, MessagePayloadError> {
        self.validate()?;
        if self.version != RATCHET_MESSAGE_VERSION
            || self.ratchet_counter != Some(message_key.index)
            || event_id.is_empty()
        {
            return Err(MessagePayloadError::DecryptionFailed);
        }
        let counter = self
            .ratchet_counter
            .ok_or(MessagePayloadError::MissingField(RATCHET_MESSAGE_VERSION))?;
        let recipient_id = self
            .recipient_id
            .as_deref()
            .ok_or(MessagePayloadError::MissingField(RATCHET_MESSAGE_VERSION))?;
        let ciphertext = BASE64
            .decode(
                self.ciphertext
                    .as_deref()
                    .ok_or(MessagePayloadError::MissingField(RATCHET_MESSAGE_VERSION))?,
            )
            .map_err(|error| MessagePayloadError::InvalidBase64(error.to_string()))?;
        let nonce = BASE64
            .decode(
                self.ratchet_nonce
                    .as_deref()
                    .ok_or(MessagePayloadError::MissingField(RATCHET_MESSAGE_VERSION))?,
            )
            .map_err(|error| MessagePayloadError::InvalidBase64(error.to_string()))?;
        let aad = ratchet_message_aad(
            &self.chat_id,
            &self.sender_id,
            recipient_id,
            counter,
            event_id,
        );
        let plaintext = hal_crypto::XChaCha20Poly1305Cipher::decrypt(
            &message_key.key[..],
            &hal_crypto::EncryptedMessage { nonce, ciphertext },
            Some(&aad),
        )
        .map_err(|_| MessagePayloadError::DecryptionFailed)?;
        String::from_utf8(plaintext).map_err(|_| MessagePayloadError::DecryptionFailed)
    }

    pub fn decrypt_v4(
        &self,
        message_key: &hal_crypto::MessageKey,
        event_id: &str,
    ) -> Result<String, MessagePayloadError> {
        self.validate()?;
        if self.version != MESSAGE_VERSION_V4
            || self.ratchet_counter != Some(message_key.index)
            || event_id.is_empty()
        {
            return Err(MessagePayloadError::DecryptionFailed);
        }
        let counter = self
            .ratchet_counter
            .ok_or(MessagePayloadError::MissingField(MESSAGE_VERSION_V4))?;
        let recipient_id = self
            .recipient_id
            .as_deref()
            .ok_or(MessagePayloadError::MissingField(MESSAGE_VERSION_V4))?;
        let ciphertext = BASE64
            .decode(
                self.ciphertext
                    .as_deref()
                    .ok_or(MessagePayloadError::MissingField(MESSAGE_VERSION_V4))?,
            )
            .map_err(|error| MessagePayloadError::InvalidBase64(error.to_string()))?;
        let nonce = BASE64
            .decode(
                self.ratchet_nonce
                    .as_deref()
                    .ok_or(MessagePayloadError::MissingField(MESSAGE_VERSION_V4))?,
            )
            .map_err(|error| MessagePayloadError::InvalidBase64(error.to_string()))?;
        let aad = ratchet_message_aad(
            &self.chat_id,
            &self.sender_id,
            recipient_id,
            counter,
            event_id,
        );
        let plaintext = hal_crypto::XChaCha20Poly1305Cipher::decrypt(
            &message_key.key[..],
            &hal_crypto::EncryptedMessage { nonce, ciphertext },
            Some(&aad),
        )
        .map_err(|_| MessagePayloadError::DecryptionFailed)?;
        String::from_utf8(plaintext).map_err(|_| MessagePayloadError::DecryptionFailed)
    }

    pub fn decrypt(
        &self,
        recipient_signing_key: &SigningKey,
        event_id: &str,
    ) -> Result<String, MessageDecryptError> {
        self.validate()
            .map_err(|_| MessageDecryptError::InvalidPayload)?;
        match self.version {
            LEGACY_MESSAGE_VERSION if self.ciphertext.is_none() => {
                self.text.clone().ok_or(MessageDecryptError::InvalidPayload)
            }
            ENCRYPTED_MESSAGE_VERSION
                if self.text.is_none()
                    && !self.chat_id.is_empty()
                    && !self.sender_id.is_empty()
                    && self
                        .recipient_id
                        .as_deref()
                        .is_some_and(|id| !id.is_empty())
                    && !event_id.is_empty() =>
            {
                if self.recipient_id.as_deref()
                    != Some(
                        crate::dht::NodeId::from_public_key(&recipient_signing_key.verifying_key())
                            .to_hex()
                            .as_str(),
                    )
                {
                    return Err(MessageDecryptError::RecipientKeyMismatch);
                }
                let ciphertext = self
                    .ciphertext
                    .as_deref()
                    .ok_or(MessageDecryptError::InvalidPayload)?;
                let decoded = BASE64
                    .decode(ciphertext)
                    .map_err(|_| MessageDecryptError::InvalidCiphertextEncoding)?;
                let plaintext = hal_crypto::decrypt_message(
                    recipient_signing_key,
                    &decoded,
                    &self.sender_id,
                    event_id,
                )
                .map_err(|_| MessageDecryptError::DecryptionFailed)?;
                String::from_utf8(plaintext).map_err(|_| MessageDecryptError::InvalidPlaintext)
            }
            _ => Err(MessageDecryptError::InvalidPayload),
        }
    }

    pub fn validate(&self) -> Result<(), MessagePayloadError> {
        if self
            .reply_to_id
            .as_ref()
            .is_some_and(|reply_to_id| reply_to_id.is_empty() || reply_to_id.len() > 128)
        {
            return Err(MessagePayloadError::InvalidMetadata);
        }
        if self
            .group_id
            .as_ref()
            .is_some_and(|group_id| group_id.is_empty() || group_id != &self.chat_id)
        {
            return Err(MessagePayloadError::InvalidMetadata);
        }
        if matches!(
            self.version,
            LEGACY_MESSAGE_VERSION | ENCRYPTED_MESSAGE_VERSION | RATCHET_MESSAGE_VERSION
        ) && (self.chain_id.is_some()
            || self.dh_pubkey.is_some()
            || self.prev_chain_length.is_some())
        {
            if self.version == RATCHET_MESSAGE_VERSION {
                let reason = if self.chain_id.is_some() {
                    "v3 must not carry chain_id"
                } else if self.dh_pubkey.is_some() {
                    "v3 must not carry dh_pubkey"
                } else {
                    "v3 must not carry prev_chain_length"
                };
                return Err(MessagePayloadError::InvalidPayload(reason));
            }
            return Err(MessagePayloadError::InvalidPayload(
                "V1-V2 must not carry V4 fields",
            ));
        }
        if self.version == MESSAGE_VERSION_V4 {
            if self.chain_id.is_none() {
                return Err(MessagePayloadError::InvalidPayload("v4 requires chain_id"));
            }
            if self.dh_pubkey.is_some() != self.prev_chain_length.is_some() {
                return Err(MessagePayloadError::InvalidPayload(
                    "v4 dh_pubkey and prev_chain_length must be present together",
                ));
            }
        }
        match self.version {
            LEGACY_MESSAGE_VERSION => {
                if self.text.is_none() || self.ciphertext.is_some() {
                    return Err(MessagePayloadError::MissingField(LEGACY_MESSAGE_VERSION));
                }
                if self.ratchet_counter.is_some() || self.ratchet_nonce.is_some() {
                    return Err(MessagePayloadError::UnexpectedField(LEGACY_MESSAGE_VERSION));
                }
                Ok(())
            }
            ENCRYPTED_MESSAGE_VERSION
                if self.text.is_none()
                    && self.ciphertext.is_some()
                    && !self.chat_id.is_empty()
                    && !self.sender_id.is_empty()
                    && self
                        .recipient_id
                        .as_deref()
                        .is_some_and(|id| !id.is_empty())
                    && self.ratchet_counter.is_none()
                    && self.ratchet_nonce.is_none() =>
            {
                Ok(())
            }
            ENCRYPTED_MESSAGE_VERSION => {
                if self.ratchet_counter.is_some() || self.ratchet_nonce.is_some() {
                    Err(MessagePayloadError::UnexpectedField(
                        ENCRYPTED_MESSAGE_VERSION,
                    ))
                } else {
                    Err(MessagePayloadError::MissingField(ENCRYPTED_MESSAGE_VERSION))
                }
            }
            RATCHET_MESSAGE_VERSION | MESSAGE_VERSION_V4 => {
                let version = self.version;
                if self.text.is_some() {
                    return Err(MessagePayloadError::UnexpectedField(version));
                }
                if self.chat_id.is_empty()
                    || self.sender_id.is_empty()
                    || self.recipient_id.as_deref().is_none_or(str::is_empty)
                    || self.ratchet_counter.is_none()
                    || self.ratchet_nonce.is_none()
                    || self.ciphertext.as_deref().is_none_or(str::is_empty)
                {
                    return Err(MessagePayloadError::MissingField(version));
                }
                let ciphertext = BASE64
                    .decode(
                        self.ciphertext
                            .as_deref()
                            .ok_or(MessagePayloadError::MissingField(version))?,
                    )
                    .map_err(|error| MessagePayloadError::InvalidBase64(error.to_string()))?;
                if ciphertext.is_empty() {
                    return Err(MessagePayloadError::MissingField(version));
                }
                let nonce = BASE64
                    .decode(
                        self.ratchet_nonce
                            .as_deref()
                            .ok_or(MessagePayloadError::MissingField(version))?,
                    )
                    .map_err(|error| MessagePayloadError::InvalidBase64(error.to_string()))?;
                if nonce.len() != hal_crypto::NONCE_LEN {
                    return Err(MessagePayloadError::InvalidMetadata);
                }
                Ok(())
            }
            version => Err(MessagePayloadError::InvalidVersion(version)),
        }
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn chat_id(&self) -> &str {
        &self.chat_id
    }

    pub fn sender_id(&self) -> &str {
        &self.sender_id
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn recipient_id(&self) -> Option<&str> {
        self.recipient_id.as_deref()
    }

    pub fn ratchet_counter(&self) -> Option<u64> {
        self.ratchet_counter
    }

    pub fn ratchet_nonce(&self) -> Option<&str> {
        self.ratchet_nonce.as_deref()
    }
}

fn ratchet_message_aad(
    chat_id: &str,
    sender_id: &str,
    recipient_id: &str,
    counter: u64,
    event_id: &str,
) -> Vec<u8> {
    let mut aad = b"hal-msg-v3:".to_vec();
    aad.extend_from_slice(chat_id.as_bytes());
    aad.extend_from_slice(sender_id.as_bytes());
    aad.extend_from_slice(recipient_id.as_bytes());
    aad.extend_from_slice(&counter.to_be_bytes());
    aad.extend_from_slice(event_id.as_bytes());
    aad
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterEntry {
    /// Assigned participant index in 1..=7.
    pub share_index: u32,
    #[serde(with = "bytes32_serde")]
    pub node_id: [u8; 32],
}

pub const JURY_ROSTER_DOMAIN: &[u8] = b"HAL-JURY-ROSTER-v1\0";
pub const JURY_INVITATION_DOMAIN_V2: &[u8] = b"HAL-JURY-INVITATION-v2\0";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InvitationPayloadError {
    #[error("roster must contain exactly 7 entries")]
    WrongRosterSize,
    #[error("roster share indices must be 1..=7 with no gaps")]
    InvalidRosterIndices,
    #[error("roster contains duplicate node ids")]
    DuplicateRosterNode,
    #[error("roster hash mismatch")]
    RosterHashMismatch,
    #[error("invitation ID mismatch")]
    InvitationIdMismatch,
    #[error("share_index not in roster or mismatched")]
    ShareIndexMismatch,
}

/// Canonical roster hash. Entries are hashed in ascending share-index order.
pub fn compute_roster_hash(
    complaint_id: &[u8; 32],
    roster: &[RosterEntry],
) -> Result<[u8; 32], InvitationPayloadError> {
    if roster.len() != 7 {
        return Err(InvitationPayloadError::WrongRosterSize);
    }
    let mut sorted = roster.to_vec();
    sorted.sort_by_key(|entry| entry.share_index);
    let mut seen = std::collections::HashSet::new();
    for (index, entry) in sorted.iter().enumerate() {
        if entry.share_index != index as u32 + 1 {
            return Err(InvitationPayloadError::InvalidRosterIndices);
        }
        if !seen.insert(entry.node_id) {
            return Err(InvitationPayloadError::DuplicateRosterNode);
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(JURY_ROSTER_DOMAIN);
    hasher.update(complaint_id);
    for entry in &sorted {
        hasher.update(entry.share_index.to_be_bytes());
        hasher.update(entry.node_id);
    }
    Ok(hasher.finalize().into())
}

/// Compute the v2 invitation ID, binding it to the roster generation.
pub fn compute_invitation_id_v2(
    complaint_id: &[u8; 32],
    complainant_node_id: &[u8; 32],
    candidate_node_id: &[u8; 32],
    roster_generation: u32,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(JURY_INVITATION_DOMAIN_V2);
    hasher.update(complaint_id);
    hasher.update(complainant_node_id);
    hasher.update(candidate_node_id);
    hasher.update(roster_generation.to_be_bytes());
    hasher.finalize().into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JuryInvitationPayload {
    #[serde(with = "bytes32_serde")]
    pub complaint_id: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub complainant_node_id: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub candidate_node_id: [u8; 32],
    /// Index assigned to this candidate (1..=7).
    pub share_index: u32,
    /// Full roster, sorted by share_index ascending.
    pub roster: Vec<RosterEntry>,
    /// Commitment to the full roster.
    #[serde(with = "bytes32_serde")]
    pub roster_hash: [u8; 32],
    /// Roster generation.
    pub roster_generation: u32,
    /// Invitation ID computed with the v2 formula.
    #[serde(with = "bytes32_serde")]
    pub invitation_id: [u8; 32],
    pub issued_at: u64,
    pub response_deadline: u64,
}

impl JuryInvitationPayload {
    /// Verify roster shape/hash, invitation ID, and this candidate's assigned index.
    pub fn verify(&self) -> Result<(), InvitationPayloadError> {
        let computed_hash = compute_roster_hash(&self.complaint_id, &self.roster)?;
        if computed_hash != self.roster_hash {
            return Err(InvitationPayloadError::RosterHashMismatch);
        }
        let expected_id = compute_invitation_id_v2(
            &self.complaint_id,
            &self.complainant_node_id,
            &self.candidate_node_id,
            self.roster_generation,
        );
        if expected_id != self.invitation_id {
            return Err(InvitationPayloadError::InvitationIdMismatch);
        }
        let entry = self
            .roster
            .iter()
            .find(|entry| entry.node_id == self.candidate_node_id)
            .ok_or(InvitationPayloadError::ShareIndexMismatch)?;
        if entry.share_index != self.share_index {
            return Err(InvitationPayloadError::ShareIndexMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JuryInvitationResponsePayload {
    #[serde(with = "bytes32_serde")]
    pub invitation_id: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub complaint_id: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub candidate_node_id: [u8; 32],
    pub accepted: bool,
    /// Must match the invitation; 0 when rejected.
    pub share_index: u32,
    #[serde(with = "bytes32_serde")]
    pub roster_hash: [u8; 32],
    /// Required when accepted; signed by the candidate.
    pub acceptance: Option<crate::dht::jury_acceptance::JuryAcceptanceRecord>,
    pub responded_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JuryShareDeliveryPayload {
    #[serde(with = "bytes32_serde")]
    pub message_id: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub complaint_id: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub dealer_node_id: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub dealer_public_key: [u8; 32],
    pub dealer_share_index: u32,
    pub recipient_share_index: u32,
    #[serde(with = "bytes32_serde")]
    pub share_value: [u8; 32],
    pub issued_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JuryShareAckPayload {
    #[serde(with = "bytes32_serde")]
    pub message_id: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub shared_message_id: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub complaint_id: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub dealer_node_id: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub recipient_node_id: [u8; 32],
    /// Receipt-only ACK: confirms that the recipient stored the share in its inbox.
    ///
    /// `true` means the share passed cryptographic verification (`verify_share`
    /// against Feldman commitments). Until E1-4d-3c-3 implements that verification,
    /// this field is always `false`: the recipient confirms delivery only, not
    /// validity. The dealer must not interpret `false` as rejection; it means
    /// "received, not yet verified".
    pub share_valid: bool,
    pub acked_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JuryEvidenceDeliveryPayload {
    #[serde(with = "bytes32_serde")]
    pub complaint_id: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub respondent_node_id: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub jury_pubkey: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub evidence_hash: [u8; 32],
    #[serde(with = "bytes32_serde")]
    pub encapsulation: [u8; 32],
    #[serde(with = "bytes12_serde")]
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    #[serde(with = "bytes64_serde")]
    pub signature: [u8; 64],
    pub issued_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JuryVerdictPrivatePayload {
    pub verdict: crate::jury_vote::JuryVerdict,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteRedemptionRequestPayload {
    pub token_hex: String,
    pub redeem_request_nonce: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteRedemptionResponsePayload {
    pub token_hash: [u8; 32],
    pub redeem_request_nonce: [u8; 32],
    pub proof: crate::dht::NestedProof,
}

mod bytes32_serde {
    use super::*;

    pub fn serialize<S: Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        value.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 32], D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|bytes: Vec<u8>| serde::de::Error::invalid_length(bytes.len(), &"32 bytes"))
    }
}

mod bytes12_serde {
    use super::*;

    pub fn serialize<S: Serializer>(value: &[u8; 12], serializer: S) -> Result<S::Ok, S::Error> {
        value.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 12], D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|bytes: Vec<u8>| serde::de::Error::invalid_length(bytes.len(), &"12 bytes"))
    }
}

mod bytes64_serde {
    use super::*;

    pub fn serialize<S: Serializer>(value: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        value.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 64], D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|bytes: Vec<u8>| serde::de::Error::invalid_length(bytes.len(), &"64 bytes"))
    }
}

impl SyncEvent {
    pub fn new(id: String, event_type: SyncEventType, data: String) -> Self {
        Self {
            id,
            event_type,
            data,
            timestamp: chrono::Utc::now().timestamp() as u64,
            signature: String::new(),
        }
    }

    pub fn jury_invitation(payload: &JuryInvitationPayload) -> Result<Self> {
        Ok(Self::new(
            format!("jury-invitation-{}", hex::encode(payload.invitation_id)),
            SyncEventType::JuryInvitation,
            serde_json::to_string(payload)?,
        ))
    }

    pub fn jury_invitation_response(payload: &JuryInvitationResponsePayload) -> Result<Self> {
        Ok(Self::new(
            format!(
                "jury-invitation-response-{}",
                hex::encode(payload.invitation_id)
            ),
            SyncEventType::JuryInvitationResponse,
            serde_json::to_string(payload)?,
        ))
    }

    pub fn jury_share_delivery(payload: &JuryShareDeliveryPayload) -> Result<Self> {
        Ok(Self::new(
            format!("jury-share-{}", hex::encode(payload.message_id)),
            SyncEventType::JuryShareDelivery,
            serde_json::to_string(payload)?,
        ))
    }

    pub fn jury_share_ack(payload: &JuryShareAckPayload) -> Result<Self> {
        Ok(Self::new(
            format!("jury-share-ack-{}", hex::encode(payload.message_id)),
            SyncEventType::JuryShareAck,
            serde_json::to_string(payload)?,
        ))
    }

    fn signing_payload(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            &self.id,
            self.event_type,
            &self.data,
            self.timestamp,
        ))?)
    }

    pub fn sign(&mut self, private_key: &[u8]) -> Result<()> {
        let bytes: [u8; 32] = private_key
            .try_into()
            .map_err(|_| anyhow::anyhow!("Ed25519 private key must be 32 bytes"))?;
        self.signature = hex::encode(
            SigningKey::from_bytes(&bytes)
                .sign(&self.signing_payload()?)
                .to_bytes(),
        );
        Ok(())
    }

    pub fn verify(&self, public_key: &str) -> Result<bool> {
        let public: [u8; 32] = hex::decode(public_key)
            .map_err(|err| anyhow::anyhow!("Invalid Ed25519 public key: {err}"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Ed25519 public key must be 32 bytes"))?;
        let signature: [u8; 64] = hex::decode(&self.signature)
            .map_err(|err| anyhow::anyhow!("Invalid event signature: {err}"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Ed25519 signature must be 64 bytes"))?;
        Ok(VerifyingKey::from_bytes(&public)?
            .verify(&self.signing_payload()?, &Signature::from_bytes(&signature))
            .is_ok())
    }

    pub fn jury_evidence_delivery(payload: &JuryEvidenceDeliveryPayload) -> Result<Self> {
        Ok(Self::new(
            format!(
                "jury-evidence-{}-{}",
                hex::encode(payload.complaint_id),
                hex::encode(payload.respondent_node_id)
            ),
            SyncEventType::JuryEvidenceDelivery,
            serde_json::to_string(payload)?,
        ))
    }

    pub fn jury_verdict_private(payload: &JuryVerdictPrivatePayload) -> Result<Self> {
        Ok(Self::new(
            format!(
                "jury-verdict-private-{}-{}",
                hex::encode(payload.verdict.complaint_id),
                hex::encode(payload.verdict.evidence_hash)
            ),
            SyncEventType::JuryVerdictPrivate,
            serde_json::to_string(payload)?,
        ))
    }

    pub fn invite_redemption_request(payload: &InviteRedemptionRequestPayload) -> Result<Self> {
        let token = hex::decode(&payload.token_hex)?;
        if token.len() != 16 {
            return Err(anyhow::anyhow!("invite redemption token must be 16 bytes"));
        }
        let mut hasher = sha2::Sha256::new();
        hasher.update(hal_protocol::invite::TOKEN_HASH_DOMAIN);
        hasher.update(token);
        Ok(Self::new(
            format!(
                "invite-redemption-request-{}-{}",
                hex::encode(hasher.finalize()),
                hex::encode(payload.redeem_request_nonce)
            ),
            SyncEventType::InviteRedemptionRequest,
            serde_json::to_string(payload)?,
        ))
    }

    pub fn invite_redemption_response(payload: &InviteRedemptionResponsePayload) -> Result<Self> {
        Ok(Self::new(
            format!(
                "invite-redemption-response-{}-{}",
                hex::encode(payload.token_hash),
                hex::encode(payload.redeem_request_nonce)
            ),
            SyncEventType::InviteRedemptionResponse,
            serde_json::to_string(payload)?,
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncSettings {
    pub language: String,
    pub theme: String,
    pub notifications_enabled: bool,
}

impl Default for SyncSettings {
    fn default() -> Self {
        Self {
            language: "uk".into(),
            theme: "dark".into(),
            notifications_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncedContact {
    pub pubkey: String,
    pub name: String,
    pub last_modified: u64,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncManager {
    pub device_id: String,
    pub contacts: HashMap<String, SyncedContact>,
    pub settings: SyncSettings,
    pub events: Vec<SyncEvent>,
    pub last_sync: u64,
    pub version: u64,
    #[serde(default)]
    applied_event_ids: HashSet<String>,
    #[serde(default)]
    applied_event_id_order: VecDeque<String>,
    #[serde(default)]
    contact_tombstones: HashMap<String, (u64, String)>,
    #[serde(default)]
    contact_last_event_ids: HashMap<String, String>,
    #[serde(default)]
    settings_last_modified: u64,
    #[serde(default)]
    settings_last_event_id: Option<String>,
    #[cfg(test)]
    #[serde(skip)]
    fail_next_message_persist: bool,
}

fn is_newer_event(event_ts: u64, event_id: &str, current_ts: u64, current_id: &str) -> bool {
    event_ts > current_ts || (event_ts == current_ts && event_id > current_id)
}

impl SyncManager {
    pub fn new(device_id: String) -> Self {
        Self {
            device_id,
            contacts: HashMap::new(),
            settings: SyncSettings::default(),
            events: Vec::new(),
            last_sync: chrono::Utc::now().timestamp() as u64,
            version: 0,
            applied_event_ids: HashSet::new(),
            applied_event_id_order: VecDeque::new(),
            contact_tombstones: HashMap::new(),
            contact_last_event_ids: HashMap::new(),
            settings_last_modified: 0,
            settings_last_event_id: None,
            #[cfg(test)]
            fail_next_message_persist: false,
        }
    }

    pub fn sync_contact(&mut self, pubkey: String, name: String) -> Result<()> {
        let event = SyncEvent::new(
            uuid::Uuid::new_v4().to_string(),
            SyncEventType::ContactAdded,
            serde_json::json!({"pubkey": pubkey, "name": name}).to_string(),
        );
        self.contacts.insert(
            pubkey.clone(),
            SyncedContact {
                pubkey: pubkey.clone(),
                name: name.clone(),
                last_modified: event.timestamp,
                version: self.version,
            },
        );
        self.contact_last_event_ids.insert(pubkey, event.id.clone());
        self.push_event(event);
        self.version += 1;
        Ok(())
    }

    pub fn remove_contact(&mut self, pubkey: &str) -> Result<()> {
        self.contacts.remove(pubkey);
        let event = SyncEvent::new(
            uuid::Uuid::new_v4().to_string(),
            SyncEventType::ContactDeleted,
            serde_json::json!({"pubkey": pubkey}).to_string(),
        );
        self.contact_tombstones
            .insert(pubkey.to_string(), (event.timestamp, event.id.clone()));
        self.contact_last_event_ids.remove(pubkey);
        self.push_event(event);
        self.version += 1;
        Ok(())
    }

    pub fn sync_settings(&mut self, settings: SyncSettings) -> Result<()> {
        self.settings = settings.clone();
        let event = SyncEvent::new(
            uuid::Uuid::new_v4().to_string(),
            SyncEventType::SettingsUpdated,
            serde_json::to_string(&settings)?,
        );
        self.settings_last_modified = event.timestamp;
        self.settings_last_event_id = Some(event.id.clone());
        self.push_event(event);
        self.version += 1;
        Ok(())
    }

    #[deprecated(note = "use add_message_encrypted_with_id for direct messages")]
    #[allow(deprecated)]
    pub fn add_message(
        &mut self,
        chat_id: String,
        sender_id: String,
        recipient_id: Option<String>,
        text: String,
    ) -> Result<()> {
        self.add_message_with_id(
            uuid::Uuid::new_v4().to_string(),
            chrono::Utc::now().timestamp().max(0) as u64,
            chat_id,
            sender_id,
            recipient_id,
            text,
        )
    }

    #[deprecated(note = "use add_message_encrypted_with_id for direct messages")]
    pub fn add_message_with_id(
        &mut self,
        event_id: String,
        timestamp: u64,
        chat_id: String,
        sender_id: String,
        recipient_id: Option<String>,
        text: String,
    ) -> Result<()> {
        let payload =
            MessageAddedPayload::new_legacy(chat_id, sender_id, recipient_id, text, timestamp);
        self.push_message_event(event_id, timestamp, payload)
    }

    pub fn add_message_encrypted_with_id(
        &mut self,
        event_id: String,
        timestamp: u64,
        chat_id: String,
        sender_id: String,
        recipient_id: String,
        recipient_pubkey: &VerifyingKey,
        text: &str,
    ) -> Result<()> {
        let payload = MessageAddedPayload::new_encrypted(
            chat_id,
            sender_id,
            recipient_id,
            recipient_pubkey,
            text,
            timestamp,
            &event_id,
        )
        .map_err(|error| anyhow::anyhow!("failed to create encrypted message payload: {error}"))?;
        self.add_message_payload_with_id(event_id, timestamp, payload)
    }

    pub(crate) fn add_message_payload_with_id(
        &mut self,
        event_id: String,
        timestamp: u64,
        payload: MessageAddedPayload,
    ) -> Result<()> {
        #[cfg(test)]
        if std::mem::replace(&mut self.fail_next_message_persist, false) {
            return Err(anyhow::anyhow!("injected message persistence failure"));
        }
        payload
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid message payload: {error}"))?;
        if !matches!(
            payload.version,
            ENCRYPTED_MESSAGE_VERSION | RATCHET_MESSAGE_VERSION | MESSAGE_VERSION_V4
        ) {
            return Err(anyhow::anyhow!(
                "encrypted message event requires payload version 2, 3, or 4"
            ));
        }
        self.push_message_event(event_id, timestamp, payload)
    }

    #[cfg(test)]
    pub(crate) fn fail_next_message_persist(&mut self) {
        self.fail_next_message_persist = true;
    }

    fn push_message_event(
        &mut self,
        event_id: String,
        timestamp: u64,
        payload: MessageAddedPayload,
    ) -> Result<()> {
        let mut event = SyncEvent::new(
            event_id,
            SyncEventType::MessageAdded,
            serde_json::to_string(&payload)?,
        );
        event.timestamp = timestamp;
        self.push_event(event);
        self.version += 1;
        Ok(())
    }

    pub fn add_home_event(&mut self, event_type: SyncEventType, data: String) -> Result<()> {
        if !matches!(
            event_type,
            SyncEventType::HomeLinkRequest
                | SyncEventType::HomeLinkResponse
                | SyncEventType::HomeLinkConfirm
                | SyncEventType::HomeSyncChunk
                | SyncEventType::HomeSyncAck
        ) {
            return Err(anyhow::anyhow!("event type is not a Home linking event"));
        }
        self.push_event(SyncEvent::new(
            uuid::Uuid::new_v4().to_string(),
            event_type,
            data,
        ));
        self.version += 1;
        Ok(())
    }

    pub fn add_protocol_event(&mut self, event_type: SyncEventType, data: String) -> Result<()> {
        if !matches!(
            event_type,
            SyncEventType::X3dhInit | SyncEventType::X3dhRespond
        ) {
            return Err(anyhow::anyhow!("event type is not a protocol event"));
        }
        self.push_event(SyncEvent::new(
            uuid::Uuid::new_v4().to_string(),
            event_type,
            data,
        ));
        self.version += 1;
        Ok(())
    }

    pub fn add_group_create_event(&mut self, payload: GroupCreatePayload) -> Result<()> {
        if uuid::Uuid::parse_str(&payload.group_id).is_err()
            || payload.name.trim().is_empty()
            || payload.name.len() > 64
            || payload.recipient_id.is_empty()
            || payload.members.is_empty()
            || payload.members.len() > 500
            || payload
                .avatar_b64
                .as_ref()
                .is_some_and(|avatar| avatar.len() > 350_000)
        {
            return Err(anyhow::anyhow!("invalid GroupCreate event metadata"));
        }
        self.push_event(SyncEvent::new(
            uuid::Uuid::new_v4().to_string(),
            SyncEventType::GroupCreate,
            serde_json::to_string(&payload)?,
        ));
        self.version += 1;
        Ok(())
    }

    pub fn add_group_key_distribution_event(
        &mut self,
        payload: GroupKeyDistributionPayload,
    ) -> Result<()> {
        if uuid::Uuid::parse_str(&payload.group_id).is_err()
            || payload.recipient_id.is_empty()
            || hex::decode(&payload.group_key).is_err()
            || hex::decode(&payload.group_key).is_ok_and(|key| key.len() != 32)
        {
            return Err(anyhow::anyhow!(
                "invalid GroupKeyDistribution event metadata"
            ));
        }
        self.push_event(SyncEvent::new(
            uuid::Uuid::new_v4().to_string(),
            SyncEventType::GroupKeyDistribution,
            serde_json::to_string(&payload)?,
        ));
        self.version += 1;
        Ok(())
    }

    pub fn add_group_message_event(&mut self, payload: GroupMessagePayload) -> Result<()> {
        if uuid::Uuid::parse_str(&payload.message_id).is_err()
            || uuid::Uuid::parse_str(&payload.group_id).is_err()
            || payload.sender_id.is_empty()
            || payload.recipient_id.is_empty()
            || payload.nonce.is_empty()
            || payload.ciphertext.is_empty()
            || payload.ciphertext.len() > 16_384
        {
            return Err(anyhow::anyhow!("invalid GroupMessage event metadata"));
        }
        self.push_event(SyncEvent::new(
            uuid::Uuid::new_v4().to_string(),
            SyncEventType::GroupMessage,
            serde_json::to_string(&payload)?,
        ));
        self.version += 1;
        Ok(())
    }

    pub fn add_message_read_event(&mut self, payload: MessageReadPayload) -> Result<()> {
        if uuid::Uuid::parse_str(&payload.message_id).is_err()
            || payload.reader_id.is_empty()
            || payload.recipient_id.is_empty()
            || payload.reader_id == payload.recipient_id
        {
            return Err(anyhow::anyhow!("invalid MessageRead event metadata"));
        }
        self.push_event(SyncEvent::new(
            uuid::Uuid::new_v4().to_string(),
            SyncEventType::MessageRead,
            serde_json::to_string(&payload)?,
        ));
        self.version += 1;
        Ok(())
    }

    pub fn add_profile_update_event(&mut self, payload: ProfileUpdatePayload) -> Result<()> {
        if payload.display_name.trim().is_empty()
            || payload.display_name.chars().count() > 64
            || payload.display_name.chars().any(char::is_control)
            || payload.recipient_id.is_empty()
            || payload
                .avatar_b64
                .as_ref()
                .is_some_and(|avatar| avatar.len() > 350_000)
        {
            return Err(anyhow::anyhow!("invalid ProfileUpdate event metadata"));
        }
        self.push_event(SyncEvent::new(
            uuid::Uuid::new_v4().to_string(),
            SyncEventType::ProfileUpdate,
            serde_json::to_string(&payload)?,
        ));
        self.version += 1;
        Ok(())
    }

    pub fn get_pending_events(&self) -> Vec<SyncEvent> {
        self.events.clone()
    }

    fn push_event(&mut self, event: SyncEvent) {
        self.events.push(event);
    }

    fn remember_applied_event_id(&mut self, event_id: String) {
        self.applied_event_ids.insert(event_id.clone());
        self.applied_event_id_order.push_back(event_id);
        while self.applied_event_ids.len() > MAX_APPLIED_EVENT_IDS {
            if let Some(oldest) = self.applied_event_id_order.pop_front() {
                self.applied_event_ids.remove(&oldest);
            } else if let Some(oldest) = self.applied_event_ids.iter().next().cloned() {
                self.applied_event_ids.remove(&oldest);
            }
        }
    }

    pub(crate) fn remove_unsent_event(&mut self, event_id: &str) -> bool {
        let previous_len = self.events.len();
        self.events.retain(|event| event.id != event_id);
        let removed = self.events.len() != previous_len;
        if removed {
            self.version = self.version.saturating_sub(1);
        }
        removed
    }

    pub fn clear_events(&mut self) {
        self.events.clear();
        self.last_sync = chrono::Utc::now().timestamp() as u64;
    }

    pub fn merge_events(&mut self, events: Vec<SyncEvent>) -> Result<()> {
        for event in events {
            if self.applied_event_ids.contains(&event.id) {
                continue;
            }
            self.remember_applied_event_id(event.id.clone());
            match event.event_type {
                SyncEventType::ContactAdded | SyncEventType::ContactUpdated => {
                    let data: serde_json::Value = serde_json::from_str(&event.data)?;
                    let pubkey = data["pubkey"].as_str().unwrap_or_default().to_string();
                    let name = data["name"].as_str().unwrap_or("Unknown").to_string();
                    let newer_than_contact = self.contacts.get(&pubkey).map_or(true, |current| {
                        is_newer_event(
                            event.timestamp,
                            &event.id,
                            current.last_modified,
                            self.contact_last_event_ids
                                .get(&pubkey)
                                .map(String::as_str)
                                .unwrap_or_default(),
                        )
                    });
                    let newer_than_delete = self.contact_tombstones.get(&pubkey).map_or(
                        true,
                        |(deleted_at, deleted_id)| {
                            is_newer_event(event.timestamp, &event.id, *deleted_at, deleted_id)
                        },
                    );
                    let newer = newer_than_contact && newer_than_delete;
                    if newer {
                        self.contacts.insert(
                            pubkey.clone(),
                            SyncedContact {
                                pubkey: pubkey.clone(),
                                name,
                                last_modified: event.timestamp,
                                version: self.version,
                            },
                        );
                        self.contact_last_event_ids.insert(pubkey, event.id.clone());
                    }
                }
                SyncEventType::ContactDeleted => {
                    let data: serde_json::Value = serde_json::from_str(&event.data)?;
                    if let Some(pubkey) = data["pubkey"].as_str() {
                        let newer_than_contact =
                            self.contacts.get(pubkey).map_or(true, |current| {
                                is_newer_event(
                                    event.timestamp,
                                    &event.id,
                                    current.last_modified,
                                    self.contact_last_event_ids
                                        .get(pubkey)
                                        .map(String::as_str)
                                        .unwrap_or_default(),
                                )
                            });
                        let newer_than_delete = self.contact_tombstones.get(pubkey).map_or(
                            true,
                            |(deleted_at, deleted_id)| {
                                is_newer_event(event.timestamp, &event.id, *deleted_at, deleted_id)
                            },
                        );
                        let newer = newer_than_contact && newer_than_delete;
                        if newer {
                            self.contacts.remove(pubkey);
                            self.contact_last_event_ids.remove(pubkey);
                            self.contact_tombstones
                                .insert(pubkey.to_string(), (event.timestamp, event.id.clone()));
                        }
                    }
                }
                SyncEventType::SettingsUpdated => {
                    if is_newer_event(
                        event.timestamp,
                        &event.id,
                        self.settings_last_modified,
                        self.settings_last_event_id.as_deref().unwrap_or_default(),
                    ) {
                        self.settings = serde_json::from_str(&event.data)?;
                        self.settings_last_modified = event.timestamp;
                        self.settings_last_event_id = Some(event.id.clone());
                    }
                }
                SyncEventType::MessageAdded
                | SyncEventType::MessageRead
                | SyncEventType::GroupCreate
                | SyncEventType::GroupKeyDistribution
                | SyncEventType::GroupMessage
                | SyncEventType::ProfileUpdate
                | SyncEventType::FileTransferInit
                | SyncEventType::FileTransferChunk
                | SyncEventType::FileTransferComplete
                | SyncEventType::FileTransferCancel => {}
                SyncEventType::HomeLinkRequest
                | SyncEventType::HomeLinkResponse
                | SyncEventType::HomeLinkConfirm
                | SyncEventType::HomeSyncChunk
                | SyncEventType::HomeSyncAck
                | SyncEventType::DraftUpdate
                | SyncEventType::SasPairing
                | SyncEventType::RelayRequest
                | SyncEventType::RelayResponse
                | SyncEventType::RelayForward
                | SyncEventType::X3dhInit
                | SyncEventType::X3dhRespond
                | SyncEventType::JuryInvitation
                | SyncEventType::JuryInvitationResponse
                | SyncEventType::JuryShareDelivery
                | SyncEventType::JuryShareAck
                | SyncEventType::JuryEvidenceDelivery
                | SyncEventType::JuryVerdictPrivate
                | SyncEventType::InviteRedemptionRequest
                | SyncEventType::InviteRedemptionResponse
                | SyncEventType::PeerPresence => {
                    // Home linking is handled outside the generic sync merge path.
                }
            }
        }
        Ok(())
    }

    pub fn get_contact_count(&self) -> usize {
        self.contacts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::jury_acceptance::sign_acceptance;
    use ed25519_dalek::SigningKey;

    #[test]
    fn file_transfer_chunk_uses_bounded_base64_json_encoding() {
        let payload = FileTransferChunkPayload {
            recipient_id: "peer".to_string(),
            file_id: "a42977d5-ae19-455d-9a47-0e21fcf22ba5".to_string(),
            chunk_index: 0,
            data: vec![0x5a; FILE_TRANSFER_CHUNK_SIZE],
        };
        let encoded = serde_json::to_vec(&payload).expect("serialize file chunk");
        assert!(encoded.len() < 48 * 1024);
        let decoded: FileTransferChunkPayload =
            serde_json::from_slice(&encoded).expect("deserialize file chunk");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn invite_redemption_payload_roundtrip() {
        let request = InviteRedemptionRequestPayload {
            token_hex: "5a".repeat(16),
            redeem_request_nonce: [7; 32],
        };
        let encoded = serde_json::to_vec(&request).expect("serialize request");
        let decoded: InviteRedemptionRequestPayload =
            serde_json::from_slice(&encoded).expect("deserialize request");
        assert_eq!(decoded, request);

        let response = InviteRedemptionResponsePayload {
            token_hash: [8; 32],
            redeem_request_nonce: [9; 32],
            proof: crate::dht::NestedProof { hops: Vec::new() },
        };
        let encoded = serde_json::to_vec(&response).expect("serialize response");
        let decoded: InviteRedemptionResponsePayload =
            serde_json::from_slice(&encoded).expect("deserialize response");
        assert_eq!(decoded, response);
    }

    #[test]
    fn invite_redemption_sync_events_encode_decode() {
        let request = InviteRedemptionRequestPayload {
            token_hex: "6b".repeat(16),
            redeem_request_nonce: [3; 32],
        };
        let request_event =
            SyncEvent::invite_redemption_request(&request).expect("create request event");
        assert_eq!(
            request_event.event_type,
            SyncEventType::InviteRedemptionRequest
        );
        assert_eq!(
            serde_json::from_str::<InviteRedemptionRequestPayload>(&request_event.data)
                .expect("decode request event"),
            request
        );

        let response = InviteRedemptionResponsePayload {
            token_hash: [4; 32],
            redeem_request_nonce: [5; 32],
            proof: crate::dht::NestedProof { hops: Vec::new() },
        };
        let response_event =
            SyncEvent::invite_redemption_response(&response).expect("create response event");
        assert_eq!(
            response_event.event_type,
            SyncEventType::InviteRedemptionResponse
        );
        assert_eq!(
            serde_json::from_str::<InviteRedemptionResponsePayload>(&response_event.data)
                .expect("decode response event"),
            response
        );
    }

    fn test_roster() -> Vec<RosterEntry> {
        (1..=7)
            .map(|share_index| RosterEntry {
                share_index,
                node_id: [share_index as u8; 32],
            })
            .collect()
    }

    fn test_invitation() -> JuryInvitationPayload {
        let complaint_id = [1; 32];
        let complainant_node_id = [2; 32];
        let roster = test_roster();
        let candidate_node_id = roster[2].node_id;
        let roster_generation = 4;
        JuryInvitationPayload {
            complaint_id,
            complainant_node_id,
            candidate_node_id,
            share_index: 3,
            roster_hash: compute_roster_hash(&complaint_id, &roster).expect("compute roster hash"),
            roster,
            roster_generation,
            invitation_id: compute_invitation_id_v2(
                &complaint_id,
                &complainant_node_id,
                &candidate_node_id,
                roster_generation,
            ),
            issued_at: 100,
            response_deadline: 200,
        }
    }

    #[test]
    fn sync_event_type_jury_variants_serialize_roundtrip() {
        let variants = [
            SyncEventType::JuryInvitation,
            SyncEventType::JuryInvitationResponse,
            SyncEventType::JuryShareDelivery,
            SyncEventType::JuryShareAck,
            SyncEventType::JuryEvidenceDelivery,
        ];
        for variant in variants {
            let encoded = serde_json::to_string(&variant).expect("serialize event type");
            let decoded: SyncEventType =
                serde_json::from_str(&encoded).expect("deserialize event type");
            assert_eq!(decoded, variant);
        }
    }

    #[test]
    fn invitation_id_v2_deterministic() {
        assert_eq!(
            compute_invitation_id_v2(&[1; 32], &[2; 32], &[3; 32], 4),
            compute_invitation_id_v2(&[1; 32], &[2; 32], &[3; 32], 4)
        );
    }

    #[test]
    fn invitation_id_v2_differs_on_generation() {
        assert_ne!(
            compute_invitation_id_v2(&[1; 32], &[2; 32], &[3; 32], 4),
            compute_invitation_id_v2(&[1; 32], &[2; 32], &[3; 32], 5)
        );
    }

    #[test]
    fn roster_entry_serde_roundtrip() {
        let entry = test_roster().remove(0);
        let encoded = serde_json::to_string(&entry).expect("serialize roster entry");
        assert_eq!(
            serde_json::from_str::<RosterEntry>(&encoded).expect("deserialize"),
            entry
        );
    }

    #[test]
    fn compute_roster_hash_deterministic() {
        let roster = test_roster();
        assert_eq!(
            compute_roster_hash(&[10; 32], &roster).expect("hash roster"),
            compute_roster_hash(&[10; 32], &roster).expect("hash roster again")
        );
    }

    #[test]
    fn compute_roster_hash_differs_on_complaint() {
        let roster = test_roster();
        assert_ne!(
            compute_roster_hash(&[10; 32], &roster).expect("hash roster"),
            compute_roster_hash(&[11; 32], &roster).expect("hash roster")
        );
    }

    #[test]
    fn compute_roster_hash_differs_on_reorder() {
        let roster = test_roster();
        let mut reordered = roster.clone();
        reordered.reverse();
        assert_eq!(
            compute_roster_hash(&[10; 32], &roster).expect("hash sorted roster"),
            compute_roster_hash(&[10; 32], &reordered).expect("hash reordered roster")
        );
    }

    #[test]
    fn compute_roster_hash_rejects_wrong_size() {
        let roster = test_roster();
        assert_eq!(
            compute_roster_hash(&[10; 32], &roster[..6]),
            Err(InvitationPayloadError::WrongRosterSize)
        );
        let mut oversized = roster;
        oversized.push(RosterEntry {
            share_index: 8,
            node_id: [8; 32],
        });
        assert_eq!(
            compute_roster_hash(&[10; 32], &oversized),
            Err(InvitationPayloadError::WrongRosterSize)
        );
    }

    #[test]
    fn compute_roster_hash_rejects_gap_indices() {
        let mut roster = test_roster();
        roster[1].share_index = 3;
        roster[2].share_index = 4;
        roster[3].share_index = 5;
        roster[4].share_index = 6;
        roster[5].share_index = 7;
        roster[6].share_index = 8;
        assert_eq!(
            compute_roster_hash(&[10; 32], &roster),
            Err(InvitationPayloadError::InvalidRosterIndices)
        );
    }

    #[test]
    fn compute_roster_hash_rejects_duplicate_node() {
        let mut roster = test_roster();
        roster[6].node_id = roster[0].node_id;
        assert_eq!(
            compute_roster_hash(&[10; 32], &roster),
            Err(InvitationPayloadError::DuplicateRosterNode)
        );
    }

    #[test]
    fn invitation_payload_verify_accepts_valid() {
        test_invitation()
            .verify()
            .expect("valid invitation should verify");
    }

    #[test]
    fn invitation_payload_verify_rejects_wrong_roster_hash() {
        let mut invitation = test_invitation();
        invitation.roster_hash = [99; 32];
        assert_eq!(
            invitation.verify(),
            Err(InvitationPayloadError::RosterHashMismatch)
        );
    }

    #[test]
    fn invitation_payload_verify_rejects_candidate_not_in_roster() {
        let mut invitation = test_invitation();
        invitation.candidate_node_id = [99; 32];
        invitation.invitation_id = compute_invitation_id_v2(
            &invitation.complaint_id,
            &invitation.complainant_node_id,
            &invitation.candidate_node_id,
            invitation.roster_generation,
        );
        assert_eq!(
            invitation.verify(),
            Err(InvitationPayloadError::ShareIndexMismatch)
        );
    }

    #[test]
    fn invitation_payload_verify_rejects_mismatched_index() {
        let mut invitation = test_invitation();
        invitation.share_index = 4;
        assert_eq!(
            invitation.verify(),
            Err(InvitationPayloadError::ShareIndexMismatch)
        );
    }

    #[test]
    fn jury_invitation_payload_serde_roundtrip() {
        let payload = test_invitation();
        let encoded = serde_json::to_string(&payload).expect("serialize invitation");
        assert_eq!(
            serde_json::from_str::<JuryInvitationPayload>(&encoded).expect("deserialize"),
            payload
        );
    }

    #[test]
    fn invitation_response_payload_serde_roundtrip() {
        let signing_key = SigningKey::from_bytes(&[42; 32]);
        let complaint_id = [10; 32];
        let acceptance =
            sign_acceptance(&signing_key, complaint_id, 3, 150).expect("sign jury acceptance");
        let payload = JuryInvitationResponsePayload {
            invitation_id: [11; 32],
            complaint_id,
            candidate_node_id: acceptance.juror_node_id,
            accepted: true,
            share_index: 3,
            roster_hash: [12; 32],
            acceptance: Some(acceptance),
            responded_at: 150,
        };
        let encoded = serde_json::to_string(&payload).expect("serialize response");
        assert_eq!(
            serde_json::from_str::<JuryInvitationResponsePayload>(&encoded)
                .expect("deserialize response"),
            payload
        );
    }

    #[test]
    fn jury_share_delivery_payload_serde_roundtrip() {
        let payload = JuryShareDeliveryPayload {
            message_id: [1; 32],
            complaint_id: [2; 32],
            dealer_node_id: [3; 32],
            dealer_public_key: [4; 32],
            dealer_share_index: 1,
            recipient_share_index: 2,
            share_value: [5; 32],
            issued_at: 100,
        };
        let encoded = serde_json::to_string(&payload).expect("serialize share");
        assert_eq!(
            serde_json::from_str::<JuryShareDeliveryPayload>(&encoded).expect("deserialize"),
            payload
        );
    }

    #[test]
    fn jury_share_ack_payload_serde_roundtrip() {
        let payload = JuryShareAckPayload {
            message_id: [1; 32],
            shared_message_id: [5; 32],
            complaint_id: [2; 32],
            dealer_node_id: [3; 32],
            recipient_node_id: [4; 32],
            share_valid: true,
            acked_at: 100,
        };
        let encoded = serde_json::to_string(&payload).expect("serialize ACK");
        assert_eq!(
            serde_json::from_str::<JuryShareAckPayload>(&encoded).expect("deserialize"),
            payload
        );
    }

    #[test]
    fn signed_event_roundtrip_rejects_tampering() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let public = hex::encode(key.verifying_key().to_bytes());
        let mut event = SyncEvent::new(
            "event".into(),
            SyncEventType::MessageAdded,
            "payload".into(),
        );
        event.sign(&key.to_bytes()).expect("sign");
        assert!(event.verify(&public).expect("verify"));
        event.data = "tampered".into();
        assert!(!event.verify(&public).expect("tampered verify"));
    }

    #[test]
    fn group_create_event_roundtrips_with_recipient() {
        let payload = GroupCreatePayload {
            group_id: "75fe0cc2-1cef-4477-a6eb-90e2624a0056".into(),
            name: "Network Group".into(),
            avatar_b64: Some("aGVsbG8=".into()),
            members: vec!["member-public-key".into()],
            recipient_id: "recipient".into(),
        };
        let mut manager = SyncManager::new("identity".into());
        manager
            .add_group_create_event(payload.clone())
            .expect("add group invite");
        let events = manager.get_pending_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, SyncEventType::GroupCreate);
        assert_eq!(
            serde_json::from_str::<GroupCreatePayload>(&events[0].data)
                .expect("deserialize group invite"),
            payload
        );
    }

    #[test]
    fn two_clients_merge_same_contact_state() {
        let mut android = SyncManager::new("shared-identity".into());
        let mut desktop = SyncManager::new("shared-identity".into());
        android
            .sync_contact("peer".into(), "Peer".into())
            .expect("contact");
        desktop
            .merge_events(android.get_pending_events())
            .expect("merge");
        assert_eq!(desktop.get_contact_count(), 1);
    }

    #[test]
    fn applied_event_ids_capped() {
        let mut manager = SyncManager::new("identity".into());
        let events = (0..MAX_APPLIED_EVENT_IDS + 10_000)
            .map(|index| {
                SyncEvent::new(
                    format!("event-{index}"),
                    SyncEventType::X3dhInit,
                    String::new(),
                )
            })
            .collect();
        manager.merge_events(events).expect("merge events");
        assert_eq!(manager.applied_event_ids.len(), MAX_APPLIED_EVENT_IDS);
        assert_eq!(manager.applied_event_id_order.len(), MAX_APPLIED_EVENT_IDS);
        assert!(!manager.applied_event_ids.contains("event-0"));
    }

    #[test]
    fn newer_delete_wins_over_older_add() {
        let mut manager = SyncManager::new("identity".into());
        let mut add = SyncEvent::new(
            "add".into(),
            SyncEventType::ContactAdded,
            serde_json::json!({"pubkey": "peer", "name": "Peer"}).to_string(),
        );
        add.timestamp = 10;
        let mut delete = SyncEvent::new(
            "delete".into(),
            SyncEventType::ContactDeleted,
            serde_json::json!({"pubkey": "peer"}).to_string(),
        );
        delete.timestamp = 20;
        manager.merge_events(vec![add, delete]).expect("merge");
        assert_eq!(manager.get_contact_count(), 0);
    }

    #[test]
    fn older_delete_loses_to_newer_add() {
        let mut manager = SyncManager::new("identity".into());
        let mut delete = SyncEvent::new(
            "delete".into(),
            SyncEventType::ContactDeleted,
            serde_json::json!({"pubkey": "peer"}).to_string(),
        );
        delete.timestamp = 10;
        let mut add = SyncEvent::new(
            "add".into(),
            SyncEventType::ContactAdded,
            serde_json::json!({"pubkey": "peer", "name": "Peer"}).to_string(),
        );
        add.timestamp = 20;
        manager.merge_events(vec![delete, add]).expect("merge");
        assert_eq!(manager.get_contact_count(), 1);
    }

    #[test]
    fn settings_lww_by_timestamp() {
        let mut manager = SyncManager::new("identity".into());
        let mut newer = SyncEvent::new(
            "newer".into(),
            SyncEventType::SettingsUpdated,
            serde_json::json!({"language": "en", "theme": "light", "notifications_enabled": false})
                .to_string(),
        );
        newer.timestamp = 20;
        let mut older = SyncEvent::new(
            "older".into(),
            SyncEventType::SettingsUpdated,
            serde_json::json!({"language": "uk", "theme": "dark", "notifications_enabled": true})
                .to_string(),
        );
        older.timestamp = 10;
        manager.merge_events(vec![newer, older]).expect("merge");
        assert_eq!(manager.settings.language, "en");
    }

    #[test]
    fn tie_break_by_event_id_contact_add() {
        let mut first = SyncManager::new("identity".into());
        let mut second = SyncManager::new("identity".into());
        let data_a = serde_json::json!({"pubkey": "peer", "name": "A"}).to_string();
        let data_b = serde_json::json!({"pubkey": "peer", "name": "B"}).to_string();
        let mut event_a = SyncEvent::new("event-a".into(), SyncEventType::ContactAdded, data_a);
        let mut event_b = SyncEvent::new("event-b".into(), SyncEventType::ContactUpdated, data_b);
        event_a.timestamp = 10;
        event_b.timestamp = 10;

        first
            .merge_events(vec![event_a.clone(), event_b.clone()])
            .expect("merge");
        second.merge_events(vec![event_b, event_a]).expect("merge");
        assert_eq!(first.contacts["peer"].name, "B");
        assert_eq!(second.contacts["peer"].name, "B");
    }

    #[test]
    fn message_added_payload_roundtrip_with_recipient() {
        let payload = MessageAddedPayload {
            version: LEGACY_MESSAGE_VERSION,
            chat_id: "chat-1".into(),
            group_id: None,
            reply_to_id: None,
            sender_id: "sender-a".into(),
            recipient_id: Some("recipient-b".into()),
            timestamp: 123,
            text: Some("hello".into()),
            ciphertext: None,
            ratchet_counter: None,
            ratchet_nonce: None,
            chain_id: None,
            dh_pubkey: None,
            prev_chain_length: None,
        };

        let encoded = serde_json::to_string(&payload).expect("serialize");
        let decoded: MessageAddedPayload = serde_json::from_str(&encoded).expect("deserialize");

        assert_eq!(decoded.recipient_id.as_deref(), Some("recipient-b"));
    }

    #[test]
    fn message_added_payload_roundtrip_without_recipient() {
        let json = r#"{"chat_id":"chat-1","sender_id":"sender-a","text":"hello"}"#;
        let decoded: MessageAddedPayload =
            serde_json::from_str(json).expect("deserialize old payload");

        assert_eq!(decoded.recipient_id, None);
        assert_eq!(decoded.text.as_deref(), Some("hello"));
    }

    #[test]
    fn message_added_payload_backward_compat() {
        let json = r#"{"chat_id":"chat-1","sender_id":"sender-a","text":"hello"}"#;

        let decoded: MessageAddedPayload =
            serde_json::from_str(json).expect("deserialize old payload");
        let reencoded = serde_json::to_string(&decoded).expect("re-serialize");

        assert!(reencoded.contains("\"recipient_id\":null"));
    }

    fn test_identity(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn identity_id(key: &SigningKey) -> String {
        crate::dht::NodeId::from_public_key(&key.verifying_key()).to_hex()
    }

    #[test]
    fn message_payload_v1_roundtrip() {
        let payload = MessageAddedPayload::new_legacy(
            "chat".into(),
            "sender".into(),
            Some("recipient".into()),
            "legacy text".into(),
            123,
        );
        let json = serde_json::to_string(&payload).expect("serialize v1");
        let parsed: MessageAddedPayload = serde_json::from_str(&json).expect("parse v1");
        assert_eq!(parsed.version, LEGACY_MESSAGE_VERSION);
        assert_eq!(parsed.text.as_deref(), Some("legacy text"));
        assert_eq!(parsed.ciphertext, None);
    }

    #[test]
    fn message_payload_v2_roundtrip() {
        let recipient = test_identity(41);
        let payload = MessageAddedPayload::new_encrypted(
            "chat".into(),
            "sender".into(),
            identity_id(&recipient),
            &recipient.verifying_key(),
            "secret text",
            456,
            "event-v2",
        )
        .expect("create v2 payload");
        let json = serde_json::to_string(&payload).expect("serialize v2");
        let parsed: MessageAddedPayload = serde_json::from_str(&json).expect("parse v2");
        assert_eq!(parsed.version, ENCRYPTED_MESSAGE_VERSION);
        assert_eq!(parsed.text, None);
        assert!(parsed.ciphertext.is_some());
    }

    #[test]
    fn message_payload_v1_backward_compat() {
        let old_json =
            r#"{"chat_id":"chat","sender_id":"sender","recipient_id":"peer","text":"old"}"#;
        let parsed: MessageAddedPayload =
            serde_json::from_str(old_json).expect("parse historical v1 payload");
        assert_eq!(parsed.version, LEGACY_MESSAGE_VERSION);
        assert_eq!(parsed.text.as_deref(), Some("old"));
        assert_eq!(parsed.timestamp, 0);
        parsed.validate().expect("legacy payload validates");
    }

    #[test]
    fn message_payload_v2_decrypt_returns_plaintext() {
        let recipient = test_identity(42);
        let payload = MessageAddedPayload::new_encrypted(
            "chat".into(),
            "sender".into(),
            identity_id(&recipient),
            &recipient.verifying_key(),
            "secret",
            456,
            "event-v2",
        )
        .expect("create v2 payload");
        assert_eq!(
            payload.decrypt(&recipient, "event-v2").expect("decrypt"),
            "secret"
        );
    }

    #[test]
    fn message_payload_v2_wrong_recipient_fails() {
        let recipient = test_identity(43);
        let other = test_identity(44);
        let payload = MessageAddedPayload::new_encrypted(
            "chat".into(),
            "sender".into(),
            identity_id(&recipient),
            &recipient.verifying_key(),
            "secret",
            456,
            "event-v2",
        )
        .expect("create v2 payload");
        assert!(payload.decrypt(&other, "event-v2").is_err());
    }

    #[test]
    fn message_payload_v2_wrong_event_id_fails() {
        let recipient = test_identity(45);
        let payload = MessageAddedPayload::new_encrypted(
            "chat".into(),
            "sender".into(),
            identity_id(&recipient),
            &recipient.verifying_key(),
            "secret",
            456,
            "event-v2",
        )
        .expect("create v2 payload");
        assert!(payload.decrypt(&recipient, "other-event").is_err());
    }

    #[test]
    fn message_payload_v1_decrypt_returns_text() {
        let payload = MessageAddedPayload::new_legacy(
            "chat".into(),
            "sender".into(),
            None,
            "historical".into(),
            123,
        );
        assert_eq!(
            payload
                .decrypt(&test_identity(46), "unused-event")
                .expect("read legacy text"),
            "historical"
        );
    }

    #[test]
    fn message_payload_metadata_is_available_without_decryption() {
        let recipient = test_identity(47);
        let payload = MessageAddedPayload::new_encrypted(
            "chat".into(),
            "sender".into(),
            identity_id(&recipient),
            &recipient.verifying_key(),
            "secret",
            789,
            "event-v2",
        )
        .expect("create v2 payload");
        assert_eq!(payload.chat_id(), "chat");
        assert_eq!(payload.sender_id(), "sender");
        assert_eq!(payload.timestamp(), 789);
        assert_eq!(
            payload.recipient_id(),
            Some(identity_id(&recipient).as_str())
        );
    }

    #[test]
    fn message_payload_v2_serialized_size_is_reasonable() {
        let recipient = test_identity(48);
        let plaintext = "x".repeat(1024);
        let payload = MessageAddedPayload::new_encrypted(
            "chat".into(),
            "sender".into(),
            identity_id(&recipient),
            &recipient.verifying_key(),
            &plaintext,
            789,
            "event-v2",
        )
        .expect("create v2 payload");
        let json = serde_json::to_string(&payload).expect("serialize v2");
        assert!(!json.contains("\"text\""));
        assert!(json.len() < plaintext.len() * 4);
    }

    #[test]
    fn message_payload_encrypted_sync_event_contains_only_ciphertext() {
        let recipient = test_identity(49);
        let mut manager = SyncManager::new("device".into());
        manager
            .add_message_encrypted_with_id(
                "event-v2".into(),
                900,
                "chat".into(),
                "sender".into(),
                identity_id(&recipient),
                &recipient.verifying_key(),
                "secret",
            )
            .expect("add encrypted message");
        let event = manager.events.last().expect("message event");
        let data: serde_json::Value =
            serde_json::from_str(&event.data).expect("parse event payload");
        assert_eq!(data["version"], ENCRYPTED_MESSAGE_VERSION);
        assert!(data.get("ciphertext").is_some());
        assert!(data.get("text").is_none());
    }

    #[test]
    fn message_payload_v2_rejects_recipient_key_mismatch() {
        let recipient = test_identity(50);
        let wrong_recipient = test_identity(51);
        let result = MessageAddedPayload::new_encrypted(
            "chat".into(),
            "sender".into(),
            identity_id(&wrong_recipient),
            &recipient.verifying_key(),
            "secret",
            789,
            "event-v2",
        );
        assert!(matches!(
            result,
            Err(MessagePayloadError::RecipientKeyMismatch)
        ));
    }

    fn ratchet_message_key(seed: u8) -> hal_crypto::MessageKey {
        hal_crypto::SymmetricRatchet::new(&[seed; 32])
            .advance()
            .expect("derive ratchet message key")
    }

    fn v3_payload(plaintext: &str, key: &hal_crypto::MessageKey) -> MessageAddedPayload {
        MessageAddedPayload::new_ratchet_encrypted(
            "chat-v3".into(),
            "sender-v3".into(),
            "recipient-v3".into(),
            plaintext,
            key,
            key.index,
            "event-v3",
            987,
        )
        .expect("create V3 payload")
    }

    fn v4_payload(plaintext: &str, key: &hal_crypto::MessageKey) -> MessageAddedPayload {
        let mut payload = v3_payload(plaintext, key);
        payload.version = MESSAGE_VERSION_V4;
        payload.chain_id = Some(7);
        payload
    }

    #[test]
    fn v4_roundtrip_with_chain_id() {
        let key = ratchet_message_key(66);
        let mut payload = v4_payload("v4 ratchet", &key);
        payload.dh_pubkey = Some([0xA5; 32]);
        payload.prev_chain_length = Some(12);
        let encoded = serde_json::to_string(&payload).unwrap();
        let decoded: MessageAddedPayload = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, payload);
        assert!(decoded.validate().is_ok());
    }

    #[test]
    fn v4_requires_chain_id() {
        let key = ratchet_message_key(67);
        let mut payload = v4_payload("v4 ratchet", &key);
        payload.chain_id = None;
        assert!(matches!(
            payload.validate(),
            Err(MessagePayloadError::InvalidPayload("v4 requires chain_id"))
        ));
    }

    #[test]
    fn v3_rejects_chain_id() {
        let key = ratchet_message_key(68);
        let mut payload = v3_payload("v3 ratchet", &key);
        payload.chain_id = Some(0);
        assert!(matches!(
            payload.validate(),
            Err(MessagePayloadError::InvalidPayload(
                "v3 must not carry chain_id"
            ))
        ));
    }

    #[test]
    fn v3_rejects_dh_pubkey() {
        let key = ratchet_message_key(69);
        let mut payload = v3_payload("v3 ratchet", &key);
        payload.dh_pubkey = Some([0; 32]);
        assert!(matches!(
            payload.validate(),
            Err(MessagePayloadError::InvalidPayload(
                "v3 must not carry dh_pubkey"
            ))
        ));
    }

    #[test]
    fn v3_rejects_prev_chain_length() {
        let key = ratchet_message_key(74);
        let mut payload = v3_payload("v3 ratchet", &key);
        payload.prev_chain_length = Some(0);
        assert!(matches!(
            payload.validate(),
            Err(MessagePayloadError::InvalidPayload(
                "v3 must not carry prev_chain_length"
            ))
        ));
    }

    #[test]
    fn v4_dh_pubkey_requires_prev_chain_length() {
        let key = ratchet_message_key(70);
        let mut payload = v4_payload("v4 ratchet", &key);
        payload.dh_pubkey = Some([0xA5; 32]);
        assert!(matches!(
            payload.validate(),
            Err(MessagePayloadError::InvalidPayload(
                "v4 dh_pubkey and prev_chain_length must be present together"
            ))
        ));
    }

    #[test]
    fn v4_prev_chain_length_requires_dh_pubkey() {
        let key = ratchet_message_key(71);
        let mut payload = v4_payload("v4 ratchet", &key);
        payload.prev_chain_length = Some(12);
        assert!(matches!(
            payload.validate(),
            Err(MessagePayloadError::InvalidPayload(
                "v4 dh_pubkey and prev_chain_length must be present together"
            ))
        ));
    }

    #[test]
    fn v4_rejects_text() {
        let key = ratchet_message_key(75);
        let mut payload = v4_payload("v4 ratchet", &key);
        payload.text = Some("unexpected plaintext".into());
        assert!(matches!(
            payload.validate(),
            Err(MessagePayloadError::UnexpectedField(MESSAGE_VERSION_V4))
        ));
    }

    #[test]
    fn v4_unknown_version_still_rejected() {
        let key = ratchet_message_key(72);
        let mut payload = v4_payload("v4 ratchet", &key);
        payload.version = 99;
        assert!(matches!(
            payload.validate(),
            Err(MessagePayloadError::InvalidVersion(99))
        ));
    }

    #[test]
    fn v3_serialization_unchanged() {
        let payload = MessageAddedPayload {
            version: RATCHET_MESSAGE_VERSION,
            chat_id: "c".into(),
            group_id: None,
            reply_to_id: None,
            sender_id: "s".into(),
            recipient_id: Some("r".into()),
            timestamp: 1,
            text: None,
            ciphertext: Some("AQ==".into()),
            ratchet_counter: Some(2),
            ratchet_nonce: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()),
            chain_id: None,
            dh_pubkey: None,
            prev_chain_length: None,
        };
        let encoded = serde_json::to_string(&payload).unwrap();
        assert_eq!(
            encoded,
            r#"{"version":3,"chat_id":"c","sender_id":"s","recipient_id":"r","timestamp":1,"ciphertext":"AQ==","ratchet_counter":2,"ratchet_nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#
        );
        assert!(!encoded.contains("chain_id"));
        assert!(!encoded.contains("dh_pubkey"));
        assert!(!encoded.contains("prev_chain_length"));
        let decoded: MessageAddedPayload = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn v3_roundtrip() {
        let key = ratchet_message_key(52);
        let payload = v3_payload("ratchet secret", &key);
        assert_eq!(
            payload.decrypt_v3(&key, "event-v3").unwrap(),
            "ratchet secret"
        );
    }

    #[test]
    fn v3_decrypt_wrong_key_fails() {
        let key = ratchet_message_key(53);
        let other_key = ratchet_message_key(54);
        let payload = v3_payload("ratchet secret", &key);
        assert!(payload.decrypt_v3(&other_key, "event-v3").is_err());
    }

    #[test]
    fn v3_decrypt_wrong_event_id_fails() {
        let key = ratchet_message_key(55);
        let payload = v3_payload("ratchet secret", &key);
        assert!(payload.decrypt_v3(&key, "other-event").is_err());
    }

    #[test]
    fn v3_decrypt_wrong_counter_fails() {
        let key = ratchet_message_key(56);
        let mut payload = v3_payload("ratchet secret", &key);
        payload.ratchet_counter = Some(key.index + 1);
        assert!(payload.decrypt_v3(&key, "event-v3").is_err());
    }

    #[test]
    fn v3_serialization_roundtrip() {
        let key = ratchet_message_key(57);
        let payload = v3_payload("ratchet secret", &key);
        let encoded = serde_json::to_string(&payload).unwrap();
        let decoded: MessageAddedPayload = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn v3_metadata_accessible_without_decrypt() {
        let key = ratchet_message_key(58);
        let payload = v3_payload("ratchet secret", &key);
        assert_eq!(payload.chat_id(), "chat-v3");
        assert_eq!(payload.sender_id(), "sender-v3");
        assert_eq!(payload.recipient_id(), Some("recipient-v3"));
        assert_eq!(payload.timestamp(), 987);
        assert_eq!(payload.version(), RATCHET_MESSAGE_VERSION);
    }

    #[test]
    fn v3_counter_preserved() {
        let key = ratchet_message_key(59);
        let payload = v3_payload("ratchet secret", &key);
        assert_eq!(payload.ratchet_counter(), Some(key.index));
        assert!(payload.ratchet_nonce().is_some());
    }

    #[test]
    fn versions_coexist() {
        let recipient = test_identity(60);
        let v1 = MessageAddedPayload::new_legacy(
            "chat".into(),
            "sender".into(),
            None,
            "legacy".into(),
            1,
        );
        let v2 = MessageAddedPayload::new_encrypted(
            "chat".into(),
            "sender".into(),
            identity_id(&recipient),
            &recipient.verifying_key(),
            "ecies",
            2,
            "event-v2",
        )
        .unwrap();
        let key = ratchet_message_key(61);
        let v3 = v3_payload("ratchet", &key);
        let encoded = serde_json::to_string(&vec![v1, v2, v3]).unwrap();
        let decoded: Vec<MessageAddedPayload> = serde_json::from_str(&encoded).unwrap();
        assert!(decoded.iter().all(|payload| payload.validate().is_ok()));
        assert_eq!(
            decoded
                .iter()
                .map(MessageAddedPayload::version)
                .collect::<Vec<_>>(),
            [
                LEGACY_MESSAGE_VERSION,
                ENCRYPTED_MESSAGE_VERSION,
                RATCHET_MESSAGE_VERSION
            ]
        );
    }

    #[test]
    fn validate_v1_requires_text() {
        let mut payload = MessageAddedPayload::new_legacy(
            "chat".into(),
            "sender".into(),
            None,
            "legacy".into(),
            1,
        );
        payload.text = None;
        assert!(payload.validate().is_err());
    }

    #[test]
    fn validate_v3_requires_counter_and_nonce() {
        let key = ratchet_message_key(62);
        let mut payload = v3_payload("ratchet", &key);
        payload.ratchet_counter = None;
        assert!(payload.validate().is_err());
        payload.ratchet_counter = Some(key.index);
        payload.ratchet_nonce = None;
        assert!(payload.validate().is_err());
    }

    #[test]
    fn validate_v3_rejects_text_and_ciphertext() {
        let key = ratchet_message_key(63);
        let mut payload = v3_payload("ratchet", &key);
        payload.text = Some("unexpected plaintext".into());
        assert!(matches!(
            payload.validate(),
            Err(MessagePayloadError::UnexpectedField(
                RATCHET_MESSAGE_VERSION
            ))
        ));
    }

    #[test]
    fn validate_v3_rejects_empty_ciphertext() {
        let key = ratchet_message_key(65);
        let mut payload = v3_payload("ratchet", &key);
        payload.ciphertext = Some(String::new());
        assert!(payload.validate().is_err());
    }

    #[test]
    fn v3_empty_plaintext_roundtrip() {
        let key = ratchet_message_key(64);
        let payload = v3_payload("", &key);
        assert_eq!(payload.decrypt_v3(&key, "event-v3").unwrap(), "");
    }

    #[test]
    fn tie_break_by_event_id_contact_delete() {
        let mut first = SyncManager::new("identity".into());
        let mut second = SyncManager::new("identity".into());
        let mut add = SyncEvent::new(
            "event-a".into(),
            SyncEventType::ContactAdded,
            serde_json::json!({"pubkey": "peer", "name": "Peer"}).to_string(),
        );
        let mut delete = SyncEvent::new(
            "event-z".into(),
            SyncEventType::ContactDeleted,
            serde_json::json!({"pubkey": "peer"}).to_string(),
        );
        add.timestamp = 10;
        delete.timestamp = 10;

        first
            .merge_events(vec![add.clone(), delete.clone()])
            .expect("merge");
        second.merge_events(vec![delete, add]).expect("merge");
        assert_eq!(first.get_contact_count(), 0);
        assert_eq!(second.get_contact_count(), 0);
    }

    #[test]
    fn tie_break_by_event_id_settings() {
        let mut first = SyncManager::new("identity".into());
        let mut second = SyncManager::new("identity".into());
        let mut event_a = SyncEvent::new(
            "event-a".into(),
            SyncEventType::SettingsUpdated,
            serde_json::json!({"language": "uk", "theme": "dark", "notifications_enabled": true})
                .to_string(),
        );
        let mut event_b = SyncEvent::new(
            "event-b".into(),
            SyncEventType::SettingsUpdated,
            serde_json::json!({"language": "en", "theme": "light", "notifications_enabled": false})
                .to_string(),
        );
        event_a.timestamp = 10;
        event_b.timestamp = 10;

        first
            .merge_events(vec![event_a.clone(), event_b.clone()])
            .expect("merge");
        second.merge_events(vec![event_b, event_a]).expect("merge");
        assert_eq!(first.settings.language, "en");
        assert_eq!(second.settings.language, "en");
    }

    #[test]
    fn same_timestamp_different_ids_deterministic() {
        let mut forward = SyncManager::new("identity".into());
        let mut reverse = SyncManager::new("identity".into());
        let mut low = SyncEvent::new(
            "id-1".into(),
            SyncEventType::ContactAdded,
            serde_json::json!({"pubkey": "peer", "name": "low"}).to_string(),
        );
        let mut high = SyncEvent::new(
            "id-2".into(),
            SyncEventType::ContactUpdated,
            serde_json::json!({"pubkey": "peer", "name": "high"}).to_string(),
        );
        low.timestamp = 42;
        high.timestamp = 42;

        forward
            .merge_events(vec![low.clone(), high.clone()])
            .expect("merge");
        reverse.merge_events(vec![high, low]).expect("merge");
        assert_eq!(forward.contacts["peer"].name, reverse.contacts["peer"].name);
        assert_eq!(forward.contacts["peer"].name, "high");
    }
}
