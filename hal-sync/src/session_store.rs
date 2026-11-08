use crate::abuse_metrics::AbuseMetrics;
use crate::dht::NodeId;
use hal_crypto::{MessageKey, SymmetricRatchet};
use hal_storage::{ClientStorage, SessionRow, SkippedKeyRow};
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
#[cfg(test)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Mutex as TokioMutex;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

const LOW_TO_HIGH_DOMAIN: &[u8] = b"hal-ratchet-low-to-high-v1:";
const HIGH_TO_LOW_DOMAIN: &[u8] = b"hal-ratchet-high-to-low-v1:";
pub const MAX_RATCHET_GAP: u64 = 500;
pub const MAX_SKIPPED_KEYS: usize = 2000;
/// Message-count trigger defined in `docs/RATCHET_DH.md`.
pub const RATCHET_INTERVAL_MESSAGES: u32 = 50;
/// Time-to-live for retained skipped message keys.
pub const SKIPPED_KEY_TTL_SECS: u64 = 24 * 60 * 60;
const RETIRED_CHAIN_TTL_SECS: u64 = 24 * 60 * 60;
const MAX_RETIRED_CHAINS: usize = 32;
const DH_RATCHET_RK_INFO: &[u8] = b"hal-dh-ratchet-v1-rk";
const DH_RATCHET_CKR_INFO: &[u8] = b"hal-dh-ratchet-v1-ckr";
const DH_RATCHET_CKS_INFO: &[u8] = b"hal-dh-ratchet-v1-cks";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    LowToHigh,
    HighToLow,
}

pub struct PendingDhRatchet {
    pub new_priv: [u8; 32],
    pub new_pub: [u8; 32],
    pub rk_new: [u8; 32],
    pub ckr_new: [u8; 32],
    pub frozen_prev_chain_length: u32,
    pre_root_key: [u8; 32],
    pre_sending_chain_key: [u8; 32],
    pre_sending_index: u64,
    pre_receiving_chain_key: [u8; 32],
    pre_receiving_index: u64,
    pre_dh_privkey: [u8; 32],
    pre_dh_pubkey: [u8; 32],
    pre_messages_since_ratchet: u32,
    pub pre_prev_chain_length: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum V4RatchetAction {
    None,
    DuplicateAdvertise,
    ResponderStep([u8; 32]),
    InitiatorComplete([u8; 32]),
    CollisionCase1([u8; 32]),
    CollisionCase3Larger([u8; 32]),
    CollisionCase3Smaller([u8; 32]),
}

impl Drop for PendingDhRatchet {
    fn drop(&mut self) {
        self.new_priv.zeroize();
        self.rk_new.zeroize();
        self.ckr_new.zeroize();
        self.pre_root_key.zeroize();
        self.pre_sending_chain_key.zeroize();
        self.pre_receiving_chain_key.zeroize();
        self.pre_dh_privkey.zeroize();
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("biometric confirmation required: {0}")]
    BiometricRequired(String),
    #[error("no session exists for the peer")]
    MissingSession,
    #[error("session handshake is still pending")]
    SessionNotReady,
    #[error("requested receive counter {requested} is behind next counter {next}")]
    CounterBehind { requested: u64, next: u64 },
    #[error("requested receive counter {requested} is ahead of next counter {next}")]
    CounterAhead { requested: u64, next: u64 },
    #[error("sending counter mismatch: expected {expected}, actual {actual}")]
    CounterMismatch { expected: u64, actual: u64 },
    #[error("session requires a new X3DH handshake")]
    NeedsResync,
    #[error("ratchet session changed while receive was being processed")]
    SessionReplaced,
    #[error("receive key preparation is already in progress")]
    ReceiveAlreadyPrepared,
    #[error("receive commit requires a matching prepared key")]
    ReceiveNotPrepared,
    #[error("ratchet counter or session generation overflow")]
    CounterOverflow,
    #[error("DH ratchet chain epoch exceeds the V4 wire limit")]
    ChainEpochOverflow,
    #[error("requested receive counter {requested} exceeds maximum gap from {next}")]
    GapTooLarge { requested: u64, next: u64 },
    #[error("skipped key unavailable for counter {0}")]
    SkippedKeyUnavailable(u64),
    #[cfg(test)]
    #[error("injected send commit failure")]
    InjectedCommitFailure,
    #[cfg(test)]
    #[error("injected session persistence failure")]
    InjectedPersistenceFailure,
    #[error("cannot establish a session with the local identity")]
    SelfSession,
    #[error("failed to expand directional ratchet seed")]
    SeedDerivation,
    #[error("invalid or non-contributory DH ratchet public key")]
    InvalidDhRatchetPublicKey,
    #[error("DH ratchet KDF expansion failed")]
    DhRatchetKdf,
    #[error("a DH ratchet initiation is already pending")]
    PendingRatchetExists,
    #[error("no DH ratchet initiation is pending")]
    NoPendingRatchet,
    #[error("pending DH ratchet state changed before completion")]
    PendingRatchetStateChanged,
    #[error("ratchet advancement failed: {0}")]
    Ratchet(#[from] anyhow::Error),
}

/// Per-contact biometric/policy requirement.
/// Per B6_TIER_BIOMETRIC.md §4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactPolicy {
    /// Default: peer must have proof-of-live age >= 7d.
    /// No biometric on every action.
    AgeProof,
    /// Biometric not less than once per interval.
    BiometricInterval {
        interval_secs: u64,
        last_verified: u64,
    },
    /// Biometric on every send/decrypt with this contact.
    Paranoid,
}

impl Default for ContactPolicy {
    fn default() -> Self {
        Self::AgeProof
    }
}

pub struct Session {
    pub peer_identity: NodeId,
    pub root_key: [u8; 32],
    pub dh_our_privkey: [u8; 32],
    pub dh_our_pubkey: [u8; 32],
    pub dh_peer_pubkey: Option<[u8; 32]>,
    pub chain_epoch: u64,
    pub messages_since_ratchet: u32,
    pub peer_supports_v4: Option<bool>,
    pub peer_supports_invite_redemption: Option<bool>,
    pub prev_chain_length: Option<u32>,
    pub contact_policy: ContactPolicy,
    pending_dh_ratchet: Option<PendingDhRatchet>,
    pub sending_chain: SymmetricRatchet,
    pub receiving_chain: SymmetricRatchet,
    pub direction: Direction,
    pub established_at: u64,
    pub last_used_at: u64,
    responded: bool,
    needs_resync: bool,
    generation: u64,
    prepared_receive: Option<PreparedReceive>,
    next_receive_prepare_id: u64,
    skipped_keys: HashMap<(u64, u64), SkippedKey>,
    retired_receiving_chains: Vec<RetiredReceivingChain>,
    send_lock: Arc<TokioMutex<()>>,
    receive_lock: Arc<TokioMutex<()>>,
    pending_ephemeral: Option<[u8; 32]>,
    pending_signed_prekey: Option<[u8; 32]>,
    pending_opk_id: Option<u32>,
}

struct RetiredReceivingChain {
    chain_epoch: u64,
    receiving_chain: SymmetricRatchet,
    created_at: u64,
    skipped_keys: HashMap<u64, RetiredSkippedKey>,
}

struct RetiredSkippedKey {
    key: MessageKey,
    received_at: u64,
}

struct PreparedReceive {
    counter: u64,
    chain_epoch: u64,
    generation: u64,
    prepare_id: u64,
    mode: PreparedReceiveMode,
}

#[derive(Clone, Copy)]
struct PreparedReceiveMode {
    from_skipped: bool,
    skipped_received_at: Option<u64>,
}

pub struct SkippedKey {
    key: MessageKey,
    received_at: u64,
    chain_epoch: u64,
}

impl std::fmt::Debug for SkippedKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SkippedKey")
            .field("counter", &self.key.index)
            .field("chain_epoch", &self.chain_epoch)
            .field("received_at", &self.received_at)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// Owned receive material prepared for transactional decryption and commit.
pub struct ReceivePreview {
    pub counter: u64,
    pub chain_epoch: u64,
    pub skipped_to_insert: Vec<(u64, MessageKey)>,
    pub target_key: MessageKey,
    pub from_skipped: bool,
    retired_chain_update: Option<RetiredChainReceiveUpdate>,
    generation: u64,
    prepare_id: u64,
}

struct RetiredChainReceiveUpdate {
    expected_next_index: u64,
    receiving_chain: Option<SymmetricRatchet>,
    skipped_to_insert: Vec<(u64, MessageKey)>,
    consumed_skipped_counter: Option<u64>,
}

impl std::fmt::Debug for ReceivePreview {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReceivePreview")
            .field("counter", &self.counter)
            .field(
                "skipped_counters",
                &self
                    .skipped_to_insert
                    .iter()
                    .map(|(counter, _)| *counter)
                    .collect::<Vec<_>>(),
            )
            .field("target_key", &self.target_key)
            .field("from_skipped", &self.from_skipped)
            .finish()
    }
}

impl ReceivePreview {
    pub fn is_out_of_order(&self) -> bool {
        self.from_skipped
            || !self.skipped_to_insert.is_empty()
            || self.retired_chain_update.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct SessionView {
    pub peer_identity: NodeId,
    pub direction: Direction,
    pub send_counter: u64,
    pub recv_counter: u64,
    pub established_at: u64,
    pub last_used_at: u64,
    pub responded: bool,
    pub needs_resync: bool,
    pub skipped_keys_count: usize,
}

impl Session {
    fn new(
        peer_identity: NodeId,
        root_key: [u8; 32],
        sending_chain: SymmetricRatchet,
        receiving_chain: SymmetricRatchet,
        direction: Direction,
        now: u64,
        generation: u64,
        peer_supports_v4: Option<bool>,
    ) -> Self {
        let our_dh_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let our_dh_public = PublicKey::from(&our_dh_secret).to_bytes();
        Self {
            peer_identity,
            root_key,
            dh_our_privkey: our_dh_secret.to_bytes(),
            dh_our_pubkey: our_dh_public,
            dh_peer_pubkey: None,
            chain_epoch: 0,
            messages_since_ratchet: 0,
            peer_supports_v4,
            peer_supports_invite_redemption: None,
            prev_chain_length: None,
            contact_policy: ContactPolicy::default(),
            pending_dh_ratchet: None,
            sending_chain,
            receiving_chain,
            direction,
            established_at: now,
            last_used_at: now,
            responded: true,
            needs_resync: false,
            generation,
            prepared_receive: None,
            next_receive_prepare_id: 0,
            skipped_keys: HashMap::new(),
            retired_receiving_chains: Vec::new(),
            send_lock: Arc::new(TokioMutex::new(())),
            receive_lock: Arc::new(TokioMutex::new(())),
            pending_ephemeral: None,
            pending_signed_prekey: None,
            pending_opk_id: None,
        }
    }

    fn from_persisted(
        peer_identity: NodeId,
        root_key: [u8; 32],
        dh_our_privkey: Option<[u8; 32]>,
        dh_our_pubkey: Option<[u8; 32]>,
        dh_peer_pubkey: Option<[u8; 32]>,
        chain_epoch: u64,
        messages_since_ratchet: u32,
        sending_chain: SymmetricRatchet,
        receiving_chain: SymmetricRatchet,
        direction: Direction,
        established_at: u64,
        last_used_at: u64,
        responded: bool,
        needs_resync: bool,
        generation: u64,
        peer_supports_v4: Option<bool>,
        peer_supports_invite_redemption: Option<bool>,
        prev_chain_length: Option<u32>,
        pending_dh_ratchet: Option<PendingDhRatchet>,
        retired_receiving_chains: Vec<RetiredReceivingChain>,
        contact_policy: ContactPolicy,
    ) -> Result<Self, SessionError> {
        let mut session = Self::new(
            peer_identity,
            root_key,
            sending_chain,
            receiving_chain,
            direction,
            established_at,
            generation,
            peer_supports_v4,
        );
        session.peer_supports_invite_redemption = peer_supports_invite_redemption;
        match (dh_our_privkey, dh_our_pubkey) {
            (Some(private), Some(public)) => {
                if PublicKey::from(&StaticSecret::from(private)).to_bytes() != public {
                    session.root_key.zeroize();
                    session.dh_our_privkey.zeroize();
                    return Err(SessionError::Ratchet(anyhow::anyhow!(
                        "persisted DH keypair does not match"
                    )));
                }
                session.dh_our_privkey.zeroize();
                session.dh_our_privkey = private;
                session.dh_our_pubkey = public;
            }
            (None, None) => {}
            _ => {
                session.root_key.zeroize();
                session.dh_our_privkey.zeroize();
                return Err(SessionError::Ratchet(anyhow::anyhow!(
                    "persisted DH keypair is incomplete"
                )));
            }
        }
        session.dh_peer_pubkey = dh_peer_pubkey;
        session.chain_epoch = chain_epoch;
        session.messages_since_ratchet = messages_since_ratchet;
        session.prev_chain_length = prev_chain_length;
        session.last_used_at = last_used_at;
        session.responded = responded;
        session.needs_resync = needs_resync;
        session.pending_dh_ratchet = pending_dh_ratchet;
        session.retired_receiving_chains = retired_receiving_chains;
        session.contact_policy = contact_policy;
        Ok(session)
    }

    pub fn dh_ratchet_step(&mut self, peer_new_dh_pub: [u8; 32]) -> Result<(), SessionError> {
        let new_private =
            Zeroizing::new(StaticSecret::random_from_rng(rand::thread_rng()).to_bytes());
        self.dh_ratchet_step_with_new_private(peer_new_dh_pub, new_private)
    }

    fn dh_ratchet_step_with_new_private(
        &mut self,
        peer_new_dh_pub: [u8; 32],
        new_private: Zeroizing<[u8; 32]>,
    ) -> Result<(), SessionError> {
        if self.pending_dh_ratchet.is_some() {
            return Err(SessionError::PendingRatchetExists);
        }
        if self.prepared_receive.is_some() {
            return Err(SessionError::ReceiveAlreadyPrepared);
        }
        let next_epoch = self
            .chain_epoch
            .checked_add(1)
            .ok_or(SessionError::CounterOverflow)?;
        let peer_public = PublicKey::from(peer_new_dh_pub);
        let current_secret = StaticSecret::from(self.dh_our_privkey);
        let dh1 = current_secret.diffie_hellman(&peer_public);
        if !dh1.was_contributory() {
            return Err(SessionError::InvalidDhRatchetPublicKey);
        }
        let (rk_new, ckr_new) = derive_dh_ratchet_outputs(
            &self.root_key,
            dh1.as_bytes(),
            self.chain_epoch,
            DH_RATCHET_CKR_INFO,
        )?;

        let new_secret = StaticSecret::from(*new_private);
        let new_public = PublicKey::from(&new_secret).to_bytes();
        let dh2 = new_secret.diffie_hellman(&peer_public);
        if !dh2.was_contributory() {
            return Err(SessionError::InvalidDhRatchetPublicKey);
        }
        let (rk_next, cks_new) =
            derive_dh_ratchet_outputs(&rk_new, dh2.as_bytes(), next_epoch, DH_RATCHET_CKS_INFO)?;

        let frozen_prev_chain_length = self.messages_since_ratchet;
        self.retire_receiving_chain(SymmetricRatchet::new(&ckr_new), crate::runtime::unix_now());
        self.root_key.copy_from_slice(&rk_next[..]);
        self.chain_epoch = next_epoch;
        self.dh_our_privkey.zeroize();
        self.dh_our_privkey = *new_private;
        self.dh_our_pubkey = new_public;
        self.dh_peer_pubkey = Some(peer_new_dh_pub);
        self.sending_chain = SymmetricRatchet::new(&cks_new);
        self.prev_chain_length = Some(frozen_prev_chain_length);
        self.messages_since_ratchet = 0;
        Ok(())
    }

    /// Start the sending half of a DH ratchet and immediately commit DH1.
    pub fn dh_ratchet_initiate(&mut self) -> Result<[u8; 32], SessionError> {
        if self.pending_dh_ratchet.is_some() {
            return Err(SessionError::PendingRatchetExists);
        }
        if self.prepared_receive.is_some() {
            return Err(SessionError::ReceiveAlreadyPrepared);
        }
        if self.chain_epoch >= u64::from(u32::MAX) {
            return Err(SessionError::ChainEpochOverflow);
        }
        let peer_public = self
            .dh_peer_pubkey
            .ok_or(SessionError::InvalidDhRatchetPublicKey)?;
        let new_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let new_priv = Zeroizing::new(new_secret.to_bytes());
        let new_pub = PublicKey::from(&new_secret).to_bytes();
        let dh1 = new_secret.diffie_hellman(&PublicKey::from(peer_public));
        if !dh1.was_contributory() {
            return Err(SessionError::InvalidDhRatchetPublicKey);
        }
        let (rk_new, ckr_new) = derive_dh_ratchet_outputs(
            &self.root_key,
            dh1.as_bytes(),
            self.chain_epoch,
            DH_RATCHET_CKR_INFO,
        )?;

        let (pre_sending_chain_key, pre_sending_index) = self.sending_chain.serialize();
        let (pre_receiving_chain_key, pre_receiving_index) = self.receiving_chain.serialize();
        let frozen_prev_chain_length = self.messages_since_ratchet;
        let pre_prev_chain_length = self.prev_chain_length;
        self.pending_dh_ratchet = Some(PendingDhRatchet {
            new_priv: *new_priv,
            new_pub,
            rk_new: *rk_new,
            ckr_new: *ckr_new,
            frozen_prev_chain_length,
            pre_root_key: self.root_key,
            pre_sending_chain_key: *pre_sending_chain_key,
            pre_sending_index,
            pre_receiving_chain_key: *pre_receiving_chain_key,
            pre_receiving_index,
            pre_dh_privkey: self.dh_our_privkey,
            pre_dh_pubkey: self.dh_our_pubkey,
            pre_messages_since_ratchet: self.messages_since_ratchet,
            pre_prev_chain_length,
        });

        self.root_key.copy_from_slice(&rk_new[..]);
        self.dh_our_privkey.zeroize();
        self.dh_our_privkey = *new_priv;
        self.dh_our_pubkey = new_pub;
        self.sending_chain = SymmetricRatchet::new(&ckr_new);
        self.prev_chain_length = Some(frozen_prev_chain_length);
        self.messages_since_ratchet = 0;
        Ok(new_pub)
    }

    /// Complete a pending sending half after receiving the peer's new DH key.
    pub fn dh_ratchet_complete(&mut self, peer_new_pub: [u8; 32]) -> Result<(), SessionError> {
        if self.prepared_receive.is_some() {
            return Err(SessionError::ReceiveAlreadyPrepared);
        }
        let next_epoch = self
            .chain_epoch
            .checked_add(1)
            .ok_or(SessionError::CounterOverflow)?;
        let pending = self
            .pending_dh_ratchet
            .as_ref()
            .ok_or(SessionError::NoPendingRatchet)?;
        if self.root_key != pending.rk_new {
            return Err(SessionError::PendingRatchetStateChanged);
        }
        let new_secret = StaticSecret::from(pending.new_priv);
        let peer_public = PublicKey::from(peer_new_pub);
        let dh2 = new_secret.diffie_hellman(&peer_public);
        if !dh2.was_contributory() {
            return Err(SessionError::InvalidDhRatchetPublicKey);
        }
        let (root_key_after_dh2, recv_chain_key_after_dh2) = derive_dh_ratchet_outputs(
            &pending.rk_new,
            dh2.as_bytes(),
            next_epoch,
            DH_RATCHET_CKS_INFO,
        )?;
        self.retire_receiving_chain(
            SymmetricRatchet::new(&recv_chain_key_after_dh2),
            crate::runtime::unix_now(),
        );
        self.root_key.copy_from_slice(&root_key_after_dh2[..]);
        self.chain_epoch = next_epoch;
        self.dh_peer_pubkey = Some(peer_new_pub);
        self.pending_dh_ratchet = None;
        Ok(())
    }

    pub fn dh_ratchet_cancel(&mut self) -> Result<(), SessionError> {
        if self.prepared_receive.is_some() {
            return Err(SessionError::ReceiveAlreadyPrepared);
        }
        let pending = self
            .pending_dh_ratchet
            .take()
            .ok_or(SessionError::NoPendingRatchet)?;
        self.root_key.zeroize();
        self.root_key = pending.pre_root_key;
        self.sending_chain = SymmetricRatchet::from_persisted(
            pending.pre_sending_chain_key,
            pending.pre_sending_index,
        );
        self.receiving_chain = SymmetricRatchet::from_persisted(
            pending.pre_receiving_chain_key,
            pending.pre_receiving_index,
        );
        self.dh_our_privkey.zeroize();
        self.dh_our_privkey = pending.pre_dh_privkey;
        self.dh_our_pubkey = pending.pre_dh_pubkey;
        self.messages_since_ratchet = pending.pre_messages_since_ratchet;
        self.prev_chain_length = pending.pre_prev_chain_length;
        Ok(())
    }

    pub fn dh_ratchet_collision_abort(
        &mut self,
        peer_new_dh_pub: [u8; 32],
    ) -> Result<(), SessionError> {
        if self.prepared_receive.is_some() {
            return Err(SessionError::ReceiveAlreadyPrepared);
        }
        let next_epoch = self
            .chain_epoch
            .checked_add(1)
            .ok_or(SessionError::CounterOverflow)?;
        let pending = self
            .pending_dh_ratchet
            .as_ref()
            .ok_or(SessionError::NoPendingRatchet)?;
        let peer_public = PublicKey::from(peer_new_dh_pub);
        let old_secret = StaticSecret::from(pending.pre_dh_privkey);
        let dh1 = old_secret.diffie_hellman(&peer_public);
        if !dh1.was_contributory() {
            return Err(SessionError::InvalidDhRatchetPublicKey);
        }
        let (rk_new, ckr_new) = derive_dh_ratchet_outputs(
            &pending.pre_root_key,
            dh1.as_bytes(),
            self.chain_epoch,
            DH_RATCHET_CKR_INFO,
        )?;
        // ECDH commutativity makes DH(old_priv, peer_new) match the retained
        // initiator's DH1; reusing pending.new_priv makes both peers' DH2 match.
        let pending_secret = StaticSecret::from(pending.new_priv);
        let dh2 = pending_secret.diffie_hellman(&peer_public);
        if !dh2.was_contributory() {
            return Err(SessionError::InvalidDhRatchetPublicKey);
        }
        let (rk_next, cks_new) =
            derive_dh_ratchet_outputs(&rk_new, dh2.as_bytes(), next_epoch, DH_RATCHET_CKS_INFO)?;
        let pending = self
            .pending_dh_ratchet
            .take()
            .ok_or(SessionError::NoPendingRatchet)?;

        self.retired_receiving_chains.push(RetiredReceivingChain {
            chain_epoch: self.chain_epoch,
            receiving_chain: SymmetricRatchet::from_persisted(
                pending.pre_receiving_chain_key,
                pending.pre_receiving_index,
            ),
            created_at: crate::runtime::unix_now(),
            skipped_keys: HashMap::new(),
        });
        self.prune_retired_receiving_chains(crate::runtime::unix_now());
        self.root_key.zeroize();
        self.root_key.copy_from_slice(&rk_next[..]);
        self.sending_chain = SymmetricRatchet::new(&cks_new);
        self.receiving_chain = SymmetricRatchet::new(&ckr_new);
        self.dh_our_privkey.zeroize();
        self.dh_our_privkey = pending.new_priv;
        self.dh_our_pubkey = pending.new_pub;
        self.dh_peer_pubkey = Some(peer_new_dh_pub);
        self.chain_epoch = next_epoch;
        self.messages_since_ratchet = 0;
        self.prev_chain_length = Some(pending.pre_messages_since_ratchet);
        Ok(())
    }

    fn retire_receiving_chain(&mut self, next: SymmetricRatchet, now: u64) {
        let previous = std::mem::replace(&mut self.receiving_chain, next);
        self.retired_receiving_chains.push(RetiredReceivingChain {
            chain_epoch: self.chain_epoch,
            receiving_chain: previous,
            created_at: now,
            skipped_keys: HashMap::new(),
        });
        self.prune_retired_receiving_chains(now);
    }

    fn prune_retired_receiving_chains(&mut self, now: u64) {
        self.retired_receiving_chains
            .retain(|chain| now.saturating_sub(chain.created_at) < RETIRED_CHAIN_TTL_SECS);
        for chain in &mut self.retired_receiving_chains {
            chain.skipped_keys.retain(|_, skipped| {
                now.saturating_sub(skipped.received_at) < SKIPPED_KEY_TTL_SECS
            });
            while chain.skipped_keys.len() > MAX_SKIPPED_KEYS {
                let oldest = chain
                    .skipped_keys
                    .iter()
                    .min_by_key(|(counter, skipped)| (skipped.received_at, **counter))
                    .map(|(counter, _)| *counter);
                if let Some(counter) = oldest {
                    chain.skipped_keys.remove(&counter);
                } else {
                    break;
                }
            }
        }
        while self.retired_receiving_chains.len() > MAX_RETIRED_CHAINS {
            self.retired_receiving_chains.remove(0);
        }
    }

    pub fn pending_dh_advertisement(&self) -> Option<([u8; 32], u32)> {
        self.pending_dh_ratchet
            .as_ref()
            .map(|pending| (pending.new_pub, pending.frozen_prev_chain_length))
    }

    pub fn has_pending_dh_ratchet(&self) -> bool {
        self.pending_dh_ratchet.is_some()
    }

    pub fn pending_dh_public_key(&self) -> Option<[u8; 32]> {
        self.pending_dh_ratchet
            .as_ref()
            .map(|pending| pending.new_pub)
    }

    pub fn is_v4_active(&self) -> bool {
        self.peer_supports_v4 == Some(true)
    }

    pub(crate) fn v4_receive_key(
        &self,
        chain_id: u32,
        counter: u64,
        peer_new_dh_pub: Option<[u8; 32]>,
    ) -> Result<(MessageKey, V4RatchetAction), SessionError> {
        if !self.responded {
            return Err(SessionError::SessionNotReady);
        }
        if self.needs_resync {
            return Err(SessionError::NeedsResync);
        }

        let (chain_key, expected_epoch, action) = match peer_new_dh_pub {
            Some(peer_new) => match self.pending_dh_ratchet.as_ref() {
                Some(pending) if peer_new == pending.new_pub => (
                    *self.receiving_chain.serialize().0,
                    self.chain_epoch,
                    V4RatchetAction::DuplicateAdvertise,
                ),
                Some(pending) if self.prev_chain_length.is_some() => {
                    let peer_public = PublicKey::from(peer_new);
                    let old_secret = StaticSecret::from(pending.pre_dh_privkey);
                    let dh1 = old_secret.diffie_hellman(&peer_public);
                    if !dh1.was_contributory() {
                        return Err(SessionError::InvalidDhRatchetPublicKey);
                    }
                    let (_, ckr_new) = derive_dh_ratchet_outputs(
                        &pending.pre_root_key,
                        dh1.as_bytes(),
                        self.chain_epoch,
                        DH_RATCHET_CKR_INFO,
                    )?;
                    (
                        *ckr_new,
                        self.chain_epoch
                            .checked_add(1)
                            .ok_or(SessionError::CounterOverflow)?,
                        V4RatchetAction::CollisionCase1(peer_new),
                    )
                }
                Some(pending) if peer_new < pending.new_pub => {
                    let peer_public = PublicKey::from(peer_new);
                    let old_secret = StaticSecret::from(pending.pre_dh_privkey);
                    let dh1 = old_secret.diffie_hellman(&peer_public);
                    if !dh1.was_contributory() {
                        return Err(SessionError::InvalidDhRatchetPublicKey);
                    }
                    let (_, ckr_new) = derive_dh_ratchet_outputs(
                        &pending.pre_root_key,
                        dh1.as_bytes(),
                        self.chain_epoch,
                        DH_RATCHET_CKR_INFO,
                    )?;
                    (
                        *ckr_new,
                        self.chain_epoch
                            .checked_add(1)
                            .ok_or(SessionError::CounterOverflow)?,
                        V4RatchetAction::CollisionCase3Larger(peer_new),
                    )
                }
                Some(_) => {
                    let pending = self
                        .pending_dh_ratchet
                        .as_ref()
                        .ok_or(SessionError::NoPendingRatchet)?;
                    let next_epoch = self
                        .chain_epoch
                        .checked_add(1)
                        .ok_or(SessionError::CounterOverflow)?;
                    let new_secret = StaticSecret::from(pending.new_priv);
                    let dh2 = new_secret.diffie_hellman(&PublicKey::from(peer_new));
                    if !dh2.was_contributory() {
                        return Err(SessionError::InvalidDhRatchetPublicKey);
                    }
                    let (_, cks_new) = derive_dh_ratchet_outputs(
                        &pending.rk_new,
                        dh2.as_bytes(),
                        next_epoch,
                        DH_RATCHET_CKS_INFO,
                    )?;
                    (
                        *cks_new,
                        next_epoch,
                        V4RatchetAction::CollisionCase3Smaller(peer_new),
                    )
                }
                None if self.dh_peer_pubkey != Some(peer_new) => {
                    let next_epoch = self
                        .chain_epoch
                        .checked_add(1)
                        .ok_or(SessionError::CounterOverflow)?;
                    let dh1 = StaticSecret::from(self.dh_our_privkey)
                        .diffie_hellman(&PublicKey::from(peer_new));
                    if !dh1.was_contributory() {
                        return Err(SessionError::InvalidDhRatchetPublicKey);
                    }
                    let (_, ckr_new) = derive_dh_ratchet_outputs(
                        &self.root_key,
                        dh1.as_bytes(),
                        self.chain_epoch,
                        DH_RATCHET_CKR_INFO,
                    )?;
                    (
                        *ckr_new,
                        next_epoch,
                        V4RatchetAction::ResponderStep(peer_new),
                    )
                }
                None => (
                    *self.receiving_chain.serialize().0,
                    self.chain_epoch,
                    V4RatchetAction::DuplicateAdvertise,
                ),
            },
            None => (
                *self.receiving_chain.serialize().0,
                self.chain_epoch,
                V4RatchetAction::None,
            ),
        };
        if u64::from(chain_id) != expected_epoch {
            return Err(SessionError::CounterAhead {
                requested: u64::from(chain_id),
                next: expected_epoch,
            });
        }
        let peeked = SymmetricRatchet::new(&chain_key).peek_chain(counter)?;
        Ok((peeked.target_key, action))
    }

    pub fn needs_dh_ratchet(&self) -> bool {
        self.messages_since_ratchet >= RATCHET_INTERVAL_MESSAGES
    }

    fn view(&self) -> SessionView {
        SessionView {
            peer_identity: self.peer_identity,
            direction: self.direction,
            send_counter: self.sending_chain.next_index(),
            recv_counter: self.receiving_chain.next_index(),
            established_at: self.established_at,
            last_used_at: self.last_used_at,
            responded: self.responded,
            needs_resync: self.needs_resync,
            skipped_keys_count: self.skipped_keys.len(),
        }
    }

    fn reserve_receive(
        &mut self,
        counter: u64,
        chain_epoch: u64,
        mode: PreparedReceiveMode,
    ) -> Result<u64, SessionError> {
        let prepare_id = self.next_receive_prepare_id;
        self.next_receive_prepare_id = prepare_id
            .checked_add(1)
            .ok_or(SessionError::CounterOverflow)?;
        self.prepared_receive = Some(PreparedReceive {
            counter,
            chain_epoch,
            generation: self.generation,
            prepare_id,
            mode,
        });
        Ok(prepare_id)
    }

    fn zeroize_secrets(&mut self) {
        self.root_key.zeroize();
        self.dh_our_privkey.zeroize();
        if let Some(pending) = self.pending_dh_ratchet.as_mut() {
            pending.new_priv.zeroize();
            pending.rk_new.zeroize();
            pending.ckr_new.zeroize();
            pending.pre_root_key.zeroize();
            pending.pre_sending_chain_key.zeroize();
            pending.pre_receiving_chain_key.zeroize();
            pending.pre_dh_privkey.zeroize();
        }
        if let Some(ephemeral) = self.pending_ephemeral.as_mut() {
            ephemeral.zeroize();
        }
        if let Some(signed_prekey) = self.pending_signed_prekey.as_mut() {
            signed_prekey.zeroize();
        }
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Session")
            .field("peer_identity", &self.peer_identity)
            .field("root_key", &"[REDACTED]")
            .field("dh_our_privkey", &"[REDACTED]")
            .field("sending_chain", &"[REDACTED]")
            .field("receiving_chain", &"[REDACTED]")
            .field("dh_our_pubkey", &self.dh_our_pubkey)
            .field("dh_peer_pubkey", &self.dh_peer_pubkey)
            .field("chain_epoch", &self.chain_epoch)
            .field("messages_since_ratchet", &self.messages_since_ratchet)
            .field("peer_supports_v4", &self.peer_supports_v4)
            .field(
                "peer_supports_invite_redemption",
                &self.peer_supports_invite_redemption,
            )
            .field("prev_chain_length", &self.prev_chain_length)
            .field("direction", &self.direction)
            .field("established_at", &self.established_at)
            .field("last_used_at", &self.last_used_at)
            .field("responded", &self.responded)
            .field("needs_resync", &self.needs_resync)
            .field("send_lock", &"[LOCK]")
            .field("receive_lock", &"[LOCK]")
            .field("skipped_key_count", &self.skipped_keys.len())
            .finish()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

pub struct SessionStore {
    sessions: HashMap<NodeId, Session>,
    generation: u64,
    metrics: Arc<AbuseMetrics>,
    storage: Option<Arc<StdMutex<ClientStorage>>>,
    negative_cache: HashSet<NodeId>,
    persistence_lock: Arc<TokioMutex<()>>,
    #[cfg(test)]
    fail_next_send_commit: bool,
    #[cfg(test)]
    fail_next_session_persist: Arc<AtomicBool>,
}

pub(crate) struct SessionPersistenceSnapshot {
    row: SessionRow,
    skipped: Vec<SkippedKeyRow>,
    #[cfg(test)]
    fail_next_persist: Arc<AtomicBool>,
}

impl SessionPersistenceSnapshot {
    pub(crate) fn persist(
        &self,
        storage: &Arc<StdMutex<ClientStorage>>,
    ) -> Result<(), SessionError> {
        #[cfg(test)]
        if self.fail_next_persist.swap(false, Ordering::SeqCst) {
            return Err(SessionError::InjectedPersistenceFailure);
        }
        let mut storage = storage
            .lock()
            .map_err(|_| SessionError::Ratchet(anyhow::anyhow!("session storage lock poisoned")))?;
        storage
            .save_session_with_skipped(&self.row, &self.skipped)
            .map_err(|error| {
                SessionError::Ratchet(anyhow::anyhow!("persist session with skipped: {error}"))
            })
    }
}

impl Drop for SessionPersistenceSnapshot {
    fn drop(&mut self) {
        self.row.root_key.zeroize();
        self.row.sending_chain_key.zeroize();
        self.row.receiving_chain_key.zeroize();
        if let Some(key) = self.row.pending_dh_privkey.as_mut() {
            key.zeroize();
        }
        if let Some(key) = self.row.pending_rk_new.as_mut() {
            key.zeroize();
        }
        if let Some(key) = self.row.pending_ckr_new.as_mut() {
            key.zeroize();
        }
        if let Some(key) = self.row.pre_initiate_root_key.as_mut() {
            key.zeroize();
        }
        if let Some(key) = self.row.pre_initiate_dh_our_privkey.as_mut() {
            key.zeroize();
        }
        if let Some(state) = self.row.pre_initiate_sending_chain_state.as_mut() {
            state.zeroize();
        }
        if let Some(state) = self.row.pre_initiate_receiving_chain_state.as_mut() {
            state.zeroize();
        }
        for skipped in &mut self.skipped {
            skipped.message_key.zeroize();
        }
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::with_metrics(Arc::new(AbuseMetrics::new()))
    }
}

impl Drop for SessionStore {
    fn drop(&mut self) {
        let skipped_count = self
            .sessions
            .values()
            .map(|session| session.skipped_keys.len() as u64)
            .fold(0, u64::saturating_add);
        let _ = self.metrics.ratchet_skipped_keys_current.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| Some(current.saturating_sub(skipped_count)),
        );
    }
}

pub fn derive_direction_seeds(
    root_key: &[u8; 32],
    local: &NodeId,
    peer: &NodeId,
) -> Result<([u8; 32], [u8; 32], Direction), SessionError> {
    if local == peer {
        return Err(SessionError::SelfSession);
    }
    let (send_domain, recv_domain, direction) = if local.as_bytes() < peer.as_bytes() {
        (LOW_TO_HIGH_DOMAIN, HIGH_TO_LOW_DOMAIN, Direction::LowToHigh)
    } else {
        (HIGH_TO_LOW_DOMAIN, LOW_TO_HIGH_DOMAIN, Direction::HighToLow)
    };
    let send_seed = derive_seed(root_key, send_domain)?;
    let recv_seed = derive_seed(root_key, recv_domain)?;
    Ok((send_seed, recv_seed, direction))
}

fn derive_seed(root_key: &[u8; 32], domain: &[u8]) -> Result<[u8; 32], SessionError> {
    let hkdf = Hkdf::<Sha256>::new(Some(domain), root_key);
    let mut seed = [0u8; 32];
    hkdf.expand(&[], &mut seed)
        .map_err(|_| SessionError::SeedDerivation)?;
    Ok(seed)
}

fn serialize_chain_state(chain_key: &[u8; 32], next_index: u64) -> Vec<u8> {
    let mut state = Vec::with_capacity(40);
    state.extend_from_slice(chain_key);
    state.extend_from_slice(&next_index.to_be_bytes());
    state
}

fn deserialize_chain_state(
    state: Option<Vec<u8>>,
    field: &str,
) -> Result<([u8; 32], u64), SessionError> {
    let state = state.ok_or_else(|| {
        SessionError::Ratchet(anyhow::anyhow!("persisted pending state missing {field}"))
    })?;
    if state.len() != 40 {
        return Err(SessionError::Ratchet(anyhow::anyhow!(
            "persisted pending {field} must be 40 bytes"
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&state[..32]);
    let index = u64::from_be_bytes(
        state[32..]
            .try_into()
            .map_err(|_| SessionError::Ratchet(anyhow::anyhow!("invalid {field} index")))?,
    );
    Ok((key, index))
}

fn restore_pending_dh_ratchet(row: &SessionRow) -> Result<Option<PendingDhRatchet>, SessionError> {
    if !row.pending_dh_marker {
        return Ok(None);
    }
    let key = |value: Option<[u8; 32]>, name: &str| {
        value.ok_or_else(|| {
            SessionError::Ratchet(anyhow::anyhow!("persisted pending state missing {name}"))
        })
    };
    let (pre_sending_chain_key, pre_sending_index) = deserialize_chain_state(
        row.pre_initiate_sending_chain_state.clone(),
        "sending chain",
    )?;
    let (pre_receiving_chain_key, pre_receiving_index) = deserialize_chain_state(
        row.pre_initiate_receiving_chain_state.clone(),
        "receiving chain",
    )?;
    let pending = PendingDhRatchet {
        new_priv: key(row.pending_dh_privkey, "DH private key")?,
        new_pub: key(row.pending_dh_pubkey, "DH public key")?,
        rk_new: key(row.pending_rk_new, "new root key")?,
        ckr_new: key(row.pending_ckr_new, "new sending chain")?,
        frozen_prev_chain_length: row.pre_initiate_messages_since_ratchet.ok_or_else(|| {
            SessionError::Ratchet(anyhow::anyhow!(
                "persisted pending state missing pre-initiate message count"
            ))
        })?,
        pre_root_key: key(row.pre_initiate_root_key, "pre-initiate root key")?,
        pre_sending_chain_key,
        pre_sending_index,
        pre_receiving_chain_key,
        pre_receiving_index,
        pre_dh_privkey: key(
            row.pre_initiate_dh_our_privkey,
            "pre-initiate DH private key",
        )?,
        pre_dh_pubkey: key(row.pre_initiate_dh_our_pubkey, "pre-initiate DH public key")?,
        pre_messages_since_ratchet: row.pre_initiate_messages_since_ratchet.ok_or_else(|| {
            SessionError::Ratchet(anyhow::anyhow!(
                "persisted pending state missing pre-initiate message count"
            ))
        })?,
        pre_prev_chain_length: row.pre_initiate_prev_chain_length,
    };
    if PublicKey::from(&StaticSecret::from(pending.new_priv)).to_bytes() != pending.new_pub
        || PublicKey::from(&StaticSecret::from(pending.pre_dh_privkey)).to_bytes()
            != pending.pre_dh_pubkey
        || row.root_key != pending.rk_new
    {
        return Err(SessionError::Ratchet(anyhow::anyhow!(
            "persisted pending DH ratchet state is inconsistent"
        )));
    }
    Ok(Some(pending))
}

fn contact_policy_from_row(row: &SessionRow) -> Result<ContactPolicy, SessionError> {
    let malformed = || {
        SessionError::Ratchet(anyhow::anyhow!(
            "persisted contact policy fields are inconsistent"
        ))
    };
    match row.contact_policy_kind {
        0 if row.contact_policy_interval_secs.is_none()
            && row.contact_policy_last_verified.is_none() =>
        {
            Ok(ContactPolicy::AgeProof)
        }
        1 => {
            let interval_secs =
                u64::try_from(row.contact_policy_interval_secs.ok_or_else(malformed)?)
                    .map_err(|_| malformed())?;
            let last_verified =
                u64::try_from(row.contact_policy_last_verified.ok_or_else(malformed)?)
                    .map_err(|_| malformed())?;
            Ok(ContactPolicy::BiometricInterval {
                interval_secs,
                last_verified,
            })
        }
        2 if row.contact_policy_interval_secs.is_none()
            && row.contact_policy_last_verified.is_none() =>
        {
            Ok(ContactPolicy::Paranoid)
        }
        _ => Err(malformed()),
    }
}

fn derive_dh_ratchet_outputs(
    root_key: &[u8; 32],
    dh_shared_secret: &[u8; 32],
    epoch: u64,
    chain_info: &[u8],
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>), SessionError> {
    let mut ikm = Zeroizing::new([0u8; 72]);
    ikm[..32].copy_from_slice(root_key);
    ikm[32..64].copy_from_slice(dh_shared_secret);
    ikm[64..].copy_from_slice(&epoch.to_be_bytes());

    let hkdf = Hkdf::<Sha256>::new(None, &*ikm);
    let mut next_root_key = Zeroizing::new([0u8; 32]);
    let mut chain_key = Zeroizing::new([0u8; 32]);
    hkdf.expand(DH_RATCHET_RK_INFO, &mut *next_root_key)
        .map_err(|_| SessionError::DhRatchetKdf)?;
    hkdf.expand(chain_info, &mut *chain_key)
        .map_err(|_| SessionError::DhRatchetKdf)?;
    Ok((next_root_key, chain_key))
}

fn serialize_retired_receiving_chains(chains: &[RetiredReceivingChain]) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"HRRC1");
    blob.extend_from_slice(&(chains.len() as u32).to_be_bytes());
    for chain in chains {
        let (chain_key, next_index) = chain.receiving_chain.serialize();
        blob.extend_from_slice(&chain.chain_epoch.to_be_bytes());
        blob.extend_from_slice(&chain.created_at.to_be_bytes());
        blob.extend_from_slice(&chain_key[..]);
        blob.extend_from_slice(&next_index.to_be_bytes());
        blob.extend_from_slice(&(chain.skipped_keys.len() as u32).to_be_bytes());
        for (counter, skipped) in &chain.skipped_keys {
            blob.extend_from_slice(&counter.to_be_bytes());
            blob.extend_from_slice(&skipped.received_at.to_be_bytes());
            blob.extend_from_slice(&skipped.key.key[..]);
        }
    }
    blob
}

fn deserialize_retired_receiving_chains(
    blob: Option<&[u8]>,
    now: u64,
) -> Result<Vec<RetiredReceivingChain>, SessionError> {
    let Some(blob) = blob else {
        return Ok(Vec::new());
    };
    let invalid = || SessionError::Ratchet(anyhow::anyhow!("malformed retired receiving chains"));
    if blob.len() < 9 || &blob[..5] != b"HRRC1" {
        return Err(invalid());
    }
    let mut cursor = 5;
    let read_u32 = |blob: &[u8], cursor: &mut usize| -> Result<u32, SessionError> {
        let end = cursor.checked_add(4).ok_or_else(invalid)?;
        let bytes: [u8; 4] = blob
            .get(*cursor..end)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?;
        *cursor = end;
        Ok(u32::from_be_bytes(bytes))
    };
    let read_u64 = |blob: &[u8], cursor: &mut usize| -> Result<u64, SessionError> {
        let end = cursor.checked_add(8).ok_or_else(invalid)?;
        let bytes: [u8; 8] = blob
            .get(*cursor..end)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?;
        *cursor = end;
        Ok(u64::from_be_bytes(bytes))
    };
    let chain_count = read_u32(blob, &mut cursor)? as usize;
    if chain_count > MAX_RETIRED_CHAINS {
        return Err(invalid());
    }
    let mut chains = Vec::with_capacity(chain_count);
    for _ in 0..chain_count {
        let chain_epoch = read_u64(blob, &mut cursor)?;
        let created_at = read_u64(blob, &mut cursor)?;
        let key_end = cursor.checked_add(32).ok_or_else(invalid)?;
        let key: [u8; 32] = blob
            .get(cursor..key_end)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?;
        cursor = key_end;
        let next_index = read_u64(blob, &mut cursor)?;
        let skipped_count = read_u32(blob, &mut cursor)? as usize;
        if skipped_count > MAX_SKIPPED_KEYS {
            return Err(invalid());
        }
        let mut skipped_keys = HashMap::with_capacity(skipped_count);
        for _ in 0..skipped_count {
            let counter = read_u64(blob, &mut cursor)?;
            let received_at = read_u64(blob, &mut cursor)?;
            let key_end = cursor.checked_add(32).ok_or_else(invalid)?;
            let message_key: [u8; 32] = blob
                .get(cursor..key_end)
                .ok_or_else(invalid)?
                .try_into()
                .map_err(|_| invalid())?;
            cursor = key_end;
            if now.saturating_sub(received_at) < SKIPPED_KEY_TTL_SECS {
                skipped_keys.insert(
                    counter,
                    RetiredSkippedKey {
                        key: MessageKey {
                            index: counter,
                            key: Zeroizing::new(message_key),
                        },
                        received_at,
                    },
                );
            }
        }
        if now.saturating_sub(created_at) < RETIRED_CHAIN_TTL_SECS {
            chains.push(RetiredReceivingChain {
                chain_epoch,
                receiving_chain: SymmetricRatchet::from_persisted(key, next_index),
                created_at,
                skipped_keys,
            });
        }
    }
    if cursor != blob.len() {
        return Err(invalid());
    }
    Ok(chains)
}

impl SessionStore {
    fn cache_skipped_keys(
        session: &mut Session,
        skipped_keys: Vec<(u64, MessageKey)>,
        received_at: u64,
        metrics: &AbuseMetrics,
    ) {
        Self::prune_expired_skipped_keys(session, received_at, metrics);
        for (counter, key) in skipped_keys {
            let identity = (session.chain_epoch, counter);
            let replaced = session
                .skipped_keys
                .insert(
                    identity,
                    SkippedKey {
                        key,
                        received_at,
                        chain_epoch: session.chain_epoch,
                    },
                )
                .is_some();
            metrics
                .ratchet_skipped_keys_inserted_total
                .fetch_add(1, Ordering::Relaxed);
            if !replaced {
                metrics
                    .ratchet_skipped_keys_current
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        while session.skipped_keys.len() > MAX_SKIPPED_KEYS {
            let oldest = session
                .skipped_keys
                .iter()
                .min_by_key(|(identity, skipped)| (skipped.received_at, **identity))
                .map(|(identity, _)| *identity);
            if let Some(identity) = oldest {
                session.skipped_keys.remove(&identity);
                metrics
                    .ratchet_skipped_keys_evicted_total
                    .fetch_add(1, Ordering::Relaxed);
                metrics
                    .ratchet_skipped_keys_current
                    .fetch_sub(1, Ordering::Relaxed);
            } else {
                break;
            }
        }
    }

    fn prune_expired_skipped_keys(
        session: &mut Session,
        now: u64,
        metrics: &AbuseMetrics,
    ) -> usize {
        let cutoff = now.saturating_sub(SKIPPED_KEY_TTL_SECS);
        let before = session.skipped_keys.len();
        session
            .skipped_keys
            .retain(|_, skipped| skipped.received_at >= cutoff);
        let expired = before - session.skipped_keys.len();
        if expired > 0 {
            metrics
                .ratchet_skipped_keys_expired_total
                .fetch_add(expired as u64, Ordering::Relaxed);
            metrics
                .ratchet_skipped_keys_current
                .fetch_sub(expired as u64, Ordering::Relaxed);
        }
        expired
    }

    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_metrics(metrics: Arc<AbuseMetrics>) -> Self {
        Self {
            sessions: HashMap::new(),
            generation: 0,
            metrics,
            storage: None,
            negative_cache: HashSet::new(),
            persistence_lock: Arc::new(TokioMutex::new(())),
            #[cfg(test)]
            fail_next_send_commit: false,
            #[cfg(test)]
            fail_next_session_persist: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_storage(
        storage: Arc<StdMutex<ClientStorage>>,
        metrics: Option<Arc<AbuseMetrics>>,
    ) -> Self {
        Self {
            sessions: HashMap::new(),
            generation: 0,
            metrics: metrics.unwrap_or_else(|| Arc::new(AbuseMetrics::new())),
            storage: Some(storage),
            negative_cache: HashSet::new(),
            persistence_lock: Arc::new(TokioMutex::new(())),
            #[cfg(test)]
            fail_next_send_commit: false,
            #[cfg(test)]
            fail_next_session_persist: Arc::new(AtomicBool::new(false)),
        }
    }

    fn peer_key(peer: &NodeId) -> String {
        peer.to_hex()
    }

    fn session_to_row(session: &Session) -> Result<SessionRow, SessionError> {
        let (sending_chain_key, sending_index) = session.sending_chain.serialize();
        let (receiving_chain_key, receiving_index) = session.receiving_chain.serialize();
        let pending = session.pending_dh_ratchet.as_ref();
        let pending_sending_state = pending.map(|pending| {
            serialize_chain_state(&pending.pre_sending_chain_key, pending.pre_sending_index)
        });
        let pending_receiving_state = pending.map(|pending| {
            serialize_chain_state(
                &pending.pre_receiving_chain_key,
                pending.pre_receiving_index,
            )
        });
        let (contact_policy_kind, contact_policy_interval_secs, contact_policy_last_verified) =
            match session.contact_policy {
                ContactPolicy::AgeProof => (0, None, None),
                ContactPolicy::BiometricInterval {
                    interval_secs,
                    last_verified,
                } => (
                    1,
                    Some(i64::try_from(interval_secs).map_err(|_| {
                        SessionError::Ratchet(anyhow::anyhow!(
                            "contact policy interval out of range"
                        ))
                    })?),
                    Some(i64::try_from(last_verified).map_err(|_| {
                        SessionError::Ratchet(anyhow::anyhow!(
                            "contact policy verification time out of range"
                        ))
                    })?),
                ),
                ContactPolicy::Paranoid => (2, None, None),
            };
        Ok(SessionRow {
            peer_identity_hex: Self::peer_key(&session.peer_identity),
            generation: session.generation,
            direction: match session.direction {
                Direction::LowToHigh => 0,
                Direction::HighToLow => 1,
            },
            root_key: session.root_key,
            sending_chain_key: *sending_chain_key,
            sending_index,
            receiving_chain_key: *receiving_chain_key,
            receiving_index,
            established_at: session.established_at,
            last_used_at: session.last_used_at,
            responded: session.responded,
            needs_resync: session.needs_resync,
            dh_our_privkey: Some(session.dh_our_privkey),
            dh_our_pubkey: Some(session.dh_our_pubkey),
            dh_peer_pubkey: session.dh_peer_pubkey,
            chain_epoch: session.chain_epoch,
            messages_since_ratchet: u64::from(session.messages_since_ratchet),
            peer_supports_v4: session.peer_supports_v4,
            peer_supports_invite_redemption: session.peer_supports_invite_redemption,
            prev_chain_length: session.prev_chain_length,
            pending_dh_marker: pending.is_some(),
            pending_dh_privkey: pending.map(|pending| pending.new_priv),
            pending_dh_pubkey: pending.map(|pending| pending.new_pub),
            pending_rk_new: pending.map(|pending| pending.rk_new),
            pending_ckr_new: pending.map(|pending| pending.ckr_new),
            pre_initiate_root_key: pending.map(|pending| pending.pre_root_key),
            pre_initiate_sending_chain_state: pending_sending_state,
            pre_initiate_receiving_chain_state: pending_receiving_state,
            pre_initiate_dh_our_privkey: pending.map(|pending| pending.pre_dh_privkey),
            pre_initiate_dh_our_pubkey: pending.map(|pending| pending.pre_dh_pubkey),
            pre_initiate_prev_chain_length: pending
                .and_then(|pending| pending.pre_prev_chain_length),
            pre_initiate_messages_since_ratchet: pending
                .map(|pending| pending.pre_messages_since_ratchet),
            retired_receiving_chains_blob: Some(serialize_retired_receiving_chains(
                &session.retired_receiving_chains,
            )),
            contact_policy_kind,
            contact_policy_interval_secs,
            contact_policy_last_verified,
        })
    }

    fn skipped_to_rows(session: &Session) -> Vec<SkippedKeyRow> {
        session
            .skipped_keys
            .iter()
            .map(|((chain_epoch, counter), skipped)| SkippedKeyRow {
                peer_identity_hex: Self::peer_key(&session.peer_identity),
                chain_epoch: *chain_epoch,
                counter: *counter,
                message_key: *skipped.key.key,
                received_at: skipped.received_at,
            })
            .collect()
    }

    fn restore_session_from_row(
        row: SessionRow,
        skipped_rows: Vec<SkippedKeyRow>,
    ) -> Result<Session, SessionError> {
        let peer_identity = NodeId::from_hex(&row.peer_identity_hex)
            .map_err(|error| SessionError::Ratchet(anyhow::anyhow!(error)))?;
        let direction = match row.direction {
            0 => Direction::LowToHigh,
            _ => Direction::HighToLow,
        };
        let messages_since_ratchet = u32::try_from(row.messages_since_ratchet).map_err(|_| {
            SessionError::Ratchet(anyhow::anyhow!("messages_since_ratchet out of range"))
        })?;
        let pending_dh_ratchet = restore_pending_dh_ratchet(&row)?;
        let retired_receiving_chains = deserialize_retired_receiving_chains(
            row.retired_receiving_chains_blob.as_deref(),
            crate::runtime::unix_now(),
        )?;
        let contact_policy = contact_policy_from_row(&row)?;
        let mut session = Session::from_persisted(
            peer_identity,
            row.root_key,
            row.dh_our_privkey,
            row.dh_our_pubkey,
            row.dh_peer_pubkey,
            row.chain_epoch,
            messages_since_ratchet,
            SymmetricRatchet::from_persisted(row.sending_chain_key, row.sending_index),
            SymmetricRatchet::from_persisted(row.receiving_chain_key, row.receiving_index),
            direction,
            row.established_at,
            row.last_used_at,
            row.responded,
            row.needs_resync,
            row.generation,
            row.peer_supports_v4,
            row.peer_supports_invite_redemption,
            row.prev_chain_length,
            pending_dh_ratchet,
            retired_receiving_chains,
            contact_policy,
        )?;
        for skipped in skipped_rows {
            session.skipped_keys.insert(
                (skipped.chain_epoch, skipped.counter),
                SkippedKey {
                    key: MessageKey {
                        index: skipped.counter,
                        key: zeroize::Zeroizing::new(skipped.message_key),
                    },
                    received_at: skipped.received_at,
                    chain_epoch: skipped.chain_epoch,
                },
            );
        }
        Ok(session)
    }

    pub(crate) fn persistence_snapshot(
        &self,
        peer: &NodeId,
    ) -> Result<Option<SessionPersistenceSnapshot>, SessionError> {
        let session = self
            .sessions
            .get(peer)
            .ok_or(SessionError::MissingSession)?;
        if self.storage.is_none() {
            return Ok(None);
        }
        Ok(Some(SessionPersistenceSnapshot {
            row: Self::session_to_row(session)?,
            skipped: Self::skipped_to_rows(session),
            #[cfg(test)]
            fail_next_persist: Arc::clone(&self.fail_next_session_persist),
        }))
    }

    #[cfg(test)]
    pub(crate) fn fail_next_session_persist(&self) {
        self.fail_next_session_persist.store(true, Ordering::SeqCst);
    }

    pub(crate) fn storage_handle(&self) -> Option<Arc<StdMutex<ClientStorage>>> {
        self.storage.as_ref().map(Arc::clone)
    }

    pub(crate) fn persistence_lock_handle(&self) -> Arc<TokioMutex<()>> {
        Arc::clone(&self.persistence_lock)
    }

    pub(crate) fn needs_storage_load(&self, peer: &NodeId) -> bool {
        !self.sessions.contains_key(peer) && !self.negative_cache.contains(peer)
    }

    pub(crate) fn remember_storage_miss(&mut self, peer: NodeId) {
        self.negative_cache.insert(peer);
    }

    pub(crate) fn install_loaded_session(&mut self, session: Session) {
        let peer = session.peer_identity;
        self.negative_cache.remove(&peer);
        if let Some(replaced) = self.sessions.insert(peer, session) {
            self.metrics
                .ratchet_skipped_keys_current
                .fetch_sub(replaced.skipped_keys.len() as u64, Ordering::Relaxed);
        }
        if let Some(loaded) = self.sessions.get(&peer) {
            self.metrics
                .ratchet_skipped_keys_current
                .fetch_add(loaded.skipped_keys.len() as u64, Ordering::Relaxed);
            self.generation = self.generation.max(loaded.generation);
        }
    }

    pub(crate) fn load_session_from_storage(
        storage: &Arc<StdMutex<ClientStorage>>,
        peer: &NodeId,
    ) -> Result<Option<Session>, SessionError> {
        let peer_hex = Self::peer_key(peer);
        let storage = storage
            .lock()
            .map_err(|_| SessionError::Ratchet(anyhow::anyhow!("session storage lock poisoned")))?;
        let Some(row) = storage
            .load_session(&peer_hex)
            .map_err(|error| SessionError::Ratchet(anyhow::anyhow!("load session: {error}")))?
        else {
            return Ok(None);
        };
        let skipped = storage.load_skipped_keys(&peer_hex).map_err(|error| {
            SessionError::Ratchet(anyhow::anyhow!("load skipped keys: {error}"))
        })?;
        Self::restore_session_from_row(row, skipped).map(Some)
    }

    pub fn get(&self, peer: &NodeId) -> Option<&Session> {
        self.sessions.get(peer)
    }

    pub fn get_mut(&mut self, peer: &NodeId) -> Option<&mut Session> {
        self.sessions.get_mut(peer)
    }

    pub fn set_peer_supports_v4(
        &mut self,
        peer: &NodeId,
        capability: Option<bool>,
    ) -> Result<(), SessionError> {
        let session = self
            .sessions
            .get_mut(peer)
            .ok_or(SessionError::MissingSession)?;
        session.peer_supports_v4 = capability;
        Ok(())
    }

    pub fn set_peer_supports_invite_redemption(
        &mut self,
        peer: &NodeId,
        capability: Option<bool>,
    ) -> Result<(), SessionError> {
        let session = self
            .sessions
            .get_mut(peer)
            .ok_or(SessionError::MissingSession)?;
        session.peer_supports_invite_redemption = capability;
        Ok(())
    }

    pub fn peer_supports_invite_redemption(&self, peer: &NodeId) -> bool {
        self.sessions
            .get(peer)
            .is_some_and(|session| session.peer_supports_invite_redemption == Some(true))
    }

    pub fn prune_skipped_keys_at_or_after(
        &mut self,
        peer: &NodeId,
        chain_epoch: u64,
        first_counter: u32,
    ) -> Result<usize, SessionError> {
        let session = self
            .sessions
            .get_mut(peer)
            .ok_or(SessionError::MissingSession)?;
        let before = session.skipped_keys.len();
        session.skipped_keys.retain(|(epoch, counter), _| {
            *epoch != chain_epoch || *counter < u64::from(first_counter)
        });
        let removed = before - session.skipped_keys.len();
        if removed > 0 {
            self.metrics
                .ratchet_skipped_keys_current
                .fetch_sub(removed as u64, Ordering::Relaxed);
            self.metrics
                .ratchet_skipped_keys_evicted_total
                .fetch_add(removed as u64, Ordering::Relaxed);
        }
        Ok(removed)
    }

    pub fn forget(&mut self, peer: &NodeId) -> Result<(), SessionError> {
        let storage = self.forget_from_memory(peer);
        let Some(storage) = storage else {
            return Ok(());
        };
        let peer_hex = Self::peer_key(peer);
        let storage = storage
            .lock()
            .map_err(|_| SessionError::Ratchet(anyhow::anyhow!("session storage lock poisoned")))?;
        storage
            .delete_session(&peer_hex)
            .map_err(|error| SessionError::Ratchet(anyhow::anyhow!("forget session: {error}")))?;
        Ok(())
    }

    pub(crate) fn forget_from_memory(
        &mut self,
        peer: &NodeId,
    ) -> Option<Arc<StdMutex<ClientStorage>>> {
        if let Some(removed) = self.sessions.remove(peer) {
            self.metrics
                .ratchet_skipped_keys_current
                .fetch_sub(removed.skipped_keys.len() as u64, Ordering::Relaxed);
        }
        self.negative_cache.remove(peer);
        self.storage_handle()
    }

    pub fn get_or_load(&mut self, peer: &NodeId) -> Result<Option<&Session>, SessionError> {
        if self.sessions.contains_key(peer) {
            self.negative_cache.remove(peer);
            return Ok(self.sessions.get(peer));
        }
        if self.negative_cache.contains(peer) {
            return Ok(None);
        }
        let Some(storage) = self.storage.as_ref() else {
            self.remember_storage_miss(*peer);
            return Ok(None);
        };
        let Some(session) = Self::load_session_from_storage(storage, peer)? else {
            self.remember_storage_miss(*peer);
            return Ok(None);
        };
        self.install_loaded_session(session);
        Ok(self.sessions.get(peer))
    }

    pub fn insert_with_chains(
        &mut self,
        peer_identity: NodeId,
        root_key: [u8; 32],
        local_id: &NodeId,
        now: u64,
    ) -> Result<(), SessionError> {
        self.insert_session(peer_identity, root_key, local_id, now, None)
    }

    pub(crate) fn insert_pending_with_chains(
        &mut self,
        peer_identity: NodeId,
        root_key: [u8; 32],
        local_id: &NodeId,
        now: u64,
        ephemeral: [u8; 32],
        signed_prekey: [u8; 32],
        opk_id: Option<u32>,
    ) -> Result<(), SessionError> {
        self.insert_session(
            peer_identity,
            root_key,
            local_id,
            now,
            Some((ephemeral, signed_prekey, opk_id)),
        )
    }

    pub(crate) fn insert_pending_resync_with_chains(
        &mut self,
        peer_identity: NodeId,
        root_key: [u8; 32],
        local_id: &NodeId,
        now: u64,
        ephemeral: [u8; 32],
        signed_prekey: [u8; 32],
        opk_id: Option<u32>,
    ) -> Result<(), SessionError> {
        self.insert_session(
            peer_identity,
            root_key,
            local_id,
            now,
            Some((ephemeral, signed_prekey, opk_id)),
        )?;
        if let Some(session) = self.sessions.get_mut(&peer_identity) {
            session.needs_resync = true;
        }
        Ok(())
    }

    fn insert_session(
        &mut self,
        peer_identity: NodeId,
        mut root_key: [u8; 32],
        local_id: &NodeId,
        now: u64,
        pending: Option<([u8; 32], [u8; 32], Option<u32>)>,
    ) -> Result<(), SessionError> {
        let (mut send_seed, mut recv_seed, direction) =
            match derive_direction_seeds(&root_key, local_id, &peer_identity) {
                Ok(seeds) => seeds,
                Err(error) => {
                    root_key.zeroize();
                    if let Some((mut ephemeral, mut signed_prekey, _)) = pending {
                        ephemeral.zeroize();
                        signed_prekey.zeroize();
                    }
                    return Err(error);
                }
            };
        let sending_chain = SymmetricRatchet::new(&send_seed);
        let receiving_chain = SymmetricRatchet::new(&recv_seed);
        send_seed.zeroize();
        recv_seed.zeroize();

        let Some(generation) = self.generation.checked_add(1) else {
            root_key.zeroize();
            if let Some((mut ephemeral, mut signed_prekey, _)) = pending {
                ephemeral.zeroize();
                signed_prekey.zeroize();
            }
            return Err(SessionError::CounterOverflow);
        };
        self.generation = generation;
        let mut session = Session::new(
            peer_identity,
            root_key,
            sending_chain,
            receiving_chain,
            direction,
            now,
            generation,
            None,
        );
        if let Some((ephemeral, signed_prekey, opk_id)) = pending {
            session.responded = false;
            session.pending_ephemeral = Some(ephemeral);
            session.pending_signed_prekey = Some(signed_prekey);
            session.pending_opk_id = opk_id;
        }
        if let Some(replaced) = self.sessions.insert(session.peer_identity, session) {
            self.metrics
                .ratchet_skipped_keys_current
                .fetch_sub(replaced.skipped_keys.len() as u64, Ordering::Relaxed);
        }
        self.negative_cache.remove(&peer_identity);
        Ok(())
    }

    pub fn get_view(&self, peer: &NodeId) -> Option<SessionView> {
        self.sessions.get(peer).map(Session::view)
    }

    pub fn send_lock(&self, peer: &NodeId) -> Result<Arc<TokioMutex<()>>, SessionError> {
        self.send_lock_with_generation(peer).map(|(lock, _)| lock)
    }

    pub fn send_lock_with_generation(
        &self,
        peer: &NodeId,
    ) -> Result<(Arc<TokioMutex<()>>, u64), SessionError> {
        let session = self
            .sessions
            .get(peer)
            .ok_or(SessionError::MissingSession)?;
        if !session.responded {
            return Err(SessionError::SessionNotReady);
        }
        if session.needs_resync {
            return Err(SessionError::NeedsResync);
        }
        Ok((Arc::clone(&session.send_lock), session.generation))
    }

    pub fn receive_lock(&self, peer: &NodeId) -> Result<(Arc<TokioMutex<()>>, u64), SessionError> {
        let session = self
            .sessions
            .get(peer)
            .ok_or(SessionError::MissingSession)?;
        if !session.responded {
            return Err(SessionError::SessionNotReady);
        }
        if session.needs_resync {
            return Err(SessionError::NeedsResync);
        }
        Ok((Arc::clone(&session.receive_lock), session.generation))
    }

    pub fn advance_sending(
        &mut self,
        peer: &NodeId,
        now: u64,
    ) -> Result<(MessageKey, u64), SessionError> {
        let session = self
            .sessions
            .get_mut(peer)
            .ok_or(SessionError::MissingSession)?;
        if !session.responded {
            return Err(SessionError::SessionNotReady);
        }
        if session.needs_resync {
            return Err(SessionError::NeedsResync);
        }
        let key = session.sending_chain.advance()?;
        let counter = key.index;
        session.last_used_at = now;
        Ok((key, counter))
    }

    pub fn peek_sending(&self, peer: &NodeId) -> Result<(MessageKey, u64), SessionError> {
        let generation = self
            .sessions
            .get(peer)
            .ok_or(SessionError::MissingSession)?
            .generation;
        self.peek_sending_for_generation(peer, generation)
    }

    pub fn peek_sending_for_generation(
        &self,
        peer: &NodeId,
        expected_generation: u64,
    ) -> Result<(MessageKey, u64), SessionError> {
        let session = self
            .sessions
            .get(peer)
            .ok_or(SessionError::MissingSession)?;
        if !session.responded {
            return Err(SessionError::SessionNotReady);
        }
        if session.needs_resync {
            return Err(SessionError::NeedsResync);
        }
        if session.generation != expected_generation {
            return Err(SessionError::SessionReplaced);
        }
        if session.sending_chain.next_index() == u64::MAX {
            return Err(SessionError::CounterOverflow);
        }
        let counter = session.sending_chain.next_index();
        let key = session.sending_chain.peek_next()?;
        Ok((key, counter))
    }

    pub fn commit_sending(
        &mut self,
        peer: &NodeId,
        expected_counter: u64,
        now: u64,
    ) -> Result<(), SessionError> {
        self.commit_sending_for_generation(peer, expected_counter, None, now)
    }

    pub fn commit_sending_for_generation(
        &mut self,
        peer: &NodeId,
        expected_counter: u64,
        expected_generation: Option<u64>,
        now: u64,
    ) -> Result<(), SessionError> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_send_commit) {
            return Err(SessionError::InjectedCommitFailure);
        }
        let session = self
            .sessions
            .get_mut(peer)
            .ok_or(SessionError::MissingSession)?;
        if !session.responded {
            return Err(SessionError::SessionNotReady);
        }
        if session.needs_resync {
            return Err(SessionError::NeedsResync);
        }
        if expected_generation.is_some_and(|generation| session.generation != generation) {
            return Err(SessionError::SessionReplaced);
        }
        if session.sending_chain.next_index() == u64::MAX {
            return Err(SessionError::CounterOverflow);
        }
        let actual = session.sending_chain.next_index();
        if actual != expected_counter {
            return Err(SessionError::CounterMismatch {
                expected: expected_counter,
                actual,
            });
        }
        let messages_since_ratchet = session
            .messages_since_ratchet
            .checked_add(1)
            .ok_or(SessionError::CounterOverflow)?;
        let key = session.sending_chain.advance()?;
        if key.index != expected_counter {
            return Err(SessionError::CounterMismatch {
                expected: expected_counter,
                actual: key.index,
            });
        }
        session.messages_since_ratchet = messages_since_ratchet;
        session.last_used_at = now;
        Ok(())
    }

    /// Prepare an in-order or out-of-order receive without advancing the chain.
    ///
    /// Runtime V3 dispatch uses this API to retain skipped message keys.
    pub fn prepare_receive_with_skipped(
        &mut self,
        peer: &NodeId,
        counter: u64,
        expected_generation: u64,
    ) -> Result<ReceivePreview, SessionError> {
        self.prepare_receive_with_skipped_at(
            peer,
            counter,
            expected_generation,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        )
    }

    pub fn prepare_receive_with_skipped_at(
        &mut self,
        peer: &NodeId,
        counter: u64,
        expected_generation: u64,
        now: u64,
    ) -> Result<ReceivePreview, SessionError> {
        let session = self
            .sessions
            .get_mut(peer)
            .ok_or(SessionError::MissingSession)?;
        if !session.responded {
            return Err(SessionError::SessionNotReady);
        }
        if session.needs_resync {
            return Err(SessionError::NeedsResync);
        }
        if session.generation != expected_generation {
            return Err(SessionError::SessionReplaced);
        }
        if session.prepared_receive.is_some() {
            return Err(SessionError::ReceiveAlreadyPrepared);
        }
        if counter == u64::MAX {
            return Err(SessionError::CounterOverflow);
        }

        Self::prune_expired_skipped_keys(session, now, &self.metrics);
        let next = session.receiving_chain.next_index();
        let chain_epoch = session.chain_epoch;
        let (target_key, skipped_to_insert, from_skipped, skipped_received_at) = if counter < next {
            let skipped = session
                .skipped_keys
                .remove(&(chain_epoch, counter))
                .ok_or(SessionError::SkippedKeyUnavailable(counter))?;
            self.metrics
                .ratchet_skipped_keys_current
                .fetch_sub(1, Ordering::Relaxed);
            (skipped.key, Vec::new(), true, Some(skipped.received_at))
        } else {
            if counter - next > MAX_RATCHET_GAP {
                return Err(SessionError::GapTooLarge {
                    requested: counter,
                    next,
                });
            }
            let peeked = session.receiving_chain.peek_chain(counter)?;
            (peeked.target_key, peeked.skipped, false, None)
        };
        let prepare_id = match session.reserve_receive(
            counter,
            chain_epoch,
            PreparedReceiveMode {
                from_skipped,
                skipped_received_at,
            },
        ) {
            Ok(prepare_id) => prepare_id,
            Err(error) => {
                if from_skipped {
                    if let Some(received_at) = skipped_received_at {
                        session.skipped_keys.insert(
                            (chain_epoch, counter),
                            SkippedKey {
                                key: target_key,
                                received_at,
                                chain_epoch,
                            },
                        );
                        self.metrics
                            .ratchet_skipped_keys_current
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
                return Err(error);
            }
        };
        Ok(ReceivePreview {
            counter,
            chain_epoch,
            skipped_to_insert,
            target_key,
            from_skipped,
            retired_chain_update: None,
            generation: session.generation,
            prepare_id,
        })
    }

    pub fn prepare_v4_skipped_receive(
        &mut self,
        peer: &NodeId,
        chain_epoch: u64,
        counter: u64,
        expected_generation: u64,
        now: u64,
    ) -> Result<ReceivePreview, SessionError> {
        let session = self
            .sessions
            .get_mut(peer)
            .ok_or(SessionError::MissingSession)?;
        if !session.responded {
            return Err(SessionError::SessionNotReady);
        }
        if session.needs_resync {
            return Err(SessionError::NeedsResync);
        }
        if session.generation != expected_generation {
            return Err(SessionError::SessionReplaced);
        }
        if session.prepared_receive.is_some() {
            return Err(SessionError::ReceiveAlreadyPrepared);
        }
        if counter == u64::MAX {
            return Err(SessionError::CounterOverflow);
        }
        Self::prune_expired_skipped_keys(session, now, &self.metrics);
        let skipped = session
            .skipped_keys
            .remove(&(chain_epoch, counter))
            .ok_or(SessionError::SkippedKeyUnavailable(counter))?;
        self.metrics
            .ratchet_skipped_keys_current
            .fetch_sub(1, Ordering::Relaxed);
        let target_key = skipped.key;
        let skipped_received_at = skipped.received_at;
        let prepare_id = match session.reserve_receive(
            counter,
            chain_epoch,
            PreparedReceiveMode {
                from_skipped: true,
                skipped_received_at: Some(skipped_received_at),
            },
        ) {
            Ok(prepare_id) => prepare_id,
            Err(error) => {
                session.skipped_keys.insert(
                    (chain_epoch, counter),
                    SkippedKey {
                        key: target_key,
                        received_at: skipped_received_at,
                        chain_epoch,
                    },
                );
                self.metrics
                    .ratchet_skipped_keys_current
                    .fetch_add(1, Ordering::Relaxed);
                return Err(error);
            }
        };
        Ok(ReceivePreview {
            counter,
            chain_epoch,
            skipped_to_insert: Vec::new(),
            target_key,
            from_skipped: true,
            retired_chain_update: None,
            generation: session.generation,
            prepare_id,
        })
    }

    pub fn prepare_v4_retired_receive(
        &mut self,
        peer: &NodeId,
        chain_epoch: u64,
        counter: u64,
        expected_generation: u64,
        now: u64,
    ) -> Result<ReceivePreview, SessionError> {
        let session = self
            .sessions
            .get_mut(peer)
            .ok_or(SessionError::MissingSession)?;
        if !session.responded {
            return Err(SessionError::SessionNotReady);
        }
        if session.needs_resync {
            return Err(SessionError::NeedsResync);
        }
        if session.generation != expected_generation {
            return Err(SessionError::SessionReplaced);
        }
        if session.prepared_receive.is_some() {
            return Err(SessionError::ReceiveAlreadyPrepared);
        }
        if counter == u64::MAX {
            return Err(SessionError::CounterOverflow);
        }
        Self::prune_expired_skipped_keys(session, now, &self.metrics);
        session.prune_retired_receiving_chains(now);
        let chain = session
            .retired_receiving_chains
            .iter_mut()
            .find(|chain| chain.chain_epoch == chain_epoch)
            .ok_or(SessionError::SkippedKeyUnavailable(counter))?;
        let next_index = chain.receiving_chain.next_index();
        let (
            target_key,
            from_skipped,
            skipped_received_at,
            next_chain,
            skipped_to_insert,
            consumed,
        ) = if let Some(skipped) = chain.skipped_keys.get(&counter) {
            (
                MessageKey {
                    index: skipped.key.index,
                    key: Zeroizing::new(*skipped.key.key),
                },
                true,
                Some(skipped.received_at),
                None,
                Vec::new(),
                Some(counter),
            )
        } else {
            if counter < next_index {
                return Err(SessionError::SkippedKeyUnavailable(counter));
            }
            if counter - next_index > MAX_RATCHET_GAP {
                return Err(SessionError::GapTooLarge {
                    requested: counter,
                    next: next_index,
                });
            }
            let peeked = chain.receiving_chain.peek_chain(counter)?;
            let (chain_key, current_index) = chain.receiving_chain.serialize();
            let mut advanced_chain = SymmetricRatchet::from_persisted(*chain_key, current_index);
            let advanced_target = advanced_chain.skip_to(counter)?;
            if advanced_target.key.as_ref() != peeked.target_key.key.as_ref() {
                return Err(SessionError::CounterMismatch {
                    expected: peeked.target_key.index,
                    actual: advanced_target.index,
                });
            }
            (
                peeked.target_key,
                false,
                None,
                Some(advanced_chain),
                peeked.skipped,
                None,
            )
        };
        let prepare_id = session.reserve_receive(
            counter,
            chain_epoch,
            PreparedReceiveMode {
                from_skipped,
                skipped_received_at,
            },
        )?;
        Ok(ReceivePreview {
            counter,
            chain_epoch,
            skipped_to_insert: Vec::new(),
            target_key,
            from_skipped,
            retired_chain_update: Some(RetiredChainReceiveUpdate {
                expected_next_index: next_index,
                receiving_chain: next_chain,
                skipped_to_insert,
                consumed_skipped_counter: consumed,
            }),
            generation: session.generation,
            prepare_id,
        })
    }

    /// Commit a prepared preview after authentication. Runtime persistence follows
    /// from an owned snapshot after releasing the SessionStore lock.
    pub fn commit_receive_preview(
        &mut self,
        peer: &NodeId,
        preview: ReceivePreview,
        now: u64,
    ) -> Result<(), SessionError> {
        let session = self
            .sessions
            .get_mut(peer)
            .ok_or(SessionError::MissingSession)?;
        if session.generation != preview.generation {
            return Err(SessionError::SessionReplaced);
        }
        let Some(prepared) = session.prepared_receive.as_ref() else {
            return Err(SessionError::ReceiveNotPrepared);
        };
        let (from_skipped, skipped_received_at) = match prepared.mode {
            PreparedReceiveMode {
                from_skipped,
                skipped_received_at,
            } if prepared.counter == preview.counter
                && prepared.chain_epoch == preview.chain_epoch
                && (from_skipped
                    || session.chain_epoch == preview.chain_epoch
                    || preview.retired_chain_update.is_some())
                && prepared.generation == preview.generation
                && prepared.prepare_id == preview.prepare_id
                && preview.from_skipped == from_skipped =>
            {
                (from_skipped, skipped_received_at)
            }
            _ => return Err(SessionError::ReceiveNotPrepared),
        };
        if !session.responded {
            session.prepared_receive = None;
            return Err(SessionError::SessionNotReady);
        }
        if session.needs_resync {
            session.prepared_receive = None;
            if from_skipped && preview.retired_chain_update.is_none() {
                if let Some(received_at) = skipped_received_at {
                    session.skipped_keys.insert(
                        (preview.chain_epoch, preview.counter),
                        SkippedKey {
                            key: preview.target_key,
                            received_at,
                            chain_epoch: preview.chain_epoch,
                        },
                    );
                    self.metrics
                        .ratchet_skipped_keys_current
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            return Err(SessionError::NeedsResync);
        }

        if preview.target_key.index != preview.counter {
            session.prepared_receive = None;
            return Err(SessionError::CounterMismatch {
                expected: preview.counter,
                actual: preview.target_key.index,
            });
        }
        if let Some(update) = preview.retired_chain_update {
            let Some(retired) = session
                .retired_receiving_chains
                .iter_mut()
                .find(|chain| chain.chain_epoch == preview.chain_epoch)
            else {
                session.prepared_receive = None;
                return Err(SessionError::SkippedKeyUnavailable(preview.counter));
            };
            if retired.receiving_chain.next_index() != update.expected_next_index {
                session.prepared_receive = None;
                return Err(SessionError::ReceiveNotPrepared);
            }
            if let Some(consumed_counter) = update.consumed_skipped_counter {
                if !from_skipped
                    || consumed_counter != preview.counter
                    || !update.skipped_to_insert.is_empty()
                    || update.receiving_chain.is_some()
                {
                    session.prepared_receive = None;
                    return Err(SessionError::ReceiveNotPrepared);
                }
                if retired.skipped_keys.remove(&consumed_counter).is_none() {
                    session.prepared_receive = None;
                    return Err(SessionError::SkippedKeyUnavailable(consumed_counter));
                }
            } else {
                if from_skipped || update.receiving_chain.is_none() {
                    session.prepared_receive = None;
                    return Err(SessionError::ReceiveNotPrepared);
                }
                let next = retired.receiving_chain.next_index();
                if preview.counter < next || preview.counter - next > MAX_RATCHET_GAP {
                    session.prepared_receive = None;
                    return Err(SessionError::ReceiveNotPrepared);
                }
                if update.skipped_to_insert.len() as u64 != preview.counter - next
                    || update
                        .skipped_to_insert
                        .iter()
                        .enumerate()
                        .any(|(offset, (index, key))| {
                            *index != next + offset as u64 || key.index != *index
                        })
                {
                    session.prepared_receive = None;
                    return Err(SessionError::ReceiveNotPrepared);
                }
                retired.receiving_chain = update
                    .receiving_chain
                    .ok_or(SessionError::ReceiveNotPrepared)?;
                for (counter, key) in update.skipped_to_insert {
                    retired.skipped_keys.insert(
                        counter,
                        RetiredSkippedKey {
                            key,
                            received_at: now,
                        },
                    );
                }
                retired.skipped_keys.remove(&preview.counter);
                while retired.skipped_keys.len() > MAX_SKIPPED_KEYS {
                    let oldest = retired
                        .skipped_keys
                        .iter()
                        .min_by_key(|(counter, skipped)| (skipped.received_at, **counter))
                        .map(|(counter, _)| *counter);
                    if let Some(counter) = oldest {
                        retired.skipped_keys.remove(&counter);
                    } else {
                        break;
                    }
                }
            }
            session.prune_retired_receiving_chains(now);
            session.prepared_receive = None;
            session.last_used_at = now;
            return Ok(());
        }
        if from_skipped {
            if !preview.skipped_to_insert.is_empty() || skipped_received_at.is_none() {
                session.prepared_receive = None;
                session.skipped_keys.insert(
                    (preview.chain_epoch, preview.counter),
                    SkippedKey {
                        key: preview.target_key,
                        received_at: skipped_received_at.unwrap_or(now),
                        chain_epoch: preview.chain_epoch,
                    },
                );
                self.metrics
                    .ratchet_skipped_keys_current
                    .fetch_add(1, Ordering::Relaxed);
                return Err(SessionError::ReceiveNotPrepared);
            }
        } else {
            let next = session.receiving_chain.next_index();
            if preview.counter < next {
                session.prepared_receive = None;
                return Err(SessionError::CounterBehind {
                    requested: preview.counter,
                    next,
                });
            }
            if preview.counter - next > MAX_RATCHET_GAP {
                session.prepared_receive = None;
                return Err(SessionError::GapTooLarge {
                    requested: preview.counter,
                    next,
                });
            }
            if preview.skipped_to_insert.len() as u64 != preview.counter - next
                || preview
                    .skipped_to_insert
                    .iter()
                    .enumerate()
                    .any(|(offset, (index, key))| {
                        *index != next + offset as u64 || key.index != *index
                    })
            {
                session.prepared_receive = None;
                return Err(SessionError::ReceiveNotPrepared);
            }
            let expected = session.receiving_chain.peek_chain(preview.counter)?;
            if expected.target_key.key.as_ref() != preview.target_key.key.as_ref()
                || expected.skipped.len() != preview.skipped_to_insert.len()
                || expected.skipped.iter().zip(&preview.skipped_to_insert).any(
                    |((expected_index, expected_key), (index, key))| {
                        expected_index != index || expected_key.key.as_ref() != key.key.as_ref()
                    },
                )
            {
                session.prepared_receive = None;
                return Err(SessionError::ReceiveNotPrepared);
            }
            let _ = session.receiving_chain.skip_to(preview.counter)?;

            Self::cache_skipped_keys(session, preview.skipped_to_insert, now, &self.metrics);
        }

        Self::prune_expired_skipped_keys(session, now, &self.metrics);
        session.prepared_receive = None;
        session.last_used_at = now;
        Ok(())
    }

    /// Abort a prepared preview; an already-consumed skipped key is restored.
    pub fn abort_receive_preview(
        &mut self,
        peer: &NodeId,
        preview: ReceivePreview,
    ) -> Result<(), SessionError> {
        let session = self
            .sessions
            .get_mut(peer)
            .ok_or(SessionError::MissingSession)?;
        if session.generation != preview.generation {
            return Err(SessionError::SessionReplaced);
        }
        let Some(prepared) = session.prepared_receive.as_ref() else {
            return Err(SessionError::ReceiveNotPrepared);
        };
        if let Some(update) = preview.retired_chain_update.as_ref() {
            let expected_from_skipped = update.consumed_skipped_counter.is_some();
            if prepared.counter != preview.counter
                || prepared.chain_epoch != preview.chain_epoch
                || prepared.generation != preview.generation
                || prepared.prepare_id != preview.prepare_id
                || prepared.mode.from_skipped != expected_from_skipped
                || preview.from_skipped != expected_from_skipped
            {
                return Err(SessionError::ReceiveNotPrepared);
            }
            session.prepared_receive = None;
            return Ok(());
        }
        let skipped_received_at = match prepared.mode {
            PreparedReceiveMode {
                from_skipped: true,
                skipped_received_at: Some(received_at),
                ..
            } if prepared.counter == preview.counter
                && prepared.generation == preview.generation
                && prepared.prepare_id == preview.prepare_id
                && preview.from_skipped =>
            {
                Some(received_at)
            }
            PreparedReceiveMode {
                from_skipped: false,
                skipped_received_at: None,
                ..
            } if prepared.counter == preview.counter
                && prepared.generation == preview.generation
                && prepared.prepare_id == preview.prepare_id
                && !preview.from_skipped =>
            {
                None
            }
            _ => return Err(SessionError::ReceiveNotPrepared),
        };
        if let Some(received_at) = skipped_received_at {
            session.skipped_keys.insert(
                (preview.chain_epoch, preview.counter),
                SkippedKey {
                    key: preview.target_key,
                    received_at,
                    chain_epoch: preview.chain_epoch,
                },
            );
            self.metrics
                .ratchet_skipped_keys_current
                .fetch_add(1, Ordering::Relaxed);
        }
        session.prepared_receive = None;
        Ok(())
    }

    pub fn mark_needs_resync(&mut self, peer: &NodeId) -> Result<bool, SessionError> {
        let session = self
            .sessions
            .get_mut(peer)
            .ok_or(SessionError::MissingSession)?;
        let newly_marked = !session.needs_resync;
        session.needs_resync = true;
        Ok(newly_marked)
    }

    #[cfg(test)]
    pub fn fail_next_send_commit(&mut self) {
        self.fail_next_send_commit = true;
    }

    pub fn advance_receiving(
        &mut self,
        peer: &NodeId,
        target_counter: u64,
        now: u64,
    ) -> Result<(MessageKey, u64), SessionError> {
        let session = self
            .sessions
            .get_mut(peer)
            .ok_or(SessionError::MissingSession)?;
        if !session.responded {
            return Err(SessionError::SessionNotReady);
        }
        if session.needs_resync {
            return Err(SessionError::NeedsResync);
        }
        if session.prepared_receive.is_some() {
            return Err(SessionError::ReceiveAlreadyPrepared);
        }
        Self::prune_expired_skipped_keys(session, now, &self.metrics);
        let next = session.receiving_chain.next_index();
        if target_counter < next {
            let skipped = session
                .skipped_keys
                .remove(&(session.chain_epoch, target_counter))
                .ok_or(SessionError::SkippedKeyUnavailable(target_counter))?;
            self.metrics
                .ratchet_skipped_keys_current
                .fetch_sub(1, Ordering::Relaxed);
            session.last_used_at = now;
            return Ok((skipped.key, target_counter));
        }
        if target_counter - next > MAX_RATCHET_GAP {
            return Err(SessionError::GapTooLarge {
                requested: target_counter,
                next,
            });
        }
        let peeked = session.receiving_chain.peek_chain(target_counter)?;
        let committed_target = session.receiving_chain.skip_to(target_counter)?;
        if committed_target.key.as_ref() != peeked.target_key.key.as_ref() {
            return Err(SessionError::CounterMismatch {
                expected: peeked.target_key.index,
                actual: committed_target.index,
            });
        }
        Self::cache_skipped_keys(session, peeked.skipped, now, &self.metrics);
        let counter = peeked.target_key.index;
        session.last_used_at = now;
        Ok((peeked.target_key, counter))
    }

    pub fn advance_receiving_with<T, E>(
        &mut self,
        peer: &NodeId,
        target_counter: u64,
        now: u64,
        operation: impl FnOnce(&MessageKey) -> std::result::Result<T, E>,
    ) -> Result<std::result::Result<(T, u64), E>, SessionError> {
        let session = self
            .sessions
            .get_mut(peer)
            .ok_or(SessionError::MissingSession)?;
        if !session.responded {
            return Err(SessionError::SessionNotReady);
        }
        if session.needs_resync {
            return Err(SessionError::NeedsResync);
        }
        if session.prepared_receive.is_some() {
            return Err(SessionError::ReceiveAlreadyPrepared);
        }
        let generation = session.generation;
        let preview =
            self.prepare_receive_with_skipped_at(peer, target_counter, generation, now)?;
        let counter = preview.counter;
        match operation(&preview.target_key) {
            Ok(value) => {
                self.commit_receive_preview(peer, preview, now)?;
                Ok(Ok((value, counter)))
            }
            Err(error) => {
                self.abort_receive_preview(peer, preview)?;
                Ok(Err(error))
            }
        }
    }

    pub fn remove(&mut self, peer: &NodeId) -> Option<Session> {
        let removed = self.sessions.remove(peer)?;
        if let Some(storage) = self.storage.as_ref() {
            let peer_hex = Self::peer_key(peer);
            let Ok(storage) = storage.lock() else {
                return Some(removed);
            };
            let _ = storage.delete_session(&peer_hex);
        }
        self.metrics
            .ratchet_skipped_keys_current
            .fetch_sub(removed.skipped_keys.len() as u64, Ordering::Relaxed);
        Some(removed)
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    pub(crate) fn mark_responded(
        &mut self,
        peer: &NodeId,
        ephemeral: &[u8; 32],
        signed_prekey: &[u8; 32],
        opk_id: Option<u32>,
        now: u64,
    ) -> bool {
        let Some(session) = self.sessions.get_mut(peer) else {
            return false;
        };
        if session.pending_ephemeral.as_ref() != Some(ephemeral)
            || session.pending_signed_prekey.as_ref() != Some(signed_prekey)
            || session.pending_opk_id != opk_id
        {
            return false;
        }
        session.pending_ephemeral = None;
        session.pending_signed_prekey = None;
        session.pending_opk_id = None;
        session.responded = true;
        session.needs_resync = false;
        session.last_used_at = now;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preview_store() -> (SessionStore, NodeId, u64) {
        let local = NodeId::from_bytes([81; 32]);
        let peer = NodeId::from_bytes([82; 32]);
        let mut store = SessionStore::new();
        store.insert_with_chains(peer, [83; 32], &local, 5).unwrap();
        let (_, generation) = store.receive_lock(&peer).unwrap();
        (store, peer, generation)
    }

    fn receive_and_skip(store: &mut SessionStore, peer: &NodeId, generation: u64, counter: u64) {
        let preview = store
            .prepare_receive_with_skipped_at(peer, counter, generation, 10)
            .unwrap();
        store.commit_receive_preview(peer, preview, 10).unwrap();
    }
    use ed25519_dalek::SigningKey;

    fn node(byte: u8) -> NodeId {
        NodeId::from_public_key(&SigningKey::from_bytes(&[byte; 32]).verifying_key())
    }

    #[test]
    fn derive_seeds_differ_for_direction() {
        let (send, recv, _) = derive_direction_seeds(&[9; 32], &node(1), &node(2)).unwrap();
        assert_ne!(send, recv);
    }

    #[test]
    fn a_send_matches_b_recv() {
        let a = node(1);
        let b = node(2);
        let (a_send, _, _) = derive_direction_seeds(&[9; 32], &a, &b).unwrap();
        let (_, b_recv, _) = derive_direction_seeds(&[9; 32], &b, &a).unwrap();
        assert_eq!(a_send, b_recv);
    }

    #[test]
    fn a_recv_matches_b_send() {
        let a = node(1);
        let b = node(2);
        let (_, a_recv, _) = derive_direction_seeds(&[9; 32], &a, &b).unwrap();
        let (b_send, _, _) = derive_direction_seeds(&[9; 32], &b, &a).unwrap();
        assert_eq!(a_recv, b_send);
    }

    #[test]
    fn direction_low_to_high() {
        let a = NodeId::from_bytes([0; 32]);
        let b = NodeId::from_bytes([1; 32]);
        let (_, _, direction) = derive_direction_seeds(&[9; 32], &a, &b).unwrap();
        assert_eq!(direction, Direction::LowToHigh);
    }

    #[test]
    fn direction_high_to_low() {
        let a = NodeId::from_bytes([0; 32]);
        let b = NodeId::from_bytes([1; 32]);
        let (_, _, direction) = derive_direction_seeds(&[9; 32], &b, &a).unwrap();
        assert_eq!(direction, Direction::HighToLow);
    }

    #[test]
    fn session_view_has_no_chains() {
        let mut store = SessionStore::new();
        let local = NodeId::from_bytes([1; 32]);
        let peer = NodeId::from_bytes([2; 32]);
        store.insert_with_chains(peer, [9; 32], &local, 5).unwrap();
        let view = store.get_view(&peer).unwrap();
        assert_eq!((view.send_counter, view.recv_counter), (0, 0));
        assert!(!format!("{view:?}").contains("chain_key"));
    }

    #[test]
    fn advance_sending_increments_counter() {
        let mut store = SessionStore::new();
        let local = NodeId::from_bytes([1; 32]);
        let peer = NodeId::from_bytes([2; 32]);
        store.insert_with_chains(peer, [9; 32], &local, 5).unwrap();
        let (_, counter) = store.advance_sending(&peer, 6).unwrap();
        assert_eq!(counter, 0);
        assert_eq!(store.get_view(&peer).unwrap().send_counter, 1);
    }

    #[test]
    fn advance_sending_produces_sequence() {
        let mut store = SessionStore::new();
        let local = NodeId::from_bytes([1; 32]);
        let peer = NodeId::from_bytes([2; 32]);
        store.insert_with_chains(peer, [9; 32], &local, 5).unwrap();
        let counters = (0..3)
            .map(|_| store.advance_sending(&peer, 6).unwrap().1)
            .collect::<Vec<_>>();
        assert_eq!(counters, [0, 1, 2]);
    }

    #[test]
    fn advance_receiving_at_next_counter_works() {
        let mut store = SessionStore::new();
        let local = NodeId::from_bytes([1; 32]);
        let peer = NodeId::from_bytes([2; 32]);
        store.insert_with_chains(peer, [9; 32], &local, 5).unwrap();
        let (_, counter) = store.advance_receiving(&peer, 0, 6).unwrap();
        assert_eq!(counter, 0);
    }

    #[test]
    fn advance_receiving_skip_to() {
        let mut store = SessionStore::new();
        let local = NodeId::from_bytes([1; 32]);
        let peer = NodeId::from_bytes([2; 32]);
        store.insert_with_chains(peer, [9; 32], &local, 5).unwrap();
        let (key, counter) = store.advance_receiving(&peer, 2, 6).unwrap();
        assert_eq!(key.index, 2);
        assert_eq!(counter, 2);
        assert_eq!(store.get_view(&peer).unwrap().recv_counter, 3);
        assert!((0..2).all(|index| store
            .sessions
            .get(&peer)
            .unwrap()
            .skipped_keys
            .contains_key(&(0, index))));
    }

    #[test]
    fn advance_receiving_backward_fails() {
        let mut store = SessionStore::new();
        let local = NodeId::from_bytes([1; 32]);
        let peer = NodeId::from_bytes([2; 32]);
        store.insert_with_chains(peer, [9; 32], &local, 5).unwrap();
        store.advance_receiving(&peer, 0, 6).unwrap();
        assert!(matches!(
            store.advance_receiving(&peer, 0, 7),
            Err(SessionError::SkippedKeyUnavailable(0))
        ));
    }

    #[test]
    fn failed_receive_operation_does_not_advance_chain() {
        let local = NodeId::from_bytes([1; 32]);
        let peer = NodeId::from_bytes([2; 32]);
        let mut receiver = SessionStore::new();
        let mut sender = SessionStore::new();
        receiver
            .insert_with_chains(peer, [9; 32], &local, 5)
            .unwrap();
        sender.insert_with_chains(local, [9; 32], &peer, 5).unwrap();

        let failed: Result<Result<((), u64), &str>, SessionError> =
            receiver.advance_receiving_with(&peer, 0, 6, |_| Err("bad authentication"));
        assert!(matches!(failed, Ok(Err("bad authentication"))));
        assert_eq!(receiver.get_view(&peer).unwrap().recv_counter, 0);

        let (sent_key, sent_counter) = sender.advance_sending(&local, 6).unwrap();
        let (received_key, received_counter) = receiver
            .advance_receiving_with(&peer, 0, 7, |key| Ok::<_, &str>(*key.key == *sent_key.key))
            .unwrap()
            .unwrap();
        assert!(received_key);
        assert_eq!(sent_counter, received_counter);
        assert_eq!(receiver.get_view(&peer).unwrap().recv_counter, 1);
    }

    #[test]
    fn advance_receiving_with_ahead_caches_skipped_only_after_success() {
        let local = NodeId::from_bytes([84; 32]);
        let peer = NodeId::from_bytes([85; 32]);
        let mut store = SessionStore::new();
        store.insert_with_chains(peer, [86; 32], &local, 5).unwrap();

        let failed: Result<Result<((), u64), &str>, SessionError> =
            store.advance_receiving_with(&peer, 2, 6, |_| Err("authentication failed"));
        assert!(matches!(failed, Ok(Err("authentication failed"))));
        assert_eq!(store.get_view(&peer).unwrap().recv_counter, 0);
        assert!(store.sessions.get(&peer).unwrap().skipped_keys.is_empty());

        let accepted: Result<Result<(u64, u64), &str>, SessionError> =
            store.advance_receiving_with(&peer, 2, 7, |key| Ok::<_, &str>(key.index));
        assert_eq!(accepted.unwrap().unwrap(), (2, 2));
        assert_eq!(store.get_view(&peer).unwrap().recv_counter, 3);
        assert!((0..2).all(|index| store
            .sessions
            .get(&peer)
            .unwrap()
            .skipped_keys
            .contains_key(&(0, index))));
    }

    #[test]
    fn prepared_receive_advances_only_after_commit() {
        let local = NodeId::from_bytes([13; 32]);
        let peer = NodeId::from_bytes([14; 32]);
        let mut store = SessionStore::new();
        store.insert_with_chains(peer, [28; 32], &local, 5).unwrap();

        let (_, generation) = store.receive_lock(&peer).unwrap();
        let preview = store
            .prepare_receive_with_skipped_at(&peer, 0, generation, 5)
            .unwrap();
        assert_eq!(preview.target_key.index, 0);
        assert_eq!(store.get_view(&peer).unwrap().recv_counter, 0);
        store.abort_receive_preview(&peer, preview).unwrap();
        assert_eq!(store.get_view(&peer).unwrap().recv_counter, 0);
        let preview = store
            .prepare_receive_with_skipped_at(&peer, 0, generation, 5)
            .unwrap();
        store.commit_receive_preview(&peer, preview, 6).unwrap();
        assert_eq!(store.get_view(&peer).unwrap().recv_counter, 1);
    }

    #[test]
    fn prepare_receive_in_order_no_skipped() {
        let (mut store, peer, generation) = preview_store();

        let preview = store
            .prepare_receive_with_skipped_at(&peer, 0, generation, 5)
            .unwrap();

        assert_eq!(preview.counter, 0);
        assert!(!preview.from_skipped);
        assert!(preview.skipped_to_insert.is_empty());
        assert_eq!(preview.target_key.index, 0);
        assert_eq!(store.get_view(&peer).unwrap().recv_counter, 0);
    }

    #[test]
    fn commit_receive_in_order_advances() {
        let (mut store, peer, generation) = preview_store();
        let preview = store
            .prepare_receive_with_skipped_at(&peer, 0, generation, 5)
            .unwrap();

        store.commit_receive_preview(&peer, preview, 11).unwrap();

        assert_eq!(store.get_view(&peer).unwrap().recv_counter, 1);
        assert!(store.sessions.get(&peer).unwrap().skipped_keys.is_empty());
    }

    #[test]
    fn prepare_receive_ahead_returns_skipped() {
        let (mut store, peer, generation) = preview_store();

        let preview = store
            .prepare_receive_with_skipped_at(&peer, 3, generation, 5)
            .unwrap();

        assert_eq!(preview.counter, 3);
        assert!(!preview.from_skipped);
        assert_eq!(preview.target_key.index, 3);
        assert_eq!(
            preview
                .skipped_to_insert
                .iter()
                .map(|(counter, _)| *counter)
                .collect::<Vec<_>>(),
            [0, 1, 2]
        );
        assert_eq!(store.get_view(&peer).unwrap().recv_counter, 0);
    }

    #[test]
    fn commit_receive_ahead_inserts_skipped() {
        let (mut store, peer, generation) = preview_store();
        let preview = store
            .prepare_receive_with_skipped_at(&peer, 3, generation, 5)
            .unwrap();

        store.commit_receive_preview(&peer, preview, 12).unwrap();

        let session = store.sessions.get(&peer).unwrap();
        assert_eq!(session.receiving_chain.next_index(), 4);
        assert!((0..3).all(|counter| session.skipped_keys.contains_key(&(0, counter))));
        assert!(session
            .skipped_keys
            .values()
            .all(|skipped| skipped.received_at == 12));
    }

    #[test]
    fn prepare_receive_behind_takes_from_skipped() {
        let (mut store, peer, generation) = preview_store();
        receive_and_skip(&mut store, &peer, generation, 3);

        let preview = store
            .prepare_receive_with_skipped_at(&peer, 1, generation, 10)
            .unwrap();

        assert!(preview.from_skipped);
        assert_eq!(preview.target_key.index, 1);
        assert!(preview.skipped_to_insert.is_empty());
        assert!(!store
            .sessions
            .get(&peer)
            .unwrap()
            .skipped_keys
            .contains_key(&(0, 1)));
    }

    #[test]
    fn commit_receive_behind_consumes_skipped() {
        let (mut store, peer, generation) = preview_store();
        receive_and_skip(&mut store, &peer, generation, 3);
        let preview = store
            .prepare_receive_with_skipped_at(&peer, 1, generation, 10)
            .unwrap();

        store.commit_receive_preview(&peer, preview, 13).unwrap();

        let session = store.sessions.get(&peer).unwrap();
        assert_eq!(session.receiving_chain.next_index(), 4);
        assert!(!session.skipped_keys.contains_key(&(0, 1)));
        assert_eq!(session.skipped_keys.len(), 2);
    }

    #[test]
    fn abort_receive_behind_returns_key() {
        let (mut store, peer, generation) = preview_store();
        receive_and_skip(&mut store, &peer, generation, 3);
        let expected_key = *store
            .sessions
            .get(&peer)
            .unwrap()
            .skipped_keys
            .get(&(0, 1))
            .unwrap()
            .key
            .key;
        let preview = store
            .prepare_receive_with_skipped_at(&peer, 1, generation, 10)
            .unwrap();

        store.abort_receive_preview(&peer, preview).unwrap();

        let session = store.sessions.get(&peer).unwrap();
        assert_eq!(
            *session.skipped_keys.get(&(0, 1)).unwrap().key.key,
            expected_key
        );
        assert_eq!(session.skipped_keys.get(&(0, 1)).unwrap().received_at, 10);
    }

    #[test]
    fn prepare_receive_gap_too_large() {
        let (mut store, peer, generation) = preview_store();

        assert!(matches!(
            store.prepare_receive_with_skipped_at(&peer, 1000, generation, 5),
            Err(SessionError::GapTooLarge { .. })
        ));
        assert_eq!(store.get_view(&peer).unwrap().recv_counter, 0);
    }

    #[test]
    fn prepare_receive_behind_unavailable() {
        let (mut store, peer, generation) = preview_store();
        store.advance_receiving(&peer, 0, 11).unwrap();

        assert!(matches!(
            store.prepare_receive_with_skipped_at(&peer, 0, generation, 11),
            Err(SessionError::SkippedKeyUnavailable(0))
        ));
        assert_eq!(store.get_view(&peer).unwrap().recv_counter, 1);
    }

    #[test]
    fn receive_preview_cannot_commit_into_replaced_session() {
        let (mut store, peer, generation) = preview_store();
        let preview = store
            .prepare_receive_with_skipped_at(&peer, 2, generation, 5)
            .unwrap();
        let local = NodeId::from_bytes([81; 32]);
        store
            .insert_with_chains(peer, [84; 32], &local, 11)
            .unwrap();

        assert!(matches!(
            store.commit_receive_preview(&peer, preview, 12),
            Err(SessionError::SessionReplaced)
        ));
        assert_eq!(store.get_view(&peer).unwrap().recv_counter, 0);
    }

    #[test]
    fn prepared_receive_cannot_commit_into_replaced_session() {
        let (mut store, peer, generation) = preview_store();
        let preview = store
            .prepare_receive_with_skipped_at(&peer, 0, generation, 5)
            .unwrap();
        let local = NodeId::from_bytes([85; 32]);
        store.insert_with_chains(peer, [86; 32], &local, 6).unwrap();

        assert!(matches!(
            store.commit_receive_preview(&peer, preview, 7),
            Err(SessionError::SessionReplaced)
        ));
        assert_eq!(store.get_view(&peer).unwrap().recv_counter, 0);
    }

    #[test]
    fn receive_commit_requires_matching_prepare_and_is_single_use() {
        let (mut store, peer, generation) = preview_store();
        let preview = store
            .prepare_receive_with_skipped_at(&peer, 0, generation, 5)
            .unwrap();
        assert!(matches!(
            store.prepare_receive_with_skipped_at(&peer, 0, generation, 5),
            Err(SessionError::ReceiveAlreadyPrepared)
        ));

        store.commit_receive_preview(&peer, preview, 6).unwrap();
        assert!(matches!(
            store.prepare_receive_with_skipped_at(&peer, 0, generation, 6),
            Err(SessionError::SkippedKeyUnavailable(0))
        ));
        assert_eq!(store.get_view(&peer).unwrap().recv_counter, 1);
    }

    #[test]
    fn commit_receive_ahead_evicts_lru_when_full() {
        let (mut store, peer, generation) = preview_store();
        let session = store.sessions.get_mut(&peer).unwrap();
        for counter in 100..100 + MAX_SKIPPED_KEYS as u64 {
            session.skipped_keys.insert(
                (0, counter),
                SkippedKey {
                    key: MessageKey {
                        index: counter,
                        key: zeroize::Zeroizing::new([counter as u8; 32]),
                    },
                    received_at: counter,
                    chain_epoch: 0,
                },
            );
        }
        store
            .metrics
            .ratchet_skipped_keys_current
            .store(MAX_SKIPPED_KEYS as u64, Ordering::Relaxed);
        let preview = store
            .prepare_receive_with_skipped_at(&peer, 2, generation, 5)
            .unwrap();

        store.commit_receive_preview(&peer, preview, 5000).unwrap();

        let skipped = &store.sessions.get(&peer).unwrap().skipped_keys;
        assert_eq!(skipped.len(), MAX_SKIPPED_KEYS);
        assert!(!skipped.contains_key(&(0, 100)));
        assert!(!skipped.contains_key(&(0, 101)));
        assert!(skipped.contains_key(&(0, 102)));
        assert!(skipped.contains_key(&(0, 0)));
        assert!(skipped.contains_key(&(0, 1)));
    }

    #[test]
    fn skipped_key_expires_after_ttl() {
        let (mut store, peer, generation) = preview_store();
        receive_and_skip(&mut store, &peer, generation, 1);
        let preview = store
            .prepare_receive_with_skipped_at(&peer, 2, generation, 11)
            .unwrap();

        store
            .commit_receive_preview(&peer, preview, SKIPPED_KEY_TTL_SECS + 11)
            .unwrap();

        let session = store.sessions.get(&peer).unwrap();
        assert!(!session.skipped_keys.contains_key(&(0, 0)));
        assert_eq!(session.skipped_keys.len(), 0);
        assert_eq!(
            store
                .metrics
                .ratchet_skipped_keys_expired_total
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn skipped_key_retained_within_ttl() {
        let (mut store, peer, generation) = preview_store();
        receive_and_skip(&mut store, &peer, generation, 1);

        let preview = store
            .prepare_receive_with_skipped_at(&peer, 0, generation, 10 + 23 * 60 * 60)
            .unwrap();

        assert!(preview.from_skipped);
        store.abort_receive_preview(&peer, preview).unwrap();
        assert_eq!(store.get_view(&peer).unwrap().skipped_keys_count, 1);
    }

    #[test]
    fn prepare_receive_with_expired_skipped_fails() {
        let (mut store, peer, generation) = preview_store();
        receive_and_skip(&mut store, &peer, generation, 1);

        assert!(matches!(
            store.prepare_receive_with_skipped_at(&peer, 0, generation, SKIPPED_KEY_TTL_SECS + 11),
            Err(SessionError::SkippedKeyUnavailable(0))
        ));
        assert_eq!(store.get_view(&peer).unwrap().skipped_keys_count, 0);
        assert_eq!(
            store
                .metrics
                .ratchet_skipped_keys_expired_total
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn commit_receive_prunes_expired_before_lru() {
        let (mut store, peer, generation) = preview_store();
        let now = SKIPPED_KEY_TTL_SECS + 1;
        let session = store.sessions.get_mut(&peer).unwrap();
        for (counter, received_at) in [(100, 0), (101, 0), (102, 0), (103, now - 1), (104, now - 1)]
        {
            session.skipped_keys.insert(
                (0, counter),
                SkippedKey {
                    key: MessageKey {
                        index: counter,
                        key: zeroize::Zeroizing::new([counter as u8; 32]),
                    },
                    received_at,
                    chain_epoch: 0,
                },
            );
        }
        store
            .metrics
            .ratchet_skipped_keys_current
            .store(5, Ordering::Relaxed);
        let preview = store
            .prepare_receive_with_skipped_at(&peer, 2, generation, 100)
            .unwrap();

        store.commit_receive_preview(&peer, preview, now).unwrap();

        let session = store.sessions.get(&peer).unwrap();
        assert_eq!(session.skipped_keys.len(), 4);
        assert!(!session.skipped_keys.contains_key(&(0, 100)));
        assert!(!session.skipped_keys.contains_key(&(0, 101)));
        assert!(!session.skipped_keys.contains_key(&(0, 102)));
        assert!(session.skipped_keys.contains_key(&(0, 103)));
        assert!(session.skipped_keys.contains_key(&(0, 104)));
        assert_eq!(
            store
                .metrics
                .ratchet_skipped_keys_evicted_total
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            store
                .metrics
                .ratchet_skipped_keys_expired_total
                .load(Ordering::Relaxed),
            3
        );
    }

    #[test]
    fn skipped_keys_inserted_metric() {
        let metrics = Arc::new(AbuseMetrics::new());
        let local = NodeId::from_bytes([81; 32]);
        let peer = NodeId::from_bytes([82; 32]);
        let mut store = SessionStore::with_metrics(Arc::clone(&metrics));
        store.insert_with_chains(peer, [83; 32], &local, 5).unwrap();
        let (_, generation) = store.receive_lock(&peer).unwrap();
        let preview = store
            .prepare_receive_with_skipped_at(&peer, 3, generation, 10)
            .unwrap();

        store.commit_receive_preview(&peer, preview, 10).unwrap();

        assert_eq!(
            metrics
                .ratchet_skipped_keys_inserted_total
                .load(Ordering::Relaxed),
            3
        );
        assert_eq!(
            metrics.ratchet_skipped_keys_current.load(Ordering::Relaxed),
            3
        );
    }

    #[test]
    fn skipped_keys_expired_metric() {
        let metrics = Arc::new(AbuseMetrics::new());
        let local = NodeId::from_bytes([81; 32]);
        let peer = NodeId::from_bytes([82; 32]);
        let mut store = SessionStore::with_metrics(Arc::clone(&metrics));
        store.insert_with_chains(peer, [83; 32], &local, 5).unwrap();
        let (_, generation) = store.receive_lock(&peer).unwrap();
        let preview = store
            .prepare_receive_with_skipped_at(&peer, 2, generation, 10)
            .unwrap();
        store.commit_receive_preview(&peer, preview, 10).unwrap();

        let preview = store
            .prepare_receive_with_skipped_at(&peer, 3, generation, 11)
            .unwrap();
        store
            .commit_receive_preview(&peer, preview, SKIPPED_KEY_TTL_SECS + 11)
            .unwrap();

        assert_eq!(
            metrics
                .ratchet_skipped_keys_expired_total
                .load(Ordering::Relaxed),
            2
        );
        assert_eq!(
            metrics.ratchet_skipped_keys_current.load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn skipped_keys_evicted_metric() {
        let metrics = Arc::new(AbuseMetrics::new());
        let local = NodeId::from_bytes([81; 32]);
        let peer = NodeId::from_bytes([82; 32]);
        let mut store = SessionStore::with_metrics(Arc::clone(&metrics));
        store.insert_with_chains(peer, [83; 32], &local, 5).unwrap();
        let (_, generation) = store.receive_lock(&peer).unwrap();
        let session = store.sessions.get_mut(&peer).unwrap();
        for counter in 100..100 + MAX_SKIPPED_KEYS as u64 {
            session.skipped_keys.insert(
                (0, counter),
                SkippedKey {
                    key: MessageKey {
                        index: counter,
                        key: zeroize::Zeroizing::new([counter as u8; 32]),
                    },
                    received_at: counter,
                    chain_epoch: 0,
                },
            );
        }
        metrics
            .ratchet_skipped_keys_current
            .store(MAX_SKIPPED_KEYS as u64, Ordering::Relaxed);
        let preview = store
            .prepare_receive_with_skipped_at(&peer, 2, generation, 5000)
            .unwrap();

        store.commit_receive_preview(&peer, preview, 5000).unwrap();

        assert_eq!(
            metrics
                .ratchet_skipped_keys_evicted_total
                .load(Ordering::Relaxed),
            2
        );
        assert_eq!(
            metrics.ratchet_skipped_keys_current.load(Ordering::Relaxed),
            MAX_SKIPPED_KEYS as u64
        );
    }

    #[test]
    fn skipped_keys_current_metric_tracks_insert_consume_and_remove() {
        let metrics = Arc::new(AbuseMetrics::new());
        let local = NodeId::from_bytes([81; 32]);
        let peer = NodeId::from_bytes([82; 32]);
        let mut store = SessionStore::with_metrics(Arc::clone(&metrics));
        store.insert_with_chains(peer, [83; 32], &local, 5).unwrap();
        let (_, generation) = store.receive_lock(&peer).unwrap();
        let preview = store
            .prepare_receive_with_skipped_at(&peer, 3, generation, 10)
            .unwrap();
        store.commit_receive_preview(&peer, preview, 10).unwrap();
        assert_eq!(
            metrics.ratchet_skipped_keys_current.load(Ordering::Relaxed),
            3
        );
        assert_eq!(store.get_view(&peer).unwrap().skipped_keys_count, 3);

        let preview = store
            .prepare_receive_with_skipped_at(&peer, 1, generation, 11)
            .unwrap();
        assert_eq!(
            metrics.ratchet_skipped_keys_current.load(Ordering::Relaxed),
            2
        );
        store.commit_receive_preview(&peer, preview, 11).unwrap();
        assert_eq!(store.get_view(&peer).unwrap().skipped_keys_count, 2);
        store.remove(&peer);
        assert_eq!(
            metrics.ratchet_skipped_keys_current.load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn skipped_key_not_leaked_in_debug() {
        let (mut store, peer, generation) = preview_store();
        receive_and_skip(&mut store, &peer, generation, 2);
        let session = store.sessions.get(&peer).unwrap();
        let leaked_hex = hex::encode(
            session
                .skipped_keys
                .get(&(0, 0))
                .unwrap()
                .key
                .key
                .as_slice(),
        );

        assert!(!format!("{session:?}").contains(&leaked_hex));
        assert!(!format!("{:?}", session.skipped_keys.get(&(0, 0)).unwrap()).contains(&leaked_hex));
    }

    #[test]
    fn receive_commit_after_session_removal_is_rejected() {
        let local = NodeId::from_bytes([38; 32]);
        let peer = NodeId::from_bytes([39; 32]);
        let mut store = SessionStore::new();
        store.insert_with_chains(peer, [40; 32], &local, 5).unwrap();
        let (_, generation) = store.receive_lock(&peer).unwrap();
        let preview = store
            .prepare_receive_with_skipped_at(&peer, 0, generation, 5)
            .unwrap();
        store.remove(&peer);

        assert!(matches!(
            store.commit_receive_preview(&peer, preview, 6),
            Err(SessionError::MissingSession)
        ));
    }

    #[test]
    fn receive_gap_over_limit_is_rejected_without_chain_work() {
        let local = NodeId::from_bytes([41; 32]);
        let peer = NodeId::from_bytes([42; 32]);
        let mut store = SessionStore::new();
        store.insert_with_chains(peer, [43; 32], &local, 5).unwrap();
        let (_, generation) = store.receive_lock(&peer).unwrap();

        assert!(matches!(
            store.prepare_receive_with_skipped_at(&peer, MAX_RATCHET_GAP + 1, generation, 5,),
            Err(SessionError::GapTooLarge {
                requested: 501,
                next: 0
            })
        ));
        assert_eq!(store.get_view(&peer).unwrap().recv_counter, 0);
    }

    #[test]
    fn stale_receive_lock_generation_is_rejected_before_key_derivation() {
        let local = NodeId::from_bytes([44; 32]);
        let peer = NodeId::from_bytes([45; 32]);
        let mut store = SessionStore::new();
        store.insert_with_chains(peer, [46; 32], &local, 5).unwrap();
        let (_, old_generation) = store.receive_lock(&peer).unwrap();
        store.insert_with_chains(peer, [47; 32], &local, 6).unwrap();
        let (_, new_generation) = store.receive_lock(&peer).unwrap();

        assert_ne!(old_generation, new_generation);
        assert!(matches!(
            store.prepare_receive_with_skipped_at(&peer, 0, old_generation, 5),
            Err(SessionError::SessionReplaced)
        ));
        assert_eq!(store.get_view(&peer).unwrap().recv_counter, 0);
    }

    #[test]
    fn needs_resync_blocks_ratchet_operations_until_session_replaced() {
        let local = NodeId::from_bytes([15; 32]);
        let peer = NodeId::from_bytes([16; 32]);
        let mut store = SessionStore::new();
        store.insert_with_chains(peer, [29; 32], &local, 5).unwrap();

        assert!(store.mark_needs_resync(&peer).unwrap());
        assert!(!store.mark_needs_resync(&peer).unwrap());
        assert!(store.get_view(&peer).unwrap().needs_resync);
        assert!(matches!(
            store.peek_sending(&peer),
            Err(SessionError::NeedsResync)
        ));
        assert!(matches!(
            store.prepare_receive_with_skipped_at(&peer, 0, 0, 5),
            Err(SessionError::NeedsResync)
        ));

        store.insert_with_chains(peer, [30; 32], &local, 7).unwrap();
        assert!(!store.get_view(&peer).unwrap().needs_resync);
    }

    #[test]
    fn peek_sending_returns_next_counter_without_advancing() {
        let local = NodeId::from_bytes([3; 32]);
        let peer = NodeId::from_bytes([4; 32]);
        let mut store = SessionStore::new();
        store.insert_with_chains(peer, [23; 32], &local, 5).unwrap();

        let (key, counter) = store.peek_sending(&peer).unwrap();
        assert_eq!(counter, 0);
        assert_eq!(key.index, 0);
        assert_eq!(store.get_view(&peer).unwrap().send_counter, 0);
    }

    #[test]
    fn commit_sending_after_peek_advances_once() {
        let local = NodeId::from_bytes([5; 32]);
        let peer = NodeId::from_bytes([6; 32]);
        let mut store = SessionStore::new();
        store.insert_with_chains(peer, [24; 32], &local, 5).unwrap();

        let (key, counter) = store.peek_sending(&peer).unwrap();
        store.commit_sending(&peer, counter, 6).unwrap();
        let (next_key, next_counter) = store.peek_sending(&peer).unwrap();
        assert_eq!(counter, 0);
        assert_eq!(key.index, counter);
        assert_eq!(next_counter, 1);
        assert_eq!(next_key.index, 1);
        assert_eq!(store.get_view(&peer).unwrap().send_counter, 1);
    }

    #[test]
    fn commit_sending_wrong_counter_fails_without_advancing() {
        let local = NodeId::from_bytes([7; 32]);
        let peer = NodeId::from_bytes([8; 32]);
        let mut store = SessionStore::new();
        store.insert_with_chains(peer, [25; 32], &local, 5).unwrap();

        let error = store.commit_sending(&peer, 1, 6).unwrap_err();
        assert!(matches!(
            error,
            SessionError::CounterMismatch {
                expected: 1,
                actual: 0
            }
        ));
        assert_eq!(store.get_view(&peer).unwrap().send_counter, 0);
    }

    #[test]
    fn peek_does_not_commit_sending_counter() {
        let local = NodeId::from_bytes([9; 32]);
        let peer = NodeId::from_bytes([10; 32]);
        let mut store = SessionStore::new();
        store.insert_with_chains(peer, [26; 32], &local, 5).unwrap();

        let (_, counter) = store.peek_sending(&peer).unwrap();
        assert_eq!(store.get_view(&peer).unwrap().send_counter, 0);

        let (retry_key, retry_counter) = store.peek_sending(&peer).unwrap();
        assert_eq!(retry_counter, counter);
        assert_eq!(retry_key.index, counter);
    }

    #[test]
    fn repeated_peek_and_commit_uses_monotonic_counters() {
        let local = NodeId::from_bytes([11; 32]);
        let peer = NodeId::from_bytes([12; 32]);
        let mut store = SessionStore::new();
        store.insert_with_chains(peer, [27; 32], &local, 5).unwrap();

        for expected in 0..3 {
            let (key, counter) = store.peek_sending(&peer).unwrap();
            assert_eq!(counter, expected);
            assert_eq!(key.index, expected);
            store.commit_sending(&peer, expected, 6 + expected).unwrap();
        }
        assert_eq!(store.get_view(&peer).unwrap().send_counter, 3);
    }

    fn persist_test_session(store: &SessionStore, peer: &NodeId) {
        let snapshot = store.persistence_snapshot(peer).unwrap().unwrap();
        let storage = store.storage_handle().unwrap();
        snapshot.persist(&storage).unwrap();
    }

    fn session_policy_roundtrip(policy: ContactPolicy) -> ContactPolicy {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session-policy.sqlite3");
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(path, &[0x42u8; 32]).unwrap(),
        ));
        let local = NodeId::from_bytes([91; 32]);
        let peer = NodeId::from_bytes([92; 32]);
        {
            let mut store = SessionStore::with_storage(Arc::clone(&storage), None);
            store
                .insert_with_chains(peer, [93; 32], &local, 10)
                .unwrap();
            store.sessions.get_mut(&peer).unwrap().contact_policy = policy;
            persist_test_session(&store, &peer);
        }
        let mut reopened = SessionStore::with_storage(storage, None);
        reopened.get_or_load(&peer).unwrap().unwrap().contact_policy
    }

    #[test]
    fn contact_policy_default_is_age_proof() {
        let (store, peer, _) = preview_store();
        assert_eq!(
            store.get(&peer).unwrap().contact_policy,
            ContactPolicy::AgeProof
        );
    }

    #[test]
    fn contact_policy_roundtrip_age_proof_sql() {
        assert_eq!(
            session_policy_roundtrip(ContactPolicy::AgeProof),
            ContactPolicy::AgeProof
        );
    }

    #[test]
    fn contact_policy_roundtrip_biometric_interval_sql() {
        let policy = ContactPolicy::BiometricInterval {
            interval_secs: 900,
            last_verified: 1_728_000_000,
        };
        assert_eq!(session_policy_roundtrip(policy), policy);
    }

    #[test]
    fn contact_policy_roundtrip_paranoid_sql() {
        assert_eq!(
            session_policy_roundtrip(ContactPolicy::Paranoid),
            ContactPolicy::Paranoid
        );
    }

    fn ratchet_fixture() -> (SessionStore, NodeId, NodeId, [u8; 32]) {
        let local = NodeId::from_bytes([31; 32]);
        let peer = NodeId::from_bytes([32; 32]);
        let mut store = SessionStore::new();
        store.insert_with_chains(peer, [33; 32], &local, 1).unwrap();
        (store, peer, local, [33; 32])
    }

    fn two_dh_sessions() -> (Session, Session) {
        let mut a = Session::new(
            NodeId::from_bytes([61; 32]),
            [62; 32],
            SymmetricRatchet::new(&[63; 32]),
            SymmetricRatchet::new(&[64; 32]),
            Direction::LowToHigh,
            1,
            1,
            None,
        );
        let mut b = Session::new(
            NodeId::from_bytes([65; 32]),
            [62; 32],
            SymmetricRatchet::new(&[66; 32]),
            SymmetricRatchet::new(&[67; 32]),
            Direction::HighToLow,
            1,
            1,
            None,
        );
        a.dh_peer_pubkey = Some(b.dh_our_pubkey);
        b.dh_peer_pubkey = Some(a.dh_our_pubkey);
        (a, b)
    }

    fn execute_dh_cycle(a: &mut Session, b: &mut Session) -> Result<(), SessionError> {
        let a_new_pub = a.dh_ratchet_initiate()?;
        b.dh_ratchet_step(a_new_pub)?;
        let b_new_pub = b.dh_our_pubkey;
        a.dh_ratchet_complete(b_new_pub)
    }

    fn peer_dh_public() -> [u8; 32] {
        PublicKey::from(&StaticSecret::random_from_rng(rand::thread_rng())).to_bytes()
    }

    #[test]
    fn dh_ratchet_step_advances_chain_epoch() {
        let (mut store, peer, _, _) = ratchet_fixture();
        let session = store.sessions.get_mut(&peer).unwrap();
        session.dh_ratchet_step(peer_dh_public()).unwrap();
        assert_eq!(session.chain_epoch, 1);
    }

    #[test]
    fn dh_ratchet_step_updates_root_key() {
        let (mut store, peer, _, original_root) = ratchet_fixture();
        let session = store.sessions.get_mut(&peer).unwrap();
        session.dh_ratchet_step(peer_dh_public()).unwrap();
        assert_ne!(session.root_key, original_root);
        assert_eq!(session.root_key.len(), 32);
    }

    #[test]
    fn dh_ratchet_step_rotates_dh_keypair() {
        let (mut store, peer, _, _) = ratchet_fixture();
        let session = store.sessions.get_mut(&peer).unwrap();
        let old_public = session.dh_our_pubkey;
        session.dh_ratchet_step(peer_dh_public()).unwrap();
        assert_ne!(session.dh_our_pubkey, old_public);
        assert_eq!(
            PublicKey::from(&StaticSecret::from(session.dh_our_privkey)).to_bytes(),
            session.dh_our_pubkey
        );
    }

    #[test]
    fn dh_ratchet_step_sets_peer_dh_pub() {
        let (mut store, peer, _, _) = ratchet_fixture();
        let peer_public = peer_dh_public();
        store
            .sessions
            .get_mut(&peer)
            .unwrap()
            .dh_ratchet_step(peer_public)
            .unwrap();
        assert_eq!(
            store.sessions.get(&peer).unwrap().dh_peer_pubkey,
            Some(peer_public)
        );
    }

    #[test]
    fn dh_ratchet_step_resets_messages_since_ratchet() {
        let (mut store, peer, _, _) = ratchet_fixture();
        let session = store.sessions.get_mut(&peer).unwrap();
        session.messages_since_ratchet = 41;
        session.dh_ratchet_step(peer_dh_public()).unwrap();
        assert_eq!(session.messages_since_ratchet, 0);
    }

    #[test]
    fn dh_ratchet_step_preserves_skipped_keys() {
        let (mut store, peer, _, _) = ratchet_fixture();
        let session = store.sessions.get_mut(&peer).unwrap();
        let key = MessageKey {
            index: 0,
            key: Zeroizing::new([0xA5; 32]),
        };
        session.skipped_keys.insert(
            (0, 0),
            SkippedKey {
                key,
                received_at: 1,
                chain_epoch: 0,
            },
        );
        session.dh_ratchet_step(peer_dh_public()).unwrap();
        assert!(session.skipped_keys.contains_key(&(0, 0)));
        assert_eq!(session.skipped_keys.get(&(0, 0)).unwrap().chain_epoch, 0);
        session.skipped_keys.insert(
            (1, 0),
            SkippedKey {
                key: MessageKey {
                    index: 0,
                    key: Zeroizing::new([0x5A; 32]),
                },
                received_at: 2,
                chain_epoch: 1,
            },
        );
        assert_eq!(session.skipped_keys.len(), 2);
    }

    #[test]
    fn dh_ratchet_step_send_recv_chains_differ() {
        let (mut store, peer, _, _) = ratchet_fixture();
        let session = store.sessions.get_mut(&peer).unwrap();
        session.dh_ratchet_step(peer_dh_public()).unwrap();
        let (send_key, _) = session.sending_chain.serialize();
        let (recv_key, _) = session.receiving_chain.serialize();
        assert_ne!(*send_key, *recv_key);
    }

    #[test]
    fn dh_ratchet_full_cycle_symmetric() {
        let (mut a, mut b) = two_dh_sessions();
        execute_dh_cycle(&mut a, &mut b).unwrap();
        assert_eq!(a.root_key, b.root_key);
        assert_eq!(a.chain_epoch, b.chain_epoch);
        assert_eq!(a.dh_our_pubkey, b.dh_peer_pubkey.unwrap());
        assert_eq!(b.dh_our_pubkey, a.dh_peer_pubkey.unwrap());
    }

    #[test]
    fn dh_ratchet_full_cycle_chains_match() {
        let (mut a, mut b) = two_dh_sessions();
        execute_dh_cycle(&mut a, &mut b).unwrap();
        let (a_send, _) = a.sending_chain.serialize();
        let (a_recv, _) = a.receiving_chain.serialize();
        let (b_send, _) = b.sending_chain.serialize();
        let (b_recv, _) = b.receiving_chain.serialize();
        assert_eq!(a_send, b_recv);
        assert_eq!(a_recv, b_send);
    }

    #[test]
    fn dh_ratchet_multiple_cycles_consistent() {
        let (mut a, mut b) = two_dh_sessions();
        for _ in 0..3 {
            execute_dh_cycle(&mut a, &mut b).unwrap();
            assert_eq!(a.root_key, b.root_key);
        }
        assert_eq!(a.chain_epoch, 3);
        assert_eq!(b.chain_epoch, 3);
    }

    #[test]
    fn dh_ratchet_initiate_then_cancel_restores_all_pre_initiate_state() {
        let (mut a, _) = two_dh_sessions();
        let root_before = a.root_key;
        let dh_priv_before = a.dh_our_privkey;
        let dh_pub_before = a.dh_our_pubkey;
        let messages_since_before = a.messages_since_ratchet;
        let (send_chain_before, send_index_before) = a.sending_chain.serialize();
        let (recv_chain_before, recv_index_before) = a.receiving_chain.serialize();
        a.dh_ratchet_initiate().unwrap();
        assert_ne!(a.root_key, root_before);
        a.dh_ratchet_cancel().unwrap();
        assert_eq!(a.root_key, root_before);
        assert_eq!(a.dh_our_privkey, dh_priv_before);
        assert_eq!(a.dh_our_pubkey, dh_pub_before);
        assert_eq!(a.messages_since_ratchet, messages_since_before);
        assert_eq!(
            a.sending_chain.serialize(),
            (send_chain_before, send_index_before)
        );
        assert_eq!(
            a.receiving_chain.serialize(),
            (recv_chain_before, recv_index_before)
        );
        assert!(a.pending_dh_ratchet.is_none());
    }

    #[test]
    fn dh_ratchet_initiate_twice_errors() {
        let (mut a, _) = two_dh_sessions();
        a.dh_ratchet_initiate().unwrap();
        assert!(matches!(
            a.dh_ratchet_initiate(),
            Err(SessionError::PendingRatchetExists)
        ));
    }

    #[test]
    fn dh_ratchet_complete_without_initiate_errors() {
        let (mut a, _) = two_dh_sessions();
        assert!(matches!(
            a.dh_ratchet_complete(peer_dh_public()),
            Err(SessionError::NoPendingRatchet)
        ));
        assert!(matches!(
            a.dh_ratchet_cancel(),
            Err(SessionError::NoPendingRatchet)
        ));
    }

    #[test]
    fn dh_ratchet_step_multiple_rounds() {
        let (mut store, peer, _, _) = ratchet_fixture();
        let session = store.sessions.get_mut(&peer).unwrap();
        for _ in 0..3 {
            session.dh_ratchet_step(peer_dh_public()).unwrap();
        }
        assert_eq!(session.chain_epoch, 3);
    }

    #[test]
    fn dh_ratchet_step_invalid_peer_key_errors_without_mutation() {
        let (mut store, peer, _, _) = ratchet_fixture();
        let session = store.sessions.get_mut(&peer).unwrap();
        let original_root = session.root_key;
        let original_private = session.dh_our_privkey;
        assert!(matches!(
            session.dh_ratchet_step([0; 32]),
            Err(SessionError::InvalidDhRatchetPublicKey)
        ));
        assert_eq!(session.root_key, original_root);
        assert_eq!(session.dh_our_privkey, original_private);
    }

    #[test]
    fn dh_ratchet_step_deterministic() {
        let initial_root = [0xA1; 32];
        let our_private = [0xB2; 32];
        let peer_private = [0xC3; 32];
        let new_private = [0xD4; 32];
        let peer_public = PublicKey::from(&StaticSecret::from(peer_private)).to_bytes();
        let our_public = PublicKey::from(&StaticSecret::from(our_private)).to_bytes();
        let mut a = Session::new(
            NodeId::from_bytes([91; 32]),
            initial_root,
            SymmetricRatchet::new(&[1; 32]),
            SymmetricRatchet::new(&[2; 32]),
            Direction::LowToHigh,
            1,
            1,
            None,
        );
        let mut b = Session::new(
            NodeId::from_bytes([92; 32]),
            initial_root,
            SymmetricRatchet::new(&[3; 32]),
            SymmetricRatchet::new(&[4; 32]),
            Direction::HighToLow,
            1,
            1,
            None,
        );
        for session in [&mut a, &mut b] {
            session.dh_our_privkey = our_private;
            session.dh_our_pubkey = our_public;
            session.dh_peer_pubkey = Some(peer_public);
            session
                .dh_ratchet_step_with_new_private(peer_public, Zeroizing::new(new_private))
                .unwrap();
        }

        let dh1 = StaticSecret::from(our_private).diffie_hellman(&PublicKey::from(peer_public));
        let mut ikm_dh1 = [0u8; 72];
        ikm_dh1[..32].copy_from_slice(&initial_root);
        ikm_dh1[32..64].copy_from_slice(dh1.as_bytes());
        ikm_dh1[64..].copy_from_slice(&0u64.to_be_bytes());
        let mut root_after_dh1 = [0u8; 32];
        Hkdf::<Sha256>::new(None, &ikm_dh1)
            .expand(DH_RATCHET_RK_INFO, &mut root_after_dh1)
            .unwrap();
        let dh2 = StaticSecret::from(new_private).diffie_hellman(&PublicKey::from(peer_public));
        let mut ikm_dh2 = [0u8; 72];
        ikm_dh2[..32].copy_from_slice(&root_after_dh1);
        ikm_dh2[32..64].copy_from_slice(dh2.as_bytes());
        ikm_dh2[64..].copy_from_slice(&1u64.to_be_bytes());
        let mut expected_root = [0u8; 32];
        Hkdf::<Sha256>::new(None, &ikm_dh2)
            .expand(DH_RATCHET_RK_INFO, &mut expected_root)
            .unwrap();
        assert_eq!(a.root_key, expected_root);
        assert_eq!(a.root_key, b.root_key);
        assert_eq!(a.chain_epoch, b.chain_epoch);
        assert_eq!(a.dh_our_pubkey, b.dh_our_pubkey);
    }

    #[test]
    fn needs_dh_ratchet_after_interval() {
        let (mut store, peer, _, _) = ratchet_fixture();
        let session = store.sessions.get_mut(&peer).unwrap();
        session.messages_since_ratchet = 49;
        assert!(!session.needs_dh_ratchet());
        session.messages_since_ratchet = 50;
        assert!(session.needs_dh_ratchet());
    }

    #[test]
    fn restart_persists_session() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.sqlite3");
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[0x42u8; 32]).unwrap(),
        ));
        let local = NodeId::from_bytes([1; 32]);
        let peer = NodeId::from_bytes([2; 32]);

        {
            let mut store = SessionStore::with_storage(Arc::clone(&storage), None);
            store.insert_with_chains(peer, [9; 32], &local, 5).unwrap();
            persist_test_session(&store, &peer);
        }

        let mut reopened = SessionStore::with_storage(storage, None);
        let loaded = reopened.get_or_load(&peer).unwrap().unwrap();
        assert_eq!(loaded.peer_identity, peer);
        assert_eq!(loaded.root_key, [9; 32]);
        assert_eq!(loaded.generation, 1);
        assert_eq!(loaded.direction, Direction::LowToHigh);
    }

    #[test]
    fn retired_receiving_chain_and_skipped_keys_survive_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.sqlite3");
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[0x42u8; 32]).unwrap(),
        ));
        let (mut initiator, mut receiver) = two_dh_sessions();
        let expected_old_key = *receiver
            .receiving_chain
            .peek_chain(1)
            .unwrap()
            .target_key
            .key;
        let new_pub = initiator.dh_ratchet_initiate().unwrap();
        receiver.dh_ratchet_step(new_pub).unwrap();
        let peer = receiver.peer_identity;
        let now = crate::runtime::unix_now();
        {
            let mut store = SessionStore::with_storage(Arc::clone(&storage), None);
            store.sessions.insert(peer, receiver);
            let (_, generation) = store.receive_lock(&peer).unwrap();
            let preview = store
                .prepare_v4_retired_receive(&peer, 0, 3, generation, now)
                .unwrap();
            store.commit_receive_preview(&peer, preview, now).unwrap();
            persist_test_session(&store, &peer);
        }

        let mut reopened = SessionStore::with_storage(storage, None);
        reopened.get_or_load(&peer).unwrap();
        let (_, generation) = reopened.receive_lock(&peer).unwrap();
        let loaded = reopened.get(&peer).unwrap();
        assert_eq!(loaded.retired_receiving_chains.len(), 1);
        assert_eq!(
            loaded.retired_receiving_chains[0]
                .receiving_chain
                .next_index(),
            4
        );
        assert_eq!(loaded.retired_receiving_chains[0].skipped_keys.len(), 3);
        let preview = reopened
            .prepare_v4_retired_receive(&peer, 0, 1, generation, now + 1)
            .unwrap();
        assert_eq!(*preview.target_key.key, expected_old_key);
        reopened.abort_receive_preview(&peer, preview).unwrap();

        let loaded = reopened.get_mut(&peer).unwrap();
        loaded.retired_receiving_chains[0].created_at =
            crate::runtime::unix_now().saturating_sub(RETIRED_CHAIN_TTL_SECS);
        let row = SessionStore::session_to_row(loaded).unwrap();
        let expired = deserialize_retired_receiving_chains(
            row.retired_receiving_chains_blob.as_deref(),
            crate::runtime::unix_now(),
        )
        .unwrap();
        assert!(expired.is_empty());
    }

    #[test]
    fn session_dh_fields_survive_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.sqlite3");
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[0x42u8; 32]).unwrap(),
        ));
        let local = NodeId::from_bytes([41; 32]);
        let peer = NodeId::from_bytes([42; 32]);
        let (dh_priv, dh_pub, peer_pub);
        {
            let mut store = SessionStore::with_storage(Arc::clone(&storage), None);
            store.insert_with_chains(peer, [43; 32], &local, 5).unwrap();
            let session = store.sessions.get_mut(&peer).unwrap();
            session.dh_peer_pubkey = Some(peer_dh_public());
            session.chain_epoch = 7;
            session.messages_since_ratchet = 21;
            dh_priv = session.dh_our_privkey;
            dh_pub = session.dh_our_pubkey;
            peer_pub = session.dh_peer_pubkey;
            persist_test_session(&store, &peer);
        }
        let mut reopened = SessionStore::with_storage(storage, None);
        let loaded = reopened.get_or_load(&peer).unwrap().unwrap();
        assert_eq!(loaded.dh_our_privkey, dh_priv);
        assert_eq!(loaded.dh_our_pubkey, dh_pub);
        assert_eq!(loaded.dh_peer_pubkey, peer_pub);
        assert_eq!(loaded.chain_epoch, 7);
        assert_eq!(loaded.messages_since_ratchet, 21);
    }

    #[test]
    fn debug_does_not_leak_root_key() {
        let (store, peer, _, root_key) = ratchet_fixture();
        let session = store.sessions.get(&peer).unwrap();
        let row = SessionStore::session_to_row(session).unwrap();
        let debug = format!("{row:?}");
        assert!(!debug.contains(&hex::encode(root_key)));
        assert!(!debug.contains(&hex::encode(session.dh_our_privkey)));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn session_dh_step_survives_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.sqlite3");
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[0x42u8; 32]).unwrap(),
        ));
        let local = NodeId::from_bytes([51; 32]);
        let peer = NodeId::from_bytes([52; 32]);
        let expected;
        {
            let mut store = SessionStore::with_storage(Arc::clone(&storage), None);
            store.insert_with_chains(peer, [53; 32], &local, 5).unwrap();
            let session = store.sessions.get_mut(&peer).unwrap();
            session.skipped_keys.insert(
                (0, 5),
                SkippedKey {
                    key: MessageKey {
                        index: 5,
                        key: Zeroizing::new([0x5A; 32]),
                    },
                    received_at: 5,
                    chain_epoch: 0,
                },
            );
            session.dh_ratchet_step(peer_dh_public()).unwrap();
            let session = store.sessions.get(&peer).unwrap();
            expected = (
                session.chain_epoch,
                session.root_key,
                session.dh_our_privkey,
                session.dh_our_pubkey,
                session.dh_peer_pubkey,
            );
            persist_test_session(&store, &peer);
        }
        let mut reopened = SessionStore::with_storage(storage, None);
        let loaded = reopened.get_or_load(&peer).unwrap().unwrap();
        assert_eq!(loaded.chain_epoch, expected.0);
        assert_eq!(loaded.root_key, expected.1);
        assert_eq!(loaded.dh_our_privkey, expected.2);
        assert_eq!(loaded.dh_our_pubkey, expected.3);
        assert_eq!(loaded.dh_peer_pubkey, expected.4);
        assert!(loaded.skipped_keys.contains_key(&(0, 5)));
    }

    #[test]
    fn skipped_keys_persistence_preserves_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.sqlite3");
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[0x42u8; 32]).unwrap(),
        ));
        let local = NodeId::from_bytes([71; 32]);
        let peer = NodeId::from_bytes([72; 32]);
        {
            let mut store = SessionStore::with_storage(Arc::clone(&storage), None);
            store.insert_with_chains(peer, [73; 32], &local, 5).unwrap();
            let session = store.sessions.get_mut(&peer).unwrap();
            session.skipped_keys.insert(
                (0, 9),
                SkippedKey {
                    key: MessageKey {
                        index: 9,
                        key: Zeroizing::new([0x39; 32]),
                    },
                    received_at: 5,
                    chain_epoch: 0,
                },
            );
            session.dh_ratchet_step(peer_dh_public()).unwrap();
            persist_test_session(&store, &peer);
        }
        let mut reopened = SessionStore::with_storage(storage, None);
        let loaded = reopened.get_or_load(&peer).unwrap().unwrap();
        let skipped = loaded.skipped_keys.get(&(0, 9)).unwrap();
        assert_eq!(skipped.chain_epoch, 0);
        assert_eq!(skipped.key.index, 9);
    }

    #[test]
    fn skipped_keys_retain_old_epoch_after_step() {
        let (mut store, peer, _, _) = ratchet_fixture();
        let session = store.sessions.get_mut(&peer).unwrap();
        session.skipped_keys.insert(
            (0, 11),
            SkippedKey {
                key: MessageKey {
                    index: 11,
                    key: Zeroizing::new([0x4B; 32]),
                },
                received_at: 1,
                chain_epoch: 0,
            },
        );
        session.dh_ratchet_step(peer_dh_public()).unwrap();
        assert_eq!(session.chain_epoch, 1);
        assert!(session.skipped_keys.contains_key(&(0, 11)));
        assert_eq!(session.skipped_keys.get(&(0, 11)).unwrap().chain_epoch, 0);
        assert_eq!(
            SessionStore::prune_expired_skipped_keys(session, 2, &AbuseMetrics::new(),),
            0
        );
        assert!(session.skipped_keys.contains_key(&(0, 11)));
    }

    #[test]
    fn pending_dh_ratchet_survives_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.sqlite3");
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[0x42u8; 32]).unwrap(),
        ));
        let local = NodeId::from_bytes([81; 32]);
        let peer = NodeId::from_bytes([82; 32]);
        let (root_after_initiate, new_pub);
        {
            let mut store = SessionStore::with_storage(Arc::clone(&storage), None);
            store.insert_with_chains(peer, [83; 32], &local, 5).unwrap();
            let session = store.sessions.get_mut(&peer).unwrap();
            session.dh_peer_pubkey = Some(peer_dh_public());
            session.peer_supports_v4 = Some(true);
            session.peer_supports_invite_redemption = Some(true);
            session.messages_since_ratchet = 17;
            let root_before = session.root_key;
            new_pub = session.dh_ratchet_initiate().unwrap();
            root_after_initiate = session.root_key;
            assert_ne!(root_after_initiate, root_before);
            assert_eq!(session.prev_chain_length, Some(17));
            persist_test_session(&store, &peer);
        }
        let mut reopened = SessionStore::with_storage(storage, None);
        let loaded = reopened.get_or_load(&peer).unwrap().unwrap();
        assert_eq!(loaded.root_key, root_after_initiate);
        assert_eq!(loaded.peer_supports_v4, Some(true));
        assert_eq!(loaded.peer_supports_invite_redemption, Some(true));
        assert_eq!(loaded.prev_chain_length, Some(17));
        assert_eq!(loaded.pending_dh_public_key(), Some(new_pub));
        assert!(loaded.has_pending_dh_ratchet());
        let root_before_cancel = loaded.pending_dh_ratchet.as_ref().unwrap().pre_root_key;
        let restored = reopened.sessions.get_mut(&peer).unwrap();
        restored.dh_ratchet_cancel().unwrap();
        assert_eq!(restored.root_key, root_before_cancel);
        assert_eq!(restored.messages_since_ratchet, 17);
        assert_eq!(restored.prev_chain_length, None);
    }

    #[test]
    fn peer_supports_invite_redemption_defaults_false() {
        let mut store = SessionStore::new();
        let local = NodeId::from_bytes([83; 32]);
        let peer = NodeId::from_bytes([84; 32]);
        store.insert_with_chains(peer, [85; 32], &local, 5).unwrap();

        assert!(!store.peer_supports_invite_redemption(&peer));
        store
            .set_peer_supports_invite_redemption(&peer, Some(true))
            .unwrap();
        assert!(store.peer_supports_invite_redemption(&peer));
        store
            .set_peer_supports_invite_redemption(&peer, None)
            .unwrap();
        assert!(!store.peer_supports_invite_redemption(&peer));
    }

    #[test]
    fn initiate_commits_root_and_switches_sending_chain_immediately() {
        let (mut session, _) = two_dh_sessions();
        let root_before = session.root_key;
        let send_before = session.sending_chain.serialize();
        let receive_before = session.receiving_chain.serialize();

        let new_pub = session.dh_ratchet_initiate().unwrap();

        assert_ne!(session.root_key, root_before);
        assert_ne!(session.sending_chain.serialize(), send_before);
        assert_eq!(session.receiving_chain.serialize(), receive_before);
        assert_eq!(session.dh_our_pubkey, new_pub);
        assert_eq!(session.pending_dh_advertisement(), Some((new_pub, 0)));
        assert_eq!(session.chain_epoch, 0);
        assert_eq!(session.messages_since_ratchet, 0);
    }

    #[test]
    fn initiate_freezes_previous_chain_length_for_advertisement() {
        let (mut session, _) = two_dh_sessions();
        session.messages_since_ratchet = 37;

        let new_pub = session.dh_ratchet_initiate().unwrap();

        assert_eq!(session.pending_dh_advertisement(), Some((new_pub, 37)));
        assert_eq!(session.messages_since_ratchet, 0);
    }

    #[test]
    fn initiate_returns_public_key_matching_pending_state() {
        let (mut session, _) = two_dh_sessions();

        let new_pub = session.dh_ratchet_initiate().unwrap();

        let pending = session.pending_dh_ratchet.as_ref().unwrap();
        assert_eq!(new_pub, pending.new_pub);
        assert_eq!(session.dh_our_pubkey, pending.new_pub);
        assert_eq!(session.root_key, pending.rk_new);
    }

    #[test]
    fn collision_abort_is_cancel_then_responder_step() {
        let (mut initiator, mut aborting_peer) = two_dh_sessions();
        let old_epoch = aborting_peer.chain_epoch;
        let peer_new_pub = initiator.dh_ratchet_initiate().unwrap();
        aborting_peer.dh_ratchet_initiate().unwrap();

        aborting_peer
            .dh_ratchet_collision_abort(peer_new_pub)
            .unwrap();

        assert!(aborting_peer.pending_dh_ratchet.is_none());
        assert_eq!(aborting_peer.chain_epoch, old_epoch + 1);
        assert_eq!(aborting_peer.dh_peer_pubkey, Some(peer_new_pub));
        assert_ne!(
            aborting_peer.sending_chain.serialize().0,
            aborting_peer.receiving_chain.serialize().0
        );
    }

    #[test]
    fn collision_abort_root_matches_retained_initiator() {
        let (mut smaller, mut larger) = two_dh_sessions();
        let smaller_pub = smaller.dh_ratchet_initiate().unwrap();
        let larger_pub = larger.dh_ratchet_initiate().unwrap();

        if smaller_pub < larger_pub {
            larger.dh_ratchet_collision_abort(smaller_pub).unwrap();
            let response_pub = larger.dh_our_pubkey;
            smaller.dh_ratchet_complete(response_pub).unwrap();
        } else {
            smaller.dh_ratchet_collision_abort(larger_pub).unwrap();
            let response_pub = smaller.dh_our_pubkey;
            larger.dh_ratchet_complete(response_pub).unwrap();
        }

        assert_eq!(smaller.root_key, larger.root_key);
        assert_eq!(smaller.chain_epoch, larger.chain_epoch);
        assert_eq!(
            smaller.sending_chain.serialize().0,
            larger.receiving_chain.serialize().0
        );
        assert_eq!(
            smaller.receiving_chain.serialize().0,
            larger.sending_chain.serialize().0
        );
    }

    #[test]
    fn collision_case1_peer_sent_we_did_not() {
        let (mut receiver, mut peer) = two_dh_sessions();
        let peer_new_pub = peer.dh_ratchet_initiate().unwrap();
        receiver.dh_ratchet_initiate().unwrap();
        assert!(receiver.prev_chain_length.is_some());
        let (_, action) = receiver.v4_receive_key(1, 0, Some(peer_new_pub)).unwrap();
        assert!(matches!(action, V4RatchetAction::CollisionCase1(_)));
        receiver.dh_ratchet_collision_abort(peer_new_pub).unwrap();
        assert!(!receiver.has_pending_dh_ratchet());
        assert_eq!(receiver.dh_peer_pubkey, Some(peer_new_pub));
    }

    #[test]
    fn collision_case3_larger_aborts() {
        let (mut a, mut b) = two_dh_sessions();
        let a_pub = a.dh_ratchet_initiate().unwrap();
        let b_pub = b.dh_ratchet_initiate().unwrap();
        let (larger, smaller_pub) = if a_pub > b_pub {
            (&mut a, b_pub)
        } else {
            (&mut b, a_pub)
        };
        larger.prev_chain_length = None;
        let (_, action) = larger.v4_receive_key(1, 0, Some(smaller_pub)).unwrap();
        assert!(matches!(action, V4RatchetAction::CollisionCase3Larger(_)));
        larger.dh_ratchet_collision_abort(smaller_pub).unwrap();
        assert!(!larger.has_pending_dh_ratchet());
        assert_eq!(larger.dh_peer_pubkey, Some(smaller_pub));
    }

    #[test]
    fn collision_case3_smaller_retained() {
        let (mut a, mut b) = two_dh_sessions();
        let a_pub = a.dh_ratchet_initiate().unwrap();
        let b_pub = b.dh_ratchet_initiate().unwrap();
        let (smaller, larger_pub) = if a_pub < b_pub {
            (&mut a, b_pub)
        } else {
            (&mut b, a_pub)
        };
        smaller.prev_chain_length = None;
        let (_, action) = smaller.v4_receive_key(1, 0, Some(larger_pub)).unwrap();
        assert!(matches!(action, V4RatchetAction::CollisionCase3Smaller(_)));
        smaller.dh_ratchet_complete(larger_pub).unwrap();
        assert!(!smaller.has_pending_dh_ratchet());
        assert_eq!(smaller.dh_peer_pubkey, Some(larger_pub));
    }

    #[test]
    fn collision_both_converge_to_same_root_after_tiebreak() {
        let (mut a, mut b) = two_dh_sessions();
        let a_pub = a.dh_ratchet_initiate().unwrap();
        let b_pub = b.dh_ratchet_initiate().unwrap();
        if a_pub < b_pub {
            b.dh_ratchet_collision_abort(a_pub).unwrap();
            let response_pub = b.dh_our_pubkey;
            a.dh_ratchet_complete(response_pub).unwrap();
        } else {
            a.dh_ratchet_collision_abort(b_pub).unwrap();
            let response_pub = a.dh_our_pubkey;
            b.dh_ratchet_complete(response_pub).unwrap();
        }
        assert_eq!(a.root_key, b.root_key);
        assert_eq!(a.chain_epoch, b.chain_epoch);
        assert_eq!(
            a.sending_chain.serialize().0,
            b.receiving_chain.serialize().0
        );
        assert_eq!(
            a.receiving_chain.serialize().0,
            b.sending_chain.serialize().0
        );
    }

    #[test]
    fn v4_response_completes_pending() {
        let (mut initiator, mut responder) = two_dh_sessions();
        let initiator_pub = initiator.dh_ratchet_initiate().unwrap();
        responder.dh_ratchet_step(initiator_pub).unwrap();
        let responder_pub = responder.dh_our_pubkey;
        initiator.dh_ratchet_complete(responder_pub).unwrap();
        assert!(!initiator.has_pending_dh_ratchet());
        assert_eq!(initiator.chain_epoch, responder.chain_epoch);
        assert_eq!(initiator.root_key, responder.root_key);
    }

    #[test]
    fn save_during_pending_persists_committed_initiate_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.sqlite3");
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[0x42u8; 32]).unwrap(),
        ));
        let local = NodeId::from_bytes([101; 32]);
        let peer = NodeId::from_bytes([102; 32]);
        let root_after_initiate;
        let sending_before;
        let receiving_before;
        let sending_after_initiate;
        {
            let mut store = SessionStore::with_storage(Arc::clone(&storage), None);
            store
                .insert_with_chains(peer, [103; 32], &local, 5)
                .unwrap();
            let session = store.sessions.get_mut(&peer).unwrap();
            session.dh_peer_pubkey = Some(peer_dh_public());
            let root_before = session.root_key;
            sending_before = session.sending_chain.serialize();
            receiving_before = session.receiving_chain.serialize();
            session.dh_ratchet_initiate().unwrap();
            root_after_initiate = session.root_key;
            sending_after_initiate = session.sending_chain.serialize();
            assert_ne!(root_after_initiate, root_before);
            assert_ne!(sending_after_initiate, sending_before);
            persist_test_session(&store, &peer);
        }

        let mut reopened = SessionStore::with_storage(storage, None);
        reopened.get_or_load(&peer).unwrap();
        let loaded = reopened.sessions.get(&peer).unwrap();
        assert_eq!(loaded.root_key, root_after_initiate);
        assert_eq!(loaded.sending_chain.serialize(), sending_after_initiate);
        assert_eq!(loaded.receiving_chain.serialize(), receiving_before);
        assert!(loaded.pending_dh_ratchet.is_some());
        assert_eq!(loaded.prev_chain_length, Some(0));
        assert_eq!(
            loaded.pending_dh_public_key().unwrap(),
            loaded.dh_our_pubkey
        );
        let session = reopened.sessions.get_mut(&peer).unwrap();
        session.dh_ratchet_cancel().unwrap();
        assert!(session.pending_dh_ratchet.is_none());
        let (message_key, counter) = reopened.advance_sending(&peer, 6).unwrap();
        assert_eq!(counter, sending_after_initiate.1);
        assert_eq!(message_key.index, counter);
    }

    #[test]
    fn complete_after_restart_fails_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.sqlite3");
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[0x42u8; 32]).unwrap(),
        ));
        let local = NodeId::from_bytes([111; 32]);
        let peer = NodeId::from_bytes([112; 32]);
        let pending_pub;
        {
            let mut store = SessionStore::with_storage(Arc::clone(&storage), None);
            store
                .insert_with_chains(peer, [113; 32], &local, 5)
                .unwrap();
            let session = store.sessions.get_mut(&peer).unwrap();
            session.dh_peer_pubkey = Some(peer_dh_public());
            pending_pub = session.dh_ratchet_initiate().unwrap();
            persist_test_session(&store, &peer);
        }

        let mut reopened = SessionStore::with_storage(storage, None);
        let loaded = reopened.sessions.get_mut(&peer);
        assert!(loaded.is_none());
        reopened.get_or_load(&peer).unwrap();
        let session = reopened.sessions.get_mut(&peer).unwrap();
        assert_eq!(session.pending_dh_public_key(), Some(pending_pub));
        assert!(session.pending_dh_ratchet.is_some());
        assert!(matches!(
            session.dh_ratchet_complete(peer_dh_public()),
            Ok(()) | Err(SessionError::InvalidDhRatchetPublicKey)
        ));
    }

    #[test]
    fn restart_persists_skipped_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.sqlite3");
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[0x42u8; 32]).unwrap(),
        ));
        let local = NodeId::from_bytes([10; 32]);
        let peer = NodeId::from_bytes([11; 32]);

        {
            let mut store = SessionStore::with_storage(Arc::clone(&storage), None);
            store.insert_with_chains(peer, [77; 32], &local, 5).unwrap();
            let (_, generation) = store.receive_lock(&peer).unwrap();
            let preview = store
                .prepare_receive_with_skipped_at(&peer, 2, generation, 10)
                .unwrap();
            store.commit_receive_preview(&peer, preview, 10).unwrap();
            persist_test_session(&store, &peer);
        }

        let mut reopened = SessionStore::with_storage(storage, None);
        let loaded = reopened.get_or_load(&peer).unwrap().unwrap();
        assert!(loaded.skipped_keys.contains_key(&(0, 0)));
        assert!(loaded.skipped_keys.contains_key(&(0, 1)));
        assert_eq!(loaded.skipped_keys.len(), 2);
    }

    #[test]
    fn get_or_load_miss_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.sqlite3");
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[0x42u8; 32]).unwrap(),
        ));
        let mut store = SessionStore::with_storage(storage, None);
        let peer = NodeId::from_bytes([12; 32]);
        assert!(store.get_or_load(&peer).unwrap().is_none());
    }

    #[test]
    fn get_or_load_hit_returns_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.sqlite3");
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[0x42u8; 32]).unwrap(),
        ));
        let local = NodeId::from_bytes([13; 32]);
        let peer = NodeId::from_bytes([14; 32]);

        {
            let mut store = SessionStore::with_storage(Arc::clone(&storage), None);
            store.insert_with_chains(peer, [88; 32], &local, 6).unwrap();
            persist_test_session(&store, &peer);
        }

        let mut reopened = SessionStore::with_storage(storage, None);
        let loaded = reopened.get_or_load(&peer).unwrap().unwrap();
        assert_eq!(loaded.peer_identity, peer);
        assert_eq!(loaded.root_key, [88; 32]);
    }

    #[test]
    fn save_session_with_skipped_roundtrip_keeps_pair_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.sqlite3");
        let storage = Arc::new(StdMutex::new(
            ClientStorage::open(&path, &[0x42u8; 32]).unwrap(),
        ));
        let local = NodeId::from_bytes([15; 32]);
        let peer = NodeId::from_bytes([16; 32]);

        let row = {
            let mut store = SessionStore::with_storage(Arc::clone(&storage), None);
            store.insert_with_chains(peer, [91; 32], &local, 7).unwrap();
            let session = store.sessions.get(&peer).unwrap();
            SessionStore::session_to_row(session).unwrap()
        };

        let skipped = vec![SkippedKeyRow {
            peer_identity_hex: SessionStore::peer_key(&peer),
            chain_epoch: 0,
            counter: 42,
            message_key: [0x33; 32],
            received_at: 99,
        }];

        {
            let mut storage_handle = storage.lock().unwrap();
            storage_handle
                .save_session_with_skipped(&row, &skipped)
                .unwrap();
        }

        let storage_handle = storage.lock().unwrap();
        let loaded = storage_handle
            .load_session(&SessionStore::peer_key(&peer))
            .unwrap()
            .unwrap();
        assert_eq!(loaded.peer_identity_hex, SessionStore::peer_key(&peer));
        assert_eq!(
            storage_handle
                .load_skipped_keys(&SessionStore::peer_key(&peer))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn load_session_wrong_id_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.sqlite3");
        let storage = ClientStorage::open(&path, &[0x42u8; 32]).unwrap();
        assert!(storage.load_session("missing-peer").unwrap().is_none());
    }

    #[test]
    fn list_session_ids_reflects_saves() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.sqlite3");
        let storage = ClientStorage::open(&path, &[0x42u8; 32]).unwrap();
        let row_a = SessionRow {
            peer_identity_hex: "peer-a".to_string(),
            generation: 1,
            direction: 0,
            root_key: [1u8; 32],
            sending_chain_key: [2u8; 32],
            sending_index: 0,
            receiving_chain_key: [3u8; 32],
            receiving_index: 0,
            established_at: 1,
            last_used_at: 2,
            responded: true,
            needs_resync: false,
            dh_our_privkey: None,
            dh_our_pubkey: None,
            dh_peer_pubkey: None,
            chain_epoch: 0,
            messages_since_ratchet: 0,
            ..Default::default()
        };
        let row_b = SessionRow {
            peer_identity_hex: "peer-b".to_string(),
            generation: 2,
            direction: 1,
            root_key: [4u8; 32],
            sending_chain_key: [5u8; 32],
            sending_index: 1,
            receiving_chain_key: [6u8; 32],
            receiving_index: 1,
            established_at: 3,
            last_used_at: 4,
            responded: false,
            needs_resync: true,
            dh_our_privkey: None,
            dh_our_pubkey: None,
            dh_peer_pubkey: None,
            chain_epoch: 0,
            messages_since_ratchet: 0,
            ..Default::default()
        };

        storage.save_session(&row_a).unwrap();
        storage.save_session(&row_b).unwrap();
        let ids = storage.list_session_ids().unwrap();
        assert_eq!(ids, vec!["peer-a".to_string(), "peer-b".to_string()]);
    }

    #[test]
    fn delete_session_removes_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.sqlite3");
        let mut storage = ClientStorage::open(&path, &[0x42u8; 32]).unwrap();
        let row = SessionRow {
            peer_identity_hex: "peer-delete".to_string(),
            generation: 3,
            direction: 0,
            root_key: [7u8; 32],
            sending_chain_key: [8u8; 32],
            sending_index: 0,
            receiving_chain_key: [9u8; 32],
            receiving_index: 0,
            established_at: 1,
            last_used_at: 2,
            responded: true,
            needs_resync: false,
            dh_our_privkey: None,
            dh_our_pubkey: None,
            dh_peer_pubkey: None,
            chain_epoch: 0,
            messages_since_ratchet: 0,
            ..Default::default()
        };
        let skipped = vec![SkippedKeyRow {
            peer_identity_hex: "peer-delete".to_string(),
            chain_epoch: 0,
            counter: 5,
            message_key: [0x11; 32],
            received_at: 20,
        }];

        storage.save_session_with_skipped(&row, &skipped).unwrap();
        storage.delete_session("peer-delete").unwrap();
        assert!(storage.load_session("peer-delete").unwrap().is_none());
        assert!(storage.load_skipped_keys("peer-delete").unwrap().is_empty());
    }

    #[test]
    fn prune_expired_skipped_keys_integration() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.sqlite3");
        let mut storage = ClientStorage::open(&path, &[0x42u8; 32]).unwrap();
        let row = SessionRow {
            peer_identity_hex: "peer-prune".to_string(),
            generation: 1,
            direction: 0,
            root_key: [10u8; 32],
            sending_chain_key: [11u8; 32],
            sending_index: 0,
            receiving_chain_key: [12u8; 32],
            receiving_index: 0,
            established_at: 1,
            last_used_at: 2,
            responded: true,
            needs_resync: false,
            dh_our_privkey: None,
            dh_our_pubkey: None,
            dh_peer_pubkey: None,
            chain_epoch: 0,
            messages_since_ratchet: 0,
            ..Default::default()
        };
        let skipped = vec![
            SkippedKeyRow {
                peer_identity_hex: "peer-prune".to_string(),
                chain_epoch: 0,
                counter: 1,
                message_key: [0x21; 32],
                received_at: 10,
            },
            SkippedKeyRow {
                peer_identity_hex: "peer-prune".to_string(),
                chain_epoch: 0,
                counter: 2,
                message_key: [0x22; 32],
                received_at: 200,
            },
        ];

        storage.save_session_with_skipped(&row, &skipped).unwrap();
        let removed = storage.prune_expired_skipped_keys(50).unwrap();
        assert_eq!(removed, 1);
        let remaining = storage.load_skipped_keys("peer-prune").unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].counter, 2);
    }

    #[test]
    fn storage_error_propagates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.sqlite3");
        let storage = ClientStorage::open(&path, &[0x42u8; 32]).unwrap();
        let invalid = SessionRow {
            peer_identity_hex: "peer-invalid".to_string(),
            generation: u64::MAX,
            direction: 0,
            root_key: [1u8; 32],
            sending_chain_key: [2u8; 32],
            sending_index: 0,
            receiving_chain_key: [3u8; 32],
            receiving_index: 0,
            established_at: 1,
            last_used_at: 2,
            responded: true,
            needs_resync: false,
            dh_our_privkey: None,
            dh_our_pubkey: None,
            dh_peer_pubkey: None,
            chain_epoch: 0,
            messages_since_ratchet: 0,
            ..Default::default()
        };

        let err = storage.save_session(&invalid).unwrap_err();
        assert!(
            matches!(err, hal_storage::SessionPersistenceError::Malformed(_))
                || matches!(err, hal_storage::SessionPersistenceError::Storage(_))
        );
    }

    #[test]
    fn session_zeroize_secrets_clears_key_material() {
        let mut store = SessionStore::new();
        let local = NodeId::from_bytes([1; 32]);
        let peer = NodeId::from_bytes([2; 32]);
        store.insert_with_chains(peer, [9; 32], &local, 5).unwrap();
        let mut session = store.remove(&peer).unwrap();
        session.dh_our_privkey = [10; 32];
        session.zeroize_secrets();
        assert_eq!(session.root_key, [0; 32]);
        assert_eq!(session.dh_our_privkey, [0; 32]);
    }

    #[test]
    fn session_debug_redacts_secrets() {
        let mut store = SessionStore::new();
        let local = NodeId::from_bytes([1; 32]);
        let peer = NodeId::from_bytes([2; 32]);
        store.insert_with_chains(peer, [9; 32], &local, 5).unwrap();
        let session = store.remove(&peer).unwrap();
        let debug = format!("{session:?}");
        assert!(debug.contains("root_key: \"[REDACTED]\""));
        assert!(debug.contains("dh_our_privkey: \"[REDACTED]\""));
        assert!(!debug.contains("chain_key"));
    }

    #[test]
    fn session_view_debug_no_secrets() {
        let mut store = SessionStore::new();
        let local = NodeId::from_bytes([1; 32]);
        let peer = NodeId::from_bytes([2; 32]);
        store.insert_with_chains(peer, [9; 32], &local, 5).unwrap();
        let view = store.get_view(&peer).unwrap();
        let debug = format!("{view:?}");
        assert!(!debug.contains("9, 9"));
        assert!(!debug.contains("chain_key"));
    }
}
