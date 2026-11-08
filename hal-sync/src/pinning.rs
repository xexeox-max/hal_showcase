//! Key pinning: the identity_id <-> long-term key binding table.
//!
//! Closes review finding #3: a signed envelope proves the sender controls
//! SOME key, but nothing bound that key to the claimed identity. Pinning
//! keeps the authoritative mapping; conflicts fail closed.

use anyhow::{anyhow, Result};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustSource {
    /// Operator explicitly trusted this pair.
    Manual,
    /// Learned from a signed referral chain (see hal-protocol referral).
    Referral,
    /// First-contact learning when the operator enabled it.
    FirstContact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRecord {
    pub identity_id: String,
    pub public_key_hex: String,
    pub since_epoch: u64,
    pub source: TrustSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingCheck {
    /// Pair matches the pinned record.
    Trusted,
    /// Identity never seen - caller decides whether first contact applies.
    Unknown,
    /// CONFLICT: identity is pinned to a DIFFERENT key (or vice versa).
    Conflicted { pinned_key_hex: String },
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct KnownHosts {
    hosts: HashMap<String, HostRecord>,
}

impl KnownHosts {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pin_manual(&mut self, identity_id: &str, public_key_hex: &str, now: u64) -> Result<()> {
        let public_key_bytes: [u8; 32] = hex::decode(public_key_hex)
            .map_err(|error| anyhow!("invalid public key hex: {error}"))?
            .try_into()
            .map_err(|_| anyhow!("public key must contain exactly 32 bytes"))?;
        VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|error| anyhow!("invalid Ed25519 public key: {error}"))?;
        if let BindingCheck::Conflicted { .. } = self.check(identity_id, public_key_hex) {
            return Err(anyhow!(
                "identity {identity_id} is already pinned to a different public key"
            ));
        }
        if matches!(
            self.check(identity_id, public_key_hex),
            BindingCheck::Trusted
        ) {
            return Ok(());
        }
        self.hosts.insert(
            identity_id.to_string(),
            HostRecord {
                identity_id: identity_id.to_string(),
                public_key_hex: public_key_hex.to_string(),
                since_epoch: now,
                source: TrustSource::Manual,
            },
        );
        Ok(())
    }

    /// Learn on first contact. Returns false (and records nothing) when a
    /// conflicting key for this identity already exists.
    pub fn learn_first_contact(
        &mut self,
        identity_id: &str,
        public_key_hex: &str,
        now: u64,
    ) -> bool {
        match self.check(identity_id, public_key_hex) {
            BindingCheck::Trusted => true,
            BindingCheck::Conflicted { .. } => false,
            BindingCheck::Unknown => {
                self.hosts.insert(
                    identity_id.to_string(),
                    HostRecord {
                        identity_id: identity_id.to_string(),
                        public_key_hex: public_key_hex.to_string(),
                        since_epoch: now,
                        source: TrustSource::FirstContact,
                    },
                );
                true
            }
        }
    }

    pub fn check(&self, identity_id: &str, public_key_hex: &str) -> BindingCheck {
        match self.hosts.get(identity_id) {
            None => BindingCheck::Unknown,
            Some(record) => {
                if record.public_key_hex == public_key_hex {
                    BindingCheck::Trusted
                } else {
                    BindingCheck::Conflicted {
                        pinned_key_hex: record.public_key_hex.clone(),
                    }
                }
            }
        }
    }

    pub fn record_of(&self, identity_id: &str) -> Option<&HostRecord> {
        self.hosts.get(identity_id)
    }

    pub fn remove_if_matches(&mut self, identity_id: &str, public_key_hex: &str) -> bool {
        if matches!(
            self.check(identity_id, public_key_hex),
            BindingCheck::Trusted
        ) {
            self.hosts.remove(identity_id);
            true
        } else {
            false
        }
    }

    /// Return each identity and its pinned public key. Ordering is unspecified.
    pub fn identities(&self) -> Vec<(String, String)> {
        self.hosts
            .iter()
            .map(|(identity_id, record)| (identity_id.clone(), record.public_key_hex.clone()))
            .collect()
    }

    pub fn all_identity_ids(&self) -> Vec<String> {
        self.hosts.keys().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }
}
