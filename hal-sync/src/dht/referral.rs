use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::dht::group::{GroupId, GroupRegistry};
use crate::dht::NodeId;
use crate::pinning::KnownHosts;

pub const REFERRAL_DEFAULT_TTL_SECS: u64 = 30 * 24 * 3600;
pub const REFERRAL_DEFAULT_THRESHOLD: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Referral {
    pub referrer_id: NodeId,
    pub subject_id: NodeId,
    pub inviter_id: NodeId,
    pub group_id: Option<GroupId>,
    pub confirmed_at: u64,
    pub nonce: [u8; 16],
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

#[derive(Debug, Serialize)]
struct ReferralPayload<'a> {
    referrer_id: &'a NodeId,
    subject_id: &'a NodeId,
    inviter_id: &'a NodeId,
    group_id: &'a Option<GroupId>,
    confirmed_at: u64,
    nonce: &'a [u8; 16],
}

impl Referral {
    pub fn create(
        referrer_id: NodeId,
        subject_id: NodeId,
        inviter_id: NodeId,
        group_id: Option<GroupId>,
        now: u64,
        signing_key: &SigningKey,
        nonce: [u8; 16],
    ) -> Self {
        let payload = ReferralPayload {
            referrer_id: &referrer_id,
            subject_id: &subject_id,
            inviter_id: &inviter_id,
            group_id: &group_id,
            confirmed_at: now,
            nonce: &nonce,
        };
        let bytes = serde_json::to_vec(&payload).unwrap_or_default();
        let signature = signing_key.sign(&bytes).to_bytes();

        Self {
            referrer_id,
            subject_id,
            inviter_id,
            group_id,
            confirmed_at: now,
            nonce,
            signature,
        }
    }

    pub fn verify(
        &self,
        referrer_pubkey: &VerifyingKey,
        now: u64,
        max_age_secs: u64,
    ) -> Result<(), ReferralError> {
        if now < self.confirmed_at {
            return Err(ReferralError::FromFuture);
        }

        if now > self.confirmed_at.saturating_add(max_age_secs) {
            return Err(ReferralError::Expired);
        }

        let payload = ReferralPayload {
            referrer_id: &self.referrer_id,
            subject_id: &self.subject_id,
            inviter_id: &self.inviter_id,
            group_id: &self.group_id,
            confirmed_at: self.confirmed_at,
            nonce: &self.nonce,
        };
        let bytes = serde_json::to_vec(&payload).map_err(|_| ReferralError::Malformed)?;
        let signature = Signature::from_bytes(&self.signature);
        referrer_pubkey
            .verify(&bytes, &signature)
            .map_err(|_| ReferralError::InvalidSignature)
    }

    pub fn to_base64(&self) -> Result<String, ReferralError> {
        let bytes = serde_json::to_vec(self).map_err(|_| ReferralError::Malformed)?;
        Ok(base64_encode(&bytes))
    }

    pub fn from_base64(s: &str) -> Result<Self, ReferralError> {
        let bytes = base64_decode(s)?;
        serde_json::from_slice(&bytes).map_err(|_| ReferralError::Malformed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferralError {
    InvalidSignature,
    Expired,
    FromFuture,
    Malformed,
    ReferrerNotKnown,
    ReferrerNotCommon,
    ThresholdNotMet { have: u32, need: u32 },
}

impl std::fmt::Display for ReferralError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "invalid referral signature"),
            Self::Expired => write!(f, "referral expired"),
            Self::FromFuture => write!(f, "referral from future"),
            Self::Malformed => write!(f, "malformed referral"),
            Self::ReferrerNotKnown => write!(f, "referrer is not known"),
            Self::ReferrerNotCommon => write!(f, "referrer is not common"),
            Self::ThresholdNotMet { have, need } => {
                write!(f, "threshold not met: have {have}, need {need}")
            }
        }
    }
}

impl std::error::Error for ReferralError {}

pub fn accept_referral(
    referral: &Referral,
    referrer_pubkey: &VerifyingKey,
    inviter_id: NodeId,
    groups: &mut GroupRegistry,
    hosts: &mut KnownHosts,
    now: u64,
) -> Result<(), ReferralError> {
    referral.verify(referrer_pubkey, now, REFERRAL_DEFAULT_TTL_SECS)?;

    if referral.inviter_id != inviter_id {
        return Err(ReferralError::Malformed);
    }

    if hosts.record_of(&referral.referrer_id.to_hex()).is_none() {
        return Err(ReferralError::ReferrerNotKnown);
    }

    if let Some(group_id) = referral.group_id {
        groups.add_member(group_id, referral.subject_id);
    }

    hosts.learn_first_contact(
        &referral.subject_id.to_hex(),
        &referral.subject_id.to_hex(),
        now,
    );

    Ok(())
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(bytes)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, ReferralError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| ReferralError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn nonce(seed: u8) -> [u8; 16] {
        [seed; 16]
    }

    #[test]
    fn create_and_verify_roundtrip() {
        let referrer_key = key(1);
        let referrer_pubkey = referrer_key.verifying_key();
        let referrer_id = NodeId::from_public_key(&referrer_pubkey);
        let subject_id = NodeId::from_bytes([0x11; 32]);
        let inviter_id = NodeId::from_bytes([0x22; 32]);

        let referral = Referral::create(
            referrer_id,
            subject_id,
            inviter_id,
            None,
            1_000,
            &referrer_key,
            nonce(1),
        );
        assert!(referral
            .verify(&referrer_pubkey, 1_500, 30 * 24 * 3600)
            .is_ok());
    }

    #[test]
    fn expired_referral_rejected() {
        let referrer_key = key(2);
        let referrer_pubkey = referrer_key.verifying_key();
        let referrer_id = NodeId::from_public_key(&referrer_pubkey);
        let subject_id = NodeId::from_bytes([0x33; 32]);
        let inviter_id = NodeId::from_bytes([0x44; 32]);

        let referral = Referral::create(
            referrer_id,
            subject_id,
            inviter_id,
            Some(42),
            100,
            &referrer_key,
            nonce(2),
        );
        assert_eq!(
            referral.verify(
                &referrer_pubkey,
                100 + REFERRAL_DEFAULT_TTL_SECS + 1,
                REFERRAL_DEFAULT_TTL_SECS
            ),
            Err(ReferralError::Expired)
        );
    }

    #[test]
    fn from_future_rejected() {
        let referrer_key = key(3);
        let referrer_pubkey = referrer_key.verifying_key();
        let referrer_id = NodeId::from_public_key(&referrer_pubkey);
        let subject_id = NodeId::from_bytes([0x55; 32]);
        let inviter_id = NodeId::from_bytes([0x66; 32]);

        let referral = Referral::create(
            referrer_id,
            subject_id,
            inviter_id,
            None,
            1_000,
            &referrer_key,
            nonce(3),
        );
        assert_eq!(
            referral.verify(&referrer_pubkey, 999, REFERRAL_DEFAULT_TTL_SECS),
            Err(ReferralError::FromFuture)
        );
    }

    #[test]
    fn invalid_signature_rejected() {
        let referrer_key = key(4);
        let wrong_key = key(5);
        let referrer_id = NodeId::from_public_key(&referrer_key.verifying_key());
        let subject_id = NodeId::from_bytes([0x77; 32]);
        let inviter_id = NodeId::from_bytes([0x88; 32]);

        let referral = Referral::create(
            referrer_id,
            subject_id,
            inviter_id,
            None,
            1_000,
            &referrer_key,
            nonce(4),
        );
        assert_eq!(
            referral.verify(&wrong_key.verifying_key(), 1_500, REFERRAL_DEFAULT_TTL_SECS),
            Err(ReferralError::InvalidSignature)
        );
    }

    #[test]
    fn accept_referral_with_unknown_referrer_rejected() {
        let referrer_key = key(6);
        let referrer_pubkey = referrer_key.verifying_key();
        let referrer_id = NodeId::from_public_key(&referrer_pubkey);
        let subject_id = NodeId::from_bytes([0x99; 32]);
        let inviter_id = NodeId::from_bytes([0xaa; 32]);
        let referral = Referral::create(
            referrer_id,
            subject_id,
            inviter_id,
            None,
            1_000,
            &referrer_key,
            nonce(5),
        );

        let mut groups = GroupRegistry::new();
        let mut hosts = KnownHosts::new();

        assert_eq!(
            accept_referral(
                &referral,
                &referrer_pubkey,
                inviter_id,
                &mut groups,
                &mut hosts,
                1_500
            ),
            Err(ReferralError::ReferrerNotKnown)
        );
    }

    #[test]
    fn accept_referral_wrong_inviter_rejected() {
        let referrer_key = key(7);
        let referrer_pubkey = referrer_key.verifying_key();
        let referrer_id = NodeId::from_public_key(&referrer_pubkey);
        let subject_id = NodeId::from_bytes([0xbb; 32]);
        let inviter_id = NodeId::from_bytes([0xcc; 32]);
        let wrong_inviter = NodeId::from_bytes([0xdd; 32]);
        let referral = Referral::create(
            referrer_id,
            subject_id,
            inviter_id,
            Some(99),
            1_000,
            &referrer_key,
            nonce(6),
        );

        let mut groups = GroupRegistry::new();
        let mut hosts = KnownHosts::new();
        hosts
            .pin_manual(
                &referrer_id.to_hex(),
                &hex::encode(referrer_pubkey.to_bytes()),
                500,
            )
            .unwrap();

        assert_eq!(
            accept_referral(
                &referral,
                &referrer_pubkey,
                wrong_inviter,
                &mut groups,
                &mut hosts,
                1_500
            ),
            Err(ReferralError::Malformed)
        );
    }
}
