use anyhow::{anyhow, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const INTEGRITY_GRACE_SECONDS: u64 = 3 * 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityWave {
    pub wave_id: String,
    pub network_epoch: u64,
    pub issued_at: u64,
    pub response_deadline: u64,
    pub required_measurement: String,
    pub authority_public_key: String,
    pub signature: String,
}

impl IntegrityWave {
    pub fn new(
        wave_id: String,
        network_epoch: u64,
        issued_at: u64,
        response_deadline: u64,
        required_measurement: String,
        authority_public_key: String,
    ) -> Self {
        Self {
            wave_id,
            network_epoch,
            issued_at,
            response_deadline,
            required_measurement,
            authority_public_key,
            signature: String::new(),
        }
    }

    pub fn signing_payload(&self) -> Vec<u8> {
        format!(
            "integrity-wave:v1:{}:{}:{}:{}:{}:{}",
            self.wave_id,
            self.network_epoch,
            self.issued_at,
            self.response_deadline,
            self.required_measurement,
            self.authority_public_key,
        )
        .into_bytes()
    }

    pub fn sign(&mut self, private_key: &[u8; 32]) {
        self.signature = hex::encode(
            SigningKey::from_bytes(private_key)
                .sign(&self.signing_payload())
                .to_bytes(),
        );
    }

    pub fn verify(&self, now: u64) -> Result<()> {
        if self.wave_id.trim().is_empty() || self.required_measurement.trim().is_empty() {
            return Err(anyhow!("integrity wave contains empty required fields"));
        }
        if self.response_deadline < self.issued_at {
            return Err(anyhow!("integrity wave deadline precedes issue time"));
        }
        if now < self.issued_at {
            return Err(anyhow!("integrity wave is not active yet"));
        }
        let public_key: [u8; 32] = hex::decode(&self.authority_public_key)
            .map_err(|_| anyhow!("invalid authority public key"))?
            .try_into()
            .map_err(|_| anyhow!("authority public key must be 32 bytes"))?;
        let signature: [u8; 64] = hex::decode(&self.signature)
            .map_err(|_| anyhow!("invalid integrity wave signature"))?
            .try_into()
            .map_err(|_| anyhow!("integrity wave signature must be 64 bytes"))?;
        VerifyingKey::from_bytes(&public_key)?
            .verify(&self.signing_payload(), &Signature::from_bytes(&signature))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityResponse {
    pub wave_id: String,
    pub network_epoch: u64,
    pub node_id: String,
    pub node_public_key: String,
    pub software_measurement: String,
    pub observed_at: u64,
    pub signature: String,
}

impl IntegrityResponse {
    pub fn new(
        wave: &IntegrityWave,
        node_public_key: String,
        software_measurement: String,
        observed_at: u64,
    ) -> Result<Self> {
        let node_id = identity_for_public_key(&node_public_key)?;
        Ok(Self {
            wave_id: wave.wave_id.clone(),
            network_epoch: wave.network_epoch,
            node_id,
            node_public_key,
            software_measurement,
            observed_at,
            signature: String::new(),
        })
    }

    pub fn signing_payload(&self) -> Vec<u8> {
        format!(
            "integrity-response:v1:{}:{}:{}:{}:{}:{}",
            self.wave_id,
            self.network_epoch,
            self.node_id,
            self.node_public_key,
            self.software_measurement,
            self.observed_at,
        )
        .into_bytes()
    }

    pub fn sign(&mut self, private_key: &[u8; 32]) {
        self.signature = hex::encode(
            SigningKey::from_bytes(private_key)
                .sign(&self.signing_payload())
                .to_bytes(),
        );
    }

    pub fn verify(&self, wave: &IntegrityWave, now: u64) -> Result<()> {
        wave.verify(now)?;
        if self.wave_id != wave.wave_id || self.network_epoch != wave.network_epoch {
            return Err(anyhow!("integrity response targets another wave"));
        }
        if self.observed_at < wave.issued_at || self.observed_at > now {
            return Err(anyhow!("integrity response timestamp is outside its wave"));
        }
        let public_key: [u8; 32] = hex::decode(&self.node_public_key)
            .map_err(|_| anyhow!("invalid node public key"))?
            .try_into()
            .map_err(|_| anyhow!("node public key must be 32 bytes"))?;
        if identity_for_public_key(&self.node_public_key)? != self.node_id {
            return Err(anyhow!(
                "integrity response identity does not match public key"
            ));
        }
        let signature: [u8; 64] = hex::decode(&self.signature)
            .map_err(|_| anyhow!("invalid integrity response signature"))?
            .try_into()
            .map_err(|_| anyhow!("integrity response signature must be 64 bytes"))?;
        VerifyingKey::from_bytes(&public_key)?
            .verify(&self.signing_payload(), &Signature::from_bytes(&signature))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityDisposition {
    Active,
    Warning,
    Restricted,
    Untrusted,
    Revoked,
}

pub fn evaluate_response(
    response: &IntegrityResponse,
    wave: &IntegrityWave,
    now: u64,
) -> IntegrityDisposition {
    if response.verify(wave, now).is_err() {
        return IntegrityDisposition::Revoked;
    }
    if response.software_measurement != wave.required_measurement {
        IntegrityDisposition::Revoked
    } else {
        IntegrityDisposition::Active
    }
}

pub fn evaluate_no_response(
    wave: &IntegrityWave,
    now: u64,
    reachable: bool,
    exempt_until: Option<u64>,
) -> IntegrityDisposition {
    if !reachable || exempt_until.is_some_and(|until| now <= until) {
        return IntegrityDisposition::Active;
    }
    if now <= wave.response_deadline {
        IntegrityDisposition::Warning
    } else if now
        <= wave
            .response_deadline
            .saturating_add(INTEGRITY_GRACE_SECONDS)
    {
        IntegrityDisposition::Restricted
    } else {
        IntegrityDisposition::Revoked
    }
}

fn identity_for_public_key(public_key: &str) -> Result<String> {
    let public_key_bytes: [u8; 32] = hex::decode(public_key)
        .map_err(|_| anyhow!("invalid public key"))?
        .try_into()
        .map_err(|_| anyhow!("public key must be 32 bytes"))?;
    let mut hash = Sha256::new();
    hash.update(public_key_bytes);
    Ok(hex::encode(hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> ([u8; 32], [u8; 32]) {
        ([41; 32], [42; 32])
    }

    fn signed_wave() -> IntegrityWave {
        let (authority, _) = keys();
        let authority_public_key = hex::encode(
            SigningKey::from_bytes(&authority)
                .verifying_key()
                .to_bytes(),
        );
        let mut wave = IntegrityWave::new(
            "wave-1".into(),
            7,
            100,
            200,
            "approved-build".into(),
            authority_public_key,
        );
        wave.sign(&authority);
        wave
    }

    #[test]
    fn signed_wave_and_matching_response_are_active() {
        let wave = signed_wave();
        let (_, node_key) = keys();
        let node_signing_key = SigningKey::from_bytes(&node_key);
        let mut response = IntegrityResponse::new(
            &wave,
            hex::encode(node_signing_key.verifying_key().to_bytes()),
            "approved-build".into(),
            150,
        )
        .unwrap();
        response.sign(&node_key);
        assert_eq!(
            evaluate_response(&response, &wave, 160),
            IntegrityDisposition::Active
        );
    }

    #[test]
    fn changed_measurement_is_revoked() {
        let wave = signed_wave();
        let (_, node_key) = keys();
        let node_signing_key = SigningKey::from_bytes(&node_key);
        let mut response = IntegrityResponse::new(
            &wave,
            hex::encode(node_signing_key.verifying_key().to_bytes()),
            "fork-build".into(),
            150,
        )
        .unwrap();
        response.sign(&node_key);
        assert_eq!(
            evaluate_response(&response, &wave, 160),
            IntegrityDisposition::Revoked
        );
    }

    #[test]
    fn reachable_silent_node_progresses_without_punishing_offline_nodes() {
        let wave = signed_wave();
        assert_eq!(
            evaluate_no_response(&wave, 150, false, None),
            IntegrityDisposition::Active
        );
        assert_eq!(
            evaluate_no_response(&wave, 150, true, None),
            IntegrityDisposition::Warning
        );
        assert_eq!(
            evaluate_no_response(&wave, 201, true, None),
            IntegrityDisposition::Restricted
        );
        assert_eq!(
            evaluate_no_response(&wave, 201 + INTEGRITY_GRACE_SECONDS + 1, true, None),
            IntegrityDisposition::Revoked
        );
        assert_eq!(
            evaluate_no_response(&wave, 1_000, true, Some(2_000)),
            IntegrityDisposition::Active
        );
    }
}
