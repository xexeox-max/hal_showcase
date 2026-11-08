use anyhow::{anyhow, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpdateChannel {
    PlayBase,
    PeerStable,
    PeerBeta,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub prerelease: Option<String>,
}

impl UpdateVersion {
    pub fn parse(value: &str) -> Result<Self> {
        let (core, prerelease) = value
            .split_once('-')
            .map_or((value, None), |(core, pre)| (core, Some(pre.to_string())));
        let parts: Vec<_> = core.split('.').collect();
        if parts.len() != 3 {
            return Err(anyhow!("invalid update version: {value}"));
        }
        Ok(Self {
            major: parts[0].parse()?,
            minor: parts[1].parse()?,
            patch: parts[2].parse()?,
            prerelease,
        })
    }
}

impl Ord for UpdateVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            self.major,
            self.minor,
            self.patch,
            self.prerelease.is_some(),
        )
            .cmp(&(
                other.major,
                other.minor,
                other.patch,
                other.prerelease.is_some(),
            ))
    }
}
impl PartialOrd for UpdateVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpdateArtifactKind {
    AndroidApk,
    DesktopPackage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateArtifact {
    pub kind: UpdateArtifactKind,
    pub version: UpdateVersion,
    pub platform: String,
    pub architecture: String,
    pub package_url: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub release_notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateManifest {
    pub manifest_id: String,
    pub channel: UpdateChannel,
    pub publisher_identity_id: String,
    pub publisher_public_key: String,
    pub generated_at: u64,
    pub expires_at: u64,
    pub artifacts: Vec<UpdateArtifact>,
    pub signature: String,
}

impl UpdateManifest {
    pub fn new(
        channel: UpdateChannel,
        publisher_identity_id: String,
        publisher_public_key: String,
        generated_at: u64,
        expires_at: u64,
        artifacts: Vec<UpdateArtifact>,
    ) -> Self {
        Self {
            manifest_id: uuid::Uuid::new_v4().to_string(),
            channel,
            publisher_identity_id,
            publisher_public_key,
            generated_at,
            expires_at,
            artifacts,
            signature: String::new(),
        }
    }

    fn signing_payload(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            &self.manifest_id,
            self.channel,
            &self.publisher_identity_id,
            &self.publisher_public_key,
            self.generated_at,
            self.expires_at,
            &self.artifacts,
        ))?)
    }

    pub fn sign(&mut self, private_key: &[u8]) -> Result<()> {
        let key: [u8; 32] = private_key
            .try_into()
            .map_err(|_| anyhow!("Ed25519 private key must be 32 bytes"))?;
        self.signature = hex::encode(
            SigningKey::from_bytes(&key)
                .sign(&self.signing_payload()?)
                .to_bytes(),
        );
        Ok(())
    }

    pub fn verify(&self, now: u64, expected_publisher: Option<&str>) -> Result<()> {
        if now >= self.expires_at {
            return Err(anyhow!("update manifest expired"));
        }
        if expected_publisher.is_some_and(|expected| expected != self.publisher_identity_id) {
            return Err(anyhow!("manifest publisher is not trusted"));
        }
        let public: [u8; 32] = hex::decode(&self.publisher_public_key)?
            .try_into()
            .map_err(|_| anyhow!("invalid publisher public key"))?;
        let mut hash = Sha256::new();
        hash.update(public);
        if self.publisher_identity_id != hex::encode(hash.finalize()) {
            return Err(anyhow!("publisher identity does not match public key"));
        }
        let signature: [u8; 64] = hex::decode(&self.signature)?
            .try_into()
            .map_err(|_| anyhow!("invalid manifest signature"))?;
        VerifyingKey::from_bytes(&public)?
            .verify(&self.signing_payload()?, &Signature::from_bytes(&signature))?;
        for artifact in &self.artifacts {
            if artifact.sha256.len() != 64
                || !artifact.sha256.chars().all(|c| c.is_ascii_hexdigit())
                || artifact.size_bytes == 0
                || artifact.package_url.trim().is_empty()
            {
                return Err(anyhow!("invalid update artifact"));
            }
        }
        Ok(())
    }

    pub fn rollback_versions(
        &self,
        kind: UpdateArtifactKind,
        platform: &str,
        architecture: &str,
    ) -> Vec<&UpdateArtifact> {
        let mut versions: Vec<_> = self
            .artifacts
            .iter()
            .filter(|artifact| {
                artifact.kind == kind
                    && artifact.platform == platform
                    && artifact.architecture == architecture
            })
            .collect();
        versions.sort_by(|a, b| b.version.cmp(&a.version));
        versions
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(bytes);
    hex::encode(hash.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_manifest_keeps_all_rollback_versions() {
        let key = SigningKey::from_bytes(&[6; 32]);
        let public = key.verifying_key().to_bytes();
        let mut hash = Sha256::new();
        hash.update(public);
        let identity = hex::encode(hash.finalize());
        let artifact = |version: &str| UpdateArtifact {
            kind: UpdateArtifactKind::AndroidApk,
            version: UpdateVersion::parse(version).unwrap(),
            platform: "android".into(),
            architecture: "arm64-v8a".into(),
            package_url: "hal://package".into(),
            sha256: "a".repeat(64),
            size_bytes: 1,
            release_notes: String::new(),
        };
        let mut manifest = UpdateManifest::new(
            UpdateChannel::PeerStable,
            identity.clone(),
            hex::encode(public),
            100,
            2000,
            vec![artifact("1.0.0"), artifact("1.1.0"), artifact("2.0.0")],
        );
        manifest.sign(&key.to_bytes()).unwrap();
        manifest.verify(1000, Some(&identity)).unwrap();
        assert_eq!(
            manifest
                .rollback_versions(UpdateArtifactKind::AndroidApk, "android", "arm64-v8a")
                .len(),
            3
        );
    }
}
