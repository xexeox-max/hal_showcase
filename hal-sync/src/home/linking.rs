use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hal_crypto::ecies::{open_to_identity, seal_to_identity, SealedEnvelope};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::device::{DeviceCapabilities, DeviceInfo, DeviceRole};
use super::secret::HomeSecret;

pub const LINK_PROTOCOL_VERSION: u8 = 1;
const LINKING_QR_PREFIX: &str = "hal://link-device?";

fn sha256_hex(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    hex::encode(hasher.finalize())
}

fn timestamp_is_recent(ts: u64) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let delta = now.abs_diff(ts);
    delta <= 300
}

fn qr_percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(char::from(b"0123456789ABCDEF"[(byte >> 4) as usize]));
            encoded.push(char::from(b"0123456789ABCDEF"[(byte & 0x0f) as usize]));
        }
    }
    encoded
}

fn qr_percent_decode(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(anyhow!("invalid QR percent escape"));
        }
        let high = (bytes[index + 1] as char)
            .to_digit(16)
            .ok_or_else(|| anyhow!("invalid QR percent escape"))?;
        let low = (bytes[index + 2] as char)
            .to_digit(16)
            .ok_or_else(|| anyhow!("invalid QR percent escape"))?;
        decoded.push(((high << 4) | low) as u8);
        index += 3;
    }
    String::from_utf8(decoded).map_err(|_| anyhow!("QR value is not valid UTF-8"))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkingQr {
    pub version: u8,
    pub primary_device_id: String,
    pub primary_pubkey: String,
    pub primary_addr: String,
    pub linking_token: String,
    pub expires: u64,
}

impl LinkingQr {
    pub fn create(
        primary_signing_key: &SigningKey,
        primary_addr: String,
        ttl_seconds: u64,
    ) -> Result<Self> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expires = now
            .checked_add(ttl_seconds)
            .ok_or_else(|| anyhow!("QR expiration overflow"))?;
        let primary_pubkey = hex::encode(primary_signing_key.verifying_key().to_bytes());
        Ok(Self {
            version: LINK_PROTOCOL_VERSION,
            primary_device_id: sha256_hex(&primary_signing_key.verifying_key().to_bytes()),
            primary_pubkey,
            primary_addr,
            linking_token: Self::generate_token(),
            expires,
        })
    }

    pub fn generate_token() -> String {
        let mut token = [0u8; 32];
        OsRng.fill_bytes(&mut token);
        hex::encode(token)
    }

    pub fn to_link(&self) -> String {
        format!(
            "{LINKING_QR_PREFIX}v={}&primary_device_id={}&primary_pubkey={}&primary_addr={}&linking_token={}&expires={}",
            self.version,
            qr_percent_encode(&self.primary_device_id),
            qr_percent_encode(&self.primary_pubkey),
            qr_percent_encode(&self.primary_addr),
            qr_percent_encode(&self.linking_token),
            self.expires,
        )
    }

    pub fn from_link(link: &str) -> Result<Self> {
        let query = link
            .strip_prefix(LINKING_QR_PREFIX)
            .ok_or_else(|| anyhow!("invalid QR scheme or path"))
            .context("parse Home Linking QR prefix")?;
        let mut values = std::collections::HashMap::new();
        for (index, part) in query.split('&').enumerate() {
            let (key, value) = part
                .split_once('=')
                .ok_or_else(|| anyhow!("invalid QR parameter"))
                .with_context(|| format!("parse Home Linking QR parameter {}", index + 1))?;
            let decoded = qr_percent_decode(value)
                .with_context(|| format!("decode Home Linking QR parameter {key}"))?;
            if key.is_empty() || values.insert(key, decoded).is_some() {
                return Err(anyhow!("duplicate or empty QR parameter")
                    .context(format!("validate Home Linking QR parameter {}", index + 1)));
            }
        }
        if values.len() != 6 {
            return Err(anyhow!("missing or unknown QR parameter")
                .context("validate Home Linking QR parameter set"));
        }
        let version = values
            .remove("v")
            .ok_or_else(|| anyhow!("missing QR version"))?
            .parse::<u8>()
            .context("parse Home Linking QR version")?;
        let qr = Self {
            version,
            primary_device_id: values
                .remove("primary_device_id")
                .ok_or_else(|| anyhow!("missing primary device id"))?,
            primary_pubkey: values
                .remove("primary_pubkey")
                .ok_or_else(|| anyhow!("missing primary public key"))?,
            primary_addr: values
                .remove("primary_addr")
                .ok_or_else(|| anyhow!("missing primary address"))?,
            linking_token: values
                .remove("linking_token")
                .ok_or_else(|| anyhow!("missing linking token"))?,
            expires: values
                .remove("expires")
                .ok_or_else(|| anyhow!("missing QR expiration"))?
                .parse::<u64>()
                .context("parse Home Linking QR expiration")?,
        };
        qr.verify().context("verify Home Linking QR fields")?;
        Ok(qr)
    }

    pub fn verify(&self) -> Result<()> {
        if self.version != LINK_PROTOCOL_VERSION {
            return Err(anyhow!("unsupported QR version"));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if self.expires < now {
            return Err(anyhow!("linking QR has expired"));
        }
        if self.primary_addr.trim().is_empty() {
            return Err(anyhow!("primary address is empty"));
        }
        let token =
            hex::decode(&self.linking_token).map_err(|_| anyhow!("linking token must be hex"))?;
        if token.len() != 32 {
            return Err(anyhow!("linking token must be 32 bytes"));
        }
        let public_key = hex::decode(&self.primary_pubkey)
            .map_err(|_| anyhow!("primary public key must be hex"))?;
        if public_key.len() != 32 {
            return Err(anyhow!("primary public key must be 32 bytes"));
        }
        if self.primary_device_id != sha256_hex(&public_key) {
            return Err(anyhow!("primary device id does not match public key"));
        }
        VerifyingKey::from_bytes(
            &public_key
                .try_into()
                .map_err(|_| anyhow!("invalid primary public key length"))?,
        )?;
        Ok(())
    }
}

fn role_as_bytes(role: DeviceRole) -> &'static [u8] {
    match role {
        DeviceRole::Primary => b"primary",
        DeviceRole::Secondary => b"secondary",
        DeviceRole::Mobile => b"mobile",
    }
}

fn device_info_payload(info: &DeviceInfo) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(info.device_id.as_bytes());
    payload.extend_from_slice(b"|");
    payload.extend_from_slice(info.device_pubkey.as_bytes());
    payload.extend_from_slice(b"|");
    payload.extend_from_slice(info.stack_id.as_bytes());
    payload.extend_from_slice(b"|");
    payload.extend_from_slice(info.added_at.to_string().as_bytes());
    payload.extend_from_slice(b"|");
    payload.extend_from_slice(info.added_by.as_bytes());
    payload.extend_from_slice(b"|");
    payload.extend_from_slice(role_as_bytes(info.role));
    payload.extend_from_slice(b"|");
    payload.extend_from_slice(info.last_seen.to_string().as_bytes());
    payload.extend_from_slice(b"|");
    payload.extend_from_slice(info.capabilities.storage_quota_bytes.to_string().as_bytes());
    payload.extend_from_slice(b"|");
    payload.extend_from_slice(info.capabilities.cpu_cores.to_string().as_bytes());
    payload.extend_from_slice(b"|");
    payload.extend_from_slice(if info.capabilities.is_always_on {
        b"1"
    } else {
        b"0"
    });
    payload.extend_from_slice(b"|");
    payload.extend_from_slice(if info.capabilities.has_tee {
        b"1"
    } else {
        b"0"
    });
    payload
}

fn requested_role_payload(role: DeviceRole) -> &'static [u8] {
    role_as_bytes(role)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkRequest {
    pub version: u8,
    pub new_device_id: String,
    pub new_device_pubkey: String,
    pub requested_role: DeviceRole,
    pub capabilities: DeviceCapabilities,
    pub linking_token: String,
    pub timestamp: u64,
    pub nonce: String,
    pub signature: String,
}

impl LinkRequest {
    pub fn new(
        new_device_pubkey: String,
        requested_role: DeviceRole,
        capabilities: DeviceCapabilities,
        linking_token: String,
    ) -> Self {
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let new_device_id = sha256_hex(new_device_pubkey.as_bytes());
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            version: LINK_PROTOCOL_VERSION,
            new_device_id,
            new_device_pubkey,
            requested_role,
            capabilities,
            linking_token,
            timestamp,
            nonce: hex::encode(nonce),
            signature: String::new(),
        }
    }

    pub fn sign(&mut self, signing_key: &SigningKey) {
        let signature = signing_key.sign(&self.signing_payload());
        self.signature = hex::encode(signature.to_bytes());
    }

    pub fn verify(&self) -> Result<()> {
        let expected_id = sha256_hex(self.new_device_pubkey.as_bytes());
        if self.new_device_id != expected_id {
            return Err(anyhow!("device identity does not match the public key"));
        }
        if !timestamp_is_recent(self.timestamp) {
            return Err(anyhow!(
                "link request timestamp is outside the allowed window"
            ));
        }
        let public_bytes = hex::decode(&self.new_device_pubkey)
            .map_err(|error| anyhow!("invalid device public key: {error}"))?;
        if public_bytes.len() != 32 {
            return Err(anyhow!("device public key must be 32 bytes"));
        }
        let verifying_key = VerifyingKey::from_bytes(
            &public_bytes
                .try_into()
                .map_err(|_| anyhow!("invalid device public key length"))?,
        )?;
        let signature = hex::decode(&self.signature)
            .map_err(|error| anyhow!("invalid link request signature: {error}"))?;
        if signature.len() != 64 {
            return Err(anyhow!("link request signature must be 64 bytes"));
        }
        let sig = ed25519_dalek::Signature::from_slice(&signature)
            .map_err(|error| anyhow!("invalid Ed25519 signature: {error}"))?;
        verifying_key
            .verify(&self.signing_payload(), &sig)
            .map_err(|error| anyhow!("link request signature verification failed: {error}"))?;
        Ok(())
    }

    fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[self.version]);
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(self.new_device_id.as_bytes());
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(self.new_device_pubkey.as_bytes());
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(requested_role_payload(self.requested_role));
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(self.capabilities.storage_quota_bytes.to_string().as_bytes());
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(self.capabilities.cpu_cores.to_string().as_bytes());
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(if self.capabilities.is_always_on {
            b"1"
        } else {
            b"0"
        });
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(if self.capabilities.has_tee {
            b"1"
        } else {
            b"0"
        });
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(self.linking_token.as_bytes());
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(self.timestamp.to_string().as_bytes());
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(self.nonce.as_bytes());
        payload
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkResponse {
    pub version: u8,
    pub primary_device_id: String,
    pub primary_pubkey: String,
    pub stack_id: String,
    pub link_nonce: String,
    pub sealed_home_secret: SealedEnvelope,
    pub all_devices: Vec<DeviceInfo>,
    pub timestamp: u64,
    pub signature: String,
}

pub fn handle_link_request(
    request: &LinkRequest,
    expected_linking_token: &str,
    stack: &mut crate::home::HomeStack,
    primary_signing_key: &SigningKey,
    home_secret: &HomeSecret,
    all_devices: Vec<DeviceInfo>,
) -> Result<LinkResponse> {
    request.verify()?;
    if request.linking_token != expected_linking_token {
        return Err(anyhow!("linking token mismatch"));
    }
    let public_bytes = hex::decode(&request.new_device_pubkey)
        .map_err(|error| anyhow!("invalid device public key: {error}"))?;
    let new_device_pubkey = VerifyingKey::from_bytes(
        &public_bytes
            .try_into()
            .map_err(|_| anyhow!("invalid device public key length"))?,
    )?;
    let mut sorted_devices = all_devices;
    if let Some(existing) = stack.devices.get_mut(&request.new_device_id) {
        let existing_public_key = hex::decode(&existing.device_pubkey)
            .map_err(|_| anyhow!("Identity Mismatch: stored public key is invalid"))?;
        if existing_public_key != new_device_pubkey.to_bytes() {
            return Err(anyhow!(
                "Identity Mismatch: device public key does not match"
            ));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        existing.last_seen = now;
        existing.role = request.requested_role;
        existing.capabilities = request.capabilities.clone();
        if let Some(device) = sorted_devices
            .iter_mut()
            .find(|device| device.device_id == request.new_device_id)
        {
            *device = existing.clone();
        } else {
            sorted_devices.push(existing.clone());
        }
    }
    stack.record_link_nonce(request.nonce.clone())?;
    sorted_devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    let link_nonce = hex::encode(OsRng.next_u64().to_be_bytes());
    LinkResponse::create(
        primary_signing_key,
        &new_device_pubkey,
        home_secret,
        stack.stack_id.clone(),
        sorted_devices,
        link_nonce,
    )
}

pub fn handle_link_response(
    response: &LinkResponse,
    new_device_signing_key: &SigningKey,
    new_device_role: DeviceRole,
    capabilities: DeviceCapabilities,
) -> Result<(HomeSecret, crate::home::HomeStack, DeviceInfo)> {
    response.verify()?;
    let home_secret = response.open_secret(new_device_signing_key)?;
    let new_device_id = sha256_hex(&new_device_signing_key.verifying_key().to_bytes());
    let mut stack = crate::home::HomeStack::new(
        response.stack_id.clone(),
        response.primary_device_id.clone(),
    );
    for device in &response.all_devices {
        stack.add_device(device.clone())?;
    }
    if let Some(primary) = stack.get_device(&response.primary_device_id) {
        if primary.device_pubkey != response.primary_pubkey {
            return Err(anyhow!(
                "Home Stack primary public key does not match LinkResponse"
            ));
        }
    } else {
        stack.add_device(DeviceInfo {
            device_id: response.primary_device_id.clone(),
            device_pubkey: response.primary_pubkey.clone(),
            stack_id: response.stack_id.clone(),
            added_at: response.timestamp,
            added_by: response.primary_device_id.clone(),
            role: DeviceRole::Primary,
            last_seen: response.timestamp,
            capabilities: DeviceCapabilities::default(),
        })?;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let self_info = DeviceInfo {
        device_id: new_device_id.clone(),
        device_pubkey: hex::encode(new_device_signing_key.verifying_key().to_bytes()),
        stack_id: response.stack_id.clone(),
        added_at: now,
        added_by: response.primary_device_id.clone(),
        role: new_device_role,
        last_seen: now,
        capabilities,
    };
    stack.add_device(self_info.clone())?;
    Ok((home_secret, stack, self_info))
}

impl LinkResponse {
    pub fn create(
        primary_signing_key: &SigningKey,
        new_device_pubkey: &VerifyingKey,
        home_secret: &HomeSecret,
        stack_id: String,
        all_devices: Vec<DeviceInfo>,
        link_nonce: String,
    ) -> Result<Self> {
        let mut canonical_devices = all_devices;
        canonical_devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        let primary_pubkey = hex::encode(primary_signing_key.verifying_key().to_bytes());
        let primary_device_id = sha256_hex(&primary_signing_key.verifying_key().to_bytes());
        let aad = format!("{}|{}|{}", stack_id, primary_device_id, link_nonce);
        let sealed_home_secret =
            seal_to_identity(new_device_pubkey, home_secret.as_bytes(), aad.as_bytes())?;
        let mut response = Self {
            version: LINK_PROTOCOL_VERSION,
            primary_device_id,
            primary_pubkey,
            stack_id,
            link_nonce,
            sealed_home_secret,
            all_devices: canonical_devices,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            signature: String::new(),
        };
        response.sign(primary_signing_key);
        Ok(response)
    }

    pub fn sign(&mut self, signing_key: &SigningKey) {
        let signature = signing_key.sign(&self.signing_payload());
        self.signature = hex::encode(signature.to_bytes());
    }

    pub fn verify(&self) -> Result<()> {
        if !timestamp_is_recent(self.timestamp) {
            return Err(anyhow!(
                "link response timestamp is outside the allowed window"
            ));
        }
        let primary_pubkey = hex::decode(&self.primary_pubkey)
            .map_err(|error| anyhow!("invalid primary public key: {error}"))?;
        if primary_pubkey.len() != 32 {
            return Err(anyhow!("primary public key must be 32 bytes"));
        }
        let key: [u8; 32] = primary_pubkey
            .try_into()
            .map_err(|_| anyhow!("primary public key length mismatch"))?;
        let verifying_key = VerifyingKey::from_bytes(&key)?;
        let signature = hex::decode(&self.signature)
            .map_err(|error| anyhow!("invalid link response signature: {error}"))?;
        if signature.len() != 64 {
            return Err(anyhow!("link response signature must be 64 bytes"));
        }
        let sig = ed25519_dalek::Signature::from_slice(&signature)
            .map_err(|error| anyhow!("invalid Ed25519 signature: {error}"))?;
        verifying_key
            .verify(&self.signing_payload(), &sig)
            .map_err(|error| anyhow!("link response signature verification failed: {error}"))?;
        let expected_id = sha256_hex(&key);
        if self.primary_device_id != expected_id {
            return Err(anyhow!(
                "primary device id does not match primary public key"
            ));
        }
        Ok(())
    }

    pub fn open_secret(&self, new_device_signing_key: &SigningKey) -> Result<HomeSecret> {
        self.verify()?;
        let aad = format!(
            "{}|{}|{}",
            self.stack_id, self.primary_device_id, self.link_nonce
        );
        let plain = open_to_identity(
            new_device_signing_key,
            &self.sealed_home_secret,
            aad.as_bytes(),
        )?;
        let bytes: [u8; 32] = plain
            .try_into()
            .map_err(|_| anyhow!("home secret must be 32 bytes"))?;
        Ok(HomeSecret::from_bytes(bytes))
    }

    fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[self.version]);
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(self.primary_device_id.as_bytes());
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(self.primary_pubkey.as_bytes());
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(self.stack_id.as_bytes());
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(self.link_nonce.as_bytes());
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(self.sealed_home_secret.ephemeral_public.as_slice());
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(self.sealed_home_secret.nonce.as_slice());
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(self.sealed_home_secret.ciphertext.as_slice());
        payload.extend_from_slice(b"|");
        let mut devices = self.all_devices.clone();
        devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        for device in &devices {
            let device_bytes = device_info_payload(device);
            payload.extend_from_slice(&device_bytes);
            payload.extend_from_slice(b"|");
        }
        payload.extend_from_slice(self.timestamp.to_string().as_bytes());
        payload
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkConfirm {
    pub version: u8,
    pub new_device_id: String,
    pub new_device_pubkey: String,
    pub primary_device_id: String,
    pub link_nonce: String,
    pub timestamp: u64,
    pub hmac: String,
    pub signature: String,
}

impl LinkConfirm {
    pub fn create(
        new_device_signing_key: &SigningKey,
        primary_device_id: String,
        home_secret: &HomeSecret,
        link_nonce: String,
    ) -> Result<Self> {
        let new_device_id = sha256_hex(&new_device_signing_key.verifying_key().to_bytes());
        let new_device_pubkey = hex::encode(new_device_signing_key.verifying_key().to_bytes());
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let key = derive_proof_key(home_secret, &link_nonce)?;
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&key)
            .map_err(|error| anyhow!("invalid HMAC key: {error}"))?;
        mac.update(new_device_id.as_bytes());
        mac.update(b"|");
        mac.update(primary_device_id.as_bytes());
        mac.update(b"|");
        mac.update(link_nonce.as_bytes());
        mac.update(b"|");
        mac.update(timestamp.to_string().as_bytes());
        let mut confirm = Self {
            version: LINK_PROTOCOL_VERSION,
            new_device_id,
            new_device_pubkey,
            primary_device_id,
            link_nonce,
            timestamp,
            hmac: hex::encode(mac.finalize().into_bytes()),
            signature: String::new(),
        };
        confirm.signature = hex::encode(
            new_device_signing_key
                .sign(&confirm.signing_payload())
                .to_bytes(),
        );
        Ok(confirm)
    }

    pub fn verify(&self, home_secret: &HomeSecret, primary_device_id: &str) -> Result<()> {
        if self.primary_device_id != primary_device_id {
            return Err(anyhow!("primary device mismatch"));
        }
        if !timestamp_is_recent(self.timestamp) {
            return Err(anyhow!(
                "link confirm timestamp is outside the allowed window"
            ));
        }
        let expected_id = sha256_hex(&hex::decode(&self.new_device_pubkey)?);
        if self.new_device_id != expected_id {
            return Err(anyhow!(
                "new device id does not match new device public key"
            ));
        }
        let key = derive_proof_key(home_secret, &self.link_nonce)?;
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&key)
            .map_err(|error| anyhow!("invalid HMAC key: {error}"))?;
        mac.update(self.new_device_id.as_bytes());
        mac.update(b"|");
        mac.update(self.primary_device_id.as_bytes());
        mac.update(b"|");
        mac.update(self.link_nonce.as_bytes());
        mac.update(b"|");
        mac.update(self.timestamp.to_string().as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());
        if self.hmac != expected {
            return Err(anyhow!("link confirm HMAC mismatch"));
        }

        let bytes = hex::decode(&self.new_device_pubkey)
            .map_err(|error| anyhow!("invalid device public key: {error}"))?;
        if bytes.len() != 32 {
            return Err(anyhow!("device_id must be 32 bytes (sha256 hash)"));
        }
        let verifying_key = VerifyingKey::from_bytes(
            &bytes
                .try_into()
                .map_err(|_| anyhow!("invalid device key length"))?,
        )?;
        let signature = hex::decode(&self.signature)
            .map_err(|error| anyhow!("invalid link confirm signature: {error}"))?;
        if signature.len() != 64 {
            return Err(anyhow!("link confirm signature must be 64 bytes"));
        }
        let sig = ed25519_dalek::Signature::from_slice(&signature)
            .map_err(|error| anyhow!("invalid Ed25519 signature: {error}"))?;
        verifying_key
            .verify(&self.signing_payload(), &sig)
            .map_err(|error| anyhow!("link confirm signature verification failed: {error}"))?;
        Ok(())
    }

    fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[self.version]);
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(self.new_device_id.as_bytes());
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(self.new_device_pubkey.as_bytes());
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(self.primary_device_id.as_bytes());
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(self.link_nonce.as_bytes());
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(self.timestamp.to_string().as_bytes());
        payload.extend_from_slice(b"|");
        payload.extend_from_slice(self.hmac.as_bytes());
        payload
    }
}

pub fn derive_proof_key(home_secret: &HomeSecret, link_nonce: &str) -> Result<[u8; 32]> {
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(home_secret.as_bytes())
        .map_err(|error| anyhow!("invalid proof key input: {error}"))?;
    mac.update(link_nonce.as_bytes());
    let digest = mac.finalize().into_bytes();
    let bytes: [u8; 32] = digest
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("proof key must be 32 bytes"))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_request_sign_verify() {
        let key = SigningKey::from_bytes(&[11; 32]);
        let pubkey = hex::encode(key.verifying_key().to_bytes());
        let mut request = LinkRequest::new(
            pubkey.clone(),
            DeviceRole::Mobile,
            DeviceCapabilities::default(),
            "token-1".into(),
        );
        request.sign(&key);
        request.verify().expect("verify request");
    }

    #[test]
    fn link_confirm_new_device_id_matches_request() {
        let key = SigningKey::from_bytes(&[21; 32]);
        let pubkey = hex::encode(key.verifying_key().to_bytes());
        let mut request = LinkRequest::new(
            pubkey.clone(),
            DeviceRole::Mobile,
            DeviceCapabilities::default(),
            "token-req".into(),
        );
        request.sign(&key);
        request.verify().expect("request valid");
        let confirm = LinkConfirm::create(
            &key,
            "primary-device".into(),
            &HomeSecret::generate(),
            "nonce-req".into(),
        )
        .expect("confirm");
        assert_eq!(
            confirm.new_device_id,
            sha256_hex(&key.verifying_key().to_bytes())
        );
        assert!(confirm.new_device_id == sha256_hex(&hex::decode(pubkey).unwrap()));
    }

    #[test]
    fn link_confirm_rejects_tampered_signature() {
        let key = SigningKey::from_bytes(&[22; 32]);
        let home_secret = HomeSecret::generate();
        let mut confirm = LinkConfirm::create(
            &key,
            "primary-device".into(),
            &home_secret,
            "nonce-bad".into(),
        )
        .expect("confirm");
        confirm.signature = "00".repeat(32);
        assert!(confirm.verify(&home_secret, "primary-device").is_err());
    }

    #[test]
    fn link_response_signing_payload_deterministic() {
        let primary = SigningKey::from_bytes(&[23; 32]);
        let home_secret = HomeSecret::generate();
        let first = vec![
            DeviceInfo {
                device_id: "z".to_string(),
                device_pubkey: "zz".to_string(),
                stack_id: "stack".to_string(),
                added_at: 1,
                added_by: "primary".to_string(),
                role: DeviceRole::Mobile,
                last_seen: 1,
                capabilities: DeviceCapabilities::default(),
            },
            DeviceInfo {
                device_id: "a".to_string(),
                device_pubkey: "aa".to_string(),
                stack_id: "stack".to_string(),
                added_at: 1,
                added_by: "primary".to_string(),
                role: DeviceRole::Primary,
                last_seen: 1,
                capabilities: DeviceCapabilities::default(),
            },
            DeviceInfo {
                device_id: "m".to_string(),
                device_pubkey: "mm".to_string(),
                stack_id: "stack".to_string(),
                added_at: 1,
                added_by: "primary".to_string(),
                role: DeviceRole::Secondary,
                last_seen: 1,
                capabilities: DeviceCapabilities::default(),
            },
        ];
        let mut second = first.clone();
        second.reverse();
        let mut response = LinkResponse::create(
            &primary,
            &primary.verifying_key(),
            &home_secret,
            "stack".to_string(),
            first,
            "nonce".to_string(),
        )
        .expect("create");
        let canonical_payload = response.signing_payload();
        response.all_devices = second;
        assert_eq!(canonical_payload, response.signing_payload());
    }

    #[test]
    fn handle_link_request_rejects_replay() {
        let primary_key = SigningKey::from_bytes(&[26; 32]);
        let new_key = SigningKey::from_bytes(&[27; 32]);
        let mut stack =
            crate::home::HomeStack::new("stack".to_string(), "primary-device".to_string());
        let request = LinkRequest::new(
            hex::encode(new_key.verifying_key().to_bytes()),
            DeviceRole::Mobile,
            DeviceCapabilities::default(),
            "token".to_string(),
        );
        let mut signed = request;
        signed.sign(&new_key);
        let response = handle_link_request(
            &signed,
            "token",
            &mut stack,
            &primary_key,
            &HomeSecret::generate(),
            vec![],
        )
        .expect("first ok");
        assert!(!response.link_nonce.is_empty());
        assert!(handle_link_request(
            &signed,
            "token",
            &mut stack,
            &primary_key,
            &HomeSecret::generate(),
            vec![]
        )
        .is_err());
    }

    #[test]
    fn handle_link_request_relinks_same_identity_and_refreshes_device() {
        let primary_key = SigningKey::from_bytes(&[30; 32]);
        let new_key = SigningKey::from_bytes(&[31; 32]);
        let secret = HomeSecret::generate();
        let mut stack =
            crate::home::HomeStack::new("stack".to_string(), "primary-device".to_string());
        let mut request = LinkRequest::new(
            hex::encode(new_key.verifying_key().to_bytes()),
            DeviceRole::Mobile,
            DeviceCapabilities {
                storage_quota_bytes: 4096,
                cpu_cores: 4,
                is_always_on: false,
                has_tee: false,
            },
            "token".to_string(),
        );
        request.sign(&new_key);
        let old_last_seen = 1;
        let existing = DeviceInfo {
            device_id: request.new_device_id.clone(),
            device_pubkey: request.new_device_pubkey.clone(),
            stack_id: "stack".to_string(),
            added_at: 1,
            added_by: "primary-device".to_string(),
            role: DeviceRole::Mobile,
            last_seen: old_last_seen,
            capabilities: DeviceCapabilities::default(),
        };
        stack.add_device(existing.clone()).expect("existing device");

        let response = handle_link_request(
            &request,
            "token",
            &mut stack,
            &primary_key,
            &secret,
            vec![existing],
        )
        .expect("same identity should relink");

        let updated = stack
            .get_device(&request.new_device_id)
            .expect("device remains linked");
        assert!(updated.last_seen > old_last_seen);
        assert_eq!(updated.capabilities.storage_quota_bytes, 4096);
        assert_eq!(response.all_devices.len(), 1);
        assert_eq!(response.all_devices[0].last_seen, updated.last_seen);
        assert!(stack.has_link_nonce(&request.nonce));
    }

    #[test]
    fn handle_link_request_rejects_identity_key_mismatch() {
        let primary_key = SigningKey::from_bytes(&[32; 32]);
        let new_key = SigningKey::from_bytes(&[33; 32]);
        let different_key = SigningKey::from_bytes(&[34; 32]);
        let mut stack =
            crate::home::HomeStack::new("stack".to_string(), "primary-device".to_string());
        let mut request = LinkRequest::new(
            hex::encode(new_key.verifying_key().to_bytes()),
            DeviceRole::Mobile,
            DeviceCapabilities::default(),
            "token".to_string(),
        );
        request.sign(&new_key);
        stack
            .add_device(DeviceInfo {
                device_id: request.new_device_id.clone(),
                device_pubkey: hex::encode(different_key.verifying_key().to_bytes()),
                stack_id: "stack".to_string(),
                added_at: 1,
                added_by: "primary-device".to_string(),
                role: DeviceRole::Mobile,
                last_seen: 1,
                capabilities: DeviceCapabilities::default(),
            })
            .expect("existing device");

        let error = handle_link_request(
            &request,
            "token",
            &mut stack,
            &primary_key,
            &HomeSecret::generate(),
            vec![],
        )
        .expect_err("key mismatch must be rejected");

        assert!(error.to_string().contains("Identity Mismatch"));
        assert!(!stack.has_link_nonce(&request.nonce));
    }

    #[test]
    fn handle_link_response_roundtrip() {
        let primary_key = SigningKey::from_bytes(&[28; 32]);
        let new_key = SigningKey::from_bytes(&[29; 32]);
        let secret = HomeSecret::generate();
        let mut stack =
            crate::home::HomeStack::new("stack".to_string(), "primary-device".to_string());
        let request = LinkRequest::new(
            hex::encode(new_key.verifying_key().to_bytes()),
            DeviceRole::Mobile,
            DeviceCapabilities::default(),
            "token".to_string(),
        );
        let mut signed = request;
        signed.sign(&new_key);
        let response = handle_link_request(
            &signed,
            "token",
            &mut stack,
            &primary_key,
            &secret,
            vec![DeviceInfo {
                device_id: "primary-device".to_string(),
                device_pubkey: hex::encode(primary_key.verifying_key().to_bytes()),
                stack_id: "stack".to_string(),
                added_at: 1,
                added_by: "primary-device".to_string(),
                role: DeviceRole::Primary,
                last_seen: 1,
                capabilities: DeviceCapabilities::default(),
            }],
        )
        .expect("request ok");
        let (opened, mut device_stack, self_info) = handle_link_response(
            &response,
            &new_key,
            DeviceRole::Mobile,
            DeviceCapabilities::default(),
        )
        .expect("response ok");
        assert_eq!(opened.as_bytes(), secret.as_bytes());
        assert!(device_stack.is_linked("primary-device"));
        assert!(device_stack.is_linked(&self_info.device_id));
    }

    #[test]
    fn home_linking_full_roundtrip_via_hex() {
        let primary_key = SigningKey::from_bytes(&[30; 32]);
        let new_key = SigningKey::from_bytes(&[31; 32]);
        let home_secret = HomeSecret::generate();
        let primary_device_id = sha256_hex(&primary_key.verifying_key().to_bytes());
        let mut primary_stack = crate::home::HomeStack::new("stack-hex".into(), primary_device_id);

        let mut request = LinkRequest::new(
            hex::encode(new_key.verifying_key().to_bytes()),
            DeviceRole::Mobile,
            DeviceCapabilities::default(),
            "link-token".into(),
        );
        request.sign(&new_key);
        let request_json = serde_json::to_string(&request).expect("request json");
        let request: LinkRequest = serde_json::from_str(&request_json).expect("request");

        let response = handle_link_request(
            &request,
            "link-token",
            &mut primary_stack,
            &primary_key,
            &home_secret,
            vec![],
        )
        .expect("response");
        let response_json = serde_json::to_string(&response).expect("response json");
        let response: LinkResponse = serde_json::from_str(&response_json).expect("response");

        let (opened_secret, new_stack, self_info) = handle_link_response(
            &response,
            &new_key,
            DeviceRole::Mobile,
            DeviceCapabilities::default(),
        )
        .expect("open response");
        assert_eq!(opened_secret.as_bytes(), home_secret.as_bytes());
        assert!(new_stack.is_linked(&self_info.device_id));

        let secret_hex = hex::encode(opened_secret.as_bytes());
        let confirm = LinkConfirm::create(
            &new_key,
            response.primary_device_id.clone(),
            &HomeSecret::from_bytes(
                hex::decode(&secret_hex)
                    .expect("secret hex")
                    .try_into()
                    .expect("secret length"),
            ),
            response.link_nonce.clone(),
        )
        .expect("confirm");
        assert!(confirm
            .verify(&home_secret, &response.primary_device_id)
            .is_ok());
    }

    #[test]
    fn link_request_rejects_tampered() {
        let key = SigningKey::from_bytes(&[12; 32]);
        let pubkey = hex::encode(key.verifying_key().to_bytes());
        let mut request = LinkRequest::new(
            pubkey,
            DeviceRole::Secondary,
            DeviceCapabilities::default(),
            "token-2".into(),
        );
        request.sign(&key);
        request.linking_token = "tampered".into();
        assert!(request.verify().is_err());
    }

    #[test]
    fn link_request_rejects_wrong_identity() {
        let key = SigningKey::from_bytes(&[13; 32]);
        let mut request = LinkRequest::new(
            hex::encode([0u8; 32]),
            DeviceRole::Primary,
            DeviceCapabilities::default(),
            "token-3".into(),
        );
        request.sign(&key);
        assert!(request.verify().is_err());
    }

    #[test]
    fn link_response_open_secret_roundtrip() {
        let primary_key = SigningKey::from_bytes(&[14; 32]);
        let new_key = SigningKey::from_bytes(&[15; 32]);
        let home_secret = HomeSecret::generate();
        let response = LinkResponse::create(
            &primary_key,
            &new_key.verifying_key(),
            &home_secret,
            "stack-1".into(),
            vec![],
            "nonce-abc".into(),
        )
        .expect("create");
        let opened = response.open_secret(&new_key).expect("open");
        assert_eq!(opened.as_bytes(), home_secret.as_bytes());
    }

    #[test]
    fn link_response_rejects_wrong_recipient() {
        let primary_key = SigningKey::from_bytes(&[16; 32]);
        let correct_key = SigningKey::from_bytes(&[17; 32]);
        let wrong_key = SigningKey::from_bytes(&[18; 32]);
        let key = HomeSecret::generate();
        let response = LinkResponse::create(
            &primary_key,
            &correct_key.verifying_key(),
            &key,
            "stack-1".into(),
            vec![],
            "nonce-xyz".into(),
        )
        .expect("create");
        assert!(response.open_secret(&wrong_key).is_err());
    }

    #[test]
    fn link_confirm_hmac_matches() {
        let key = SigningKey::from_bytes(&[19; 32]);
        let secret = HomeSecret::generate();
        let link_nonce = "nonce-confirm".to_string();
        let confirm =
            LinkConfirm::create(&key, "primary-device".into(), &secret, link_nonce.clone())
                .expect("create");
        assert!(confirm.verify(&secret, "primary-device").is_ok());
    }

    #[test]
    fn link_confirm_rejects_wrong_secret() {
        let key = SigningKey::from_bytes(&[20; 32]);
        let secret = HomeSecret::generate();
        let other = HomeSecret::generate();
        let confirm =
            LinkConfirm::create(&key, "primary-device".into(), &secret, "nonce-bad".into())
                .expect("create");
        assert!(confirm.verify(&other, "primary-device").is_err());
    }

    #[test]
    fn linking_qr_create_has_valid_identity_and_token() {
        let key = SigningKey::from_bytes(&[32; 32]);
        let qr = LinkingQr::create(&key, "192.168.1.20:4242".into(), 300).expect("create QR");
        assert_eq!(qr.version, LINK_PROTOCOL_VERSION);
        assert_eq!(
            qr.primary_pubkey,
            hex::encode(key.verifying_key().to_bytes())
        );
        assert_eq!(
            qr.primary_device_id,
            sha256_hex(&key.verifying_key().to_bytes())
        );
        assert_eq!(hex::decode(&qr.linking_token).expect("token hex").len(), 32);
        assert!(qr.verify().is_ok());
    }

    #[test]
    fn linking_qr_roundtrip_uses_fixed_order_and_encodes_address() {
        let key = SigningKey::from_bytes(&[33; 32]);
        let qr = LinkingQr::create(&key, "[2001:db8::1]:4242?route=local".into(), 300)
            .expect("create QR");
        let link = qr.to_link();
        assert!(link.starts_with("hal://link-device?v=1&primary_device_id="));
        assert!(link.contains("primary_addr=%5B2001%3Adb8%3A%3A1%5D%3A4242%3Froute%3Dlocal"));
        let decoded = LinkingQr::from_link(&link).expect("parse QR");
        assert_eq!(decoded, qr);
    }

    #[test]
    fn linking_qr_rejects_expired_link() {
        let key = SigningKey::from_bytes(&[34; 32]);
        let mut qr = LinkingQr::create(&key, "127.0.0.1:4242".into(), 300).expect("create QR");
        qr.expires = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs()
            .saturating_sub(1);
        assert!(qr.verify().is_err());
        assert!(LinkingQr::from_link(&qr.to_link()).is_err());
    }

    #[test]
    fn linking_qr_rejects_malformed_or_tampered_link() {
        assert!(LinkingQr::from_link("https://link-device?v=1").is_err());
        let key = SigningKey::from_bytes(&[35; 32]);
        let qr = LinkingQr::create(&key, "127.0.0.1:4242".into(), 300).expect("create QR");
        let tampered = qr.to_link().replace("expires=", "expires=bad");
        assert!(LinkingQr::from_link(&tampered).is_err());
    }
}
