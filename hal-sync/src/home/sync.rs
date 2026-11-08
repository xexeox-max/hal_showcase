use anyhow::{anyhow, Result};
use hal_crypto::{EncryptedMessage, XChaCha20Poly1305Cipher};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::HomeSecret;

pub const HOME_SYNC_CHUNK_BYTES: usize = 32 * 1024;
const HOME_SYNC_MAX_SNAPSHOT_BYTES: usize = 128 * 1024 * 1024;
const HOME_SYNC_MAX_CHUNKS: usize = HOME_SYNC_MAX_SNAPSHOT_BYTES / HOME_SYNC_CHUNK_BYTES;
const HOME_SYNC_TRANSFER_VERSION: u8 = 1;
const HOME_SYNC_AAD_PREFIX: &str = "HAL-HomeSync-Chunk-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomeSyncChunk {
    pub version: u8,
    pub transfer_id: String,
    pub index: u32,
    pub total: u32,
    pub snapshot_sha256: String,
    pub encrypted: EncryptedMessage,
}

pub fn seal_home_sync_snapshot(
    snapshot: &hal_storage::HomeSyncSnapshot,
    home_secret: &HomeSecret,
) -> Result<Vec<HomeSyncChunk>> {
    let plaintext = serde_json::to_vec(snapshot)?;
    if plaintext.is_empty() || plaintext.len() > HOME_SYNC_MAX_SNAPSHOT_BYTES {
        return Err(anyhow!(
            "Home sync snapshot size must be between 1 byte and {HOME_SYNC_MAX_SNAPSHOT_BYTES} bytes"
        ));
    }

    let transfer_id = uuid::Uuid::new_v4().to_string();
    let digest = hex::encode(Sha256::digest(&plaintext));
    let total = plaintext.len().div_ceil(HOME_SYNC_CHUNK_BYTES);
    if total > HOME_SYNC_MAX_CHUNKS {
        return Err(anyhow!("Home sync snapshot requires too many chunks"));
    }

    let key = derive_home_sync_key(home_secret)?;
    plaintext
        .chunks(HOME_SYNC_CHUNK_BYTES)
        .enumerate()
        .map(|(index, bytes)| {
            let index =
                u32::try_from(index).map_err(|_| anyhow!("Home sync chunk index overflow"))?;
            let total =
                u32::try_from(total).map_err(|_| anyhow!("Home sync chunk count overflow"))?;
            let aad = chunk_aad(&transfer_id, index, total, &digest);
            let encrypted = XChaCha20Poly1305Cipher::encrypt(&key[..], bytes, Some(&aad))?;
            Ok(HomeSyncChunk {
                version: HOME_SYNC_TRANSFER_VERSION,
                transfer_id: transfer_id.clone(),
                index,
                total,
                snapshot_sha256: digest.clone(),
                encrypted,
            })
        })
        .collect()
}

pub fn open_home_sync_snapshot(
    chunks: &[HomeSyncChunk],
    home_secret: &HomeSecret,
) -> Result<hal_storage::HomeSyncSnapshot> {
    let first = chunks
        .first()
        .ok_or_else(|| anyhow!("Home sync transfer has no chunks"))?;
    let total =
        usize::try_from(first.total).map_err(|_| anyhow!("invalid Home sync chunk count"))?;
    if first.version != HOME_SYNC_TRANSFER_VERSION
        || total == 0
        || total > HOME_SYNC_MAX_CHUNKS
        || chunks.len() != total
        || first.transfer_id.is_empty()
        || first.snapshot_sha256.len() != 64
    {
        return Err(anyhow!("invalid Home sync transfer metadata"));
    }

    let key = derive_home_sync_key(home_secret)?;
    let mut ordered: Vec<Option<&HomeSyncChunk>> = vec![None; total];
    for chunk in chunks {
        if chunk.version != first.version
            || chunk.transfer_id != first.transfer_id
            || chunk.total != first.total
            || chunk.snapshot_sha256 != first.snapshot_sha256
        {
            return Err(anyhow!(
                "Home sync chunks have inconsistent transfer metadata"
            ));
        }
        let index = usize::try_from(chunk.index).map_err(|_| anyhow!("invalid Home sync index"))?;
        if index >= total || ordered[index].replace(chunk).is_some() {
            return Err(anyhow!(
                "Home sync transfer has an invalid or duplicate chunk"
            ));
        }
    }

    let mut plaintext = Vec::new();
    for (index, chunk) in ordered.into_iter().enumerate() {
        let chunk = chunk.ok_or_else(|| anyhow!("Home sync transfer is missing a chunk"))?;
        let aad = chunk_aad(
            &first.transfer_id,
            u32::try_from(index).map_err(|_| anyhow!("Home sync chunk index overflow"))?,
            first.total,
            &first.snapshot_sha256,
        );
        let decrypted = XChaCha20Poly1305Cipher::decrypt(&key[..], &chunk.encrypted, Some(&aad))?;
        if decrypted.len() > HOME_SYNC_CHUNK_BYTES
            || plaintext.len().saturating_add(decrypted.len()) > HOME_SYNC_MAX_SNAPSHOT_BYTES
        {
            return Err(anyhow!("Home sync snapshot exceeds the size limit"));
        }
        plaintext.extend_from_slice(&decrypted);
    }

    let actual_digest = hex::encode(Sha256::digest(&plaintext));
    if actual_digest != first.snapshot_sha256 {
        return Err(anyhow!("Home sync snapshot digest does not match"));
    }
    let snapshot: hal_storage::HomeSyncSnapshot = serde_json::from_slice(&plaintext)?;
    if snapshot.version != 1 {
        return Err(anyhow!(
            "unsupported Home sync snapshot version: {}",
            snapshot.version
        ));
    }
    Ok(snapshot)
}

fn derive_home_sync_key(home_secret: &HomeSecret) -> Result<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(
        Some(HOME_SYNC_AAD_PREFIX.as_bytes()),
        home_secret.as_bytes(),
    );
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"snapshot chunk encryption", key.as_mut())
        .map_err(|_| anyhow!("could not derive Home sync encryption key"))?;
    Ok(key)
}

fn chunk_aad(transfer_id: &str, index: u32, total: u32, digest: &str) -> Vec<u8> {
    format!(
        "{}|{}|{}|{}|{}",
        HOME_SYNC_AAD_PREFIX, transfer_id, index, total, digest
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot_with_text(text: &str) -> hal_storage::HomeSyncSnapshot {
        hal_storage::HomeSyncSnapshot {
            version: 1,
            circles: Vec::new(),
            contacts: Vec::new(),
            groups: Vec::new(),
            messages: vec![hal_storage::HomeSyncMessage {
                id: "message-1".to_string(),
                chat_id: "peer-1".to_string(),
                sender_id: "sender-1".to_string(),
                kind: "text".to_string(),
                content: Some(text.to_string()),
                timestamp: 100,
                reactions: "[]".to_string(),
                group_id: None,
                reply_to_id: None,
                is_read: false,
                delivery_status: "sent".to_string(),
                sender_public_key: None,
            }],
            file_transfers: Vec::new(),
            media_files: Vec::new(),
        }
    }

    #[test]
    fn encrypted_home_sync_snapshot_roundtrips_across_chunks() {
        let secret = HomeSecret::from_bytes([0x4a; 32]);
        let snapshot = snapshot_with_text(&"x".repeat(HOME_SYNC_CHUNK_BYTES + 100));
        let chunks = seal_home_sync_snapshot(&snapshot, &secret).expect("seal snapshot");

        assert_eq!(chunks.len(), 2);
        assert!(chunks
            .iter()
            .all(|chunk| chunk.encrypted.ciphertext.len() <= HOME_SYNC_CHUNK_BYTES + 16));
        let shuffled = chunks.iter().rev().cloned().collect::<Vec<_>>();
        assert_eq!(
            open_home_sync_snapshot(&shuffled, &secret).expect("open snapshot"),
            snapshot
        );
    }

    #[test]
    fn home_sync_snapshot_rejects_wrong_secret_and_tampered_chunk() {
        let secret = HomeSecret::from_bytes([0x4a; 32]);
        let mut chunks = seal_home_sync_snapshot(&snapshot_with_text("private"), &secret)
            .expect("seal snapshot");
        assert!(open_home_sync_snapshot(&chunks, &HomeSecret::from_bytes([0x4b; 32])).is_err());

        chunks[0].index = 1;
        assert!(open_home_sync_snapshot(&chunks, &secret).is_err());
    }
}
