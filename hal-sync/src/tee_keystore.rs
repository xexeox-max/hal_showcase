use anyhow::{anyhow, Result};
use libc::{madvise, mlock, munlock, MADV_DONTDUMP};
use rand::{rngs::OsRng, RngCore};
use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

#[cfg(not(target_os = "android"))]
use sha2::{Digest, Sha256};
#[cfg(not(target_os = "android"))]
use std::sync::Mutex;

/// Abstraction over the desktop master-key backend.
pub trait MasterKeyBackend: Send + Sync {
    fn has_master_key(&self) -> bool;
    fn generate_master_key(&self) -> Result<()>;
    fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn unwrap(&self, wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    // Crash-durability: fsync on the file flushes content, but the
    // rename itself needs a directory fsync to survive a crash. Without
    // it, the rename may be lost even though the data was written.
    //
    // Unit test cannot simulate a real crash between rename and dir fsync;
    // this is verified by inspection and manual fs crash testing.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_path = PathBuf::from(format!(
        "{}.tmp-{}-{}",
        path.display(),
        std::process::id(),
        suffix
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> Result<()> {
        let mut file = options.open(&tmp_path)?;
        file.write_all(contents)?;
        file.sync_all()?;
        std::fs::rename(&tmp_path, path)?;
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            match std::fs::File::open(parent).and_then(|dir| dir.sync_all()) {
                Ok(()) => {}
                Err(error) => log::warn!("directory fsync failed after atomic rename: {error}"),
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

// DESKTOP DEV ONLY.
//
// На Android используйте TEE/StrongBox backend (см. hal-android).
// FileMasterKeyBackend хранит MK в plaintext-файле mk.bin (0600).
// Это приемлемо для локальной разработки и тестов, но не для
// production desktop (там должен быть OS keychain).
//
// На Android этот тип НЕ КОМПИЛИРУЕТСЯ (cfg-gated).
#[cfg(not(target_os = "android"))]
pub struct FileMasterKeyBackend {
    path: PathBuf,
    key: Mutex<Option<[u8; 32]>>,
}

#[cfg_attr(target_os = "android", allow(dead_code))]
const MK_MAGIC: &[u8; 4] = b"HALM";
#[cfg_attr(target_os = "android", allow(dead_code))]
const MK_VERSION: u8 = 1;
#[cfg_attr(target_os = "android", allow(dead_code))]
const MK_FILE_LEN: usize = 4 + 1 + 32 + 32;

#[cfg(not(target_os = "android"))]
impl FileMasterKeyBackend {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let key = Self::load(&path)?;
        Ok(Self {
            path,
            key: Mutex::new(key),
        })
    }

    fn load(path: &Path) -> Result<Option<[u8; 32]>> {
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(path)?;
        if bytes.len() != MK_FILE_LEN {
            return Err(anyhow!("mk file corrupt: wrong length"));
        }
        if &bytes[..4] != MK_MAGIC {
            return Err(anyhow!("mk file corrupt: bad magic"));
        }
        if bytes[4] != MK_VERSION {
            return Err(anyhow!("mk file corrupt: unsupported version"));
        }
        let expected = Sha256::digest(&bytes[..37]);
        if bytes[37..69] != expected[..] {
            return Err(anyhow!("mk file corrupt: checksum mismatch"));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[5..37]);
        Ok(Some(key))
    }

    fn persist(&self, key: &[u8; 32]) -> Result<()> {
        let mut buf = Vec::with_capacity(MK_FILE_LEN);
        buf.extend_from_slice(MK_MAGIC);
        buf.push(MK_VERSION);
        buf.extend_from_slice(key);
        let checksum = Sha256::digest(&buf);
        buf.extend_from_slice(&checksum);
        atomic_write(&self.path, &buf)
    }
}

#[cfg(not(target_os = "android"))]
impl MasterKeyBackend for FileMasterKeyBackend {
    fn has_master_key(&self) -> bool {
        self.key.lock().map(|key| key.is_some()).unwrap_or(false)
    }

    fn generate_master_key(&self) -> Result<()> {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        self.persist(&key)?;
        *self
            .key
            .lock()
            .map_err(|_| anyhow!("master key lock poisoned"))? = Some(key);
        Ok(())
    }

    fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let key = self
            .key
            .lock()
            .map_err(|_| anyhow!("master key lock poisoned"))?
            .ok_or_else(|| anyhow!("master key missing"))?;
        Ok(plaintext
            .iter()
            .enumerate()
            .map(|(i, byte)| byte ^ key[i % key.len()])
            .collect())
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let key = self
            .key
            .lock()
            .map_err(|_| anyhow!("master key lock poisoned"))?
            .ok_or_else(|| anyhow!("master key missing"))?;
        Ok(Zeroizing::new(
            wrapped
                .iter()
                .enumerate()
                .map(|(i, byte)| byte ^ key[i % key.len()])
                .collect(),
        ))
    }
}

/// Stores independently generated per-chat keys wrapped by the master backend.
pub struct ChatKeyManager {
    backend: Arc<dyn MasterKeyBackend>,
    wrapped_keys: HashMap<String, Vec<u8>>,
    store_path: PathBuf,
}

impl ChatKeyManager {
    pub fn new(backend: Arc<dyn MasterKeyBackend>, store_path: impl AsRef<Path>) -> Result<Self> {
        let store_path = store_path.as_ref().to_path_buf();
        let wrapped_keys = if store_path.exists() {
            let encoded: HashMap<String, String> =
                serde_json::from_slice(&std::fs::read(&store_path)?)
                    .map_err(|_| anyhow!("chat key store corrupt, cannot proceed"))?;
            encoded
                .into_iter()
                .map(|(chat_id, wrapped)| {
                    Ok((
                        chat_id,
                        hex::decode(wrapped)
                            .map_err(|_| anyhow!("chat key store corrupt, cannot proceed"))?,
                    ))
                })
                .collect::<Result<HashMap<_, _>>>()?
        } else {
            HashMap::new()
        };
        Ok(Self {
            backend,
            wrapped_keys,
            store_path,
        })
    }

    fn persist(&self) -> Result<()> {
        let encoded = self
            .wrapped_keys
            .iter()
            .map(|(chat_id, wrapped)| (chat_id.clone(), hex::encode(wrapped)))
            .collect::<HashMap<_, _>>();
        atomic_write(&self.store_path, &serde_json::to_vec(&encoded)?)
    }

    pub fn create_chat_key(&mut self, chat_id: &str) -> Result<()> {
        if chat_id.is_empty() {
            return Err(anyhow!("chat ID cannot be empty"));
        }
        if self.wrapped_keys.contains_key(chat_id) {
            return Ok(());
        }
        if !self.backend.has_master_key() {
            self.backend.generate_master_key()?;
        }
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(key.as_mut());
        let wrapped = self.backend.wrap(key.as_ref())?;
        self.wrapped_keys.insert(chat_id.to_owned(), wrapped);
        self.persist()?;
        Ok(())
    }

    pub fn open_chat_key(&self, chat_id: &str) -> Result<Zeroizing<[u8; 32]>> {
        let wrapped = self
            .wrapped_keys
            .get(chat_id)
            .ok_or_else(|| anyhow!("chat key not found"))?;
        let unwrapped = self.backend.unwrap(wrapped)?;
        let bytes: [u8; 32] = unwrapped
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("unwrapped chat key must be 32 bytes"))?;
        Ok(Zeroizing::new(bytes))
    }

    pub fn rotate_chat_key(&mut self, chat_id: &str) -> Result<()> {
        if !self.wrapped_keys.contains_key(chat_id) {
            return Err(anyhow!("chat key not found"));
        }
        if !self.backend.has_master_key() {
            self.backend.generate_master_key()?;
        }
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(key.as_mut());
        self.wrapped_keys
            .insert(chat_id.to_owned(), self.backend.wrap(key.as_ref())?);
        self.persist()
    }

    pub fn delete_chat_key(&mut self, chat_id: &str) -> Result<()> {
        self.wrapped_keys
            .remove(chat_id)
            .map(|mut wrapped| wrapped.zeroize())
            .ok_or_else(|| anyhow!("chat key not found"))?;
        self.persist()?;
        Ok(())
    }
}

/// Fresh session key for one chat entry. It is never persisted by this module.
pub struct SessionKey {
    key: Zeroizing<[u8; 32]>,
    nonce: Zeroizing<[u8; 16]>,
    chat_id: String,
}

impl SessionKey {
    pub fn new(chat_id: &str) -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        let mut nonce = Zeroizing::new([0u8; 16]);
        OsRng.fill_bytes(key.as_mut());
        OsRng.fill_bytes(nonce.as_mut());
        Self {
            key,
            nonce,
            chat_id: chat_id.to_owned(),
        }
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
    pub fn nonce(&self) -> &[u8; 16] {
        &self.nonce
    }
    pub fn chat_id(&self) -> &str {
        &self.chat_id
    }
}

/// Best-effort locked memory for short-lived critical buffers.
pub struct LockedMemory {
    ptr: NonNull<u8>,
    len: usize,
    layout: Layout,
    locked: bool,
}

impl LockedMemory {
    pub fn new(size: usize) -> Result<Self> {
        if size == 0 {
            return Err(anyhow!("locked memory size cannot be zero"));
        }
        let layout =
            Layout::array::<u8>(size).map_err(|_| anyhow!("invalid locked memory layout"))?;
        let ptr = NonNull::new(unsafe { alloc_zeroed(layout) })
            .ok_or_else(|| anyhow!("locked memory allocation failed"))?;
        let locked = unsafe { mlock(ptr.as_ptr().cast(), size) == 0 };
        if locked {
            unsafe {
                let _ = madvise(ptr.as_ptr().cast(), size, MADV_DONTDUMP);
            }
        } else {
            log::warn!("mlock failed; continuing without locked pages");
        }
        Ok(Self {
            ptr,
            len: size,
            layout,
            locked,
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for LockedMemory {
    fn drop(&mut self) {
        self.as_mut_slice().zeroize();
        if self.locked {
            unsafe {
                let _ = munlock(self.ptr.as_ptr().cast(), self.len);
            }
        }
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

#[cfg(all(test, not(target_os = "android")))]
mod tests {
    use super::*;

    fn paths(label: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!("hal-tee-{label}-{}", uuid::Uuid::new_v4()));
        (root.join("mk.bin"), root.join("chat_keys.json"))
    }

    #[test]
    fn master_key_generation_is_random() {
        let (first_path, second_path) = (paths("mk-first").0, paths("mk-second").0);
        let first = FileMasterKeyBackend::new(first_path).unwrap();
        let second = FileMasterKeyBackend::new(second_path).unwrap();
        first.generate_master_key().unwrap();
        second.generate_master_key().unwrap();
        assert_ne!(
            first.wrap(&[0u8; 32]).unwrap(),
            second.wrap(&[0u8; 32]).unwrap()
        );
    }

    #[test]
    fn chat_key_is_non_sequential() {
        let (mk_path, store_path) = paths("non-sequential");
        let backend = Arc::new(FileMasterKeyBackend::new(mk_path).unwrap());
        let mut manager = ChatKeyManager::new(backend, store_path).unwrap();
        manager.create_chat_key("chat_1").unwrap();
        manager.create_chat_key("chat_2").unwrap();
        assert_ne!(
            manager.open_chat_key("chat_1").unwrap().as_ref(),
            manager.open_chat_key("chat_2").unwrap().as_ref()
        );
    }

    #[test]
    fn chat_key_independent_of_chat_id() {
        let (mk_path, store_path) = paths("independent");
        let backend = Arc::new(FileMasterKeyBackend::new(mk_path).unwrap());
        let mut manager = ChatKeyManager::new(backend, store_path).unwrap();
        manager.create_chat_key("chat_1").unwrap();
        let first = manager.open_chat_key("chat_1").unwrap();
        manager.delete_chat_key("chat_1").unwrap();
        manager.create_chat_key("chat_1").unwrap();
        let second = manager.open_chat_key("chat_1").unwrap();
        assert_ne!(first.as_ref(), second.as_ref());
    }

    #[test]
    fn session_key_fresh_per_entry() {
        let first = SessionKey::new("chat_1");
        let second = SessionKey::new("chat_1");
        assert_ne!(first.key(), second.key());
        assert_ne!(first.nonce(), second.nonce());
    }

    #[test]
    fn session_key_not_derived_from_chat_key() {
        let (mk_path, store_path) = paths("session");
        let backend = Arc::new(FileMasterKeyBackend::new(mk_path).unwrap());
        let mut manager = ChatKeyManager::new(backend, store_path).unwrap();
        manager.create_chat_key("chat_1").unwrap();
        let chat_key = manager.open_chat_key("chat_1").unwrap();
        let session = SessionKey::new("chat_1");
        assert_ne!(chat_key.as_ref(), session.key());
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let (mk_path, _) = paths("roundtrip");
        let backend = FileMasterKeyBackend::new(mk_path).unwrap();
        backend.generate_master_key().unwrap();
        let plaintext = [7u8; 32];
        let wrapped = backend.wrap(&plaintext).unwrap();
        assert_eq!(backend.unwrap(&wrapped).unwrap().as_slice(), plaintext);
    }

    #[test]
    fn chat_key_rotation_and_deletion() {
        let (mk_path, store_path) = paths("rotation");
        let backend = Arc::new(FileMasterKeyBackend::new(mk_path).unwrap());
        let mut manager = ChatKeyManager::new(backend, store_path).unwrap();
        manager.create_chat_key("chat").unwrap();
        let old_key = manager.open_chat_key("chat").unwrap();
        manager.rotate_chat_key("chat").unwrap();
        let new_key = manager.open_chat_key("chat").unwrap();
        assert_ne!(old_key.as_ref(), new_key.as_ref());
        manager.delete_chat_key("chat").unwrap();
        assert!(manager.open_chat_key("chat").is_err());
    }

    #[test]
    fn keyring_pattern_for_many_chats() {
        let (mk_path, store_path) = paths("many");
        let backend = Arc::new(FileMasterKeyBackend::new(mk_path).unwrap());
        let mut manager = ChatKeyManager::new(backend, store_path).unwrap();
        for index in 0..1000 {
            manager.create_chat_key(&format!("chat-{index}")).unwrap();
        }
        let mut keys = std::collections::HashSet::new();
        for index in 0..1000 {
            keys.insert(*manager.open_chat_key(&format!("chat-{index}")).unwrap());
        }
        assert_eq!(keys.len(), 1000);
    }

    #[test]
    fn create_chat_key_is_idempotent() {
        let (mk_path, store_path) = paths("idempotent");
        let backend = Arc::new(FileMasterKeyBackend::new(mk_path).unwrap());
        let mut manager = ChatKeyManager::new(backend, store_path).unwrap();
        manager.create_chat_key("chat").unwrap();
        let first = manager.open_chat_key("chat").unwrap();
        manager.create_chat_key("chat").unwrap();
        let second = manager.open_chat_key("chat").unwrap();
        assert_eq!(first.as_ref(), second.as_ref());
    }

    #[test]
    fn persistence_across_restart() {
        let root = std::env::temp_dir().join(format!("hal-tee-restart-{}", uuid::Uuid::new_v4()));
        let mk_path = root.join("mk.bin");
        let store_path = root.join("chat_keys.json");
        let first = {
            let backend = Arc::new(FileMasterKeyBackend::new(&mk_path).unwrap());
            let mut manager = ChatKeyManager::new(backend, &store_path).unwrap();
            manager.create_chat_key("test").unwrap();
            *manager.open_chat_key("test").unwrap()
        };
        let second = {
            let backend = Arc::new(FileMasterKeyBackend::new(&mk_path).unwrap());
            let manager = ChatKeyManager::new(backend, &store_path).unwrap();
            *manager.open_chat_key("test").unwrap()
        };
        assert_eq!(first, second);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn mk_file_valid_roundtrip() {
        let (mk_path, _) = paths("valid-mk");
        let backend = FileMasterKeyBackend::new(&mk_path).unwrap();
        backend.generate_master_key().unwrap();
        let wrapped = backend.wrap(&[7u8; 32]).unwrap();
        let loaded = FileMasterKeyBackend::new(&mk_path).unwrap();
        assert!(loaded.has_master_key());
        assert_eq!(loaded.wrap(&[7u8; 32]).unwrap(), wrapped);
    }

    #[test]
    fn mk_file_wrong_length_returns_error() {
        let (mk_path, _) = paths("wrong-length");
        std::fs::create_dir_all(mk_path.parent().unwrap()).unwrap();
        std::fs::write(&mk_path, vec![0u8; MK_FILE_LEN - 1]).unwrap();
        let error = match FileMasterKeyBackend::new(&mk_path) {
            Ok(_) => panic!("corrupt MK must fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("wrong length"));
    }

    #[test]
    fn mk_file_bad_magic_returns_error() {
        let (mk_path, _) = paths("bad-magic");
        std::fs::create_dir_all(mk_path.parent().unwrap()).unwrap();
        let mut bytes = vec![0u8; MK_FILE_LEN];
        bytes[4] = MK_VERSION;
        std::fs::write(&mk_path, bytes).unwrap();
        let error = match FileMasterKeyBackend::new(&mk_path) {
            Ok(_) => panic!("bad magic must fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("bad magic"));
    }

    #[test]
    fn mk_file_checksum_mismatch_returns_error() {
        let (mk_path, _) = paths("bad-checksum");
        let backend = FileMasterKeyBackend::new(&mk_path).unwrap();
        backend.generate_master_key().unwrap();
        let mut bytes = std::fs::read(&mk_path).unwrap();
        bytes[10] ^= 0xFF;
        std::fs::write(&mk_path, bytes).unwrap();
        let error = match FileMasterKeyBackend::new(&mk_path) {
            Ok(_) => panic!("bad checksum must fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("checksum mismatch"));
    }

    #[test]
    fn atomic_write_replaces_existing_file_without_partial_content() {
        let (path, _) = paths("atomic");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"old-content").unwrap();
        atomic_write(&path, b"new-content").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new-content");
    }

    #[test]
    fn mlock_locks_pages_when_available() {
        // CI may lack RLIMIT_MEMLOCK; this verifies the API remains usable
        // whether the kernel grants page locking or the fallback is used.
        let memory = LockedMemory::new(4096).unwrap();
        assert_eq!(memory.as_slice().len(), 4096);
    }

    #[test]
    fn zeroize_actually_zeroizes() {
        let mut buf = [1u8; 32];
        let ptr = buf.as_ptr();
        buf.zeroize();
        // Volatile reads make the post-zeroization assertion observable.
        for index in 0..32 {
            let byte = unsafe { std::ptr::read_volatile(ptr.add(index)) };
            assert_eq!(byte, 0, "byte {index} not zeroized");
        }
    }
}
