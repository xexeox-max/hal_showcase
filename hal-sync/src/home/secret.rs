use anyhow::{anyhow, Result};
use rand::{rngs::OsRng, RngCore};
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::tee_keystore::MasterKeyBackend;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HomeSecret(Zeroizing<[u8; 32]>);

impl HomeSecret {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(Zeroizing::new(bytes))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub struct HomeSecretStore {
    backend: Arc<dyn MasterKeyBackend>,
    wrapped: Option<Vec<u8>>,
}

impl HomeSecretStore {
    pub fn new(backend: Arc<dyn MasterKeyBackend>) -> Self {
        Self {
            backend,
            wrapped: None,
        }
    }

    pub fn load_or_generate(&mut self) -> Result<HomeSecret> {
        if let Some(_) = self.wrapped {
            return self.get();
        }
        if !self.backend.has_master_key() {
            self.backend.generate_master_key()?;
        }
        let secret = HomeSecret::generate();
        let wrapped = self.backend.wrap(secret.as_bytes())?;
        self.wrapped = Some(wrapped);
        Ok(secret)
    }

    pub fn set_wrapped(&mut self, wrapped: Vec<u8>) {
        self.wrapped = Some(wrapped);
    }

    pub fn wrapped(&self) -> Option<&[u8]> {
        self.wrapped.as_deref()
    }

    pub fn get(&self) -> Result<HomeSecret> {
        let wrapped = self
            .wrapped
            .as_ref()
            .ok_or_else(|| anyhow!("home secret is not set"))?;
        let unwrapped = self.backend.unwrap(wrapped)?;
        let bytes: [u8; 32] = unwrapped
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("home secret must be 32 bytes"))?;
        Ok(HomeSecret::from_bytes(bytes))
    }

    pub fn set(&mut self, secret: HomeSecret) -> Result<()> {
        if !self.backend.has_master_key() {
            self.backend.generate_master_key()?;
        }
        let wrapped = self.backend.wrap(secret.as_bytes())?;
        self.wrapped = Some(wrapped);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee_keystore::FileMasterKeyBackend;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_backend() -> Arc<dyn MasterKeyBackend> {
        let path = std::env::temp_dir().join(format!(
            "hal-home-secret-{}.bin",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        Arc::new(FileMasterKeyBackend::new(path).expect("mk backend"))
    }

    #[test]
    fn generate_creates_unique_secret() {
        let first = HomeSecret::generate();
        let second = HomeSecret::generate();
        assert_ne!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let backend = tmp_backend();
        backend.generate_master_key().expect("generate master key");
        let secret = HomeSecret::generate();
        let wrapped = backend.wrap(secret.as_bytes()).expect("wrap");
        let unwrapped = backend.unwrap(&wrapped).expect("unwrap");
        let bytes: [u8; 32] = unwrapped.as_slice().try_into().expect("length");
        assert_eq!(bytes, *secret.as_bytes());
    }

    #[test]
    fn set_then_get_preserves_value() {
        let backend = tmp_backend();
        let mut store = HomeSecretStore::new(backend);
        let secret = HomeSecret::generate();
        store.set(secret.clone()).expect("set");
        let loaded = store.get().expect("get");
        assert_eq!(loaded.as_bytes(), secret.as_bytes());
    }

    #[test]
    fn get_before_set_returns_error() {
        let backend = tmp_backend();
        let store = HomeSecretStore::new(backend);
        assert!(store.get().is_err());
    }
}
