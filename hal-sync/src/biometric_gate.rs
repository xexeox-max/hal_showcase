//! Biometric gate abstraction. Per B6_TIER_BIOMETRIC.md §3.
//!
//! The gate is platform-agnostic; Android implements it over
//! BiometricPrompt, desktop may use OS-native, tests use MockBiometricGate.
//! Core (hal-sync) does not know about the platform API.

use async_trait::async_trait;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BiometricError {
    /// Platform does not support biometric confirmation.
    Unavailable,
    /// User rejected or dismissed the prompt.
    Rejected,
    /// Too many failed attempts; platform locked.
    Locked,
    /// Platform-specific error (JNI failure, timeout, etc.).
    Platform(String),
}

impl fmt::Display for BiometricError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => write!(f, "biometric unavailable"),
            Self::Rejected => write!(f, "biometric rejected"),
            Self::Locked => write!(f, "biometric locked"),
            Self::Platform(msg) => write!(f, "biometric platform error: {msg}"),
        }
    }
}

impl std::error::Error for BiometricError {}

/// Platform-agnostic biometric confirmation gate.
/// Per B6_TIER_BIOMETRIC.md §3.
#[async_trait]
pub trait BiometricGate: Send + Sync {
    /// Request user confirmation. `prompt` is UI-facing text.
    /// Returns Ok(()) on confirmation, Err on rejection/failure.
    async fn verify(&self, prompt: &str) -> Result<(), BiometricError>;

    /// Whether biometric confirmation is available on the platform.
    /// If false, B6.4 policy degrades to AgeProof.
    fn is_available(&self) -> bool;
}

/// Programmable gate for tests. Per B6_TIER_BIOMETRIC.md §3.
pub struct MockBiometricGate {
    available: bool,
    response: std::sync::Mutex<MockResponse>,
}

#[derive(Debug, Clone)]
pub enum MockResponse {
    Ok,
    Rejected,
    Locked,
    Unavailable,
    Platform(String),
}

impl MockBiometricGate {
    pub fn new(available: bool) -> Self {
        Self {
            available,
            response: std::sync::Mutex::new(MockResponse::Ok),
        }
    }

    pub fn set_response(&self, response: MockResponse) {
        let mut current = match self.response.lock() {
            Ok(current) => current,
            Err(poisoned) => {
                log::error!("mock biometric response lock poisoned; recovering state");
                poisoned.into_inner()
            }
        };
        *current = response;
    }
}

#[async_trait]
impl BiometricGate for MockBiometricGate {
    async fn verify(&self, _prompt: &str) -> Result<(), BiometricError> {
        let response = self.response.lock().map_err(|error| {
            log::error!("mock biometric response lock poisoned: {error}");
            BiometricError::Platform("mock response lock poisoned".into())
        })?;
        match response.clone() {
            MockResponse::Ok => Ok(()),
            MockResponse::Rejected => Err(BiometricError::Rejected),
            MockResponse::Locked => Err(BiometricError::Locked),
            MockResponse::Unavailable => Err(BiometricError::Unavailable),
            MockResponse::Platform(msg) => Err(BiometricError::Platform(msg)),
        }
    }

    fn is_available(&self) -> bool {
        self.available
    }
}

#[cfg(test)]
mod tests {
    use super::{BiometricError, BiometricGate, MockBiometricGate, MockResponse};
    use std::sync::Arc;

    #[test]
    fn mock_available_true() {
        assert!(MockBiometricGate::new(true).is_available());
    }

    #[test]
    fn mock_available_false() {
        assert!(!MockBiometricGate::new(false).is_available());
    }

    #[tokio::test]
    async fn mock_verify_ok() {
        let gate = MockBiometricGate::new(true);
        gate.set_response(MockResponse::Ok);
        assert_eq!(gate.verify("confirm").await, Ok(()));
    }

    #[tokio::test]
    async fn mock_verify_rejected() {
        let gate = MockBiometricGate::new(true);
        gate.set_response(MockResponse::Rejected);
        assert_eq!(gate.verify("confirm").await, Err(BiometricError::Rejected));
    }

    #[tokio::test]
    async fn mock_verify_locked() {
        let gate = MockBiometricGate::new(true);
        gate.set_response(MockResponse::Locked);
        assert_eq!(gate.verify("confirm").await, Err(BiometricError::Locked));
    }

    #[tokio::test]
    async fn mock_verify_unavailable() {
        let gate = MockBiometricGate::new(true);
        gate.set_response(MockResponse::Unavailable);
        assert_eq!(
            gate.verify("confirm").await,
            Err(BiometricError::Unavailable)
        );
    }

    #[tokio::test]
    async fn mock_verify_platform_error() {
        let gate = MockBiometricGate::new(true);
        gate.set_response(MockResponse::Platform("x".into()));
        assert_eq!(
            gate.verify("confirm").await,
            Err(BiometricError::Platform("x".into()))
        );
    }

    #[tokio::test]
    async fn mock_response_switchable() {
        let gate = MockBiometricGate::new(true);
        assert_eq!(gate.verify("confirm").await, Ok(()));
        gate.set_response(MockResponse::Rejected);
        assert_eq!(gate.verify("confirm").await, Err(BiometricError::Rejected));
    }

    #[test]
    fn biometric_error_display() {
        assert_eq!(
            BiometricError::Unavailable.to_string(),
            "biometric unavailable"
        );
        assert_eq!(BiometricError::Rejected.to_string(), "biometric rejected");
        assert_eq!(BiometricError::Locked.to_string(), "biometric locked");
        assert_eq!(
            BiometricError::Platform("x".into()).to_string(),
            "biometric platform error: x"
        );
    }

    #[tokio::test]
    async fn gate_object_safe() {
        let gate: Arc<dyn BiometricGate> = Arc::new(MockBiometricGate::new(true));
        assert!(gate.is_available());
        assert_eq!(gate.verify("confirm").await, Ok(()));
    }
}
