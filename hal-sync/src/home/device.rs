use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceRole {
    Primary,
    Secondary,
    Mobile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCapabilities {
    pub storage_quota_bytes: u64,
    pub cpu_cores: u8,
    pub is_always_on: bool,
    pub has_tee: bool,
}

impl Default for DeviceCapabilities {
    fn default() -> Self {
        Self {
            storage_quota_bytes: 0,
            cpu_cores: 0,
            is_always_on: false,
            has_tee: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub device_pubkey: String,
    pub stack_id: String,
    pub added_at: u64,
    pub added_by: String,
    pub role: DeviceRole,
    pub last_seen: u64,
    pub capabilities: DeviceCapabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomeStack {
    pub stack_id: String,
    pub primary_device_id: String,
    pub devices: HashMap<String, DeviceInfo>,
    pub used_link_nonces: HashSet<String>,
}

impl HomeStack {
    pub fn new(stack_id: String, primary_device_id: String) -> Self {
        Self {
            stack_id,
            primary_device_id,
            devices: HashMap::new(),
            used_link_nonces: HashSet::new(),
        }
    }

    pub fn add_device(&mut self, info: DeviceInfo) -> Result<()> {
        if info.stack_id != self.stack_id {
            return Err(anyhow!("device does not belong to this stack"));
        }
        if self.devices.contains_key(&info.device_id) {
            return Err(anyhow!("device already linked: {}", info.device_id));
        }
        self.devices.insert(info.device_id.clone(), info);
        Ok(())
    }

    pub fn remove_device(&mut self, device_id: &str) -> Result<()> {
        if !self.devices.contains_key(device_id) {
            return Err(anyhow!("device not found: {}", device_id));
        }
        self.devices.remove(device_id);
        Ok(())
    }

    pub fn get_device(&self, device_id: &str) -> Option<&DeviceInfo> {
        self.devices.get(device_id)
    }

    pub fn is_linked(&self, device_id: &str) -> bool {
        self.devices.contains_key(device_id)
    }

    pub fn record_link_nonce(&mut self, nonce_hex: String) -> Result<()> {
        if self.used_link_nonces.contains(&nonce_hex) {
            return Err(anyhow!("nonce already used: {}", nonce_hex));
        }
        self.used_link_nonces.insert(nonce_hex);
        Ok(())
    }

    pub fn has_link_nonce(&self, nonce_hex: &str) -> bool {
        self.used_link_nonces.contains(nonce_hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_device(device_id: &str, stack_id: &str) -> DeviceInfo {
        DeviceInfo {
            device_id: device_id.to_string(),
            device_pubkey: format!("pub-{device_id}"),
            stack_id: stack_id.to_string(),
            added_at: 100,
            added_by: "primary".to_string(),
            role: DeviceRole::Mobile,
            last_seen: 100,
            capabilities: DeviceCapabilities::default(),
        }
    }

    #[test]
    fn add_remove_device() {
        let mut stack = HomeStack::new("stack-1".into(), "primary".into());
        let device = sample_device("mobile-1", "stack-1");
        stack.add_device(device.clone()).expect("add");
        assert_eq!(stack.get_device("mobile-1").unwrap().device_id, "mobile-1");
        stack.remove_device("mobile-1").expect("remove");
        assert!(stack.get_device("mobile-1").is_none());
    }

    #[test]
    fn record_nonce_rejects_replay() {
        let mut stack = HomeStack::new("stack-1".into(), "primary".into());
        stack.record_link_nonce("nonce-1".into()).expect("first");
        assert!(stack.record_link_nonce("nonce-1".into()).is_err());
    }

    #[test]
    fn is_linked_after_add() {
        let mut stack = HomeStack::new("stack-1".into(), "primary".into());
        stack
            .add_device(sample_device("mobile-2", "stack-1"))
            .expect("add");
        assert!(stack.is_linked("mobile-2"));
    }
}
