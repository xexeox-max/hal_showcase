use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DhtProfile {
    Recommended,
    Economy,
    Aggressive,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtPollerConfig {
    pub max_parallel: usize,
    pub channel_capacity: usize,
    pub rpc_timeout_secs: u64,
    pub refresh_interval_normal_secs: u64,
    pub refresh_interval_active_secs: u64,
    pub refresh_interval_battery_secs: u64,
    pub max_lookup_rounds: usize,
    pub profile: DhtProfile,
}

impl Default for DhtPollerConfig {
    fn default() -> Self {
        Self::recommended()
    }
}

impl DhtPollerConfig {
    pub fn recommended() -> Self {
        Self {
            max_parallel: 8,
            channel_capacity: 64,
            rpc_timeout_secs: 5,
            refresh_interval_normal_secs: 30 * 60,
            refresh_interval_active_secs: 10 * 60,
            refresh_interval_battery_secs: 60 * 60,
            max_lookup_rounds: 8,
            profile: DhtProfile::Recommended,
        }
    }

    pub fn economy() -> Self {
        Self {
            max_parallel: 4,
            channel_capacity: 32,
            rpc_timeout_secs: 8,
            refresh_interval_normal_secs: 60 * 60,
            refresh_interval_active_secs: 30 * 60,
            refresh_interval_battery_secs: 3 * 60 * 60,
            max_lookup_rounds: 6,
            profile: DhtProfile::Economy,
        }
    }

    pub fn aggressive() -> Self {
        Self {
            max_parallel: 16,
            channel_capacity: 128,
            rpc_timeout_secs: 3,
            refresh_interval_normal_secs: 15 * 60,
            refresh_interval_active_secs: 5 * 60,
            refresh_interval_battery_secs: 30 * 60,
            max_lookup_rounds: 10,
            profile: DhtProfile::Aggressive,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.max_parallel == 0 || self.max_parallel > 64 {
            return Err("max_parallel must be 1..=64".into());
        }
        if self.channel_capacity < 8 || self.channel_capacity > 1024 {
            return Err("channel_capacity must be 8..=1024".into());
        }
        if self.rpc_timeout_secs < 1 || self.rpc_timeout_secs > 60 {
            return Err("rpc_timeout_secs must be 1..=60".into());
        }
        if self.max_lookup_rounds == 0 || self.max_lookup_rounds > 32 {
            return Err("max_lookup_rounds must be 1..=32".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recommended_config_valid() {
        let config = DhtPollerConfig::recommended();
        assert!(config.validate().is_ok());
        assert_eq!(config.profile, DhtProfile::Recommended);
    }

    #[test]
    fn economy_config_valid() {
        let config = DhtPollerConfig::economy();
        assert!(config.validate().is_ok());
        assert_eq!(config.profile, DhtProfile::Economy);
    }

    #[test]
    fn aggressive_config_valid() {
        let config = DhtPollerConfig::aggressive();
        assert!(config.validate().is_ok());
        assert_eq!(config.profile, DhtProfile::Aggressive);
    }

    #[test]
    fn custom_config_rejects_invalid_max_parallel() {
        let mut config = DhtPollerConfig::recommended();
        config.max_parallel = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn custom_config_rejects_invalid_channel_capacity() {
        let mut config = DhtPollerConfig::recommended();
        config.channel_capacity = 7;
        assert!(config.validate().is_err());
    }
}
