use serde::{Deserialize, Serialize};

use super::config::DhtPollerConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BatteryContext {
    ChargingWifi,
    ChargingMobile,
    BatteryWifi,
    BatteryMobile,
}

impl BatteryContext {
    pub fn refresh_interval_secs(self, config: &DhtPollerConfig) -> u64 {
        match self {
            BatteryContext::ChargingWifi => config.refresh_interval_active_secs,
            BatteryContext::ChargingMobile => config.refresh_interval_normal_secs,
            BatteryContext::BatteryWifi => config.refresh_interval_normal_secs,
            BatteryContext::BatteryMobile => config.refresh_interval_battery_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charging_wifi_uses_active_interval() {
        let config = DhtPollerConfig::recommended();
        assert_eq!(
            BatteryContext::ChargingWifi.refresh_interval_secs(&config),
            config.refresh_interval_active_secs
        );
    }

    #[test]
    fn battery_mobile_uses_battery_interval() {
        let config = DhtPollerConfig::recommended();
        assert_eq!(
            BatteryContext::BatteryMobile.refresh_interval_secs(&config),
            config.refresh_interval_battery_secs
        );
    }
}
