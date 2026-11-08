use hal_settings::{ClusterZonePolicy, ClusterZoneUpdateMode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZoneObservationSource {
    CarrierNetwork,
    Wifi,
    CarrierNetworkAndWifi,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneObservation {
    pub zone_token: String,
    pub source: ZoneObservationSource,
    pub observed_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneUpdateDecision {
    Disabled,
    Unchanged,
    Candidate,
    Changed,
}

#[derive(Debug, Clone, Default)]
pub struct ZoneObservationTracker {
    current: Option<ZoneObservation>,
    candidate_token: Option<String>,
    candidate_observations: u8,
    last_sample_at: Option<u64>,
}

impl ZoneObservationTracker {
    pub fn current(&self) -> Option<&ZoneObservation> {
        self.current.as_ref()
    }

    pub fn can_sample(&self, policy: &ClusterZonePolicy, now: u64) -> bool {
        policy.is_enabled()
            && self
                .last_sample_at
                .is_none_or(|last| now >= last.saturating_add(policy.interval_seconds))
    }

    pub fn observe(
        &mut self,
        policy: &ClusterZonePolicy,
        observation: ZoneObservation,
    ) -> ZoneUpdateDecision {
        if matches!(policy.mode, ClusterZoneUpdateMode::Disabled) {
            return ZoneUpdateDecision::Disabled;
        }
        self.last_sample_at = Some(observation.observed_at);
        if self
            .current
            .as_ref()
            .is_some_and(|current| current.zone_token == observation.zone_token)
        {
            self.candidate_token = None;
            self.candidate_observations = 0;
            return ZoneUpdateDecision::Unchanged;
        }
        if self.candidate_token.as_ref() == Some(&observation.zone_token) {
            self.candidate_observations = self.candidate_observations.saturating_add(1);
        } else {
            self.candidate_token = Some(observation.zone_token.clone());
            self.candidate_observations = 1;
        }
        if self.candidate_observations < 2 {
            return ZoneUpdateDecision::Candidate;
        }
        self.current = Some(observation);
        self.candidate_token = None;
        self.candidate_observations = 0;
        ZoneUpdateDecision::Changed
    }
}

pub fn zone_token(
    epoch: u64,
    epoch_salt: &[u8],
    carrier_signals: &[&str],
    wifi_signals: &[&str],
) -> String {
    let mut carrier = carrier_signals
        .iter()
        .map(|value| value.as_bytes())
        .collect::<Vec<_>>();
    let mut wifi = wifi_signals
        .iter()
        .map(|value| value.as_bytes())
        .collect::<Vec<_>>();
    carrier.sort_unstable();
    wifi.sort_unstable();
    let mut hash = Sha256::new();
    hash.update(b"hal-infinity:zone:v1");
    hash.update(epoch.to_be_bytes());
    hash.update((epoch_salt.len() as u64).to_be_bytes());
    hash.update(epoch_salt);
    for (kind, values) in [(b'c', carrier), (b'w', wifi)] {
        hash.update([kind]);
        hash.update((values.len() as u64).to_be_bytes());
        for value in values {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value);
        }
    }
    hex::encode(hash.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ClusterZonePolicy {
        ClusterZonePolicy {
            mode: ClusterZoneUpdateMode::ManualOnly,
            ..ClusterZonePolicy::default()
        }
    }

    fn observation(token: &str, observed_at: u64) -> ZoneObservation {
        ZoneObservation {
            zone_token: token.into(),
            source: ZoneObservationSource::CarrierNetworkAndWifi,
            observed_at,
            expires_at: observed_at + 86_400,
        }
    }

    #[test]
    fn token_is_order_independent_and_rotates_with_salt() {
        let first = zone_token(7, b"salt", &["cell-b", "cell-a"], &["wifi-b", "wifi-a"]);
        let second = zone_token(7, b"salt", &["cell-a", "cell-b"], &["wifi-a", "wifi-b"]);
        assert_eq!(first, second);
        assert_ne!(
            first,
            zone_token(
                7,
                b"next-salt",
                &["cell-a", "cell-b"],
                &["wifi-a", "wifi-b"]
            )
        );
    }

    #[test]
    fn zone_change_requires_two_observations() {
        let mut tracker = ZoneObservationTracker::default();
        assert_eq!(
            tracker.observe(&policy(), observation("a", 100)),
            ZoneUpdateDecision::Candidate
        );
        assert_eq!(
            tracker.observe(&policy(), observation("a", 200)),
            ZoneUpdateDecision::Changed
        );
        assert_eq!(
            tracker.observe(&policy(), observation("b", 300)),
            ZoneUpdateDecision::Candidate
        );
        assert_eq!(
            tracker.observe(&policy(), observation("b", 400)),
            ZoneUpdateDecision::Changed
        );
    }

    #[test]
    fn disabled_policy_does_not_store_observation() {
        let mut tracker = ZoneObservationTracker::default();
        let disabled = ClusterZonePolicy::default();
        assert_eq!(
            tracker.observe(&disabled, observation("a", 100)),
            ZoneUpdateDecision::Disabled
        );
        assert!(tracker.current().is_none());
        assert!(!tracker.can_sample(&disabled, 100_000));
    }
}
