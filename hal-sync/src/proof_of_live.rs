//! PR-B7.1: ProofOfLive evaluator — aggregate all trackers into one status.

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::activity_tracker::ActivityTracker;
use crate::age_tracker::AgeTracker;
use crate::dht::NodeId;

pub const AGE_MIN_SECS: u64 = 7 * 86_400;
pub const UPTIME_MIN_RATIO: f32 = 0.80;
pub const UPTIME_WINDOW_SECS: u64 = 7 * 86_400;
pub const GRACE_SECS: u64 = 300;
pub const ACTIVITY_MIN_OBSERVATIONS: usize = 1;
pub const ACTIVITY_WINDOW_SECS: u64 = 30 * 86_400;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProofOfLiveStatus {
    Full,
    TooYoung { age_secs: u64 },
    LowUptime { ratio: f32 },
    NoActivity,
    InsufficientData,
}

impl ProofOfLiveStatus {
    pub fn is_full(&self) -> bool {
        matches!(self, Self::Full)
    }

    pub fn can_cold_contact(&self) -> bool {
        matches!(self, Self::Full)
    }

    pub fn can_issue_invite(&self) -> bool {
        matches!(self, Self::Full)
    }

    pub fn can_use_dht_store(&self) -> bool {
        matches!(self, Self::Full)
    }
}

pub struct ProofOfLive {
    age: Arc<Mutex<AgeTracker>>,
    activity: Arc<Mutex<ActivityTracker>>,
}

impl ProofOfLive {
    pub fn new(age: Arc<Mutex<AgeTracker>>, activity: Arc<Mutex<ActivityTracker>>) -> Self {
        Self { age, activity }
    }

    pub async fn status(&self, identity: &NodeId, now: u64) -> ProofOfLiveStatus {
        let age_tracker = self.age.lock().await;
        let first_seen = match age_tracker.first_seen(identity) {
            Ok(Some(ts)) => ts,
            Ok(None) | Err(_) => return ProofOfLiveStatus::InsufficientData,
        };
        let age_secs = now.saturating_sub(first_seen);
        if age_secs < AGE_MIN_SECS {
            return ProofOfLiveStatus::TooYoung { age_secs };
        }

        let mut activity_tracker = self.activity.lock().await;
        let observations = match activity_tracker
            .observations_since(identity, now.saturating_sub(ACTIVITY_WINDOW_SECS), now)
            .await
        {
            Ok(items) => items,
            Err(_) => return ProofOfLiveStatus::InsufficientData,
        };
        if observations.len() < ACTIVITY_MIN_OBSERVATIONS {
            return ProofOfLiveStatus::NoActivity;
        }

        let ratio = match activity_tracker
            .uptime_ratio(identity, UPTIME_WINDOW_SECS, GRACE_SECS, now)
            .await
        {
            Ok(r) => r,
            Err(_) => return ProofOfLiveStatus::InsufficientData,
        };
        if ratio < UPTIME_MIN_RATIO {
            return ProofOfLiveStatus::LowUptime { ratio };
        }

        ProofOfLiveStatus::Full
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use hal_storage::ClientStorage;

    use super::{
        ProofOfLive, ProofOfLiveStatus, ACTIVITY_MIN_OBSERVATIONS, ACTIVITY_WINDOW_SECS,
        AGE_MIN_SECS, GRACE_SECS, UPTIME_MIN_RATIO, UPTIME_WINDOW_SECS,
    };
    use crate::activity_tracker::ActivityTracker;
    use crate::age_tracker::AgeTracker;
    use crate::dht::NodeId;

    fn node(seed: u8) -> NodeId {
        NodeId::from_bytes([seed; 32])
    }

    fn tracker_pair() -> (
        PathBuf,
        Arc<tokio::sync::Mutex<AgeTracker>>,
        Arc<tokio::sync::Mutex<ActivityTracker>>,
    ) {
        let path = std::env::temp_dir().join(format!(
            "hal-proof-of-live-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        let storage = ClientStorage::open(&path, &[0x55; 32]).expect("open storage");
        let storage = Arc::new(std::sync::Mutex::new(storage));
        let age = Arc::new(tokio::sync::Mutex::new(AgeTracker::new(Arc::clone(
            &storage,
        ))));
        let activity = Arc::new(tokio::sync::Mutex::new(ActivityTracker::new(Arc::clone(
            &storage,
        ))));
        (path, age, activity)
    }

    fn cleanup(path: PathBuf) {
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn insufficient_data_when_no_first_seen() {
        let (path, age, activity) = tracker_pair();
        let identity = node(1);
        let status = ProofOfLive::new(age, activity)
            .status(&identity, 10_000)
            .await;
        assert_eq!(status, ProofOfLiveStatus::InsufficientData);
        cleanup(path);
    }

    #[tokio::test]
    async fn too_young_below_threshold() {
        let (path, age, activity) = tracker_pair();
        let identity = node(2);
        let now = AGE_MIN_SECS + 10_000;
        age.lock()
            .await
            .observe(identity, now - 3 * 86_400)
            .expect("observe");
        let status = ProofOfLive::new(age, activity).status(&identity, now).await;
        assert!(matches!(status, ProofOfLiveStatus::TooYoung { .. }));
        cleanup(path);
    }

    #[tokio::test]
    async fn no_activity_when_empty_observations() {
        let (path, age, activity) = tracker_pair();
        let identity = node(3);
        let now = AGE_MIN_SECS + 10_000;
        age.lock()
            .await
            .observe(identity, now - AGE_MIN_SECS)
            .expect("observe");
        let status = ProofOfLive::new(age, activity).status(&identity, now).await;
        assert_eq!(status, ProofOfLiveStatus::NoActivity);
        cleanup(path);
    }

    #[tokio::test]
    async fn low_uptime_when_sparse_observations() {
        let (path, age, activity) = tracker_pair();
        let identity = node(4);
        let now = AGE_MIN_SECS + 10_000;
        age.lock()
            .await
            .observe(identity, now - AGE_MIN_SECS)
            .expect("observe");
        activity
            .lock()
            .await
            .record(identity, "event-1".into(), now - UPTIME_WINDOW_SECS + 1)
            .await
            .expect("record");
        let status = ProofOfLive::new(age, activity).status(&identity, now).await;
        assert!(matches!(status, ProofOfLiveStatus::LowUptime { .. }));
        cleanup(path);
    }

    #[tokio::test]
    async fn full_when_all_conditions_met() {
        let (path, age, activity) = tracker_pair();
        let identity = node(5);
        let now = AGE_MIN_SECS + 10_000;
        age.lock()
            .await
            .observe(identity, now - AGE_MIN_SECS)
            .expect("observe");

        let mut tracker = activity.lock().await;
        for step in (0..UPTIME_WINDOW_SECS).step_by(300) {
            tracker
                .record(
                    identity,
                    format!("e-{step}"),
                    now - UPTIME_WINDOW_SECS + step,
                )
                .await
                .expect("record");
            if step % 900 == 0 {
                tracker.flush().await.expect("flush");
            }
        }
        drop(tracker);

        let status = ProofOfLive::new(age, activity).status(&identity, now).await;
        assert_eq!(status, ProofOfLiveStatus::Full);
        cleanup(path);
    }

    #[tokio::test]
    async fn age_just_over_threshold() {
        let (path, age, activity) = tracker_pair();
        let identity = node(6);
        let now = AGE_MIN_SECS + 1;
        age.lock().await.observe(identity, 1).expect("observe");
        let status = ProofOfLive::new(age, activity).status(&identity, now).await;
        assert_eq!(status, ProofOfLiveStatus::NoActivity);
        cleanup(path);
    }

    #[tokio::test]
    async fn uptime_exactly_at_threshold() {
        let (path, age, activity) = tracker_pair();
        let identity = node(7);
        let now = AGE_MIN_SECS + 1000;
        age.lock().await.observe(identity, 1).expect("observe");
        for step in [0, 1000, 2000, 3000] {
            activity
                .lock()
                .await
                .record(
                    identity,
                    format!("t-{step}"),
                    now - UPTIME_WINDOW_SECS + step,
                )
                .await
                .expect("record");
        }
        let status = ProofOfLive::new(age, activity).status(&identity, now).await;
        assert!(
            matches!(status, ProofOfLiveStatus::LowUptime { .. })
                || matches!(status, ProofOfLiveStatus::Full)
        );
        cleanup(path);
    }

    #[tokio::test]
    async fn full_status_methods_correct() {
        let status = ProofOfLiveStatus::Full;
        assert!(status.is_full());
        assert!(status.can_cold_contact());
        assert!(status.can_issue_invite());
        assert!(status.can_use_dht_store());
        assert!(!ProofOfLiveStatus::NoActivity.can_cold_contact());
    }
}
