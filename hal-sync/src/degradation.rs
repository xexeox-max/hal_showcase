use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub const DEFAULT_DEGRADATION_REFRESH_FAILURES: u64 = 3;
pub const DEFAULT_DEGRADATION_BADGE_FAILURE_RATIO: f64 = 0.5;

#[derive(Debug, Default)]
pub struct DegradationState {
    active: AtomicBool,
    refresh_failures: AtomicU64,
    badge_failures: AtomicU64,
    stale_cache_events: AtomicU64,
    degraded_entered_total: AtomicU64,
    degraded_cleared_total: AtomicU64,
    pub degraded_unknown_rejected_total: AtomicU64,
    pub degraded_known_accepted_total: AtomicU64,
}

impl DegradationState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    pub fn activate(&self) {
        if !self.active.swap(true, Ordering::Relaxed) {
            self.degraded_entered_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn clear(&self) {
        if self.active.swap(false, Ordering::Relaxed) {
            self.degraded_cleared_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_refresh_failure(&self) {
        let failures = self.refresh_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= DEFAULT_DEGRADATION_REFRESH_FAILURES {
            self.activate();
        }
    }

    pub fn record_refresh_success(&self) {
        self.refresh_failures.store(0, Ordering::Relaxed);
        if self.is_active() {
            self.clear();
        }
    }

    pub fn record_badge_failure(&self) {
        self.badge_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_badge_success(&self) {
        self.badge_failures.store(0, Ordering::Relaxed);
        if self.is_active() {
            self.clear();
        }
    }

    pub fn observe_badge_round(&self, failed: u64, total: u64) {
        if total == 0 {
            return;
        }
        let ratio = failed as f64 / total as f64;
        if ratio >= DEFAULT_DEGRADATION_BADGE_FAILURE_RATIO {
            self.activate();
        } else if self.is_active() {
            self.clear();
        }
    }

    pub fn mark_stale_cache(&self) {
        self.stale_cache_events.fetch_add(1, Ordering::Relaxed);
        self.activate();
    }

    pub fn unknown_rejected(&self) {
        self.degraded_unknown_rejected_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn known_accepted(&self) {
        self.degraded_known_accepted_total
            .fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_activates_and_clears() {
        let state = DegradationState::new();
        assert!(!state.is_active());
        state.activate();
        assert!(state.is_active());
        state.clear();
        assert!(!state.is_active());
    }

    #[test]
    fn state_records_failure_thresholds() {
        let state = DegradationState::new();
        state.record_refresh_failure();
        state.record_refresh_failure();
        state.record_badge_failure();
        assert!(!state.is_active());
    }

    #[test]
    fn state_counts_unknown_rejections() {
        let state = DegradationState::new();
        state.activate();
        state.unknown_rejected();
        assert_eq!(
            state
                .degraded_unknown_rejected_total
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn state_counts_known_accepts() {
        let state = DegradationState::new();
        state.activate();
        state.known_accepted();
        assert_eq!(
            state.degraded_known_accepted_total.load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn state_tracks_stale_cache() {
        let state = DegradationState::new();
        state.mark_stale_cache();
        assert_eq!(state.stale_cache_events.load(Ordering::Relaxed), 1);
    }
}
