use crate::integrity::IntegrityDisposition;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityWaveRecovery {
    pub wave_id: String,
    pub node_id: String,
    pub previous_disposition: IntegrityDisposition,
    pub attempted_at: u64,
    pub recheck_attempts: u32,
    pub cluster_confirmations: Vec<String>,
    pub last_recheck: u64,
}

impl IntegrityWaveRecovery {
    pub fn new(
        wave_id: String,
        node_id: String,
        previous_disposition: IntegrityDisposition,
        attempted_at: u64,
    ) -> Self {
        Self {
            wave_id,
            node_id,
            previous_disposition,
            attempted_at,
            recheck_attempts: 0,
            cluster_confirmations: Vec::new(),
            last_recheck: attempted_at,
        }
    }

    pub fn add_cluster_confirmation(&mut self, peer_id: String) {
        if !self.cluster_confirmations.contains(&peer_id) {
            self.cluster_confirmations.push(peer_id);
        }
    }

    pub fn has_quorum(&self, required_confirmations: usize) -> bool {
        self.cluster_confirmations.len() >= required_confirmations
    }

    pub fn can_retry(&self, max_attempts: u32, recheck_interval_secs: u64, now: u64) -> bool {
        self.recheck_attempts < max_attempts
            && now >= self.last_recheck.saturating_add(recheck_interval_secs)
    }

    pub fn record_attempt(&mut self, now: u64) {
        self.recheck_attempts = self.recheck_attempts.saturating_add(1);
        self.last_recheck = now;
    }

    pub fn is_expired(&self, ttl_secs: u64, now: u64) -> bool {
        now >= self.attempted_at.saturating_add(ttl_secs)
    }
}

pub fn try_recovery(
    recovery: &mut IntegrityWaveRecovery,
    reachable: bool,
    cluster_confirmed: bool,
) -> Option<IntegrityDisposition> {
    if cluster_confirmed || reachable {
        recovery.add_cluster_confirmation("self".to_string());
    }

    if recovery.has_quorum(2) {
        Some(recovery.previous_disposition)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_confirmation_restores_previous_disposition() {
        let mut recovery = IntegrityWaveRecovery::new(
            "wave-1".into(),
            "node-abc".into(),
            IntegrityDisposition::Active,
            1000,
        );
        recovery.add_cluster_confirmation("peer-1".into());
        assert_eq!(
            try_recovery(&mut recovery, true, false),
            Some(IntegrityDisposition::Active)
        );
    }

    #[test]
    fn duplicate_confirmations_do_not_inflate_quorum() {
        let mut recovery = IntegrityWaveRecovery::new(
            "wave-1".into(),
            "node-abc".into(),
            IntegrityDisposition::Restricted,
            1000,
        );
        recovery.add_cluster_confirmation("peer-1".into());
        recovery.add_cluster_confirmation("peer-1".into());
        assert!(!recovery.has_quorum(2));
        assert_eq!(recovery.cluster_confirmations.len(), 1);
    }

    #[test]
    fn retry_limit_and_ttl_are_enforced() {
        let mut recovery = IntegrityWaveRecovery::new(
            "wave-1".into(),
            "node-abc".into(),
            IntegrityDisposition::Active,
            1000,
        );
        recovery.last_recheck = 0;
        for attempt in 0..50 {
            let now = 1000 + attempt * 61;
            assert!(recovery.can_retry(50, 60, now));
            recovery.record_attempt(now);
        }
        assert!(!recovery.can_retry(50, 60, 5000));
        assert!(recovery.is_expired(5 * 86_400, 1000 + 6 * 86_400));
    }
}
