use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Метрики trust-решений. Отдельно от DhtMetrics (сеть vs trust).
///
/// В первой итерации — только кумулятивные счётчики (denies + records).
/// Relationship counts (known/circle/unknown/banned) — TODO, отложены
/// до появления UI / запроса snapshot.
#[derive(Debug, Default)]
pub struct TrustMetrics {
    /// Отброшено: узел забанен.
    pub denies_banned: AtomicU64,

    /// Отброшено: stranger, rate limit исчерпан (входящие).
    pub denies_stranger_rate: AtomicU64,

    /// Отброшено: contact add, rate limit исчерпан.
    pub denies_contact_rate: AtomicU64,

    /// Отброшено: KnownHosts вернул Conflicted (подмена ключа).
    pub conflicted: AtomicU64,

    /// Записано сообщений (после успешной обработки).
    pub recorded_messages: AtomicU64,

    /// Записано контактов (после успешного add_contact).
    pub recorded_contacts: AtomicU64,

    /// Отправка cold-contact заблокирована из-за локального stigma.
    pub send_stigma_blocked_total: AtomicU64,

    /// Cold-contact отправка разрешена при состоянии Watching.
    pub send_watching_seen_total: AtomicU64,

    /// Получены envelopes от peers без предварительной KnownHosts-записи.
    pub envelope_cold_received_total: AtomicU64,

    /// Получены envelopes от уже известных peers.
    pub envelope_warm_received_total: AtomicU64,
}

impl TrustMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_denies_banned(&self) {
        self.denies_banned.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_denies_stranger_rate(&self) {
        self.denies_stranger_rate.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_denies_contact_rate(&self) {
        self.denies_contact_rate.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_conflicted(&self) {
        self.conflicted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_recorded_messages(&self) {
        self.recorded_messages.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_recorded_contacts(&self) {
        self.recorded_contacts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_send_stigma_blocked(&self) {
        self.send_stigma_blocked_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_send_watching_seen(&self) {
        self.send_watching_seen_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_envelope_cold_received(&self) {
        self.envelope_cold_received_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_envelope_warm_received(&self) {
        self.envelope_warm_received_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> TrustMetricsSnapshot {
        TrustMetricsSnapshot {
            denies_banned: self.denies_banned.load(Ordering::Relaxed),
            denies_stranger_rate: self.denies_stranger_rate.load(Ordering::Relaxed),
            denies_contact_rate: self.denies_contact_rate.load(Ordering::Relaxed),
            conflicted: self.conflicted.load(Ordering::Relaxed),
            recorded_messages: self.recorded_messages.load(Ordering::Relaxed),
            recorded_contacts: self.recorded_contacts.load(Ordering::Relaxed),
            send_stigma_blocked_total: self.send_stigma_blocked_total.load(Ordering::Relaxed),
            send_watching_seen_total: self.send_watching_seen_total.load(Ordering::Relaxed),
            envelope_cold_received_total: self.envelope_cold_received_total.load(Ordering::Relaxed),
            envelope_warm_received_total: self.envelope_warm_received_total.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustMetricsSnapshot {
    pub denies_banned: u64,
    pub denies_stranger_rate: u64,
    pub denies_contact_rate: u64,
    pub conflicted: u64,
    pub recorded_messages: u64,
    pub recorded_contacts: u64,
    pub send_stigma_blocked_total: u64,
    pub send_watching_seen_total: u64,
    pub envelope_cold_received_total: u64,
    pub envelope_warm_received_total: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_metrics_are_zero() {
        let metrics = TrustMetrics::new();
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.denies_banned, 0);
        assert_eq!(snapshot.denies_stranger_rate, 0);
        assert_eq!(snapshot.denies_contact_rate, 0);
        assert_eq!(snapshot.conflicted, 0);
        assert_eq!(snapshot.recorded_messages, 0);
        assert_eq!(snapshot.recorded_contacts, 0);
        assert_eq!(snapshot.send_stigma_blocked_total, 0);
        assert_eq!(snapshot.send_watching_seen_total, 0);
        assert_eq!(snapshot.envelope_cold_received_total, 0);
        assert_eq!(snapshot.envelope_warm_received_total, 0);
    }

    #[test]
    fn counters_increment() {
        let metrics = TrustMetrics::new();
        metrics.inc_denies_banned();
        metrics.inc_denies_banned();
        metrics.inc_denies_stranger_rate();
        metrics.inc_conflicted();
        metrics.inc_recorded_messages();
        metrics.inc_send_stigma_blocked();
        metrics.inc_send_watching_seen();
        metrics.inc_envelope_cold_received();
        metrics.inc_envelope_warm_received();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.denies_banned, 2);
        assert_eq!(snapshot.denies_stranger_rate, 1);
        assert_eq!(snapshot.conflicted, 1);
        assert_eq!(snapshot.recorded_messages, 1);
        assert_eq!(snapshot.send_stigma_blocked_total, 1);
        assert_eq!(snapshot.send_watching_seen_total, 1);
        assert_eq!(snapshot.envelope_cold_received_total, 1);
        assert_eq!(snapshot.envelope_warm_received_total, 1);
        assert_eq!(snapshot.denies_contact_rate, 0);
        assert_eq!(snapshot.recorded_contacts, 0);
    }

    #[test]
    fn snapshot_is_independent_copy() {
        let metrics = TrustMetrics::new();
        metrics.inc_denies_banned();
        let snapshot1 = metrics.snapshot();
        metrics.inc_denies_banned();
        let snapshot2 = metrics.snapshot();
        assert_eq!(snapshot1.denies_banned, 1);
        assert_eq!(snapshot2.denies_banned, 2);
    }
}
