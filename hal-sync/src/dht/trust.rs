use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::dht::NodeId;

/// Начальный score для нового узла.
pub const TRUST_INITIAL: u8 = 50;

/// Максимум и минимум.
pub const TRUST_MAX: u8 = 100;
pub const TRUST_MIN: u8 = 0;

/// Пороги для TrustAction.
pub const TRUST_BADGE_THRESHOLD: u8 = 30;
pub const TRUST_CONTACT_TIMEOUT_THRESHOLD: u8 = 20;
pub const TRUST_BLOCK_NEW_MESSAGES_THRESHOLD: u8 = 10;
pub const TRUST_BAN_THRESHOLD: u8 = 5;

/// Окно для метрик (1 час).
pub const METRICS_WINDOW_SECS: u64 = 3600;

/// Пороги поведения.
pub const BEHAVIOR_NORMAL_CONTACTS_MAX: u32 = 10;
pub const BEHAVIOR_SUSPICIOUS_CONTACTS_MAX: u32 = 100;
pub const BEHAVIOR_ANOMALOUS_CONTACTS_MAX: u32 = 200;
pub const BEHAVIOR_ANOMALOUS_STRANGER_MESSAGES: u32 = 200;
pub const BEHAVIOR_SUSPICIOUS_STRANGER_MESSAGES: u32 = 50;

/// Число warnings подряд, после которого применяется доп. штраф.
pub const WARNINGS_FOR_EXTRA_PENALTY: u32 = 5;
pub const EXTRA_PENALTY: u8 = 10;

// ============================================================
// TrustScore
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtTrustScore {
    node_id: NodeId,
    score: u8,
    warnings_count: u32,
    created_at: u64,
    last_updated_at: u64,
    last_penalized_at: Option<u64>,
    last_rewarded_at: Option<u64>,
}

impl DhtTrustScore {
    pub fn new(node_id: NodeId, now: u64) -> Self {
        Self {
            node_id,
            score: TRUST_INITIAL,
            warnings_count: 0,
            created_at: now,
            last_updated_at: now,
            last_penalized_at: None,
            last_rewarded_at: None,
        }
    }

    /// Применить delta: i16 (может быть отрицательным).
    /// Само clamp к 0..100.
    pub fn apply_delta(&mut self, delta: i16, now: u64) {
        let next = (self.score as i16 + delta).clamp(TRUST_MIN as i16, TRUST_MAX as i16) as u8;
        self.score = next;
        self.last_updated_at = now;

        match delta.cmp(&0) {
            std::cmp::Ordering::Less => {
                self.last_penalized_at = Some(now);
                self.last_rewarded_at = None;
            }
            std::cmp::Ordering::Greater => {
                self.last_rewarded_at = Some(now);
                self.last_penalized_at = None;
            }
            std::cmp::Ordering::Equal => {}
        }

        self.clamp();
    }

    /// Принудительно clamp.
    fn clamp(&mut self) {
        self.score = self.score.clamp(TRUST_MIN, TRUST_MAX);
    }
}

// ============================================================
// TrustAction
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustAction {
    Normal,
    ShowBadge,
    TimeoutContacts,
    BlockNewMessages,
    Ban,
}

impl TrustAction {
    pub fn from_score(score: u8) -> Self {
        match score {
            score if score >= TRUST_BADGE_THRESHOLD => Self::Normal,
            20..=29 => Self::ShowBadge,
            10..=19 => Self::TimeoutContacts,
            5..=9 => Self::BlockNewMessages,
            _ => Self::Ban,
        }
    }

    pub fn is_restricted(self) -> bool {
        matches!(
            self,
            Self::TimeoutContacts | Self::BlockNewMessages | Self::Ban
        )
    }

    /// Разрешает ли это action добавление контактов.
    pub fn allows_contact_add(self) -> bool {
        matches!(self, Self::Normal | Self::ShowBadge)
    }

    /// Разрешает ли это action отправку новых сообщений.
    pub fn allows_message_to_stranger(self) -> bool {
        matches!(self, Self::Normal | Self::ShowBadge)
    }

    /// Забанен ли узел.
    pub fn is_banned(self) -> bool {
        self == Self::Ban
    }
}

// ============================================================
// BehaviorMetrics
// ============================================================

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BehaviorMetrics {
    window_start: u64,
    messages_sent: u32,
    messages_to_strangers: u32,
    new_contacts: u32,
    unique_recipients: u32,
    messages_read_by_others: u32,
    replies_from_others: u32,
}

impl BehaviorMetrics {
    pub fn new(now: u64) -> Self {
        Self {
            window_start: now,
            ..Default::default()
        }
    }

    pub fn reset(&mut self, now: u64) {
        *self = Self::new(now);
    }

    pub fn is_window_expired(&self, now: u64) -> bool {
        now.saturating_sub(self.window_start) >= METRICS_WINDOW_SECS
    }

    pub fn is_anomalous(&self) -> bool {
        self.messages_to_strangers >= BEHAVIOR_ANOMALOUS_STRANGER_MESSAGES
            || self.new_contacts >= BEHAVIOR_ANOMALOUS_CONTACTS_MAX
    }

    pub fn is_suspicious(&self) -> bool {
        self.messages_to_strangers >= BEHAVIOR_SUSPICIOUS_STRANGER_MESSAGES
            || self.new_contacts > BEHAVIOR_NORMAL_CONTACTS_MAX
    }

    pub fn is_normal(&self) -> bool {
        !self.is_anomalous() && !self.is_suspicious()
    }
}

// ============================================================
// TrustScoreManager
// ============================================================

#[derive(Debug, Default)]
pub struct TrustScoreManager {
    scores: HashMap<NodeId, DhtTrustScore>,
    metrics: HashMap<NodeId, BehaviorMetrics>,
}

impl TrustScoreManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Score узла. Default — TRUST_INITIAL (50) если не отслеживается.
    pub fn score_of(&self, node_id: &NodeId) -> u8 {
        self.scores
            .get(node_id)
            .map(|score| score.score)
            .unwrap_or(TRUST_INITIAL)
    }

    /// Action узла на основе score.
    pub fn action_of(&self, node_id: &NodeId) -> TrustAction {
        TrustAction::from_score(self.score_of(node_id))
    }

    /// Убедиться, что узел отслеживается. Создаст с initial score.
    pub fn ensure(&mut self, node_id: NodeId, now: u64) {
        self.scores
            .entry(node_id)
            .or_insert_with(|| DhtTrustScore::new(node_id, now));
        self.metrics
            .entry(node_id)
            .or_insert_with(|| BehaviorMetrics::new(now));
    }

    /// Явно сбросить метрики для узла (для тестов и для будущего API).
    pub fn reset_metrics(&mut self, node_id: &NodeId, now: u64) {
        if let Some(metrics) = self.metrics.get_mut(node_id) {
            metrics.reset(now);
        }
    }

    /// Записать отправку сообщения.
    /// is_stranger — true, если получатель не в KnownHosts.
    pub fn record_message(&mut self, node_id: &NodeId, is_stranger: bool, now: u64) {
        self.ensure(*node_id, now);

        let metrics = self.metrics.get_mut(node_id).unwrap();
        if metrics.is_window_expired(now) {
            metrics.reset(now);
        }
        metrics.messages_sent += 1;
        if is_stranger {
            metrics.messages_to_strangers += 1;
        }
    }

    /// Записать добавление контакта.
    pub fn record_contact_add(&mut self, node_id: &NodeId, now: u64) {
        self.ensure(*node_id, now);

        let metrics = self.metrics.get_mut(node_id).unwrap();
        if metrics.is_window_expired(now) {
            metrics.reset(now);
        }
        metrics.new_contacts += 1;
    }

    /// Применить штраф вручную (за плохое поведение).
    pub fn penalize(&mut self, node_id: &NodeId, delta: u8, reason: &str, now: u64) {
        let _ = reason;
        self.ensure(*node_id, now);
        let score = self.scores.get_mut(node_id).unwrap();
        score.apply_delta(-(delta as i16), now);
    }

    /// Наградить за нормальное поведение.
    pub fn reward(&mut self, node_id: &NodeId, delta: u8, now: u64) {
        self.ensure(*node_id, now);
        let score = self.scores.get_mut(node_id).unwrap();
        score.apply_delta(delta as i16, now);
    }

    /// Пересчитать score на основе метрик за окно.
    pub fn recompute(&mut self, node_id: &NodeId, now: u64) {
        self.ensure(*node_id, now);

        let metrics = self.metrics.get_mut(node_id).unwrap();
        if metrics.is_window_expired(now) {
            metrics.reset(now);
        }

        let score = self.scores.get_mut(node_id).unwrap();

        if metrics.is_anomalous() {
            score.apply_delta(-20, now);
            score.warnings_count += 1;
        } else if metrics.is_suspicious() {
            score.apply_delta(-5, now);
            score.warnings_count += 1;
        } else {
            score.apply_delta(1, now);
            score.warnings_count = 0;
        }

        if score.warnings_count >= WARNINGS_FOR_EXTRA_PENALTY {
            score.apply_delta(-(EXTRA_PENALTY as i16), now);
            score.warnings_count = 0;
        }

        score.clamp();
    }

    /// Количество отслеживаемых узлов.
    pub fn tracked_nodes(&self) -> usize {
        self.scores.len()
    }

    /// Удалить узлы, у которых не было активности хотя бы 24 часа.
    pub fn cleanup_old(&mut self, now: u64) {
        let stale_threshold = now.saturating_sub(24 * 3600);
        let stale: Vec<_> = self
            .scores
            .iter()
            .filter(|(_, score)| score.last_updated_at < stale_threshold)
            .map(|(node_id, _)| *node_id)
            .collect();

        for node in stale {
            self.scores.remove(&node);
            self.metrics.remove(&node);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(seed: u8) -> NodeId {
        NodeId::from_bytes([seed; 32])
    }

    #[test]
    fn new_score_starts_at_initial() {
        let manager = TrustScoreManager::new();
        let node_id = node(1);
        assert_eq!(manager.score_of(&node_id), TRUST_INITIAL);
    }

    #[test]
    fn apply_delta_positive() {
        let mut score = DhtTrustScore::new(node(2), 10);
        score.apply_delta(5, 20);
        assert_eq!(score.score, 55);
    }

    #[test]
    fn apply_delta_negative() {
        let mut score = DhtTrustScore::new(node(3), 10);
        score.apply_delta(-8, 20);
        assert_eq!(score.score, 42);
    }

    #[test]
    fn apply_delta_clamps_to_max() {
        let mut score = DhtTrustScore::new(node(4), 10);
        score.apply_delta(200, 20);
        assert_eq!(score.score, TRUST_MAX);
    }

    #[test]
    fn apply_delta_clamps_to_min() {
        let mut score = DhtTrustScore::new(node(5), 10);
        score.apply_delta(-200, 20);
        assert_eq!(score.score, TRUST_MIN);
    }

    #[test]
    fn trust_action_from_score_normal() {
        assert_eq!(TrustAction::from_score(30), TrustAction::Normal);
    }

    #[test]
    fn trust_action_from_score_badge() {
        assert_eq!(TrustAction::from_score(25), TrustAction::ShowBadge);
    }

    #[test]
    fn trust_action_from_score_timeout() {
        assert_eq!(TrustAction::from_score(15), TrustAction::TimeoutContacts);
    }

    #[test]
    fn trust_action_from_score_block() {
        assert_eq!(TrustAction::from_score(7), TrustAction::BlockNewMessages);
    }

    #[test]
    fn trust_action_from_score_ban() {
        assert_eq!(TrustAction::from_score(4), TrustAction::Ban);
    }

    #[test]
    fn record_message_normal_keeps_score_stable() {
        let mut manager = TrustScoreManager::new();
        let node_id = node(6);

        for _ in 0..10 {
            manager.record_message(&node_id, false, 1000);
        }

        assert!(manager.score_of(&node_id) >= TRUST_INITIAL);
    }

    #[test]
    fn record_many_stranger_messages_drops_score() {
        let mut manager = TrustScoreManager::new();
        let node_id = node(30);
        let now = 1000;

        manager.ensure(node_id, now);
        for _ in 0..150 {
            manager.record_message(&node_id, true, now);
        }

        manager.recompute(&node_id, now);

        assert_eq!(
            manager.score_of(&node_id),
            45,
            "expected 45 after one suspicious window"
        );
    }

    #[test]
    fn record_many_contacts_drops_score() {
        let mut manager = TrustScoreManager::new();
        let node_id = node(8);
        let now = 1000;

        manager.ensure(node_id, now);
        for _ in 0..150 {
            manager.record_contact_add(&node_id, now);
        }

        manager.recompute(&node_id, now);

        assert_eq!(
            manager.score_of(&node_id),
            45,
            "expected 45 after one suspicious contact window"
        );
    }

    #[test]
    fn normal_behavior_rewards_score() {
        let mut manager = TrustScoreManager::new();
        let node_id = node(20);
        let now = 1000;

        manager.ensure(node_id, now);
        for i in 0..5 {
            manager.record_message(&node_id, false, now + i);
        }

        manager.recompute(&node_id, now + 5);

        assert_eq!(
            manager.score_of(&node_id),
            51,
            "expected exactly 51 after 1 normal recompute"
        );
    }

    #[test]
    fn warnings_threshold_triggers_extra_penalty() {
        let mut manager = TrustScoreManager::new();
        let node_id = node(9);

        for cycle in 0..WARNINGS_FOR_EXTRA_PENALTY {
            let now = 1000 + (cycle as u64 + 1) * METRICS_WINDOW_SECS;
            manager.ensure(node_id, now);
            manager.reset_metrics(&node_id, now);

            for _ in 0..20 {
                manager.record_contact_add(&node_id, now);
            }

            manager.recompute(&node_id, now);
        }

        assert_eq!(
            manager.score_of(&node_id),
            15,
            "expected exactly 15 after 5 suspicious cycles"
        );
    }

    #[test]
    fn metrics_window_resets_after_hour() {
        let mut manager = TrustScoreManager::new();
        let node_id = node(40);
        let start = 1000;

        manager.ensure(node_id, start);
        for _ in 0..20 {
            manager.record_contact_add(&node_id, start);
        }

        let now = start + 2 * METRICS_WINDOW_SECS;
        manager.record_contact_add(&node_id, now);

        let metrics = manager.metrics.get(&node_id).unwrap();
        assert_eq!(metrics.new_contacts, 1, "metrics should reset after window");
    }

    #[test]
    fn cleanup_old_removes_idle_nodes() {
        let mut manager = TrustScoreManager::new();
        let node_old = node(30);
        let node_recent = node(31);

        let old_now = 1000;
        let recent_now = 1000 + 25 * 3600;
        manager.ensure(node_old, old_now);
        manager.ensure(node_recent, recent_now);

        let cleanup_now = recent_now + 3600;
        manager.cleanup_old(cleanup_now);

        assert_eq!(manager.tracked_nodes(), 1);
    }
}
