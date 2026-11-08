use std::sync::{Arc, Mutex};

use crate::dht::group::GroupGraph;
use crate::dht::rate_limit::{RateDecision, RateLimiter};
use crate::dht::trust::{TrustAction, TrustScoreManager};
use crate::dht::NodeId;
use crate::pinning::KnownHosts;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relationship {
    /// Узел входит в один из trust circles. Полное доверие.
    Circle,
    /// Узел есть в KnownHosts, но не в круге.
    Known,
    /// Узла нет ни в KnownHosts, ни в Circle.
    Unknown,
    /// TrustAction::Ban.
    Banned,
}

/// Действие Oracle. Отличается от TrustAction тем, что
/// включает Trusted — состояние "не оценивается".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OracleAction {
    /// Known узел. Не оценивается. Полное доверие.
    Trusted,
    /// score >= 30.
    Normal,
    /// 20..=29.
    ShowBadge,
    /// 10..=19.
    TimeoutContacts,
    /// 5..=9.
    BlockNewMessages,
    /// 0..=4.
    Ban,
}

impl OracleAction {
    /// Из score (0..=100). Trusted здесь НЕ участвует —
    /// он только для Known.
    pub fn from_score(score: u8) -> Self {
        match score {
            s if s >= 30 => Self::Normal,
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

    pub fn allows_contact_add(self) -> bool {
        matches!(self, Self::Trusted | Self::Normal | Self::ShowBadge)
    }

    pub fn allows_message_to_stranger(self) -> bool {
        matches!(self, Self::Trusted | Self::Normal | Self::ShowBadge)
    }

    pub fn is_banned(self) -> bool {
        self == Self::Ban
    }
}

/// Полная информация о доверии к узлу.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeTrust {
    /// relationship: Known / Unknown / Banned.
    pub relationship: Relationship,
    /// Социальная метка "спамер". Пока ВСЕГДА false.
    /// Заложено под 8.3c (referral-цепочки).
    pub is_marked_spam: bool,
}

impl NodeTrust {
    pub fn new(relationship: Relationship) -> Self {
        Self {
            relationship,
            is_marked_spam: false,
        }
    }
}

pub trait TrustOracle: Send + Sync {
    /// Текущий relationship узла.
    fn relationship(&self, node_id: &NodeId) -> Relationship;

    /// Текущий score (0..=100) для Unknown/Banned; для Known -> None.
    fn score(&self, node_id: &NodeId, now: u64) -> Option<u8>;

    /// OracleAction по текущему состоянию.
    fn action(&self, node_id: &NodeId, now: u64) -> OracleAction;

    /// Полная информация о trust.
    fn trust_of(&self, node_id: &NodeId) -> NodeTrust;

    /// Разрешено ли добавить контакт.
    /// Known -> true (доверяем).
    /// Unknown -> action.allows_contact_add() && rate не Reject.
    /// Banned -> false.
    fn allows_contact_add(&self, node_id: &NodeId, now: u64) -> bool;

    /// Разрешено ли отправить сообщение незнакомцу.
    /// Known -> true.
    /// Unknown -> action.allows_message_to_stranger() && rate не Reject.
    /// Banned -> false.
    fn allows_message_to_stranger(&self, node_id: &NodeId, now: u64) -> bool;

    /// Забанен ли узел.
    fn is_banned(&self, node_id: &NodeId, now: u64) -> bool;

    /// Записать факт сообщения от узла.
    /// Known -> НЕ инкрементит метрики (круг неисчерпаем).
    /// Unknown -> инкрементит messages_sent / messages_to_strangers.
    /// Banned -> НЕ инкрементит.
    fn record_message(&self, node_id: &NodeId, is_stranger: bool, now: u64);

    /// Записать факт добавления контакта.
    /// Known -> НЕ инкрементит.
    /// Unknown -> инкрементит new_contacts.
    /// Banned -> НЕ инкрементит.
    fn record_contact_add(&self, node_id: &NodeId, now: u64);

    /// Пересчитать score на основе метрик за окно.
    fn recompute(&self, node_id: &NodeId, now: u64);

    /// Удалить устаревшие узлы из score + rate + metrics.
    fn cleanup_old(&self, now: u64);
}

pub struct BasicTrustOracle {
    scores: Arc<Mutex<TrustScoreManager>>,
    rates: Arc<Mutex<RateLimiter>>,
    hosts: Arc<Mutex<KnownHosts>>,
    groups: Arc<dyn GroupGraph>,
}

impl BasicTrustOracle {
    pub fn new(
        scores: Arc<Mutex<TrustScoreManager>>,
        rates: Arc<Mutex<RateLimiter>>,
        hosts: Arc<Mutex<KnownHosts>>,
        groups: Arc<dyn GroupGraph>,
    ) -> Self {
        Self {
            scores,
            rates,
            hosts,
            groups,
        }
    }
}

impl TrustOracle for BasicTrustOracle {
    fn relationship(&self, node_id: &NodeId) -> Relationship {
        if let Ok(scores) = self.scores.lock() {
            if scores.action_of(node_id) == TrustAction::Ban {
                return Relationship::Banned;
            }
        }

        if self.groups.is_in_any_group(node_id) {
            return Relationship::Circle;
        }

        let identity = node_id.to_hex();
        match self.hosts.lock() {
            Ok(hosts) => {
                if hosts.record_of(&identity).is_some() {
                    Relationship::Known
                } else {
                    Relationship::Unknown
                }
            }
            Err(_) => Relationship::Unknown,
        }
    }

    fn score(&self, node_id: &NodeId, _now: u64) -> Option<u8> {
        match self.relationship(node_id) {
            Relationship::Known | Relationship::Circle => None,
            Relationship::Banned | Relationship::Unknown => match self.scores.lock() {
                Ok(scores) => Some(scores.score_of(node_id)),
                Err(_) => None,
            },
        }
    }

    fn action(&self, node_id: &NodeId, now: u64) -> OracleAction {
        match self.relationship(node_id) {
            Relationship::Known | Relationship::Circle => OracleAction::Trusted,
            Relationship::Banned => OracleAction::Ban,
            Relationship::Unknown => match self.score(node_id, now) {
                Some(s) => OracleAction::from_score(s),
                None => OracleAction::Ban,
            },
        }
    }

    fn trust_of(&self, node_id: &NodeId) -> NodeTrust {
        NodeTrust::new(self.relationship(node_id))
    }

    fn allows_contact_add(&self, node_id: &NodeId, now: u64) -> bool {
        match self.relationship(node_id) {
            Relationship::Banned => false,
            Relationship::Known | Relationship::Circle => true,
            Relationship::Unknown => {
                let action = self.action(node_id, now);
                if !action.allows_contact_add() {
                    return false;
                }

                let Ok(mut rates) = self.rates.lock() else {
                    return false;
                };

                !matches!(
                    rates.check_contact_add(node_id, now),
                    RateDecision::Reject(_)
                )
            }
        }
    }

    fn allows_message_to_stranger(&self, node_id: &NodeId, now: u64) -> bool {
        match self.relationship(node_id) {
            Relationship::Banned => false,
            Relationship::Known | Relationship::Circle => true,
            Relationship::Unknown => {
                let action = self.action(node_id, now);
                if !action.allows_message_to_stranger() {
                    return false;
                }

                let Ok(mut rates) = self.rates.lock() else {
                    return false;
                };

                !matches!(rates.check_message(node_id, now), RateDecision::Reject(_))
            }
        }
    }

    fn is_banned(&self, node_id: &NodeId, _now: u64) -> bool {
        matches!(self.relationship(node_id), Relationship::Banned)
    }

    fn record_message(&self, node_id: &NodeId, is_stranger: bool, now: u64) {
        match self.relationship(node_id) {
            Relationship::Known | Relationship::Circle | Relationship::Banned => return,
            Relationship::Unknown => {
                let Ok(mut scores) = self.scores.lock() else {
                    return;
                };
                scores.record_message(node_id, is_stranger, now);
            }
        }
    }

    fn record_contact_add(&self, node_id: &NodeId, now: u64) {
        match self.relationship(node_id) {
            Relationship::Known | Relationship::Circle | Relationship::Banned => return,
            Relationship::Unknown => {
                let Ok(mut scores) = self.scores.lock() else {
                    return;
                };
                scores.record_contact_add(node_id, now);
            }
        }
    }

    fn recompute(&self, node_id: &NodeId, now: u64) {
        if matches!(
            self.relationship(node_id),
            Relationship::Known | Relationship::Circle
        ) {
            return;
        }

        let Ok(mut scores) = self.scores.lock() else {
            return;
        };
        scores.recompute(node_id, now);
    }

    fn cleanup_old(&self, now: u64) {
        if let Ok(mut scores) = self.scores.lock() {
            scores.cleanup_old(now);
        }
        if let Ok(mut rates) = self.rates.lock() {
            rates.cleanup_old(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::rate_limit::{RateLimiter, RATE_MESSAGES_PER_HOUR, RATE_NEW_CONTACTS_PER_DAY};
    use ed25519_dalek::SigningKey;

    fn node(seed: u8) -> NodeId {
        NodeId::from_bytes([seed; 32])
    }

    fn key_hex(seed: u8) -> String {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let verifying_key = signing_key.verifying_key();
        verifying_key
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn unknown_node_is_unknown() {
        let oracle = BasicTrustOracle::new(
            Arc::new(Mutex::new(TrustScoreManager::new())),
            Arc::new(Mutex::new(RateLimiter::new())),
            Arc::new(Mutex::new(KnownHosts::new())),
            Arc::new(crate::dht::GroupRegistry::new()),
        );

        assert_eq!(oracle.relationship(&node(1)), Relationship::Unknown);
    }

    #[test]
    fn known_node_is_known() {
        let hosts = Arc::new(Mutex::new(KnownHosts::new()));
        let node_id = node(2);
        let identity_id = node_id.to_hex();
        let key = key_hex(2);

        {
            let mut hosts_guard = hosts.lock().unwrap();
            hosts_guard.pin_manual(&identity_id, &key, 100).unwrap();
        }

        let oracle = BasicTrustOracle::new(
            Arc::new(Mutex::new(TrustScoreManager::new())),
            Arc::new(Mutex::new(RateLimiter::new())),
            hosts,
            Arc::new(crate::dht::GroupRegistry::new()),
        );

        assert_eq!(oracle.relationship(&node_id), Relationship::Known);
    }

    #[test]
    fn banned_node_is_banned() {
        let scores = Arc::new(Mutex::new(TrustScoreManager::new()));
        let node_id = node(3);

        {
            let mut scores_guard = scores.lock().unwrap();
            scores_guard.penalize(&node_id, 70, "bad", 1000);
        }

        let oracle = BasicTrustOracle::new(
            scores,
            Arc::new(Mutex::new(RateLimiter::new())),
            Arc::new(Mutex::new(KnownHosts::new())),
            Arc::new(crate::dht::GroupRegistry::new()),
        );

        assert_eq!(oracle.relationship(&node_id), Relationship::Banned);
        assert!(oracle.is_banned(&node_id, 1000));
    }

    #[test]
    fn unknown_node_contact_add_respects_rate_limit() {
        let oracle = BasicTrustOracle::new(
            Arc::new(Mutex::new(TrustScoreManager::new())),
            Arc::new(Mutex::new(RateLimiter::new())),
            Arc::new(Mutex::new(KnownHosts::new())),
            Arc::new(crate::dht::GroupRegistry::new()),
        );
        let node_id = node(4);
        let start = 1000u64;

        for offset in 0..RATE_NEW_CONTACTS_PER_DAY {
            assert!(oracle.allows_contact_add(&node_id, start + offset as u64));
        }

        assert!(!oracle.allows_contact_add(&node_id, start + RATE_NEW_CONTACTS_PER_DAY as u64));
    }

    #[test]
    fn known_node_bypasses_rate_limit() {
        let hosts = Arc::new(Mutex::new(KnownHosts::new()));
        let node_id = node(5);
        let identity_id = node_id.to_hex();

        {
            let mut hosts_guard = hosts.lock().unwrap();
            hosts_guard
                .pin_manual(&identity_id, &key_hex(5), 100)
                .unwrap();
        }

        let rates = Arc::new(Mutex::new(RateLimiter::new()));
        {
            let mut rates_guard = rates.lock().unwrap();
            for offset in 0..RATE_MESSAGES_PER_HOUR {
                let _ = rates_guard.check_message(&node_id, 200 + offset as u64);
            }
        }

        let oracle = BasicTrustOracle::new(
            Arc::new(Mutex::new(TrustScoreManager::new())),
            rates,
            hosts,
            Arc::new(crate::dht::GroupRegistry::new()),
        );

        assert_eq!(oracle.relationship(&node_id), Relationship::Known);
        assert!(oracle.allows_message_to_stranger(&node_id, 300 + RATE_MESSAGES_PER_HOUR as u64));
    }

    #[test]
    fn banned_node_denied_everywhere() {
        let scores = Arc::new(Mutex::new(TrustScoreManager::new()));
        let node_id = node(6);

        {
            let mut scores_guard = scores.lock().unwrap();
            scores_guard.penalize(&node_id, 60, "spam", 1000);
        }

        let oracle = BasicTrustOracle::new(
            scores,
            Arc::new(Mutex::new(RateLimiter::new())),
            Arc::new(Mutex::new(KnownHosts::new())),
            Arc::new(crate::dht::GroupRegistry::new()),
        );

        assert_eq!(oracle.relationship(&node_id), Relationship::Banned);
        assert!(!oracle.allows_contact_add(&node_id, 1000));
        assert!(!oracle.allows_message_to_stranger(&node_id, 1000));
        assert!(oracle.is_banned(&node_id, 1000));
    }

    #[test]
    fn record_message_unknown_increments_metrics() {
        let scores = Arc::new(Mutex::new(TrustScoreManager::new()));
        let oracle = BasicTrustOracle::new(
            Arc::clone(&scores),
            Arc::new(Mutex::new(RateLimiter::new())),
            Arc::new(Mutex::new(KnownHosts::new())),
            Arc::new(crate::dht::GroupRegistry::new()),
        );
        let node_id = node(7);

        oracle.record_message(&node_id, true, 1000);
        oracle.record_message(&node_id, true, 1000);
        oracle.recompute(&node_id, 1000);

        let score = scores.lock().unwrap().score_of(&node_id);
        assert_ne!(score, crate::dht::trust::TRUST_INITIAL);
    }

    #[test]
    fn record_message_known_does_not_increment() {
        let hosts = Arc::new(Mutex::new(KnownHosts::new()));
        let scores = Arc::new(Mutex::new(TrustScoreManager::new()));
        let node_id = node(8);
        let identity_id = node_id.to_hex();
        let key = key_hex(8);

        {
            let mut hosts_guard = hosts.lock().unwrap();
            hosts_guard.pin_manual(&identity_id, &key, 100).unwrap();
        }

        let oracle = BasicTrustOracle::new(
            Arc::clone(&scores),
            Arc::new(Mutex::new(RateLimiter::new())),
            hosts,
            Arc::new(crate::dht::GroupRegistry::new()),
        );

        for _ in 0..20 {
            oracle.record_message(&node_id, true, 1000);
        }

        assert_eq!(
            scores.lock().unwrap().score_of(&node_id),
            crate::dht::trust::TRUST_INITIAL
        );
    }

    #[test]
    fn record_contact_add_unknown_increments() {
        let scores = Arc::new(Mutex::new(TrustScoreManager::new()));
        let oracle = BasicTrustOracle::new(
            Arc::clone(&scores),
            Arc::new(Mutex::new(RateLimiter::new())),
            Arc::new(Mutex::new(KnownHosts::new())),
            Arc::new(crate::dht::GroupRegistry::new()),
        );
        let node_id = node(9);

        for _ in 0..15 {
            oracle.record_contact_add(&node_id, 1000);
        }
        oracle.recompute(&node_id, 1000);

        let score = scores.lock().unwrap().score_of(&node_id);
        assert!(score < crate::dht::trust::TRUST_INITIAL);
    }

    #[test]
    fn recompute_updates_score() {
        let scores = Arc::new(Mutex::new(TrustScoreManager::new()));
        let oracle = BasicTrustOracle::new(
            Arc::clone(&scores),
            Arc::new(Mutex::new(RateLimiter::new())),
            Arc::new(Mutex::new(KnownHosts::new())),
            Arc::new(crate::dht::GroupRegistry::new()),
        );
        let node_id = node(10);

        for _ in 0..80 {
            oracle.record_message(&node_id, true, 1000);
        }
        let before = oracle.score(&node_id, 1000).unwrap();
        oracle.recompute(&node_id, 1000);
        let after = oracle.score(&node_id, 1000).unwrap();

        assert_eq!(before, crate::dht::trust::TRUST_INITIAL);
        assert_ne!(after, before);
    }

    #[test]
    fn cleanup_old_removes_stale() {
        let scores = Arc::new(Mutex::new(TrustScoreManager::new()));
        let oracle = BasicTrustOracle::new(
            Arc::clone(&scores),
            Arc::new(Mutex::new(RateLimiter::new())),
            Arc::new(Mutex::new(KnownHosts::new())),
            Arc::new(crate::dht::GroupRegistry::new()),
        );
        let node_id = node(11);

        oracle.record_message(&node_id, true, 1000);
        oracle.cleanup_old(1000 + 25 * 3600);

        assert_eq!(scores.lock().unwrap().tracked_nodes(), 0);
    }

    #[test]
    fn known_node_score_is_none() {
        let hosts = Arc::new(Mutex::new(KnownHosts::new()));
        let node_id = node(12);
        let identity_id = node_id.to_hex();
        let key = key_hex(12);

        {
            let mut hosts_guard = hosts.lock().unwrap();
            hosts_guard.pin_manual(&identity_id, &key, 100).unwrap();
        }

        let oracle = BasicTrustOracle::new(
            Arc::new(Mutex::new(TrustScoreManager::new())),
            Arc::new(Mutex::new(RateLimiter::new())),
            hosts,
            Arc::new(crate::dht::GroupRegistry::new()),
        );

        assert_eq!(oracle.score(&node_id, 1000), None);
    }

    #[test]
    fn known_node_action_is_trusted() {
        let hosts = Arc::new(Mutex::new(KnownHosts::new()));
        let node_id = node(13);
        let identity_id = node_id.to_hex();
        let key = key_hex(13);

        {
            let mut hosts_guard = hosts.lock().unwrap();
            hosts_guard.pin_manual(&identity_id, &key, 100).unwrap();
        }

        let oracle = BasicTrustOracle::new(
            Arc::new(Mutex::new(TrustScoreManager::new())),
            Arc::new(Mutex::new(RateLimiter::new())),
            hosts,
            Arc::new(crate::dht::GroupRegistry::new()),
        );

        assert_eq!(oracle.action(&node_id, 1000), OracleAction::Trusted);
    }

    #[test]
    fn known_node_recompute_is_skipped() {
        let hosts = Arc::new(Mutex::new(KnownHosts::new()));
        let scores = Arc::new(Mutex::new(TrustScoreManager::new()));
        let node_id = node(14);
        let identity_id = node_id.to_hex();
        let key = key_hex(14);

        {
            let mut hosts_guard = hosts.lock().unwrap();
            hosts_guard.pin_manual(&identity_id, &key, 100).unwrap();
        }

        {
            let mut scores_guard = scores.lock().unwrap();
            for _ in 0..80 {
                scores_guard.record_message(&node_id, true, 1000);
            }
        }

        let oracle = BasicTrustOracle::new(
            Arc::clone(&scores),
            Arc::new(Mutex::new(RateLimiter::new())),
            hosts,
            Arc::new(crate::dht::GroupRegistry::new()),
        );

        let before = scores.lock().unwrap().score_of(&node_id);
        oracle.recompute(&node_id, 1000);
        let after = scores.lock().unwrap().score_of(&node_id);

        assert_eq!(before, crate::dht::trust::TRUST_INITIAL);
        assert_eq!(before, after);
    }

    #[test]
    fn unknown_node_score_is_some() {
        let oracle = BasicTrustOracle::new(
            Arc::new(Mutex::new(TrustScoreManager::new())),
            Arc::new(Mutex::new(RateLimiter::new())),
            Arc::new(Mutex::new(KnownHosts::new())),
            Arc::new(crate::dht::GroupRegistry::new()),
        );

        assert_eq!(
            oracle.score(&node(15), 1000),
            Some(crate::dht::trust::TRUST_INITIAL)
        );
    }

    #[test]
    fn node_trust_has_spam_flag() {
        let oracle = BasicTrustOracle::new(
            Arc::new(Mutex::new(TrustScoreManager::new())),
            Arc::new(Mutex::new(RateLimiter::new())),
            Arc::new(Mutex::new(KnownHosts::new())),
            Arc::new(crate::dht::GroupRegistry::new()),
        );

        assert!(!oracle.trust_of(&node(16)).is_marked_spam);
    }

    #[test]
    fn circle_node_is_trusted_and_not_scored() {
        let scores = Arc::new(Mutex::new(TrustScoreManager::new()));
        let node_id = node(18);
        let mut groups = crate::dht::GroupRegistry::new();
        let group_id = groups.create_group(Some("family".into()));
        assert!(groups.add_member(group_id, node_id));

        let oracle = BasicTrustOracle::new(
            Arc::clone(&scores),
            Arc::new(Mutex::new(RateLimiter::new())),
            Arc::new(Mutex::new(KnownHosts::new())),
            Arc::new(groups),
        );

        oracle.record_message(&node_id, true, 1000);
        oracle.record_contact_add(&node_id, 1000);

        assert_eq!(oracle.relationship(&node_id), Relationship::Circle);
        assert_eq!(oracle.action(&node_id, 1000), OracleAction::Trusted);
        assert_eq!(oracle.score(&node_id, 1000), None);
        assert_eq!(
            scores.lock().unwrap().score_of(&node_id),
            crate::dht::trust::TRUST_INITIAL
        );
    }

    #[test]
    fn banned_circle_node_is_banned() {
        let scores = Arc::new(Mutex::new(TrustScoreManager::new()));
        let node_id = node(19);
        let mut groups = crate::dht::GroupRegistry::new();
        let group_id = groups.create_group(None);
        groups.add_member(group_id, node_id);
        scores.lock().unwrap().penalize(&node_id, 100, "bad", 1000);

        let oracle = BasicTrustOracle::new(
            Arc::clone(&scores),
            Arc::new(Mutex::new(RateLimiter::new())),
            Arc::new(Mutex::new(KnownHosts::new())),
            Arc::new(groups),
        );

        assert_eq!(oracle.relationship(&node_id), Relationship::Banned);
        assert_eq!(oracle.action(&node_id, 1000), OracleAction::Ban);
        assert!(!oracle.allows_message_to_stranger(&node_id, 1000));
    }

    #[test]
    fn poisoned_mutex_does_not_panic() {
        let scores = Arc::new(Mutex::new(TrustScoreManager::new()));
        let poisoned_scores = Arc::clone(&scores);
        let handle = std::thread::spawn(move || {
            let _guard = poisoned_scores.lock().unwrap();
            panic!("poison for test");
        });
        let _ = handle.join();

        let oracle = BasicTrustOracle::new(
            scores,
            Arc::new(Mutex::new(RateLimiter::new())),
            Arc::new(Mutex::new(KnownHosts::new())),
            Arc::new(crate::dht::GroupRegistry::new()),
        );

        assert_eq!(oracle.score(&node(17), 1000), None);
        assert!(!oracle.allows_contact_add(&node(17), 1000));
        assert_eq!(oracle.relationship(&node(17)), Relationship::Unknown);
    }
}
