use std::collections::HashMap;

use crate::dht::group::GroupId;
use crate::dht::NodeId;

pub type NotificationId = u64;
pub const NOTIFICATION_DEFAULT_TTL_SECS: u64 = 7 * 24 * 3600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotificationKind {
    /// «A хочет добавить B — знаком ли тебе B?»
    ConfirmRequest,
    /// «A приглашает тебя в группу Z»
    InviteReceived,
    /// «C подтвердил B»
    ReferralReceived,
    /// Кандидат может участвовать в jury — UI должен спросить.
    JuryOptInRequest,
    /// Арбитр принял — пора публиковать commitments.
    JuryCommitmentsNeeded,
    /// Commitments собраны — пора отправлять shares.
    JurySharesNeeded,
    /// Все shares собраны — jury готова к расшифровке.
    JuryReadyForDecryption,
    /// Evidence расшифровано — juror может подать голос.
    JuryVoteNeeded,
    /// Все evidence данного complaint получили verdict.
    JuryVerdictReady,
    /// Сторона жалобы получила приватный вердикт.
    JuryVerdictReceived,
    /// Complainant: jury набрана, можно переходить к evidence.
    JuryReadyForEvidence,
    /// Jury assembly не завершилась в срок.
    JuryAssemblyExpired,
    /// Local peer is grandfathered but has no redemption proof yet.
    /// Must redeem before the cutover deadline.
    InviteRedemptionRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationStatus {
    Pending,
    Accepted,
    Rejected,
    Expired,
    Ignored,
}

#[derive(Debug, Clone)]
pub struct Notification {
    pub id: NotificationId,
    pub kind: NotificationKind,
    pub from: NodeId,
    pub subject: NodeId,
    pub group_id: Option<GroupId>,
    pub created_at: u64,
    pub expires_at: u64,
    pub status: NotificationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifierError {
    NotFound,
    AlreadyAnswered,
    Expired,
}

impl std::fmt::Display for NotifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "notification not found"),
            Self::AlreadyAnswered => write!(f, "notification already answered"),
            Self::Expired => write!(f, "notification expired"),
        }
    }
}

impl std::error::Error for NotifierError {}

#[derive(Debug, Default)]
pub struct Notifier {
    notifications: HashMap<NotificationId, Notification>,
    next_id: NotificationId,
}

impl Notifier {
    pub fn new() -> Self {
        Self {
            notifications: HashMap::new(),
            next_id: 1,
        }
    }

    pub fn create(
        &mut self,
        kind: NotificationKind,
        from: NodeId,
        subject: NodeId,
        group_id: Option<GroupId>,
        now: u64,
        ttl_secs: u64,
    ) -> NotificationId {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let notification = Notification {
            id,
            kind,
            from,
            subject,
            group_id,
            created_at: now,
            expires_at: now.saturating_add(ttl_secs),
            status: NotificationStatus::Pending,
        };
        self.notifications.insert(id, notification);
        id
    }

    pub fn respond(
        &mut self,
        id: NotificationId,
        accept: bool,
        now: u64,
    ) -> Result<&Notification, NotifierError> {
        let notification = self
            .notifications
            .get_mut(&id)
            .ok_or(NotifierError::NotFound)?;

        if notification.status != NotificationStatus::Pending {
            return Err(NotifierError::AlreadyAnswered);
        }

        if now > notification.expires_at {
            notification.status = NotificationStatus::Expired;
            return Err(NotifierError::Expired);
        }

        notification.status = if accept {
            NotificationStatus::Accepted
        } else {
            NotificationStatus::Rejected
        };

        Ok(notification)
    }

    pub fn ignore(&mut self, id: NotificationId) -> Result<(), NotifierError> {
        let notification = self
            .notifications
            .get_mut(&id)
            .ok_or(NotifierError::NotFound)?;

        if notification.status != NotificationStatus::Pending {
            return Err(NotifierError::AlreadyAnswered);
        }

        notification.status = NotificationStatus::Ignored;
        Ok(())
    }

    pub fn pending(&self) -> Vec<&Notification> {
        self.notifications
            .values()
            .filter(|notification| notification.status == NotificationStatus::Pending)
            .collect()
    }

    pub fn by_id(&self, id: NotificationId) -> Option<&Notification> {
        self.notifications.get(&id)
    }

    pub fn cleanup_expired(&mut self, now: u64) -> usize {
        let expired_ids: Vec<_> = self
            .notifications
            .iter()
            .filter_map(|(&id, notification)| {
                (notification.status == NotificationStatus::Pending
                    && now > notification.expires_at)
                    .then_some(id)
            })
            .collect();

        let removed = expired_ids.len();
        for id in expired_ids {
            let entry = self.notifications.get_mut(&id);
            if let Some(notification) = entry {
                notification.status = NotificationStatus::Expired;
            }
            self.notifications.remove(&id);
        }
        removed
    }

    pub fn len(&self) -> usize {
        self.notifications.len()
    }

    pub fn is_empty(&self) -> bool {
        self.notifications.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(seed: u8) -> NodeId {
        NodeId::from_bytes([seed; 32])
    }

    #[test]
    fn create_returns_unique_id() {
        let mut notifier = Notifier::new();
        let first = notifier.create(
            NotificationKind::ConfirmRequest,
            node(1),
            node(2),
            None,
            100,
            3600,
        );
        let second = notifier.create(
            NotificationKind::InviteReceived,
            node(3),
            node(4),
            Some(7),
            200,
            3600,
        );

        assert_eq!(first, 1);
        assert_eq!(second, 2);
        assert_eq!(notifier.len(), 2);
    }

    #[test]
    fn respond_accept() {
        let mut notifier = Notifier::new();
        let id = notifier.create(
            NotificationKind::ConfirmRequest,
            node(1),
            node(2),
            None,
            100,
            3600,
        );

        let notification = notifier.respond(id, true, 200).unwrap();
        assert_eq!(notification.status, NotificationStatus::Accepted);
    }

    #[test]
    fn respond_reject() {
        let mut notifier = Notifier::new();
        let id = notifier.create(
            NotificationKind::ConfirmRequest,
            node(1),
            node(2),
            None,
            100,
            3600,
        );

        let notification = notifier.respond(id, false, 200).unwrap();
        assert_eq!(notification.status, NotificationStatus::Rejected);
    }

    #[test]
    fn respond_twice_rejected() {
        let mut notifier = Notifier::new();
        let id = notifier.create(
            NotificationKind::ConfirmRequest,
            node(1),
            node(2),
            None,
            100,
            3600,
        );

        notifier.respond(id, true, 200).unwrap();
        assert!(matches!(
            notifier.respond(id, false, 250),
            Err(NotifierError::AlreadyAnswered)
        ));
    }

    #[test]
    fn respond_expired() {
        let mut notifier = Notifier::new();
        let id = notifier.create(
            NotificationKind::ReferralReceived,
            node(10),
            node(11),
            Some(42),
            100,
            10,
        );

        assert!(matches!(
            notifier.respond(id, true, 111),
            Err(NotifierError::Expired)
        ));
        assert_eq!(
            notifier.by_id(id).unwrap().status,
            NotificationStatus::Expired
        );
    }

    #[test]
    fn pending_filters_correctly() {
        let mut notifier = Notifier::new();
        let first = notifier.create(
            NotificationKind::ConfirmRequest,
            node(1),
            node(2),
            None,
            100,
            1000,
        );
        let second = notifier.create(
            NotificationKind::InviteReceived,
            node(3),
            node(4),
            Some(9),
            100,
            1000,
        );

        notifier.respond(first, true, 150).unwrap();
        let pending = notifier.pending();

        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, second);
        assert_eq!(pending[0].status, NotificationStatus::Pending);
    }

    #[test]
    fn ignore_marks_ignored() {
        let mut notifier = Notifier::new();
        let id = notifier.create(
            NotificationKind::ReferralReceived,
            node(5),
            node(6),
            None,
            100,
            1000,
        );

        notifier.ignore(id).unwrap();
        assert_eq!(
            notifier.by_id(id).unwrap().status,
            NotificationStatus::Ignored
        );
    }

    #[test]
    fn cleanup_removes_expired() {
        let mut notifier = Notifier::new();
        let active_id = notifier.create(
            NotificationKind::ConfirmRequest,
            node(1),
            node(2),
            None,
            100,
            200,
        );
        let expired_id = notifier.create(
            NotificationKind::InviteReceived,
            node(3),
            node(4),
            Some(12),
            100,
            10,
        );

        assert_eq!(notifier.cleanup_expired(200), 1);
        assert!(notifier.by_id(active_id).is_some());
        assert!(notifier.by_id(expired_id).is_none());
    }
}
