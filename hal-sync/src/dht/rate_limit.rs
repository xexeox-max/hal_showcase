//! Rate limiting with optional asynchronous persistence.
//!
//! Persistence worker lifecycle:
//! The worker is spawned at construction and runs until its receiver or
//! runtime is dropped. If it dies, persistence degrades to in-memory:
//! subsequent enqueue calls return `WorkerStopped`, are counted in
//! `rate_limiter_worker_failed_total`, and do not accumulate pending
//! snapshots. Automatic recovery is not implemented. A restart reloads
//! whatever was persisted before worker failure; rate limiting continues
//! in memory while cross-restart durability is unavailable.

use std::sync::{Arc, Mutex as StdMutex};

use std::collections::{HashMap, HashSet, VecDeque};

use crate::abuse_metrics::AbuseMetrics;
use crate::dht::NodeId;
use hal_storage::{ClientStorage, RateLimiterState};
use tokio::sync::{mpsc, oneshot};

pub const RATE_LIMITER_PERSIST_QUEUE_CAPACITY: usize = 256;

/// Лимит сообщений за окно 1 час.
pub const RATE_MESSAGES_PER_HOUR: u32 = 50;

/// Лимит добавлений контактов за окно 24 часа.
/// Новый пользователь может сразу добавить 500 (миграция).
pub const RATE_NEW_CONTACTS_PER_DAY: u32 = 500;

/// Порог "подозрительно" для новых контактов за сутки.
pub const RATE_NEW_CONTACTS_SUSPICIOUS: u32 = 10;

/// Порог "аномально" для новых контактов за сутки.
pub const RATE_NEW_CONTACTS_ANOMALOUS: u32 = 30;

/// Размер окна для сообщений (1 час).
pub const RATE_MESSAGE_WINDOW_SECS: u64 = 3600;

/// Размер окна для истории отклонённых сообщений (1 час).
pub const RATE_REJECT_WINDOW_SECS: u64 = 3600;

/// Порог отклонений для Tier 1.
pub const RATE_REJECT_THROTTLE: usize = 3;

/// Порог отклонений для Tier 2.
pub const RATE_REJECT_WARNING: usize = 10;

/// Порог отклонений для блокировки.
pub const RATE_REJECT_BLOCKED: usize = 50;

pub const RATE_BURST_WINDOW_SECS: u64 = 30;
pub const RATE_BURST_MESSAGES: u32 = 10;
pub const RATE_ROLLING_WINDOW_SECS: u64 = 30 * 86_400;
pub const RATE_ROLLING_WATCHING: u32 = 50;
pub const RATE_ROLLING_WARNING: u32 = 200;
pub const RATE_ROLLING_BLOCKED: u32 = 500;
pub const FIRST_CONTACT_WINDOW_SECS: u64 = 7 * 86_400;
pub const FIRST_CONTACT_ACCEPTED_THRESHOLD: u32 = 10;

/// Размер окна для контактов (24 часа).
pub const RATE_CONTACT_WINDOW_SECS: u64 = 86400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateTier {
    Normal,
    Throttled,
    Warning,
    Blocked,
}

impl RateTier {
    pub fn rate_multiplier(self) -> f32 {
        match self {
            Self::Normal => 1.0,
            Self::Throttled => 0.1,
            Self::Warning => 0.01,
            Self::Blocked => 0.0,
        }
    }

    pub fn is_normal(self) -> bool {
        matches!(self, Self::Normal)
    }
}

/// Решение rate limiter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateDecision {
    /// Операция разрешена.
    Allow,
    /// Операция разрешена с burst-throttle tier.
    Throttle { reason: String },
    /// Операция разрешена, но с предупреждением.
    Warn(String),
    /// Операция отклонена.
    Reject(String),
}

impl RateDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow | Self::Throttle { .. } | Self::Warn(_))
    }

    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Reject(_))
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Allow => None,
            Self::Throttle { reason } | Self::Warn(reason) | Self::Reject(reason) => Some(reason),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BurstResult {
    BelowThreshold,
    Throttled,
}

/// Rate limiter с sliding windows.
pub struct RateLimiter {
    /// Timestamps сообщений per sender (за последний час).
    message_windows: HashMap<NodeId, Vec<u64>>,
    /// Timestamps отклонённых попыток per identity (за последний час).
    reject_windows: HashMap<NodeId, VecDeque<u64>>,
    /// Timestamps всех rate-limit rejects per identity (за последние 30 дней).
    rolling_reject_windows: HashMap<NodeId, VecDeque<u64>>,
    /// Timestamps accepted messages per sender (за последние 30 секунд).
    burst_windows: HashMap<NodeId, VecDeque<u64>>,
    /// First observed timestamp for the first-contact tier.
    first_seen: HashMap<NodeId, u64>,
    /// Accepted message count for the first-contact graduation threshold.
    accepted_counts: HashMap<NodeId, u32>,
    /// Timestamps добавлений контактов per node (за последние 24 часа).
    contact_windows: HashMap<NodeId, Vec<u64>>,
    persistence: Option<RateLimiterPersistence>,
}

#[derive(Debug)]
enum PersistenceSnapshot {
    Save(RateLimiterState),
    Delete,
}

enum PersistenceMessage {
    Snapshot(String),
    RecordReject {
        identity_hex: String,
        rejected_at: u64,
        kind: &'static str,
    },
    ObserveFirstSeen {
        identity_hex: String,
        first_seen_at: u64,
    },
    Flush(oneshot::Sender<std::result::Result<(), String>>),
}

struct RateLimiterPersistence {
    sender: mpsc::Sender<PersistenceMessage>,
    pending: Arc<StdMutex<HashMap<String, PersistenceSnapshot>>>,
    capacity: usize,
    abuse_metrics: Arc<AbuseMetrics>,
    worker_failed: std::sync::atomic::AtomicBool,
}

#[derive(Debug, PartialEq, Eq)]
enum QueueResult {
    Queued,
    Coalesced,
    DroppedFull,
    WorkerStopped,
    LockPoisoned,
}

impl RateLimiterPersistence {
    fn new(
        capacity: usize,
        abuse_metrics: Arc<AbuseMetrics>,
    ) -> (Self, mpsc::Receiver<PersistenceMessage>) {
        let (sender, receiver) = mpsc::channel(capacity);
        (
            Self {
                sender,
                pending: Arc::new(StdMutex::new(HashMap::with_capacity(capacity))),
                capacity,
                abuse_metrics,
                worker_failed: std::sync::atomic::AtomicBool::new(false),
            },
            receiver,
        )
    }

    fn mark_worker_stopped(&self) {
        if !self
            .worker_failed
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            self.abuse_metrics
                .rate_limiter_worker_failed_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            log::warn!(
                "rate limiter persistence worker stopped; clearing pending snapshots and continuing in memory"
            );
        }
        match self.pending.lock() {
            Ok(mut pending) => pending.clear(),
            Err(_) => log::error!("rate limiter persistence coalesce lock poisoned"),
        }
    }

    fn enqueue_reject(&self, identity_hex: String, rejected_at: u64) {
        if self
            .worker_failed
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return;
        }
        match self.sender.try_send(PersistenceMessage::RecordReject {
            identity_hex: identity_hex.clone(),
            rejected_at,
            kind: "hourly_rate_limit",
        }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                log::error!(
                    "rate reject history queue full; reject history not persisted for {identity_hex}"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => self.mark_worker_stopped(),
        }
    }

    fn enqueue_first_seen(&self, identity_hex: String, first_seen_at: u64) {
        if self
            .worker_failed
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return;
        }
        match self.sender.try_send(PersistenceMessage::ObserveFirstSeen {
            identity_hex: identity_hex.clone(),
            first_seen_at,
        }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => log::error!(
                "rate first-seen queue full; first-seen timestamp not persisted for {identity_hex}"
            ),
            Err(mpsc::error::TrySendError::Closed(_)) => self.mark_worker_stopped(),
        }
    }

    fn enqueue(&self, identity_hex: String, snapshot: PersistenceSnapshot) -> QueueResult {
        let mut pending = match self.pending.lock() {
            Ok(pending) => pending,
            Err(_) => {
                log::error!("rate limiter persistence coalesce lock poisoned");
                return QueueResult::LockPoisoned;
            }
        };
        if self.sender.is_closed() {
            drop(pending);
            self.mark_worker_stopped();
            return QueueResult::WorkerStopped;
        }
        if pending.contains_key(&identity_hex) {
            pending.insert(identity_hex, snapshot);
            if self.sender.is_closed() {
                drop(pending);
                self.mark_worker_stopped();
                return QueueResult::WorkerStopped;
            }
            return QueueResult::Coalesced;
        }
        if pending.len() >= self.capacity {
            log::error!(
                "rate limiter persistence queue full; dropping new snapshot for {identity_hex}"
            );
            return QueueResult::DroppedFull;
        }

        pending.insert(identity_hex.clone(), snapshot);
        match self
            .sender
            .try_send(PersistenceMessage::Snapshot(identity_hex.clone()))
        {
            Ok(()) => QueueResult::Queued,
            Err(mpsc::error::TrySendError::Full(_)) => {
                pending.remove(&identity_hex);
                log::error!(
                    "rate limiter persistence channel full; dropping snapshot for {identity_hex}"
                );
                QueueResult::DroppedFull
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                drop(pending);
                self.mark_worker_stopped();
                QueueResult::WorkerStopped
            }
        }
    }

    async fn run_persistence_worker(
        storage: Arc<StdMutex<ClientStorage>>,
        mut receiver: mpsc::Receiver<PersistenceMessage>,
        pending: Arc<StdMutex<HashMap<String, PersistenceSnapshot>>>,
    ) {
        let mut persistence_error = None;
        while let Some(message) = receiver.recv().await {
            match message {
                PersistenceMessage::Snapshot(identity_hex) => {
                    let snapshot = match pending.lock() {
                        Ok(mut pending) => pending.remove(&identity_hex),
                        Err(_) => {
                            log::error!("rate limiter persistence coalesce lock poisoned");
                            persistence_error =
                                Some("rate limiter persistence coalesce lock poisoned".into());
                            continue;
                        }
                    };
                    let Some(snapshot) = snapshot else {
                        log::error!("rate limiter persistence snapshot missing for {identity_hex}");
                        continue;
                    };
                    let result = match snapshot {
                        PersistenceSnapshot::Save(state) => {
                            persist_rate_limiter_state(&storage, &state)
                        }
                        PersistenceSnapshot::Delete => storage
                            .lock()
                            .map_err(|_| anyhow::anyhow!("client storage mutex poisoned"))
                            .and_then(|storage| {
                                storage
                                    .identity_history()
                                    .delete_rate_limiter_state(&identity_hex)
                            }),
                    };
                    if let Err(error) = result {
                        log::error!(
                            "failed to persist rate limiter state for {identity_hex}: {error:#}"
                        );
                        persistence_error = Some(error.to_string());
                    }
                }
                PersistenceMessage::RecordReject {
                    identity_hex,
                    rejected_at,
                    kind,
                } => {
                    let result = storage
                        .lock()
                        .map_err(|_| anyhow::anyhow!("client storage mutex poisoned"))
                        .and_then(|storage| {
                            storage.identity_history().record_reject(
                                &identity_hex,
                                rejected_at,
                                kind,
                            )
                        });
                    if let Err(error) = result {
                        log::error!(
                            "failed to persist rate reject history for {identity_hex}: {error:#}"
                        );
                        persistence_error = Some(error.to_string());
                    }
                }
                PersistenceMessage::ObserveFirstSeen {
                    identity_hex,
                    first_seen_at,
                } => {
                    let result = storage
                        .lock()
                        .map_err(|_| anyhow::anyhow!("client storage mutex poisoned"))
                        .and_then(|storage| {
                            storage
                                .identity_history()
                                .observe_first_seen(&identity_hex, first_seen_at)
                                .map(|_| ())
                        });
                    if let Err(error) = result {
                        log::error!(
                            "failed to persist first-seen timestamp for {identity_hex}: {error:#}"
                        );
                        persistence_error = Some(error.to_string());
                    }
                }
                PersistenceMessage::Flush(reply) => {
                    let result = persistence_error.take().map_or(Ok(()), Err);
                    let _ = reply.send(result);
                }
            }
        }
    }

    #[cfg(test)]
    fn pending_len(&self) -> usize {
        match self.pending.lock() {
            Ok(pending) => pending.len(),
            Err(_) => 0,
        }
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            message_windows: HashMap::new(),
            reject_windows: HashMap::new(),
            rolling_reject_windows: HashMap::new(),
            burst_windows: HashMap::new(),
            first_seen: HashMap::new(),
            accepted_counts: HashMap::new(),
            contact_windows: HashMap::new(),
            persistence: None,
        }
    }

    /// Loads persisted state and starts its background writer.
    ///
    /// Returns an error when called outside an active Tokio runtime.
    pub fn with_storage(storage: Arc<StdMutex<ClientStorage>>) -> anyhow::Result<Self> {
        Self::with_storage_and_metrics(storage, Arc::new(AbuseMetrics::new()))
    }

    /// Loads persisted state and starts its background writer using shared metrics.
    ///
    /// Returns an error when called outside an active Tokio runtime.
    pub fn with_storage_and_metrics(
        storage: Arc<StdMutex<ClientStorage>>,
        abuse_metrics: Arc<AbuseMetrics>,
    ) -> anyhow::Result<Self> {
        let now = unix_now_secs()?;
        let rolling_cutoff = now.saturating_sub(RATE_ROLLING_WINDOW_SECS);
        let (states, reject_history, first_seen_rows) = {
            let storage_guard = storage
                .lock()
                .map_err(|_| anyhow::anyhow!("client storage mutex poisoned"))?;
            let history = storage_guard.identity_history();
            let states = history.rate_limiter_states()?;
            let rejects = history.reject_history_since(rolling_cutoff)?;
            history.prune_rejects_before(rolling_cutoff)?;
            let mut statement = storage_guard
                .connection()
                .prepare("SELECT identity_hex, first_seen_at FROM identity_first_seen")?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
            })?;
            let first_seen = rows.collect::<rusqlite::Result<Vec<_>>>()?;
            (states, rejects, first_seen)
        };

        let mut limiter = Self::new();
        for state in states {
            let identity_bytes: [u8; 32] = hex::decode(&state.identity_hex)
                .map_err(|error| {
                    anyhow::anyhow!(
                        "invalid persisted rate limiter identity {}: {error}",
                        state.identity_hex
                    )
                })?
                .try_into()
                .map_err(|_| {
                    anyhow::anyhow!(
                        "invalid persisted rate limiter identity length: {}",
                        state.identity_hex
                    )
                })?;
            let identity = NodeId::from_bytes(identity_bytes);
            if !state.messages.is_empty() {
                limiter.message_windows.insert(identity, state.messages);
            }
            if !state.rejects.is_empty() {
                limiter
                    .reject_windows
                    .insert(identity, state.rejects.into_iter().collect());
            }
            if !state.contacts.is_empty() {
                limiter.contact_windows.insert(identity, state.contacts);
            }
        }
        for (identity_hex, rejected_at) in reject_history {
            let identity_bytes: [u8; 32] = hex::decode(&identity_hex)
                .map_err(|error| {
                    anyhow::anyhow!("invalid persisted reject identity {identity_hex}: {error}")
                })?
                .try_into()
                .map_err(|_| {
                    anyhow::anyhow!("invalid persisted reject identity length: {identity_hex}")
                })?;
            limiter
                .rolling_reject_windows
                .entry(NodeId::from_bytes(identity_bytes))
                .or_default()
                .push_back(rejected_at);
        }
        for (identity_hex, first_seen_at) in first_seen_rows {
            let identity_bytes: [u8; 32] = hex::decode(&identity_hex)
                .map_err(|error| {
                    anyhow::anyhow!("invalid first-seen identity {identity_hex}: {error}")
                })?
                .try_into()
                .map_err(|_| {
                    anyhow::anyhow!("invalid first-seen identity length: {identity_hex}")
                })?;
            limiter
                .first_seen
                .insert(NodeId::from_bytes(identity_bytes), first_seen_at);
        }

        let handle = tokio::runtime::Handle::try_current().map_err(|error| {
            anyhow::anyhow!("RateLimiter::with_storage requires a Tokio runtime: {error}")
        })?;
        let (persistence, persistence_rx) =
            RateLimiterPersistence::new(RATE_LIMITER_PERSIST_QUEUE_CAPACITY, abuse_metrics);
        let pending = Arc::clone(&persistence.pending);
        handle.spawn(RateLimiterPersistence::run_persistence_worker(
            storage,
            persistence_rx,
            pending,
        ));
        limiter.persistence = Some(persistence);
        limiter.cleanup_old(now);
        Ok(limiter)
    }

    pub async fn flush_persistence(&self) -> anyhow::Result<()> {
        let Some(persistence) = self.persistence.as_ref() else {
            return Ok(());
        };
        let (reply, result) = oneshot::channel();
        if persistence
            .sender
            .send(PersistenceMessage::Flush(reply))
            .await
            .is_err()
        {
            persistence.mark_worker_stopped();
            return Err(anyhow::anyhow!("rate limiter persistence worker stopped"));
        }
        match result.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(anyhow::anyhow!("rate limiter persistence failed: {error}")),
            Err(_) => {
                persistence.mark_worker_stopped();
                Err(anyhow::anyhow!("rate limiter persistence worker stopped"))
            }
        }
    }

    /// Проверить, может ли sender отправить ещё одно сообщение.
    /// Обновляет окно (добавляет timestamp), если разрешено.
    pub fn check_message(&mut self, sender: &NodeId, now: u64) -> RateDecision {
        self.cleanup_old(now);
        if let std::collections::hash_map::Entry::Vacant(entry) = self.first_seen.entry(*sender) {
            entry.insert(now);
            if let Some(persistence) = self.persistence.as_ref() {
                persistence.enqueue_first_seen(sender.to_hex(), now);
            }
        }
        let hourly_limit_exceeded = {
            let window = self.message_windows.entry(*sender).or_default();
            window.retain(|timestamp| now.saturating_sub(*timestamp) < RATE_MESSAGE_WINDOW_SECS);
            window.len() as u32 >= RATE_MESSAGES_PER_HOUR
        };

        if hourly_limit_exceeded {
            let rejects = self.reject_windows.entry(*sender).or_default();
            rejects.retain(|timestamp| now.saturating_sub(*timestamp) < RATE_REJECT_WINDOW_SECS);
            rejects.push_back(now);
            self.rolling_reject_windows
                .entry(*sender)
                .or_default()
                .push_back(now);
            if let Some(persistence) = self.persistence.as_ref() {
                persistence.enqueue_reject(sender.to_hex(), now);
            }
            self.queue_persist_state(sender);
            return RateDecision::Reject("rate limit exceeded".into());
        }

        self.message_windows.entry(*sender).or_default().push(now);
        let accepted = self.accepted_counts.entry(*sender).or_default();
        *accepted = accepted.saturating_add(1);
        let burst = self.record_burst_message(sender, now);
        self.queue_persist_state(sender);
        match burst {
            BurstResult::BelowThreshold => RateDecision::Allow,
            BurstResult::Throttled => RateDecision::Throttle {
                reason: "burst threshold reached; Watching tier (0.1x)".into(),
            },
        }
    }

    pub fn record_burst_message(&mut self, sender: &NodeId, now: u64) -> BurstResult {
        let window = self.burst_windows.entry(*sender).or_default();
        window.retain(|timestamp| now.saturating_sub(*timestamp) < RATE_BURST_WINDOW_SECS);
        let threshold_exceeded = window.len() as u32 >= RATE_BURST_MESSAGES;
        window.push_back(now);
        if threshold_exceeded {
            BurstResult::Throttled
        } else {
            BurstResult::BelowThreshold
        }
    }

    /// Проверить, может ли node добавить ещё один контакт.
    /// Обновляет окно, если разрешено.
    pub fn check_contact_add(&mut self, node: &NodeId, now: u64) -> RateDecision {
        let window = self.contact_windows.entry(*node).or_default();
        window.retain(|timestamp| now.saturating_sub(*timestamp) < RATE_CONTACT_WINDOW_SECS);

        let count = window.len() as u32;
        if count >= RATE_NEW_CONTACTS_PER_DAY {
            return RateDecision::Reject("daily contact limit exceeded".into());
        }

        window.push(now);

        let decision = if count >= RATE_NEW_CONTACTS_ANOMALOUS {
            RateDecision::Warn("anomalous contact rate".into())
        } else if count >= RATE_NEW_CONTACTS_SUSPICIOUS {
            RateDecision::Warn("suspicious contact rate".into())
        } else {
            RateDecision::Allow
        };
        self.queue_persist_state(node);
        decision
    }

    /// Удалить устаревшие timestamps из обоих окон.
    pub fn cleanup_old(&mut self, now: u64) {
        let mut changed_identities = HashSet::new();
        for (identity, timestamps) in self.message_windows.iter_mut() {
            let previous_len = timestamps.len();
            timestamps
                .retain(|timestamp| now.saturating_sub(*timestamp) < RATE_MESSAGE_WINDOW_SECS);
            if timestamps.len() != previous_len {
                changed_identities.insert(*identity);
            }
        }
        for (identity, timestamps) in self.reject_windows.iter_mut() {
            let previous_len = timestamps.len();
            timestamps.retain(|timestamp| now.saturating_sub(*timestamp) < RATE_REJECT_WINDOW_SECS);
            if timestamps.len() != previous_len {
                changed_identities.insert(*identity);
            }
        }
        for timestamps in self.rolling_reject_windows.values_mut() {
            timestamps
                .retain(|timestamp| now.saturating_sub(*timestamp) < RATE_ROLLING_WINDOW_SECS);
        }
        for timestamps in self.burst_windows.values_mut() {
            timestamps.retain(|timestamp| now.saturating_sub(*timestamp) < RATE_BURST_WINDOW_SECS);
        }
        for (identity, timestamps) in self.contact_windows.iter_mut() {
            let previous_len = timestamps.len();
            timestamps
                .retain(|timestamp| now.saturating_sub(*timestamp) < RATE_CONTACT_WINDOW_SECS);
            if timestamps.len() != previous_len {
                changed_identities.insert(*identity);
            }
        }
        self.message_windows
            .retain(|_, timestamps| !timestamps.is_empty());
        self.reject_windows
            .retain(|_, timestamps| !timestamps.is_empty());
        self.rolling_reject_windows
            .retain(|_, timestamps| !timestamps.is_empty());
        self.burst_windows
            .retain(|_, timestamps| !timestamps.is_empty());
        self.contact_windows
            .retain(|_, timestamps| !timestamps.is_empty());
        for identity in changed_identities {
            self.queue_persist_state(&identity);
        }
    }

    /// Текущее число сообщений в окне (без обновления).
    pub fn messages_in_window(&self, sender: &NodeId, now: u64) -> usize {
        self.message_windows
            .get(sender)
            .map(|timestamps| {
                timestamps
                    .iter()
                    .filter(|timestamp| now.saturating_sub(**timestamp) < RATE_MESSAGE_WINDOW_SECS)
                    .count()
            })
            .unwrap_or(0)
    }

    /// Количество отклонённых сообщений в окне (без обновления).
    pub fn rejects_in_window(&self, identity: &NodeId, now: u64) -> usize {
        let cutoff = now.saturating_sub(RATE_REJECT_WINDOW_SECS);
        self.reject_windows
            .get(identity)
            .map(|timestamps| {
                timestamps
                    .iter()
                    .filter(|timestamp| **timestamp > cutoff)
                    .count()
            })
            .unwrap_or(0)
    }

    /// Текущий rate-limit tier по истории отклонённых сообщений (без обновления).
    pub fn current_tier(&self, identity: &NodeId, now: u64) -> RateTier {
        let rejects = self.rejects_in_window(identity, now);
        let hourly_tier = if rejects >= RATE_REJECT_BLOCKED {
            RateTier::Blocked
        } else if rejects >= RATE_REJECT_WARNING {
            RateTier::Warning
        } else if rejects >= RATE_REJECT_THROTTLE {
            RateTier::Throttled
        } else {
            RateTier::Normal
        };
        let rolling_rejects = self
            .rolling_reject_windows
            .get(identity)
            .map(|timestamps| {
                timestamps
                    .iter()
                    .filter(|timestamp| now.saturating_sub(**timestamp) < RATE_ROLLING_WINDOW_SECS)
                    .count() as u32
            })
            .unwrap_or(0);
        let rolling_tier = if rolling_rejects >= RATE_ROLLING_BLOCKED {
            RateTier::Blocked
        } else if rolling_rejects >= RATE_ROLLING_WARNING {
            RateTier::Warning
        } else if rolling_rejects >= RATE_ROLLING_WATCHING {
            RateTier::Throttled
        } else if self.burst_windows.get(identity).is_some_and(|timestamps| {
            timestamps
                .iter()
                .filter(|timestamp| now.saturating_sub(**timestamp) < RATE_BURST_WINDOW_SECS)
                .count() as u32
                >= RATE_BURST_MESSAGES
        }) {
            RateTier::Throttled
        } else {
            RateTier::Normal
        };
        let first_contact_tier = self.first_contact_tier(identity, now);
        match (hourly_tier, rolling_tier) {
            (RateTier::Blocked, _) | (_, RateTier::Blocked) => RateTier::Blocked,
            (RateTier::Warning, _) | (_, RateTier::Warning) => RateTier::Warning,
            (RateTier::Throttled, _) | (_, RateTier::Throttled) => RateTier::Throttled,
            (_, _) if first_contact_tier == RateTier::Throttled => RateTier::Throttled,
            _ => RateTier::Normal,
        }
    }

    fn first_contact_tier(&self, identity: &NodeId, now: u64) -> RateTier {
        let Some(first_seen) = self.first_seen.get(identity) else {
            return RateTier::Normal;
        };
        let window_elapsed = now.saturating_sub(*first_seen) >= FIRST_CONTACT_WINDOW_SECS;
        let threshold_passed = self.accepted_counts.get(identity).copied().unwrap_or(0)
            >= FIRST_CONTACT_ACCEPTED_THRESHOLD;
        if window_elapsed && threshold_passed {
            RateTier::Normal
        } else {
            RateTier::Throttled
        }
    }

    /// Текущее число контактов в окне (без обновления).
    pub fn contacts_in_window(&self, node: &NodeId, now: u64) -> usize {
        self.contact_windows
            .get(node)
            .map(|timestamps| {
                timestamps
                    .iter()
                    .filter(|timestamp| now.saturating_sub(**timestamp) < RATE_CONTACT_WINDOW_SECS)
                    .count()
            })
            .unwrap_or(0)
    }

    /// Количество отслеживаемых nodes.
    pub fn tracked_nodes(&self) -> usize {
        self.message_windows
            .keys()
            .chain(self.reject_windows.keys())
            .chain(self.rolling_reject_windows.keys())
            .chain(self.contact_windows.keys())
            .collect::<HashSet<_>>()
            .len()
    }

    fn queue_persist_state(&self, identity: &NodeId) {
        let Some(persistence) = self.persistence.as_ref() else {
            return;
        };
        let identity_hex = identity.to_hex();
        let messages = self.message_windows.get(identity);
        let rejects = self.reject_windows.get(identity);
        let contacts = self.contact_windows.get(identity);
        let has_state = messages.is_some_and(|values| !values.is_empty())
            || rejects.is_some_and(|values| !values.is_empty())
            || contacts.is_some_and(|values| !values.is_empty());
        let snapshot = if has_state {
            PersistenceSnapshot::Save(RateLimiterState {
                identity_hex: identity_hex.clone(),
                messages: messages.cloned().unwrap_or_default(),
                rejects: rejects
                    .map(|values| values.iter().copied().collect())
                    .unwrap_or_default(),
                contacts: contacts.cloned().unwrap_or_default(),
            })
        } else {
            PersistenceSnapshot::Delete
        };
        let _ = persistence.enqueue(identity_hex, snapshot);
    }
}

fn persist_rate_limiter_state(
    storage: &Arc<StdMutex<ClientStorage>>,
    state: &RateLimiterState,
) -> anyhow::Result<()> {
    storage
        .lock()
        .map_err(|_| anyhow::anyhow!("client storage mutex poisoned"))?
        .identity_history()
        .save_rate_limiter_state(state, unix_now_secs()?)
}

fn unix_now_secs() -> anyhow::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| anyhow::anyhow!("system clock is before Unix epoch: {error}"))
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(seed: u8) -> NodeId {
        NodeId::from_bytes([seed; 32])
    }

    fn fill_message_window(limiter: &mut RateLimiter, sender: &NodeId) {
        for now in 0..RATE_MESSAGES_PER_HOUR as u64 {
            assert!(limiter.check_message(sender, now).is_allowed());
        }
    }

    fn record_rejects(limiter: &mut RateLimiter, sender: &NodeId, count: usize) {
        fill_message_window(limiter, sender);
        let start = RATE_MESSAGES_PER_HOUR as u64;
        for now in start..start + count as u64 {
            assert!(limiter.check_message(sender, now).is_rejected());
        }
    }

    fn seed_established_peer(limiter: &mut RateLimiter, sender: &NodeId, now: u64) {
        limiter
            .first_seen
            .insert(*sender, now.saturating_sub(FIRST_CONTACT_WINDOW_SECS));
        limiter
            .accepted_counts
            .insert(*sender, FIRST_CONTACT_ACCEPTED_THRESHOLD);
    }

    #[test]
    fn new_limiter_empty() {
        let limiter = RateLimiter::new();
        assert_eq!(limiter.tracked_nodes(), 0);
    }

    #[test]
    fn first_message_allowed() {
        let mut limiter = RateLimiter::new();
        let decision = limiter.check_message(&node(1), 100);
        assert_eq!(decision, RateDecision::Allow);
    }

    #[test]
    fn fifty_messages_allowed() {
        let mut limiter = RateLimiter::new();
        for now in 0..RATE_MESSAGES_PER_HOUR as u64 {
            let decision = limiter.check_message(&node(2), now);
            assert!(decision.is_allowed());
        }
    }

    #[test]
    fn fifty_first_rejected_and_recovered_after_window() {
        let mut limiter = RateLimiter::new();
        let sender = node(3);

        // 50 сообщений — разрешены.
        for now in 0..RATE_MESSAGES_PER_HOUR as u64 {
            assert!(limiter.check_message(&sender, now).is_allowed());
        }

        // 51-е в том же окне — Reject.
        let decision = limiter.check_message(&sender, 50);
        assert!(
            decision.is_rejected(),
            "expected rejection, got {:?}",
            decision
        );

        // 52-е через час+1сек — старые истекли, Allow.
        let future = RATE_MESSAGE_WINDOW_SECS + 1;
        let decision = limiter.check_message(&sender, future);
        assert!(
            decision.is_allowed(),
            "expected recovery after window, got {:?}",
            decision
        );
    }

    #[test]
    fn current_tier_normal_no_history() {
        let limiter = RateLimiter::new();
        assert_eq!(limiter.current_tier(&node(22), 100), RateTier::Normal);
    }

    #[test]
    fn current_tier_throttled_after_3_rejects() {
        let mut limiter = RateLimiter::new();
        let sender = node(23);
        record_rejects(&mut limiter, &sender, RATE_REJECT_THROTTLE);
        assert_eq!(limiter.current_tier(&sender, 52), RateTier::Throttled);
    }

    #[test]
    fn current_tier_warning_after_10_rejects() {
        let mut limiter = RateLimiter::new();
        let sender = node(24);
        record_rejects(&mut limiter, &sender, RATE_REJECT_WARNING);
        assert_eq!(limiter.current_tier(&sender, 59), RateTier::Warning);
    }

    #[test]
    fn current_tier_blocked_after_50_rejects() {
        let mut limiter = RateLimiter::new();
        let sender = node(25);
        record_rejects(&mut limiter, &sender, RATE_REJECT_BLOCKED);
        assert_eq!(limiter.current_tier(&sender, 99), RateTier::Blocked);
    }

    #[test]
    fn burst_below_threshold_passes() {
        let mut limiter = RateLimiter::new();
        let sender = node(31);
        let start = FIRST_CONTACT_WINDOW_SECS + 1;
        seed_established_peer(&mut limiter, &sender, start);
        for now in start..start + u64::from(RATE_BURST_MESSAGES - 1) {
            assert_eq!(limiter.check_message(&sender, now), RateDecision::Allow);
        }
        assert_eq!(
            limiter.current_tier(&sender, start + u64::from(RATE_BURST_MESSAGES - 2)),
            RateTier::Normal
        );
    }

    #[test]
    fn burst_at_threshold_throttles() {
        let mut limiter = RateLimiter::new();
        let sender = node(32);
        let start = FIRST_CONTACT_WINDOW_SECS + 1;
        seed_established_peer(&mut limiter, &sender, start);
        for now in start..start + u64::from(RATE_BURST_MESSAGES) {
            assert!(limiter.check_message(&sender, now).is_allowed());
        }

        let decision = limiter.check_message(&sender, start + u64::from(RATE_BURST_MESSAGES));
        assert!(matches!(decision, RateDecision::Throttle { .. }));
        assert!(decision.is_allowed());
        assert_eq!(
            limiter.current_tier(&sender, start + u64::from(RATE_BURST_MESSAGES)),
            RateTier::Throttled
        );
        assert_eq!(RateTier::Throttled.rate_multiplier(), 0.1);
    }

    #[test]
    fn burst_window_expires_after_30s() {
        let mut limiter = RateLimiter::new();
        let sender = node(33);
        let start = FIRST_CONTACT_WINDOW_SECS + 1;
        seed_established_peer(&mut limiter, &sender, start);
        for _ in 0..=RATE_BURST_MESSAGES {
            limiter.check_message(&sender, start);
        }

        assert_eq!(
            limiter.current_tier(&sender, start + 29),
            RateTier::Throttled
        );
        assert_eq!(limiter.current_tier(&sender, start + 30), RateTier::Normal);
    }

    #[test]
    fn rolling_50_rejects_returns_watching() {
        let mut limiter = RateLimiter::new();
        let sender = node(34);
        limiter
            .rolling_reject_windows
            .insert(sender, (0..RATE_ROLLING_WATCHING as u64).collect());

        assert_eq!(limiter.current_tier(&sender, 100), RateTier::Throttled);
    }

    #[test]
    fn rolling_500_rejects_returns_blocked() {
        let mut limiter = RateLimiter::new();
        let sender = node(35);
        limiter
            .rolling_reject_windows
            .insert(sender, (0..RATE_ROLLING_BLOCKED as u64).collect());

        assert_eq!(limiter.current_tier(&sender, 1_000), RateTier::Blocked);
    }

    #[test]
    fn first_contact_new_peer_returns_throttled() {
        let mut limiter = RateLimiter::new();
        let sender = node(36);
        limiter.first_seen.insert(sender, 100);

        assert_eq!(limiter.current_tier(&sender, 100), RateTier::Throttled);
    }

    #[test]
    fn first_contact_window_elapsed_but_threshold_not_met_returns_throttled() {
        let mut limiter = RateLimiter::new();
        let sender = node(37);
        limiter.first_seen.insert(sender, 100);

        assert_eq!(
            limiter.current_tier(&sender, 100 + FIRST_CONTACT_WINDOW_SECS),
            RateTier::Throttled
        );
    }

    #[test]
    fn first_contact_threshold_met_but_window_not_elapsed_returns_throttled() {
        let mut limiter = RateLimiter::new();
        let sender = node(38);
        limiter.first_seen.insert(sender, 100);
        limiter
            .accepted_counts
            .insert(sender, FIRST_CONTACT_ACCEPTED_THRESHOLD);

        assert_eq!(
            limiter.current_tier(&sender, 100 + FIRST_CONTACT_WINDOW_SECS - 1),
            RateTier::Throttled
        );
    }

    #[test]
    fn first_contact_both_conditions_met_returns_normal() {
        let mut limiter = RateLimiter::new();
        let sender = node(39);
        limiter.first_seen.insert(sender, 100);
        limiter
            .accepted_counts
            .insert(sender, FIRST_CONTACT_ACCEPTED_THRESHOLD);

        assert_eq!(
            limiter.current_tier(&sender, 100 + FIRST_CONTACT_WINDOW_SECS),
            RateTier::Normal
        );
    }

    #[test]
    fn first_contact_unknown_peer_not_affected() {
        let limiter = RateLimiter::new();

        assert_eq!(limiter.current_tier(&node(40), 100), RateTier::Normal);
    }

    #[test]
    fn first_contact_does_not_override_blocked() {
        let mut limiter = RateLimiter::new();
        let sender = node(41);
        limiter.first_seen.insert(sender, 100);
        limiter
            .rolling_reject_windows
            .insert(sender, (0..RATE_ROLLING_BLOCKED as u64).collect());

        assert_eq!(limiter.current_tier(&sender, 100), RateTier::Blocked);
    }

    #[test]
    fn first_contact_stricter_than_burst() {
        let mut limiter = RateLimiter::new();
        let sender = node(42);
        limiter.first_seen.insert(sender, 100);
        limiter
            .burst_windows
            .insert(sender, (0..RATE_BURST_MESSAGES as u64).collect());

        assert_eq!(limiter.current_tier(&sender, 105), RateTier::Throttled);
    }

    #[tokio::test]
    async fn first_contact_bootstraps_from_persisted_first_seen() {
        let directory = tempfile::tempdir().expect("temporary storage directory");
        let sender = node(43);
        let now = unix_now_secs().expect("current time");
        let storage = open_rate_limiter_storage(&directory);
        {
            let storage_guard = storage.lock().expect("storage lock");
            storage_guard
                .identity_history()
                .observe_first_seen(&sender.to_hex(), now)
                .expect("persist first-seen timestamp");
        }

        let limiter = RateLimiter::with_storage(storage).expect("load rate limiter");

        assert_eq!(limiter.current_tier(&sender, now), RateTier::Throttled);
    }

    #[tokio::test]
    async fn first_contact_check_persists_first_seen_and_counts_acceptance() {
        let directory = tempfile::tempdir().expect("temporary storage directory");
        let sender = node(44);
        let now = unix_now_secs().expect("current time");
        let storage = open_rate_limiter_storage(&directory);
        let mut limiter =
            RateLimiter::with_storage(Arc::clone(&storage)).expect("load rate limiter");

        assert!(limiter.check_message(&sender, now).is_allowed());
        assert_eq!(limiter.accepted_counts.get(&sender), Some(&1));
        limiter
            .flush_persistence()
            .await
            .expect("persist first-seen timestamp");
        assert_eq!(
            storage
                .lock()
                .expect("storage lock")
                .identity_history()
                .first_seen(&sender.to_hex())
                .expect("read first-seen timestamp"),
            Some(now)
        );
    }

    #[test]
    fn current_tier_ignores_expired_rejects() {
        let mut limiter = RateLimiter::new();
        let sender = node(26);
        record_rejects(&mut limiter, &sender, RATE_REJECT_THROTTLE);
        let now = FIRST_CONTACT_WINDOW_SECS + RATE_REJECT_WINDOW_SECS + 53;
        limiter.first_seen.insert(sender, 0);
        limiter
            .accepted_counts
            .insert(sender, FIRST_CONTACT_ACCEPTED_THRESHOLD);
        assert_eq!(limiter.current_tier(&sender, now), RateTier::Normal);
    }

    #[test]
    fn rejects_at_exact_boundary_expire() {
        let mut limiter = RateLimiter::new();
        let sender = node(30);
        fill_message_window(&mut limiter, &sender);
        assert!(limiter
            .check_message(&sender, RATE_MESSAGES_PER_HOUR as u64)
            .is_rejected());

        let now = RATE_REJECT_WINDOW_SECS + RATE_MESSAGES_PER_HOUR as u64;
        seed_established_peer(&mut limiter, &sender, now + FIRST_CONTACT_WINDOW_SECS);
        assert_eq!(limiter.rejects_in_window(&sender, now), 0);
        assert_eq!(
            limiter.current_tier(&sender, now + FIRST_CONTACT_WINDOW_SECS),
            RateTier::Normal
        );
    }

    #[test]
    fn cleanup_runs_on_check_message() {
        let mut limiter = RateLimiter::new();
        let message_sender = node(31);
        let contact_owner = node(32);
        let next_sender = node(33);

        record_rejects(&mut limiter, &message_sender, RATE_REJECT_THROTTLE);
        assert!(limiter.check_contact_add(&contact_owner, 100).is_allowed());

        assert!(limiter
            .check_message(&next_sender, RATE_CONTACT_WINDOW_SECS + 101)
            .is_allowed());

        assert_eq!(limiter.tracked_nodes(), 2);
        assert_eq!(
            limiter.messages_in_window(&message_sender, RATE_CONTACT_WINDOW_SECS + 101),
            0
        );
        assert_eq!(
            limiter.rejects_in_window(&message_sender, RATE_CONTACT_WINDOW_SECS + 101),
            0
        );
        assert_eq!(
            limiter.contacts_in_window(&contact_owner, RATE_CONTACT_WINDOW_SECS + 101),
            0
        );
    }

    #[test]
    fn current_tier_pure_read_no_mutation() {
        let mut limiter = RateLimiter::new();
        let sender = node(27);
        record_rejects(&mut limiter, &sender, RATE_REJECT_WARNING);
        let messages_before = limiter.messages_in_window(&sender, 59);
        let rejects_before = limiter.rejects_in_window(&sender, 59);

        assert_eq!(limiter.current_tier(&sender, 59), RateTier::Warning);
        assert_eq!(limiter.current_tier(&sender, 59), RateTier::Warning);
        assert_eq!(limiter.messages_in_window(&sender, 59), messages_before);
        assert_eq!(limiter.rejects_in_window(&sender, 59), rejects_before);
        assert_eq!(
            limiter.current_tier(&sender, RATE_REJECT_WINDOW_SECS + 60),
            RateTier::Throttled
        );
        assert_eq!(limiter.current_tier(&sender, 59), RateTier::Warning);
    }

    #[test]
    fn reject_decision_records_in_reject_windows() {
        let mut limiter = RateLimiter::new();
        let sender = node(28);
        fill_message_window(&mut limiter, &sender);

        assert!(limiter.check_message(&sender, 50).is_rejected());
        assert_eq!(limiter.rejects_in_window(&sender, 50), 1);
        assert_eq!(limiter.tracked_nodes(), 1);
    }

    #[test]
    fn accept_decision_does_not_record_reject() {
        let mut limiter = RateLimiter::new();
        let sender = node(29);

        assert!(limiter.check_message(&sender, 100).is_allowed());
        assert_eq!(limiter.rejects_in_window(&sender, 100), 0);
    }

    #[test]
    fn rate_multiplier_correct_for_each_tier() {
        assert_eq!(RateTier::Normal.rate_multiplier(), 1.0);
        assert_eq!(RateTier::Throttled.rate_multiplier(), 0.1);
        assert_eq!(RateTier::Warning.rate_multiplier(), 0.01);
        assert_eq!(RateTier::Blocked.rate_multiplier(), 0.0);
        assert!(RateTier::Normal.is_normal());
        assert!(!RateTier::Throttled.is_normal());
    }

    #[test]
    fn messages_in_window_counts_correctly() {
        let mut limiter = RateLimiter::new();
        limiter.check_message(&node(4), 10);
        limiter.check_message(&node(4), 20);
        limiter.check_message(&node(4), 30);
        assert_eq!(limiter.messages_in_window(&node(4), 30), 3);
    }

    #[test]
    fn old_messages_expire() {
        let mut limiter = RateLimiter::new();
        limiter.check_message(&node(5), 10);
        limiter.check_message(&node(5), 20);
        assert_eq!(
            limiter.messages_in_window(&node(5), RATE_MESSAGE_WINDOW_SECS + 50),
            0
        );
    }

    #[test]
    fn first_contact_add_allowed() {
        let mut limiter = RateLimiter::new();
        let decision = limiter.check_contact_add(&node(6), 100);
        assert_eq!(decision, RateDecision::Allow);
    }

    #[test]
    fn suspicious_threshold_warns() {
        let mut limiter = RateLimiter::new();
        for now in 0..RATE_NEW_CONTACTS_SUSPICIOUS as u64 {
            let decision = limiter.check_contact_add(&node(7), now + 1);
            assert!(decision.is_allowed());
        }
        let decision = limiter.check_contact_add(&node(7), RATE_NEW_CONTACTS_SUSPICIOUS as u64 + 1);
        assert!(matches!(decision, RateDecision::Warn(_)));
    }

    #[test]
    fn anomalous_threshold_warns() {
        let mut limiter = RateLimiter::new();
        for now in 0..RATE_NEW_CONTACTS_ANOMALOUS as u64 {
            let decision = limiter.check_contact_add(&node(8), now + 1);
            assert!(decision.is_allowed());
        }
        let decision = limiter.check_contact_add(&node(8), RATE_NEW_CONTACTS_ANOMALOUS as u64 + 1);
        assert!(matches!(decision, RateDecision::Warn(_)));
    }

    #[test]
    fn hard_limit_rejects() {
        let mut limiter = RateLimiter::new();
        for now in 0..RATE_NEW_CONTACTS_PER_DAY as u64 {
            let decision = limiter.check_contact_add(&node(9), now + 1);
            assert!(decision.is_allowed() || matches!(decision, RateDecision::Warn(_)));
        }
        let decision = limiter.check_contact_add(&node(9), RATE_NEW_CONTACTS_PER_DAY as u64 + 1);
        assert!(decision.is_rejected());
    }

    #[test]
    fn contact_limit_recovers_after_24h() {
        let mut limiter = RateLimiter::new();
        let target = node(10);

        // Заполняем окно до hard limit.
        for now in 0..RATE_NEW_CONTACTS_PER_DAY as u64 {
            let _ = limiter.check_contact_add(&target, now);
        }

        // 501-й — Reject.
        let decision = limiter.check_contact_add(&target, RATE_NEW_CONTACTS_PER_DAY as u64);
        assert!(decision.is_rejected());

        // Через 24h+1сек — Allow.
        let future = RATE_CONTACT_WINDOW_SECS + 1;
        let decision = limiter.check_contact_add(&target, future);
        assert!(
            decision.is_allowed(),
            "expected recovery after 24h, got {:?}",
            decision
        );
    }

    #[test]
    fn cleanup_old_removes_expired() {
        let mut limiter = RateLimiter::new();
        limiter.check_message(&node(10), 10);
        limiter.check_contact_add(&node(11), 10);
        limiter.cleanup_old(RATE_MESSAGE_WINDOW_SECS + RATE_CONTACT_WINDOW_SECS + 10);
        assert_eq!(
            limiter.messages_in_window(
                &node(10),
                RATE_MESSAGE_WINDOW_SECS + RATE_CONTACT_WINDOW_SECS + 10
            ),
            0
        );
        assert_eq!(
            limiter.contacts_in_window(
                &node(11),
                RATE_MESSAGE_WINDOW_SECS + RATE_CONTACT_WINDOW_SECS + 10
            ),
            0
        );
    }

    #[test]
    fn cleanup_old_removes_empty_entries() {
        let mut limiter = RateLimiter::new();
        limiter.check_message(&node(12), 10);
        limiter.check_contact_add(&node(13), 10);
        limiter.cleanup_old(RATE_MESSAGE_WINDOW_SECS + RATE_CONTACT_WINDOW_SECS + 100);
        assert_eq!(limiter.tracked_nodes(), 0);
    }

    #[test]
    fn with_storage_returns_error_outside_runtime() {
        let directory = tempfile::tempdir().expect("temporary storage directory");
        let storage = open_rate_limiter_storage(&directory);
        let result = RateLimiter::with_storage(storage);
        assert!(matches!(
            result,
            Err(error) if error.to_string().contains("requires a Tokio runtime")
        ));
    }

    fn open_rate_limiter_storage(directory: &tempfile::TempDir) -> Arc<StdMutex<ClientStorage>> {
        let storage =
            ClientStorage::open(directory.path().join("rate-limiter.sqlite3"), &[0x42; 32])
                .expect("open rate limiter storage");
        Arc::new(StdMutex::new(storage))
    }

    fn persisted_snapshot(identity: &NodeId, timestamp: u64) -> PersistenceSnapshot {
        PersistenceSnapshot::Save(RateLimiterState {
            identity_hex: identity.to_hex(),
            messages: vec![timestamp],
            rejects: Vec::new(),
            contacts: Vec::new(),
        })
    }

    fn rate_limiter_with_stopped_worker(metrics: Arc<AbuseMetrics>) -> RateLimiter {
        let (persistence, receiver) =
            RateLimiterPersistence::new(RATE_LIMITER_PERSIST_QUEUE_CAPACITY, metrics);
        drop(receiver);
        RateLimiter {
            message_windows: HashMap::new(),
            reject_windows: HashMap::new(),
            rolling_reject_windows: HashMap::new(),
            burst_windows: HashMap::new(),
            first_seen: HashMap::new(),
            accepted_counts: HashMap::new(),
            contact_windows: HashMap::new(),
            persistence: Some(persistence),
        }
    }

    async fn flush_persistence_queue(
        persistence: &RateLimiterPersistence,
    ) -> std::result::Result<(), String> {
        let (reply, result) = oneshot::channel();
        persistence
            .sender
            .send(PersistenceMessage::Flush(reply))
            .await
            .map_err(|_| "rate limiter persistence worker stopped".to_owned())?;
        result
            .await
            .map_err(|_| "rate limiter persistence worker stopped".to_owned())?
    }

    #[test]
    fn persistence_queue_bounded_under_spam() {
        let identity = node(45);
        let (persistence, receiver) = RateLimiterPersistence::new(
            RATE_LIMITER_PERSIST_QUEUE_CAPACITY,
            Arc::new(AbuseMetrics::new()),
        );

        for timestamp in 0..10_000 {
            persistence.enqueue(identity.to_hex(), persisted_snapshot(&identity, timestamp));
        }

        assert!(receiver.len() <= RATE_LIMITER_PERSIST_QUEUE_CAPACITY);
        assert!(persistence.pending_len() <= RATE_LIMITER_PERSIST_QUEUE_CAPACITY);
        assert_eq!(receiver.len(), 1);
        assert_eq!(persistence.pending_len(), 1);
    }

    #[test]
    fn persistence_coalesce_same_identity() {
        let identity = node(46);
        let (persistence, receiver) = RateLimiterPersistence::new(
            RATE_LIMITER_PERSIST_QUEUE_CAPACITY,
            Arc::new(AbuseMetrics::new()),
        );

        assert_eq!(
            persistence.enqueue(identity.to_hex(), persisted_snapshot(&identity, 0)),
            QueueResult::Queued
        );
        for timestamp in 1..100 {
            assert_eq!(
                persistence.enqueue(identity.to_hex(), persisted_snapshot(&identity, timestamp)),
                QueueResult::Coalesced
            );
        }

        let pending = persistence.pending.lock().expect("pending lock");
        let Some(PersistenceSnapshot::Save(latest)) = pending.get(&identity.to_hex()) else {
            panic!("latest identity snapshot missing");
        };
        assert_eq!(latest.messages, vec![99]);
        assert_eq!(pending.len(), 1);
        assert_eq!(receiver.len(), 1);
    }

    #[test]
    fn persistence_worker_death_sets_metric() {
        let identity = node(47);
        let metrics = Arc::new(AbuseMetrics::new());
        let (persistence, receiver) =
            RateLimiterPersistence::new(RATE_LIMITER_PERSIST_QUEUE_CAPACITY, Arc::clone(&metrics));
        drop(receiver);

        assert_eq!(
            persistence.enqueue(identity.to_hex(), persisted_snapshot(&identity, 100)),
            QueueResult::WorkerStopped
        );
        assert_eq!(
            metrics
                .rate_limiter_worker_failed_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn pending_not_accumulated_after_worker_death() {
        let metrics = Arc::new(AbuseMetrics::new());
        let (persistence, receiver) =
            RateLimiterPersistence::new(RATE_LIMITER_PERSIST_QUEUE_CAPACITY, Arc::clone(&metrics));
        for seed in 60..65 {
            let identity = node(seed);
            assert_eq!(
                persistence.enqueue(identity.to_hex(), persisted_snapshot(&identity, 100)),
                QueueResult::Queued
            );
        }
        drop(receiver);

        for seed in 100..200 {
            let identity = node(seed);
            assert_eq!(
                persistence.enqueue(identity.to_hex(), persisted_snapshot(&identity, 200)),
                QueueResult::WorkerStopped
            );
        }
        assert_eq!(persistence.pending_len(), 0);
        assert_eq!(
            metrics
                .rate_limiter_worker_failed_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn worker_death_metric_increments_once_per_worker() {
        let metrics = Arc::new(AbuseMetrics::new());
        let (persistence, receiver) =
            RateLimiterPersistence::new(RATE_LIMITER_PERSIST_QUEUE_CAPACITY, Arc::clone(&metrics));
        drop(receiver);

        for seed in 1..=100 {
            let identity = node(seed);
            assert_eq!(
                persistence.enqueue(identity.to_hex(), persisted_snapshot(&identity, 300)),
                QueueResult::WorkerStopped
            );
        }
        assert_eq!(persistence.pending_len(), 0);
        assert_eq!(
            metrics
                .rate_limiter_worker_failed_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn flush_persistence_after_worker_death_returns_error() {
        let metrics = Arc::new(AbuseMetrics::new());
        let limiter = rate_limiter_with_stopped_worker(Arc::clone(&metrics));

        let result = limiter.flush_persistence().await;
        assert!(matches!(
            result,
            Err(error) if error.to_string().contains("worker stopped")
        ));
        assert_eq!(
            metrics
                .rate_limiter_worker_failed_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn rate_limiting_continues_in_memory_after_worker_death() {
        let metrics = Arc::new(AbuseMetrics::new());
        let mut limiter = rate_limiter_with_stopped_worker(Arc::clone(&metrics));
        let identity = node(201);

        assert!(limiter.check_message(&identity, 100).is_allowed());
        assert_eq!(limiter.messages_in_window(&identity, 100), 1);
        assert_eq!(
            limiter
                .persistence
                .as_ref()
                .expect("persistence exists")
                .pending_len(),
            0
        );
        assert_eq!(
            metrics
                .rate_limiter_worker_failed_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn persistence_writer_survives_queue_full() {
        let directory = tempfile::tempdir().expect("temporary storage directory");
        let storage = open_rate_limiter_storage(&directory);
        let capacity = 2;
        let (persistence, receiver) =
            RateLimiterPersistence::new(capacity, Arc::new(AbuseMetrics::new()));
        let pending = Arc::clone(&persistence.pending);
        let mut queued = Vec::new();
        let mut dropped = Vec::new();

        for seed in 50..60 {
            let identity = node(seed);
            match persistence.enqueue(identity.to_hex(), persisted_snapshot(&identity, 100)) {
                QueueResult::Queued => queued.push(identity),
                QueueResult::DroppedFull => dropped.push(identity),
                result => panic!("unexpected queue result: {result:?}"),
            }
        }
        assert_eq!(queued.len(), capacity);
        assert_eq!(dropped.len(), 10 - capacity);
        assert_eq!(receiver.len(), capacity);
        assert_eq!(persistence.pending_len(), capacity);

        let worker = tokio::spawn(RateLimiterPersistence::run_persistence_worker(
            Arc::clone(&storage),
            receiver,
            pending,
        ));
        flush_persistence_queue(&persistence)
            .await
            .expect("writer processes snapshots before flush");
        assert_eq!(
            storage
                .lock()
                .expect("storage lock")
                .identity_history()
                .rate_limiter_states()
                .expect("read initial states")
                .len(),
            capacity
        );

        for identity in dropped {
            assert_eq!(
                persistence.enqueue(identity.to_hex(), persisted_snapshot(&identity, 200)),
                QueueResult::Queued
            );
            flush_persistence_queue(&persistence)
                .await
                .expect("writer remains available after queue overflow");
        }

        assert_eq!(
            storage
                .lock()
                .expect("storage lock")
                .identity_history()
                .rate_limiter_states()
                .expect("read final states")
                .len(),
            10
        );
        drop(persistence);
        worker.await.expect("persistence worker exits cleanly");
    }

    #[tokio::test]
    async fn rate_limiter_state_survives_restart() {
        let directory = tempfile::tempdir().expect("temporary storage directory");
        let sender = node(40);
        let now = unix_now_secs().expect("current time");
        {
            let storage = open_rate_limiter_storage(&directory);
            let mut limiter =
                RateLimiter::with_storage(Arc::clone(&storage)).expect("load rate limiter");
            for offset in 0..30 {
                assert!(limiter.check_message(&sender, now + offset).is_allowed());
            }
            limiter
                .flush_persistence()
                .await
                .expect("persist message history");
        }

        let storage = open_rate_limiter_storage(&directory);
        let limiter = RateLimiter::with_storage(storage).expect("reload rate limiter");
        assert_eq!(
            limiter.messages_in_window(&sender, now + 29),
            30,
            "accepted message timestamps survive restart"
        );
    }

    #[tokio::test]
    async fn rate_limiter_rejects_survive_restart() {
        let directory = tempfile::tempdir().expect("temporary storage directory");
        let sender = node(41);
        let now = unix_now_secs().expect("current time");
        {
            let storage = open_rate_limiter_storage(&directory);
            let mut limiter =
                RateLimiter::with_storage(Arc::clone(&storage)).expect("load rate limiter");
            for offset in 0..RATE_MESSAGES_PER_HOUR as u64 {
                assert!(limiter.check_message(&sender, now + offset).is_allowed());
            }
            for offset in 0..RATE_REJECT_THROTTLE as u64 {
                assert!(limiter
                    .check_message(&sender, now + RATE_MESSAGES_PER_HOUR as u64 + offset)
                    .is_rejected());
            }
            limiter
                .flush_persistence()
                .await
                .expect("persist reject history");
        }

        let storage = open_rate_limiter_storage(&directory);
        let limiter = RateLimiter::with_storage(storage).expect("reload rate limiter");
        assert_eq!(
            limiter.current_tier(
                &sender,
                now + RATE_MESSAGES_PER_HOUR as u64 + RATE_REJECT_THROTTLE as u64
            ),
            RateTier::Throttled
        );
    }

    #[tokio::test]
    async fn rate_limiter_rolling_reject_history_survives_restart() {
        let directory = tempfile::tempdir().expect("temporary storage directory");
        let sender = node(46);
        let now = unix_now_secs().expect("current time");
        {
            let storage = open_rate_limiter_storage(&directory);
            {
                let storage_guard = storage.lock().expect("storage lock");
                let history = storage_guard.identity_history();
                for offset in 0..RATE_ROLLING_WATCHING {
                    history
                        .record_reject(
                            &sender.to_hex(),
                            now + u64::from(offset),
                            "hourly_rate_limit",
                        )
                        .expect("persist rolling reject");
                }
            }
            let limiter = RateLimiter::with_storage(storage).expect("load rate limiter");
            assert_eq!(
                limiter.current_tier(&sender, now + u64::from(RATE_ROLLING_WATCHING)),
                RateTier::Throttled
            );
        }
    }

    #[tokio::test]
    async fn rate_limiter_cleanup_persists() {
        let directory = tempfile::tempdir().expect("temporary storage directory");
        let old_sender = node(42);
        let current_sender = node(43);
        let now = unix_now_secs().expect("current time");
        let old_time = now - RATE_CONTACT_WINDOW_SECS - 100;
        let storage = open_rate_limiter_storage(&directory);
        let mut limiter =
            RateLimiter::with_storage(Arc::clone(&storage)).expect("load rate limiter");
        for offset in 0..RATE_MESSAGES_PER_HOUR as u64 {
            assert!(limiter
                .check_message(&old_sender, old_time + offset)
                .is_allowed());
        }
        assert!(limiter
            .check_contact_add(&old_sender, old_time)
            .is_allowed());

        assert!(limiter.check_message(&current_sender, now).is_allowed());
        limiter
            .flush_persistence()
            .await
            .expect("persist cleaned rate history");

        let states = storage
            .lock()
            .expect("storage lock")
            .identity_history()
            .rate_limiter_states()
            .expect("read persisted states");
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].identity_hex, current_sender.to_hex());
    }

    #[test]
    fn rate_limiter_missing_storage_uses_memory() {
        let mut limiter = RateLimiter::new();
        let sender = node(44);
        for now in 0..30 {
            assert!(limiter.check_message(&sender, now).is_allowed());
        }
        assert_eq!(limiter.messages_in_window(&sender, 29), 30);
    }

    #[test]
    fn tracked_nodes_count() {
        let mut limiter = RateLimiter::new();
        limiter.check_message(&node(14), 10);
        limiter.check_message(&node(15), 20);
        limiter.check_contact_add(&node(16), 30);
        assert_eq!(limiter.tracked_nodes(), 3);
    }

    #[test]
    fn concurrent_nodes_independent() {
        let mut limiter = RateLimiter::new();
        for i in 0..RATE_MESSAGES_PER_HOUR as u64 {
            let decision = limiter.check_message(&node(17), i);
            assert!(decision.is_allowed());
        }
        let decision = limiter.check_message(&node(18), 1_000);
        assert_eq!(decision, RateDecision::Allow);
    }
}
