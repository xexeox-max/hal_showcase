//! ObservableEvents — zero-cost event notification for test synchronisation.
//!
//! Notify::notify_waiters is a no-op when no waiter is registered: one
//! atomic load and an empty waiter-list check. Production behavior is
//! unchanged when tests are not waiting.
//!
//! See docs/FLAKY_HARDENING.md §3.

use tokio::sync::Notify;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    InboundEnvelope,
    InboundObservationRecorded,
    RelayForwarded,
    TransportStigmaRejected,
    LinkRequestProcessed,
    StorageMessageWritten,
}

#[derive(Debug, Default)]
pub struct ObservableEvents {
    inbound_envelope: Notify,
    inbound_observation_recorded: Notify,
    relay_forwarded: Notify,
    transport_stigma_rejected: Notify,
    link_request_processed: Notify,
    storage_message_written: Notify,
}

impl ObservableEvents {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn notifier(&self, kind: EventKind) -> &Notify {
        match kind {
            EventKind::InboundEnvelope => &self.inbound_envelope,
            EventKind::InboundObservationRecorded => &self.inbound_observation_recorded,
            EventKind::RelayForwarded => &self.relay_forwarded,
            EventKind::TransportStigmaRejected => &self.transport_stigma_rejected,
            EventKind::LinkRequestProcessed => &self.link_request_processed,
            EventKind::StorageMessageWritten => &self.storage_message_written,
        }
    }

    pub fn notify(&self, kind: EventKind) {
        self.notifier(kind).notify_waiters();
    }
}
