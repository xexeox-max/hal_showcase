//! PR-D2.2: background writer for inbound observations to PeerDirectory.

use std::sync::Arc;

use tokio::sync::{mpsc, oneshot, Mutex};

use crate::observable_events::{EventKind, ObservableEvents};
use crate::peer_directory::PeerDirectory;
use crate::runtime::PeerAddressState;
use crate::InboundObservation;

pub const INBOUND_OBSERVATION_QUEUE_CAPACITY: usize = 256;

pub struct InboundObserverTask {
    directory: Arc<Mutex<PeerDirectory>>,
    observable: Arc<ObservableEvents>,
    peer_address_state: Option<Arc<Mutex<PeerAddressState>>>,
}

impl InboundObserverTask {
    pub fn new(directory: Arc<Mutex<PeerDirectory>>) -> Self {
        Self::with_observable(directory, Arc::new(ObservableEvents::new()))
    }

    pub fn with_observable(
        directory: Arc<Mutex<PeerDirectory>>,
        observable: Arc<ObservableEvents>,
    ) -> Self {
        Self {
            directory,
            observable,
            peer_address_state: None,
        }
    }

    pub(crate) fn with_peer_address_state(
        mut self,
        peer_address_state: Arc<Mutex<PeerAddressState>>,
    ) -> Self {
        self.peer_address_state = Some(peer_address_state);
        self
    }

    pub async fn run(
        self,
        mut rx: mpsc::Receiver<InboundObservation>,
        mut shutdown: oneshot::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    log::info!("inbound observer: shutdown");
                    break;
                }
                observation = rx.recv() => {
                    match observation {
                        Some(observation) => {
                            let identity_id = observation.identity_id.clone();
                            let address = observation.remote_addr.to_string();
                            let mut directory = self.directory.lock().await;
                            if let Err(error) = directory.record_inbound(
                                observation.remote_addr,
                                observation.identity_id,
                                observation.public_key_hex,
                                observation.observed_at,
                            ) {
                                log::debug!("inbound observer: record failed: {error:?}");
                            } else {
                                drop(directory);
                                if let Some(state) = &self.peer_address_state {
                                    state.lock().await.confirm_address(&identity_id, &address);
                                }
                                self.observable
                                    .notify(EventKind::InboundObservationRecorded);
                            }
                        }
                        None => {
                            log::info!("inbound observer: channel closed");
                            break;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use ed25519_dalek::SigningKey;
    use tokio::sync::{mpsc, oneshot, Mutex};

    use super::*;
    use crate::abuse_metrics::AbuseMetrics;
    use crate::transport::try_send_inbound_observation;

    fn observation(seed: u8, address: &str) -> InboundObservation {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let verifying_key = signing_key.verifying_key();
        InboundObservation {
            remote_addr: address.parse::<SocketAddr>().expect("socket address"),
            identity_id: crate::NodeId::from_public_key(&verifying_key).to_hex(),
            public_key_hex: hex::encode(verifying_key.to_bytes()),
            observed_at: crate::runtime::unix_now(),
        }
    }

    async fn wait_for_entry(directory: &Arc<Mutex<PeerDirectory>>, address: &str, now: u64) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if directory
                    .lock()
                    .await
                    .lookup_by_address(address, now)
                    .is_some()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("observer should record within timeout");
    }

    #[tokio::test]
    async fn inbound_observation_writes_to_directory() {
        let directory = Arc::new(Mutex::new(PeerDirectory::default_config()));
        let (tx, rx) = mpsc::channel(2);
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task =
            tokio::spawn(InboundObserverTask::new(Arc::clone(&directory)).run(rx, shutdown_rx));
        let observation = observation(131, "127.0.0.1:9131");
        let identity_id = observation.identity_id.clone();
        let address = observation.remote_addr.to_string();
        let now = observation.observed_at;
        tx.send(observation).await.expect("send observation");
        wait_for_entry(&directory, &address, now).await;
        assert_eq!(
            directory
                .lock()
                .await
                .lookup_by_address(&address, now)
                .expect("recorded entry")
                .identity_id,
            identity_id
        );
        let _ = shutdown.send(());
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("observer shutdown timeout")
            .expect("observer task join");
    }

    #[tokio::test]
    async fn inbound_observation_shutdown_clean() {
        let directory = Arc::new(Mutex::new(PeerDirectory::default_config()));
        let (_tx, rx) = mpsc::channel(2);
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(InboundObserverTask::new(directory).run(rx, shutdown_rx));
        shutdown.send(()).expect("send shutdown");
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("observer shutdown timeout")
            .expect("observer task join");
    }

    #[tokio::test]
    async fn inbound_observation_dropped_when_full() {
        let (tx, _rx) = mpsc::channel(1);
        let metrics = AbuseMetrics::new();
        tx.send(observation(132, "127.0.0.1:9132"))
            .await
            .expect("fill observation channel");
        assert!(!try_send_inbound_observation(
            &tx,
            observation(133, "127.0.0.1:9133"),
            Some(&metrics),
        ));
        assert_eq!(metrics.snapshot().inbound_observation_dropped_total, 1);
    }

    #[tokio::test]
    async fn inbound_observer_skips_bad_observation() {
        let directory = Arc::new(Mutex::new(PeerDirectory::default_config()));
        let (tx, rx) = mpsc::channel(2);
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task =
            tokio::spawn(InboundObserverTask::new(Arc::clone(&directory)).run(rx, shutdown_rx));
        let mut bad = observation(134, "127.0.0.1:9134");
        bad.identity_id =
            crate::NodeId::from_public_key(&SigningKey::from_bytes(&[135; 32]).verifying_key())
                .to_hex();
        tx.send(bad).await.expect("send invalid observation");
        let valid = observation(136, "127.0.0.1:9136");
        let valid_addr = valid.remote_addr.to_string();
        let now = valid.observed_at;
        tx.send(valid).await.expect("send valid observation");
        wait_for_entry(&directory, &valid_addr, now).await;
        let metrics = directory.lock().await.metrics_snapshot();
        assert_eq!(metrics.recorded_inbound_total, 1);
        assert_eq!(metrics.rejected_invalid_identity_total, 1);
        let _ = shutdown.send(());
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("observer shutdown timeout")
            .expect("observer task join");
    }
}
