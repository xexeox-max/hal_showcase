//! PR-B4.3: background worker for prompt auto-badge publication.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use hal_settings::NetworkTrustPolicy;
use tokio::sync::oneshot;

use crate::dht::badge::{Badge, BadgeContext, BadgeId, BadgeKind};
use crate::dht::endpoint::EndpointCache;
use crate::dht::routing::RoutingTable;
use crate::dht::NodeId;
use crate::pinning::KnownHosts;
use crate::runtime::{publish_badge_impl, unix_now};
use crate::runtime_context::RuntimeContext;

pub const AUTO_BADGE_TICK: Duration = Duration::from_secs(30);
pub const AUTO_BADGE_DRAIN_BATCH: usize = 16;
pub const REPLY_WINDOW_SECS: u64 = 24 * 60 * 60;

pub struct AutoBadgeWorker {
    ctx: Arc<RuntimeContext>,
    signing_key: SigningKey,
    identity_id: String,
    public_key: String,
    dht_local_id: NodeId,
    dht_routing: Arc<tokio::sync::Mutex<RoutingTable>>,
    dht_cache: Arc<tokio::sync::Mutex<EndpointCache>>,
    hosts: Arc<std::sync::Mutex<KnownHosts>>,
    trust_policy: NetworkTrustPolicy,
}

impl AutoBadgeWorker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ctx: Arc<RuntimeContext>,
        signing_key: SigningKey,
        identity_id: String,
        public_key: String,
        dht_local_id: NodeId,
        dht_routing: Arc<tokio::sync::Mutex<RoutingTable>>,
        dht_cache: Arc<tokio::sync::Mutex<EndpointCache>>,
        hosts: Arc<std::sync::Mutex<KnownHosts>>,
        trust_policy: NetworkTrustPolicy,
    ) -> Self {
        Self {
            ctx,
            signing_key,
            identity_id,
            public_key,
            dht_local_id,
            dht_routing,
            dht_cache,
            hosts,
            trust_policy,
        }
    }

    pub async fn run(self, mut shutdown: oneshot::Receiver<()>) {
        let mut ticker = tokio::time::interval(AUTO_BADGE_TICK);
        ticker.tick().await;

        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    log::info!("auto-badge worker: shutdown");
                    break;
                }
                _ = ticker.tick() => {
                    if let Err(error) = self.drain_once().await {
                        log::warn!("auto-badge worker drain failed: {error}");
                    }
                }
            }
        }
    }

    pub(crate) async fn drain_once(&self) -> Result<()> {
        let pending = {
            let mut queue = self.ctx.auto_badge_queue.lock().await;
            let drained = queue.drain();
            drained
                .into_iter()
                .take(AUTO_BADGE_DRAIN_BATCH)
                .collect::<Vec<_>>()
        };

        for item in pending {
            if item.message_ids.is_empty() {
                continue;
            }

            let subject_hex = item.subject_id.to_hex();
            let local_hex = self.dht_local_id.to_hex();
            let since = item.observed_at.saturating_sub(REPLY_WINDOW_SECS);
            let reply_lookup = match self.ctx.storage.as_ref() {
                Some(storage) => {
                    let result = match storage.lock() {
                        Ok(storage_guard) => storage_guard.sync_storage().outgoing_to(
                            &local_hex,
                            &subject_hex,
                            since,
                        ),
                        Err(_) => Err(anyhow!("storage poisoned")),
                    };
                    result
                }
                None => Err(anyhow!("storage unavailable")),
            };
            let has_reply = match reply_lookup {
                Ok(ids) if !ids.is_empty() => true,
                Ok(_) => {
                    log::debug!("reply-guard: no outbound reply found for subject {subject_hex}");
                    false
                }
                Err(error) => {
                    self.ctx
                        .abuse_metrics
                        .auto_badge_skipped_no_storage_total
                        .fetch_add(1, Ordering::Relaxed);
                    log::warn!("reply-guard: storage lookup unavailable: {error}");
                    false
                }
            };
            if has_reply {
                self.ctx
                    .abuse_metrics
                    .auto_badge_skipped_reply_total
                    .fetch_add(1, Ordering::Relaxed);
                log::debug!("auto-badge skipped: local replied to subject {subject_hex} in window");
                continue;
            }

            let now = unix_now();
            let badge = Badge::create(
                rand_badge_id(),
                item.subject_id,
                None,
                BadgeKind::Flooder,
                item.message_ids.clone(),
                BadgeContext::ColdContact,
                item.reason.clone(),
                self.dht_local_id,
                now,
                Some(now.saturating_add(30 * 24 * 60 * 60)),
                &self.signing_key,
            )?;
            let subject_id = badge.subject_id;

            match publish_badge_impl(
                &self.ctx,
                &self.signing_key,
                &self.identity_id,
                &self.public_key,
                self.dht_local_id,
                &self.dht_routing,
                &self.dht_cache,
                &self.hosts,
                &self.trust_policy,
                badge,
            )
            .await
            {
                Ok(()) => {
                    let level = self.ctx.stigma_gate(&subject_id, unix_now()).await;
                    self.ctx.stigma_cache.update(subject_id, level);
                    self.ctx
                        .abuse_metrics
                        .auto_badge_published_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Err(error) => {
                    log::warn!("auto-badge publish failed: {error}");
                    self.ctx
                        .abuse_metrics
                        .auto_badge_publish_failed_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }

        Ok(())
    }
}

fn rand_badge_id() -> BadgeId {
    rand::random::<u64>()
}
