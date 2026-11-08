//! PR-B5: periodically recompute stigma for known identities and refresh cache.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::sync::oneshot;
use tokio::time::{interval, Interval};

use crate::dht::NodeId;
use crate::runtime::unix_now;
use crate::runtime_context::RuntimeContext;

pub const STIGMA_REFRESH_DEFAULT_INTERVAL: Duration = Duration::from_secs(60);

pub struct StigmaRefreshTask {
    ctx: Arc<RuntimeContext>,
    interval: Duration,
}

impl StigmaRefreshTask {
    pub fn new(ctx: Arc<RuntimeContext>, interval: Duration) -> Self {
        Self { ctx, interval }
    }

    pub fn default_config(ctx: Arc<RuntimeContext>) -> Self {
        Self::new(ctx, STIGMA_REFRESH_DEFAULT_INTERVAL)
    }

    pub async fn run(self, mut shutdown: oneshot::Receiver<()>) {
        let mut ticker: Interval = interval(self.interval);
        ticker.tick().await;
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    log::info!("stigma refresh: shutdown");
                    break;
                }
                _ = ticker.tick() => {
                    if let Err(error) = self.run_once().await {
                        log::warn!("stigma refresh failed: {error}");
                    }
                }
            }
        }
    }

    pub(crate) async fn run_once(&self) -> Result<()> {
        let now = unix_now();
        let identities: Vec<NodeId> = {
            let hosts = self
                .ctx
                .hosts
                .lock()
                .map_err(|_| anyhow!("hosts poisoned"))?;
            hosts
                .identities()
                .into_iter()
                .filter_map(|(identity_id, _)| NodeId::from_hex(&identity_id).ok())
                .collect()
        };

        let mut new_map = HashMap::new();
        for identity in identities {
            let level = self.ctx.stigma_gate(&identity, now).await;
            new_map.insert(identity, level);
        }
        self.ctx.stigma_cache.bulk_replace(new_map);
        self.ctx
            .abuse_metrics
            .stigma_refresh_rounds_total
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ed25519_dalek::SigningKey;
    use tokio::sync::oneshot;

    use super::*;
    use crate::dht::badge::{Badge, BadgeContext, BadgeKind, BADGE_REFLECTION_PERIOD_SECS};
    use crate::runtime::PeerRuntime;

    async fn runtime_with_stigma() -> (PeerRuntime, NodeId) {
        let local_seed = [201; 32];
        let local_key = SigningKey::from_bytes(&local_seed);
        let local_id = NodeId::from_public_key(&local_key.verifying_key());
        let runtime =
            PeerRuntime::start(local_id.to_hex(), local_seed, "stigma-refresh-test".into())
                .await
                .expect("runtime");
        let subject_key = SigningKey::from_bytes(&[202; 32]);
        let subject_id = NodeId::from_public_key(&subject_key.verifying_key());
        runtime
            .pin_peer(
                &subject_id.to_hex(),
                &hex::encode(subject_key.verifying_key().to_bytes()),
            )
            .await
            .expect("pin subject");
        runtime
            .pin_peer(
                &local_id.to_hex(),
                &hex::encode(local_key.verifying_key().to_bytes()),
            )
            .await
            .expect("pin issuer");

        let now = unix_now();
        let badge = Badge::create(
            9001,
            subject_id,
            None,
            BadgeKind::Spammer,
            vec!["stigma-refresh-evidence".into()],
            BadgeContext::ColdContact,
            "refresh test stigma".into(),
            local_id,
            now.saturating_sub(BADGE_REFLECTION_PERIOD_SECS + 1),
            None,
            &local_key,
        )
        .expect("create badge");
        runtime
            .runtime_context()
            .badge_store
            .lock()
            .await
            .publish(badge)
            .expect("publish local badge");
        (runtime, subject_id)
    }

    #[tokio::test]
    async fn refresh_round_populates_cache() {
        let (runtime, subject) = runtime_with_stigma().await;
        let task = StigmaRefreshTask::default_config(runtime.runtime_context());
        task.run_once().await.expect("refresh round");
        assert!(runtime
            .runtime_context()
            .stigma_cache
            .is_stigmatized(&subject));
        runtime.stop().await.expect("stop runtime");
    }

    #[tokio::test]
    async fn refresh_shutdown_clean() {
        let (runtime, _) = runtime_with_stigma().await;
        let task = StigmaRefreshTask::new(runtime.runtime_context(), Duration::from_secs(60));
        let (shutdown, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(task.run(shutdown_rx));
        shutdown.send(()).expect("send shutdown");
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("refresh task timeout")
            .expect("refresh task join");
        runtime.stop().await.expect("stop runtime");
    }

    #[tokio::test]
    async fn refresh_updates_counter() {
        let (runtime, _) = runtime_with_stigma().await;
        let ctx = runtime.runtime_context();
        let task = StigmaRefreshTask::default_config(Arc::clone(&ctx));
        task.run_once().await.expect("refresh round");
        assert_eq!(ctx.abuse_metrics.snapshot().stigma_refresh_rounds_total, 1);
        runtime.stop().await.expect("stop runtime");
    }
}
