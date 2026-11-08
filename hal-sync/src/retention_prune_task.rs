use std::sync::Arc;

use anyhow::Result;
use tokio::sync::oneshot;
use tokio::sync::Mutex;

use crate::activity_tracker::ActivityTracker;
use crate::runtime_context::RuntimeContext;

pub const PRUNE_INTERVAL_SECS: u64 = 3600;

pub struct RetentionPruneTask {
    activity: Arc<Mutex<ActivityTracker>>,
    ctx: Arc<RuntimeContext>,
}

impl RetentionPruneTask {
    pub fn new(activity: Arc<Mutex<ActivityTracker>>, ctx: Arc<RuntimeContext>) -> Self {
        Self { activity, ctx }
    }

    pub async fn run(self, shutdown: oneshot::Receiver<()>) {
        let mut shutdown = shutdown;
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                _ = tokio::time::sleep(std::time::Duration::from_secs(PRUNE_INTERVAL_SECS)) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    if let Err(error) = self.run_once(now).await {
                        log::debug!("retention prune failed: {error}");
                    }
                }
            }
        }
    }

    async fn run_once(&self, now: u64) -> Result<()> {
        let mut activity = self.activity.lock().await;
        activity.prune(now).await?;
        Ok(())
    }
}
