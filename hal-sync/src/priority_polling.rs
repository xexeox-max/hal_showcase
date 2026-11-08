use anyhow::Result;
use hal_settings::{PriorityContactPolicy, PriorityPollState};
use std::collections::HashMap;
use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{interval, Duration};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorityPollRequest {
    pub contact_id: String,
    pub interval_seconds: u64,
}

pub struct PriorityPollingRuntime {
    policies: std::sync::Arc<Mutex<HashMap<String, PriorityContactPolicy>>>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl PriorityPollingRuntime {
    pub fn start(now: u64) -> (Self, mpsc::Receiver<PriorityPollRequest>) {
        let policies =
            std::sync::Arc::new(Mutex::new(HashMap::<String, PriorityContactPolicy>::new()));
        let (requests, receiver) = mpsc::channel(64);
        let (stop, mut stop_rx) = watch::channel(false);
        let task_policies = std::sync::Arc::clone(&policies);
        let task = tokio::spawn(async move {
            let mut last_now = now;
            let mut timer = interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    _ = timer.tick() => {
                        last_now = last_now.saturating_add(1);
                        let snapshot = task_policies.lock().await.values_mut().filter_map(|policy| {
                            policy.adapt(last_now);
                            (policy.enabled && policy.state == PriorityPollState::Fast).then(|| PriorityPollRequest {
                                contact_id: policy.contact_id.clone(),
                                interval_seconds: policy.interval.seconds(),
                            })
                        }).collect::<Vec<_>>();
                        for request in snapshot { let _ = requests.send(request).await; }
                    }
                    changed = stop_rx.changed() => {
                        if changed.is_err() || *stop_rx.borrow() { break; }
                    }
                }
            }
        });
        (
            Self {
                policies,
                stop,
                task: Some(task),
            },
            receiver,
        )
    }

    pub async fn set_policy(&self, policy: PriorityContactPolicy) -> Result<()> {
        policy.validate().map_err(|error| anyhow::anyhow!(error))?;
        self.policies
            .lock()
            .await
            .insert(policy.contact_id.clone(), policy);
        Ok(())
    }

    pub async fn activate(&self, contact_id: &str, now: u64) -> bool {
        let mut policies = self.policies.lock().await;
        let Some(policy) = policies.get_mut(contact_id) else {
            return false;
        };
        policy.activate(now);
        true
    }

    pub async fn record_activity(&self, contact_id: &str, now: u64) -> bool {
        let mut policies = self.policies.lock().await;
        let Some(policy) = policies.get_mut(contact_id) else {
            return false;
        };
        policy.record_activity(now);
        true
    }

    pub async fn state(&self, contact_id: &str) -> Option<PriorityPollState> {
        self.policies
            .lock()
            .await
            .get(contact_id)
            .map(|policy| policy.state)
    }

    pub async fn stop(mut self) -> Result<()> {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            task.await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hal_settings::PriorityPollInterval;

    #[tokio::test]
    async fn only_enabled_active_contact_generates_fast_requests() {
        let (runtime, mut requests) = PriorityPollingRuntime::start(100);
        let mut policy = PriorityContactPolicy::new("peer".into(), 100);
        policy.enabled = true;
        policy.interval = PriorityPollInterval::OneSecond;
        runtime.set_policy(policy).await.expect("policy");
        runtime.activate("peer", 100).await;
        let request = tokio::time::timeout(Duration::from_secs(2), requests.recv())
            .await
            .expect("poll timeout")
            .expect("request");
        assert_eq!(request.contact_id, "peer");
        assert_eq!(request.interval_seconds, 1);
        runtime.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn inactivity_returns_contact_to_normal_state() {
        let (runtime, _requests) = PriorityPollingRuntime::start(100);
        let mut policy = PriorityContactPolicy::new("peer".into(), 100);
        policy.enabled = true;
        policy.inactivity_timeout_seconds = 2;
        runtime.set_policy(policy).await.expect("policy");
        runtime.activate("peer", 100).await;
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(runtime.state("peer").await, Some(PriorityPollState::Normal));
        runtime.stop().await.expect("stop");
    }
}
