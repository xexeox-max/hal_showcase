use anyhow::Result;
use hal_settings::{NetworkScanPolicy, PollPolicy};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{interval, Duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollBranch {
    Channels,
    NearbyPeers,
    AvailablePeers,
    MobileClients,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollRequest {
    pub branch: PollBranch,
    pub max_items: usize,
}

pub struct PollingRuntime {
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl PollingRuntime {
    pub fn start(policy: NetworkScanPolicy) -> (Self, mpsc::Receiver<PollRequest>) {
        Self::start_with_capacity(policy, 100)
    }

    /// Battery-aware variant: the scan cadence stretches by the live
    /// capacity score (hal-cluster workload multiplier), so a struggling
    /// phone scans rarely instead of draining in cyclic wakeups.
    pub fn start_with_capacity(
        policy: NetworkScanPolicy,
        service_score: u8,
    ) -> (Self, mpsc::Receiver<PollRequest>) {
        let multiplier = hal_cluster::workload::sync_interval_multiplier(service_score);
        let (request_tx, request_rx) = mpsc::channel(64);
        let (stop, stop_rx) = watch::channel(false);
        let policies = [
            (PollBranch::Channels, policy.channels),
            (PollBranch::NearbyPeers, policy.nearby_peers),
            (PollBranch::AvailablePeers, policy.available_peers),
            (PollBranch::MobileClients, policy.mobile_clients),
        ];
        let tasks = policies
            .into_iter()
            .map(|(branch, branch_policy)| {
                let tx = request_tx.clone();
                let stop_rx = stop_rx.clone();
                tokio::spawn(run_branch(branch, branch_policy, tx, stop_rx, multiplier))
            })
            .collect();
        (Self { stop, tasks }, request_rx)
    }

    pub async fn stop(self) -> Result<()> {
        let _ = self.stop.send(true);
        for task in self.tasks {
            task.await?;
        }
        Ok(())
    }
}

async fn run_branch(
    branch: PollBranch,
    policy: PollPolicy,
    tx: mpsc::Sender<PollRequest>,
    mut stop: watch::Receiver<bool>,
    capacity_multiplier: f32,
) {
    let scaled = ((policy.interval_seconds as f32 * capacity_multiplier).round() as u64).max(1);
    let mut timer = interval(Duration::from_secs(scaled));
    loop {
        tokio::select! {
            _ = timer.tick() => {
                if policy.schedule == hal_settings::ScanSchedule::Continuous {
                    let _ = tx.send(PollRequest { branch, max_items: policy.max_items_per_pass }).await;
                }
            }
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() { break; }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn branches_are_independent_and_stoppable() {
        let mut policy = NetworkScanPolicy::default();
        policy.channels.schedule = hal_settings::ScanSchedule::Continuous;
        policy.channels.interval_seconds = 1;
        policy.nearby_peers.schedule = hal_settings::ScanSchedule::StartupOnly;
        let (runtime, mut requests) = PollingRuntime::start(policy);
        let request = tokio::time::timeout(Duration::from_secs(2), requests.recv())
            .await
            .expect("poll timeout")
            .expect("poll request");
        assert_eq!(request.branch, PollBranch::Channels);
        runtime.stop().await.expect("stop polling");
    }
}
