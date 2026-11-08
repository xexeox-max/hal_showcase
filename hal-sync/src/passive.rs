use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelRuntimeState {
    Passive,
    Activating,
    Active,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelInterest {
    pub channel_id: String,
    pub last_cursor: Option<String>,
    pub check_interval_ms: u64,
    pub state: ChannelRuntimeState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetedCheck {
    pub channel_id: String,
    pub cursor: Option<String>,
    pub max_items: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActivationReason {
    UserRequest,
    IncomingConnection { request_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationRequest {
    pub channel_id: String,
    pub reason: ActivationReason,
}

#[derive(Debug, Default)]
pub struct PassiveScheduler {
    interests: HashMap<String, ChannelInterest>,
    pending_activation: Vec<ActivationRequest>,
}

impl PassiveScheduler {
    pub fn subscribe(&mut self, interest: ChannelInterest) {
        self.interests.insert(interest.channel_id.clone(), interest);
    }

    pub fn unsubscribe(&mut self, channel_id: &str) {
        self.interests.remove(channel_id);
        self.pending_activation
            .retain(|request| request.channel_id != channel_id);
    }

    pub fn plan_targeted_checks(
        &self,
        due_channel_ids: &[String],
        max_items: usize,
    ) -> Vec<TargetedCheck> {
        let due = due_channel_ids.iter().collect::<HashSet<_>>();
        self.interests
            .values()
            .filter(|interest| {
                due.contains(&interest.channel_id) && interest.state == ChannelRuntimeState::Passive
            })
            .map(|interest| TargetedCheck {
                channel_id: interest.channel_id.clone(),
                cursor: interest.last_cursor.clone(),
                max_items,
            })
            .collect()
    }

    pub fn request_activation(&mut self, request: ActivationRequest) {
        if self.interests.contains_key(&request.channel_id)
            && !self
                .pending_activation
                .iter()
                .any(|pending| pending.channel_id == request.channel_id)
        {
            self.pending_activation.push(request);
        }
    }

    pub fn take_activation_requests(&mut self) -> Vec<ActivationRequest> {
        let requests = std::mem::take(&mut self.pending_activation);
        for request in &requests {
            if let Some(interest) = self.interests.get_mut(&request.channel_id) {
                interest.state = ChannelRuntimeState::Activating;
            }
        }
        requests
    }

    pub fn mark_active(&mut self, channel_id: &str) {
        if let Some(interest) = self.interests.get_mut(channel_id) {
            interest.state = ChannelRuntimeState::Active;
        }
    }

    pub fn mark_passive(&mut self, channel_id: &str, cursor: Option<String>) {
        if let Some(interest) = self.interests.get_mut(channel_id) {
            interest.last_cursor = cursor;
            interest.state = ChannelRuntimeState::Passive;
        }
    }

    pub fn active_channel_count(&self) -> usize {
        self.interests
            .values()
            .filter(|interest| interest.state == ChannelRuntimeState::Active)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interest(id: &str) -> ChannelInterest {
        ChannelInterest {
            channel_id: id.into(),
            last_cursor: Some("cursor-1".into()),
            check_interval_ms: 60_000,
            state: ChannelRuntimeState::Passive,
        }
    }

    #[test]
    fn passive_checks_only_touch_subscribed_passive_channels() {
        let mut scheduler = PassiveScheduler::default();
        scheduler.subscribe(interest("channel-a"));
        scheduler.subscribe(interest("channel-b"));
        scheduler.mark_active("channel-b");

        let checks = scheduler.plan_targeted_checks(
            &["channel-a".into(), "channel-b".into(), "unknown".into()],
            8,
        );
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].channel_id, "channel-a");
        assert_eq!(checks[0].max_items, 8);
    }

    #[test]
    fn activation_is_demand_driven_and_returns_to_passive() {
        let mut scheduler = PassiveScheduler::default();
        scheduler.subscribe(interest("channel-a"));
        scheduler.request_activation(ActivationRequest {
            channel_id: "channel-a".into(),
            reason: ActivationReason::UserRequest,
        });

        let requests = scheduler.take_activation_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(scheduler.active_channel_count(), 0);
        scheduler.mark_active("channel-a");
        assert_eq!(scheduler.active_channel_count(), 1);
        scheduler.mark_passive("channel-a", Some("cursor-2".into()));
        assert_eq!(scheduler.active_channel_count(), 0);
    }
}
