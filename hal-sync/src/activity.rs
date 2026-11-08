use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActivityMode {
    Calm,
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActivityTrigger {
    Message,
    NewsFeed,
    ChannelUpdate,
    Call,
    VoiceMessage,
    UrgentAlert,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActivityTransport {
    StoreAndForward,
    Interactive,
    Realtime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityPlan {
    pub mode: ActivityMode,
    pub transport: ActivityTransport,
    pub poll_interval_seconds: u64,
    pub allow_media: bool,
}

impl ActivityTrigger {
    pub fn default_mode(self) -> ActivityMode {
        match self {
            Self::Message | Self::NewsFeed | Self::ChannelUpdate => ActivityMode::Calm,
            Self::Call | Self::VoiceMessage | Self::UrgentAlert => ActivityMode::Active,
        }
    }
}

impl ActivityMode {
    pub fn plan(self) -> ActivityPlan {
        match self {
            Self::Calm => ActivityPlan {
                mode: self,
                transport: ActivityTransport::StoreAndForward,
                poll_interval_seconds: 300,
                allow_media: false,
            },
            Self::Active => ActivityPlan {
                mode: self,
                transport: ActivityTransport::Realtime,
                poll_interval_seconds: 1,
                allow_media: true,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct ActivityController {
    mode: ActivityMode,
    active_until: Option<u64>,
    urgent_alerts_enabled: bool,
}

impl Default for ActivityController {
    fn default() -> Self {
        Self::new(true)
    }
}

impl ActivityController {
    pub fn new(urgent_alerts_enabled: bool) -> Self {
        Self {
            mode: ActivityMode::Calm,
            active_until: None,
            urgent_alerts_enabled,
        }
    }

    pub fn mode(&self) -> ActivityMode {
        self.mode
    }

    pub fn plan(&self) -> ActivityPlan {
        self.mode.plan()
    }

    pub fn request(&mut self, trigger: ActivityTrigger, now: u64) -> ActivityMode {
        if trigger == ActivityTrigger::UrgentAlert && !self.urgent_alerts_enabled {
            return self.mode;
        }
        match trigger.default_mode() {
            ActivityMode::Calm => self.mode,
            ActivityMode::Active => {
                let duration = match trigger {
                    ActivityTrigger::Message
                    | ActivityTrigger::NewsFeed
                    | ActivityTrigger::ChannelUpdate => 0,
                    ActivityTrigger::Call => 60,
                    ActivityTrigger::VoiceMessage => 30,
                    ActivityTrigger::UrgentAlert => 30,
                };
                self.mode = ActivityMode::Active;
                self.active_until = Some(now.saturating_add(duration));
                self.mode
            }
        }
    }

    pub fn tick(&mut self, now: u64) -> ActivityMode {
        if self.active_until.is_some_and(|deadline| now >= deadline) {
            self.mode = ActivityMode::Calm;
            self.active_until = None;
        }
        self.mode
    }

    pub fn release(&mut self) {
        self.mode = ActivityMode::Calm;
        self.active_until = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calm_events_do_not_wake_realtime_transport() {
        let mut controller = ActivityController::default();
        assert_eq!(
            controller.request(ActivityTrigger::Message, 100),
            ActivityMode::Calm
        );
        assert_eq!(
            controller.request(ActivityTrigger::NewsFeed, 100),
            ActivityMode::Calm
        );
        assert_eq!(
            controller.plan().transport,
            ActivityTransport::StoreAndForward
        );
    }

    #[test]
    fn active_events_use_realtime_then_return_to_calm() {
        let mut controller = ActivityController::default();
        assert_eq!(
            controller.request(ActivityTrigger::Call, 100),
            ActivityMode::Active
        );
        assert_eq!(controller.plan().transport, ActivityTransport::Realtime);
        assert_eq!(controller.tick(159), ActivityMode::Active);
        assert_eq!(controller.tick(160), ActivityMode::Calm);
    }

    #[test]
    fn urgent_alerts_are_user_controllable() {
        let mut controller = ActivityController::new(false);
        assert_eq!(
            controller.request(ActivityTrigger::UrgentAlert, 100),
            ActivityMode::Calm
        );
        controller.request(ActivityTrigger::VoiceMessage, 100);
        controller.release();
        assert_eq!(controller.mode(), ActivityMode::Calm);
    }
}
