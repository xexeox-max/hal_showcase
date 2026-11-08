use crate::{PollBranch, PollRequest};
use anyhow::Result;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub type PollFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

pub trait PollHandler: Send + Sync {
    fn handle(&self, request: PollRequest) -> PollFuture;
}

pub struct PollDispatcher {
    channels: Option<Arc<dyn PollHandler>>,
    nearby_peers: Option<Arc<dyn PollHandler>>,
    available_peers: Option<Arc<dyn PollHandler>>,
    mobile_clients: Option<Arc<dyn PollHandler>>,
}

impl PollDispatcher {
    pub fn new() -> Self {
        Self {
            channels: None,
            nearby_peers: None,
            available_peers: None,
            mobile_clients: None,
        }
    }

    pub fn with_handler(mut self, branch: PollBranch, handler: Arc<dyn PollHandler>) -> Self {
        match branch {
            PollBranch::Channels => self.channels = Some(handler),
            PollBranch::NearbyPeers => self.nearby_peers = Some(handler),
            PollBranch::AvailablePeers => self.available_peers = Some(handler),
            PollBranch::MobileClients => self.mobile_clients = Some(handler),
        }
        self
    }

    pub async fn dispatch(&self, request: PollRequest) -> Result<bool> {
        let handler = match request.branch {
            PollBranch::Channels => self.channels.as_ref(),
            PollBranch::NearbyPeers => self.nearby_peers.as_ref(),
            PollBranch::AvailablePeers => self.available_peers.as_ref(),
            PollBranch::MobileClients => self.mobile_clients.as_ref(),
        };
        let Some(handler) = handler else {
            return Ok(false);
        };
        handler.handle(request).await?;
        Ok(true)
    }
}

impl Default for PollDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingHandler(Arc<AtomicUsize>);

    impl PollHandler for CountingHandler {
        fn handle(&self, _request: PollRequest) -> PollFuture {
            let counter = Arc::clone(&self.0);
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn dispatcher_routes_each_branch_to_its_handler() {
        let counter = Arc::new(AtomicUsize::new(0));
        let dispatcher = PollDispatcher::new().with_handler(
            PollBranch::Channels,
            Arc::new(CountingHandler(Arc::clone(&counter))),
        );
        assert!(dispatcher
            .dispatch(PollRequest {
                branch: PollBranch::Channels,
                max_items: 8
            })
            .await
            .unwrap());
        assert!(!dispatcher
            .dispatch(PollRequest {
                branch: PollBranch::NearbyPeers,
                max_items: 8
            })
            .await
            .unwrap());
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }
}
