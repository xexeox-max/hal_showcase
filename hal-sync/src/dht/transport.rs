use async_trait::async_trait;

use super::peer_info::PeerInfo;
use super::wire::{DhtError, DhtRequest, DhtResponse};

#[async_trait]
pub trait DhtTransport: Send + Sync {
    async fn send_request(
        &self,
        peer: &PeerInfo,
        request: DhtRequest,
    ) -> Result<DhtResponse, DhtError>;
}
