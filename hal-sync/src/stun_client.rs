use std::net::SocketAddr;

use anyhow::{anyhow, Result};

use crate::stun::{StunClient, StunConfig};

pub async fn discover_public_address(stun_server: &str) -> Result<SocketAddr> {
    let client = StunClient::new(StunConfig {
        servers: vec![stun_server.to_string()],
        ..StunConfig::default()
    });
    let endpoint = client.discover().await?;
    let address = SocketAddr::new(endpoint.ip, endpoint.port);
    if address.ip().is_unspecified() || address.port() == 0 {
        return Err(anyhow!(
            "STUN returned an unusable public address: {address}"
        ));
    }
    Ok(address)
}
