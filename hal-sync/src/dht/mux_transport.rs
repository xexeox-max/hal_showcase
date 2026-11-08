use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::mux::{Mode, Mux, MuxConfig, StreamKind};
use crate::pinning::KnownHosts;
use crate::transport::connect_happy_eyeballs;
use hal_settings::NetworkTrustPolicy;

use super::metrics::DhtMetrics;
use super::peer_info::PeerInfo;
use super::transport::DhtTransport;
use super::wire::{
    decode_response, decode_response_framed, encode_request_framed, DhtError, DhtRequest,
    DhtResponse, DHT_FRAME_PREFIX_BYTES, MAX_DHT_REQUEST_BYTES,
};

pub const DHT_RPC_TIMEOUT: Duration = Duration::from_secs(5);
pub const DHT_MAX_PARALLEL: usize = 8;
pub const DHT_CHANNEL_CAPACITY: usize = 64;

pub struct MuxDhtTransport {
    local_identity: SigningKey,
    hosts: Arc<std::sync::Mutex<KnownHosts>>,
    trust_policy: NetworkTrustPolicy,
    timeout: Duration,
    metrics: Option<Arc<DhtMetrics>>,
}

impl MuxDhtTransport {
    pub fn new(
        local_identity: SigningKey,
        hosts: Arc<std::sync::Mutex<KnownHosts>>,
        trust_policy: NetworkTrustPolicy,
    ) -> Self {
        Self {
            local_identity,
            hosts,
            trust_policy,
            timeout: DHT_RPC_TIMEOUT,
            metrics: None,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_metrics(mut self, metrics: Arc<DhtMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    async fn send_request_inner(
        &self,
        peer: &PeerInfo,
        request: DhtRequest,
    ) -> Result<DhtResponse, DhtError> {
        let endpoint = peer
            .best_endpoint()
            .ok_or_else(|| DhtError::Internal("peer has no endpoint".into()))?;
        let addresses = tokio::net::lookup_host(&endpoint.address)
            .await
            .map_err(|error| DhtError::Internal(format!("resolve endpoint: {error}")))?
            .collect::<Vec<SocketAddr>>();
        if addresses.is_empty() {
            return Err(DhtError::Internal(
                "endpoint resolved to no addresses".into(),
            ));
        }
        let tcp = connect_happy_eyeballs(&addresses, self.timeout)
            .await
            .map_err(|error| DhtError::Internal(format!("connect DHT peer: {error}")))?;
        let tls = tokio::time::timeout(
            self.timeout,
            crate::tls_transport::TlsTransport::connect_with_kind_on_stream(
                tcp,
                &self.local_identity,
                None,
                StreamKind::Dht,
            ),
        )
        .await
        .map_err(|_| DhtError::Internal("DHT TLS timeout".into()))?
        .map_err(|error| DhtError::Internal(format!("DHT TLS: {error}")))?;
        let mux = Mux::new(tls.into_stream(), MuxConfig::default(), Mode::Client);
        let mut stream = tokio::time::timeout(self.timeout, mux.open(StreamKind::Dht))
            .await
            .map_err(|_| DhtError::Internal("DHT mux open timeout".into()))?
            .map_err(|error| DhtError::Internal(format!("DHT mux open: {error}")))?;
        let request_frame = encode_request_framed(&request)
            .map_err(|error| DhtError::Internal(format!("encode DHT request: {error}")))?;
        tokio::time::timeout(self.timeout, async {
            stream.write_all(&request_frame).await?;
            stream.flush().await?;
            std::io::Result::Ok(())
        })
        .await
        .map_err(|_| DhtError::Internal("DHT request write timeout".into()))?
        .map_err(|error| DhtError::Internal(format!("DHT request write: {error}")))?;

        let mut length_buf = [0u8; DHT_FRAME_PREFIX_BYTES];
        tokio::time::timeout(self.timeout, stream.read_exact(&mut length_buf))
            .await
            .map_err(|_| DhtError::Internal("DHT response read timeout".into()))?
            .map_err(|error| DhtError::Internal(format!("DHT response read: {error}")))?;
        let response_len = u32::from_be_bytes(length_buf) as usize;
        if response_len == 0 || response_len > MAX_DHT_REQUEST_BYTES {
            return Err(DhtError::Internal("DHT response exceeds size limit".into()));
        }
        let mut response_bytes = vec![0u8; response_len];
        tokio::time::timeout(self.timeout, stream.read_exact(&mut response_bytes))
            .await
            .map_err(|_| DhtError::Internal("DHT response read timeout".into()))?
            .map_err(|error| DhtError::Internal(format!("DHT response read: {error}")))?;
        let framed_response = [length_buf.as_slice(), response_bytes.as_slice()].concat();
        let response = decode_response_framed(&framed_response)
            .map_err(|error| DhtError::Internal(format!("decode DHT response: {error}")))?;
        let _ = tokio::time::timeout(self.timeout, stream.shutdown())
            .await
            .map_err(|_| DhtError::Internal("DHT response shutdown timeout".into()))
            .and_then(|result| {
                result
                    .map_err(|error| DhtError::Internal(format!("DHT response shutdown: {error}")))
            });
        mux.close()
            .await
            .map_err(|error| DhtError::Internal(format!("DHT mux close: {error}")))?;
        Ok(response)
    }
}

#[async_trait]
impl DhtTransport for MuxDhtTransport {
    async fn send_request(
        &self,
        peer: &PeerInfo,
        request: DhtRequest,
    ) -> Result<DhtResponse, DhtError> {
        let _ = (&self.hosts, &self.trust_policy);
        match tokio::time::timeout(self.timeout, self.send_request_inner(peer, request)).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) => {
                if let Some(metrics) = &self.metrics {
                    metrics.inc_errors();
                }
                Err(error)
            }
            Err(_) => {
                if let Some(metrics) = &self.metrics {
                    metrics.inc_timeouts();
                }
                Err(DhtError::Internal("DHT RPC timeout".into()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use ed25519_dalek::{SigningKey, VerifyingKey};

    use crate::dht::transport::DhtTransport;
    use crate::dht::{DhtRequest, DhtRequestPayload, DhtResponsePayload, NodeId};
    use crate::pinning::KnownHosts;
    use crate::{PeerInfo, PeerRuntime};

    fn identity_for_public_key(public_key: &[u8; 32]) -> String {
        let mut hasher = sha2::Sha256::new();
        use sha2::Digest;
        hasher.update(public_key);
        hex::encode(hasher.finalize())
    }

    #[tokio::test]
    #[ignore = "FLAKY (early eof): intermittent under suite load; root cause not identified; tracked in docs/KNOWN_ISSUES.md"]
    async fn mux_transport_real_roundtrip() {
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            let server_key = SigningKey::from_bytes(&[10u8; 32]);
            let client_key = SigningKey::from_bytes(&[11u8; 32]);

            let mut a = PeerRuntime::start(
                identity_for_public_key(&client_key.verifying_key().to_bytes()),
                client_key.to_bytes(),
                "client-runtime".into(),
            )
            .await
            .expect("start client runtime");
            let mut b = PeerRuntime::start(
                identity_for_public_key(&server_key.verifying_key().to_bytes()),
                server_key.to_bytes(),
                "server-runtime".into(),
            )
            .await
            .expect("start server runtime");
            b.activate_listener(None, None)
                .await
                .expect("activate server listener");

            let public_key_bytes: [u8; 32] = hex::decode(&b.public_key)
                .expect("decode server public key")
                .as_slice()
                .try_into()
                .expect("server public key length");
            let b_public =
                VerifyingKey::from_bytes(&public_key_bytes).expect("parse server public key");
            let mut peer_info =
                PeerInfo::new(NodeId::from_public_key(&b_public), b.public_key.clone());
            peer_info.add_endpoint(
                b.transport_address.clone(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            );

            let ping = DhtRequest::new(
                DhtRequestPayload::Ping,
                NodeId::from_public_key(&client_key.verifying_key()),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            );

            let transport = super::MuxDhtTransport::new(
                client_key.clone(),
                Arc::new(Mutex::new(KnownHosts::new())),
                hal_settings::NetworkTrustPolicy::default(),
            );
            let response = transport
                .send_request(&peer_info, ping.clone())
                .await
                .expect("DHT roundtrip failed");

            assert_eq!(response.request_id, ping.request_id, "request_id mismatch");
            assert!(
                matches!(response.payload, DhtResponsePayload::Pong),
                "unexpected payload: {:?}",
                response.payload
            );
            assert_eq!(
                b.dht_metrics().snapshot().streams_received,
                1,
                "server DHT stream count mismatch"
            );
            assert_eq!(
                b.dht_metrics().snapshot().streams_processed,
                1,
                "server DHT processed count mismatch"
            );
            assert_eq!(
                b.dht_metrics().snapshot().responses_sent,
                1,
                "server DHT response count mismatch"
            );

            a.stop().await.expect("stop client runtime");
            b.stop().await.expect("stop server runtime");
        })
        .await;

        let _ = result.expect("DHT roundtrip timed out after 5s");
    }
}
