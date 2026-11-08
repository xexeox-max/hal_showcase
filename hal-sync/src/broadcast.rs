use anyhow::{anyhow, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hal_settings::{BroadcastDelivery, BroadcastMode, FeedChange, MediaBroadcastRequest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBroadcastRequest {
    pub request: MediaBroadcastRequest,
    pub subscriber_identity_id: String,
    pub subscriber_public_key: String,
    pub signature: String,
}

impl SignedBroadcastRequest {
    pub fn new(request: MediaBroadcastRequest, identity_id: String, public_key: String) -> Self {
        Self {
            request,
            subscriber_identity_id: identity_id,
            subscriber_public_key: public_key,
            signature: String::new(),
        }
    }

    fn signing_payload(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            &self.request,
            &self.subscriber_identity_id,
            &self.subscriber_public_key,
        ))?)
    }

    pub fn sign(&mut self, private_key: &[u8]) -> Result<()> {
        let key: [u8; 32] = private_key
            .try_into()
            .map_err(|_| anyhow!("private key must be 32 bytes"))?;
        self.signature = hex::encode(
            SigningKey::from_bytes(&key)
                .sign(&self.signing_payload()?)
                .to_bytes(),
        );
        Ok(())
    }

    pub fn verify(&self) -> Result<()> {
        let public: [u8; 32] = hex::decode(&self.subscriber_public_key)?
            .try_into()
            .map_err(|_| anyhow!("public key must be 32 bytes"))?;
        let signature: [u8; 64] = hex::decode(&self.signature)?
            .try_into()
            .map_err(|_| anyhow!("signature must be 64 bytes"))?;
        let mut hash = Sha256::new();
        hash.update(public);
        if self.subscriber_identity_id != hex::encode(hash.finalize()) {
            return Err(anyhow!("subscriber identity does not match public key"));
        }
        if self.request.subscriber_id != self.subscriber_identity_id {
            return Err(anyhow!("request subscriber does not match signed identity"));
        }
        VerifyingKey::from_bytes(&public)?
            .verify(&self.signing_payload()?, &Signature::from_bytes(&signature))?;
        self.request.validate().map_err(|error| anyhow!(error))
    }
}

#[derive(Debug, Default)]
pub struct BroadcastRegistry {
    requests: HashMap<String, MediaBroadcastRequest>,
    queues: HashMap<String, VecDeque<BroadcastDelivery>>,
}

impl BroadcastRegistry {
    pub fn register_signed(&mut self, signed: SignedBroadcastRequest, now: u64) -> Result<()> {
        signed.verify()?;
        let request = signed.request;
        if request.is_expired(now) {
            return Err(anyhow!("broadcast request has expired"));
        }
        self.queues.entry(request.request_id.clone()).or_default();
        self.requests.insert(request.request_id.clone(), request);
        Ok(())
    }

    pub fn register(&mut self, request: MediaBroadcastRequest, now: u64) -> Result<()> {
        request.validate().map_err(|error| anyhow!(error))?;
        if request.is_expired(now) {
            return Err(anyhow!("broadcast request has expired"));
        }
        self.queues.entry(request.request_id.clone()).or_default();
        self.requests.insert(request.request_id.clone(), request);
        Ok(())
    }

    pub fn revoke(&mut self, request_id: &str) -> bool {
        self.queues.remove(request_id);
        self.requests.remove(request_id).is_some()
    }

    pub fn publish_change(&mut self, change: &FeedChange, now: u64) -> usize {
        let mut delivered = 0;
        let request_ids: Vec<_> = self.requests.keys().cloned().collect();
        for request_id in request_ids {
            let Some(request) = self.requests.get(&request_id).cloned() else {
                continue;
            };
            if request.is_expired(now) {
                self.revoke(&request_id);
                continue;
            }
            if request.mode != BroadcastMode::ContinuousFeed
                || !request
                    .filter
                    .channel_ids
                    .iter()
                    .any(|id| id == &change.channel_id)
                || !request
                    .filter
                    .change_kinds
                    .iter()
                    .any(|kind| kind == &change.kind)
                || (!request.filter.include_media && !change.media_refs.is_empty())
            {
                continue;
            }
            let queue = self.queues.entry(request_id.clone()).or_default();
            for target in request.targets {
                if queue.len() >= request.max_queue_items {
                    break;
                }
                queue.push_back(BroadcastDelivery {
                    request_id: request_id.clone(),
                    subscriber_id: request.subscriber_id.clone(),
                    target,
                    change: change.clone(),
                });
                delivered += 1;
            }
        }
        delivered
    }

    pub fn take_deliveries(
        &mut self,
        request_id: &str,
        max_items: usize,
    ) -> Vec<BroadcastDelivery> {
        let Some(queue) = self.queues.get_mut(request_id) else {
            return Vec::new();
        };
        let count = max_items.min(queue.len());
        queue.drain(..count).collect()
    }

    pub fn active_request_count(&self) -> usize {
        self.requests.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use hal_settings::{BroadcastTarget, FeedChangeKind, FeedFilter};

    fn request() -> MediaBroadcastRequest {
        MediaBroadcastRequest {
            request_id: "request".into(),
            subscriber_id: "subscriber".into(),
            mode: BroadcastMode::ContinuousFeed,
            targets: vec![BroadcastTarget {
                peer_id: "peer".into(),
                transport_address: "127.0.0.1:1".into(),
            }],
            filter: FeedFilter {
                channel_ids: vec!["news".into()],
                change_kinds: vec![FeedChangeKind::NewItem],
                include_media: false,
            },
            requested_at: 1,
            expires_at: Some(100),
            max_queue_items: 10,
            max_fanout_targets: 1,
        }
    }

    #[test]
    fn endpoint_fans_out_only_requested_feed_changes() {
        let mut registry = BroadcastRegistry::default();
        registry.register(request(), 2).expect("register");
        let change = FeedChange {
            channel_id: "news".into(),
            item_id: "item".into(),
            kind: FeedChangeKind::NewItem,
            payload_ref: "content://item".into(),
            media_refs: vec![],
            created_at: 3,
        };
        assert_eq!(registry.publish_change(&change, 3), 1);
        assert_eq!(registry.take_deliveries("request", 10).len(), 1);
    }

    #[test]
    fn endpoint_does_not_broadcast_unrequested_channels_or_media() {
        let mut registry = BroadcastRegistry::default();
        registry.register(request(), 2).expect("register");
        let change = FeedChange {
            channel_id: "other".into(),
            item_id: "item".into(),
            kind: FeedChangeKind::NewItem,
            payload_ref: "content://item".into(),
            media_refs: vec!["media://video".into()],
            created_at: 3,
        };
        assert_eq!(registry.publish_change(&change, 3), 0);
    }

    #[test]
    fn signed_subscriber_request_is_required_for_network_registration() {
        let key = SigningKey::from_bytes(&[21; 32]);
        let public = key.verifying_key().to_bytes();
        let mut hash = Sha256::new();
        hash.update(public);
        let identity = hex::encode(hash.finalize());
        let mut request = request();
        request.subscriber_id = identity.clone();
        let mut signed = SignedBroadcastRequest::new(request, identity, hex::encode(public));
        signed.sign(&key.to_bytes()).expect("sign request");
        let mut registry = BroadcastRegistry::default();
        registry
            .register_signed(signed, 2)
            .expect("register signed request");
        assert_eq!(registry.active_request_count(), 1);
    }
}
