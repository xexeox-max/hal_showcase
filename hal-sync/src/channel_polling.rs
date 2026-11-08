use crate::{PollFuture, PollHandler, PollRequest, SyncEvent, SyncEventType, SyncManager};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelCursor {
    pub channel_id: String,
    pub value: Option<String>,
    pub revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelChange {
    pub channel_id: String,
    pub item_id: String,
    pub revision: u64,
    pub kind: String,
    pub payload: String,
    pub next_cursor: Option<String>,
}

pub trait ChannelSource: Send + Sync {
    fn poll(&self, cursor: ChannelCursor, limit: usize) -> PollFutureResult;
}

pub type PollFutureResult =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<ChannelChange>>> + Send>>;

pub struct ChannelPollHandler {
    source: Arc<dyn ChannelSource>,
    cursors: Arc<Mutex<HashMap<String, ChannelCursor>>>,
    sync: Arc<Mutex<SyncManager>>,
}

impl ChannelPollHandler {
    pub fn new(source: Arc<dyn ChannelSource>, sync: Arc<Mutex<SyncManager>>) -> Self {
        Self {
            source,
            cursors: Arc::new(Mutex::new(HashMap::new())),
            sync,
        }
    }

    pub async fn set_cursor(&self, cursor: ChannelCursor) {
        self.cursors
            .lock()
            .await
            .insert(cursor.channel_id.clone(), cursor);
    }

    pub async fn cursor(&self, channel_id: &str) -> Option<ChannelCursor> {
        self.cursors.lock().await.get(channel_id).cloned()
    }
}

impl PollHandler for ChannelPollHandler {
    fn handle(&self, request: PollRequest) -> PollFuture {
        let source = Arc::clone(&self.source);
        let cursors = Arc::clone(&self.cursors);
        let sync = Arc::clone(&self.sync);
        Box::pin(async move {
            let cursor = cursors
                .lock()
                .await
                .values()
                .next()
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no subscribed channel cursor"))?;
            let changes = source.poll(cursor.clone(), request.max_items).await?;
            let mut manager = sync.lock().await;
            for change in changes {
                if change.revision <= cursor.revision {
                    continue;
                }
                manager.events.push(SyncEvent::new(
                    format!(
                        "channel:{}:{}:{}",
                        change.channel_id, change.item_id, change.revision
                    ),
                    match change.kind.as_str() {
                        "deleted" => SyncEventType::ContactDeleted,
                        _ => SyncEventType::MessageAdded,
                    },
                    change.payload.clone(),
                ));
                manager.version += 1;
                cursors.lock().await.insert(
                    change.channel_id.clone(),
                    ChannelCursor {
                        channel_id: change.channel_id,
                        value: change.next_cursor,
                        revision: change.revision,
                    },
                );
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PollBranch;

    struct TestSource;

    impl ChannelSource for TestSource {
        fn poll(&self, cursor: ChannelCursor, _limit: usize) -> PollFutureResult {
            Box::pin(async move {
                Ok(vec![ChannelChange {
                channel_id: cursor.channel_id,
                item_id: "item-1".into(),
                revision: cursor.revision + 1,
                kind: "new".into(),
                payload: serde_json::json!({ "chat_id": "news", "sender_id": "channel", "text": "new item" }).to_string(),
                next_cursor: Some("cursor-2".into()),
            }])
            })
        }
    }

    #[tokio::test]
    async fn channel_poll_uses_cursor_and_emits_sync_event() {
        let sync = Arc::new(Mutex::new(SyncManager::new("client".into())));
        let handler = ChannelPollHandler::new(Arc::new(TestSource), Arc::clone(&sync));
        handler
            .set_cursor(ChannelCursor {
                channel_id: "news".into(),
                value: Some("cursor-1".into()),
                revision: 1,
            })
            .await;
        handler
            .handle(PollRequest {
                branch: PollBranch::Channels,
                max_items: 8,
            })
            .await
            .expect("poll");
        assert_eq!(sync.lock().await.events.len(), 1);
        assert_eq!(handler.cursor("news").await.unwrap().revision, 2);
    }
}
