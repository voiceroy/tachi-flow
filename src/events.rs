//! Live updates: every swap change is published on a broadcast channel. The
//! UI reads it as server-sent events; registered webhooks get a POST per event.

use serde::Serialize;
use uuid::Uuid;

use crate::model::{Swap, WebhookRequest};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum Event {
    Swap(Box<Swap>),
}

impl Event {
    pub fn id(&self) -> Uuid {
        match self {
            Self::Swap(s) => s.id,
        }
    }

    /// One SSE frame: `event: <kind>` + JSON `data:`.
    pub fn sse_frame(&self) -> String {
        let kind = match self {
            Self::Swap(_) => "swap",
        };
        let json = serde_json::to_string(self).unwrap_or_else(|_| "{}".into());
        format!("event: {kind}\ndata: {json}\n\n")
    }
}

pub const CHANNEL_CAPACITY: usize = 1024;
pub const MAX_WEBHOOKS: usize = 100;

/// Fire-and-forget delivery to every matching webhook.
pub fn deliver(http: &reqwest::Client, hooks: &[WebhookRequest], event: &Event) {
    for hook in hooks
        .iter()
        .filter(|h| h.swap_id.is_none_or(|id| id == event.id()))
    {
        let req = http.post(&hook.url).json(event);
        let url = hook.url.clone();
        tokio::spawn(async move {
            if let Err(err) = req.send().await {
                tracing::debug!(%err, %url, "webhook delivery");
            }
        });
    }
}

pub fn webhook_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("webhook client")
}

pub fn validate_webhook_url(url: &str) -> Result<(), crate::error::Error> {
    let ok = url.starts_with("https://") || url.starts_with("http://");
    if ok && url.len() <= 2048 {
        Ok(())
    } else {
        Err(crate::error::Error::Invalid(
            "webhook url must be http(s) and at most 2048 chars".into(),
        ))
    }
}
