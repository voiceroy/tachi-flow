//! Tachi push stream (`/tachi_ws`): one subscription per desk key. Any frame
//! crediting a desk (a user's VTXO payment, change, a deposit) triggers a sync
//! pass right away instead of waiting for the 8-second ticker.
//!
//! The daemon is push-only and rejects an unfiltered socket with HTTP 400.

use std::time::Duration;

use futures_util::StreamExt;
use tokio::sync::mpsc;

use crate::engine::Engine;

/// `https://host` → `wss://host/tachi_ws?address=<key>`.
pub fn ws_url(base_url: &str, address: &str) -> String {
    let base = base_url
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1);
    format!("{}/tachi_ws?address={address}", base.trim_end_matches('/'))
}

/// Run forever: watch every desk key, debounce frames into sync passes.
pub async fn run(engine: Engine) {
    let (tx, mut rx) = mpsc::channel::<()>(64);
    for key in engine.desk_tachi_keys() {
        let url = ws_url(engine.tachi().base_url(), &key);
        tokio::spawn(subscribe(url, tx.clone()));
    }
    drop(tx);
    while rx.recv().await.is_some() {
        // Let a burst of frames (pending + committed) collapse into one pass.
        tokio::time::sleep(Duration::from_millis(750)).await;
        while rx.try_recv().is_ok() {}
        if let Err(err) = engine.sync_all().await {
            tracing::warn!(%err, "push-triggered sync");
        }
    }
}

async fn subscribe(url: String, kick: mpsc::Sender<()>) {
    let mut backoff = Duration::from_secs(1);
    loop {
        match tokio_tungstenite::connect_async(url.as_str()).await {
            Ok((mut socket, _)) => {
                tracing::info!(%url, "tachi push stream connected");
                backoff = Duration::from_secs(1);
                while let Some(frame) = socket.next().await {
                    match frame {
                        Ok(msg) if msg.is_text() || msg.is_binary() => {
                            tracing::debug!(frame = %msg, "tachi push");
                            let _ = kick.try_send(());
                        }
                        Ok(_) => {}
                        Err(err) => {
                            tracing::warn!(%err, %url, "tachi push stream");
                            break;
                        }
                    }
                }
            }
            Err(err) => tracing::warn!(%err, %url, "tachi push connect"),
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_url_from_rpc_base() {
        assert_eq!(
            ws_url("https://rpc-regtest.tachibtc.com/", "ab"),
            "wss://rpc-regtest.tachibtc.com/tachi_ws?address=ab"
        );
        assert_eq!(ws_url("http://127.0.0.1:9", "cd"), "ws://127.0.0.1:9/tachi_ws?address=cd");
    }
}
