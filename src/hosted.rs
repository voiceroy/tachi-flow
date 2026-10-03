//! Hosted (third-party) desks: liquidity providers that run their own keys
//! and funds elsewhere. The operator registers a desk's endpoint and pins
//! its quote-signing keys; this server then asks it for quotes alongside the
//! house desks and only passes on quotes that verify.
//!
//! Protocol: a hosted desk answers `POST {endpoint}/v1/quotes` with a
//! [`CreateQuoteRequest`] body and returns a [`Quote`] signed with BIP340
//! over [`crate::engine::quote_commitment`] — exactly what tachi-flow's own
//! quote route returns, so any tachi-flow instance can be a hosted desk. The
//! user then settles with that desk directly (its `pay` instructions); this
//! server never holds its funds.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::engine::verify_quote_signature;
use crate::error::Error;
use crate::model::{CreateQuoteRequest, Quote};

/// How long a hosted desk gets to answer an RFQ.
pub const HOSTED_QUOTE_TIMEOUT_SECS: u64 = 3;
pub const MAX_HOSTED_DESKS: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostedDesk {
    pub id: String,
    pub name: String,
    /// Base URL of the desk's API (`{endpoint}/v1/quotes`).
    pub endpoint: String,
    /// x-only keys (hex) the desk signs quotes with; anything else is refused.
    pub pubkeys: Vec<String>,
    pub registered_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_quote_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Quotes it returned that verified / were refused.
    #[serde(default)]
    pub quotes_ok: u64,
    #[serde(default)]
    pub quotes_refused: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDeskRequest {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub pubkeys: Vec<String>,
}

/// A hosted desk's verified answer to an RFQ.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostedQuote {
    pub desk_id: String,
    pub desk_name: String,
    /// Where the user settles this quote.
    pub endpoint: String,
    pub quote: Quote,
}

impl RegisterDeskRequest {
    pub fn validate(&self) -> Result<(), Error> {
        let id_ok = !self.id.is_empty()
            && self.id.len() <= 32
            && self.id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        if !id_ok {
            return Err(Error::Invalid("desk id: 1-32 chars of [A-Za-z0-9-]".into()));
        }
        if self.name.trim().is_empty() || self.name.len() > 64 {
            return Err(Error::Invalid("desk name: 1-64 chars".into()));
        }
        crate::events::validate_webhook_url(&self.endpoint)
            .map_err(|_| Error::Invalid("endpoint must be an http(s) URL of at most 2048 chars".into()))?;
        if self.pubkeys.is_empty() || self.pubkeys.len() > 8 {
            return Err(Error::Invalid("pubkeys: 1-8 x-only keys".into()));
        }
        for k in &self.pubkeys {
            let ok = hex::decode(k)
                .ok()
                .and_then(|b| bitcoin::secp256k1::XOnlyPublicKey::from_slice(&b).ok())
                .is_some();
            if !ok {
                return Err(Error::Invalid(format!("pubkey {k} is not an x-only key")));
            }
        }
        Ok(())
    }
}

/// Is `quote` a valid answer from `desk` to `req`? Checks the pinned key,
/// the BIP340 signature, the terms asked for, and that it has not expired.
pub fn check_hosted_quote(desk: &HostedDesk, req: &CreateQuoteRequest, quote: &Quote) -> Result<(), String> {
    let key = quote.desk_pubkey.as_deref().ok_or("quote is not signed")?;
    if !desk.pubkeys.iter().any(|k| k.eq_ignore_ascii_case(key)) {
        return Err(format!("signed by {key}, which is not a key registered for {}", desk.id));
    }
    verify_quote_signature(quote)?;
    if quote.side != req.side || quote.amount_sats != req.amount_sats {
        return Err("quote is for different terms than were asked".into());
    }
    if quote.receive_sats + quote.fee_sats != quote.amount_sats {
        return Err("quote's fee and receive amount do not add up".into());
    }
    if req.user_refund_pubkey_hex.is_some() && quote.user_pubkey_hex != req.user_refund_pubkey_hex {
        return Err("quote is bound to a different user key".into());
    }
    if quote.expires_at <= Utc::now() {
        return Err("quote already expired".into());
    }
    Ok(())
}

/// Ask one hosted desk for a quote and check it.
pub async fn fetch_quote(
    http: &reqwest::Client,
    desk: &HostedDesk,
    req: &CreateQuoteRequest,
) -> Result<HostedQuote, String> {
    let url = format!("{}/v1/quotes", desk.endpoint.trim_end_matches('/'));
    let resp = http
        .post(&url)
        .timeout(std::time::Duration::from_secs(HOSTED_QUOTE_TIMEOUT_SECS))
        .json(req)
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    let status = resp.status();
    let body = resp.bytes().await.map_err(|e| format!("read failed: {e}"))?;
    if !status.is_success() {
        let text = String::from_utf8_lossy(&body[..body.len().min(300)]).to_string();
        return Err(format!("HTTP {status}: {text}"));
    }
    if body.len() > 64 * 1024 {
        return Err("response too large".into());
    }
    let quote: Quote = serde_json::from_slice(&body).map_err(|e| format!("not a quote: {e}"))?;
    check_hosted_quote(desk, req, &quote)?;
    Ok(HostedQuote {
        desk_id: desk.id.clone(),
        desk_name: desk.name.clone(),
        endpoint: desk.endpoint.clone(),
        quote,
    })
}
