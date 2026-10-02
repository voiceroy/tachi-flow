//! Lightning node used by the desk for VTXO ↔ Lightning swaps.
//!
//! `in` (Lightning → VTXOs) uses a hold invoice on the desk's payment hash: the
//! user's HTLC is only *held* until the desk has paid VTXOs, then settled. If
//! the desk never pays, the invoice is cancelled and Lightning returns the
//! user's funds. `out` (VTXOs → Lightning): the desk pays the user's invoice
//! after it sees their VTXOs.
//!
//! Backends: LND's REST API, or an in-memory mock for tests.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE as B64URL};
use bitcoin::hashes::{Hash, sha256};
use serde_json::Value;

use crate::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvoiceState {
    Open,
    /// The payer's HTLC is locked in and waiting for settle/cancel.
    Accepted,
    Settled,
    Canceled,
}

#[derive(Debug, Clone)]
pub struct DecodedInvoice {
    pub payment_hash: [u8; 32],
    pub amount_sats: u64,
}

#[derive(Clone)]
pub enum LightningNode {
    Lnd(Lnd),
    Mock(Arc<MockNode>),
}

impl LightningNode {
    /// From `LND_REST_URL`, `LND_MACAROON_HEX` (or `LND_MACAROON_PATH`) and
    /// optional `LND_TLS_CERT_PATH`. `None` when Lightning is not configured.
    pub fn from_env() -> Result<Option<Self>, Error> {
        let Ok(url) = std::env::var("LND_REST_URL") else {
            return Ok(None);
        };
        let macaroon = match std::env::var("LND_MACAROON_HEX") {
            Ok(m) => m,
            Err(_) => {
                let path = std::env::var("LND_MACAROON_PATH").map_err(|_| {
                    Error::Invalid("LND_REST_URL needs LND_MACAROON_HEX or LND_MACAROON_PATH".into())
                })?;
                hex::encode(std::fs::read(&path).map_err(|e| Error::Invalid(format!("{path}: {e}")))?)
            }
        };
        let cert = std::env::var("LND_TLS_CERT_PATH")
            .ok()
            .map(|p| std::fs::read(&p).map_err(|e| Error::Invalid(format!("{p}: {e}"))))
            .transpose()?;
        Ok(Some(Self::Lnd(Lnd::new(&url, &macaroon, cert.as_deref())?)))
    }

    pub async fn add_hold_invoice(
        &self,
        hash: &[u8; 32],
        amount_sats: u64,
        memo: &str,
        expiry_secs: u64,
    ) -> Result<String, Error> {
        match self {
            Self::Lnd(n) => n.add_hold_invoice(hash, amount_sats, memo, expiry_secs).await,
            Self::Mock(n) => Ok(n.add_hold_invoice(hash, amount_sats)),
        }
    }

    pub async fn invoice_state(&self, hash: &[u8; 32]) -> Result<InvoiceState, Error> {
        match self {
            Self::Lnd(n) => n.invoice_state(hash).await,
            Self::Mock(n) => n.state(hash),
        }
    }

    pub async fn settle(&self, preimage: &[u8; 32]) -> Result<(), Error> {
        match self {
            Self::Lnd(n) => n.settle(preimage).await,
            Self::Mock(n) => n.settle(preimage),
        }
    }

    pub async fn cancel(&self, hash: &[u8; 32]) -> Result<(), Error> {
        match self {
            Self::Lnd(n) => n.cancel(hash).await,
            Self::Mock(n) => n.cancel(hash),
        }
    }

    pub async fn decode(&self, invoice: &str) -> Result<DecodedInvoice, Error> {
        match self {
            Self::Lnd(n) => n.decode(invoice).await,
            Self::Mock(n) => n.decode(invoice),
        }
    }

    /// Pay `invoice`; returns the preimage.
    pub async fn pay(&self, invoice: &str, max_fee_sats: u64) -> Result<[u8; 32], Error> {
        match self {
            Self::Lnd(n) => n.pay(invoice, max_fee_sats).await,
            Self::Mock(n) => n.pay(invoice),
        }
    }
}

#[derive(Clone)]
pub struct Lnd {
    http: reqwest::Client,
    base: String,
}

impl Lnd {
    pub fn new(base: &str, macaroon_hex: &str, tls_cert_pem: Option<&[u8]>) -> Result<Self, Error> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "Grpc-Metadata-macaroon",
            macaroon_hex
                .trim()
                .parse()
                .map_err(|_| Error::Invalid("macaroon is not a valid header value".into()))?,
        );
        let mut builder = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(60));
        if let Some(pem) = tls_cert_pem {
            // LND serves a self-signed cert; trust exactly that one.
            let cert = reqwest::Certificate::from_pem(pem)
                .map_err(|e| Error::Invalid(format!("LND TLS cert: {e}")))?;
            builder = builder.add_root_certificate(cert);
        }
        Ok(Self {
            http: builder.build().map_err(|e| Error::Invalid(e.to_string()))?,
            base: base.trim_end_matches('/').to_string(),
        })
    }

    async fn call(&self, req: reqwest::RequestBuilder) -> Result<Value, Error> {
        let resp = req.send().await.map_err(|e| Error::Tachi(format!("lnd: {e}")))?;
        let status = resp.status();
        let body: Value = resp
            .json()
            .await
            .map_err(|e| Error::Tachi(format!("lnd body: {e}")))?;
        if !status.is_success() {
            return Err(Error::TachiRejected(format!("lnd HTTP {status}: {body}")));
        }
        Ok(body)
    }

    async fn add_hold_invoice(
        &self,
        hash: &[u8; 32],
        amount_sats: u64,
        memo: &str,
        expiry_secs: u64,
    ) -> Result<String, Error> {
        let body = self
            .call(self.http.post(format!("{}/v2/invoices/hodl", self.base)).json(&serde_json::json!({
                "hash": B64.encode(hash),
                "value": amount_sats.to_string(),
                "memo": memo,
                "expiry": expiry_secs.to_string(),
            })))
            .await?;
        body["payment_request"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| Error::Tachi(format!("lnd hodl invoice: {body}")))
    }

    async fn invoice_state(&self, hash: &[u8; 32]) -> Result<InvoiceState, Error> {
        let body = self
            .call(
                self.http
                    .get(format!("{}/v2/invoices/lookup", self.base))
                    .query(&[("payment_hash", B64URL.encode(hash))]),
            )
            .await?;
        Ok(match body["state"].as_str() {
            Some("ACCEPTED") => InvoiceState::Accepted,
            Some("SETTLED") => InvoiceState::Settled,
            Some("CANCELED") => InvoiceState::Canceled,
            _ => InvoiceState::Open,
        })
    }

    async fn settle(&self, preimage: &[u8; 32]) -> Result<(), Error> {
        self.call(
            self.http
                .post(format!("{}/v2/invoices/settle", self.base))
                .json(&serde_json::json!({ "preimage": B64.encode(preimage) })),
        )
        .await
        .map(|_| ())
    }

    async fn cancel(&self, hash: &[u8; 32]) -> Result<(), Error> {
        self.call(
            self.http
                .post(format!("{}/v2/invoices/cancel", self.base))
                .json(&serde_json::json!({ "payment_hash": B64.encode(hash) })),
        )
        .await
        .map(|_| ())
    }

    async fn decode(&self, invoice: &str) -> Result<DecodedInvoice, Error> {
        let body = self
            .call(self.http.get(format!("{}/v1/payreq/{}", self.base, invoice.trim())))
            .await?;
        let hash = hex::decode(body["payment_hash"].as_str().unwrap_or_default())
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| Error::Invalid("invoice has no payment hash".into()))?;
        let amount_sats = body["num_satoshis"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        Ok(DecodedInvoice {
            payment_hash: hash,
            amount_sats,
        })
    }

    async fn pay(&self, invoice: &str, max_fee_sats: u64) -> Result<[u8; 32], Error> {
        let body = self
            .call(
                self.http
                    .post(format!("{}/v1/channels/transactions", self.base))
                    .json(&serde_json::json!({
                        "payment_request": invoice.trim(),
                        "fee_limit": { "fixed": max_fee_sats.to_string() },
                    })),
            )
            .await?;
        if let Some(err) = body["payment_error"].as_str().filter(|e| !e.is_empty()) {
            return Err(Error::TachiRejected(format!("lightning payment failed: {err}")));
        }
        B64.decode(body["payment_preimage"].as_str().unwrap_or_default())
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| Error::Tachi(format!("lnd payment returned no preimage: {body}")))
    }
}

/// In-memory node: invoices are `mock:<hash hex>:<sats>`.
#[derive(Default)]
pub struct MockNode {
    invoices: Mutex<HashMap<[u8; 32], (u64, InvoiceState)>>,
    /// Preimages for invoices this node can "pay" (as if the payee revealed them).
    pub payable: Mutex<HashMap<[u8; 32], [u8; 32]>>,
    pub paid: Mutex<Vec<String>>,
}

impl MockNode {
    fn add_hold_invoice(&self, hash: &[u8; 32], amount_sats: u64) -> String {
        self.invoices
            .lock()
            .unwrap()
            .insert(*hash, (amount_sats, InvoiceState::Open));
        format!("mock:{}:{amount_sats}", hex::encode(hash))
    }

    pub fn state_of(&self, hash: &[u8; 32]) -> Option<InvoiceState> {
        self.invoices.lock().unwrap().get(hash).map(|i| i.1)
    }

    /// Simulate the payer locking in their HTLC.
    pub fn accept(&self, hash: &[u8; 32]) {
        if let Some(inv) = self.invoices.lock().unwrap().get_mut(hash) {
            inv.1 = InvoiceState::Accepted;
        }
    }

    fn state(&self, hash: &[u8; 32]) -> Result<InvoiceState, Error> {
        self.invoices
            .lock()
            .unwrap()
            .get(hash)
            .map(|i| i.1)
            .ok_or_else(|| Error::Invalid("unknown invoice".into()))
    }

    fn settle(&self, preimage: &[u8; 32]) -> Result<(), Error> {
        let hash = sha256::Hash::hash(preimage).to_byte_array();
        let mut inv = self.invoices.lock().unwrap();
        let entry = inv
            .get_mut(&hash)
            .ok_or_else(|| Error::Invalid("preimage matches no invoice".into()))?;
        if entry.1 != InvoiceState::Accepted {
            return Err(Error::Invalid("invoice not accepted".into()));
        }
        entry.1 = InvoiceState::Settled;
        Ok(())
    }

    fn cancel(&self, hash: &[u8; 32]) -> Result<(), Error> {
        if let Some(inv) = self.invoices.lock().unwrap().get_mut(hash) {
            inv.1 = InvoiceState::Canceled;
        }
        Ok(())
    }

    fn decode(&self, invoice: &str) -> Result<DecodedInvoice, Error> {
        let mut parts = invoice.trim().strip_prefix("mock:").unwrap_or_default().split(':');
        let hash = parts
            .next()
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| Error::Invalid("not a mock invoice".into()))?;
        let amount_sats = parts.next().and_then(|a| a.parse().ok()).unwrap_or(0);
        Ok(DecodedInvoice {
            payment_hash: hash,
            amount_sats,
        })
    }

    fn pay(&self, invoice: &str) -> Result<[u8; 32], Error> {
        let d = self.decode(invoice)?;
        let pre = self
            .payable
            .lock()
            .unwrap()
            .get(&d.payment_hash)
            .copied()
            .ok_or_else(|| Error::TachiRejected("no route".into()))?;
        self.paid.lock().unwrap().push(invoice.to_string());
        Ok(pre)
    }
}
