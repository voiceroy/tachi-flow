//! Tachi hosted regtest faucet. It pays P2WPKH, not P2WSH lock addresses.

use serde_json::Value;

use crate::error::Error;

pub fn faucet_url() -> String {
    std::env::var("TACHI_FAUCET_URL").unwrap_or_else(|_| "https://faucet.tachibtc.com".into())
}

/// Ask the faucet to send `amount_btc` to a **regular** `bcrt1q` (P2WPKH) address.
pub async fn drip(address: &str, amount_btc: f64) -> Result<String, Error> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| Error::Tachi(e.to_string()))?;
    let url = format!("{}/api/faucet", faucet_url().trim_end_matches('/'));
    let resp = http
        .post(url)
        .json(&serde_json::json!({
            "address": address,
            "amountBtc": amount_btc,
            "proof": null
        }))
        .send()
        .await
        .map_err(|e| Error::Tachi(format!("faucet: {e}")))?;
    let payload: Value = resp
        .json()
        .await
        .map_err(|e| Error::Tachi(format!("faucet body: {e}")))?;
    if payload.get("ok") != Some(&Value::Bool(true)) {
        let err = payload
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("faucet refused");
        return Err(Error::Tachi(format!(
            "{err}. The faucet only pays a normal wallet (P2WPKH), not a swap lock."
        )));
    }
    payload
        .get("txid")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Error::Tachi(format!("faucet missing txid: {payload}")))
}
