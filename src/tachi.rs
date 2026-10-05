use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Error;

#[derive(Clone)]
pub struct TachiClient {
    http: reqwest::Client,
    base_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vtxo {
    pub id: String,
    pub owner: String,
    pub amount: u64,
    #[serde(default)]
    pub spent: bool,
    #[serde(default)]
    pub height: u64,
    #[serde(default)]
    pub script: String,
    #[serde(default)]
    pub locked: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Health {
    pub ok: bool,
    pub detail: String,
}

impl TachiClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self, Error> {
        let http = reqwest::Client::builder()
            .user_agent("tachi-flow/0.1")
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .map_err(|e| Error::Tachi(e.to_string()))?;
        Ok(Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_string(),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub async fn health(&self) -> Health {
        match self
            .http
            .get(format!("{}/health", self.base_url))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => Health {
                ok: true,
                detail: resp.text().await.unwrap_or_else(|_| "ok".into()),
            },
            Ok(resp) => Health {
                ok: false,
                detail: format!("HTTP {}", resp.status()),
            },
            Err(err) => Health {
                ok: false,
                detail: err.to_string(),
            },
        }
    }

    /// Bitcoin Core JSON-RPC 1.0 proxy as documented at POST `/`.
    pub async fn bitcoin_rpc(&self, method: &str, params: Value) -> Result<Value, Error> {
        let body = serde_json::json!({
            "id": "tachi-flow",
            "jsonrpc": "1.0",
            "method": method,
            "params": params,
        });
        let resp = self
            .http
            .post(format!("{}/", self.base_url))
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Tachi(e.to_string()))?;
        let payload: Value = resp.json().await.map_err(|e| Error::Tachi(e.to_string()))?;
        if !payload.get("error").is_none_or(Value::is_null) {
            return Err(Error::TachiRejected(payload["error"].to_string()));
        }
        Ok(payload.get("result").cloned().unwrap_or(Value::Null))
    }

    /// `estimatesmartfee` in sat/vB, `None` when the node has no estimate.
    pub async fn estimate_fee_rate(&self, target_blocks: u32) -> Result<Option<f64>, Error> {
        let result = self
            .bitcoin_rpc("estimatesmartfee", serde_json::json!([target_blocks]))
            .await?;
        // BTC per kvB → sat per vB.
        Ok(result
            .get("feerate")
            .and_then(Value::as_f64)
            .map(|btc_per_kvb| btc_per_kvb * 100_000_000.0 / 1_000.0))
    }

    /// Confirmations of a tx: `Some(0)` in the mempool, `None` if the node
    /// does not know it (never sent, or evicted).
    pub async fn tx_confirmations(&self, txid: &str) -> Result<Option<u32>, Error> {
        match self
            .bitcoin_rpc("getrawtransaction", serde_json::json!([txid, true]))
            .await
        {
            Ok(tx) => Ok(Some(
                tx.get("confirmations").and_then(Value::as_u64).unwrap_or(0) as u32,
            )),
            Err(Error::TachiRejected(why)) if why.contains("-5") || why.contains("No such") => Ok(None),
            Err(err) => Err(err),
        }
    }

    pub async fn block_height(&self) -> Result<u32, Error> {
        let info = self
            .bitcoin_rpc("getblockchaininfo", serde_json::json!([]))
            .await?;
        info.get("blocks")
            .and_then(Value::as_u64)
            .map(|h| h as u32)
            .ok_or_else(|| Error::Tachi("getblockchaininfo.blocks missing".into()))
    }

    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<T, Error> {
        let resp = self
            .http
            .get(format!("{}{path}", self.base_url))
            .query(query)
            .send()
            .await
            .map_err(|e| Error::Tachi(e.to_string()))?;
        let status = resp.status();
        let text = resp.text().await.map_err(|e| Error::Tachi(e.to_string()))?;
        if !status.is_success() {
            return Err(Error::Tachi(format!("{path} HTTP {status}: {text}")));
        }
        serde_json::from_str(&text).map_err(|e| Error::Tachi(format!("{path} decode: {e}: {text}")))
    }

    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<T, Error> {
        let resp = self
            .http
            .post(format!("{}{path}", self.base_url))
            .json(body)
            .send()
            .await
            .map_err(|e| Error::Tachi(e.to_string()))?;
        let status = resp.status();
        let text = resp.text().await.map_err(|e| Error::Tachi(e.to_string()))?;
        if !status.is_success() {
            return Err(Error::Tachi(format!("{path} HTTP {status}: {text}")));
        }
        serde_json::from_str(&text).map_err(|e| Error::Tachi(format!("{path} decode: {e}: {text}")))
    }

    pub async fn get_vtxo(&self, id: &str) -> Result<Vtxo, Error> {
        self.find_vtxo(id)
            .await?
            .ok_or_else(|| Error::Tachi(format!("vtxo {id} not found")))
    }

    /// `Ok(None)` only when Tachi says the VTXO does not exist (HTTP 404).
    /// Transport errors stay errors so callers never mistake them for "not paid".
    pub async fn find_vtxo(&self, id: &str) -> Result<Option<Vtxo>, Error> {
        let resp = self
            .http
            .get(format!("{}/tachi_vtxo", self.base_url))
            .query(&[("id", id)])
            .send()
            .await
            .map_err(|e| Error::Tachi(e.to_string()))?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let text = resp.text().await.map_err(|e| Error::Tachi(e.to_string()))?;
        if !status.is_success() {
            return Err(Error::Tachi(format!("/tachi_vtxo HTTP {status}: {text}")));
        }
        serde_json::from_str(&text)
            .map(Some)
            .map_err(|e| Error::Tachi(format!("/tachi_vtxo decode: {e}: {text}")))
    }

    pub async fn address_vtxos(&self, address: &str) -> Result<Vec<Vtxo>, Error> {
        #[derive(Deserialize)]
        struct Resp {
            #[serde(default)]
            vtxos: Vec<Vtxo>,
        }
        let resp: Resp = self
            .get_json(
                "/tachi_addressVtxos",
                &[("address", address), ("includeSpent", "false")],
            )
            .await?;
        Ok(resp.vtxos)
    }

    pub async fn next_nonce(&self, address: &str) -> Result<u64, Error> {
        #[derive(Deserialize)]
        struct Resp {
            #[serde(default)]
            next_nonce: u64,
        }
        let resp: Resp = self
            .get_json("/tachi_nonce", &[("address", address)])
            .await?;
        Ok(resp.next_nonce)
    }

    pub async fn recommended_fee_sats(&self) -> Result<u64, Error> {
        #[derive(Deserialize)]
        struct Resp {
            #[serde(default)]
            recommended_fee_sat: u64,
            #[serde(default)]
            min_fee_sat: u64,
        }
        let resp: Resp = self.get_json("/tachi_feeEstimate", &[]).await?;
        let fee = if resp.recommended_fee_sat > 0 {
            resp.recommended_fee_sat
        } else {
            resp.min_fee_sat
        };
        Ok(fee.max(1))
    }

    pub async fn broadcast_tx_sync(&self, hex_tx: &str) -> Result<String, Error> {
        let payload: Value = self
            .post_json(
                "/tachi_txBroadcastSync",
                &serde_json::json!({ "tx": hex_tx }),
            )
            .await?;
        if let Some(err) = payload.get("error").filter(|e| !e.is_null()) {
            return Err(Error::Tachi(format!("broadcast: {err}")));
        }
        let result = payload.get("result").cloned().unwrap_or(Value::Null);
        let code = result.get("code").and_then(Value::as_u64).unwrap_or(0);
        if code != 0 {
            let log = result
                .get("log")
                .and_then(Value::as_str)
                .unwrap_or("checktx failed");
            return Err(Error::TachiRejected(format!("CheckTx code {code}: {log}")));
        }
        result
            .get("hash")
            .and_then(Value::as_str)
            .map(|s| s.to_string())
            .ok_or_else(|| Error::Tachi("broadcast missing hash".into()))
    }

    pub async fn scan_address(&self, address: &str) -> Result<Vec<ChainUtxo>, Error> {
        let result = self
            .bitcoin_rpc(
                "scantxoutset",
                serde_json::json!(["start", [format!("addr({address})")]]),
            )
            .await?;
        let mut out = Vec::new();
        if let Some(unspents) = result.get("unspents").and_then(Value::as_array) {
            for u in unspents {
                let txid = u.get("txid").and_then(Value::as_str).unwrap_or("").to_string();
                let vout = u.get("vout").and_then(Value::as_u64).unwrap_or(0) as u32;
                let value_sats = if let Some(s) = u.get("value_sats").and_then(Value::as_u64) {
                    s
                } else {
                    let btc = u.get("amount").and_then(Value::as_f64).unwrap_or(0.0);
                    (btc * 100_000_000.0).round() as u64
                };
                if !txid.is_empty() && value_sats > 0 {
                    out.push(ChainUtxo {
                        txid,
                        vout,
                        value_sats,
                    });
                }
            }
        }
        Ok(out)
    }

    /// Mempool-aware `gettxout`. Used so a just-broadcast faucet/lock tx is visible
    /// before the next block (`scantxoutset` only sees confirmed coins).
    pub async fn get_tx_out(&self, txid: &str, vout: u32) -> Result<Option<ChainUtxo>, Error> {
        let result = self
            .bitcoin_rpc("gettxout", serde_json::json!([txid, vout, true]))
            .await?;
        if result.is_null() {
            return Ok(None);
        }
        let value_sats = if let Some(s) = result.get("value_sats").and_then(Value::as_u64) {
            s
        } else {
            let btc = result.get("value").and_then(Value::as_f64).unwrap_or(0.0);
            (btc * 100_000_000.0).round() as u64
        };
        if value_sats == 0 {
            return Ok(None);
        }
        Ok(Some(ChainUtxo {
            txid: txid.to_string(),
            vout,
            value_sats,
        }))
    }

    /// Confirmed-only `gettxout` with what a claim advance needs to price the
    /// output: value, confirmations, and the scriptPubKey it pays.
    pub async fn confirmed_tx_out(&self, txid: &str, vout: u32) -> Result<Option<TxOutInfo>, Error> {
        let result = self
            .bitcoin_rpc("gettxout", serde_json::json!([txid, vout, false]))
            .await?;
        if result.is_null() {
            return Ok(None);
        }
        let btc = result.get("value").and_then(Value::as_f64).unwrap_or(0.0);
        Ok(Some(TxOutInfo {
            value_sats: (btc * 100_000_000.0).round() as u64,
            confirmations: result
                .get("confirmations")
                .and_then(Value::as_u64)
                .unwrap_or(0) as u32,
            script_pubkey_hex: result
                .pointer("/scriptPubKey/hex")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        }))
    }

    /// The validators' compressed keys: the quorum in every vault script.
    pub async fn quorum_keys(&self) -> Result<Vec<bitcoin::PublicKey>, Error> {
        let v: Value = self.get_json("/tachi_validators", &[]).await?;
        v.get("validators")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Tachi("/tachi_validators: no validators".into()))?
            .iter()
            .map(|val| {
                val.get("pub_key_hex")
                    .and_then(Value::as_str)
                    .and_then(|k| k.parse().ok())
                    .ok_or_else(|| Error::Tachi("/tachi_validators: bad pub_key_hex".into()))
            })
            .collect()
    }

    /// Watchtower receipts for a vault (spends of its funding outpoint it has
    /// classified `legitimate` / `stale` / `anomalous`).
    pub async fn watchtower_receipts(&self, vault_id: &str) -> Result<Vec<Value>, Error> {
        let v: Value = self
            .get_json("/tachi_watchtower/receipts", &[("vault", vault_id)])
            .await?;
        Ok(v.get("receipts").and_then(Value::as_array).cloned().unwrap_or_default())
    }

    /// Vault ids registered on Tachi for an x-only user key.
    pub async fn vault_ids(&self, user_xonly_hex: &str) -> Result<Vec<String>, Error> {
        let v: Value = self
            .get_json("/tachi_listVaults", &[("user", user_xonly_hex), ("page_size", "100")])
            .await?;
        Ok(v.get("vaults")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.get("vault_id").and_then(Value::as_str).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Raw hex of a tx the node knows (mempool or chain).
    pub async fn raw_tx(&self, txid: &str) -> Result<String, Error> {
        let hex = self
            .bitcoin_rpc("getrawtransaction", serde_json::json!([txid, false]))
            .await?;
        hex.as_str()
            .map(str::to_string)
            .ok_or_else(|| Error::Tachi(format!("getrawtransaction: {hex}")))
    }

    pub async fn send_raw_tx(&self, hex_tx: &str) -> Result<String, Error> {
        let txid = self
            .bitcoin_rpc("sendrawtransaction", serde_json::json!([hex_tx]))
            .await?;
        txid.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| Error::Tachi(format!("sendrawtransaction: {txid}")))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainUtxo {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutInfo {
    pub value_sats: u64,
    pub confirmations: u32,
    pub script_pubkey_hex: String,
}
