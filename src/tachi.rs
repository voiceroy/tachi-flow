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
            return Err(Error::Tachi(payload["error"].to_string()));
        }
        Ok(payload.get("result").cloned().unwrap_or(Value::Null))
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
        self.get_json("/tachi_vtxo", &[("id", id)]).await
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
            return Err(Error::Tachi(format!("CheckTx code {code}: {log}")));
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
