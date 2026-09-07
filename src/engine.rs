use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use bitcoin::absolute::LockTime;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Address, CompressedPublicKey, Network, OutPoint};
use chrono::{Duration, Utc};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::Error;
use crate::htlc::{
    claim_tx_hex, generate_keypair, p2wpkh_send_hex, p2wsh_address, parse_txid, payment_hash,
    pubkey_from_hex, random_preimage, redeem_script,
};
use crate::model::{
    CreateQuoteRequest, LiquidityProvider, ObserveLockRequest, ObserveVtxoRequest, PayInstructions,
    Quote, Side, Swap, SwapStatus, fee_sats,
};
use crate::tachi::TachiClient;
use crate::tachi_tx::{
    TransferInput, TransferOutput, looks_like_tachi_owner, looks_like_vtxo_id, parse_tachi_owner,
    parse_vtxo_id, select_vtxos, sign_deposit, sign_transfer, xonly_from_secret,
};

const MIN_SWAP_SATS: u64 = 10_000;
const MIN_FEE_SATS: u64 = 200;
const QUOTE_TTL_SECS: i64 = 10 * 60;
const HTLC_TIMEOUT_BLOCKS: u32 = 144;
const CLAIM_FEE_SATS: u64 = 500;
const FALLBACK_HEIGHT: u32 = 200_000;

struct Inner {
    quotes: HashMap<Uuid, Quote>,
    swaps: HashMap<Uuid, Swap>,
    lps: Vec<LiquidityProvider>,
    /// preimage + LP secret for inbound HTLCs, keyed by quote id then swap id.
    inbound_secrets: HashMap<Uuid, ([u8; 32], SecretKey)>,
    /// VTXO ids the LP already held when an outbound swap opened.
    baseline_vtxos: HashMap<Uuid, Vec<String>>,
}

#[derive(Clone)]
struct LpWallet {
    id: String,
    secret: SecretKey,
    claim_address: Address,
    fee_ppm: u64,
}

#[derive(Clone)]
pub struct Engine {
    inner: Arc<RwLock<Inner>>,
    tachi: TachiClient,
    network: Network,
    wallets: Vec<LpWallet>,
    /// Unit tests keep the old in-memory booths. Production talks to Tachi.
    test_mode: bool,
    /// Last Bitcoin height from Tachi. Quotes never wait on RPC for this.
    height: Arc<AtomicU32>,
}

impl Engine {
    pub fn new(tachi: TachiClient, network: Network) -> Self {
        Self::from_lp_secret(tachi, network, generate_keypair().secret)
    }

    pub fn from_lp_secret(tachi: TachiClient, network: Network, lp_secret: SecretKey) -> Self {
        Self::live(
            tachi,
            network,
            vec![("lp-alpha".into(), lp_secret, 8_000)],
        )
    }

    /// Dual in-memory LPs (no Tachi). Used by `TEST_MODE=1` for HTTP stress.
    pub fn simulated(tachi: TachiClient, network: Network) -> Self {
        Self::from_lp_secret_mode(tachi, network, generate_keypair().secret, true)
    }

    pub fn live(
        tachi: TachiClient,
        network: Network,
        keys: Vec<(String, SecretKey, u64)>,
    ) -> Self {
        Self::from_wallets(tachi, network, keys, false)
    }

    fn from_lp_secret_mode(
        tachi: TachiClient,
        network: Network,
        lp_secret: SecretKey,
        test_mode: bool,
    ) -> Self {
        let bravo = generate_keypair().secret;
        Self::from_wallets(
            tachi,
            network,
            vec![
                ("lp-alpha".into(), lp_secret, 8_000),
                ("lp-bravo".into(), bravo, 10_000),
            ],
            test_mode,
        )
    }

    fn from_wallets(
        tachi: TachiClient,
        network: Network,
        keys: Vec<(String, SecretKey, u64)>,
        test_mode: bool,
    ) -> Self {
        let wallets: Vec<LpWallet> = keys
            .into_iter()
            .map(|(id, secret, fee_ppm)| LpWallet {
                claim_address: claim_addr(&secret, network),
                id,
                secret,
                fee_ppm,
            })
            .collect();
        let lps = if test_mode {
            vec![
                lp("lp-alpha", 50_000, 20_000_000, 8_000, None, None, "simulated"),
                lp("lp-bravo", 20_000_000, 5_000_000, 10_000, None, None, "simulated"),
            ]
        } else {
            wallets
                .iter()
                .map(|w| {
                    lp(
                        &w.id,
                        0,
                        0,
                        w.fee_ppm,
                        Some(hex::encode(xonly_from_secret(&w.secret))),
                        Some(w.claim_address.to_string()),
                        "tachi",
                    )
                })
                .collect()
        };
        Self {
            inner: Arc::new(RwLock::new(Inner {
                quotes: HashMap::new(),
                swaps: HashMap::new(),
                lps,
                inbound_secrets: HashMap::new(),
                baseline_vtxos: HashMap::new(),
            })),
            tachi,
            network,
            wallets,
            test_mode,
            height: Arc::new(AtomicU32::new(FALLBACK_HEIGHT)),
        }
    }

    fn lp_wallet(&self, id: &str) -> Result<&LpWallet, Error> {
        self.wallets
            .iter()
            .find(|w| w.id == id)
            .ok_or_else(|| Error::Invalid(format!("unknown lp {id}")))
    }

    fn default_wallet(&self) -> &LpWallet {
        &self.wallets[0]
    }

    pub fn cached_height(&self) -> u32 {
        self.height.load(Ordering::Relaxed)
    }

    pub async fn refresh_height(&self) {
        if let Ok(h) = self.tachi.block_height().await {
            self.height.store(h, Ordering::Relaxed);
        }
    }

    pub fn tachi(&self) -> &TachiClient {
        &self.tachi
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn tachi_lp_pubkey_hex(&self) -> String {
        hex::encode(xonly_from_secret(&self.default_wallet().secret))
    }

    pub fn lp_secret_hex(&self) -> String {
        hex::encode(self.default_wallet().secret.secret_bytes())
    }

    pub fn marketplace(&self) -> Vec<serde_json::Value> {
        self.wallets
            .iter()
            .map(|w| {
                serde_json::json!({
                    "id": w.id,
                    "tachi_pubkey": hex::encode(xonly_from_secret(&w.secret)),
                    "l1_address": w.claim_address.to_string(),
                    "fee_ppm": w.fee_ppm,
                })
            })
            .collect()
    }

    pub async fn tachi_wallet(&self) -> Result<serde_json::Value, Error> {
        let mut lps = Vec::new();
        for w in &self.wallets {
            let pk = hex::encode(xonly_from_secret(&w.secret));
            let vtxos = self.tachi.address_vtxos(&pk).await.unwrap_or_default();
            let unspent: u64 = vtxos
                .iter()
                .filter(|v| !v.spent && !v.locked)
                .map(|v| v.amount)
                .sum();
            lps.push(serde_json::json!({
                "id": w.id,
                "tachi_pubkey": pk,
                "l1_address": w.claim_address.to_string(),
                "unspent_sats": unspent,
                "vtxo_count": vtxos.len(),
                "vtxos": vtxos,
            }));
        }
        Ok(serde_json::json!({
            "tachi_lp_pubkey": self.tachi_lp_pubkey_hex(),
            "lps": lps,
            "unspent_sats": lps.iter().map(|v| v["unspent_sats"].as_u64().unwrap_or(0)).sum::<u64>(),
            "vtxo_count": lps.iter().map(|v| v["vtxo_count"].as_u64().unwrap_or(0)).sum::<u64>(),
        }))
    }

    pub async fn inventory(&self) -> Vec<LiquidityProvider> {
        if !self.test_mode {
            let _ = self.refresh_live_inventory().await;
        }
        self.inner.read().await.lps.clone()
    }

    async fn live_vtxo_sats_for(&self, secret: &SecretKey) -> u64 {
        let pk = hex::encode(xonly_from_secret(secret));
        let vtxos = self.tachi.address_vtxos(&pk).await.unwrap_or_default();
        vtxos
            .iter()
            .filter(|v| !v.spent && !v.locked)
            .map(|v| v.amount)
            .sum()
    }

    async fn live_l1_sats_for(&self, addr: &Address) -> u64 {
        self.tachi
            .scan_address(&addr.to_string())
            .await
            .unwrap_or_default()
            .iter()
            .map(|u| u.value_sats)
            .sum()
    }

    pub async fn refresh_live_inventory(&self) -> Result<(), Error> {
        if self.test_mode {
            return Ok(());
        }
        let mut books = Vec::new();
        for w in &self.wallets {
            books.push((
                w.id.clone(),
                self.live_vtxo_sats_for(&w.secret).await,
                self.live_l1_sats_for(&w.claim_address).await,
                hex::encode(xonly_from_secret(&w.secret)),
                w.claim_address.to_string(),
            ));
        }
        let mut inner = self.inner.write().await;
        for (id, vtxo_sats, l1_sats, pk, l1_addr) in books {
            if let Some(lp) = inner.lps.iter_mut().find(|lp| lp.id == id) {
                lp.vtxo_sats = vtxo_sats;
                lp.l1_sats = l1_sats;
                lp.max_swap_sats = vtxo_sats.max(l1_sats).max(2_000_000);
                lp.tachi_pubkey = Some(pk);
                lp.l1_address = Some(l1_addr);
                lp.source = Some("tachi".into());
            }
        }
        Ok(())
    }

    pub async fn list_swaps(&self) -> Vec<Swap> {
        let mut v: Vec<_> = self.inner.read().await.swaps.values().cloned().collect();
        v.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        v
    }

    pub async fn get_swap(&self, id: Uuid) -> Result<Swap, Error> {
        self.inner
            .read()
            .await
            .swaps
            .get(&id)
            .cloned()
            .ok_or(Error::SwapNotFound)
    }

    pub async fn create_quote(&self, req: CreateQuoteRequest) -> Result<Quote, Error> {
        if req.amount_sats < MIN_SWAP_SATS {
            return Err(Error::AmountTooSmall(MIN_SWAP_SATS));
        }

        // Never wait on Tachi for a quote. Height comes from the last ticker
        // refresh (or FALLBACK_HEIGHT); inbound HTLC timeout is still ~144 blocks.
        let timeout_height = self.cached_height().saturating_add(HTLC_TIMEOUT_BLOCKS);

        if !self.test_mode {
            match req.side {
                Side::In => {
                    let dest = req.user_tachi_address.as_deref().ok_or_else(|| {
                        Error::Invalid(
                            "user_tachi_address must be a Tachi P2TR or 64-char x-only key".into(),
                        )
                    })?;
                    if !looks_like_tachi_owner(dest, self.network) {
                        return Err(Error::Invalid(
                            "user_tachi_address must be a Tachi P2TR or 64-char x-only key".into(),
                        ));
                    }
                }
                Side::Out => {
                    let dest = req.user_l1_address.as_deref().ok_or_else(|| {
                        Error::Invalid("user_l1_address must be a bitcoin address".into())
                    })?;
                    let _: Address<bitcoin::address::NetworkUnchecked> = dest
                        .parse()
                        .map_err(|_| Error::Invalid("user_l1_address is not a bitcoin address".into()))?;
                }
            }
        }

        let mut inner = self.inner.write().await;
        release_expired_quotes(&mut inner);
        let lp = select_lp(&inner.lps, req.side, req.amount_sats)
            .cloned()
            .ok_or(Error::NoLiquidity {
                side: req.side,
                amount_sats: req.amount_sats,
            })?;

        let fee = fee_sats(req.amount_sats, lp.fee_ppm, MIN_FEE_SATS);
        let receive = req.amount_sats.saturating_sub(fee);
        if receive == 0 {
            return Err(Error::Invalid("fee consumes the whole amount".into()));
        }

        let quote_id = Uuid::now_v7();
        let pay = match req.side {
            Side::In => {
                let user_pk = req.user_refund_pubkey_hex.as_deref().ok_or_else(|| {
                    Error::Invalid("user_refund_pubkey_hex is required for in".into())
                })?;
                let user_pk = pubkey_from_hex(user_pk)?;
                let w = self.lp_wallet(&lp.id)?;
                let lp_pk =
                    bitcoin::PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
                        &bitcoin::secp256k1::Secp256k1::new(),
                        &w.secret,
                    ));
                let preimage = random_preimage();
                let hash = payment_hash(&preimage);
                let timeout = LockTime::from_height(timeout_height)
                    .map_err(|e| Error::Bitcoin(e.to_string()))?;
                let script = redeem_script(&hash, &lp_pk, &user_pk, timeout);
                let address = p2wsh_address(&script, self.network);
                inner
                    .inbound_secrets
                    .insert(quote_id, (preimage, w.secret));
                PayInstructions::L1Htlc {
                    address: address.to_string(),
                    payment_hash_hex: hash.to_string(),
                    timeout_height,
                    redeem_script_hex: hex::encode(script.as_bytes()),
                }
            }
            Side::Out => {
                let w = self.lp_wallet(&lp.id)?;
                PayInstructions::TachiVtxo {
                    pay_to: hex::encode(xonly_from_secret(&w.secret)),
                    memo: format!("tachi-flow out {} {}", lp.id, quote_id),
                }
            }
        };

        let blocks = HTLC_TIMEOUT_BLOCKS;
        let hint = match req.side {
            Side::In => Some(format!(
                "Send bitcoin to the locked address. The desk pays you Tachi coins after it sees the payment. If it never pays, you can take the bitcoin back after {blocks} blocks (about a day on a real chain)."
            )),
            Side::Out => Some(format!(
                "Send Tachi coins to the desk key shown in pay_to. It then pays your bitcoin address. Quote expires in 10 minutes."
            )),
        };

        let quote = Quote {
            id: quote_id,
            side: req.side,
            amount_sats: req.amount_sats,
            fee_sats: fee,
            receive_sats: receive,
            lp_id: lp.id,
            eta_seconds: if req.side == Side::In { 120 } else { 30 },
            expires_at: Utc::now() + Duration::seconds(QUOTE_TTL_SECS),
            user_tachi_address: req.user_tachi_address,
            user_l1_address: req.user_l1_address,
            pay,
            hint,
        };

        debit_lp(&mut inner.lps, &quote.lp_id, quote.side, quote.receive_sats)?;
        inner.quotes.insert(quote.id, quote.clone());
        Ok(quote)
    }

    pub async fn open_swap(&self, quote_id: Uuid) -> Result<Swap, Error> {
        let mut inner = self.inner.write().await;
        let quote = inner.quotes.remove(&quote_id).ok_or(Error::QuoteNotFound)?;
        if quote.expires_at < Utc::now() {
            inner.inbound_secrets.remove(&quote_id);
            credit_lp(&mut inner.lps, &quote.lp_id, quote.side, quote.receive_sats);
            return Err(Error::QuoteExpired);
        }

        let now = Utc::now();
        let swap = Swap {
            id: Uuid::now_v7(),
            quote_id: quote.id,
            side: quote.side,
            status: SwapStatus::Quoted,
            lp_id: quote.lp_id.clone(),
            amount_sats: quote.amount_sats,
            fee_sats: quote.fee_sats,
            receive_sats: quote.receive_sats,
            pay: quote.pay.clone(),
            user_tachi_address: quote.user_tachi_address.clone(),
            user_l1_address: quote.user_l1_address.clone(),
            l1_lock_txid: None,
            vtxo_payment_id: None,
            tachi_tx_hash: None,
            claim_tx_hex: None,
            created_at: now,
            updated_at: now,
        };

        if let Some(secret) = inner.inbound_secrets.remove(&quote.id) {
            inner.inbound_secrets.insert(swap.id, secret);
        }
        let swap_id = swap.id;
        inner.swaps.insert(swap.id, swap.clone());
        drop(inner);
        if !self.test_mode && swap.side == Side::Out {
            let pk = hex::encode(xonly_from_secret(&self.lp_wallet(&swap.lp_id)?.secret));
            if let Ok(vtxos) = self.tachi.address_vtxos(&pk).await {
                let ids: Vec<String> = vtxos.into_iter().map(|v| v.id).collect();
                self.inner.write().await.baseline_vtxos.insert(swap_id, ids);
            }
        }
        Ok(swap)
    }

    /// Confirm the inbound HTLC on Bitcoin (via Tachi's bitcoind) and pay VTXOs.
    pub async fn observe_lock(&self, id: Uuid, lock: ObserveLockRequest) -> Result<Swap, Error> {
        let swap = {
            let inner = self.inner.read().await;
            inner.swaps.get(&id).cloned().ok_or(Error::SwapNotFound)?
        };
        if swap.side != Side::In {
            return Err(Error::WrongSide(swap.side));
        }
        if swap.status != SwapStatus::Quoted {
            return Err(Error::BadTransition {
                from: swap.status,
                to: SwapStatus::InboundLocked,
            });
        }

        let lock = if self.test_mode {
            lock
        } else {
            self.scan_htlc(&swap).await?.ok_or_else(|| {
                Error::Invalid("HTLC not funded yet — pay the lock address, then POST /v1/sync".into())
            })?
        };
        if lock.value_sats < swap.amount_sats {
            return Err(Error::Invalid("underpaid HTLC".into()));
        }

        let payout = if let Some(dest) = swap
            .user_tachi_address
            .as_deref()
            .filter(|s| looks_like_tachi_owner(s, self.network))
        {
            Some(self.send_vtxo_from(&swap.lp_id, dest, swap.receive_sats).await?)
        } else {
            None
        };
        if payout.is_none() && !self.test_mode {
            return Err(Error::Invalid(
                "user_tachi_address is required so the LP can pay VTXOs on Tachi".into(),
            ));
        }
        let claim_to = self.lp_wallet(&swap.lp_id)?.claim_address.clone();

        let mut inner = self.inner.write().await;
        let mut swap = inner.swaps.get(&id).cloned().ok_or(Error::SwapNotFound)?;
        if swap.status != SwapStatus::Quoted {
            return Err(Error::BadTransition {
                from: swap.status,
                to: SwapStatus::InboundLocked,
            });
        }

        swap.status = SwapStatus::LpSettled;
        swap.l1_lock_txid = Some(lock.txid.clone());
        if let Some(payout) = payout {
            swap.vtxo_payment_id = Some(payout.output_vtxo_id);
            swap.tachi_tx_hash = Some(payout.tendermint_hash);
        } else {
            swap.vtxo_payment_id = Some(format!("sim-vtxo-{}", swap.id));
        }
        swap.updated_at = Utc::now();

        match &swap.pay {
            PayInstructions::L1Htlc {
                redeem_script_hex, ..
            } if let (Ok(txid), Some((preimage, secret))) = (
                parse_txid(&lock.txid),
                inner.inbound_secrets.get(&id).cloned(),
            ) =>
            {
                if let Ok(bytes) = hex::decode(redeem_script_hex) {
                    let redeem = bitcoin::ScriptBuf::from_bytes(bytes);
                    let funding = OutPoint {
                        txid,
                        vout: lock.vout,
                    };
                    if let Ok(hex) = claim_tx_hex(
                        funding,
                        lock.value_sats,
                        CLAIM_FEE_SATS,
                        &redeem,
                        &preimage,
                        &secret,
                        &claim_to,
                    ) {
                        swap.claim_tx_hex = Some(hex);
                    }
                }
            }
            _ => (),
        }

        inner.swaps.insert(id, swap.clone());
        Ok(swap)
    }

    pub async fn observe_vtxo(&self, id: Uuid, paid: ObserveVtxoRequest) -> Result<Swap, Error> {
        let mut inner = self.inner.write().await;
        let mut swap = inner.swaps.get(&id).cloned().ok_or(Error::SwapNotFound)?;
        if swap.side != Side::Out {
            return Err(Error::WrongSide(swap.side));
        }
        if swap.status != SwapStatus::Quoted {
            return Err(Error::BadTransition {
                from: swap.status,
                to: SwapStatus::OutboundPaid,
            });
        }
        if !self.test_mode && !looks_like_vtxo_id(&paid.vtxo_id) {
            return Err(Error::Invalid(
                "pass the 64-char Tachi vtxo id the user paid to the LP".into(),
            ));
        }

        if looks_like_vtxo_id(&paid.vtxo_id) {
            drop(inner);
            let vtxo = self.tachi.get_vtxo(&paid.vtxo_id).await?;
            if vtxo.spent {
                return Err(Error::Invalid(format!("vtxo {} is already spent", vtxo.id)));
            }
            if vtxo.locked {
                return Err(Error::Invalid(format!("vtxo {} is locked", vtxo.id)));
            }
            if vtxo.amount < swap.amount_sats {
                return Err(Error::Invalid(format!(
                    "vtxo {} underpays: {} < {}",
                    vtxo.id, vtxo.amount, swap.amount_sats
                )));
            }
            let lp_owner = hex::encode(xonly_from_secret(&self.lp_wallet(&swap.lp_id)?.secret));
            if !vtxo.owner.eq_ignore_ascii_case(&lp_owner) {
                return Err(Error::Invalid(format!(
                    "vtxo {} owner {} is not LP {}",
                    vtxo.id, vtxo.owner, lp_owner
                )));
            }
            inner = self.inner.write().await;
            swap = inner.swaps.get(&id).cloned().ok_or(Error::SwapNotFound)?;
            if swap.status != SwapStatus::Quoted {
                return Err(Error::BadTransition {
                    from: swap.status,
                    to: SwapStatus::OutboundPaid,
                });
            }
        }

        swap.status = SwapStatus::LpSettled;
        swap.vtxo_payment_id = Some(paid.vtxo_id);
        swap.updated_at = Utc::now();
        let l1_dest = swap.user_l1_address.clone();
        inner.swaps.insert(id, swap.clone());
        drop(inner);

        if !self.test_mode {
            let dest = l1_dest.ok_or_else(|| {
                Error::Invalid("user_l1_address is required for a real L1 payout".into())
            })?;
            let txid = self.pay_l1(&swap.lp_id, &dest, swap.receive_sats).await?;
            let mut inner = self.inner.write().await;
            if let Some(s) = inner.swaps.get_mut(&id) {
                s.l1_lock_txid = Some(txid);
                s.updated_at = Utc::now();
                swap = s.clone();
            }
        } else {
            let mut inner = self.inner.write().await;
            if let Some(s) = inner.swaps.get_mut(&id) {
                s.l1_lock_txid = Some(format!("sim-l1-payout-{}", id));
                swap = s.clone();
            }
        }
        Ok(swap)
    }

    pub async fn claim(&self, id: Uuid) -> Result<Swap, Error> {
        let mut inner = self.inner.write().await;
        let mut swap = inner.swaps.get(&id).cloned().ok_or(Error::SwapNotFound)?;
        if swap.side != Side::In {
            return Err(Error::WrongSide(swap.side));
        }
        if swap.status != SwapStatus::LpSettled {
            return Err(Error::BadTransition {
                from: swap.status,
                to: SwapStatus::Claimed,
            });
        }
        if self.test_mode {
            credit_lp_l1(&mut inner.lps, &swap.lp_id, swap.amount_sats);
        }
        let claim_hex = swap.claim_tx_hex.clone();
        swap.status = SwapStatus::Claimed;
        swap.updated_at = Utc::now();
        inner.swaps.insert(id, swap.clone());
        drop(inner);
        if !self.test_mode {
            if let Some(hex) = claim_hex {
                match self.tachi.send_raw_tx(&hex).await {
                    Ok(txid) => {
                        tracing::info!(%txid, "broadcast HTLC claim");
                    }
                    Err(err) => {
                        tracing::warn!(%err, "claim broadcast failed; hex still on swap");
                    }
                }
            }
        }
        Ok(swap)
    }

    pub async fn refund(&self, id: Uuid) -> Result<Swap, Error> {
        let mut inner = self.inner.write().await;
        let mut swap = inner.swaps.get(&id).cloned().ok_or(Error::SwapNotFound)?;
        if swap.status != SwapStatus::Quoted {
            return Err(Error::BadTransition {
                from: swap.status,
                to: SwapStatus::Refunded,
            });
        }
        swap.status = SwapStatus::Refunded;
        swap.updated_at = Utc::now();
        inner.inbound_secrets.remove(&id);
        credit_lp(&mut inner.lps, &swap.lp_id, swap.side, swap.receive_sats);
        inner.swaps.insert(id, swap.clone());
        Ok(swap)
    }

    pub async fn mark_lp_default(&self, id: Uuid) -> Result<Swap, Error> {
        let mut inner = self.inner.write().await;
        let mut swap = inner.swaps.get(&id).cloned().ok_or(Error::SwapNotFound)?;
        if swap.status != SwapStatus::Quoted && swap.status != SwapStatus::OutboundPaid {
            return Err(Error::BadTransition {
                from: swap.status,
                to: SwapStatus::Failed,
            });
        }
        if swap.status == SwapStatus::Quoted {
            credit_lp(&mut inner.lps, &swap.lp_id, swap.side, swap.receive_sats);
        }
        if let Some(lp) = inner.lps.iter_mut().find(|lp| lp.id == swap.lp_id) {
            lp.defaulted = true;
        }
        swap.status = SwapStatus::Failed;
        swap.updated_at = Utc::now();
        inner.swaps.insert(id, swap.clone());
        Ok(swap)
    }

    /// Spend LP VTXOs on Tachi to `dest` (P2TR address or x-only pubkey hex).
    pub async fn send_vtxo(
        &self,
        dest: &str,
        amount_sats: u64,
    ) -> Result<crate::tachi_tx::SignedTransfer, Error> {
        self.send_vtxo_from(&self.default_wallet().id.clone(), dest, amount_sats)
            .await
    }

    pub async fn send_vtxo_from(
        &self,
        lp_id: &str,
        dest: &str,
        amount_sats: u64,
    ) -> Result<crate::tachi_tx::SignedTransfer, Error> {
        let owner = parse_tachi_owner(dest, self.network)?;
        let w = self.lp_wallet(lp_id)?;
        let lp_pk = xonly_from_secret(&w.secret);
        let lp_hex = hex::encode(lp_pk);
        let secret = w.secret;

        let unspent = self.tachi.address_vtxos(&lp_hex).await?;
        let fee = self.tachi.recommended_fee_sats().await?;
        let need = amount_sats.saturating_add(fee);
        let (coins, total) = select_vtxos(&unspent, need)?;
        let nonce = self.tachi.next_nonce(&lp_hex).await?;

        let inputs: Result<Vec<_>, _> = coins
            .iter()
            .map(|v| {
                Ok(TransferInput {
                    vtxo_id: parse_vtxo_id(&v.id)?,
                    value_sats: v.amount,
                })
            })
            .collect();
        let inputs = inputs?;

        let mut outputs = vec![TransferOutput {
            owner,
            amount: amount_sats,
        }];
        let change = total.saturating_sub(need);
        if change > 0 {
            outputs.push(TransferOutput {
                owner: lp_pk,
                amount: change,
            });
        }

        let signed = sign_transfer(&secret, &inputs, &outputs, fee, nonce)?;
        let hash = self.tachi.broadcast_tx_sync(&signed.hex).await?;
        Ok(crate::tachi_tx::SignedTransfer {
            hex: signed.hex,
            tendermint_hash: hash,
            output_vtxo_id: signed.output_vtxo_id,
        })
    }

    /// Ledger DEPOSIT (type 0x04). The daemon still requires a matching L1 vault
    /// funding; this is the on-Tachi half. Used to probe funding and to register
    /// a deposit after coins land in a TAURUS vault.
    pub async fn deposit_vtxo(
        &self,
        amount_sats: u64,
        lp_id: Option<&str>,
    ) -> Result<crate::tachi_tx::SignedTransfer, Error> {
        if amount_sats < MIN_SWAP_SATS {
            return Err(Error::AmountTooSmall(MIN_SWAP_SATS));
        }
        let w = match lp_id {
            Some(id) => self.lp_wallet(id)?,
            None => self.default_wallet(),
        };
        let lp_hex = hex::encode(xonly_from_secret(&w.secret));
        let secret = w.secret;
        let nonce = self.tachi.next_nonce(&lp_hex).await?;
        let fee = self.tachi.recommended_fee_sats().await?;
        let signed = sign_deposit(&secret, amount_sats, fee, nonce)?;
        let hash = self.tachi.broadcast_tx_sync(&signed.hex).await?;
        Ok(crate::tachi_tx::SignedTransfer {
            hex: signed.hex,
            tendermint_hash: hash,
            output_vtxo_id: signed.output_vtxo_id,
        })
    }

    pub async fn sync_all(&self) -> Result<Vec<Swap>, Error> {
        let ids: Vec<Uuid> = self
            .inner
            .read()
            .await
            .swaps
            .values()
            .filter(|s| s.status == SwapStatus::Quoted)
            .map(|s| s.id)
            .collect();
        let mut updated = Vec::new();
        for id in ids {
            match self.sync_swap(id).await {
                Ok(Some(s)) => updated.push(s),
                Ok(None) => {}
                Err(err) => tracing::warn!(%id, %err, "sync swap"),
            }
        }
        Ok(updated)
    }

    pub async fn sync_swap(&self, id: Uuid) -> Result<Option<Swap>, Error> {
        let swap = self.get_swap(id).await?;
        if swap.status != SwapStatus::Quoted {
            return Ok(None);
        }
        match swap.side {
            Side::In => {
                if self.scan_htlc(&swap).await?.is_some() {
                    let dummy = ObserveLockRequest {
                        txid: String::new(),
                        vout: 0,
                        value_sats: 0,
                    };
                    Ok(Some(self.observe_lock(id, dummy).await?))
                } else {
                    Ok(None)
                }
            }
            Side::Out => {
                if let Some(vtxo_id) = self.new_inbound_vtxo(&swap).await? {
                    Ok(Some(
                        self.observe_vtxo(
                            id,
                            ObserveVtxoRequest { vtxo_id },
                        )
                        .await?,
                    ))
                } else {
                    Ok(None)
                }
            }
        }
    }

    async fn scan_htlc(&self, swap: &Swap) -> Result<Option<ObserveLockRequest>, Error> {
        let PayInstructions::L1Htlc { address, .. } = &swap.pay else {
            return Ok(None);
        };
        let utxos = self.tachi.scan_address(address).await?;
        let Some(u) = utxos
            .into_iter()
            .find(|u| u.value_sats >= swap.amount_sats)
        else {
            return Ok(None);
        };
        Ok(Some(ObserveLockRequest {
            txid: u.txid,
            vout: u.vout,
            value_sats: u.value_sats,
        }))
    }

    async fn new_inbound_vtxo(&self, swap: &Swap) -> Result<Option<String>, Error> {
        let pk = hex::encode(xonly_from_secret(&self.lp_wallet(&swap.lp_id)?.secret));
        let vtxos = self.tachi.address_vtxos(&pk).await?;
        let baseline = self
            .inner
            .read()
            .await
            .baseline_vtxos
            .get(&swap.id)
            .cloned()
            .unwrap_or_default();
        Ok(vtxos
            .into_iter()
            .filter(|v| !v.spent && !v.locked && !baseline.iter().any(|id| id == &v.id))
            .find(|v| v.amount >= swap.amount_sats)
            .map(|v| v.id))
    }

    async fn pay_l1(&self, lp_id: &str, dest: &str, amount_sats: u64) -> Result<String, Error> {
        let dest = dest
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .map_err(|_| Error::Invalid("user_l1_address is not a bitcoin address".into()))?
            .require_network(self.network)
            .map_err(|e| {
                Error::Invalid(format!(
                    "user_l1_address must be a {} address: {e}",
                    self.network
                ))
            })?;
        let w = self.lp_wallet(lp_id)?;
        let claim = w.claim_address.clone();
        let secret = w.secret;
        let utxos = self.tachi.scan_address(&claim.to_string()).await?;
        let mut picked: Vec<(OutPoint, u64)> = Vec::new();
        let mut total = 0u64;
        let need = amount_sats + CLAIM_FEE_SATS;
        let mut sorted = utxos;
        sorted.sort_by(|a, b| b.value_sats.cmp(&a.value_sats));
        for u in sorted {
            let txid = parse_txid(&u.txid)?;
            picked.push((
                OutPoint {
                    txid,
                    vout: u.vout,
                },
                u.value_sats,
            ));
            total += u.value_sats;
            if total >= need {
                break;
            }
        }
        let hex = p2wpkh_send_hex(
            &picked,
            &dest,
            amount_sats,
            CLAIM_FEE_SATS,
            &claim,
            &secret,
            self.network,
        )?;
        self.tachi.send_raw_tx(&hex).await
    }
}

fn claim_addr(secret: &SecretKey, network: Network) -> Address {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let public = bitcoin::PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
        &secp, secret,
    ));
    let compressed =
        CompressedPublicKey::try_from(public).expect("generated keys are compressed");
    Address::p2wpkh(&compressed, bitcoin::KnownHrp::from(network))
}

fn lp(
    id: &str,
    l1_sats: u64,
    vtxo_sats: u64,
    fee_ppm: u64,
    tachi_pubkey: Option<String>,
    l1_address: Option<String>,
    source: &str,
) -> LiquidityProvider {
    LiquidityProvider {
        id: id.into(),
        l1_sats,
        vtxo_sats,
        fee_ppm,
        max_swap_sats: 2_000_000,
        defaulted: false,
        tachi_pubkey,
        l1_address,
        source: Some(source.into()),
    }
}

fn select_lp(lps: &[LiquidityProvider], side: Side, amount: u64) -> Option<&LiquidityProvider> {
    lps.iter()
        .filter(|lp| !lp.defaulted && amount <= lp.max_swap_sats)
        .filter(|lp| match side {
            Side::In => lp.vtxo_sats >= amount,
            Side::Out => lp.l1_sats >= amount,
        })
        .min_by_key(|lp| {
            (
                lp.fee_ppm,
                std::cmp::Reverse(match side {
                    Side::In => lp.vtxo_sats,
                    Side::Out => lp.l1_sats,
                }),
            )
        })
}

fn debit_lp(lps: &mut [LiquidityProvider], id: &str, side: Side, amount: u64) -> Result<(), Error> {
    let lp = lps
        .iter_mut()
        .find(|lp| lp.id == id)
        .ok_or_else(|| Error::Invalid(format!("unknown lp {id}")))?;
    match side {
        Side::In => {
            if lp.vtxo_sats < amount {
                return Err(Error::NoLiquidity {
                    side,
                    amount_sats: amount,
                });
            }
            lp.vtxo_sats -= amount;
        }
        Side::Out => {
            if lp.l1_sats < amount {
                return Err(Error::NoLiquidity {
                    side,
                    amount_sats: amount,
                });
            }
            lp.l1_sats -= amount;
        }
    }
    Ok(())
}

fn credit_lp(lps: &mut [LiquidityProvider], id: &str, side: Side, amount: u64) {
    if let Some(lp) = lps.iter_mut().find(|lp| lp.id == id) {
        match side {
            Side::In => lp.vtxo_sats = lp.vtxo_sats.saturating_add(amount),
            Side::Out => lp.l1_sats = lp.l1_sats.saturating_add(amount),
        }
    }
}

fn credit_lp_l1(lps: &mut [LiquidityProvider], id: &str, amount: u64) {
    if let Some(lp) = lps.iter_mut().find(|lp| lp.id == id) {
        lp.l1_sats = lp.l1_sats.saturating_add(amount);
    }
}

fn release_expired_quotes(inner: &mut Inner) {
    let now = Utc::now();
    let expired: Vec<Uuid> = inner
        .quotes
        .iter()
        .filter(|(_, q)| q.expires_at < now)
        .map(|(id, _)| *id)
        .collect();
    for id in expired {
        if let Some(q) = inner.quotes.remove(&id) {
            inner.inbound_secrets.remove(&id);
            credit_lp(&mut inner.lps, &q.lp_id, q.side, q.receive_sats);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> Engine {
        let tachi = TachiClient::new("http://127.0.0.1:9").expect("client");
        Engine::from_lp_secret_mode(tachi, Network::Signet, generate_keypair().secret, true)
    }

    #[tokio::test]
    async fn routes_in_to_vtxo_heavy_lp() {
        let e = engine();
        let user = generate_keypair();
        let q = e
            .create_quote(CreateQuoteRequest {
                side: Side::In,
                amount_sats: 100_000,
                user_tachi_address: Some("tb1ptest".into()),
                user_l1_address: None,
                user_refund_pubkey_hex: Some(user.public.to_string()),
            })
            .await
            .expect("quote");
        assert_eq!(q.lp_id, "lp-alpha");
        assert!(matches!(q.pay, PayInstructions::L1Htlc { .. }));
    }

    #[tokio::test]
    async fn routes_out_to_l1_heavy_lp() {
        let e = engine();
        let q = e
            .create_quote(CreateQuoteRequest {
                side: Side::Out,
                amount_sats: 100_000,
                user_tachi_address: None,
                user_l1_address: Some("tb1qtest".into()),
                user_refund_pubkey_hex: None,
            })
            .await
            .expect("quote");
        assert_eq!(q.lp_id, "lp-bravo");
    }

    #[tokio::test]
    async fn inbound_lock_settles_and_refund_before_lock() {
        let e = engine();
        let user = generate_keypair();
        let q = e
            .create_quote(CreateQuoteRequest {
                side: Side::In,
                amount_sats: 100_000,
                user_tachi_address: Some("tb1ptest".into()),
                user_l1_address: None,
                user_refund_pubkey_hex: Some(user.public.to_string()),
            })
            .await
            .unwrap();
        let swap = e.open_swap(q.id).await.unwrap();
        let refunded = e.refund(swap.id).await.unwrap();
        assert_eq!(refunded.status, SwapStatus::Refunded);
    }

    #[tokio::test]
    async fn inbound_lock_settles_and_builds_claim() {
        let e = engine();
        let user = generate_keypair();
        let q = e
            .create_quote(CreateQuoteRequest {
                side: Side::In,
                amount_sats: 100_000,
                user_tachi_address: Some("tb1ptest".into()),
                user_l1_address: None,
                user_refund_pubkey_hex: Some(user.public.to_string()),
            })
            .await
            .unwrap();
        let swap = e.open_swap(q.id).await.unwrap();
        let settled = e
            .observe_lock(
                swap.id,
                ObserveLockRequest {
                    txid: "aa".repeat(32),
                    vout: 0,
                    value_sats: 100_000,
                },
            )
            .await
            .unwrap();
        assert_eq!(settled.status, SwapStatus::LpSettled);
        assert!(settled.claim_tx_hex.is_some());
        assert_eq!(
            settled.vtxo_payment_id.as_deref(),
            Some(format!("sim-vtxo-{}", swap.id).as_str())
        );

        let claimed = e.claim(swap.id).await.unwrap();
        assert_eq!(claimed.status, SwapStatus::Claimed);

        let alpha = e
            .inventory()
            .await
            .into_iter()
            .find(|lp| lp.id == "lp-alpha")
            .expect("alpha");
        assert_eq!(alpha.vtxo_sats, 20_000_000 - 99_200);
        assert_eq!(alpha.l1_sats, 50_000 + 100_000);
    }

    #[tokio::test]
    #[ignore = "hits public Tachi regtest RPC"]
    async fn live_empty_lp_wallet_is_a_tachi_error() {
        let tachi = TachiClient::new("https://rpc-regtest.tachibtc.com").expect("client");
        let e = Engine::new(tachi, Network::Regtest);
        let dest = e.tachi_lp_pubkey_hex();
        let err = e.send_vtxo(&dest, 10_000).await.expect_err("no coins");
        let msg = err.to_string();
        assert!(
            msg.contains("unspent") || msg.contains("need"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn deposit_encode_is_type_4() {
        let secret = bitcoin::secp256k1::SecretKey::from_slice(&[3u8; 32]).unwrap();
        let signed = sign_deposit(&secret, 50_000, 1, 1).unwrap();
        let raw = hex::decode(&signed.hex).unwrap();
        assert_eq!(raw[0], 1);
        assert_eq!(raw[1], 4);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_inbound_cycles_preserve_inventory() {
        let e = engine();
        let user = generate_keypair();
        let n = 200u64;
        let amount = 10_000u64;
        let fee = fee_sats(amount, 8_000, MIN_FEE_SATS);
        let receive = amount - fee;

        let mut handles = Vec::with_capacity(n as usize);
        for i in 0..n {
            let e = e.clone();
            let pk = user.public.to_string();
            handles.push(tokio::spawn(async move {
                let q = e
                    .create_quote(CreateQuoteRequest {
                        side: Side::In,
                        amount_sats: amount,
                        user_tachi_address: Some("tb1ptest".into()),
                        user_l1_address: None,
                        user_refund_pubkey_hex: Some(pk),
                    })
                    .await?;
                let swap = e.open_swap(q.id).await?;
                e.observe_lock(
                    swap.id,
                    ObserveLockRequest {
                        txid: format!("{i:064x}"),
                        vout: 0,
                        value_sats: amount,
                    },
                )
                .await?;
                e.claim(swap.id).await
            }));
        }

        let mut ok = 0u64;
        for h in handles {
            h.await.expect("join").expect("cycle");
            ok += 1;
        }

        let alpha = e
            .inventory()
            .await
            .into_iter()
            .find(|lp| lp.id == "lp-alpha")
            .expect("alpha");
        assert_eq!(ok, n);
        assert_eq!(alpha.vtxo_sats, 20_000_000 - ok * receive);
        assert_eq!(alpha.l1_sats, 50_000 + ok * amount);
        assert!(!alpha.defaulted);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_outbound_cycles_preserve_inventory() {
        let e = engine();
        // 100k is above lp-alpha's 50k L1 book, so routing cannot stampede the cheap LP.
        let n = 150u64;
        let amount = 100_000u64;
        let fee = fee_sats(amount, 10_000, MIN_FEE_SATS);
        let receive = amount - fee;

        let mut handles = Vec::with_capacity(n as usize);
        for i in 0..n {
            let e = e.clone();
            handles.push(tokio::spawn(async move {
                let q = e
                    .create_quote(CreateQuoteRequest {
                        side: Side::Out,
                        amount_sats: amount,
                        user_tachi_address: None,
                        user_l1_address: Some("tb1qtest".into()),
                        user_refund_pubkey_hex: None,
                    })
                    .await?;
                let swap = e.open_swap(q.id).await?;
                e.observe_vtxo(
                    swap.id,
                    ObserveVtxoRequest {
                        vtxo_id: format!("sim-{i}"),
                    },
                )
                .await
            }));
        }

        let mut ok = 0u64;
        for h in handles {
            h.await.expect("join").expect("cycle");
            ok += 1;
        }

        let bravo = e
            .inventory()
            .await
            .into_iter()
            .find(|lp| lp.id == "lp-bravo")
            .expect("bravo");
        assert_eq!(ok, n);
        assert_eq!(bravo.l1_sats, 20_000_000 - ok * receive);
        assert_eq!(bravo.vtxo_sats, 5_000_000);
        let alpha = e
            .inventory()
            .await
            .into_iter()
            .find(|lp| lp.id == "lp-alpha")
            .expect("alpha");
        assert_eq!(alpha.l1_sats, 50_000);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_out_quotes_spill_after_alpha_reserved() {
        let e = engine();
        let mut handles = Vec::new();
        for _ in 0..32 {
            let e = e.clone();
            handles.push(tokio::spawn(async move {
                e.create_quote(CreateQuoteRequest {
                    side: Side::Out,
                    amount_sats: 10_000,
                    user_tachi_address: None,
                    user_l1_address: Some("tb1qtest".into()),
                    user_refund_pubkey_hex: None,
                })
                .await
            }));
        }
        let mut alpha = 0;
        let mut bravo = 0;
        for h in handles {
            let q = h.await.expect("join").expect("quote");
            match q.lp_id.as_str() {
                "lp-alpha" => alpha += 1,
                "lp-bravo" => bravo += 1,
                other => panic!("unexpected lp {other}"),
            }
        }
        // alpha L1 = 50k; each 10k out reserves receive (~9800). Only a handful
        // bind the cheap LP; the rest spill to bravo.
        assert!(alpha >= 1 && alpha <= 5, "alpha got {alpha}");
        assert!(bravo >= 1, "bravo got no spillover");
        assert_eq!(alpha + bravo, 32);
        let books = e.inventory().await;
        let a = books.iter().find(|lp| lp.id == "lp-alpha").unwrap();
        let b = books.iter().find(|lp| lp.id == "lp-bravo").unwrap();
        assert!(a.l1_sats < 50_000);
        assert!(b.l1_sats < 20_000_000);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_open_swap_consumes_quote_once() {
        let e = engine();
        let user = generate_keypair();
        let q = e
            .create_quote(CreateQuoteRequest {
                side: Side::In,
                amount_sats: 10_000,
                user_tachi_address: Some("tb1ptest".into()),
                user_l1_address: None,
                user_refund_pubkey_hex: Some(user.public.to_string()),
            })
            .await
            .unwrap();

        let mut handles = Vec::new();
        for _ in 0..32 {
            let e = e.clone();
            let id = q.id;
            handles.push(tokio::spawn(async move { e.open_swap(id).await }));
        }

        let mut wins = 0;
        let mut misses = 0;
        for h in handles {
            match h.await.expect("join") {
                Ok(_) => wins += 1,
                Err(Error::QuoteNotFound) => misses += 1,
                Err(other) => panic!("unexpected {other}"),
            }
        }
        assert_eq!(wins, 1);
        assert_eq!(misses, 31);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_observe_lock_settles_once() {
        let e = engine();
        let user = generate_keypair();
        let q = e
            .create_quote(CreateQuoteRequest {
                side: Side::In,
                amount_sats: 10_000,
                user_tachi_address: Some("tb1ptest".into()),
                user_l1_address: None,
                user_refund_pubkey_hex: Some(user.public.to_string()),
            })
            .await
            .unwrap();
        let swap = e.open_swap(q.id).await.unwrap();

        let mut handles = Vec::new();
        for i in 0..32 {
            let e = e.clone();
            let id = swap.id;
            handles.push(tokio::spawn(async move {
                e.observe_lock(
                    id,
                    ObserveLockRequest {
                        txid: format!("{i:064x}"),
                        vout: 0,
                        value_sats: 10_000,
                    },
                )
                .await
            }));
        }

        let mut wins = 0;
        let mut conflicts = 0;
        for h in handles {
            match h.await.expect("join") {
                Ok(s) => {
                    assert_eq!(s.status, SwapStatus::LpSettled);
                    wins += 1;
                }
                Err(Error::BadTransition { .. }) => conflicts += 1,
                Err(other) => panic!("unexpected {other}"),
            }
        }
        assert_eq!(wins, 1);
        assert_eq!(conflicts, 31);

        let fee = fee_sats(10_000, 8_000, MIN_FEE_SATS);
        let alpha = e
            .inventory()
            .await
            .into_iter()
            .find(|lp| lp.id == "lp-alpha")
            .expect("alpha");
        assert_eq!(alpha.vtxo_sats, 20_000_000 - (10_000 - fee));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_quotes_stop_at_inventory_and_spill() {
        let e = engine();
        let user = generate_keypair();
        // lp-alpha vtxo = 20M; receive per 2M in-quote ≈ 1_984_000 → 10 quotes, then NoLiquidity
        // (bravo only has 5M vtxo so it cannot take a 2M in).
        let amount = 2_000_000u64;
        let n = 12u64;

        let mut handles = Vec::new();
        for _ in 0..n {
            let e = e.clone();
            let pk = user.public.to_string();
            handles.push(tokio::spawn(async move {
                e.create_quote(CreateQuoteRequest {
                    side: Side::In,
                    amount_sats: amount,
                    user_tachi_address: Some("tb1ptest".into()),
                    user_l1_address: None,
                    user_refund_pubkey_hex: Some(pk),
                })
                .await
            }));
        }

        let mut alpha_n = 0u64;
        let mut bravo_n = 0u64;
        let mut rejected = 0u64;
        for h in handles {
            match h.await.expect("join") {
                Ok(q) if q.lp_id == "lp-alpha" => alpha_n += 1,
                Ok(q) if q.lp_id == "lp-bravo" => bravo_n += 1,
                Ok(q) => panic!("unexpected lp {}", q.lp_id),
                Err(Error::NoLiquidity { .. }) => rejected += 1,
                Err(other) => panic!("unexpected {other}"),
            }
        }

        let a_recv = amount - fee_sats(amount, 8_000, MIN_FEE_SATS);
        let b_recv = amount - fee_sats(amount, 10_000, MIN_FEE_SATS);
        let books = e.inventory().await;
        let alpha = books.iter().find(|lp| lp.id == "lp-alpha").unwrap();
        let bravo = books.iter().find(|lp| lp.id == "lp-bravo").unwrap();
        assert_eq!(alpha_n + bravo_n + rejected, n);
        assert!(alpha_n >= 1);
        assert!(bravo_n >= 1, "leftover 2M in-quotes must spill to bravo");
        assert_eq!(alpha.vtxo_sats, 20_000_000 - alpha_n * a_recv);
        assert_eq!(bravo.vtxo_sats, 5_000_000 - bravo_n * b_recv);
        assert!(alpha.vtxo_sats < a_recv);
    }

    #[tokio::test]
    async fn inbound_then_out_spills_to_bravo_once_alpha_l1_is_reserved() {
        let e = engine();
        let user = generate_keypair();
        // 300 * 10k inbound claims: alpha L1 50k → 3_050_000, cheapest for 100k out.
        let n_in = 300u64;
        for i in 0..n_in {
            let q = e
                .create_quote(CreateQuoteRequest {
                    side: Side::In,
                    amount_sats: 10_000,
                    user_tachi_address: Some("tb1ptest".into()),
                    user_l1_address: None,
                    user_refund_pubkey_hex: Some(user.public.to_string()),
                })
                .await
                .unwrap();
            let s = e.open_swap(q.id).await.unwrap();
            e.observe_lock(
                s.id,
                ObserveLockRequest {
                    txid: format!("{i:064x}"),
                    vout: 0,
                    value_sats: 10_000,
                },
            )
            .await
            .unwrap();
            e.claim(s.id).await.unwrap();
        }
        let alpha = e
            .inventory()
            .await
            .into_iter()
            .find(|lp| lp.id == "lp-alpha")
            .unwrap();
        assert_eq!(alpha.l1_sats, 50_000 + n_in * 10_000);

        // 40 parallel 100k out quotes: reservation fills alpha then spills to bravo.
        let mut handles = Vec::new();
        for _ in 0..40 {
            let e = e.clone();
            handles.push(tokio::spawn(async move {
                e.create_quote(CreateQuoteRequest {
                    side: Side::Out,
                    amount_sats: 100_000,
                    user_tachi_address: None,
                    user_l1_address: Some("tb1qtest".into()),
                    user_refund_pubkey_hex: None,
                })
                .await
            }));
        }
        let mut alpha_n = 0;
        let mut bravo_n = 0;
        let mut no_liq = 0;
        for h in handles {
            match h.await.expect("join") {
                Ok(q) if q.lp_id == "lp-alpha" => alpha_n += 1,
                Ok(q) if q.lp_id == "lp-bravo" => bravo_n += 1,
                Ok(q) => panic!("unexpected lp {}", q.lp_id),
                Err(Error::NoLiquidity { .. }) => no_liq += 1,
                Err(other) => panic!("unexpected {other}"),
            }
        }
        assert!(bravo_n >= 1, "bravo unused; alpha={alpha_n} bravo={bravo_n} 409={no_liq}");
        assert_eq!(no_liq, 0, "spillover should absorb leftover RFQs");
    }

    #[tokio::test]
    async fn inbound_quote_does_not_call_tachi() {
        // engine() points Tachi at :9 — connection refused if we await RPC.
        let e = engine();
        let user = generate_keypair();
        let started = std::time::Instant::now();
        e.create_quote(CreateQuoteRequest {
            side: Side::In,
            amount_sats: 10_000,
            user_tachi_address: Some("tb1ptest".into()),
            user_l1_address: None,
            user_refund_pubkey_hex: Some(user.public.to_string()),
        })
        .await
        .expect("quote");
        assert!(
            started.elapsed() < std::time::Duration::from_millis(500),
            "quote blocked on Tachi RPC"
        );
    }
}
