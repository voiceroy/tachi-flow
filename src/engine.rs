use std::collections::{HashMap, HashSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, Network, OutPoint, PublicKey, ScriptBuf};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedMutexGuard, RwLock};
use uuid::Uuid;

use crate::advance::{
    ExpectedSpend, MAX_SPEND_FEE_SATS, csv_script, discount_sats, p2wsh, parse_csv_script,
    presign_spend, verify_presigned,
};
use crate::error::Error;
use crate::events::{Event, MAX_WEBHOOKS, validate_webhook_url};
use crate::htlc::{
    HTLC_SPEND_VBYTES, claim_tx_hex, generate_keypair, p2wpkh_address, p2wpkh_send_hex,
    p2wpkh_send_many_hex, p2wpkh_send_vbytes, p2wsh_address, parse_txid, payment_hash,
    pubkey_from_hex, random_preimage, redeem_script, refund_tx_hex, txid_of_hex,
};
use crate::lightning::{InvoiceState, LightningNode};
use crate::model::{
    Advance, AdvanceAcceptRequest, AdvanceQuoteRequest, AdvanceStatus, CreatePlanRequest,
    CreateQuoteRequest, ExitPlan, HtlcLock, LiquidityProvider, LnDirection, LnQuoteRequest,
    LnStatus, LnSwap, ObserveLockRequest, ObserveVtxoRequest, PayInstructions, PriceBreakdown,
    Quote, Side, Swap, SwapStatus, WebhookRequest, fee_sats,
};
use crate::tachi::TachiClient;
use crate::tachi_tx::{
    SignedTransfer, TransferInput, TransferOutput, looks_like_tachi_owner, looks_like_vtxo_id,
    output_vtxo_id, parse_tachi_owner, parse_vtxo_id, select_vtxos, sign_deposit, sign_transfer,
    xonly_from_secret,
};

const MIN_SWAP_SATS: u64 = 10_000;
const MAX_SWAP_SATS: u64 = 2_000_000;
const MIN_FEE_SATS: u64 = 200;
const DEFAULT_QUOTE_TTL_SECS: u64 = 10 * 60;
const MIN_QUOTE_TTL_SECS: u64 = 30;
const MAX_QUOTE_TTL_SECS: u64 = 60 * 60;
/// A deadline lock is funded once the tip is this close to its deadline, so
/// locks that come due together share one L1 tx.
const LOCK_LEAD_BLOCKS: u32 = 3;
/// Deadlines shown on the price curve.
pub const DEADLINE_PRESETS: [u32; 6] = [0, 6, 36, 144, 432, 1008];
pub const HTLC_TIMEOUT_BLOCKS: u32 = 144;
/// Stop settling this many blocks before an HTLC times out, so a claim has
/// time to confirm before the other side can take the refund path.
const SAFETY_MARGIN_BLOCKS: u32 = 12;
/// TAURUS unilateral-exit leaf (CSV). The swap exists so users skip this wait.
pub const VAULT_EXIT_BLOCKS: u32 = 1008;
const CLAIM_FEE_SATS: u64 = 500;
/// Test mode has no chain behind it.
const SIM_HEIGHT: u32 = 200_000;
/// Spend-lock id for the bond escrow wallet.
const ESCROW_ID: &str = "escrow";
/// Desks scoring below this (fills vs defaults, Laplace-smoothed) stop routing.
const MIN_ROUTING_SCORE_PPM: u64 = 400_000;
/// What a defaulting desk owes the user from its bond: share of the swap...
const DEFAULT_PENALTY_PPM: u64 = 10_000;
/// ...but at least this much (capped by the bond itself).
const MIN_COMPENSATION_SATS: u64 = 500;
/// How long a claim-advance or Lightning quote holds.
const SIDE_QUOTE_TTL_SECS: i64 = 10 * 60;
/// Most a desk pays in Lightning routing fees for an `out` swap.
const LN_MAX_ROUTING_FEE_SATS: u64 = 100;
/// Anti-griefing: open quotes plus unpaid swaps one client may hold...
const MAX_OPEN_PER_CLIENT: usize = 6;
/// ...and how much desk stock they may tie up between them.
const MAX_HELD_SATS_PER_CLIENT: u64 = 4_000_000;
/// A quote for more than this share of a desk's free stock only stays firm
/// for `LARGE_QUOTE_MAX_TTL_SECS`, so a big hold cannot sit for an hour.
const LARGE_QUOTE_SHARE_PPM: u64 = 250_000;
const LARGE_QUOTE_MAX_TTL_SECS: u64 = 120;
/// An opened swap nobody pays releases its stock after this long.
const UNPAID_SWAP_SECS: i64 = 60 * 60;
/// Deadline swaps are only "unpaid" this many blocks past their deadline.
const UNPAID_SWAP_BLOCKS: u32 = 6;
/// Fee-rate floor for the desk's own L1 txs (2 sat/vB).
const MIN_FEE_RATE_MSAT_VB: u64 = 2_000;
/// Confirmation target asked of `estimatesmartfee`.
const FEE_TARGET_BLOCKS: u32 = 6;
/// Bump a desk claim that is still unconfirmed this close to the timeout.
const BUMP_BEFORE_TIMEOUT_BLOCKS: u32 = 6;

/// Knobs for [`price`]. All values are parts per million.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct PricingConfig {
    /// Fee change when a swap would leave the desk entirely on one side.
    pub skew_ppm: u64,
    /// Cost of holding a price firm, per hour of quote TTL.
    pub ttl_ppm_per_hour: u64,
    /// Share of the fee waived at a full 1008-block (vault-exit) deadline.
    pub max_deadline_discount_ppm: u64,
    pub min_fee_ppm: u64,
    pub max_fee_ppm: u64,
}

impl Default for PricingConfig {
    fn default() -> Self {
        Self {
            skew_ppm: 10_000,
            ttl_ppm_per_hour: 3_000,
            max_deadline_discount_ppm: 800_000,
            min_fee_ppm: 500,
            max_fee_ppm: 50_000,
        }
    }
}

impl PricingConfig {
    /// Every desk charges exactly its base `fee_ppm`.
    pub fn flat() -> Self {
        Self {
            skew_ppm: 0,
            ttl_ppm_per_hour: 0,
            max_deadline_discount_ppm: 0,
            min_fee_ppm: 0,
            max_fee_ppm: u64::MAX / 2,
        }
    }
}

#[derive(Default)]
struct Inner {
    quotes: HashMap<Uuid, Quote>,
    swaps: HashMap<Uuid, Swap>,
    lps: Vec<LiquidityProvider>,
    /// HTLC preimages, keyed by quote id, then by swap id once opened.
    preimages: HashMap<Uuid, [u8; 32]>,
    /// VTXO ids the LP already held when an outbound swap opened.
    baseline_vtxos: HashMap<Uuid, Vec<String>>,
    /// VTXOs the desks minted or got back as change. Never a user payment.
    own_vtxos: HashSet<String>,
    /// Ephemeral faucet wallets funding inbound locks (demo helper), by swap id.
    fund_keys: HashMap<Uuid, SecretKey>,
    /// Signed VTXO payouts not yet seen on Tachi, by swap id. Retries re-send
    /// this exact tx instead of signing a second payout.
    pending_payouts: HashMap<Uuid, PendingPayout>,
    /// Signed outbound L1 locks, by swap id, re-broadcast until visible.
    pending_locks: HashMap<Uuid, String>,
    plans: HashMap<Uuid, ExitPlan>,
    /// VTXOs each desk has in escrow.
    bonds: HashMap<String, u64>,
    /// (fills, defaults) per desk.
    reputation: HashMap<String, (u64, u64)>,
    advances: HashMap<Uuid, Advance>,
    /// Signed advance payouts, by advance id, so a retry re-sends, never re-pays.
    pending_advance_txs: HashMap<Uuid, String>,
    ln_swaps: HashMap<Uuid, LnSwap>,
    webhooks: Vec<WebhookRequest>,
    /// Who asked for each open quote / unpaid swap (by id), for the
    /// per-client caps. Not persisted: holds expire within the hour anyway.
    clients: HashMap<Uuid, String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct PendingPayout {
    signed: SignedTransfer,
    nonce: u64,
}

/// Coins and nonce a desk has committed to in-flight txs that Tachi or
/// bitcoind may not show yet. Lives behind the desk's spend mutex.
#[derive(Default)]
struct LpSpend {
    next_nonce: Option<u64>,
    vtxos: HashSet<String>,
    /// L1 coins already spent by our own unconfirmed txs.
    l1: HashSet<OutPoint>,
    /// Outputs our own broadcasts paid back to this desk (change, claims,
    /// refunds) that are not confirmed yet. Spendable right away, so the
    /// desk need not wait a block between exits.
    pending: HashMap<OutPoint, u64>,
}

impl LpSpend {
    fn nonce(&self, ledger_next: u64) -> u64 {
        self.next_nonce.map_or(ledger_next, |n| n.max(ledger_next))
    }

    fn used(&mut self, built: &BuiltTransfer) {
        self.next_nonce = Some(built.nonce + 1);
        self.vtxos.extend(built.inputs.iter().cloned());
    }

    /// Tachi refused a tx outright; fall back to what the ledger says.
    fn forget_tachi(&mut self) {
        self.next_nonce = None;
        self.vtxos.clear();
    }

    /// Coins a new L1 payment may use: confirmed ones, then our own pending
    /// change, minus anything an in-flight tx already spends. Pending coins
    /// that have since confirmed are dropped from `pending` (no double count),
    /// and spent markers for coins that are gone are forgotten.
    fn spendable_l1(&mut self, confirmed: &[(OutPoint, u64)]) -> Vec<(OutPoint, u64)> {
        let seen: HashSet<OutPoint> = confirmed.iter().map(|(op, _)| *op).collect();
        self.pending.retain(|op, _| !seen.contains(op));
        let pending = &self.pending;
        self.l1.retain(|op| seen.contains(op) || pending.contains_key(op));
        let mut first: Vec<_> = confirmed
            .iter()
            .filter(|(op, _)| !self.l1.contains(op))
            .copied()
            .collect();
        first.sort_by_key(|(_, v)| std::cmp::Reverse(*v));
        let mut then: Vec<_> = self
            .pending
            .iter()
            .filter(|(op, _)| !self.l1.contains(op))
            .map(|(op, v)| (*op, *v))
            .collect();
        then.sort_by_key(|(_, v)| std::cmp::Reverse(*v));
        first.extend(then);
        first
    }
}

/// The terms a desk signs: everything that decides what the user gets and
/// pays, not presentation text. Serialised as JSON (fixed field order).
#[derive(Serialize)]
struct QuoteCommitment<'a> {
    domain: &'static str,
    id: Uuid,
    side: Side,
    amount_sats: u64,
    fee_sats: u64,
    receive_sats: u64,
    lp_id: &'a str,
    expires_at: &'a chrono::DateTime<Utc>,
    pay: &'a PayInstructions,
    user_pubkey_hex: &'a Option<String>,
    lock_by_height: Option<u32>,
}

/// SHA-256 of the quote's committed terms, the message a desk signs.
pub fn quote_commitment(q: &Quote) -> [u8; 32] {
    let body = QuoteCommitment {
        domain: "tachi-flow/quote/v1",
        id: q.id,
        side: q.side,
        amount_sats: q.amount_sats,
        fee_sats: q.fee_sats,
        receive_sats: q.receive_sats,
        lp_id: &q.lp_id,
        expires_at: &q.expires_at,
        pay: &q.pay,
        user_pubkey_hex: &q.user_pubkey_hex,
        lock_by_height: q.lock_by_height,
    };
    let json = serde_json::to_vec(&body).expect("quote commitment serialises");
    bitcoin::hashes::sha256::Hash::hash(&json).to_byte_array()
}

fn sign_quote(q: &mut Quote, desk_secret: &SecretKey) {
    let secp = Secp256k1::new();
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, desk_secret);
    let msg = bitcoin::secp256k1::Message::from_digest(quote_commitment(q));
    let sig = secp.sign_schnorr(&msg, &keypair);
    q.desk_pubkey = Some(hex::encode(keypair.x_only_public_key().0.serialize()));
    q.desk_signature = Some(hex::encode(sig.as_ref()));
}

/// Check a quote's BIP340 signature against the key it names. Callers must
/// still check that the key belongs to the desk in `lp_id`.
pub fn verify_quote_signature(q: &Quote) -> Result<(), String> {
    let pk = q.desk_pubkey.as_deref().ok_or("quote is not signed")?;
    let sig = q.desk_signature.as_deref().ok_or("quote is not signed")?;
    let pk = hex::decode(pk)
        .ok()
        .and_then(|b| bitcoin::secp256k1::XOnlyPublicKey::from_slice(&b).ok())
        .ok_or("desk_pubkey is not an x-only key")?;
    let sig = hex::decode(sig)
        .ok()
        .and_then(|b| bitcoin::secp256k1::schnorr::Signature::from_slice(&b).ok())
        .ok_or("desk_signature is not a 64-byte Schnorr signature")?;
    let msg = bitcoin::secp256k1::Message::from_digest(quote_commitment(q));
    Secp256k1::verification_only()
        .verify_schnorr(&sig, &msg, &pk)
        .map_err(|_| "signature does not match the quote's terms".to_string())
}

/// Fee for `vbytes` at `msat_vb` milli-sat/vB, rounded up.
fn fee_at(msat_vb: u64, vbytes: u64) -> u64 {
    (msat_vb * vbytes).div_ceil(1_000)
}

/// Fee for the next attempt at a stuck claim: double the last one, but never
/// more than half of what the claim is worth. `None` once that cap is hit.
fn bumped_fee(previous_fee: u64, value_sats: u64) -> Option<u64> {
    let next = previous_fee.saturating_mul(2).min(value_sats / 2);
    (next > previous_fee).then_some(next)
}

/// Outputs of `hex_tx` paying `spk`, as (outpoint, value).
fn outputs_to(hex_tx: &str, spk: &ScriptBuf) -> Vec<(OutPoint, u64)> {
    let Some(tx) = hex::decode(hex_tx)
        .ok()
        .and_then(|b| bitcoin::consensus::deserialize::<bitcoin::Transaction>(&b).ok())
    else {
        return Vec::new();
    };
    let txid = tx.compute_txid();
    tx.output
        .iter()
        .enumerate()
        .filter(|(_, o)| &o.script_pubkey == spk)
        .map(|(vout, o)| {
            (
                OutPoint {
                    txid,
                    vout: vout as u32,
                },
                o.value.to_sat(),
            )
        })
        .collect()
}

struct BuiltTransfer {
    signed: SignedTransfer,
    nonce: u64,
    inputs: Vec<String>,
    /// Outputs that land back on a desk key (change, LP-to-LP).
    own_outputs: Vec<String>,
}

/// A validated quote request, with timeouts fixed against the current tip.
struct QuoteTerms {
    ttl_secs: u64,
    deadline: u32,
    user_pk: Option<PublicKey>,
    timeout_height: u32,
    lock_by_height: Option<u32>,
}

/// One desk's share of a quote request (the whole amount, or a plan leg).
struct Leg {
    amount_sats: u64,
    fee_sats: u64,
    pricing: PriceBreakdown,
    rfq_id: Option<Uuid>,
    plan_id: Option<Uuid>,
}

impl Leg {
    /// How long this leg stays firm (`firm_ttl` may have shortened it).
    fn ttl_secs(&self) -> u64 {
        self.pricing.ttl_secs
    }
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
    /// Last Bitcoin height from Tachi; 0 until the first successful fetch.
    height: Arc<AtomicU32>,
    /// Fee rate for the desk's own L1 txs, in milli-sat/vB (refreshed with
    /// the height; never below `MIN_FEE_RATE_MSAT_VB`).
    fee_rate: Arc<AtomicU64>,
    persist: Option<PathBuf>,
    /// Serialises snapshot + write so an older snapshot never lands last.
    persist_lock: Arc<tokio::sync::Mutex<()>>,
    /// One in-flight operation per swap. Anything that moves money holds it.
    swap_locks: Arc<Mutex<HashMap<Uuid, Arc<tokio::sync::Mutex<()>>>>>,
    /// One in-flight spend per desk wallet (and the escrow).
    lp_spends: Arc<HashMap<String, Arc<tokio::sync::Mutex<LpSpend>>>>,
    pricing: PricingConfig,
    /// Holds desk bonds. Custodial: this server controls the key.
    escrow: SecretKey,
    events: tokio::sync::broadcast::Sender<Event>,
    webhook_http: reqwest::Client,
    lightning: Option<LightningNode>,
}

impl Engine {
    pub fn new(tachi: TachiClient, network: Network) -> Self {
        Self::from_lp_secret(tachi, network, generate_keypair().secret)
    }

    pub fn from_lp_secret(tachi: TachiClient, network: Network, lp_secret: SecretKey) -> Self {
        Self::live(tachi, network, vec![("lp-alpha".into(), lp_secret, 8_000)])
    }

    /// Dual in-memory LPs (no Tachi). Used by `TEST_MODE=1` for HTTP stress.
    pub fn simulated(tachi: TachiClient, network: Network) -> Self {
        Self::from_lp_secret_mode(tachi, network, generate_keypair().secret, true)
    }

    pub fn live(tachi: TachiClient, network: Network, keys: Vec<(String, SecretKey, u64)>) -> Self {
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
                claim_address: p2wpkh_address(&secret, network),
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
        let lp_spends = wallets
            .iter()
            .map(|w| w.id.clone())
            .chain([ESCROW_ID.to_string()])
            .map(|id| (id, Arc::default()))
            .collect();
        let (events, _) = tokio::sync::broadcast::channel(crate::events::CHANNEL_CAPACITY);
        Self {
            inner: Arc::new(RwLock::new(Inner {
                lps,
                ..Inner::default()
            })),
            tachi,
            network,
            wallets,
            test_mode,
            height: Arc::new(AtomicU32::new(if test_mode { SIM_HEIGHT } else { 0 })),
            fee_rate: Arc::new(AtomicU64::new(MIN_FEE_RATE_MSAT_VB)),
            persist: None,
            persist_lock: Arc::default(),
            swap_locks: Arc::default(),
            lp_spends: Arc::new(lp_spends),
            pricing: PricingConfig::default(),
            escrow: generate_keypair().secret,
            events,
            webhook_http: crate::events::webhook_client(),
            lightning: None,
        }
    }

    pub fn with_pricing(mut self, pricing: PricingConfig) -> Self {
        self.pricing = pricing;
        self
    }

    pub fn with_escrow(mut self, secret: SecretKey) -> Self {
        self.escrow = secret;
        self
    }

    pub fn with_lightning(mut self, node: Option<LightningNode>) -> Self {
        self.lightning = node;
        self
    }

    pub fn escrow_pubkey_hex(&self) -> String {
        hex::encode(xonly_from_secret(&self.escrow))
    }

    pub fn lightning_enabled(&self) -> bool {
        self.lightning.is_some()
    }

    /// Tachi keys whose credits matter to us (desks + escrow), for the push stream.
    pub fn desk_tachi_keys(&self) -> Vec<String> {
        self.wallets
            .iter()
            .map(|w| hex::encode(xonly_from_secret(&w.secret)))
            .chain([self.escrow_pubkey_hex()])
            .collect()
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    async fn publish(&self, event: Event) {
        let hooks = self.inner.read().await.webhooks.clone();
        crate::events::deliver(&self.webhook_http, &hooks, &event);
        let _ = self.events.send(event);
    }

    pub async fn add_webhook(&self, hook: WebhookRequest) -> Result<usize, Error> {
        validate_webhook_url(&hook.url)?;
        let n = {
            let mut inner = self.inner.write().await;
            if inner.webhooks.len() >= MAX_WEBHOOKS {
                return Err(Error::Invalid(format!("at most {MAX_WEBHOOKS} webhooks")));
            }
            inner.webhooks.push(hook);
            inner.webhooks.len()
        };
        self.save_state().await;
        Ok(n)
    }

    /// Secret behind a spend lock id: a desk wallet, or the escrow.
    fn spend_secret(&self, id: &str) -> Result<SecretKey, Error> {
        if id == ESCROW_ID {
            Ok(self.escrow)
        } else {
            Ok(self.lp_wallet(id)?.secret)
        }
    }

    pub fn pricing(&self) -> PricingConfig {
        self.pricing
    }

    /// Load/save quotes, swaps, and HTLC preimages across restarts. A file that
    /// exists but does not parse is an error: starting empty would drop every
    /// preimage the desk needs to claim.
    pub fn with_persist(mut self, path: impl AsRef<Path>) -> Result<Self, Error> {
        self.persist = Some(path.as_ref().to_path_buf());
        self.load_state()?;
        Ok(self)
    }

    fn load_state(&self) -> Result<(), Error> {
        let Some(path) = &self.persist else {
            return Ok(());
        };
        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(Error::Invalid(format!("read {}: {err}", path.display()))),
        };
        let corrupt = |why: String| {
            Error::Invalid(format!(
                "{} is unreadable ({why}). It holds HTLC preimages; repair it or move it aside before starting",
                path.display()
            ))
        };
        let file: PersistFile = serde_json::from_str(&raw).map_err(|e| corrupt(e.to_string()))?;
        let preimages = file
            .preimages
            .into_iter()
            .map(|row| {
                let pre: [u8; 32] = hex::decode(&row.preimage_hex)
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| corrupt(format!("bad preimage for {}", row.id)))?;
                Ok((row.id, pre))
            })
            .collect::<Result<_, Error>>()?;
        let fund_keys = file
            .fund_keys
            .into_iter()
            .map(|row| {
                let sk = hex::decode(&row.secret_hex)
                    .ok()
                    .and_then(|b| SecretKey::from_slice(&b).ok())
                    .ok_or_else(|| corrupt(format!("bad fund key for {}", row.id)))?;
                Ok((row.id, sk))
            })
            .collect::<Result<_, Error>>()?;

        let mut inner = self
            .inner
            .try_write()
            .expect("state loads before the engine is shared");
        inner.quotes = file.quotes.into_iter().map(|q| (q.id, q)).collect();
        inner.swaps = file.swaps.into_iter().map(|s| (s.id, s)).collect();
        inner.baseline_vtxos = file.baseline_vtxos;
        inner.preimages = preimages;
        inner.own_vtxos = file.own_vtxos.into_iter().collect();
        inner.fund_keys = fund_keys;
        inner.pending_payouts = file.pending_payouts;
        inner.pending_locks = file.pending_locks;
        inner.plans = file.plans.into_iter().map(|p| (p.id, p)).collect();
        inner.bonds = file.bonds;
        inner.reputation = file.reputation;
        inner.advances = file.advances.into_iter().map(|a| (a.id, a)).collect();
        inner.pending_advance_txs = file.pending_advance_txs;
        inner.ln_swaps = file.ln_swaps.into_iter().map(|l| (l.id, l)).collect();
        inner.webhooks = file.webhooks;
        apply_desk_stats(&mut inner);
        tracing::info!(
            quotes = inner.quotes.len(),
            swaps = inner.swaps.len(),
            "loaded tachi-flow state"
        );
        Ok(())
    }

    async fn save_state(&self) {
        let Some(path) = self.persist.clone() else {
            return;
        };
        let _writer = self.persist_lock.lock().await;
        let json = {
            let inner = self.inner.read().await;
            serde_json::to_vec_pretty(&PersistFile::from(&*inner))
        };
        let json = match json {
            Ok(json) => json,
            Err(err) => {
                tracing::error!(%err, "persist encode");
                return;
            }
        };
        match tokio::task::spawn_blocking(move || write_atomic(&path, &json)).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::error!(%err, "persist write"),
            Err(err) => tracing::error!(%err, "persist task"),
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

    fn is_lp_key(&self, xonly: &[u8; 32]) -> bool {
        self.wallets
            .iter()
            .any(|w| &xonly_from_secret(&w.secret) == xonly)
    }

    fn swap_mutex(&self, id: Uuid) -> Arc<tokio::sync::Mutex<()>> {
        self.swap_locks
            .lock()
            .expect("swap lock map")
            .entry(id)
            .or_default()
            .clone()
    }

    async fn lock_swap(&self, id: Uuid) -> OwnedMutexGuard<()> {
        self.swap_mutex(id).lock_owned().await
    }

    async fn lp_spend(&self, lp_id: &str) -> Result<OwnedMutexGuard<LpSpend>, Error> {
        let spend = self
            .lp_spends
            .get(lp_id)
            .ok_or_else(|| Error::Invalid(format!("unknown lp {lp_id}")))?
            .clone();
        Ok(spend.lock_owned().await)
    }

    pub fn cached_height(&self) -> u32 {
        self.height.load(Ordering::Relaxed)
    }

    pub async fn refresh_height(&self) {
        if self.test_mode {
            return;
        }
        match self.tachi.block_height().await {
            Ok(h) => self.height.store(h, Ordering::Relaxed),
            Err(err) => tracing::warn!(%err, "block height"),
        }
        match self.tachi.estimate_fee_rate(FEE_TARGET_BLOCKS).await {
            Ok(Some(rate)) => {
                let msat = ((rate * 1_000.0) as u64).max(MIN_FEE_RATE_MSAT_VB);
                self.fee_rate.store(msat, Ordering::Relaxed);
            }
            Ok(None) => {}
            Err(err) => tracing::debug!(%err, "fee estimate"),
        }
    }

    /// Current fee rate, milli-sat/vB.
    pub fn fee_rate_msat_vb(&self) -> u64 {
        self.fee_rate.load(Ordering::Relaxed)
    }

    /// Fee for a tx of `vbytes` at the current rate.
    fn fee_for(&self, vbytes: u64) -> u64 {
        fee_at(self.fee_rate_msat_vb(), vbytes)
    }

    /// Height used for HTLC timeouts. Never a made-up number on a live chain.
    async fn known_height(&self) -> Result<u32, Error> {
        if self.cached_height() == 0 {
            self.refresh_height().await;
        }
        match self.cached_height() {
            0 => Err(Error::Tachi(
                "Bitcoin block height unknown (Tachi RPC unreachable)".into(),
            )),
            h => Ok(h),
        }
    }

    /// Height right before a settle/refund decision.
    async fn fresh_height(&self) -> Result<u32, Error> {
        self.refresh_height().await;
        self.known_height().await
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

    pub fn marketplace(&self) -> Vec<serde_json::Value> {
        self.wallets
            .iter()
            .map(|w| {
                serde_json::json!({
                    "id": w.id,
                    "tachi_pubkey": hex::encode(xonly_from_secret(&w.secret)),
                    "l1_address": w.claim_address.to_string(),
                    "fee_ppm": w.fee_ppm,
                    "vault_exit_blocks": VAULT_EXIT_BLOCKS,
                    "swap_timeout_blocks": HTLC_TIMEOUT_BLOCKS,
                    "backing": "Desk reserve: Tachi VTXOs + L1 at the claim address. A TAURUS vault exit is ~1008 blocks; this desk swaps against that wait.",
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
            self.refresh_live_inventory().await;
        }
        let mut inner = self.inner.write().await;
        apply_desk_stats(&mut inner);
        inner.lps.clone()
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

    /// What the desk can spend on L1 right now: confirmed coins it has not
    /// already spent in the mempool, plus its own unconfirmed change.
    async fn live_l1_sats_for(&self, lp_id: &str, addr: &Address) -> u64 {
        let confirmed: Vec<(OutPoint, u64)> = self
            .tachi
            .scan_address(&addr.to_string())
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|u| Some((OutPoint { txid: parse_txid(&u.txid).ok()?, vout: u.vout }, u.value_sats)))
            .collect();
        match self.lp_spend(lp_id).await {
            Ok(mut spend) => spend.spendable_l1(&confirmed).iter().map(|(_, v)| v).sum(),
            Err(_) => confirmed.iter().map(|(_, v)| v).sum(),
        }
    }

    /// Books = what the desk holds on chain minus what open quotes and swaps
    /// have already promised. Recomputed from scratch, so reservations survive.
    pub async fn refresh_live_inventory(&self) {
        if self.test_mode {
            return;
        }
        let mut books = Vec::new();
        for w in &self.wallets {
            books.push((
                w.id.clone(),
                self.live_vtxo_sats_for(&w.secret).await,
                self.live_l1_sats_for(&w.id, &w.claim_address).await,
            ));
        }
        let mut inner = self.inner.write().await;
        for (id, vtxo_sats, l1_sats) in books {
            let (vtxo_held, l1_held) = reserved(&inner, &id);
            if let Some(lp) = inner.lps.iter_mut().find(|lp| lp.id == id) {
                lp.vtxo_sats = vtxo_sats.saturating_sub(vtxo_held);
                lp.l1_sats = l1_sats.saturating_sub(l1_held);
                lp.max_swap_sats = MAX_SWAP_SATS;
                lp.source = Some("tachi".into());
                lp.vault_exit_blocks = Some(VAULT_EXIT_BLOCKS);
                lp.backing = Some(
                    "Desk reserve (VTXOs + L1). Not your vault — you skip the 1008-block exit."
                        .into(),
                );
            }
        }
        apply_desk_stats(&mut inner);
    }

    /// Market numbers for the stats page: volume, fees, batching savings,
    /// per-desk track record, and time saved against a vault exit.
    pub async fn stats(&self) -> serde_json::Value {
        let inner = self.inner.read().await;
        let swaps: Vec<&Swap> = inner.swaps.values().collect();
        let done: Vec<&Swap> = swaps
            .iter()
            .copied()
            .filter(|s| s.status == SwapStatus::Claimed)
            .collect();

        let mut by_status: std::collections::BTreeMap<String, u64> = Default::default();
        for s in &swaps {
            let key = serde_json::to_value(s.status)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default();
            *by_status.entry(key).or_default() += 1;
        }
        let volume = |side: Side| -> u64 {
            done.iter().filter(|s| s.side == side).map(|s| s.amount_sats).sum()
        };

        // Batching: outbound locks funded vs funding txs actually used.
        let locks: Vec<&Swap> = swaps
            .iter()
            .copied()
            .filter(|s| s.side == Side::Out && s.l1_lock_txid.is_some())
            .collect();
        let lock_txs: HashSet<&str> = locks.iter().filter_map(|s| s.l1_lock_txid.as_deref()).collect();

        let settle_secs: Vec<i64> = done
            .iter()
            .map(|s| (s.updated_at - s.created_at).num_seconds().max(0))
            .collect();
        let avg_settle = if settle_secs.is_empty() {
            None
        } else {
            Some(settle_secs.iter().sum::<i64>() / settle_secs.len() as i64)
        };
        // A TAURUS exit is VAULT_EXIT_BLOCKS of ~10 minutes each.
        let vault_exit_secs = i64::from(VAULT_EXIT_BLOCKS) * 600;

        let desks: Vec<serde_json::Value> = inner
            .lps
            .iter()
            .map(|lp| {
                let mine: Vec<&Swap> = done.iter().copied().filter(|s| s.lp_id == lp.id).collect();
                serde_json::json!({
                    "id": lp.id,
                    "fee_ppm": lp.fee_ppm,
                    "swaps_settled": mine.len(),
                    "volume_sats": mine.iter().map(|s| s.amount_sats).sum::<u64>(),
                    "fees_earned_sats": mine.iter().map(|s| s.fee_sats).sum::<u64>(),
                    "fills": lp.fills,
                    "defaults": lp.defaults,
                    "score_ppm": lp.score_ppm,
                    "bond_sats": lp.bond_sats,
                    "routing": routable(lp),
                })
            })
            .collect();

        serde_json::json!({
            "swaps": {
                "total": swaps.len(),
                "by_status": by_status,
                "settled": done.len(),
                "volume_in_sats": volume(Side::In),
                "volume_out_sats": volume(Side::Out),
                "fees_earned_sats": done.iter().map(|s| s.fee_sats).sum::<u64>(),
                "defaults_compensated_sats": swaps.iter().filter_map(|s| s.compensation_sats).sum::<u64>(),
            },
            "batching": {
                "outbound_locks": locks.len(),
                "funding_txs": lock_txs.len(),
                "txs_saved": locks.len().saturating_sub(lock_txs.len()),
            },
            "time": {
                "avg_settle_secs": avg_settle,
                "vault_exit_secs": vault_exit_secs,
                "vault_exit_blocks": VAULT_EXIT_BLOCKS,
            },
            "desks": desks,
            "advances": {
                "total": inner.advances.len(),
                "advanced_sats": inner.advances.values().filter(|a| a.advance_txid.is_some()).map(|a| a.advance_sats).sum::<u64>(),
                "collected": inner.advances.values().filter(|a| a.status == AdvanceStatus::Collected).count(),
                "lost": inner.advances.values().filter(|a| a.status == AdvanceStatus::Lost).count(),
            },
            "lightning_swaps": inner.ln_swaps.len(),
            "exit_plans": inner.plans.len(),
            "fee_rate_sat_vb": self.fee_rate_msat_vb() as f64 / 1_000.0,
        })
    }

    pub async fn list_swaps(&self) -> Vec<Swap> {
        let mut v: Vec<_> = self.inner.read().await.swaps.values().cloned().collect();
        v.sort_by_key(|s| std::cmp::Reverse(s.updated_at));
        v
    }

    /// Is this a genuine quote from one of our desks?
    pub fn verify_quote(&self, q: &Quote) -> serde_json::Value {
        let signature = verify_quote_signature(q);
        let desk_key = self
            .lp_wallet(&q.lp_id)
            .ok()
            .map(|w| hex::encode(xonly_from_secret(&w.secret)));
        let key_matches = desk_key.is_some() && desk_key.as_deref() == q.desk_pubkey.as_deref();
        serde_json::json!({
            "valid": signature.is_ok() && key_matches,
            "signature_ok": signature.is_ok(),
            "signed_by_desk": key_matches,
            "desk": q.lp_id,
            "reason": signature.err().or_else(|| (!key_matches).then(|| format!("key is not desk {}'s", q.lp_id))),
        })
    }

    /// A user brings a signed quote: did the desk honour it? Checks the
    /// signature, then compares the swap opened from it with the signed terms
    /// and reports any recorded default.
    pub async fn dispute(&self, q: &Quote) -> serde_json::Value {
        let mut verdict = self.verify_quote(q);
        let swap = self
            .inner
            .read()
            .await
            .swaps
            .values()
            .find(|s| s.quote_id == q.id)
            .cloned();
        let Some(s) = swap else {
            verdict["swap"] = serde_json::Value::Null;
            verdict["finding"] = "no swap was opened from this quote".into();
            return verdict;
        };
        let pay_same = serde_json::to_value(&s.pay).ok() == serde_json::to_value(&q.pay).ok();
        let honoured = s.amount_sats == q.amount_sats
            && s.fee_sats == q.fee_sats
            && s.receive_sats == q.receive_sats
            && s.lp_id == q.lp_id
            && pay_same;
        verdict["swap"] = serde_json::json!({
            "id": s.id,
            "status": s.status,
            "desk_defaulted": s.desk_defaulted,
            "compensation_sats": s.compensation_sats,
            "compensation_vtxo_id": s.compensation_vtxo_id,
        });
        verdict["terms_honoured"] = honoured.into();
        verdict["finding"] = match (verdict["valid"].as_bool() == Some(true), honoured, s.desk_defaulted) {
            (false, _, _) => "the quote is not a valid desk signature; nothing is proven".into(),
            (true, false, _) => "the swap's terms differ from what the desk signed".into(),
            (true, true, true) => "terms were honoured but the desk defaulted on settlement".into(),
            (true, true, false) => "the desk honoured the signed terms".into(),
        };
        verdict
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

    /// Apply `f` to a stored swap, stamp it, persist, and return the new copy.
    async fn update_swap(&self, id: Uuid, f: impl FnOnce(&mut Swap)) -> Result<Swap, Error> {
        let out = {
            let mut inner = self.inner.write().await;
            let s = inner.swaps.get_mut(&id).ok_or(Error::SwapNotFound)?;
            f(s);
            s.updated_at = Utc::now();
            s.clone()
        };
        self.save_state().await;
        self.publish(Event::Swap(Box::new(out.clone()))).await;
        Ok(out)
    }

    fn lp_pubkey(&self, lp_id: &str) -> Result<PublicKey, Error> {
        let w = self.lp_wallet(lp_id)?;
        Ok(PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
            &Secp256k1::new(),
            &w.secret,
        )))
    }

    fn build_htlc(
        &self,
        claimer: &PublicKey,
        refunder: &PublicKey,
        timeout_height: u32,
    ) -> Result<([u8; 32], HtlcLock), Error> {
        let preimage = random_preimage();
        let hash = payment_hash(&preimage);
        let timeout =
            LockTime::from_height(timeout_height).map_err(|e| Error::Bitcoin(e.to_string()))?;
        let script = redeem_script(&hash, claimer, refunder, timeout);
        Ok((
            preimage,
            HtlcLock {
                address: p2wsh_address(&script, self.network).to_string(),
                payment_hash_hex: hash.to_string(),
                timeout_height,
                redeem_script_hex: hex::encode(script.as_bytes()),
            },
        ))
    }

    /// Best single quote across desks. Reserves only that desk's stock.
    pub async fn create_quote(&self, req: CreateQuoteRequest) -> Result<Quote, Error> {
        let mut quotes = self.quote_desks(req, false, None).await?;
        Ok(quotes.remove(0))
    }

    /// [`Self::create_quote`] on behalf of an outside client, within its caps.
    pub async fn create_quote_for(&self, client: &str, req: CreateQuoteRequest) -> Result<Quote, Error> {
        let mut quotes = self.quote_desks(req, false, Some(client)).await?;
        Ok(quotes.remove(0))
    }

    /// RFQ: firm quotes from every desk that can fill, cheapest first. Each
    /// reserves stock until it expires; accepting one releases the others.
    pub async fn request_quotes(&self, req: CreateQuoteRequest) -> Result<Vec<Quote>, Error> {
        self.quote_desks(req, true, None).await
    }

    /// [`Self::request_quotes`] on behalf of an outside client, within its caps.
    pub async fn request_quotes_for(
        &self,
        client: &str,
        req: CreateQuoteRequest,
    ) -> Result<Vec<Quote>, Error> {
        self.quote_desks(req, true, Some(client)).await
    }

    /// Fee by deadline for each desk at its current books. Reserves nothing.
    pub async fn price_curve(&self, side: Side, amount_sats: u64) -> Vec<serde_json::Value> {
        let inner = self.inner.read().await;
        inner
            .lps
            .iter()
            .filter(|lp| !lp.defaulted)
            .map(|lp| {
                let points: Vec<_> = DEADLINE_PRESETS
                    .iter()
                    .filter(|&&d| side == Side::Out || d == 0)
                    .map(|&d| {
                        let p = price(&self.pricing, lp, side, amount_sats, DEFAULT_QUOTE_TTL_SECS, d);
                        serde_json::json!({
                            "deadline_blocks": d,
                            "fee_ppm": p.fee_ppm,
                            "fee_sats": fee_sats(amount_sats, p.fee_ppm, MIN_FEE_SATS),
                        })
                    })
                    .collect();
                serde_json::json!({
                    "lp_id": lp.id,
                    "can_fill": can_fill(lp, side, amount_sats),
                    "points": points,
                })
            })
            .collect()
    }

    async fn quote_desks(
        &self,
        req: CreateQuoteRequest,
        all: bool,
        client: Option<&str>,
    ) -> Result<Vec<Quote>, Error> {
        if req.amount_sats < MIN_SWAP_SATS {
            return Err(Error::AmountTooSmall(MIN_SWAP_SATS));
        }
        if req.amount_sats > MAX_SWAP_SATS {
            return Err(Error::Invalid(format!(
                "amount must be at most {MAX_SWAP_SATS} sats (POST /v1/exits splits larger amounts across desks)"
            )));
        }
        let terms = self.quote_terms(&req).await?;

        let mut inner = self.inner.write().await;
        release_expired_quotes(&mut inner);
        let mut offers: Vec<(LiquidityProvider, PriceBreakdown, u64)> = inner
            .lps
            .iter()
            .filter(|lp| can_fill(lp, req.side, req.amount_sats))
            .map(|lp| {
                let ttl = firm_ttl(lp, req.side, req.amount_sats, terms.ttl_secs);
                let p = price(&self.pricing, lp, req.side, req.amount_sats, ttl, terms.deadline);
                (lp.clone(), p, fee_sats(req.amount_sats, p.fee_ppm, MIN_FEE_SATS))
            })
            .collect();
        if offers.is_empty() {
            return Err(Error::NoLiquidity {
                side: req.side,
                amount_sats: req.amount_sats,
            });
        }
        offers.retain(|(_, _, fee)| *fee < req.amount_sats);
        if offers.is_empty() {
            return Err(Error::Invalid("fee consumes the whole amount".into()));
        }
        // Cheapest in sats; when the minimum fee makes desks tie, the lower
        // rate wins, then the deeper book.
        offers.sort_by_key(|(lp, p, fee)| (*fee, p.fee_ppm, std::cmp::Reverse(book(lp, req.side))));
        if !all {
            offers.truncate(1);
        }
        let held: u64 = offers
            .iter()
            .map(|(_, _, fee)| reserve_sats(req.side, req.amount_sats - fee))
            .sum();
        check_client(&inner, client, offers.len(), held)?;

        let rfq_id = all.then(Uuid::now_v7);
        let mut quotes = Vec::with_capacity(offers.len());
        for (lp, pricing, fee) in offers {
            let leg = Leg {
                amount_sats: req.amount_sats,
                fee_sats: fee,
                pricing,
                rfq_id,
                plan_id: None,
            };
            let quote = self.make_quote(&mut inner, &lp.id, &req, &terms, leg)?;
            if let Some(client) = client {
                inner.clients.insert(quote.id, client.to_string());
            }
            quotes.push(quote);
        }
        drop(inner);
        self.save_state().await;
        Ok(quotes)
    }

    /// Split one amount across desks, cheapest marginal price first. Every leg
    /// is a firm quote; `accept_plan` opens them all. Bigger than any single
    /// desk (or `MAX_SWAP_SATS`) is fine: that is the point.
    pub async fn plan_exit(&self, req: CreatePlanRequest) -> Result<ExitPlan, Error> {
        self.plan_exit_inner(req, None).await
    }

    /// [`Self::plan_exit`] on behalf of an outside client, within its caps.
    pub async fn plan_exit_for(&self, client: &str, req: CreatePlanRequest) -> Result<ExitPlan, Error> {
        self.plan_exit_inner(req, Some(client)).await
    }

    async fn plan_exit_inner(
        &self,
        req: CreatePlanRequest,
        client: Option<&str>,
    ) -> Result<ExitPlan, Error> {
        let max_leg = req.max_leg_sats.unwrap_or(MAX_SWAP_SATS).min(MAX_SWAP_SATS);
        let req = req.quote;
        if req.amount_sats < MIN_SWAP_SATS {
            return Err(Error::AmountTooSmall(MIN_SWAP_SATS));
        }
        if max_leg < MIN_SWAP_SATS {
            return Err(Error::Invalid(format!("max_leg_sats must be at least {MIN_SWAP_SATS}")));
        }
        let terms = self.quote_terms(&req).await?;
        let plan_id = Uuid::now_v7();

        let mut inner = self.inner.write().await;
        release_expired_quotes(&mut inner);
        let mut legs: Vec<Quote> = Vec::new();
        let mut remaining = req.amount_sats;
        while remaining > 0 {
            let best = inner
                .lps
                .iter()
                .filter_map(|lp| {
                    let mut chunk = remaining.min(capacity(lp, req.side)).min(max_leg);
                    // Never strand a remainder too small to be its own leg.
                    let rest = remaining - chunk;
                    if rest > 0 && rest < MIN_SWAP_SATS {
                        chunk = chunk.saturating_sub(MIN_SWAP_SATS - rest);
                    }
                    if chunk < MIN_SWAP_SATS {
                        return None;
                    }
                    let ttl = firm_ttl(lp, req.side, chunk, terms.ttl_secs);
                    let p = price(&self.pricing, lp, req.side, chunk, ttl, terms.deadline);
                    let fee = fee_sats(chunk, p.fee_ppm, MIN_FEE_SATS);
                    (fee < chunk).then(|| (lp.id.clone(), chunk, p, fee))
                })
                .min_by_key(|(_, chunk, p, fee)| {
                    // Cheapest per sat moved, then the bigger leg (fewer legs).
                    (fee * 1_000_000 / chunk, p.fee_ppm, std::cmp::Reverse(*chunk))
                });
            let Some((lp_id, chunk, pricing, fee)) = best else {
                release_quotes(&mut inner, &legs);
                return Err(Error::NoLiquidity {
                    side: req.side,
                    amount_sats: req.amount_sats,
                });
            };
            let leg = Leg {
                amount_sats: chunk,
                fee_sats: fee,
                pricing,
                rfq_id: None,
                plan_id: Some(plan_id),
            };
            legs.push(self.make_quote(&mut inner, &lp_id, &req, &terms, leg)?);
            remaining -= chunk;
        }
        // The legs are not tagged with the client yet, so the caps see only
        // its earlier holds plus these.
        let held: u64 = legs.iter().map(|q| reserve_sats(q.side, q.receive_sats)).sum();
        if let Err(err) = check_client(&inner, client, legs.len(), held) {
            release_quotes(&mut inner, &legs);
            return Err(err);
        }
        if let Some(client) = client {
            for q in &legs {
                inner.clients.insert(q.id, client.to_string());
            }
        }
        let plan = ExitPlan {
            id: plan_id,
            side: req.side,
            amount_sats: req.amount_sats,
            fee_sats: legs.iter().map(|q| q.fee_sats).sum(),
            receive_sats: legs.iter().map(|q| q.receive_sats).sum(),
            legs,
            swap_ids: Vec::new(),
        };
        inner.plans.insert(plan_id, plan.clone());
        drop(inner);
        self.save_state().await;
        Ok(plan)
    }

    /// Open every leg of a plan. Legs that already expired are reported, the
    /// rest still open (each leg is an independent swap).
    pub async fn accept_plan(&self, plan_id: Uuid) -> Result<ExitPlan, Error> {
        let plan = self
            .inner
            .read()
            .await
            .plans
            .get(&plan_id)
            .cloned()
            .ok_or(Error::QuoteNotFound)?;
        if !plan.swap_ids.is_empty() {
            return Ok(plan);
        }
        let mut swap_ids = Vec::new();
        let mut failed = Vec::new();
        for leg in &plan.legs {
            match self.open_swap(leg.id).await {
                Ok(s) => swap_ids.push(s.id),
                Err(err) => failed.push(format!("{} via {}: {err}", leg.amount_sats, leg.lp_id)),
            }
        }
        if swap_ids.is_empty() {
            return Err(Error::Invalid(format!("no leg could open: {}", failed.join("; "))));
        }
        let plan = {
            let mut inner = self.inner.write().await;
            let p = inner.plans.get_mut(&plan_id).ok_or(Error::QuoteNotFound)?;
            p.swap_ids = swap_ids;
            p.clone()
        };
        self.save_state().await;
        if !failed.is_empty() {
            tracing::warn!(%plan_id, ?failed, "plan legs did not open");
        }
        Ok(plan)
    }

    pub async fn get_plan(&self, plan_id: Uuid) -> Result<ExitPlan, Error> {
        self.inner
            .read()
            .await
            .plans
            .get(&plan_id)
            .cloned()
            .ok_or(Error::QuoteNotFound)
    }

    /// Validate a quote request and fix its timeouts against the current tip.
    async fn quote_terms(&self, req: &CreateQuoteRequest) -> Result<QuoteTerms, Error> {
        let ttl_secs = req.ttl_secs.unwrap_or(DEFAULT_QUOTE_TTL_SECS);
        if !(MIN_QUOTE_TTL_SECS..=MAX_QUOTE_TTL_SECS).contains(&ttl_secs) {
            return Err(Error::Invalid(format!(
                "ttl_secs must be {MIN_QUOTE_TTL_SECS}..={MAX_QUOTE_TTL_SECS}"
            )));
        }
        let deadline = req.deadline_blocks.unwrap_or(0);
        if deadline > VAULT_EXIT_BLOCKS {
            return Err(Error::Invalid(format!(
                "deadline_blocks must be at most {VAULT_EXIT_BLOCKS} (a vault exit)"
            )));
        }
        if deadline > 0 && req.side == Side::In {
            return Err(Error::Invalid(
                "deadline_blocks applies to out swaps (when the desk locks bitcoin for you)".into(),
            ));
        }

        if !self.test_mode {
            match req.side {
                Side::In => {
                    let dest = req.user_tachi_address.as_deref().unwrap_or_default();
                    if !looks_like_tachi_owner(dest) {
                        return Err(Error::Invalid(
                            "user_tachi_address must be a Tachi P2TR or 64-char x-only key".into(),
                        ));
                    }
                }
                Side::Out => {
                    let dest = req.user_l1_address.as_deref().ok_or_else(|| {
                        Error::Invalid("user_l1_address must be a bitcoin address".into())
                    })?;
                    dest.parse::<Address<bitcoin::address::NetworkUnchecked>>()
                        .map_err(|_| {
                            Error::Invalid("user_l1_address is not a bitcoin address".into())
                        })?
                        .require_network(self.network)
                        .map_err(|_| {
                            Error::Invalid(format!(
                                "user_l1_address must be a {} address",
                                self.network
                            ))
                        })?;
                }
            }
        }

        let user_pk = req
            .user_refund_pubkey_hex
            .as_deref()
            .map(pubkey_from_hex)
            .transpose()?;
        if user_pk.is_none() && (req.side == Side::In || !self.test_mode) {
            return Err(Error::Invalid(match req.side {
                Side::In => "user_refund_pubkey_hex is required for in".into(),
                Side::Out => "user_refund_pubkey_hex is required for out (your key to claim the desk's lock)".into(),
            }));
        }

        // Quotes use the cached height (refreshed by the ticker). On a live
        // chain we fetch it once if we have never seen it, rather than guess.
        // A deadline pushes the timeout out so the desk's refund window still
        // starts after the latest lock.
        let height = self.known_height().await?;
        Ok(QuoteTerms {
            ttl_secs,
            deadline,
            user_pk,
            timeout_height: height + deadline + HTLC_TIMEOUT_BLOCKS,
            lock_by_height: (deadline > 0).then_some(height + deadline),
        })
    }

    /// Build one desk's quote, reserve its stock, and store it.
    fn make_quote(
        &self,
        inner: &mut Inner,
        lp_id: &str,
        req: &CreateQuoteRequest,
        terms: &QuoteTerms,
        leg: Leg,
    ) -> Result<Quote, Error> {
        let quote_id = Uuid::now_v7();
        let (preimage, pay) = self.pay_instructions(
            lp_id,
            req.side,
            terms.user_pk.as_ref(),
            terms.timeout_height,
            quote_id,
        )?;
        let mut quote = Quote {
            id: quote_id,
            side: req.side,
            amount_sats: leg.amount_sats,
            fee_sats: leg.fee_sats,
            receive_sats: leg.amount_sats - leg.fee_sats,
            lp_id: lp_id.to_string(),
            eta_seconds: if req.side == Side::In { 120 } else { 30 },
            expires_at: Utc::now() + Duration::seconds(leg.ttl_secs() as i64),
            user_tachi_address: req.user_tachi_address.clone(),
            user_l1_address: req.user_l1_address.clone(),
            pay,
            hint: Some(quote_hint(req.side, terms.lock_by_height)),
            vault_exit_blocks: VAULT_EXIT_BLOCKS,
            swap_timeout_blocks: HTLC_TIMEOUT_BLOCKS,
            comparison: Some(quote_comparison(leg.fee_sats, &leg.pricing, terms.lock_by_height)),
            user_pubkey_hex: terms.user_pk.map(|p| p.to_string()),
            pricing: Some(leg.pricing),
            rfq_id: leg.rfq_id,
            lock_by_height: terms.lock_by_height,
            plan_id: leg.plan_id,
            desk_pubkey: None,
            desk_signature: None,
        };
        sign_quote(&mut quote, &self.lp_wallet(lp_id)?.secret);
        debit_lp(
            &mut inner.lps,
            &quote.lp_id,
            quote.side,
            reserve_sats(quote.side, quote.receive_sats),
        )?;
        if let Some(preimage) = preimage {
            inner.preimages.insert(quote_id, preimage);
        }
        inner.quotes.insert(quote.id, quote.clone());
        Ok(quote)
    }

    /// HTLC + payment instructions for one desk's quote.
    fn pay_instructions(
        &self,
        lp_id: &str,
        side: Side,
        user_pk: Option<&PublicKey>,
        timeout_height: u32,
        quote_id: Uuid,
    ) -> Result<(Option<[u8; 32]>, PayInstructions), Error> {
        let lp_pk = self.lp_pubkey(lp_id)?;
        match (side, user_pk) {
            (Side::In, Some(user_pk)) => {
                let (preimage, lock) = self.build_htlc(&lp_pk, user_pk, timeout_height)?;
                Ok((
                    Some(preimage),
                    PayInstructions::L1Htlc {
                        address: lock.address,
                        payment_hash_hex: lock.payment_hash_hex,
                        timeout_height: lock.timeout_height,
                        redeem_script_hex: lock.redeem_script_hex,
                    },
                ))
            }
            (Side::In, None) => Err(Error::Invalid(
                "user_refund_pubkey_hex is required for in".into(),
            )),
            (Side::Out, user_pk) => {
                // User claims with preimage; LP refunds after timeout.
                let (preimage, lock) = match user_pk {
                    Some(user_pk) => {
                        let (pre, lock) = self.build_htlc(user_pk, &lp_pk, timeout_height)?;
                        (Some(pre), Some(lock))
                    }
                    None => (None, None),
                };
                Ok((
                    preimage,
                    PayInstructions::TachiVtxo {
                        pay_to: hex::encode(xonly_from_secret(&self.lp_wallet(lp_id)?.secret)),
                        memo: format!("tachi-flow out {lp_id} {quote_id}"),
                        lock,
                    },
                ))
            }
        }
    }

    pub async fn open_swap(&self, quote_id: Uuid) -> Result<Swap, Error> {
        let swap_id = Uuid::now_v7();
        // Held before the swap is visible, so background sync cannot race the
        // desk's first lock.
        let _guard = self.lock_swap(swap_id).await;
        let mut inner = self.inner.write().await;
        let quote = inner.quotes.remove(&quote_id).ok_or(Error::QuoteNotFound)?;
        if quote.expires_at < Utc::now() {
            inner.preimages.remove(&quote_id);
            credit_lp(
                &mut inner.lps,
                &quote.lp_id,
                quote.side,
                reserve_sats(quote.side, quote.receive_sats),
            );
            drop(inner);
            self.save_state().await;
            return Err(Error::QuoteExpired);
        }
        if let Some(rfq) = quote.rfq_id {
            let siblings: Vec<Uuid> = inner
                .quotes
                .values()
                .filter(|q| q.rfq_id == Some(rfq))
                .map(|q| q.id)
                .collect();
            for id in siblings {
                if let Some(q) = inner.quotes.remove(&id) {
                    inner.preimages.remove(&id);
                    credit_lp(&mut inner.lps, &q.lp_id, q.side, reserve_sats(q.side, q.receive_sats));
                }
            }
        }

        let now = Utc::now();
        let swap = Swap {
            id: swap_id,
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
            faucet_txid: None,
            fund_address: None,
            demo_note: None,
            user_pubkey_hex: quote.user_pubkey_hex.clone(),
            refund_txid: None,
            preimage_hex: None,
            lock_by_height: quote.lock_by_height,
            l1_lock_vout: None,
            lock_batch_size: None,
            plan_id: quote.plan_id,
            desk_defaulted: false,
            compensation_sats: None,
            compensation_vtxo_id: None,
            l1_lock_value_sats: None,
            claim_confirmed: false,
        };

        if let Some(preimage) = inner.preimages.remove(&quote.id) {
            inner.preimages.insert(swap_id, preimage);
        }
        // The unpaid swap keeps counting against its client's caps.
        if let Some(client) = inner.clients.remove(&quote.id) {
            inner.clients.insert(swap_id, client);
        }
        inner.swaps.insert(swap_id, swap.clone());
        drop(inner);
        self.publish(Event::Swap(Box::new(swap))).await;

        if !self.test_mode && quote.side == Side::Out {
            let pk = hex::encode(xonly_from_secret(&self.lp_wallet(&quote.lp_id)?.secret));
            // Without a baseline, auto-detection stays off for this swap and only
            // an explicit payment (pay-vtxo / observe) settles it.
            match self.tachi.address_vtxos(&pk).await {
                Ok(vtxos) => {
                    let ids = vtxos.into_iter().map(|v| v.id).collect();
                    self.inner.write().await.baseline_vtxos.insert(swap_id, ids);
                }
                Err(err) => tracing::warn!(%err, %swap_id, "outbound baseline"),
            }
            // Locks are funded by the batch pass (every sync, ~8 s), so exits
            // opened together share one L1 tx and its fee.
            let note = match quote.lock_by_height {
                Some(by) => format!(
                    "The desk locks bitcoin for you by block {by}, batched with other exits. Send Tachi coins only after the lock is up."
                ),
                None => "The desk locks bitcoin in its next batch (seconds), shared with other exits opened now. Send Tachi coins only after the lock is up.".into(),
            };
            self.update_swap(swap_id, |s| s.demo_note = Some(note)).await?;
        }
        self.save_state().await;
        self.get_swap(swap_id).await
    }

    /// LP locks `receive_sats` (+ the user's claim fee) on L1 first. Caller
    /// holds the swap lock. Once signed, the lock is never re-signed unless
    /// bitcoind rejected it outright, so a lost reply cannot fund it twice.
    async fn fund_outbound_lock(&self, id: Uuid) -> Result<Swap, Error> {
        let swap = self.get_swap(id).await?;
        let Some(lock) = swap.pay.htlc().filter(|_| swap.side == Side::Out) else {
            return Ok(swap);
        };
        if swap.l1_lock_txid.is_some() {
            return self.rebroadcast_outbound_lock(&swap).await;
        }
        match swap.status {
            SwapStatus::Quoted => {
                let h = self.known_height().await?;
                if h + SAFETY_MARGIN_BLOCKS >= lock.timeout_height {
                    return Err(Error::Invalid(format!(
                        "too close to the lock timeout (block {}) to fund it",
                        lock.timeout_height
                    )));
                }
                if !lock_due(&swap, h) {
                    return Ok(swap);
                }
            }
            // The user already paid; the desk owes this lock regardless.
            SwapStatus::LpSettled => {}
            _ => return Ok(swap),
        }
        let lp_id = swap.lp_id.clone();
        self.lock_batch(&lp_id, vec![swap]).await?;
        self.get_swap(id).await
    }

    /// Fund several outbound locks from one desk in a single L1 tx. Callers
    /// hold every swap's lock. Output `i` is swap `i`'s HTLC.
    async fn lock_batch(&self, lp_id: &str, swaps: Vec<Swap>) -> Result<(), Error> {
        let mut outputs = Vec::with_capacity(swaps.len());
        for swap in &swaps {
            let lock = swap
                .pay
                .htlc()
                .ok_or_else(|| Error::Invalid(format!("swap {} has no lock", swap.id)))?;
            outputs.push((lock.address, swap.receive_sats + CLAIM_FEE_SATS));
        }
        let (hex, inputs) = self.sign_l1_payment(lp_id, &outputs).await?;
        let txid = txid_of_hex(&hex)?.to_string();
        let n = swaps.len();
        {
            let mut inner = self.inner.write().await;
            for swap in &swaps {
                inner.pending_locks.insert(swap.id, hex.clone());
            }
        }
        for (vout, swap) in swaps.iter().enumerate() {
            let txid = txid.clone();
            self.update_swap(swap.id, |s| {
                s.l1_lock_txid = Some(txid);
                s.l1_lock_vout = Some(vout as u32);
                s.lock_batch_size = Some(n as u32);
                s.demo_note = Some(if n > 1 {
                    format!("Desk locked bitcoin first (HTLC), batched with {} other exits in one tx. Send VTXOs only after this.", n - 1)
                } else {
                    format!("Desk locked bitcoin first (HTLC). Send VTXOs only after this. Vault exit would be {VAULT_EXIT_BLOCKS} blocks.")
                });
            })
            .await?;
        }
        match self.broadcast_l1(&hex).await {
            Ok(_) => {
                tracing::info!(%txid, locks = n, lp = lp_id, "outbound locks funded");
                Ok(())
            }
            Err(Error::TachiRejected(why)) => {
                for swap in &swaps {
                    self.drop_outbound_lock(swap.id, lp_id, &inputs, &why).await?;
                }
                Err(Error::TachiRejected(why))
            }
            // Unknown outcome: keep the signed tx; sync re-sends it.
            Err(err) => {
                tracing::warn!(%err, %txid, "outbound lock broadcast");
                Ok(())
            }
        }
    }

    /// Batch every outbound lock that has come due, one L1 tx per desk.
    async fn fund_due_outbound_locks(&self) {
        let Ok(h) = self.known_height().await else {
            return;
        };
        let due: Vec<Swap> = self
            .inner
            .read()
            .await
            .swaps
            .values()
            .filter(|s| awaiting_lock(s, h))
            .cloned()
            .collect();
        let mut by_lp: std::collections::BTreeMap<String, Vec<Uuid>> = Default::default();
        for s in due {
            by_lp.entry(s.lp_id).or_default().push(s.id);
        }
        for (lp_id, ids) in by_lp {
            let mut guards = Vec::new();
            let mut batch = Vec::new();
            for id in ids {
                // Skip swaps someone else is working on; re-check under the lock.
                let Ok(guard) = self.swap_mutex(id).try_lock_owned() else {
                    continue;
                };
                if let Ok(s) = self.get_swap(id).await
                    && awaiting_lock(&s, h)
                {
                    guards.push(guard);
                    batch.push(s);
                }
            }
            if batch.is_empty() {
                continue;
            }
            if let Err(err) = self.lock_batch(&lp_id, batch).await {
                tracing::warn!(%err, lp = %lp_id, "batched outbound locks");
            }
        }
    }

    /// Re-send a signed outbound lock until bitcoind shows it.
    async fn rebroadcast_outbound_lock(&self, swap: &Swap) -> Result<Swap, Error> {
        let Some(hex) = self.inner.read().await.pending_locks.get(&swap.id).cloned() else {
            return Ok(swap.clone());
        };
        if self.scan_htlc(swap).await?.is_some() {
            self.inner.write().await.pending_locks.remove(&swap.id);
            self.save_state().await;
            return Ok(swap.clone());
        }
        match self.broadcast_l1(&hex).await {
            Ok(_) => Ok(swap.clone()),
            Err(Error::TachiRejected(why)) => {
                let inputs = tx_inputs(&hex)?;
                self.drop_outbound_lock(swap.id, &swap.lp_id, &inputs, &why)
                    .await
            }
            Err(err) => Err(err),
        }
    }

    /// bitcoind refused the lock tx, so it can never confirm: forget it and
    /// release its coins so the next sync signs a fresh one.
    async fn drop_outbound_lock(
        &self,
        id: Uuid,
        lp_id: &str,
        inputs: &[OutPoint],
        why: &str,
    ) -> Result<Swap, Error> {
        tracing::warn!(%id, why, "outbound lock rejected; will re-sign");
        {
            let mut spend = self.lp_spend(lp_id).await?;
            for op in inputs {
                spend.l1.remove(op);
            }
        }
        self.inner.write().await.pending_locks.remove(&id);
        self.update_swap(id, |s| {
            s.l1_lock_txid = None;
            s.l1_lock_vout = None;
            s.demo_note = Some(format!(
                "Desk lock was rejected by bitcoind ({why}). Retrying. Do not send Tachi coins yet."
            ));
        })
        .await
    }

    /// Faucet a normal P2WPKH, then send into the inbound HTLC. The hosted faucet
    /// refuses P2WSH lock addresses (`unknown output kind: p2wsh`).
    pub async fn fund_inbound(&self, id: Uuid) -> Result<Swap, Error> {
        if self.test_mode {
            return Err(Error::Invalid(
                "faucet helper is for live Tachi regtest, not TEST_MODE".into(),
            ));
        }
        let _guard = self.lock_swap(id).await;
        let swap = self.get_swap(id).await?;
        if swap.side != Side::In {
            return Err(Error::WrongSide(swap.side));
        }
        if swap.status != SwapStatus::Quoted {
            return Err(Error::BadTransition {
                from: swap.status,
                to: SwapStatus::InboundLocked,
            });
        }
        if swap.l1_lock_txid.is_some() {
            return Ok(swap);
        }
        let lock = swap
            .pay
            .htlc()
            .ok_or_else(|| Error::Invalid("swap is not waiting on an L1 lock".into()))?;
        if self.fresh_height().await? + SAFETY_MARGIN_BLOCKS >= lock.timeout_height {
            return Err(Error::Invalid(
                "too close to the lock timeout; the desk would not settle it".into(),
            ));
        }
        let dest = lock
            .address
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .map_err(|_| Error::Invalid("lock address".into()))?
            .require_network(self.network)
            .map_err(|e| Error::Bitcoin(e.to_string()))?;

        // Reuse the drip from an earlier attempt instead of asking twice.
        let existing = self.inner.read().await.fund_keys.get(&id).copied();
        let (sk, faucet_txid) = match (existing, swap.faucet_txid.clone()) {
            (Some(sk), Some(txid)) => (sk, txid),
            _ => {
                let sk = generate_keypair().secret;
                let from = p2wpkh_address(&sk, self.network);
                let drip_sats = swap.amount_sats.saturating_add(20_000).max(40_000);
                let amount_btc = drip_sats as f64 / 100_000_000.0;
                let txid = crate::faucet::drip(&from.to_string(), amount_btc).await?;
                self.inner.write().await.fund_keys.insert(id, sk);
                let t = txid.clone();
                self.update_swap(id, |s| {
                    s.faucet_txid = Some(t);
                    s.fund_address = Some(from.to_string());
                })
                .await?;
                (sk, txid)
            }
        };
        let from = p2wpkh_address(&sk, self.network);
        let u = self.wait_for_faucet_coin(&faucet_txid).await?;
        let fee = 300u64;
        if u.value_sats <= swap.amount_sats + fee {
            return Err(Error::Invalid(format!(
                "faucet sent {} sats, need {} for the lock plus fee",
                u.value_sats, swap.amount_sats
            )));
        }
        let op = OutPoint {
            txid: parse_txid(&u.txid)?,
            vout: u.vout,
        };
        let hex = p2wpkh_send_hex(
            &[(op, u.value_sats)],
            &dest,
            swap.amount_sats,
            fee,
            &from,
            &sk,
            self.network,
        )?;
        let lock_txid = self.broadcast_l1(&hex).await?;
        self.inner.write().await.fund_keys.remove(&id);
        self.update_swap(id, |s| {
            s.l1_lock_txid = Some(lock_txid);
            s.demo_note = Some(
                "The Tachi faucet cannot pay a lock address, so we fauceted a normal wallet and forwarded coins into the lock.".into(),
            );
        })
        .await
    }

    fn check_owner(&self, swap: &Swap, secret: &SecretKey) -> Result<(), Error> {
        let Some(want) = swap.user_pubkey_hex.as_deref() else {
            return if self.test_mode {
                Ok(())
            } else {
                Err(Error::Invalid("swap has no user key on record".into()))
            };
        };
        let have = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
            &Secp256k1::new(),
            secret,
        ));
        if have.to_string().eq_ignore_ascii_case(want) {
            Ok(())
        } else {
            Err(Error::Invalid(
                "secret_hex does not match this swap's key".into(),
            ))
        }
    }

    /// Demo helper: spend the user's VTXOs to the outbound `pay_to` using their
    /// secret, then claim the desk's lock. Calling it again after a payment
    /// never pays twice; it only retries confirmation and the claim.
    pub async fn user_pay_outbound(&self, id: Uuid, secret_hex: &str) -> Result<Swap, Error> {
        let secret = parse_secret(secret_hex)?;
        let _guard = self.lock_swap(id).await;
        let swap = self.get_swap(id).await?;
        if swap.side != Side::Out {
            return Err(Error::WrongSide(swap.side));
        }
        self.check_owner(&swap, &secret)?;
        match swap.status {
            SwapStatus::Quoted => {
                let paid = match swap.vtxo_payment_id.clone() {
                    Some(paid) => paid,
                    None => self.send_outbound_payment(&swap, &secret).await?,
                };
                if !self.await_and_observe(id, &paid).await? {
                    return self
                        .update_swap(id, |s| {
                            s.demo_note = Some(
                                "Payment sent; waiting for Tachi to include it. Click Send again to check (it will not pay twice).".into(),
                            );
                        })
                        .await;
                }
            }
            // Paid already: retry the claim only.
            SwapStatus::LpSettled => {}
            from => {
                return Err(Error::BadTransition {
                    from,
                    to: SwapStatus::Claimed,
                });
            }
        }
        if self.test_mode {
            return self.get_swap(id).await;
        }
        match self.claim_outbound(id, &secret).await {
            Ok(swap) => Ok(swap),
            Err(err) => {
                let timeout = swap.pay.htlc().map(|l| l.timeout_height).unwrap_or_default();
                self.update_swap(id, |s| {
                    s.demo_note = Some(format!(
                        "Your payment is recorded but the claim failed ({err}). Click Send again to retry the claim (no second payment), or claim with the preimage from any wallet before block {timeout}."
                    ));
                })
                .await
            }
        }
    }

    /// Pay the desk from the user's key. The payment id is stored before the tx
    /// leaves, so a lost reply cannot lead to a second payment.
    async fn send_outbound_payment(&self, swap: &Swap, secret: &SecretKey) -> Result<String, Error> {
        let PayInstructions::TachiVtxo { pay_to, lock, .. } = &swap.pay else {
            return Err(Error::Invalid("swap is not waiting on a VTXO payment".into()));
        };
        if !self.test_mode {
            let lock = lock
                .as_ref()
                .ok_or_else(|| Error::Invalid("swap has no desk lock".into()))?;
            if self.scan_htlc(swap).await?.is_none() {
                return Err(Error::Invalid(
                    "desk has not locked bitcoin yet — wait for the HTLC, then send Tachi coins"
                        .into(),
                ));
            }
            let h = self.fresh_height().await?;
            if h + SAFETY_MARGIN_BLOCKS >= lock.timeout_height {
                return Err(Error::Invalid(format!(
                    "the desk can refund its lock at block {} (now {h}); too late to pay safely",
                    lock.timeout_height
                )));
            }
        }
        let mut spend = LpSpend::default();
        let built = self
            .build_transfer(secret, &spend, pay_to, swap.amount_sats)
            .await?;
        let paid = built.signed.output_vtxo_id.clone();
        let p = paid.clone();
        self.update_swap(swap.id, |s| s.vtxo_payment_id = Some(p))
            .await?;
        match self.broadcast_transfer(&mut spend, &built).await {
            Ok(hash) => {
                self.update_swap(swap.id, |s| s.tachi_tx_hash = Some(hash))
                    .await?;
                Ok(paid)
            }
            Err(Error::TachiRejected(why)) => {
                self.update_swap(swap.id, |s| s.vtxo_payment_id = None)
                    .await?;
                Err(Error::TachiRejected(why))
            }
            // May have landed; the stored id lets a retry check instead of pay.
            Err(err) => Err(err),
        }
    }

    /// Tachi commits a block after CheckTx; give it a few seconds. Returns
    /// whether the payment was seen and the swap settled.
    async fn await_and_observe(&self, id: Uuid, vtxo_id: &str) -> Result<bool, Error> {
        if self.test_mode {
            self.observe_vtxo_inner(id, vtxo_id).await?;
            return Ok(true);
        }
        for _ in 0..10 {
            if self.tachi.find_vtxo(vtxo_id).await?.is_some() {
                self.observe_vtxo_inner(id, vtxo_id).await?;
                return Ok(true);
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        Ok(false)
    }

    async fn claim_outbound(&self, id: Uuid, user_secret: &SecretKey) -> Result<Swap, Error> {
        let swap = self.get_swap(id).await?;
        if swap.status != SwapStatus::LpSettled {
            return Ok(swap);
        }
        let Some(lock) = swap.pay.htlc() else {
            return Ok(swap);
        };
        let preimage = self
            .inner
            .read()
            .await
            .preimages
            .get(&id)
            .copied()
            .ok_or_else(|| Error::Invalid("missing outbound preimage".into()))?;
        let utxo = self
            .scan_htlc(&swap)
            .await?
            .ok_or_else(|| Error::Invalid("outbound HTLC not visible — cannot claim yet".into()))?;
        let dest = swap
            .user_l1_address
            .as_deref()
            .ok_or_else(|| Error::Invalid("user_l1_address required to claim".into()))?
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .map_err(|_| Error::Invalid("user_l1_address".into()))?
            .require_network(self.network)
            .map_err(|e| Error::Bitcoin(e.to_string()))?;
        let hex = claim_tx_hex(
            OutPoint {
                txid: parse_txid(&utxo.txid)?,
                vout: utxo.vout,
            },
            utxo.value_sats,
            CLAIM_FEE_SATS,
            &redeem_from_hex(&lock.redeem_script_hex)?,
            &preimage,
            user_secret,
            &dest,
        )?;
        let sent = self.broadcast_l1(&hex).await?;
        self.record_fill(&swap.lp_id).await;
        self.update_swap(id, |s| {
            s.claim_tx_hex = Some(hex);
            s.status = SwapStatus::Claimed;
            s.demo_note = Some(format!(
                "You claimed the desk lock ({sent}). Same HTLC pattern as inbound, roles reversed."
            ));
        })
        .await
    }

    /// Mint VTXOs onto empty live LP books so inbound quotes have something to sell.
    pub async fn ensure_demo_liquidity(&self) -> Result<(), Error> {
        if self.test_mode {
            return Ok(());
        }
        for w in &self.wallets {
            let have = self.live_vtxo_sats_for(&w.secret).await;
            if have < 50_000 {
                tracing::info!(lp = %w.id, have, "demo deposit 100000 VTXOs");
                self.deposit_vtxo(100_000, Some(&w.id)).await?;
            }
        }
        self.refresh_live_inventory().await;
        Ok(())
    }

    /// Operator override / test hook: confirm the inbound HTLC and pay VTXOs.
    /// Live mode ignores the body and reads the lock from Bitcoin.
    pub async fn observe_lock(&self, id: Uuid, lock: ObserveLockRequest) -> Result<Swap, Error> {
        let _guard = self.lock_swap(id).await;
        self.observe_lock_inner(id, lock).await
    }

    async fn observe_lock_inner(&self, id: Uuid, lock: ObserveLockRequest) -> Result<Swap, Error> {
        let swap = self.get_swap(id).await?;
        if swap.side != Side::In {
            return Err(Error::WrongSide(swap.side));
        }
        if swap.status != SwapStatus::Quoted {
            return Err(Error::BadTransition {
                from: swap.status,
                to: SwapStatus::InboundLocked,
            });
        }
        let htlc = swap
            .pay
            .htlc()
            .ok_or_else(|| Error::Invalid("swap has no L1 lock".into()))?;

        let funding = if self.test_mode {
            lock
        } else {
            self.scan_htlc(&swap).await?.ok_or_else(|| {
                Error::Invalid(
                    "HTLC not funded yet — pay the lock address, then POST /v1/sync".into(),
                )
            })?
        };
        if funding.value_sats < swap.amount_sats {
            return Err(Error::Invalid("underpaid HTLC".into()));
        }

        let h = if self.test_mode {
            self.cached_height()
        } else {
            self.fresh_height().await?
        };
        if h + SAFETY_MARGIN_BLOCKS >= htlc.timeout_height {
            return self.expire(id).await;
        }

        // Build the claim before paying, so a paid swap always has one.
        let preimage = self
            .inner
            .read()
            .await
            .preimages
            .get(&id)
            .copied()
            .ok_or_else(|| Error::Invalid("missing inbound preimage".into()))?;
        let w = self.lp_wallet(&swap.lp_id)?;
        let claim_hex = claim_tx_hex(
            OutPoint {
                txid: parse_txid(&funding.txid)?,
                vout: funding.vout,
            },
            funding.value_sats,
            self.fee_for(HTLC_SPEND_VBYTES).min(funding.value_sats / 2),
            &redeem_from_hex(&htlc.redeem_script_hex)?,
            &preimage,
            &w.secret,
            &w.claim_address,
        )?;

        let payout = if self.test_mode {
            None
        } else {
            let dest = swap
                .user_tachi_address
                .as_deref()
                .filter(|s| looks_like_tachi_owner(s))
                .ok_or_else(|| {
                    Error::Invalid(
                        "user_tachi_address is required so the LP can pay VTXOs on Tachi".into(),
                    )
                })?;
            Some(
                self.settle_payout(id, &swap.lp_id, dest, swap.receive_sats)
                    .await?,
            )
        };

        self.inner.write().await.pending_payouts.remove(&id);
        let swap = self
            .update_swap(id, |s| {
                s.status = SwapStatus::LpSettled;
                s.l1_lock_txid = Some(funding.txid.clone());
                s.l1_lock_value_sats = Some(funding.value_sats);
                s.claim_tx_hex = Some(claim_hex);
                match payout {
                    Some(p) => {
                        s.vtxo_payment_id = Some(p.output_vtxo_id);
                        s.tachi_tx_hash = Some(p.tendermint_hash);
                    }
                    None => s.vtxo_payment_id = Some(format!("sim-vtxo-{}", s.id)),
                }
            })
            .await?;
        if !self.test_mode {
            // A failure here is recorded on the swap and retried by sync.
            if let Ok(claimed) = self.claim_inbound_inner(id).await {
                return Ok(claimed);
            }
            return self.get_swap(id).await;
        }
        Ok(swap)
    }

    /// Pay VTXOs exactly once for `id` (a swap, LN swap, or compensation) from
    /// a desk wallet or the escrow. The signed tx is persisted before
    /// broadcast; a retry re-sends it, or confirms it already landed, and only
    /// re-signs when the old tx provably cannot land.
    async fn settle_payout(
        &self,
        id: Uuid,
        lp_id: &str,
        dest: &str,
        amount_sats: u64,
    ) -> Result<SignedTransfer, Error> {
        let mut spend = self.lp_spend(lp_id).await?;
        let secret = self.spend_secret(lp_id)?;
        let pk_hex = hex::encode(xonly_from_secret(&secret));

        let pending = self.inner.read().await.pending_payouts.get(&id).cloned();
        if let Some(p) = pending {
            if self.tachi.find_vtxo(&p.signed.output_vtxo_id).await?.is_some() {
                return Ok(p.signed);
            }
            if self.tachi.next_nonce(&pk_hex).await? <= p.nonce {
                // Our nonce is still unused: re-send the identical tx.
                match self.tachi.broadcast_tx_sync(&p.signed.hex).await {
                    Ok(hash) => {
                        return Ok(SignedTransfer {
                            tendermint_hash: hash,
                            ..p.signed
                        });
                    }
                    Err(Error::TachiRejected(why)) => {
                        tracing::warn!(%id, why, "stale payout rejected; re-signing");
                        spend.forget_tachi();
                    }
                    Err(err) => return Err(err),
                }
            }
            // Either Tachi refused it, or another tx consumed its nonce while
            // its output never appeared: it cannot land. Safe to re-sign.
            self.inner.write().await.pending_payouts.remove(&id);
        }

        let built = self
            .build_transfer(&secret, &spend, dest, amount_sats)
            .await?;
        self.inner.write().await.pending_payouts.insert(
            id,
            PendingPayout {
                signed: built.signed.clone(),
                nonce: built.nonce,
            },
        );
        self.save_state().await;
        match self.broadcast_transfer(&mut spend, &built).await {
            Ok(hash) => Ok(SignedTransfer {
                tendermint_hash: hash,
                ..built.signed
            }),
            Err(Error::TachiRejected(why)) => {
                self.inner.write().await.pending_payouts.remove(&id);
                self.save_state().await;
                Err(Error::TachiRejected(why))
            }
            Err(err) => Err(err),
        }
    }

    /// Operator override / test hook for an outbound VTXO payment.
    pub async fn observe_vtxo(&self, id: Uuid, paid: ObserveVtxoRequest) -> Result<Swap, Error> {
        let _guard = self.lock_swap(id).await;
        self.observe_vtxo_inner(id, &paid.vtxo_id).await
    }

    async fn observe_vtxo_inner(&self, id: Uuid, vtxo_id: &str) -> Result<Swap, Error> {
        let swap = self.get_swap(id).await?;
        if swap.side != Side::Out {
            return Err(Error::WrongSide(swap.side));
        }
        if swap.status != SwapStatus::Quoted {
            return Err(Error::BadTransition {
                from: swap.status,
                to: SwapStatus::LpSettled,
            });
        }
        if !self.test_mode && !looks_like_vtxo_id(vtxo_id) {
            return Err(Error::Invalid(
                "pass the 64-char Tachi vtxo id the user paid to the LP".into(),
            ));
        }
        {
            let inner = self.inner.read().await;
            if let Some(other) = inner
                .swaps
                .values()
                .find(|s| s.id != id && s.vtxo_payment_id.as_deref() == Some(vtxo_id))
            {
                return Err(Error::Invalid(format!(
                    "vtxo {vtxo_id} already pays swap {}",
                    other.id
                )));
            }
            if inner.own_vtxos.contains(vtxo_id) {
                return Err(Error::Invalid(format!(
                    "vtxo {vtxo_id} is the desk's own coin, not a payment"
                )));
            }
        }

        if looks_like_vtxo_id(vtxo_id) {
            // `spent` is fine: the desk may already have spent what it received.
            let vtxo = self.tachi.get_vtxo(vtxo_id).await?;
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
        }

        let preimage = self.inner.read().await.preimages.get(&id).copied();
        let test_mode = self.test_mode;
        let swap = self
            .update_swap(id, |s| {
                s.status = SwapStatus::LpSettled;
                s.vtxo_payment_id = Some(vtxo_id.to_string());
                if let (Some(lock), Some(pre)) = (s.pay.htlc(), preimage) {
                    s.preimage_hex = Some(hex::encode(pre));
                    s.demo_note = Some(format!(
                        "Desk received your Tachi coins. Claim its lock with the preimage before block {}.",
                        lock.timeout_height
                    ));
                }
                if test_mode && s.l1_lock_txid.is_none() {
                    s.l1_lock_txid = Some(format!("sim-l1-payout-{}", s.id));
                }
            })
            .await?;
        self.inner.write().await.baseline_vtxos.remove(&id);
        Ok(swap)
    }

    /// Operator / test hook: broadcast the desk's inbound claim.
    pub async fn claim(&self, id: Uuid) -> Result<Swap, Error> {
        let _guard = self.lock_swap(id).await;
        self.claim_inbound_inner(id).await
    }

    /// Status turns `Claimed` only after the claim is accepted, so a failed
    /// broadcast stays `LpSettled` and sync keeps retrying it.
    async fn claim_inbound_inner(&self, id: Uuid) -> Result<Swap, Error> {
        let swap = self.get_swap(id).await?;
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
            credit_lp_l1(
                &mut self.inner.write().await.lps,
                &swap.lp_id,
                swap.amount_sats,
            );
            self.record_fill(&swap.lp_id).await;
            return self
                .update_swap(id, |s| s.status = SwapStatus::Claimed)
                .await;
        }
        let hex = swap
            .claim_tx_hex
            .clone()
            .ok_or_else(|| Error::Invalid("swap has no claim tx".into()))?;
        match self.broadcast_l1(&hex).await {
            Ok(txid) => {
                tracing::info!(%txid, %id, "broadcast HTLC claim");
                self.record_fill(&swap.lp_id).await;
                self.update_swap(id, |s| {
                    s.status = SwapStatus::Claimed;
                    s.demo_note = Some(format!("Desk claimed the lock ({txid})."));
                })
                .await
            }
            Err(err) => {
                tracing::warn!(%err, %id, "claim broadcast failed; sync retries");
                let note = format!("Desk claim not broadcast yet ({err}); retrying.");
                self.update_swap(id, |s| s.demo_note = Some(note)).await?;
                Err(err)
            }
        }
    }

    /// User refund / cancel. Live mode needs the user's secret, both to prove
    /// the swap is theirs and to sign the on-chain refund.
    pub async fn refund(&self, id: Uuid, secret: Option<SecretKey>) -> Result<Swap, Error> {
        let _guard = self.lock_swap(id).await;
        let swap = self.get_swap(id).await?;
        match &secret {
            Some(sk) => self.check_owner(&swap, sk)?,
            None if !self.test_mode => {
                return Err(Error::Invalid(
                    "secret_hex is required to refund or cancel a swap".into(),
                ));
            }
            None => {}
        }
        match (swap.side, swap.status) {
            (Side::In, SwapStatus::Quoted | SwapStatus::Expired | SwapStatus::Refunded) => {
                self.refund_inbound(swap, secret).await
            }
            (Side::Out, SwapStatus::Quoted) if swap.vtxo_payment_id.is_none() => {
                self.cancel(&swap).await
            }
            (Side::Out, SwapStatus::Expired) => self.cancel(&swap).await,
            (_, from) => Err(Error::BadTransition {
                from,
                to: SwapStatus::Refunded,
            }),
        }
    }

    async fn cancel(&self, swap: &Swap) -> Result<Swap, Error> {
        let note = match (swap.side, swap.pay.htlc()) {
            (Side::Out, Some(lock)) if swap.l1_lock_txid.is_some() => format!(
                "Cancelled. Do not send Tachi coins. The desk takes its lock back after block {}.",
                lock.timeout_height
            ),
            _ => "Cancelled before any bitcoin was locked.".into(),
        };
        self.update_swap(swap.id, |s| {
            s.status = SwapStatus::Refunded;
            s.demo_note = Some(note);
        })
        .await
    }

    async fn refund_inbound(&self, swap: Swap, secret: Option<SecretKey>) -> Result<Swap, Error> {
        if swap.refund_txid.is_some() {
            return Ok(swap);
        }
        let funding = if self.test_mode {
            None
        } else {
            self.scan_htlc(&swap).await?
        };
        let Some(funding) = funding else {
            return if swap.status == SwapStatus::Refunded {
                Ok(swap)
            } else {
                self.cancel(&swap).await
            };
        };
        let lock = swap
            .pay
            .htlc()
            .ok_or_else(|| Error::Invalid("swap has no L1 lock".into()))?;
        let h = self.fresh_height().await?;
        if h < lock.timeout_height {
            return Err(Error::Invalid(if swap.status == SwapStatus::Quoted {
                format!(
                    "your lock is funded; the desk settles it, or you can refund after block {} (now {h})",
                    lock.timeout_height
                )
            } else {
                format!(
                    "refund opens at block {} (now {h})",
                    lock.timeout_height
                )
            }));
        }
        let secret = secret.ok_or_else(|| Error::Invalid("secret_hex required".into()))?;
        let dest = p2wpkh_address(&secret, self.network);
        let hex = refund_tx_hex(
            OutPoint {
                txid: parse_txid(&funding.txid)?,
                vout: funding.vout,
            },
            funding.value_sats,
            CLAIM_FEE_SATS,
            &redeem_from_hex(&lock.redeem_script_hex)?,
            LockTime::from_height(lock.timeout_height).map_err(|e| Error::Bitcoin(e.to_string()))?,
            &secret,
            &dest,
        )?;
        let txid = self.broadcast_l1(&hex).await?;
        self.update_swap(swap.id, |s| {
            s.status = SwapStatus::Refunded;
            s.refund_txid = Some(txid.clone());
            s.demo_note = Some(format!(
                "Refunded {} sats to {dest} ({txid}).",
                funding.value_sats - CLAIM_FEE_SATS
            ));
        })
        .await
    }

    /// The desk has already paid VTXOs for an inbound lock; if its claim is
    /// still unconfirmed this close to the timeout, the user could refund the
    /// lock and keep both. Re-sign the claim at a higher fee (RBF) until it
    /// confirms, and re-send it if the mempool dropped it.
    async fn bump_desk_claim(&self, swap: &Swap, height: u32) -> Result<(), Error> {
        let (Some(hex), Some(value), Some(lock)) = (
            swap.claim_tx_hex.clone(),
            swap.l1_lock_value_sats,
            swap.pay.htlc(),
        ) else {
            return Ok(());
        };
        let txid = txid_of_hex(&hex)?.to_string();
        match self.tachi.tx_confirmations(&txid).await? {
            Some(c) if c > 0 => {
                self.update_swap(swap.id, |s| s.claim_confirmed = true).await?;
                return Ok(());
            }
            None => {
                if let Err(err) = self.broadcast_l1(&hex).await {
                    tracing::warn!(%err, id = %swap.id, "re-send dropped claim");
                }
                return Ok(());
            }
            Some(_) => {}
        }
        if height + BUMP_BEFORE_TIMEOUT_BLOCKS < lock.timeout_height {
            return Ok(());
        }
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(
            &hex::decode(&hex).map_err(|e| Error::Invalid(e.to_string()))?,
        )
        .map_err(|e| Error::Bitcoin(e.to_string()))?;
        let paid_out: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        let Some(fee) = bumped_fee(value.saturating_sub(paid_out), value) else {
            tracing::warn!(id = %swap.id, "claim fee already at its cap; not bumping");
            return Ok(());
        };
        let preimage = self
            .inner
            .read()
            .await
            .preimages
            .get(&swap.id)
            .copied()
            .ok_or_else(|| Error::Invalid("missing inbound preimage".into()))?;
        let w = self.lp_wallet(&swap.lp_id)?;
        let bumped = claim_tx_hex(
            tx.input[0].previous_output,
            value,
            fee,
            &redeem_from_hex(&lock.redeem_script_hex)?,
            &preimage,
            &w.secret,
            &w.claim_address,
        )?;
        let new_txid = self.broadcast_l1(&bumped).await?;
        tracing::info!(id = %swap.id, fee, %new_txid, "bumped desk claim");
        self.update_swap(swap.id, |s| {
            s.claim_tx_hex = Some(bumped);
            s.demo_note = Some(format!(
                "Desk claim was slow to confirm near the timeout; re-sent at {fee} sats fee ({new_txid})."
            ));
        })
        .await?;
        Ok(())
    }

    /// Desk takes back an outbound lock the user never paid for, after timeout.
    async fn lp_refund_outbound(&self, swap: &Swap, height: u32) -> Result<(), Error> {
        let Some(lock) = swap.pay.htlc() else {
            return Ok(());
        };
        if swap.refund_txid.is_some() || height < lock.timeout_height {
            return Ok(());
        }
        // Gone means claimed (or never confirmed); nothing to take back.
        let Some(funding) = self.scan_htlc(swap).await? else {
            return Ok(());
        };
        let w = self.lp_wallet(&swap.lp_id)?;
        let hex = refund_tx_hex(
            OutPoint {
                txid: parse_txid(&funding.txid)?,
                vout: funding.vout,
            },
            funding.value_sats,
            self.fee_for(HTLC_SPEND_VBYTES).min(funding.value_sats / 2),
            &redeem_from_hex(&lock.redeem_script_hex)?,
            LockTime::from_height(lock.timeout_height).map_err(|e| Error::Bitcoin(e.to_string()))?,
            &w.secret,
            &w.claim_address,
        )?;
        let txid = self.broadcast_l1(&hex).await?;
        self.update_swap(swap.id, |s| {
            s.refund_txid = Some(txid.clone());
            s.demo_note = Some(format!(
                "Desk took its unpaid lock back after block {} ({txid}).",
                lock.timeout_height
            ));
        })
        .await?;
        Ok(())
    }

    /// Too close to the timeout to settle. Also decides whether the desk is to
    /// blame: it never locked bitcoin for an `out` swap, or the user's `in`
    /// lock was funded and the desk never paid. A desk default costs it
    /// reputation and pays the user from its bond.
    async fn expire(&self, id: Uuid) -> Result<Swap, Error> {
        let swap = self.get_swap(id).await?;
        let timeout = swap.pay.htlc().map(|l| l.timeout_height).unwrap_or_default();
        let desk_failed = match swap.side {
            Side::Out => swap.l1_lock_txid.is_none() && swap.pay.htlc().is_some(),
            Side::In => {
                // A pending payout means the desk may have paid; never blame it then.
                let maybe_paid = self.inner.read().await.pending_payouts.contains_key(&id);
                !self.test_mode && !maybe_paid && self.scan_htlc(&swap).await?.is_some()
            }
        };
        let mut note = match swap.side {
            Side::In => format!(
                "Too close to the lock's timeout (block {timeout}) to settle safely. If you paid the lock, refund it after block {timeout}."
            ),
            Side::Out => format!(
                "Expired before payment. Do not send Tachi coins now. The desk takes its lock back after block {timeout}."
            ),
        };
        let compensation = if desk_failed {
            let comp = self.record_default(&swap.lp_id, swap.amount_sats).await;
            note.push_str(&format!(
                " The desk defaulted on this swap{}.",
                if comp > 0 {
                    format!("; {comp} sats from its bond are on their way to your Tachi key")
                } else {
                    " (it had no bond to pay you from)".to_string()
                }
            ));
            Some(comp).filter(|c| *c > 0)
        } else {
            None
        };
        let swap = self
            .update_swap(id, |s| {
                s.status = SwapStatus::Expired;
                s.desk_defaulted = desk_failed;
                s.compensation_sats = compensation;
                s.demo_note = Some(note);
            })
            .await?;
        if compensation.is_some() {
            // Failure is retried by sync (`compensation_owed`).
            if let Err(err) = self.pay_compensation(&swap).await {
                tracing::warn!(%err, %id, "bond compensation");
            }
        }
        self.get_swap(id).await
    }

    /// Count a default and reserve compensation out of the desk's bond.
    async fn record_default(&self, lp_id: &str, amount_sats: u64) -> u64 {
        let comp = {
            let mut inner = self.inner.write().await;
            inner.reputation.entry(lp_id.to_string()).or_default().1 += 1;
            let bond = inner.bonds.entry(lp_id.to_string()).or_default();
            let owed = (amount_sats * DEFAULT_PENALTY_PPM / 1_000_000).max(MIN_COMPENSATION_SATS);
            let comp = owed.min(*bond);
            *bond -= comp;
            apply_desk_stats(&mut inner);
            comp
        };
        tracing::warn!(lp = lp_id, comp, "desk default recorded");
        self.save_state().await;
        comp
    }

    async fn record_fill(&self, lp_id: &str) {
        let mut inner = self.inner.write().await;
        inner.reputation.entry(lp_id.to_string()).or_default().0 += 1;
        apply_desk_stats(&mut inner);
    }

    /// Pay a default's compensation from escrow to the user's Tachi key.
    async fn pay_compensation(&self, swap: &Swap) -> Result<(), Error> {
        let Some(amount) = swap.compensation_sats else {
            return Ok(());
        };
        if swap.compensation_vtxo_id.is_some() {
            return Ok(());
        }
        let dest = swap
            .user_tachi_address
            .clone()
            .filter(|a| looks_like_tachi_owner(a))
            .or_else(|| swap.user_pubkey_hex.clone())
            .ok_or_else(|| Error::Invalid("no Tachi key to compensate".into()))?;
        let vtxo_id = if self.test_mode {
            format!("sim-comp-{}", swap.id)
        } else {
            self.settle_payout(comp_key(swap.id), ESCROW_ID, &dest, amount)
                .await?
                .output_vtxo_id
        };
        self.inner.write().await.pending_payouts.remove(&comp_key(swap.id));
        self.update_swap(swap.id, |s| s.compensation_vtxo_id = Some(vtxo_id))
            .await?;
        Ok(())
    }

    /// Desk posts VTXOs to escrow as a bond. Custodial: this server holds the
    /// escrow key, so a bond protects users only as far as the operator is honest.
    pub async fn post_bond(&self, lp_id: &str, amount_sats: u64) -> Result<u64, Error> {
        self.lp_wallet(lp_id)?;
        if amount_sats < MIN_SWAP_SATS {
            return Err(Error::AmountTooSmall(MIN_SWAP_SATS));
        }
        if !self.test_mode {
            self.send_vtxo_from(lp_id, &self.escrow_pubkey_hex(), amount_sats)
                .await?;
        }
        let total = {
            let mut inner = self.inner.write().await;
            let bond = inner.bonds.entry(lp_id.to_string()).or_default();
            *bond += amount_sats;
            let total = *bond;
            apply_desk_stats(&mut inner);
            total
        };
        self.save_state().await;
        Ok(total)
    }

    pub async fn mark_lp_default(&self, id: Uuid) -> Result<Swap, Error> {
        let _guard = self.lock_swap(id).await;
        let swap = self.get_swap(id).await?;
        if swap.status != SwapStatus::Quoted && swap.status != SwapStatus::OutboundPaid {
            return Err(Error::BadTransition {
                from: swap.status,
                to: SwapStatus::Failed,
            });
        }
        {
            let mut inner = self.inner.write().await;
            if swap.status == SwapStatus::Quoted {
                credit_lp(
                    &mut inner.lps,
                    &swap.lp_id,
                    swap.side,
                    reserve_sats(swap.side, swap.receive_sats),
                );
            }
            if let Some(lp) = inner.lps.iter_mut().find(|lp| lp.id == swap.lp_id) {
                lp.defaulted = true;
            }
        }
        self.update_swap(id, |s| s.status = SwapStatus::Failed).await
    }

    /// Spend LP VTXOs on Tachi to `dest` (P2TR address or x-only pubkey hex).
    pub async fn send_vtxo(&self, dest: &str, amount_sats: u64) -> Result<SignedTransfer, Error> {
        self.send_vtxo_from(&self.default_wallet().id.clone(), dest, amount_sats)
            .await
    }

    pub async fn send_vtxo_from(
        &self,
        lp_id: &str,
        dest: &str,
        amount_sats: u64,
    ) -> Result<SignedTransfer, Error> {
        let mut spend = self.lp_spend(lp_id).await?;
        let secret = self.spend_secret(lp_id)?;
        let built = self
            .build_transfer(&secret, &spend, dest, amount_sats)
            .await?;
        let hash = self.broadcast_transfer(&mut spend, &built).await?;
        Ok(SignedTransfer {
            tendermint_hash: hash,
            ..built.signed
        })
    }

    /// Select coins (skipping ones already in flight), pick a nonce, and sign.
    async fn build_transfer(
        &self,
        secret: &SecretKey,
        spend: &LpSpend,
        dest: &str,
        amount_sats: u64,
    ) -> Result<BuiltTransfer, Error> {
        let owner = parse_tachi_owner(dest)?;
        let pk = xonly_from_secret(secret);
        let pk_hex = hex::encode(pk);

        let unspent: Vec<_> = self
            .tachi
            .address_vtxos(&pk_hex)
            .await?
            .into_iter()
            .filter(|v| !spend.vtxos.contains(&v.id))
            .collect();
        let fee = self.tachi.recommended_fee_sats().await?;
        let need = amount_sats.saturating_add(fee);
        let (coins, total) = select_vtxos(&unspent, need)?;
        let nonce = spend.nonce(self.tachi.next_nonce(&pk_hex).await?);

        let inputs = coins
            .iter()
            .map(|v| {
                Ok(TransferInput {
                    vtxo_id: parse_vtxo_id(&v.id)?,
                    value_sats: v.amount,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let mut outputs = vec![TransferOutput {
            owner,
            amount: amount_sats,
        }];
        let change = total.saturating_sub(need);
        if change > 0 {
            outputs.push(TransferOutput {
                owner: pk,
                amount: change,
            });
        }

        let signed = sign_transfer(secret, &inputs, &outputs, fee, nonce)?;
        let mut own_outputs = Vec::new();
        if self.is_lp_key(&pk) {
            let raw = hex::decode(&signed.hex).map_err(|e| Error::Invalid(e.to_string()))?;
            if self.is_lp_key(&owner) {
                own_outputs.push(signed.output_vtxo_id.clone());
            }
            if change > 0 {
                own_outputs.push(hex::encode(output_vtxo_id(&raw, 1)));
            }
        }
        Ok(BuiltTransfer {
            signed,
            nonce,
            inputs: coins.into_iter().map(|v| v.id).collect(),
            own_outputs,
        })
    }

    async fn broadcast_transfer(
        &self,
        spend: &mut LpSpend,
        built: &BuiltTransfer,
    ) -> Result<String, Error> {
        if !built.own_outputs.is_empty() {
            self.inner
                .write()
                .await
                .own_vtxos
                .extend(built.own_outputs.iter().cloned());
            self.save_state().await;
        }
        match self.tachi.broadcast_tx_sync(&built.signed.hex).await {
            Ok(hash) => {
                spend.used(built);
                Ok(hash)
            }
            Err(Error::TachiRejected(why)) => {
                spend.forget_tachi();
                Err(Error::TachiRejected(why))
            }
            // Unknown outcome: assume it may land, so nothing reuses its coins.
            Err(err) => {
                spend.used(built);
                Err(err)
            }
        }
    }

    /// Ledger DEPOSIT (type 0x04). The daemon still requires a matching L1 vault
    /// funding; this is the on-Tachi half. Used to probe funding and to register
    /// a deposit after coins land in a TAURUS vault.
    pub async fn deposit_vtxo(
        &self,
        amount_sats: u64,
        lp_id: Option<&str>,
    ) -> Result<SignedTransfer, Error> {
        if amount_sats < MIN_SWAP_SATS {
            return Err(Error::AmountTooSmall(MIN_SWAP_SATS));
        }
        let w = match lp_id {
            Some(id) => self.lp_wallet(id)?,
            None => self.default_wallet(),
        };
        let mut spend = self.lp_spend(&w.id).await?;
        let lp_hex = hex::encode(xonly_from_secret(&w.secret));
        let nonce = spend.nonce(self.tachi.next_nonce(&lp_hex).await?);
        let fee = self.tachi.recommended_fee_sats().await?;
        let signed = sign_deposit(&w.secret, amount_sats, fee, nonce)?;
        let built = BuiltTransfer {
            own_outputs: vec![signed.output_vtxo_id.clone()],
            signed,
            nonce,
            inputs: Vec::new(),
        };
        let hash = self.broadcast_transfer(&mut spend, &built).await?;
        Ok(SignedTransfer {
            tendermint_hash: hash,
            ..built.signed
        })
    }

    /// Background pass: settle what was paid, claim what was settled, expire
    /// what is too close to its timeout, and reclaim unpaid outbound locks.
    /// Swaps someone else is working on right now are skipped, not waited on.
    /// Opened but never paid: after `UNPAID_SWAP_SECS` the swap stops holding
    /// desk stock. An inbound lock nobody funded, or an outbound swap whose
    /// lock is up (and past any deadline) with no VTXOs sent.
    async fn release_unpaid_swaps(&self) {
        let cutoff = Utc::now() - Duration::seconds(UNPAID_SWAP_SECS);
        let h = self.cached_height();
        let stale: Vec<Swap> = self
            .inner
            .read()
            .await
            .swaps
            .values()
            .filter(|s| s.status == SwapStatus::Quoted && s.created_at < cutoff)
            .filter(|s| match s.side {
                Side::In => s.l1_lock_txid.is_none() && s.faucet_txid.is_none(),
                Side::Out => {
                    s.vtxo_payment_id.is_none()
                        && s.l1_lock_txid.is_some()
                        && s.lock_by_height.is_none_or(|by| h >= by + UNPAID_SWAP_BLOCKS)
                }
            })
            .cloned()
            .collect();
        for swap in stale {
            let Ok(_guard) = self.swap_mutex(swap.id).try_lock_owned() else {
                continue;
            };
            // A lock paid by an outside wallet only shows on chain; never
            // release a swap whose user did pay.
            if swap.side == Side::In && !self.test_mode {
                match self.scan_htlc(&swap).await {
                    Ok(None) => {}
                    _ => continue,
                }
            }
            let Ok(current) = self.get_swap(swap.id).await else {
                continue;
            };
            if current.status != SwapStatus::Quoted || current.updated_at != swap.updated_at {
                continue;
            }
            credit_lp(
                &mut self.inner.write().await.lps,
                &swap.lp_id,
                swap.side,
                reserve_sats(swap.side, swap.receive_sats),
            );
            let timeout = swap.pay.htlc().map(|l| l.timeout_height).unwrap_or_default();
            let note = match swap.side {
                Side::In => format!(
                    "Nobody paid the lock within an hour, so the desk released the stock. If you pay it anyway, refund it after block {timeout}."
                ),
                Side::Out => format!(
                    "No Tachi coins arrived within an hour, so the swap expired. Do not send them now; the desk takes its lock back after block {timeout}."
                ),
            };
            if let Err(err) = self
                .update_swap(swap.id, |s| {
                    s.status = SwapStatus::Expired;
                    s.demo_note = Some(note);
                })
                .await
            {
                tracing::warn!(%err, id = %swap.id, "release unpaid swap");
            }
        }
    }

    pub async fn sync_all(&self) -> Result<Vec<Swap>, Error> {
        let released = release_expired_quotes(&mut *self.inner.write().await);
        if released {
            self.save_state().await;
        }
        self.release_unpaid_swaps().await;
        if !self.test_mode {
            self.fund_due_outbound_locks().await;
        }
        let ids: Vec<Uuid> = self
            .inner
            .read()
            .await
            .swaps
            .values()
            .filter(|s| needs_sync(s))
            .map(|s| s.id)
            .collect();
        let mut updated = Vec::new();
        for id in ids {
            let Ok(_guard) = self.swap_mutex(id).try_lock_owned() else {
                continue;
            };
            match self.sync_locked(id).await {
                Ok(Some(s)) => updated.push(s),
                Ok(None) => {}
                Err(err) => tracing::warn!(%id, %err, "sync swap"),
            }
        }
        self.sync_advances().await;
        self.sync_ln_swaps().await;
        Ok(updated)
    }

    pub async fn sync_swap(&self, id: Uuid) -> Result<Option<Swap>, Error> {
        self.refresh_height().await;
        if !self.test_mode {
            // A due lock goes out with whatever else is due, not on its own.
            self.fund_due_outbound_locks().await;
        }
        let _guard = self.lock_swap(id).await;
        self.sync_locked(id).await
    }

    async fn sync_locked(&self, id: Uuid) -> Result<Option<Swap>, Error> {
        let before = self.get_swap(id).await?;
        if self.test_mode || !needs_sync(&before) {
            return Ok(None);
        }
        let h = self.known_height().await?;
        let near_timeout = before
            .pay
            .htlc()
            .is_some_and(|l| h + SAFETY_MARGIN_BLOCKS >= l.timeout_height);
        if compensation_owed(&before) {
            self.pay_compensation(&before).await?;
        }
        match (before.side, before.status) {
            (Side::In, SwapStatus::Quoted) => {
                if near_timeout {
                    self.expire(id).await?;
                } else if self.scan_htlc(&before).await?.is_some() {
                    self.observe_lock_inner(id, ObserveLockRequest::default())
                        .await?;
                }
            }
            (Side::In, SwapStatus::LpSettled) => {
                self.claim_inbound_inner(id).await?;
            }
            (Side::In, SwapStatus::Claimed) => {
                self.bump_desk_claim(&before, h).await?;
            }
            (Side::Out, SwapStatus::Quoted) => {
                if let Err(err) = self.fund_outbound_lock(id).await {
                    tracing::warn!(%id, %err, "outbound lock");
                }
                let paid = match before.vtxo_payment_id.clone() {
                    Some(p) => self.tachi.find_vtxo(&p).await?.map(|_| p),
                    None => self.new_inbound_vtxo(&before).await?,
                };
                if let Some(vtxo_id) = paid {
                    self.observe_vtxo_inner(id, &vtxo_id).await?;
                } else if near_timeout && before.vtxo_payment_id.is_none() {
                    self.expire(id).await?;
                }
            }
            // The user paid; make sure the desk's lock exists for them to claim.
            (Side::Out, SwapStatus::LpSettled) => {
                self.fund_outbound_lock(id).await?;
            }
            (Side::Out, SwapStatus::Expired | SwapStatus::Refunded | SwapStatus::Failed) => {
                self.lp_refund_outbound(&before, h).await?;
            }
            _ => {}
        }
        let after = self.get_swap(id).await?;
        Ok((after.updated_at != before.updated_at).then_some(after))
    }

    async fn scan_htlc(&self, swap: &Swap) -> Result<Option<ObserveLockRequest>, Error> {
        let Some(lock) = swap.pay.htlc() else {
            return Ok(None);
        };
        let need = if swap.side == Side::Out {
            swap.receive_sats
        } else {
            swap.amount_sats
        };
        // Mempool-aware first, so a just-broadcast lock counts.
        if let Some(txid) = swap.l1_lock_txid.as_deref() {
            let vouts = match swap.l1_lock_vout {
                Some(v) => v..v + 1,
                None => 0..2,
            };
            for vout in vouts {
                if let Ok(Some(u)) = self.tachi.get_tx_out(txid, vout).await
                    && u.value_sats >= need
                {
                    return Ok(Some(ObserveLockRequest {
                        txid: u.txid,
                        vout: u.vout,
                        value_sats: u.value_sats,
                    }));
                }
            }
        }
        let utxos = self.tachi.scan_address(&lock.address).await?;
        Ok(utxos
            .into_iter()
            .find(|u| u.value_sats >= need)
            .map(|u| ObserveLockRequest {
                txid: u.txid,
                vout: u.vout,
                value_sats: u.value_sats,
            }))
    }

    /// Find the user's payment for an outbound swap without being told its id.
    /// Tachi transfers carry no memo, so this only matches when it is
    /// unambiguous: a new coin of exactly the swap amount that is not the
    /// desk's own, not already credited, and no other open swap on this desk
    /// is waiting for the same amount.
    async fn new_inbound_vtxo(&self, swap: &Swap) -> Result<Option<String>, Error> {
        let (baseline, used, own) = {
            let inner = self.inner.read().await;
            let Some(baseline) = inner.baseline_vtxos.get(&swap.id).cloned() else {
                return Ok(None);
            };
            let rivals = inner.swaps.values().any(|s| {
                s.id != swap.id
                    && s.side == Side::Out
                    && s.status == SwapStatus::Quoted
                    && s.lp_id == swap.lp_id
                    && s.amount_sats == swap.amount_sats
                    && s.vtxo_payment_id.is_none()
            });
            if rivals {
                return Ok(None);
            }
            let used: HashSet<String> = inner
                .swaps
                .values()
                .filter_map(|s| s.vtxo_payment_id.clone())
                .collect();
            (baseline, used, inner.own_vtxos.clone())
        };
        let pk = hex::encode(xonly_from_secret(&self.lp_wallet(&swap.lp_id)?.secret));
        let vtxos = self.tachi.address_vtxos(&pk).await?;
        Ok(vtxos
            .into_iter()
            .filter(|v| {
                !v.spent
                    && !v.locked
                    && v.amount == swap.amount_sats
                    && !baseline.contains(&v.id)
                    && !own.contains(&v.id)
                    && !used.contains(&v.id)
            })
            .map(|v| v.id)
            .next())
    }

    /// Sign an L1 payment from the desk's claim address. Coins picked here are
    /// held until restart so a second payment never double-spends them while
    /// the first is unconfirmed (`scantxoutset` only sees confirmed coins).
    async fn sign_l1_payment(
        &self,
        lp_id: &str,
        outputs: &[(String, u64)],
    ) -> Result<(String, Vec<OutPoint>), Error> {
        let outputs = outputs
            .iter()
            .map(|(dest, sats)| {
                let addr = dest
                    .parse::<Address<bitcoin::address::NetworkUnchecked>>()
                    .map_err(|_| Error::Invalid(format!("{dest} is not a bitcoin address")))?
                    .require_network(self.network)
                    .map_err(|e| {
                        Error::Invalid(format!("{dest} must be a {} address: {e}", self.network))
                    })?;
                Ok((addr, *sats))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let amount_sats: u64 = outputs.iter().map(|(_, v)| *v).sum();
        let mut spend = self.lp_spend(lp_id).await?;
        let w = self.lp_wallet(lp_id)?;
        let confirmed = self
            .tachi
            .scan_address(&w.claim_address.to_string())
            .await?
            .into_iter()
            .map(|u| Ok((OutPoint { txid: parse_txid(&u.txid)?, vout: u.vout }, u.value_sats)))
            .collect::<Result<Vec<_>, Error>>()?;
        // The fee grows with each input picked (outputs + change).
        let fee_with = |inputs: usize| self.fee_for(p2wpkh_send_vbytes(inputs, outputs.len() + 1));
        let mut picked: Vec<(OutPoint, u64)> = Vec::new();
        let mut total = 0u64;
        for (op, value) in spend.spendable_l1(&confirmed) {
            // A pending coin must still be in the mempool: if its parent was
            // dropped or it was spent elsewhere, forget it.
            if spend.pending.contains_key(&op)
                && !matches!(
                    self.tachi.get_tx_out(&op.txid.to_string(), op.vout).await,
                    Ok(Some(_))
                )
            {
                spend.pending.remove(&op);
                continue;
            }
            picked.push((op, value));
            total += value;
            if total >= amount_sats + fee_with(picked.len()) {
                break;
            }
        }
        // One fee for the whole tx: batching is where deadline swaps save.
        let hex = p2wpkh_send_many_hex(
            &picked,
            &outputs,
            fee_with(picked.len()),
            &w.claim_address,
            &w.secret,
            self.network,
        )?;
        let inputs: Vec<OutPoint> = picked.into_iter().map(|(op, _)| op).collect();
        spend.l1.extend(inputs.iter().copied());
        Ok((hex, inputs))
    }

    /// Broadcast via Tachi's bitcoind. A tx the node already has counts as
    /// sent. Any output paying a desk becomes that desk's pending coin.
    async fn broadcast_l1(&self, hex_tx: &str) -> Result<String, Error> {
        let txid = txid_of_hex(hex_tx)?.to_string();
        let sent = match self.tachi.send_raw_tx(hex_tx).await {
            Ok(sent) => sent,
            Err(Error::TachiRejected(why)) if why.contains("already") => txid,
            Err(err) => return Err(err),
        };
        self.note_desk_outputs(hex_tx).await;
        Ok(sent)
    }

    async fn note_desk_outputs(&self, hex_tx: &str) {
        for w in &self.wallets {
            let mine = outputs_to(hex_tx, &w.claim_address.script_pubkey());
            if mine.is_empty() {
                continue;
            }
            if let Ok(mut spend) = self.lp_spend(&w.id).await {
                spend.pending.extend(mine);
            }
        }
    }

    /// The hosted faucet's payout, once bitcoind shows it (mempool-aware).
    async fn wait_for_faucet_coin(&self, faucet_txid: &str) -> Result<crate::tachi::ChainUtxo, Error> {
        for _ in 0..25 {
            for vout in 0..4u32 {
                if let Ok(Some(u)) = self.tachi.get_tx_out(faucet_txid, vout).await {
                    return Ok(u);
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        }
        Err(Error::Tachi(
            "faucet paid but the coin is not visible on RPC yet — try again".into(),
        ))
    }
}

/// Claim advances (#8): the desk buys a maturing timelocked output.
impl Engine {
    pub async fn list_advances(&self) -> Vec<Advance> {
        let mut v: Vec<_> = self.inner.read().await.advances.values().cloned().collect();
        v.sort_by_key(|a| std::cmp::Reverse(a.updated_at));
        v
    }

    pub async fn get_advance(&self, id: Uuid) -> Result<Advance, Error> {
        self.inner
            .read()
            .await
            .advances
            .get(&id)
            .cloned()
            .ok_or_else(|| Error::Invalid(format!("unknown advance {id}")))
    }

    async fn update_advance(&self, id: Uuid, f: impl FnOnce(&mut Advance)) -> Result<Advance, Error> {
        let out = {
            let mut inner = self.inner.write().await;
            let a = inner
                .advances
                .get_mut(&id)
                .ok_or_else(|| Error::Invalid(format!("unknown advance {id}")))?;
            f(a);
            a.updated_at = Utc::now();
            a.clone()
        };
        self.save_state().await;
        self.publish(Event::Advance(Box::new(out.clone()))).await;
        Ok(out)
    }

    /// Price an advance on a confirmed CSV output. Reserves the desk's L1.
    pub async fn quote_advance(&self, req: AdvanceQuoteRequest) -> Result<Advance, Error> {
        if self.test_mode {
            return Err(Error::Invalid("claim advances need a live chain".into()));
        }
        let script = redeem_from_hex(&req.witness_script_hex)?;
        let (csv_blocks, _) = parse_csv_script(&script).ok_or_else(|| {
            Error::Invalid(
                "unsupported script: expected <csv> OP_CSV OP_DROP <pubkey> OP_CHECKSIG".into(),
            )
        })?;
        let user_l1 = req
            .user_l1_address
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .map_err(|_| Error::Invalid("user_l1_address is not a bitcoin address".into()))?
            .require_network(self.network)
            .map_err(|e| Error::Invalid(format!("user_l1_address: {e}")))?;
        let info = self
            .tachi
            .confirmed_tx_out(&req.txid, req.vout)
            .await?
            .ok_or_else(|| {
                Error::Invalid("output not found: unconfirmed, spent, or never existed".into())
            })?;
        if info.script_pubkey_hex != hex::encode(p2wsh(&script, self.network).script_pubkey().as_bytes()) {
            return Err(Error::Invalid("witness script does not match the output".into()));
        }
        parse_txid(&req.txid)?;
        let tip = self.fresh_height().await?;
        // BIP68: the spend can be mined at `confirm_height + csv`.
        let mature_height = tip + 1 - info.confirmations + csv_blocks;
        let blocks_left = mature_height.saturating_sub(tip + 1);
        let min_desk_sats = info.value_sats.saturating_sub(MAX_SPEND_FEE_SATS);
        let discount = discount_sats(info.value_sats, blocks_left);
        let advance_sats = min_desk_sats
            .saturating_sub(discount)
            .saturating_sub(CLAIM_FEE_SATS);
        if advance_sats < MIN_SWAP_SATS {
            return Err(Error::AmountTooSmall(MIN_SWAP_SATS + discount + MAX_SPEND_FEE_SATS));
        }

        let id = Uuid::now_v7();
        let now = Utc::now();
        let advance = {
            let mut inner = self.inner.write().await;
            if inner.advances.values().any(|a| {
                a.outpoint_txid == req.txid
                    && a.outpoint_vout == req.vout
                    && matches!(a.status, AdvanceStatus::Quoted | AdvanceStatus::Advanced)
            }) {
                return Err(Error::Invalid("this output already has an open advance".into()));
            }
            let lp = inner
                .lps
                .iter()
                .filter(|lp| routable(lp) && lp.l1_sats >= advance_sats + CLAIM_FEE_SATS)
                .max_by_key(|lp| lp.l1_sats)
                .cloned()
                .ok_or(Error::NoLiquidity {
                    side: Side::Out,
                    amount_sats: advance_sats,
                })?;
            let w = self.lp_wallet(&lp.id)?;
            let advance = Advance {
                id,
                lp_id: lp.id.clone(),
                status: AdvanceStatus::Quoted,
                outpoint_txid: req.txid.clone(),
                outpoint_vout: req.vout,
                value_sats: info.value_sats,
                witness_script_hex: req.witness_script_hex.clone(),
                csv_blocks,
                mature_height,
                desk_address: w.claim_address.to_string(),
                min_desk_sats,
                discount_sats: discount,
                advance_sats,
                user_l1_address: user_l1.to_string(),
                expires_at: now + Duration::seconds(SIDE_QUOTE_TTL_SECS),
                advance_txid: None,
                presigned_tx_hex: None,
                collect_txid: None,
                note: Some(format!(
                    "Sign a spend of {}:{} paying at least {min_desk_sats} sats to {}, with sequence {csv_blocks}. The desk pays you {advance_sats} sats now and broadcasts your spend at block {mature_height}.",
                    req.txid, req.vout, w.claim_address
                )),
                created_at: now,
                updated_at: now,
            };
            debit_lp(&mut inner.lps, &lp.id, Side::Out, advance_sats + CLAIM_FEE_SATS)?;
            inner.advances.insert(id, advance.clone());
            advance
        };
        self.save_state().await;
        self.publish(Event::Advance(Box::new(advance.clone()))).await;
        Ok(advance)
    }

    /// Verify the user's pre-signed spend, then pay the advance.
    pub async fn accept_advance(&self, id: Uuid, req: AdvanceAcceptRequest) -> Result<Advance, Error> {
        let _guard = self.lock_swap(id).await;
        let a = self.get_advance(id).await?;
        if a.status != AdvanceStatus::Quoted {
            return Err(Error::Invalid(format!("advance is {:?}", a.status)));
        }
        if a.expires_at < Utc::now() {
            self.expire_advance(&a).await?;
            return Err(Error::QuoteExpired);
        }
        let script = redeem_from_hex(&a.witness_script_hex)?;
        let (csv_blocks, owner) =
            parse_csv_script(&script).ok_or_else(|| Error::Invalid("stored script".into()))?;
        let desk_address = a
            .desk_address
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .map_err(|_| Error::Invalid("desk address".into()))?
            .assume_checked();
        let outpoint = OutPoint {
            txid: parse_txid(&a.outpoint_txid)?,
            vout: a.outpoint_vout,
        };
        verify_presigned(
            &req.presigned_tx_hex,
            &ExpectedSpend {
                outpoint,
                value_sats: a.value_sats,
                script: &script,
                csv_blocks,
                owner: &owner,
                desk_address: &desk_address,
                min_desk_sats: a.min_desk_sats,
            },
        )?;
        if self
            .tachi
            .confirmed_tx_out(&a.outpoint_txid, a.outpoint_vout)
            .await?
            .is_none()
        {
            return Err(Error::Invalid("the output was already spent".into()));
        }

        let (hex, inputs) = self
            .sign_l1_payment(&a.lp_id, &[(a.user_l1_address.clone(), a.advance_sats)])
            .await?;
        let txid = txid_of_hex(&hex)?.to_string();
        // Recorded before broadcast: a lost reply must not lead to paying twice.
        self.inner.write().await.pending_advance_txs.insert(id, hex.clone());
        let presigned = req.presigned_tx_hex.trim().to_string();
        let t = txid.clone();
        let a = self
            .update_advance(id, |a| {
                a.status = AdvanceStatus::Advanced;
                a.advance_txid = Some(t);
                a.presigned_tx_hex = Some(presigned);
                a.note = Some(format!(
                    "Desk paid {} sats now. It collects your output at block {}.",
                    a.advance_sats, a.mature_height
                ));
            })
            .await?;
        match self.broadcast_l1(&hex).await {
            Ok(_) => {}
            Err(Error::TachiRejected(why)) => {
                {
                    let mut spend = self.lp_spend(&a.lp_id).await?;
                    for op in &inputs {
                        spend.l1.remove(op);
                    }
                }
                self.inner.write().await.pending_advance_txs.remove(&id);
                let note = format!("Desk payout was rejected ({why}); try again.");
                self.update_advance(id, |a| {
                    a.status = AdvanceStatus::Quoted;
                    a.advance_txid = None;
                    a.presigned_tx_hex = None;
                    a.note = Some(note);
                })
                .await?;
                return Err(Error::TachiRejected(why));
            }
            // Unknown outcome: the signed payout is kept and re-sent by sync.
            Err(err) => tracing::warn!(%err, %id, "advance payout broadcast"),
        }
        Ok(a)
    }

    /// Sign the user's spend for an advance with their demo key (a wallet's job).
    pub async fn demo_presign_advance(&self, id: Uuid, secret_hex: &str) -> Result<String, Error> {
        let a = self.get_advance(id).await?;
        let secret = parse_secret(secret_hex)?;
        let script = redeem_from_hex(&a.witness_script_hex)?;
        let desk = a
            .desk_address
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .map_err(|_| Error::Invalid("desk address".into()))?
            .assume_checked();
        presign_spend(
            OutPoint {
                txid: parse_txid(&a.outpoint_txid)?,
                vout: a.outpoint_vout,
            },
            a.value_sats,
            &script,
            a.csv_blocks,
            &secret,
            &desk,
            a.min_desk_sats,
        )
    }

    /// Demo: faucet coins into a CSV-locked output owned by `pubkey_hex` — a
    /// stand-in for a vault refund still waiting out its delay.
    pub async fn demo_csv_lock(
        &self,
        pubkey_hex: &str,
        csv_blocks: u32,
        amount_sats: u64,
    ) -> Result<serde_json::Value, Error> {
        if self.test_mode {
            return Err(Error::Invalid("needs the live faucet".into()));
        }
        if !(1..=VAULT_EXIT_BLOCKS).contains(&csv_blocks) {
            return Err(Error::Invalid(format!("csv_blocks must be 1..={VAULT_EXIT_BLOCKS}")));
        }
        if !(20_000..=200_000).contains(&amount_sats) {
            return Err(Error::Invalid("amount_sats must be 20000..=200000".into()));
        }
        let owner = pubkey_from_hex(pubkey_hex)?;
        let script = csv_script(csv_blocks, &owner);
        let lock = p2wsh(&script, self.network);
        let sk = generate_keypair().secret;
        let from = p2wpkh_address(&sk, self.network);
        let drip = (amount_sats + 20_000) as f64 / 100_000_000.0;
        let faucet_txid = crate::faucet::drip(&from.to_string(), drip).await?;
        let u = self.wait_for_faucet_coin(&faucet_txid).await?;
        let hex = p2wpkh_send_hex(
            &[(
                OutPoint {
                    txid: parse_txid(&u.txid)?,
                    vout: u.vout,
                },
                u.value_sats,
            )],
            &lock,
            amount_sats,
            300,
            &from,
            &sk,
            self.network,
        )?;
        let txid = self.broadcast_l1(&hex).await?;
        Ok(serde_json::json!({
            "txid": txid,
            "vout": 0,
            "value_sats": amount_sats,
            "address": lock.to_string(),
            "csv_blocks": csv_blocks,
            "witness_script_hex": hex::encode(script.as_bytes()),
            "note": "Quote an advance once this confirms (next block).",
        }))
    }

    async fn expire_advance(&self, a: &Advance) -> Result<(), Error> {
        {
            let mut inner = self.inner.write().await;
            credit_lp(&mut inner.lps, &a.lp_id, Side::Out, a.advance_sats + CLAIM_FEE_SATS);
        }
        self.update_advance(a.id, |a| {
            a.status = AdvanceStatus::Expired;
            a.note = Some("Quote expired before a signed spend arrived.".into());
        })
        .await
        .map(|_| ())
    }

    /// Expire stale quotes, re-send unconfirmed payouts, collect at maturity.
    async fn sync_advances(&self) {
        let open: Vec<Advance> = self
            .inner
            .read()
            .await
            .advances
            .values()
            .filter(|a| matches!(a.status, AdvanceStatus::Quoted | AdvanceStatus::Advanced))
            .cloned()
            .collect();
        if open.is_empty() || self.test_mode {
            return;
        }
        let Ok(h) = self.known_height().await else {
            return;
        };
        for a in open {
            let Ok(_guard) = self.swap_mutex(a.id).try_lock_owned() else {
                continue;
            };
            if let Err(err) = self.sync_advance(a, h).await {
                tracing::warn!(%err, "sync advance");
            }
        }
    }

    async fn sync_advance(&self, a: Advance, h: u32) -> Result<(), Error> {
        let a = self.get_advance(a.id).await?;
        match a.status {
            AdvanceStatus::Quoted if a.expires_at < Utc::now() => self.expire_advance(&a).await,
            AdvanceStatus::Advanced => {
                let pending = self.inner.read().await.pending_advance_txs.get(&a.id).cloned();
                if let (Some(hex), Some(txid)) = (pending, a.advance_txid.as_deref()) {
                    if self.tachi.get_tx_out(txid, 0).await?.is_some() {
                        self.inner.write().await.pending_advance_txs.remove(&a.id);
                    } else if let Err(err) = self.broadcast_l1(&hex).await {
                        tracing::warn!(%err, id = %a.id, "advance payout re-send");
                    }
                }
                if h + 1 < a.mature_height {
                    return Ok(());
                }
                let presigned = a.presigned_tx_hex.clone().unwrap_or_default();
                match self.broadcast_l1(&presigned).await {
                    Ok(txid) => {
                        self.record_fill(&a.lp_id).await;
                        self.update_advance(a.id, |a| {
                            a.status = AdvanceStatus::Collected;
                            a.collect_txid = Some(txid.clone());
                            a.note = Some(format!("Desk collected the output ({txid})."));
                        })
                        .await?;
                    }
                    Err(Error::TachiRejected(why)) => {
                        let gone = self
                            .tachi
                            .confirmed_tx_out(&a.outpoint_txid, a.outpoint_vout)
                            .await?
                            .is_none();
                        if gone {
                            self.update_advance(a.id, |a| {
                                a.status = AdvanceStatus::Lost;
                                a.note = Some(format!(
                                    "The output was spent elsewhere before the desk collected ({why})."
                                ));
                            })
                            .await?;
                        }
                    }
                    Err(err) => return Err(err),
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// VTXO ↔ Lightning swaps (#9).
impl Engine {
    fn ln(&self) -> Result<&LightningNode, Error> {
        self.lightning.as_ref().ok_or_else(|| {
            Error::Invalid("Lightning is not configured on this desk (set LND_REST_URL)".into())
        })
    }

    pub async fn list_ln_swaps(&self) -> Vec<LnSwap> {
        let mut v: Vec<_> = self.inner.read().await.ln_swaps.values().cloned().collect();
        v.sort_by_key(|l| std::cmp::Reverse(l.updated_at));
        v
    }

    pub async fn get_ln_swap(&self, id: Uuid) -> Result<LnSwap, Error> {
        self.inner
            .read()
            .await
            .ln_swaps
            .get(&id)
            .cloned()
            .ok_or(Error::SwapNotFound)
    }

    async fn update_ln(&self, id: Uuid, f: impl FnOnce(&mut LnSwap)) -> Result<LnSwap, Error> {
        let out = {
            let mut inner = self.inner.write().await;
            let l = inner.ln_swaps.get_mut(&id).ok_or(Error::SwapNotFound)?;
            f(l);
            l.updated_at = Utc::now();
            l.clone()
        };
        self.save_state().await;
        self.publish(Event::Ln(Box::new(out.clone()))).await;
        Ok(out)
    }

    pub async fn ln_quote(&self, req: LnQuoteRequest) -> Result<LnSwap, Error> {
        let ln = self.ln()?.clone();
        let id = Uuid::now_v7();
        let now = Utc::now();
        let expires_at = now + Duration::seconds(SIDE_QUOTE_TTL_SECS);
        let user_tachi = req
            .user_tachi_address
            .clone()
            .filter(|a| self.test_mode || looks_like_tachi_owner(a))
            .ok_or_else(|| Error::Invalid("user_tachi_address must be a Tachi key".into()))?;
        let swap = match req.direction {
            LnDirection::In => {
                let amount = req
                    .amount_sats
                    .ok_or_else(|| Error::Invalid("amount_sats is required for in".into()))?;
                if !(MIN_SWAP_SATS..=MAX_SWAP_SATS).contains(&amount) {
                    return Err(Error::Invalid(format!(
                        "amount_sats must be {MIN_SWAP_SATS}..={MAX_SWAP_SATS}"
                    )));
                }
                let (lp_id, fee) = {
                    let mut inner = self.inner.write().await;
                    let (lp_id, fee) = inner
                        .lps
                        .iter()
                        .filter(|lp| can_fill(lp, Side::In, amount))
                        .map(|lp| {
                            let p = price(&self.pricing, lp, Side::In, amount, SIDE_QUOTE_TTL_SECS as u64, 0);
                            (lp.id.clone(), fee_sats(amount, p.fee_ppm, MIN_FEE_SATS))
                        })
                        .min_by_key(|(_, fee)| *fee)
                        .ok_or(Error::NoLiquidity {
                            side: Side::In,
                            amount_sats: amount,
                        })?;
                    debit_lp(&mut inner.lps, &lp_id, Side::In, amount - fee)?;
                    (lp_id, fee)
                };
                let preimage = random_preimage();
                let hash = payment_hash(&preimage).to_byte_array();
                let invoice = match ln
                    .add_hold_invoice(&hash, amount, &format!("tachi-flow {id}"), SIDE_QUOTE_TTL_SECS as u64)
                    .await
                {
                    Ok(inv) => inv,
                    Err(err) => {
                        credit_lp(&mut self.inner.write().await.lps, &lp_id, Side::In, amount - fee);
                        return Err(err);
                    }
                };
                self.inner.write().await.preimages.insert(id, preimage);
                LnSwap {
                    id,
                    direction: LnDirection::In,
                    status: LnStatus::Waiting,
                    lp_id,
                    amount_sats: amount,
                    fee_sats: fee,
                    receive_sats: amount - fee,
                    payment_hash_hex: hex::encode(hash),
                    invoice,
                    tachi_address: user_tachi,
                    refund_tachi_address: None,
                    vtxo_payment_id: None,
                    note: Some("Pay this invoice. Your payment is only held until the desk has sent your VTXOs; if it never does, the invoice is cancelled and Lightning returns your funds.".into()),
                    expires_at,
                    created_at: now,
                    updated_at: now,
                }
            }
            LnDirection::Out => {
                let invoice = req
                    .invoice
                    .clone()
                    .ok_or_else(|| Error::Invalid("invoice is required for out".into()))?;
                let decoded = ln.decode(&invoice).await?;
                if decoded.amount_sats < 1_000 {
                    return Err(Error::Invalid(
                        "invoice must carry an amount of at least 1000 sats".into(),
                    ));
                }
                let lp = {
                    let inner = self.inner.read().await;
                    inner
                        .lps
                        .iter()
                        .filter(|lp| routable(lp))
                        .min_by_key(|lp| lp.fee_ppm)
                        .cloned()
                        .ok_or(Error::NoLiquidity {
                            side: Side::Out,
                            amount_sats: decoded.amount_sats,
                        })?
                };
                let fee = fee_sats(decoded.amount_sats, lp.fee_ppm, MIN_FEE_SATS)
                    + LN_MAX_ROUTING_FEE_SATS;
                let pay_to = hex::encode(xonly_from_secret(&self.lp_wallet(&lp.id)?.secret));
                LnSwap {
                    id,
                    direction: LnDirection::Out,
                    status: LnStatus::Waiting,
                    lp_id: lp.id,
                    amount_sats: decoded.amount_sats + fee,
                    fee_sats: fee,
                    receive_sats: decoded.amount_sats,
                    payment_hash_hex: hex::encode(decoded.payment_hash),
                    invoice,
                    tachi_address: pay_to,
                    refund_tachi_address: Some(user_tachi),
                    vtxo_payment_id: None,
                    note: Some(format!(
                        "Send {} sats of VTXOs to the desk key; it then pays your invoice. If the payment fails outright, your VTXOs come back.",
                        decoded.amount_sats + fee
                    )),
                    expires_at,
                    created_at: now,
                    updated_at: now,
                }
            }
        };
        self.inner.write().await.ln_swaps.insert(id, swap.clone());
        self.save_state().await;
        self.publish(Event::Ln(Box::new(swap.clone()))).await;
        Ok(swap)
    }

    /// `out`: credit the user's VTXO payment, then pay their invoice.
    pub async fn ln_paid(&self, id: Uuid, vtxo_id: &str) -> Result<LnSwap, Error> {
        let _guard = self.lock_swap(id).await;
        let s = self.get_ln_swap(id).await?;
        if s.direction != LnDirection::Out || s.status != LnStatus::Waiting {
            return Err(Error::Invalid(format!("Lightning swap is {:?}", s.status)));
        }
        {
            let inner = self.inner.read().await;
            let credited = inner
                .swaps
                .values()
                .filter_map(|x| x.vtxo_payment_id.as_deref())
                .chain(inner.ln_swaps.values().filter_map(|x| x.vtxo_payment_id.as_deref()))
                .any(|v| v == vtxo_id);
            if credited || inner.own_vtxos.contains(vtxo_id) {
                return Err(Error::Invalid(format!("vtxo {vtxo_id} is not a fresh payment")));
            }
        }
        if !self.test_mode {
            let vtxo = self.tachi.get_vtxo(vtxo_id).await?;
            if !vtxo.owner.eq_ignore_ascii_case(&s.tachi_address) || vtxo.amount < s.amount_sats {
                return Err(Error::Invalid(format!(
                    "vtxo {vtxo_id} must pay at least {} sats to {}",
                    s.amount_sats, s.tachi_address
                )));
            }
        }
        let v = vtxo_id.to_string();
        self.update_ln(id, |l| {
            l.status = LnStatus::Accepted;
            l.vtxo_payment_id = Some(v);
            l.note = Some("Desk has your VTXOs and is paying your invoice.".into());
        })
        .await?;
        self.ln_pay_out(id).await
    }

    /// Demo helper: pay an `out` swap from the user's demo key, then credit it.
    pub async fn ln_pay_from_demo(&self, id: Uuid, secret_hex: &str) -> Result<LnSwap, Error> {
        let s = self.get_ln_swap(id).await?;
        if self.test_mode {
            return self.ln_paid(id, &format!("sim-ln-{id}")).await;
        }
        let secret = parse_secret(secret_hex)?;
        let mut spend = LpSpend::default();
        let built = self
            .build_transfer(&secret, &spend, &s.tachi_address, s.amount_sats)
            .await?;
        self.broadcast_transfer(&mut spend, &built).await?;
        let paid = built.signed.output_vtxo_id;
        for _ in 0..10 {
            if self.tachi.find_vtxo(&paid).await?.is_some() {
                return self.ln_paid(id, &paid).await;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        Err(Error::Tachi(format!(
            "payment {paid} sent but not visible yet; report it with POST /v1/ln/{id}/paid"
        )))
    }

    /// Pay an accepted `out` swap's invoice. Re-running is safe: a node never
    /// pays the same payment hash twice.
    async fn ln_pay_out(&self, id: Uuid) -> Result<LnSwap, Error> {
        let ln = self.ln()?.clone();
        let s = self.get_ln_swap(id).await?;
        match ln.pay(&s.invoice, LN_MAX_ROUTING_FEE_SATS).await {
            Ok(preimage) => {
                let ok = hex::encode(payment_hash(&preimage).to_byte_array()) == s.payment_hash_hex;
                self.record_fill(&s.lp_id).await;
                self.update_ln(id, |l| {
                    l.status = LnStatus::Completed;
                    l.note = Some(if ok {
                        format!("Invoice paid. Preimage {} is your receipt.", hex::encode(preimage))
                    } else {
                        "Invoice paid, but the node returned a preimage that does not match.".into()
                    });
                })
                .await
            }
            Err(Error::TachiRejected(why)) => {
                // The payment definitively failed: give the VTXOs back.
                let refund = s.refund_tachi_address.clone().unwrap_or_default();
                let back = if self.test_mode {
                    format!("sim-ln-refund-{id}")
                } else {
                    self.settle_payout(id, &s.lp_id, &refund, s.amount_sats.saturating_sub(1))
                        .await?
                        .output_vtxo_id
                };
                self.inner.write().await.pending_payouts.remove(&id);
                self.update_ln(id, |l| {
                    l.status = LnStatus::Failed;
                    l.note = Some(format!(
                        "Lightning payment failed ({why}); your VTXOs were returned ({back})."
                    ));
                })
                .await
            }
            Err(err) => {
                let note = format!("Paying the invoice did not finish ({err}); retrying.");
                self.update_ln(id, |l| l.note = Some(note)).await?;
                Err(err)
            }
        }
    }

    async fn sync_ln_swaps(&self) {
        if self.lightning.is_none() {
            return;
        }
        let open: Vec<Uuid> = self
            .inner
            .read()
            .await
            .ln_swaps
            .values()
            .filter(|l| matches!(l.status, LnStatus::Waiting | LnStatus::Accepted))
            .map(|l| l.id)
            .collect();
        for id in open {
            let Ok(_guard) = self.swap_mutex(id).try_lock_owned() else {
                continue;
            };
            if let Err(err) = self.sync_ln(id).await {
                tracing::warn!(%err, %id, "sync lightning swap");
            }
        }
    }

    async fn sync_ln(&self, id: Uuid) -> Result<(), Error> {
        let ln = self.ln()?.clone();
        let s = self.get_ln_swap(id).await?;
        match (s.direction, s.status) {
            (LnDirection::In, LnStatus::Waiting | LnStatus::Accepted) => {
                let hash: [u8; 32] = hex::decode(&s.payment_hash_hex)
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| Error::Invalid("stored payment hash".into()))?;
                match ln.invoice_state(&hash).await? {
                    InvoiceState::Accepted => {
                        // The user's HTLC is held: pay VTXOs first, then settle.
                        let paid = if self.test_mode {
                            format!("sim-ln-vtxo-{id}")
                        } else {
                            self.settle_payout(id, &s.lp_id, &s.tachi_address, s.receive_sats)
                                .await?
                                .output_vtxo_id
                        };
                        let p = paid.clone();
                        self.update_ln(id, |l| {
                            l.status = LnStatus::Accepted;
                            l.vtxo_payment_id = Some(p);
                        })
                        .await?;
                        let preimage = self
                            .inner
                            .read()
                            .await
                            .preimages
                            .get(&id)
                            .copied()
                            .ok_or_else(|| Error::Invalid("missing preimage".into()))?;
                        ln.settle(&preimage).await?;
                        self.inner.write().await.pending_payouts.remove(&id);
                        self.record_fill(&s.lp_id).await;
                        self.update_ln(id, |l| {
                            l.status = LnStatus::Completed;
                            l.note = Some(format!("VTXOs sent ({paid}); invoice settled."));
                        })
                        .await?;
                    }
                    InvoiceState::Settled => {
                        self.update_ln(id, |l| l.status = LnStatus::Completed).await?;
                    }
                    InvoiceState::Canceled => self.ln_cancel(&s, "invoice cancelled").await?,
                    InvoiceState::Open if s.expires_at < Utc::now() => {
                        ln.cancel(&hash).await?;
                        self.ln_cancel(&s, "invoice expired unpaid").await?;
                    }
                    InvoiceState::Open => {}
                }
            }
            (LnDirection::Out, LnStatus::Accepted) => {
                self.ln_pay_out(id).await?;
            }
            (LnDirection::Out, LnStatus::Waiting) if s.expires_at < Utc::now() => {
                self.update_ln(id, |l| {
                    l.status = LnStatus::Cancelled;
                    l.note = Some("Expired before any VTXOs arrived. Do not pay now.".into());
                })
                .await?;
            }
            _ => {}
        }
        Ok(())
    }

    async fn ln_cancel(&self, s: &LnSwap, why: &str) -> Result<(), Error> {
        credit_lp(&mut self.inner.write().await.lps, &s.lp_id, Side::In, s.receive_sats);
        self.inner.write().await.preimages.remove(&s.id);
        let why = why.to_string();
        self.update_ln(s.id, |l| {
            l.status = LnStatus::Cancelled;
            l.note = Some(format!("Cancelled: {why}. Lightning returns any held payment."));
        })
        .await
        .map(|_| ())
    }
}

/// Pending-payout key for a default's compensation, distinct from the swap's own.
fn comp_key(swap_id: Uuid) -> Uuid {
    Uuid::new_v5(&swap_id, b"compensation")
}

pub fn parse_secret(secret_hex: &str) -> Result<SecretKey, Error> {
    let bytes = hex::decode(secret_hex.trim()).map_err(|e| Error::Invalid(e.to_string()))?;
    SecretKey::from_slice(&bytes).map_err(|e| Error::Invalid(format!("secret: {e}")))
}

fn redeem_from_hex(redeem_hex: &str) -> Result<ScriptBuf, Error> {
    Ok(ScriptBuf::from_bytes(
        hex::decode(redeem_hex).map_err(|e| Error::Invalid(e.to_string()))?,
    ))
}

fn tx_inputs(hex_tx: &str) -> Result<Vec<OutPoint>, Error> {
    let bytes = hex::decode(hex_tx).map_err(|e| Error::Invalid(e.to_string()))?;
    let tx: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&bytes).map_err(|e| Error::Bitcoin(e.to_string()))?;
    Ok(tx.input.iter().map(|i| i.previous_output).collect())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// Which swaps the background pass still has work on.
fn needs_sync(s: &Swap) -> bool {
    match (s.side, s.status) {
        (_, SwapStatus::Quoted) | (Side::In, SwapStatus::LpSettled) => true,
        (Side::Out, SwapStatus::LpSettled) => s.l1_lock_txid.is_none(),
        (Side::Out, SwapStatus::Expired | SwapStatus::Refunded | SwapStatus::Failed)
            if s.l1_lock_txid.is_some() && s.refund_txid.is_none() =>
        {
            true
        }
        // Watch the desk's claim until it confirms, to bump it if it stalls.
        (Side::In, SwapStatus::Claimed) => {
            !s.claim_confirmed && s.claim_tx_hex.is_some() && s.l1_lock_value_sats.is_some()
        }
        _ => compensation_owed(s),
    }
}

/// A default was recorded but the bond payout has not landed yet.
fn compensation_owed(s: &Swap) -> bool {
    s.desk_defaulted && s.compensation_sats.is_some() && s.compensation_vtxo_id.is_none()
}

/// Refresh each desk's bond / fills / defaults / score from the books.
fn apply_desk_stats(inner: &mut Inner) {
    for lp in inner.lps.iter_mut() {
        let (fills, defaults) = inner.reputation.get(&lp.id).copied().unwrap_or_default();
        lp.fills = fills;
        lp.defaults = defaults;
        lp.score_ppm = (fills + 1) * 1_000_000 / (fills + defaults + 2);
        lp.bond_sats = inner.bonds.get(&lp.id).copied().unwrap_or_default();
    }
}

/// Stock a quote ties up: VTXOs for `in`; for `out`, L1 for the lock plus the
/// user's claim fee and the desk's own funding-tx fee.
fn reserve_sats(side: Side, receive_sats: u64) -> u64 {
    match side {
        Side::In => receive_sats,
        Side::Out => receive_sats + 2 * CLAIM_FEE_SATS,
    }
}

/// (VTXO, L1) sats held by open quotes and unsettled swaps for one desk.
fn reserved(inner: &Inner, lp_id: &str) -> (u64, u64) {
    let quotes = inner
        .quotes
        .values()
        .map(|q| (&q.lp_id, q.side, q.receive_sats));
    let swaps = inner
        .swaps
        .values()
        .filter(|s| s.status == SwapStatus::Quoted)
        .map(|s| (&s.lp_id, s.side, s.receive_sats));
    let (mut vtxo, mut l1) = (0u64, 0u64);
    for (id, side, receive) in quotes.chain(swaps) {
        if id != lp_id {
            continue;
        }
        match side {
            Side::In => vtxo += reserve_sats(side, receive),
            Side::Out => l1 += reserve_sats(side, receive),
        }
    }
    // Claim advances promise L1; Lightning `in` swaps promise VTXOs.
    l1 += inner
        .advances
        .values()
        .filter(|a| a.lp_id == lp_id && a.status == AdvanceStatus::Quoted)
        .map(|a| a.advance_sats + CLAIM_FEE_SATS)
        .sum::<u64>();
    vtxo += inner
        .ln_swaps
        .values()
        .filter(|l| {
            l.lp_id == lp_id
                && l.direction == LnDirection::In
                && matches!(l.status, LnStatus::Waiting | LnStatus::Accepted)
        })
        .map(|l| l.receive_sats)
        .sum::<u64>();
    (vtxo, l1)
}

#[derive(Serialize, Deserialize)]
struct PersistFile {
    quotes: Vec<Quote>,
    swaps: Vec<Swap>,
    #[serde(default)]
    baseline_vtxos: HashMap<Uuid, Vec<String>>,
    /// Older files called this `inbound_secrets` and also stored the LP key
    /// per row; that field is ignored now.
    #[serde(default, alias = "inbound_secrets")]
    preimages: Vec<PreimageRow>,
    #[serde(default)]
    own_vtxos: Vec<String>,
    #[serde(default)]
    fund_keys: Vec<KeyRow>,
    #[serde(default)]
    pending_payouts: HashMap<Uuid, PendingPayout>,
    #[serde(default)]
    pending_locks: HashMap<Uuid, String>,
    #[serde(default)]
    plans: Vec<ExitPlan>,
    #[serde(default)]
    bonds: HashMap<String, u64>,
    #[serde(default)]
    reputation: HashMap<String, (u64, u64)>,
    #[serde(default)]
    advances: Vec<Advance>,
    #[serde(default)]
    pending_advance_txs: HashMap<Uuid, String>,
    #[serde(default)]
    ln_swaps: Vec<LnSwap>,
    #[serde(default)]
    webhooks: Vec<WebhookRequest>,
}

impl From<&Inner> for PersistFile {
    fn from(inner: &Inner) -> Self {
        Self {
            quotes: inner.quotes.values().cloned().collect(),
            swaps: inner.swaps.values().cloned().collect(),
            baseline_vtxos: inner.baseline_vtxos.clone(),
            preimages: inner
                .preimages
                .iter()
                .map(|(id, pre)| PreimageRow {
                    id: *id,
                    preimage_hex: hex::encode(pre),
                })
                .collect(),
            own_vtxos: inner.own_vtxos.iter().cloned().collect(),
            fund_keys: inner
                .fund_keys
                .iter()
                .map(|(id, sk)| KeyRow {
                    id: *id,
                    secret_hex: hex::encode(sk.secret_bytes()),
                })
                .collect(),
            pending_payouts: inner.pending_payouts.clone(),
            pending_locks: inner.pending_locks.clone(),
            plans: inner.plans.values().cloned().collect(),
            bonds: inner.bonds.clone(),
            reputation: inner.reputation.clone(),
            advances: inner.advances.values().cloned().collect(),
            pending_advance_txs: inner.pending_advance_txs.clone(),
            ln_swaps: inner.ln_swaps.values().cloned().collect(),
            webhooks: inner.webhooks.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct PreimageRow {
    id: Uuid,
    preimage_hex: String,
}

#[derive(Serialize, Deserialize)]
struct KeyRow {
    id: Uuid,
    secret_hex: String,
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
        max_swap_sats: MAX_SWAP_SATS,
        defaulted: false,
        tachi_pubkey,
        l1_address,
        source: Some(source.into()),
        vault_exit_blocks: Some(VAULT_EXIT_BLOCKS),
        backing: Some("Desk reserve. TAURUS exit is 1008 blocks; swaps skip that wait.".into()),
        bond_sats: 0,
        fills: 0,
        defaults: 0,
        score_ppm: 500_000,
    }
}

/// Price one desk's quote. Starts from the desk's base fee, then:
/// - skew: averaged over the swap's before/after effect on the desk's VTXO
///   share, so draining the scarce side costs more and refilling it is cheaper;
/// - TTL: holding a price firm longer costs more;
/// - deadline: letting the desk lock bitcoin later earns a discount that
///   reaches `max_deadline_discount_ppm` at a full vault-exit wait.
pub fn price(
    cfg: &PricingConfig,
    lp: &LiquidityProvider,
    side: Side,
    amount_sats: u64,
    ttl_secs: u64,
    deadline_blocks: u32,
) -> PriceBreakdown {
    const HALF: i128 = 500_000;
    let (v, l, a) = (
        lp.vtxo_sats as i128,
        lp.l1_sats as i128,
        amount_sats as i128,
    );
    let share = |v: i128, l: i128| {
        let (v, l) = (v.max(0), l.max(0));
        if v + l == 0 { HALF } else { v * 1_000_000 / (v + l) }
    };
    let before = share(v, l);
    let after = match side {
        Side::In => share(v - a, l + a),
        Side::Out => share(v + a, l - a),
    };
    let mid = (before + after) / 2;
    let imbalance = match side {
        Side::In => HALF - mid,
        Side::Out => mid - HALF,
    };
    let skew = cfg.skew_ppm as i128 * imbalance / HALF;
    let ttl = cfg.ttl_ppm_per_hour as i128 * ttl_secs as i128 / 3600;
    let subtotal = lp.fee_ppm as i128 + skew + ttl;
    let d = deadline_blocks.min(VAULT_EXIT_BLOCKS) as i128;
    let discount = subtotal.max(0) * cfg.max_deadline_discount_ppm as i128 / 1_000_000 * d
        / VAULT_EXIT_BLOCKS as i128;
    let fee = (subtotal - discount).clamp(cfg.min_fee_ppm as i128, cfg.max_fee_ppm as i128);
    PriceBreakdown {
        base_ppm: lp.fee_ppm,
        skew_ppm: skew as i64,
        ttl_ppm: ttl as i64,
        deadline_discount_ppm: discount as i64,
        fee_ppm: fee as u64,
        vtxo_share_before_ppm: before as u64,
        vtxo_share_after_ppm: after as u64,
        ttl_secs,
        deadline_blocks,
    }
}

/// The side of a desk's books a swap draws on.
fn book(lp: &LiquidityProvider, side: Side) -> u64 {
    match side {
        Side::In => lp.vtxo_sats,
        Side::Out => lp.l1_sats,
    }
}

fn can_fill(lp: &LiquidityProvider, side: Side, amount_sats: u64) -> bool {
    routable(lp)
        && amount_sats <= lp.max_swap_sats
        && book(lp, side) >= reserve_sats(side, amount_sats)
}

/// Not banned by the operator and not failing too often.
fn routable(lp: &LiquidityProvider) -> bool {
    !lp.defaulted && lp.score_ppm >= MIN_ROUTING_SCORE_PPM
}

/// Largest amount a desk can take on `side` right now (0 if it cannot route).
fn capacity(lp: &LiquidityProvider, side: Side) -> u64 {
    if !routable(lp) {
        return 0;
    }
    let book = match side {
        Side::In => book(lp, side),
        Side::Out => book(lp, side).saturating_sub(2 * CLAIM_FEE_SATS),
    };
    book.min(lp.max_swap_sats)
}

/// Whether an outbound lock should be funded at `height` (deadline swaps wait
/// until close to their deadline so locks due together share a tx).
fn lock_due(swap: &Swap, height: u32) -> bool {
    swap.lock_by_height
        .is_none_or(|by| height + LOCK_LEAD_BLOCKS >= by)
}

/// Unpaid outbound swap whose lock is due and not yet signed.
fn awaiting_lock(s: &Swap, height: u32) -> bool {
    s.side == Side::Out
        && s.status == SwapStatus::Quoted
        && s.l1_lock_txid.is_none()
        && lock_due(s, height)
        && s
            .pay
            .htlc()
            .is_some_and(|l| height + SAFETY_MARGIN_BLOCKS < l.timeout_height)
}

fn quote_hint(side: Side, lock_by_height: Option<u32>) -> String {
    let blocks = HTLC_TIMEOUT_BLOCKS;
    match (side, lock_by_height) {
        (Side::In, _) => format!(
            "Swap vs vault: pay a lock now (~{blocks} blocks to refund if the desk stalls) instead of a TAURUS unilateral exit (~{VAULT_EXIT_BLOCKS} blocks, about a week). The Tachi faucet cannot pay the lock — use Fund with faucet."
        ),
        (Side::Out, None) => format!(
            "Swap vs vault: the desk locks bitcoin first (~{blocks}-block refund for them). You send Tachi coins only after that lock is up, then you claim. A vault exit would be ~{VAULT_EXIT_BLOCKS} blocks."
        ),
        (Side::Out, Some(by)) => format!(
            "Scheduled exit: the desk locks bitcoin for you by block {by} (batched with other exits, so it costs less). You send Tachi coins only after that lock is up, then you claim. A vault exit would be ~{VAULT_EXIT_BLOCKS} blocks."
        ),
    }
}

fn quote_comparison(fee: u64, p: &PriceBreakdown, lock_by_height: Option<u32>) -> String {
    let pct = |ppm: i64| format!("{:+.2}%", ppm as f64 / 10_000.0);
    let mut out = format!(
        "This swap: fee {fee} sats ({:.2}% = base {:.2}%, inventory {}, firm {}s {}",
        p.fee_ppm as f64 / 10_000.0,
        p.base_ppm as f64 / 10_000.0,
        pct(p.skew_ppm),
        p.ttl_secs,
        pct(p.ttl_ppm),
    );
    if p.deadline_discount_ppm > 0 {
        out.push_str(&format!(", deadline {}", pct(-p.deadline_discount_ppm)));
    }
    out.push_str(&format!(
        "), refund window {HTLC_TIMEOUT_BLOCKS} blocks. TAURUS vault exit: {VAULT_EXIT_BLOCKS} blocks (~7 days) and no LP fee."
    ));
    if let Some(by) = lock_by_height {
        out.push_str(&format!(" Bitcoin locked for you by block {by}."));
    }
    out
}

fn debit_lp(lps: &mut [LiquidityProvider], id: &str, side: Side, amount: u64) -> Result<(), Error> {
    let lp = lps
        .iter_mut()
        .find(|lp| lp.id == id)
        .ok_or_else(|| Error::Invalid(format!("unknown lp {id}")))?;
    let book = match side {
        Side::In => &mut lp.vtxo_sats,
        Side::Out => &mut lp.l1_sats,
    };
    if *book < amount {
        return Err(Error::NoLiquidity {
            side,
            amount_sats: amount,
        });
    }
    *book -= amount;
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

/// Drop expired quotes and release their stock. Returns whether any went.
fn release_expired_quotes(inner: &mut Inner) -> bool {
    let now = Utc::now();
    let expired: Vec<Uuid> = inner
        .quotes
        .iter()
        .filter(|(_, q)| q.expires_at < now)
        .map(|(id, _)| *id)
        .collect();
    for id in &expired {
        if let Some(q) = inner.quotes.remove(id) {
            inner.preimages.remove(id);
            credit_lp(
                &mut inner.lps,
                &q.lp_id,
                q.side,
                reserve_sats(q.side, q.receive_sats),
            );
        }
    }
    // Forget clients whose holds are gone (quote expired/accepted, swap paid).
    let (quotes, swaps) = (&inner.quotes, &inner.swaps);
    inner.clients.retain(|id, _| {
        quotes.contains_key(id) || swaps.get(id).is_some_and(|s| s.status == SwapStatus::Quoted)
    });
    !expired.is_empty()
}

/// Drop not-yet-accepted quotes and give their stock back.
fn release_quotes(inner: &mut Inner, quotes: &[Quote]) {
    for leg in quotes {
        if let Some(q) = inner.quotes.remove(&leg.id) {
            inner.preimages.remove(&leg.id);
            credit_lp(&mut inner.lps, &q.lp_id, q.side, reserve_sats(q.side, q.receive_sats));
        }
    }
}

/// Per-client caps on open quotes + unpaid swaps and the stock they hold.
/// `None` (operator / internal callers) is never capped.
fn check_client(
    inner: &Inner,
    client: Option<&str>,
    new_holds: usize,
    new_sats: u64,
) -> Result<(), Error> {
    let Some(client) = client else {
        return Ok(());
    };
    let (mut open, mut held) = (0usize, 0u64);
    for (id, who) in &inner.clients {
        if who != client {
            continue;
        }
        let hold = inner
            .quotes
            .get(id)
            .map(|q| (q.side, q.receive_sats))
            .or_else(|| {
                inner
                    .swaps
                    .get(id)
                    .filter(|s| s.status == SwapStatus::Quoted)
                    .map(|s| (s.side, s.receive_sats))
            });
        if let Some((side, receive)) = hold {
            open += 1;
            held += reserve_sats(side, receive);
        }
    }
    if open + new_holds > MAX_OPEN_PER_CLIENT {
        return Err(Error::RateLimited(format!(
            "at most {MAX_OPEN_PER_CLIENT} open quotes or unpaid swaps per client (you hold {open}); accept, pay or let some expire first"
        )));
    }
    if held + new_sats > MAX_HELD_SATS_PER_CLIENT {
        return Err(Error::RateLimited(format!(
            "at most {MAX_HELD_SATS_PER_CLIENT} sats of desk stock held per client (you hold {held})"
        )));
    }
    Ok(())
}

/// How long a quote may stay firm: as requested, unless it would tie up more
/// than `LARGE_QUOTE_SHARE_PPM` of the desk's free stock.
fn firm_ttl(lp: &LiquidityProvider, side: Side, amount_sats: u64, requested: u64) -> u64 {
    let large = u128::from(amount_sats) * 1_000_000
        > u128::from(book(lp, side)) * u128::from(LARGE_QUOTE_SHARE_PPM);
    if large {
        requested.min(LARGE_QUOTE_MAX_TTL_SECS)
    } else {
        requested
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> Engine {
        let tachi = TachiClient::new("http://127.0.0.1:9").expect("client");
        // Flat pricing keeps fee math in these routing/concurrency tests exact.
        Engine::from_lp_secret_mode(tachi, Network::Signet, generate_keypair().secret, true)
            .with_pricing(PricingConfig::flat())
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
                ttl_secs: None,
                deadline_blocks: None,
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
                ttl_secs: None,
                deadline_blocks: None,
            })
            .await
            .expect("quote");
        assert_eq!(q.lp_id, "lp-bravo");
        assert!(q.comparison.unwrap().contains("1008"));
        assert_eq!(q.vault_exit_blocks, 1008);
    }

    #[tokio::test]
    async fn outbound_quote_user_claims_htlc() {
        let e = engine();
        let user = generate_keypair();
        let q = e
            .create_quote(CreateQuoteRequest {
                side: Side::Out,
                amount_sats: 100_000,
                user_tachi_address: None,
                user_l1_address: Some("tb1qtest".into()),
                user_refund_pubkey_hex: Some(user.public.to_string()),
                ttl_secs: None,
                deadline_blocks: None,
            })
            .await
            .expect("quote");
        match q.pay {
            PayInstructions::TachiVtxo { lock: Some(lock), .. } => {
                assert!(lock.address.starts_with("tb1"));
                assert!(!lock.redeem_script_hex.is_empty());
            }
            other => panic!("expected outbound lock, got {other:?}"),
        }
        assert!(q.comparison.as_deref().unwrap_or("").contains("1008"));
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
                ttl_secs: None,
                deadline_blocks: None,
            })
            .await
            .unwrap();
        let swap = e.open_swap(q.id).await.unwrap();
        let refunded = e.refund(swap.id, None).await.unwrap();
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
                ttl_secs: None,
                deadline_blocks: None,
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
                        ttl_secs: None,
                        deadline_blocks: None,
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
        let held = reserve_sats(Side::Out, amount - fee);

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
                        ttl_secs: None,
                        deadline_blocks: None,
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
        assert_eq!(bravo.l1_sats, 20_000_000 - ok * held);
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
                    ttl_secs: None,
                    deadline_blocks: None,
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
        // alpha L1 = 50k; each 10k out reserves receive + fees (~10.8k). Only a handful
        // bind the cheap LP; the rest spill to bravo.
        assert!((1..=5).contains(&alpha), "alpha got {alpha}");
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
                ttl_secs: None,
                deadline_blocks: None,
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
                ttl_secs: None,
                deadline_blocks: None,
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
                    ttl_secs: None,
                    deadline_blocks: None,
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
                    ttl_secs: None,
                    deadline_blocks: None,
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
                    ttl_secs: None,
                    deadline_blocks: None,
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
            ttl_secs: None,
            deadline_blocks: None,
        })
        .await
        .expect("quote");
        assert!(
            started.elapsed() < std::time::Duration::from_millis(500),
            "quote blocked on Tachi RPC"
        );
    }

    #[tokio::test]
    async fn live_quote_refuses_unknown_height() {
        // Live engine pointed at a dead port: no height, so no made-up timeout.
        let tachi = TachiClient::new("http://127.0.0.1:9").expect("client");
        let e = Engine::new(tachi, Network::Regtest);
        let user = generate_keypair();
        let err = e
            .create_quote(CreateQuoteRequest {
                side: Side::In,
                amount_sats: 10_000,
                user_tachi_address: Some(e.tachi_lp_pubkey_hex()),
                user_l1_address: None,
                user_refund_pubkey_hex: Some(user.public.to_string()),
                ttl_secs: None,
                deadline_blocks: None,
            })
            .await
            .expect_err("height unknown");
        assert!(err.to_string().contains("height"), "{err}");
    }

    #[tokio::test]
    async fn reservations_survive_inventory_refresh_math() {
        let e = engine();
        let user = generate_keypair();
        e.create_quote(CreateQuoteRequest {
            side: Side::In,
            amount_sats: 100_000,
            user_tachi_address: Some("tb1ptest".into()),
            user_l1_address: None,
            user_refund_pubkey_hex: Some(user.public.to_string()),
            ttl_secs: None,
            deadline_blocks: None,
        })
        .await
        .unwrap();
        e.create_quote(CreateQuoteRequest {
            side: Side::Out,
            amount_sats: 100_000,
            user_tachi_address: None,
            user_l1_address: Some("tb1qtest".into()),
            user_refund_pubkey_hex: None,
            ttl_secs: None,
            deadline_blocks: None,
        })
        .await
        .unwrap();
        let inner = e.inner.read().await;
        let in_recv = 100_000 - fee_sats(100_000, 8_000, MIN_FEE_SATS);
        let out_recv = 100_000 - fee_sats(100_000, 10_000, MIN_FEE_SATS);
        assert_eq!(reserved(&inner, "lp-alpha"), (in_recv, 0));
        assert_eq!(
            reserved(&inner, "lp-bravo"),
            (0, out_recv + 2 * CLAIM_FEE_SATS)
        );
    }

    #[tokio::test]
    async fn refund_requires_matching_key() {
        let e = engine();
        let user = generate_keypair();
        let stranger = generate_keypair();
        let q = e
            .create_quote(CreateQuoteRequest {
                side: Side::In,
                amount_sats: 10_000,
                user_tachi_address: Some("tb1ptest".into()),
                user_l1_address: None,
                user_refund_pubkey_hex: Some(user.public.to_string()),
                ttl_secs: None,
                deadline_blocks: None,
            })
            .await
            .unwrap();
        let swap = e.open_swap(q.id).await.unwrap();
        let err = e
            .refund(swap.id, Some(stranger.secret))
            .await
            .expect_err("wrong key");
        assert!(err.to_string().contains("does not match"), "{err}");
        let ok = e.refund(swap.id, Some(user.secret)).await.unwrap();
        assert_eq!(ok.status, SwapStatus::Refunded);
    }

    #[tokio::test]
    async fn outbound_payment_reveals_preimage_and_is_credited_once() {
        let e = engine();
        let user = generate_keypair();
        let mut ids = Vec::new();
        for _ in 0..2 {
            let q = e
                .create_quote(CreateQuoteRequest {
                    side: Side::Out,
                    amount_sats: 100_000,
                    user_tachi_address: None,
                    user_l1_address: Some("tb1qtest".into()),
                    user_refund_pubkey_hex: Some(user.public.to_string()),
                    ttl_secs: None,
                    deadline_blocks: None,
                })
                .await
                .unwrap();
            ids.push(e.open_swap(q.id).await.unwrap().id);
        }
        let paid = e
            .observe_vtxo(ids[0], ObserveVtxoRequest { vtxo_id: "sim-1".into() })
            .await
            .unwrap();
        assert_eq!(paid.status, SwapStatus::LpSettled);
        assert_eq!(paid.preimage_hex.as_ref().map(String::len), Some(64));
        let err = e
            .observe_vtxo(ids[1], ObserveVtxoRequest { vtxo_id: "sim-1".into() })
            .await
            .expect_err("same payment twice");
        assert!(err.to_string().contains("already pays"), "{err}");
    }

    #[tokio::test]
    async fn persist_roundtrip_keeps_preimages_and_rejects_corrupt_file() {
        let dir = std::env::temp_dir().join(format!("tachi-flow-test-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let tachi = TachiClient::new("http://127.0.0.1:9").expect("client");
        let e = Engine::from_lp_secret_mode(tachi.clone(), Network::Signet, generate_keypair().secret, true)
            .with_persist(&path)
            .unwrap();
        let user = generate_keypair();
        let q = e
            .create_quote(CreateQuoteRequest {
                side: Side::In,
                amount_sats: 10_000,
                user_tachi_address: Some("tb1ptest".into()),
                user_l1_address: None,
                user_refund_pubkey_hex: Some(user.public.to_string()),
                ttl_secs: None,
                deadline_blocks: None,
            })
            .await
            .unwrap();
        let swap = e.open_swap(q.id).await.unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("secret_hex"), "LP secrets must not be persisted per swap");

        let again = Engine::from_lp_secret_mode(tachi.clone(), Network::Signet, generate_keypair().secret, true)
            .with_persist(&path)
            .unwrap();
        assert!(again.inner.read().await.preimages.contains_key(&swap.id));

        std::fs::write(&path, "{ not json").unwrap();
        let err = Engine::from_lp_secret_mode(tachi, Network::Signet, generate_keypair().secret, true)
            .with_persist(&path)
            .err()
            .expect("corrupt file must not start empty");
        assert!(err.to_string().contains("preimages"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Simulated books with the default (dynamic) pricing.
    fn priced_engine() -> Engine {
        let tachi = TachiClient::new("http://127.0.0.1:9").expect("client");
        Engine::from_lp_secret_mode(tachi, Network::Signet, generate_keypair().secret, true)
    }

    fn desk(vtxo_sats: u64, l1_sats: u64) -> LiquidityProvider {
        lp("d", l1_sats, vtxo_sats, 8_000, None, None, "test")
    }

    #[test]
    fn skew_charges_for_draining_the_scarce_side() {
        let cfg = PricingConfig::default();
        let vtxo_rich = desk(1_800_000, 200_000);
        let sell_vtxo = price(&cfg, &vtxo_rich, Side::In, 100_000, 600, 0);
        let buy_vtxo = price(&cfg, &vtxo_rich, Side::Out, 100_000, 600, 0);
        assert!(sell_vtxo.skew_ppm < 0, "{sell_vtxo:?}");
        assert!(buy_vtxo.skew_ppm > 0, "{buy_vtxo:?}");
        assert!(sell_vtxo.fee_ppm < buy_vtxo.fee_ppm);
        assert_eq!(sell_vtxo.vtxo_share_before_ppm, 900_000);
        assert_eq!(sell_vtxo.vtxo_share_after_ppm, 850_000);

        // From balance, either direction moves away from it and costs a little.
        let balanced = desk(1_000_000, 1_000_000);
        assert!(price(&cfg, &balanced, Side::In, 100_000, 600, 0).skew_ppm > 0);
        assert!(price(&cfg, &balanced, Side::Out, 100_000, 600, 0).skew_ppm > 0);
    }

    #[test]
    fn longer_firm_quotes_cost_more_and_deadlines_cost_less() {
        let cfg = PricingConfig::default();
        let d = desk(1_000_000, 1_000_000);
        let short = price(&cfg, &d, Side::Out, 100_000, 60, 0);
        let long = price(&cfg, &d, Side::Out, 100_000, 3_600, 0);
        assert_eq!(long.ttl_ppm, 3_000);
        assert!(long.fee_ppm > short.fee_ppm);

        let fees: Vec<u64> = DEADLINE_PRESETS
            .iter()
            .map(|&dl| price(&cfg, &d, Side::Out, 100_000, 600, dl).fee_ppm)
            .collect();
        assert!(fees.windows(2).all(|w| w[1] <= w[0]), "{fees:?}");
        let vault_wait = price(&cfg, &d, Side::Out, 100_000, 600, VAULT_EXIT_BLOCKS);
        let subtotal = vault_wait.base_ppm as i64 + vault_wait.skew_ppm + vault_wait.ttl_ppm;
        assert_eq!(vault_wait.deadline_discount_ppm, subtotal * 8 / 10);
        // Never below the floor, whatever the discount.
        let cheap = LiquidityProvider { fee_ppm: 0, ..d };
        assert_eq!(
            price(&cfg, &cheap, Side::Out, 100_000, 600, VAULT_EXIT_BLOCKS).fee_ppm,
            cfg.min_fee_ppm
        );
    }

    #[test]
    fn flat_pricing_is_the_base_fee() {
        let d = desk(1_800_000, 200_000);
        let p = price(&PricingConfig::flat(), &d, Side::Out, 100_000, 3_600, 1008);
        assert_eq!(p.fee_ppm, 8_000);
    }

    #[tokio::test]
    async fn rfq_quotes_every_desk_and_accepting_releases_the_rest() {
        let e = priced_engine();
        let user = generate_keypair();
        let quotes = e
            .request_quotes(CreateQuoteRequest {
                side: Side::In,
                amount_sats: 100_000,
                user_tachi_address: Some("tb1ptest".into()),
                user_l1_address: None,
                user_refund_pubkey_hex: Some(user.public.to_string()),
                ttl_secs: Some(120),
                deadline_blocks: None,
            })
            .await
            .unwrap();
        assert_eq!(quotes.len(), 2);
        assert!(quotes[0].fee_sats <= quotes[1].fee_sats);
        // alpha is VTXO-rich and cheaper at base: it should win selling VTXOs.
        assert_eq!(quotes[0].lp_id, "lp-alpha");
        assert!(quotes.iter().all(|q| q.rfq_id.is_some() && q.rfq_id == quotes[0].rfq_id));
        let ttl = (quotes[0].expires_at - Utc::now()).num_seconds();
        assert!((100..=120).contains(&ttl), "ttl {ttl}");

        let bravo_book = |books: &[LiquidityProvider]| {
            books.iter().find(|lp| lp.id == "lp-bravo").unwrap().vtxo_sats
        };
        assert_eq!(
            bravo_book(&e.inventory().await),
            5_000_000 - quotes[1].receive_sats,
            "every RFQ quote is firm, so each reserves stock"
        );

        e.open_swap(quotes[0].id).await.unwrap();
        assert_eq!(bravo_book(&e.inventory().await), 5_000_000);
        let err = e.open_swap(quotes[1].id).await.expect_err("sibling released");
        assert!(matches!(err, Error::QuoteNotFound));
    }

    #[tokio::test]
    async fn deadline_quotes_schedule_the_lock_and_cost_less() {
        let e = priced_engine();
        let user = generate_keypair();
        let req = |deadline| CreateQuoteRequest {
            side: Side::Out,
            amount_sats: 100_000,
            user_tachi_address: None,
            user_l1_address: Some("tb1qtest".into()),
            user_refund_pubkey_hex: Some(user.public.to_string()),
            ttl_secs: None,
            deadline_blocks: Some(deadline),
        };
        let now = e.create_quote(req(0)).await.unwrap();
        let later = e.create_quote(req(144)).await.unwrap();
        assert_eq!(now.lock_by_height, None);
        assert_eq!(later.lock_by_height, Some(SIM_HEIGHT + 144));
        assert!(later.fee_sats < now.fee_sats, "{} !< {}", later.fee_sats, now.fee_sats);
        let timeout = later.pay.htlc().unwrap().timeout_height;
        assert_eq!(timeout, SIM_HEIGHT + 144 + HTLC_TIMEOUT_BLOCKS);

        let swap = e.open_swap(later.id).await.unwrap();
        let by = SIM_HEIGHT + 144;
        assert!(!lock_due(&swap, by - LOCK_LEAD_BLOCKS - 1));
        assert!(lock_due(&swap, by - LOCK_LEAD_BLOCKS));
        assert!(awaiting_lock(&swap, by));
        assert!(!awaiting_lock(&swap, timeout - SAFETY_MARGIN_BLOCKS));

        let err = e
            .create_quote(CreateQuoteRequest {
                side: Side::In,
                user_tachi_address: Some("tb1ptest".into()),
                user_l1_address: None,
                ..req(6)
            })
            .await
            .expect_err("deadline is outbound only");
        assert!(err.to_string().contains("out swaps"), "{err}");
        let err = e.create_quote(req(VAULT_EXIT_BLOCKS + 1)).await.expect_err("cap");
        assert!(err.to_string().contains("at most"), "{err}");
    }

    fn plan_req(side: Side, amount_sats: u64, max_leg_sats: Option<u64>) -> CreatePlanRequest {
        let user = generate_keypair();
        CreatePlanRequest {
            quote: CreateQuoteRequest {
                side,
                amount_sats,
                user_tachi_address: Some("tb1ptest".into()),
                user_l1_address: Some("tb1qtest".into()),
                user_refund_pubkey_hex: Some(user.public.to_string()),
                ttl_secs: None,
                deadline_blocks: None,
            },
            max_leg_sats,
        }
    }

    #[tokio::test]
    async fn exit_plan_splits_past_single_swap_limit_and_opens_every_leg() {
        let e = engine();
        // 3M is over MAX_SWAP_SATS: a single quote must refuse, a plan splits.
        let single = e.create_quote(plan_req(Side::Out, 3_000_000, None).quote).await;
        assert!(single.is_err());

        let plan = e.plan_exit(plan_req(Side::Out, 3_000_000, None)).await.unwrap();
        assert!(plan.legs.len() >= 2);
        assert_eq!(plan.legs.iter().map(|q| q.amount_sats).sum::<u64>(), 3_000_000);
        assert!(plan.legs.iter().all(|q| q.amount_sats <= MAX_SWAP_SATS));
        assert!(plan.legs.iter().all(|q| q.plan_id == Some(plan.id)));
        assert_eq!(plan.fee_sats, plan.legs.iter().map(|q| q.fee_sats).sum::<u64>());

        let opened = e.accept_plan(plan.id).await.unwrap();
        assert_eq!(opened.swap_ids.len(), plan.legs.len());
        for id in &opened.swap_ids {
            assert_eq!(e.get_swap(*id).await.unwrap().plan_id, Some(plan.id));
        }
        // Accepting twice is a no-op, not a second set of swaps.
        assert_eq!(e.accept_plan(plan.id).await.unwrap().swap_ids, opened.swap_ids);
    }

    #[tokio::test]
    async fn exit_plan_never_strands_a_tiny_remainder() {
        let e = engine();
        let plan = e.plan_exit(plan_req(Side::In, 25_000, Some(20_000))).await.unwrap();
        let mut legs: Vec<u64> = plan.legs.iter().map(|q| q.amount_sats).collect();
        legs.sort();
        assert_eq!(legs, vec![10_000, 15_000]);
    }

    #[tokio::test]
    async fn exit_plan_without_enough_stock_reserves_nothing() {
        let e = engine();
        let before = e.inventory().await;
        // Both desks together hold 25M VTXOs.
        let err = e.plan_exit(plan_req(Side::In, 30_000_000, None)).await.unwrap_err();
        assert!(matches!(err, Error::NoLiquidity { .. }), "{err}");
        let after = e.inventory().await;
        for (a, b) in before.iter().zip(&after) {
            assert_eq!(a.vtxo_sats, b.vtxo_sats, "{} book leaked", a.id);
        }
        assert!(e.inner.read().await.quotes.is_empty());
    }

    #[tokio::test]
    async fn desk_default_pays_from_bond_and_costs_routing() {
        let e = engine();
        assert_eq!(e.post_bond("lp-alpha", 50_000).await.unwrap(), 50_000);
        let user = generate_keypair();
        // A 10k out routes to alpha (cheapest base fee; its 50k L1 covers it).
        let q = e
            .create_quote(CreateQuoteRequest {
                side: Side::Out,
                amount_sats: 10_000,
                user_tachi_address: None,
                user_l1_address: Some("tb1qtest".into()),
                user_refund_pubkey_hex: Some(user.public.to_string()),
                ttl_secs: None,
                deadline_blocks: None,
            })
            .await
            .unwrap();
        assert_eq!(q.lp_id, "lp-alpha");
        let swap = e.open_swap(q.id).await.unwrap();

        // The desk never locked bitcoin before the timeout: its default.
        let expired = e.expire(swap.id).await.unwrap();
        assert_eq!(expired.status, SwapStatus::Expired);
        assert!(expired.desk_defaulted);
        let owed = (q.amount_sats * DEFAULT_PENALTY_PPM / 1_000_000).max(MIN_COMPENSATION_SATS);
        assert_eq!(expired.compensation_sats, Some(owed));
        assert_eq!(
            expired.compensation_vtxo_id.as_deref(),
            Some(format!("sim-comp-{}", swap.id).as_str())
        );

        let alpha = e
            .inventory()
            .await
            .into_iter()
            .find(|lp| lp.id == "lp-alpha")
            .unwrap();
        assert_eq!(alpha.bond_sats, 50_000 - owed);
        assert_eq!((alpha.fills, alpha.defaults), (0, 1));
        assert!(alpha.score_ppm < MIN_ROUTING_SCORE_PPM);
        // With a poor score alpha drops out of routing.
        let next = e
            .create_quote(CreateQuoteRequest {
                side: Side::In,
                amount_sats: 10_000,
                user_tachi_address: Some("tb1ptest".into()),
                user_l1_address: None,
                user_refund_pubkey_hex: Some(user.public.to_string()),
                ttl_secs: None,
                deadline_blocks: None,
            })
            .await
            .unwrap();
        assert_eq!(next.lp_id, "lp-bravo");
    }

    #[tokio::test]
    async fn fills_raise_the_score() {
        let e = engine();
        let user = generate_keypair();
        for i in 0..3 {
            let q = e
                .create_quote(CreateQuoteRequest {
                    side: Side::In,
                    amount_sats: 10_000,
                    user_tachi_address: Some("tb1ptest".into()),
                    user_l1_address: None,
                    user_refund_pubkey_hex: Some(user.public.to_string()),
                    ttl_secs: None,
                    deadline_blocks: None,
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
        let alpha = e.inventory().await.into_iter().find(|lp| lp.id == "lp-alpha").unwrap();
        assert_eq!(alpha.fills, 3);
        assert_eq!(alpha.score_ppm, 4 * 1_000_000 / 5);
    }

    #[tokio::test]
    async fn swap_changes_stream_as_events() {
        let e = engine();
        let mut rx = e.subscribe();
        let user = generate_keypair();
        let q = e
            .create_quote(CreateQuoteRequest {
                side: Side::In,
                amount_sats: 10_000,
                user_tachi_address: Some("tb1ptest".into()),
                user_l1_address: None,
                user_refund_pubkey_hex: Some(user.public.to_string()),
                ttl_secs: None,
                deadline_blocks: None,
            })
            .await
            .unwrap();
        let s = e.open_swap(q.id).await.unwrap();
        e.observe_lock(
            s.id,
            ObserveLockRequest {
                txid: "ab".repeat(32),
                vout: 0,
                value_sats: 10_000,
            },
        )
        .await
        .unwrap();
        let mut seen = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            let Event::Swap(sw) = &ev else { continue };
            assert_eq!(sw.id, s.id);
            assert!(ev.sse_frame().starts_with("event: swap\ndata: {"));
            seen.push(sw.status);
        }
        assert_eq!(seen.first(), Some(&SwapStatus::Quoted));
        assert_eq!(seen.last(), Some(&SwapStatus::LpSettled));
    }

    fn ln_engine() -> (Engine, Arc<crate::lightning::MockNode>) {
        let mock = Arc::new(crate::lightning::MockNode::default());
        let e = engine().with_lightning(Some(LightningNode::Mock(mock.clone())));
        (e, mock)
    }

    #[tokio::test]
    async fn lightning_in_holds_the_htlc_until_vtxos_are_paid() {
        let (e, mock) = ln_engine();
        let s = e
            .ln_quote(LnQuoteRequest {
                direction: LnDirection::In,
                amount_sats: Some(50_000),
                invoice: None,
                user_tachi_address: Some("tb1ptest".into()),
            })
            .await
            .unwrap();
        assert_eq!(s.status, LnStatus::Waiting);
        let hash: [u8; 32] = hex::decode(&s.payment_hash_hex).unwrap().try_into().unwrap();

        // Nothing happens until the payer's HTLC is held.
        e.sync_all().await.unwrap();
        assert_eq!(e.get_ln_swap(s.id).await.unwrap().status, LnStatus::Waiting);

        mock.accept(&hash);
        e.sync_all().await.unwrap();
        let done = e.get_ln_swap(s.id).await.unwrap();
        assert_eq!(done.status, LnStatus::Completed);
        assert!(done.vtxo_payment_id.is_some());
        // Settled with the desk's preimage only after the VTXOs went out.
        assert_eq!(mock.state_of(&hash), Some(InvoiceState::Settled));
    }

    #[tokio::test]
    async fn lightning_out_pays_after_vtxos_and_refunds_on_failure() {
        let (e, mock) = ln_engine();
        let preimage = [7u8; 32];
        let hash = payment_hash(&preimage).to_byte_array();
        let invoice = format!("mock:{}:20000", hex::encode(hash));
        mock.payable.lock().unwrap().insert(hash, preimage);
        let s = e
            .ln_quote(LnQuoteRequest {
                direction: LnDirection::Out,
                amount_sats: None,
                invoice: Some(invoice.clone()),
                user_tachi_address: Some("tb1ptest".into()),
            })
            .await
            .unwrap();
        assert_eq!(s.receive_sats, 20_000);
        assert!(s.amount_sats > 20_000, "user covers fee + routing");
        let done = e.ln_paid(s.id, "sim-pay-1").await.unwrap();
        assert_eq!(done.status, LnStatus::Completed);
        assert_eq!(mock.paid.lock().unwrap().as_slice(), [invoice]);
        // The same VTXO cannot pay a second swap.
        let unroutable = format!("mock:{}:20000", hex::encode([9u8; 32]));
        let s2 = e
            .ln_quote(LnQuoteRequest {
                direction: LnDirection::Out,
                amount_sats: None,
                invoice: Some(unroutable),
                user_tachi_address: Some("tb1ptest".into()),
            })
            .await
            .unwrap();
        assert!(e.ln_paid(s2.id, "sim-pay-1").await.is_err());
        // No route: the payment fails outright and the VTXOs go back.
        let failed = e.ln_paid(s2.id, "sim-pay-2").await.unwrap();
        assert_eq!(failed.status, LnStatus::Failed);
        assert!(failed.note.unwrap().contains("returned"));
    }

    #[tokio::test]
    async fn lightning_routes_refuse_when_not_configured() {
        let e = engine();
        let err = e
            .ln_quote(LnQuoteRequest {
                direction: LnDirection::In,
                amount_sats: Some(50_000),
                invoice: None,
                user_tachi_address: Some("tb1ptest".into()),
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not configured"), "{err}");
    }

    fn in_req(amount_sats: u64, ttl_secs: Option<u64>) -> CreateQuoteRequest {
        CreateQuoteRequest {
            side: Side::In,
            amount_sats,
            user_tachi_address: Some("tb1ptest".into()),
            user_l1_address: None,
            user_refund_pubkey_hex: Some(generate_keypair().public.to_string()),
            ttl_secs,
            deadline_blocks: None,
        }
    }

    #[tokio::test]
    async fn clients_are_capped_on_open_holds_including_unpaid_swaps() {
        let e = engine();
        let mut ids = Vec::new();
        for _ in 0..MAX_OPEN_PER_CLIENT {
            ids.push(e.create_quote_for("1.2.3.4", in_req(10_000, None)).await.unwrap().id);
        }
        let err = e.create_quote_for("1.2.3.4", in_req(10_000, None)).await.unwrap_err();
        assert!(matches!(err, Error::RateLimited(_)), "{err}");
        // Someone else is unaffected, and the operator is never capped.
        e.create_quote_for("5.6.7.8", in_req(10_000, None)).await.unwrap();
        e.create_quote(in_req(10_000, None)).await.unwrap();

        // Accepting a quote does not free the slot: the unpaid swap still holds stock.
        e.open_swap(ids[0]).await.unwrap();
        assert!(e.create_quote_for("1.2.3.4", in_req(10_000, None)).await.is_err());
    }

    #[tokio::test]
    async fn rfq_counts_every_quote_and_held_sats_are_capped() {
        let e = engine();
        for _ in 0..MAX_OPEN_PER_CLIENT - 1 {
            e.create_quote_for("9.9.9.9", in_req(10_000, None)).await.unwrap();
        }
        // Both desks would quote: two holds where only one slot is left.
        let err = e.request_quotes_for("9.9.9.9", in_req(10_000, None)).await.unwrap_err();
        assert!(matches!(err, Error::RateLimited(_)), "{err}");

        // 2M quotes hold ~1.98M each: the third would pass the 4M cap.
        e.create_quote_for("4.4.4.4", in_req(2_000_000, None)).await.unwrap();
        e.create_quote_for("4.4.4.4", in_req(2_000_000, None)).await.unwrap();
        let err = e.create_quote_for("4.4.4.4", in_req(2_000_000, None)).await.unwrap_err();
        assert!(err.to_string().contains("sats of desk stock"), "{err}");
    }

    #[tokio::test]
    async fn big_holds_only_stay_firm_briefly() {
        let e = engine();
        // 2M is 10% of alpha's 20M VTXOs but 40% of bravo's 5M.
        let quotes = e.request_quotes(in_req(2_000_000, Some(3_600))).await.unwrap();
        let ttl = |lp: &str| {
            let q = quotes.iter().find(|q| q.lp_id == lp).unwrap();
            (q.expires_at - Utc::now()).num_seconds()
        };
        assert!(ttl("lp-alpha") > 3_000, "alpha keeps the hour");
        assert!(ttl("lp-bravo") <= LARGE_QUOTE_MAX_TTL_SECS as i64, "bravo is capped");
        let bravo = quotes.iter().find(|q| q.lp_id == "lp-bravo").unwrap();
        assert_eq!(bravo.pricing.unwrap().ttl_secs, LARGE_QUOTE_MAX_TTL_SECS);
    }

    #[tokio::test]
    async fn unpaid_swaps_release_their_stock() {
        let e = engine();
        let q = e.create_quote_for("1.2.3.4", in_req(100_000, None)).await.unwrap();
        let swap = e.open_swap(q.id).await.unwrap();
        let book = |lps: Vec<LiquidityProvider>| lps.into_iter().find(|l| l.id == "lp-alpha").unwrap().vtxo_sats;
        let held = book(e.inventory().await);

        // Not stale yet: nothing happens.
        e.sync_all().await.unwrap();
        assert_eq!(e.get_swap(swap.id).await.unwrap().status, SwapStatus::Quoted);

        e.inner.write().await.swaps.get_mut(&swap.id).unwrap().created_at -=
            Duration::seconds(UNPAID_SWAP_SECS + 1);
        e.sync_all().await.unwrap();
        let s = e.get_swap(swap.id).await.unwrap();
        assert_eq!(s.status, SwapStatus::Expired);
        assert!(s.demo_note.unwrap().contains("released"));
        assert_eq!(book(e.inventory().await), held + q.receive_sats);
        // The client's slot is free again: it may hold the full allowance.
        let inner = e.inner.read().await;
        assert!(check_client(&inner, Some("1.2.3.4"), MAX_OPEN_PER_CLIENT, 0).is_ok());
    }

    fn op(n: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: parse_txid(&format!("{n:02x}").repeat(32)).unwrap(),
            vout,
        }
    }

    #[test]
    fn unconfirmed_change_is_spendable_without_double_counting() {
        let mut spend = LpSpend::default();
        let confirmed = vec![(op(1, 0), 50_000), (op(2, 0), 80_000)];
        // One confirmed coin is already spent by our pending lock, whose
        // change came back to us.
        spend.l1.insert(op(2, 0));
        spend.pending.insert(op(3, 1), 29_000);
        let coins = spend.spendable_l1(&confirmed);
        assert_eq!(coins, vec![(op(1, 0), 50_000), (op(3, 1), 29_000)]);

        // Once the change confirms it shows in the scan: counted once, as confirmed.
        let confirmed = vec![(op(1, 0), 50_000), (op(3, 1), 29_000)];
        let coins = spend.spendable_l1(&confirmed);
        assert_eq!(coins.len(), 2);
        assert!(spend.pending.is_empty());
        // The spent marker for the coin that left the UTXO set is forgotten.
        assert!(spend.l1.is_empty());
    }

    #[test]
    fn outputs_to_finds_desk_change() {
        let desk = generate_keypair();
        let desk_addr = p2wpkh_address(&desk.secret, Network::Regtest);
        let user = p2wpkh_address(&generate_keypair().secret, Network::Regtest);
        let hex = p2wpkh_send_hex(
            &[(op(7, 0), 100_000)],
            &user,
            30_000,
            500,
            &desk_addr,
            &desk.secret,
            Network::Regtest,
        )
        .unwrap();
        let mine = outputs_to(&hex, &desk_addr.script_pubkey());
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].0.vout, 1);
        assert_eq!(mine[0].1, 100_000 - 30_000 - 500);
        assert_eq!(mine[0].0.txid, txid_of_hex(&hex).unwrap());
    }

    #[test]
    fn fees_follow_rate_and_size_and_bumps_are_capped() {
        // 2 sat/vB on a 1-in/2-out send: (11 + 68 + 86) vB.
        assert_eq!(fee_at(2_000, p2wpkh_send_vbytes(1, 2)), 330);
        assert_eq!(fee_at(1_500, 3), 5, "rounds up");
        assert_eq!(bumped_fee(300, 100_000), Some(600));
        assert_eq!(bumped_fee(40_000, 100_000), Some(50_000), "capped at half");
        assert_eq!(bumped_fee(50_000, 100_000), None, "nothing left to bump");
    }

    #[tokio::test]
    async fn desk_claim_is_sized_by_fee_rate_and_signals_rbf() {
        let e = engine();
        let q = e.create_quote(in_req(100_000, None)).await.unwrap();
        let s = e.open_swap(q.id).await.unwrap();
        let settled = e
            .observe_lock(
                s.id,
                ObserveLockRequest {
                    txid: "ab".repeat(32),
                    vout: 0,
                    value_sats: 100_000,
                },
            )
            .await
            .unwrap();
        assert_eq!(settled.l1_lock_value_sats, Some(100_000));
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(
            &hex::decode(settled.claim_tx_hex.unwrap()).unwrap(),
        )
        .unwrap();
        let fee = 100_000 - tx.output[0].value.to_sat();
        assert_eq!(fee, fee_at(MIN_FEE_RATE_MSAT_VB, HTLC_SPEND_VBYTES));
        assert!(tx.input[0].sequence.is_rbf(), "claim must be replaceable");
    }

    #[tokio::test]
    async fn stats_sum_settled_volume_fees_and_track_record() {
        let e = engine();
        for i in 0..2 {
            let q = e.create_quote(in_req(100_000, None)).await.unwrap();
            let s = e.open_swap(q.id).await.unwrap();
            e.observe_lock(
                s.id,
                ObserveLockRequest {
                    txid: format!("{i:064x}"),
                    vout: 0,
                    value_sats: 100_000,
                },
            )
            .await
            .unwrap();
            e.claim(s.id).await.unwrap();
        }
        // One accepted and left unpaid.
        let q = e.create_quote(in_req(50_000, None)).await.unwrap();
        e.open_swap(q.id).await.unwrap();

        let st = e.stats().await;
        assert_eq!(st["swaps"]["total"], 3);
        assert_eq!(st["swaps"]["settled"], 2);
        assert_eq!(st["swaps"]["by_status"]["claimed"], 2);
        assert_eq!(st["swaps"]["by_status"]["quoted"], 1);
        assert_eq!(st["swaps"]["volume_in_sats"], 200_000);
        let fee = fee_sats(100_000, 8_000, MIN_FEE_SATS);
        assert_eq!(st["swaps"]["fees_earned_sats"], 2 * fee);
        let alpha = st["desks"].as_array().unwrap().iter().find(|d| d["id"] == "lp-alpha").unwrap();
        assert_eq!(alpha["fills"], 2);
        assert_eq!(alpha["swaps_settled"], 2);
        assert_eq!(st["time"]["vault_exit_blocks"], VAULT_EXIT_BLOCKS);
        assert!(st["time"]["avg_settle_secs"].as_i64().is_some());
    }

    #[tokio::test]
    async fn quotes_are_signed_and_survive_a_json_round_trip() {
        let e = engine();
        let q = e.create_quote(in_req(100_000, None)).await.unwrap();
        // What the user holds is the JSON the API returned.
        let back: Quote = serde_json::from_str(&serde_json::to_string(&q).unwrap()).unwrap();
        let v = e.verify_quote(&back);
        assert_eq!(v["valid"], true, "{v}");

        let mut tampered = back.clone();
        tampered.fee_sats -= 1;
        let v = e.verify_quote(&tampered);
        assert_eq!(v["valid"], false);
        assert_eq!(v["signature_ok"], false);

        // A valid signature from the wrong key does not count as the desk's.
        let mut forged = back.clone();
        sign_quote(&mut forged, &generate_keypair().secret);
        let v = e.verify_quote(&forged);
        assert_eq!(v["signature_ok"], true);
        assert_eq!(v["signed_by_desk"], false);
        assert_eq!(v["valid"], false);
    }

    #[tokio::test]
    async fn disputes_compare_the_swap_with_the_signed_terms() {
        let e = engine();
        let q = e.create_quote(in_req(100_000, None)).await.unwrap();
        let none = e.dispute(&q).await;
        assert!(none["finding"].as_str().unwrap().contains("no swap"));

        let s = e.open_swap(q.id).await.unwrap();
        let ok = e.dispute(&q).await;
        assert_eq!(ok["terms_honoured"], true, "{ok}");

        // Had the desk quietly changed the fee, the signed quote proves it.
        e.inner.write().await.swaps.get_mut(&s.id).unwrap().fee_sats += 500;
        let bad = e.dispute(&q).await;
        assert_eq!(bad["terms_honoured"], false);
        assert!(bad["finding"].as_str().unwrap().contains("differ"));
    }
}
