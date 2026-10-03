use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    In,
    Out,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapStatus {
    Quoted,
    InboundLocked,
    OutboundPaid,
    LpSettled,
    Claimed,
    Refunded,
    Failed,
    /// Too close to the HTLC timeout to settle safely. Funds go back via refund.
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidityProvider {
    pub id: String,
    pub l1_sats: u64,
    pub vtxo_sats: u64,
    pub fee_ppm: u64,
    pub max_swap_sats: u64,
    pub defaulted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tachi_pubkey: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l1_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Desk float sits behind a TAURUS-style 1008-block unilateral exit if
    /// you used the vault instead of this swap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_exit_blocks: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backing: Option<String>,
    /// VTXOs this desk has posted to escrow. Pays users when the desk defaults.
    #[serde(default)]
    pub bond_sats: u64,
    /// Swaps this desk completed.
    #[serde(default)]
    pub fills: u64,
    /// Swaps this desk failed (never locked for `out`, never paid a funded `in`).
    #[serde(default)]
    pub defaults: u64,
    /// `(fills + 1) / (fills + defaults + 2)` in ppm; below 400k the desk stops routing.
    #[serde(default)]
    pub score_ppm: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quote {
    pub id: Uuid,
    pub side: Side,
    pub amount_sats: u64,
    pub fee_sats: u64,
    pub receive_sats: u64,
    pub lp_id: String,
    pub eta_seconds: u64,
    pub expires_at: DateTime<Utc>,
    pub user_tachi_address: Option<String>,
    pub user_l1_address: Option<String>,
    pub pay: PayInstructions,
    /// Plain-language refund / next-step copy for the UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// TAURUS unilateral exit (~a week). Swap exists to skip this.
    #[serde(default)]
    pub vault_exit_blocks: u32,
    #[serde(default)]
    pub swap_timeout_blocks: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comparison: Option<String>,
    /// Compressed pubkey the user controls (refund key `in`, claim key `out`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_pubkey_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pricing: Option<PriceBreakdown>,
    /// Set when this quote came from an RFQ. Accepting one releases the rest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rfq_id: Option<Uuid>,
    /// Outbound with a deadline: the desk locks bitcoin by this height.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_by_height: Option<u32>,
    /// Set when this quote is one leg of a split exit plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<Uuid>,
    /// The quoting desk's Tachi key (x-only hex) and its BIP340 signature over
    /// the quote's terms (see `quote_commitment`), so a user can prove later
    /// what the desk promised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desk_pubkey: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desk_signature: Option<String>,
}

/// One amount split across desks: each leg is an ordinary quote, then swap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitPlan {
    pub id: Uuid,
    pub side: Side,
    pub amount_sats: u64,
    pub fee_sats: u64,
    pub receive_sats: u64,
    pub legs: Vec<Quote>,
    /// Filled in once the plan is accepted.
    #[serde(default)]
    pub swap_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePlanRequest {
    #[serde(flatten)]
    pub quote: CreateQuoteRequest,
    /// Largest leg to send any one desk (default: the desk's own limit).
    #[serde(default)]
    pub max_leg_sats: Option<u64>,
}

/// How a quote's fee was built. All figures are parts per million of the amount,
/// except the shares, which are parts per million of the desk's books.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceBreakdown {
    pub base_ppm: u64,
    /// Inventory skew: positive when this swap drains the desk's scarce side.
    pub skew_ppm: i64,
    /// Cost of holding the price firm for the quote's TTL.
    pub ttl_ppm: i64,
    /// Discount for letting the desk lock bitcoin later (outbound deadline).
    pub deadline_discount_ppm: i64,
    pub fee_ppm: u64,
    pub vtxo_share_before_ppm: u64,
    pub vtxo_share_after_ppm: u64,
    pub ttl_secs: u64,
    pub deadline_blocks: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum PayInstructions {
    L1Htlc {
        address: String,
        payment_hash_hex: String,
        timeout_height: u32,
        redeem_script_hex: String,
    },
    TachiVtxo {
        pay_to: String,
        memo: String,
        /// Outbound: LP funds this HTLC first; user claims with preimage after paying VTXOs.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lock: Option<HtlcLock>,
    },
}

impl PayInstructions {
    /// The L1 HTLC behind this swap: the user's lock (`in`) or the desk's (`out`).
    pub fn htlc(&self) -> Option<HtlcLock> {
        match self {
            Self::L1Htlc {
                address,
                payment_hash_hex,
                timeout_height,
                redeem_script_hex,
            } => Some(HtlcLock {
                address: address.clone(),
                payment_hash_hex: payment_hash_hex.clone(),
                timeout_height: *timeout_height,
                redeem_script_hex: redeem_script_hex.clone(),
            }),
            Self::TachiVtxo { lock, .. } => lock.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HtlcLock {
    pub address: String,
    pub payment_hash_hex: String,
    pub timeout_height: u32,
    pub redeem_script_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Swap {
    pub id: Uuid,
    pub quote_id: Uuid,
    pub side: Side,
    pub status: SwapStatus,
    pub lp_id: String,
    pub amount_sats: u64,
    pub fee_sats: u64,
    pub receive_sats: u64,
    pub pay: PayInstructions,
    pub user_tachi_address: Option<String>,
    pub user_l1_address: Option<String>,
    pub l1_lock_txid: Option<String>,
    pub vtxo_payment_id: Option<String>,
    pub tachi_tx_hash: Option<String>,
    pub claim_tx_hex: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Faucet drip that funded the ephemeral P2WPKH (demo helper).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub faucet_txid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fund_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub demo_note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_pubkey_hex: Option<String>,
    /// L1 refund of the HTLC after its timeout (user for `in`, desk for `out`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refund_txid: Option<String>,
    /// Outbound: revealed once the desk sees your VTXOs, so you can claim the
    /// desk's lock with any wallet, not only through this server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preimage_hex: Option<String>,
    /// Outbound with a deadline: the desk locks bitcoin by this height.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_by_height: Option<u32>,
    /// Output index of the desk's lock (batched locks share one tx).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l1_lock_vout: Option<u32>,
    /// How many outbound locks shared the desk's funding tx.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_batch_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<Uuid>,
    /// The desk failed this swap (see `LiquidityProvider::defaults`).
    #[serde(default)]
    pub desk_defaulted: bool,
    /// VTXOs paid to the user from the desk's bond after a default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compensation_sats: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compensation_vtxo_id: Option<String>,
    /// Value of the user's inbound lock, kept so a stuck desk claim can be
    /// re-signed at a higher fee.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l1_lock_value_sats: Option<u64>,
    /// The desk's inbound claim has at least one confirmation.
    #[serde(default)]
    pub claim_confirmed: bool,
}

/// A desk buying a maturing timelocked output for bitcoin now (claim advance).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advance {
    pub id: Uuid,
    pub lp_id: String,
    pub status: AdvanceStatus,
    pub outpoint_txid: String,
    pub outpoint_vout: u32,
    pub value_sats: u64,
    pub witness_script_hex: String,
    /// The output's CSV delay and the height it becomes spendable.
    pub csv_blocks: u32,
    pub mature_height: u32,
    /// Where the user's pre-signed spend must pay, and at least how much.
    pub desk_address: String,
    pub min_desk_sats: u64,
    pub discount_sats: u64,
    pub advance_sats: u64,
    pub user_l1_address: String,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advance_txid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presigned_tx_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collect_txid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvanceStatus {
    /// Priced; waiting for the user's pre-signed spend.
    Quoted,
    /// Desk paid the advance; waiting for the output to mature.
    Advanced,
    /// Desk broadcast the pre-signed spend after maturity.
    Collected,
    /// The output was spent elsewhere first (the risk the discount prices).
    Lost,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvanceQuoteRequest {
    pub txid: String,
    pub vout: u32,
    /// `<csv> OP_CSV OP_DROP <pubkey> OP_CHECKSIG` behind the P2WSH output.
    pub witness_script_hex: String,
    pub user_l1_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvanceAcceptRequest {
    /// Spend of the output to `desk_address`, signed by the user.
    pub presigned_tx_hex: String,
}

/// Swap between Tachi VTXOs and Lightning, through the desk's LN node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnSwap {
    pub id: Uuid,
    pub direction: LnDirection,
    pub status: LnStatus,
    pub lp_id: String,
    pub amount_sats: u64,
    pub fee_sats: u64,
    pub receive_sats: u64,
    pub payment_hash_hex: String,
    /// `in`: the hold invoice the user pays. `out`: the user's invoice the desk pays.
    pub invoice: String,
    /// `in`: where the desk sends VTXOs. `out`: where the user sends VTXOs.
    pub tachi_address: String,
    /// `out`: where VTXOs go back if the Lightning payment definitively fails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refund_tachi_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vtxo_payment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LnDirection {
    /// Lightning in, VTXOs out to the user.
    In,
    /// VTXOs in, Lightning payment out to the user.
    Out,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LnStatus {
    /// `in`: waiting for the user to pay the hold invoice. `out`: waiting for VTXOs.
    Waiting,
    /// `in`: the user's HTLC is held; desk is paying VTXOs.
    Accepted,
    /// `in`: VTXOs paid and invoice settled. `out`: invoice paid.
    Completed,
    /// `in`: invoice cancelled, the user's HTLC returned.
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnQuoteRequest {
    pub direction: LnDirection,
    /// `in` only (the invoice amount). For `out` the amount comes from the invoice.
    #[serde(default)]
    pub amount_sats: Option<u64>,
    /// `out`: the user's BOLT11 invoice. `in`: unused.
    #[serde(default)]
    pub invoice: Option<String>,
    /// The user's Tachi key: receives VTXOs (`in`) or refunds (`out`).
    #[serde(default)]
    pub user_tachi_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookRequest {
    pub url: String,
    /// Only events for this swap (default: every swap).
    #[serde(default)]
    pub swap_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateQuoteRequest {
    pub side: Side,
    pub amount_sats: u64,
    pub user_tachi_address: Option<String>,
    pub user_l1_address: Option<String>,
    /// Compressed secp256k1 pubkey hex (33 bytes). Required for `in` so the
    /// HTLC refund path is the user's key.
    pub user_refund_pubkey_hex: Option<String>,
    /// How long the price stays firm (30..=3600 s, default 600). Longer costs more.
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    /// Outbound only: blocks the desk may wait before locking bitcoin for you
    /// (0..=1008, default 0). Later is cheaper; 1008 matches a vault exit.
    #[serde(default)]
    pub deadline_blocks: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSwapRequest {
    pub quote_id: Uuid,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObserveLockRequest {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserveVtxoRequest {
    pub vtxo_id: String,
}

pub fn fee_sats(amount: u64, fee_ppm: u64, min_fee: u64) -> u64 {
    let proportional = amount.saturating_mul(fee_ppm) / 1_000_000;
    proportional.max(min_fee)
}
