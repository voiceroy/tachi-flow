//! Claim advances: a desk buys a timelocked output that is still maturing
//! (e.g. a vault refund waiting out its delay) and pays bitcoin now.
//!
//! The user hands over a spend of that output to the desk, signed now but only
//! valid once the CSV delay has passed. The desk checks every part of it here
//! before paying: the script, the outpoint, the relative timelock, the payee,
//! and the signature. What it cannot rule out is the user spending the output
//! first once it matures; the discount prices that race.
//!
//! Supported script (P2WSH): `<csv> OP_CSV OP_DROP <pubkey> OP_CHECKSIG`.

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP};
use bitcoin::script::{Builder, Instruction};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};

use crate::error::Error;

/// Risk of the user racing the desk at maturity, charged on every advance.
pub const BASE_DISCOUNT_PPM: u64 = 5_000;
/// Time value of the desk's bitcoin while it waits, per block to maturity.
pub const PER_BLOCK_DISCOUNT_PPM: u64 = 20;
/// Fee the pre-signed spend may leave for miners.
pub const MAX_SPEND_FEE_SATS: u64 = 1_000;

pub fn csv_script(csv_blocks: u32, owner: &PublicKey) -> ScriptBuf {
    Builder::new()
        .push_int(i64::from(csv_blocks))
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_key(owner)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// `(csv_blocks, owner)` if `script` is exactly the supported template.
pub fn parse_csv_script(script: &ScriptBuf) -> Option<(u32, PublicKey)> {
    let ins: Vec<Instruction> = script.instructions().collect::<Result<_, _>>().ok()?;
    let [csv, Instruction::Op(cs), Instruction::Op(drop), Instruction::PushBytes(key), Instruction::Op(chk)] =
        ins.as_slice()
    else {
        return None;
    };
    if *cs != OP_CSV || *drop != OP_DROP || *chk != OP_CHECKSIG {
        return None;
    }
    let csv = match csv {
        Instruction::PushBytes(b) => {
            let b = b.as_bytes();
            if b.is_empty() || b.len() > 3 {
                return None;
            }
            let mut v = 0u32;
            for (i, byte) in b.iter().enumerate() {
                v |= u32::from(*byte) << (8 * i);
            }
            // Negative or flagged (time-based) delays are not block delays.
            if v & 0x0040_0000 != 0 || b[b.len() - 1] & 0x80 != 0 {
                return None;
            }
            v
        }
        Instruction::Op(op) => {
            let code = op.to_u8();
            // OP_1..OP_16
            if !(0x51..=0x60).contains(&code) {
                return None;
            }
            u32::from(code - 0x50)
        }
    };
    if csv == 0 || csv > 0xffff {
        return None;
    }
    let owner = PublicKey::from_slice(key.as_bytes()).ok()?;
    Some((csv, owner))
}

/// Discount the desk keeps for advancing `value_sats` that matures in `blocks_left`.
pub fn discount_sats(value_sats: u64, blocks_left: u32) -> u64 {
    let ppm = BASE_DISCOUNT_PPM + PER_BLOCK_DISCOUNT_PPM * u64::from(blocks_left);
    (u128::from(value_sats) * u128::from(ppm) / 1_000_000) as u64
}

/// Check the user's pre-signed spend before paying for it.
pub struct ExpectedSpend<'a> {
    pub outpoint: OutPoint,
    pub value_sats: u64,
    pub script: &'a ScriptBuf,
    pub csv_blocks: u32,
    pub owner: &'a PublicKey,
    pub desk_address: &'a Address,
    pub min_desk_sats: u64,
}

pub fn verify_presigned(tx_hex: &str, want: &ExpectedSpend) -> Result<Transaction, Error> {
    let bad = |why: &str| Error::Invalid(format!("pre-signed spend: {why}"));
    let bytes = hex::decode(tx_hex.trim()).map_err(|_| bad("not hex"))?;
    let tx: Transaction =
        bitcoin::consensus::deserialize(&bytes).map_err(|e| bad(&e.to_string()))?;
    if tx.version.0 < 2 {
        return Err(bad("version must be 2 for a CSV spend"));
    }
    let [input] = tx.input.as_slice() else {
        return Err(bad("must spend exactly the one output"));
    };
    if input.previous_output != want.outpoint {
        return Err(bad("spends the wrong outpoint"));
    }
    match input.sequence.to_relative_lock_time() {
        Some(bitcoin::relative::LockTime::Blocks(h)) if u32::from(h.value()) >= want.csv_blocks => {}
        _ => return Err(bad("sequence must carry the output's CSV block delay")),
    }
    let paid: u64 = tx
        .output
        .iter()
        .filter(|o| o.script_pubkey == want.desk_address.script_pubkey())
        .map(|o| o.value.to_sat())
        .sum();
    if paid < want.min_desk_sats {
        return Err(bad(&format!(
            "pays the desk {paid} sats, needs at least {}",
            want.min_desk_sats
        )));
    }
    let witness: Vec<&[u8]> = input.witness.iter().collect();
    let [sig, script] = witness.as_slice() else {
        return Err(bad("witness must be <signature> <witness script>"));
    };
    if *script != want.script.as_bytes() {
        return Err(bad("witness script does not match the output"));
    }
    let (hash_ty, sig_der) = sig.split_last().ok_or_else(|| bad("empty signature"))?;
    if *hash_ty != EcdsaSighashType::All as u8 {
        return Err(bad("signature must be SIGHASH_ALL"));
    }
    let sig = bitcoin::secp256k1::ecdsa::Signature::from_der(sig_der)
        .map_err(|_| bad("signature is not DER"))?;
    let sighash = SighashCache::new(&tx)
        .p2wsh_signature_hash(
            0,
            want.script,
            Amount::from_sat(want.value_sats),
            EcdsaSighashType::All,
        )
        .map_err(|e| bad(&e.to_string()))?;
    Secp256k1::verification_only()
        .verify_ecdsa(
            &Message::from_digest(sighash.to_byte_array()),
            &sig,
            &want.owner.inner,
        )
        .map_err(|_| bad("signature does not verify for the output's key"))?;
    Ok(tx)
}

/// Sign the spend a user hands to the desk (demo helper; a wallet does this).
pub fn presign_spend(
    outpoint: OutPoint,
    value_sats: u64,
    script: &ScriptBuf,
    csv_blocks: u32,
    owner_secret: &SecretKey,
    pay_to: &Address,
    pay_sats: u64,
) -> Result<String, Error> {
    if pay_sats > value_sats {
        return Err(Error::Invalid("spend pays more than the output holds".into()));
    }
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_height(csv_blocks as u16),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(pay_sats),
            script_pubkey: pay_to.script_pubkey(),
        }],
    };
    let sighash = SighashCache::new(&tx)
        .p2wsh_signature_hash(0, script, Amount::from_sat(value_sats), EcdsaSighashType::All)
        .map_err(|e| Error::Bitcoin(e.to_string()))?;
    let sig = Secp256k1::new().sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), owner_secret);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All as u8);
    let mut w = Witness::new();
    w.push(sig_bytes);
    w.push(script.as_bytes());
    tx.input[0].witness = w;
    Ok(serialize_hex(&tx))
}

pub fn p2wsh(script: &ScriptBuf, network: Network) -> Address {
    Address::p2wsh(script, bitcoin::KnownHrp::from(network))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::htlc::{generate_keypair, p2wpkh_address, parse_txid};

    fn setup() -> (crate::htlc::Keypair, ScriptBuf, OutPoint, Address) {
        let user = generate_keypair();
        let script = csv_script(144, &user.public);
        let op = OutPoint {
            txid: parse_txid(&"ef".repeat(32)).unwrap(),
            vout: 0,
        };
        let desk = p2wpkh_address(&generate_keypair().secret, Network::Regtest);
        (user, script, op, desk)
    }

    #[test]
    fn template_roundtrips_small_and_large_delays() {
        let user = generate_keypair();
        for csv in [1u32, 16, 17, 144, 1008, 65_535] {
            let s = csv_script(csv, &user.public);
            assert_eq!(parse_csv_script(&s), Some((csv, user.public)), "csv {csv}");
        }
        let other = crate::htlc::redeem_script(
            &crate::htlc::payment_hash(&[1; 32]),
            &user.public,
            &user.public,
            LockTime::from_height(100).unwrap(),
        );
        assert_eq!(parse_csv_script(&other), None);
    }

    #[test]
    fn good_presigned_spend_verifies() {
        let (user, script, op, desk) = setup();
        let hex = presign_spend(op, 50_000, &script, 144, &user.secret, &desk, 49_500).unwrap();
        let want = ExpectedSpend {
            outpoint: op,
            value_sats: 50_000,
            script: &script,
            csv_blocks: 144,
            owner: &user.public,
            desk_address: &desk,
            min_desk_sats: 49_000,
        };
        verify_presigned(&hex, &want).expect("valid");
    }

    #[test]
    fn rejects_wrong_key_short_delay_and_underpayment() {
        let (user, script, op, desk) = setup();
        let want = |min| ExpectedSpend {
            outpoint: op,
            value_sats: 50_000,
            script: &script,
            csv_blocks: 144,
            owner: &user.public,
            desk_address: &desk,
            min_desk_sats: min,
        };
        let stranger = generate_keypair();
        let forged = presign_spend(op, 50_000, &script, 144, &stranger.secret, &desk, 49_500).unwrap();
        assert!(verify_presigned(&forged, &want(49_000)).unwrap_err().to_string().contains("does not verify"));

        let early = presign_spend(op, 50_000, &script, 10, &user.secret, &desk, 49_500).unwrap();
        assert!(verify_presigned(&early, &want(49_000)).unwrap_err().to_string().contains("CSV"));

        let cheap = presign_spend(op, 50_000, &script, 144, &user.secret, &desk, 40_000).unwrap();
        assert!(verify_presigned(&cheap, &want(49_000)).unwrap_err().to_string().contains("pays the desk"));

        // Signed for a different value: the sighash commits to the amount.
        let wrong_value = presign_spend(op, 60_000, &script, 144, &user.secret, &desk, 49_500).unwrap();
        assert!(verify_presigned(&wrong_value, &want(49_000)).is_err());
    }

    #[test]
    fn discount_grows_with_wait() {
        assert_eq!(discount_sats(1_000_000, 0), 5_000);
        assert_eq!(discount_sats(1_000_000, 1008), 5_000 + 20_160);
    }
}
