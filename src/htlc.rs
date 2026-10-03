//! P2WSH HTLC: claimer spends with preimage; other party refunds after CLTV.
//! Inbound: LP claims, user refunds. Outbound: user claims, LP refunds.

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::opcodes::all::{
    OP_CHECKSIG,
    // rust-bitcoin 0.32: BIP-65 is `OP_CLTV` (also `OP_NOP2`). There is no
    // `OP_CHECKLOCKTIMEVERIFY` in `opcodes::all`.
    OP_CLTV as OP_CHECKLOCKTIMEVERIFY,
    OP_DROP,
    OP_ELSE,
    OP_ENDIF,
    OP_EQUALVERIFY,
    OP_IF,
    OP_SHA256,
};
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    Address, Amount, KnownHrp, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness, secp256k1,
};

use crate::error::Error;

pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

pub fn generate_keypair() -> Keypair {
    let secp = Secp256k1::new();
    let secret = SecretKey::new(&mut secp256k1::rand::thread_rng());
    let public = PublicKey::new(secp256k1::PublicKey::from_secret_key(&secp, &secret));
    Keypair { secret, public }
}

pub fn p2wpkh_address(secret: &SecretKey, network: Network) -> Address {
    let secp = Secp256k1::new();
    let public = PublicKey::new(secp256k1::PublicKey::from_secret_key(&secp, secret));
    let compressed = bitcoin::CompressedPublicKey::try_from(public).expect("compressed");
    Address::p2wpkh(&compressed, KnownHrp::from(network))
}

pub fn pubkey_from_hex(hex: &str) -> Result<PublicKey, Error> {
    let bytes = hex::decode(hex.trim()).map_err(|e| Error::Invalid(e.to_string()))?;
    PublicKey::from_slice(&bytes).map_err(|e| Error::Bitcoin(e.to_string()))
}

pub fn payment_hash(preimage: &[u8; 32]) -> sha256::Hash {
    sha256::Hash::hash(preimage)
}

/// Standard swap HTLC redeem script:
/// `OP_IF OP_SHA256 <hash> OP_EQUALVERIFY <claimer> OP_CHECKSIG
///  OP_ELSE <lock> OP_CLTV OP_DROP <refunder> OP_CHECKSIG OP_ENDIF`
pub fn redeem_script(
    payment_hash: &sha256::Hash,
    claimer: &PublicKey,
    refunder: &PublicKey,
    timeout: LockTime,
) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_IF)
        .push_opcode(OP_SHA256)
        .push_slice(payment_hash.to_byte_array())
        .push_opcode(OP_EQUALVERIFY)
        .push_key(claimer)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ELSE)
        .push_lock_time(timeout)
        .push_opcode(OP_CHECKLOCKTIMEVERIFY)
        .push_opcode(OP_DROP)
        .push_key(refunder)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ENDIF)
        .into_script()
}

pub fn p2wsh_address(script: &ScriptBuf, network: Network) -> Address {
    Address::p2wsh(script, KnownHrp::from(network))
}

pub fn random_preimage() -> [u8; 32] {
    let sk = SecretKey::new(&mut secp256k1::rand::thread_rng());
    sk.secret_bytes()
}

/// Rough vsize of an HTLC claim or refund: one P2WSH input with the redeem
/// script, signature and (for a claim) preimage, and one output.
pub const HTLC_SPEND_VBYTES: u64 = 150;

/// Rough vsize of a P2WPKH wallet send.
pub fn p2wpkh_send_vbytes(inputs: usize, outputs: usize) -> u64 {
    // 11 overhead, 68 per P2WPKH input, 43 per output (P2WSH; P2WPKH is 31).
    11 + 68 * inputs as u64 + 43 * outputs as u64
}

/// Sign a P2WSH claim (IF branch: preimage + claimer signature). Signals
/// RBF so a stuck claim can be fee-bumped before the refund path opens.
pub fn claim_tx_hex(
    funding: OutPoint,
    value_sats: u64,
    fee_sats: u64,
    redeem: &ScriptBuf,
    preimage: &[u8; 32],
    claimer_secret: &SecretKey,
    destination: &Address,
) -> Result<String, Error> {
    spend_htlc(
        funding,
        value_sats,
        fee_sats,
        redeem,
        claimer_secret,
        destination,
        LockTime::ZERO,
        Sequence::ENABLE_RBF_NO_LOCKTIME,
        &[preimage.as_slice(), &[1u8]],
    )
}

/// Sign a P2WSH refund (ELSE branch: refunder signature after the CLTV timeout).
pub fn refund_tx_hex(
    funding: OutPoint,
    value_sats: u64,
    fee_sats: u64,
    redeem: &ScriptBuf,
    timeout: LockTime,
    refunder_secret: &SecretKey,
    destination: &Address,
) -> Result<String, Error> {
    // Empty push selects OP_ELSE (MINIMALIF). nLockTime must reach the CLTV
    // value and the input must not be final, or CLTV fails.
    spend_htlc(
        funding,
        value_sats,
        fee_sats,
        redeem,
        refunder_secret,
        destination,
        timeout,
        Sequence::ENABLE_LOCKTIME_NO_RBF,
        &[&[]],
    )
}

#[allow(clippy::too_many_arguments)]
fn spend_htlc(
    funding: OutPoint,
    value_sats: u64,
    fee_sats: u64,
    redeem: &ScriptBuf,
    secret: &SecretKey,
    destination: &Address,
    lock_time: LockTime,
    sequence: Sequence,
    branch: &[&[u8]],
) -> Result<String, Error> {
    if value_sats <= fee_sats {
        return Err(Error::Invalid("HTLC spend fee exceeds value".into()));
    }
    let secp = Secp256k1::new();
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time,
        input: vec![TxIn {
            previous_output: funding,
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value_sats - fee_sats),
            script_pubkey: destination.script_pubkey(),
        }],
    };

    let mut cache = SighashCache::new(&tx);
    let sighash = cache
        .p2wsh_signature_hash(
            0,
            redeem.as_script(),
            Amount::from_sat(value_sats),
            EcdsaSighashType::All,
        )
        .map_err(|e| Error::Bitcoin(e.to_string()))?;

    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_ecdsa(&msg, secret);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All as u8);

    let mut witness = Witness::new();
    witness.push(sig_bytes);
    for item in branch {
        witness.push(item);
    }
    witness.push(redeem.as_bytes());
    tx.input[0].witness = witness;

    Ok(serialize_hex(&tx))
}

/// Txid of a raw transaction, so a re-broadcast can be recognised as the same tx.
pub fn txid_of_hex(hex_tx: &str) -> Result<Txid, Error> {
    let bytes = hex::decode(hex_tx).map_err(|e| Error::Invalid(e.to_string()))?;
    let tx: Transaction = bitcoin::consensus::deserialize(&bytes)
        .map_err(|e| Error::Bitcoin(e.to_string()))?;
    Ok(tx.compute_txid())
}

/// Sign a P2WPKH payment from `lp_secret` (the LP claim address).
pub fn p2wpkh_send_hex(
    inputs: &[(OutPoint, u64)],
    dest: &Address,
    send_sats: u64,
    fee_sats: u64,
    change: &Address,
    lp_secret: &SecretKey,
    network: Network,
) -> Result<String, Error> {
    p2wpkh_send_many_hex(
        inputs,
        &[(dest.clone(), send_sats)],
        fee_sats,
        change,
        lp_secret,
        network,
    )
}

/// Like [`p2wpkh_send_hex`] but pays several outputs in one tx (output order
/// is preserved, so output `i` is `outputs[i]`; change goes last).
pub fn p2wpkh_send_many_hex(
    inputs: &[(OutPoint, u64)],
    outputs: &[(Address, u64)],
    fee_sats: u64,
    change: &Address,
    lp_secret: &SecretKey,
    network: Network,
) -> Result<String, Error> {
    if outputs.is_empty() {
        return Err(Error::Invalid("payment needs at least one output".into()));
    }
    let total: u64 = inputs.iter().map(|(_, v)| *v).sum();
    let send_sats: u64 = outputs.iter().map(|(_, v)| *v).sum();
    let need = send_sats.saturating_add(fee_sats);
    if total < need {
        return Err(Error::Invalid(format!(
            "L1 wallet has {total} sats, need {need}"
        )));
    }
    let secp = Secp256k1::new();
    let lp_pub = PublicKey::new(secp256k1::PublicKey::from_secret_key(&secp, lp_secret));
    let compressed =
        bitcoin::CompressedPublicKey::try_from(lp_pub).map_err(|e| Error::Bitcoin(e.to_string()))?;
    let spk = bitcoin::Address::p2wpkh(&compressed, bitcoin::KnownHrp::from(network)).script_pubkey();

    let mut outputs: Vec<TxOut> = outputs
        .iter()
        .map(|(addr, sats)| TxOut {
            value: Amount::from_sat(*sats),
            script_pubkey: addr.script_pubkey(),
        })
        .collect();
    let change_sats = total - need;
    if change_sats > 0 {
        outputs.push(TxOut {
            value: Amount::from_sat(change_sats),
            script_pubkey: change.script_pubkey(),
        });
    }

    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs
            .iter()
            .map(|(op, _)| TxIn {
                previous_output: *op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs,
    };

    for (i, (_, value)) in inputs.iter().enumerate() {
        let mut cache = SighashCache::new(&tx);
        let sighash = cache
            .p2wpkh_signature_hash(i, &spk, Amount::from_sat(*value), EcdsaSighashType::All)
            .map_err(|e| Error::Bitcoin(e.to_string()))?;
        let msg = Message::from_digest(sighash.to_byte_array());
        let sig = secp.sign_ecdsa(&msg, lp_secret);
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(EcdsaSighashType::All as u8);
        let mut witness = Witness::new();
        witness.push(sig_bytes);
        witness.push(lp_pub.to_bytes());
        tx.input[i].witness = witness;
    }
    Ok(serialize_hex(&tx))
}

pub fn parse_txid(hex: &str) -> Result<Txid, Error> {
    hex.parse::<Txid>().map_err(|e| Error::Bitcoin(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbound_address_is_p2wsh_signet() {
        let lp = generate_keypair();
        let user = generate_keypair();
        let preimage = random_preimage();
        let hash = payment_hash(&preimage);
        let timeout = LockTime::from_height(200_000).expect("height");
        let script = redeem_script(&hash, &lp.public, &user.public, timeout);
        let addr = p2wsh_address(&script, Network::Signet);
        let s = addr.to_string();
        assert!(s.starts_with("tb1"), "{s}");
        assert_eq!(addr.address_type(), Some(bitcoin::AddressType::P2wsh));
    }

    #[test]
    fn batched_send_keeps_output_order() {
        let lp = generate_keypair();
        let change = p2wpkh_address(&lp.secret, Network::Regtest);
        let a = p2wpkh_address(&generate_keypair().secret, Network::Regtest);
        let b = p2wpkh_address(&generate_keypair().secret, Network::Regtest);
        let input = (
            OutPoint {
                txid: parse_txid(&"cd".repeat(32)).unwrap(),
                vout: 1,
            },
            100_000,
        );
        let hex = p2wpkh_send_many_hex(
            &[input],
            &[(a.clone(), 20_000), (b.clone(), 30_000)],
            500,
            &change,
            &lp.secret,
            Network::Regtest,
        )
        .unwrap();
        let tx: Transaction =
            bitcoin::consensus::deserialize(&hex::decode(&hex).unwrap()).unwrap();
        assert_eq!(tx.output.len(), 3);
        assert_eq!(tx.output[0].script_pubkey, a.script_pubkey());
        assert_eq!(tx.output[1].script_pubkey, b.script_pubkey());
        assert_eq!(tx.output[2].value, Amount::from_sat(100_000 - 50_000 - 500));
    }

    #[test]
    fn refund_spends_else_branch_after_timeout() {
        let lp = generate_keypair();
        let user = generate_keypair();
        let hash = payment_hash(&random_preimage());
        let timeout = LockTime::from_height(15_000).expect("height");
        let script = redeem_script(&hash, &lp.public, &user.public, timeout);
        let dest = p2wpkh_address(&user.secret, Network::Regtest);
        let funding = OutPoint {
            txid: parse_txid(&"ab".repeat(32)).unwrap(),
            vout: 0,
        };
        let hex = refund_tx_hex(funding, 20_000, 500, &script, timeout, &user.secret, &dest).unwrap();
        let tx: Transaction =
            bitcoin::consensus::deserialize(&hex::decode(&hex).unwrap()).unwrap();
        assert_eq!(tx.lock_time, timeout);
        assert!(tx.input[0].sequence.enables_absolute_lock_time());
        let w: Vec<&[u8]> = tx.input[0].witness.iter().collect();
        assert_eq!(w.len(), 3);
        assert!(w[1].is_empty(), "ELSE branch selector must be empty");
        assert_eq!(w[2], script.as_bytes());
        assert_eq!(txid_of_hex(&hex).unwrap(), tx.compute_txid());
    }
}
