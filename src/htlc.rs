//! P2WSH HTLC: LP claims with preimage, user refunds after CLTV.

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

pub fn pubkey_from_hex(hex: &str) -> Result<PublicKey, Error> {
    let bytes = hex::decode(hex.trim()).map_err(|e| Error::Invalid(e.to_string()))?;
    PublicKey::from_slice(&bytes).map_err(|e| Error::Bitcoin(e.to_string()))
}

pub fn payment_hash(preimage: &[u8; 32]) -> sha256::Hash {
    sha256::Hash::hash(preimage)
}

/// Standard swap HTLC redeem script:
/// `OP_IF OP_SHA256 <hash> OP_EQUALVERIFY <lp> OP_CHECKSIG
///  OP_ELSE <lock> OP_CLTV OP_DROP <user> OP_CHECKSIG OP_ENDIF`
pub fn redeem_script(
    payment_hash: &sha256::Hash,
    lp_pubkey: &PublicKey,
    user_pubkey: &PublicKey,
    timeout: LockTime,
) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_IF)
        .push_opcode(OP_SHA256)
        .push_slice(payment_hash.to_byte_array())
        .push_opcode(OP_EQUALVERIFY)
        .push_key(lp_pubkey)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ELSE)
        .push_lock_time(timeout)
        .push_opcode(OP_CHECKLOCKTIMEVERIFY)
        .push_opcode(OP_DROP)
        .push_key(user_pubkey)
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

/// Sign a P2WSH claim (IF branch: preimage + LP signature).
pub fn claim_tx_hex(
    funding: OutPoint,
    value_sats: u64,
    fee_sats: u64,
    redeem: &ScriptBuf,
    preimage: &[u8; 32],
    lp_secret: &SecretKey,
    destination: &Address,
) -> Result<String, Error> {
    if value_sats <= fee_sats {
        return Err(Error::Invalid("claim fee exceeds value".into()));
    }

    let secp = Secp256k1::new();
    let lp_pub = PublicKey::new(secp256k1::PublicKey::from_secret_key(&secp, lp_secret));

    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: funding,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
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
    let sig = secp.sign_ecdsa(&msg, lp_secret);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All as u8);

    let mut witness = Witness::new();
    witness.push(sig_bytes);
    witness.push(preimage);
    witness.push([1u8]);
    witness.push(redeem.as_bytes());
    tx.input[0].witness = witness;

    let _ = lp_pub;
    Ok(serialize_hex(&tx))
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
    let total: u64 = inputs.iter().map(|(_, v)| *v).sum();
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

    let mut outputs = vec![TxOut {
        value: Amount::from_sat(send_sats),
        script_pubkey: dest.script_pubkey(),
    }];
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
                sequence: Sequence::MAX,
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
    hex.parse::<Txid>()
        .map_err(|e| Error::Bitcoin(e.to_string()))
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
}
