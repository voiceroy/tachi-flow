//! Desk bonds on L1 (P2WSH):
//!
//! ```text
//! OP_IF
//!     <operator> OP_CHECKSIG                       slash / cooperative release
//! OP_ELSE
//!     <csv> OP_CSV OP_DROP <desk> OP_CHECKSIG      desk reclaims on its own
//! OP_ENDIF
//! ```
//!
//! The operator alone can pay a defaulting desk's users out of the bond (and
//! must re-lock the rest to the same script). The desk alone can always take
//! its bond back after `csv` blocks, so an operator who disappears or refuses
//! to release cannot freeze it. What this does *not* stop: the operator could
//! misuse the slash path, since Bitcoin script cannot pin where it pays.

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP, OP_ELSE, OP_ENDIF, OP_IF};
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Address, Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

use crate::error::Error;

/// Blocks a desk waits to reclaim its bond without the operator (~1 day).
pub const BOND_CSV_BLOCKS: u16 = 144;
/// Rough vsize of a bond spend (one P2WSH input, up to two outputs).
pub const BOND_SPEND_VBYTES: u64 = 180;

pub fn bond_script(operator: &PublicKey, desk: &PublicKey, csv_blocks: u16) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_IF)
        .push_key(operator)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ELSE)
        .push_int(i64::from(csv_blocks))
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_key(desk)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ENDIF)
        .into_script()
}

/// Operator path (IF): pay `outputs` from the bond (slash or release).
pub fn spend_as_operator(
    bond: OutPoint,
    value_sats: u64,
    script: &ScriptBuf,
    operator: &SecretKey,
    outputs: &[(Address, u64)],
) -> Result<String, Error> {
    spend(bond, value_sats, script, operator, outputs, Sequence::ENABLE_RBF_NO_LOCKTIME, &[1u8])
}

/// Desk path (ELSE): reclaim the whole bond after the CSV delay.
pub fn spend_as_desk(
    bond: OutPoint,
    value_sats: u64,
    script: &ScriptBuf,
    csv_blocks: u16,
    desk: &SecretKey,
    to: &Address,
    fee_sats: u64,
) -> Result<String, Error> {
    if value_sats <= fee_sats {
        return Err(Error::Invalid("bond is smaller than the fee".into()));
    }
    spend(
        bond,
        value_sats,
        script,
        desk,
        &[(to.clone(), value_sats - fee_sats)],
        Sequence::from_height(csv_blocks),
        &[],
    )
}

fn spend(
    bond: OutPoint,
    value_sats: u64,
    script: &ScriptBuf,
    signer: &SecretKey,
    outputs: &[(Address, u64)],
    sequence: Sequence,
    branch: &[u8],
) -> Result<String, Error> {
    let paid: u64 = outputs.iter().map(|(_, v)| v).sum();
    if outputs.is_empty() || paid >= value_sats {
        return Err(Error::Invalid("bond spend must leave a fee".into()));
    }
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bond,
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        }],
        output: outputs
            .iter()
            .map(|(addr, v)| TxOut {
                value: Amount::from_sat(*v),
                script_pubkey: addr.script_pubkey(),
            })
            .collect(),
    };
    let sighash = SighashCache::new(&tx)
        .p2wsh_signature_hash(0, script, Amount::from_sat(value_sats), EcdsaSighashType::All)
        .map_err(|e| Error::Bitcoin(e.to_string()))?;
    let sig = Secp256k1::new().sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), signer);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All as u8);
    let mut w = Witness::new();
    w.push(sig_bytes);
    w.push(branch);
    w.push(script.as_bytes());
    tx.input[0].witness = w;
    Ok(serialize_hex(&tx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::htlc::{generate_keypair, p2wpkh_address, p2wsh_address, parse_txid};
    use bitcoin::Network;

    #[test]
    fn operator_and_desk_paths_spend_the_right_branch() {
        let op = generate_keypair();
        let desk = generate_keypair();
        let script = bond_script(&op.public, &desk.public, BOND_CSV_BLOCKS);
        let addr = p2wsh_address(&script, Network::Regtest);
        assert_eq!(addr.address_type(), Some(bitcoin::AddressType::P2wsh));
        let bond = OutPoint {
            txid: parse_txid(&"bd".repeat(32)).unwrap(),
            vout: 0,
        };
        let user = p2wpkh_address(&generate_keypair().secret, Network::Regtest);

        // Slash: pay the user, re-lock the rest to the same bond.
        let hex = spend_as_operator(bond, 50_000, &script, &op.secret, &[(user.clone(), 1_000), (addr.clone(), 48_500)]).unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&hex::decode(&hex).unwrap()).unwrap();
        let w: Vec<&[u8]> = tx.input[0].witness.iter().collect();
        assert_eq!(w[1], &[1u8], "IF branch");
        assert_eq!(tx.output[1].script_pubkey, addr.script_pubkey());

        // Reclaim: ELSE branch with the CSV in nSequence.
        let to = p2wpkh_address(&desk.secret, Network::Regtest);
        let hex = spend_as_desk(bond, 50_000, &script, BOND_CSV_BLOCKS, &desk.secret, &to, 400).unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&hex::decode(&hex).unwrap()).unwrap();
        let w: Vec<&[u8]> = tx.input[0].witness.iter().collect();
        assert!(w[1].is_empty(), "ELSE branch");
        assert_eq!(
            tx.input[0].sequence.to_relative_lock_time(),
            Some(bitcoin::relative::LockTime::from_height(BOND_CSV_BLOCKS))
        );
        assert_eq!(tx.output[0].value.to_sat(), 49_600);

        assert!(spend_as_operator(bond, 1_000, &script, &op.secret, &[(user, 1_000)]).is_err());
    }
}
