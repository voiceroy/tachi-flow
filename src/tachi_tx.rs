//! TachiTx transfer envelope (Tachid `types.EncodeTx`, big-endian).
//!
//! Wire layout from `@tachibtc/taurus-vault-core` 0.3.4 `encodeTachiTx`:
//! version u8, type u8, inputs, outputs, fee i64, nonce u64, pubkey, signature,
//! psbt (u32-prefixed), optional vault payload.

use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::{Address, Network};

use crate::error::Error;
use crate::tachi::Vtxo;

pub const TACHI_TX_VERSION: u8 = 1;
pub const TACHI_TX_TYPE_TRANSFER: u8 = 1;
pub const TACHI_TX_TYPE_DEPOSIT: u8 = 4;

#[derive(Clone, Copy)]
pub struct TransferInput {
    pub vtxo_id: [u8; 32],
    pub value_sats: u64,
}

#[derive(Clone, Copy)]
pub struct TransferOutput {
    pub owner: [u8; 32],
    pub amount: u64,
}

#[derive(Debug, Clone)]
pub struct SignedTransfer {
    pub hex: String,
    pub tendermint_hash: String,
    pub output_vtxo_id: String,
}

pub fn xonly_from_secret(secret: &SecretKey) -> [u8; 32] {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, secret);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
    xonly.serialize()
}

fn owner_from_key_bytes(bytes: &[u8]) -> Result<[u8; 32], Error> {
    match bytes.len() {
        32 => bytes
            .try_into()
            .map_err(|_| Error::Invalid("owner key".into())),
        33 if bytes[0] == 0x02 || bytes[0] == 0x03 => bytes[1..]
            .try_into()
            .map_err(|_| Error::Invalid("owner key".into())),
        65 if bytes[0] == 0x04 => bytes[1..33]
            .try_into()
            .map_err(|_| Error::Invalid("owner key".into())),
        n => Err(Error::Invalid(format!(
            "got {n} bytes of hex ({} chars). Tachi dest is a 32-byte x-only key (64 hex chars), a 33-byte compressed pubkey (66 hex chars), or a P2TR address (bcrt1p…/tb1p…/bc1p…). Do not send an L1 HTLC script, claim tx, or bcrt1q address",
            n * 2
        ))),
    }
}

pub fn parse_tachi_owner(s: &str, _network: Network) -> Result<[u8; 32], Error> {
    let t = s
        .trim()
        .trim_matches('"')
        .trim_start_matches("0x")
        .trim_start_matches("0X");

    if !t.is_empty() && t.bytes().all(|b| b.is_ascii_hexdigit()) {
        let bytes = hex::decode(t).map_err(|e| Error::Invalid(e.to_string()))?;
        return owner_from_key_bytes(&bytes);
    }

    let addr: Address<bitcoin::address::NetworkUnchecked> = t.parse().map_err(|_| {
        Error::Invalid(format!(
            "invalid Tachi dest {t:?}. Use 64-char x-only hex (GET / → tachi_lp_pubkey) or a P2TR address starting with bcrt1p, tb1p, or bc1p"
        ))
    })?;
    let addr = addr.assume_checked();
    let spk = addr.script_pubkey();
    let bytes = spk.as_bytes();
    if bytes.len() == 34 && bytes[0] == 0x51 && bytes[1] == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes[2..34]);
        return Ok(out);
    }
    Err(Error::Invalid(format!(
        "{t} is not Taproot. VTXO owners are P2TR (bcrt1p/tb1p/bc1p), not SegWit v0 (bcrt1q/tb1q) HTLC addresses"
    )))
}

pub fn looks_like_tachi_owner(s: &str, network: Network) -> bool {
    parse_tachi_owner(s, network).is_ok()
}

pub fn looks_like_vtxo_id(s: &str) -> bool {
    let t = s.trim();
    t.len() == 64 && hex::decode(t).ok().is_some_and(|b| b.len() == 32)
}

pub fn select_vtxos(unspent: &[Vtxo], need: u64) -> Result<(Vec<Vtxo>, u64), Error> {
    let mut coins: Vec<&Vtxo> = unspent
        .iter()
        .filter(|v| !v.spent && !v.locked && v.amount > 0)
        .collect();
    coins.sort_by_key(|a| std::cmp::Reverse(a.amount));
    let mut picked = Vec::new();
    let mut total = 0u64;
    for v in coins {
        picked.push(v.clone());
        total = total.saturating_add(v.amount);
        if total >= need {
            return Ok((picked, total));
        }
    }
    Err(Error::Tachi(format!(
        "LP Tachi wallet has {total} sats unspent, need {need}"
    )))
}

pub fn encode_transfer(
    inputs: &[TransferInput],
    outputs: &[TransferOutput],
    fee: u64,
    nonce: u64,
    pub_key: &[u8; 32],
    signature: &[u8],
) -> Result<Vec<u8>, Error> {
    encode_tx(
        TACHI_TX_TYPE_TRANSFER,
        inputs,
        outputs,
        fee,
        nonce,
        pub_key,
        signature,
    )
}

pub fn encode_tx(
    tx_type: u8,
    inputs: &[TransferInput],
    outputs: &[TransferOutput],
    fee: u64,
    nonce: u64,
    pub_key: &[u8; 32],
    signature: &[u8],
) -> Result<Vec<u8>, Error> {
    if outputs.is_empty() {
        return Err(Error::Invalid("tx needs outputs".into()));
    }
    if tx_type == TACHI_TX_TYPE_TRANSFER && inputs.is_empty() {
        return Err(Error::Invalid("transfer needs inputs and outputs".into()));
    }
    if !signature.is_empty() && signature.len() != 64 {
        return Err(Error::Invalid("schnorr signature must be 64 bytes".into()));
    }

    let mut buf = Vec::new();
    buf.push(TACHI_TX_VERSION);
    buf.push(tx_type);
    buf.extend_from_slice(&(inputs.len() as u16).to_be_bytes());
    for inp in inputs {
        buf.extend_from_slice(&inp.vtxo_id);
        buf.extend_from_slice(&[0u8; 32]); // txid blanked on ledger-native spends
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&(inp.value_sats as i64).to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes()); // empty sigScript
    }
    buf.extend_from_slice(&(outputs.len() as u16).to_be_bytes());
    for out in outputs {
        buf.extend_from_slice(&32u16.to_be_bytes());
        buf.extend_from_slice(&out.owner);
        buf.extend_from_slice(&(out.amount as i64).to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
    }
    buf.extend_from_slice(&(fee as i64).to_be_bytes());
    buf.extend_from_slice(&nonce.to_be_bytes());
    buf.extend_from_slice(&32u16.to_be_bytes());
    buf.extend_from_slice(pub_key);
    buf.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    buf.extend_from_slice(signature);
    buf.extend_from_slice(&0u32.to_be_bytes()); // empty PSBT: ledger VTXO transfer
    Ok(buf)
}

pub fn sighash_tx(
    tx_type: u8,
    inputs: &[TransferInput],
    outputs: &[TransferOutput],
    fee: u64,
    nonce: u64,
    pub_key: &[u8; 32],
) -> Result<[u8; 32], Error> {
    // Tachid types.SigHash: signature + psbt blanked; each input is
    // {vtxoId, txid:0, vout:0, valueSats:0, sigScript:empty}.
    let blanked: Vec<TransferInput> = inputs
        .iter()
        .map(|inp| TransferInput {
            vtxo_id: inp.vtxo_id,
            value_sats: 0,
        })
        .collect();
    let preimage = encode_tx(tx_type, &blanked, outputs, fee, nonce, pub_key, &[])?;
    Ok(sha256::Hash::hash(&preimage).to_byte_array())
}

pub fn sign_tx(
    secret: &SecretKey,
    tx_type: u8,
    inputs: &[TransferInput],
    outputs: &[TransferOutput],
    fee: u64,
    nonce: u64,
) -> Result<SignedTransfer, Error> {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, secret);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
    let pub_key = xonly.serialize();

    let hash = sighash_tx(tx_type, inputs, outputs, fee, nonce, &pub_key)?;
    let msg = Message::from_digest(hash);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
    let sig_bytes = sig.as_ref();

    let encoded = encode_tx(tx_type, inputs, outputs, fee, nonce, &pub_key, sig_bytes)?;
    let tm_hash = sha256::Hash::hash(&encoded);
    let output_vtxo_id = output_vtxo_id(&encoded, 0);
    Ok(SignedTransfer {
        hex: hex::encode(encoded),
        tendermint_hash: hex::encode(tm_hash),
        output_vtxo_id: hex::encode(output_vtxo_id),
    })
}

pub fn sign_transfer(
    secret: &SecretKey,
    inputs: &[TransferInput],
    outputs: &[TransferOutput],
    fee: u64,
    nonce: u64,
) -> Result<SignedTransfer, Error> {
    sign_tx(secret, TACHI_TX_TYPE_TRANSFER, inputs, outputs, fee, nonce)
}

pub fn sign_deposit(
    secret: &SecretKey,
    amount_sats: u64,
    fee: u64,
    nonce: u64,
) -> Result<SignedTransfer, Error> {
    let owner = xonly_from_secret(secret);
    sign_tx(
        secret,
        TACHI_TX_TYPE_DEPOSIT,
        &[],
        &[TransferOutput {
            owner,
            amount: amount_sats,
        }],
        fee,
        nonce,
    )
}

/// `SHA256(SHA256(EncodeTx(tx)) || BE_uint32(outputIndex))`
pub fn output_vtxo_id(encoded: &[u8], output_index: u32) -> [u8; 32] {
    let tx_hash = sha256::Hash::hash(encoded);
    let mut buf = [0u8; 36];
    buf[..32].copy_from_slice(&tx_hash.to_byte_array());
    buf[32..].copy_from_slice(&output_index.to_be_bytes());
    sha256::Hash::hash(&buf).to_byte_array()
}

pub fn parse_vtxo_id(s: &str) -> Result<[u8; 32], Error> {
    let bytes = hex::decode(s.trim()).map_err(|e| Error::Invalid(e.to_string()))?;
    bytes
        .try_into()
        .map_err(|_| Error::Invalid("vtxo id must be 32 bytes".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_header_is_v1_type1() {
        let inp = TransferInput {
            vtxo_id: [0xab; 32],
            value_sats: 100_000,
        };
        let out = TransferOutput {
            owner: [0xcd; 32],
            amount: 99_999,
        };
        let pk = [0x11; 32];
        let bytes = encode_transfer(&[inp], &[out], 1, 7, &pk, &[]).unwrap();
        assert_eq!(bytes[0], 1);
        assert_eq!(bytes[1], 1);
        assert_eq!(&bytes[2..4], &1u16.to_be_bytes());
        assert_eq!(&bytes[4..36], &[0xab; 32]);
    }

    #[test]
    fn sign_roundtrip_has_64_byte_sig() {
        let secret = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pk = xonly_from_secret(&secret);
        let inp = TransferInput {
            vtxo_id: [1u8; 32],
            value_sats: 50_000,
        };
        let out = TransferOutput {
            owner: pk,
            amount: 49_999,
        };
        let signed = sign_transfer(&secret, &[inp], &[out], 1, 1).unwrap();
        let raw = hex::decode(&signed.hex).unwrap();
        assert_eq!(raw[0], 1);
        assert_eq!(raw[1], 1);
        assert_eq!(signed.output_vtxo_id.len(), 64);
        assert_eq!(signed.tendermint_hash.len(), 64);
    }

    #[test]
    fn transfer_sighash_zeros_input_value() {
        let pk = [0x11u8; 32];
        let valued = TransferInput {
            vtxo_id: [1u8; 32],
            value_sats: 100_000,
        };
        let zeroed = TransferInput {
            vtxo_id: [1u8; 32],
            value_sats: 0,
        };
        let out = TransferOutput {
            owner: pk,
            amount: 99_999,
        };
        let h_valued = sighash_tx(TACHI_TX_TYPE_TRANSFER, &[valued], &[out], 1, 1, &pk).unwrap();
        let h_zeroed = sha256::Hash::hash(
            &encode_tx(TACHI_TX_TYPE_TRANSFER, &[zeroed], &[out], 1, 1, &pk, &[]).unwrap(),
        )
        .to_byte_array();
        let h_wire = sha256::Hash::hash(
            &encode_tx(TACHI_TX_TYPE_TRANSFER, &[valued], &[out], 1, 1, &pk, &[]).unwrap(),
        )
        .to_byte_array();
        assert_eq!(h_valued, h_zeroed);
        assert_ne!(h_valued, h_wire);
    }

    #[test]
    fn parse_xonly_hex() {
        let hex32 = "b59aa9e53cea3947b204002e14c439a0bfbf9de39ead5673b77c0bafe8b4e561";
        let owner = parse_tachi_owner(hex32, Network::Regtest).unwrap();
        assert_eq!(hex::encode(owner), hex32);
        let with_prefix = parse_tachi_owner(&format!("0x{hex32}"), Network::Signet).unwrap();
        assert_eq!(hex::encode(with_prefix), hex32);
    }

    #[test]
    fn parse_compressed_pubkey_hex() {
        let compressed = "02b59aa9e53cea3947b204002e14c439a0bfbf9de39ead5673b77c0bafe8b4e561";
        let owner = parse_tachi_owner(compressed, Network::Regtest).unwrap();
        assert_eq!(
            hex::encode(owner),
            "b59aa9e53cea3947b204002e14c439a0bfbf9de39ead5673b77c0bafe8b4e561"
        );
    }

    #[test]
    fn wrong_length_hex_mentions_byte_count() {
        let err = parse_tachi_owner("aabbccdd", Network::Regtest).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("4 bytes"), "{msg}");
        assert!(msg.contains("bcrt1p"), "{msg}");
    }
}
