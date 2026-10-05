//! Tachi TAURUS vault refund outputs (`to_local`), so a claim advance can buy
//! a real vault refund while it waits out its delay.
//!
//! P2TR, NUMS internal key, a single tapscript leaf:
//!
//! ```text
//! OP_IF
//!     <q1> OP_CHECKSIG <q2> OP_CHECKSIGADD ... <q7> OP_CHECKSIGADD <M> OP_NUMEQUAL
//! OP_ELSE
//!     <delay> OP_CSV OP_DROP <user> OP_CHECKSIG
//! OP_ENDIF
//! ```
//!
//! The quorum keys are the validators' compressed keys sorted by their 33
//! bytes, then stripped to x-only. The user spends through OP_ELSE with
//! witness `[sig64, <empty>, script, control block]`, nSequence = delay and
//! SIGHASH_DEFAULT. There is no revocation key: the quorum branch is live the
//! whole time, which is why an advance also asks the watchtower about it.

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::opcodes::all::{
    OP_CHECKSIG, OP_CHECKSIGADD, OP_CSV, OP_DROP, OP_ELSE, OP_ENDIF, OP_IF, OP_NUMEQUAL,
};
use bitcoin::script::{Builder, Instruction};
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{
    Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};

use crate::error::Error;

/// BIP341 NUMS point (SHA256 of the uncompressed generator), x-only.
pub const NUMS_HEX: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
/// Delay a real vault refund carries (the vault's exit CSV).
pub const VAULT_REFUND_DELAY: u16 = 1008;

/// The parts of a `to_local` leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToLocal {
    pub quorum: Vec<XOnlyPublicKey>,
    pub threshold: u8,
    pub delay: u16,
    pub user: XOnlyPublicKey,
}

fn nums() -> XOnlyPublicKey {
    let bytes = hex::decode(NUMS_HEX).expect("NUMS hex");
    XOnlyPublicKey::from_slice(&bytes).expect("NUMS point")
}

/// Quorum order Tachi uses: sort by compressed bytes, then drop the prefix.
/// (Sorting x-only keys gives a different order.)
pub fn sorted_quorum(keys: &[PublicKey]) -> Vec<XOnlyPublicKey> {
    let mut v: Vec<[u8; 33]> = keys.iter().map(|k| k.inner.serialize()).collect();
    v.sort();
    v.dedup();
    v.iter()
        .map(|b| XOnlyPublicKey::from_slice(&b[1..]).expect("x-only of a valid key"))
        .collect()
}

impl ToLocal {
    pub fn script(&self) -> ScriptBuf {
        let mut b = Builder::new().push_opcode(OP_IF);
        for (i, q) in self.quorum.iter().enumerate() {
            b = b
                .push_x_only_key(q)
                .push_opcode(if i == 0 { OP_CHECKSIG } else { OP_CHECKSIGADD });
        }
        b.push_int(i64::from(self.threshold))
            .push_opcode(OP_NUMEQUAL)
            .push_opcode(OP_ELSE)
            .push_int(i64::from(self.delay))
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_x_only_key(&self.user)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ENDIF)
            .into_script()
    }

    pub fn spend_info(&self) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(0, self.script())
            .expect("single leaf")
            .finalize(&Secp256k1::verification_only(), nums())
            .expect("complete tree")
    }

    pub fn address(&self, network: Network) -> Address {
        let info = self.spend_info();
        Address::p2tr_tweaked(info.output_key(), bitcoin::KnownHrp::from(network))
    }

    fn control_block(&self) -> Vec<u8> {
        self.spend_info()
            .control_block(&(self.script(), LeafVersion::TapScript))
            .expect("leaf is in the tree")
            .serialize()
    }

    fn leaf_hash(&self) -> TapLeafHash {
        TapLeafHash::from_script(&self.script(), LeafVersion::TapScript)
    }
}

/// Read a `to_local` leaf; `None` unless `script` is exactly the template
/// (rebuilt and byte-compared, so non-minimal pushes are refused too).
pub fn parse_to_local(script: &ScriptBuf) -> Option<ToLocal> {
    let ins: Vec<Instruction> = script.instructions().collect::<Result<_, _>>().ok()?;
    let mut it = ins.iter();
    if !matches!(it.next()?, Instruction::Op(op) if *op == OP_IF) {
        return None;
    }
    let mut quorum = Vec::new();
    let threshold = loop {
        match it.next()? {
            Instruction::PushBytes(b) if b.len() == 32 => {
                quorum.push(XOnlyPublicKey::from_slice(b.as_bytes()).ok()?);
                let want = if quorum.len() == 1 { OP_CHECKSIG } else { OP_CHECKSIGADD };
                if !matches!(it.next()?, Instruction::Op(op) if *op == want) {
                    return None;
                }
            }
            other => break script_num(other)?,
        }
    };
    if !matches!(it.next()?, Instruction::Op(op) if *op == OP_NUMEQUAL)
        || !matches!(it.next()?, Instruction::Op(op) if *op == OP_ELSE)
    {
        return None;
    }
    let delay = script_num(it.next()?)?;
    let user = match it.nth(2)? {
        Instruction::PushBytes(b) if b.len() == 32 => XOnlyPublicKey::from_slice(b.as_bytes()).ok()?,
        _ => return None,
    };
    let parsed = ToLocal {
        threshold: u8::try_from(threshold).ok()?,
        delay: u16::try_from(delay).ok()?,
        quorum,
        user,
    };
    if parsed.quorum.is_empty()
        || parsed.threshold == 0
        || usize::from(parsed.threshold) > parsed.quorum.len()
        || parsed.delay == 0
        || parsed.script() != *script
    {
        return None;
    }
    Some(parsed)
}

/// A small non-negative script number (OP_1..OP_16 or a ≤3-byte push).
fn script_num(ins: &Instruction) -> Option<u32> {
    match ins {
        Instruction::Op(op) if (0x51..=0x60).contains(&op.to_u8()) => Some(u32::from(op.to_u8() - 0x50)),
        Instruction::PushBytes(b) if !b.is_empty() && b.len() <= 3 => {
            let b = b.as_bytes();
            if b[b.len() - 1] & 0x80 != 0 {
                return None;
            }
            Some(b.iter().enumerate().fold(0u32, |v, (i, x)| v | u32::from(*x) << (8 * i)))
        }
        _ => None,
    }
}

/// The vault funding output's cooperative leaf, which a refund spends:
/// `<user> CHECKSIGVERIFY <q1> CHECKSIG <q2..> CHECKSIGADD <M> NUMEQUAL`.
pub fn cooperative_script(tl: &ToLocal) -> ScriptBuf {
    let mut b = Builder::new()
        .push_x_only_key(&tl.user)
        .push_opcode(bitcoin::opcodes::all::OP_CHECKSIGVERIFY);
    for (i, q) in tl.quorum.iter().enumerate() {
        b = b
            .push_x_only_key(q)
            .push_opcode(if i == 0 { OP_CHECKSIG } else { OP_CHECKSIGADD });
    }
    b.push_int(i64::from(tl.threshold))
        .push_opcode(OP_NUMEQUAL)
        .into_script()
}

/// Check that `refund` is a quorum-co-signed cooperative refund of the vault
/// whose funding output is `funding`: it spends that output through the
/// cooperative leaf for this user and quorum (committed in the output key),
/// the user signed, and at least `threshold` validators signed. The quorum
/// only co-signs a vault's latest state, so this is the quorum's own
/// attestation that the refund is legitimate. Returns how many signed.
pub fn verify_quorum_refund(refund: &Transaction, funding: &TxOut, tl: &ToLocal) -> Result<usize, Error> {
    let bad = |why: &str| Error::Invalid(format!("vault refund: {why}"));
    let [input] = refund.input.as_slice() else {
        return Err(bad("a refund spends exactly the vault's funding output"));
    };
    let spk = funding.script_pubkey.as_bytes();
    if !funding.script_pubkey.is_p2tr() {
        return Err(bad("funding output is not taproot"));
    }
    let output_key = XOnlyPublicKey::from_slice(&spk[2..34]).map_err(|_| bad("funding output key"))?;
    let coop = cooperative_script(tl);
    let w: Vec<&[u8]> = input.witness.iter().collect();
    let n = tl.quorum.len();
    if w.len() != n + 3 {
        return Err(bad("witness is not a cooperative-leaf spend"));
    }
    let (sigs, rest) = w.split_at(n);
    let [user_sig, script, cb] = rest else {
        return Err(bad("witness is not a cooperative-leaf spend"));
    };
    if *script != coop.as_bytes() {
        return Err(bad("did not spend the cooperative leaf for this user and quorum"));
    }
    let cb = bitcoin::taproot::ControlBlock::decode(cb).map_err(|_| bad("control block"))?;
    let secp = Secp256k1::verification_only();
    if !cb.verify_taproot_commitment(&secp, output_key, &coop) {
        return Err(bad("cooperative leaf is not committed in the funding output"));
    }
    let leaf = TapLeafHash::from_script(&coop, LeafVersion::TapScript);
    let msg = |ty: TapSighashType| -> Result<Message, Error> {
        let h = SighashCache::new(refund)
            .taproot_script_spend_signature_hash(0, &Prevouts::All(std::slice::from_ref(funding)), leaf, ty)
            .map_err(|e| Error::Bitcoin(e.to_string()))?;
        Ok(Message::from_digest(h.to_byte_array()))
    };
    let check = |sig: &[u8], key: &XOnlyPublicKey| -> bool {
        let (sig, ty) = match sig.len() {
            64 => (sig, TapSighashType::Default),
            65 => match TapSighashType::from_consensus_u8(sig[64]) {
                Ok(ty) => (&sig[..64], ty),
                Err(_) => return false,
            },
            _ => return false,
        };
        let Ok(sig) = bitcoin::secp256k1::schnorr::Signature::from_slice(sig) else {
            return false;
        };
        msg(ty).is_ok_and(|m| secp.verify_schnorr(&sig, &m, key).is_ok())
    };
    if !check(user_sig, &tl.user) {
        return Err(bad("user signature does not verify"));
    }
    // Script order pops q1's signature first, so the stack holds them reversed.
    let signed = sigs
        .iter()
        .enumerate()
        .filter(|(i, sig)| !sig.is_empty() && check(sig, &tl.quorum[n - 1 - i]))
        .count();
    if signed < usize::from(tl.threshold) {
        return Err(bad(&format!(
            "only {signed} validator signatures verify; the quorum needs {}",
            tl.threshold
        )));
    }
    Ok(signed)
}

/// Tachi's vault id: SHA256(funding txid in internal byte order ‖ vout
/// big-endian). Internal order is the reverse of how explorers display a
/// txid (and is what `listVaults` reports as `funding_txid`).
pub fn vault_id(funding_txid: &bitcoin::Txid, vout: u32) -> String {
    let mut bytes = funding_txid.to_byte_array().to_vec();
    bytes.extend_from_slice(&vout.to_be_bytes());
    sha256::Hash::hash(&bytes).to_string()
}

/// What the desk needs from the user's pre-signed `to_local` spend.
pub struct ExpectedToLocalSpend<'a> {
    pub outpoint: OutPoint,
    pub value_sats: u64,
    pub to_local: &'a ToLocal,
    pub network: Network,
    pub desk_address: &'a Address,
    pub min_desk_sats: u64,
}

fn sighash(tx: &Transaction, want: &ExpectedToLocalSpend) -> Result<Message, Error> {
    let prevout = TxOut {
        value: Amount::from_sat(want.value_sats),
        script_pubkey: want.to_local.address(want.network).script_pubkey(),
    };
    let h = SighashCache::new(tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[prevout]),
            want.to_local.leaf_hash(),
            TapSighashType::Default,
        )
        .map_err(|e| Error::Bitcoin(e.to_string()))?;
    Ok(Message::from_digest(h.to_byte_array()))
}

/// Check every part of the user's delayed spend before the desk pays for it.
pub fn verify_presigned(tx_hex: &str, want: &ExpectedToLocalSpend) -> Result<Transaction, Error> {
    let bad = |why: &str| Error::Invalid(format!("pre-signed vault refund spend: {why}"));
    let bytes = hex::decode(tx_hex.trim()).map_err(|_| bad("not hex"))?;
    let tx: Transaction = bitcoin::consensus::deserialize(&bytes).map_err(|e| bad(&e.to_string()))?;
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
        Some(bitcoin::relative::LockTime::Blocks(h)) if h.value() >= want.to_local.delay => {}
        _ => return Err(bad("sequence must carry the refund's CSV block delay")),
    }
    let paid: u64 = tx
        .output
        .iter()
        .filter(|o| o.script_pubkey == want.desk_address.script_pubkey())
        .map(|o| o.value.to_sat())
        .sum();
    if paid < want.min_desk_sats {
        return Err(bad(&format!("pays the desk {paid} sats, needs at least {}", want.min_desk_sats)));
    }
    let w: Vec<&[u8]> = input.witness.iter().collect();
    let [sig, branch, script, cb] = w.as_slice() else {
        return Err(bad("witness must be <sig> <empty> <script> <control block>"));
    };
    if !branch.is_empty() {
        return Err(bad("must take the OP_ELSE (user) branch"));
    }
    if *script != want.to_local.script().as_bytes() {
        return Err(bad("leaf script does not match the output"));
    }
    if *cb != want.to_local.control_block().as_slice() {
        return Err(bad("control block does not match the output"));
    }
    if sig.len() != 64 {
        return Err(bad("signature must be 64 bytes (SIGHASH_DEFAULT)"));
    }
    let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(sig).map_err(|_| bad("bad signature"))?;
    Secp256k1::verification_only()
        .verify_schnorr(&sig, &sighash(&tx, want)?, &want.to_local.user)
        .map_err(|_| bad("signature does not verify for the refund's user key"))?;
    Ok(tx)
}

/// Sign the user's delayed spend (demo helper; the Tachi wallet does this).
pub fn presign_spend(
    want: &ExpectedToLocalSpend,
    user_secret: &SecretKey,
    pay_sats: u64,
) -> Result<String, Error> {
    if pay_sats > want.value_sats {
        return Err(Error::Invalid("spend pays more than the output holds".into()));
    }
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: want.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_height(want.to_local.delay),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(pay_sats),
            script_pubkey: want.desk_address.script_pubkey(),
        }],
    };
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, user_secret);
    let sig = secp.sign_schnorr(&sighash(&tx, want)?, &keypair);
    let mut w = Witness::new();
    w.push(sig.as_ref());
    w.push([]);
    w.push(want.to_local.script().as_bytes());
    w.push(want.to_local.control_block());
    tx.input[0].witness = w;
    Ok(serialize_hex(&tx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::htlc::{generate_keypair, p2wpkh_address, parse_txid};

    /// The regtest validator set as `/tachi_validators` lists it.
    const LIVE_QUORUM: [&str; 7] = [
        "03ccd51dac229bf173e6f43dfcfb21c7445bad93255afa0cfcaebbcfe287958977",
        "034ab1008db3d6e33adacfcad9158a14b1ff66a7529072b20ab9139b118ef2e276",
        "033c8e5ecd2f0974e0ba417e423597ea20eaedb948d2de32f63d23c1c7fe181eb4",
        "02d3a1104032d33236abaccd78ca3f43966c1c321d13320ced60f39c52d1a51c35",
        "0358a7ed060e4dd2ed2e70ffd10d5f9400f6580b16c71618510a844a9b61de770a",
        "037039d9c7dd78422313730f61f5356914200eb09cdfaf400b960cdb4d03862e47",
        "03e125950f3c8b6fe2ecb2e17036aa0ee2c9b8f9bbe00458fdc5c5a98b15c302ff",
    ];

    fn live_quorum() -> Vec<XOnlyPublicKey> {
        let keys: Vec<PublicKey> = LIVE_QUORUM.iter().map(|k| k.parse().unwrap()).collect();
        sorted_quorum(&keys)
    }

    #[test]
    fn matches_the_tachi_sdk_vector() {
        // Vector from the SDK's buildToLocalP2trOutput for this user + quorum.
        let user = "919bd528cbdb231554144b270eb91f615b827dbf0c62deaece4e0b5e3b331868".parse().unwrap();
        let tl = ToLocal {
            quorum: live_quorum(),
            threshold: 5,
            delay: VAULT_REFUND_DELAY,
            user,
        };
        assert_eq!(
            hex::encode(tl.address(Network::Regtest).script_pubkey().as_bytes()),
            "5120c1a182093820a88ef38dc82f5098a339ff9c298a42676a689ef45f88c1961e57"
        );
        assert_eq!(
            tl.leaf_hash().to_string(),
            "8124b729cae0a19cc7f3ec0284fe6496233ee37b0c478c70e0c0214b40d2c3a6"
        );
        assert_eq!(&hex::encode(tl.control_block())[2..], NUMS_HEX);
        assert_eq!(parse_to_local(&tl.script()), Some(tl));
    }

    /// A real vault opened on Tachi regtest and refunded with the quorum's
    /// co-signature (vault fd7f6344…, refund ee87e41e…, 6-block delay).
    const LIVE_REFUND: &str = "02000000000101ecb64c50db7939c1c4d97c2735b0d00f302bb2d7a3cfe804dbd69531e731b44d0000000000a54918800108e8000000000000225120ce3f77888baa1031c3d2e5c6f5c8428ef1521589a967cbea94e1cc4415c88ee70a407d0e901e9eeeaa9986fd2fdfebfb4f02ecd00e901bbbe4db7eff103493da844b28c44d1963e4c130a8ec4f49c788b5605d9676e5ba44f51b455f63aae752fbf5406d4b3e0800a3f21e8c79f0e3e4bea06c04dd8d42fc050a48c4bed8a7b37b358aabbcfce6b273f56b8cc8c44c7e7f42ec0354335f92025c925c656084c8d4ba0c00409e3baca44430b8ba319abe056670f3cc9dec0876dee0230fd0a8a7016158c1e4f87953dc174acb0fef4ff88c714efb9fc7894ae2963a65ae5dd63e50414c10ca401d1d9a1e06400d4709bf47cc68c0222b548c5bfb7812c1a1dc060312324cf90581b2d114bb3130d535c1a29cb54d55ccb41b5591ea8bdf9915dea654337960e900409df642e4f0f80c99e40eba918d17282f3a5376ea0ea49a321b9d398932bc4880af36e6ea2fbedf1265df7d2110d9799ae5eb4f6267e2d1347201c0a42e30d525405cb816a5e2299dfe9e928c963936ff1774f16a7929cb8ab1c9fbf62d1aab75492ef5b5f7d5bd56066604764eed57c847ee8a5f379340e1a2d1ab766aadc2dc1dfd120120077994dbe3e4681ed61fe8d0608b51afaa281126e2fa6bd3bcf604f95833b243ad20d3a1104032d33236abaccd78ca3f43966c1c321d13320ced60f39c52d1a51c35ac203c8e5ecd2f0974e0ba417e423597ea20eaedb948d2de32f63d23c1c7fe181eb4ba204ab1008db3d6e33adacfcad9158a14b1ff66a7529072b20ab9139b118ef2e276ba2058a7ed060e4dd2ed2e70ffd10d5f9400f6580b16c71618510a844a9b61de770aba207039d9c7dd78422313730f61f5356914200eb09cdfaf400b960cdb4d03862e47ba20ccd51dac229bf173e6f43dfcfb21c7445bad93255afa0cfcaebbcfe287958977ba20e125950f3c8b6fe2ecb2e17036aa0ee2c9b8f9bbe00458fdc5c5a98b15c302ffba559c41c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac05f72a9dd3034a60a164a2ca7bd6579401c2124e2e70124a0246737b7df0343799cc77020";
    const LIVE_FUNDING: &str = "02000000000101fa41853573a7cb168d777195ea29eb22392979d819998ae8a4a2c3378ba3106c0000000000ffffffff0260ea000000000000225120f895b209ce9559e9530dac26f7577513f5931c2caafc68454a43b760d98935012c4c00000000000016001485d2f1aac0362e9fe2e871132ef638ba89ba42ba024830450221008b62d59539a73988e78c84b205f885491edcf21a8934fb633fb80fea23721d2602203092965b8edc6ceceec44df749339abcb9787876653168828b412abf82e7b094012102077994dbe3e4681ed61fe8d0608b51afaa281126e2fa6bd3bcf604f95833b24300000000";
    const LIVE_TO_LOCAL: &str = "6320d3a1104032d33236abaccd78ca3f43966c1c321d13320ced60f39c52d1a51c35ac203c8e5ecd2f0974e0ba417e423597ea20eaedb948d2de32f63d23c1c7fe181eb4ba204ab1008db3d6e33adacfcad9158a14b1ff66a7529072b20ab9139b118ef2e276ba2058a7ed060e4dd2ed2e70ffd10d5f9400f6580b16c71618510a844a9b61de770aba207039d9c7dd78422313730f61f5356914200eb09cdfaf400b960cdb4d03862e47ba20ccd51dac229bf173e6f43dfcfb21c7445bad93255afa0cfcaebbcfe287958977ba20e125950f3c8b6fe2ecb2e17036aa0ee2c9b8f9bbe00458fdc5c5a98b15c302ffba559c6756b27520077994dbe3e4681ed61fe8d0608b51afaa281126e2fa6bd3bcf604f95833b243ac68";

    #[test]
    fn live_quorum_refund_verifies_and_tampering_fails() {
        let tx = |h: &str| -> Transaction { bitcoin::consensus::deserialize(&hex::decode(h).unwrap()).unwrap() };
        let (refund, funding) = (tx(LIVE_REFUND), tx(LIVE_FUNDING));
        let tl = parse_to_local(&ScriptBuf::from_bytes(hex::decode(LIVE_TO_LOCAL).unwrap())).unwrap();
        assert_eq!(tl.quorum, live_quorum());
        assert_eq!(verify_quorum_refund(&refund, &funding.output[0], &tl).unwrap(), 5);
        assert_eq!(refund.output[0].script_pubkey, tl.address(Network::Regtest).script_pubkey());

        // Signatures commit to the outputs: redirecting the refund breaks them.
        let mut stolen = refund.clone();
        stolen.output[0].script_pubkey = funding.output[1].script_pubkey.clone();
        assert!(verify_quorum_refund(&stolen, &funding.output[0], &tl).is_err());
    }

    #[test]
    fn vault_id_matches_a_live_vault() {
        // The live vault's funding tx as bitcoind shows it (listVaults
        // reports the same txid byte-reversed).
        let l1_txid = parse_txid("9a8dc45a133ee012ab675ecede6b1144f47565e3f9a14e1f170ac6302e53f1ae").unwrap();
        assert_eq!(
            vault_id(&l1_txid, 0),
            "e0ca7d690e4f5c7bf54dab2c4edc0077717fe3ea89bb185be13f6c78a1b904ff"
        );
    }

    #[test]
    fn delayed_spend_verifies_and_forgeries_do_not() {
        let user = generate_keypair();
        let (user_x, _) = user.public.inner.x_only_public_key();
        let tl = ToLocal {
            quorum: live_quorum(),
            threshold: 5,
            delay: 144,
            user: user_x,
        };
        let desk = p2wpkh_address(&generate_keypair().secret, Network::Regtest);
        let want = |min| ExpectedToLocalSpend {
            outpoint: OutPoint {
                txid: parse_txid(&"7a".repeat(32)).unwrap(),
                vout: 1,
            },
            value_sats: 80_000,
            to_local: &tl,
            network: Network::Regtest,
            desk_address: &desk,
            min_desk_sats: min,
        };
        let hex = presign_spend(&want(79_000), &user.secret, 79_500).unwrap();
        let tx = verify_presigned(&hex, &want(79_000)).expect("valid");
        assert_eq!(tx.input[0].witness.len(), 4);

        let forged = presign_spend(&want(79_000), &generate_keypair().secret, 79_500).unwrap();
        assert!(verify_presigned(&forged, &want(79_000)).unwrap_err().to_string().contains("does not verify"));
        assert!(verify_presigned(&hex, &want(79_600)).unwrap_err().to_string().contains("pays the desk"));

        // A different delay is a different script, so a different output.
        let short = ToLocal { delay: 10, ..tl.clone() };
        let early = presign_spend(&ExpectedToLocalSpend { to_local: &short, ..want(79_000) }, &user.secret, 79_500).unwrap();
        assert!(verify_presigned(&early, &want(79_000)).is_err());
    }

    #[test]
    fn rejects_other_scripts() {
        let user = generate_keypair();
        let csv = crate::advance::csv_script(144, &user.public);
        assert_eq!(parse_to_local(&csv), None);
        let (x, _) = user.public.inner.x_only_public_key();
        let over = ToLocal { quorum: vec![x], threshold: 2, delay: 5, user: x };
        assert_eq!(parse_to_local(&over.script()), None);
    }
}
