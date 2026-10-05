// Open a real TAURUS vault on Tachi regtest and refund it to `to_local`
// with the validator quorum's co-signature, using Tachi's own SDK.
//
//   node vault-refund.mjs <user_secret_hex> [csv_blocks] [amount_sats]
//
// Prints one JSON line: the refund's to_local outpoint and leaf script (what
// a claim advance needs), the vault id, and the watchtower receipt.
import * as ecc from "@bitcoinerlab/secp256k1";
import { ECPairFactory } from "ecpair";
import * as bitcoin from "bitcoinjs-lib";
import * as V from "@tachibtc/taurus-vault-core";

const B = process.env.TACHI_BASE_URL || "https://rpc-regtest.tachibtc.com";
const FAUCET = process.env.TACHI_FAUCET_URL || "https://faucet.tachibtc.com";
const net = bitcoin.networks.regtest;
const ECPair = ECPairFactory(ecc);
const log = (...a) => console.error("[vault]", ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const [secretHex, csvArg, amountArg] = process.argv.slice(2);
if (!secretHex) throw new Error("usage: vault-refund.mjs <user_secret_hex> [csv] [amount]");
const csvBlocks = Number(csvArg || 6);
const amount = BigInt(amountArg || 60000);

const kp = ECPair.fromPrivateKey(Buffer.from(secretHex, "hex"), { network: net });
const signer = V.normalizeTaprootSigner(kp);
const pub33 = Buffer.from(kp.publicKey);
const xonly = Buffer.from(V.toXOnly(pub33));

async function rpc(method, params) {
  const r = await fetch(B + "/", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "1.0", id: 1, method, params }),
  });
  const j = await r.json();
  if (j.error) throw new Error(`${method}: ${JSON.stringify(j.error)}`);
  return j.result;
}
async function waitConfirmed(txid, vout) {
  for (;;) {
    const o = await rpc("gettxout", [txid, vout, false]).catch(() => null);
    if (o && o.confirmations >= 1) return o;
    await sleep(5000);
  }
}
async function voutPaying(txid, address) {
  for (let i = 0; i < 60; i++) {
    const tx = await rpc("getrawtransaction", [txid, true]).catch(() => null);
    const v = tx?.vout.find((o) => o.scriptPubKey.address === address);
    if (v) return { vout: v.n, sats: BigInt(Math.round(v.value * 1e8)) };
    await sleep(2000);
  }
  throw new Error("faucet tx never showed up");
}

// 1. The vault: user key + today's 7 validators, 5-of-7, short exit for the demo.
const vals = await (await fetch(`${B}/tachi_validators`)).json();
const nodePubkeys = vals.validators.map((v) => v.pub_key_hex);
const vault = await V.createVault({ network: "regtest", userPubkey: pub33, nodePubkeys, csvBlocks });
log("vault address", vault.p2tr.address, "csv", vault.p2tr.exitLeaf.csvBlocks);

// 2. Fund it: faucet -> the user's P2WPKH -> the vault (SegWit funding).
// FUND_TXID resumes from a vault funding that already confirmed (vout 0).
let fundTxid = process.env.FUND_TXID;
if (!fundTxid) {
  const wpkh = bitcoin.payments.p2wpkh({ pubkey: pub33, network: net });
  const drip = await (await fetch(`${FAUCET}/api/faucet`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ address: wpkh.address, amountBtc: Number(amount + 20000n) / 1e8, proof: null }),
  })).json();
  if (!drip.ok) throw new Error("faucet: " + JSON.stringify(drip));
  const coin = await voutPaying(drip.txid, wpkh.address);
  const fundPsbt = new bitcoin.Psbt({ network: net });
  fundPsbt.addInput({ hash: drip.txid, index: coin.vout, witnessUtxo: { script: wpkh.output, value: coin.sats } });
  fundPsbt.addOutput({ address: vault.p2tr.address, value: amount });
  fundPsbt.addOutput({ address: wpkh.address, value: coin.sats - amount - 500n });
  fundPsbt.signInput(0, kp);
  fundPsbt.finalizeAllInputs();
  fundTxid = await rpc("sendrawtransaction", [fundPsbt.extractTransaction().toHex()]);
  log("vault funded", fundTxid, "- waiting for a block");
}
await waitConfirmed(fundTxid, 0);
log("funding confirmed", fundTxid);

// 3. A ledger VTXO for the open fee (a vault open must spend one).
const q = { baseUrl: B };
let nonce = await V.getAccountNonce(xonly, q);
const fee = 1n;
const dep = await V.signTachiTx(V.buildTachiTxDeposit({ userXOnly: xonly, amountSats: 1000n, nonce, feeSats: fee }), signer);
const BROADCAST = { url: `${B}/tachi_txBroadcastSync`, treatDuplicateAsAccepted: true };
const depSent = await V.broadcastTachiTx(dep, BROADCAST);
log("fee VTXO deposit", JSON.stringify(depSent));
await V.waitForTachiTxCommit(depSent.tendermintTxHash, { baseUrl: B, overallTimeoutMs: 120000 });
const feeVtxo = V.vtxoIdFromDeposit(dep, 0);

// 4. Open (register) the vault on Tachi.
const fundingTxid = Buffer.from(fundTxid, "hex").reverse();
const reg = await V.registerVault({
  vault,
  outpoint: { fundingTxid, fundingVout: 0 },
  userSigner: signer,
  inputs: [{ vtxoId: feeVtxo }],
  outputs: [{ owner: xonly, amount: 1000n - fee }],
  feeSats: fee,
  broadcast: BROADCAST,
  account: q,
  confirm: { baseUrl: B, overallTimeoutMs: 120000 },
});
log("vault opened", reg.vaultIdHex);

// 5. Refund at state 0: user signs, the quorum co-signs, then broadcast.
const toLocal = V.buildToLocalP2trOutput({
  network: "regtest",
  nodePubkeys,
  userDelayedPubkey: vault.p2tr.cooperativeLeaf.userKey,
  toSelfDelay: vault.p2tr.exitLeaf.csvBlocks,
});
const hint = V.encodeStateHint(0n, V.deriveStateObfuscator(pub33, V.quorumAggregateKey(nodePubkeys)));
const refundFee = 600n;
const userValue = amount - refundFee;
const { psbt } = V.buildRefundPsbt({
  vault, toLocal, feeSats: refundFee, userValueSats: userValue,
  funding: { txid: fundTxid, vout: 0, valueSats: amount, scriptPubKey: vault.p2tr.output.toString("hex") },
  sequence: hint.sequence, locktime: hint.locktime,
});
const opts = { maxFeeSats: 5000n, toLocal, expectedUserValueSats: userValue, expectedDelayedPubkey: vault.p2tr.cooperativeLeaf.userKey };
await V.signRefundPsbtAsUser(psbt, signer, vault, opts);
let cos;
for (let i = 0; ; i++) {
  try {
    cos = await V.cosignRefund(psbt, vault, { url: `${B}/tachi_signTransaction`, timeoutMs: 120000 });
    break;
  } catch (e) {
    if (i >= 4) throw e;
    log("co-sign retry:", e.message);
  }
}
log("quorum co-signed:", cos.signatures, "signatures");
const refundHex = V.finalizeRefundPsbt(psbt, vault, opts);
const refundTxid = await rpc("sendrawtransaction", [refundHex]);
log("refund broadcast", refundTxid, "- waiting for a block and the watchtower");
await waitConfirmed(refundTxid, 0);

// 6. The watchtower's verdict on the refund (it scans L1 after each block).
let receipt = null;
for (let i = 0; i < 60 && !receipt; i++) {
  const r = await (await fetch(`${B}/tachi_watchtower/receipts?vault=${reg.vaultIdHex}`)).json();
  receipt = (r.receipts || []).find((x) => x.spend_txid === refundTxid) || null;
  if (!receipt) await sleep(5000);
}
log("watchtower receipt", JSON.stringify(receipt));

console.log(JSON.stringify({
  txid: refundTxid,
  vout: 0,
  value_sats: Number(userValue),
  address: toLocal.address,
  csv_blocks: csvBlocks,
  witness_script_hex: Buffer.from(toLocal.script).toString("hex"),
  vault_id: reg.vaultIdHex,
  funding_txid: fundTxid,
  receipt,
}));
