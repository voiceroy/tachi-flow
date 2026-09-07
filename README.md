# tachi-flow

OP_Freedom **bounty #10 — Liquidity Management** PoC against **live Tachi regtest** (`https://rpc-regtest.tachibtc.com`).

Quotes L1 ↔ VTXO swaps. Inventory is the LP’s real Tachi VTXOs plus Bitcoin UTXOs at the claim address (via Tachi’s `scantxoutset`). Inbound HTLCs are watched on bitcoind; VTXO payouts are TachiTx transfers. A background sync runs every 8 seconds.

## Run

```bash
cargo test
cargo run
```

Restart after pulls so `tachi-lp.secret` keeps the same Tachi identity.

Env:

| Variable | Default |
|---|---|
| `BIND` | `127.0.0.1:8080` |
| `TACHI_BASE_URL` | `https://rpc-regtest.tachibtc.com` |
| `BITCOIN_NETWORK` | `regtest` |
| `TACHI_LP_SECRET_HEX` | else `tachi-lp.secret` |

Then `./scripts/demo.sh`.

## Swap flow (live)

**In (L1 → VTXO)**

1. `POST /v1/quotes` with `user_tachi_address` = 64-char x-only or `bcrt1p…`, plus `user_refund_pubkey_hex`
2. Pay the returned HTLC `bcrt1q…` on Tachi’s Bitcoin regtest
3. `POST /v1/sync` (or wait ~8s) — scan finds the lock, LP sends VTXOs, claim tx is broadcast if bitcoind accepts it

**Out (VTXO → L1)**

1. Quote with `user_l1_address` = a **regtest** Bitcoin address (`bcrt1q…` / `bcrt1p…`)
2. Pay VTXOs to the LP Tachi pubkey (`GET /` → `tachi_lp_pubkey`)
3. Sync — new VTXO on the LP triggers an L1 send from the claim address (needs coins there, usually after inbound claims)

Regtest VTXO balance can be topped up with `POST /v1/vtxo/deposit` (Tachi ledger deposit + min fee). That is a real daemon tx, not an in-process fake.

## API

- `GET /` — service, bounty, `tachi_lp_pubkey`
- `GET /health` — Tachi daemon
- `GET /v1/inventory` — live LP (`source: tachi`)
- `GET /v1/tachi/wallet` — unspent VTXOs
- `POST /v1/vtxo/deposit` / `POST /v1/vtxo/send`
- `POST /v1/quotes` — `side: in|out`
- `POST /v1/swaps` — `{ "quote_id": "..." }`
- `GET /v1/swaps/{id}`
- `POST /v1/sync` — scan all quoted swaps
- `POST /v1/swaps/{id}/sync`
- `POST /v1/swaps/{id}/observe/lock` — same as sync for inbound (must be funded on chain)
- `POST /v1/swaps/{id}/observe/vtxo` — `{ "vtxo_id": "<64 hex>" }` paid to the LP
- `POST /v1/swaps/{id}/claim` — broadcast the HTLC claim
- `POST /v1/demo/keys` — refund pubkey + `tachi_xonly_hex`

## Honest limits

- Tachi **regtest**, not mainnet.
- You still need Bitcoin on that regtest to fund an inbound HTLC (the hosted node may not give you a faucet).
- Outbound L1 send needs UTXOs at the LP claim address (after a successful inbound claim, or a deposit to that `bcrt1q…`).
- Unit tests keep an in-memory booth so they do not hit the public RPC.
