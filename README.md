# tachi-flow

OP_Freedom **bounty #10 — Liquidity Management** PoC against **live Tachi regtest** (`https://rpc-regtest.tachibtc.com`).

Quotes L1 ↔ VTXO swaps so you **skip a TAURUS ~1008-block vault exit**. Two desks reserve stock.

- **In:** you lock bitcoin in an HTLC (~144-block refund) → desk pays VTXOs → desk claims.
- **Out:** desk locks bitcoin first (you claim with the preimage) → you send VTXOs → you claim the HTLC. Same script, roles reversed. Not “pay VTXOs and hope.”

Open `http://127.0.0.1:8080` for the demo UI.

## Demo (inbound, the path judges care about)

```bash
cargo run
```

1. Open `http://127.0.0.1:8080`. The page creates a **demo identity** and keeps it in the browser.
2. Direction: **I have bitcoin, I want Tachi coins**. Amount `20000`. **Get quotes from every desk** → pick a desk → Accept quote.
3. Click **Fund with faucet**.  
   Do **not** paste the lock address into https://faucet.tachibtc.com — that faucet rejects P2WSH lock addresses (`unknown output kind: p2wsh`). The desk faucets a normal wallet and forwards coins into the lock.
4. Status moves to **claimed**. VTXOs sit on the Tachi key shown at the top.

Optional outbound: quote **out** (same identity). Accept — the desk funds an HTLC to you. Then **Send my Tachi coins**. You claim the lock. If the desk never locks, you never send VTXOs. Clicking **Send** again after paying never pays twice; it only retries the claim.

**Refund / cancel** cancels a swap before any bitcoin is locked. If you already paid an inbound lock and the desk did not settle, the same button refunds it on-chain once the lock's timeout block has passed.

Swaps survive `cargo run` restarts (`tachi-flow-state.json`, gitignored). Empty LP books get a demo VTXO deposit on startup.

## What the vault can't do

A TAURUS vault has one exit: the whole deposit, after a fixed ~1008-block CSV, at no fee. The desks turn that wait into a priced market:

- **Inventory-skew pricing.** Each desk's fee moves with its books. A swap that drains a desk's scarce side costs more; one that refills it costs less. The skew is averaged over the swap's before/after effect on the desk's VTXO share, so big swaps pay for their own impact. Every quote carries a `pricing` breakdown (base, inventory, firm-quote cost, deadline discount).
- **RFQ with firm, expiring quotes.** `POST /v1/rfq` returns a firm quote from every desk that can fill, cheapest first. Each one reserves stock until it expires (`ttl_secs`, 30 s–1 h; holding a price longer costs more). Accepting one releases the rest.
- **Pick your deadline (outbound).** `deadline_blocks` (0–1008) says how long the desk may wait before locking your bitcoin. Later is cheaper, down to 80% off at a full vault-exit wait. `GET /v1/price-curve` shows fee by deadline for each desk.
- **Batched exits.** Every outbound lock that is due, deadline or "now", is funded by the desk's next batch pass (each sync, ~8 s), one L1 tx per desk. Each swap records its `l1_lock_vout` and `lock_batch_size`.

Defaults (ppm): skew ±10,000 at full imbalance, 3,000/hour of quote TTL, 80% max deadline discount, fee floor 500, cap 50,000 (`PricingConfig`).

## Run tests

```bash
cargo test
```

Env:

| Variable | Default |
|---|---|
| `BIND` | `127.0.0.1:8080` |
| `TACHI_BASE_URL` | `https://rpc-regtest.tachibtc.com` |
| `BITCOIN_NETWORK` | `regtest` |
| `TACHI_FAUCET_URL` | `https://faucet.tachibtc.com` |
| `TEST_MODE` | unset = live Tachi |
| `ADMIN_TOKEN` | unset = read/create `tachi-flow-admin.token` (0600) |

LP identities: `tachi-lp-alpha.secret` / `tachi-lp-bravo.secret` (migrates old `tachi-lp.secret`).

## API

- `GET /` — UI
- `POST /v1/rfq` — firm quotes from every desk; body like `/v1/quotes` plus optional `ttl_secs`, `deadline_blocks`
- `POST /v1/quotes` — best single quote (same body)
- `GET /v1/price-curve?side=out&amount_sats=…` — fee by deadline per desk (reserves nothing)
- `POST /v1/swaps` · `POST /v1/sync` · `POST /v1/swaps/{id}/sync`
- `POST /v1/swaps/{id}/fund` — faucet helper for inbound
- `POST /v1/swaps/{id}/pay-vtxo` — `{ "secret_hex": "..." }` for outbound from the demo key (idempotent)
- `POST /v1/swaps/{id}/refund` — `{ "secret_hex": "..." }`; cancel, or on-chain refund after the timeout
- `POST /v1/demo/keys` — refund pubkey, Tachi x-only, L1 `bcrt1q…`

Operator routes need `x-admin-token: <token>` (or `Authorization: Bearer <token>`): `/v1/vtxo/send`, `/v1/vtxo/deposit`, `/v1/swaps/{id}/observe/lock`, `/v1/swaps/{id}/observe/vtxo`, `/v1/swaps/{id}/claim`, `/v1/swaps/{id}/lp-default`. There is no CORS layer; the UI is same-origin.

## Swap lifecycle

`quoted` → `lp_settled` → `claimed`, or `expired` / `refunded` / `failed`.

- Timeouts are absolute block heights. The server fetches the tip before serving and refuses to quote while it is unknown.
- The desk stops settling 12 blocks before a lock's timeout. Such swaps become `expired`; the user refunds an inbound lock after the timeout, and the desk takes back an unpaid outbound lock.
- Desk payouts (VTXOs and L1 locks) are signed and saved before broadcast. Retries re-send the same tx or confirm it landed, so a lost reply cannot pay twice.
- Open quotes and unsettled swaps hold desk inventory; live books are chain balance minus those holds.
- State is written atomically. A corrupt `tachi-flow-state.json` stops startup instead of silently dropping preimages.

## Honest limits

- Tachi **regtest**, not mainnet.
- The faucet helper is a **demo convenience**. A real wallet pays the lock directly.
- Desk inventory is **LP float** (VTXOs + L1 claim address), labeled against a 1008-block TAURUS exit. It is not opening a vault for the user.
- `POST /v1/vtxo/deposit` is a Tachi ledger mint for demo books, not a user TAURUS deposit.
- Outbound VTXOs themselves are not scripted (Tachi transfers are owner-based); safety is **LP locks L1 first**, then you pay.
- Outbound is **not trustless**. The desk holds the preimage. After you pay VTXOs, a dishonest desk could withhold it and refund its lock after the timeout. This desk reveals the preimage on the swap (`preimage_hex`) as soon as it sees your payment, so you can claim with any wallet, but that is a promise, not a protocol guarantee. A real fix needs hash-locked VTXOs on Tachi.
- Tachi transfers carry no memo. Outbound payments are matched automatically only when unambiguous (exact amount, new coin, no other open swap on that desk waiting for the same amount); otherwise pay through `pay-vtxo`, which records the payment id.