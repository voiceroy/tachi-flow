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

Swaps survive `cargo run` restarts. State lives in SQLite (`tachi-flow-state.db`, gitignored): one row per swap, quote, advance, bond and so on, and each save writes only the rows that changed, in one WAL transaction with full sync. On first start an existing `tachi-flow-state.json` is imported (and left in place). `STATE_PATH=….json` keeps the old single-file JSON store. Empty LP books get a demo VTXO deposit on startup.

## What the vault can't do

A TAURUS vault has one exit: the whole deposit, after a fixed ~1008-block CSV, at no fee. The desks turn that wait into a priced market:

- **Inventory-skew pricing.** Each desk's fee moves with its books. A swap that drains a desk's scarce side costs more; one that refills it costs less. The skew is averaged over the swap's before/after effect on the desk's VTXO share, so big swaps pay for their own impact. Every quote carries a `pricing` breakdown (base, inventory, firm-quote cost, deadline discount).
- **RFQ with firm, expiring quotes.** `POST /v1/rfq` returns a firm quote from every desk that can fill, cheapest first. Each one reserves stock until it expires (`ttl_secs`, 30 s–1 h; holding a price longer costs more). Accepting one releases the rest.
- **Pick your deadline (outbound).** `deadline_blocks` (0–1008) says how long the desk may wait before locking your bitcoin. Later is cheaper, down to 80% off at a full vault-exit wait. `GET /v1/price-curve` shows fee by deadline for each desk.
- **Batched exits.** Every outbound lock that is due, deadline or "now", is funded by the desk's next batch pass (each sync, ~8 s), one L1 tx per desk. Each swap records its `l1_lock_vout` and `lock_batch_size`.
- **Split exits.** `POST /v1/exits` splits any amount (also above one swap's 2M limit or one desk's stock) into legs, cheapest marginal price first, never leaving a remainder too small to be its own leg. Every leg is a firm quote; `POST /v1/exits/{id}/accept` opens them all. If the desks can't cover the whole amount, nothing is reserved.
- **Desk bonds and track record.** Desks lock their own L1 into a bond script (`POST /v1/lps/{id}/bond`, operator route): `IF <operator> CHECKSIG ELSE 144 CSV DROP <desk> CHECKSIG ENDIF`. The operator can slash it; the desk can always take it back alone after 144 blocks, so a vanished operator cannot freeze it. A desk *defaults* when it never locks bitcoin for an outbound swap, or never pays a funded inbound lock, before the timeout margin. Then the user gets 1% of the swap (at least 500 sats, at most what is bonded), paid on L1 out of the bond to their address (or a P2WPKH of their swap key), with the rest re-locked to the same script. Desks bonded under the older VTXO escrow are paid from that instead. `GET /v1/bonds` lists every bond with its script; `POST /v1/lps/{id}/bond/withdraw {"unilateral": false}` returns a desk's bonds once nothing it owes is in flight (`unilateral: true` uses the desk's own CSV path). Each desk's score is `(fills + 1) / (fills + defaults + 2)`; below 40% it stops routing. The books show bond, fills, defaults and score.
- **Desk rebalancing.** Pricing nudges flow; rebalancing moves stock. When one desk holds more than 70% of its free books in VTXOs and another less than 30%, they swap at zero fee: the first sends VTXOs, the second sends the same in L1 back. The amount brings both toward 50/50 without overshooting, capped at 1M sats. Sync tries every 10 minutes; `POST /v1/rebalance` (operator) forces one and `GET /v1/rebalances` lists them. The VTXO leg goes first; if the L1 leg back fails, it stays `pending_l1` and is retried. A desk with no skewed counterpart can't rebalance this way (that would need a vault deposit or exit).
- **Signed quotes.** Each desk signs every quote with its own key: a BIP340 Schnorr signature over a domain-tagged commitment to the terms (id, side, amounts, fee, desk, expiry, payment/HTLC instructions, user key, deadline). The quote carries `desk_pubkey` and `desk_signature`. `POST /v1/quotes/verify` checks a quote; `POST /v1/disputes` takes a signed quote and reports whether the swap opened from it kept those terms and whether the desk defaulted. Anyone can check the signature offline against the desk keys in `/v1/meta`.
- **Live updates.** `GET /v1/events` is a server-sent event stream of every swap, advance and Lightning-swap change; the UI uses it instead of polling. `POST /v1/webhooks` (operator route) POSTs each event to a URL. The server also subscribes to Tachi's push stream (`/tachi_ws`) for every desk key, so a VTXO payment triggers a sync immediately rather than on the next tick.
- **Claim advances.** Bitcoin stuck behind a timelock (like a vault refund waiting out its delay) can be sold for bitcoin now. The user hands the desk a spend of the output, signed now but valid only at maturity. The desk checks the script (`<csv> OP_CSV OP_DROP <pubkey> OP_CHECKSIG`, P2WSH), the outpoint, the CSV sequence, the payee and amount, and the signature, then pays `value − discount` immediately and broadcasts the spend at maturity. Discount: 0.5% + 0.002% per block left. `POST /v1/demo/csv-lock` makes such an output from the faucet.
  - **Real vault refunds.** The desk also accepts Tachi's own refund output: the TAURUS `to_local` P2TR (NUMS internal key, one leaf `IF <q1> CHECKSIG <q2..q7> CHECKSIGADD 5 NUMEQUAL ELSE <delay> CSV DROP <user> CHECKSIG ENDIF`). It rebuilds the output key from the leaf, requires the quorum to be today's validator set (`/tachi_validators`, sorted by compressed key) with a ≥ 2/3 threshold, and checks the user's delayed spend: witness `[sig64, <empty>, leaf, control block]`, nSequence = delay, BIP341 SIGHASH_DEFAULT. Because the quorum branch never expires, it then asks Tachi's watchtower (`/tachi_watchtower/receipts?vault=<id>`, id = SHA256(funding txid ‖ vout BE)) about the refund tx: `stale` / `anomalous` is refused, `legitimate` is advanced, and no receipt is refused unless `VAULT_ADVANCE_UNRECEIPTED=1`. The script recipe matches the Tachi SDK's test vector and the vault id a live vault. `{"vault": true}` on `/v1/demo/csv-lock` builds a `to_local` under the live quorum (short delay, no vault behind it).
- **Hosted third-party desks.** Outside LPs run their own server, keys and funds; the operator registers each one (`POST /v1/desks/hosted {id, name, endpoint, pubkeys}`, operator route) and pins the x-only keys it signs quotes with. `POST /v1/market/quotes` asks the house desks and every hosted desk in parallel (3 s each, `POST {endpoint}/v1/quotes`) and passes on a hosted quote only if its BIP340 signature verifies under a pinned key and its terms match the request; failures are listed under `refused`. The response names the best price. The user settles a hosted quote with that desk directly, so this server never holds its funds. Any tachi-flow instance can be a hosted desk, and `POST /v1/quotes/verify` / `/v1/disputes` recognise hosted desks' signatures.
- **Lightning.** With an LND node (`LND_REST_URL`), Lightning → VTXOs uses a hold invoice on the desk's payment hash: the user's payment is only held until the desk has sent VTXOs, then settled; if the desk never pays, the invoice is cancelled and Lightning returns the funds. VTXOs → Lightning: the desk pays the user's invoice after it sees their VTXOs, and returns the VTXOs if the payment definitively fails.

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
| `LND_REST_URL` | unset = Lightning off |
| `LND_MACAROON_HEX` / `LND_MACAROON_PATH` | required with `LND_REST_URL` |
| `LND_TLS_CERT_PATH` | LND's self-signed cert, if not publicly trusted |
| `STATE_PATH` | `tachi-flow-state.db` (SQLite); a `.json` path uses the JSON file store |
| `VAULT_ADVANCE_UNRECEIPTED` | unset = advance only on vault refunds the watchtower classified `legitimate`; `1` = also without a receipt, at +2% discount |

LP identities: `tachi-lp-alpha.secret` / `tachi-lp-bravo.secret` (migrates old `tachi-lp.secret`). Bond escrow: `tachi-escrow.secret`.

## API

- `GET /` — UI
- `GET /v1/stats` — settled volume and fees, swaps by status, batching savings, per-desk track record, average settle time vs a vault exit
- `POST /v1/quotes/verify` · `POST /v1/disputes` — body: a quote as returned; check its desk signature / whether it was honoured
- `POST /v1/rfq` — firm quotes from every desk; body like `/v1/quotes` plus optional `ttl_secs`, `deadline_blocks`
- `POST /v1/market/quotes` — RFQ including hosted desks · `GET /v1/desks/hosted` · `POST /v1/desks/hosted` · `DELETE /v1/desks/hosted/{id}` (operator)
- `POST /v1/quotes` — best single quote (same body)
- `GET /v1/price-curve?side=out&amount_sats=…` — fee by deadline per desk (reserves nothing)
- `POST /v1/swaps` · `POST /v1/sync` · `POST /v1/swaps/{id}/sync`
- `POST /v1/swaps/{id}/fund` — faucet helper for inbound
- `POST /v1/swaps/{id}/pay-vtxo` — `{ "secret_hex": "..." }` for outbound from the demo key (idempotent)
- `POST /v1/swaps/{id}/refund` — `{ "secret_hex": "..." }`; cancel, or on-chain refund after the timeout
- `POST /v1/demo/keys` — refund pubkey, Tachi x-only, L1 `bcrt1q…`
- `POST /v1/exits` · `GET /v1/exits/{id}` · `POST /v1/exits/{id}/accept` — split exits
- `GET /v1/events` — server-sent events (`?swap_id=` to filter)
- `POST /v1/advances/quote` · `GET /v1/advances` · `GET /v1/advances/{id}` · `POST /v1/advances/{id}/accept` — claim advances; `POST /v1/advances/{id}/demo-presign` and `POST /v1/demo/csv-lock` are demo helpers
- `POST /v1/ln/quotes` · `GET /v1/ln/swaps` · `GET /v1/ln/swaps/{id}` · `POST /v1/ln/swaps/{id}/paid` · `POST /v1/ln/swaps/{id}/pay-vtxo` — Lightning

Operator routes need `x-admin-token: <token>` (or `Authorization: Bearer <token>`): `/v1/vtxo/send`, `/v1/vtxo/deposit`, `/v1/swaps/{id}/observe/lock`, `/v1/swaps/{id}/observe/vtxo`, `/v1/swaps/{id}/claim`, `/v1/swaps/{id}/lp-default`, `/v1/lps/{id}/bond`, `/v1/lps/{id}/bond/withdraw`, `/v1/webhooks`, `/v1/rebalance`, `POST`/`DELETE /v1/desks/hosted`. There is no CORS layer; the UI is same-origin.

## Swap lifecycle

`quoted` → `lp_settled` → `claimed`, or `expired` / `refunded` / `failed`.

- Timeouts are absolute block heights. The server fetches the tip before serving and refuses to quote while it is unknown.
- The desk stops settling 12 blocks before a lock's timeout. Such swaps become `expired`; the user refunds an inbound lock after the timeout, and the desk takes back an unpaid outbound lock.
- Desk payouts (VTXOs and L1 locks) are signed and saved before broadcast. Retries re-send the same tx or confirm it landed, so a lost reply cannot pay twice.
- Open quotes and unsettled swaps hold desk inventory; live books are chain balance minus those holds.
- Desks spend their own unconfirmed change. Outputs a desk's broadcasts pay back to it (change, claims, refunds) are spendable at once, after a mempool check, so back-to-back exits don't wait for a block. Books count confirmed coins not already spent in the mempool, plus that pending change.
- Desk fees follow bitcoind's `estimatesmartfee` (6-block target, floor 2 sat/vB, shown in `/v1/meta`), sized by each tx's estimated vsize. This covers funding sends, inbound claims and refunds. Claims and funding txs signal RBF. If a desk's inbound claim is still unconfirmed 6 blocks before the HTLC timeout, it is re-signed at double the fee (capped at half the lock) and re-sent, as is a claim the mempool dropped. A user's outbound claim keeps the fixed 500-sat cushion built into the desk's lock; the server cannot re-sign it later because it never keeps the user's key.
- Holding stock is capped so nobody can freeze the desks for free. Per client (peer IP; the admin token is exempt): at most 6 open quotes or unpaid swaps and 4M sats of stock held, else `429`. A quote for more than a quarter of a desk's free stock stays firm for at most 120 s. An opened swap nobody pays within an hour (and 6 blocks past any deadline) expires and releases its stock.
- State is written atomically (one SQLite transaction, or a rename for JSON). A corrupt store stops startup instead of silently dropping preimages.

## Honest limits

- Tachi **regtest**, not mainnet.
- The faucet helper is a **demo convenience**. A real wallet pays the lock directly.
- Desk inventory is **LP float** (VTXOs + L1 claim address), labeled against a 1008-block TAURUS exit. It is not opening a vault for the user.
- `POST /v1/vtxo/deposit` is a Tachi ledger mint for demo books, not a user TAURUS deposit.
- Outbound VTXOs themselves are not scripted (Tachi transfers are owner-based); safety is **LP locks L1 first**, then you pay.
- Outbound is **not trustless**. The desk holds the preimage. After you pay VTXOs, a dishonest desk could withhold it and refund its lock after the timeout. This desk reveals the preimage on the swap (`preimage_hex`) as soon as it sees your payment, so you can claim with any wallet, but that is a promise, not a protocol guarantee. A real fix needs hash-locked VTXOs on Tachi.
- Tachi transfers carry no memo. Outbound payments are matched automatically only when unambiguous (exact amount, new coin, no other open swap on that desk waiting for the same amount); otherwise pay through `pay-vtxo`, which records the payment id.
- **Bonds trust the operator on slashing.** The desk cannot lose its bond to a vanished operator, but Bitcoin script cannot restrict where the operator's slash path pays, so a dishonest operator could take a bond. Older VTXO escrow bonds remain fully custodial. In this demo both desks run on the same server, so `unilateral` withdrawal shows the script path rather than real independence.
- **Claim advances carry a race.** At maturity the user's own key can also spend the output; whoever broadcasts first wins. The discount prices that risk, and a lost race shows as `lost`. For vault refunds there is a second race: the validator quorum can spend `to_local` at any time, so the desk relies on the watchtower's verdict and an honest 5-of-7. The watchtower receipt format is inferred from Tachi's API spec; regtest has no receipts yet to check it against, and refunds created under an earlier validator set are refused.
- **Hosted desks are vetted by signature, not by track record.** A verified quote proves what the desk promised, but this server cannot see whether it settles, so hosted desks have no fills/defaults score or bond here; the operator decides whom to register.
- **Lightning is untested against a live node.** Tachi regtest has no Lightning node, so the LND client is exercised through a mock in the tests. Lightning → VTXOs is as trust-minimised as a hold invoice allows; VTXOs → Lightning trusts the desk to pay after receiving VTXOs (same as outbound swaps).
- **Webhooks** are operator-only because the server makes outbound requests to whatever URL is registered.
