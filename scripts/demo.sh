#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://127.0.0.1:8080}"

echo "== health"
curl -sS "$BASE/health" | python3 -m json.tool

echo "== live inventory (Tachi VTXOs + scanned L1)"
curl -sS "$BASE/v1/inventory" | python3 -m json.tool

echo "== LP Tachi wallet"
WALLET=$(curl -sS "$BASE/v1/tachi/wallet")
python3 -m json.tool <<<"$WALLET"
UNSPENT=$(python3 -c "import json,sys; print(json.load(sys.stdin)['unspent_sats'])" <<<"$WALLET")
if [ "$UNSPENT" -lt 50000 ]; then
  echo "== deposit 100000 VTXOs to LP (regtest)"
  curl -sS -X POST "$BASE/v1/vtxo/deposit" \
    -H 'content-type: application/json' \
    -d '{"amount_sats":100000}' | python3 -m json.tool
  sleep 3
  curl -sS "$BASE/v1/tachi/wallet" | python3 -m json.tool
fi

echo "== demo keys (refund + Tachi dest)"
KEYS=$(curl -sS -X POST "$BASE/v1/demo/keys")
python3 -m json.tool <<<"$KEYS"
PUB=$(python3 -c "import json,sys; print(json.load(sys.stdin)['pubkey_hex'])" <<<"$KEYS")
TACHI=$(python3 -c "import json,sys; print(json.load(sys.stdin)['tachi_xonly_hex'])" <<<"$KEYS")

echo "== send 10000 VTXOs to the demo Tachi key"
curl -sS -X POST "$BASE/v1/vtxo/send" \
  -H 'content-type: application/json' \
  -d "{\"dest\":\"$TACHI\",\"amount_sats\":10000}" | python3 -m json.tool
sleep 2

echo "== quote in (real Tachi dest; pay the HTLC on Bitcoin then sync)"
QUOTE=$(curl -sS -X POST "$BASE/v1/quotes" \
  -H 'content-type: application/json' \
  -d "{\"side\":\"in\",\"amount_sats\":20000,\"user_tachi_address\":\"$TACHI\",\"user_refund_pubkey_hex\":\"$PUB\"}")
python3 -m json.tool <<<"$QUOTE"
QID=$(python3 -c "import json,sys; print(json.load(sys.stdin)['id'])" <<<"$QUOTE")
LOCK=$(python3 -c "import json,sys; print(json.load(sys.stdin)['pay']['address'])" <<<"$QUOTE")

echo "== open swap"
SWAP=$(curl -sS -X POST "$BASE/v1/swaps" \
  -H 'content-type: application/json' \
  -d "{\"quote_id\":\"$QID\"}")
python3 -m json.tool <<<"$SWAP"
SID=$(python3 -c "import json,sys; print(json.load(sys.stdin)['id'])" <<<"$SWAP")

echo "== waiting for Bitcoin payment to $LOCK"
echo "    (background sync every 8s, or: curl -X POST $BASE/v1/swaps/$SID/sync)"
curl -sS -X POST "$BASE/v1/swaps/$SID/sync" | python3 -m json.tool
