#!/usr/bin/env python3
"""HTTP stress for tachi-flow.

Hits the local Actix API with concurrent readers, quote/swap pipelines, and
race cases. Uses simulated VTXO/L1 settlement (non-Tachi addresses / ids) so
the run does not broadcast to the Tachi daemon.

Example:

    TEST_MODE=1 ADMIN_TOKEN=stress BIND=127.0.0.1:18080 cargo run --release
    ./scripts/stress.py --base http://127.0.0.1:18080 --admin-token stress
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any


def pct(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    idx = min(len(sorted_vals) - 1, max(0, int(round((p / 100.0) * (len(sorted_vals) - 1)))))
    return sorted_vals[idx]


@dataclass
class Stats:
    lock: threading.Lock = field(default_factory=threading.Lock)
    latencies_ms: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))
    status: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    errors: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    ok: Counter = field(default_factory=Counter)
    fail: Counter = field(default_factory=Counter)

    def record(self, name: str, ms: float, code: int, body: str | None = None) -> None:
        with self.lock:
            self.latencies_ms[name].append(ms)
            self.status[name][code] += 1
            if 200 <= code < 300:
                self.ok[name] += 1
            else:
                self.fail[name] += 1
                if body:
                    snippet = body[:160].replace("\n", " ")
                    self.errors[name][f"{code} {snippet}"] += 1

    def record_exc(self, name: str, ms: float, err: str) -> None:
        with self.lock:
            self.latencies_ms[name].append(ms)
            self.fail[name] += 1
            self.status[name][0] += 1
            self.errors[name][err[:160]] += 1

    def report(self, elapsed: float) -> None:
        names = sorted(set(self.latencies_ms) | set(self.ok) | set(self.fail))
        total_ok = sum(self.ok.values())
        total_fail = sum(self.fail.values())
        total = total_ok + total_fail
        print()
        print(f"elapsed {elapsed:.2f}s  requests {total}  ok {total_ok}  fail {total_fail}  rps {total / elapsed:.1f}")
        print(f"{'op':<22} {'n':>7} {'ok':>7} {'fail':>7} {'p50':>8} {'p95':>8} {'p99':>8} {'max':>8}")
        for name in names:
            samples = sorted(self.latencies_ms.get(name, []))
            n = len(samples)
            print(
                f"{name:<22} {n:7d} {self.ok[name]:7d} {self.fail[name]:7d} "
                f"{pct(samples, 50):8.1f} {pct(samples, 95):8.1f} {pct(samples, 99):8.1f} "
                f"{(samples[-1] if samples else 0):8.1f}"
            )
        for name in names:
            if self.errors[name]:
                print(f"\nerrors {name}:")
                for msg, count in self.errors[name].most_common(8):
                    print(f"  {count:5d}  {msg}")


class Client:
    def __init__(self, base: str, timeout: float, admin_token: str = "") -> None:
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.admin_token = admin_token

    def call(
        self,
        stats: Stats,
        name: str,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        expect: int | None = None,
    ) -> tuple[int, Any]:
        data = None if body is None else json.dumps(body).encode()
        headers = {"accept": "application/json"}
        if self.admin_token:
            headers["x-admin-token"] = self.admin_token
        if data is not None:
            headers["content-type"] = "application/json"
        req = urllib.request.Request(
            self.base + path,
            data=data,
            headers=headers,
            method=method,
        )
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode()
                code = resp.status
        except urllib.error.HTTPError as e:
            raw = e.read().decode(errors="replace")
            code = e.code
        except Exception as e:
            ms = (time.perf_counter() - t0) * 1000
            stats.record_exc(name, ms, f"{type(e).__name__}: {e}")
            return 0, {"error": str(e)}
        ms = (time.perf_counter() - t0) * 1000
        stats.record(name, ms, code, raw if code >= 400 else None)
        parsed: Any = raw
        if raw:
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = raw
        if expect is not None and code != expect:
            raise AssertionError(f"{name} expected {expect} got {code}: {parsed}")
        return code, parsed


def demo_pubkey(client: Client, stats: Stats) -> str:
    _, keys = client.call(stats, "demo_keys", "POST", "/v1/demo/keys", expect=200)
    return keys["pubkey_hex"]


def inbound_cycle(client: Client, stats: Stats, pubkey: str, i: int, amount: int) -> None:
    _, quote = client.call(
        stats,
        "quote_in",
        "POST",
        "/v1/quotes",
        {
            "side": "in",
            "amount_sats": amount,
            "user_tachi_address": "tb1ptest",
            "user_refund_pubkey_hex": pubkey,
        },
        expect=201,
    )
    _, swap = client.call(
        stats,
        "open_swap",
        "POST",
        "/v1/swaps",
        {"quote_id": quote["id"]},
        expect=201,
    )
    sid = swap["id"]
    client.call(
        stats,
        "observe_lock",
        "POST",
        f"/v1/swaps/{sid}/observe/lock",
        {
            "txid": f"{i:064x}",
            "vout": 0,
            "value_sats": amount,
        },
        expect=200,
    )
    client.call(stats, "claim", "POST", f"/v1/swaps/{sid}/claim", expect=200)
    client.call(stats, "get_swap", "GET", f"/v1/swaps/{sid}", expect=200)


def outbound_cycle(client: Client, stats: Stats, i: int, amount: int) -> str:
    _, quote = client.call(
        stats,
        "quote_out",
        "POST",
        "/v1/quotes",
        {"side": "out", "amount_sats": amount, "user_l1_address": "tb1qtest"},
        expect=201,
    )
    lp_id = quote["lp_id"]
    _, swap = client.call(
        stats,
        "open_swap",
        "POST",
        "/v1/swaps",
        {"quote_id": quote["id"]},
        expect=201,
    )
    sid = swap["id"]
    client.call(
        stats,
        "observe_vtxo",
        "POST",
        f"/v1/swaps/{sid}/observe/vtxo",
        {"vtxo_id": f"sim-{i}"},
        expect=200,
    )
    client.call(stats, "get_swap", "GET", f"/v1/swaps/{sid}", expect=200)
    return lp_id


def race_open_swap(client: Client, stats: Stats, pubkey: str, workers: int) -> None:
    _, quote = client.call(
        stats,
        "quote_in",
        "POST",
        "/v1/quotes",
        {
            "side": "in",
            "amount_sats": 10_000,
            "user_tachi_address": "tb1ptest",
            "user_refund_pubkey_hex": pubkey,
        },
        expect=201,
    )
    qid = quote["id"]
    codes: list[int] = []
    lock = threading.Lock()

    def one() -> None:
        code, _ = client.call(stats, "open_swap_race", "POST", "/v1/swaps", {"quote_id": qid})
        with lock:
            codes.append(code)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(one) for _ in range(workers)]
        for f in as_completed(futs):
            f.result()
    wins = codes.count(201)
    misses = codes.count(404)
    print(f"race open_swap: {workers} concurrent, wins={wins} not_found={misses} other={len(codes) - wins - misses}")
    if wins != 1:
        raise SystemExit(f"expected exactly one open_swap winner, got {wins}")


def race_observe_lock(client: Client, stats: Stats, pubkey: str, workers: int) -> None:
    _, quote = client.call(
        stats,
        "quote_in",
        "POST",
        "/v1/quotes",
        {
            "side": "in",
            "amount_sats": 10_000,
            "user_tachi_address": "tb1ptest",
            "user_refund_pubkey_hex": pubkey,
        },
        expect=201,
    )
    _, swap = client.call(stats, "open_swap", "POST", "/v1/swaps", {"quote_id": quote["id"]}, expect=201)
    sid = swap["id"]
    codes: list[int] = []
    lock = threading.Lock()

    def one(i: int) -> None:
        code, _ = client.call(
            stats,
            "observe_lock_race",
            "POST",
            f"/v1/swaps/{sid}/observe/lock",
            {"txid": f"{i:064x}", "vout": 0, "value_sats": 10_000},
        )
        with lock:
            codes.append(code)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(one, i) for i in range(workers)]
        for f in as_completed(futs):
            f.result()
    wins = codes.count(200)
    conflicts = codes.count(409)
    print(f"race observe_lock: {workers} concurrent, wins={wins} conflict={conflicts} other={len(codes) - wins - conflicts}")
    if wins != 1:
        raise SystemExit(f"expected exactly one observe_lock winner, got {wins}")


def inventory(client: Client, stats: Stats) -> list[dict[str, Any]]:
    _, body = client.call(stats, "inventory", "GET", "/v1/inventory", expect=200)
    return body


def run_pool(n: int, workers: int, fn) -> None:
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(fn, i) for i in range(n)]
        for f in as_completed(futs):
            f.result()


def main() -> int:
    p = argparse.ArgumentParser(description="Stress tachi-flow over HTTP")
    p.add_argument("--base", default="http://127.0.0.1:18080")
    p.add_argument("--workers", type=int, default=64)
    p.add_argument("--reads", type=int, default=2000)
    p.add_argument("--keys", type=int, default=400)
    p.add_argument("--inbound", type=int, default=300)
    p.add_argument("--outbound", type=int, default=180)
    p.add_argument("--amount-in", type=int, default=10_000)
    p.add_argument("--amount-out", type=int, default=100_000)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument(
        "--admin-token",
        default=os.environ.get("ADMIN_TOKEN", ""),
        help="for observe/claim operator routes (default: $ADMIN_TOKEN)",
    )
    p.add_argument("--skip-races", action="store_true")
    p.add_argument(
        "--stampede",
        action="store_true",
        help="extra 10k out quotes after inbound (should spill, not 409)",
    )
    args = p.parse_args()

    stats = Stats()
    client = Client(args.base, args.timeout, args.admin_token)

    print(f"target {args.base}")
    code, meta = client.call(stats, "meta", "GET", "/v1/meta", expect=200)
    print(f"service {meta.get('service')} network {meta.get('network')} tachi {meta.get('tachi')}")
    before = inventory(client, stats)
    print("inventory before:")
    print(json.dumps(before, indent=2))

    t0 = time.perf_counter()

    print(f"\n== GET / + /v1/inventory x {args.reads} workers={args.workers}")
    def read_storm(i: int) -> None:
        if i % 2 == 0:
            client.call(stats, "root", "GET", "/")
        else:
            client.call(stats, "inventory", "GET", "/v1/inventory")
    run_pool(args.reads, args.workers, read_storm)

    print(f"== POST /v1/demo/keys x {args.keys}")
    run_pool(args.keys, args.workers, lambda _i: client.call(stats, "demo_keys", "POST", "/v1/demo/keys"))

    pubkey = demo_pubkey(client, stats)

    # Inbound first (the order that used to 409): claims fatten alpha L1, then
    # 100k out RFQs must reserve alpha then spill to bravo instead of stacking.
    print(f"== inbound quote/swap/lock/claim x {args.inbound} amount={args.amount_in}")
    run_pool(
        args.inbound,
        args.workers,
        lambda i: inbound_cycle(client, stats, pubkey, i, args.amount_in),
    )

    out_lps: Counter = Counter()
    out_lock = threading.Lock()
    print(f"== outbound quote/swap/observe_vtxo x {args.outbound} amount={args.amount_out}")

    def out_one(i: int) -> None:
        lp_id = outbound_cycle(client, stats, i, args.amount_out)
        with out_lock:
            out_lps[lp_id] += 1

    run_pool(args.outbound, args.workers, out_one)
    print(f"outbound lp split: {dict(out_lps)}")
    if args.outbound >= 40 and out_lps["lp-bravo"] < 1:
        raise SystemExit("outbound did not spill to lp-bravo after inbound claims")

    if args.stampede:
        print("== extra 10k out quotes (reserve/spill, expect 201)")
        stampede_lps: Counter = Counter()
        stampede_lock = threading.Lock()

        def stampede(i: int) -> None:
            _, quote = client.call(
                stats,
                "stampede_quote_out",
                "POST",
                "/v1/quotes",
                {"side": "out", "amount_sats": 10_000, "user_l1_address": "tb1qtest"},
                expect=201,
            )
            with stampede_lock:
                stampede_lps[quote["lp_id"]] += 1
            _, swap = client.call(
                stats, "stampede_open", "POST", "/v1/swaps", {"quote_id": quote["id"]}, expect=201
            )
            client.call(
                stats,
                "stampede_observe",
                "POST",
                f"/v1/swaps/{swap['id']}/observe/vtxo",
                {"vtxo_id": f"stampede-{i}"},
                expect=200,
            )

        run_pool(64, 32, stampede)
        print(f"stampede lp split: {dict(stampede_lps)}")

    if not args.skip_races:
        print(f"== race open_swap x {args.workers}")
        race_open_swap(client, stats, pubkey, args.workers)
        print(f"== race observe_lock x {args.workers}")
        race_observe_lock(client, stats, pubkey, args.workers)

    elapsed = time.perf_counter() - t0
    after = inventory(client, stats)
    stats.report(elapsed)

    print("\ninventory after:")
    print(json.dumps(after, indent=2))

    by_id = {lp["id"]: lp for lp in after}
    for lp in after:
        if lp["l1_sats"] < 0 or lp["vtxo_sats"] < 0:
            raise SystemExit(f"negative inventory on {lp['id']}")
    if "lp-alpha" not in by_id or "lp-bravo" not in by_id:
        raise SystemExit("expected simulated lp-alpha/lp-bravo (run with TEST_MODE=1)")

    alpha = by_id["lp-alpha"]
    bravo = by_id["lp-bravo"]
    if alpha["vtxo_sats"] > 20_000_000:
        raise SystemExit("alpha vtxo book grew (inbound should have spent it)")
    if args.outbound and bravo["l1_sats"] >= 20_000_000 and out_lps["lp-bravo"] == 0:
        raise SystemExit("bravo L1 untouched and no outbound routed there")

    allowed_fail = {"open_swap_race", "observe_lock_race"}
    hard = [name for name, n in stats.fail.items() if n and name not in allowed_fail]
    if hard:
        print(f"\nnon-race failures in: {hard}", file=sys.stderr)
        return 1
    print("\nok: no negative inventory, races exclusive, outbound spilled, non-race requests succeeded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
