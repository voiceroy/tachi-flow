// Records the tachi-flow demo against the live regtest server.
// Writes raw.webm plus cuts.json (spans to drop: waits for blocks/faucet).
const { chromium } = require('playwright');
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const URL = process.env.DEMO_URL || 'http://127.0.0.1:8090/';
const OUT = __dirname;
const VAULT_HELPER = process.env.VAULT_HELPER || path.join(__dirname, 'vault-refund.mjs');
const W = 1440, H = 900;

(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || '/usr/bin/chromium' });
  const ctx = await browser.newContext({
    viewport: { width: W, height: H },
    recordVideo: { dir: OUT, size: { width: W, height: H } },
  });
  const page = await ctx.newPage();
  const t0 = Date.now();
  const now = () => (Date.now() - t0) / 1000;
  const cuts = [];
  let cutFrom = null;
  const cutStart = () => { cutFrom = now(); };
  const cutEnd = () => { cuts.push([cutFrom, now()]); cutFrom = null; };
  const pause = (ms) => page.waitForTimeout(ms);

  await page.goto(URL);
  await pause(1500);

  // Overlay: caption bar, title card, fake cursor.
  await page.addStyleTag({ content: `
    #demo-cap { position: fixed; left: 50%; bottom: 28px; transform: translateX(-50%);
      max-width: 1100px; width: calc(100% - 160px); z-index: 9999; pointer-events: none;
      background: rgba(8,10,14,.92); border: 1px solid #f4c14e55; border-radius: 12px;
      padding: 16px 24px; color: #f3f5f8; font: 500 22px/1.4 Inter, system-ui, sans-serif;
      box-shadow: 0 10px 40px rgba(0,0,0,.5); transition: opacity .35s; }
    #demo-cap small { display: block; color: #f4c14e; font-size: 14px; letter-spacing: .08em;
      text-transform: uppercase; margin-bottom: 4px; }
    #demo-card { position: fixed; inset: 0; z-index: 10000; display: flex; flex-direction: column;
      align-items: center; justify-content: center; background: #0b0e13; color: #f3f5f8;
      font: 500 24px/1.5 Inter, system-ui, sans-serif; text-align: center; transition: opacity .6s; }
    #demo-card h1 { font: 700 64px/1.1 Inter, system-ui, sans-serif; margin: 0 0 18px; color: #f4c14e; }
    #demo-card p { margin: 6px 0; color: #c9d2de; max-width: 900px; }
    #demo-card ul { text-align: left; color: #c9d2de; font-size: 22px; margin-top: 18px; }
    #demo-cursor { position: fixed; z-index: 9998; width: 22px; height: 22px; border-radius: 50%;
      background: rgba(244,193,78,.85); border: 2px solid #fff; pointer-events: none;
      transform: translate(-50%,-50%); transition: left .6s ease, top .6s ease; left: 50%; top: 50%; }
    .demo-hl { outline: 3px solid #f4c14e !important; outline-offset: 4px; border-radius: 8px; }
  ` });
  await page.evaluate(() => {
    const c = document.createElement('div'); c.id = 'demo-cap'; c.style.opacity = 0;
    document.body.appendChild(c);
    const k = document.createElement('div'); k.id = 'demo-cursor'; document.body.appendChild(k);
  });

  const caption = async (label, text, ms = 0) => {
    await page.evaluate(([l, t]) => {
      const c = document.getElementById('demo-cap');
      c.innerHTML = (l ? `<small>${l}</small>` : '') + t;
      c.style.opacity = 1;
    }, [label, text]);
    if (ms) await pause(ms);
  };
  const card = async (html, ms) => {
    await page.evaluate((h) => {
      let d = document.getElementById('demo-card');
      if (!d) { d = document.createElement('div'); d.id = 'demo-card'; document.body.appendChild(d); }
      d.innerHTML = h; d.style.opacity = 1;
    }, html);
    await pause(ms);
    await page.evaluate(() => { document.getElementById('demo-card').style.opacity = 0; });
    await pause(700);
    await page.evaluate(() => document.getElementById('demo-card').remove());
  };
  const show = async (sel, ms = 900) => {
    await page.locator(sel).first().evaluate((e) => e.scrollIntoView({ behavior: 'smooth', block: 'center' }));
    await pause(ms);
  };
  const point = async (sel) => {
    const box = await page.locator(sel).first().boundingBox();
    await page.evaluate(([x, y]) => {
      const k = document.getElementById('demo-cursor'); k.style.left = x + 'px'; k.style.top = y + 'px';
    }, [box.x + box.width / 2, box.y + box.height / 2]);
    await pause(700);
  };
  const highlight = async (sel, ms = 1800) => {
    const el = page.locator(sel).first();
    await el.evaluate((e) => e.classList.add('demo-hl'));
    await pause(ms);
    await el.evaluate((e) => e.classList.remove('demo-hl'));
  };
  const click = async (sel) => {
    await show(sel, 700);
    await point(sel);
    await page.click(sel);
    await pause(500);
  };
  const waitFor = async (expr, timeoutMs) => {
    const end = Date.now() + timeoutMs;
    while (Date.now() < end) {
      const v = await page.evaluate(expr).catch(() => null);
      if (v) return v;
      await pause(2000);
    }
    throw new Error('timed out waiting for ' + expr);
  };
  const section = (title) => `section:has(h2:text-is("${title}"))`;

  // --- Title -------------------------------------------------------------
  await card(`<h1>tachi-flow</h1>
    <p>Leave a Tachi TAURUS vault in minutes, not a week.</p>
    <p style="color:#8b98a8;font-size:20px">Competing liquidity desks swap on-chain bitcoin ⇄ Tachi VTXOs · live on Tachi regtest</p>`, 4500);

  // --- Problem + market ----------------------------------------------------
  await caption('The problem', 'A unilateral TAURUS vault exit waits ~1008 blocks: about a week. tachi-flow desks hold both sides and swap you out now.', 4500);
  await show(section('Marketplace'), 1200);
  await caption('Marketplace', 'Two desks compete. Fees move with each desk\'s inventory; each posts a bond and carries a public fill/default score.');
  await highlight(section('Marketplace') + ' table', 4500);
  await show(section('Desk stats'), 1200);
  await caption('Desk stats', 'Live market numbers: volume, fees, batching savings, and average settle time vs the vault\'s week.', 4500);

  // --- Inbound swap ----------------------------------------------------------
  await show(section('Get a quote'), 1000);
  await caption('Swap in', 'Bitcoin → Tachi coins. Ask every desk for a firm quote (RFQ).');
  await page.selectOption('#side', 'in');
  await point('#amount');
  await page.fill('#amount', '12000');
  await pause(800);
  await click('#btnQuote');
  await waitFor('document.getElementById("quoteBox").innerText.includes("Signed")', 20000);
  await caption('Signed quotes', 'Each desk signs its quote (BIP340). The user can later prove exactly what the desk promised.');
  await highlight('#quoteBox', 5000);

  await click('#btnOpen');
  await waitFor('typeof swap !== "undefined" && swap && swap.id', 20000);
  await caption('Accept', 'Accepting opens an HTLC: the bitcoin is locked to the desk\'s hash, with a refund path back to you.', 4500);
  await click('#btnFund');
  await caption('Pay the lock', 'The faucet plays the user\'s wallet and pays the lock on L1…');
  await pause(2500);
  cutStart();
  await waitFor('typeof swap !== "undefined" && swap && swap.status === "claimed"', 15 * 60 * 1000);
  cutEnd();
  await show('#swapHint', 900);
  await caption('Claimed', 'The desk sent Tachi coins first, then claimed the bitcoin with the revealed preimage. Week-long exit: skipped.');
  await highlight(section('Swap'), 5000);
  await show(section('Recent swaps'), 1000);
  await pause(2500);

  // --- Split exit ----------------------------------------------------------
  await show(section('Get a quote'), 900);
  await caption('Big exits', 'Too big for one desk? Split it across desks, cheapest first.');
  await page.selectOption('#side', 'out');
  await page.fill('#amount', '60000');
  await pause(600);
  await show(section('Split a big exit across desks'), 900);
  await point('#maxLeg');
  await page.fill('#maxLeg', '35000');
  await click('#btnPlan');
  await waitFor('document.getElementById("planBox").innerText.includes("legs")', 20000);
  await caption('Split exit', 'One plan, several firm legs, each priced by the desk\'s inventory and settled as its own swap with its own HTLC.');
  await highlight('#planBox', 5000);

  // --- Vault refund advance ------------------------------------------------
  await show(section('Sell a maturing claim'), 1000);
  await caption('Claim advances', 'Waiting out a vault refund? Sell it. The desk pays now, at a discount, and collects when it matures.', 4500);
  // A real vault for this user's key, opened and refunded with Tachi's own
  // SDK (the user's wallet side; the desk only sees the resulting refund).
  await caption('A real vault', 'The user opens a real TAURUS vault on Tachi, then refunds it: the 5-of-7 validator quorum co-signs the refund (Tachi\'s own SDK).');
  const secret = await page.evaluate('keys.secret_hex');
  cutStart();
  const refund = JSON.parse(execFileSync('node', [VAULT_HELPER, secret, '2', '60000'], {
    cwd: path.dirname(VAULT_HELPER),
    stdio: ['ignore', 'pipe', 'inherit'],
    timeout: 60 * 60 * 1000,
  }).toString());
  cutEnd();
  await page.evaluate((r) => {
    csvLock = r;
    document.getElementById('advBox').innerHTML =
      `<p>Vault <code>${r.vault_id.slice(0, 16)}…</code> refunded <strong>${r.value_sats.toLocaleString()} sats</strong> to its to_local output (${r.txid.slice(0, 16)}…:0), locked for ${r.csv_blocks} blocks.</p>` +
      `<p class="hint">Refund co-signed by the validator quorum and confirmed on L1.</p>`;
  }, refund);
  await show('#advBox', 800);
  await highlight('#advBox', 4500);
  cutStart();
  let quoted = false;
  for (let i = 0; i < 60 && !quoted; i++) {
    await page.click('#btnAdvQuote');
    await pause(3000);
    quoted = await page.evaluate('typeof advance !== "undefined" && !!advance && advance.status === "quoted"');
    if (!quoted) {
      await page.evaluate(() => document.querySelectorAll('#advBox .warn').forEach((e) => e.remove()));
      await pause(10000);
    }
  }
  cutEnd();
  if (!quoted) throw new Error('advance never quoted');
  await show('#advBox', 800);
  await caption('Quote', 'The desk checks the refund itself: a vault registered on Tachi, and 5 of today\'s 7 validators\' signatures that verify. No watchtower receipt needed.');
  await highlight('#advBox', 6000);
  await click('#btnAdvAccept');
  await waitFor('typeof advance !== "undefined" && advance && advance.status === "advanced"', 30000);
  await caption('Paid now', 'The user\'s pre-signed spend checked out; the desk paid the advance on L1 immediately.');
  await highlight('#advBox', 5000);

  // Wait for maturity: the desk broadcasts the user's pre-signed spend.
  await caption('Maturity', 'Now the desk waits out the refund delay…', 2500);
  cutStart();
  await waitFor(`fetch("/v1/advances/" + advance.id).then(r => r.json()).then(a => {
      if (a.status !== "collected") return false;
      showAdvance(a);
      return true;
    })`, 30 * 60 * 1000);
  cutEnd();
  await show('#advBox', 800);
  await caption('Collected', 'At maturity the desk broadcast the user\'s pre-signed taproot spend and Bitcoin accepted it: the advance is repaid.');
  await highlight('#advBox', 6000);

  // --- Stats + close -------------------------------------------------------
  await show(section('Desk stats'), 1200);
  await caption('', 'Every swap, advance and default feeds the stats and each desk\'s score.', 4000);
  await card(`<h1>tachi-flow</h1>
    <ul>
      <li>Minutes instead of a ~1008-block vault exit</li>
      <li>Competing desks · RFQ · split exits · deadlines</li>
      <li>Signed quotes · L1 bonds with a CSV escape · reputation</li>
      <li>Advances on real TAURUS vault refunds</li>
      <li>Lightning · fee bumping · rebalancing · hosted desks · SQLite</li>
    </ul>
    <p style="color:#8b98a8;font-size:18px;margin-top:22px">Proof of concept on Tachi regtest · OP_Freedom bounty #10</p>`, 6000);

  await page.close();
  const video = await page.video().path();
  await ctx.close();
  await browser.close();
  fs.renameSync(video, path.join(OUT, 'raw.webm'));
  fs.writeFileSync(path.join(OUT, 'cuts.json'), JSON.stringify(cuts));
  console.log('done', JSON.stringify(cuts));
})().catch((e) => { console.error(e); process.exit(1); });
