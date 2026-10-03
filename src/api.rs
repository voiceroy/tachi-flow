use std::future::{Ready, ready};

use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpRequest, HttpResponse, get, post, web};
use serde::Serialize;
use uuid::Uuid;

use crate::engine::{
    DEADLINE_PRESETS, Engine, HTLC_TIMEOUT_BLOCKS, PricingConfig, VAULT_EXIT_BLOCKS, parse_secret,
};
use crate::error::Error;
use crate::htlc::{generate_keypair, p2wpkh_address};
use crate::model::{
    AdvanceAcceptRequest, AdvanceQuoteRequest, CreatePlanRequest, CreateQuoteRequest,
    CreateSwapRequest, LnQuoteRequest, ObserveLockRequest, ObserveVtxoRequest, Side,
    WebhookRequest,
};
use crate::tachi::Health;
use crate::tachi_tx::xonly_from_secret;

/// Token for desk-operator routes (moving desk funds, overriding swap state).
#[derive(Clone)]
pub struct AdminToken(pub String);

/// Extractor that only succeeds with `x-admin-token: <token>` or
/// `Authorization: Bearer <token>`.
pub struct Admin;

impl FromRequest for Admin {
    type Error = Error;
    type Future = Ready<Result<Self, Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        ready(if is_admin(req) { Ok(Admin) } else { Err(Error::Unauthorized) })
    }
}

fn is_admin(req: &HttpRequest) -> bool {
    let header = |name| req.headers().get(name).and_then(|v| v.to_str().ok());
    let given = header("x-admin-token")
        .or_else(|| header("authorization").and_then(|v| v.strip_prefix("Bearer ")));
    req.app_data::<web::Data<AdminToken>>()
        .zip(given)
        .is_some_and(|(want, got)| constant_time_eq(want.0.as_bytes(), got.trim().as_bytes()))
}

/// Who a quote request counts against for the anti-griefing caps: the peer
/// IP. Operator requests (admin token) are not capped.
fn quote_client(req: &HttpRequest) -> Option<String> {
    if is_admin(req) {
        return None;
    }
    Some(
        req.peer_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| "unknown".into()),
    )
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Serialize)]
struct Meta {
    service: &'static str,
    bounty: &'static str,
    network: String,
    tachi: String,
    tachi_lp_pubkey: String,
    lps: Vec<serde_json::Value>,
    height: u32,
    vault_exit_blocks: u32,
    swap_timeout_blocks: u32,
    pricing: PricingConfig,
    deadline_presets: [u32; 6],
    /// Tachi key holding desk bonds (custodial escrow).
    escrow_pubkey: String,
    /// Fee rate the desks use for their own L1 txs.
    fee_rate_sat_vb: f64,
    lightning: bool,
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(ui)
        .service(meta)
        .service(health)
        .service(inventory)
        .service(stats)
        .service(create_quote)
        .service(rfq)
        .service(price_curve)
        .service(open_swap)
        .service(list_swaps)
        .service(get_swap)
        .service(observe_lock)
        .service(observe_vtxo)
        .service(claim)
        .service(refund)
        .service(lp_default)
        .service(demo_keys)
        .service(send_vtxo)
        .service(deposit_vtxo)
        .service(tachi_wallet)
        .service(sync_all)
        .service(sync_swap)
        .service(fund_inbound)
        .service(pay_outbound)
        .service(plan_exit)
        .service(get_plan)
        .service(accept_plan)
        .service(post_bond)
        .service(events)
        .service(add_webhook)
        .service(quote_advance)
        .service(list_advances)
        .service(get_advance)
        .service(accept_advance)
        .service(demo_presign_advance)
        .service(demo_csv_lock)
        .service(ln_quote)
        .service(list_ln_swaps)
        .service(get_ln_swap)
        .service(ln_paid)
        .service(ln_pay_vtxo);
}

#[get("/")]
async fn ui() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../static/index.html"))
}

#[get("/v1/meta")]
async fn meta(engine: web::Data<Engine>) -> HttpResponse {
    HttpResponse::Ok().json(Meta {
        service: "tachi-flow",
        bounty: "#10 Liquidity Management",
        network: engine.network().to_string(),
        tachi: engine.tachi().base_url().to_string(),
        tachi_lp_pubkey: engine.tachi_lp_pubkey_hex(),
        lps: engine.marketplace(),
        height: engine.cached_height(),
        vault_exit_blocks: VAULT_EXIT_BLOCKS,
        swap_timeout_blocks: HTLC_TIMEOUT_BLOCKS,
        pricing: engine.pricing(),
        deadline_presets: DEADLINE_PRESETS,
        escrow_pubkey: engine.escrow_pubkey_hex(),
        fee_rate_sat_vb: engine.fee_rate_msat_vb() as f64 / 1_000.0,
        lightning: engine.lightning_enabled(),
    })
}

/// Split one amount across desks (#5). Legs are firm quotes; accept opens all.
#[post("/v1/exits")]
async fn plan_exit(
    req: HttpRequest,
    engine: web::Data<Engine>,
    body: web::Json<CreatePlanRequest>,
) -> Result<HttpResponse, Error> {
    let plan = match quote_client(&req) {
        Some(client) => engine.plan_exit_for(&client, body.into_inner()).await?,
        None => engine.plan_exit(body.into_inner()).await?,
    };
    Ok(HttpResponse::Created().json(plan))
}

#[get("/v1/exits/{id}")]
async fn get_plan(engine: web::Data<Engine>, path: web::Path<Uuid>) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(engine.get_plan(path.into_inner()).await?))
}

#[post("/v1/exits/{id}/accept")]
async fn accept_plan(
    engine: web::Data<Engine>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(engine.accept_plan(path.into_inner()).await?))
}

#[derive(serde::Deserialize)]
struct BondBody {
    amount_sats: u64,
}

/// Desk posts VTXOs to the bond escrow (#6). Operator route.
#[post("/v1/lps/{id}/bond")]
async fn post_bond(
    _admin: Admin,
    engine: web::Data<Engine>,
    path: web::Path<String>,
    body: web::Json<BondBody>,
) -> Result<HttpResponse, Error> {
    let total = engine.post_bond(&path, body.amount_sats).await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "lp_id": *path, "bond_sats": total })))
}

#[derive(serde::Deserialize)]
struct EventsQuery {
    swap_id: Option<Uuid>,
}

/// Server-sent events (#7): every swap / advance / Lightning-swap change.
#[get("/v1/events")]
async fn events(engine: web::Data<Engine>, q: web::Query<EventsQuery>) -> HttpResponse {
    use tokio::sync::broadcast::error::RecvError;
    let filter = q.swap_id;
    let stream = futures_util::stream::unfold(engine.subscribe(), move |mut rx| async move {
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(15), rx.recv()).await {
                Ok(Ok(ev)) if filter.is_none_or(|id| id == ev.id()) => {
                    let frame = web::Bytes::from(ev.sse_frame());
                    return Some((Ok::<_, actix_web::Error>(frame), rx));
                }
                Ok(Ok(_)) | Ok(Err(RecvError::Lagged(_))) => continue,
                Ok(Err(RecvError::Closed)) => return None,
                // Keep proxies from closing an idle stream.
                Err(_) => return Some((Ok(web::Bytes::from_static(b": keepalive\n\n")), rx)),
            }
        }
    });
    HttpResponse::Ok()
        .content_type("text/event-stream")
        .insert_header(("cache-control", "no-cache"))
        .streaming(stream)
}

/// Register a URL to POST every event to. Operator route: the server makes
/// outbound requests to whatever is registered.
#[post("/v1/webhooks")]
async fn add_webhook(
    _admin: Admin,
    engine: web::Data<Engine>,
    body: web::Json<WebhookRequest>,
) -> Result<HttpResponse, Error> {
    let n = engine.add_webhook(body.into_inner()).await?;
    Ok(HttpResponse::Created().json(serde_json::json!({ "webhooks": n })))
}

/// Price an advance on a maturing CSV output (#8).
#[post("/v1/advances/quote")]
async fn quote_advance(
    engine: web::Data<Engine>,
    body: web::Json<AdvanceQuoteRequest>,
) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Created().json(engine.quote_advance(body.into_inner()).await?))
}

#[get("/v1/advances")]
async fn list_advances(engine: web::Data<Engine>) -> HttpResponse {
    HttpResponse::Ok().json(engine.list_advances().await)
}

#[get("/v1/advances/{id}")]
async fn get_advance(engine: web::Data<Engine>, path: web::Path<Uuid>) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(engine.get_advance(path.into_inner()).await?))
}

/// Hand over the pre-signed spend; the desk verifies it and pays the advance.
#[post("/v1/advances/{id}/accept")]
async fn accept_advance(
    engine: web::Data<Engine>,
    path: web::Path<Uuid>,
    body: web::Json<AdvanceAcceptRequest>,
) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(engine.accept_advance(path.into_inner(), body.into_inner()).await?))
}

/// Demo: sign the advance's spend with the demo key (a wallet does this).
#[post("/v1/advances/{id}/demo-presign")]
async fn demo_presign_advance(
    engine: web::Data<Engine>,
    path: web::Path<Uuid>,
    body: web::Json<SecretBody>,
) -> Result<HttpResponse, Error> {
    let hex = engine
        .demo_presign_advance(path.into_inner(), &body.secret_hex)
        .await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "presigned_tx_hex": hex })))
}

#[derive(serde::Deserialize)]
struct CsvLockBody {
    pubkey_hex: String,
    csv_blocks: u32,
    amount_sats: u64,
}

/// Demo: faucet coins into a CSV-locked output (a stand-in for a vault refund
/// still waiting out its delay).
#[post("/v1/demo/csv-lock")]
async fn demo_csv_lock(
    engine: web::Data<Engine>,
    body: web::Json<CsvLockBody>,
) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(
        engine
            .demo_csv_lock(&body.pubkey_hex, body.csv_blocks, body.amount_sats)
            .await?,
    ))
}

/// VTXO ↔ Lightning (#9). `in`: returns a hold invoice. `out`: takes yours.
#[post("/v1/ln/quotes")]
async fn ln_quote(
    engine: web::Data<Engine>,
    body: web::Json<LnQuoteRequest>,
) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Created().json(engine.ln_quote(body.into_inner()).await?))
}

#[get("/v1/ln/swaps")]
async fn list_ln_swaps(engine: web::Data<Engine>) -> HttpResponse {
    HttpResponse::Ok().json(engine.list_ln_swaps().await)
}

#[get("/v1/ln/swaps/{id}")]
async fn get_ln_swap(engine: web::Data<Engine>, path: web::Path<Uuid>) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(engine.get_ln_swap(path.into_inner()).await?))
}

/// `out`: report the VTXO you paid the desk with.
#[post("/v1/ln/swaps/{id}/paid")]
async fn ln_paid(
    engine: web::Data<Engine>,
    path: web::Path<Uuid>,
    body: web::Json<ObserveVtxoRequest>,
) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(engine.ln_paid(path.into_inner(), &body.vtxo_id).await?))
}

/// `out` demo helper: pay from the demo key, then credit the payment.
#[post("/v1/ln/swaps/{id}/pay-vtxo")]
async fn ln_pay_vtxo(
    engine: web::Data<Engine>,
    path: web::Path<Uuid>,
    body: web::Json<SecretBody>,
) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(
        engine
            .ln_pay_from_demo(path.into_inner(), &body.secret_hex)
            .await?,
    ))
}

#[get("/v1/swaps")]
async fn list_swaps(engine: web::Data<Engine>) -> HttpResponse {
    HttpResponse::Ok().json(engine.list_swaps().await)
}

#[get("/health")]
async fn health(engine: web::Data<Engine>) -> HttpResponse {
    let tachi: Health = engine.tachi().health().await;
    let status = if tachi.ok {
        actix_web::http::StatusCode::OK
    } else {
        actix_web::http::StatusCode::SERVICE_UNAVAILABLE
    };
    HttpResponse::build(status).json(serde_json::json!({
        "service": "ok",
        "tachi": tachi,
    }))
}

#[get("/v1/inventory")]
async fn inventory(engine: web::Data<Engine>) -> HttpResponse {
    HttpResponse::Ok().json(engine.inventory().await)
}

/// Volume, fees, batching savings, per-desk track record, time saved.
#[get("/v1/stats")]
async fn stats(engine: web::Data<Engine>) -> HttpResponse {
    HttpResponse::Ok().json(engine.stats().await)
}

#[post("/v1/quotes")]
async fn create_quote(
    req: HttpRequest,
    engine: web::Data<Engine>,
    body: web::Json<CreateQuoteRequest>,
) -> Result<HttpResponse, Error> {
    let quote = match quote_client(&req) {
        Some(client) => engine.create_quote_for(&client, body.into_inner()).await?,
        None => engine.create_quote(body.into_inner()).await?,
    };
    Ok(HttpResponse::Created().json(quote))
}

/// Firm quotes from every desk that can fill, cheapest first. Accepting one
/// (POST /v1/swaps) releases the others.
#[post("/v1/rfq")]
async fn rfq(
    req: HttpRequest,
    engine: web::Data<Engine>,
    body: web::Json<CreateQuoteRequest>,
) -> Result<HttpResponse, Error> {
    let quotes = match quote_client(&req) {
        Some(client) => engine.request_quotes_for(&client, body.into_inner()).await?,
        None => engine.request_quotes(body.into_inner()).await?,
    };
    Ok(HttpResponse::Created().json(quotes))
}

#[derive(serde::Deserialize)]
struct CurveQuery {
    side: Side,
    amount_sats: u64,
}

/// Fee by deadline per desk at current books. Reserves nothing.
#[get("/v1/price-curve")]
async fn price_curve(engine: web::Data<Engine>, q: web::Query<CurveQuery>) -> HttpResponse {
    HttpResponse::Ok().json(engine.price_curve(q.side, q.amount_sats).await)
}

#[post("/v1/swaps")]
async fn open_swap(
    engine: web::Data<Engine>,
    body: web::Json<CreateSwapRequest>,
) -> Result<HttpResponse, Error> {
    let swap = engine.open_swap(body.quote_id).await?;
    Ok(HttpResponse::Created().json(swap))
}

#[get("/v1/swaps/{id}")]
async fn get_swap(
    engine: web::Data<Engine>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(engine.get_swap(path.into_inner()).await?))
}

#[post("/v1/swaps/{id}/observe/lock")]
async fn observe_lock(
    _admin: Admin,
    engine: web::Data<Engine>,
    path: web::Path<Uuid>,
    body: web::Json<ObserveLockRequest>,
) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(engine.observe_lock(path.into_inner(), body.into_inner()).await?))
}

#[post("/v1/swaps/{id}/observe/vtxo")]
async fn observe_vtxo(
    _admin: Admin,
    engine: web::Data<Engine>,
    path: web::Path<Uuid>,
    body: web::Json<ObserveVtxoRequest>,
) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(engine.observe_vtxo(path.into_inner(), body.into_inner()).await?))
}

#[post("/v1/swaps/{id}/claim")]
async fn claim(
    _admin: Admin,
    engine: web::Data<Engine>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(engine.claim(path.into_inner()).await?))
}

#[derive(serde::Deserialize)]
struct SecretBody {
    secret_hex: String,
}

/// Cancel before funding, or refund your lock on-chain after its timeout.
/// `secret_hex` proves the swap is yours and signs the refund.
#[post("/v1/swaps/{id}/refund")]
async fn refund(
    engine: web::Data<Engine>,
    path: web::Path<Uuid>,
    body: Option<web::Json<SecretBody>>,
) -> Result<HttpResponse, Error> {
    let secret = body.map(|b| parse_secret(&b.secret_hex)).transpose()?;
    Ok(HttpResponse::Ok().json(engine.refund(path.into_inner(), secret).await?))
}

#[post("/v1/swaps/{id}/lp-default")]
async fn lp_default(
    _admin: Admin,
    engine: web::Data<Engine>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(engine.mark_lp_default(path.into_inner()).await?))
}

#[derive(Serialize)]
struct DemoKeys {
    secret_hex: String,
    pubkey_hex: String,
    /// Tachi VTXO owner: 32-byte x-only (64 hex). Use this as `dest` / `user_tachi_address`.
    tachi_xonly_hex: String,
    /// P2WPKH on the configured network — faucet and outbound payouts.
    l1_address: String,
}

#[derive(serde::Deserialize)]
struct SendVtxoBody {
    dest: String,
    amount_sats: u64,
    lp_id: Option<String>,
}

#[get("/v1/tachi/wallet")]
async fn tachi_wallet(engine: web::Data<Engine>) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(engine.tachi_wallet().await?))
}

/// Scan Bitcoin + Tachi for quoted swaps and settle any that have been paid.
#[post("/v1/sync")]
async fn sync_all(engine: web::Data<Engine>) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(engine.sync_all().await?))
}

#[post("/v1/swaps/{id}/sync")]
async fn sync_swap(
    engine: web::Data<Engine>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, Error> {
    match engine.sync_swap(path.into_inner()).await? {
        Some(swap) => Ok(HttpResponse::Ok().json(swap)),
        None => Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "waiting",
            "hint": "pay the quote address, then sync again"
        }))),
    }
}

#[derive(serde::Deserialize)]
struct DepositVtxoBody {
    amount_sats: u64,
    lp_id: Option<String>,
}

/// Register a Tachi DEPOSIT for the LP identity (still needs L1 vault funding).
#[post("/v1/vtxo/deposit")]
async fn deposit_vtxo(
    _admin: Admin,
    engine: web::Data<Engine>,
    body: web::Json<DepositVtxoBody>,
) -> Result<HttpResponse, Error> {
    let paid = engine
        .deposit_vtxo(body.amount_sats, body.lp_id.as_deref())
        .await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "tachi_tx_hash": paid.tendermint_hash,
        "vtxo_id": paid.output_vtxo_id,
        "hex": paid.hex,
    })))
}

/// Broadcast a Tachi VTXO transfer from the LP wallet.
#[post("/v1/vtxo/send")]
async fn send_vtxo(
    _admin: Admin,
    engine: web::Data<Engine>,
    body: web::Json<SendVtxoBody>,
) -> Result<HttpResponse, Error> {
    let paid = if let Some(lp) = body.lp_id.as_deref() {
        engine
            .send_vtxo_from(lp, &body.dest, body.amount_sats)
            .await?
    } else {
        engine.send_vtxo(&body.dest, body.amount_sats).await?
    };
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "tachi_tx_hash": paid.tendermint_hash,
        "vtxo_id": paid.output_vtxo_id,
        "hex": paid.hex,
    })))
}

#[post("/v1/demo/keys")]
async fn demo_keys(engine: web::Data<Engine>) -> HttpResponse {
    let kp = generate_keypair();
    HttpResponse::Ok().json(DemoKeys {
        secret_hex: hex::encode(kp.secret.secret_bytes()),
        pubkey_hex: kp.public.to_string(),
        tachi_xonly_hex: hex::encode(xonly_from_secret(&kp.secret)),
        l1_address: p2wpkh_address(&kp.secret, engine.network()).to_string(),
    })
}

/// Faucet a P2WPKH and forward into the inbound lock (hosted faucet refuses P2WSH).
#[post("/v1/swaps/{id}/fund")]
async fn fund_inbound(
    engine: web::Data<Engine>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(engine.fund_inbound(path.into_inner()).await?))
}

/// Sign a VTXO payment from the user's demo secret to the outbound desk key,
/// then claim the desk's lock. Safe to call again: it never pays twice.
#[post("/v1/swaps/{id}/pay-vtxo")]
async fn pay_outbound(
    engine: web::Data<Engine>,
    path: web::Path<Uuid>,
    body: web::Json<SecretBody>,
) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(
        engine
            .user_pay_outbound(path.into_inner(), &body.secret_hex)
            .await?,
    ))
}

#[cfg(test)]
mod tests {
    use actix_web::{App, test};
    use bitcoin::Network;

    use super::*;
    use crate::tachi::TachiClient;

    fn app_engine() -> Engine {
        Engine::simulated(
            TachiClient::new("http://127.0.0.1:9").expect("client"),
            Network::Regtest,
        )
    }

    #[actix_web::test]
    async fn operator_routes_need_the_admin_token() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(app_engine()))
                .app_data(web::Data::new(AdminToken("s3cret".into())))
                .configure(configure),
        )
        .await;
        let body = serde_json::json!({ "dest": "00", "amount_sats": 10_000 });

        let req = test::TestRequest::post()
            .uri("/v1/vtxo/send")
            .set_json(&body)
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 401);

        let req = test::TestRequest::post()
            .uri("/v1/vtxo/send")
            .insert_header(("x-admin-token", "wrong"))
            .set_json(&body)
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 401);

        // Right token gets past auth (and then fails on the bogus dest).
        let req = test::TestRequest::post()
            .uri("/v1/vtxo/send")
            .insert_header(("authorization", "Bearer s3cret"))
            .set_json(&body)
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 400);

        let req = test::TestRequest::get().uri("/v1/meta").to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 200);
    }

    #[actix_web::test]
    async fn rfq_and_price_curve_routes() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(app_engine()))
                .configure(configure),
        )
        .await;
        let user = generate_keypair();
        let req = test::TestRequest::post()
            .uri("/v1/rfq")
            .set_json(serde_json::json!({
                "side": "out",
                "amount_sats": 10_000,
                "user_l1_address": "bcrt1qtest",
                "user_refund_pubkey_hex": user.public.to_string(),
                "deadline_blocks": 144,
            }))
            .to_request();
        let quotes: Vec<serde_json::Value> = test::call_and_read_body_json(&app, req).await;
        assert_eq!(quotes.len(), 2, "both desks quote");
        assert!(quotes[0]["fee_sats"].as_u64() <= quotes[1]["fee_sats"].as_u64());
        assert_eq!(quotes[0]["rfq_id"], quotes[1]["rfq_id"]);

        let req = test::TestRequest::get()
            .uri("/v1/price-curve?side=out&amount_sats=100000")
            .to_request();
        let curve: Vec<serde_json::Value> = test::call_and_read_body_json(&app, req).await;
        let points = curve[0]["points"].as_array().unwrap();
        assert_eq!(points.len(), DEADLINE_PRESETS.len());
        let first = points[0]["fee_ppm"].as_u64().unwrap();
        let last = points[points.len() - 1]["fee_ppm"].as_u64().unwrap();
        assert!(last < first, "waiting a vault exit must be cheaper: {first} -> {last}");
    }
}
