use actix_web::{HttpResponse, get, post, web};
use serde::Serialize;
use uuid::Uuid;

use crate::engine::Engine;
use crate::error::Error;
use crate::htlc::generate_keypair;
use crate::tachi_tx::xonly_from_secret;
use crate::model::{CreateQuoteRequest, CreateSwapRequest, ObserveLockRequest, ObserveVtxoRequest};
use crate::tachi::Health;

#[derive(Serialize)]
struct Meta {
    service: &'static str,
    bounty: &'static str,
    network: String,
    tachi: String,
    tachi_lp_pubkey: String,
    lps: Vec<serde_json::Value>,
    height: u32,
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(ui)
        .service(meta)
        .service(health)
        .service(inventory)
        .service(create_quote)
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
        .service(sync_swap);
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
    })
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

#[post("/v1/quotes")]
async fn create_quote(
    engine: web::Data<Engine>,
    body: web::Json<CreateQuoteRequest>,
) -> Result<HttpResponse, Error> {
    let quote = engine.create_quote(body.into_inner()).await?;
    Ok(HttpResponse::Created().json(quote))
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
    engine: web::Data<Engine>,
    path: web::Path<Uuid>,
    body: web::Json<ObserveLockRequest>,
) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(engine.observe_lock(path.into_inner(), body.into_inner()).await?))
}

#[post("/v1/swaps/{id}/observe/vtxo")]
async fn observe_vtxo(
    engine: web::Data<Engine>,
    path: web::Path<Uuid>,
    body: web::Json<ObserveVtxoRequest>,
) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(engine.observe_vtxo(path.into_inner(), body.into_inner()).await?))
}

#[post("/v1/swaps/{id}/claim")]
async fn claim(engine: web::Data<Engine>, path: web::Path<Uuid>) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(engine.claim(path.into_inner()).await?))
}

#[post("/v1/swaps/{id}/refund")]
async fn refund(engine: web::Data<Engine>, path: web::Path<Uuid>) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(engine.refund(path.into_inner()).await?))
}

#[post("/v1/swaps/{id}/lp-default")]
async fn lp_default(
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
async fn demo_keys() -> HttpResponse {
    let kp = generate_keypair();
    HttpResponse::Ok().json(DemoKeys {
        secret_hex: hex::encode(kp.secret.secret_bytes()),
        pubkey_hex: kp.public.to_string(),
        tachi_xonly_hex: hex::encode(xonly_from_secret(&kp.secret)),
    })
}
