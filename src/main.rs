use std::env;

use actix_cors::Cors;
use actix_web::{App, HttpServer, web};
use bitcoin::Network;
use tachi_flow::Engine;
use tachi_flow::api;
use tachi_flow::tachi::TachiClient;
use tracing_actix_web::TracingLogger;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tachi_flow=debug".into()),
        )
        .init();

    let bind = env::var("BIND").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let tachi_url =
        env::var("TACHI_BASE_URL").unwrap_or_else(|_| "https://rpc-regtest.tachibtc.com".into());
    let network = match env::var("BITCOIN_NETWORK").as_deref() {
        Ok("signet") => Network::Signet,
        Ok("bitcoin") | Ok("mainnet") => Network::Bitcoin,
        _ => Network::Regtest,
    };

    let tachi = TachiClient::new(tachi_url).expect("tachi client");
    let test_mode = matches!(
        env::var("TEST_MODE").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    );
    let engine = if test_mode {
        tracing::warn!("TEST_MODE: simulated lp-alpha / lp-bravo, no live Tachi books");
        tachi_flow::Engine::simulated(tachi, network)
    } else {
        let alpha = load_or_create_secret("tachi-lp-alpha.secret", "tachi-lp.secret");
        let bravo = load_or_create_secret("tachi-lp-bravo.secret", "");
        Engine::live(
            tachi,
            network,
            vec![
                ("lp-alpha".into(), alpha, 8_000),
                ("lp-bravo".into(), bravo, 10_000),
            ],
        )
    };

    tracing::info!(
        %bind,
        network = %engine.network(),
        tachi = engine.tachi().base_url(),
        tachi_lp_pubkey = %engine.tachi_lp_pubkey_hex(),
        "tachi-flow listening"
    );

    let ticker = engine.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(8)).await;
            ticker.refresh_height().await;
            let _ = ticker.refresh_live_inventory().await;
            if let Err(err) = ticker.sync_all().await {
                tracing::warn!(%err, "background sync");
            }
        }
    });

    HttpServer::new(move || {
        App::new()
            .wrap(TracingLogger::default())
            .wrap(Cors::permissive())
            .app_data(web::Data::new(engine.clone()))
            .configure(api::configure)
    })
    .bind(&bind)?
    .run()
    .await
}

fn load_or_create_secret(path: &str, migrate_from: &str) -> bitcoin::secp256k1::SecretKey {
    let read = std::fs::read_to_string(path).ok().or_else(|| {
        if migrate_from.is_empty() {
            None
        } else {
            std::fs::read_to_string(migrate_from).ok()
        }
    });
    if let Some(hex_sk) = read {
        let bytes = hex::decode(hex_sk.trim()).expect("lp secret hex");
        return bitcoin::secp256k1::SecretKey::from_slice(&bytes).expect("32-byte secp256k1 key");
    }
    let secret = tachi_flow::htlc::generate_keypair().secret;
    let _ = std::fs::write(path, hex::encode(secret.secret_bytes()));
    secret
}
