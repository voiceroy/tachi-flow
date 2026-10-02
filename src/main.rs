use std::env;
use std::path::Path;

use actix_web::{App, HttpServer, web};
use bitcoin::Network;
use tachi_flow::Engine;
use tachi_flow::api::{self, AdminToken};
use tachi_flow::tachi::TachiClient;
use tracing_actix_web::TracingLogger;

const ADMIN_TOKEN_FILE: &str = "tachi-flow-admin.token";

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
        Engine::simulated(tachi, network)
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
        .with_escrow(load_or_create_secret("tachi-escrow.secret", ""))
        .with_persist("tachi-flow-state.json")
        .unwrap_or_else(|err| panic!("{err}"))
    };

    // HTLC timeouts are absolute heights; never quote before we know the tip.
    engine.refresh_height().await;
    if !test_mode && engine.cached_height() == 0 {
        tracing::warn!("block height unknown; quotes fail until Tachi RPC answers");
    }

    let admin = AdminToken(load_or_create_admin_token());
    tracing::info!(
        %bind,
        network = %engine.network(),
        tachi = engine.tachi().base_url(),
        tachi_lp_pubkey = %engine.tachi_lp_pubkey_hex(),
        height = engine.cached_height(),
        "tachi-flow listening (operator routes need the admin token)"
    );

    if !test_mode {
        let books = engine.clone();
        tokio::spawn(async move {
            if let Err(err) = books.ensure_demo_liquidity().await {
                tracing::warn!(%err, "demo liquidity");
            }
        });
    }

    let ticker = engine.clone();
    tokio::spawn(async move {
        loop {
            ticker.refresh_height().await;
            ticker.refresh_live_inventory().await;
            if let Err(err) = ticker.sync_all().await {
                tracing::warn!(%err, "background sync");
            }
            tokio::time::sleep(std::time::Duration::from_secs(8)).await;
        }
    });

    // No CORS layer: the UI is same-origin, and other sites must not be able
    // to drive this desk from a visitor's browser.
    HttpServer::new(move || {
        App::new()
            .wrap(TracingLogger::default())
            .app_data(web::Data::new(engine.clone()))
            .app_data(web::Data::new(admin.clone()))
            .configure(api::configure)
    })
    .bind(&bind)?
    .run()
    .await
}

/// `ADMIN_TOKEN` env, else `tachi-flow-admin.token`, else a new random token
/// written there (mode 0600).
fn load_or_create_admin_token() -> String {
    if let Ok(token) = env::var("ADMIN_TOKEN")
        && !token.trim().is_empty()
    {
        return token.trim().to_string();
    }
    if let Ok(token) = std::fs::read_to_string(ADMIN_TOKEN_FILE)
        && !token.trim().is_empty()
    {
        return token.trim().to_string();
    }
    let token = hex::encode(tachi_flow::htlc::random_preimage());
    write_private(Path::new(ADMIN_TOKEN_FILE), &token).expect("write admin token");
    tracing::info!(file = ADMIN_TOKEN_FILE, "created admin token");
    token
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
    write_private(Path::new(path), &hex::encode(secret.secret_bytes())).expect("write lp secret");
    secret
}

fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(contents.as_bytes())
}
