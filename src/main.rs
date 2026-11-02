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

    // BIND wins; on a host that assigns PORT (Railway, Fly…) listen on all
    // interfaces at that port; otherwise local only.
    let bind = env::var("BIND").unwrap_or_else(|_| match env::var("PORT") {
        Ok(port) => format!("0.0.0.0:{port}"),
        Err(_) => "127.0.0.1:8080".into(),
    });
    // The primary network (`--network signet` wins over BITCOIN_NETWORK) also
    // answers at `/v1/…`; every network in NETWORKS gets its own engine, state
    // file and Tachi RPC at `/{network}/v1/…`, so swaps on two chains never mix.
    let primary = network_arg()
        .or_else(|| env::var("BITCOIN_NETWORK").ok())
        .unwrap_or_else(|| "regtest".into());
    let mut names = vec![primary.clone()];
    for name in env::var("NETWORKS")
        .unwrap_or_else(|_| "regtest,signet".into())
        .split(',')
        .map(str::trim)
        .filter(|n| !n.is_empty())
    {
        if !names.iter().any(|n| n == name) {
            names.push(name.to_string());
        }
    }

    let test_mode = matches!(
        env::var("TEST_MODE").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    );
    if test_mode {
        tracing::warn!("TEST_MODE: simulated lp-alpha / lp-bravo, no live Tachi books");
    }
    let unreceipted = matches!(
        env::var("VAULT_ADVANCE_UNRECEIPTED").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    );
    if unreceipted {
        tracing::warn!("advancing on vault refunds without a watchtower receipt (extra discount)");
    }

    let mut engines = Vec::new();
    for name in &names {
        let engine = build_engine(name, name == &primary, test_mode)
            .with_unreceipted_vault_advances(unreceipted);
        // HTLC timeouts are absolute heights; never quote before we know the tip.
        engine.refresh_height().await;
        if !test_mode && engine.cached_height() == 0 {
            tracing::warn!(network = %name, "block height unknown; quotes fail until Tachi RPC answers");
        }
        spawn_background(engine.clone(), test_mode);
        engines.push((name.clone(), engine));
    }

    // Behind a reverse proxy the peer address is the proxy's; count the caps
    // against the IP it forwards instead. Only set this where a proxy that
    // appends to X-Forwarded-For fronts every request.
    let trust_proxy = matches!(
        env::var("TRUST_PROXY").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    );
    if trust_proxy {
        tracing::info!("TRUST_PROXY: per-client caps use the last X-Forwarded-For entry");
    }

    let admin = AdminToken(load_or_create_admin_token());
    for (name, engine) in &engines {
        tracing::info!(
            %bind,
            network = %name,
            primary = name == &primary,
            tachi = engine.tachi().base_url(),
            tachi_lp_pubkey = %engine.tachi_lp_pubkey_hex(),
            height = engine.cached_height(),
            "tachi-flow listening (operator routes need the admin token)"
        );
    }
    let networks = api::Networks {
        primary: primary.clone(),
        all: names,
    };

    // No CORS layer: the UI is same-origin, and other sites must not be able
    // to drive this desk from a visitor's browser.
    HttpServer::new(move || {
        let mut app = App::new()
            .wrap(TracingLogger::default())
            .app_data(web::Data::new(admin.clone()))
            .app_data(web::Data::new(networks.clone()));
        if trust_proxy {
            app = app.app_data(web::Data::new(api::TrustProxy));
        }
        for (name, engine) in &engines {
            app = app.service(
                web::scope(&format!("/{name}"))
                    .app_data(web::Data::new(engine.clone()))
                    .configure(api::configure),
            );
        }
        let primary = &engines[0].1;
        app.app_data(web::Data::new(primary.clone()))
            .configure(api::configure)
    })
    .bind(&bind)?
    .run()
    .await
}

/// One network's engine: its Tachi RPC, its own state file, the shared desk
/// keys. Lightning and the TACHI_BASE_URL / STATE_PATH overrides apply to the
/// primary network only.
fn build_engine(name: &str, primary: bool, test_mode: bool) -> Engine {
    let (network, default_tachi, default_state) = match name {
        "regtest" => (Network::Regtest, "https://rpc-regtest.tachibtc.com", "tachi-flow-state.db"),
        "signet" => (Network::Signet, "https://rpc-signet.tachibtc.com", "tachi-flow-state-signet.db"),
        "bitcoin" | "mainnet" => (Network::Bitcoin, "", "tachi-flow-state-mainnet.db"),
        other => panic!("unknown network {other:?}: use regtest or signet"),
    };
    let override_var = |var: &str| if primary { env::var(var).ok() } else { None };
    let tachi_url = override_var("TACHI_BASE_URL").unwrap_or_else(|| {
        assert!(!default_tachi.is_empty(), "set TACHI_BASE_URL for {name}");
        default_tachi.into()
    });
    let tachi = TachiClient::new(tachi_url).expect("tachi client");
    let engine = if test_mode {
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
        .with_persist_migrating(
            override_var("STATE_PATH").unwrap_or_else(|| default_state.into()),
            // The legacy JSON store only ever held regtest swaps.
            (network == Network::Regtest).then_some("tachi-flow-state.json"),
        )
        .unwrap_or_else(|err| panic!("{err}"))
    };
    if !primary {
        return engine;
    }
    let lightning = tachi_flow::lightning::LightningNode::from_env()
        .unwrap_or_else(|err| panic!("lightning config: {err}"));
    if lightning.is_some() {
        tracing::info!(network = %name, "Lightning enabled (LND REST)");
    }
    engine.with_lightning(lightning)
}

fn spawn_background(engine: Engine, test_mode: bool) {
    if !test_mode {
        let books = engine.clone();
        tokio::spawn(async move {
            if let Err(err) = books.ensure_demo_liquidity().await {
                tracing::warn!(network = %books.network(), %err, "demo liquidity");
            }
        });
        // Push stream: settle the moment Tachi credits a desk, not on the next tick.
        tokio::spawn(tachi_flow::watch::run(engine.clone()));
    }

    tokio::spawn(async move {
        loop {
            engine.refresh_height().await;
            engine.refresh_live_inventory().await;
            if let Err(err) = engine.sync_all().await {
                tracing::warn!(network = %engine.network(), %err, "background sync");
            }
            tokio::time::sleep(std::time::Duration::from_secs(8)).await;
        }
    });
}

/// `--network <name>` or `--network=<name>` from the command line.
fn network_arg() -> Option<String> {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--network" {
            return args.next();
        }
        if let Some(name) = arg.strip_prefix("--network=") {
            return Some(name.to_string());
        }
    }
    None
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
