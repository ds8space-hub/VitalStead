//! Manual end-to-end verification harness for T-401 (WHOOP connector).
//!
//! NOT part of `cargo test` / CI — this is a one-off tool run by a human against a
//! real WHOOP developer app and a real WHOOP account, per the T-401 spec's "Manual
//! Verification" section. It exists to catch places where the ASSUMPTION-marked
//! DTO fields (src/core/connectors/whoop/dto.rs) diverge from the real WHOOP API v2
//! response shape.
//!
//! Usage:
//!   set -a && source .env && set +a
//!   VITALSTEAD_OAUTH_FIXED_PORT=53682 cargo run --example whoop_manual_connect
//!
//! Required in .env: WHOOP_CLIENT_ID, WHOOP_CLIENT_SECRET
//! (WHOOP dashboard redirect URL must be exactly http://127.0.0.1:53682/callback)
//!
//! Security (D-015): this binary never prints WHOOP_CLIENT_SECRET, access_token,
//! or refresh_token to stdout/stderr — only status codes, record counts, and CSV
//! file paths. Tokens are stored in the real macOS Keychain via CredentialVault,
//! same as production would.

use vitalstead_mcp::core::connectors::rate_limiter::PacedThrottle;
use vitalstead_mcp::core::connectors::whoop::client::WhoopApiClient;
use vitalstead_mcp::core::connectors::whoop::connect::WhoopConnectSession;
use vitalstead_mcp::core::connectors::whoop::sync::{WhoopSyncRequest, WhoopSyncSession, RealClock};
use vitalstead_mcp::core::csv::CsvWriter;
use vitalstead_mcp::core::oauth::{RealSleeper, RefreshCoordinator};
use vitalstead_mcp::core::security::SecretString;
use vitalstead_mcp::adapters::MacAtomicFileWriter;
use vitalstead_mcp::{build_credential_vault, build_oauth_callback_handler, build_token_exchange_client};

fn main() {
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();

    // The real macOS OAuthCallbackHandler::listen_for_callback (T-301) does
    // `tokio::spawn` internally and needs an ambient tokio runtime already
    // active on this thread. `.enter()` (not `.block_on()`) makes the ambient
    // Handle available for that spawn without this thread itself being "inside"
    // a block_on call — the runtime's own worker threads (multi-thread flavor)
    // drive the spawned listener task in the background regardless.
    let _rt = tokio::runtime::Runtime::new().expect("tokio runtime creation");
    let _guard = _rt.enter();

    let client_id = std::env::var("WHOOP_CLIENT_ID")
        .expect("WHOOP_CLIENT_ID must be set (source .env first)");
    let client_secret = std::env::var("WHOOP_CLIENT_SECRET")
        .expect("WHOOP_CLIENT_SECRET must be set (source .env first)");
    // Note: VITALSTEAD_OAUTH_FIXED_PORT is still read by MacOSOAuthCallbackHandler::listen_for_callback
    // internally. If set, it overrides the OS-assigned port, so the dynamic port selection
    // in start_and_bind will still use this fixed port (for dev purposes).
    let _ = std::env::var("VITALSTEAD_OAUTH_FIXED_PORT")
        .expect("VITALSTEAD_OAUTH_FIXED_PORT must be set (must match WHOOP dashboard redirect URL, e.g. 53682)");

    let connection_id = "whoop_manual_e2e".to_string();
    let service = "vitalstead.dev.whoop.manual_e2e".to_string();

    let vault = build_credential_vault();
    let callback_handler: std::sync::Arc<dyn vitalstead_mcp::adapters::OAuthCallbackHandler> =
        std::sync::Arc::from(build_oauth_callback_handler());
    let token_client = build_token_exchange_client();

    // WHOOP_SKIP_OAUTH=1: reuse tokens already stored in Keychain from a prior
    // successful run instead of doing a fresh browser login every time. If the
    // access_token happens to be expired, expires_at is deliberately set to
    // "now" so the sync's own refresh-before-fetch check (AC#4) fires
    // immediately and refreshes using the already-stored refresh_token — this
    // exercises the real refresh path too, not just a shortcut.
    let skip_oauth = std::env::var("WHOOP_SKIP_OAUTH").as_deref() == Ok("1");

    let expires_at = if skip_oauth {
        match vault.retrieve(&service, "access_token") {
            Ok(_) => {
                println!("=== Step 1: OAuth authorization (SKIPPED — WHOOP_SKIP_OAUTH=1) ===");
                println!("Reusing tokens from Keychain; sync will refresh if needed.");
                std::time::SystemTime::now()
            }
            Err(_) => {
                eprintln!("❌ WHOOP_SKIP_OAUTH=1 but no access_token found in Keychain for this service.");
                eprintln!("Run once WITHOUT WHOOP_SKIP_OAUTH first to establish a connection.");
                std::process::exit(1);
            }
        }
    } else {
        println!("=== Step 1: OAuth authorization ===");
        println!("A browser window will open. Log in to WHOOP and approve ALL requested permissions.");
        println!("(Waiting up to 5 minutes for the callback...)");

        let flow = vitalstead_mcp::core::oauth::AuthorizationFlow::new(callback_handler.clone());
        let connect_session = WhoopConnectSession::new(&flow, token_client.as_ref(), vault.as_ref());
        let connect_result = connect_session.connect(
            connection_id.clone(),
            client_id.clone(),
            Some(SecretString::new(client_secret.clone())),
            service.clone(),
        );

        match connect_result {
            Ok(vitalstead_mcp::core::connectors::whoop::connect::WhoopConnectOutcome::Connected { expires_at }) => {
                println!("✅ Connected. Access token stored in Keychain, expires_at = {expires_at:?}");
                expires_at
            }
            Err(e) => {
                eprintln!("❌ Connect failed: {e}");
                eprintln!(
                    "If this is MissingOfflineScope/ScopeNotConfirmed: the ASSUMPTION in \
                     WhoopConnectSession::connect() about TokenResponse.scope (T-401 spec §3/§7) \
                     may not hold for the real WHOOP API — capture the actual token response shape \
                     (WITHOUT the token values) and report back for a spec correction, not a silent patch."
                );
                std::process::exit(1);
            }
        }
    };

    println!();
    println!("=== Step 2: Sync last 3 days ===");

    let refresh_coordinator = RefreshCoordinator::new();
    let sleeper = RealSleeper;
    let clock = RealClock;
    let api_client = WhoopApiClient::new();
    let throttle = PacedThrottle::new(100, std::time::Duration::from_secs(60));

    let sync_session = WhoopSyncSession::new(
        vault.as_ref(),
        token_client.as_ref(),
        &refresh_coordinator,
        &sleeper,
        &clock,
        &api_client,
        &throttle,
    );

    let target_dir = std::env::temp_dir().join("vitalstead_whoop_manual_e2e");
    std::fs::create_dir_all(&target_dir).expect("create target_dir");

    let atomic = MacAtomicFileWriter::new();
    let writer = CsvWriter::new(&atomic);

    let now = chrono::Utc::now();
    let request = WhoopSyncRequest {
        connection_id,
        service,
        client_id,
        client_secret: Some(SecretString::new(client_secret)),
        time_range: (now - chrono::Duration::days(3), now),
        expires_at,
        target_dir: target_dir.clone(),
    };

    match sync_session.sync(request, &writer) {
        Ok(outcome) => {
            println!("✅ Sync succeeded: {outcome:?}");
            println!("CSV files written to: {}", target_dir.display());
            for name in ["sleep.csv", "recovery.csv", "cycles.csv", "workouts.csv"] {
                let path = target_dir.join(name);
                if path.exists() {
                    let content = std::fs::read_to_string(&path).unwrap_or_default();
                    let line_count = content.lines().count();
                    println!("  {name}: {line_count} lines (including header)");
                } else {
                    println!("  {name}: NOT CREATED");
                }
            }
            println!();
            println!("Next: open the CSV files yourself and check that column values look");
            println!("plausible (compare against the WHOOP app). Report back any parsing");
            println!("errors or unexpected empty fields — do NOT paste real health values");
            println!("into chat, just describe which columns look wrong.");
        }
        Err(e) => {
            eprintln!("❌ Sync failed: {e:?}");
            eprintln!(
                "If this is a WHOOP API client/DTO error: capture the endpoint path and \
                 status code (already safe to share, no secrets) and report back — the \
                 dto.rs field mapping is an ASSUMPTION pending this exact verification."
            );
            std::process::exit(1);
        }
    }
}
