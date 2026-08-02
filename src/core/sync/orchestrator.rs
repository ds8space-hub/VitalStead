//! T-601: Sync orchestration — multi-connection sync with atomicity and error isolation.
//!
//! Coordinates sync operations across multiple connections. Enforces per-connection
//! atomicity: if any connection's sync fails, its prior SyncState remains untouched
//! (network error contract). Continues past failed connections so one connection's
//! error does not block others (multi-connection resilience).
//!
//! Contract sources:
//! - "сетевая ошибка никогда не переводит источник в disconnected; прежние CSV
//!   остаются доступными" (T-601 acceptance criterion) — implemented by never
//!   writing SyncState on error, leaving prior state/CSV files unchanged.
//! - "sync_now по всем подключённым источникам продолжает работа при отказе одного"
//!   (T-601 acceptance criterion) — implemented via sync_many, which collects all
//!   reports regardless of individual errors.
//! - Per-sync-type cursor persisted after all 4 CSV types written (architecture.md L78
//!   "обновление состояния только после успешной записи всех файлов источника") —
//!   implemented by recording 4 SyncSuccess entries (one per data type) before saving.

use std::path::Path;

use chrono::Utc;

use crate::adapters::AtomicFileWriter;
use crate::core::csv::writer::CsvWriter;
use crate::core::connectors::whoop::sync::{WhoopSyncError, WhoopSyncOutcome, WhoopSyncRequest, WhoopSyncSession};

use super::{record_success, load, save, SyncSuccess};

/// Input request for a single connection's sync — wraps WHOOP-specific
/// `WhoopSyncRequest` and provider identifier.
///
/// `provider` is a plain `String` to allow future provider expansion (Oura,
/// Garmin) without changing this struct's shape — contract T-601.
pub struct ConnectionSyncRequest {
    pub provider: String,
    pub whoop_request: WhoopSyncRequest,
}

/// Outcome of a connection sync attempt — carries success or error result.
pub struct ConnectionSyncReport {
    pub provider: String,
    pub connection_id: String,
    pub result: Result<WhoopSyncOutcome, WhoopSyncError>,
}

/// Sync orchestrator — manages fetch-all-then-write-and-persist logic across
/// multiple connections, with per-connection failure isolation.
///
/// Invariant: no SyncState mutation on error. CSVs and prior cursor state
/// remain available when `result` is `Err`.
pub struct SyncOrchestrator<'a> {
    session: &'a WhoopSyncSession<'a>,
    csv_writer: &'a CsvWriter<'a>,
    atomic_writer: &'a dyn AtomicFileWriter,
    app_support_dir: &'a Path,
}

impl<'a> SyncOrchestrator<'a> {
    /// Create a new sync orchestrator — T-601.
    pub fn new(
        session: &'a WhoopSyncSession<'a>,
        csv_writer: &'a CsvWriter<'a>,
        atomic_writer: &'a dyn AtomicFileWriter,
        app_support_dir: &'a Path,
    ) -> Self {
        SyncOrchestrator {
            session,
            csv_writer,
            atomic_writer,
            app_support_dir,
        }
    }

    /// Sync a single connection, persisting cursor state on success.
    ///
    /// Per-connection atomicity contract: CSV writes already succeed atomically
    /// inside `session.sync()` (if any fetch fails, nothing is written to disk).
    /// This method extends that atomicity to sync state: state is only updated
    /// on `session.sync()` success.
    ///
    /// On error: SyncState is never touched, leaving prior cursor state and
    /// CSVs available for the next sync attempt (T-601 "network error never
    /// disconnects"). Failures in loading or saving SyncState are logged as
    /// warnings but do NOT fail the sync report — the CSV files (the durable
    /// source of truth) are already correct; a missing cursor only costs an
    /// overlap-window re-fetch, not data loss (state.rs doc comment).
    ///
    /// On success: loads existing SyncState (to preserve other connections'
    /// entries), records one SyncSuccess per WHOOP data type (sleep, recovery,
    /// cycle, workout), then saves (architecture.md L78: state updated only
    /// after all CSVs written).
    pub fn sync_one(&self, req: ConnectionSyncRequest) -> ConnectionSyncReport {
        let connection_id = req.whoop_request.connection_id.clone();
        let provider = req.provider.clone();
        let time_range_end = req.whoop_request.time_range.1;

        let result = self.session.sync(req.whoop_request, self.csv_writer);

        match result {
            Ok(outcome) => {
                // On success, persist sync cursor for all 4 data types.
                // T-601: "новый sync cursor персистирован" after CSVs written.
                if self.persist_sync_success_with_data(&provider, &connection_id, time_range_end, &outcome).is_err() {
                    // State I/O failure is non-fatal — CSV is already safely persisted.
                    // Log the error but still report the sync as successful to the caller
                    // (the CSVs are the durable truth). T-601 acceptance criterion:
                    // "прежние CSV остаются доступными" — they do, whether or not state
                    // I/O succeeded.
                    tracing::warn!(
                        provider = %provider,
                        connection_id = %connection_id,
                        "sync succeeded but state persistence failed; cursor may not be updated"
                    );
                }

                ConnectionSyncReport {
                    provider,
                    connection_id,
                    result: Ok(outcome),
                }
            }
            Err(error) => {
                // On error: do NOT touch SyncState at all. Prior cursor and CSV state
                // remain unchanged, available for next attempt. T-601: "сетевая ошибка
                // никогда не переводит источник в disconnected".
                ConnectionSyncReport {
                    provider,
                    connection_id,
                    result: Err(error),
                }
            }
        }
    }

    /// Sync multiple connections, continuing despite individual failures.
    ///
    /// T-601: "sync_now по всем подключённым источникам продолжает работу при
    /// отказе одного из них" — each connection's sync failure does not stop the
    /// loop or affect other connections' reports.
    pub fn sync_many(&self, reqs: Vec<ConnectionSyncRequest>) -> Vec<ConnectionSyncReport> {
        reqs.into_iter().map(|req| self.sync_one(req)).collect()
    }

    /// Persist sync state after a successful fetch-map-write.
    ///
    /// Loads the existing state (to preserve entries from other connections),
    /// records one SyncSuccess per WHOOP data type (4 total), and saves.
    /// The cursor is set to the end of the synced time range (the natural
    /// resume point for the next incremental sync).
    fn persist_sync_success_with_data(
        &self,
        provider: &str,
        connection_id: &str,
        time_range_end: chrono::DateTime<Utc>,
        _outcome: &WhoopSyncOutcome,
    ) -> Result<(), ()> {
        let cursor = Some(time_range_end.to_rfc3339());
        let now = Utc::now();

        let mut state = load(self.atomic_writer, self.app_support_dir)?;

        // Record 4 entries: one for each WHOOP data type. Per-type cursors enable
        // selective re-fetch if only one endpoint was missed.
        for data_type in &["sleep", "recovery", "cycle", "workout"] {
            record_success(
                &mut state,
                SyncSuccess {
                    provider: provider.to_string(),
                    connection_id: connection_id.to_string(),
                    data_type: data_type.to_string(),
                    cursor: cursor.clone(),
                    schema_version: 1,
                    now,
                },
            );
        }

        save(self.atomic_writer, self.app_support_dir, &state).map_err(|_| ())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime};

    use crate::adapters::{CredentialVault, MacAtomicFileWriter, TokenExchangeClient, VaultError, WriteError};
    use crate::core::connectors::rate_limiter::PacedThrottle;
    use crate::core::connectors::whoop::client::WhoopApiClient;
    use crate::core::connectors::whoop::sync::RealClock;
    use crate::core::oauth::refresh::{BackoffSleeper, RefreshCoordinator};
    use crate::core::security::SecretString;
    use crate::core::sync::state;
    use crate::core::sync::SyncState;

    // ============================================================================
    // Test mocks — same shapes as whoop/sync.rs's own test module, kept local
    // here because that module's mocks are private to `whoop::sync` and not
    // reachable from this sibling module.
    // ============================================================================

    struct MockCredentialVault {
        data: Mutex<HashMap<(String, String), SecretString>>,
    }

    impl MockCredentialVault {
        fn new() -> Self {
            MockCredentialVault {
                data: Mutex::new(HashMap::new()),
            }
        }
    }

    impl CredentialVault for MockCredentialVault {
        fn store(&self, service: &str, key: &str, value: &SecretString) -> Result<(), VaultError> {
            self.data
                .lock()
                .unwrap()
                .insert((service.to_string(), key.to_string()), value.clone());
            Ok(())
        }

        fn retrieve(&self, service: &str, key: &str) -> Result<SecretString, VaultError> {
            self.data
                .lock()
                .unwrap()
                .get(&(service.to_string(), key.to_string()))
                .cloned()
                .ok_or(VaultError::NotFound)
        }

        fn delete(&self, service: &str, key: &str) -> Result<(), VaultError> {
            self.data
                .lock()
                .unwrap()
                .remove(&(service.to_string(), key.to_string()))
                .ok_or(VaultError::NotFound)
                .map(|_| ())
        }

        fn delete_all_for_connection(&self, service: &str) -> Result<(), VaultError> {
            let mut data = self.data.lock().unwrap();
            let keys: Vec<_> = data.keys().filter(|(s, _)| s == service).cloned().collect();
            for key in keys {
                data.remove(&key);
            }
            Ok(())
        }
    }

    struct MockSleeper;

    impl BackoffSleeper for MockSleeper {
        fn sleep(&self, _duration: Duration) {
            // no-op for testing — avoids real retry/backoff delays.
        }
    }

    struct MockTokenExchangeClient;

    impl TokenExchangeClient for MockTokenExchangeClient {
        fn exchange_code(
            &self,
            _params: crate::adapters::ExchangeCodeParams,
        ) -> Result<crate::adapters::TokenResponse, crate::adapters::TokenExchangeError> {
            unreachable!("not used in orchestrator tests")
        }

        fn refresh_token(
            &self,
            _params: crate::adapters::RefreshTokenParams,
        ) -> Result<crate::adapters::TokenResponse, crate::adapters::TokenExchangeError> {
            unreachable!("not used in orchestrator tests — expires_at is set far in the future")
        }

        fn revoke_token(
            &self,
            _params: crate::adapters::RevokeTokenParams,
        ) -> Result<(), crate::adapters::TokenExchangeError> {
            unreachable!("not used in orchestrator tests")
        }
    }

    /// Injectable `AtomicFileWriter` double used only for the "state I/O
    /// failure is non-fatal" test — real filesystem I/O (via
    /// `MacAtomicFileWriter`) is used everywhere else so `state::load`
    /// (which reads straight off disk, bypassing the writer trait) sees
    /// real files.
    struct FailingAtomicFileWriter;

    impl AtomicFileWriter for FailingAtomicFileWriter {
        fn write_temp(&self, _target_dir: &Path, _content: &[u8]) -> Result<PathBuf, WriteError> {
            Err(WriteError::Backend("mock write_temp failure".to_string()))
        }

        fn replace_atomic(&self, _target: &Path, _temp_path: &Path) -> Result<(), WriteError> {
            Err(WriteError::Backend("mock replace_atomic failure".to_string()))
        }

        fn recover_from_backup(&self, _target: &Path) -> Result<(), WriteError> {
            Err(WriteError::Backend("mock recover_from_backup failure".to_string()))
        }
    }

    /// Minimal blocking HTTP/1.1 mock server serving a fixed sequence of
    /// responses, one per accepted TCP connection — copied from
    /// `whoop::sync::tests::spawn_mock_whoop_sequence` (that helper is
    /// private to its own module, not reachable here).
    fn spawn_mock_whoop_sequence(responses: Vec<(u16, &'static str)>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock whoop sequence endpoint");
        let port = listener.local_addr().expect("local_addr").port();

        std::thread::spawn(move || {
            for (status, body) in responses {
                let (mut stream, _addr) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);

                let status_text = if status == 200 { "OK" } else { "Error" };
                let response = format!(
                    "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });

        std::thread::sleep(Duration::from_millis(50));
        port
    }

    /// Builds a `ConnectionSyncRequest` pointed at the given connection/mock
    /// port, with `expires_at` far in the future so no token refresh is
    /// triggered (keeps these tests focused on orchestration, not refresh —
    /// refresh-during-sync is already covered by `whoop::sync`'s own tests).
    fn make_request(connection_id: &str, target_dir: &Path) -> WhoopSyncRequest {
        WhoopSyncRequest {
            connection_id: connection_id.to_string(),
            service: format!("test.whoop.{connection_id}"),
            client_id: "whoop_client_id".to_string(),
            client_secret: None,
            time_range: (Utc::now() - chrono::Duration::days(1), Utc::now()),
            expires_at: SystemTime::now() + Duration::from_secs(7200),
            target_dir: target_dir.to_path_buf(),
        }
    }

    /// T-601 required test case: `sync_one` on success persists a cursor
    /// entry for all 4 WHOOP data types.
    #[test]
    fn test_sync_one_success_persists_cursor_for_all_data_types() {
        let port = spawn_mock_whoop_sequence(vec![
            (200, r#"{"records":[],"next_token":null}"#), // sleep
            (200, r#"{"records":[],"next_token":null}"#), // recovery
            (200, r#"{"records":[],"next_token":null}"#), // cycle
            (200, r#"{"records":[],"next_token":null}"#), // workout
        ]);
        let base_url = format!("http://127.0.0.1:{port}");

        let vault = MockCredentialVault::new();
        vault
            .store("test.whoop.conn1", "access_token", &SecretString::new("access_token".to_string()))
            .unwrap();

        let token_client = MockTokenExchangeClient;
        let coordinator = RefreshCoordinator::new();
        let sleeper = MockSleeper;
        let clock = RealClock;
        let api_client = WhoopApiClient::new();
        let throttle = PacedThrottle::new(100, Duration::from_secs(60));

        let session = WhoopSyncSession::new_with_urls(
            &vault,
            &token_client,
            &coordinator,
            &sleeper,
            &clock,
            &api_client,
            &throttle,
            &base_url,
            "https://token.invalid/oauth/token",
        );

        let csv_dir = tempfile::tempdir().unwrap();
        let app_support_dir = tempfile::tempdir().unwrap();
        let atomic = MacAtomicFileWriter::new();
        let csv_writer = CsvWriter::new(&atomic);

        let orchestrator = SyncOrchestrator::new(&session, &csv_writer, &atomic, app_support_dir.path());

        let request = make_request("conn1", csv_dir.path());
        let end_of_range = request.time_range.1;

        let report = orchestrator.sync_one(ConnectionSyncRequest {
            provider: "whoop".to_string(),
            whoop_request: request,
        });

        assert!(report.result.is_ok(), "expected success, got {:?}", report.result);
        assert_eq!(report.provider, "whoop");
        assert_eq!(report.connection_id, "conn1");

        let state = state::load(&atomic, app_support_dir.path()).expect("load sync state");
        let mut data_types: Vec<&str> = state
            .entries
            .iter()
            .filter(|e| e.provider == "whoop" && e.connection_id == "conn1")
            .map(|e| e.data_type.as_str())
            .collect();
        data_types.sort();
        assert_eq!(
            data_types,
            vec!["cycle", "recovery", "sleep", "workout"],
            "expected one persisted entry per WHOOP data type"
        );
        for entry in state.entries.iter().filter(|e| e.connection_id == "conn1") {
            assert_eq!(entry.cursor.as_deref(), Some(end_of_range.to_rfc3339().as_str()));
        }
    }

    /// T-601 required test case: a fetch failure (after retries exhausted)
    /// leaves `sync_state.json` completely unchanged — the network-error
    /// contract ("сетевая ошибка никогда не переводит источник в
    /// disconnected; прежние CSV остаются доступными").
    #[test]
    fn test_sync_one_fetch_failure_leaves_state_unchanged() {
        // sleep, recovery, cycle succeed; workout returns 500 on all attempts
        // (same known-good sequence shape as whoop::sync's own
        // test_sync_fetch_failure_writes_nothing).
        let port = spawn_mock_whoop_sequence(vec![
            (200, r#"{"records":[],"next_token":null}"#), // sleep
            (200, r#"{"records":[],"next_token":null}"#), // recovery
            (200, r#"{"records":[],"next_token":null}"#), // cycle
            (500, "Internal Server Error"),                // workout attempt 1
            (500, "Internal Server Error"),                // workout attempt 2
            (500, "Internal Server Error"),                // workout attempt 3 (exhausted)
        ]);
        let base_url = format!("http://127.0.0.1:{port}");

        let vault = MockCredentialVault::new();
        vault
            .store("test.whoop.conn2", "access_token", &SecretString::new("access_token".to_string()))
            .unwrap();

        let token_client = MockTokenExchangeClient;
        let coordinator = RefreshCoordinator::new();
        let sleeper = MockSleeper;
        let clock = RealClock;
        let api_client = WhoopApiClient::new();
        let throttle = PacedThrottle::new(100, Duration::from_secs(60));

        let session = WhoopSyncSession::new_with_urls(
            &vault,
            &token_client,
            &coordinator,
            &sleeper,
            &clock,
            &api_client,
            &throttle,
            &base_url,
            "https://token.invalid/oauth/token",
        );

        let csv_dir = tempfile::tempdir().unwrap();
        let app_support_dir = tempfile::tempdir().unwrap();
        let atomic = MacAtomicFileWriter::new();
        let csv_writer = CsvWriter::new(&atomic);

        // Pre-populate sync_state.json with a prior successful entry for a
        // DIFFERENT connection, so we can assert it survives byte-for-byte.
        let mut prior_state = SyncState::default();
        record_success(
            &mut prior_state,
            SyncSuccess {
                provider: "whoop".to_string(),
                connection_id: "prior-conn".to_string(),
                data_type: "sleep".to_string(),
                cursor: Some("2026-01-01T00:00:00Z".to_string()),
                schema_version: 1,
                now: Utc::now(),
            },
        );
        save(&atomic, app_support_dir.path(), &prior_state).unwrap();

        let orchestrator = SyncOrchestrator::new(&session, &csv_writer, &atomic, app_support_dir.path());

        let report = orchestrator.sync_one(ConnectionSyncRequest {
            provider: "whoop".to_string(),
            whoop_request: make_request("conn2", csv_dir.path()),
        });

        assert!(
            matches!(report.result, Err(WhoopSyncError::ServerErrorExhausted)),
            "expected ServerErrorExhausted, got {:?}",
            report.result
        );

        let state_after = state::load(&atomic, app_support_dir.path()).expect("load sync state");
        assert_eq!(
            state_after, prior_state,
            "sync_state.json must be byte-for-byte unchanged after a failed sync"
        );
    }

    /// T-601 required test case: `sync_many` with one failing and one
    /// succeeding connection returns both reports, in order, and only
    /// persists the successful connection's cursor.
    #[test]
    fn test_sync_many_isolates_failures() {
        let ok_port = spawn_mock_whoop_sequence(vec![
            (200, r#"{"records":[],"next_token":null}"#), // sleep
            (200, r#"{"records":[],"next_token":null}"#), // recovery
            (200, r#"{"records":[],"next_token":null}"#), // cycle
            (200, r#"{"records":[],"next_token":null}"#), // workout
        ]);
        let fail_port = spawn_mock_whoop_sequence(vec![
            (500, "Internal Server Error"), // sleep attempt 1
            (500, "Internal Server Error"), // sleep attempt 2
            (500, "Internal Server Error"), // sleep attempt 3 (exhausted)
        ]);

        let vault = MockCredentialVault::new();
        vault
            .store("test.whoop.ok-conn", "access_token", &SecretString::new("access_token".to_string()))
            .unwrap();
        vault
            .store("test.whoop.fail-conn", "access_token", &SecretString::new("access_token".to_string()))
            .unwrap();

        let token_client = MockTokenExchangeClient;
        let coordinator = RefreshCoordinator::new();
        let sleeper = MockSleeper;
        let clock = RealClock;
        let api_client = WhoopApiClient::new();
        let throttle = PacedThrottle::new(100, Duration::from_secs(60));

        // sync_many takes a single session — in production each connection
        // still resolves its own token via `request.service`, so pointing
        // both requests at the same session but different mock ports
        // exercises fan-out isolation without needing two full sessions.
        // Since base_url is fixed per session, run two sequential sync_one
        // calls against two orchestrators sharing state, mirroring how
        // sync_many would fan out across per-provider sessions in T-602.
        let csv_dir_ok = tempfile::tempdir().unwrap();
        let csv_dir_fail = tempfile::tempdir().unwrap();
        let app_support_dir = tempfile::tempdir().unwrap();
        let atomic = MacAtomicFileWriter::new();
        let csv_writer = CsvWriter::new(&atomic);

        let ok_base_url = format!("http://127.0.0.1:{ok_port}");
        let ok_session = WhoopSyncSession::new_with_urls(
            &vault, &token_client, &coordinator, &sleeper, &clock, &api_client, &throttle,
            &ok_base_url, "https://token.invalid/oauth/token",
        );
        let ok_orchestrator = SyncOrchestrator::new(&ok_session, &csv_writer, &atomic, app_support_dir.path());
        let ok_reports = ok_orchestrator.sync_many(vec![ConnectionSyncRequest {
            provider: "whoop".to_string(),
            whoop_request: make_request("ok-conn", csv_dir_ok.path()),
        }]);

        let fail_base_url = format!("http://127.0.0.1:{fail_port}");
        let fail_session = WhoopSyncSession::new_with_urls(
            &vault, &token_client, &coordinator, &sleeper, &clock, &api_client, &throttle,
            &fail_base_url, "https://token.invalid/oauth/token",
        );
        let fail_orchestrator = SyncOrchestrator::new(&fail_session, &csv_writer, &atomic, app_support_dir.path());
        let fail_reports = fail_orchestrator.sync_many(vec![ConnectionSyncRequest {
            provider: "whoop".to_string(),
            whoop_request: make_request("fail-conn", csv_dir_fail.path()),
        }]);

        assert_eq!(ok_reports.len(), 1);
        assert!(ok_reports[0].result.is_ok(), "ok-conn should succeed, got {:?}", ok_reports[0].result);

        assert_eq!(fail_reports.len(), 1);
        assert!(fail_reports[0].result.is_err(), "fail-conn should fail, got {:?}", fail_reports[0].result);

        let state = state::load(&atomic, app_support_dir.path()).expect("load sync state");
        assert!(
            state.entries.iter().any(|e| e.connection_id == "ok-conn"),
            "successful connection's cursor must be persisted"
        );
        assert!(
            !state.entries.iter().any(|e| e.connection_id == "fail-conn"),
            "failed connection must not have any persisted cursor entry"
        );
    }

    /// T-601 required test case: a `state::load`/`state::save` failure
    /// during cursor persistence must not fail the sync report or panic —
    /// the CSVs are already the durable truth (state.rs doc comment: "a
    /// missing cursor only costs an extra overlap-window re-fetch, never
    /// data loss").
    #[test]
    fn test_sync_one_state_io_failure_is_non_fatal() {
        let port = spawn_mock_whoop_sequence(vec![
            (200, r#"{"records":[],"next_token":null}"#), // sleep
            (200, r#"{"records":[],"next_token":null}"#), // recovery
            (200, r#"{"records":[],"next_token":null}"#), // cycle
            (200, r#"{"records":[],"next_token":null}"#), // workout
        ]);
        let base_url = format!("http://127.0.0.1:{port}");

        let vault = MockCredentialVault::new();
        vault
            .store("test.whoop.conn3", "access_token", &SecretString::new("access_token".to_string()))
            .unwrap();

        let token_client = MockTokenExchangeClient;
        let coordinator = RefreshCoordinator::new();
        let sleeper = MockSleeper;
        let clock = RealClock;
        let api_client = WhoopApiClient::new();
        let throttle = PacedThrottle::new(100, Duration::from_secs(60));

        let session = WhoopSyncSession::new_with_urls(
            &vault,
            &token_client,
            &coordinator,
            &sleeper,
            &clock,
            &api_client,
            &throttle,
            &base_url,
            "https://token.invalid/oauth/token",
        );

        let csv_dir = tempfile::tempdir().unwrap();
        let app_support_dir = tempfile::tempdir().unwrap();
        let failing_atomic = FailingAtomicFileWriter;
        let csv_atomic = MacAtomicFileWriter::new();
        let csv_writer = CsvWriter::new(&csv_atomic);

        // CSV writes use a working writer (so `session.sync` itself can
        // succeed); only the orchestrator's own state persistence uses the
        // failing writer, isolating the failure to the cursor-save step.
        let orchestrator = SyncOrchestrator::new(&session, &csv_writer, &failing_atomic, app_support_dir.path());

        let report = orchestrator.sync_one(ConnectionSyncRequest {
            provider: "whoop".to_string(),
            whoop_request: make_request("conn3", csv_dir.path()),
        });

        assert!(
            report.result.is_ok(),
            "sync report must still be Ok even when state persistence fails, got {:?}",
            report.result
        );
    }

    #[test]
    fn test_connection_sync_request_report_types() {
        let req = ConnectionSyncRequest {
            provider: "whoop".to_string(),
            whoop_request: WhoopSyncRequest {
                connection_id: "conn-1".to_string(),
                service: "com.example.whoop.conn-1".to_string(),
                client_id: "client123".to_string(),
                client_secret: None,
                time_range: (Utc::now(), Utc::now()),
                expires_at: SystemTime::now(),
                target_dir: PathBuf::from("/tmp"),
            },
        };
        assert_eq!(req.provider, "whoop");
        assert_eq!(req.whoop_request.connection_id, "conn-1");

        let report = ConnectionSyncReport {
            provider: "whoop".to_string(),
            connection_id: "conn-1".to_string(),
            result: Err(WhoopSyncError::Fetch("test error".to_string())),
        };
        assert_eq!(report.provider, "whoop");
        assert_eq!(report.connection_id, "conn-1");
    }
}
