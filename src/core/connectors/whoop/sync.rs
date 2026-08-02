//! WHOOP sync orchestration (Step 5 — T-401).
//!
//! Manages the full sync lifecycle for WHOOP connectors:
//! 1. FETCH phase: paginate through 4 endpoints (sleep, recovery, cycle, workout) with throttling
//! 2. MAP phase: DTO → CsvRow transformation
//! 3. WRITE phase: atomic upsert to CSV files (only if all fetches successful per ADR-020)
//!
//! Per ADR-020 sync atomicity contract: if ANY fetch fails after retries exhausted,
//! NOTHING is written to disk — the entire sync aborts.

use chrono::{DateTime, Utc};
use std::path::PathBuf;
use std::time::SystemTime;

use crate::adapters::{CredentialVault, TokenExchangeClient, VaultError};
use crate::core::csv::serialize::CsvRow;
use crate::core::csv::upsert::upsert;
use crate::core::csv::writer::CsvWriter;
use crate::core::oauth::refresh::{BackoffSleeper, RefreshCoordinator, RefreshError, RefreshOrchestrator, RefreshOutcome, RefreshRequest, REFRESH_LEAD_TIME};
use crate::core::security::SecretString;

use super::client::{WhoopApiClient, WhoopApiError};
use super::dto::{CycleRecord, RecoveryRecord, SleepRecord, WorkoutRecord};
use super::mapping::{cycle_schema, map_cycle, map_recovery, map_sleep, map_workout, recovery_schema, sleep_schema, workout_schema};

/// Testability seam for system time — allows tests to mock time without sleeping.
pub trait Clock: Send + Sync {
    /// Get current system time.
    fn now(&self) -> SystemTime;
}

/// Real implementation using `SystemTime::now()`.
pub struct RealClock;

impl Clock for RealClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Production WHOOP API v2 base URL (ASSUMPTION, T-401 spec §3 — verify on manual e2e).
const WHOOP_BASE_URL: &str = "https://api.prod.whoop.com/developer/v2";
/// Production WHOOP OAuth token endpoint (ASSUMPTION, T-401 spec §3).
const WHOOP_TOKEN_ENDPOINT: &str = "https://api.prod.whoop.com/oauth/oauth2/token";

/// WHOOP sync session — coordinates fetch, map, write phases.
pub struct WhoopSyncSession<'a> {
    vault: &'a dyn CredentialVault,
    token_client: &'a dyn TokenExchangeClient,
    refresh_coordinator: &'a RefreshCoordinator,
    sleeper: &'a dyn BackoffSleeper,
    clock: &'a dyn Clock,
    api_client: &'a WhoopApiClient,
    throttle: &'a crate::core::connectors::rate_limiter::PacedThrottle,
    /// WHOOP API base URL — overridable only via `new_with_urls` (test seam) so
    /// integration tests can point fetch_page calls at a local mock HTTP server.
    base_url: &'a str,
    /// OAuth token endpoint — same test-seam rationale as `base_url`.
    token_endpoint: &'a str,
}

/// Input parameters for a WHOOP sync operation.
pub struct WhoopSyncRequest {
    /// Unique connection identifier.
    pub connection_id: String,
    /// Vault namespace (e.g., "{bundle_id}.whoop.{connection_id}").
    pub service: String,
    /// OAuth client identifier.
    pub client_id: String,
    /// OAuth client secret (if applicable).
    pub client_secret: Option<SecretString>,
    /// Time range for filtering (RFC3339 start, end).
    pub time_range: (DateTime<Utc>, DateTime<Utc>),
    /// Current access token expiry time (for refresh pre-check).
    pub expires_at: SystemTime,
    /// Target directory for CSV files.
    pub target_dir: PathBuf,
}

/// Outcome of a successful sync.
#[derive(Debug)]
pub enum WhoopSyncOutcome {
    /// Sync completed successfully.
    Synced {
        /// Number of sleep records synced.
        sleep_count: usize,
        /// Number of recovery records synced.
        recovery_count: usize,
        /// Number of cycle records synced.
        cycle_count: usize,
        /// Number of workout records synced.
        workout_count: usize,
    },
}

/// Error type for sync operations.
#[derive(Debug, Clone)]
pub enum WhoopSyncError {
    /// Fetch phase failed (API error after retries).
    Fetch(String),
    /// Rate limit exhausted without recovery.
    RateLimitExhausted,
    /// Network errors exhausted without recovery.
    NetworkExhausted,
    /// Server errors (5xx) exhausted without recovery.
    ServerErrorExhausted,
    /// Token refresh failed.
    Refresh(RefreshError),
    /// CSV write phase failed.
    Write { csv_type: &'static str },
    /// Vault error.
    Vault(VaultError),
}

impl<'a> WhoopSyncSession<'a> {
    /// Create a new WHOOP sync session.
    pub fn new(
        vault: &'a dyn CredentialVault,
        token_client: &'a dyn TokenExchangeClient,
        refresh_coordinator: &'a RefreshCoordinator,
        sleeper: &'a dyn BackoffSleeper,
        clock: &'a dyn Clock,
        api_client: &'a WhoopApiClient,
        throttle: &'a crate::core::connectors::rate_limiter::PacedThrottle,
    ) -> Self {
        WhoopSyncSession {
            vault,
            token_client,
            refresh_coordinator,
            sleeper,
            clock,
            api_client,
            throttle,
            base_url: WHOOP_BASE_URL,
            token_endpoint: WHOOP_TOKEN_ENDPOINT,
        }
    }

    /// Test-only constructor — overrides `base_url`/`token_endpoint` so integration
    /// tests can point `WhoopApiClient::fetch_page` at a local mock HTTP server
    /// instead of the real WHOOP API. Production code always uses `new()`.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_urls(
        vault: &'a dyn CredentialVault,
        token_client: &'a dyn TokenExchangeClient,
        refresh_coordinator: &'a RefreshCoordinator,
        sleeper: &'a dyn BackoffSleeper,
        clock: &'a dyn Clock,
        api_client: &'a WhoopApiClient,
        throttle: &'a crate::core::connectors::rate_limiter::PacedThrottle,
        base_url: &'a str,
        token_endpoint: &'a str,
    ) -> Self {
        WhoopSyncSession {
            vault,
            token_client,
            refresh_coordinator,
            sleeper,
            clock,
            api_client,
            throttle,
            base_url,
            token_endpoint,
        }
    }

    /// Execute a full sync operation.
    ///
    /// Atomicity: if ANY fetch fails (after retries), NOTHING is written to disk.
    pub fn sync(
        &self,
        request: WhoopSyncRequest,
        writer: &CsvWriter,
    ) -> Result<WhoopSyncOutcome, WhoopSyncError> {
        let token_endpoint = self.token_endpoint;
        let base_url = self.base_url;

        // Get initial access token from vault
        let mut access_token = self
            .vault
            .retrieve(&request.service, "access_token")
            .map_err(WhoopSyncError::Vault)?;

        let mut current_expires_at = request.expires_at;

        // PHASE 1: FETCH all records from all 4 endpoints with pagination
        let (sleep_records, recovery_records, cycle_records, workout_records) = {
            // Fetch sleep records
            let sleep_records = self.fetch_records_paginated::<SleepRecord>(
                &mut access_token,
                &mut current_expires_at,
                &request,
                token_endpoint,
                base_url,
                "/activity/sleep",
            )?;

            // Fetch recovery records
            let recovery_records = self.fetch_records_paginated::<RecoveryRecord>(
                &mut access_token,
                &mut current_expires_at,
                &request,
                token_endpoint,
                base_url,
                "/recovery",
            )?;

            // Fetch cycle records
            let cycle_records = self.fetch_records_paginated::<CycleRecord>(
                &mut access_token,
                &mut current_expires_at,
                &request,
                token_endpoint,
                base_url,
                "/cycle",
            )?;

            // Fetch workout records
            let workout_records = self.fetch_records_paginated::<WorkoutRecord>(
                &mut access_token,
                &mut current_expires_at,
                &request,
                token_endpoint,
                base_url,
                "/activity/workout",
            )?;

            (sleep_records, recovery_records, cycle_records, workout_records)
        };

        // PHASE 2: MAP DTO → CsvRow
        let synced_at = Utc::now();

        let sleep_rows: Vec<CsvRow> = sleep_records.iter().map(|r| map_sleep(r, synced_at)).collect();
        let recovery_rows: Vec<CsvRow> = recovery_records.iter().map(|r| map_recovery(r, synced_at)).collect();
        let cycle_rows: Vec<CsvRow> = cycle_records.iter().map(|r| map_cycle(r, synced_at)).collect();
        let workout_rows: Vec<CsvRow> = workout_records.iter().map(|r| map_workout(r, synced_at)).collect();

        // PHASE 3: WRITE (only if all fetches succeeded)
        // Atomicity: if any write fails, abort
        let sleep_stats = upsert(
            &request.target_dir.join("sleep.csv"),
            &sleep_schema(),
            &sleep_rows,
            &[],
            1,
            writer,
        )
        .map_err(|_| WhoopSyncError::Write { csv_type: "sleep" })?;

        let recovery_stats = upsert(
            &request.target_dir.join("recovery.csv"),
            &recovery_schema(),
            &recovery_rows,
            &[],
            1,
            writer,
        )
        .map_err(|_| WhoopSyncError::Write { csv_type: "recovery" })?;

        let cycle_stats = upsert(
            &request.target_dir.join("cycles.csv"),
            &cycle_schema(),
            &cycle_rows,
            &[],
            1,
            writer,
        )
        .map_err(|_| WhoopSyncError::Write { csv_type: "cycle" })?;

        let workout_stats = upsert(
            &request.target_dir.join("workouts.csv"),
            &workout_schema(),
            &workout_rows,
            &[],
            1,
            writer,
        )
        .map_err(|_| WhoopSyncError::Write { csv_type: "workout" })?;

        Ok(WhoopSyncOutcome::Synced {
            sleep_count: sleep_stats.inserted + sleep_stats.updated,
            recovery_count: recovery_stats.inserted + recovery_stats.updated,
            cycle_count: cycle_stats.inserted + cycle_stats.updated,
            workout_count: workout_stats.inserted + workout_stats.updated,
        })
    }

    /// Fetch all pages of records from a single endpoint with pagination, throttling, and refresh.
    fn fetch_records_paginated<T: serde::de::DeserializeOwned>(
        &self,
        access_token: &mut SecretString,
        current_expires_at: &mut SystemTime,
        request: &WhoopSyncRequest,
        token_endpoint: &str,
        base_url: &str,
        endpoint_path: &str,
    ) -> Result<Vec<T>, WhoopSyncError> {
        let mut records = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            // Check if refresh is due
            let now = self.clock.now();
            if self.should_refresh(*current_expires_at, now) {
                let refresh_request = RefreshRequest {
                    connection_id: request.connection_id.clone(),
                    service: request.service.clone(),
                    token_endpoint: token_endpoint.to_string(),
                    client_id: request.client_id.clone(),
                    client_secret: request.client_secret.clone(),
                    expires_at: *current_expires_at,
                };

                let orchestrator = RefreshOrchestrator::new(
                    self.vault,
                    self.token_client,
                    self.refresh_coordinator,
                    self.sleeper,
                );

                match orchestrator.refresh(refresh_request, now) {
                    Ok(RefreshOutcome::Refreshed {
                        expires_at,
                        ..
                    }) => {
                        *access_token = self
                            .vault
                            .retrieve(&request.service, "access_token")
                            .map_err(WhoopSyncError::Vault)?;
                        *current_expires_at = expires_at;
                    }
                    Ok(RefreshOutcome::ReauthorizationRequired) => {
                        return Err(WhoopSyncError::Refresh(RefreshError::ClientError {
                            status: 401,
                            error: Some("reauthorization_required".to_string()),
                        }));
                    }
                    Err(e) => return Err(WhoopSyncError::Refresh(e)),
                }
            }

            // Apply throttle before request
            self.throttle.throttle(self.sleeper);

            // Fetch page with retry logic
            let page = self.fetch_page_with_retries::<T>(
                access_token,
                request,
                token_endpoint,
                base_url,
                endpoint_path,
                next_token.as_deref(),
            )?;

            // Add records from this page
            records.extend(page.records);

            // Check for next page
            match page.next_token {
                Some(token) => next_token = Some(token),
                None => break, // Last page
            }
        }

        Ok(records)
    }

    /// Fetch a single page with retry logic for various error types.
    fn fetch_page_with_retries<T: serde::de::DeserializeOwned>(
        &self,
        access_token: &mut SecretString,
        request: &WhoopSyncRequest,
        token_endpoint: &str,
        base_url: &str,
        endpoint_path: &str,
        next_token: Option<&str>,
    ) -> Result<super::dto::WhoopPage<T>, WhoopSyncError> {
        match self.api_client.fetch_page(
            base_url,
            endpoint_path,
            access_token,
            request.time_range.0,
            request.time_range.1,
            next_token,
        ) {
            Ok(page) => Ok(page),
            Err(WhoopApiError::Unauthorized) => {
                // Trigger immediate refresh and retry once
                let refresh_request = RefreshRequest {
                    connection_id: request.connection_id.clone(),
                    service: request.service.clone(),
                    token_endpoint: token_endpoint.to_string(),
                    client_id: request.client_id.clone(),
                    client_secret: request.client_secret.clone(),
                    expires_at: self.clock.now(),
                };

                let orchestrator = RefreshOrchestrator::new(
                    self.vault,
                    self.token_client,
                    self.refresh_coordinator,
                    self.sleeper,
                );

                match orchestrator.refresh(refresh_request, self.clock.now()) {
                    Ok(RefreshOutcome::Refreshed {
                        expires_at: _,
                        ..
                    }) => {
                        *access_token = self
                            .vault
                            .retrieve(&request.service, "access_token")
                            .map_err(WhoopSyncError::Vault)?;

                        // Retry the request with new token
                        self.api_client
                            .fetch_page(
                                base_url,
                                endpoint_path,
                                access_token,
                                request.time_range.0,
                                request.time_range.1,
                                next_token,
                            )
                            .map_err(|_| WhoopSyncError::Fetch("unauthorized after refresh".to_string()))
                    }
                    Err(e) => Err(WhoopSyncError::Refresh(e)),
                    Ok(RefreshOutcome::ReauthorizationRequired) => {
                        Err(WhoopSyncError::Fetch("reauthorization required".to_string()))
                    }
                }
            }
            Err(WhoopApiError::RateLimited { retry_after_secs }) => {
                for attempt in 1..=5 {
                    let default_backoff = match attempt {
                        1 => 2,
                        2 => 4,
                        3 => 8,
                        4 => 16,
                        _ => 32,
                    };
                    let backoff = retry_after_secs.unwrap_or(default_backoff).min(60);

                    self.sleeper.sleep(std::time::Duration::from_secs(backoff));

                    match self.api_client.fetch_page(
                        base_url,
                        endpoint_path,
                        access_token,
                        request.time_range.0,
                        request.time_range.1,
                        next_token,
                    ) {
                        Ok(page) => return Ok(page),
                        Err(WhoopApiError::RateLimited { .. }) if attempt < 5 => continue,
                        Err(_) => return Err(WhoopSyncError::RateLimitExhausted),
                    }
                }
                Err(WhoopSyncError::RateLimitExhausted)
            }
            Err(WhoopApiError::Network(_)) => {
                for attempt in 1..=3 {
                    let backoff = match attempt {
                        1 => 1,
                        2 => 2,
                        _ => 4,
                    };

                    self.sleeper.sleep(std::time::Duration::from_secs(backoff));

                    match self.api_client.fetch_page(
                        base_url,
                        endpoint_path,
                        access_token,
                        request.time_range.0,
                        request.time_range.1,
                        next_token,
                    ) {
                        Ok(page) => return Ok(page),
                        Err(WhoopApiError::Network(_)) if attempt < 3 => continue,
                        Err(_) => return Err(WhoopSyncError::NetworkExhausted),
                    }
                }
                Err(WhoopSyncError::NetworkExhausted)
            }
            Err(WhoopApiError::ServerError(_)) => {
                for attempt in 1..=3 {
                    let backoff = match attempt {
                        1 => 2,
                        2 => 4,
                        _ => 8,
                    };

                    self.sleeper.sleep(std::time::Duration::from_secs(backoff));

                    match self.api_client.fetch_page(
                        base_url,
                        endpoint_path,
                        access_token,
                        request.time_range.0,
                        request.time_range.1,
                        next_token,
                    ) {
                        Ok(page) => return Ok(page),
                        Err(WhoopApiError::ServerError(_)) if attempt < 3 => continue,
                        Err(_) => return Err(WhoopSyncError::ServerErrorExhausted),
                    }
                }
                Err(WhoopSyncError::ServerErrorExhausted)
            }
            Err(e) => Err(WhoopSyncError::Fetch(format!("{:?}", e))),
        }
    }

    /// Check if refresh is due based on current time and expiry.
    fn should_refresh(&self, expires_at: SystemTime, now: SystemTime) -> bool {
        match expires_at.checked_sub(REFRESH_LEAD_TIME) {
            Some(due_at) => now >= due_at,
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Duration;

    /// Clock double that returns a pre-scripted sequence of timestamps, one per
    /// `.now()` call (clamped to the last entry once exhausted) — simulates real
    /// time elapsing DURING a single synchronous `sync()` call, which cannot be
    /// paused mid-execution to advance a plain mock clock. `.now()` is called
    /// once per endpoint's pagination loop iteration (once per page fetched);
    /// with no pagination in these tests that's once per endpoint, in order:
    /// sleep, recovery, cycle, workout.
    struct SteppingClock {
        times: Vec<SystemTime>,
        call_count: Mutex<usize>,
    }

    impl SteppingClock {
        fn new(times: Vec<SystemTime>) -> Self {
            SteppingClock {
                times,
                call_count: Mutex::new(0),
            }
        }
    }

    impl Clock for SteppingClock {
        fn now(&self) -> SystemTime {
            let mut count = self.call_count.lock().unwrap();
            let idx = *count;
            *count += 1;
            let clamped = idx.min(self.times.len() - 1);
            self.times[clamped]
        }
    }

    struct MockSleeper {
        total_sleep: Mutex<Duration>,
    }

    impl MockSleeper {
        fn new() -> Self {
            MockSleeper {
                total_sleep: Mutex::new(Duration::ZERO),
            }
        }

        #[allow(dead_code)]
        fn total_sleep(&self) -> Duration {
            *self.total_sleep.lock().unwrap()
        }
    }

    impl BackoffSleeper for MockSleeper {
        fn sleep(&self, duration: Duration) {
            *self.total_sleep.lock().unwrap() += duration;
        }
    }

    /// Mock credential vault for testing
    struct MockCredentialVault {
        data: Mutex<HashMap<(String, String), SecretString>>,
        store_call_count: Mutex<u32>,
    }

    impl MockCredentialVault {
        fn new() -> Self {
            MockCredentialVault {
                data: Mutex::new(HashMap::new()),
                store_call_count: Mutex::new(0),
            }
        }

        #[allow(dead_code)]
        fn store_call_count(&self) -> u32 {
            *self.store_call_count.lock().unwrap()
        }

        fn get(&self, service: &str, key: &str) -> Option<SecretString> {
            self.data
                .lock()
                .unwrap()
                .get(&(service.to_string(), key.to_string()))
                .cloned()
        }
    }

    impl CredentialVault for MockCredentialVault {
        fn store(&self, service: &str, key: &str, value: &SecretString) -> Result<(), VaultError> {
            *self.store_call_count.lock().unwrap() += 1;
            self.data
                .lock()
                .unwrap()
                .insert((service.to_string(), key.to_string()), value.clone());
            Ok(())
        }

        fn retrieve(&self, service: &str, key: &str) -> Result<SecretString, VaultError> {
            self.get(service, key).ok_or(VaultError::NotFound)
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

    /// Mock token exchange client for testing
    struct MockTokenExchangeClient {
        responses: Mutex<std::collections::VecDeque<Result<crate::adapters::TokenResponse, crate::adapters::TokenExchangeError>>>,
        call_count: Mutex<u32>,
    }

    impl MockTokenExchangeClient {
        fn new() -> Self {
            MockTokenExchangeClient {
                responses: Mutex::new(std::collections::VecDeque::new()),
                call_count: Mutex::new(0),
            }
        }

        fn queue_response(&self, response: Result<crate::adapters::TokenResponse, crate::adapters::TokenExchangeError>) {
            self.responses.lock().unwrap().push_back(response);
        }

        fn call_count(&self) -> u32 {
            *self.call_count.lock().unwrap()
        }
    }

    impl TokenExchangeClient for MockTokenExchangeClient {
        fn exchange_code(
            &self,
            _params: crate::adapters::ExchangeCodeParams,
        ) -> Result<crate::adapters::TokenResponse, crate::adapters::TokenExchangeError> {
            unreachable!("exchange_code not used in sync tests")
        }

        fn refresh_token(
            &self,
            _params: crate::adapters::RefreshTokenParams,
        ) -> Result<crate::adapters::TokenResponse, crate::adapters::TokenExchangeError> {
            *self.call_count.lock().unwrap() += 1;
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(crate::adapters::TokenExchangeError::Network("no response queued".to_string())))
        }

        fn revoke_token(
            &self,
            _params: crate::adapters::RevokeTokenParams,
        ) -> Result<(), crate::adapters::TokenExchangeError> {
            unreachable!("revoke_token not used in sync tests")
        }
    }

    /// Minimal blocking HTTP/1.1 mock server serving a FIXED SEQUENCE of responses,
    /// one per accepted TCP connection, in order. Unlike `client.rs`'s
    /// `spawn_mock_whoop_endpoint` (single connection only), this accepts
    /// `responses.len()` connections — needed because a full `sync()` call makes
    /// multiple sequential HTTP requests (one per endpoint, plus retries).
    /// Captures the `Authorization` header of each request, in call order.
    fn spawn_mock_whoop_sequence(
        responses: Vec<(u16, &'static str)>,
    ) -> (u16, std::sync::Arc<Mutex<Vec<Option<String>>>>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock whoop sequence endpoint");
        let port = listener.local_addr().expect("local_addr").port();
        let captured: std::sync::Arc<Mutex<Vec<Option<String>>>> = std::sync::Arc::new(Mutex::new(Vec::new()));
        let captured_clone = std::sync::Arc::clone(&captured);

        std::thread::spawn(move || {
            for (status, body) in responses {
                let (mut stream, _addr) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let mut buf = [0u8; 8192];
                if let Ok(n) = stream.read(&mut buf) {
                    let request_str = String::from_utf8_lossy(&buf[..n]).to_string();
                    // reqwest sends header names lowercased ("authorization: ..."), unlike
                    // the "Authorization: " title-case search in client.rs's single-shot mock.
                    let auth_header = request_str.find("authorization: ").map(|start| {
                        let auth_start = start + "authorization: ".len();
                        let end = request_str[auth_start..]
                            .find('\r')
                            .unwrap_or(request_str[auth_start..].len());
                        request_str[auth_start..auth_start + end].to_string()
                    });
                    captured_clone.lock().unwrap().push(auth_header);
                }

                let status_text = if status == 200 { "OK" } else { "Error" };
                let response = format!(
                    "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });

        std::thread::sleep(Duration::from_millis(50));
        (port, captured)
    }

    /// AC#4 (T-401, most important functional criterion): a sync spanning longer
    /// than the access token's lifetime must not fail — it must refresh mid-sync
    /// and use the new token for subsequent requests.
    ///
    /// Uses `SteppingClock` to simulate >65 minutes elapsing between the first
    /// endpoint (sleep, still on the old token) and the remaining three endpoints
    /// (recovery/cycle/workout, which must observe the refreshed token) — a real
    /// `std::thread::sleep`-based test would be impractically slow and flaky.
    #[test]
    fn test_sync_long_running_triggers_refresh_mid_sync() {
        let (port, captured) = spawn_mock_whoop_sequence(vec![
            (200, r#"{"records":[],"next_token":null}"#), // sleep — old token
            (200, r#"{"records":[],"next_token":null}"#), // recovery — new token
            (200, r#"{"records":[],"next_token":null}"#), // cycle — new token
            (200, r#"{"records":[],"next_token":null}"#), // workout — new token
        ]);
        let base_url = format!("http://127.0.0.1:{port}");

        let vault = MockCredentialVault::new();
        vault
            .store("test.whoop.conn1", "access_token", &SecretString::new("old_access_token".to_string()))
            .unwrap();
        vault
            .store("test.whoop.conn1", "refresh_token", &SecretString::new("stored_refresh_token".to_string()))
            .unwrap();

        let token_client = MockTokenExchangeClient::new();
        token_client.queue_response(Ok(crate::adapters::TokenResponse {
            access_token: SecretString::new("new_access_token".to_string()),
            refresh_token: None,
            expires_in_secs: 3600,
            scope: None,
        }));

        let coordinator = RefreshCoordinator::new();
        let sleeper = MockSleeper::new();

        // idx 0 (sleep) -> base_time (not due: expires in 60min, REFRESH_LEAD_TIME=5min).
        // idx 1 (recovery) -> base_time+70min (due; triggers the ONE refresh).
        //   store_response() computes the new expiry from REAL SystemTime::now()
        //   (+3600s), not from this mock clock — so after the refresh, "due" is
        //   relative to ~real_now+55min, not to base_time+65min.
        // idx 2,3 (cycle/workout) -> back to base_time — comfortably below the new
        //   due threshold, so should_refresh() returns false and refresh is NOT
        //   triggered again (this is what proves "refresh happens exactly once").
        let base_time = SystemTime::now();
        let clock = SteppingClock::new(vec![
            base_time,
            base_time + Duration::from_secs(70 * 60),
            base_time,
            base_time,
        ]);
        let expires_at = base_time.checked_add(Duration::from_secs(3600)).unwrap();

        let api_client = WhoopApiClient::new();
        let throttle = crate::core::connectors::rate_limiter::PacedThrottle::new(100, Duration::from_secs(60));

        let session = WhoopSyncSession::new_with_urls(
            &vault,
            &token_client,
            &coordinator,
            &sleeper,
            &clock,
            &api_client,
            &throttle,
            &base_url,
            "https://api.prod.whoop.com/oauth/oauth2/token",
        );

        let dir = tempfile::tempdir().unwrap();
        let atomic = crate::adapters::MacAtomicFileWriter::new();
        let writer = CsvWriter::new(&atomic);

        let request = WhoopSyncRequest {
            connection_id: "conn1".to_string(),
            service: "test.whoop.conn1".to_string(),
            client_id: "whoop_client_id".to_string(),
            client_secret: None,
            time_range: (Utc::now() - chrono::Duration::days(1), Utc::now()),
            expires_at,
            target_dir: dir.path().to_path_buf(),
        };

        let result = session.sync(request, &writer);
        assert!(result.is_ok(), "sync should succeed across a token-expiry boundary, got {result:?}");

        // Refresh triggered exactly once, not once per remaining endpoint.
        assert_eq!(token_client.call_count(), 1, "refresh_token should be called exactly once");

        // Exactly 4 HTTP requests reached the mock WHOOP API (one per endpoint, no retries).
        let auth_headers = captured.lock().unwrap().clone();
        assert_eq!(auth_headers.len(), 4, "expected exactly 4 requests (sleep, recovery, cycle, workout)");

        assert_eq!(
            auth_headers[0].as_deref(),
            Some("Bearer old_access_token"),
            "sleep request (before refresh) must use the OLD token"
        );
        for (i, label) in [(1, "recovery"), (2, "cycle"), (3, "workout")] {
            assert_eq!(
                auth_headers[i].as_deref(),
                Some("Bearer new_access_token"),
                "{label} request (after mid-sync refresh) must use the NEW token"
            );
        }
    }

    /// ADR-020 (sync atomicity contract): if ANY of the 4 endpoint fetches fails
    /// after exhausting retries, NO CSV file is written to disk — not even for
    /// endpoints that fetched successfully before the failing one.
    #[test]
    fn test_sync_fetch_failure_writes_nothing() {
        // sleep, recovery, cycle succeed; workout returns 500 on all 3 retry attempts
        // (backoff 2s/4s/8s — MockSleeper doesn't actually sleep, so this is fast).
        let (port, _captured) = spawn_mock_whoop_sequence(vec![
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
        vault
            .store("test.whoop.conn2", "refresh_token", &SecretString::new("refresh_token".to_string()))
            .unwrap();

        let token_client = MockTokenExchangeClient::new();
        let coordinator = RefreshCoordinator::new();
        let sleeper = MockSleeper::new();
        let clock = RealClock;
        let api_client = WhoopApiClient::new();
        let throttle = crate::core::connectors::rate_limiter::PacedThrottle::new(100, Duration::from_secs(60));

        let session = WhoopSyncSession::new_with_urls(
            &vault,
            &token_client,
            &coordinator,
            &sleeper,
            &clock,
            &api_client,
            &throttle,
            &base_url,
            "https://api.prod.whoop.com/oauth/oauth2/token",
        );

        let dir = tempfile::tempdir().unwrap();
        let atomic = crate::adapters::MacAtomicFileWriter::new();
        let writer = CsvWriter::new(&atomic);

        let request = WhoopSyncRequest {
            connection_id: "conn2".to_string(),
            service: "test.whoop.conn2".to_string(),
            client_id: "whoop_client_id".to_string(),
            client_secret: None,
            // expires far in the future — no refresh should trigger in this test.
            expires_at: SystemTime::now() + Duration::from_secs(7200),
            time_range: (Utc::now() - chrono::Duration::days(1), Utc::now()),
            target_dir: dir.path().to_path_buf(),
        };

        let result = session.sync(request, &writer);
        assert!(
            matches!(result, Err(WhoopSyncError::ServerErrorExhausted)),
            "expected ServerErrorExhausted after workout endpoint exhausts retries, got {result:?}"
        );

        for csv_name in ["sleep.csv", "recovery.csv", "cycles.csv", "workouts.csv"] {
            assert!(
                !dir.path().join(csv_name).exists(),
                "{csv_name} must NOT be written when any endpoint fetch fails (ADR-020 atomicity)"
            );
        }
    }

    /// D-008 (provayders don't mix in CSV/folders): proves that WhoopSyncSession
    /// has no hardcoded shared/default target_dir — each sync() call writes
    /// exclusively to the request.target_dir. Two different target_dir values
    /// (simulating future WHOOP vs Oura connectors, or two different WHOOP connections)
    /// physically do not intersect on disk.
    #[test]
    fn test_sync_writes_only_to_request_target_dir_no_cross_contamination() {
        // Mock WHOOP sequence: 4 empty responses (sleep, recovery, cycle, workout)
        let (port, _captured) = spawn_mock_whoop_sequence(vec![
            (200, r#"{"records":[],"next_token":null}"#), // sleep
            (200, r#"{"records":[],"next_token":null}"#), // recovery
            (200, r#"{"records":[],"next_token":null}"#), // cycle
            (200, r#"{"records":[],"next_token":null}"#), // workout
        ]);
        let base_url = format!("http://127.0.0.1:{port}");

        // Setup vault and other mocks
        let vault = MockCredentialVault::new();
        vault
            .store("test.whoop.conn_isolation", "access_token", &SecretString::new("access_token".to_string()))
            .unwrap();
        vault
            .store("test.whoop.conn_isolation", "refresh_token", &SecretString::new("refresh_token".to_string()))
            .unwrap();

        let token_client = MockTokenExchangeClient::new();
        let coordinator = RefreshCoordinator::new();
        let sleeper = MockSleeper::new();
        let clock = RealClock;
        let api_client = WhoopApiClient::new();
        let throttle = crate::core::connectors::rate_limiter::PacedThrottle::new(100, Duration::from_secs(60));

        let session = WhoopSyncSession::new_with_urls(
            &vault,
            &token_client,
            &coordinator,
            &sleeper,
            &clock,
            &api_client,
            &throttle,
            &base_url,
            "https://api.prod.whoop.com/oauth/oauth2/token",
        );

        // Create TWO separate directories to simulate two different connections
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();

        let atomic = crate::adapters::MacAtomicFileWriter::new();
        let writer = CsvWriter::new(&atomic);

        // Sync to dir_a
        let request = WhoopSyncRequest {
            connection_id: "conn_isolation".to_string(),
            service: "test.whoop.conn_isolation".to_string(),
            client_id: "whoop_client_id".to_string(),
            client_secret: None,
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            time_range: (Utc::now() - chrono::Duration::days(1), Utc::now()),
            target_dir: dir_a.path().to_path_buf(),
        };

        let result = session.sync(request, &writer);
        assert!(result.is_ok(), "sync to dir_a should succeed, got {result:?}");

        // Assert: dir_a contains all 4 CSV files
        for csv_name in ["sleep.csv", "recovery.csv", "cycles.csv", "workouts.csv"] {
            assert!(
                dir_a.path().join(csv_name).exists(),
                "{csv_name} must be written to dir_a (the sync request target)"
            );
        }

        // Assert: dir_b is completely empty (never passed to sync, so nothing written there)
        let dir_b_contents: Vec<_> = std::fs::read_dir(dir_b.path())
            .expect("read dir_b")
            .collect();
        assert!(
            dir_b_contents.is_empty(),
            "dir_b (never passed to sync) must remain empty, but found: {:?}",
            dir_b_contents
        );
    }
}
