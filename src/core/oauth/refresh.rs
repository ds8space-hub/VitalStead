//! OAuth token refresh orchestration — T-203, EPIC-03-oauth.md.
//!
//! Implements automatic token refresh with concurrency exclusion (mutex-protected per
//! connection) and exponential backoff retry logic. The refresh orchestrator handles:
//! 1. Retrieving stored refresh tokens from the vault
//! 2. Calling the token exchange client
//! 3. Storing updated tokens atomically
//! 4. Retrying transient errors (network, rate limit, 5xx) with appropriate backoff
//! 5. Mapping `invalid_grant` to `ReauthorizationRequired` (not a failure state)
//! 6. Caching outcomes per connection to prevent duplicate network calls
//!
//! No platform-specific code; no references to `core::csv` (credentials-and-security.md L49).
//! Composed at the application layer via RefreshOrchestrator.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crate::adapters::{CredentialVault, RefreshTokenParams, TokenExchangeClient, TokenExchangeError, VaultError};
use crate::core::security::SecretString;

/// Token refresh lead time — how far before expiry to trigger a refresh (credentials-and-security.md L44).
///
/// "например за пять минут" (for example, five minutes) — the exact value is locked to 5 minutes.
pub const REFRESH_LEAD_TIME: Duration = Duration::from_secs(5 * 60);

/// Check if a token refresh is due based on expiry time and current time.
///
/// A refresh is due if `now >= (expires_at - REFRESH_LEAD_TIME)`.
/// This ensures we refresh proactively, not reactively when the token has just expired.
pub fn is_refresh_due(expires_at: SystemTime, now: SystemTime) -> bool {
    match expires_at.checked_sub(REFRESH_LEAD_TIME) {
        Some(due_at) => now >= due_at,
        None => true, // If lead time is larger than expires_at, always refresh
    }
}

/// Testability seam for backoff sleep duration — abstraction of `std::thread::sleep`.
///
/// Not a T-006 platform adapter (nothing OS-specific here); lives in core/oauth as a
/// pure DI seam for orchestration testing. Allows tests to record sleep durations
/// without actually blocking execution.
pub trait BackoffSleeper: Send + Sync {
    /// Sleep for the given duration.
    fn sleep(&self, duration: Duration);
}

/// Real implementation that delegates to `std::thread::sleep`.
pub struct RealSleeper;

impl BackoffSleeper for RealSleeper {
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Outcome of a refresh attempt — either successful refresh or reauthorization required.
///
/// `ReauthorizationRequired` maps `invalid_grant`, which is not treated as a failure
/// state (credentials-and-security.md L49) — it's a transition to a different state
/// in the connection state machine (ReauthorizationRequired).
#[derive(Debug, Clone, PartialEq)]
pub enum RefreshOutcome {
    /// Token successfully refreshed and stored.
    Refreshed {
        /// Whether the access token was stored (always true on success).
        access_token_stored: bool,
        /// Whether the refresh token was rotated (provider-dependent, per credentials-and-security.md L46).
        refresh_token_rotated: bool,
        /// New expiry timestamp for the new access token.
        expires_at: SystemTime,
    },
    /// Refresh token expired or revoked — reauthorization required.
    ///
    /// Maps `TokenExchangeError::InvalidGrant` (OAuth spec). Not retried.
    /// Application logic transitions to `ConnectionState::ReauthorizationRequired`.
    ReauthorizationRequired,
}

/// Error type for refresh operations — represents failure modes after all retries exhausted.
#[derive(Debug, Clone, PartialEq)]
pub enum RefreshError {
    /// Network errors exhausted (3 attempts with backoff 1s, 2s, 4s).
    NetworkExhausted,
    /// Rate limit errors exhausted (5 attempts with backoff per Retry-After or default table).
    RateLimitExhausted,
    /// Server errors (5xx) exhausted (3 attempts with backoff 2s, 4s, 8s).
    ServerErrorExhausted,
    /// Client error (4xx, not `invalid_grant`) — not retried.
    ClientError { status: u16, error: Option<String> },
    /// Vault (credential storage) error — not retried.
    Vault(VaultError),
}

/// Request to refresh a token — input to the orchestrator.
///
/// Supplies all parameters needed for a refresh operation: connection identity,
/// token endpoint details, and expiry tracking.
#[derive(Clone)]
pub struct RefreshRequest {
    /// Unique connection identifier (e.g., "conn_a1b2c3d4").
    pub connection_id: String,
    /// Vault namespace (T-201 §3.1 format: `{bundle_id}.{provider}.{connection_id}`).
    pub service: String,
    /// OAuth token endpoint URL.
    pub token_endpoint: String,
    /// OAuth client identifier.
    pub client_id: String,
    /// OAuth client secret (if applicable).
    pub client_secret: Option<SecretString>,
    /// Current expiry time of the access token.
    ///
    /// Expiry storage and tracking are outside T-203 scope; caller provides this
    /// and receives the new expiry time in the `Refreshed` outcome.
    pub expires_at: SystemTime,
}

/// Concurrency coordination for refresh operations.
///
/// Maintains per-connection mutexes to ensure that concurrent refresh calls for the
/// same connection are serialized and deduplicated. The first caller holds the lock,
/// executes the network request, and caches the outcome. The second caller waits on
/// the same lock, then reads the cached outcome instead of hitting the network again.
///
/// This is the mechanism for "параллельный refresh исключён" (parallel refresh excluded) —
/// not just serialized, but deduplicated.
pub struct RefreshCoordinator {
    /// Map from connection_id to per-connection lock wrapping cached outcome.
    ///
    /// Arc<Mutex<Option<RefreshOutcome>>> allows:
    /// - Multiple RefreshOrchestrator instances (via Arc)
    /// - Mutex to serialize concurrent calls
    /// - Option to represent "no cached outcome yet" vs "outcome cached"
    locks: Mutex<HashMap<String, Arc<Mutex<Option<RefreshOutcome>>>>>,
}

impl RefreshCoordinator {
    /// Create a new refresh coordinator.
    pub fn new() -> Self {
        RefreshCoordinator {
            locks: Mutex::new(HashMap::new()),
        }
    }

    /// Retrieve or create the per-connection lock.
    fn lock_for(&self, connection_id: &str) -> Arc<Mutex<Option<RefreshOutcome>>> {
        let mut map = self.locks.lock().expect("coordinator lock poisoned");
        map.entry(connection_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(None)))
            .clone()
    }

    /// Clear cached outcome for a connection — used when transitioning from
    /// `AuthorizationPending` to `Connected` after reauthorization.
    ///
    /// Without this, a stale `ReauthorizationRequired` cached from a previous
    /// failed refresh would be returned forever.
    pub fn clear(&self, connection_id: &str) {
        if let Some(lock) = self.locks.lock().expect("coordinator lock poisoned").get(connection_id) {
            *lock.lock().expect("per-connection lock poisoned") = None;
        }
    }
}

impl Default for RefreshCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

/// OAuth token refresh orchestrator.
///
/// Composes the vault, token exchange client, concurrency coordinator, and backoff sleeper
/// to implement the full refresh orchestration logic. Created at the application layer with
/// injected dependencies.
pub struct RefreshOrchestrator<'a> {
    vault: &'a dyn CredentialVault,
    token_client: &'a dyn TokenExchangeClient,
    coordinator: &'a RefreshCoordinator,
    sleeper: &'a dyn BackoffSleeper,
}

impl<'a> RefreshOrchestrator<'a> {
    /// Create a new refresh orchestrator with the given dependencies.
    pub fn new(
        vault: &'a dyn CredentialVault,
        token_client: &'a dyn TokenExchangeClient,
        coordinator: &'a RefreshCoordinator,
        sleeper: &'a dyn BackoffSleeper,
    ) -> Self {
        RefreshOrchestrator {
            vault,
            token_client,
            coordinator,
            sleeper,
        }
    }

    /// Execute a refresh operation, handling concurrency, retry, and caching.
    ///
    /// # Concurrency model
    ///
    /// - First caller: acquires per-connection lock, executes refresh, caches outcome
    /// - Concurrent callers: block on lock, read cached outcome when first completes
    /// - Result: network call happens exactly once; deduplication (not just serialization)
    ///
    /// # Caching
    ///
    /// Outcomes are cached until `RefreshCoordinator::clear()` is called.
    /// - `Refreshed{expires_at}` — cache remains valid until the new token expires
    ///   (caller re-checks `is_refresh_due` before reading cache)
    /// - `ReauthorizationRequired` — cache remains valid until coordinator.clear() (user reconnects)
    ///
    /// # Retry logic
    ///
    /// Transient errors are retried with exponential backoff:
    /// - Network: 3 attempts (1s, 2s, 4s)
    /// - Rate limit: 5 attempts (2s, 4s, 8s, 16s, 32s; capped at 60s; can override via Retry-After)
    /// - Server error: 3 attempts (2s, 4s, 8s)
    ///
    /// Non-retryable errors fail immediately:
    /// - invalid_grant → RefreshOutcome::ReauthorizationRequired
    /// - ClientError (4xx) → RefreshError::ClientError
    /// - Vault errors → RefreshError::Vault
    ///
    /// # Arguments
    ///
    /// * `request` - Refresh request with connection details and token endpoint
    /// * `now` - Current time for cache validity checks
    ///
    /// # Returns
    ///
    /// - `Ok(RefreshOutcome)` — token refreshed or reauthorization required
    /// - `Err(RefreshError)` — irrecoverable error after retries or vault operation
    pub fn refresh(
        &self,
        request: RefreshRequest,
        now: SystemTime,
    ) -> Result<RefreshOutcome, RefreshError> {
        let lock = self.coordinator.lock_for(&request.connection_id);
        let mut cached = lock.lock().expect("per-connection lock poisoned");

        // Return cached outcome if still valid
        if let Some(outcome) = cached.as_ref() {
            let still_valid = match outcome {
                RefreshOutcome::Refreshed { expires_at, .. } => !is_refresh_due(*expires_at, now),
                RefreshOutcome::ReauthorizationRequired => true,
            };
            if still_valid {
                return Ok(outcome.clone());
            }
        }

        // Retrieve stored refresh token
        let refresh_token = self
            .vault
            .retrieve(&request.service, "refresh_token")
            .map_err(RefreshError::Vault)?;

        // Execute refresh with retry logic
        let outcome = self.do_refresh_with_retry(&request, refresh_token)?;
        *cached = Some(outcome.clone());
        Ok(outcome)
    }

    /// Execute the refresh operation with exponential backoff retry logic.
    fn do_refresh_with_retry(
        &self,
        request: &RefreshRequest,
        refresh_token: SecretString,
    ) -> Result<RefreshOutcome, RefreshError> {
        let mut network_attempts = 0u32;
        let mut rate_limit_attempts = 0u32;
        let mut server_error_attempts = 0u32;

        loop {
            let params = RefreshTokenParams {
                token_endpoint: request.token_endpoint.clone(),
                client_id: request.client_id.clone(),
                client_secret: request.client_secret.clone(),
                refresh_token: refresh_token.clone(),
            };

            match self.token_client.refresh_token(params) {
                Ok(response) => {
                    return self.store_response(request, response);
                }
                Err(TokenExchangeError::InvalidGrant) => {
                    return Ok(RefreshOutcome::ReauthorizationRequired);
                }
                Err(TokenExchangeError::ClientError { status, error }) => {
                    return Err(RefreshError::ClientError { status, error });
                }
                Err(TokenExchangeError::Network(_)) => {
                    network_attempts += 1;
                    if network_attempts > 3 {
                        return Err(RefreshError::NetworkExhausted);
                    }
                    let backoff_secs = match network_attempts {
                        1 => 1,
                        2 => 2,
                        _ => 4,
                    };
                    self.sleeper.sleep(Duration::from_secs(backoff_secs));
                }
                Err(TokenExchangeError::ServerError(_)) => {
                    server_error_attempts += 1;
                    if server_error_attempts > 3 {
                        return Err(RefreshError::ServerErrorExhausted);
                    }
                    let backoff_secs = match server_error_attempts {
                        1 => 2,
                        2 => 4,
                        _ => 8,
                    };
                    self.sleeper.sleep(Duration::from_secs(backoff_secs));
                }
                Err(TokenExchangeError::RateLimited { retry_after_secs }) => {
                    rate_limit_attempts += 1;
                    if rate_limit_attempts > 5 {
                        return Err(RefreshError::RateLimitExhausted);
                    }
                    let backoff = retry_after_secs.unwrap_or_else(|| {
                        match rate_limit_attempts {
                            1 => 2,
                            2 => 4,
                            3 => 8,
                            4 => 16,
                            _ => 32,
                        }
                    })
                    .min(60);
                    self.sleeper.sleep(Duration::from_secs(backoff));
                }
            }
        }
    }

    /// Store the refreshed tokens in the vault and return the outcome.
    fn store_response(
        &self,
        request: &RefreshRequest,
        response: crate::adapters::TokenResponse,
    ) -> Result<RefreshOutcome, RefreshError> {
        // Store new access token
        self.vault
            .store(&request.service, "access_token", &response.access_token)
            .map_err(RefreshError::Vault)?;

        let rotated = response.refresh_token.is_some();
        if let Some(new_refresh_token) = &response.refresh_token {
            // Atomic overwrite of refresh token (old value never deleted separately)
            // per credentials-and-security.md L46.
            self.vault
                .store(&request.service, "refresh_token", new_refresh_token)
                .map_err(RefreshError::Vault)?;
        }

        let expires_at = SystemTime::now() + Duration::from_secs(response.expires_in_secs);
        Ok(RefreshOutcome::Refreshed {
            access_token_stored: true,
            refresh_token_rotated: rotated,
            expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Mock credential vault for testing.
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
                .expect("data lock poisoned")
                .insert((service.to_string(), key.to_string()), value.clone());
            Ok(())
        }

        fn retrieve(&self, service: &str, key: &str) -> Result<SecretString, VaultError> {
            self.data
                .lock()
                .expect("data lock poisoned")
                .get(&(service.to_string(), key.to_string()))
                .cloned()
                .ok_or(VaultError::NotFound)
        }

        fn delete(&self, service: &str, key: &str) -> Result<(), VaultError> {
            self.data
                .lock()
                .expect("data lock poisoned")
                .remove(&(service.to_string(), key.to_string()))
                .ok_or(VaultError::NotFound)
                .map(|_| ())
        }

        fn delete_all_for_connection(&self, service: &str) -> Result<(), VaultError> {
            let mut data = self.data.lock().expect("data lock poisoned");
            let keys_to_remove: Vec<_> = data
                .keys()
                .filter(|(s, _)| s == service)
                .cloned()
                .collect();
            for key in keys_to_remove {
                data.remove(&key);
            }
            Ok(())
        }
    }

    /// Mock token exchange client for testing.
    struct MockTokenExchangeClient {
        responses: Mutex<VecDeque<Result<crate::adapters::TokenResponse, TokenExchangeError>>>,
        call_count: Mutex<u32>,
    }

    impl MockTokenExchangeClient {
        fn new() -> Self {
            MockTokenExchangeClient {
                responses: Mutex::new(VecDeque::new()),
                call_count: Mutex::new(0),
            }
        }

        fn queue_response(&self, response: Result<crate::adapters::TokenResponse, TokenExchangeError>) {
            self.responses.lock().expect("responses lock poisoned").push_back(response);
        }

        fn call_count(&self) -> u32 {
            *self.call_count.lock().expect("call_count lock poisoned")
        }
    }

    impl TokenExchangeClient for MockTokenExchangeClient {
        fn exchange_code(
            &self,
            _params: crate::adapters::ExchangeCodeParams,
        ) -> Result<crate::adapters::TokenResponse, TokenExchangeError> {
            unreachable!("exchange_code not used in T-203 tests")
        }

        fn refresh_token(
            &self,
            _params: RefreshTokenParams,
        ) -> Result<crate::adapters::TokenResponse, TokenExchangeError> {
            *self.call_count.lock().expect("call_count lock poisoned") += 1;
            self.responses
                .lock()
                .expect("responses lock poisoned")
                .pop_front()
                .unwrap_or_else(|| Err(TokenExchangeError::Network("no response queued".to_string())))
        }

        fn revoke_token(
            &self,
            _params: crate::adapters::RevokeTokenParams,
        ) -> Result<(), TokenExchangeError> {
            unreachable!("revoke_token not used in T-203 tests")
        }
    }

    /// Mock sleeper that records sleep durations without actually blocking.
    struct NoopSleeper {
        sleeps: Mutex<Vec<Duration>>,
    }

    impl NoopSleeper {
        fn new() -> Self {
            NoopSleeper {
                sleeps: Mutex::new(Vec::new()),
            }
        }

        fn sleeps(&self) -> Vec<Duration> {
            self.sleeps.lock().expect("sleeps lock poisoned").clone()
        }
    }

    impl BackoffSleeper for NoopSleeper {
        fn sleep(&self, duration: Duration) {
            self.sleeps.lock().expect("sleeps lock poisoned").push(duration);
        }
    }

    // T1: is_refresh_due returns true past lead time
    #[test]
    fn test_is_refresh_due_true_past_lead_time() {
        let now = SystemTime::now();
        let expires_at = now + Duration::from_secs(4 * 60); // 4 minutes from now
        assert!(is_refresh_due(expires_at, now)); // 4 min < 5 min lead time
    }

    // T2: is_refresh_due returns false before lead time
    #[test]
    fn test_is_refresh_due_false_before_lead_time() {
        let now = SystemTime::now();
        let expires_at = now + Duration::from_secs(6 * 60); // 6 minutes from now
        assert!(!is_refresh_due(expires_at, now)); // 6 min > 5 min lead time
    }

    // T3: refresh stores new access token
    #[test]
    fn test_refresh_stores_new_access_token() {
        let vault = MockCredentialVault::new();
        let client = MockTokenExchangeClient::new();
        let coordinator = RefreshCoordinator::new();
        let sleeper = NoopSleeper::new();

        let new_token = SecretString::new("new_access_token_123".to_string());
        client.queue_response(Ok(crate::adapters::TokenResponse {
            access_token: new_token.clone(),
            refresh_token: None,
            expires_in_secs: 3600,
            scope: None,
        }));

        vault
            .store("test.oura.conn1", "refresh_token", &SecretString::new("stored_refresh".to_string()))
            .unwrap();

        let orchestrator = RefreshOrchestrator::new(&vault, &client, &coordinator, &sleeper);
        let request = RefreshRequest {
            connection_id: "conn1".to_string(),
            service: "test.oura.conn1".to_string(),
            token_endpoint: "https://api.oura.cloud/oauth/token".to_string(),
            client_id: "test_client".to_string(),
            client_secret: None,
            expires_at: SystemTime::now() + Duration::from_secs(100),
        };

        let result = orchestrator.refresh(request, SystemTime::now()).unwrap();
        assert_eq!(
            vault
                .retrieve("test.oura.conn1", "access_token")
                .unwrap()
                .expose_secret(),
            "new_access_token_123"
        );
        assert!(matches!(
            result,
            RefreshOutcome::Refreshed {
                refresh_token_rotated: false,
                ..
            }
        ));
    }

    // T4: refresh rotates refresh token atomically
    #[test]
    fn test_refresh_rotates_refresh_token_atomically() {
        let vault = MockCredentialVault::new();
        let client = MockTokenExchangeClient::new();
        let coordinator = RefreshCoordinator::new();
        let sleeper = NoopSleeper::new();

        let new_access = SecretString::new("new_access_456".to_string());
        let new_refresh = SecretString::new("new_refresh_789".to_string());
        client.queue_response(Ok(crate::adapters::TokenResponse {
            access_token: new_access.clone(),
            refresh_token: Some(new_refresh.clone()),
            expires_in_secs: 3600,
            scope: None,
        }));

        vault
            .store("test.oura.conn2", "refresh_token", &SecretString::new("old_refresh".to_string()))
            .unwrap();

        let orchestrator = RefreshOrchestrator::new(&vault, &client, &coordinator, &sleeper);
        let request = RefreshRequest {
            connection_id: "conn2".to_string(),
            service: "test.oura.conn2".to_string(),
            token_endpoint: "https://api.oura.cloud/oauth/token".to_string(),
            client_id: "test_client".to_string(),
            client_secret: None,
            expires_at: SystemTime::now() + Duration::from_secs(100),
        };

        let result = orchestrator.refresh(request, SystemTime::now()).unwrap();
        assert_eq!(
            vault
                .retrieve("test.oura.conn2", "refresh_token")
                .unwrap()
                .expose_secret(),
            "new_refresh_789"
        );
        assert!(matches!(
            result,
            RefreshOutcome::Refreshed {
                refresh_token_rotated: true,
                ..
            }
        ));
    }

    // T5: concurrent refresh calls dedupe single network call
    #[test]
    fn test_concurrent_refresh_calls_dedupe_single_network_call() {
        use std::thread;

        let vault = Arc::new(MockCredentialVault::new());
        let client = Arc::new(MockTokenExchangeClient::new());
        let coordinator = Arc::new(RefreshCoordinator::new());
        let sleeper = Arc::new(NoopSleeper::new());

        let new_token = SecretString::new("concurrent_token".to_string());
        client.queue_response(Ok(crate::adapters::TokenResponse {
            access_token: new_token.clone(),
            refresh_token: None,
            expires_in_secs: 3600,
            scope: None,
        }));

        vault
            .store("test.oura.conn3", "refresh_token", &SecretString::new("stored_refresh".to_string()))
            .unwrap();

        let mut handles = vec![];

        for _ in 0..2 {
            let vault = vault.clone();
            let client = client.clone();
            let coordinator = coordinator.clone();
            let sleeper = sleeper.clone();

            let handle = thread::spawn(move || {
                let orchestrator = RefreshOrchestrator::new(
                    vault.as_ref(),
                    client.as_ref(),
                    coordinator.as_ref(),
                    sleeper.as_ref(),
                );
                let request = RefreshRequest {
                    connection_id: "conn3".to_string(),
                    service: "test.oura.conn3".to_string(),
                    token_endpoint: "https://api.oura.cloud/oauth/token".to_string(),
                    client_id: "test_client".to_string(),
                    client_secret: None,
                    expires_at: SystemTime::now() + Duration::from_secs(100),
                };

                orchestrator.refresh(request, SystemTime::now())
            });

            handles.push(handle);
        }

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Both threads should get Ok results
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());

        // Mock should have been called exactly once (deduplication)
        assert_eq!(client.call_count(), 1);

        // Both results should be identical
        assert_eq!(results[0], results[1]);
    }

    // T6: invalid_grant maps to reauthorization required
    #[test]
    fn test_invalid_grant_maps_to_reauthorization_required() {
        let vault = MockCredentialVault::new();
        let client = MockTokenExchangeClient::new();
        let coordinator = RefreshCoordinator::new();
        let sleeper = NoopSleeper::new();

        client.queue_response(Err(TokenExchangeError::InvalidGrant));

        vault
            .store("test.oura.conn4", "refresh_token", &SecretString::new("stored_refresh".to_string()))
            .unwrap();

        let orchestrator = RefreshOrchestrator::new(&vault, &client, &coordinator, &sleeper);
        let request = RefreshRequest {
            connection_id: "conn4".to_string(),
            service: "test.oura.conn4".to_string(),
            token_endpoint: "https://api.oura.cloud/oauth/token".to_string(),
            client_id: "test_client".to_string(),
            client_secret: None,
            expires_at: SystemTime::now() + Duration::from_secs(100),
        };

        let result = orchestrator.refresh(request, SystemTime::now()).unwrap();
        assert_eq!(result, RefreshOutcome::ReauthorizationRequired);
    }

    // T7: network error retries with locked backoff then succeeds
    #[test]
    fn test_network_error_retries_with_locked_backoff_then_succeeds() {
        let vault = MockCredentialVault::new();
        let client = MockTokenExchangeClient::new();
        let coordinator = RefreshCoordinator::new();
        let sleeper = NoopSleeper::new();

        client.queue_response(Err(TokenExchangeError::Network("timeout".to_string())));
        client.queue_response(Err(TokenExchangeError::Network("timeout".to_string())));
        let new_token = SecretString::new("recovered_token".to_string());
        client.queue_response(Ok(crate::adapters::TokenResponse {
            access_token: new_token,
            refresh_token: None,
            expires_in_secs: 3600,
            scope: None,
        }));

        vault
            .store("test.oura.conn5", "refresh_token", &SecretString::new("stored_refresh".to_string()))
            .unwrap();

        let orchestrator = RefreshOrchestrator::new(&vault, &client, &coordinator, &sleeper);
        let request = RefreshRequest {
            connection_id: "conn5".to_string(),
            service: "test.oura.conn5".to_string(),
            token_endpoint: "https://api.oura.cloud/oauth/token".to_string(),
            client_id: "test_client".to_string(),
            client_secret: None,
            expires_at: SystemTime::now() + Duration::from_secs(100),
        };

        let result = orchestrator.refresh(request, SystemTime::now()).unwrap();
        assert!(matches!(result, RefreshOutcome::Refreshed { .. }));
        assert_eq!(sleeper.sleeps(), vec![Duration::from_secs(1), Duration::from_secs(2)]);
        assert_eq!(client.call_count(), 3);
    }

    // T8: network error exhausts after max retries
    #[test]
    fn test_network_error_exhausts_after_max_retries() {
        let vault = MockCredentialVault::new();
        let client = MockTokenExchangeClient::new();
        let coordinator = RefreshCoordinator::new();
        let sleeper = NoopSleeper::new();

        for _ in 0..4 {
            client.queue_response(Err(TokenExchangeError::Network("timeout".to_string())));
        }

        vault
            .store("test.oura.conn6", "refresh_token", &SecretString::new("stored_refresh".to_string()))
            .unwrap();

        let orchestrator = RefreshOrchestrator::new(&vault, &client, &coordinator, &sleeper);
        let request = RefreshRequest {
            connection_id: "conn6".to_string(),
            service: "test.oura.conn6".to_string(),
            token_endpoint: "https://api.oura.cloud/oauth/token".to_string(),
            client_id: "test_client".to_string(),
            client_secret: None,
            expires_at: SystemTime::now() + Duration::from_secs(100),
        };

        let result = orchestrator.refresh(request, SystemTime::now());
        assert!(matches!(result, Err(RefreshError::NetworkExhausted)));
        assert_eq!(sleeper.sleeps(), vec![
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(4)
        ]);
        assert_eq!(client.call_count(), 4);
    }

    // T9: rate limit respects retry after header
    #[test]
    fn test_rate_limit_respects_retry_after_header() {
        let vault = MockCredentialVault::new();
        let client = MockTokenExchangeClient::new();
        let coordinator = RefreshCoordinator::new();
        let sleeper = NoopSleeper::new();

        client.queue_response(Err(TokenExchangeError::RateLimited {
            retry_after_secs: Some(3),
        }));
        let new_token = SecretString::new("rate_limited_token".to_string());
        client.queue_response(Ok(crate::adapters::TokenResponse {
            access_token: new_token,
            refresh_token: None,
            expires_in_secs: 3600,
            scope: None,
        }));

        vault
            .store("test.oura.conn7", "refresh_token", &SecretString::new("stored_refresh".to_string()))
            .unwrap();

        let orchestrator = RefreshOrchestrator::new(&vault, &client, &coordinator, &sleeper);
        let request = RefreshRequest {
            connection_id: "conn7".to_string(),
            service: "test.oura.conn7".to_string(),
            token_endpoint: "https://api.oura.cloud/oauth/token".to_string(),
            client_id: "test_client".to_string(),
            client_secret: None,
            expires_at: SystemTime::now() + Duration::from_secs(100),
        };

        let result = orchestrator.refresh(request, SystemTime::now()).unwrap();
        assert!(matches!(result, RefreshOutcome::Refreshed { .. }));
        assert_eq!(sleeper.sleeps(), vec![Duration::from_secs(3)]);
        assert_eq!(client.call_count(), 2);
    }

    // T10: rate limit exhausts after max retries
    #[test]
    fn test_rate_limit_exhausts_after_max_retries() {
        let vault = MockCredentialVault::new();
        let client = MockTokenExchangeClient::new();
        let coordinator = RefreshCoordinator::new();
        let sleeper = NoopSleeper::new();

        for _ in 0..6 {
            client.queue_response(Err(TokenExchangeError::RateLimited {
                retry_after_secs: None,
            }));
        }

        vault
            .store("test.oura.conn8", "refresh_token", &SecretString::new("stored_refresh".to_string()))
            .unwrap();

        let orchestrator = RefreshOrchestrator::new(&vault, &client, &coordinator, &sleeper);
        let request = RefreshRequest {
            connection_id: "conn8".to_string(),
            service: "test.oura.conn8".to_string(),
            token_endpoint: "https://api.oura.cloud/oauth/token".to_string(),
            client_id: "test_client".to_string(),
            client_secret: None,
            expires_at: SystemTime::now() + Duration::from_secs(100),
        };

        let result = orchestrator.refresh(request, SystemTime::now());
        assert!(matches!(result, Err(RefreshError::RateLimitExhausted)));
        assert_eq!(sleeper.sleeps(), vec![
            Duration::from_secs(2),
            Duration::from_secs(4),
            Duration::from_secs(8),
            Duration::from_secs(16),
            Duration::from_secs(32)
        ]);
        assert_eq!(client.call_count(), 6);
    }

    // T11: server error retries then exhausts
    #[test]
    fn test_server_error_retries_then_exhausts() {
        let vault = MockCredentialVault::new();
        let client = MockTokenExchangeClient::new();
        let coordinator = RefreshCoordinator::new();
        let sleeper = NoopSleeper::new();

        for _ in 0..4 {
            client.queue_response(Err(TokenExchangeError::ServerError(503)));
        }

        vault
            .store("test.oura.conn9", "refresh_token", &SecretString::new("stored_refresh".to_string()))
            .unwrap();

        let orchestrator = RefreshOrchestrator::new(&vault, &client, &coordinator, &sleeper);
        let request = RefreshRequest {
            connection_id: "conn9".to_string(),
            service: "test.oura.conn9".to_string(),
            token_endpoint: "https://api.oura.cloud/oauth/token".to_string(),
            client_id: "test_client".to_string(),
            client_secret: None,
            expires_at: SystemTime::now() + Duration::from_secs(100),
        };

        let result = orchestrator.refresh(request, SystemTime::now());
        assert!(matches!(result, Err(RefreshError::ServerErrorExhausted)));
        assert_eq!(sleeper.sleeps(), vec![
            Duration::from_secs(2),
            Duration::from_secs(4),
            Duration::from_secs(8)
        ]);
    }

    // T12: client error 4xx no retry
    #[test]
    fn test_client_error_4xx_no_retry() {
        let vault = MockCredentialVault::new();
        let client = MockTokenExchangeClient::new();
        let coordinator = RefreshCoordinator::new();
        let sleeper = NoopSleeper::new();

        client.queue_response(Err(TokenExchangeError::ClientError {
            status: 400,
            error: None,
        }));

        vault
            .store("test.oura.conn10", "refresh_token", &SecretString::new("stored_refresh".to_string()))
            .unwrap();

        let orchestrator = RefreshOrchestrator::new(&vault, &client, &coordinator, &sleeper);
        let request = RefreshRequest {
            connection_id: "conn10".to_string(),
            service: "test.oura.conn10".to_string(),
            token_endpoint: "https://api.oura.cloud/oauth/token".to_string(),
            client_id: "test_client".to_string(),
            client_secret: None,
            expires_at: SystemTime::now() + Duration::from_secs(100),
        };

        let result = orchestrator.refresh(request, SystemTime::now());
        assert!(matches!(result, Err(RefreshError::ClientError { status: 400, .. })));
        assert_eq!(sleeper.sleeps(), vec![]);
        assert_eq!(client.call_count(), 1);
    }

    // T13: refresh reuses cached outcome when not yet due again
    #[test]
    fn test_refresh_reuses_cached_outcome_when_not_yet_due_again() {
        let vault = MockCredentialVault::new();
        let client = MockTokenExchangeClient::new();
        let coordinator = RefreshCoordinator::new();
        let sleeper = NoopSleeper::new();

        let new_token = SecretString::new("cached_token".to_string());
        client.queue_response(Ok(crate::adapters::TokenResponse {
            access_token: new_token,
            refresh_token: None,
            expires_in_secs: 3600,
            scope: None,
        }));

        vault
            .store("test.oura.conn11", "refresh_token", &SecretString::new("stored_refresh".to_string()))
            .unwrap();

        let orchestrator = RefreshOrchestrator::new(&vault, &client, &coordinator, &sleeper);
        let now = SystemTime::now();
        let request = RefreshRequest {
            connection_id: "conn11".to_string(),
            service: "test.oura.conn11".to_string(),
            token_endpoint: "https://api.oura.cloud/oauth/token".to_string(),
            client_id: "test_client".to_string(),
            client_secret: None,
            expires_at: now + Duration::from_secs(7200),
        };

        let _result1 = orchestrator.refresh(request.clone(), now).unwrap();
        assert_eq!(client.call_count(), 1);

        let _result2 = orchestrator.refresh(request, now).unwrap();
        assert_eq!(client.call_count(), 1); // Still 1 because cached
    }

    // T14: coordinator clear removes cached outcome
    #[test]
    fn test_coordinator_clear_removes_cached_outcome() {
        let vault = MockCredentialVault::new();
        let client = MockTokenExchangeClient::new();
        let coordinator = RefreshCoordinator::new();
        let sleeper = NoopSleeper::new();

        let new_token = SecretString::new("fresh_token".to_string());
        client.queue_response(Ok(crate::adapters::TokenResponse {
            access_token: new_token.clone(),
            refresh_token: None,
            expires_in_secs: 3600,
            scope: None,
        }));

        let another_token = SecretString::new("another_token".to_string());
        client.queue_response(Ok(crate::adapters::TokenResponse {
            access_token: another_token,
            refresh_token: None,
            expires_in_secs: 3600,
            scope: None,
        }));

        vault
            .store("test.oura.conn12", "refresh_token", &SecretString::new("stored_refresh".to_string()))
            .unwrap();

        let orchestrator = RefreshOrchestrator::new(&vault, &client, &coordinator, &sleeper);
        let now = SystemTime::now();
        let request = RefreshRequest {
            connection_id: "conn12".to_string(),
            service: "test.oura.conn12".to_string(),
            token_endpoint: "https://api.oura.cloud/oauth/token".to_string(),
            client_id: "test_client".to_string(),
            client_secret: None,
            expires_at: now + Duration::from_secs(7200),
        };

        let _result1 = orchestrator.refresh(request.clone(), now).unwrap();
        assert_eq!(client.call_count(), 1);

        coordinator.clear("conn12");

        let _result2 = orchestrator.refresh(request, now).unwrap();
        assert_eq!(client.call_count(), 2); // Network call happened again
    }
}
