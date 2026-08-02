//! WHOOP OAuth authorization flow orchestration (Step 4 — T-401).
//!
//! Manages the OAuth authorization sequence:
//! 1. Generate CSRF state and build authorization URL
//! 2. Listen for OAuth callback on localhost
//! 3. Exchange code for tokens
//! 4. Validate offline scope
//! 5. Store tokens in vault atomically
//!
//! NOTE: Ambient tokio runtime (found on manual e2e verification, T-401) — the real
//! macOS `listen_for_callback` needs an ambient tokio runtime for its internal
//! `tokio::spawn`; `connect()`'s wait for the callback result reuses that ambient
//! `Handle` via `Handle::try_current()` rather than creating a second nested
//! `Runtime` (which panics). Callers with no ambient runtime (unit tests using
//! `MockCallbackHandler`) fall back to a throwaway `Runtime`, unaffected.
//!
//! AuthorizationFlow::start()/validate_callback() now used directly (T-403) — previous
//! manual bypass removed. Caller generates state via AuthorizationFlow::generate_state(),
//! passes it to start() along with the pre-built authorization_url (which includes the state).

use crate::adapters::{CallbackError, CredentialVault, TokenExchangeClient, TokenExchangeError, VaultError};
use crate::adapters::ExchangeCodeParams;
use crate::core::security::SecretString;
use std::time::SystemTime;

/// WHOOP OAuth connection session orchestrator (T-604).
///
/// Encapsulates the platform-independent OAuth flow: state generation, browser launch,
/// callback waiting, token exchange, and vault storage.
///
/// T-604: Now injects a shared `AuthorizationFlow` (Arc-based) instead of raw callback_handler.
/// This ensures that repeated `connect()` calls for the same connection_id share the same
/// pending authorization store, implementing T-302 semantics correctly.
pub struct WhoopConnectSession<'a> {
    flow: &'a crate::core::oauth::AuthorizationFlow,
    token_client: &'a dyn TokenExchangeClient,
    vault: &'a dyn CredentialVault,
}

/// Successful connection outcome.
pub enum WhoopConnectOutcome {
    /// Tokens successfully obtained and stored.
    Connected {
        /// Expiry time of the new access token.
        expires_at: SystemTime,
    },
}

/// Error type for WHOOP connection flow.
#[derive(Debug, Clone)]
pub enum WhoopConnectError {
    /// Platform callback handler error (listener bind, browser launch).
    Callback(CallbackError),

    /// Callback state does not match expected (CSRF validation failure).
    StateMismatch,

    /// Callback not received within timeout window (5-minute window exceeded).
    Timeout,

    /// Authorization attempt exceeded the timeout window (T-403: pending authorization expired
    /// before callback was received). Different from Timeout: indicates the pending record existed
    /// but was too old, vs. callback never arriving.
    Expired,

    /// Provider in callback does not match expected provider (T-403: internal error,
    /// indicates a programming bug where wrong provider was passed to validate_callback).
    ProviderMismatch,

    /// Pending authorization record not found (T-403: internal error, indicates a programming
    /// bug where connection_id was corrupted or duplicate start() overwrote the pending record).
    NoMatchingPending,

    /// Provider returned an error (user denied, invalid client, etc.).
    ProviderDenied {
        error: String,
        error_description: Option<String>,
    },

    /// Token exchange failed (network, server error, invalid code).
    TokenExchange(TokenExchangeError),

    /// User-facing message (rendered by tool layer, D-012):
    /// "WHOOP did not grant persistent access — please reconnect and approve all requested permissions."
    MissingOfflineScope,

    /// TokenResponse.scope field absent or empty (provider did not return scope).
    ScopeNotConfirmed,

    /// Credential vault error (storage failure).
    Vault(VaultError),
}

impl std::fmt::Display for WhoopConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WhoopConnectError::Callback(e) => write!(f, "callback error: {}", e),
            WhoopConnectError::StateMismatch => write!(f, "state mismatch"),
            WhoopConnectError::Timeout => write!(f, "authorization timeout"),
            WhoopConnectError::Expired => write!(f, "authorization expired"),
            WhoopConnectError::ProviderMismatch => write!(f, "provider mismatch"),
            WhoopConnectError::NoMatchingPending => write!(f, "no matching pending authorization"),
            WhoopConnectError::ProviderDenied { error, .. } => write!(f, "provider denied: {}", error),
            WhoopConnectError::TokenExchange(e) => write!(f, "token exchange error: {:?}", e),
            WhoopConnectError::MissingOfflineScope => write!(f, "offline scope not granted"),
            WhoopConnectError::ScopeNotConfirmed => write!(f, "scope field not confirmed"),
            WhoopConnectError::Vault(e) => write!(f, "vault error: {}", e),
        }
    }
}

impl std::error::Error for WhoopConnectError {}

impl<'a> WhoopConnectSession<'a> {
    /// Create a new WHOOP connection session with shared authorization flow (T-604).
    ///
    /// # Arguments
    ///
    /// * `flow` - Shared `AuthorizationFlow` (Arc-wrapped callback handler + pending store)
    /// * `token_client` - Token exchange adapter
    /// * `vault` - Credential vault adapter
    pub fn new(
        flow: &'a crate::core::oauth::AuthorizationFlow,
        token_client: &'a dyn TokenExchangeClient,
        vault: &'a dyn CredentialVault,
    ) -> Self {
        WhoopConnectSession {
            flow,
            token_client,
            vault,
        }
    }

    /// Build a WHOOP authorization URL with all 5 required scopes.
    ///
    /// # Arguments
    ///
    /// * `client_id` - OAuth client identifier
    /// * `redirect_uri` - OAuth redirect URI (must be URL-encoded)
    /// * `state` - CSRF state token (must be included in URL)
    ///
    /// # Returns
    ///
    /// Authorization URL with format:
    /// `https://api.prod.whoop.com/oauth/oauth2/auth?client_id={client_id}&redirect_uri={encoded_uri}&response_type=code&scope=offline+read:cycles+read:sleep+read:recovery+read:workout&state={state}`
    pub fn build_authorization_url(client_id: &str, redirect_uri: &str, state: &str) -> String {
        // Percent-encode redirect_uri manually to avoid external dependency
        let encoded_uri = Self::percent_encode(redirect_uri);

        // Scopes per WHOOP spec: offline, read:cycles, read:sleep, read:recovery, read:workout
        // Space-delimited (RFC 6749 scope_delimiter)
        format!(
            "https://api.prod.whoop.com/oauth/oauth2/auth?client_id={}&redirect_uri={}&response_type=code&scope=offline+read:cycles+read:sleep+read:recovery+read:workout&state={}",
            client_id, encoded_uri, state
        )
    }

    /// Percent-encode a string for URL parameters (RFC 3986).
    /// Encodes reserved characters and spaces.
    fn percent_encode(input: &str) -> String {
        input
            .bytes()
            .map(|b| match b {
                // Unreserved: ALPHA / DIGIT / "-" / "." / "_" / "~"
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
                // Encode everything else
                _ => format!("%{:02X}", b),
            })
            .collect()
    }

    /// Execute the WHOOP OAuth connection flow (T-604).
    ///
    /// T-604: Removed `redirect_uri` parameter. The port is determined dynamically when
    /// the callback listener binds, and the redirect_uri is constructed from that port.
    ///
    /// # Arguments
    ///
    /// * `connection_id` - Unique connection identifier
    /// * `client_id` - OAuth client ID
    /// * `client_secret` - OAuth client secret (if applicable)
    /// * `service` - Vault namespace (e.g., "{bundle_id}.whoop.{connection_id}")
    ///
    /// # Errors
    ///
    /// Returns `WhoopConnectError` if callback fails, state mismatches, token exchange fails,
    /// offline scope is missing, or vault storage fails. Tokens are NOT stored on any error.
    pub fn connect(
        &self,
        connection_id: String,
        client_id: String,
        client_secret: Option<SecretString>,
        service: String,
    ) -> Result<WhoopConnectOutcome, WhoopConnectError> {
        // Step 1: Generate CSRF state using AuthorizationFlow
        let state = crate::core::oauth::AuthorizationFlow::generate_state();

        // Step 2: Use start_and_bind to listen for callback, get the port, and build URL
        //        The closure builds the authorization URL once we know the port.
        let client_id_clone = client_id.clone();
        let state_clone = state.clone();
        let (_pending, receiver, authorization_url, port) = self.flow.start_and_bind(
            connection_id.clone(),
            "whoop".to_string(),
            state.clone(),
            move |port: u16| Self::build_authorization_url(&client_id_clone, &format!("http://127.0.0.1:{}/callback", port), &state_clone),
        ).map_err(|e| match e {
            crate::core::oauth::AuthorizationError::Callback(cb_err) => {
                if matches!(cb_err, CallbackError::Timeout) {
                    WhoopConnectError::Timeout
                } else {
                    WhoopConnectError::Callback(cb_err)
                }
            },
            crate::core::oauth::AuthorizationError::Expired => WhoopConnectError::Expired,
            crate::core::oauth::AuthorizationError::StateMismatch => WhoopConnectError::StateMismatch,
            crate::core::oauth::AuthorizationError::ProviderMismatch => WhoopConnectError::ProviderMismatch,
            crate::core::oauth::AuthorizationError::NoMatchingPendingAuthorization => WhoopConnectError::NoMatchingPending,
            crate::core::oauth::AuthorizationError::ProviderDenied { error, error_description } => WhoopConnectError::ProviderDenied { error, error_description },
        })?;

        // Extract the port and construct redirect_uri for token exchange
        let redirect_uri = format!("http://127.0.0.1:{}/callback", port);

        // Diagnostic (safe — no secrets: client_id/redirect_uri/state are not
        // confidential per D-015, unlike client_secret/tokens/codes). Printed
        // at info level so a manual e2e run can copy-paste the URL if the
        // system browser launch doesn't visibly navigate there.
        tracing::info!(url = %authorization_url, "WHOOP authorization URL");

        // Step 3: Wait for callback result.
        //
        // Bug found on manual e2e verification (T-401): the real macOS
        // `listen_for_callback` (T-301) internally does `tokio::spawn`, which
        // requires an ambient tokio runtime already active on this thread —
        // but unconditionally creating a brand-new `Runtime` here to block on
        // `receiver.recv` panics ("Cannot start a runtime from within a
        // runtime") whenever `connect()` is called from a context that already
        // has one entered (which it always will, once EPIC-06 wires this into
        // the MCP server's own `#[tokio::main]` runtime). Reuse the ambient
        // `Handle` when present (production, e2e harness); fall back to a
        // throwaway `Runtime` only when none exists (unit tests using
        // `MockCallbackHandler`, which never calls `tokio::spawn` and so never
        // required an ambient runtime in the first place).
        let callback_result = match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle.block_on(receiver.recv),
            Err(_) => tokio::runtime::Runtime::new()
                .expect("tokio runtime creation")
                .block_on(receiver.recv),
        }
        .map_err(|_| WhoopConnectError::Timeout)?
        .map_err(WhoopConnectError::Callback)?;

        // Step 4: Validate callback result using shared AuthorizationFlow
        let code = self.flow.validate_callback(&connection_id, "whoop", callback_result).map_err(|e| match e {
            crate::core::oauth::AuthorizationError::Callback(cb_err) => WhoopConnectError::Callback(cb_err),
            crate::core::oauth::AuthorizationError::Expired => WhoopConnectError::Expired,
            crate::core::oauth::AuthorizationError::StateMismatch => WhoopConnectError::StateMismatch,
            crate::core::oauth::AuthorizationError::ProviderMismatch => WhoopConnectError::ProviderMismatch,
            crate::core::oauth::AuthorizationError::NoMatchingPendingAuthorization => WhoopConnectError::NoMatchingPending,
            crate::core::oauth::AuthorizationError::ProviderDenied { error, error_description } => WhoopConnectError::ProviderDenied { error, error_description },
        })?;

        // Step 5: Exchange code for tokens
        let token_endpoint = "https://api.prod.whoop.com/oauth/oauth2/token";
        let exchange_params = ExchangeCodeParams {
            token_endpoint: token_endpoint.to_string(),
            client_id,
            client_secret,
            code,
            redirect_uri,
        };

        let token_response = self
            .token_client
            .exchange_code(exchange_params)
            .map_err(WhoopConnectError::TokenExchange)?;

        // Step 6: Validate offline scope
        match token_response.scope {
            None => return Err(WhoopConnectError::ScopeNotConfirmed),
            Some(ref scope_str) => {
                let has_offline = scope_str.split_whitespace().any(|s| s == "offline");
                if !has_offline {
                    return Err(WhoopConnectError::MissingOfflineScope);
                }
            }
        }

        // Step 7: Store tokens in vault atomically
        // Only proceed if all previous validations passed
        self.vault
            .store(&service, "access_token", &token_response.access_token)
            .map_err(WhoopConnectError::Vault)?;

        if let Some(refresh_token) = &token_response.refresh_token {
            self.vault
                .store(&service, "refresh_token", refresh_token)
                .map_err(WhoopConnectError::Vault)?;
        }

        // Calculate expires_at from now + expires_in_secs
        let expires_at = SystemTime::now() + std::time::Duration::from_secs(token_response.expires_in_secs);

        Ok(WhoopConnectOutcome::Connected { expires_at })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::{CallbackResult, OAuthCallbackHandler};
    use std::sync::Mutex;

    /// Mock OAuthCallbackHandler for testing
    struct MockCallbackHandler {
        code: String,
        error_result: Option<(String, Option<String>)>, // (error, error_description)
        expected_state: Mutex<Option<String>>,
    }

    impl MockCallbackHandler {
        /// Create a handler that succeeds with a code (state will be captured and matched)
        fn new_success(code: String) -> Self {
            MockCallbackHandler {
                code,
                error_result: None,
                expected_state: Mutex::new(None),
            }
        }

        /// Create a handler that returns a provider error
        fn new_error(error: String, error_description: Option<String>) -> Self {
            MockCallbackHandler {
                code: "unused".to_string(),
                error_result: Some((error, error_description)),
                expected_state: Mutex::new(None),
            }
        }

        /// Create a handler that returns success with wrong state (for state mismatch tests)
        fn new_with_wrong_state(code: String, wrong_state: String) -> Self {
            let mut h = MockCallbackHandler {
                code,
                error_result: None,
                expected_state: Mutex::new(None),
            };
            h.expected_state = Mutex::new(Some(wrong_state));
            h
        }
    }

    impl OAuthCallbackHandler for MockCallbackHandler {
        fn listen_for_callback(&self, expected_state: &str) -> Result<crate::adapters::CallbackReceiver, CallbackError> {
            let (tx, rx) = tokio::sync::oneshot::channel::<Result<CallbackResult, CallbackError>>();

            let result = if let Some((error, desc)) = &self.error_result {
                CallbackResult::Error {
                    error: error.clone(),
                    error_description: desc.clone(),
                }
            } else {
                // Use either the expected state (normal case) or a wrong state (for state mismatch test)
                let state = self
                    .expected_state
                    .lock()
                    .unwrap()
                    .as_ref()
                    .cloned()
                    .unwrap_or_else(|| expected_state.to_string());
                CallbackResult::Success {
                    code: self.code.clone(),
                    state,
                }
            };

            let _ = tx.send(Ok(result));
            Ok(crate::adapters::CallbackReceiver { recv: rx, port: 9999 })
        }

        fn open_system_browser(&self, _url: &str) -> Result<(), CallbackError> {
            Ok(())
        }
    }

    /// Mock TokenExchangeClient for testing
    struct MockTokenExchangeClient {
        response: crate::adapters::TokenResponse,
    }

    impl MockTokenExchangeClient {
        fn new(response: crate::adapters::TokenResponse) -> Self {
            MockTokenExchangeClient { response }
        }
    }

    impl TokenExchangeClient for MockTokenExchangeClient {
        fn exchange_code(
            &self,
            _params: ExchangeCodeParams,
        ) -> Result<crate::adapters::TokenResponse, TokenExchangeError> {
            Ok(self.response.clone())
        }

        fn refresh_token(
            &self,
            _params: crate::adapters::RefreshTokenParams,
        ) -> Result<crate::adapters::TokenResponse, TokenExchangeError> {
            unreachable!("refresh_token not used in connection tests")
        }

        fn revoke_token(&self, _params: crate::adapters::RevokeTokenParams) -> Result<(), TokenExchangeError> {
            unreachable!("revoke_token not used in connection tests")
        }
    }

    /// Mock CredentialVault for testing
    struct MockCredentialVault {
        data: Mutex<std::collections::HashMap<(String, String), SecretString>>,
    }

    impl MockCredentialVault {
        fn new() -> Self {
            MockCredentialVault {
                data: Mutex::new(std::collections::HashMap::new()),
            }
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

    #[test]
    fn test_build_authorization_url_includes_all_five_scopes() {
        let url = WhoopConnectSession::build_authorization_url("client123", "http://localhost:9999/callback", "state_xyz");

        assert!(url.contains("client_id=client123"));
        assert!(url.contains("redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("scope=offline+read:cycles+read:sleep+read:recovery+read:workout"));
        assert!(url.contains("state=state_xyz"));
    }

    // Note: Full integration tests for connect() require tokio runtime (for receiver.recv.await).
    // These are tested via integration tests or manual e2e; unit tests here verify individual components.

    #[test]
    fn test_connect_propagates_provider_denied() {
        let callback = std::sync::Arc::new(MockCallbackHandler::new_error(
            "access_denied".to_string(),
            Some("user rejected".to_string()),
        ));

        let token_client = MockTokenExchangeClient::new(crate::adapters::TokenResponse {
            access_token: SecretString::new("access".to_string()),
            refresh_token: None,
            expires_in_secs: 3600,
            scope: Some("offline".to_string()),
        });

        let vault = MockCredentialVault::new();
        let flow = crate::core::oauth::AuthorizationFlow::new(callback);
        let session = WhoopConnectSession::new(&flow, &token_client, &vault);
        let result = session.connect(
            "conn_test".to_string(),
            "client123".to_string(),
            None,
            "test.whoop.conn_test".to_string(),
        );

        assert!(matches!(result, Err(WhoopConnectError::ProviderDenied { .. })));
    }

    #[test]
    fn test_connect_rejects_callback_with_wrong_state() {
        let callback = std::sync::Arc::new(MockCallbackHandler::new_with_wrong_state(
            "auth_code_xyz".to_string(),
            "wrong_state".to_string(), // Will not match the generated state
        ));

        let token_client = MockTokenExchangeClient::new(crate::adapters::TokenResponse {
            access_token: SecretString::new("access".to_string()),
            refresh_token: None,
            expires_in_secs: 3600,
            scope: Some("offline".to_string()),
        });

        let vault = MockCredentialVault::new();
        let flow = crate::core::oauth::AuthorizationFlow::new(callback);
        let session = WhoopConnectSession::new(&flow, &token_client, &vault);
        let result = session.connect(
            "conn_test".to_string(),
            "client123".to_string(),
            None,
            "test.whoop.conn_test".to_string(),
        );

        assert!(matches!(result, Err(WhoopConnectError::StateMismatch)));
        assert!(vault.get("test.whoop.conn_test", "access_token").is_none());
    }

    #[test]
    fn test_connect_fails_with_missing_offline_scope_and_does_not_store_tokens() {
        // AC#1: offline scope is REQUIRED
        // Mock token response WITHOUT "offline" in scope
        let callback = std::sync::Arc::new(MockCallbackHandler::new_success("auth_code_xyz".to_string()));

        let token_client = MockTokenExchangeClient::new(crate::adapters::TokenResponse {
            access_token: SecretString::new("access_token".to_string()),
            refresh_token: None,
            expires_in_secs: 3600,
            scope: Some("read:sleep read:recovery read:cycles read:workout".to_string()), // NO "offline"
        });

        let vault = MockCredentialVault::new();
        let flow = crate::core::oauth::AuthorizationFlow::new(callback);
        let session = WhoopConnectSession::new(&flow, &token_client, &vault);
        let result = session.connect(
            "conn_test".to_string(),
            "client123".to_string(),
            None,
            "test.whoop.conn_test".to_string(),
        );

        // AC#1: Result must be MissingOfflineScope
        assert!(matches!(result, Err(WhoopConnectError::MissingOfflineScope)));

        // AC#1: Tokens must NOT be stored in vault (atomicity — validation before storage)
        assert!(vault.get("test.whoop.conn_test", "access_token").is_none());
        assert!(vault.get("test.whoop.conn_test", "refresh_token").is_none());
    }

    #[test]
    fn test_connect_fails_when_scope_field_absent_in_token_response() {
        // AC#1: scope field in token response must be present and non-empty
        // Mock token response with scope = None
        let callback = std::sync::Arc::new(MockCallbackHandler::new_success("auth_code_xyz".to_string()));

        let token_client = MockTokenExchangeClient::new(crate::adapters::TokenResponse {
            access_token: SecretString::new("access_token".to_string()),
            refresh_token: None,
            expires_in_secs: 3600,
            scope: None, // scope field is absent
        });

        let vault = MockCredentialVault::new();
        let flow = crate::core::oauth::AuthorizationFlow::new(callback);
        let session = WhoopConnectSession::new(&flow, &token_client, &vault);
        let result = session.connect(
            "conn_test".to_string(),
            "client123".to_string(),
            None,
            "test.whoop.conn_test".to_string(),
        );

        // AC#1: Result must be ScopeNotConfirmed
        assert!(matches!(result, Err(WhoopConnectError::ScopeNotConfirmed)));

        // AC#1: Tokens must NOT be stored in vault
        assert!(vault.get("test.whoop.conn_test", "access_token").is_none());
        assert!(vault.get("test.whoop.conn_test", "refresh_token").is_none());
    }
}
