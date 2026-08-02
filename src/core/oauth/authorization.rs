//! OAuth authorization flow state machine (T-006 Adapter 2 usage, T-202, T-604).
//!
//! No `#[cfg(target_os = ...)]` allowed here — core logic is platform-independent.

use crate::adapters::OAuthCallbackHandler;
use std::time::{SystemTime, Duration};
use std::sync::{Mutex, Arc};
use std::collections::HashMap;
use uuid::Uuid;

use super::state::ConnectionState;

/// AUTHORIZATION_TIMEOUT — maximum time to wait for OAuth callback (T-006 L104-106, T-202).
///
/// If the user does not complete authorization within this window, the flow is cancelled.
pub const AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(5 * 60); // 5 minutes

/// Pending authorization attempt — holds state needed to validate the callback (T-202 criterion 2).
///
/// Created by `AuthorizationFlow::start()`, validated by `AuthorizationFlow::validate_callback()`.
#[derive(Debug, Clone)]
pub struct PendingAuthorization {
    /// Unique connection identifier (e.g., "conn_a1b2c3d4").
    pub connection_id: String,

    /// OAuth provider name (e.g., "oura", "whoop", "garmin").
    pub provider: String,

    /// CSRF state token generated during `start()` — must match callback's state param.
    /// Generated via `Uuid::new_v4().to_string()` per credentials-and-security.md L28.
    pub state: String,

    /// Timestamp when this authorization was initiated.
    pub created_at: SystemTime,
}

impl PendingAuthorization {
    /// Check if this authorization has exceeded the timeout window.
    pub fn is_expired(&self, now: SystemTime) -> bool {
        if let Ok(elapsed) = now.duration_since(self.created_at) {
            elapsed > AUTHORIZATION_TIMEOUT
        } else {
            // Clock skew or error — treat as expired to be conservative
            true
        }
    }
}

/// Errors that can occur during OAuth authorization flow.
#[derive(Debug, Clone)]
pub enum AuthorizationError {
    /// No matching PendingAuthorization for this callback (replay/stale attempt).
    NoMatchingPendingAuthorization,

    /// Callback's state token does not match the expected state (CSRF attack prevention).
    StateMismatch,

    /// Authorization attempt exceeded the timeout window.
    Expired,

    /// Callback indicates a different provider than the pending authorization.
    ProviderMismatch,

    /// Provider returned an error (user denied, invalid client, etc.)
    ProviderDenied {
        error: String,
        error_description: Option<String>,
    },

    /// Platform callback handler returned an error (scheme not registered, timeout, browser error).
    Callback(crate::adapters::CallbackError),
}

/// Authorization flow manager (T-202 criteria 1-4, T-302 store + replay protection, T-604).
///
/// Orchestrates the OAuth authorization sequence:
/// 1. `start()` — generate CSRF state, open browser, store pending authorization
/// 2. `start_and_bind()` — listen for callback (bind to OS-assigned port), build URL dynamically, open browser
/// 3. `validate_callback()` — retrieve and remove pending authorization, validate and return code
/// 4. `cancel()` — abort the flow and return to NotConnected
///
/// Uses an `Arc<dyn OAuthCallbackHandler>` trait object (Arc-wrapped) for the platform-specific
/// callback handling (localhost loopback listening, browser launching). The Arc allows sharing
/// a single flow instance across multiple connection attempts (T-302 AC: "repeated connect_provider
/// for same connection_id before first completion — pending record overwritten").
///
/// Maintains an in-memory store of pending authorizations (T-302 criterion 1):
/// records are deleted immediately after first validation attempt, success or error (criterion 2),
/// providing replay attack protection (criterion 3).
pub struct AuthorizationFlow {
    callback_handler: Arc<dyn OAuthCallbackHandler>,
    /// In-memory store of pending authorizations, keyed by connection_id.
    /// T-302: Mutex protects concurrent access; removed on first validation attempt.
    pending: Mutex<HashMap<String, PendingAuthorization>>,
}

impl AuthorizationFlow {
    /// Create a new authorization flow with the given callback handler.
    ///
    /// # Arguments
    ///
    /// * `callback_handler` - Arc-wrapped platform-specific implementation of callback handling
    ///   (injected from lib.rs composition root)
    pub fn new(callback_handler: Arc<dyn OAuthCallbackHandler>) -> Self {
        AuthorizationFlow {
            callback_handler,
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Generate a fresh CSRF state token — callers needing the state BEFORE
    /// building their authorization_url (any provider requiring state in the
    /// URL query string, e.g. WHOOP, Oura) call this first, build their URL, then
    /// pass the same state into `start()`.
    ///
    /// # Returns
    ///
    /// A cryptographically random UUID v4 string suitable for CSRF protection.
    pub fn generate_state() -> String {
        Uuid::new_v4().to_string()
    }

    /// Start the OAuth authorization flow with dynamic URL binding (T-604).
    ///
    /// This method corrects the architectural issue where the port is unknown until
    /// the callback handler's listener binds to it. The flow is:
    /// 1. Listen for callback → get the actual bound port from the listener
    /// 2. Build authorization URL using the known port (via closure)
    /// 3. Open browser to the built URL
    /// 4. Store pending authorization
    /// 5. Return pending record, receiver, URL, and port
    ///
    /// # Arguments
    ///
    /// * `connection_id` - Unique connection identifier (e.g., "conn_a1b2c3d4")
    /// * `provider` - OAuth provider name (e.g., "oura", "whoop", "garmin")
    /// * `state` - CSRF state token (caller-generated, typically via `Self::generate_state()`)
    /// * `build_url` - Closure that takes the bound port and returns the authorization URL.
    ///   The closure receives the actual OS-assigned port (or fixed port from env var)
    ///   and must return the complete authorization URL with redirect_uri and state embedded.
    ///
    /// # Returns
    ///
    /// A tuple `(PendingAuthorization, CallbackReceiver, authorization_url, port)`:
    /// - `PendingAuthorization` — returned for caller reference (also stored internally)
    /// - `CallbackReceiver` — await this to receive the callback when user completes auth
    /// - `authorization_url` — the URL that was opened in the browser
    /// - `port` — the port the listener is bound to
    ///
    /// # Errors
    ///
    /// Returns `AuthorizationError::Callback(CallbackError::...)` if:
    /// - Loopback listener could not be bound (callback handler returns ListenerBindFailed)
    /// - Browser cannot be launched (callback handler returns BrowserLaunchFailed)
    ///
    /// Per T-604: This method combines port binding, URL construction, and browser launch
    /// in the correct order, ensuring the redirect_uri in the authorization URL matches
    /// the actual port the listener is bound to.
    pub fn start_and_bind<F>(
        &self,
        connection_id: String,
        provider: String,
        state: String,
        build_url: F,
    ) -> Result<(PendingAuthorization, crate::adapters::CallbackReceiver, String, u16), AuthorizationError>
    where
        F: FnOnce(u16) -> String,
    {
        // Step 1: Listen for callback before opening browser (get the actual port)
        let receiver = self
            .callback_handler
            .listen_for_callback(&state)
            .map_err(AuthorizationError::Callback)?;

        // Extract port from receiver
        let port = receiver.port;

        // Step 2: Build authorization URL now that we know the port
        let authorization_url = build_url(port);

        // Step 3: Open browser to authorization URL
        self.callback_handler
            .open_system_browser(&authorization_url)
            .map_err(AuthorizationError::Callback)?;

        // Step 4: Create and store pending authorization record
        let pending = PendingAuthorization {
            connection_id: connection_id.clone(),
            provider: provider.clone(),
            state: state.clone(),
            created_at: SystemTime::now(),
        };

        // Store pending authorization (T-302 criterion 1)
        self.pending.lock().unwrap().insert(connection_id, pending.clone());

        // Step 5: Return all the information
        Ok((pending, receiver, authorization_url, port))
    }

    /// Start the OAuth authorization flow — open browser and wait for callback.
    ///
    /// # Arguments
    ///
    /// * `connection_id` - Unique connection identifier (e.g., "conn_a1b2c3d4")
    /// * `provider` - OAuth provider name (e.g., "oura", "whoop", "garmin")
    /// * `state` - CSRF state token (caller-generated, typically via `Self::generate_state()`)
    /// * `authorization_url` - The OAuth provider's authorization endpoint URL
    ///   (must include the state parameter in the query string,
    ///   e.g., `https://api.oura.cloud/oauth/authorize?client_id=...&redirect_uri=...&state=...`)
    ///
    /// # Returns
    ///
    /// A tuple `(PendingAuthorization, CallbackReceiver)`:
    /// - `PendingAuthorization` — returned for caller reference (also stored internally)
    /// - `CallbackReceiver` — await this to receive the callback when user completes auth
    ///
    /// # Errors
    ///
    /// Returns `AuthorizationError::Callback(CallbackError::...)` if:
    /// - Loopback listener could not be bound (callback handler returns ListenerBindFailed)
    /// - Browser cannot be launched (callback handler returns BrowserLaunchFailed)
    ///
    /// Per T-202 criterion 1: "start() returns the state and a callback receiver to the caller."
    ///
    /// Per T-302: Pending authorization is stored in the internal store (keyed by connection_id).
    /// Subsequent calls to `start()` with the same connection_id will overwrite the previous record.
    pub fn start(
        &self,
        connection_id: String,
        provider: String,
        state: String,
        authorization_url: &str,
    ) -> Result<(PendingAuthorization, crate::adapters::CallbackReceiver), AuthorizationError> {
        // Create pending authorization record
        let pending = PendingAuthorization {
            connection_id: connection_id.clone(),
            provider: provider.clone(),
            state: state.clone(),
            created_at: SystemTime::now(),
        };

        // Listen for callback before opening browser (avoid race condition)
        let receiver = self
            .callback_handler
            .listen_for_callback(&state)
            .map_err(AuthorizationError::Callback)?;

        // Open browser to authorization URL
        self.callback_handler
            .open_system_browser(authorization_url)
            .map_err(AuthorizationError::Callback)?;

        // Store pending authorization (T-302 criterion 1)
        self.pending.lock().unwrap().insert(connection_id, pending.clone());

        Ok((pending, receiver))
    }

    /// Validate the OAuth callback and return the authorization code.
    ///
    /// # Arguments
    ///
    /// * `connection_id` - The connection identifier used in `start()`
    /// * `expected_provider` - The provider we expect (e.g., "oura")
    /// * `callback_result` - The callback result received from the handler
    ///   (parsed from the loopback HTTP redirect by the platform layer)
    ///
    /// # Returns
    ///
    /// The authorization code (to be exchanged for tokens in T-203) if all validations pass.
    ///
    /// # Errors
    ///
    /// - `NoMatchingPendingAuthorization` — no pending authorization found for connection_id
    ///   (replay attack, stale flow, or connection_id mismatch). Note: pending is removed
    ///   from the store BEFORE subsequent checks, so any validation error also consumes the record.
    /// - `Expired` — pending authorization exceeded 5-minute timeout (T-006 L104-106)
    /// - `StateMismatch` — callback state ≠ pending.state (CSRF attack)
    /// - `ProviderMismatch` — callback provider ≠ expected_provider
    /// - `ProviderDenied` — provider returned an error (user denied, invalid_client, etc.)
    ///
    /// Per T-202 criterion 2: "validate_callback() enforces CSRF and timeout checks."
    /// Per T-302 criterion 2: Pending authorization is deleted from the store immediately,
    /// before validation checks, so any second attempt to use the same connection_id
    /// will fail with `NoMatchingPendingAuthorization` (protecting against replay).
    pub fn validate_callback(
        &self,
        connection_id: &str,
        expected_provider: &str,
        callback_result: crate::adapters::CallbackResult,
    ) -> Result<String, AuthorizationError> {
        // Remove pending authorization from store (T-302 criterion 2).
        // This MUST happen first, before any validation checks, to ensure that
        // any second attempt (replay) fails immediately.
        let pending = self
            .pending
            .lock()
            .unwrap()
            .remove(connection_id)
            .ok_or(AuthorizationError::NoMatchingPendingAuthorization)?;

        // Check for timeout (T-006 L104-106: 5 minutes)
        if pending.is_expired(SystemTime::now()) {
            return Err(AuthorizationError::Expired);
        }

        match callback_result {
            crate::adapters::CallbackResult::Success { code, state } => {
                // CSRF validation: state must match exactly
                if state != pending.state {
                    return Err(AuthorizationError::StateMismatch);
                }

                // Provider validation: must match expected provider
                if pending.provider != expected_provider {
                    return Err(AuthorizationError::ProviderMismatch);
                }

                // All checks passed — return the authorization code
                Ok(code)
            }

            crate::adapters::CallbackResult::Error {
                error,
                error_description,
            } => {
                // Provider returned an error
                Err(AuthorizationError::ProviderDenied {
                    error,
                    error_description,
                })
            }
        }
    }

    /// Cancel the authorization flow and return to NotConnected state.
    ///
    /// Per T-202 criterion 4 (EPIC-03-oauth.md L19): "cancel() is available
    /// to abort the flow without proceeding to token exchange."
    pub fn cancel(&self) -> ConnectionState {
        ConnectionState::NotConnected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::{CallbackError, CallbackReceiver, CallbackResult, OAuthCallbackHandler};

    /// Mock implementation of OAuthCallbackHandler for unit tests.
    ///
    /// Captures the URL passed to `open_system_browser` for assertion in tests.
    struct MockCallbackHandler {
        captured_url: std::sync::Mutex<Option<String>>,
    }

    impl Default for MockCallbackHandler {
        fn default() -> Self {
            MockCallbackHandler {
                captured_url: std::sync::Mutex::new(None),
            }
        }
    }

    impl OAuthCallbackHandler for MockCallbackHandler {
        fn listen_for_callback(&self, _expected_state: &str) -> Result<CallbackReceiver, CallbackError> {
            // Create a dummy oneshot receiver for testing
            let (_tx, rx) = tokio::sync::oneshot::channel::<Result<CallbackResult, CallbackError>>();
            Ok(CallbackReceiver { recv: rx, port: 0 })
        }

        fn open_system_browser(&self, url: &str) -> Result<(), CallbackError> {
            *self.captured_url.lock().unwrap() = Some(url.to_string());
            Ok(())
        }
    }

    // Test-only helper: insert a pending authorization with arbitrary created_at
    // (used for testing expired records without waiting 5 minutes)
    #[cfg(test)]
    impl AuthorizationFlow {
        fn insert_pending_for_test(&self, p: PendingAuthorization) {
            self.pending.lock().unwrap().insert(p.connection_id.clone(), p);
        }
    }

    /// T1: start() opens system browser with provided state.
    ///
    /// Mock successfully returns; assert pending.state matches caller-provided state.
    #[test]
    fn test_start_opens_system_browser_with_generated_state() {
        let mock = Arc::new(MockCallbackHandler::default());
        let flow = AuthorizationFlow::new(mock.clone());

        let state = AuthorizationFlow::generate_state();
        let auth_url = "https://api.oura.cloud/oauth/authorize?client_id=test&state=will_be_included";
        let result = flow.start(
            "conn_test123".to_string(),
            "oura".to_string(),
            state.clone(),
            auth_url,
        );

        assert!(result.is_ok());
        let (pending, _receiver) = result.unwrap();

        // Verify state matches what we provided
        assert_eq!(pending.state, state);
        // Verify it looks like a UUID (rough check: contains hyphens, length ~36)
        assert!(pending.state.len() > 30);

        // Verify that the URL was passed to open_system_browser unmodified
        let captured = mock.captured_url.lock().unwrap().clone();
        assert_eq!(captured, Some(auth_url.to_string()));
    }

    /// T2: validate_callback() accepts matching state.
    ///
    /// start() stores pending, then validate_callback(connection_id, ..., Success{state: pending.state}) → Ok(code).
    #[test]
    fn test_validate_callback_accepts_matching_state() {
        let mock = Arc::new(MockCallbackHandler::default());
        let flow = AuthorizationFlow::new(mock.clone());

        let state = AuthorizationFlow::generate_state();
        let auth_url = "https://api.oura.cloud/oauth/authorize";
        let start_result = flow.start(
            "conn_test".to_string(),
            "oura".to_string(),
            state.clone(),
            auth_url,
        );
        assert!(start_result.is_ok());
        let (pending, _receiver) = start_result.unwrap();

        let callback_result = CallbackResult::Success {
            code: "auth_code_xyz".to_string(),
            state: pending.state.clone(),
        };

        let result = flow.validate_callback(&pending.connection_id, "oura", callback_result);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "auth_code_xyz");
    }

    /// T3: validate_callback() rejects state mismatch.
    ///
    /// Success{state:"wrong"} → Err(StateMismatch), and record is deleted.
    #[test]
    fn test_validate_callback_rejects_state_mismatch() {
        let mock = Arc::new(MockCallbackHandler::default());
        let flow = AuthorizationFlow::new(mock.clone());

        let pending = PendingAuthorization {
            connection_id: "conn_test".to_string(),
            provider: "oura".to_string(),
            state: "correct_state_123".to_string(),
            created_at: SystemTime::now(),
        };

        // Use test helper to insert the pending authorization
        flow.insert_pending_for_test(pending.clone());

        let callback_result = CallbackResult::Success {
            code: "auth_code_xyz".to_string(),
            state: "wrong_state_456".to_string(),
        };

        let result = flow.validate_callback(&pending.connection_id, "oura", callback_result);
        assert!(matches!(result, Err(AuthorizationError::StateMismatch)));
    }

    /// T4: validate_callback() rejects provider mismatch.
    ///
    /// pending.provider "oura", expected_provider "whoop" → Err(ProviderMismatch), and record is deleted.
    #[test]
    fn test_validate_callback_rejects_provider_mismatch() {
        let mock = Arc::new(MockCallbackHandler::default());
        let flow = AuthorizationFlow::new(mock.clone());

        let pending = PendingAuthorization {
            connection_id: "conn_test".to_string(),
            provider: "oura".to_string(),
            state: "correct_state_123".to_string(),
            created_at: SystemTime::now(),
        };

        // Use test helper to insert the pending authorization
        flow.insert_pending_for_test(pending.clone());

        let callback_result = CallbackResult::Success {
            code: "auth_code_xyz".to_string(),
            state: "correct_state_123".to_string(),
        };

        let result = flow.validate_callback(&pending.connection_id, "whoop", callback_result);
        assert!(matches!(result, Err(AuthorizationError::ProviderMismatch)));
    }

    /// T5: validate_callback() rejects expired.
    ///
    /// created_at = now - 6min → Err(Expired), and record is deleted.
    #[test]
    fn test_validate_callback_rejects_expired() {
        let mock = Arc::new(MockCallbackHandler::default());
        let flow = AuthorizationFlow::new(mock.clone());

        let now = SystemTime::now();
        let created_at = now - Duration::from_secs(6 * 60); // 6 minutes ago

        let pending = PendingAuthorization {
            connection_id: "conn_test".to_string(),
            provider: "oura".to_string(),
            state: "correct_state_123".to_string(),
            created_at,
        };

        // Use test helper to insert the pending authorization with past timestamp
        flow.insert_pending_for_test(pending.clone());

        let callback_result = CallbackResult::Success {
            code: "auth_code_xyz".to_string(),
            state: "correct_state_123".to_string(),
        };

        let result = flow.validate_callback(&pending.connection_id, "oura", callback_result);
        assert!(matches!(result, Err(AuthorizationError::Expired)));
    }

    /// T6: validate_callback() rejects replay after successful use.
    ///
    /// First validate_callback() succeeds and removes the record.
    /// Second validate_callback() with same connection_id → Err(NoMatchingPendingAuthorization).
    /// This tests that the record is deleted after first use (T-302 criterion 2).
    #[test]
    fn test_validate_callback_rejects_replay() {
        let mock = Arc::new(MockCallbackHandler::default());
        let flow = AuthorizationFlow::new(mock.clone());

        // Start authorization and store pending record
        let state = AuthorizationFlow::generate_state();
        let auth_url = "https://api.oura.cloud/oauth/authorize";
        let start_result = flow.start(
            "conn_replay_test".to_string(),
            "oura".to_string(),
            state,
            auth_url,
        );
        assert!(start_result.is_ok());
        let (pending, _receiver) = start_result.unwrap();

        // First callback validation succeeds
        let callback_result = CallbackResult::Success {
            code: "auth_code_xyz".to_string(),
            state: pending.state.clone(),
        };

        let result1 = flow.validate_callback(&pending.connection_id, "oura", callback_result.clone());
        assert!(result1.is_ok());
        assert_eq!(result1.unwrap(), "auth_code_xyz");

        // Second callback validation with same connection_id fails (record was deleted)
        let result2 = flow.validate_callback(&pending.connection_id, "oura", callback_result);
        assert!(matches!(
            result2,
            Err(AuthorizationError::NoMatchingPendingAuthorization)
        ));
    }

    /// T7: validate_callback() surfaces provider denied.
    ///
    /// CallbackResult::Error{..} → Err(ProviderDenied{..}), and record is deleted.
    #[test]
    fn test_validate_callback_surfaces_provider_denied() {
        let mock = Arc::new(MockCallbackHandler::default());
        let flow = AuthorizationFlow::new(mock.clone());

        let pending = PendingAuthorization {
            connection_id: "conn_test".to_string(),
            provider: "oura".to_string(),
            state: "correct_state_123".to_string(),
            created_at: SystemTime::now(),
        };

        // Use test helper to insert the pending authorization
        flow.insert_pending_for_test(pending.clone());

        let callback_result = CallbackResult::Error {
            error: "access_denied".to_string(),
            error_description: Some("user denied the request".to_string()),
        };

        let result = flow.validate_callback(&pending.connection_id, "oura", callback_result);
        assert!(matches!(result, Err(AuthorizationError::ProviderDenied { .. })));

        if let Err(AuthorizationError::ProviderDenied {
            error,
            error_description,
        }) = result
        {
            assert_eq!(error, "access_denied");
            assert_eq!(error_description, Some("user denied the request".to_string()));
        }
    }

    /// T8: cancel() returns NotConnected.
    ///
    /// AuthorizationFlow::cancel() == ConnectionState::NotConnected.
    #[test]
    fn test_cancel_returns_not_connected() {
        let mock = Arc::new(MockCallbackHandler::default());
        let flow = AuthorizationFlow::new(mock.clone());

        let result = flow.cancel();
        assert_eq!(result, ConnectionState::NotConnected);
    }

    /// T9: validate_callback() rejects replay after validation error.
    ///
    /// First call fails (e.g., StateMismatch) and deletes the record.
    /// Second call with same connection_id → Err(NoMatchingPendingAuthorization).
    /// This ensures replay protection even after validation failures.
    #[test]
    fn test_validate_callback_rejects_replay_after_error() {
        let mock = Arc::new(MockCallbackHandler::default());
        let flow = AuthorizationFlow::new(mock.clone());

        let pending = PendingAuthorization {
            connection_id: "conn_error_replay".to_string(),
            provider: "oura".to_string(),
            state: "correct_state".to_string(),
            created_at: SystemTime::now(),
        };

        // Insert pending authorization
        flow.insert_pending_for_test(pending.clone());

        // First validation attempt fails due to state mismatch
        let wrong_callback = CallbackResult::Success {
            code: "auth_code".to_string(),
            state: "wrong_state".to_string(),
        };

        let result1 = flow.validate_callback(&pending.connection_id, "oura", wrong_callback);
        assert!(matches!(result1, Err(AuthorizationError::StateMismatch)));

        // Second validation attempt with same connection_id fails because record was deleted
        let correct_callback = CallbackResult::Success {
            code: "auth_code".to_string(),
            state: "correct_state".to_string(),
        };

        let result2 = flow.validate_callback(&pending.connection_id, "oura", correct_callback);
        assert!(matches!(
            result2,
            Err(AuthorizationError::NoMatchingPendingAuthorization)
        ));
    }

    /// T10: validate_callback() rejects unknown connection_id.
    ///
    /// Validate with connection_id that was never started (no pending record exists)
    /// → Err(NoMatchingPendingAuthorization).
    #[test]
    fn test_validate_callback_rejects_unknown_connection_id() {
        let mock = Arc::new(MockCallbackHandler::default());
        let flow = AuthorizationFlow::new(mock.clone());

        let callback_result = CallbackResult::Success {
            code: "auth_code_xyz".to_string(),
            state: "some_state".to_string(),
        };

        // Never called start(), so no pending record exists
        let result = flow.validate_callback("unknown_connection_id", "oura", callback_result);
        assert!(matches!(
            result,
            Err(AuthorizationError::NoMatchingPendingAuthorization)
        ));
    }
}
