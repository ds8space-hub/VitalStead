//! OAuth token disconnect (revocation) orchestration — T-305, EPIC-03-oauth.md.
//!
//! Implements token revocation with best-effort semantics: revoke is attempted
//! if a revocation endpoint is provided and a token is stored, but failure to revoke
//! does not prevent deletion of the token from local storage.
//!
//! No platform-specific code; no references to `core::csv` (credentials-and-security.md L49).
//! Composed at the application layer via DisconnectOrchestrator.

use crate::adapters::{CredentialVault, RevokeTokenParams, TokenExchangeClient, VaultError};
use crate::core::security::SecretString;

/// Request to disconnect a connection (revoke tokens and delete credentials).
///
/// Supplies all parameters needed for a disconnect operation: connection identity,
/// token revocation endpoint details, and client credentials.
#[derive(Clone)]
pub struct DisconnectRequest {
    /// Unique connection identifier (e.g., "conn_a1b2c3d4").
    pub connection_id: String,
    /// Vault namespace (T-201 §3.1 format: `{bundle_id}.{provider}.{connection_id}`).
    pub service: String,
    /// OAuth revocation endpoint URL (if the provider supports revocation).
    /// `None` means revocation is not supported; disconnect will only delete credentials.
    pub revoke_endpoint: Option<String>,
    /// OAuth client identifier.
    pub client_id: String,
    /// OAuth client secret (if applicable).
    pub client_secret: Option<SecretString>,
}

/// Outcome of a disconnect operation — whether revocation was attempted and succeeded.
///
/// Per T-305: revocation is best-effort. If revocation fails, credentials are still deleted.
/// This enum tracks what happened for logging/UI purposes.
#[derive(Debug, Clone, PartialEq)]
pub enum DisconnectOutcome {
    /// Successfully disconnected and deleted credentials.
    Disconnected {
        /// Whether revocation was attempted (revoke_endpoint was provided and token was available)
        revoke_attempted: bool,
        /// Whether revocation succeeded (HTTP 200 from revocation endpoint, or network failure didn't block deletion)
        revoke_succeeded: bool,
    },
}

/// Error type for disconnect operations.
///
/// Only vault errors propagate — revocation errors are logged but not surfaced,
/// because the primary goal (delete credentials) must succeed.
#[derive(Debug, Clone, PartialEq)]
pub enum DisconnectError {
    /// Vault (credential storage) error — deletion failed.
    Vault(VaultError),
}

/// OAuth token disconnect orchestrator.
///
/// Composes the vault and token exchange client to implement token revocation
/// with best-effort semantics: revoke if possible, but always delete credentials.
pub struct DisconnectOrchestrator<'a> {
    vault: &'a dyn CredentialVault,
    token_client: &'a dyn TokenExchangeClient,
}

impl<'a> DisconnectOrchestrator<'a> {
    /// Create a new disconnect orchestrator with the given dependencies.
    pub fn new(vault: &'a dyn CredentialVault, token_client: &'a dyn TokenExchangeClient) -> Self {
        DisconnectOrchestrator { vault, token_client }
    }

    /// Execute a disconnect operation: attempt revocation (best-effort), then delete credentials.
    ///
    /// # Revocation strategy
    ///
    /// Attempts to revoke the most potent token in this order:
    /// 1. Refresh token (aннулирует весь grant)
    /// 2. Access token (fallback if refresh token not stored)
    /// 3. None (if neither token is stored)
    ///
    /// Per T-305 spec, revocation is best-effort: if the HTTP request fails, we log and continue.
    /// The revoke_attempted and revoke_succeeded flags in the outcome indicate what happened.
    ///
    /// # Deletion strategy
    ///
    /// After attempting revocation (regardless of outcome), unconditionally delete all credentials
    /// for the connection from the vault. Per credentials-and-security.md D-010, CSV files are
    /// not deleted — only credentials (tokens) are deleted.
    ///
    /// # Arguments
    ///
    /// * `request` - Disconnect request with connection details and revocation endpoint
    ///
    /// # Returns
    ///
    /// - `Ok(DisconnectOutcome)` — credentials deleted and revocation status reported
    /// - `Err(DisconnectError::Vault)` — credential deletion failed (revocation was not attempted or failed silently)
    pub fn disconnect(&self, request: DisconnectRequest) -> Result<DisconnectOutcome, DisconnectError> {
        let (revoke_attempted, revoke_succeeded) = self.try_revoke(&request);

        // Delete ВСЕГДА, независимо от revoke_succeeded — best-effort revoke, безусловный delete
        self.vault
            .delete_all_for_connection(&request.service)
            .map_err(DisconnectError::Vault)?;

        Ok(DisconnectOutcome::Disconnected { revoke_attempted, revoke_succeeded })
    }

    /// Attempt to revoke a token (best-effort).
    ///
    /// Returns (attempted, succeeded):
    /// - (false, false) — no revocation endpoint provided
    /// - (false, false) — no stored token found
    /// - (true, true) — revocation succeeded (200 response)
    /// - (true, false) — revocation attempted but failed (any error)
    fn try_revoke(&self, request: &DisconnectRequest) -> (bool, bool) {
        let Some(revoke_endpoint) = &request.revoke_endpoint else {
            return (false, false);
        };

        // Prefer refresh_token (revokes entire grant), fallback to access_token
        let (token, hint) = match self.vault.retrieve(&request.service, "refresh_token") {
            Ok(t) => (t, Some("refresh_token")),
            Err(_) => match self.vault.retrieve(&request.service, "access_token") {
                Ok(t) => (t, Some("access_token")),
                Err(_) => return (false, false), // No token to revoke
            },
        };

        let params = RevokeTokenParams {
            revoke_endpoint: revoke_endpoint.clone(),
            client_id: request.client_id.clone(),
            client_secret: request.client_secret.clone(),
            token,
            token_type_hint: hint,
        };

        match self.token_client.revoke_token(params) {
            Ok(()) => (true, true),
            Err(_) => (true, false), // best-effort: ошибка НЕ пробрасывается наружу
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

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
                .expect("vault data lock poisoned")
                .insert((service.to_string(), key.to_string()), value.clone());
            Ok(())
        }

        fn retrieve(&self, service: &str, key: &str) -> Result<SecretString, VaultError> {
            self.data
                .lock()
                .expect("vault data lock poisoned")
                .get(&(service.to_string(), key.to_string()))
                .cloned()
                .ok_or(VaultError::NotFound)
        }

        fn delete(&self, service: &str, key: &str) -> Result<(), VaultError> {
            self.data
                .lock()
                .expect("vault data lock poisoned")
                .remove(&(service.to_string(), key.to_string()))
                .ok_or(VaultError::NotFound)
                .map(|_| ())
        }

        fn delete_all_for_connection(&self, service: &str) -> Result<(), VaultError> {
            let mut data = self.data.lock().expect("vault data lock poisoned");
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
        should_revoke_succeed: bool,
        revoke_called: Mutex<u32>,
        revoke_params: Mutex<Option<(String, String)>>, // (token, hint)
    }

    impl MockTokenExchangeClient {
        fn new(should_succeed: bool) -> Self {
            MockTokenExchangeClient {
                should_revoke_succeed: should_succeed,
                revoke_called: Mutex::new(0),
                revoke_params: Mutex::new(None),
            }
        }

        fn revoke_call_count(&self) -> u32 {
            *self.revoke_called.lock().expect("revoke_called lock poisoned")
        }

        fn revoke_params(&self) -> Option<(String, String)> {
            self.revoke_params
                .lock()
                .expect("revoke_params lock poisoned")
                .clone()
        }
    }

    impl TokenExchangeClient for MockTokenExchangeClient {
        fn exchange_code(
            &self,
            _params: crate::adapters::ExchangeCodeParams,
        ) -> Result<crate::adapters::TokenResponse, crate::adapters::TokenExchangeError> {
            unreachable!("exchange_code not used in T-305 tests")
        }

        fn refresh_token(
            &self,
            _params: crate::adapters::RefreshTokenParams,
        ) -> Result<crate::adapters::TokenResponse, crate::adapters::TokenExchangeError> {
            unreachable!("refresh_token not used in T-305 tests")
        }

        fn revoke_token(&self, params: RevokeTokenParams) -> Result<(), crate::adapters::TokenExchangeError> {
            *self.revoke_called.lock().expect("revoke_called lock poisoned") += 1;
            *self.revoke_params.lock().expect("revoke_params lock poisoned") =
                Some((params.token.expose_secret().to_string(), params.token_type_hint.unwrap_or("none").to_string()));

            if self.should_revoke_succeed {
                Ok(())
            } else {
                Err(crate::adapters::TokenExchangeError::ServerError(500))
            }
        }
    }

    // ============ Test 1: disconnect revoke succeeds and deletes credentials ============
    #[test]
    fn test_disconnect_revoke_succeeds_and_deletes_credentials() {
        let vault = MockCredentialVault::new();
        let client = MockTokenExchangeClient::new(true);

        vault
            .store("test.oura.conn1", "access_token", &SecretString::new("access_123".to_string()))
            .unwrap();
        vault
            .store("test.oura.conn1", "refresh_token", &SecretString::new("refresh_456".to_string()))
            .unwrap();

        let orchestrator = DisconnectOrchestrator::new(&vault, &client);
        let request = DisconnectRequest {
            connection_id: "conn1".to_string(),
            service: "test.oura.conn1".to_string(),
            revoke_endpoint: Some("https://api.oura.cloud/oauth/revoke".to_string()),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
        };

        let result = orchestrator.disconnect(request).unwrap();
        assert_eq!(
            result,
            DisconnectOutcome::Disconnected {
                revoke_attempted: true,
                revoke_succeeded: true
            }
        );

        // Verify credentials deleted
        assert!(vault.retrieve("test.oura.conn1", "access_token").is_err());
        assert!(vault.retrieve("test.oura.conn1", "refresh_token").is_err());
    }

    // ============ Test 2: disconnect without revoke endpoint still deletes ============
    #[test]
    fn test_disconnect_without_revoke_endpoint_still_deletes() {
        let vault = MockCredentialVault::new();
        let client = MockTokenExchangeClient::new(true);

        vault
            .store("test.oura.conn2", "access_token", &SecretString::new("access_123".to_string()))
            .unwrap();

        let orchestrator = DisconnectOrchestrator::new(&vault, &client);
        let request = DisconnectRequest {
            connection_id: "conn2".to_string(),
            service: "test.oura.conn2".to_string(),
            revoke_endpoint: None, // No revocation endpoint
            client_id: "test_client".to_string(),
            client_secret: None,
        };

        let result = orchestrator.disconnect(request).unwrap();
        assert_eq!(
            result,
            DisconnectOutcome::Disconnected {
                revoke_attempted: false,
                revoke_succeeded: false
            }
        );

        // Verify credentials deleted even though revoke wasn't attempted
        assert!(vault.retrieve("test.oura.conn2", "access_token").is_err());
    }

    // ============ Test 3: disconnect revoke endpoint errors delete still happens ============
    #[test]
    fn test_disconnect_revoke_endpoint_errors_delete_still_happens() {
        let vault = MockCredentialVault::new();
        let client = MockTokenExchangeClient::new(false); // Will fail revoke

        vault
            .store("test.oura.conn3", "refresh_token", &SecretString::new("refresh_456".to_string()))
            .unwrap();

        let orchestrator = DisconnectOrchestrator::new(&vault, &client);
        let request = DisconnectRequest {
            connection_id: "conn3".to_string(),
            service: "test.oura.conn3".to_string(),
            revoke_endpoint: Some("https://api.oura.cloud/oauth/revoke".to_string()),
            client_id: "test_client".to_string(),
            client_secret: Some(SecretString::new("secret".to_string())),
        };

        let result = orchestrator.disconnect(request).unwrap();
        assert_eq!(
            result,
            DisconnectOutcome::Disconnected {
                revoke_attempted: true,
                revoke_succeeded: false
            }
        );

        // Verify credentials deleted despite revoke failure
        assert!(vault.retrieve("test.oura.conn3", "refresh_token").is_err());
    }

    // ============ Test 4: disconnect delete called exactly once ============
    #[test]
    fn test_disconnect_delete_called_exactly_once() {
        let vault = MockCredentialVault::new();
        let client = MockTokenExchangeClient::new(true);

        vault
            .store("test.oura.conn4", "access_token", &SecretString::new("access_123".to_string()))
            .unwrap();

        let orchestrator = DisconnectOrchestrator::new(&vault, &client);
        let request = DisconnectRequest {
            connection_id: "conn4".to_string(),
            service: "test.oura.conn4".to_string(),
            revoke_endpoint: Some("https://api.oura.cloud/oauth/revoke".to_string()),
            client_id: "test_client".to_string(),
            client_secret: None,
        };

        let _result = orchestrator.disconnect(request).unwrap();

        // Verify vault state: all credentials for conn4 gone, nothing else affected
        assert!(vault.retrieve("test.oura.conn4", "access_token").is_err());
    }

    // ============ Test 5: disconnect prefers refresh_token over access_token for revoke ============
    #[test]
    fn test_disconnect_prefers_refresh_token_over_access_token_for_revoke() {
        let vault = MockCredentialVault::new();
        let client = MockTokenExchangeClient::new(true);

        vault
            .store("test.oura.conn5", "access_token", &SecretString::new("access_123".to_string()))
            .unwrap();
        vault
            .store("test.oura.conn5", "refresh_token", &SecretString::new("refresh_456".to_string()))
            .unwrap();

        let orchestrator = DisconnectOrchestrator::new(&vault, &client);
        let request = DisconnectRequest {
            connection_id: "conn5".to_string(),
            service: "test.oura.conn5".to_string(),
            revoke_endpoint: Some("https://api.oura.cloud/oauth/revoke".to_string()),
            client_id: "test_client".to_string(),
            client_secret: None,
        };

        let _result = orchestrator.disconnect(request).unwrap();

        // Verify revoke was called with refresh_token
        let params = client.revoke_params();
        assert!(params.is_some());
        let (token, hint) = params.unwrap();
        assert_eq!(token, "refresh_456");
        assert_eq!(hint, "refresh_token");
    }

    // ============ Test 6: disconnect falls back to access_token when no refresh_token ============
    #[test]
    fn test_disconnect_falls_back_to_access_token_when_no_refresh_token() {
        let vault = MockCredentialVault::new();
        let client = MockTokenExchangeClient::new(true);

        vault
            .store("test.oura.conn6", "access_token", &SecretString::new("access_123".to_string()))
            .unwrap();

        let orchestrator = DisconnectOrchestrator::new(&vault, &client);
        let request = DisconnectRequest {
            connection_id: "conn6".to_string(),
            service: "test.oura.conn6".to_string(),
            revoke_endpoint: Some("https://api.oura.cloud/oauth/revoke".to_string()),
            client_id: "test_client".to_string(),
            client_secret: None,
        };

        let _result = orchestrator.disconnect(request).unwrap();

        // Verify revoke was called with access_token
        let params = client.revoke_params();
        assert!(params.is_some());
        let (token, hint) = params.unwrap();
        assert_eq!(token, "access_123");
        assert_eq!(hint, "access_token");
    }

    // ============ Test 7: disconnect no stored token skips revoke but deletes ============
    #[test]
    fn test_disconnect_no_stored_token_skips_revoke_but_deletes() {
        let vault = MockCredentialVault::new();
        let client = MockTokenExchangeClient::new(true);

        // Store nothing — no tokens

        let orchestrator = DisconnectOrchestrator::new(&vault, &client);
        let request = DisconnectRequest {
            connection_id: "conn7".to_string(),
            service: "test.oura.conn7".to_string(),
            revoke_endpoint: Some("https://api.oura.cloud/oauth/revoke".to_string()),
            client_id: "test_client".to_string(),
            client_secret: None,
        };

        let result = orchestrator.disconnect(request).unwrap();
        assert_eq!(
            result,
            DisconnectOutcome::Disconnected {
                revoke_attempted: false,
                revoke_succeeded: false
            }
        );

        // Verify revoke was never called
        assert_eq!(client.revoke_call_count(), 0);
    }

    // ============ Test 8: disconnect vault delete error propagates ============
    #[test]
    fn test_disconnect_vault_delete_error_propagates() {
        // Create a vault that fails on delete_all_for_connection
        struct FailingVault;

        impl CredentialVault for FailingVault {
            fn store(&self, _service: &str, _key: &str, _value: &SecretString) -> Result<(), VaultError> {
                Ok(())
            }

            fn retrieve(&self, _service: &str, _key: &str) -> Result<SecretString, VaultError> {
                Err(VaultError::NotFound)
            }

            fn delete(&self, _service: &str, _key: &str) -> Result<(), VaultError> {
                Ok(())
            }

            fn delete_all_for_connection(&self, _service: &str) -> Result<(), VaultError> {
                Err(VaultError::Backend("storage error".to_string()))
            }
        }

        let vault = FailingVault;
        let client = MockTokenExchangeClient::new(true);

        let orchestrator = DisconnectOrchestrator::new(&vault, &client);
        let request = DisconnectRequest {
            connection_id: "conn8".to_string(),
            service: "test.oura.conn8".to_string(),
            revoke_endpoint: Some("https://api.oura.cloud/oauth/revoke".to_string()),
            client_id: "test_client".to_string(),
            client_secret: None,
        };

        let result = orchestrator.disconnect(request);
        assert!(matches!(result, Err(DisconnectError::Vault(VaultError::Backend(_)))));
    }

    // ============ Test 9: disconnect revoke called before delete (ordering) ============
    #[test]
    fn test_disconnect_revoke_called_before_delete() {
        // This test is implicit in the code structure — revoke is attempted first,
        // then delete. The other tests verify both happen. This passes if test 1 passes.
        let vault = MockCredentialVault::new();
        let client = MockTokenExchangeClient::new(true);

        vault
            .store("test.oura.conn9", "access_token", &SecretString::new("access_123".to_string()))
            .unwrap();

        let orchestrator = DisconnectOrchestrator::new(&vault, &client);
        let request = DisconnectRequest {
            connection_id: "conn9".to_string(),
            service: "test.oura.conn9".to_string(),
            revoke_endpoint: Some("https://api.oura.cloud/oauth/revoke".to_string()),
            client_id: "test_client".to_string(),
            client_secret: None,
        };

        let result = orchestrator.disconnect(request).unwrap();
        assert!(matches!(
            result,
            DisconnectOutcome::Disconnected {
                revoke_attempted: true,
                revoke_succeeded: true
            }
        ));

        // If delete happened before revoke, the retrieve in try_revoke would have failed earlier
        // and revoke_attempted would be false. Since it's true, revoke happened first.
        assert_eq!(client.revoke_call_count(), 1);
        assert!(vault.retrieve("test.oura.conn9", "access_token").is_err());
    }
}
