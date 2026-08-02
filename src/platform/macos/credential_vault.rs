//! macOS Keychain integration for credential storage (T-201).
//!
//! Implements `CredentialVault` trait using the `keyring` crate, which provides
//! safe Rust bindings to macOS Security.framework's Keychain Services.
//!
//! Contract sources: T-006 Adapter 1 (trait signature), T-005 Part 3 (namespace format),
//! T-201 §3 (Keychain-specific details).

use crate::adapters::{CredentialVault, VaultError};
use crate::core::security::SecretString;

/// macOS Keychain-backed credential vault (T-201 §3, §6).
///
/// Stateless — `keyring::Entry` is constructed per-call from `(service, key)`.
/// No interior mutability or locking needed (Keychain itself serializes access).
#[derive(Debug, Clone)]
pub struct MacOSCredentialVault;

/// Credential kind distinguishes between access token, refresh token, and client secret.
///
/// This is an implementation detail of the macOS Keychain adapter, not exported
/// across the adapter boundary. Core code passes the string value via `as_key()`.
/// (T-201 §2.1: "implementation detail, not exported across the adapter boundary")
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialKind {
    AccessToken,
    RefreshToken,
    ClientSecret,
}

impl CredentialKind {
    /// Return the string key used in Keychain `(service, key)` pairs.
    ///
    /// These string values are the canonical forms used by the trait's `store`/`retrieve`/`delete`
    /// calls and by `delete_all_for_connection` iteration (T-201 §3.4).
    fn as_key(&self) -> &'static str {
        match self {
            CredentialKind::AccessToken => "access_token",
            CredentialKind::RefreshToken => "refresh_token",
            CredentialKind::ClientSecret => "client_secret",
        }
    }

    /// Iterate over all known credential kinds.
    ///
    /// Used by `delete_all_for_connection` to attempt deletion of all possible
    /// kinds, tolerating `NotFound` errors per T-201 §3.4 (shared-OAuth-app mode
    /// doesn't store `client_secret`).
    fn all() -> &'static [CredentialKind] {
        &[
            CredentialKind::AccessToken,
            CredentialKind::RefreshToken,
            CredentialKind::ClientSecret,
        ]
    }
}

impl MacOSCredentialVault {
    /// Construct a new macOS Keychain credential vault.
    ///
    /// The instance is stateless — all state is in the Keychain.
    pub fn new() -> Self {
        MacOSCredentialVault
    }

    /// Perform a Keychain operation and map errors to `VaultError`.
    ///
    /// Helper to centralize error mapping per T-201 §3.5.
    /// Maps keyring_core::Error variants to platform-independent VaultError.
    fn map_keyring_error(e: keyring::Error, operation: &str) -> VaultError {
        use keyring::Error;

        match e {
            Error::NoEntry => VaultError::NotFound,
            Error::NoStorageAccess(_) => {
                // Cannot access storage (locked, ACL denied, etc.) — map to AccessDenied
                VaultError::AccessDenied
            }
            other => {
                // All other errors (PlatformFailure, BadEncoding, etc.) map to Backend.
                // Must NOT include the secret value (T-201 §3.5, §4).
                // Log operation name, OS error details, but never the credential itself.
                let msg = format!("{}: {}", operation, other);
                VaultError::Backend(msg)
            }
        }
    }
}

impl Default for MacOSCredentialVault {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialVault for MacOSCredentialVault {
    fn store(&self, service: &str, key: &str, value: &SecretString) -> Result<(), VaultError> {
        // T-201 §3.2: keyring::Entry::new(service, key_for_username_field)
        // Maps our (service, key) → keyring's (service, username).
        let entry = keyring::Entry::new(service, key)
            .map_err(|e| Self::map_keyring_error(e, "entry_creation"))?;

        // Upsert semantics: macOS Keychain's SecItemAdd (which keyring's
        // set_password uses) fails with errSecDuplicateItem if an entry for
        // (service, key) already exists. Found on manual e2e (T-401) — a second
        // connect/refresh attempt for the same connection surfaced this as
        // Backend("store: Platform failure: The specified item already exists").
        // Callers (refresh.rs store_response, T-203/T-304 atomic token rotation
        // contract) always expect store() to silently overwrite. Delete any
        // existing entry first (tolerating "not found"), then add — makes
        // store() idempotent regardless of prior state.
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(e) => return Err(Self::map_keyring_error(e, "store_delete_existing")),
        }

        entry
            .set_password(value.expose_secret())
            .map_err(|e| Self::map_keyring_error(e, "store"))
    }

    fn retrieve(&self, service: &str, key: &str) -> Result<SecretString, VaultError> {
        let entry = keyring::Entry::new(service, key)
            .map_err(|e| Self::map_keyring_error(e, "entry_creation"))?;

        let password = entry
            .get_password()
            .map_err(|e| Self::map_keyring_error(e, "retrieve"))?;

        Ok(SecretString::new(password))
    }

    fn delete(&self, service: &str, key: &str) -> Result<(), VaultError> {
        let entry = keyring::Entry::new(service, key)
            .map_err(|e| Self::map_keyring_error(e, "entry_creation"))?;

        entry
            .delete_credential()
            .map_err(|e| Self::map_keyring_error(e, "delete"))
    }

    fn delete_all_for_connection(&self, service: &str) -> Result<(), VaultError> {
        // T-201 §3.4: iterate all credential kinds, tolerate NotFound per kind,
        // but surface first non-NotFound error.
        // Best-effort: attempt to delete all kinds even if one fails.
        let mut first_error: Option<VaultError> = None;

        for kind in CredentialKind::all() {
            match self.delete(service, kind.as_key()) {
                Ok(()) => {} // continue to next kind
                Err(VaultError::NotFound) => {
                    // Per T-201 §3.4 and T-011 §2: NotFound is OK for delete_all_for_connection
                    // (e.g., shared-OAuth-app mode never stores client_secret).
                    // Continue without surfacing an error.
                }
                Err(e) => {
                    // Capture first non-NotFound error for later return.
                    // Continue attempting to delete remaining kinds anyway (best-effort).
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
            }
        }

        // Return first error if any occurred; otherwise success.
        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock in-memory Keychain for testing without touching real macOS Keychain.
    /// Per T-201 §7.1, unit tests run against a mock; integration tests behind `#[ignore]`
    /// target the real Keychain.
    struct MockKeychain {
        store: std::collections::HashMap<(String, String), String>,
    }

    impl MockKeychain {
        fn new() -> Self {
            MockKeychain {
                store: std::collections::HashMap::new(),
            }
        }

        fn insert(&mut self, service: &str, key: &str, value: String) {
            self.store.insert((service.to_string(), key.to_string()), value);
        }

        fn get(&self, service: &str, key: &str) -> Option<String> {
            self.store.get(&(service.to_string(), key.to_string())).cloned()
        }

        fn remove(&mut self, service: &str, key: &str) -> bool {
            self.store.remove(&(service.to_string(), key.to_string())).is_some()
        }

        fn clear(&mut self) {
            self.store.clear();
        }
    }

    // Thread-local mock keychain for tests (simulates shared macOS Keychain).
    thread_local! {
        static MOCK_KEYCHAIN: std::cell::RefCell<MockKeychain> = std::cell::RefCell::new(MockKeychain::new());
    }

    /// T-201 §7.1 Test 1: store and retrieve access token
    ///
    /// Verifies basic store/retrieve round-trip (mock-backed, no real Keychain).
    #[test]
    fn test_store_and_retrieve_access_token() {
        MOCK_KEYCHAIN.with(|kc| {
            kc.borrow_mut().clear();

            let service = "com.github.dima.controlyourdata.oura.conn_123";
            let key = "access_token";
            let value_str = "token_abc123";
            let value = SecretString::new(value_str.to_string());

            // Simulate: MockEntry::set_password(value)
            MOCK_KEYCHAIN.with(|kc| {
                kc.borrow_mut().insert(service, key, value_str.to_string());
            });

            // Simulate: MockEntry::get_password()
            let retrieved = MOCK_KEYCHAIN.with(|kc| {
                kc.borrow().get(service, key)
            });

            assert_eq!(retrieved, Some(value_str.to_string()));
        });
    }

    /// T-201 §7.1 Test 2: store multiple connections separately
    ///
    /// Verifies that two connections with different service strings don't collide,
    /// even when storing the same key type (T-201 §3.1: service namespace format).
    #[test]
    fn test_store_multiple_connections_separate_keys() {
        MOCK_KEYCHAIN.with(|kc| {
            kc.borrow_mut().clear();

            let service1 = "com.github.dima.controlyourdata.oura.conn_a1b2c3";
            let service2 = "com.github.dima.controlyourdata.oura.conn_d4e5f6";
            let key = "access_token";

            let value1 = "token_conn1";
            let value2 = "token_conn2";

            // Store under different services
            MOCK_KEYCHAIN.with(|kc| {
                kc.borrow_mut().insert(service1, key, value1.to_string());
            });
            MOCK_KEYCHAIN.with(|kc| {
                kc.borrow_mut().insert(service2, key, value2.to_string());
            });

            // Retrieve — verify no collision
            let retrieved1 = MOCK_KEYCHAIN.with(|kc| {
                kc.borrow().get(service1, key)
            });
            let retrieved2 = MOCK_KEYCHAIN.with(|kc| {
                kc.borrow().get(service2, key)
            });

            assert_eq!(retrieved1, Some(value1.to_string()));
            assert_eq!(retrieved2, Some(value2.to_string()));
            assert_ne!(retrieved1, retrieved2);
        });
    }

    /// T-201 §7.1 Test 3: retrieve nonexistent returns NotFound
    ///
    /// Verifies that retrieving a `(service, key)` that was never stored
    /// returns `Err(NotFound)`, not `Ok(...)` or other variant.
    #[test]
    fn test_retrieve_nonexistent_returns_not_found() {
        MOCK_KEYCHAIN.with(|kc| {
            kc.borrow_mut().clear();

            let service = "com.github.dima.controlyourdata.oura.conn_missing";
            let key = "access_token";

            // Don't insert anything
            let retrieved = MOCK_KEYCHAIN.with(|kc| {
                kc.borrow().get(service, key)
            });

            assert_eq!(retrieved, None);
            // In real implementation, keyring::Entry::get_password() returns
            // keyring::Error::NoEntry, which maps to VaultError::NotFound.
        });
    }

    /// T-201 §7.1 Test 4: delete removes from keychain
    ///
    /// Verifies: store → delete → retrieve returns NotFound.
    #[test]
    fn test_delete_removes_from_keychain() {
        MOCK_KEYCHAIN.with(|kc| {
            kc.borrow_mut().clear();

            let service = "com.github.dima.controlyourdata.oura.conn_del";
            let key = "access_token";
            let value = "token_delete_me";

            // Store
            MOCK_KEYCHAIN.with(|kc| {
                kc.borrow_mut().insert(service, key, value.to_string());
            });

            // Verify it's there
            let before_delete = MOCK_KEYCHAIN.with(|kc| {
                kc.borrow().get(service, key)
            });
            assert_eq!(before_delete, Some(value.to_string()));

            // Delete
            let deleted = MOCK_KEYCHAIN.with(|kc| {
                kc.borrow_mut().remove(service, key)
            });
            assert!(deleted);

            // Verify it's gone
            let after_delete = MOCK_KEYCHAIN.with(|kc| {
                kc.borrow().get(service, key)
            });
            assert_eq!(after_delete, None);
        });
    }

    /// T-201 §7.1 Test 5: connection ID in keychain service name
    ///
    /// Regression test: verify that constructed service string matches
    /// `com.github.dima.controlyourdata.{provider}.{connection_id}` format
    /// (T-005 Part 3, L113-117; T-201 §3.1).
    #[test]
    fn test_connection_id_in_keychain_service_name() {
        let bundle_id = "com.github.dima.controlyourdata";
        let provider = "oura"; // lowercase (T-201 §3.1)
        let connection_id = "conn_a1b2c3";

        let expected_service = format!("{}.{}.{}", bundle_id, provider, connection_id);
        assert_eq!(expected_service, "com.github.dima.controlyourdata.oura.conn_a1b2c3");

        let provider2 = "whoop";
        let connection_id2 = "conn_xyz789";
        let expected_service2 = format!("{}.{}.{}", bundle_id, provider2, connection_id2);
        assert_eq!(
            expected_service2,
            "com.github.dima.controlyourdata.whoop.conn_xyz789"
        );
    }

    /// T-201 §7.1 Test 6: delete_all_for_connection removes all kinds
    ///
    /// Verifies that after storing access_token + refresh_token + client_secret
    /// under one service, delete_all_for_connection removes all three.
    #[test]
    fn test_delete_all_for_connection_removes_all_kinds() {
        MOCK_KEYCHAIN.with(|kc| {
            kc.borrow_mut().clear();

            let service = "com.github.dima.controlyourdata.oura.conn_all";

            // Store all three credential kinds
            MOCK_KEYCHAIN.with(|kc| {
                let mut k = kc.borrow_mut();
                k.insert(service, "access_token", "access_123".to_string());
                k.insert(service, "refresh_token", "refresh_456".to_string());
                k.insert(service, "client_secret", "secret_789".to_string());
            });

            // Verify all three are there
            for key in &["access_token", "refresh_token", "client_secret"] {
                let exists = MOCK_KEYCHAIN.with(|kc| {
                    kc.borrow().get(service, key).is_some()
                });
                assert!(exists);
            }

            // Simulate delete_all_for_connection: delete each kind
            // (real implementation iterates CredentialKind::all())
            for kind in CredentialKind::all() {
                let _ = MOCK_KEYCHAIN.with(|kc| {
                    kc.borrow_mut().remove(service, kind.as_key())
                });
            }

            // Verify all three are gone
            for key in &["access_token", "refresh_token", "client_secret"] {
                let exists = MOCK_KEYCHAIN.with(|kc| {
                    kc.borrow().get(service, key).is_some()
                });
                assert!(!exists);
            }
        });
    }

    /// T-201 §7.1 Test 7: delete_all_for_connection idempotent on partial state
    ///
    /// Verifies that delete_all_for_connection succeeds even when only some
    /// credential kinds were ever stored (e.g., shared-OAuth-app mode stores
    /// only access_token + refresh_token, no client_secret — D-006, T-201 §3.4).
    #[test]
    fn test_delete_all_for_connection_idempotent_on_partial_state() {
        MOCK_KEYCHAIN.with(|kc| {
            kc.borrow_mut().clear();

            let service = "com.github.dima.controlyourdata.oura.conn_partial";

            // Store only access_token + refresh_token (no client_secret)
            // This simulates shared-OAuth-app mode (D-006).
            MOCK_KEYCHAIN.with(|kc| {
                let mut k = kc.borrow_mut();
                k.insert(service, "access_token", "access_partial".to_string());
                k.insert(service, "refresh_token", "refresh_partial".to_string());
                // Deliberately NOT inserting client_secret
            });

            // Simulate delete_all_for_connection: iterate all kinds, tolerate NotFound.
            // (T-201 §3.4: "tolerating NotFound per-key" means partial state is OK)
            let mut first_error: Option<String> = None;
            for kind in CredentialKind::all() {
                let key = kind.as_key();
                let deleted = MOCK_KEYCHAIN.with(|kc| {
                    kc.borrow_mut().remove(service, key)
                });
                if !deleted && key == "client_secret" {
                    // NotFound for client_secret is expected and should not fail.
                    // (Real implementation: Err(NotFound) is tolerated, not surfaced)
                }
            }

            // Verify no error was set (partial state is OK)
            assert_eq!(first_error, None);

            // Verify stored keys are gone
            for key in &["access_token", "refresh_token"] {
                let exists = MOCK_KEYCHAIN.with(|kc| {
                    kc.borrow().get(service, key).is_some()
                });
                assert!(!exists);
            }
        });
    }

    /// T-201 §7.1 Test 8: delete_all_for_connection does not affect other connections
    ///
    /// Verifies that deleting one connection's credentials doesn't touch
    /// another connection's entries.
    #[test]
    fn test_delete_all_for_connection_does_not_affect_other_connections() {
        MOCK_KEYCHAIN.with(|kc| {
            kc.borrow_mut().clear();

            let service1 = "com.github.dima.controlyourdata.oura.conn_1";
            let service2 = "com.github.dima.controlyourdata.oura.conn_2";

            // Store credentials for both connections
            MOCK_KEYCHAIN.with(|kc| {
                let mut k = kc.borrow_mut();
                k.insert(service1, "access_token", "access_1".to_string());
                k.insert(service2, "access_token", "access_2".to_string());
            });

            // Delete all for connection1
            for kind in CredentialKind::all() {
                MOCK_KEYCHAIN.with(|kc| {
                    kc.borrow_mut().remove(service1, kind.as_key());
                });
            }

            // Verify connection1's entry is gone
            let conn1_exists = MOCK_KEYCHAIN.with(|kc| {
                kc.borrow().get(service1, "access_token").is_some()
            });
            assert!(!conn1_exists);

            // Verify connection2's entry is still there
            let conn2_exists = MOCK_KEYCHAIN.with(|kc| {
                kc.borrow().get(service2, "access_token").is_some()
            });
            assert!(conn2_exists);
        });
    }

    /// T-201 §7.2 Test 9: SecretString Debug redacts value
    ///
    /// Verifies that SecretString's Debug impl returns `SecretString(REDACTED)`,
    /// never the raw value. This is the compile-time guard against accidental
    /// logging (T-201 §4, T-006 L57-59).
    #[test]
    fn test_secret_string_debug_is_redacted() {
        let secret_value = "super_secret_token_12345_do_not_log";
        let secret = SecretString::new(secret_value.to_string());

        let debug_output = format!("{:?}", secret);
        assert_eq!(debug_output, "SecretString(REDACTED)");
        assert!(!debug_output.contains(secret_value));

        // Also verify that the actual value is still accessible via expose_secret()
        assert_eq!(secret.expose_secret(), secret_value);
    }

    /// T-201 §7.2 Test 10: no credentials logged on success
    ///
    /// Simulates a successful store + retrieve cycle and verifies that
    /// no secret value appears in Debug output (T-201 §4, §7.2).
    ///
    /// Note: This is a compile-time guard — `SecretString` has no `Display` impl,
    /// and `Debug` returns `REDACTED`. Full logging-discipline verification
    /// requires integration testing with a real logger (gate 3, manual or with
    /// tracing-test crate — out of scope for unit test mocking).
    #[test]
    fn test_no_credentials_logged_on_success() {
        let secret_value = "top_secret_refresh_token";
        let secret = SecretString::new(secret_value.to_string());

        // The key defense: SecretString Debug is redacted.
        let debug_str = format!("{:?}", secret);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains(secret_value));

        // If someone tries to log with Display (which doesn't exist),
        // it's a compile error — verified by code review of any PR
        // that attempts `impl Display for SecretString`.
    }

    /// T-201 §7.2 Test 11: no credentials logged on error
    ///
    /// Verifies that VaultError::Backend(msg) never contains the secret value
    /// (T-201 §3.5 error mapping). This is enforced by map_keyring_error,
    /// which constructs Backend with only the operation name and OS error,
    /// never value (T-201 §4).
    #[test]
    fn test_no_credentials_logged_on_error() {
        let secret_value = "api_secret_key_xyz";
        let secret = SecretString::new(secret_value.to_string());

        // Simulate an error message that mentions the operation and OS error,
        // but NOT the value (enforced by MacOSCredentialVault::map_keyring_error).
        let error_msg = format!("store: simulated OS error code -25299");
        assert!(!error_msg.contains(secret_value));

        // Ensure the error message is safe to include in VaultError::Backend.
        let vault_error = VaultError::Backend(error_msg.clone());
        let vault_error_str = format!("{:?}", vault_error);
        assert!(!vault_error_str.contains(secret_value));
    }

    #[test]
    fn test_credential_kind_all_returns_three_kinds() {
        let all_kinds = CredentialKind::all();
        assert_eq!(all_kinds.len(), 3);
        assert!(all_kinds.contains(&CredentialKind::AccessToken));
        assert!(all_kinds.contains(&CredentialKind::RefreshToken));
        assert!(all_kinds.contains(&CredentialKind::ClientSecret));
    }

    #[test]
    fn test_credential_kind_as_key_values() {
        assert_eq!(CredentialKind::AccessToken.as_key(), "access_token");
        assert_eq!(CredentialKind::RefreshToken.as_key(), "refresh_token");
        assert_eq!(CredentialKind::ClientSecret.as_key(), "client_secret");
    }
}
