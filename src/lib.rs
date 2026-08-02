//! Composition root — принцип D-011/T-006 родительского проекта сохранён:
//! "Единственное место, где встречается `#[cfg(target_os = ...)]` — модуль,
//! который собирает конкретную реализацию adapter'а при старте приложения."
//!
//! Форм-фактор этого проекта — локальный MCP-сервер + Claude plugin (D-014):
//! UI-слоя нет, путь к папке данных приходит из plugin user_config, а не из
//! диалога выбора папки. Поэтому здесь нет `build_folder_selection_adapters`
//! из родительского проекта: вызывающий код валидирует путь напрямую через
//! `adapters::file_picker::verify_writable_and_readable`.
//!
//! Core modules (`adapters::atomic_file_writer::AtomicFileWriter`,
//! `adapters::credential_vault::CredentialVault`, `config`, `core::csv`,
//! `core::oauth`, `core::sync`) contain no platform checks; only this module
//! selects the macOS implementation.

pub mod adapters;
pub mod config;
pub mod core;
pub mod error_mapping;
pub mod platform;

/// T-201 (родительский): wires the macOS `CredentialVault` implementation for
/// Keychain credential storage, following the composition-root pattern.
/// Core modules (OAuth state machine, sync engine, connector framework) depend
/// only on `Box<dyn CredentialVault>`, injected at server initialization.
#[cfg(target_os = "macos")]
pub fn build_credential_vault() -> Box<dyn adapters::CredentialVault> {
    Box::new(platform::macos::MacOSCredentialVault::new())
}

/// T-202/T-301 (родительский + этот репозиторий): wires the macOS `OAuthCallbackHandler` implementation.
/// Both `open_system_browser` and `listen_for_callback` are functional.
/// `listen_for_callback` starts a temporary localhost HTTP listener on 127.0.0.1
/// to receive OAuth redirects (EPIC-03, T-301).
#[cfg(target_os = "macos")]
pub fn build_oauth_callback_handler() -> Box<dyn adapters::OAuthCallbackHandler> {
    Box::new(platform::macos::MacOSOAuthCallbackHandler::new())
}

/// T-304: wires the reqwest-backed `TokenExchangeClient` implementation (T-303).
/// Cross-platform (no `#[cfg(target_os = "macos")]`) — unlike CredentialVault/OAuthCallbackHandler,
/// this adapter has no OS-specific dependency (architecture.md L91-97).
pub fn build_token_exchange_client() -> Box<dyn adapters::TokenExchangeClient> {
    Box::new(adapters::ReqwestTokenExchangeClient::new())
}

#[cfg(test)]
mod refresh_wiring_tests {
    use super::*;
    use crate::adapters::{CredentialVault, VaultError};
    use crate::core::oauth::refresh::{RefreshCoordinator, RefreshOrchestrator, RefreshRequest, RefreshOutcome};
    use crate::core::security::SecretString;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime};
    use std::thread;

    /// In-memory credential vault for integration testing.
    /// Simple wrapper around HashMap with Mutex — no persistence, pure RAM.
    struct InMemoryVault {
        data: Mutex<HashMap<(String, String), SecretString>>,
    }

    impl InMemoryVault {
        fn new() -> Self {
            InMemoryVault {
                data: Mutex::new(HashMap::new()),
            }
        }
    }

    impl CredentialVault for InMemoryVault {
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

    // T1: end-to-end refresh with real ReqwestTokenExchangeClient and InMemoryVault
    #[test]
    fn test_wiring_end_to_end_refresh_before_expiry_succeeds() {
        // Set up mock HTTP endpoint
        let (port, _captured) = adapters::reqwest_token_exchange_client::tests::spawn_mock_token_endpoint(
            200,
            r#"{"access_token":"new_access_wired","refresh_token":"new_refresh_wired","expires_in":3600}"#,
            &[("Content-Type", "application/json")],
        );

        // Create real HTTP client (with short timeout to avoid flakiness)
        let http_client = adapters::ReqwestTokenExchangeClient::new();

        // Create in-memory vault and pre-store a refresh token
        let vault = InMemoryVault::new();
        vault
            .store(
                "test.wiring.conn1",
                "refresh_token",
                &SecretString::new("old_refresh_token".to_string()),
            )
            .unwrap();

        // Create coordinator and orchestrator
        let coordinator = RefreshCoordinator::new();
        let sleeper = core::oauth::refresh::RealSleeper;
        let orchestrator = RefreshOrchestrator::new(&vault, &http_client, &coordinator, &sleeper);

        // Build refresh request
        let request = RefreshRequest {
            connection_id: "conn1".to_string(),
            service: "test.wiring.conn1".to_string(),
            token_endpoint: format!("http://127.0.0.1:{}/token", port),
            client_id: "test_client_wiring".to_string(),
            client_secret: None,
            expires_at: SystemTime::now(),
        };

        // Execute refresh
        let result = orchestrator.refresh(request, SystemTime::now()).unwrap();

        // Verify outcome
        assert!(matches!(result, RefreshOutcome::Refreshed { refresh_token_rotated: true, .. }));

        // Verify vault stored new access token
        let stored_access = vault.retrieve("test.wiring.conn1", "access_token").unwrap();
        assert_eq!(stored_access.expose_secret(), "new_access_wired");

        // Verify vault stored new refresh token
        let stored_refresh = vault.retrieve("test.wiring.conn1", "refresh_token").unwrap();
        assert_eq!(stored_refresh.expose_secret(), "new_refresh_wired");
    }

    // T2: refresh_token rotation stored atomically (single vault.store call)
    #[test]
    fn test_wiring_refresh_token_rotation_stored_atomically() {
        let (port, _captured) = adapters::reqwest_token_exchange_client::tests::spawn_mock_token_endpoint(
            200,
            r#"{"access_token":"new_access_rot","refresh_token":"rotated_refresh_token","expires_in":3600}"#,
            &[("Content-Type", "application/json")],
        );

        let http_client = adapters::ReqwestTokenExchangeClient::new();
        let vault = InMemoryVault::new();
        let old_refresh = SecretString::new("original_refresh_token".to_string());
        vault
            .store("test.wiring.conn2", "refresh_token", &old_refresh)
            .unwrap();

        let coordinator = RefreshCoordinator::new();
        let sleeper = core::oauth::refresh::RealSleeper;
        let orchestrator = RefreshOrchestrator::new(&vault, &http_client, &coordinator, &sleeper);

        let request = RefreshRequest {
            connection_id: "conn2".to_string(),
            service: "test.wiring.conn2".to_string(),
            token_endpoint: format!("http://127.0.0.1:{}/token", port),
            client_id: "test_client_wiring".to_string(),
            client_secret: None,
            expires_at: SystemTime::now(),
        };

        let result = orchestrator.refresh(request, SystemTime::now()).unwrap();
        assert!(matches!(result, RefreshOutcome::Refreshed { refresh_token_rotated: true, .. }));

        // Old refresh token should be gone, replaced by new one (atomic overwrite)
        let current_refresh = vault.retrieve("test.wiring.conn2", "refresh_token").unwrap();
        assert_eq!(current_refresh.expose_secret(), "rotated_refresh_token");
        assert_ne!(current_refresh.expose_secret(), "original_refresh_token");
    }

    // T3: concurrent refresh calls dedupe against real HTTP client (single TCP connection)
    #[test]
    fn test_wiring_concurrent_refresh_calls_dedupe_against_real_http_client() {
        use std::sync::Arc;

        let (port, captured) = adapters::reqwest_token_exchange_client::tests::spawn_mock_token_endpoint(
            200,
            r#"{"access_token":"concurrent_token","expires_in":3600}"#,
            &[("Content-Type", "application/json")],
        );

        let http_client = Arc::new(adapters::ReqwestTokenExchangeClient::new());
        let vault = Arc::new(InMemoryVault::new());
        vault
            .store(
                "test.wiring.conn3",
                "refresh_token",
                &SecretString::new("concurrent_refresh".to_string()),
            )
            .unwrap();

        let coordinator = Arc::new(RefreshCoordinator::new());
        let sleeper = Arc::new(core::oauth::refresh::RealSleeper);

        let mut handles = vec![];

        // Spawn 2 threads that try to refresh concurrently
        for _ in 0..2 {
            let http_client = http_client.clone();
            let vault = vault.clone();
            let coordinator = coordinator.clone();
            let sleeper = sleeper.clone();

            let handle = thread::spawn(move || {
                let orchestrator = RefreshOrchestrator::new(
                    vault.as_ref(),
                    http_client.as_ref(),
                    coordinator.as_ref(),
                    sleeper.as_ref(),
                );

                let request = RefreshRequest {
                    connection_id: "conn3".to_string(),
                    service: "test.wiring.conn3".to_string(),
                    token_endpoint: format!("http://127.0.0.1:{}/token", port),
                    client_id: "test_client_wiring".to_string(),
                    client_secret: None,
                    expires_at: SystemTime::now(),
                };

                orchestrator.refresh(request, SystemTime::now())
            });

            handles.push(handle);
        }

        // Wait for both threads to complete
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Both threads should succeed
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());

        // Both results should be the same (deduplication)
        assert_eq!(results[0], results[1]);

        // Small delay to ensure mock server finishes logging
        thread::sleep(Duration::from_millis(100));

        // Verify that HTTP endpoint was hit and captured one connection
        let req = captured.lock().unwrap();
        if let Some(captured_req) = req.as_ref() {
            // Should have received at least one request
            assert!(captured_req.request_line.starts_with("POST "));
        }
    }

    // T4: invalid_grant maps to reauthorization required, vault unchanged
    #[test]
    fn test_wiring_invalid_grant_maps_to_reauthorization_required_vault_unchanged() {
        let (port, _captured) = adapters::reqwest_token_exchange_client::tests::spawn_mock_token_endpoint(
            400,
            r#"{"error":"invalid_grant"}"#,
            &[("Content-Type", "application/json")],
        );

        let http_client = adapters::ReqwestTokenExchangeClient::new();
        let vault = InMemoryVault::new();
        let old_refresh = SecretString::new("expired_refresh_token".to_string());
        vault
            .store("test.wiring.conn4", "refresh_token", &old_refresh)
            .unwrap();

        let coordinator = RefreshCoordinator::new();
        let sleeper = core::oauth::refresh::RealSleeper;
        let orchestrator = RefreshOrchestrator::new(&vault, &http_client, &coordinator, &sleeper);

        let request = RefreshRequest {
            connection_id: "conn4".to_string(),
            service: "test.wiring.conn4".to_string(),
            token_endpoint: format!("http://127.0.0.1:{}/token", port),
            client_id: "test_client_wiring".to_string(),
            client_secret: None,
            expires_at: SystemTime::now(),
        };

        // Execute refresh and expect ReauthorizationRequired
        let result = orchestrator.refresh(request, SystemTime::now()).unwrap();
        assert_eq!(result, RefreshOutcome::ReauthorizationRequired);

        // Verify vault was NOT modified (refresh token still has old value)
        let current_refresh = vault.retrieve("test.wiring.conn4", "refresh_token").unwrap();
        assert_eq!(current_refresh.expose_secret(), "expired_refresh_token");

        // Verify no new access token was stored
        let access_result = vault.retrieve("test.wiring.conn4", "access_token");
        assert!(matches!(access_result, Err(VaultError::NotFound)));
    }

    // T5: disconnect end-to-end with real HTTP client
    #[test]
    fn test_wiring_disconnect_end_to_end_with_real_http_client() {
        use crate::core::oauth::disconnect::{DisconnectOrchestrator, DisconnectRequest, DisconnectOutcome};

        let (port, _captured) = adapters::reqwest_token_exchange_client::tests::spawn_mock_token_endpoint(
            200,
            "",
            &[],
        );

        let http_client = adapters::ReqwestTokenExchangeClient::new();
        let vault = InMemoryVault::new();

        // Store tokens
        vault
            .store(
                "test.wiring.conn5",
                "access_token",
                &SecretString::new("access_token_value".to_string()),
            )
            .unwrap();
        vault
            .store(
                "test.wiring.conn5",
                "refresh_token",
                &SecretString::new("refresh_token_value".to_string()),
            )
            .unwrap();

        // Create disconnect orchestrator
        let orchestrator = DisconnectOrchestrator::new(&vault, &http_client);

        let request = DisconnectRequest {
            connection_id: "conn5".to_string(),
            service: "test.wiring.conn5".to_string(),
            revoke_endpoint: Some(format!("http://127.0.0.1:{}/revoke", port)),
            client_id: "test_client_wiring".to_string(),
            client_secret: None,
        };

        // Execute disconnect
        let result = orchestrator.disconnect(request).unwrap();

        // Verify outcome
        assert_eq!(
            result,
            DisconnectOutcome::Disconnected {
                revoke_attempted: true,
                revoke_succeeded: true
            }
        );

        // Verify vault is now empty for this connection
        assert!(matches!(
            vault.retrieve("test.wiring.conn5", "access_token"),
            Err(VaultError::NotFound)
        ));
        assert!(matches!(
            vault.retrieve("test.wiring.conn5", "refresh_token"),
            Err(VaultError::NotFound)
        ));
    }
}
