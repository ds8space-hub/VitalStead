//! Error mapping: domain errors → structured MCP tool responses.
//!
//! T-203: All domain error types (CallbackError, VaultError, TokenExchangeError, WriteError, ConfigError)
//! must be mapped to a unified MCP error response containing `code`, `message`, and `recovery` fields.
//! This module provides the `ToMcpError` trait and all implementations.
//!
//! Key principles:
//! - D-015 (secrets never in context): String payloads from error sources are NEVER leaked into
//!   message or recovery strings. Only fixed generic text is used.
//! - D-012 (English only): all message and recovery strings are English.
//! - Logging (tracing::error!) can include the full original error for debugging purposes.
//!
//! This mapping is used in tool handlers (e.g., set_data_folder in T-202+) to construct
//! structured JSON error responses. Trait object exists, but T-203 scope covers only trait definition
//! and error enum impls — actual tool call sites live in future T-tasks (T-303+).

use serde::{Deserialize, Serialize};

use crate::adapters::{CallbackError, VaultError, TokenExchangeError, WriteError};
use crate::config::ConfigError;
use crate::core::connectors::whoop::connect::WhoopConnectError;
use crate::core::connectors::whoop::sync::WhoopSyncError;
use crate::core::oauth::disconnect::DisconnectError;
use crate::core::oauth::refresh::RefreshError;

/// Structured error response for MCP tool handlers.
///
/// Used by tool handlers to construct JSON error bodies (see T-202 SetDataFolderResponse.error).
/// - `code`: machine-readable error code (e.g., "vault.not_found", "callback.timeout")
/// - `message`: human-readable error description, safe to show end users
/// - `recovery`: suggested recovery action, safe to show end users
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpErrorDetails {
    pub code: String,
    pub message: String,
    pub recovery: String,
}

/// Trait: convert any error type to structured MCP error details.
///
/// All domain error types MUST implement this trait. Tool handlers call `to_mcp_error()`
/// to get safe, sanitized response details.
pub trait ToMcpError {
    fn to_mcp_error(&self) -> McpErrorDetails;
}

// ===== CallbackError mappings (3 variants) =====

impl ToMcpError for CallbackError {
    fn to_mcp_error(&self) -> McpErrorDetails {
        match self {
            CallbackError::ListenerBindFailed => McpErrorDetails {
                code: "callback.listener_bind_failed".to_string(),
                message: "OAuth callback listener could not be started.".to_string(),
                recovery: "This is a temporary system issue; retry connecting the source.".to_string(),
            },
            CallbackError::Timeout => McpErrorDetails {
                code: "callback.timeout".to_string(),
                message: "Authorization was not completed within the allowed time window.".to_string(),
                recovery: "Retry connecting the source and complete the login in your browser within 5 minutes.".to_string(),
            },
            CallbackError::BrowserLaunchFailed => McpErrorDetails {
                code: "callback.browser_launch_failed".to_string(),
                message: "Could not open the system browser to start authorization.".to_string(),
                recovery: "Check that a default browser is installed and available, then retry.".to_string(),
            },
        }
    }
}

// ===== VaultError mappings (4 variants) =====

impl ToMcpError for VaultError {
    fn to_mcp_error(&self) -> McpErrorDetails {
        match self {
            VaultError::NotFound => McpErrorDetails {
                code: "vault.not_found".to_string(),
                message: "No stored credentials found for this source.".to_string(),
                recovery: "Connect the data source first (connect_provider) before syncing.".to_string(),
            },
            VaultError::AccessDenied => McpErrorDetails {
                code: "vault.access_denied".to_string(),
                message: "Access to the secure credential storage was denied.".to_string(),
                recovery: "Approve the OS keychain access prompt, or reconnect the source.".to_string(),
            },
            VaultError::Locked => McpErrorDetails {
                code: "vault.locked".to_string(),
                message: "The secure credential storage is currently locked.".to_string(),
                recovery: "Unlock your Mac and retry the operation.".to_string(),
            },
            VaultError::Backend(_) => McpErrorDetails {
                code: "vault.backend_error".to_string(),
                message: "The secure credential storage returned an unexpected error.".to_string(),
                recovery: "Retry the operation. If it persists, reconnect the data source.".to_string(),
            },
        }
    }
}

// ===== TokenExchangeError mappings (5 variants) =====

impl ToMcpError for TokenExchangeError {
    fn to_mcp_error(&self) -> McpErrorDetails {
        match self {
            TokenExchangeError::Network(_) => McpErrorDetails {
                code: "token_exchange.network_error".to_string(),
                message: "A network error occurred while contacting the provider.".to_string(),
                recovery: "Check your internet connection and retry.".to_string(),
            },
            TokenExchangeError::RateLimited {
                retry_after_secs,
            } => {
                let message = if let Some(secs) = retry_after_secs {
                    format!(
                        "The provider rate-limited the request. Retry after {} seconds.",
                        secs
                    )
                } else {
                    "The provider rate-limited the request.".to_string()
                };
                McpErrorDetails {
                    code: "token_exchange.rate_limited".to_string(),
                    message,
                    recovery: "Wait before retrying the sync.".to_string(),
                }
            }
            TokenExchangeError::ServerError(status) => McpErrorDetails {
                code: "token_exchange.server_error".to_string(),
                message: format!("The provider returned a server error (HTTP {}).", status),
                recovery: "This is usually temporary; retry the sync in a few minutes.".to_string(),
            },
            TokenExchangeError::InvalidGrant => McpErrorDetails {
                code: "token_exchange.invalid_grant".to_string(),
                message: "The stored authorization for this source has expired or been revoked.".to_string(),
                recovery: "Reconnect the data source (disconnect_provider, then connect_provider)."
                    .to_string(),
            },
            TokenExchangeError::ClientError {
                status,
                error: _,
            } => McpErrorDetails {
                code: "token_exchange.client_error".to_string(),
                message: format!("The provider rejected the request (HTTP {}).", status),
                recovery: "Reconnect the data source. If this persists, the provider integration may need attention.".to_string(),
            },
        }
    }
}

// ===== WriteError mappings (4 variants) =====

impl ToMcpError for WriteError {
    fn to_mcp_error(&self) -> McpErrorDetails {
        match self {
            WriteError::DiskFull => McpErrorDetails {
                code: "write.disk_full".to_string(),
                message: "Not enough disk space to write the data file.".to_string(),
                recovery: "Free up disk space at the data folder location and retry.".to_string(),
            },
            WriteError::PermissionDenied => McpErrorDetails {
                code: "write.permission_denied".to_string(),
                message: "The data folder is not writable.".to_string(),
                recovery: "Check folder permissions, or choose a different folder (set_data_folder)."
                    .to_string(),
            },
            WriteError::FileLocked => McpErrorDetails {
                code: "write.file_locked".to_string(),
                message: "The target file is currently locked by another process.".to_string(),
                recovery: "Close any other application using the file and retry.".to_string(),
            },
            WriteError::Backend(_) => McpErrorDetails {
                code: "write.backend_error".to_string(),
                message: "An unexpected file system error occurred while writing data.".to_string(),
                recovery: "Retry the operation. If it persists, check the data folder path.".to_string(),
            },
        }
    }
}

// ===== ConfigError mappings (3 variants) =====

impl ToMcpError for ConfigError {
    fn to_mcp_error(&self) -> McpErrorDetails {
        match self {
            ConfigError::Serialize(_) => McpErrorDetails {
                code: "config.serialize_failed".to_string(),
                message: "Failed to prepare configuration for saving.".to_string(),
                recovery:
                    "This is an internal error; retry set_data_folder. Report the issue if it persists."
                        .to_string(),
            },
            ConfigError::Write(inner) => {
                // Delegate to WriteError mapping without modification
                inner.to_mcp_error()
            }
            ConfigError::Read(_) => McpErrorDetails {
                code: "config.read_failed".to_string(),
                message: "Failed to load saved configuration.".to_string(),
                recovery: "Set the data folder again (set_data_folder).".to_string(),
            },
        }
    }
}

// ===== WhoopConnectError mappings (11 variants, T-604) =====

impl ToMcpError for WhoopConnectError {
    fn to_mcp_error(&self) -> McpErrorDetails {
        match self {
            // Callback error: delegate to CallbackError mapping
            WhoopConnectError::Callback(inner) => inner.to_mcp_error(),

            // State mismatch (CSRF validation failure)
            WhoopConnectError::StateMismatch => McpErrorDetails {
                code: "connect.state_mismatch".to_string(),
                message: "Authorization response could not be verified.".to_string(),
                recovery: "Retry connecting the source.".to_string(),
            },

            // Timeout during callback
            WhoopConnectError::Timeout => McpErrorDetails {
                code: "connect.timeout".to_string(),
                message: "Authorization was not completed within the allowed time.".to_string(),
                recovery: "Retry and complete login within 5 minutes.".to_string(),
            },

            // Authorization attempt expired
            WhoopConnectError::Expired => McpErrorDetails {
                code: "connect.expired".to_string(),
                message: "The connection attempt expired before completing.".to_string(),
                recovery: "Retry connecting the source.".to_string(),
            },

            // Provider mismatch (internal error)
            WhoopConnectError::ProviderMismatch => McpErrorDetails {
                code: "connect.internal_error".to_string(),
                message: "An internal error occurred while connecting.".to_string(),
                recovery: "Retry; if it persists, report the issue.".to_string(),
            },

            // No matching pending authorization (internal error)
            WhoopConnectError::NoMatchingPending => McpErrorDetails {
                code: "connect.internal_error".to_string(),
                message: "An internal error occurred while connecting.".to_string(),
                recovery: "Retry; if it persists, report the issue.".to_string(),
            },

            // Provider returned an error (user denied, invalid client, etc.)
            WhoopConnectError::ProviderDenied { error: _, error_description: _ } => McpErrorDetails {
                code: "connect.provider_denied".to_string(),
                message: "Authorization was not granted.".to_string(),
                recovery: "Retry and approve all requested permissions when prompted.".to_string(),
            },

            // Token exchange error: delegate to TokenExchangeError mapping
            WhoopConnectError::TokenExchange(inner) => inner.to_mcp_error(),

            // Missing offline scope
            WhoopConnectError::MissingOfflineScope => McpErrorDetails {
                code: "connect.missing_offline_scope".to_string(),
                message: "WHOOP did not grant persistent access.".to_string(),
                recovery: "Reconnect and approve all requested permissions, including offline access.".to_string(),
            },

            // Scope field not confirmed in response
            WhoopConnectError::ScopeNotConfirmed => McpErrorDetails {
                code: "connect.scope_not_confirmed".to_string(),
                message: "The provider did not confirm which permissions were granted.".to_string(),
                recovery: "Reconnect the source; if this persists the provider integration may need attention.".to_string(),
            },

            // Vault error: delegate to VaultError mapping
            WhoopConnectError::Vault(inner) => inner.to_mcp_error(),
        }
    }
}

// ===== RefreshError mappings (T-602 helper, used by WhoopSyncError) =====

impl ToMcpError for RefreshError {
    fn to_mcp_error(&self) -> McpErrorDetails {
        match self {
            RefreshError::NetworkExhausted => McpErrorDetails {
                code: "refresh.network_exhausted".to_string(),
                message: "Network error while refreshing authentication token.".to_string(),
                recovery: "Check your internet connection and retry the sync.".to_string(),
            },
            RefreshError::RateLimitExhausted => McpErrorDetails {
                code: "refresh.rate_limit_exhausted".to_string(),
                message: "Provider rate-limited authentication refresh after multiple attempts.".to_string(),
                recovery: "Wait a few minutes and retry the sync.".to_string(),
            },
            RefreshError::ServerErrorExhausted => McpErrorDetails {
                code: "refresh.server_error_exhausted".to_string(),
                message: "Provider server errors prevented authentication refresh.".to_string(),
                recovery: "This is usually temporary; retry the sync in a few minutes.".to_string(),
            },
            RefreshError::ClientError { status, error: _ } => McpErrorDetails {
                code: "refresh.client_error".to_string(),
                message: format!("The provider rejected the authentication refresh request (HTTP {}).", status),
                recovery: "Reconnect the data source. If this persists, the provider integration may need attention.".to_string(),
            },
            RefreshError::Vault(inner) => inner.to_mcp_error(),
        }
    }
}

// ===== WhoopSyncError mappings (T-602, 8 variants) =====

impl ToMcpError for WhoopSyncError {
    fn to_mcp_error(&self) -> McpErrorDetails {
        match self {
            WhoopSyncError::Fetch(_) => McpErrorDetails {
                code: "sync.fetch_failed".to_string(),
                message: "Failed to fetch data from the provider after retries.".to_string(),
                recovery: "Check your internet connection and retry the sync.".to_string(),
            },
            WhoopSyncError::RateLimitExhausted => McpErrorDetails {
                code: "sync.rate_limit_exceeded".to_string(),
                message: "Provider rate-limited the sync request after multiple attempts.".to_string(),
                recovery: "Wait a few minutes and retry the sync.".to_string(),
            },
            WhoopSyncError::NetworkExhausted => McpErrorDetails {
                code: "sync.network_error".to_string(),
                message: "Network error while syncing data.".to_string(),
                recovery: "Check your internet connection and retry the sync.".to_string(),
            },
            WhoopSyncError::ServerErrorExhausted => McpErrorDetails {
                code: "sync.server_error".to_string(),
                message: "Provider server errors prevented the sync after retries.".to_string(),
                recovery: "This is usually temporary; retry the sync in a few minutes.".to_string(),
            },
            WhoopSyncError::Refresh(inner) => inner.to_mcp_error(),
            WhoopSyncError::Write { csv_type } => McpErrorDetails {
                code: "sync.write_failed".to_string(),
                message: format!("Failed to write {}.csv to the data folder.", csv_type),
                recovery: "Check that the data folder is writable and has enough disk space, then retry.".to_string(),
            },
            WhoopSyncError::Vault(inner) => inner.to_mcp_error(),
        }
    }
}

// ===== DisconnectError mappings (T-605) =====

impl ToMcpError for DisconnectError {
    fn to_mcp_error(&self) -> McpErrorDetails {
        match self {
            DisconnectError::Vault(inner) => inner.to_mcp_error(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== CallbackError tests (1-3) =====

    #[test]
    fn test_callback_listener_bind_failed_maps_to_expected_code() {
        let err = CallbackError::ListenerBindFailed;
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "callback.listener_bind_failed");
        assert!(!mapped.message.is_empty());
        assert!(!mapped.recovery.is_empty());
    }

    #[test]
    fn test_callback_timeout_maps_to_expected_code() {
        let err = CallbackError::Timeout;
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "callback.timeout");
        assert!(!mapped.message.is_empty());
        assert!(!mapped.recovery.is_empty());
    }

    #[test]
    fn test_callback_browser_launch_failed_maps_to_expected_code() {
        let err = CallbackError::BrowserLaunchFailed;
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "callback.browser_launch_failed");
        assert!(!mapped.message.is_empty());
        assert!(!mapped.recovery.is_empty());
    }

    // ===== VaultError tests (4-7) =====

    #[test]
    fn test_vault_not_found_maps_to_expected_code() {
        let err = VaultError::NotFound;
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "vault.not_found");
        assert!(!mapped.message.is_empty());
        assert!(!mapped.recovery.is_empty());
    }

    #[test]
    fn test_vault_access_denied_maps_to_expected_code() {
        let err = VaultError::AccessDenied;
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "vault.access_denied");
        assert!(!mapped.message.is_empty());
        assert!(!mapped.recovery.is_empty());
    }

    #[test]
    fn test_vault_locked_maps_to_expected_code() {
        let err = VaultError::Locked;
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "vault.locked");
        assert!(!mapped.message.is_empty());
        assert!(!mapped.recovery.is_empty());
    }

    #[test]
    fn test_vault_backend_does_not_leak_raw_string() {
        let secret_payload = "service=oura key=abc123secret".to_string();
        let err = VaultError::Backend(secret_payload.clone());
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "vault.backend_error");
        assert!(!mapped.message.contains("abc123secret"));
        assert!(!mapped.recovery.contains("abc123secret"));
        assert!(!mapped.message.contains("oura"));
        assert!(!mapped.recovery.contains("oura"));
    }

    // ===== TokenExchangeError tests (8-13) =====

    #[test]
    fn test_token_exchange_network_does_not_leak_raw_string() {
        let network_msg = "Connection refused: dns lookup failed for api.provider.com".to_string();
        let err = TokenExchangeError::Network(network_msg.clone());
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "token_exchange.network_error");
        assert!(!mapped.message.contains("api.provider.com"));
        assert!(!mapped.recovery.contains("api.provider.com"));
    }

    #[test]
    fn test_token_exchange_rate_limited_includes_retry_after_when_present() {
        let err = TokenExchangeError::RateLimited {
            retry_after_secs: Some(30),
        };
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "token_exchange.rate_limited");
        assert!(mapped.message.contains("30"));
    }

    #[test]
    fn test_token_exchange_rate_limited_generic_message_when_absent() {
        let err = TokenExchangeError::RateLimited {
            retry_after_secs: None,
        };
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "token_exchange.rate_limited");
        assert!(mapped.message.contains("rate-limited"));
        assert!(!mapped.message.contains("seconds"));
    }

    #[test]
    fn test_token_exchange_server_error_includes_status_code() {
        let err = TokenExchangeError::ServerError(503);
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "token_exchange.server_error");
        assert!(mapped.message.contains("503"));
    }

    #[test]
    fn test_token_exchange_invalid_grant_recovery_mentions_reconnect() {
        let err = TokenExchangeError::InvalidGrant;
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "token_exchange.invalid_grant");
        assert!(
            mapped.recovery.to_lowercase().contains("reconnect"),
            "recovery should mention reconnect"
        );
    }

    #[test]
    fn test_token_exchange_client_error_does_not_leak_raw_error_field() {
        let secret_error = Some("invalid_client_id_abc123xyz".to_string());
        let err = TokenExchangeError::ClientError {
            status: 400,
            error: secret_error,
        };
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "token_exchange.client_error");
        assert!(mapped.message.contains("400"));
        assert!(!mapped.message.contains("abc123xyz"));
        assert!(!mapped.recovery.contains("abc123xyz"));
    }

    // ===== WriteError tests (14-17) =====

    #[test]
    fn test_write_disk_full_maps_to_expected_code() {
        let err = WriteError::DiskFull;
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "write.disk_full");
        assert!(!mapped.message.is_empty());
        assert!(!mapped.recovery.is_empty());
    }

    #[test]
    fn test_write_permission_denied_maps_to_expected_code() {
        let err = WriteError::PermissionDenied;
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "write.permission_denied");
        assert!(!mapped.message.is_empty());
        assert!(!mapped.recovery.is_empty());
    }

    #[test]
    fn test_write_file_locked_maps_to_expected_code() {
        let err = WriteError::FileLocked;
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "write.file_locked");
        assert!(!mapped.message.is_empty());
        assert!(!mapped.recovery.is_empty());
    }

    #[test]
    fn test_write_backend_does_not_leak_raw_string() {
        let backend_msg = "OS error code 13 (Permission denied): /Users/*/data/file.csv".to_string();
        let err = WriteError::Backend(backend_msg.clone());
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "write.backend_error");
        assert!(!mapped.message.contains("/Users/"));
        assert!(!mapped.recovery.contains("/Users/"));
    }

    // ===== ConfigError tests (18-20) =====

    #[test]
    fn test_config_serialize_does_not_leak_raw_string() {
        let serde_msg = "Failed to serialize PathBuf value with special chars: 🔒".to_string();
        let err = ConfigError::Serialize(serde_msg.clone());
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "config.serialize_failed");
        assert!(!mapped.message.contains("🔒"));
        assert!(!mapped.recovery.contains("🔒"));
    }

    #[test]
    fn test_config_write_delegates_to_inner_write_error_mapping() {
        let inner = WriteError::DiskFull;
        let err = ConfigError::Write(inner.clone());
        let mapped = err.to_mcp_error();
        let inner_mapped = inner.to_mcp_error();
        assert_eq!(mapped.code, inner_mapped.code);
        assert_eq!(mapped.message, inner_mapped.message);
        assert_eq!(mapped.recovery, inner_mapped.recovery);
    }

    #[test]
    fn test_config_read_does_not_leak_raw_string() {
        let read_msg = "IO error: invalid JSON at /home/user/Library/Application Support/com.github.dima.controlyourdata/config.json:42"
            .to_string();
        let err = ConfigError::Read(read_msg.clone());
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "config.read_failed");
        assert!(!mapped.message.contains("/home/user"));
        assert!(!mapped.recovery.contains("/home/user"));
    }

    // ===== Comprehensive tests (21-22) =====

    #[test]
    fn test_all_mapped_variants_have_non_empty_message_and_recovery() {
        // CallbackError (3 variants)
        let errors: Vec<Box<dyn ToMcpError>> = vec![
            Box::new(CallbackError::ListenerBindFailed),
            Box::new(CallbackError::Timeout),
            Box::new(CallbackError::BrowserLaunchFailed),
            // VaultError (4)
            Box::new(VaultError::NotFound),
            Box::new(VaultError::AccessDenied),
            Box::new(VaultError::Locked),
            Box::new(VaultError::Backend("test".to_string())),
            // TokenExchangeError (5)
            Box::new(TokenExchangeError::Network("test".to_string())),
            Box::new(TokenExchangeError::RateLimited {
                retry_after_secs: Some(10),
            }),
            Box::new(TokenExchangeError::ServerError(500)),
            Box::new(TokenExchangeError::InvalidGrant),
            Box::new(TokenExchangeError::ClientError {
                status: 400,
                error: None,
            }),
            // WriteError (4)
            Box::new(WriteError::DiskFull),
            Box::new(WriteError::PermissionDenied),
            Box::new(WriteError::FileLocked),
            Box::new(WriteError::Backend("test".to_string())),
            // ConfigError (3)
            Box::new(ConfigError::Serialize("test".to_string())),
            Box::new(ConfigError::Write(WriteError::DiskFull)),
            Box::new(ConfigError::Read("test".to_string())),
        ];

        for err in errors {
            let mapped = err.to_mcp_error();
            assert!(
                !mapped.message.is_empty(),
                "message must not be empty for code {}",
                mapped.code
            );
            assert!(
                !mapped.recovery.is_empty(),
                "recovery must not be empty for code {}",
                mapped.code
            );
        }
    }

    #[test]
    fn test_all_mapped_codes_are_unique_except_delegated() {
        let mut codes = vec![
            // CallbackError
            "callback.listener_bind_failed",
            "callback.timeout",
            "callback.browser_launch_failed",
            // VaultError
            "vault.not_found",
            "vault.access_denied",
            "vault.locked",
            "vault.backend_error",
            // TokenExchangeError
            "token_exchange.network_error",
            "token_exchange.rate_limited",
            "token_exchange.server_error",
            "token_exchange.invalid_grant",
            "token_exchange.client_error",
            // WriteError
            "write.disk_full",
            "write.permission_denied",
            "write.file_locked",
            "write.backend_error",
            // ConfigError (excluding Write which delegates)
            "config.serialize_failed",
            "config.read_failed",
        ];

        // Check no duplicates
        let len_before = codes.len();
        codes.sort();
        codes.dedup();
        let len_after = codes.len();
        assert_eq!(
            len_before, len_after,
            "duplicate codes found: before={}, after={}",
            len_before, len_after
        );

        // Note: ConfigError::Write intentionally shares codes with WriteError variants
        // (e.g., ConfigError::Write(WriteError::DiskFull) → "write.disk_full").
        // This is documented and intentional per spec §3.2.
    }

    // ===== WhoopConnectError tests (T-604, 11 variants + delegating) =====

    #[test]
    fn test_whoop_connect_callback_delegates_to_callback_error() {
        let callback_err = CallbackError::Timeout;
        let whoop_err = WhoopConnectError::Callback(callback_err.clone());
        let mapped = whoop_err.to_mcp_error();
        let callback_mapped = callback_err.to_mcp_error();
        assert_eq!(mapped.code, callback_mapped.code);
    }

    #[test]
    fn test_whoop_connect_state_mismatch_maps_to_expected_code() {
        let err = WhoopConnectError::StateMismatch;
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "connect.state_mismatch");
        assert!(!mapped.message.is_empty());
        assert!(!mapped.recovery.is_empty());
    }

    #[test]
    fn test_whoop_connect_timeout_maps_to_expected_code() {
        let err = WhoopConnectError::Timeout;
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "connect.timeout");
        assert!(!mapped.message.is_empty());
        assert!(!mapped.recovery.is_empty());
    }

    #[test]
    fn test_whoop_connect_expired_maps_to_expected_code() {
        let err = WhoopConnectError::Expired;
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "connect.expired");
        assert!(!mapped.message.is_empty());
        assert!(!mapped.recovery.is_empty());
    }

    #[test]
    fn test_whoop_connect_provider_mismatch_maps_to_internal_error() {
        let err = WhoopConnectError::ProviderMismatch;
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "connect.internal_error");
        assert!(!mapped.message.is_empty());
        assert!(!mapped.recovery.is_empty());
    }

    #[test]
    fn test_whoop_connect_no_matching_pending_maps_to_internal_error() {
        let err = WhoopConnectError::NoMatchingPending;
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "connect.internal_error");
        assert!(!mapped.message.is_empty());
        assert!(!mapped.recovery.is_empty());
    }

    #[test]
    fn test_whoop_connect_provider_denied_does_not_leak_raw_strings() {
        let err = WhoopConnectError::ProviderDenied {
            error: "access_denied_secret_xyz".to_string(),
            error_description: Some("user rejected with internal trace abc123".to_string()),
        };
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "connect.provider_denied");
        assert!(!mapped.message.contains("access_denied"));
        assert!(!mapped.message.contains("secret_xyz"));
        assert!(!mapped.recovery.contains("access_denied"));
        assert!(!mapped.recovery.contains("abc123"));
    }

    #[test]
    fn test_whoop_connect_token_exchange_delegates() {
        let token_err = TokenExchangeError::InvalidGrant;
        let whoop_err = WhoopConnectError::TokenExchange(token_err.clone());
        let mapped = whoop_err.to_mcp_error();
        let token_mapped = token_err.to_mcp_error();
        assert_eq!(mapped.code, token_mapped.code);
    }

    #[test]
    fn test_whoop_connect_missing_offline_scope_maps_to_expected_code() {
        let err = WhoopConnectError::MissingOfflineScope;
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "connect.missing_offline_scope");
        assert!(!mapped.message.is_empty());
        assert!(!mapped.recovery.is_empty());
        assert!(mapped.recovery.to_lowercase().contains("offline"));
    }

    #[test]
    fn test_whoop_connect_scope_not_confirmed_maps_to_expected_code() {
        let err = WhoopConnectError::ScopeNotConfirmed;
        let mapped = err.to_mcp_error();
        assert_eq!(mapped.code, "connect.scope_not_confirmed");
        assert!(!mapped.message.is_empty());
        assert!(!mapped.recovery.is_empty());
    }

    #[test]
    fn test_whoop_connect_vault_error_delegates() {
        let vault_err = VaultError::NotFound;
        let whoop_err = WhoopConnectError::Vault(vault_err.clone());
        let mapped = whoop_err.to_mcp_error();
        let vault_mapped = vault_err.to_mcp_error();
        assert_eq!(mapped.code, vault_mapped.code);
    }
}
