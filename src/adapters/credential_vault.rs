//! Platform-independent credential vault adapter trait.
//!
//! Contract source: T-006 Adapter 1 (fixed by T-201).
//! Core modules never import platform-specific implementations — only the
//! `Box<dyn CredentialVault>` injected from the composition root.

use crate::core::security::SecretString;
use std::fmt;

/// Error type for credential vault operations (T-006 L49-54).
/// `PartialEq` добавлен для сравнения в тестах refresh-оркестратора (T-203);
/// вариантов/полей контракта не меняет.
#[derive(Debug, Clone, PartialEq)]
pub enum VaultError {
    /// Item does not exist (`errSecItemNotFound` / generic keyring lookup miss).
    NotFound,
    /// User denied Keychain access prompt or ACL rejection.
    AccessDenied,
    /// Keychain locked (screen-lock state, `errSecInteractionNotAllowed`).
    Locked,
    /// Any other OS/backend error. The `String` payload must NEVER contain
    /// the secret value — only service/key identifiers and the OS error
    /// code/message (see T-201 §3.5 logging constraints).
    Backend(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::NotFound => write!(f, "credential not found"),
            VaultError::AccessDenied => write!(f, "access denied"),
            VaultError::Locked => write!(f, "vault locked"),
            VaultError::Backend(msg) => write!(f, "vault error: {}", msg),
        }
    }
}

impl std::error::Error for VaultError {}

/// Platform-independent credential storage adapter trait (T-006 L40-54, T-201 §6).
///
/// Implementations are injected at the composition root per T-006 Design Principles 1-2,
/// so core modules (OAuth state machine, sync engine) depend only on this trait,
/// not on any `keyring`/platform crate.
pub trait CredentialVault: Send + Sync {
    /// Store a credential in the vault.
    ///
    /// # Arguments
    ///
    /// * `service` - Namespaced service identifier (T-201 §3.1: `{bundle_id}.{provider}.{connection_id}`)
    /// * `key` - Credential kind: `"access_token"`, `"refresh_token"`, or `"client_secret"` (T-201 §2.1)
    /// * `value` - The secret to store; automatically redacted in logs via `SecretString` Debug impl
    ///
    /// # Errors
    ///
    /// Returns `VaultError` on OS errors, permission denial, or backend unavailability.
    fn store(&self, service: &str, key: &str, value: &SecretString) -> Result<(), VaultError>;

    /// Retrieve a credential from the vault.
    ///
    /// # Arguments
    ///
    /// * `service` - Namespaced service identifier (same format as `store`)
    /// * `key` - Credential kind: `"access_token"`, `"refresh_token"`, or `"client_secret"`
    ///
    /// # Errors
    ///
    /// Returns `VaultError::NotFound` if the `(service, key)` pair was never stored.
    /// Returns other `VaultError` variants on OS/backend errors.
    fn retrieve(&self, service: &str, key: &str) -> Result<SecretString, VaultError>;

    /// Delete a single credential from the vault.
    ///
    /// # Arguments
    ///
    /// * `service` - Namespaced service identifier
    /// * `key` - Credential kind
    ///
    /// # Errors
    ///
    /// Returns `VaultError::NotFound` if the `(service, key)` pair was never stored.
    /// Other errors indicate OS/backend failures.
    fn delete(&self, service: &str, key: &str) -> Result<(), VaultError>;

    /// Delete all credentials for a connection (all credential kinds).
    ///
    /// This is used by the uninstall flow (T-011 L36) to clean up all secrets
    /// associated with a connection.
    ///
    /// # Arguments
    ///
    /// * `service` - Namespaced service identifier (identifies the connection)
    ///
    /// # Behavior
    ///
    /// Must iterate over all known credential kinds (`access_token`, `refresh_token`,
    /// `client_secret`) and delete each. Per T-201 §3.4, if a kind was never stored
    /// (e.g., shared-OAuth-app mode doesn't store `client_secret`), the
    /// `VaultError::NotFound` for that individual key must NOT propagate as an error
    /// for the aggregate call — only non-`NotFound` errors should be surfaced.
    ///
    /// If one or more non-`NotFound` errors occur, this should return the first such
    /// error and attempt deletion of remaining kinds anyway (best-effort, per T-201 §3.4).
    ///
    /// # Errors
    ///
    /// Returns the first non-`NotFound` `VaultError` encountered, or `Ok(())` if all
    /// operations succeed or fail with `NotFound`. Per T-011 §2 and T-201 §5, the
    /// uninstall UI must be able to tell users "N of M entries could not be deleted"
    /// for partial failures — this is enforced by surfacing errors, not swallowing them.
    fn delete_all_for_connection(&self, service: &str) -> Result<(), VaultError>;
}
