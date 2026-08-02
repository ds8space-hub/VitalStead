//! macOS-specific platform adapters (T-201, T-101, etc.).
//! Composed into the main lib.rs at the application level only.

pub mod credential_vault;
pub mod oauth_callback_handler;

pub use credential_vault::MacOSCredentialVault;
pub use oauth_callback_handler::MacOSOAuthCallbackHandler;
