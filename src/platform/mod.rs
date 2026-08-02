//! Platform-specific adapter implementations (T-201, per lib.rs composition-root principle).
//! These modules are selected at the composition root in lib.rs via `#[cfg(target_os = ...)]`.

#[cfg(target_os = "macos")]
pub mod macos;
