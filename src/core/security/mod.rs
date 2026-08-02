//! Platform-independent security primitives (T-201 §2.1).
//! Core modules use these types; no platform-specific code allowed here (D-011).

pub mod secret_string;

#[cfg(test)]
mod log_lint;

pub use secret_string::SecretString;
