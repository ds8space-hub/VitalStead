//! Platform-independent core (D-011): connector contract, sync engine, CSV
//! schemas/serialization/upsert. No `#[cfg(target_os = ...)]` allowed here —
//! see `lib.rs` composition-root comment.

pub mod connectors;
pub mod csv;
pub mod oauth;
pub mod security;
pub mod sync;
