//! Connector implementations — provider-specific integrations for data synchronization.
//!
//! Each connector lives in its own submodule (e.g., `whoop`) and implements:
//! - DTO types for provider API responses
//! - Mapping to CSV rows (per csv/schema.rs contract)
//! - Rate limiting and API client logic

pub mod rate_limiter;
pub mod whoop;
