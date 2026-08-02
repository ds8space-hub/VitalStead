//! T-104 + T-601 + T-602: Sync state persistence, orchestration, and locking.
//!
//! - T-104: cursor / last-successful-sync tracking per (provider, connection_id, data_type)
//!   in `sync_state.json`. This module owns storage of that state only.
//! - T-601: orchestrator that calls `record_success` + `save` after fetch-map-write succeeds
//!   for each connection (architecture.md L78, T-601 acceptance criteria).
//! - T-602: per-connection mutual-exclusion registry to serialize concurrent sync calls.

pub mod lock;
pub mod orchestrator;
pub mod state;

pub use lock::SyncLockRegistry;
pub use orchestrator::{ConnectionSyncReport, ConnectionSyncRequest, SyncOrchestrator};
pub use state::{
    load, record_success, save, sync_state_file_path, SyncEntry, SyncState, SyncStateError,
    SyncSuccess,
};
