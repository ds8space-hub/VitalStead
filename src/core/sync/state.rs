//! Sync state persistence — T-104.
//!
//! Contract sources:
//! - State lives in the app support directory, not the user's CSV/data
//!   folder, and never contains tokens/secrets — csv-contract.md L88-92
//!   ("Для них используется отдельный файл состояния в системном каталоге
//!   приложения. Токены и secrets в этот файл не записываются.").
//! - State is updated only after all of a source's CSVs were written
//!   successfully — architecture.md L78 ("обновление состояния только
//!   после успешной записи всех файлов источника"); T-007-SCHEMA-UPSERT.md
//!   L567-586 ("Save sync state after all CSVs written" / "Transaction
//!   boundary: all CSVs written, then state persisted"). `save`/
//!   `record_success` here are the primitives; invoking them in that order
//!   is the sync loop's responsibility (out of T-104 scope).
//! - Writes go through `AtomicFileWriter` so a crash between `write_temp`
//!   and `replace_atomic` leaves the prior state untouched —
//!   T-006-PLATFORM-ADAPTERS.md L300-303.
//! - On a corrupted state file, recovery goes through
//!   `recover_from_backup` (T-006 L306-308); if both the primary file and
//!   the backup are unreadable/absent, `load` returns an empty
//!   `SyncState::default()` rather than failing the caller — a missing
//!   cursor only costs an extra overlap-window re-fetch (T-007 upsert is
//!   idempotent), never data loss.
//! - `load` performs no CSV I/O — sync state and CSV files are written
//!   through the same adapter but are **not** one transaction
//!   (T-006 L310-316).

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::adapters::{AtomicFileWriter, WriteError};
use crate::config::config_dir;

/// Current on-disk schema version for `SyncState` itself (distinct from
/// `SyncEntry::schema_version`, which tracks the per-CSV-type schema).
/// Bumped only if `SyncState`'s own shape changes; unknown future fields on
/// `SyncEntry` are ignored by `serde` by default (forward-compat).
const SYNC_STATE_VERSION: u32 = 1;

/// Container for all tracked (provider, connection_id, data_type) cursors.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncState {
    pub version: u32,
    pub entries: Vec<SyncEntry>,
}

impl Default for SyncState {
    fn default() -> Self {
        Self {
            version: SYNC_STATE_VERSION,
            entries: Vec::new(),
        }
    }
}

/// One (provider, connection_id, data_type) cursor record. No token/secret
/// fields — csv-contract.md L91-92 forbids storing secrets here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncEntry {
    pub provider: String,
    pub connection_id: String,
    pub data_type: String,
    pub cursor: Option<String>,
    pub last_successful_sync_at: DateTime<Utc>,
    pub schema_version: u32,
}

#[derive(Debug)]
pub enum SyncStateError {
    Serialize(String),
    Write(WriteError),
}

/// T-005 L91, L102-103 bundle-id app-support directory, reused from
/// `config.rs` (T-101) rather than re-deriving the bundle id string here.
fn sync_state_dir(app_support_dir: &Path) -> PathBuf {
    config_dir(app_support_dir)
}

pub fn sync_state_file_path(app_support_dir: &Path) -> PathBuf {
    sync_state_dir(app_support_dir).join("sync_state.json")
}

fn backup_state_file_path(app_support_dir: &Path) -> PathBuf {
    let mut path = sync_state_file_path(app_support_dir);
    let file_name = format!(
        "{}.backup",
        path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()
    );
    path.set_file_name(file_name);
    path
}

/// Persists `state` via the injected `AtomicFileWriter` (T-006 L300-303):
/// a write failure (disk full, permission denied, crash mid-replace)
/// cannot corrupt the previously saved `sync_state.json`.
pub fn save(
    writer: &dyn AtomicFileWriter,
    app_support_dir: &Path,
    state: &SyncState,
) -> Result<(), SyncStateError> {
    let target = sync_state_file_path(app_support_dir);
    let target_dir = sync_state_dir(app_support_dir);

    let content =
        serde_json::to_vec_pretty(state).map_err(|e| SyncStateError::Serialize(e.to_string()))?;

    std::fs::create_dir_all(&target_dir)
        .map_err(|e| SyncStateError::Write(WriteError::Backend(e.to_string())))?;

    let temp_path = writer
        .write_temp(&target_dir, &content)
        .map_err(SyncStateError::Write)?;
    writer
        .replace_atomic(&target, &temp_path)
        .map_err(SyncStateError::Write)
}

/// Loads `sync_state.json`, recovering from `.backup` on corruption
/// (T-006 L306-308). Never panics and never touches CSV files; when
/// neither the primary file nor the backup can be read, returns an empty
/// `SyncState::default()` as a safe fallback rather than an error.
pub fn load(writer: &dyn AtomicFileWriter, app_support_dir: &Path) -> Result<SyncState, ()> {
    let target = sync_state_file_path(app_support_dir);

    if let Some(state) = read_and_parse(&target) {
        return Ok(state);
    }

    // Primary file missing or corrupt: attempt recovery from backup.
    if writer.recover_from_backup(&target).is_ok() {
        if let Some(state) = read_and_parse(&target) {
            return Ok(state);
        }
    }

    // Fall back to the backup file directly in case `recover_from_backup`
    // is a no-op test double or the backup lives at a fixed sibling path.
    let backup = backup_state_file_path(app_support_dir);
    if let Some(state) = read_and_parse(&backup) {
        return Ok(state);
    }

    Ok(SyncState::default())
}

fn read_and_parse(path: &Path) -> Option<SyncState> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Grouped arguments for `record_success` — keeps the function within the
/// 5-parameter hard limit (6 logical fields would otherwise exceed it).
pub struct SyncSuccess {
    pub provider: String,
    pub connection_id: String,
    pub data_type: String,
    pub cursor: Option<String>,
    pub schema_version: u32,
    pub now: DateTime<Utc>,
}

/// In-memory upsert of the entry keyed by (provider, connection_id,
/// data_type). Caller must call `save` afterwards to persist — kept
/// separate so the sync loop can batch multiple `record_success` calls
/// (one per data type) into a single `save` after all CSVs for a source
/// are written (architecture.md L78).
pub fn record_success(state: &mut SyncState, success: SyncSuccess) {
    let existing = state.entries.iter_mut().find(|e| {
        e.provider == success.provider
            && e.connection_id == success.connection_id
            && e.data_type == success.data_type
    });

    if let Some(entry) = existing {
        entry.cursor = success.cursor;
        entry.last_successful_sync_at = success.now;
        entry.schema_version = success.schema_version;
        return;
    }

    state.entries.push(SyncEntry {
        provider: success.provider,
        connection_id: success.connection_id,
        data_type: success.data_type,
        cursor: success.cursor,
        last_successful_sync_at: success.now,
        schema_version: success.schema_version,
    });
}

#[cfg(test)]
mod tests;
