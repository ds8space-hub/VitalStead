//! App config persistence — T-101 step 4/5.
//!
//! Contract sources:
//! - `AppConfig { data_folder }`: T-101 orchestrator step 4 (D-002, T-005).
//! - Config path `~/Library/Application Support/com.github.dima.controlyourdata/config.json`:
//!   T-005-NAMING-BUNDLE-ID.md L102-103.
//! - "путь сохраняется без секретов": EPIC-02-csv-storage.md T-101 критерии приёмки —
//!   `AppConfig` intentionally has no token/secret field.
//! - "недоступный путь не повреждает существующие данные": T-101 критерии приёмки —
//!   persisted via `AtomicFileWriter`, so a failed save leaves the prior
//!   `config.json` untouched (T-006 Adapter 5, L182-191).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::adapters::{AtomicFileWriter, WriteError};

/// T-101 step 4: only the data folder path — no credentials, no tokens
/// (secrets live in `CredentialVault`, T-006 Adapter 1, never in config.json).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub data_folder: PathBuf,
}

#[derive(Debug, Clone)]
pub enum ConfigError {
    Serialize(String),
    Write(WriteError),
    Read(String),
}

/// T-005 L102-103: bundle-id-derived config directory.
/// macOS-only path construction stays out of the composition root's
/// `#[cfg(target_os = ...)]` boundary is preserved by callers only invoking
/// this from the macOS composition root (T-006 Design Principle 2).
pub fn config_dir(app_support_dir: &Path) -> PathBuf {
    app_support_dir.join("com.github.dima.controlyourdata")
}

pub fn config_file_path(app_support_dir: &Path) -> PathBuf {
    config_dir(app_support_dir).join("config.json")
}

/// Persists `AppConfig` via the injected `AtomicFileWriter` (T-101 step 5)
/// so a write failure (disk full, permission denied) cannot corrupt the
/// previously saved `config.json`.
pub fn save(
    writer: &dyn AtomicFileWriter,
    app_support_dir: &Path,
    config: &AppConfig,
) -> Result<(), ConfigError> {
    let target = config_file_path(app_support_dir);
    let target_dir = config_dir(app_support_dir);

    let content =
        serde_json::to_vec_pretty(config).map_err(|e| ConfigError::Serialize(e.to_string()))?;

    std::fs::create_dir_all(&target_dir)
        .map_err(|e| ConfigError::Write(WriteError::Backend(e.to_string())))?;

    let temp_path = writer
        .write_temp(&target_dir, &content)
        .map_err(ConfigError::Write)?;
    writer
        .replace_atomic(&target, &temp_path)
        .map_err(ConfigError::Write)
}

pub fn load(app_support_dir: &Path) -> Result<AppConfig, ConfigError> {
    let target = config_file_path(app_support_dir);
    let bytes = std::fs::read(&target).map_err(|e| ConfigError::Read(e.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| ConfigError::Read(e.to_string()))
}
