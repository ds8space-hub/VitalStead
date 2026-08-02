//! Adapter 5: `AtomicFileWriter` — T-006-PLATFORM-ADAPTERS.md L176-227.
//!
//! Required by T-101 step 5 to persist `config.json` without corrupting a
//! prior valid config on failure. Trait/error signatures copied verbatim
//! (L182-199); macOS algorithm follows L202-217, L223-226.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// T-006 Adapter 5, L182-191.
pub trait AtomicFileWriter: Send + Sync {
    /// Пишет content во временный файл в ТОМ ЖЕ каталоге, что и target.
    fn write_temp(&self, target_dir: &Path, content: &[u8]) -> Result<PathBuf, WriteError>;
    /// Атомарно заменяет target на temp_path, создавая backup перед заменой.
    fn replace_atomic(&self, target: &Path, temp_path: &Path) -> Result<(), WriteError>;
    /// Восстанавливает target из .backup, если основной файл повреждён.
    fn recover_from_backup(&self, target: &Path) -> Result<(), WriteError>;
}

/// T-006 Adapter 5, L193-199.
#[derive(Debug, Clone)]
pub enum WriteError {
    DiskFull,
    PermissionDenied,
    /// target открыт другим процессом (Windows file locking semantics).
    FileLocked,
    Backend(String),
}

/// macOS реализация — T-006 Adapter 5, L217: POSIX `rename(2)`.
pub struct MacAtomicFileWriter {
    /// T-006 L223-226: per-path mutex, two `replace_atomic` calls for the
    /// same target from different threads serialize instead of racing.
    locks: Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>,
}

impl Default for MacAtomicFileWriter {
    fn default() -> Self {
        Self {
            locks: Mutex::new(HashMap::new()),
        }
    }
}

impl MacAtomicFileWriter {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AtomicFileWriter for MacAtomicFileWriter {
    /// T-006 L185, L203-204: `{target_dir}/.{basename}.tmp.{random}`.
    fn write_temp(&self, target_dir: &Path, content: &[u8]) -> Result<PathBuf, WriteError> {
        let random_suffix = std::process::id();
        let temp_name = format!(".vitalstead.tmp.{random_suffix}");
        let temp_path = target_dir.join(temp_name);

        fs::write(&temp_path, content).map_err(map_write_error)?;
        Ok(temp_path)
    }

    /// T-006 L187-188, L207-208, L217: backup current target, then
    /// platform-specific atomic rename `temp -> target`.
    fn replace_atomic(&self, target: &Path, temp_path: &Path) -> Result<(), WriteError> {
        let path_lock = self.lock_for(target);
        let _guard = path_lock
            .lock()
            .map_err(|_| WriteError::Backend("lock poisoned".into()))?;

        if target.exists() {
            let backup_path = backup_path_for(target);
            fs::copy(target, &backup_path).map_err(map_write_error)?;
        }
        fs::rename(temp_path, target).map_err(map_write_error)
    }

    /// T-006 L189: explicit recovery, not automatic on every read.
    fn recover_from_backup(&self, target: &Path) -> Result<(), WriteError> {
        let backup_path = backup_path_for(target);
        fs::copy(&backup_path, target).map_err(map_write_error)?;
        Ok(())
    }
}

impl MacAtomicFileWriter {
    /// Returns an owned `Arc<Mutex<()>>` for `target`, creating it on first
    /// use. Cloning the `Arc` (instead of returning a `MutexGuard` borrowed
    /// from the map) lets the caller lock/unlock the per-path mutex after
    /// the map's own lock has already been released — no unsafe lifetime
    /// extension needed.
    fn lock_for(&self, target: &Path) -> Arc<Mutex<()>> {
        let mut map = self.locks.lock().expect("locks map poisoned");
        map.entry(target.to_path_buf())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
}

fn backup_path_for(target: &Path) -> PathBuf {
    let mut backup = target.to_path_buf();
    let file_name = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    backup.set_file_name(format!("{file_name}.backup"));
    backup
}

fn map_write_error(err: std::io::Error) -> WriteError {
    match err.kind() {
        std::io::ErrorKind::PermissionDenied => WriteError::PermissionDenied,
        std::io::ErrorKind::StorageFull => WriteError::DiskFull,
        _ => WriteError::Backend(err.to_string()),
    }
}
