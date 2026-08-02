//! Adapter 3: `FilePicker` — контракт T-006-PLATFORM-ADAPTERS.md L120-149
//! родительского проекта. Trait signature и `PickerError` скопированы из
//! контракта без изменений.
//!
//! Отличие от родительского проекта (D-014, MCP-форм-фактор): диалоговой
//! реализации (`MacFilePicker` на tauri-plugin-dialog) здесь нет — путь к
//! папке данных приходит из plugin user_config, путь к Garmin ZIP — аргументом
//! MCP-tool. Переиспользуемая часть — `verify_writable_and_readable`
//! (write-probe + read-probe), которой MCP-сервер валидирует полученный путь.
//! Trait сохранён для будущего desktop-фасада поверх этого же ядра.

use std::fs;
use std::path::{Path, PathBuf};

/// T-006 Adapter 3, L123-128.
pub trait FilePicker: Send + Sync {
    /// Выбор каталога для CSV (первый запуск, смена папки).
    fn pick_folder(&self, title: &str) -> Result<Option<PathBuf>, PickerError>;
    /// Выбор файла для Garmin manual import (EPIC-05).
    fn pick_file(&self, title: &str, extensions: &[&str]) -> Result<Option<PathBuf>, PickerError>;
}

/// T-006 Adapter 3, L130-134.
#[derive(Debug)]
pub enum PickerError {
    /// Пользователь закрыл диалог — не ошибка для UI, отдельный вариант.
    Cancelled,
    /// Выбранный каталог не доступен для записи.
    NotWritable,
    Backend(String),
}

/// T-006 Adapter 3, L138-142:
/// 1. Write-probe: temp file + delete → failure = `NotWritable`.
/// 2. Read-probe: directory listing → failure = `NotWritable`.
/// Both failure modes merge into the single `NotWritable` variant per contract.
///
/// В MCP-форм-факторе вызывается напрямую из обработчика конфигурации
/// (data_folder из user_config), без участия `FilePicker`.
pub fn verify_writable_and_readable(dir: &Path) -> Result<(), PickerError> {
    write_probe(dir)?;
    read_probe(dir)?;
    Ok(())
}

fn write_probe(dir: &Path) -> Result<(), PickerError> {
    let probe_path = dir.join(format!(".vitalstead-write-probe-{}", std::process::id()));
    fs::write(&probe_path, b"").map_err(|_| PickerError::NotWritable)?;
    fs::remove_file(&probe_path).map_err(|_| PickerError::NotWritable)
}

fn read_probe(dir: &Path) -> Result<(), PickerError> {
    fs::read_dir(dir).map_err(|_| PickerError::NotWritable)?;
    Ok(())
}

/// T-101 Gate 1 (родительский) — unit tests для probe-логики
/// `verify_writable_and_readable` (T-006 Adapter 3, L123-146) плюс контракта
/// `AtomicFileWriter`/`AppConfig` (T-006 Adapter 5, L182-217; T-101 step 4/5).
///
/// Tests 1-3 exercise `verify_writable_and_readable` directly against real
/// temp directories with controlled Unix permission bits. Test 4 exercises
/// the "cancel is not an error" contract via a mock `FilePicker`, since that
/// branch is pure `Option -> Result` mapping independent of any dialog backend.
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    use crate::adapters::{AtomicFileWriter, MacAtomicFileWriter};
    use crate::config::{self, AppConfig};

    /// Restores a temp dir to a removable permission state before its
    /// `TempDir` guard drops, so cleanup never fails after a test
    /// deliberately locked the directory down.
    struct RestorePerms(PathBuf);
    impl Drop for RestorePerms {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        }
    }

    // --- Test 1: full read+write access -> probes succeed --------------

    #[test]
    fn test_pick_folder_write_probe() {
        let dir = tempfile::tempdir().expect("create temp dir");
        // Default tempdir permissions already grant the creating user full
        // read/write/execute access; assert that explicitly so the test's
        // premise ("full access") is not implicit.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
            .expect("set full-access perms");

        let result = verify_writable_and_readable(dir.path());

        assert!(
            result.is_ok(),
            "expected Ok(()) for a fully-accessible directory, got {result:?}"
        );
    }

    // --- Test 2: writable but not readable -> NotWritable ---------------

    #[test]
    fn test_pick_folder_write_only_no_read() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let _restore = RestorePerms(dir.path().to_path_buf());

        // 0o300: write+execute (can create/delete files) but no read bit
        // (cannot list directory contents) -> write-probe passes,
        // read-probe fails.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o300))
            .expect("set write-only perms");

        let result = verify_writable_and_readable(dir.path());

        assert!(
            matches!(result, Err(PickerError::NotWritable)),
            "expected PickerError::NotWritable when directory is not readable, got {result:?}"
        );
    }

    // --- Test 3: readable but not writable -> NotWritable ----------------

    #[test]
    fn test_pick_folder_read_only() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let _restore = RestorePerms(dir.path().to_path_buf());

        // 0o500: read+execute (can list directory) but no write bit
        // (cannot create the write-probe file) -> write-probe fails first.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500))
            .expect("set read-only perms");

        let result = verify_writable_and_readable(dir.path());

        assert!(
            matches!(result, Err(PickerError::NotWritable)),
            "expected PickerError::NotWritable when directory is not writable, got {result:?}"
        );
    }

    // --- Test 4: user cancels the dialog -> Ok(None), not an error -------

    /// Mock `FilePicker` exercising the "cancel -> Ok(None)" contract
    /// (T-006 Adapter 3, L131: "Пользователь закрыл диалог — не ошибка для
    /// UI") without any real dialog backend.
    struct CancellingFilePicker;

    impl FilePicker for CancellingFilePicker {
        fn pick_folder(&self, _title: &str) -> Result<Option<PathBuf>, PickerError> {
            // Simulates a dialog returning nothing (user clicked Cancel).
            Ok(None)
        }

        fn pick_file(
            &self,
            _title: &str,
            _extensions: &[&str],
        ) -> Result<Option<PathBuf>, PickerError> {
            Ok(None)
        }
    }

    #[test]
    fn test_pick_folder_cancelled() {
        let picker = CancellingFilePicker;

        let result = picker.pick_folder("Choose a folder");

        assert!(
            matches!(result, Ok(None)),
            "cancellation must surface as Ok(None), not PickerError::Cancelled or any Err, got {result:?}"
        );
    }

    // --- Test 5: AppConfig save/load round-trips idempotently ------------

    #[test]
    fn test_atomic_write_idempotent() {
        let app_support_dir = tempfile::tempdir().expect("create temp dir");
        let writer = MacAtomicFileWriter::new();
        let cfg = AppConfig {
            data_folder: PathBuf::from("/Users/test/Vitalstead-Data"),
        };

        config::save(&writer, app_support_dir.path(), &cfg).expect("first save");
        let loaded_once = config::load(app_support_dir.path()).expect("first load");

        // Save again with the same content — must be idempotent: the
        // second save/load cycle must observe exactly the same config.
        config::save(&writer, app_support_dir.path(), &cfg).expect("second save");
        let loaded_twice = config::load(app_support_dir.path()).expect("second load");

        assert_eq!(loaded_once.data_folder, cfg.data_folder);
        assert_eq!(loaded_twice.data_folder, cfg.data_folder);
        assert_eq!(loaded_once.data_folder, loaded_twice.data_folder);
    }

    // --- Test 6: replace_atomic backs up the previous file first ---------

    #[test]
    fn test_atomic_write_backup() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let writer = MacAtomicFileWriter::new();
        let target = dir.path().join("config.json");
        let backup = dir.path().join("config.json.backup");

        // Establish an existing "prior valid config" at the target path.
        fs::write(&target, b"{\"data_folder\":\"/old/path\"}").expect("seed existing target");

        // Replace it via the same write_temp + replace_atomic sequence
        // config::save uses.
        let temp_path = writer
            .write_temp(dir.path(), b"{\"data_folder\":\"/new/path\"}")
            .expect("write_temp");
        writer
            .replace_atomic(&target, &temp_path)
            .expect("replace_atomic");

        assert!(
            backup.exists(),
            "replace_atomic must create a {{filename}}.backup before replacing an existing target"
        );
        let backup_contents = fs::read_to_string(&backup).expect("read backup");
        assert_eq!(
            backup_contents, "{\"data_folder\":\"/old/path\"}",
            "backup must contain the PREVIOUS target contents, not the new ones"
        );
        let target_contents = fs::read_to_string(&target).expect("read target");
        assert_eq!(
            target_contents, "{\"data_folder\":\"/new/path\"}",
            "target must contain the new contents after replace_atomic"
        );
    }
}
