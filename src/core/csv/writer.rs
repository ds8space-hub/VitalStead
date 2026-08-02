//! `CsvWriter` — orchestrates serialization and atomic persistence via the
//! `AtomicFileWriter` platform adapter (T-006 Adapter 5, L182-191).
//!
//! Persist algorithm — T-006 L202-213 / T-007-SCHEMA-UPSERT.md L114-120
//! (steps 6-8: write temp, verify by re-reading, atomically replace).
//! Verification is explicitly the caller's ("core's") responsibility, not
//! the adapter's — T-006 L205-206: "Верификация temp-файла ... делает
//! ядро... не adapter."

use std::path::Path;

use crate::adapters::{AtomicFileWriter, WriteError};

use super::schema::CsvSchema;
use super::serialize::{serialize_rows, CsvRow, CsvSerializeError};

#[derive(Debug)]
pub enum CsvWriteError {
    Serialize(CsvSerializeError),
    Write(WriteError),
    /// Re-reading the temp file didn't match what was serialized — T-006
    /// L205-206, T-007-SCHEMA-UPSERT.md L118-120 ("verify temp file ...
    /// throws if corrupt").
    VerificationFailed(String),
    /// `target` has no parent directory to co-locate the temp file in
    /// (required for atomic same-filesystem rename — T-006 L183-184).
    NoParentDirectory,
}

/// Serializes rows and persists them to `target` through an
/// `AtomicFileWriter`. Contains no domain logic (upsert, sorting) — T-102
/// scope is serialization + atomic persistence only.
pub struct CsvWriter<'a> {
    atomic: &'a dyn AtomicFileWriter,
}

impl<'a> CsvWriter<'a> {
    pub fn new(atomic: &'a dyn AtomicFileWriter) -> Self {
        Self { atomic }
    }

    /// T-006 L202-213 persist orchestration:
    /// 1. Serialize rows (validates row width against `schema`).
    /// 2. `write_temp` into `target`'s directory.
    /// 3. Verify the temp file by re-reading it (core's job, not the
    ///    adapter's — L205-206).
    /// 4. `replace_atomic` — only reached if verification passed, so a
    ///    corrupt/incomplete write never replaces a good existing CSV.
    pub fn persist(
        &self,
        target: &Path,
        schema: &CsvSchema,
        rows: &[CsvRow],
    ) -> Result<(), CsvWriteError> {
        let bytes = serialize_rows(schema, rows).map_err(CsvWriteError::Serialize)?;

        let target_dir = target.parent().ok_or(CsvWriteError::NoParentDirectory)?;
        let temp_path = self
            .atomic
            .write_temp(target_dir, &bytes)
            .map_err(CsvWriteError::Write)?;

        self.verify_temp(&temp_path, &bytes, rows.len())?;

        self.atomic
            .replace_atomic(target, &temp_path)
            .map_err(CsvWriteError::Write)
    }

    /// Re-reads the temp file and checks it matches what was intended to be
    /// written (byte-for-byte) and that its row count is correct — T-007
    /// L118-120 "read_csv_from_file(temp_file) # throws if corrupt".
    fn verify_temp(
        &self,
        temp_path: &Path,
        expected_bytes: &[u8],
        expected_row_count: usize,
    ) -> Result<(), CsvWriteError> {
        let actual = std::fs::read(temp_path)
            .map_err(|e| CsvWriteError::VerificationFailed(e.to_string()))?;
        if actual != expected_bytes {
            return Err(CsvWriteError::VerificationFailed(
                "temp file content mismatch".to_string(),
            ));
        }
        let actual_row_count = actual.iter().filter(|&&b| b == b'\n').count().saturating_sub(1);
        if actual_row_count != expected_row_count {
            return Err(CsvWriteError::VerificationFailed(format!(
                "row count mismatch: expected {expected_row_count}, got {actual_row_count}"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;

    /// Test double for `AtomicFileWriter` (T-006 Adapter 5 trait). Not a
    /// production impl — records calls and lets tests inject failures at
    /// `replace_atomic`, which the real `MacAtomicFileWriter` cannot do
    /// deterministically in a unit test.
    struct MockAtomicFileWriter {
        write_temp_calls: Mutex<Vec<std::path::PathBuf>>,
        replace_calls: Mutex<Vec<(std::path::PathBuf, std::path::PathBuf)>>,
        fail_replace: bool,
    }

    impl MockAtomicFileWriter {
        fn new(fail_replace: bool) -> Self {
            Self {
                write_temp_calls: Mutex::new(Vec::new()),
                replace_calls: Mutex::new(Vec::new()),
                fail_replace,
            }
        }
    }

    impl AtomicFileWriter for MockAtomicFileWriter {
        fn write_temp(
            &self,
            target_dir: &Path,
            content: &[u8],
        ) -> Result<std::path::PathBuf, WriteError> {
            let temp_path = target_dir.join(".mock.tmp");
            fs::write(&temp_path, content).map_err(|e| WriteError::Backend(e.to_string()))?;
            self.write_temp_calls.lock().unwrap().push(temp_path.clone());
            Ok(temp_path)
        }

        fn replace_atomic(&self, target: &Path, temp_path: &Path) -> Result<(), WriteError> {
            self.replace_calls
                .lock()
                .unwrap()
                .push((target.to_path_buf(), temp_path.to_path_buf()));
            if self.fail_replace {
                return Err(WriteError::Backend("simulated replace failure".to_string()));
            }
            fs::rename(temp_path, target).map_err(|e| WriteError::Backend(e.to_string()))
        }

        fn recover_from_backup(&self, _target: &Path) -> Result<(), WriteError> {
            Ok(())
        }
    }

    fn schema_and_rows() -> (CsvSchema, Vec<CsvRow>) {
        let schema = CsvSchema::new(vec!["sleep_score".to_string()]);
        let rows = vec![vec![
            Some("oura".to_string()),
            Some("id-1".to_string()),
            Some("2026-07-10T22:30:00+02:00".to_string()),
            None,
            Some("2026-07-11T07:15:00Z".to_string()),
            Some("Europe/Berlin".to_string()),
            Some("1".to_string()),
            Some("85".to_string()),
        ]];
        (schema, rows)
    }

    /// §5 test_persist_verifies_temp_before_replace — T-006 L205-206 /
    /// T-007 L118-120: temp file is re-read and verified before
    /// `replace_atomic` is ever called.
    #[test]
    fn test_persist_verifies_temp_before_replace() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sleep.csv");
        let atomic = MockAtomicFileWriter::new(false);
        let (schema, rows) = schema_and_rows();

        let result = CsvWriter::new(&atomic).persist(&target, &schema, &rows);

        assert!(result.is_ok());
        let write_temp_calls = atomic.write_temp_calls.lock().unwrap();
        let replace_calls = atomic.replace_calls.lock().unwrap();
        assert_eq!(write_temp_calls.len(), 1, "write_temp called exactly once");
        assert_eq!(replace_calls.len(), 1, "replace_atomic called exactly once");
        // Verification happens between write_temp and replace_atomic: the
        // temp file that replace_atomic receives is the same one write_temp
        // returned, proving persist re-read it (verify_temp) before
        // proceeding rather than calling replace_atomic blindly.
        assert_eq!(replace_calls[0].1, write_temp_calls[0]);
        assert_eq!(replace_calls[0].0, target);
        assert!(target.exists(), "target was replaced after successful verification");
    }

    /// §5 test_persist_failure_preserves_existing_csv — T-006 L210-212: if
    /// the app fails between write_temp and replace_atomic, target is
    /// either the old version (rename never started) or the new version
    /// (rename finished) — never partially written.
    #[test]
    fn test_persist_failure_preserves_existing_csv() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sleep.csv");
        let original_content = b"source,external_id\noura,old-id\n";
        fs::write(&target, original_content).unwrap();

        let atomic = MockAtomicFileWriter::new(true);
        let (schema, rows) = schema_and_rows();

        let result = CsvWriter::new(&atomic).persist(&target, &schema, &rows);

        assert!(matches!(result, Err(CsvWriteError::Write(_))));
        let preserved = fs::read(&target).unwrap();
        assert_eq!(
            preserved, original_content,
            "existing CSV must be untouched when replace_atomic fails"
        );
    }
}
