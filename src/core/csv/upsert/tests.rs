//! T-103 §7 unit test plan (T-007-SCHEMA-UPSERT.md §Part 8, GAP resolution
//! notes). Split from `upsert.rs` to keep the production file within the
//! 300-line limit.

use std::fs;
use std::path::Path;
use std::sync::Mutex;

use crate::adapters::{AtomicFileWriter, WriteError};
use crate::core::csv::schema::CsvSchema;
use crate::core::csv::serialize::CsvRow;
use crate::core::csv::writer::CsvWriter;

use super::*;

fn sleep_schema() -> CsvSchema {
    CsvSchema::new(vec!["sleep_score".to_string()])
}

fn row(source: &str, external_id: &str, recorded_at: &str, updated_at: Option<&str>, score: &str) -> CsvRow {
    vec![
        Some(source.to_string()),
        Some(external_id.to_string()),
        Some(recorded_at.to_string()),
        updated_at.map(|s| s.to_string()),
        Some("2026-07-11T07:15:00Z".to_string()),
        Some("Europe/Berlin".to_string()),
        Some("1".to_string()),
        Some(score.to_string()),
    ]
}

fn find<'a>(rows: &'a [CsvRow], external_id: &str) -> &'a CsvRow {
    rows.iter()
        .find(|r| r[EXTERNAL_ID].as_deref() == Some(external_id))
        .expect("row must be present")
}

// ---- Acceptance criteria (T-007 §Part 8, Acceptance Tests) ----

/// test_new_record_added — T-007 L99-102.
#[test]
fn test_new_record_added() {
    let existing = vec![row("oura", "id1", "2026-07-10T22:30:00+02:00", None, "80")];
    let new_rows = vec![row("oura", "id2", "2026-07-11T23:00:00+02:00", None, "75")];

    let (rows, stats) = merge_rows(&existing, &new_rows, &[], 1).unwrap();

    assert_eq!(stats, UpsertStats { inserted: 1, updated: 0, deleted: 0 });
    assert_eq!(rows.len(), 2);
}

/// test_changed_record_replaced_by_key — T-007 L88-95, id1 recalculated.
#[test]
fn test_changed_record_replaced_by_key() {
    let existing = vec![row(
        "oura",
        "id1",
        "2026-07-10T22:30:00+02:00",
        Some("2026-07-11T06:00:00Z"),
        "80",
    )];
    let new_rows = vec![row(
        "oura",
        "id1",
        "2026-07-10T22:30:00+02:00",
        Some("2026-07-13T08:00:00Z"),
        "82",
    )];

    let (rows, stats) = merge_rows(&existing, &new_rows, &[], 1).unwrap();

    assert_eq!(stats, UpsertStats { inserted: 0, updated: 1, deleted: 0 });
    assert_eq!(find(&rows, "id1")[7], Some("82".to_string()));
}

/// test_repeat_sync_idempotent — T-007 L385-399: running merge twice with
/// the same input produces byte-identical (hash-equal) output.
#[test]
fn test_repeat_sync_idempotent() {
    let new_rows = vec![
        row("oura", "id2", "2026-07-11T23:00:00+02:00", Some("2026-07-12T06:00:00Z"), "75"),
        row("oura", "id1", "2026-07-10T22:30:00+02:00", Some("2026-07-11T06:00:00Z"), "80"),
    ];

    let (rows_v1, _) = merge_rows(&[], &new_rows, &[], 1).unwrap();
    let (rows_v2, _) = merge_rows(&rows_v1, &new_rows, &[], 1).unwrap();

    let schema = sleep_schema();
    let bytes_v1 = crate::core::csv::serialize::serialize_rows(&schema, &rows_v1).unwrap();
    let bytes_v2 = crate::core::csv::serialize::serialize_rows(&schema, &rows_v2).unwrap();
    assert_eq!(bytes_v1, bytes_v2, "identical input twice must hash-equal");
}

/// test_deletion_marker_removes_row — T-007 L104-109, L349-379.
#[test]
fn test_deletion_marker_removes_row() {
    let existing = vec![
        row("whoop", "wk1", "2026-07-10T08:00:00Z", None, "5"),
        row("whoop", "wk2", "2026-07-11T08:00:00Z", None, "6"),
    ];
    let deletions = vec![DeletionMarker { source: "whoop".to_string(), external_id: "wk1".to_string() }];

    let (rows, stats) = merge_rows(&existing, &[], &deletions, 1).unwrap();

    assert_eq!(stats, UpsertStats { inserted: 0, updated: 0, deleted: 1 });
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0][EXTERNAL_ID], Some("wk2".to_string()));
}

/// test_empty_new_rows_preserves_existing — no new records, no deletions,
/// existing rows pass through unchanged.
#[test]
fn test_empty_new_rows_preserves_existing() {
    let existing = vec![row("oura", "id1", "2026-07-10T22:30:00+02:00", None, "80")];

    let (rows, stats) = merge_rows(&existing, &[], &[], 1).unwrap();

    assert_eq!(rows, existing);
    assert_eq!(stats, UpsertStats::default());
}

/// test_sort_stability_by_service_key — T-007 L111-112, L596: output is
/// sorted by (source, external_id, recorded_at) regardless of input order.
#[test]
fn test_sort_stability_by_service_key() {
    let new_rows = vec![
        row("oura", "id3", "2026-07-12T23:15:00+02:00", None, "90"),
        row("oura", "id1", "2026-07-10T22:30:00+02:00", None, "80"),
        row("oura", "id2", "2026-07-11T23:00:00+02:00", None, "75"),
    ];

    let (rows, _) = merge_rows(&[], &new_rows, &[], 1).unwrap();

    let ids: Vec<&str> = rows.iter().map(|r| r[EXTERNAL_ID].as_deref().unwrap()).collect();
    assert_eq!(ids, vec!["id1", "id2", "id3"]);
}

// ---- Edge cases (T-007 §Part 6) ----

/// test_first_sync_no_existing — T-007 L134, L405: no existing CSV at all.
#[test]
fn test_first_sync_no_existing() {
    let new_rows = vec![row("oura", "id1", "2026-07-10T22:30:00+02:00", None, "80")];

    let (rows, stats) = merge_rows(&[], &new_rows, &[], 1).unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(stats.inserted, 1);
}

/// test_empty_input_no_existing_creates_nothing — no existing rows, no new
/// rows: nothing to insert, output is empty.
#[test]
fn test_empty_input_no_existing_creates_nothing() {
    let (rows, stats) = merge_rows(&[], &[], &[], 1).unwrap();

    assert!(rows.is_empty());
    assert_eq!(stats, UpsertStats::default());
}

/// test_unchanged_record_skipped_preserves_bytes — GAP-3: identical
/// `updated_at` means old is not strictly older, so the row is skipped and
/// kept byte-for-byte (upsert never stamps timestamps).
#[test]
fn test_unchanged_record_skipped_preserves_bytes() {
    let existing = vec![row(
        "oura",
        "id2",
        "2026-07-11T23:00:00+02:00",
        Some("2026-07-12T06:00:00Z"),
        "75",
    )];
    let new_rows = vec![row(
        "oura",
        "id2",
        "2026-07-11T23:00:00+02:00",
        Some("2026-07-12T06:00:00Z"),
        "999", // different payload but same updated_at — must NOT replace
    )];

    let (rows, stats) = merge_rows(&existing, &new_rows, &[], 1).unwrap();

    assert_eq!(stats, UpsertStats::default(), "no change is recorded");
    assert_eq!(rows[0], existing[0], "existing row bytes preserved exactly");
}

/// test_null_new_updated_at_forces_replace — T-007 L91-92: NULL
/// `updated_at` on the incoming record always replaces.
#[test]
fn test_null_new_updated_at_forces_replace() {
    let existing = vec![row(
        "oura",
        "id1",
        "2026-07-10T22:30:00+02:00",
        Some("2026-07-11T06:00:00Z"),
        "80",
    )];
    let new_rows = vec![row("oura", "id1", "2026-07-10T22:30:00+02:00", None, "81")];

    let (rows, stats) = merge_rows(&existing, &new_rows, &[], 1).unwrap();

    assert_eq!(stats.updated, 1);
    assert_eq!(rows[0][7], Some("81".to_string()));
}

/// test_null_external_id_rejected — T-007 L407.
#[test]
fn test_null_external_id_rejected() {
    let mut bad_row = row("oura", "placeholder", "2026-07-10T22:30:00+02:00", None, "80");
    bad_row[EXTERNAL_ID] = None;

    let result = merge_rows(&[], &[bad_row], &[], 1);

    assert!(matches!(result, Err(UpsertError::MissingExternalId { row_index: 0 })));
}

/// test_null_recorded_at_rejected — T-007 L408.
#[test]
fn test_null_recorded_at_rejected() {
    let mut bad_row = row("oura", "id1", "placeholder", None, "80");
    bad_row[RECORDED_AT] = None;

    let result = merge_rows(&[], &[bad_row], &[], 1);

    assert!(matches!(result, Err(UpsertError::MissingRecordedAt { row_index: 0 })));
}

/// test_duplicate_key_keeps_latest — T-007 L414: two new rows share a key
/// in the same sync; the later (by `updated_at`) one wins.
#[test]
fn test_duplicate_key_keeps_latest() {
    let new_rows = vec![
        row("oura", "id1", "2026-07-10T22:30:00+02:00", Some("2026-07-11T06:00:00Z"), "80"),
        row("oura", "id1", "2026-07-10T22:30:00+02:00", Some("2026-07-13T08:00:00Z"), "82"),
    ];

    let (rows, _) = merge_rows(&[], &new_rows, &[], 1).unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0][7], Some("82".to_string()));
}

// ---- Failure path ----

struct MockAtomicFileWriter {
    fail_replace: bool,
    replace_calls: Mutex<usize>,
}

impl AtomicFileWriter for MockAtomicFileWriter {
    fn write_temp(&self, target_dir: &Path, content: &[u8]) -> Result<std::path::PathBuf, WriteError> {
        let temp_path = target_dir.join(".mock.tmp");
        fs::write(&temp_path, content).map_err(|e| WriteError::Backend(e.to_string()))?;
        Ok(temp_path)
    }

    fn replace_atomic(&self, _target: &Path, _temp_path: &Path) -> Result<(), WriteError> {
        *self.replace_calls.lock().unwrap() += 1;
        if self.fail_replace {
            return Err(WriteError::Backend("simulated replace failure".to_string()));
        }
        Ok(())
    }

    fn recover_from_backup(&self, _target: &Path) -> Result<(), WriteError> {
        Ok(())
    }
}

/// test_atomic_write_failure_preserves_existing — T-007 L138-139: a failed
/// atomic replace must leave the existing CSV on disk untouched, and
/// `upsert` must surface the failure instead of reporting success.
#[test]
fn test_atomic_write_failure_preserves_existing() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("sleep.csv");
    let schema = sleep_schema();
    let original = crate::core::csv::serialize::serialize_rows(
        &schema,
        &[row("oura", "id1", "2026-07-10T22:30:00+02:00", None, "80")],
    )
    .unwrap();
    fs::write(&target, &original).unwrap();

    let atomic = MockAtomicFileWriter { fail_replace: true, replace_calls: Mutex::new(0) };
    let writer = CsvWriter::new(&atomic);
    let new_rows = vec![row("oura", "id2", "2026-07-11T23:00:00+02:00", None, "75")];

    let result = upsert(&target, &schema, &new_rows, &[], 1, &writer);

    assert!(matches!(result, Err(UpsertError::Write(_))));
    let preserved = fs::read(&target).unwrap();
    assert_eq!(preserved, original, "existing CSV must be untouched when replace_atomic fails");
}
