//! §5 unit tests for T-104 sync state persistence.

use super::*;
use std::fs;
use std::path::PathBuf;

/// Test double for `AtomicFileWriter`, mirroring `csv/writer.rs`'s mock but
/// with a real `recover_from_backup` (copy `.backup` -> target) since
/// `state::load` depends on that behavior actually restoring the file.
struct MockAtomicFileWriter;

impl AtomicFileWriter for MockAtomicFileWriter {
    fn write_temp(&self, target_dir: &Path, content: &[u8]) -> Result<PathBuf, WriteError> {
        let temp_path = target_dir.join(".mock.tmp");
        fs::write(&temp_path, content).map_err(|e| WriteError::Backend(e.to_string()))?;
        Ok(temp_path)
    }

    fn replace_atomic(&self, target: &Path, temp_path: &Path) -> Result<(), WriteError> {
        if target.exists() {
            fs::copy(target, backup_path(target)).map_err(|e| WriteError::Backend(e.to_string()))?;
        }
        fs::rename(temp_path, target).map_err(|e| WriteError::Backend(e.to_string()))
    }

    fn recover_from_backup(&self, target: &Path) -> Result<(), WriteError> {
        fs::copy(backup_path(target), target).map_err(|e| WriteError::Backend(e.to_string()))?;
        Ok(())
    }
}

fn backup_path(target: &Path) -> PathBuf {
    let mut backup = target.to_path_buf();
    let name = target.file_name().unwrap().to_string_lossy().to_string();
    backup.set_file_name(format!("{name}.backup"));
    backup
}

fn sample_entry() -> SyncEntry {
    SyncEntry {
        provider: "oura".to_string(),
        connection_id: "conn-1".to_string(),
        data_type: "sleep".to_string(),
        cursor: Some("cursor-abc".to_string()),
        last_successful_sync_at: "2026-07-11T07:15:00Z".parse().unwrap(),
        schema_version: 1,
    }
}

/// test_state_persisted_after_successful_sync — save() writes state that
/// load() can read back unchanged.
#[test]
fn test_state_persisted_after_successful_sync() {
    let dir = tempfile::tempdir().unwrap();
    let writer = MockAtomicFileWriter;
    let state = SyncState { version: SYNC_STATE_VERSION, entries: vec![sample_entry()] };

    save(&writer, dir.path(), &state).unwrap();
    let loaded = load(&writer, dir.path()).unwrap();

    assert_eq!(loaded, state);
}

/// test_state_not_updated_on_sync_failure — mutating an in-memory
/// `SyncState` via `record_success` without calling `save` leaves any
/// previously persisted file untouched (architecture.md L78: state only
/// updated after a successful write, i.e. an explicit `save` call).
#[test]
fn test_state_not_updated_on_sync_failure() {
    let dir = tempfile::tempdir().unwrap();
    let writer = MockAtomicFileWriter;
    let persisted = SyncState { version: SYNC_STATE_VERSION, entries: vec![sample_entry()] };
    save(&writer, dir.path(), &persisted).unwrap();

    let mut in_memory = persisted.clone();
    record_success(
        &mut in_memory,
        SyncSuccess {
            provider: "whoop".to_string(),
            connection_id: "conn-2".to_string(),
            data_type: "recovery".to_string(),
            cursor: Some("new-cursor".to_string()),
            schema_version: 1,
            now: Utc::now(),
        },
    );

    let reloaded = load(&writer, dir.path()).unwrap();
    assert_eq!(reloaded, persisted, "on-disk state unchanged until save() is called");
}

/// test_state_corrupted_file_recovers_from_backup — a corrupt primary file
/// with a valid `.backup` recovers via `AtomicFileWriter::recover_from_backup`.
#[test]
fn test_state_corrupted_file_recovers_from_backup() {
    let dir = tempfile::tempdir().unwrap();
    let writer = MockAtomicFileWriter;
    let good_state = SyncState { version: SYNC_STATE_VERSION, entries: vec![sample_entry()] };
    save(&writer, dir.path(), &good_state).unwrap();
    // A second successful save is what actually produces a ".backup" via
    // `replace_atomic` (it only backs up a target that already exists).
    save(&writer, dir.path(), &good_state).unwrap();

    // Corrupt the primary file; the previous successful save() left a
    // ".backup" copy in place via replace_atomic.
    let target = sync_state_file_path(dir.path());
    fs::write(&target, b"{ not valid json").unwrap();

    let loaded = load(&writer, dir.path()).unwrap();
    assert_eq!(loaded, good_state);
}

/// test_state_corrupted_no_backup_returns_empty — corrupt primary, no
/// backup available: `load` returns an empty default rather than an error.
#[test]
fn test_state_corrupted_no_backup_returns_empty() {
    let dir = tempfile::tempdir().unwrap();
    let writer = MockAtomicFileWriter;
    let target = sync_state_file_path(dir.path());
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(&target, b"{ not valid json").unwrap();

    let loaded = load(&writer, dir.path()).unwrap();
    assert_eq!(loaded, SyncState::default());
}

/// test_state_split_by_connection_and_datatype — distinct
/// (provider, connection_id, data_type) combinations get distinct entries.
#[test]
fn test_state_split_by_connection_and_datatype() {
    let mut state = SyncState::default();
    record_success(
        &mut state,
        SyncSuccess {
            provider: "oura".to_string(),
            connection_id: "conn-1".to_string(),
            data_type: "sleep".to_string(),
            cursor: None,
            schema_version: 1,
            now: Utc::now(),
        },
    );
    record_success(
        &mut state,
        SyncSuccess {
            provider: "oura".to_string(),
            connection_id: "conn-1".to_string(),
            data_type: "activity".to_string(),
            cursor: None,
            schema_version: 1,
            now: Utc::now(),
        },
    );
    record_success(
        &mut state,
        SyncSuccess {
            provider: "oura".to_string(),
            connection_id: "conn-2".to_string(),
            data_type: "sleep".to_string(),
            cursor: None,
            schema_version: 1,
            now: Utc::now(),
        },
    );

    assert_eq!(state.entries.len(), 3, "each (provider, connection_id, data_type) triple is separate");
}

/// test_state_contains_no_tokens — the serialized `SyncEntry` shape has
/// exactly the six contract fields, none of which is a token/secret.
#[test]
fn test_state_contains_no_tokens() {
    let entry = sample_entry();
    let value = serde_json::to_value(&entry).unwrap();
    let obj = value.as_object().unwrap();

    let expected_keys: std::collections::BTreeSet<&str> = [
        "provider",
        "connection_id",
        "data_type",
        "cursor",
        "last_successful_sync_at",
        "schema_version",
    ]
    .into_iter()
    .collect();
    let actual_keys: std::collections::BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();

    assert_eq!(actual_keys, expected_keys, "no extra fields (e.g. tokens/secrets) on SyncEntry");
}

/// test_record_success_upserts_entry_in_place — a second call for the same
/// key updates the existing entry rather than appending a duplicate.
#[test]
fn test_record_success_upserts_entry_in_place() {
    let mut state = SyncState::default();
    let first_time: DateTime<Utc> = "2026-07-10T00:00:00Z".parse().unwrap();
    let second_time: DateTime<Utc> = "2026-07-11T00:00:00Z".parse().unwrap();

    record_success(
        &mut state,
        SyncSuccess {
            provider: "oura".to_string(),
            connection_id: "conn-1".to_string(),
            data_type: "sleep".to_string(),
            cursor: Some("cursor-1".to_string()),
            schema_version: 1,
            now: first_time,
        },
    );
    record_success(
        &mut state,
        SyncSuccess {
            provider: "oura".to_string(),
            connection_id: "conn-1".to_string(),
            data_type: "sleep".to_string(),
            cursor: Some("cursor-2".to_string()),
            schema_version: 2,
            now: second_time,
        },
    );

    assert_eq!(state.entries.len(), 1, "same key upserts in place, no duplicate");
    let entry = &state.entries[0];
    assert_eq!(entry.cursor, Some("cursor-2".to_string()));
    assert_eq!(entry.schema_version, 2);
    assert_eq!(entry.last_successful_sync_at, second_time);
}

/// test_state_forward_compat_unknown_fields — a future writer's unknown
/// top-level/entry fields don't break parsing on an older reader.
#[test]
fn test_state_forward_compat_unknown_fields() {
    let json = r#"{
        "version": 1,
        "future_field": "ignored",
        "entries": [
            {
                "provider": "oura",
                "connection_id": "conn-1",
                "data_type": "sleep",
                "cursor": "abc",
                "last_successful_sync_at": "2026-07-11T07:15:00Z",
                "schema_version": 1,
                "future_entry_field": 42
            }
        ]
    }"#;

    let state: SyncState = serde_json::from_str(json).unwrap();
    assert_eq!(state.entries.len(), 1);
    assert_eq!(state.entries[0].provider, "oura");
}

/// test_state_path_in_app_support_not_data_folder — the state file path is
/// derived from the app support directory (bundle-id subdirectory), never
/// from the user-chosen CSV data folder.
#[test]
fn test_state_path_in_app_support_not_data_folder() {
    let app_support_dir = Path::new("/Users/test/Library/Application Support");
    let data_folder = Path::new("/Users/test/Documents/ControlYourData");

    let path = sync_state_file_path(app_support_dir);

    assert!(path.starts_with(app_support_dir));
    assert!(!path.starts_with(data_folder));
    assert!(path.to_string_lossy().contains("com.github.dima.controlyourdata"));
    assert_eq!(path.file_name().unwrap(), "sync_state.json");
}
