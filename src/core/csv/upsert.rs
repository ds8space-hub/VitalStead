//! T-103: CSV upsert — in-memory merge/sort/delete (T-007-SCHEMA-UPSERT.md
//! Part 2), then persistence delegated to T-102's `CsvWriter`.
//!
//! `merge_rows` is pure (no I/O) so it can be unit-tested directly; `upsert`
//! is the orchestration entry point that reads the existing file, calls
//! `merge_rows`, and persists the result atomically.

use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, FixedOffset};

use super::parse::{deserialize, ParseError};
use super::schema::CsvSchema;
use super::serialize::CsvRow;
use super::writer::{CsvWriteError, CsvWriter};

/// Fixed mandatory-column indices — schema.rs `MANDATORY_COLUMNS`:
/// `source, external_id, recorded_at, updated_at, synced_at, timezone,
/// schema_version`.
const SOURCE: usize = 0;
const EXTERNAL_ID: usize = 1;
const RECORDED_AT: usize = 2;
const UPDATED_AT: usize = 3;
const SCHEMA_VERSION: usize = 6;

/// A provider-sent deletion marker — T-007-SCHEMA-UPSERT.md L349-368,
/// keyed the same way as a merge key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletionMarker {
    pub source: String,
    pub external_id: String,
}

/// T-007 L72 `upsert_stats: { inserted, updated, deleted }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UpsertStats {
    pub inserted: usize,
    pub updated: usize,
    pub deleted: usize,
}

#[derive(Debug)]
pub enum UpsertError {
    Parse(ParseError),
    Write(CsvWriteError),
    /// Existing CSV's `schema_version` doesn't match the expected one —
    /// T-007 L76-78, L412 ("do not auto-upgrade (user must reset)").
    SchemaVersionMismatch { expected: String, found: String },
    /// T-007 L407 ("Record with NULL external_id" is an error) — the
    /// symmetric `source` case is required by the same merge key rule
    /// (csv-contract.md L65-67).
    MissingSource { row_index: usize },
    MissingExternalId { row_index: usize },
    /// T-007 L408 ("Record with NULL recorded_at" is an error).
    MissingRecordedAt { row_index: usize },
    /// `updated_at` was present but not parseable as RFC 3339 (GAP-2:
    /// needed for correct cross-offset comparison, T-007 L91).
    InvalidUpdatedAt { row_index: usize },
}

/// Pure merge: applies `new_rows` onto `existing` by merge key
/// `(source, external_id)`, applies `deletions`, then sorts deterministically
/// — T-007-SCHEMA-UPSERT.md L85-113 (steps 3-5). No I/O.
pub fn merge_rows(
    existing: &[CsvRow],
    new_rows: &[CsvRow],
    deletions: &[DeletionMarker],
    schema_version: u32,
) -> Result<(Vec<CsvRow>, UpsertStats), UpsertError> {
    validate_schema_version(existing, schema_version)?;

    let mut rows: Vec<CsvRow> = existing.to_vec();
    let mut index = build_index(&rows);
    let mut stats = UpsertStats::default();

    for (row_index, new_row) in new_rows.iter().enumerate() {
        validate_new_row(new_row, row_index)?;
        apply_new_row(&mut rows, &mut index, new_row, row_index, &mut stats)?;
    }

    apply_deletions(&mut rows, &mut index, deletions, &mut stats);
    sort_rows(&mut rows);

    Ok((rows, stats))
}

/// T-007 L76-78 ("Проверить заголовки и schema version"): every existing
/// row must already carry the expected `schema_version`; a mismatch means
/// the caller is upserting into a CSV written under a different version.
fn validate_schema_version(existing: &[CsvRow], schema_version: u32) -> Result<(), UpsertError> {
    let expected = schema_version.to_string();
    for row in existing {
        if let Some(found) = row.get(SCHEMA_VERSION).and_then(|c| c.as_ref()) {
            if found != &expected {
                return Err(UpsertError::SchemaVersionMismatch {
                    expected,
                    found: found.clone(),
                });
            }
        }
    }
    Ok(())
}

/// T-007 L407-408: `source`, `external_id`, and `recorded_at` are required
/// on every incoming record (they form the merge key plus the sort key).
fn validate_new_row(row: &CsvRow, row_index: usize) -> Result<(), UpsertError> {
    if row.get(SOURCE).and_then(|c| c.as_ref()).is_none() {
        return Err(UpsertError::MissingSource { row_index });
    }
    if row.get(EXTERNAL_ID).and_then(|c| c.as_ref()).is_none() {
        return Err(UpsertError::MissingExternalId { row_index });
    }
    if row.get(RECORDED_AT).and_then(|c| c.as_ref()).is_none() {
        return Err(UpsertError::MissingRecordedAt { row_index });
    }
    Ok(())
}

/// Builds the `(source, external_id) -> rows index` lookup — T-007 L78
/// "Map<(source, external_id), row_data> -> O(1) lookup".
fn build_index(rows: &[CsvRow]) -> HashMap<(String, String), usize> {
    rows.iter()
        .enumerate()
        .filter_map(|(i, row)| Some(((row.get(SOURCE)?.clone()?, row.get(EXTERNAL_ID)?.clone()?), i)))
        .collect()
}

/// T-007 L86-102 (step 3): insert if the key is new, replace if the
/// incoming record is newer (or has no `updated_at`), otherwise skip and
/// leave the existing row byte-for-byte untouched (GAP-3: upsert never
/// stamps timestamps). Re-reading `index` after each call also gives
/// "duplicate key in same sync keeps latest" (T-007 L414) for free — a
/// later duplicate compares against the row just written by an earlier one.
fn apply_new_row(
    rows: &mut Vec<CsvRow>,
    index: &mut HashMap<(String, String), usize>,
    new_row: &CsvRow,
    row_index: usize,
    stats: &mut UpsertStats,
) -> Result<(), UpsertError> {
    let key = (
        new_row[SOURCE].clone().unwrap(),
        new_row[EXTERNAL_ID].clone().unwrap(),
    );

    match index.get(&key).copied() {
        None => {
            index.insert(key, rows.len());
            rows.push(new_row.clone());
            stats.inserted += 1;
        }
        Some(existing_index) => {
            let old_updated_at = &rows[existing_index][UPDATED_AT];
            if is_newer(&new_row[UPDATED_AT], old_updated_at, row_index)? {
                rows[existing_index] = new_row.clone();
                stats.updated += 1;
            }
        }
    }
    Ok(())
}

/// T-007 L91-98: `new.updated_at > old.updated_at OR new.updated_at IS
/// NULL` replaces; ties or an older `new.updated_at` skip. A missing
/// `old.updated_at` (no prior timestamp) is treated as older than any
/// timestamped incoming record.
fn is_newer(
    new_updated_at: &Option<String>,
    old_updated_at: &Option<String>,
    row_index: usize,
) -> Result<bool, UpsertError> {
    let new_ts = match new_updated_at {
        None => return Ok(true),
        Some(s) => parse_rfc3339(s, row_index)?,
    };
    let old_ts = match old_updated_at {
        None => return Ok(true),
        Some(s) => parse_rfc3339(s, row_index)?,
    };
    Ok(new_ts > old_ts)
}

/// GAP-2: cross-offset comparison requires parsing, not string comparison.
fn parse_rfc3339(value: &str, row_index: usize) -> Result<DateTime<FixedOffset>, UpsertError> {
    DateTime::parse_from_rfc3339(value).map_err(|_| UpsertError::InvalidUpdatedAt { row_index })
}

/// T-007 L104-109, L349-379 (step 4): remove matching rows, no tombstone.
fn apply_deletions(
    rows: &mut Vec<CsvRow>,
    index: &mut HashMap<(String, String), usize>,
    deletions: &[DeletionMarker],
    stats: &mut UpsertStats,
) {
    for marker in deletions {
        let key = (marker.source.clone(), marker.external_id.clone());
        if let Some(removed_index) = index.remove(&key) {
            rows.remove(removed_index);
            stats.deleted += 1;
            reindex_after_removal(index, removed_index);
        }
    }
}

/// `Vec::remove` shifts every later element left by one; the index must be
/// kept consistent so subsequent deletion lookups stay correct.
fn reindex_after_removal(index: &mut HashMap<(String, String), usize>, removed_index: usize) {
    for value in index.values_mut() {
        if *value > removed_index {
            *value -= 1;
        }
    }
}

/// T-007 L111-112, L596: deterministic sort by `(source, external_id,
/// recorded_at)`. The merge key `(source, external_id)` is already unique
/// per row, so this ordering is total and stability doesn't affect output.
fn sort_rows(rows: &mut [CsvRow]) {
    rows.sort_by_key(sort_key);
}

fn sort_key(row: &CsvRow) -> (String, String, String) {
    let cell = |i: usize| row.get(i).and_then(|c| c.clone()).unwrap_or_default();
    (cell(SOURCE), cell(EXTERNAL_ID), cell(RECORDED_AT))
}

/// Orchestration entry point — T-007 L64-131: reads the existing CSV (if
/// any), merges, and persists atomically via T-102's `CsvWriter`.
pub fn upsert(
    target: &Path,
    schema: &CsvSchema,
    new_rows: &[CsvRow],
    deletions: &[DeletionMarker],
    schema_version: u32,
    writer: &CsvWriter,
) -> Result<UpsertStats, UpsertError> {
    let existing = read_existing(target, schema)?;
    let (merged, stats) = merge_rows(&existing, new_rows, deletions, schema_version)?;
    writer.persist(target, schema, &merged).map_err(UpsertError::Write)?;
    Ok(stats)
}

/// T-007 L134, L405: a missing or empty existing file is "first sync" —
/// treated as zero existing rows, not an error.
fn read_existing(target: &Path, schema: &CsvSchema) -> Result<Vec<CsvRow>, UpsertError> {
    if !target.exists() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(target).map_err(|e| UpsertError::Parse(ParseError::Io(e.to_string())))?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    deserialize(schema, &bytes).map_err(UpsertError::Parse)
}

#[cfg(test)]
mod tests;
