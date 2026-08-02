//! T-102: CSV writer — serialization + atomic persistence.
//!
//! Scope (per T-102 spec): serialization and atomic persistence only. Upsert
//! (T-007 Part 2), sorting (T-007 step 5 / T-103), and domain value
//! formatting (bools, decimals, durations) are explicitly out of scope —
//! `CsvRow` cells are pre-stringified `Option<String>`.

pub mod parse;
pub mod schema;
pub mod serialize;
pub mod upsert;
pub mod writer;

pub use parse::{deserialize, ParseError};
pub use schema::{CsvSchema, MANDATORY_COLUMNS};
pub use serialize::{escape_field, serialize_rows, CsvRow, CsvSerializeError};
pub use upsert::{merge_rows, upsert as upsert_csv, DeletionMarker, UpsertError, UpsertStats};
pub use writer::{CsvWriteError, CsvWriter};
