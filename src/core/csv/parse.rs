//! CSV deserialization — the read-side counterpart to `serialize.rs`
//! (GAP-1: T-103 spec found no CSV reader existed anywhere in the codebase,
//! but T-007's upsert algorithm step 1 requires "Read existing CSV").
//!
//! Contract source: csv-contract.md L36-42 (UTF-8, header row, comma
//! delimiter, LF terminator, RFC 4180-style quoting, empty field for missing
//! values) and T-007-SCHEMA-UPSERT.md L75-77 ("Прочитать существующий CSV",
//! "Проверить заголовки и schema version"). Must round-trip byte-for-byte
//! with `serialize::serialize_rows` (T-007 L387-399 idempotency).

use super::schema::CsvSchema;
use super::serialize::CsvRow;

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The file could not be read as UTF-8 (csv-contract.md L36).
    InvalidUtf8,
    /// Underlying filesystem read failed.
    Io(String),
    /// Header row didn't match `schema.columns()` exactly — T-007-SCHEMA-
    /// UPSERT.md L76 ("Проверить заголовки").
    HeaderMismatch { expected: Vec<String>, actual: Vec<String> },
    /// A data row's cell count didn't match `schema.column_count()` —
    /// mirrors `CsvSerializeError::RowWidthMismatch` (serialize.rs) on the
    /// read side.
    RowWidthMismatch { row_index: usize, expected: usize, actual: usize },
    /// An RFC 4180 quoted field was left unterminated, or a `"` appeared
    /// outside a quoted field after non-empty unquoted content — a field
    /// must be entirely quoted or entirely unquoted (GAP-1 note: "needs
    /// proper RFC 4180 unquoting").
    MalformedQuoting { row_index: usize },
}

/// Parses RFC 4180 CSV `bytes` under `schema`: validates the header row
/// matches `schema.columns()`, then converts each data row into a `CsvRow`
/// (empty field → `None`, matching `serialize::serialize_cell`'s inverse —
/// csv-contract.md L42).
pub fn deserialize(schema: &CsvSchema, bytes: &[u8]) -> Result<Vec<CsvRow>, ParseError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ParseError::InvalidUtf8)?;
    let raw_rows = parse_raw_rows(text)?;

    let Some((header, data_rows)) = raw_rows.split_first() else {
        return Ok(Vec::new());
    };

    let expected_header = schema.columns();
    if header != &expected_header {
        return Err(ParseError::HeaderMismatch {
            expected: expected_header,
            actual: header.clone(),
        });
    }

    to_csv_rows(schema, data_rows)
}

/// T-804: inverse of `serialize::escape_formula_injection` — strips a
/// leading `'` that was inserted purely to stop spreadsheet apps from
/// interpreting a cell starting with `=`/`+`/`-`/`@` as a formula, so this
/// program's own callers (upsert comparisons, re-serialization) see the
/// original logical value, not the on-disk safety-escaped one.
///
/// Known limitation (accepted, documented — not solvable without a second
/// reserved character): a value that GENUINELY starts with `'=`/`'+`/`'-`/
/// `'@` verbatim (not from our own escaping) is indistinguishable from an
/// escaped one and will have its leading `'` incorrectly stripped on
/// read. Not reachable with current WHOOP data (no free-text fields, see
/// T-804 in `docs/tasks/EPIC-08-security.md`); would need re-evaluating if
/// a future provider's free-text field could plausibly start that way.
fn unescape_formula_injection(cell: String) -> String {
    let mut chars = cell.chars();
    match (chars.next(), chars.next()) {
        (Some('\''), Some('=' | '+' | '-' | '@')) => cell[1..].to_string(),
        _ => cell,
    }
}

/// Converts raw string cells (row index relative to data rows, i.e. after
/// the header) into `CsvRow`s, validating row width per csv-contract.md
/// L46-55 (frozen column order/count).
fn to_csv_rows(schema: &CsvSchema, data_rows: &[Vec<String>]) -> Result<Vec<CsvRow>, ParseError> {
    let expected_width = schema.column_count();
    let mut out = Vec::with_capacity(data_rows.len());
    for (row_index, raw_row) in data_rows.iter().enumerate() {
        if raw_row.len() != expected_width {
            return Err(ParseError::RowWidthMismatch {
                row_index,
                expected: expected_width,
                actual: raw_row.len(),
            });
        }
        let row: CsvRow = raw_row
            .iter()
            .map(|cell| {
                if cell.is_empty() {
                    None
                } else {
                    Some(unescape_formula_injection(cell.clone()))
                }
            })
            .collect();
        out.push(row);
    }
    Ok(out)
}

/// RFC 4180 character-level parser: handles quoted fields containing
/// embedded commas/CR/LF, and doubled `""` as an escaped quote. Splitting
/// naively on `\n` first would corrupt any field with an embedded newline,
/// so the whole text is scanned as one state machine.
fn parse_raw_rows(text: &str) -> Result<Vec<Vec<String>>, ParseError> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            consume_quoted_char(c, &mut chars, &mut field, &mut in_quotes);
        } else if c == '"' && field.is_empty() {
            in_quotes = true;
        } else if c == '"' {
            return Err(ParseError::MalformedQuoting { row_index: rows.len() });
        } else if c == ',' {
            row.push(std::mem::take(&mut field));
        } else if c == '\n' {
            row.push(std::mem::take(&mut field));
            rows.push(std::mem::take(&mut row));
        } else if c != '\r' {
            field.push(c);
        }
    }
    finish_parse(rows, row, field, in_quotes)
}

/// Handles one character while inside a quoted field: `""` is an escaped
/// quote, a lone `"` closes the field, anything else (including `,`/CR/LF)
/// is literal content (csv-contract.md L38 RFC 4180 quoting).
fn consume_quoted_char(
    c: char,
    chars: &mut std::iter::Peekable<std::str::Chars>,
    field: &mut String,
    in_quotes: &mut bool,
) {
    if c == '"' && chars.peek() == Some(&'"') {
        chars.next();
        field.push('"');
    } else if c == '"' {
        *in_quotes = false;
    } else {
        field.push(c);
    }
}

/// Flushes a trailing field/row without a final newline, and rejects an
/// unterminated quoted field (GAP-1: "proper RFC 4180 unquoting").
fn finish_parse(
    mut rows: Vec<Vec<String>>,
    mut row: Vec<String>,
    field: String,
    in_quotes: bool,
) -> Result<Vec<Vec<String>>, ParseError> {
    if in_quotes {
        return Err(ParseError::MalformedQuoting { row_index: rows.len() });
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::csv::serialize::serialize_rows;

    fn sleep_schema() -> CsvSchema {
        CsvSchema::new(vec!["sleep_score".to_string()])
    }

    fn row(cells: &[Option<&str>]) -> CsvRow {
        cells.iter().map(|c| c.map(|s| s.to_string())).collect()
    }

    /// T-804: a value written with the formula-injection guard (leading
    /// `'` prepended, see `serialize::escape_formula_injection`) round-trips
    /// back to the ORIGINAL unescaped value — the guard is transparent to
    /// this program's own callers (upsert comparisons, re-serialization);
    /// it only protects the on-disk file if opened directly in a
    /// spreadsheet app.
    #[test]
    fn test_formula_injection_guard_round_trips_to_original_value() {
        let schema = sleep_schema();
        let rows = vec![row(&[
            Some("whoop"),
            Some("=cmd|' /C calc'!A0"),
            Some("2026-07-10T22:30:00+02:00"),
            None,
            Some("2026-07-11T07:15:00Z"),
            None,
            Some("1"),
            Some("+1"),
        ])];

        let bytes = serialize_rows(&schema, &rows).unwrap();
        // Sanity: the on-disk bytes DO contain the guard (not silently a no-op).
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.contains("'=cmd|"), "expected the guard present on disk, got: {text}");

        let parsed = deserialize(&schema, &bytes).unwrap();
        assert_eq!(
            parsed, rows,
            "parsing a formula-guarded CSV must recover the exact original values \
             (external_id='=cmd|...', sleep_score='+1'), for upsert comparison (T-007) \
             to see the same logical value that was written"
        );
    }

    /// §7 test_parse_roundtrip_matches_serialize — GAP-1: parse must be the
    /// exact inverse of T-102's `serialize_rows`.
    #[test]
    fn test_parse_roundtrip_matches_serialize() {
        let schema = sleep_schema();
        let rows = vec![
            row(&[
                Some("oura"),
                Some("id-1"),
                Some("2026-07-10T22:30:00+02:00"),
                None,
                Some("2026-07-11T07:15:00Z"),
                Some("Europe/Berlin"),
                Some("1"),
                Some("85"),
            ]),
            row(&[
                Some("oura"),
                Some("id,2"),
                Some("2026-07-11T22:30:00+02:00"),
                Some("2026-07-12T06:00:00Z"),
                Some("2026-07-12T07:15:00Z"),
                None,
                Some("1"),
                Some("say \"hi\""),
            ]),
        ];

        let bytes = serialize_rows(&schema, &rows).unwrap();
        let parsed = deserialize(&schema, &bytes).unwrap();

        assert_eq!(parsed, rows);
    }

    /// §7 test_parse_quoted_field — commas and doubled quotes inside a
    /// quoted field are unescaped correctly.
    #[test]
    fn test_parse_quoted_field() {
        let schema = sleep_schema();
        let bytes = b"source,external_id,recorded_at,updated_at,synced_at,timezone,schema_version,sleep_score\noura,\"a,b\",2026-07-10T22:30:00+02:00,,2026-07-11T07:15:00Z,,1,\"say \"\"hi\"\"\"\n".to_vec();

        let parsed = deserialize(&schema, &bytes).unwrap();

        assert_eq!(parsed[0][1], Some("a,b".to_string()));
        assert_eq!(parsed[0][7], Some("say \"hi\"".to_string()));
    }

    /// §7 test_parse_empty_field — empty field parses to `None`
    /// (csv-contract.md L42).
    #[test]
    fn test_parse_empty_field() {
        let schema = sleep_schema();
        let bytes = b"source,external_id,recorded_at,updated_at,synced_at,timezone,schema_version,sleep_score\noura,id-1,2026-07-10T22:30:00+02:00,,2026-07-11T07:15:00Z,,1,\n".to_vec();

        let parsed = deserialize(&schema, &bytes).unwrap();

        assert_eq!(parsed[0][3], None);
        assert_eq!(parsed[0][7], None);
    }

    /// §7 test_parse_header_mismatch — a header that doesn't match the
    /// schema's frozen column order is rejected (T-007 L76).
    #[test]
    fn test_parse_header_mismatch() {
        let schema = sleep_schema();
        let bytes = b"source,external_id,sleep_score\noura,id-1,85\n".to_vec();

        let result = deserialize(&schema, &bytes);

        assert!(matches!(result, Err(ParseError::HeaderMismatch { .. })));
    }
}
