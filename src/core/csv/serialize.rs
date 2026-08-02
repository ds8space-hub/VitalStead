//! Pure CSV serialization — no I/O, no domain formatting.
//!
//! Contract source: csv-contract.md L36-42 (UTF-8 encoding, header row,
//! comma delimiter, LF line terminator, RFC 4180-style quoting, empty field
//! for missing values) and T-007-SCHEMA-UPSERT.md L387-399 (idempotency:
//! identical input must produce byte-identical output).

use super::schema::CsvSchema;

/// One CSV row: a pre-stringified cell per schema column, in schema column
/// order. `None` represents a missing value (csv-contract.md L42 — empty
/// field). Typed-value formatting (bools, decimals, durations) happens
/// upstream of T-102's scope.
pub type CsvRow = Vec<Option<String>>;

#[derive(Debug, PartialEq, Eq)]
pub enum CsvSerializeError {
    /// A row's cell count didn't match `schema.column_count()`. Column order
    /// is frozen per schema_version (T-007 L46-55); a mismatched row would
    /// silently shift every later column, so it is rejected instead.
    RowWidthMismatch {
        row_index: usize,
        expected: usize,
        actual: usize,
    },
}

/// T-804 (found during T-801 threat model review): neutralizes CSV/formula
/// injection (OWASP CSV Injection guidance) by prepending a single quote to
/// any value starting with `=`, `+`, `-`, or `@` — the leading characters
/// spreadsheet applications (Excel, Google Sheets) interpret as "this cell
/// is a formula". A leading `'` is the standard mitigation: spreadsheet
/// apps treat it as a "force text" marker and never execute what follows.
///
/// This only guards the on-disk file against being opened in a spreadsheet
/// app — it must stay perfectly reversible for this program's own use, so
/// `parse::unescape_formula_injection` strips the same marker back off on
/// read (T-007 upsert compares `updated_at`, not full-row equality, so this
/// round-trip doesn't affect upsert stability — see T-804 in
/// `docs/tasks/EPIC-08-security.md` for the full analysis). Not currently
/// reachable with real data: WHOOP's DTOs (`core/connectors/whoop/dto.rs`)
/// have no free-text fields an attacker could seed with a leading `=`/`+`/
/// `-`/`@` — this is defense-in-depth for future providers that do.
fn escape_formula_injection(value: &str) -> String {
    if value.starts_with(['=', '+', '-', '@']) {
        format!("'{value}")
    } else {
        value.to_string()
    }
}

/// Escapes a single field per RFC 4180 quoting (csv-contract.md L38):
/// quote the field only if it contains a comma, double-quote, CR, or LF;
/// double any internal double-quotes. Fields needing no quoting are
/// returned unquoted and untrimmed.
pub fn escape_field(field: &str) -> String {
    let needs_quoting =
        field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r');
    if !needs_quoting {
        return field.to_string();
    }
    let escaped = field.replace('"', "\"\"");
    format!("\"{escaped}\"")
}

/// Empty field for a missing value (csv-contract.md L42), otherwise the
/// formula-injection-guarded, RFC 4180-escaped cell value (T-804: formula
/// guard applies first, so a comma/quote introduced by the leading `'` is
/// still correctly RFC 4180-quoted afterwards).
fn serialize_cell(cell: &Option<String>) -> String {
    match cell {
        None => String::new(),
        Some(value) => escape_field(&escape_formula_injection(value)),
    }
}

/// Serializes `rows` under `schema` to RFC 4180 CSV bytes: UTF-8, no BOM,
/// LF line terminator (csv-contract.md L36-39). Header row is written
/// first, then rows in input order — T-102 does not sort or upsert; that is
/// T-103/T-007's responsibility.
pub fn serialize_rows(schema: &CsvSchema, rows: &[CsvRow]) -> Result<Vec<u8>, CsvSerializeError> {
    let columns = schema.columns();
    let expected_width = columns.len();

    let mut out = String::new();
    out.push_str(&columns.join(","));
    out.push('\n');

    for (row_index, row) in rows.iter().enumerate() {
        if row.len() != expected_width {
            return Err(CsvSerializeError::RowWidthMismatch {
                row_index,
                expected: expected_width,
                actual: row.len(),
            });
        }
        let line: Vec<String> = row.iter().map(serialize_cell).collect();
        out.push_str(&line.join(","));
        out.push('\n');
    }

    Ok(out.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sleep_schema() -> CsvSchema {
        CsvSchema::new(vec!["sleep_score".to_string()])
    }

    fn row(cells: &[Option<&str>]) -> CsvRow {
        cells.iter().map(|c| c.map(|s| s.to_string())).collect()
    }

    /// §5 test_write_utf8_no_bom_and_lf_terminator — csv-contract.md L36,39.
    #[test]
    fn test_write_utf8_no_bom_and_lf_terminator() {
        let schema = sleep_schema();
        let rows = vec![row(&[
            Some("oura"),
            Some("id-1"),
            Some("2026-07-10T22:30:00+02:00"),
            None,
            Some("2026-07-11T07:15:00Z"),
            Some("Europe/Berlin"),
            Some("1"),
            Some("85"),
        ])];

        let bytes = serialize_rows(&schema, &rows).unwrap();

        // No UTF-8 BOM (EF BB BF) at the start of the output.
        assert_ne!(&bytes[0..3.min(bytes.len())], &[0xEF, 0xBB, 0xBF][..]);
        let text = String::from_utf8(bytes).expect("output must be valid UTF-8");
        assert!(!text.contains('\r'), "output must use LF only, no CR");
        assert!(text.ends_with('\n'), "every line, including the last, ends with LF");
        assert_eq!(text.matches('\n').count(), 2, "header + 1 row = 2 LF terminators");
    }

    /// §5 test_escape_field_with_commas — csv-contract.md L38 (RFC 4180 quoting).
    #[test]
    fn test_escape_field_with_commas() {
        assert_eq!(escape_field("a,b"), "\"a,b\"");
    }

    /// §5 test_escape_field_with_quotes — internal quotes doubled per RFC 4180.
    #[test]
    fn test_escape_field_with_quotes() {
        assert_eq!(escape_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    /// §5 test_escape_field_with_newlines — LF and CR both trigger quoting.
    #[test]
    fn test_escape_field_with_newlines() {
        assert_eq!(escape_field("line1\nline2"), "\"line1\nline2\"");
        assert_eq!(escape_field("line1\rline2"), "\"line1\rline2\"");
    }

    /// T-804: a cell value that would be interpreted as a formula by a
    /// spreadsheet app (starts with =, +, -, or @) is written with a
    /// leading `'` guard.
    #[test]
    fn test_formula_injection_guard_prefixes_dangerous_leading_chars() {
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

        let text = String::from_utf8(serialize_rows(&schema, &rows).unwrap()).unwrap();
        let data_line = text.lines().nth(1).unwrap();

        // external_id (col 1) started with '=' — guarded.
        assert!(
            data_line.contains("'=cmd|"),
            "expected leading quote guard before '=cmd|...', got: {data_line}"
        );
        // sleep_score (last col) started with '+' — guarded.
        assert!(data_line.ends_with("'+1"), "expected leading quote guard before '+1', got: {data_line}");
    }

    /// T-804: a value with no dangerous leading char is written unchanged
    /// (no spurious escaping of ordinary data).
    #[test]
    fn test_formula_injection_guard_leaves_ordinary_values_untouched() {
        assert_eq!(escape_formula_injection("85"), "85");
        assert_eq!(escape_formula_injection("SCORED"), "SCORED");
        assert_eq!(escape_formula_injection(""), "");
        // A `-` or `@` in the MIDDLE of a value is not a leading char, no guard needed.
        assert_eq!(escape_formula_injection("2026-07-10"), "2026-07-10");
        assert_eq!(escape_formula_injection("user@example.com"), "user@example.com");
    }

    /// T-804: all 4 OWASP-flagged leading characters trigger the guard.
    #[test]
    fn test_formula_injection_guard_covers_all_four_trigger_chars() {
        assert_eq!(escape_formula_injection("=1+1"), "'=1+1");
        assert_eq!(escape_formula_injection("+1+1"), "'+1+1");
        assert_eq!(escape_formula_injection("-1+1"), "'-1+1");
        assert_eq!(escape_formula_injection("@SUM(A1:A9)"), "'@SUM(A1:A9)");
    }

    /// §5 test_escape_field_plain_unquoted — fields with no special chars are
    /// left unquoted and untrimmed.
    #[test]
    fn test_escape_field_plain_unquoted() {
        assert_eq!(escape_field("plain value"), "plain value");
        assert_eq!(escape_field(""), "");
    }

    /// §5 test_null_cell_is_empty_field — csv-contract.md L42.
    #[test]
    fn test_null_cell_is_empty_field() {
        let schema = sleep_schema();
        let rows = vec![row(&[
            Some("oura"),
            Some("id-1"),
            Some("2026-07-10T22:30:00+02:00"),
            None,
            Some("2026-07-11T07:15:00Z"),
            None,
            Some("1"),
            None,
        ])];

        let text = String::from_utf8(serialize_rows(&schema, &rows).unwrap()).unwrap();
        let data_line = text.lines().nth(1).unwrap();
        assert_eq!(
            data_line,
            "oura,id-1,2026-07-10T22:30:00+02:00,,2026-07-11T07:15:00Z,,1,"
        );
    }

    /// §5 test_stable_column_order_matches_schema — T-007 L24-34, L46-55.
    #[test]
    fn test_stable_column_order_matches_schema() {
        let schema = sleep_schema();
        let text = String::from_utf8(serialize_rows(&schema, &[]).unwrap()).unwrap();
        let header = text.lines().next().unwrap();
        assert_eq!(
            header,
            "source,external_id,recorded_at,updated_at,synced_at,timezone,schema_version,sleep_score"
        );
    }

    /// §5 test_stable_row_order_preserved_and_deterministic — T-007 L387-399
    /// idempotency: same input rows, in the same order, produce identical
    /// bytes on repeated calls; no reordering happens in this layer.
    #[test]
    fn test_stable_row_order_preserved_and_deterministic() {
        let schema = sleep_schema();
        let rows = vec![
            row(&[
                Some("oura"),
                Some("id-2"),
                Some("2026-07-11T22:30:00+02:00"),
                None,
                Some("2026-07-12T07:15:00Z"),
                Some("Europe/Berlin"),
                Some("1"),
                Some("90"),
            ]),
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
        ];

        let first = serialize_rows(&schema, &rows).unwrap();
        let second = serialize_rows(&schema, &rows).unwrap();
        assert_eq!(first, second, "identical input must produce byte-identical output");

        let text = String::from_utf8(first).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[1].starts_with("oura,id-2"), "row order is input order, not sorted");
        assert!(lines[2].starts_with("oura,id-1"), "row order is input order, not sorted");
    }

    /// §5 test_row_width_mismatch_rejected — protects frozen column order
    /// (T-007 L46-55) from silent corruption by short/long rows.
    #[test]
    fn test_row_width_mismatch_rejected() {
        let schema = sleep_schema();
        let short_row: CsvRow = row(&[Some("oura"), Some("id-1")]);

        let result = serialize_rows(&schema, &[short_row]);

        assert_eq!(
            result,
            Err(CsvSerializeError::RowWidthMismatch {
                row_index: 0,
                expected: 8,
                actual: 2,
            })
        );
    }
}
