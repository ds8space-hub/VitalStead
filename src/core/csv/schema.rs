//! CSV schema — mandatory service columns in frozen order, plus per-CSV
//! metric columns appended at the end.
//!
//! Contract source: T-007-SCHEMA-UPSERT.md L22-34 ("Mandatory Service
//! Columns... in this order, before metric-specific columns") and L46-55
//! ("Column Order Stability" — column order is frozen per CSV type per
//! `schema_version`; new metrics append at the end).

/// Mandatory service columns, in frozen order — T-007-SCHEMA-UPSERT.md L24-34:
/// `source, external_id, recorded_at, updated_at, synced_at, timezone,
/// schema_version`.
pub const MANDATORY_COLUMNS: [&str; 7] = [
    "source",
    "external_id",
    "recorded_at",
    "updated_at",
    "synced_at",
    "timezone",
    "schema_version",
];

/// A CSV schema: fixed mandatory columns + metric-specific columns for one
/// CSV type at one `schema_version` (T-007-SCHEMA-UPSERT.md L46-55).
#[derive(Debug, Clone)]
pub struct CsvSchema {
    metric_columns: Vec<String>,
}

impl CsvSchema {
    /// `metric_columns` are the CSV-type-specific columns that follow the
    /// mandatory columns, in the frozen order for this `schema_version`
    /// (T-007 L36-38, L46-51).
    pub fn new(metric_columns: Vec<String>) -> Self {
        Self { metric_columns }
    }

    /// Full header column list: mandatory columns first, metric columns
    /// after — T-007 L24 "in this order, before metric-specific columns".
    pub fn columns(&self) -> Vec<String> {
        let mut cols: Vec<String> = MANDATORY_COLUMNS.iter().map(|c| c.to_string()).collect();
        cols.extend(self.metric_columns.iter().cloned());
        cols
    }

    /// Expected cell count for every row under this schema.
    pub fn column_count(&self) -> usize {
        MANDATORY_COLUMNS.len() + self.metric_columns.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mandatory_columns_precede_metric_columns_in_frozen_order() {
        let schema = CsvSchema::new(vec!["sleep_score".to_string(), "duration_seconds".to_string()]);
        assert_eq!(
            schema.columns(),
            vec![
                "source",
                "external_id",
                "recorded_at",
                "updated_at",
                "synced_at",
                "timezone",
                "schema_version",
                "sleep_score",
                "duration_seconds",
            ]
        );
        assert_eq!(schema.column_count(), 9);
    }
}
