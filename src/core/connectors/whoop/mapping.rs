//! WHOOP DTO → CSV row mapping.
//!
//! Contract source: Step 2 spec — defines the transformation from WHOOP API DTOs
//! to CSV rows per csv-contract.md mandatory columns and metric-specific columns.
//!
//! Mandatory columns (from csv-contract.md): source, external_id, recorded_at, updated_at,
//! synced_at, timezone, schema_version (always "1" for this step).
//!
//! Metric columns are specific to each record type (sleep, recovery, cycle, workout)
//! and frozen in order per csv-contract.md column order stability rule.

use chrono::{DateTime, Utc};

use super::dto::{CycleRecord, RecoveryRecord, SleepRecord, WorkoutRecord};
use crate::core::csv::schema::CsvSchema;
use crate::core::csv::serialize::CsvRow;

/// Sleep record schema: sleep-specific metric columns in frozen order.
pub fn sleep_schema() -> CsvSchema {
    CsvSchema::new(vec![
        "nap".to_string(),
        "score_state".to_string(),
        "total_in_bed_time_milli".to_string(),
        "total_awake_time_milli".to_string(),
        "total_no_data_time_milli".to_string(),
        "total_light_sleep_time_milli".to_string(),
        "total_slow_wave_sleep_time_milli".to_string(),
        "total_rem_sleep_time_milli".to_string(),
        "sleep_cycle_count".to_string(),
        "disturbance_count".to_string(),
        "respiratory_rate".to_string(),
        "sleep_performance_percentage".to_string(),
        "sleep_consistency_percentage".to_string(),
        "sleep_efficiency_percentage".to_string(),
    ])
}

/// Recovery record schema: recovery-specific metric columns in frozen order.
pub fn recovery_schema() -> CsvSchema {
    CsvSchema::new(vec![
        "sleep_id".to_string(),
        "score_state".to_string(),
        "user_calibrating".to_string(),
        "recovery_score".to_string(),
        "resting_heart_rate".to_string(),
        "hrv_rmssd_milli".to_string(),
        "spo2_percentage".to_string(),
        "skin_temp_celsius".to_string(),
    ])
}

/// Cycle (training) record schema: cycle-specific metric columns in frozen order.
pub fn cycle_schema() -> CsvSchema {
    CsvSchema::new(vec![
        "score_state".to_string(),
        "strain".to_string(),
        "kilojoule".to_string(),
        "average_heart_rate".to_string(),
        "max_heart_rate".to_string(),
    ])
}

/// Workout record schema: workout-specific metric columns in frozen order.
pub fn workout_schema() -> CsvSchema {
    CsvSchema::new(vec![
        "sport_id".to_string(),
        "score_state".to_string(),
        "strain".to_string(),
        "average_heart_rate".to_string(),
        "max_heart_rate".to_string(),
        "kilojoule".to_string(),
        "percent_recorded".to_string(),
        "distance_meter".to_string(),
        "altitude_gain_meter".to_string(),
        "altitude_change_meter".to_string(),
    ])
}

/// Map a sleep record to a CSV row.
///
/// Mandatory columns: source="whoop", external_id=id, recorded_at=start, updated_at=updated_at,
/// synced_at=passed parameter, timezone=timezone_offset, schema_version="1".
/// Metric columns follow sleep_schema() order.
pub fn map_sleep(record: &SleepRecord, synced_at: DateTime<Utc>) -> CsvRow {
    let nap = if record.nap { Some("true".to_string()) } else { Some("false".to_string()) };

    // Stage summary metrics
    let stage = record.score.as_ref().and_then(|s| s.stage_summary.as_ref());
    let in_bed = stage.and_then(|st| st.total_in_bed_time_milli.map(|v| v.to_string()));
    let awake = stage.and_then(|st| st.total_awake_time_milli.map(|v| v.to_string()));
    let no_data = stage.and_then(|st| st.total_no_data_time_milli.map(|v| v.to_string()));
    let light = stage.and_then(|st| st.total_light_sleep_time_milli.map(|v| v.to_string()));
    let sws = stage.and_then(|st| st.total_slow_wave_sleep_time_milli.map(|v| v.to_string()));
    let rem = stage.and_then(|st| st.total_rem_sleep_time_milli.map(|v| v.to_string()));
    let cycles = stage.and_then(|st| st.sleep_cycle_count.map(|v| v.to_string()));
    let disturbances = stage.and_then(|st| st.disturbance_count.map(|v| v.to_string()));

    // Score metrics
    let respiratory = record.score.as_ref().and_then(|s| s.respiratory_rate.map(|v| v.to_string()));
    let perf = record.score.as_ref().and_then(|s| s.sleep_performance_percentage.map(|v| v.to_string()));
    let consistency = record.score.as_ref().and_then(|s| s.sleep_consistency_percentage.map(|v| v.to_string()));
    let efficiency = record.score.as_ref().and_then(|s| s.sleep_efficiency_percentage.map(|v| v.to_string()));

    vec![
        Some("whoop".to_string()),                    // source
        Some(record.id.clone()),                      // external_id
        Some(record.start.clone()),                   // recorded_at
        Some(record.updated_at.clone()),              // updated_at
        Some(synced_at.to_rfc3339()),                 // synced_at
        record.timezone_offset.clone(),               // timezone
        Some("1".to_string()),                        // schema_version
        // Metric columns
        nap,                                          // nap
        Some(record.score_state.clone()),             // score_state
        in_bed,                                       // total_in_bed_time_milli
        awake,                                        // total_awake_time_milli
        no_data,                                      // total_no_data_time_milli
        light,                                        // total_light_sleep_time_milli
        sws,                                          // total_slow_wave_sleep_time_milli
        rem,                                          // total_rem_sleep_time_milli
        cycles,                                       // sleep_cycle_count
        disturbances,                                 // disturbance_count
        respiratory,                                  // respiratory_rate
        perf,                                         // sleep_performance_percentage
        consistency,                                  // sleep_consistency_percentage
        efficiency,                                   // sleep_efficiency_percentage
    ]
}

/// Map a recovery record to a CSV row.
///
/// Uses cycle_id (not id) as external_id — RecoveryRecord has no separate `id`
/// field in WHOOP API v2, it's identified by its cycle. `cycle_id` is a JSON
/// number on the wire (confirmed on manual e2e, T-401) — converted to String
/// here since external_id is always textual.
///
/// recorded_at uses `created_at` (confirmed present on manual e2e — not
/// anticipated by the original ASSUMPTION) rather than `updated_at`:
/// RecoveryRecord has no `start`/`end` fields (a recovery score is computed
/// per-cycle, not a time-ranged event like sleep/cycle/workout), and
/// `created_at` is the closer semantic match to "when this record happened".
pub fn map_recovery(record: &RecoveryRecord, synced_at: DateTime<Utc>) -> CsvRow {
    let score_data = record.score.as_ref();

    let calibrating = score_data.and_then(|s| s.user_calibrating.map(|v| v.to_string()));
    let recovery_score = score_data.and_then(|s| s.recovery_score.map(|v| v.to_string()));
    let resting_hr = score_data.and_then(|s| s.resting_heart_rate.map(|v| v.to_string()));
    let hrv = score_data.and_then(|s| s.hrv_rmssd_milli.map(|v| v.to_string()));
    let spo2 = score_data.and_then(|s| s.spo2_percentage.map(|v| v.to_string()));
    let temp = score_data.and_then(|s| s.skin_temp_celsius.map(|v| v.to_string()));

    vec![
        Some("whoop".to_string()),                    // source
        Some(record.cycle_id.to_string()),             // external_id (cycle_id, numeric on the wire)
        record.created_at.clone().or_else(|| Some(record.updated_at.clone())), // recorded_at
        Some(record.updated_at.clone()),              // updated_at
        Some(synced_at.to_rfc3339()),                 // synced_at
        None,                                         // timezone (recovery has no timezone)
        Some("1".to_string()),                        // schema_version
        // Metric columns
        record.sleep_id.clone(),                      // sleep_id
        Some(record.score_state.clone()),             // score_state
        calibrating,                                  // user_calibrating
        recovery_score,                               // recovery_score
        resting_hr,                                   // resting_heart_rate
        hrv,                                          // hrv_rmssd_milli
        spo2,                                         // spo2_percentage
        temp,                                         // skin_temp_celsius
    ]
}

/// Map a cycle record to a CSV row.
pub fn map_cycle(record: &CycleRecord, synced_at: DateTime<Utc>) -> CsvRow {
    let score_data = record.score.as_ref();

    let strain = score_data.and_then(|s| s.strain.map(|v| v.to_string()));
    let kilojoule = score_data.and_then(|s| s.kilojoule.map(|v| v.to_string()));
    let avg_hr = score_data.and_then(|s| s.average_heart_rate.map(|v| v.to_string()));
    let max_hr = score_data.and_then(|s| s.max_heart_rate.map(|v| v.to_string()));

    vec![
        Some("whoop".to_string()),                    // source
        Some(record.id.to_string()),                  // external_id (id is numeric on the wire)
        Some(record.start.clone()),                   // recorded_at
        Some(record.updated_at.clone()),              // updated_at
        Some(synced_at.to_rfc3339()),                 // synced_at
        record.timezone_offset.clone(),               // timezone
        Some("1".to_string()),                        // schema_version
        // Metric columns
        Some(record.score_state.clone()),             // score_state
        strain,                                       // strain
        kilojoule,                                    // kilojoule
        avg_hr,                                       // average_heart_rate
        max_hr,                                       // max_heart_rate
    ]
}

/// Map a workout record to a CSV row.
pub fn map_workout(record: &WorkoutRecord, synced_at: DateTime<Utc>) -> CsvRow {
    let score_data = record.score.as_ref();

    let strain = score_data.and_then(|s| s.strain.map(|v| v.to_string()));
    let avg_hr = score_data.and_then(|s| s.average_heart_rate.map(|v| v.to_string()));
    let max_hr = score_data.and_then(|s| s.max_heart_rate.map(|v| v.to_string()));
    let kilojoule = score_data.and_then(|s| s.kilojoule.map(|v| v.to_string()));
    let percent = score_data.and_then(|s| s.percent_recorded.map(|v| v.to_string()));
    let distance = score_data.and_then(|s| s.distance_meter.map(|v| v.to_string()));
    let alt_gain = score_data.and_then(|s| s.altitude_gain_meter.map(|v| v.to_string()));
    let alt_change = score_data.and_then(|s| s.altitude_change_meter.map(|v| v.to_string()));

    vec![
        Some("whoop".to_string()),                    // source
        Some(record.id.clone()),                      // external_id
        Some(record.start.clone()),                   // recorded_at
        Some(record.updated_at.clone()),              // updated_at
        Some(synced_at.to_rfc3339()),                 // synced_at
        record.timezone_offset.clone(),               // timezone
        Some("1".to_string()),                        // schema_version
        // Metric columns
        record.sport_id.map(|v| v.to_string()),       // sport_id (WHOOP: null for unrecognized activity types)
        Some(record.score_state.clone()),             // score_state
        strain,                                       // strain
        avg_hr,                                       // average_heart_rate
        max_hr,                                       // max_heart_rate
        kilojoule,                                    // kilojoule
        percent,                                      // percent_recorded
        distance,                                     // distance_meter
        alt_gain,                                     // altitude_gain_meter
        alt_change,                                   // altitude_change_meter
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_map_sleep_all_fields_present() {
        let json = r#"{
            "id": "sleep-123",
            "start": "2026-07-10T22:30:00Z",
            "end": "2026-07-11T07:30:00Z",
            "timezone_offset": "+02:00",
            "nap": false,
            "updated_at": "2026-07-11T08:00:00Z",
            "score_state": "SCORED",
            "score": {
                "stage_summary": {
                    "total_in_bed_time_milli": 32400000,
                    "total_awake_time_milli": 1800000,
                    "total_no_data_time_milli": 0,
                    "total_light_sleep_time_milli": 10800000,
                    "total_slow_wave_sleep_time_milli": 7200000,
                    "total_rem_sleep_time_milli": 12600000,
                    "sleep_cycle_count": 5,
                    "disturbance_count": 3
                },
                "respiratory_rate": 15.5,
                "sleep_performance_percentage": 90.0,
                "sleep_consistency_percentage": 85.0,
                "sleep_efficiency_percentage": 88.0
            }
        }"#;

        let record: SleepRecord = serde_json::from_str(json).unwrap();
        let synced = DateTime::parse_from_rfc3339("2026-07-11T08:15:00Z").unwrap().with_timezone(&Utc);
        let row = map_sleep(&record, synced);

        assert_eq!(row[0], Some("whoop".to_string()));
        assert_eq!(row[1], Some("sleep-123".to_string()));
        assert_eq!(row[6], Some("1".to_string())); // schema_version
        // nap metric
        assert_eq!(row[7], Some("false".to_string()));
        // score_state metric
        assert_eq!(row[8], Some("SCORED".to_string()));
        // Check some stage summary metrics are present
        assert!(row[9].is_some()); // total_in_bed_time_milli
        assert_eq!(row[9], Some("32400000".to_string()));
    }

    #[test]
    fn test_map_sleep_missing_score_fields_are_none() {
        let json = r#"{
            "id": "sleep-456",
            "start": "2026-07-10T22:00:00Z",
            "end": "2026-07-11T06:00:00Z",
            "nap": false,
            "updated_at": "2026-07-11T07:00:00Z",
            "score_state": "PENDING_SCORE"
        }"#;

        let record: SleepRecord = serde_json::from_str(json).unwrap();
        let synced = DateTime::parse_from_rfc3339("2026-07-11T08:00:00Z").unwrap().with_timezone(&Utc);
        let row = map_sleep(&record, synced);

        // score_state is set
        assert_eq!(row[8], Some("PENDING_SCORE".to_string()));
        // But stage summary fields should be None
        assert_eq!(row[9], None); // total_in_bed_time_milli
        // respiratory_rate and other score fields should be None
        assert_eq!(row[16], None); // respiratory_rate
    }

    #[test]
    fn test_map_recovery_uses_cycle_id_as_external_id() {
        // cycle_id is a JSON number on the wire (confirmed manual e2e, T-401).
        let json = r#"{
            "cycle_id": 789,
            "sleep_id": "sleep-456",
            "created_at": "2026-07-11T07:00:00Z",
            "updated_at": "2026-07-11T08:00:00Z",
            "score_state": "SCORED",
            "score": {
                "recovery_score": 75.0,
                "resting_heart_rate": 62.0
            }
        }"#;

        let record: RecoveryRecord = serde_json::from_str(json).unwrap();
        let synced = DateTime::parse_from_rfc3339("2026-07-11T09:00:00Z").unwrap().with_timezone(&Utc);
        let row = map_recovery(&record, synced);

        // external_id should be cycle_id (converted to string), not some other id
        assert_eq!(row[1], Some("789".to_string()));
        // recorded_at should use created_at when present
        assert_eq!(row[2], Some("2026-07-11T07:00:00Z".to_string()));
        // Check that sleep_id appears in metric columns
        assert_eq!(row[7], Some("sleep-456".to_string())); // sleep_id metric
    }

    #[test]
    fn test_sleep_schema_column_order_matches_spec() {
        let schema = sleep_schema();
        let cols = schema.columns();
        // Mandatory columns (7) + metric columns (14) = 21 total
        assert_eq!(cols.len(), 21);
        // Verify metric column order per spec
        let metric_start = 7;
        assert_eq!(cols[metric_start], "nap");
        assert_eq!(cols[metric_start + 1], "score_state");
        assert_eq!(cols[metric_start + 2], "total_in_bed_time_milli");
        assert_eq!(cols[metric_start + 13], "sleep_efficiency_percentage");
    }

    #[test]
    fn test_recovery_schema_column_order_matches_spec() {
        let schema = recovery_schema();
        let cols = schema.columns();
        // Mandatory columns (7) + metric columns (8) = 15 total
        assert_eq!(cols.len(), 15);
        let metric_start = 7;
        assert_eq!(cols[metric_start], "sleep_id");
        assert_eq!(cols[metric_start + 1], "score_state");
        assert_eq!(cols[metric_start + 7], "skin_temp_celsius");
    }

    #[test]
    fn test_cycle_schema_column_order_matches_spec() {
        let schema = cycle_schema();
        let cols = schema.columns();
        // Mandatory columns (7) + metric columns (5) = 12 total
        assert_eq!(cols.len(), 12);
        let metric_start = 7;
        assert_eq!(cols[metric_start], "score_state");
        assert_eq!(cols[metric_start + 1], "strain");
        assert_eq!(cols[metric_start + 4], "max_heart_rate");
    }

    #[test]
    fn test_workout_schema_column_order_matches_spec() {
        let schema = workout_schema();
        let cols = schema.columns();
        // Mandatory columns (7) + metric columns (10) = 17 total
        assert_eq!(cols.len(), 17);
        let metric_start = 7;
        assert_eq!(cols[metric_start], "sport_id");
        assert_eq!(cols[metric_start + 1], "score_state");
        assert_eq!(cols[metric_start + 9], "altitude_change_meter");
    }

    /// T-409: WHOOP sends `sport_id: null` for some (older/unrecognized)
    /// workouts — map_workout must degrade to an empty CSV cell, not panic
    /// or silently coerce to a wrong number.
    #[test]
    fn test_map_workout_with_null_sport_id_produces_empty_column_not_panic() {
        let record = WorkoutRecord {
            id: "wkt_1".to_string(),
            start: "2025-11-01T10:00:00Z".to_string(),
            end: "2025-11-01T11:00:00Z".to_string(),
            timezone_offset: Some("+00:00".to_string()),
            sport_id: None,
            updated_at: "2025-11-01T11:05:00Z".to_string(),
            score_state: "SCORED".to_string(),
            score: None,
        };
        let row = map_workout(&record, Utc::now());
        let cols = workout_schema().columns();
        let sport_id_idx = cols.iter().position(|c| c == "sport_id").unwrap();
        assert_eq!(row[sport_id_idx], None);
    }
}
