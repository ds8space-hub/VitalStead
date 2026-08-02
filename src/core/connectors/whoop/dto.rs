//! WHOOP API v2 DTO types (Data Transfer Objects).
//!
//! Contract source: Step 2 spec — defines request/response structures for WHOOP API v2.
//! Each response is wrapped in a `WhoopPage<T>` envelope with pagination token.

use serde::Deserialize;

/// Generic envelope for paginated WHOOP API v2 responses.
///
/// All WHOOP paginated responses follow the shape:
/// `{ "records": [...], "next_token": "..." }`
#[derive(Debug, Deserialize)]
pub struct WhoopPage<T> {
    /// Array of records (sleep, recovery, cycle, workout, etc.)
    pub records: Vec<T>,
    /// Pagination token for fetching the next page (or None for last page).
    pub next_token: Option<String>,
}

/// Sleep record from WHOOP API v2.
#[derive(Debug, Deserialize, Default)]
pub struct SleepRecord {
    pub id: String,
    pub start: String, // RFC3339
    pub end: String,
    #[serde(default)]
    pub timezone_offset: Option<String>,
    #[serde(default)]
    pub nap: bool,
    pub updated_at: String,
    pub score_state: String,
    #[serde(default)]
    pub score: Option<SleepScore>,
}

/// Sleep score details.
#[derive(Debug, Deserialize, Default)]
pub struct SleepScore {
    #[serde(default)]
    pub stage_summary: Option<SleepStageSummary>,
    #[serde(default)]
    pub respiratory_rate: Option<f64>,
    #[serde(default)]
    pub sleep_performance_percentage: Option<f64>,
    #[serde(default)]
    pub sleep_consistency_percentage: Option<f64>,
    #[serde(default)]
    pub sleep_efficiency_percentage: Option<f64>,
}

/// Sleep stage breakdown.
#[derive(Debug, Deserialize, Default)]
pub struct SleepStageSummary {
    #[serde(default)]
    pub total_in_bed_time_milli: Option<u64>,
    #[serde(default)]
    pub total_awake_time_milli: Option<u64>,
    #[serde(default)]
    pub total_no_data_time_milli: Option<u64>,
    #[serde(default)]
    pub total_light_sleep_time_milli: Option<u64>,
    #[serde(default)]
    pub total_slow_wave_sleep_time_milli: Option<u64>,
    #[serde(default)]
    pub total_rem_sleep_time_milli: Option<u64>,
    #[serde(default)]
    pub sleep_cycle_count: Option<u32>,
    #[serde(default)]
    pub disturbance_count: Option<u32>,
}

/// Recovery record from WHOOP API v2.
#[derive(Debug, Deserialize, Default)]
pub struct RecoveryRecord {
    // ASSUMPTION corrected on manual e2e (T-401): real WHOOP API returns
    // cycle_id as a JSON number, not a string. Converted to String at the
    // mapping.rs boundary (external_id column is always textual).
    pub cycle_id: i64,
    #[serde(default)]
    pub sleep_id: Option<String>,
    // Found on manual e2e: real API includes created_at (not anticipated by
    // the original spec's ASSUMPTION) — used as recorded_at in mapping.rs,
    // more semantically correct than the previous updated_at fallback.
    #[serde(default)]
    pub created_at: Option<String>,
    pub updated_at: String,
    pub score_state: String,
    #[serde(default)]
    pub score: Option<RecoveryScore>,
}

/// Recovery score details.
#[derive(Debug, Deserialize, Default)]
pub struct RecoveryScore {
    #[serde(default)]
    pub user_calibrating: Option<bool>,
    #[serde(default)]
    pub recovery_score: Option<f64>,
    #[serde(default)]
    pub resting_heart_rate: Option<f64>,
    #[serde(default)]
    pub hrv_rmssd_milli: Option<f64>,
    #[serde(default)]
    pub spo2_percentage: Option<f64>,
    #[serde(default)]
    pub skin_temp_celsius: Option<f64>,
}

/// Cycle record from WHOOP API v2.
#[derive(Debug, Deserialize, Default)]
pub struct CycleRecord {
    // ASSUMPTION corrected on manual e2e (T-401): id is a JSON number on the
    // wire, not a string. Converted to String at the mapping.rs boundary.
    pub id: i64,
    pub start: String,
    // ASSUMPTION corrected on manual e2e: `end` is `null` for the current,
    // still-ongoing cycle (not yet completed) — must be optional.
    #[serde(default)]
    pub end: Option<String>,
    #[serde(default)]
    pub timezone_offset: Option<String>,
    pub updated_at: String,
    pub score_state: String,
    #[serde(default)]
    pub score: Option<CycleScore>,
}

/// Cycle (training) score details.
#[derive(Debug, Deserialize, Default)]
pub struct CycleScore {
    #[serde(default)]
    pub strain: Option<f64>,
    #[serde(default)]
    pub kilojoule: Option<f64>,
    #[serde(default)]
    pub average_heart_rate: Option<f64>,
    #[serde(default)]
    pub max_heart_rate: Option<f64>,
}

/// Workout record from WHOOP API v2.
#[derive(Debug, Deserialize, Default)]
pub struct WorkoutRecord {
    pub id: String,
    pub start: String,
    pub end: String,
    #[serde(default)]
    pub timezone_offset: Option<String>,
    // T-409: found on real e2e with ~9 months of history — WHOOP returns
    // `sport_id: null` for some workouts (activity types outside their
    // recognized catalog); a non-optional i64 made the whole page fail to
    // parse (`sync.fetch_failed`) the moment one such workout appeared,
    // which only showed up past a few months of history.
    #[serde(default)]
    pub sport_id: Option<i64>,
    pub updated_at: String,
    pub score_state: String,
    #[serde(default)]
    pub score: Option<WorkoutScore>,
}

/// Workout score details.
#[derive(Debug, Deserialize, Default)]
pub struct WorkoutScore {
    #[serde(default)]
    pub strain: Option<f64>,
    #[serde(default)]
    pub average_heart_rate: Option<f64>,
    #[serde(default)]
    pub max_heart_rate: Option<f64>,
    #[serde(default)]
    pub kilojoule: Option<f64>,
    #[serde(default)]
    pub percent_recorded: Option<f64>,
    #[serde(default)]
    pub distance_meter: Option<f64>,
    #[serde(default)]
    pub altitude_gain_meter: Option<f64>,
    #[serde(default)]
    pub altitude_change_meter: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T-409: real WHOOP API response for an older workout — `sport_id: null`
    /// (unrecognized/custom activity type). Before this field was made
    /// `Option<i64>`, deserializing this exact shape failed the whole page
    /// (`invalid type: null, expected i64`), which surfaced only once a
    /// user's sync window reached far enough into their history to include
    /// such a workout.
    #[test]
    fn test_workout_record_deserializes_with_null_sport_id() {
        let json = r#"{
            "id": "wkt_1",
            "start": "2025-11-01T10:00:00Z",
            "end": "2025-11-01T11:00:00Z",
            "timezone_offset": "+00:00",
            "sport_id": null,
            "updated_at": "2025-11-01T11:05:00Z",
            "score_state": "SCORED",
            "score": null
        }"#;
        let record: WorkoutRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.sport_id, None);
    }

    #[test]
    fn test_workout_record_deserializes_with_present_sport_id() {
        let json = r#"{
            "id": "wkt_2",
            "start": "2026-07-20T10:00:00Z",
            "end": "2026-07-20T11:00:00Z",
            "timezone_offset": "+00:00",
            "sport_id": 1,
            "updated_at": "2026-07-20T11:05:00Z",
            "score_state": "SCORED",
            "score": null
        }"#;
        let record: WorkoutRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.sport_id, Some(1));
    }
}
