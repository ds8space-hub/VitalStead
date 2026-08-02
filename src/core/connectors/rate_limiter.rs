//! Rate limiter using backoff sleeper DI seam — ADR-019.
//!
//! `PacedThrottle` enforces a minimum interval between API calls (max_requests per window).
//! Uses the same `BackoffSleeper` trait from `core::oauth::refresh` for testability seam
//! (per ADR-019, do not duplicate trait, reuse BackoffSleeper).

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::core::oauth::refresh::BackoffSleeper;

/// Rate limiter that enforces a minimum interval between calls.
///
/// Given `max_requests` per `window` duration, calculates `min_interval = window / max_requests`
/// and ensures at least `min_interval` has elapsed between consecutive `throttle()` calls.
/// The first call does not sleep.
///
/// Uses `BackoffSleeper` (ADR-019) as the DI seam for testability — allows tests to
/// inject mock sleepers that record sleep durations without actually blocking.
pub struct PacedThrottle {
    /// Minimum duration between calls, calculated as window / max_requests.
    min_interval: Duration,
    /// Timestamp of the last throttle() call, guarded by mutex for interior mutability.
    last_request_at: Mutex<Option<Instant>>,
}

impl PacedThrottle {
    /// Create a new rate limiter with the given max requests per window.
    ///
    /// # Panics
    /// Panics if `max_requests == 0` (division by zero).
    pub fn new(max_requests: u32, window: Duration) -> Self {
        if max_requests == 0 {
            panic!("max_requests must be > 0");
        }
        let min_interval = window / max_requests;
        PacedThrottle {
            min_interval,
            last_request_at: Mutex::new(None),
        }
    }

    /// Enforce the minimum interval before the next call.
    ///
    /// If this is the first call, does not sleep.
    /// If time since last call is < min_interval, sleeps for the remainder.
    /// Always updates last_request_at to Instant::now() after sleeping.
    pub fn throttle(&self, sleeper: &dyn BackoffSleeper) {
        let now = Instant::now();
        let mut last = self.last_request_at.lock().unwrap();

        if let Some(prev) = *last {
            let elapsed = now.saturating_duration_since(prev);
            if elapsed < self.min_interval {
                let sleep_duration = self.min_interval - elapsed;
                drop(last); // Release lock before sleeping
                sleeper.sleep(sleep_duration);
                // Re-acquire lock for update
                let mut last = self.last_request_at.lock().unwrap();
                *last = Some(Instant::now());
            } else {
                *last = Some(now);
            }
        } else {
            *last = Some(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock sleeper that records sleep durations for assertion.
    struct RecordingSleeper {
        /// Accumulated sleep duration for all sleep() calls.
        total_slept: Mutex<Duration>,
    }

    impl RecordingSleeper {
        fn new() -> Self {
            RecordingSleeper {
                total_slept: Mutex::new(Duration::ZERO),
            }
        }

        fn total_slept(&self) -> Duration {
            *self.total_slept.lock().unwrap()
        }
    }

    impl BackoffSleeper for RecordingSleeper {
        fn sleep(&self, duration: Duration) {
            *self.total_slept.lock().unwrap() += duration;
        }
    }

    #[test]
    fn test_throttle_no_sleep_on_first_call() {
        let throttle = PacedThrottle::new(10, Duration::from_millis(100));
        let sleeper = RecordingSleeper::new();

        throttle.throttle(&sleeper);

        assert_eq!(sleeper.total_slept(), Duration::ZERO);
    }

    #[test]
    fn test_throttle_sleeps_min_interval_between_calls() {
        let throttle = PacedThrottle::new(10, Duration::from_millis(100));
        // min_interval = 100ms / 10 = 10ms
        let sleeper = RecordingSleeper::new();

        throttle.throttle(&sleeper); // First call, no sleep

        // Simulate immediate second call (no real time passed)
        throttle.throttle(&sleeper);

        // Should have slept for approximately min_interval (10ms)
        // Allow some wiggle room due to timing precision
        let slept = sleeper.total_slept();
        assert!(
            slept >= Duration::from_millis(9),
            "Expected sleep >= 9ms, got {:?}",
            slept
        );
    }

    #[test]
    fn test_throttle_no_sleep_if_elapsed_exceeds_interval() {
        let throttle = PacedThrottle::new(10, Duration::from_millis(100));
        // min_interval = 100ms / 10 = 10ms
        let sleeper = RecordingSleeper::new();

        throttle.throttle(&sleeper); // First call, no sleep

        // Sleep for longer than min_interval in real time
        std::thread::sleep(Duration::from_millis(20));

        // Now throttle again; elapsed time exceeds min_interval
        throttle.throttle(&sleeper);

        // Should not have slept the second time
        assert_eq!(sleeper.total_slept(), Duration::ZERO);
    }

    #[test]
    #[should_panic(expected = "max_requests must be > 0")]
    fn test_throttle_panics_on_zero_max_requests() {
        let _throttle = PacedThrottle::new(0, Duration::from_secs(1));
    }
}
