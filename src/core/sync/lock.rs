//! Sync lock registry — per-connection mutual-exclusion for sync operations (T-602).
//!
//! Mirrors `RefreshCoordinator`'s mutex-per-key pattern to serialize concurrent
//! sync calls for the same (provider, connection_id) pair. T-602: "параллельный
//! вызов sync для одного провайдера исключён (аналогично refresh mutex)".

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Per-connection mutual-exclusion registry for sync operations.
///
/// Maintains per-connection locks to ensure that concurrent sync calls for the
/// same (provider, connection_id) are serialized — only one sync is in flight
/// for a given connection at any time.
pub struct SyncLockRegistry {
    /// Map from connection key to per-connection lock.
    ///
    /// Arc<Mutex<()>> allows:
    /// - Multiple sync callers (via Arc)
    /// - Mutex to serialize concurrent calls
    locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl SyncLockRegistry {
    /// Create a new sync lock registry.
    pub fn new() -> Self {
        SyncLockRegistry {
            locks: Mutex::new(HashMap::new()),
        }
    }

    /// Retrieve or create the per-connection lock.
    ///
    /// Given a key (e.g., "whoop:conn_123"), returns an Arc to the per-connection
    /// lock. Multiple calls with the same key return the SAME lock instance,
    /// allowing serialization of concurrent sync operations.
    pub fn lock_for(&self, key: &str) -> Arc<Mutex<()>> {
        let mut map = self.locks.lock().expect("lock registry mutex poisoned");
        map.entry(key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
}

impl Default for SyncLockRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_for_same_key_returns_same_arc() {
        let registry = SyncLockRegistry::new();
        let lock1 = registry.lock_for("whoop:conn_123");
        let lock2 = registry.lock_for("whoop:conn_123");

        // Both should point to the same Arc — check via pointer equality
        assert!(Arc::ptr_eq(&lock1, &lock2));
    }

    #[test]
    fn test_lock_for_different_keys_returns_different_arcs() {
        let registry = SyncLockRegistry::new();
        let lock1 = registry.lock_for("whoop:conn_123");
        let lock2 = registry.lock_for("whoop:conn_456");

        // Different keys should yield different Arcs
        assert!(!Arc::ptr_eq(&lock1, &lock2));
    }
}
