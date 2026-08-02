//! WHOOP connector — wearable health data sync from WHOOP API v2.
//!
//! Components:
//! - `dto` — WHOOP API v2 response types
//! - `mapping` — DTO → CSV row mapping per csv-contract.md
//! - `client` — HTTP client for WHOOP API with rate limiting
//! - `connect` — OAuth connection flow (T-401 Step 4)
//! - `sync` — Sync orchestration (T-401 Step 5)

pub mod client;
pub mod connect;
pub mod dto;
pub mod mapping;
pub mod sync;

#[cfg(test)]
mod tests {
    /// AC1/AC3 guard: WHOOP-specific constants (base URL, scopes) must not
    /// leak outside of core/connectors/whoop/. If this test catches
    /// "api.prod.whoop.com" in core/csv or core/oauth — the provider-agnostic
    /// boundary is violated.
    #[test]
    fn test_whoop_constants_do_not_leak_into_provider_agnostic_core() {
        let forbidden = [
            "api.prod.whoop.com",
            "read:cycles",
            "read:sleep",
            "read:recovery",
            "read:workout",
        ];

        let core_agnostic_dirs = [
            "src/core/csv",
            "src/core/oauth",
            "src/core/sync",
        ];

        let manifest_dir = env!("CARGO_MANIFEST_DIR");

        fn scan_dir(path: &std::path::Path, forbidden: &[&str]) -> Vec<(std::path::PathBuf, String)> {
            let mut violations = Vec::new();

            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();

                    if path.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            for needle in forbidden {
                                if content.contains(needle) {
                                    violations.push((path.clone(), needle.to_string()));
                                }
                            }
                        }
                    } else if path.is_dir() {
                        violations.extend(scan_dir(&path, forbidden));
                    }
                }
            }

            violations
        }

        for dir in core_agnostic_dirs {
            let dir_path = std::path::Path::new(manifest_dir).join(dir);
            let violations = scan_dir(&dir_path, &forbidden);

            if !violations.is_empty() {
                let (file, needle) = &violations[0];
                panic!(
                    "WHOOP constant '{}' found in {}: provider-agnostic boundary violated",
                    needle,
                    file.display()
                );
            }
        }
    }
}
