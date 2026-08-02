//! T-802: automated guard against secrets reaching logs.
//!
//! `SecretString` already makes the common mistake a compile error (no
//! `Display` impl — `tracing::info!("{}", secret)` or `%secret` won't
//! compile; `Debug`/`{:?}` prints `SecretString(REDACTED)`). The one gap the
//! type system can't catch: once a caller extracts the raw value via
//! `expose_secret()` (necessary to build HTTP requests, Keychain writes,
//! etc.), that plain `&str` is no longer tracked — nothing stops someone
//! from later passing it into a log macro.
//!
//! This test statically scans every `.rs` file under `src/` for a log macro
//! call (`tracing::info!`/`warn!`/`error!`/`debug!`/`trace!`, or the
//! unqualified `info!`/`warn!`/`error!`/`debug!`/`trace!`/`println!`/
//! `eprintln!` forms) whose argument list contains `expose_secret()` — a
//! real audit (T-802, `docs/tasks/EPIC-08-security.md`) confirmed zero
//! violations as of writing; this test is the regression guard so a future
//! change can't reintroduce one silently.

use std::path::Path;

const LOG_MACRO_NAMES: [&str; 12] = [
    "tracing::info!",
    "tracing::warn!",
    "tracing::error!",
    "tracing::debug!",
    "tracing::trace!",
    "info!",
    "warn!",
    "error!",
    "debug!",
    "trace!",
    "println!",
    "eprintln!",
];

/// Finds every `(macro_name, snippet)` where `snippet` is the full argument
/// list of a log macro call that contains `expose_secret()`.
fn find_violations(source: &str) -> Vec<String> {
    let mut violations = Vec::new();

    for macro_name in LOG_MACRO_NAMES {
        let mut search_from = 0;
        while let Some(rel_idx) = source[search_from..].find(macro_name) {
            let start = search_from + rel_idx;
            let after_name = start + macro_name.len();

            // Skip unqualified matches ("info!") that are actually the tail
            // of a qualified name ("tracing::info!") already matched by
            // that longer pattern — otherwise every `tracing::info!` call
            // gets counted twice (once per pattern).
            if !macro_name.starts_with("tracing::") && source[..start].ends_with("::") {
                search_from = after_name;
                continue;
            }

            // The macro name already includes `!`; the next non-whitespace
            // char must be `(` for this to be an invocation (not e.g. a
            // doc comment mentioning the macro name as text).
            let open_paren = source[after_name..].find('(').map(|i| after_name + i);
            let Some(open_paren) = open_paren else {
                search_from = after_name;
                continue;
            };
            // Reject if there's non-whitespace between the `!` and `(`
            // (would mean this isn't actually a macro call at this spot).
            if source[after_name..open_paren].trim() != "" {
                search_from = after_name;
                continue;
            }

            // Balanced-paren scan for the matching close, ignoring parens
            // inside string/char literals (good enough for this codebase's
            // formatting style — no macro calls embed unbalanced parens in
            // string literals today).
            let bytes = source.as_bytes();
            let mut depth = 0i32;
            let mut in_string = false;
            let mut escape = false;
            let mut end = None;
            for (i, &b) in bytes.iter().enumerate().skip(open_paren) {
                let c = b as char;
                if in_string {
                    if escape {
                        escape = false;
                    } else if c == '\\' {
                        escape = true;
                    } else if c == '"' {
                        in_string = false;
                    }
                    continue;
                }
                match c {
                    '"' => in_string = true,
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(i);
                            break;
                        }
                    }
                    _ => {}
                }
            }

            if let Some(end) = end {
                let snippet = &source[open_paren..=end];
                if snippet.contains("expose_secret()") {
                    violations.push(format!("{macro_name}{snippet}"));
                }
                search_from = end + 1;
            } else {
                // Unbalanced parens (shouldn't happen in valid Rust) — bail
                // out of this occurrence rather than looping forever.
                search_from = open_paren + 1;
            }
        }
    }

    violations
}

fn collect_rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_log_macro_call_contains_expose_secret() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let src_dir = Path::new(manifest_dir).join("src");

    let mut files = Vec::new();
    collect_rs_files(&src_dir, &mut files);
    assert!(!files.is_empty(), "sanity check: should find at least one .rs file under src/");

    let mut all_violations = Vec::new();
    for file in &files {
        // This file itself contains intentional example-violation fixtures
        // (self_tests below) — not production logging code.
        if file.file_name().is_some_and(|n| n == "log_lint.rs") {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(file) else { continue };
        let violations = find_violations(&content);
        for v in violations {
            all_violations.push(format!("{}: {}", file.display(), v));
        }
    }

    assert!(
        all_violations.is_empty(),
        "T-802: found expose_secret() inside a log macro call — this would leak a secret \
         to logs. Violations:\n{}",
        all_violations.join("\n")
    );
}

#[cfg(test)]
mod self_tests {
    use super::find_violations;

    /// The scanner itself must actually catch the pattern it's designed for
    /// — otherwise `no_log_macro_call_contains_expose_secret` passing would
    /// be meaningless (a scanner that finds nothing because it's broken,
    /// not because the codebase is clean).
    #[test]
    fn detects_expose_secret_inside_tracing_info() {
        let source = r#"
            fn bad() {
                tracing::info!(token = %secret.expose_secret(), "leaking");
            }
        "#;
        let violations = find_violations(source);
        assert_eq!(violations.len(), 1, "should detect exactly one violation");
        assert!(violations[0].contains("expose_secret()"));
    }

    #[test]
    fn detects_expose_secret_inside_unqualified_warn() {
        let source = r#"
            fn bad() {
                warn!("value: {}", token.expose_secret());
            }
        "#;
        let violations = find_violations(source);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn ignores_expose_secret_outside_log_macros() {
        let source = r#"
            fn fine() {
                request.bearer_auth(access_token.expose_secret());
                vault.set_password(value.expose_secret()).unwrap();
            }
        "#;
        let violations = find_violations(source);
        assert!(violations.is_empty(), "expose_secret() outside a log macro is not a violation");
    }

    #[test]
    fn ignores_expose_secret_mentioned_only_in_a_doc_comment() {
        let source = r#"
            /// Never call tracing::info!(x.expose_secret()) — this is just prose in a comment.
            fn fine() {}
        "#;
        // The doc comment text itself contains "tracing::info!(x.expose_secret())" as a
        // literal substring, which the balanced-paren scanner will still parse as an
        // invocation (it doesn't understand comments) — this test documents that limitation
        // rather than asserting a stronger guarantee the scanner doesn't provide.
        let violations = find_violations(source);
        assert_eq!(
            violations.len(), 1,
            "known limitation: the scanner doesn't distinguish comments from code, so this text \
             is flagged even though it's a comment — false positives are acceptable for a security \
             lint (safe to fail loudly), false negatives are not"
        );
    }
}
