//! Structural checks over the source tree.
//!
//! Each of these encodes a defect *class* that has already shipped once and was
//! caught only by a human remembering to look. Reviewers forget; this does not.

use std::fs;
use std::path::{Path, PathBuf};

fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).expect("readable dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            out.extend(rust_files(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out.sort();
    out
}

fn production_source(text: &str) -> &str {
    // Ignore in-file unit tests; they are allowed to do anything.
    match text.find("#[cfg(test)]") {
        Some(i) => &text[..i],
        None => text,
    }
}

/// Every multi-row read in the PostgreSQL layer must be bounded in SQL.
///
/// `read_entity` once loaded an entity's entire history per request and paged
/// it in Rust; the handler's `limit` bounded the response, not the query. A
/// `fetch_all` whose preceding query has no `LIMIT` is that bug waiting to
/// recur. Queries that are bounded by construction are listed explicitly with
/// the reason, so an exemption is a reviewed decision rather than an oversight.
#[test]
fn every_postgres_fetch_all_is_bounded_by_a_limit() {
    // (file suffix, fn name) -> why an unbounded fetch is acceptable here.
    let exemptions: &[(&str, &str, &str)] = &[
        (
            "sequencer.rs",
            "fetch_existing_event_ids_tx",
            "bound by the ingest batch, itself capped at MAX_EVENTS_PER_BATCH",
        ),
        (
            "event_store.rs",
            "read_range",
            "span rejected above MAX_READ_RANGE_SPAN before the query runs",
        ),
        (
            "ves_sequencer.rs",
            "read_range",
            "span rejected above MAX_READ_RANGE_SPAN before the query runs",
        ),
        (
            "event_store.rs",
            "read_by_type",
            "span rejected above MAX_READ_RANGE_SPAN before the query runs",
        ),
        (
            "event_store.rs",
            "get_payload_hashes",
            "reads one commitment's leaves; commitment size is bounded at creation",
        ),
        (
            "event_store.rs",
            "get_leaf_inputs",
            "reads one commitment's leaves; commitment size is bounded at creation",
        ),
    ];

    let mut violations = Vec::new();
    for path in rust_files(Path::new("src/infra/postgres")) {
        let text = fs::read_to_string(&path).expect("readable source");
        let src = production_source(&text);
        let lines: Vec<&str> = src.lines().collect();
        let file = path.file_name().unwrap().to_string_lossy().to_string();

        for (i, line) in lines.iter().enumerate() {
            if !line.contains(".fetch_all(") {
                continue;
            }
            // Walk back to the start of the query literal and check it.
            let start = i.saturating_sub(60);
            let block = lines[start..i].join("\n");
            let Some(q) = block.rfind("r#\"") else {
                continue;
            };
            let sql = &block[q..];
            if sql.to_ascii_uppercase().contains("LIMIT") {
                continue;
            }
            // Enclosing fn name.
            let fn_name = lines[..i]
                .iter()
                .rev()
                .find_map(|l| {
                    let t = l.trim_start();
                    let t = t.strip_prefix("pub ").unwrap_or(t);
                    let t = t.strip_prefix("pub(crate) ").unwrap_or(t);
                    let t = t.strip_prefix("async ").unwrap_or(t);
                    t.strip_prefix("fn ")
                        .map(|r| r.split(['(', '<']).next().unwrap_or("").to_string())
                })
                .unwrap_or_default();
            let exempt = exemptions
                .iter()
                .any(|(f, name, _)| file.ends_with(f) && *name == fn_name);
            if !exempt {
                violations.push(format!("{}:{} in fn {fn_name}", path.display(), i + 1));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "fetch_all without a LIMIT in the preceding query (add LIMIT, or add a \
         reviewed exemption with a reason):\n  {}",
        violations.join("\n  ")
    );
}

/// Production code must not panic on `unwrap`/`expect`.
///
/// The crate already enforces this via `#![deny(clippy::unwrap_used,
/// clippy::expect_used)]`; this test exists so the rule is visible from the
/// test suite too and fails loudly if the lint attribute is ever removed.
#[test]
fn lib_denies_unwrap_and_expect_in_production_code() {
    let lib = fs::read_to_string("src/lib.rs").expect("src/lib.rs");
    assert!(
        lib.contains("clippy::unwrap_used") && lib.contains("clippy::expect_used"),
        "src/lib.rs must deny clippy::unwrap_used and clippy::expect_used"
    );
}
