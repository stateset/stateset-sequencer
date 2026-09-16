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

/// STARK crates must be pinned git dependencies, never sibling path deps.
///
/// Cargo resolves every path dependency even when the feature enabling it is
/// off, so `ves-stark-* = { path = "../stateset-stark/..." }` once forced a
/// sibling checkout for *every* build, including `--no-default-features
/// --features pqc` on a clean checkout. Optional git dependencies are only
/// fetched when the `stark` feature enables them. The git pin must match
/// `STARK_REF` in CI so the upgrade stays deliberate and atomic.
#[test]
fn stark_deps_are_pinned_git_not_sibling_paths() {
    let manifest = fs::read_to_string("Cargo.toml").expect("Cargo.toml");
    // Only active (non-comment) manifest lines matter: prose may mention the
    // old layout, but no dependency may resolve through it.
    for line in manifest.lines() {
        let active = line.split('#').next().unwrap_or("");
        assert!(
            !(active.contains("path") && active.contains("stateset-stark")),
            "Cargo.toml must not path-depend on a stateset-stark checkout; use \
             pinned git dependencies so pqc-only builds work on a clean checkout: {line}"
        );
    }

    let ci = fs::read_to_string(".github/workflows/ci.yml").expect("ci.yml");
    let stark_ref = ci
        .lines()
        .find_map(|l| {
            let (_, v) = l.trim_start().strip_prefix("STARK_REF:")?.split_once('"')?;
            v.split('"').next()
        })
        .expect("STARK_REF pin in ci.yml");

    let mut git_pins = 0;
    for line in manifest
        .lines()
        .filter(|l| l.trim_start().starts_with("ves-stark-"))
    {
        assert!(
            line.contains("git = \"https://github.com/stateset/stateset-starks.git\""),
            "each ves-stark-* dep must come from the stateset-starks git repo: {line}"
        );
        assert!(
            line.contains(&format!("rev = \"{stark_ref}\"")),
            "each ves-stark-* dep must pin rev = STARK_REF ({stark_ref}): {line}"
        );
        git_pins += 1;
    }
    assert_eq!(git_pins, 4, "expected 4 ves-stark-* deps in Cargo.toml");

    // Path dependencies leave no `source` in the lockfile; git ones must.
    let lock = fs::read_to_string("Cargo.lock").expect("Cargo.lock");
    for name in [
        "ves-stark-verifier",
        "ves-stark-primitives",
        "ves-stark-batch",
        "ves-stark-prover",
        "ves-stark-air",
    ] {
        let entry = lock
            .split("[[package]]")
            .find(|e| e.contains(&format!("name = \"{name}\"")))
            .unwrap_or_else(|| panic!("Cargo.lock must contain {name}"));
        assert!(
            entry.contains("source = \"git+https://github.com/stateset/stateset-starks.git")
                && entry.contains(stark_ref),
            "Cargo.lock must resolve {name} from the stateset-starks git pin ({stark_ref})"
        );
    }
}
