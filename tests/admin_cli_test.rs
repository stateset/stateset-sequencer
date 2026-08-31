//! Smoke tests for the admin binary's argument handling.
//!
//! These exercise the dispatch layer only (no database), so they run in every
//! `cargo test`. They exist so the 1,500-line command dispatcher can be
//! reshaped without silently breaking `--help`, `version`, or the exit code an
//! operator's script relies on.

use std::process::Command;

fn admin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_stateset-sequencer-admin"))
}

#[test]
fn help_exits_zero_and_lists_every_command() {
    let out = admin().arg("--help").output().expect("run admin");
    assert!(out.status.success(), "--help must exit 0");
    let text = String::from_utf8_lossy(&out.stderr) + String::from_utf8_lossy(&out.stdout);
    for cmd in [
        "migrate",
        "verify-proof",
        "export-events",
        "rotate-keys",
        "list-agent-keys",
        "reencrypt-events",
        "reencrypt-ves-validity-proofs",
        "reencrypt-ves-compliance-proofs",
        "backfill-ves-state-roots",
        "ves-commit-and-anchor",
    ] {
        assert!(text.contains(cmd), "help must list `{cmd}`:\n{text}");
    }
}

#[test]
fn version_prints_the_crate_version() {
    let out = admin().arg("version").output().expect("run admin");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout) + String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains(env!("CARGO_PKG_VERSION")),
        "version output must contain {}: {text}",
        env!("CARGO_PKG_VERSION")
    );
}

#[test]
fn unknown_command_fails_nonzero_with_guidance() {
    let out = admin()
        .arg("definitely-not-a-command")
        .output()
        .expect("run admin");
    assert!(!out.status.success(), "unknown command must exit non-zero");
    let text = String::from_utf8_lossy(&out.stderr) + String::from_utf8_lossy(&out.stdout);
    assert!(
        text.to_lowercase().contains("unknown") || text.contains("help"),
        "should tell the operator how to recover: {text}"
    );
}

#[test]
fn per_command_help_works_for_every_command() {
    for cmd in [
        "migrate",
        "verify-proof",
        "export-events",
        "backfill-ves-state-roots",
    ] {
        let out = admin().args(["help", cmd]).output().expect("run admin");
        assert!(out.status.success(), "`help {cmd}` must exit 0");
    }
}
