//! API drift gate: REST routes <-> `docs/openapi.yaml` <-> proto descriptors.
//!
//! The sequencer serves the same capabilities over four surfaces that have
//! drifted apart before (routes mounted without documentation, proto RPCs
//! renamed without updating docs, legacy endpoints left unmarked):
//!
//! - REST routes (`src/api/mod.rs`, `src/api/handlers/x402.rs`,
//!   `src/server/router.rs`),
//! - `docs/openapi.yaml`,
//! - `proto/sequencer.proto` (gRPC v1, deprecated) and
//!   `proto/sequencer_v2.proto` (gRPC v2, current).
//!
//! These tests snapshot all four and fail on any divergence, so extending the
//! API is always a deliberate, all-surfaces change: update the code, the
//! OpenAPI spec, and the snapshots in this file together. They read the
//! working tree as text (like `source_invariants_test.rs`) and need no
//! database.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

// ============================================================================
// Snapshots (update together with the surface change, never alone)
// ============================================================================

/// Every served `(METHOD, path)`, with the mount prefix included (`/api` for
/// the API routers, bare for the root-mounted compat/health routes).
/// Stark-gated VES proof routes are included: they are textually present in
/// `src/api/mod.rs` and served whenever the `stark` feature is enabled.
const EXPECTED_ROUTES: &[(&str, &str)] = &[
    ("DELETE", "/api/v1/agents/:agent_id/api-keys/:key_prefix"),
    ("GET", "/admin"),
    ("GET", "/admin/"),
    ("GET", "/api/v1/admin/agents"),
    ("GET", "/api/v1/admin/overview"),
    ("GET", "/api/v1/admin/stores"),
    ("GET", "/api/v1/admin/tenants"),
    ("GET", "/api/v1/agents/:agent_id"),
    ("GET", "/api/v1/agents/:agent_id/api-keys"),
    ("GET", "/api/v1/agents/:agent_id/policy"),
    ("GET", "/api/v1/anchor/:batch_id/verify"),
    ("GET", "/api/v1/anchor/status"),
    ("GET", "/api/v1/commitments"),
    ("GET", "/api/v1/commitments/:batch_id"),
    ("GET", "/api/v1/entities/:entity_type/:entity_id"),
    ("GET", "/api/v1/events"),
    ("GET", "/api/v1/head"),
    ("GET", "/api/v1/projections/:entity_type/:entity_id"),
    ("GET", "/api/v1/proofs/:sequence_number"),
    ("GET", "/api/v1/schemas"),
    ("GET", "/api/v1/schemas/:schema_id"),
    ("GET", "/api/v1/schemas/event-type/:event_type"),
    ("GET", "/api/v1/schemas/event-type/:event_type/latest"),
    ("GET", "/api/v1/ves/anchor/:batch_id/verify"),
    ("GET", "/api/v1/ves/commitments"),
    ("GET", "/api/v1/ves/commitments/:batch_id"),
    ("GET", "/api/v1/ves/compliance/:event_id/proofs"),
    ("GET", "/api/v1/ves/compliance/proofs/:proof_id"),
    ("GET", "/api/v1/ves/compliance/proofs/:proof_id/verify"),
    ("GET", "/api/v1/ves/cursors/:agent_id"),
    ("GET", "/api/v1/ves/entities/:entity_type/:entity_id"),
    ("GET", "/api/v1/ves/events"),
    ("GET", "/api/v1/ves/head"),
    ("GET", "/api/v1/ves/proofs/:sequence_number"),
    ("GET", "/api/v1/ves/validity/:batch_id/inputs"),
    ("GET", "/api/v1/ves/validity/:batch_id/proofs"),
    ("GET", "/api/v1/ves/validity/proofs/:proof_id"),
    ("GET", "/api/v1/ves/validity/proofs/:proof_id/verify"),
    ("GET", "/api/v1/x402/batches/:batch_id"),
    ("GET", "/api/v1/x402/capabilities"),
    ("GET", "/api/v1/x402/payments"),
    ("GET", "/api/v1/x402/payments/:intent_id"),
    ("GET", "/api/v1/x402/payments/:intent_id/receipt"),
    ("GET", "/api/v1/x402/premium/insights"),
    ("GET", "/health"),
    ("GET", "/health/detailed"),
    ("GET", "/metrics"),
    ("GET", "/ready"),
    ("GET", "/v1/commitments/pending"),
    ("POST", "/v1/commitments/:batch_id/anchored"),
    ("POST", "/api/v1/agents/:agent_id/api-keys"),
    ("POST", "/api/v1/agents/keys"),
    ("POST", "/api/v1/agents/register"),
    ("POST", "/api/v1/anchor"),
    ("POST", "/api/v1/commitments"),
    ("POST", "/api/v1/events/ingest"),
    ("POST", "/api/v1/proofs/verify"),
    ("POST", "/api/v1/schemas"),
    ("POST", "/api/v1/schemas/validate"),
    ("POST", "/api/v1/ves/anchor"),
    ("POST", "/api/v1/ves/commitments"),
    ("POST", "/api/v1/ves/commitments/anchor"),
    ("POST", "/api/v1/ves/compliance/:event_id/inputs"),
    ("POST", "/api/v1/ves/compliance/:event_id/proofs"),
    ("POST", "/api/v1/ves/events/ingest"),
    ("POST", "/api/v1/ves/proofs/verify"),
    ("POST", "/api/v1/ves/validity/:batch_id/proofs"),
    ("POST", "/api/v1/x402/batches"),
    ("POST", "/api/v1/x402/batches/settle"),
    ("POST", "/api/v1/x402/payments"),
    ("PUT", "/api/v1/agents/:agent_id/policy"),
    ("PUT", "/api/v1/schemas/:schema_id/status"),
    ("PUT", "/api/v1/ves/cursors/:agent_id"),
    ("DELETE", "/api/v1/schemas/:schema_id"),
];

/// RPCs of the deprecated gRPC v1 service (`stateset.sequencer.v1.Sequencer`).
const EXPECTED_V1_RPCS: &[&str] = &[
    "GetCommitment",
    "GetEntityHistory",
    "GetHead",
    "GetInclusionProof",
    "Pull",
    "Push",
];

/// RPCs of the current gRPC v2 sequencer service
/// (`stateset.sequencer.v2.Sequencer`).
const EXPECTED_V2_RPCS: &[&str] = &[
    "GetCommitment",
    "GetEntityHistory",
    "GetHealth",
    "GetInclusionProof",
    "GetSyncState",
    "PullEvents",
    "Push",
    "StreamEvents",
    "SubscribeEntity",
    "SyncStream",
];

/// RPCs of the current gRPC v2 key-management service
/// (`stateset.sequencer.v2.KeyManagement`).
const EXPECTED_V2_KEY_RPCS: &[&str] = &["GetAgentKeys", "RegisterAgentKey", "RevokeAgentKey"];

/// Served routes intentionally absent from `docs/openapi.yaml`, each with the
/// reason. This list must shrink, never grow, without a reviewed justification.
const UNDOCUMENTED_ALLOWLIST: &[(&str, &str, &str)] = &[
    (
        "GET",
        "/admin",
        "HTML admin dashboard, not a JSON API operation",
    ),
    (
        "GET",
        "/admin/",
        "trailing-slash alias of the HTML admin dashboard",
    ),
];

/// Number of legacy operations marked `deprecated: true` in openapi.yaml.
/// Every legacy pre-VES operation must carry the marker; adding or removing a
/// legacy operation changes this count by design.
const EXPECTED_DEPRECATED_OPS: usize = 13;

// ============================================================================
// Source readers
// ============================================================================

/// A served route found in the Rust sources.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Route {
    method: String,
    path: String,
}

fn is_method_token_at(bytes: &[u8], i: usize, token: &str) -> bool {
    let t = token.as_bytes();
    if bytes.len() < i + t.len() + 1 || &bytes[i..i + t.len()] != t {
        return false;
    }
    if bytes[i + t.len()] != b'(' {
        return false;
    }
    if i > 0 {
        let prev = bytes[i - 1];
        if prev.is_ascii_alphanumeric() || prev == b'_' {
            return false;
        }
    }
    true
}

/// Text of the `.route(...)` call starting at `start`: lines up to (but not
/// including) the next `.route(` or 12 lines out, so dense single-line routes
/// cannot leak into each other while multi-line calls stay whole.
fn route_call_text(lines: &[&str], start: usize) -> String {
    let mut end = start + 1;
    while end < lines.len() && end < start + 12 {
        if lines[end].contains(".route(") {
            break;
        }
        end += 1;
    }
    lines[start..end].join("\n")
}

/// Methods bound in one `.route(...)` call.
fn methods_in_call(call: &str) -> Vec<String> {
    let mut methods = Vec::new();
    let bytes = call.as_bytes();
    for token in ["get", "post", "put", "delete", "patch"] {
        let mut i = 0;
        while i + token.len() < bytes.len() {
            if is_method_token_at(bytes, i, token) {
                let method = token.to_uppercase();
                if !methods.contains(&method) {
                    methods.push(method);
                }
                break;
            }
            i += 1;
        }
    }
    methods.sort();
    methods
}

/// Extract `(method, path)` routes from router sources.
///
/// `fn_mounts` maps a router `fn` name to `(mount prefix, path prefix)`:
/// the mount is prepended for documentation comparison (`/api` vs root) and
/// the path prefix expands nested routers (x402).
fn extract_routes(
    text: &str,
    fn_mounts: &[(&str, &str, &str)],
    default: (&str, &str),
) -> Vec<Route> {
    // In-file unit tests may mount throwaway routes; only production code counts.
    let text = text.split("#[cfg(test)]").next().unwrap_or(text);
    let lines: Vec<&str> = text.lines().collect();
    let mut routes = Vec::new();
    let mut current = default;
    let mut depth: i32 = 0;
    let mut in_tracked_fn = false;

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("pub fn ") || trimmed.starts_with("fn ") {
            let name = trimmed
                .trim_start_matches("pub fn ")
                .trim_start_matches("fn ")
                .split(['(', '<'])
                .next()
                .unwrap_or("")
                .trim();
            if let Some(mount) = fn_mounts.iter().find(|(n, _, _)| *n == name) {
                current = (mount.1, mount.2);
                in_tracked_fn = true;
            } else {
                in_tracked_fn = false;
            }
            depth = 0;
        }
        depth += line.chars().filter(|c| *c == '{').count() as i32;
        depth -= line.chars().filter(|c| *c == '}').count() as i32;

        // Files without named router fns (server/router.rs) are one implicit
        // scope; files with them only count routes inside a tracked fn.
        let in_scope = in_tracked_fn || fn_mounts.is_empty();
        if in_scope && line.contains(".route(") {
            let call = route_call_text(&lines, idx);
            if let Some(quoted) = call.split('"').nth(1) {
                let full = format!("{}{}{}", current.0, current.1, quoted);
                for method in methods_in_call(&call) {
                    routes.push(Route {
                        method: method.clone(),
                        path: full.clone(),
                    });
                }
            }
        }

        if depth <= 0 {
            in_tracked_fn = false;
            current = default;
        }
    }
    routes.sort();
    routes.dedup();
    routes
}

/// Normalize a path template so Axum `:param` and OpenAPI `{param}` spellings
/// compare equal, and trailing-slash aliases collapse.
fn normalize_path(path: &str) -> String {
    let mut out = String::new();
    for seg in path.split('/') {
        out.push('/');
        if seg.is_empty() {
            continue;
        }
        if seg.starts_with(':') || (seg.starts_with('{') && seg.ends_with('}')) {
            out.push_str("{p}");
        } else {
            out.push_str(seg);
        }
    }
    let normalized = out.replace("//", "/");
    if normalized.len() > 1 {
        normalized.trim_end_matches('/').to_string()
    } else {
        normalized
    }
}

/// Parse `(method, normalized path)` operations from the `paths:` section of
/// `docs/openapi.yaml` without a YAML dependency.
fn parse_openapi_ops(text: &str) -> BTreeSet<(String, String)> {
    let mut ops = BTreeSet::new();
    let mut in_paths = false;
    let mut current: Option<String> = None;
    for line in text.lines() {
        if line.starts_with("paths:") {
            in_paths = true;
            continue;
        }
        if in_paths && !line.starts_with(' ') && !line.is_empty() && !line.starts_with('#') {
            break;
        }
        if !in_paths {
            continue;
        }
        if line.starts_with("  /") && line.ends_with(':') {
            current = Some(normalize_path(line.trim().trim_end_matches(':')));
            continue;
        }
        if let Some(path) = &current {
            let stripped = line.strip_prefix("    ").unwrap_or("__indent__");
            for method in ["get", "post", "put", "delete", "patch", "head", "options"] {
                if stripped == format!("{method}:") {
                    ops.insert((method.to_uppercase(), path.clone()));
                }
            }
        }
    }
    ops
}

fn parse_proto_services(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut services: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current: Option<String> = None;
    let mut depth: i32 = 0;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("service ") {
            let name = trimmed
                .trim_start_matches("service ")
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_end_matches('{')
                .trim()
                .to_string();
            current = Some(name.clone());
            services.entry(name).or_default();
        }
        depth += line.chars().filter(|c| *c == '{').count() as i32;
        depth -= line.chars().filter(|c| *c == '}').count() as i32;
        if trimmed.starts_with("rpc ") {
            let name = trimmed
                .trim_start_matches("rpc ")
                .split('(')
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            if let Some(service) = &current {
                services
                    .get_mut(service)
                    .expect("service tracked")
                    .push(name);
            }
        }
        if depth <= 0 {
            current = None;
        }
    }
    for rpcs in services.values_mut() {
        rpcs.sort();
    }
    services
}

// ============================================================================
// Gates
// ============================================================================

/// The route snapshot matches the routers actually mounted in code.
#[test]
fn rest_routes_match_snapshot() {
    let api = fs::read_to_string("src/api/mod.rs").expect("readable src/api/mod.rs");
    let x402 = fs::read_to_string("src/api/handlers/x402.rs").expect("readable x402 handlers");
    let router = fs::read_to_string("src/server/router.rs").expect("readable src/server/router.rs");

    let mut actual = extract_routes(
        &api,
        &[
            ("router", "/api", ""),
            ("premium_router", "/api", ""),
            ("ves_proof_routes", "/api", ""),
            ("admin_router", "/api", ""),
            ("public_router", "/api", ""),
            ("anchor_compat_router", "", ""),
        ],
        ("/api", ""),
    );
    actual.extend(extract_routes(
        &x402,
        &[("x402_router", "/api", "/v1/x402")],
        ("", ""),
    ));
    actual.extend(extract_routes(&router, &[], ("", "")));
    actual.sort();
    actual.dedup();

    let expected: BTreeSet<(String, String)> = EXPECTED_ROUTES
        .iter()
        .map(|(m, p)| (m.to_string(), p.to_string()))
        .collect();
    let found: BTreeSet<(String, String)> = actual
        .iter()
        .map(|r| (r.method.clone(), r.path.clone()))
        .collect();

    let missing: Vec<_> = expected.difference(&found).collect();
    let extra: Vec<_> = found.difference(&expected).collect();

    assert!(
        missing.is_empty() && extra.is_empty(),
        "REST route snapshot drifted.\n  snapshot-but-unmounted (stale snapshot or dead route): {missing:?}\n  mounted-but-unsnapshotted (new route): {extra:?}\n  Update the route, docs/openapi.yaml, and EXPECTED_ROUTES together."
    );
}

/// Every served route is documented in `docs/openapi.yaml` (or explicitly
/// allowlisted), and every documented operation maps to a served route.
#[test]
fn openapi_covers_rest_routes() {
    let openapi = fs::read_to_string("docs/openapi.yaml").expect("readable docs/openapi.yaml");
    let documented = parse_openapi_ops(&openapi);

    // OpenAPI `servers` entries already provide the `/api` base URL, so paths
    // are documented without the mount prefix the router nests them under.
    let doc_path = |path: &str| normalize_path(path.strip_prefix("/api").unwrap_or(path));

    let allowlisted: BTreeSet<(String, String)> = UNDOCUMENTED_ALLOWLIST
        .iter()
        .map(|(m, p, _)| (m.to_string(), doc_path(p)))
        .collect();

    let mut undocumented = Vec::new();
    for (method, path) in EXPECTED_ROUTES {
        let key = (method.to_string(), doc_path(path));
        if !documented.contains(&key) && !allowlisted.contains(&key) {
            undocumented.push(format!("{method} {path}"));
        }
    }

    let served: BTreeSet<(String, String)> = EXPECTED_ROUTES
        .iter()
        .map(|(m, p)| (m.to_string(), doc_path(p)))
        .collect();
    let stale: Vec<_> = documented
        .difference(&served)
        .filter(|key| !allowlisted.contains(*key))
        .map(|(m, p)| format!("{m} {p}"))
        .collect();

    assert!(
        undocumented.is_empty(),
        "served routes missing from docs/openapi.yaml (document them or add a reviewed UNDOCUMENTED_ALLOWLIST entry):\n  {}",
        undocumented.join("\n  ")
    );
    assert!(
        stale.is_empty(),
        "docs/openapi.yaml documents operations with no served route (remove them or mount the route):\n  {}",
        stale.join("\n  ")
    );
}

/// The proto RPC snapshots match `proto/*.proto`, and v1 stays formally
/// deprecated while v2 stays current.
#[test]
fn proto_descriptors_match_snapshot() {
    let v1 = fs::read_to_string("proto/sequencer.proto").expect("readable v1 proto");
    let v2 = fs::read_to_string("proto/sequencer_v2.proto").expect("readable v2 proto");

    let v1_services = parse_proto_services(&v1);
    let v2_services = parse_proto_services(&v2);

    let v1_rpcs = v1_services.get("Sequencer").expect("v1 Sequencer service");
    assert_eq!(
        v1_rpcs,
        &EXPECTED_V1_RPCS
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
        "v1 RPC snapshot drifted; update the proto, docs, and EXPECTED_V1_RPCS together"
    );

    let v2_rpcs = v2_services.get("Sequencer").expect("v2 Sequencer service");
    assert_eq!(
        v2_rpcs,
        &EXPECTED_V2_RPCS
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
        "v2 Sequencer RPC snapshot drifted; update the proto, docs, and EXPECTED_V2_RPCS together"
    );

    let key_rpcs = v2_services
        .get("KeyManagement")
        .expect("v2 KeyManagement service");
    assert_eq!(
        key_rpcs,
        &EXPECTED_V2_KEY_RPCS.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        "v2 KeyManagement RPC snapshot drifted; update the proto, docs, and EXPECTED_V2_KEY_RPCS together"
    );

    assert!(
        v1.contains("option deprecated = true;"),
        "proto/sequencer.proto must keep `option deprecated = true` on the v1 service"
    );
    assert!(
        v1.contains("DEPRECATION NOTICE"),
        "proto/sequencer.proto must keep the v1 deprecation notice with the v2 migration map"
    );
    assert!(
        !v2.contains("option deprecated = true;"),
        "proto/sequencer_v2.proto is the current API and must not be marked deprecated"
    );
}

/// The formal v1 deprecation is declared on every surface: OpenAPI markers,
/// user docs, proto notice, and runtime headers/logs.
#[test]
fn v1_deprecation_is_declared_on_every_surface() {
    let openapi = fs::read_to_string("docs/openapi.yaml").expect("readable docs/openapi.yaml");
    let marked = openapi
        .lines()
        .filter(|line| line.trim() == "deprecated: true")
        .count();
    assert_eq!(
        marked, EXPECTED_DEPRECATED_OPS,
        "expected {EXPECTED_DEPRECATED_OPS} legacy operations marked `deprecated: true` in docs/openapi.yaml, found {marked}"
    );
    assert!(
        openapi.contains("Legacy v1 Deprecation"),
        "docs/openapi.yaml must document the legacy v1 deprecation notice"
    );
    assert!(
        openapi.contains("rel=\"successor-version\""),
        "docs/openapi.yaml must point legacy callers at the successor"
    );

    let reference = fs::read_to_string("docs/API_REFERENCE.md").expect("readable API_REFERENCE.md");
    assert!(
        reference.contains("## Legacy v1 Deprecation"),
        "docs/API_REFERENCE.md must carry the legacy v1 deprecation section"
    );

    let middleware = fs::read_to_string("src/api/middleware/deprecation.rs")
        .expect("readable deprecation middleware");
    assert!(
        middleware.contains("V1_SUNSET_HTTP_DATE"),
        "REST deprecation middleware must define the Sunset date"
    );

    let grpc = fs::read_to_string("src/grpc/service.rs").expect("readable v1 gRPC service");
    assert!(
        grpc.contains("x-sequencer-v1-deprecated"),
        "v1 gRPC responses must carry deprecation metadata"
    );
    assert!(
        grpc.contains("migrate to stateset.sequencer.v2"),
        "v1 gRPC calls must log the v2 migration warning"
    );
}
