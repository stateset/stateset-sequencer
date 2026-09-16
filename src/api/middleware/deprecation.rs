//! Formal deprecation gate for the legacy pre-VES v1 surface.
//!
//! The legacy REST endpoints (every non-`ves` `/v1/*` route: events ingest,
//! event reads, legacy commitments/proofs/entity history/projections and the
//! legacy anchor endpoints) and the gRPC `stateset.sequencer.v1` service are
//! formally deprecated in favor of the VES `/v1/ves/*` REST endpoints and the
//! gRPC `stateset.sequencer.v2` service.
//!
//! Every legacy response carries RFC 8594 `Deprecation`/`Sunset` headers plus
//! a `Link` header pointing at the successor, and every legacy call emits a
//! `warn!` log so operators can find remaining callers before removal.

use axum::body::Body;
use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;

/// Planned removal date for the legacy v1 surface (RFC 1123 HTTP date).
pub const V1_SUNSET_HTTP_DATE: &str = "Mon, 01 Mar 2027 00:00:00 GMT";

/// Successor pointer served on every legacy v1 response.
pub const V1_SUCCESSOR_LINK: &str =
    "</api/v1/ves/events/ingest>; rel=\"successor-version\", </docs/openapi.yaml>; rel=\"help\"";

/// Path prefixes (after the optional `/api` mount prefix) that belong to the
/// deprecated legacy v1 surface. The VES protocol (`/v1/ves/*`), agent
/// registration/keys/policies, the schema registry, x402 payments, admin APIs
/// and health/metrics endpoints are current and intentionally absent here.
const LEGACY_V1_PREFIXES: &[&str] = &[
    "/v1/events/ingest",
    "/v1/events",
    "/v1/head",
    "/v1/commitments",
    "/v1/proofs",
    "/v1/entities",
    "/v1/projections",
    "/v1/anchor",
];

/// Report whether a request path targets the deprecated legacy v1 surface.
///
/// Accepts paths with or without the `/api` mount prefix so the same
/// predicate works for the served router and for documentation audits.
pub fn is_legacy_v1_path(path: &str) -> bool {
    let stripped = path.strip_prefix("/api").unwrap_or(path);
    LEGACY_V1_PREFIXES.iter().any(|prefix| {
        stripped == *prefix
            || stripped
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// Attach the formal deprecation headers to a legacy v1 response.
fn stamp_deprecated(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert("deprecation", HeaderValue::from_static("true"));
    headers.insert("sunset", HeaderValue::from_static(V1_SUNSET_HTTP_DATE));
    headers.insert("link", HeaderValue::from_static(V1_SUCCESSOR_LINK));
}

/// Middleware stamping `Deprecation`/`Sunset`/`Link` headers on legacy v1
/// responses and logging each legacy call for migration tracking.
pub async fn v1_deprecation_middleware(req: Request<Body>, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let legacy = is_legacy_v1_path(&path);
    let mut response = next.run(req).await;
    if legacy {
        tracing::warn!(
            path = %path,
            sunset = V1_SUNSET_HTTP_DATE,
            "legacy v1 REST endpoint called; migrate to the VES /v1/ves/* endpoints or gRPC v2"
        );
        stamp_deprecated(&mut response);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    #[test]
    fn legacy_paths_cover_the_pre_ves_surface() {
        for path in [
            "/api/v1/events/ingest",
            "/api/v1/events",
            "/api/v1/head",
            "/api/v1/commitments",
            "/api/v1/commitments/pending",
            "/api/v1/commitments/9d1a9a37-0000-4000-8000-000000000000/anchored",
            "/api/v1/proofs/42",
            "/api/v1/proofs/verify",
            "/api/v1/entities/order/ord-1",
            "/api/v1/projections/order/ord-1",
            "/api/v1/anchor",
            "/api/v1/anchor/status",
            "/api/v1/anchor/9d1a9a37-0000-4000-8000-000000000000/verify",
            "/v1/head",
        ] {
            assert!(is_legacy_v1_path(path), "{path} must be legacy");
        }
    }

    #[test]
    fn current_surface_is_not_legacy() {
        for path in [
            "/api/v1/ves/events",
            "/api/v1/ves/events/ingest",
            "/api/v1/ves/head",
            "/api/v1/ves/commitments",
            "/api/v1/agents/register",
            "/api/v1/agents/keys",
            "/api/v1/agents/9d1a9a37-0000-4000-8000-000000000000/policy",
            "/api/v1/schemas",
            "/api/v1/schemas/validate",
            "/api/v1/x402/payments",
            "/api/v1/admin/overview",
            "/health",
            "/ready",
            "/metrics",
        ] {
            assert!(!is_legacy_v1_path(path), "{path} must not be legacy");
        }
    }

    #[tokio::test]
    async fn middleware_stamps_only_legacy_responses() {
        let app = Router::new()
            .route("/api/v1/head", get(|| async { "head" }))
            .route("/api/v1/ves/head", get(|| async { "ves-head" }))
            .layer(axum::middleware::from_fn(v1_deprecation_middleware));

        let legacy = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/head?tenant_id=1&store_id=2")
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("legacy route serves");
        assert_eq!(
            legacy.headers().get("deprecation").map(|v| v.as_bytes()),
            Some(b"true".as_slice())
        );
        assert_eq!(
            legacy
                .headers()
                .get("sunset")
                .map(|v| v.to_str().expect("ascii sunset")),
            Some(V1_SUNSET_HTTP_DATE)
        );
        assert!(legacy.headers().contains_key("link"));

        let current = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/ves/head?tenant_id=1&store_id=2")
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("current route serves");
        assert!(!current.headers().contains_key("deprecation"));
        assert!(!current.headers().contains_key("sunset"));
    }
}
