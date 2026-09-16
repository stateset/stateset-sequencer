//! Axum HTTP router construction.
//!
//! Assembles every HTTP route (public, authenticated, admin, metrics) with its
//! middleware stack. All routes and layering live here; [`super::run`] only
//! supplies state and applies process-wide layers.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, MatchedPath, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use ipnet::IpNet;
use tower_http::cors::AllowOrigin;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::warn;
use uuid::Uuid;

use crate::auth::{AuthContextExt, AuthMiddlewareState};
use crate::infra::extract_client_ip;
use crate::metrics::MetricsRegistry;

use super::state::AppState;

#[derive(Debug, Clone)]
pub(crate) enum AllowedIp {
    Exact(IpAddr),
    Cidr(IpNet),
}

impl AllowedIp {
    fn matches(&self, ip: IpAddr) -> bool {
        match self {
            AllowedIp::Exact(addr) => *addr == ip,
            AllowedIp::Cidr(net) => net.contains(&ip),
        }
    }
}

#[derive(Clone)]
pub(crate) struct AdminAccessState {
    pub(crate) allowlist: Option<Arc<Vec<AllowedIp>>>,
    pub(crate) trust_proxy_headers: bool,
}

async fn admin_ip_allowlist_middleware(
    State(state): State<AdminAccessState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: Request<Body>,
    next: Next,
) -> Response {
    let Some(allowlist) = &state.allowlist else {
        return next.run(request).await;
    };

    let client_ip = extract_client_ip(&headers, remote_addr, state.trust_proxy_headers)
        .unwrap_or(remote_addr.ip());
    let allowed = allowlist.iter().any(|entry| entry.matches(client_ip));
    if !allowed {
        warn!("Admin access denied for IP {}", client_ip);
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "error": "admin access denied",
                "code": "ADMIN_IP_DENIED"
            })),
        )
            .into_response();
    }

    next.run(request).await
}

pub(crate) fn parse_admin_allowlist() -> anyhow::Result<Option<Arc<Vec<AllowedIp>>>> {
    let raw = match std::env::var("ADMIN_IP_ALLOWLIST") {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };

    let mut entries = Vec::new();
    for token in raw.split(',') {
        let item = token.trim();
        if item.is_empty() {
            continue;
        }
        if item.contains('/') {
            let net: IpNet = item.parse().map_err(|e| {
                anyhow::anyhow!("invalid CIDR in ADMIN_IP_ALLOWLIST: {} ({})", item, e)
            })?;
            entries.push(AllowedIp::Cidr(net));
        } else {
            let ip: IpAddr = item.parse().map_err(|e| {
                anyhow::anyhow!("invalid IP in ADMIN_IP_ALLOWLIST: {} ({})", item, e)
            })?;
            entries.push(AllowedIp::Exact(ip));
        }
    }

    if entries.is_empty() {
        Ok(None)
    } else {
        Ok(Some(Arc::new(entries)))
    }
}

pub(crate) fn build_router(
    auth_state: AuthMiddlewareState,
    admin_access_state: AdminAccessState,
    payment_gate: crate::api::middleware::PaymentRequiredState,
) -> anyhow::Result<Router<AppState>> {
    let public_api = crate::api::public_router();
    let admin_allowlist_layer =
        axum::middleware::from_fn_with_state(admin_access_state, admin_ip_allowlist_middleware);
    // Premium (payment-gated) routes are merged before the auth layer is
    // applied so the x402 payment gate runs with the auth context available.
    let api = crate::api::router()
        .merge(crate::api::premium_router(payment_gate))
        .layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            crate::auth::auth_middleware,
        ));
    let admin_api = crate::api::admin_router()
        .layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            crate::auth::auth_middleware,
        ))
        .layer(admin_allowlist_layer.clone());

    let anchor_compat = crate::api::anchor_compat_router().layer(
        axum::middleware::from_fn_with_state(auth_state.clone(), crate::auth::auth_middleware),
    );

    let metrics_router = Router::new()
        .route("/metrics", get(metrics_handler))
        .layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            crate::auth::auth_middleware,
        ))
        .layer(admin_allowlist_layer.clone());

    let detailed_health_router = Router::new()
        .route(
            "/health/detailed",
            get(crate::api::handlers::health::detailed_health_check),
        )
        .layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            crate::auth::auth_middleware,
        ))
        .layer(admin_allowlist_layer.clone());

    let admin_dashboard = Router::new()
        .route("/admin", get(crate::api::handlers::admin::admin_dashboard))
        .route("/admin/", get(crate::api::handlers::admin::admin_dashboard))
        .layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            crate::auth::auth_middleware,
        ))
        .layer(admin_allowlist_layer.clone());

    let mut router = Router::new()
        .nest("/api", public_api)
        .merge(metrics_router)
        .merge(detailed_health_router)
        .merge(anchor_compat)
        .nest("/api", api)
        .nest("/api", admin_api)
        .merge(admin_dashboard)
        .route("/health", get(crate::api::handlers::health::health_check))
        .route("/ready", get(crate::api::handlers::health::readiness_check))
        .layer(TraceLayer::new_for_http());

    if let Some(cors_layer) = cors_layer_from_env()? {
        router = router.layer(cors_layer);
    }

    Ok(router)
}

fn cors_layer_from_env() -> anyhow::Result<Option<CorsLayer>> {
    let origins = match std::env::var("CORS_ALLOW_ORIGINS") {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    let origins = origins.trim();
    if origins.is_empty() {
        return Ok(None);
    }

    let allow_origin = if origins == "*" {
        AllowOrigin::any()
    } else {
        let origins: Vec<HeaderValue> = origins
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.parse::<HeaderValue>()
                    .map_err(|e| anyhow::anyhow!("Invalid CORS origin {s:?}: {e}"))
            })
            .collect::<anyhow::Result<_>>()?;
        AllowOrigin::list(origins)
    };

    Ok(Some(
        CorsLayer::new()
            .allow_origin(allow_origin)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([
                axum::http::header::AUTHORIZATION,
                axum::http::header::CONTENT_TYPE,
            ])
            .expose_headers([
                axum::http::header::HeaderName::from_static("x-request-id"),
                axum::http::header::HeaderName::from_static("x-error-code"),
                axum::http::header::RETRY_AFTER,
            ]),
    ))
}

/// Label used for every request that matched no route.
pub(crate) const UNMATCHED_PATH_LABEL: &str = "<unmatched>";

/// Decide the `path` label for a request's HTTP metrics.
///
/// Matched requests report their route template, which is a closed set. Every
/// unmatched request collapses into a single bucket: the raw URI is attacker
/// controlled and unbounded, and this middleware sits outside the auth layers,
/// so echoing it would let any anonymous client mint a time series per request
/// until the per-metric cardinality cap is spent -- pushing real routes into
/// the overflow bucket for the life of the process. Per-404 detail belongs in
/// the request log and trace, which carry the request id, not in metrics.
fn metrics_path_label(matched: Option<&str>, _raw_path: &str) -> String {
    match matched {
        Some(template) => template.to_string(),
        None => UNMATCHED_PATH_LABEL.to_string(),
    }
}

/// Middleware that extracts or generates a request ID and adds it to the
/// tracing span and response headers for cross-service correlation.
pub(crate) async fn request_id_middleware(mut req: Request<Body>, next: Next) -> Response {
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    req.extensions_mut().insert(RequestId(request_id.clone()));

    let span = tracing::Span::current();
    span.record("request_id", &request_id);

    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    if let Ok(val) = HeaderValue::from_str(&request_id) {
        headers.insert("x-request-id", val);
    }
    // Security headers
    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        axum::http::header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response
}

/// Request ID extracted from `x-request-id` header or auto-generated.
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

pub(crate) async fn http_metrics_middleware(
    State(metrics): State<Arc<MetricsRegistry>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let method = req.method().as_str().to_string();
    let path = metrics_path_label(
        req.extensions().get::<MatchedPath>().map(|p| p.as_str()),
        req.uri().path(),
    );

    let start = std::time::Instant::now();
    let response = next.run(req).await;
    let status = response.status().as_u16().to_string();
    let duration = start.elapsed().as_secs_f64();

    let labels = crate::metrics::Labels::new()
        .method(&method)
        .with("path", &path)
        .status(&status);

    metrics
        .inc_counter_labeled(
            crate::metrics::metric_names::HTTP_REQUESTS_TOTAL,
            labels.clone(),
        )
        .await;
    metrics
        .observe_histogram_labeled(
            crate::metrics::metric_names::HTTP_REQUEST_LATENCY,
            labels,
            duration,
        )
        .await;

    response
}

/// Prometheus metrics endpoint.
async fn metrics_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::Extension(AuthContextExt(auth)): axum::extract::Extension<AuthContextExt>,
) -> Response {
    if !auth.is_admin() {
        return (StatusCode::FORBIDDEN, "Admin permission required").into_response();
    }

    let metrics = state.metrics.to_prometheus().await;
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        metrics,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::{ConnectInfo, Extension, State};
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use serial_test::serial;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;
    use tower::ServiceExt;

    use crate::auth::Permissions;
    use crate::server::state::{test_app_state, test_auth_state};

    /// Requests that match no route must all share one `path` label. Emitting
    /// the raw URI here lets any unauthenticated client mint a fresh time
    /// series per request until the cardinality cap is exhausted, after which
    /// every genuine route falls into the overflow bucket -- HTTP metrics stay
    /// degraded until restart.
    #[test]
    fn metrics_path_label_buckets_every_unmatched_path() {
        let a = metrics_path_label(None, "/aaa1");
        let b = metrics_path_label(None, "/aaa2");
        let c = metrics_path_label(None, "/completely/unknown/deep/path");

        assert_eq!(a, UNMATCHED_PATH_LABEL);
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    /// A matched route reports its route template, so real endpoints stay
    /// individually observable and IDs never inflate cardinality.
    #[test]
    fn metrics_path_label_uses_matched_route_template() {
        let label = metrics_path_label(Some("/api/v1/ves/proofs/:seq"), "/api/v1/ves/proofs/12345");

        assert_eq!(label, "/api/v1/ves/proofs/:seq");
    }

    #[tokio::test]
    async fn metrics_requires_admin() {
        let state = test_app_state();

        let user_ctx = crate::auth::AuthContext {
            tenant_id: Uuid::new_v4(),
            store_ids: Vec::new(),
            agent_id: None,
            rate_limit: None,
            permissions: Permissions::read_only(),
        };
        let response =
            metrics_handler(State(state.clone()), Extension(AuthContextExt(user_ctx))).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let admin_ctx = crate::auth::AuthContext {
            tenant_id: Uuid::nil(),
            store_ids: Vec::new(),
            agent_id: None,
            rate_limit: None,
            permissions: Permissions::admin(),
        };
        let response = metrics_handler(State(state), Extension(AuthContextExt(admin_ctx))).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Drive real traffic through the real metrics middleware, then scrape the
    /// real handler and check the payload would survive a Prometheus parse.
    ///
    /// The middleware labels `http_request_latency` by method, path and status,
    /// so distinct requests create distinct label sets on one histogram name --
    /// the exact shape that previously emitted a `# TYPE` line per series and
    /// made Prometheus reject every scrape. A unit test over a hand-built
    /// registry missed it because it asserted on substrings; this asserts the
    /// whole payload, produced the way production produces it.
    #[tokio::test]
    async fn metrics_endpoint_exposition_survives_real_traffic() {
        let state = test_app_state();

        // Three distinct label sets on the request histogram and counter.
        for path in ["/api/v1/a", "/api/v1/b", "/api/v1/c"] {
            let labels = crate::metrics::Labels::new()
                .method("GET")
                .with("path", path)
                .status("200");
            state
                .metrics
                .inc_counter_labeled(
                    crate::metrics::metric_names::HTTP_REQUESTS_TOTAL,
                    labels.clone(),
                )
                .await;
            state
                .metrics
                .observe_histogram_labeled(
                    crate::metrics::metric_names::HTTP_REQUEST_LATENCY,
                    labels,
                    0.01,
                )
                .await;
        }

        let admin_ctx = crate::auth::AuthContext {
            tenant_id: Uuid::nil(),
            store_ids: Vec::new(),
            agent_id: None,
            rate_limit: None,
            permissions: Permissions::admin(),
        };
        let response = metrics_handler(State(state), Extension(AuthContextExt(admin_ctx))).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("read metrics body");
        let payload = String::from_utf8(body.to_vec()).expect("utf-8 metrics body");

        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut duplicates: Vec<&str> = Vec::new();
        for line in payload.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let name = rest.split_whitespace().next().unwrap_or("");
                if !seen.insert(name) {
                    duplicates.push(name);
                }
            }
        }

        assert!(
            duplicates.is_empty(),
            "Prometheus rejects a scrape declaring a type twice; duplicates: {duplicates:?}\n\n{payload}"
        );
        assert!(
            payload.contains("# TYPE sequencer_http_request_latency_seconds histogram"),
            "histogram should still be exported:\n{payload}"
        );
    }

    #[test]
    #[serial]
    fn parse_admin_allowlist_accepts_ips_and_cidr() {
        std::env::set_var("ADMIN_IP_ALLOWLIST", "203.0.113.10,10.0.0.0/8");
        let allowlist = parse_admin_allowlist().unwrap().unwrap();
        assert_eq!(allowlist.len(), 2);

        let ip_match = "203.0.113.10".parse::<IpAddr>().unwrap();
        let cidr_match = "10.1.2.3".parse::<IpAddr>().unwrap();
        assert!(allowlist.iter().any(|entry| entry.matches(ip_match)));
        assert!(allowlist.iter().any(|entry| entry.matches(cidr_match)));

        std::env::remove_var("ADMIN_IP_ALLOWLIST");
    }

    #[tokio::test]
    async fn admin_allowlist_blocks_unlisted_ip() {
        let allowlist = Arc::new(vec![AllowedIp::Exact(
            "203.0.113.10".parse::<IpAddr>().unwrap(),
        )]);
        let state = AdminAccessState {
            allowlist: Some(allowlist),
            trust_proxy_headers: false,
        };

        let app = Router::new()
            .route("/admin", get(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn_with_state(
                state,
                admin_ip_allowlist_middleware,
            ));

        let remote = SocketAddr::from(([198, 51, 100, 2], 1234));
        let mut req = Request::builder()
            .uri("/admin")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(remote));

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_allowlist_allows_listed_ip() {
        let allowlist = Arc::new(vec![AllowedIp::Exact(
            "203.0.113.10".parse::<IpAddr>().unwrap(),
        )]);
        let state = AdminAccessState {
            allowlist: Some(allowlist),
            trust_proxy_headers: false,
        };

        let app = Router::new()
            .route("/admin", get(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn_with_state(
                state,
                admin_ip_allowlist_middleware,
            ));

        let remote = SocketAddr::from(([203, 0, 113, 10], 1234));
        let mut req = Request::builder()
            .uri("/admin")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(remote));

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// The extracted router module must keep every startup route wired exactly
    /// as `run` serves them: the public `/health` and `/ready` probes stay
    /// reachable while unknown paths still 404.
    #[tokio::test]
    async fn router_keeps_startup_routes_wired() {
        let state = test_app_state();
        let auth_state = test_auth_state();
        let payment_gate = crate::api::middleware::PaymentRequiredState::new(
            state.x402_repository.clone(),
            state.agent_key_registry.clone(),
            Arc::new(crate::api::middleware::PaymentRequiredConfig::from_env()),
        );
        let admin_access_state = AdminAccessState {
            allowlist: None,
            trust_proxy_headers: false,
        };

        let app = build_router(auth_state, admin_access_state, payment_gate)
            .expect("router builds")
            .with_state(state);

        // `/health` is DB-free; `/ready` probes Postgres, so without a live
        // database it answers 503 — either way the route itself must be wired
        // (a missing route would 404).
        // `oneshot` provides no socket address; production serves through
        // `into_make_service_with_connect_info`, so insert it like the admin
        // allowlist tests do.
        let remote = SocketAddr::from(([127, 0, 0, 1], 1234));
        let mut req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(remote));
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "unexpected status for /health"
        );

        let mut req = Request::builder()
            .uri("/ready")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(remote));
        let response = app.clone().oneshot(req).await.unwrap();
        assert!(
            [StatusCode::OK, StatusCode::SERVICE_UNAVAILABLE].contains(&response.status()),
            "unexpected status for /ready: {}",
            response.status()
        );

        let mut req = Request::builder()
            .uri("/no-such-route")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(remote));
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "unexpected status for /no-such-route"
        );
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "unexpected status for /no-such-route"
        );
    }
}
