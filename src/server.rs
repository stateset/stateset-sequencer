//! HTTP server bootstrap for StateSet Sequencer.
//!
//! This module wires together:
//! - configuration
//! - database connection pool
//! - core services (sequencer, event store, commitment engine, VES sequencer)
//! - the Axum router

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, Method};
use axum::routing::get;
use axum::Router;
use sqlx::postgres::PgPoolOptions;
use tower_http::cors::AllowOrigin;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, Level};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};
use uuid::Uuid;

use crate::anchor::{AnchorConfig, AnchorService};
use crate::auth::{
    ApiKeyRecord, ApiKeyValidator, AuthMiddlewareState, Authenticator, JwtValidator, Permissions,
    RateLimiter, RequestLimits,
};
use crate::crypto::{secret_key_from_str, AgentSigningKey};
use crate::infra::{
    CircuitBreakerRegistry, PayloadEncryption, PgAgentKeyRegistry, PgCommitmentEngine,
    PgEventStore, PgSchemaStore, PgSequencer, PgVesCommitmentEngine, PgVesComplianceProofStore,
    PgVesValidityProofStore, PoolMonitor, SchemaValidationMode, VesSequencer,
};
use crate::metrics::{ComponentMetrics, MetricsRegistry};

/// Server configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// PostgreSQL connection URL.
    pub database_url: String,
    /// Server listen address.
    pub listen_addr: SocketAddr,
    /// Maximum database connections.
    pub max_connections: u32,
}

impl Config {
    /// Load configuration from environment variables.
    pub fn from_env() -> Self {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/stateset_sequencer".to_string());

        let port: u16 = std::env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8080);

        let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());

        let listen_addr: SocketAddr = format!("{host}:{port}")
            .parse()
            .expect("Invalid listen address");

        let max_connections: u32 = std::env::var("MAX_DB_CONNECTIONS")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(10);

        Self {
            database_url,
            listen_addr,
            max_connections,
        }
    }
}

/// Application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    pub sequencer: Arc<PgSequencer>,
    pub event_store: Arc<PgEventStore>,
    pub commitment_engine: Arc<PgCommitmentEngine>,
    pub ves_commitment_engine: Arc<PgVesCommitmentEngine>,
    pub ves_validity_proof_store: Arc<PgVesValidityProofStore>,
    pub ves_compliance_proof_store: Arc<PgVesComplianceProofStore>,
    pub anchor_service: Option<Arc<AnchorService>>,
    pub ves_sequencer: Arc<VesSequencer<PgAgentKeyRegistry>>,
    pub agent_key_registry: Arc<PgAgentKeyRegistry>,
    pub schema_store: Arc<PgSchemaStore>,
    pub metrics: Arc<MetricsRegistry>,
    /// Schema validation mode for event ingestion
    pub schema_validation_mode: SchemaValidationMode,
    /// Request limits for ingestion and payload sizing
    pub request_limits: RequestLimits,
    /// Connection pool health monitor
    pub pool_monitor: Option<Arc<PoolMonitor>>,
    /// Circuit breaker registry for external service calls
    pub circuit_breaker_registry: Option<Arc<CircuitBreakerRegistry>>,
}

/// Start the HTTP server.
pub async fn run() -> anyhow::Result<()> {
    init_tracing();

    info!("Starting StateSet Sequencer v{}", env!("CARGO_PKG_VERSION"));

    // Auth configuration
    let auth_mode = std::env::var("AUTH_MODE").unwrap_or_else(|_| "required".to_string());
    let require_auth = auth_mode != "disabled";

    let api_key_validator = Arc::new(ApiKeyValidator::new());
    let mut any_auth_configured = false;

    if let Ok(bootstrap_key) = std::env::var("BOOTSTRAP_ADMIN_API_KEY") {
        let key_hash = ApiKeyValidator::hash_key(&bootstrap_key);
        api_key_validator.register_key(ApiKeyRecord {
            key_hash,
            tenant_id: Uuid::nil(),
            store_ids: vec![],
            permissions: Permissions::admin(),
            agent_id: None,
            active: true,
            rate_limit: None,
        });
        any_auth_configured = true;
        info!("Bootstrap admin API key is configured");
    }

    let jwt_validator = match std::env::var("JWT_SECRET") {
        Ok(secret) => {
            let issuer =
                std::env::var("JWT_ISSUER").unwrap_or_else(|_| "stateset-sequencer".to_string());
            let audience =
                std::env::var("JWT_AUDIENCE").unwrap_or_else(|_| "stateset-api".to_string());
            any_auth_configured = true;
            Some(Arc::new(JwtValidator::new(
                secret.as_bytes(),
                &issuer,
                &audience,
            )))
        }
        Err(_) => None,
    };

    if require_auth && !any_auth_configured {
        anyhow::bail!(
            "AUTH_MODE=required but no auth is configured; set JWT_SECRET or BOOTSTRAP_ADMIN_API_KEY (or set AUTH_MODE=disabled for local dev)"
        );
    }

    let authenticator = {
        let authenticator = Authenticator::new(api_key_validator);
        match jwt_validator {
            Some(jwt) => Arc::new(authenticator.with_jwt(jwt)),
            None => Arc::new(authenticator),
        }
    };

    let rate_limiter = std::env::var("RATE_LIMIT_PER_MINUTE")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .map(|rpm| Arc::new(RateLimiter::new(rpm)));

    let auth_state = AuthMiddlewareState {
        authenticator,
        require_auth,
        rate_limiter,
    };

    let request_limits = RequestLimits::from_env();
    info!(
        "Request limits: max_body_size={} bytes, max_events_per_batch={}, max_event_payload_size={} bytes",
        request_limits.max_body_size,
        request_limits.max_events_per_batch,
        request_limits.max_event_payload_size
    );

    // Load configuration
    let config = Config::from_env();
    info!("Configuration loaded");
    info!("  Listen address: {}", config.listen_addr);
    info!("  Max connections: {}", config.max_connections);

    // Connect to PostgreSQL
    info!("Connecting to PostgreSQL...");
    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .connect(&config.database_url)
        .await?;
    info!("Connected to PostgreSQL");

    let migrate_on_startup = std::env::var("DB_MIGRATE_ON_STARTUP")
        .ok()
        .map(|v| {
            !matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "off"
            )
        })
        .unwrap_or(true);
    if migrate_on_startup {
        info!("Running database migrations...");
        crate::migrations::run_postgres(&pool).await?;
        info!("Database migrations applied");
    } else {
        info!("DB migrations skipped (DB_MIGRATE_ON_STARTUP=0)");
    }

    // Payload encryption-at-rest (legacy `events` table)
    let payload_encryption =
        Arc::new(PayloadEncryption::from_env().map_err(|e| anyhow::anyhow!(e.to_string()))?);
    info!(
        "Payload encryption-at-rest mode: {:?}",
        payload_encryption.mode()
    );

    // Initialize services
    let sequencer = Arc::new(PgSequencer::new(pool.clone(), payload_encryption.clone()));
    let event_store = Arc::new(PgEventStore::new(pool.clone(), payload_encryption.clone()));
    let commitment_engine = Arc::new(PgCommitmentEngine::new(pool.clone()));
    let ves_commitment_engine = Arc::new(PgVesCommitmentEngine::new(pool.clone()));
    let ves_validity_proof_store = Arc::new(PgVesValidityProofStore::new(
        pool.clone(),
        payload_encryption.clone(),
    ));
    let ves_compliance_proof_store = Arc::new(PgVesComplianceProofStore::new(
        pool.clone(),
        payload_encryption,
    ));

    // Initialize VES v1.0 services
    let agent_key_registry = Arc::new(PgAgentKeyRegistry::new(pool.clone()));
    let mut ves_sequencer = VesSequencer::new(pool.clone(), agent_key_registry.clone());
    if let Some(sequencer_id) = load_ves_sequencer_id()? {
        info!("VES sequencer id configured: {}", sequencer_id);
        ves_sequencer = ves_sequencer.with_sequencer_id(sequencer_id);
    } else {
        info!("VES sequencer id not configured (set VES_SEQUENCER_ID to pin)");
    }
    if let Some(signing_key) = load_ves_sequencer_signing_key()? {
        info!("VES sequencer receipt signing enabled");
        ves_sequencer = ves_sequencer.with_signing_key(signing_key);
    } else {
        info!("VES sequencer receipt signing disabled (set VES_SEQUENCER_SIGNING_KEY to enable)");
    }
    let ves_sequencer = Arc::new(ves_sequencer);

    // Initialize schema registry
    let schema_store = Arc::new(PgSchemaStore::new(pool.clone()));
    schema_store.initialize().await?;
    info!("Schema registry initialized");

    // Schema validation mode for event ingestion
    let schema_validation_mode = SchemaValidationMode::from_env();
    info!("Schema validation mode: {}", schema_validation_mode);

    // Initialize metrics registry
    let metrics = Arc::new(MetricsRegistry::new());
    info!("Metrics registry initialized");

    // Initialize pool monitor for health checks
    let pool_monitor = Arc::new(PoolMonitor::new(config.max_connections));
    pool_monitor.update_from_pool(&pool).await;
    info!("Pool monitor initialized");

    // Initialize circuit breaker registry for external services
    let circuit_breaker_registry = Arc::new(CircuitBreakerRegistry::new());
    info!("Circuit breaker registry initialized");

    // Initialize anchor service (optional - only if env vars are set)
    let anchor_service = match AnchorConfig::from_env() {
        Some(anchor_config) => {
            info!("Anchor service configured:");
            info!("  RPC URL: {}", anchor_config.rpc_url);
            info!("  Registry: {:?}", anchor_config.registry_address);
            info!("  Chain ID: {}", anchor_config.chain_id);
            Some(Arc::new(AnchorService::new(anchor_config)))
        }
        None => {
            info!(
                "Anchor service not configured (set L2_RPC_URL, SET_REGISTRY_ADDRESS, SEQUENCER_PRIVATE_KEY to enable)"
            );
            None
        }
    };

    // Create application state
    let state = AppState {
        sequencer,
        event_store,
        commitment_engine,
        ves_commitment_engine,
        ves_validity_proof_store,
        ves_compliance_proof_store,
        anchor_service,
        ves_sequencer,
        agent_key_registry,
        schema_store,
        metrics,
        schema_validation_mode,
        request_limits: request_limits.clone(),
        pool_monitor: Some(pool_monitor),
        circuit_breaker_registry: Some(circuit_breaker_registry),
    };

    // Start component metrics collection in background
    let component_metrics = Arc::new(ComponentMetrics::new(
        state.metrics.clone(),
        state.pool_monitor.clone(),
        state.circuit_breaker_registry.clone(),
    ));
    let _metrics_task = component_metrics.start_collection_task(std::time::Duration::from_secs(15));
    info!("Component metrics collection started (15s interval)");

    // Build router
    let app = build_router(auth_state)?
        .with_state(state)
        .layer(DefaultBodyLimit::max(request_limits.max_body_size));

    // Start server
    info!("Starting HTTP server on {}", config.listen_addr);
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;

    info!("StateSet Sequencer is ready to accept connections");
    axum::serve(listener, app).await?;

    Ok(())
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(Level::INFO.to_string()));

    let log_format = std::env::var("LOG_FORMAT").unwrap_or_default();
    let otel_enabled = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok();

    // Base formatting layer
    let fmt_layer = if log_format.to_lowercase() == "json" {
        tracing_subscriber::fmt::layer()
            .json()
            .with_target(true)
            .with_thread_ids(true)
            .with_file(true)
            .with_line_number(true)
            .boxed()
    } else {
        tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_thread_ids(true)
            .boxed()
    };

    // Build the subscriber with optional OpenTelemetry
    if otel_enabled {
        // Initialize OpenTelemetry tracer
        match init_opentelemetry_tracer() {
            Ok(tracer) => {
                let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);
                tracing_subscriber::registry()
                    .with(env_filter)
                    .with(fmt_layer)
                    .with(telemetry_layer)
                    .init();
                return;
            }
            Err(e) => {
                eprintln!("Failed to initialize OpenTelemetry: {e}. Falling back to basic tracing.");
            }
        }
    }

    // Fallback: basic tracing without OpenTelemetry
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .init();
}

fn load_ves_sequencer_signing_key() -> anyhow::Result<Option<AgentSigningKey>> {
    let key_value = match std::env::var("VES_SEQUENCER_SIGNING_KEY") {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };

    let secret = secret_key_from_str(&key_value)
        .map_err(|e| anyhow::anyhow!("invalid VES_SEQUENCER_SIGNING_KEY: {e}"))?;
    let signing_key = AgentSigningKey::from_bytes(&secret)
        .map_err(|e| anyhow::anyhow!("invalid VES_SEQUENCER_SIGNING_KEY: {e}"))?;

    Ok(Some(signing_key))
}

fn load_ves_sequencer_id() -> anyhow::Result<Option<Uuid>> {
    let value = match std::env::var("VES_SEQUENCER_ID") {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };

    let id = Uuid::parse_str(value.trim())
        .map_err(|e| anyhow::anyhow!("invalid VES_SEQUENCER_ID: {e}"))?;
    Ok(Some(id))
}

/// Initialize OpenTelemetry tracer with OTLP exporter
fn init_opentelemetry_tracer() -> Result<opentelemetry_sdk::trace::Tracer, opentelemetry::trace::TraceError> {
    use opentelemetry::trace::TracerProvider;
    use opentelemetry_otlp::WithExportConfig;

    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:4317".to_string()),
        );

    let provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(
            opentelemetry_sdk::trace::Config::default()
                .with_resource(opentelemetry_sdk::Resource::new(vec![
                    opentelemetry::KeyValue::new("service.name", "stateset-sequencer"),
                    opentelemetry::KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                ])),
        )
        .install_batch(opentelemetry_sdk::runtime::Tokio)?;

    Ok(provider.tracer("stateset-sequencer"))
}

fn build_router(auth_state: AuthMiddlewareState) -> anyhow::Result<Router<AppState>> {
    let api = crate::api::router().layer(axum::middleware::from_fn_with_state(
        auth_state.clone(),
        crate::auth::auth_middleware,
    ));

    let anchor_compat = crate::api::anchor_compat_router().layer(
        axum::middleware::from_fn_with_state(auth_state, crate::auth::auth_middleware),
    );

    let mut router = Router::new()
        .merge(anchor_compat)
        .nest("/api", api)
        .route("/health", get(crate::api::handlers::health::health_check))
        .route("/health/detailed", get(crate::api::handlers::health::detailed_health_check))
        .route("/ready", get(crate::api::handlers::health::readiness_check))
        .route("/metrics", get(metrics_handler))
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
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
            .allow_headers([
                axum::http::header::AUTHORIZATION,
                axum::http::header::CONTENT_TYPE,
            ]),
    ))
}

/// Prometheus metrics endpoint.
async fn metrics_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> ([(axum::http::header::HeaderName, &'static str); 1], String) {
    let metrics = state.metrics.to_prometheus().await;
    (
        [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        metrics,
    )
}
