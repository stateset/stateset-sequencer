//! HTTP server bootstrap for StateSet Sequencer.
//!
//! This module wires together:
//! - configuration
//! - database connection pool
//! - core services (sequencer, event store, commitment engine, VES sequencer)
//! - the Axum router

use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::{HeaderValue, Method};
use axum::routing::get;
use axum::Router;
use sqlx::postgres::PgPoolOptions;
use tower_http::cors::AllowOrigin;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, Level};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use crate::anchor::{AnchorConfig, AnchorService};
use crate::auth::{
    ApiKeyRecord, ApiKeyValidator, AuthMiddlewareState, Authenticator, JwtValidator, Permissions,
    RateLimiter,
};
use crate::domain::{StoreId, TenantId};
use crate::infra::{
    PayloadEncryption, PgAgentKeyRegistry, PgCommitmentEngine, PgEventStore, PgSequencer,
    PgVesCommitmentEngine, PgVesComplianceProofStore, PgVesValidityProofStore, Sequencer,
    VesSequencer,
};

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
    let ves_sequencer = Arc::new(VesSequencer::new(pool.clone(), agent_key_registry.clone()));

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
    };

    // Build router
    let app = build_router(auth_state)?.with_state(state);

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

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .with_thread_ids(true)
        .init();
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
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
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
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([
                axum::http::header::AUTHORIZATION,
                axum::http::header::CONTENT_TYPE,
            ]),
    ))
}

/// Health check endpoint.
async fn health_check() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "healthy",
        "service": "stateset-sequencer",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// Readiness check endpoint.
async fn readiness_check(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<axum::Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    // Check database connectivity by reading head from a known stream.
    match state
        .sequencer
        .head(
            &TenantId::from_uuid(uuid::Uuid::nil()),
            &StoreId::from_uuid(uuid::Uuid::nil()),
        )
        .await
    {
        Ok(_) => Ok(axum::Json(serde_json::json!({
            "status": "ready",
            "database": "connected",
        }))),
        Err(e) => Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            format!("Database unavailable: {}", e),
        )),
    }
}
