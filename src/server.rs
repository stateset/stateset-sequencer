//! HTTP and gRPC server bootstrap for StateSet Sequencer.
//!
//! This module wires together:
//! - configuration
//! - database connection pool
//! - core services (sequencer, event store, commitment engine, VES sequencer)
//! - the Axum HTTP router
//! - the Tonic gRPC server (v1 and v2 APIs)

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use sqlx::postgres::PgPoolOptions;
use tonic::transport::Server as TonicServer;
use tower_http::cors::AllowOrigin;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn, Level};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};
use uuid::Uuid;

use crate::grpc::{GrpcAuthInterceptor, KeyManagementServiceV2, SequencerService, SequencerServiceV2};
use crate::proto::v2::key_management_server::KeyManagementServer;
use crate::proto::sequencer_server::SequencerServer as SequencerServerV1;
use crate::proto::v2::sequencer_server::SequencerServer as SequencerServerV2;

use crate::anchor::{AnchorConfig, AnchorService};
use crate::auth::{
    ApiKeyRecord, ApiKeyValidator, AuthContextExt, AuthMiddlewareState, Authenticator,
    JwtValidator, Permissions, PgApiKeyStore, RateLimiter, RateLimiterConfig, RequestLimits,
};
use crate::crypto::{secret_key_from_str, AgentSigningKey};
use crate::infra::{
    PgAuditLogger, CacheManager, CacheManagerConfig, CircuitBreakerRegistry, PayloadEncryption,
    PgAgentKeyRegistry, PgCommitmentEngine, PgEventStore, PgSchemaStore, PgSequencer,
    PgVesCommitmentEngine, PgVesComplianceProofStore, PgVesValidityProofStore, PgX402Repository,
    PoolMonitor, SchemaValidationMode, VesSequencer,
};
use crate::metrics::{ComponentMetrics, MetricsRegistry};

/// PostgreSQL connection pool configuration.
#[derive(Debug, Clone)]
pub struct DbPoolConfig {
    /// Maximum pool size.
    pub max_connections: u32,
    /// Minimum idle connections to keep warm.
    pub min_connections: u32,
    /// Connection acquisition timeout (ms).
    pub acquire_timeout_ms: Option<u64>,
    /// Idle connection timeout (seconds).
    pub idle_timeout_secs: Option<u64>,
    /// Max connection lifetime (seconds).
    pub max_lifetime_secs: Option<u64>,
}

impl DbPoolConfig {
    fn from_env(prefix: &str, default_max: u32) -> Self {
        let max_connections = std::env::var(format!("{prefix}MAX_DB_CONNECTIONS"))
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_max);

        let min_connections = std::env::var(format!("{prefix}MIN_DB_CONNECTIONS"))
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        let acquire_timeout_ms = std::env::var(format!("{prefix}DB_ACQUIRE_TIMEOUT_MS"))
            .ok()
            .and_then(|v| v.parse().ok());

        let idle_timeout_secs = std::env::var(format!("{prefix}DB_IDLE_TIMEOUT_SECS"))
            .ok()
            .and_then(|v| v.parse().ok());

        let max_lifetime_secs = std::env::var(format!("{prefix}DB_MAX_LIFETIME_SECS"))
            .ok()
            .and_then(|v| v.parse().ok());

        Self {
            max_connections,
            min_connections,
            acquire_timeout_ms,
            idle_timeout_secs,
            max_lifetime_secs,
        }
    }
}

/// PostgreSQL session configuration.
#[derive(Debug, Clone)]
pub struct DbSessionConfig {
    /// Optional statement timeout (ms).
    pub statement_timeout_ms: Option<u64>,
    /// Optional idle-in-transaction timeout (ms).
    pub idle_in_tx_timeout_ms: Option<u64>,
    /// Optional lock timeout (ms).
    pub lock_timeout_ms: Option<u64>,
    /// application_name reported to PostgreSQL.
    pub application_name: String,
}

impl DbSessionConfig {
    fn from_env() -> Self {
        let statement_timeout_ms = std::env::var("DB_STATEMENT_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse().ok());

        let idle_in_tx_timeout_ms = std::env::var("DB_IDLE_IN_TX_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse().ok());

        let lock_timeout_ms = std::env::var("DB_LOCK_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse().ok());

        let application_name = std::env::var("DB_APPLICATION_NAME")
            .unwrap_or_else(|_| "stateset-sequencer".to_string());

        Self {
            statement_timeout_ms,
            idle_in_tx_timeout_ms,
            lock_timeout_ms,
            application_name,
        }
    }
}

/// Cache configuration.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub commitment_max: usize,
    pub commitment_ttl_secs: u64,
    pub proof_max: usize,
    pub proof_ttl_secs: u64,
    pub ves_commitment_max: usize,
    pub ves_commitment_ttl_secs: u64,
    pub ves_proof_max: usize,
    pub ves_proof_ttl_secs: u64,
    pub agent_key_max: usize,
    pub agent_key_ttl_secs: u64,
    pub schema_max: usize,
    pub schema_ttl_secs: u64,
}

impl CacheConfig {
    fn from_env() -> Self {
        let defaults = CacheManagerConfig::default();

        let commitment_max = read_usize_env("CACHE_COMMITMENT_MAX", defaults.commitment_max);
        let commitment_ttl_secs =
            read_u64_env("CACHE_COMMITMENT_TTL_SECS", defaults.commitment_ttl.as_secs());

        let proof_max = read_usize_env("CACHE_PROOF_MAX", defaults.proof_max);
        let proof_ttl_secs = read_u64_env("CACHE_PROOF_TTL_SECS", defaults.proof_ttl.as_secs());

        let ves_commitment_max =
            read_usize_env("CACHE_VES_COMMITMENT_MAX", commitment_max);
        let ves_commitment_ttl_secs =
            read_u64_env("CACHE_VES_COMMITMENT_TTL_SECS", commitment_ttl_secs);

        let ves_proof_max = read_usize_env("CACHE_VES_PROOF_MAX", proof_max);
        let ves_proof_ttl_secs = read_u64_env("CACHE_VES_PROOF_TTL_SECS", proof_ttl_secs);

        let agent_key_max = read_usize_env("CACHE_AGENT_KEY_MAX", defaults.agent_key_max);
        let agent_key_ttl_secs =
            read_u64_env("CACHE_AGENT_KEY_TTL_SECS", defaults.agent_key_ttl.as_secs());

        let schema_max = read_usize_env("CACHE_SCHEMA_MAX", defaults.schema_max);
        let schema_ttl_secs =
            read_u64_env("CACHE_SCHEMA_TTL_SECS", defaults.schema_ttl.as_secs());

        Self {
            commitment_max,
            commitment_ttl_secs,
            proof_max,
            proof_ttl_secs,
            ves_commitment_max,
            ves_commitment_ttl_secs,
            ves_proof_max,
            ves_proof_ttl_secs,
            agent_key_max,
            agent_key_ttl_secs,
            schema_max,
            schema_ttl_secs,
        }
    }

    fn to_manager_config(&self) -> CacheManagerConfig {
        CacheManagerConfig {
            commitment_max: self.commitment_max,
            commitment_ttl: Duration::from_secs(self.commitment_ttl_secs),
            proof_max: self.proof_max,
            proof_ttl: Duration::from_secs(self.proof_ttl_secs),
            ves_commitment_max: self.ves_commitment_max,
            ves_commitment_ttl: Duration::from_secs(self.ves_commitment_ttl_secs),
            ves_proof_max: self.ves_proof_max,
            ves_proof_ttl: Duration::from_secs(self.ves_proof_ttl_secs),
            agent_key_max: self.agent_key_max,
            agent_key_ttl: Duration::from_secs(self.agent_key_ttl_secs),
            schema_max: self.schema_max,
            schema_ttl: Duration::from_secs(self.schema_ttl_secs),
        }
    }
}

fn read_usize_env(var: &str, default: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
        .max(1)
}

fn read_u64_env(var: &str, default: u64) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
        .max(1)
}

/// Server configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// PostgreSQL connection URL.
    pub database_url: String,
    /// Optional read-replica connection URL.
    pub read_database_url: Option<String>,
    /// HTTP server listen address.
    pub listen_addr: SocketAddr,
    /// gRPC server listen address (optional).
    pub grpc_addr: Option<SocketAddr>,
    /// Write pool configuration.
    pub write_pool: DbPoolConfig,
    /// Read pool configuration.
    pub read_pool: DbPoolConfig,
    /// Session configuration for database connections.
    pub session: DbSessionConfig,
    /// Optional read session override.
    pub read_session: DbSessionConfig,
    /// Cache configuration.
    pub cache: CacheConfig,
}

impl Config {
    /// Load configuration from environment variables.
    pub fn from_env() -> Self {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/stateset_sequencer".to_string());

        let read_database_url = std::env::var("READ_DATABASE_URL")
            .ok()
            .filter(|v| !v.trim().is_empty());

        let port: u16 = std::env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8080);

        let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());

        let listen_addr: SocketAddr = format!("{host}:{port}")
            .parse()
            .expect("Invalid listen address");

        // gRPC port configuration (defaults to HTTP port + 1, e.g., 8081 if HTTP is 8080)
        let grpc_addr: Option<SocketAddr> = if std::env::var("GRPC_DISABLED").is_ok() {
            None
        } else {
            let grpc_port: u16 = std::env::var("GRPC_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(port + 1);
            Some(format!("{host}:{grpc_port}").parse().expect("Invalid gRPC address"))
        };

        let write_pool = DbPoolConfig::from_env("", 10);
        let read_pool = DbPoolConfig::from_env("READ_", write_pool.max_connections);
        let session = DbSessionConfig::from_env();
        let read_session_name = std::env::var("READ_DB_APPLICATION_NAME")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| format!("{}-read", session.application_name));
        let read_session = DbSessionConfig {
            application_name: read_session_name,
            ..session.clone()
        };
        let cache = CacheConfig::from_env();

        Self {
            database_url,
            read_database_url,
            listen_addr,
            grpc_addr,
            write_pool,
            read_pool,
            session,
            read_session,
            cache,
        }
    }
}

async fn build_pg_pool(
    url: &str,
    pool_config: &DbPoolConfig,
    session_config: &DbSessionConfig,
) -> anyhow::Result<sqlx::PgPool> {
    let mut options = PgPoolOptions::new()
        .max_connections(pool_config.max_connections)
        .min_connections(pool_config.min_connections);

    if let Some(ms) = pool_config.acquire_timeout_ms {
        options = options.acquire_timeout(Duration::from_millis(ms));
    }
    if let Some(secs) = pool_config.idle_timeout_secs {
        options = options.idle_timeout(Some(Duration::from_secs(secs)));
    }
    if let Some(secs) = pool_config.max_lifetime_secs {
        options = options.max_lifetime(Some(Duration::from_secs(secs)));
    }

    let session_config = session_config.clone();
    options = options.after_connect(move |conn, _meta| {
        let session_config = session_config.clone();
        Box::pin(async move {
            sqlx::query("SELECT set_config('application_name', $1, false)")
                .bind(&session_config.application_name)
                .execute(&mut *conn)
                .await?;

            if let Some(ms) = session_config.statement_timeout_ms {
                sqlx::query("SELECT set_config('statement_timeout', $1, false)")
                    .bind(format!("{ms}"))
                    .execute(&mut *conn)
                    .await?;
            }

            if let Some(ms) = session_config.idle_in_tx_timeout_ms {
                sqlx::query("SELECT set_config('idle_in_transaction_session_timeout', $1, false)")
                    .bind(format!("{ms}"))
                    .execute(&mut *conn)
                    .await?;
            }

            if let Some(ms) = session_config.lock_timeout_ms {
                sqlx::query("SELECT set_config('lock_timeout', $1, false)")
                    .bind(format!("{ms}"))
                    .execute(&mut *conn)
                    .await?;
            }

            Ok(())
        })
    });

    Ok(options.connect(url).await?)
}

/// Application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    pub sequencer: Arc<PgSequencer>,
    pub event_store: Arc<PgEventStore>,
    pub commitment_engine: Arc<PgCommitmentEngine>,
    pub commitment_reader: Arc<PgCommitmentEngine>,
    pub ves_commitment_engine: Arc<PgVesCommitmentEngine>,
    pub ves_commitment_reader: Arc<PgVesCommitmentEngine>,
    pub ves_validity_proof_store: Arc<PgVesValidityProofStore>,
    pub ves_compliance_proof_store: Arc<PgVesComplianceProofStore>,
    pub anchor_service: Option<Arc<AnchorService>>,
    pub ves_sequencer: Arc<VesSequencer<PgAgentKeyRegistry>>,
    pub ves_sequencer_reader: Arc<VesSequencer<PgAgentKeyRegistry>>,
    pub agent_key_registry: Arc<PgAgentKeyRegistry>,
    pub schema_store: Arc<PgSchemaStore>,
    pub metrics: Arc<MetricsRegistry>,
    pub cache_manager: Arc<CacheManager>,
    /// x402 payment repository
    pub x402_repository: Arc<PgX402Repository>,
    /// Schema validation mode for event ingestion
    pub schema_validation_mode: SchemaValidationMode,
    /// Request limits for ingestion and payload sizing
    pub request_limits: RequestLimits,
    /// Connection pool health monitor
    pub pool_monitor: Option<Arc<PoolMonitor>>,
    /// Circuit breaker registry for external service calls
    pub circuit_breaker_registry: Option<Arc<CircuitBreakerRegistry>>,
    /// API key validator (in-memory, for fast validation)
    pub api_key_validator: Arc<ApiKeyValidator>,
    /// API key store (database-backed, for persistence)
    pub api_key_store: Arc<PgApiKeyStore>,
    /// Public agent registration enabled
    pub public_registration_enabled: bool,
    /// Public registration rate limiter (per IP or fallback key)
    pub public_registration_limiter: Option<Arc<RateLimiter>>,
    /// Optional audit logger
    pub audit_logger: Option<Arc<PgAuditLogger>>,
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
    let mut bootstrap_record: Option<ApiKeyRecord> = None;

    if let Ok(bootstrap_key) = std::env::var("BOOTSTRAP_ADMIN_API_KEY") {
        let key_hash = ApiKeyValidator::hash_key(&bootstrap_key);
        let record = ApiKeyRecord {
            key_hash,
            tenant_id: Uuid::nil(),
            store_ids: vec![],
            permissions: Permissions::admin(),
            agent_id: None,
            active: true,
            rate_limit: None,
        };
        api_key_validator.register_key(record.clone());
        bootstrap_record = Some(record);
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

    let rate_limiter = std::env::var("RATE_LIMIT_PER_MINUTE")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .map(|rpm| Arc::new(RateLimiter::new(rpm)));

    let public_registration_enabled = std::env::var("PUBLIC_AGENT_REGISTRATION_ENABLED")
        .ok()
        .map(|v| {
            !matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "off"
            )
        })
        .unwrap_or(true);

    let public_registration_limiter = std::env::var("PUBLIC_AGENT_REGISTRATION_RATE_LIMIT_PER_MINUTE")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .map(|rpm| {
            let mut config = RateLimiterConfig {
                requests_per_minute: rpm,
                ..Default::default()
            };
            if let Some(max_entries) = std::env::var("PUBLIC_AGENT_REGISTRATION_MAX_ENTRIES")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
            {
                config.max_entries = max_entries;
            }
            if let Some(window_seconds) = std::env::var("PUBLIC_AGENT_REGISTRATION_WINDOW_SECONDS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
            {
                config.window_seconds = window_seconds;
            }
            Arc::new(RateLimiter::with_config(config))
        });

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
    info!("  HTTP listen address: {}", config.listen_addr);
    if let Some(grpc_addr) = config.grpc_addr {
        info!("  gRPC listen address: {}", grpc_addr);
    } else {
        info!("  gRPC server: disabled");
    }
    info!(
        "  Write pool: max_connections={}, min_connections={}",
        config.write_pool.max_connections, config.write_pool.min_connections
    );
    if config.read_database_url.is_some() {
        info!(
            "  Read pool: max_connections={}, min_connections={}",
            config.read_pool.max_connections, config.read_pool.min_connections
        );
    } else {
        info!("  Read pool: using primary");
    }
    info!(
        "  Cache: commitments max={} ttl={}s, proofs max={} ttl={}s, ves_commitments max={} ttl={}s, ves_proofs max={} ttl={}s",
        config.cache.commitment_max,
        config.cache.commitment_ttl_secs,
        config.cache.proof_max,
        config.cache.proof_ttl_secs,
        config.cache.ves_commitment_max,
        config.cache.ves_commitment_ttl_secs,
        config.cache.ves_proof_max,
        config.cache.ves_proof_ttl_secs
    );

    // Connect to PostgreSQL
    info!("Connecting to PostgreSQL (primary)...");
    let pool = build_pg_pool(&config.database_url, &config.write_pool, &config.session).await?;
    info!("Connected to PostgreSQL (primary)");

    let read_pool = match &config.read_database_url {
        Some(read_url) => {
            info!("Connecting to PostgreSQL (read replica)...");
            let read_pool =
                build_pg_pool(read_url, &config.read_pool, &config.read_session).await?;
            info!("Connected to PostgreSQL (read replica)");
            read_pool
        }
        None => pool.clone(),
    };

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

    let api_key_store = Arc::new(PgApiKeyStore::new(pool.clone()));
    if let Some(record) = &bootstrap_record {
        api_key_store
            .store(record)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to persist bootstrap API key: {e}"))?;
    }
    match api_key_store.has_any_active().await {
        Ok(true) => {
            any_auth_configured = true;
            info!("Active API keys detected in database");
        }
        Ok(false) => {}
        Err(e) => {
            warn!("Failed to check API key store: {}", e);
        }
    }

    if require_auth && !any_auth_configured {
        anyhow::bail!(
            "AUTH_MODE=required but no auth is configured; set JWT_SECRET or BOOTSTRAP_ADMIN_API_KEY (or set AUTH_MODE=disabled for local dev)"
        );
    }

    let audit_enabled = std::env::var("AUDIT_LOG_ENABLED")
        .ok()
        .map(|v| {
            !matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "off"
            )
        })
        .unwrap_or(true);

    let audit_logger = if audit_enabled {
        let logger = Arc::new(PgAuditLogger::new(pool.clone()));
        if let Err(e) = logger.initialize().await {
            warn!("Failed to initialize audit log table: {}", e);
        } else {
            info!("Audit logging enabled");
        }
        Some(logger)
    } else {
        info!("Audit logging disabled");
        None
    };

    let authenticator = {
        let authenticator = Authenticator::new(api_key_validator.clone())
            .with_api_key_store(api_key_store.clone());
        match jwt_validator {
            Some(jwt) => Arc::new(authenticator.with_jwt(jwt)),
            None => Arc::new(authenticator),
        }
    };

    let auth_state = AuthMiddlewareState {
        authenticator,
        require_auth,
        rate_limiter,
    };

    // Payload encryption-at-rest (legacy `events` table)
    let payload_encryption =
        Arc::new(PayloadEncryption::from_env().map_err(|e| anyhow::anyhow!(e.to_string()))?);
    info!(
        "Payload encryption-at-rest mode: {:?}",
        payload_encryption.mode()
    );

    // Initialize cache manager
    let cache_manager = Arc::new(CacheManager::with_manager_config(
        config.cache.to_manager_config(),
    ));

    // Initialize services
    let sequencer = Arc::new(PgSequencer::new(pool.clone(), payload_encryption.clone()));
    let event_store = Arc::new(PgEventStore::new(read_pool.clone(), payload_encryption.clone()));
    let commitment_engine = Arc::new(PgCommitmentEngine::new(pool.clone()));
    let commitment_reader = Arc::new(PgCommitmentEngine::new(read_pool.clone()));
    let ves_commitment_engine = Arc::new(PgVesCommitmentEngine::new(pool.clone()));
    let ves_commitment_reader = Arc::new(PgVesCommitmentEngine::new(read_pool.clone()));
    let ves_validity_proof_store = Arc::new(PgVesValidityProofStore::new(
        pool.clone(),
        payload_encryption.clone(),
    ));
    let ves_compliance_proof_store = Arc::new(PgVesComplianceProofStore::new(
        pool.clone(),
        payload_encryption,
    ));

    // Initialize VES v1.0 services
    let agent_key_registry = Arc::new(
        PgAgentKeyRegistry::new(pool.clone()).with_cache(cache_manager.agent_keys.clone()),
    );
    let mut ves_sequencer = VesSequencer::new(pool.clone(), agent_key_registry.clone());
    let mut ves_sequencer_reader = VesSequencer::new(read_pool.clone(), agent_key_registry.clone());
    if let Some(sequencer_id) = load_ves_sequencer_id()? {
        info!("VES sequencer id configured: {}", sequencer_id);
        ves_sequencer = ves_sequencer.with_sequencer_id(sequencer_id);
        ves_sequencer_reader = ves_sequencer_reader.with_sequencer_id(sequencer_id);
    } else {
        info!("VES sequencer id not configured (set VES_SEQUENCER_ID to pin)");
    }
    if let Some(signing_key) = load_ves_sequencer_signing_key()? {
        info!("VES sequencer receipt signing enabled");
        ves_sequencer = ves_sequencer.with_signing_key(signing_key.clone());
        ves_sequencer_reader = ves_sequencer_reader.with_signing_key(signing_key);
    } else {
        info!("VES sequencer receipt signing disabled (set VES_SEQUENCER_SIGNING_KEY to enable)");
    }
    let ves_sequencer = Arc::new(ves_sequencer);
    let ves_sequencer_reader = Arc::new(ves_sequencer_reader);

    // Initialize schema registry
    let schema_store = Arc::new(
        PgSchemaStore::new(pool.clone()).with_cache(cache_manager.schemas.clone()),
    );
    schema_store.initialize().await?;
    info!("Schema registry initialized");

    // Initialize x402 payment repository
    let x402_repository = Arc::new(PgX402Repository::new(pool.clone()));
    info!("x402 payment repository initialized");

    // Schema validation mode for event ingestion
    let schema_validation_mode = SchemaValidationMode::from_env();
    info!("Schema validation mode: {}", schema_validation_mode);

    // Initialize metrics registry
    let metrics = Arc::new(MetricsRegistry::new());
    info!("Metrics registry initialized");

    // Initialize pool monitor for health checks
    let pool_monitor = Arc::new(PoolMonitor::new(config.write_pool.max_connections));
    pool_monitor.update_from_pool(&pool).await;
    let _pool_monitor_task = {
        let pool = pool.clone();
        let monitor = pool_monitor.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(15));
            loop {
                interval.tick().await;
                monitor.update_from_pool(&pool).await;
            }
        })
    };
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
        commitment_reader,
        ves_commitment_engine,
        ves_commitment_reader,
        ves_validity_proof_store,
        ves_compliance_proof_store,
        anchor_service,
        ves_sequencer,
        ves_sequencer_reader,
        agent_key_registry,
        schema_store,
        metrics,
        cache_manager,
        x402_repository,
        schema_validation_mode,
        request_limits: request_limits.clone(),
        pool_monitor: Some(pool_monitor),
        circuit_breaker_registry: Some(circuit_breaker_registry),
        api_key_validator: api_key_validator.clone(),
        api_key_store: api_key_store.clone(),
        public_registration_enabled,
        public_registration_limiter,
        audit_logger,
    };

    // Start component metrics collection in background
    let component_metrics = Arc::new(ComponentMetrics::new(
        state.metrics.clone(),
        state.pool_monitor.clone(),
        state.circuit_breaker_registry.clone(),
    ));
    let _metrics_task = component_metrics.start_collection_task(std::time::Duration::from_secs(15));
    info!("Component metrics collection started (15s interval)");

    // Start gRPC server (if enabled) - must happen before build_router consumes auth_state
    let grpc_handle = if let Some(grpc_addr) = config.grpc_addr {
        // Create gRPC services
        let sequencer_v1_service = SequencerService::new(
            state.sequencer.clone(),
            state.event_store.clone(),
            state.commitment_reader.clone(),
            state.commitment_engine.clone(),
            state.cache_manager.clone(),
        );
        let sequencer_v2_service = SequencerServiceV2::new(
            state.ves_sequencer.clone(),
            state.ves_commitment_engine.clone(),
            state.ves_sequencer_reader.clone(),
            state.ves_commitment_reader.clone(),
            state.cache_manager.clone(),
        );
        let key_management_service =
            KeyManagementServiceV2::new(state.agent_key_registry.clone());

        // Create auth interceptor for gRPC
        let grpc_auth_interceptor = GrpcAuthInterceptor::new(
            auth_state.authenticator.clone(),
            auth_state.require_auth,
        );

        let grpc_server = TonicServer::builder()
            .add_service(SequencerServerV1::with_interceptor(
                sequencer_v1_service,
                grpc_auth_interceptor.clone(),
            ))
            .add_service(SequencerServerV2::with_interceptor(
                sequencer_v2_service,
                grpc_auth_interceptor.clone(),
            ))
            .add_service(KeyManagementServer::with_interceptor(
                key_management_service,
                grpc_auth_interceptor,
            ));

        info!("Starting gRPC server on {}", grpc_addr);
        Some(tokio::spawn(async move {
            if let Err(e) = grpc_server.serve(grpc_addr).await {
                tracing::error!("gRPC server error: {}", e);
            }
        }))
    } else {
        None
    };

    // Build HTTP router
    let app = build_router(auth_state)?
        .with_state(state.clone())
        .layer(DefaultBodyLimit::max(request_limits.max_body_size));

    // Start HTTP server
    info!("Starting HTTP server on {}", config.listen_addr);
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;

    info!("StateSet Sequencer is ready to accept connections");

    // Run both servers
    tokio::select! {
        result = axum::serve(listener, app) => {
            if let Err(e) = result {
                tracing::error!("HTTP server error: {}", e);
            }
        }
        _ = async {
            if let Some(handle) = grpc_handle {
                let _ = handle.await;
            } else {
                // If no gRPC server, just wait forever (HTTP server will control)
                std::future::pending::<()>().await;
            }
        } => {}
    }

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
    let public_api = crate::api::public_router();
    let api = crate::api::router().layer(axum::middleware::from_fn_with_state(
        auth_state.clone(),
        crate::auth::auth_middleware,
    ));

    let anchor_compat = crate::api::anchor_compat_router().layer(
        axum::middleware::from_fn_with_state(auth_state, crate::auth::auth_middleware),
    );

    let metrics_router = Router::new()
        .route("/metrics", get(metrics_handler))
        .layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            crate::auth::auth_middleware,
        ));

    let mut router = Router::new()
        .nest("/api", public_api)
        .merge(metrics_router)
        .merge(anchor_compat)
        .nest("/api", api)
        .route("/health", get(crate::api::handlers::health::health_check))
        .route("/health/detailed", get(crate::api::handlers::health::detailed_health_check))
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
    axum::extract::Extension(AuthContextExt(auth)): axum::extract::Extension<AuthContextExt>,
) -> Response {
    if !auth.is_admin() {
        return (StatusCode::FORBIDDEN, "Admin permission required").into_response();
    }

    let metrics = state.metrics.to_prometheus().await;
    (
        [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        metrics,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Extension, State};
    use sqlx::postgres::PgPoolOptions;

    fn build_test_state() -> AppState {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://localhost/postgres")
            .expect("connect_lazy should not require a live database");

        let payload_encryption = Arc::new(PayloadEncryption::disabled());
        let api_key_validator = Arc::new(ApiKeyValidator::new());
        let api_key_store = Arc::new(PgApiKeyStore::new(pool.clone()));

        let sequencer = Arc::new(PgSequencer::new(pool.clone(), payload_encryption.clone()));
        let event_store = Arc::new(PgEventStore::new(pool.clone(), payload_encryption.clone()));
        let commitment_engine = Arc::new(PgCommitmentEngine::new(pool.clone()));
        let commitment_reader = Arc::new(PgCommitmentEngine::new(pool.clone()));
        let ves_commitment_engine = Arc::new(PgVesCommitmentEngine::new(pool.clone()));
        let ves_commitment_reader = Arc::new(PgVesCommitmentEngine::new(pool.clone()));
        let ves_validity_proof_store = Arc::new(PgVesValidityProofStore::new(
            pool.clone(),
            payload_encryption.clone(),
        ));
        let ves_compliance_proof_store = Arc::new(PgVesComplianceProofStore::new(
            pool.clone(),
            payload_encryption,
        ));

        let cache_manager = Arc::new(CacheManager::new());
        let agent_key_registry = Arc::new(PgAgentKeyRegistry::new(pool.clone()));
        let ves_sequencer = Arc::new(VesSequencer::new(pool.clone(), agent_key_registry.clone()));
        let ves_sequencer_reader =
            Arc::new(VesSequencer::new(pool.clone(), agent_key_registry.clone()));
        let schema_store = Arc::new(PgSchemaStore::new(pool.clone()));
        let x402_repository = Arc::new(PgX402Repository::new(pool.clone()));
        let metrics = Arc::new(MetricsRegistry::new());

        AppState {
            sequencer,
            event_store,
            commitment_engine,
            commitment_reader,
            ves_commitment_engine,
            ves_commitment_reader,
            ves_validity_proof_store,
            ves_compliance_proof_store,
            anchor_service: None,
            ves_sequencer,
            ves_sequencer_reader,
            agent_key_registry,
            schema_store,
            metrics,
            cache_manager,
            x402_repository,
            schema_validation_mode: SchemaValidationMode::Disabled,
            request_limits: RequestLimits::default(),
            pool_monitor: None,
            circuit_breaker_registry: None,
            api_key_validator,
            api_key_store,
            public_registration_enabled: true,
            public_registration_limiter: None,
            audit_logger: None,
        }
    }

    #[tokio::test]
    async fn metrics_requires_admin() {
        let state = build_test_state();

        let user_ctx = crate::auth::AuthContext {
            tenant_id: Uuid::new_v4(),
            store_ids: Vec::new(),
            agent_id: None,
            permissions: Permissions::read_only(),
        };
        let response = metrics_handler(State(state.clone()), Extension(AuthContextExt(user_ctx)))
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let admin_ctx = crate::auth::AuthContext {
            tenant_id: Uuid::nil(),
            store_ids: Vec::new(),
            agent_id: None,
            permissions: Permissions::admin(),
        };
        let response = metrics_handler(State(state), Extension(AuthContextExt(admin_ctx))).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}
