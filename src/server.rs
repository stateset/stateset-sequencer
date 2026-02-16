//! HTTP and gRPC server bootstrap for StateSet Sequencer.
//!
//! This module wires together:
//! - configuration
//! - database connection pool
//! - core services (sequencer, event store, commitment engine, VES sequencer)
//! - the Axum HTTP router
//! - the Tonic gRPC server (v1 and v2 APIs)

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{ConnectInfo, DefaultBodyLimit, MatchedPath, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use ipnet::IpNet;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tonic::transport::Server as TonicServer;
use tower_http::cors::AllowOrigin;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn, Level};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};
use uuid::Uuid;

use crate::grpc::{
    GrpcAuthInterceptor, KeyManagementServiceV2, SequencerService, SequencerServiceV2,
};
use crate::proto::sequencer_server::SequencerServer as SequencerServerV1;
use crate::proto::v2::key_management_server::KeyManagementServer;
use crate::proto::v2::sequencer_server::SequencerServer as SequencerServerV2;

use crate::anchor::{AnchorConfig, AnchorService};
use crate::auth::{
    ApiKeyRecord, ApiKeyStore, ApiKeyValidator, AuthContextExt, AuthMiddlewareState, Authenticator,
    JwtValidator, Permissions, PgApiKeyStore, RateLimiter, RateLimiterConfig, RequestLimits,
};
use crate::crypto::{secret_key_from_str, AgentSigningKey};
use crate::infra::ShutdownCoordinator;
use crate::infra::{
    extract_client_ip, BatchWorkerMessage, CacheManager, CacheManagerConfig,
    CircuitBreakerRegistry, EnvSecretsProvider, PayloadEncryption, PgAgentKeyRegistry, PgAuditLogger,
    PgCommitmentEngine, PgEventStore, PgSchemaStore, PgSequencer, PgVesCommitmentEngine,
    PgVesComplianceProofStore, PgVesValidityProofStore, PgX402Repository, PoolMonitor,
    SchemaValidationMode, SecretsProvider, VesSequencer, X402BatchWorkerConfig, spawn_batch_worker,
};
use crate::metrics::{ComponentMetrics, MetricsRegistry};

/// Interval for pool health monitoring and component metrics collection.
const MONITORING_INTERVAL: Duration = Duration::from_secs(15);

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

/// Default statement timeout (30 seconds) — prevents runaway queries.
const DEFAULT_STATEMENT_TIMEOUT_MS: u64 = 30_000;
/// Default idle-in-transaction timeout (60 seconds) — prevents long-held connections.
const DEFAULT_IDLE_IN_TX_TIMEOUT_MS: u64 = 60_000;
/// Default lock timeout (10 seconds) — prevents lock contention deadlocks.
const DEFAULT_LOCK_TIMEOUT_MS: u64 = 10_000;
/// Default HTTP request timeout (30 seconds).
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

impl DbSessionConfig {
    fn from_env() -> Self {
        let statement_timeout_ms = Some(
            std::env::var("DB_STATEMENT_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_STATEMENT_TIMEOUT_MS),
        );

        let idle_in_tx_timeout_ms = Some(
            std::env::var("DB_IDLE_IN_TX_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_IDLE_IN_TX_TIMEOUT_MS),
        );

        let lock_timeout_ms = Some(
            std::env::var("DB_LOCK_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_LOCK_TIMEOUT_MS),
        );

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
        let commitment_ttl_secs = read_u64_env(
            "CACHE_COMMITMENT_TTL_SECS",
            defaults.commitment_ttl.as_secs(),
        );

        let proof_max = read_usize_env("CACHE_PROOF_MAX", defaults.proof_max);
        let proof_ttl_secs = read_u64_env("CACHE_PROOF_TTL_SECS", defaults.proof_ttl.as_secs());

        let ves_commitment_max = read_usize_env("CACHE_VES_COMMITMENT_MAX", commitment_max);
        let ves_commitment_ttl_secs =
            read_u64_env("CACHE_VES_COMMITMENT_TTL_SECS", commitment_ttl_secs);

        let ves_proof_max = read_usize_env("CACHE_VES_PROOF_MAX", proof_max);
        let ves_proof_ttl_secs = read_u64_env("CACHE_VES_PROOF_TTL_SECS", proof_ttl_secs);

        let agent_key_max = read_usize_env("CACHE_AGENT_KEY_MAX", defaults.agent_key_max);
        let agent_key_ttl_secs =
            read_u64_env("CACHE_AGENT_KEY_TTL_SECS", defaults.agent_key_ttl.as_secs());

        let schema_max = read_usize_env("CACHE_SCHEMA_MAX", defaults.schema_max);
        let schema_ttl_secs = read_u64_env("CACHE_SCHEMA_TTL_SECS", defaults.schema_ttl.as_secs());

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

#[derive(Debug, Clone, Copy)]
enum AuthMode {
    Required,
    Disabled,
}

fn parse_auth_mode() -> anyhow::Result<AuthMode> {
    let auth_mode = std::env::var("AUTH_MODE").unwrap_or_else(|_| "required".to_string());
    match auth_mode.trim().to_lowercase().as_str() {
        "required" => Ok(AuthMode::Required),
        "disabled" => Ok(AuthMode::Disabled),
        _ => Err(anyhow::anyhow!(
            "Invalid AUTH_MODE value: {auth_mode}; expected required or disabled"
        )),
    }
}

fn parse_truthy_env(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "on" | "yes"
            )
        })
        .unwrap_or(false)
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
    pub fn from_env() -> anyhow::Result<Self> {
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
            .map_err(|e| anyhow::anyhow!("Invalid listen address '{host}:{port}': {e}"))?;

        // gRPC port configuration (defaults to HTTP port + 1, e.g., 8081 if HTTP is 8080)
        let grpc_addr: Option<SocketAddr> =
            if std::env::var("GRPC_DISABLED").is_ok() {
                None
            } else {
                let grpc_port: u16 = std::env::var("GRPC_PORT")
                    .ok()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(port + 1);
                Some(format!("{host}:{grpc_port}").parse().map_err(|e| {
                    anyhow::anyhow!("Invalid gRPC address '{host}:{grpc_port}': {e}")
                })?)
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

        Ok(Self {
            database_url,
            read_database_url,
            listen_addr,
            grpc_addr,
            write_pool,
            read_pool,
            session,
            read_session,
            cache,
        })
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
    pub read_pool: PgPool,
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
    /// Whether to trust proxy headers for client IP extraction
    pub trust_proxy_headers: bool,
    /// Optional audit logger
    pub audit_logger: Option<Arc<PgAuditLogger>>,
}

#[derive(Debug, Clone)]
enum AllowedIp {
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
struct AdminAccessState {
    allowlist: Option<Arc<Vec<AllowedIp>>>,
    trust_proxy_headers: bool,
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

fn parse_admin_allowlist() -> anyhow::Result<Option<Arc<Vec<AllowedIp>>>> {
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

/// Start the HTTP server.
pub async fn run() -> anyhow::Result<()> {
    init_tracing();

    info!("Starting StateSet Sequencer v{}", env!("CARGO_PKG_VERSION"));

    // Initialize shutdown coordinator for background task lifecycle
    let shutdown_coordinator = Arc::new(ShutdownCoordinator::new());

    // Initialize secrets provider (swap implementation for Vault/KMS/HSM)
    let secrets: Box<dyn SecretsProvider> = Box::new(EnvSecretsProvider::new());

    // Auth configuration
    let auth_mode = parse_auth_mode()?;
    let allow_auth_disabled = parse_truthy_env("ALLOW_AUTH_DISABLED");
    let require_auth = match auth_mode {
        AuthMode::Required => true,
        AuthMode::Disabled if !allow_auth_disabled => {
            anyhow::bail!(
                "AUTH_MODE=disabled requires explicit opt-in via ALLOW_AUTH_DISABLED=true"
            );
        }
        AuthMode::Disabled => {
            info!(
                "AUTH_MODE=disabled is enabled via ALLOW_AUTH_DISABLED=true; authentication checks are skipped"
            );
            false
        }
    };

    let api_key_validator = Arc::new(ApiKeyValidator::new());
    let mut any_auth_configured = false;
    let mut bootstrap_record: Option<ApiKeyRecord> = None;

    if let Some(bootstrap_key) = secrets
        .bootstrap_api_key()
        .map_err(|e| anyhow::anyhow!("Failed to load bootstrap API key: {e}"))?
    {
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

    let jwt_validator = match secrets
        .jwt_secret()
        .map_err(|e| anyhow::anyhow!("Failed to load JWT secret: {e}"))?
    {
        Some(secret) => {
            let issuer = secrets
                .jwt_issuer()
                .map_err(|e| anyhow::anyhow!("Failed to load JWT issuer: {e}"))?;
            let audience = secrets
                .jwt_audience()
                .map_err(|e| anyhow::anyhow!("Failed to load JWT audience: {e}"))?;
            any_auth_configured = true;
            Some(Arc::new(JwtValidator::new(
                secret.as_bytes(),
                &issuer,
                &audience,
            )))
        }
        None => None,
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

    let public_registration_limiter =
        std::env::var("PUBLIC_AGENT_REGISTRATION_RATE_LIMIT_PER_MINUTE")
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
                if let Some(window_seconds) =
                    std::env::var("PUBLIC_AGENT_REGISTRATION_WINDOW_SECONDS")
                        .ok()
                        .and_then(|v| v.parse::<u64>().ok())
                {
                    config.window_seconds = window_seconds;
                }
                Arc::new(RateLimiter::with_config(config))
            });

    let trust_proxy_headers = std::env::var("TRUST_PROXY_HEADERS")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "on" | "yes"
            )
        })
        .unwrap_or(false);

    let admin_allowlist = parse_admin_allowlist()?;
    if let Some(list) = &admin_allowlist {
        info!("Admin IP allowlist enabled ({} entries)", list.len());
    }

    let request_limits = RequestLimits::from_env();
    info!(
        "Request limits: max_body_size={} bytes, max_events_per_batch={}, max_event_payload_size={} bytes",
        request_limits.max_body_size,
        request_limits.max_events_per_batch,
        request_limits.max_event_payload_size
    );

    // Load configuration
    let config = Config::from_env()?;
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
            "AUTH_MODE=required but no auth is configured; set JWT_SECRET or BOOTSTRAP_ADMIN_API_KEY (or set AUTH_MODE=disabled and ALLOW_AUTH_DISABLED=true for local dev)"
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
        let authenticator =
            Authenticator::new(api_key_validator.clone()).with_api_key_store(api_key_store.clone());
        match jwt_validator {
            Some(jwt) => Arc::new(authenticator.with_jwt(jwt)),
            None => Arc::new(authenticator),
        }
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
    let event_store = Arc::new(PgEventStore::new(
        read_pool.clone(),
        payload_encryption.clone(),
    ));
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
    if let Some(sequencer_id) = load_ves_sequencer_id(secrets.as_ref())? {
        info!("VES sequencer id configured: {}", sequencer_id);
        ves_sequencer = ves_sequencer.with_sequencer_id(sequencer_id);
        ves_sequencer_reader = ves_sequencer_reader.with_sequencer_id(sequencer_id);
    } else {
        info!("VES sequencer id not configured (set VES_SEQUENCER_ID to pin)");
    }
    if let Some(signing_key) = load_ves_sequencer_signing_key(secrets.as_ref())? {
        info!("VES sequencer receipt signing enabled");
        ves_sequencer = ves_sequencer.with_signing_key(signing_key.clone());
        ves_sequencer_reader = ves_sequencer_reader.with_signing_key(signing_key);
    } else {
        info!("VES sequencer receipt signing disabled (set VES_SEQUENCER_SIGNING_KEY to enable)");
    }
    let ves_sequencer = Arc::new(ves_sequencer);
    let ves_sequencer_reader = Arc::new(ves_sequencer_reader);

    // Initialize schema registry
    let schema_store =
        Arc::new(PgSchemaStore::new(pool.clone()).with_cache(cache_manager.schemas.clone()));
    schema_store.initialize().await?;
    info!("Schema registry initialized");

    // Initialize x402 payment repository
    let x402_repository = Arc::new(PgX402Repository::new(pool.clone()));
    info!("x402 payment repository initialized");

    // Start x402 batch worker
    let (x402_batch_worker_task, x402_batch_worker_control) =
        spawn_batch_worker(X402BatchWorkerConfig::from_env(), x402_repository.clone());
    let mut batch_worker_shutdown = shutdown_coordinator.signal();
    tokio::spawn(async move {
        batch_worker_shutdown.wait().await;
        let _ = x402_batch_worker_control
            .send(BatchWorkerMessage::Shutdown)
            .await;
        let _ = x402_batch_worker_task.await;
    });
    info!("x402 batch worker started");

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
        let signal = shutdown_coordinator.signal();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(MONITORING_INTERVAL);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        monitor.update_from_pool(&pool).await;
                    }
                    _ = signal.wait() => {
                        info!("Pool monitor task stopping due to shutdown");
                        break;
                    }
                }
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

    let auth_state = AuthMiddlewareState {
        authenticator,
        require_auth,
        rate_limiter,
        pool_monitor: Some(pool_monitor.clone()),
    };

    // Create application state
    let state = AppState {
        read_pool: read_pool.clone(),
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
        trust_proxy_headers,
        audit_logger,
    };

    // Start component metrics collection in background
    let component_metrics = Arc::new(ComponentMetrics::new(
        state.metrics.clone(),
        state.pool_monitor.clone(),
        state.circuit_breaker_registry.clone(),
    ));
    let _metrics_task = component_metrics
        .start_collection_task(MONITORING_INTERVAL, Some(shutdown_coordinator.signal()));
    info!(
        "Component metrics collection started ({}s interval)",
        MONITORING_INTERVAL.as_secs()
    );

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
        let key_management_service = KeyManagementServiceV2::new(state.agent_key_registry.clone());

        // Create auth interceptor for gRPC (with shared rate limiter)
        let grpc_auth_interceptor = GrpcAuthInterceptor::new(
            auth_state.authenticator.clone(),
            auth_state.require_auth,
            auth_state.rate_limiter.clone(),
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
        let grpc_shutdown = shutdown_coordinator.signal();
        Some(tokio::spawn(async move {
            if let Err(e) = grpc_server
                .serve_with_shutdown(grpc_addr, grpc_shutdown.wait())
                .await
            {
                tracing::error!("gRPC server error: {}", e);
            }
            info!("gRPC server shut down gracefully");
        }))
    } else {
        None
    };

    let admin_access_state = AdminAccessState {
        allowlist: admin_allowlist,
        trust_proxy_headers,
    };

    // Build HTTP router
    let request_timeout = Duration::from_secs(
        std::env::var("REQUEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_REQUEST_TIMEOUT_SECS),
    );
    let app = build_router(auth_state, admin_access_state)?
        .with_state(state.clone())
        .layer(DefaultBodyLimit::max(request_limits.max_body_size))
        .layer(tower_http::compression::CompressionLayer::new())
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            request_timeout,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.metrics.clone(),
            http_metrics_middleware,
        ))
        .layer(axum::middleware::from_fn(request_id_middleware));

    // Start HTTP server
    info!("Starting HTTP server on {}", config.listen_addr);
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;

    info!("StateSet Sequencer is ready to accept connections");

    // Run both servers with coordinated shutdown
    let http_shutdown = shutdown_coordinator.signal();
    tokio::select! {
        result = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(async move { http_shutdown.wait().await }) => {
            if let Err(e) = result {
                tracing::error!("HTTP server error: {}", e);
            }
            info!("HTTP server shut down gracefully");
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
                eprintln!(
                    "Failed to initialize OpenTelemetry: {e}. Falling back to basic tracing."
                );
            }
        }
    }

    // Fallback: basic tracing without OpenTelemetry
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .init();
}

fn load_ves_sequencer_signing_key(
    secrets: &dyn SecretsProvider,
) -> anyhow::Result<Option<AgentSigningKey>> {
    let key_value = match secrets
        .ves_sequencer_signing_key()
        .map_err(|e| anyhow::anyhow!("failed to load VES_SEQUENCER_SIGNING_KEY: {e}"))?
    {
        Some(value) => value,
        None => return Ok(None),
    };

    let secret = secret_key_from_str(&key_value)
        .map_err(|e| anyhow::anyhow!("invalid VES_SEQUENCER_SIGNING_KEY: {e}"))?;
    let signing_key = AgentSigningKey::from_bytes(&secret)
        .map_err(|e| anyhow::anyhow!("invalid VES_SEQUENCER_SIGNING_KEY: {e}"))?;

    Ok(Some(signing_key))
}

fn load_ves_sequencer_id(secrets: &dyn SecretsProvider) -> anyhow::Result<Option<Uuid>> {
    let value = match secrets
        .ves_sequencer_id()
        .map_err(|e| anyhow::anyhow!("failed to load VES_SEQUENCER_ID: {e}"))?
    {
        Some(value) => value,
        None => return Ok(None),
    };

    let id = Uuid::parse_str(value.trim())
        .map_err(|e| anyhow::anyhow!("invalid VES_SEQUENCER_ID: {e}"))?;
    Ok(Some(id))
}

/// Initialize OpenTelemetry tracer with OTLP exporter
fn init_opentelemetry_tracer(
) -> Result<opentelemetry_sdk::trace::Tracer, opentelemetry::trace::TraceError> {
    use opentelemetry::trace::TracerProvider;
    use opentelemetry_otlp::WithExportConfig;

    let exporter = opentelemetry_otlp::new_exporter().tonic().with_endpoint(
        std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:4317".to_string()),
    );

    let provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(opentelemetry_sdk::trace::Config::default().with_resource(
            opentelemetry_sdk::Resource::new(vec![
                opentelemetry::KeyValue::new("service.name", "stateset-sequencer"),
                opentelemetry::KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
            ]),
        ))
        .install_batch(opentelemetry_sdk::runtime::Tokio)?;

    Ok(provider.tracer("stateset-sequencer"))
}

fn build_router(
    auth_state: AuthMiddlewareState,
    admin_access_state: AdminAccessState,
) -> anyhow::Result<Router<AppState>> {
    let public_api = crate::api::public_router();
    let public_api_root = crate::api::public_router();
    let admin_allowlist_layer =
        axum::middleware::from_fn_with_state(admin_access_state, admin_ip_allowlist_middleware);
    let api = crate::api::router().layer(axum::middleware::from_fn_with_state(
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
            auth_state,
            crate::auth::auth_middleware,
        ))
        .layer(admin_allowlist_layer.clone());

    let admin_dashboard = Router::new()
        .route("/admin", get(crate::api::handlers::admin::admin_dashboard))
        .route("/admin/", get(crate::api::handlers::admin::admin_dashboard))
        .layer(admin_allowlist_layer.clone());

    let mut router = Router::new()
        .nest("/api", public_api)
        .merge(public_api_root)
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

fn normalize_metrics_path(path: &str) -> String {
    if path == "/" {
        return "/".to_string();
    }

    let normalized: Vec<String> = path
        .trim_start_matches('/')
        .split('/')
        .map(|segment| {
            if looks_like_uuid(segment) {
                ":id".to_string()
            } else {
                segment.to_string()
            }
        })
        .collect();

    format!("/{}", normalized.join("/"))
}

fn looks_like_uuid(segment: &str) -> bool {
    if segment.len() != 36 {
        return false;
    }

    let mut dash_count = 0;
    for ch in segment.chars() {
        if ch == '-' {
            dash_count += 1;
            continue;
        }
        if !ch.is_ascii_hexdigit() {
            return false;
        }
    }

    dash_count == 4
}

/// Middleware that extracts or generates a request ID and adds it to the
/// tracing span and response headers for cross-service correlation.
async fn request_id_middleware(mut req: Request<Body>, next: Next) -> Response {
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

async fn http_metrics_middleware(
    State(metrics): State<Arc<MetricsRegistry>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let method = req.method().as_str().to_string();
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| normalize_metrics_path(req.uri().path()));

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
    use sqlx::postgres::PgPoolOptions;
    use std::net::{IpAddr, SocketAddr};
    use tower::ServiceExt;

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
            read_pool: pool.clone(),
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
            trust_proxy_headers: false,
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
        let response =
            metrics_handler(State(state.clone()), Extension(AuthContextExt(user_ctx))).await;
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
}
