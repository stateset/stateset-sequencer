//! HTTP and gRPC server bootstrap for StateSet Sequencer.
//!
//! This module wires together:
//! - configuration ([`config`])
//! - database connection pools ([`config`])
//! - core services (sequencer, event store, commitment engine, VES sequencer)
//! - the Axum HTTP router ([`router`])
//! - the Tonic gRPC server (v1 and v2 APIs) ([`grpc`])
//! - background worker supervision ([`workers`])
//!
//! Shared handler state lives in [`state`].

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use tracing::{info, warn, Level};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};
use uuid::Uuid;

use crate::anchor::{AnchorConfig, AnchorService};
use crate::auth::{
    ApiKeyRecord, ApiKeyStore, ApiKeyValidator, AuthMiddlewareState, Authenticator, JwtValidator,
    Permissions, PgApiKeyStore, RateLimiter, RateLimiterConfig, RequestLimits,
};
use crate::infra::ShutdownCoordinator;
use crate::infra::{
    lock_keys, spawn_anchor_worker, spawn_batch_worker, spawn_elected_worker,
    spawn_projection_worker, spawn_settlement_worker, spawn_x402_nonce_cleanup,
    validate_trusted_proxy_allowlist, AnchorWorkerConfig, AnchorWorkerMessage, BatchWorkerMessage,
    CacheManager, CircuitBreakerRegistry, ElectionConfig, EnvSecretsProvider, PayloadEncryption,
    PgAgentKeyRegistry, PgAuditLogger, PgCommitmentEngine, PgEventStore, PgSchemaStore,
    PgSequencer, PgVesCommitmentEngine, PgVesComplianceProofStore, PgVesValidityProofStore,
    PgX402Repository, PoolMonitor, ProjectionWorkerConfig, ProjectionWorkerMessage,
    SchemaValidationMode, SecretsProvider, SettlementWorkerConfig, SettlementWorkerMessage,
    VesSequencer, X402BatchWorkerConfig,
};
#[cfg(feature = "stark")]
use crate::infra::{spawn_proof_worker, ProofWorkerConfig, ProofWorkerMessage};
use crate::metrics::{ComponentMetrics, MetricsRegistry};
use crate::settlement::{SettlementConfig, SettlementService};

mod config;
mod grpc;
mod router;
mod state;
mod workers;

pub use config::{CacheConfig, Config, DbPoolConfig, DbSessionConfig};
pub use router::RequestId;
pub use state::AppState;

use self::config::{
    connect_with_retry, enforce_secret_strength, is_production_env, load_ves_security_profile,
    load_ves_sequencer_id, load_ves_sequencer_signing_key, load_ves_signing_config,
    parse_auth_mode, parse_bool_env, parse_optional_positive_u32, parse_optional_positive_u64,
    parse_optional_positive_usize, parse_positive_u64_env, AuthMode, DEFAULT_REQUEST_TIMEOUT_SECS,
    MIN_SECRET_LEN, MONITORING_INTERVAL,
};
use self::router::{
    build_router, http_metrics_middleware, parse_admin_allowlist, request_id_middleware,
    AdminAccessState,
};
use self::workers::supervise_worker;

/// Start the HTTP server.
pub async fn run() -> anyhow::Result<()> {
    init_tracing();

    info!("Starting StateSet Sequencer v{}", env!("CARGO_PKG_VERSION"));

    // Initialize shutdown coordinator for background task lifecycle
    let shutdown_coordinator = Arc::new(ShutdownCoordinator::new());

    // Initialize secrets provider (swap implementation for Vault/KMS/HSM)
    let secrets: Box<dyn SecretsProvider> = Box::new(EnvSecretsProvider::new());

    // Auth configuration
    let is_production = is_production_env();
    let receipt_signing_key = load_ves_sequencer_signing_key(secrets.as_ref())?;
    if is_production && receipt_signing_key.is_none() {
        anyhow::bail!(
            "VES_SEQUENCER_SIGNING_KEY is required in production; unsigned VES receipts cannot be verified"
        );
    }
    let auth_mode = parse_auth_mode()?;
    let allow_auth_disabled = parse_bool_env("ALLOW_AUTH_DISABLED", false)?;
    let require_auth = match auth_mode {
        AuthMode::Required => true,
        AuthMode::Disabled if is_production => {
            anyhow::bail!(
                "AUTH_MODE=disabled is refused in production (SEQUENCER_ENV/ENVIRONMENT); \
                 authentication cannot be skipped on a production deployment"
            );
        }
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
        enforce_secret_strength(
            "BOOTSTRAP_ADMIN_API_KEY",
            &bootstrap_key,
            MIN_SECRET_LEN,
            is_production,
        )?;
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

    let jwt_secret = secrets
        .jwt_secret()
        .map_err(|e| anyhow::anyhow!("Failed to load JWT secret: {e}"))?;
    let jwt_jwks_json = secrets
        .jwt_jwks_json()
        .map_err(|e| anyhow::anyhow!("Failed to load JWT JWKS: {e}"))?;
    let jwt_jwks_url = match std::env::var("JWT_JWKS_URL") {
        Ok(value) if !value.trim().is_empty() => Some(value.trim().to_string()),
        Ok(_) | Err(std::env::VarError::NotPresent) => None,
        Err(e) => anyhow::bail!("JWT_JWKS_URL is not valid Unicode: {e}"),
    };
    if [
        jwt_secret.is_some(),
        jwt_jwks_json.is_some(),
        jwt_jwks_url.is_some(),
    ]
    .into_iter()
    .filter(|configured| *configured)
    .count()
        > 1
    {
        anyhow::bail!("JWT_SECRET, JWT_JWKS_JSON, and JWT_JWKS_URL are mutually exclusive");
    }
    let jwt_validator = match (jwt_secret, jwt_jwks_json, jwt_jwks_url) {
        (Some(secret), None, None) => {
            enforce_secret_strength("JWT_SECRET", &secret, MIN_SECRET_LEN, is_production)?;
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
        (None, Some(jwks_json), None) => {
            let issuer = secrets
                .jwt_issuer()
                .map_err(|e| anyhow::anyhow!("Failed to load JWT issuer: {e}"))?;
            let audience = secrets
                .jwt_audience()
                .map_err(|e| anyhow::anyhow!("Failed to load JWT audience: {e}"))?;
            let validator = JwtValidator::from_jwks_json(&jwks_json, &issuer, &audience)
                .map_err(|e| anyhow::anyhow!("Failed to configure JWT JWKS: {e}"))?;
            any_auth_configured = true;
            info!("Asymmetric JWT JWKS authentication is configured");
            Some(Arc::new(validator))
        }
        (None, None, Some(jwks_url)) => {
            if is_production && !jwks_url.starts_with("https://") {
                anyhow::bail!("JWT_JWKS_URL must use HTTPS in production");
            }
            let issuer = secrets
                .jwt_issuer()
                .map_err(|e| anyhow::anyhow!("Failed to load JWT issuer: {e}"))?;
            let audience = secrets
                .jwt_audience()
                .map_err(|e| anyhow::anyhow!("Failed to load JWT audience: {e}"))?;
            let validator = Arc::new(
                JwtValidator::from_jwks_url(&jwks_url, &issuer, &audience)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to fetch JWT JWKS: {e}"))?,
            );
            let refresh_interval =
                Duration::from_secs(parse_positive_u64_env("JWT_JWKS_REFRESH_SECS", 300)?);
            let refresh_validator = validator.clone();
            let refresh_signal = shutdown_coordinator.signal();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(refresh_interval);
                interval.tick().await;
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            match refresh_validator.refresh_jwks_url(&jwks_url).await {
                                Ok(()) => info!("JWT JWKS refreshed"),
                                Err(e) => warn!(error = %e, "JWT JWKS refresh failed; retaining last-known-good keys"),
                            }
                        }
                        _ = refresh_signal.wait() => break,
                    }
                }
            });
            any_auth_configured = true;
            info!("OIDC/JWKS URL authentication is configured with automatic rotation");
            Some(validator)
        }
        (None, None, None) => None,
        _ => {
            anyhow::bail!("JWT_SECRET, JWT_JWKS_JSON, and JWT_JWKS_URL are mutually exclusive")
        }
    };

    let tenant_rate_limit = parse_optional_positive_u32("RATE_LIMIT_PER_MINUTE")?;
    let rate_limit_backend =
        std::env::var("RATE_LIMIT_BACKEND").unwrap_or_else(|_| "memory".into());
    anyhow::ensure!(
        matches!(rate_limit_backend.as_str(), "memory" | "postgres"),
        "RATE_LIMIT_BACKEND must be memory or postgres"
    );
    let mut rate_limit_config = RateLimiterConfig::default();
    if let Some(capacity) = parse_optional_positive_usize("RATE_LIMIT_MAX_ENTRIES")? {
        rate_limit_config.max_entries = capacity;
    }
    if let Some(window) = parse_optional_positive_u32("RATE_LIMIT_WINDOW_SECONDS")? {
        rate_limit_config.window_seconds = u64::from(window);
    }

    let public_registration_enabled = parse_bool_env("PUBLIC_AGENT_REGISTRATION_ENABLED", false)?;

    let public_registration_limiter = if let Some(rpm) =
        parse_optional_positive_u32("PUBLIC_AGENT_REGISTRATION_RATE_LIMIT_PER_MINUTE")?
    {
        let mut config = RateLimiterConfig {
            requests_per_minute: rpm,
            ..Default::default()
        };
        if let Some(max_entries) =
            parse_optional_positive_usize("PUBLIC_AGENT_REGISTRATION_MAX_ENTRIES")?
        {
            config.max_entries = max_entries;
        }
        if let Some(window_seconds) =
            parse_optional_positive_u64("PUBLIC_AGENT_REGISTRATION_WINDOW_SECONDS")?
        {
            config.window_seconds = window_seconds;
        }
        Some(Arc::new(RateLimiter::with_config(config)))
    } else if public_registration_enabled {
        warn!("PUBLIC_AGENT_REGISTRATION_RATE_LIMIT_PER_MINUTE is unset; defaulting to 30 requests/minute");
        Some(Arc::new(RateLimiter::with_config(RateLimiterConfig {
            requests_per_minute: 30,
            ..Default::default()
        })))
    } else {
        None
    };

    let trust_proxy_headers = parse_bool_env("TRUST_PROXY_HEADERS", false)?;
    if trust_proxy_headers {
        validate_trusted_proxy_allowlist().map_err(anyhow::Error::msg)?;
    }

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

    // Connect to PostgreSQL with retry (allows Cloud SQL Proxy sidecar time to start)
    let max_startup_retries: u32 = std::env::var("DB_STARTUP_MAX_RETRIES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);
    let startup_retry_delay_secs: u64 = std::env::var("DB_STARTUP_RETRY_DELAY_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);

    info!("Connecting to PostgreSQL (primary), max retries: {max_startup_retries}...");
    let pool = connect_with_retry(
        "primary",
        &config.database_url,
        &config.write_pool,
        &config.session,
        max_startup_retries,
        startup_retry_delay_secs,
    )
    .await?;

    let read_pool = match &config.read_database_url {
        Some(read_url) => {
            info!("Connecting to PostgreSQL (read replica), max retries: {max_startup_retries}...");
            connect_with_retry(
                "read replica",
                read_url,
                &config.read_pool,
                &config.read_session,
                max_startup_retries,
                startup_retry_delay_secs,
            )
            .await?
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

    let build_limiter = |config| -> anyhow::Result<Arc<RateLimiter>> {
        let limiter = RateLimiter::with_config(config);
        Ok(Arc::new(if rate_limit_backend == "postgres" {
            limiter.with_postgres_backend(pool.clone())?
        } else {
            limiter
        }))
    };
    let rate_limiter = tenant_rate_limit
        .map(|rpm| {
            let mut config = rate_limit_config.clone();
            config.requests_per_minute = rpm;
            build_limiter(config)
        })
        .transpose()?;
    let credential_rate_limiter = build_limiter(rate_limit_config)?;
    info!(backend = %rate_limit_backend, "Request rate limiter configured");

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
            "AUTH_MODE=required but no auth is configured; set JWT_SECRET, JWT_JWKS_JSON, JWT_JWKS_URL, or BOOTSTRAP_ADMIN_API_KEY (or set AUTH_MODE=disabled and ALLOW_AUTH_DISABLED=true for local dev)"
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
    let event_store = Arc::new(PgEventStore::new(pool.clone(), payload_encryption.clone()));
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
    let security_profile = load_ves_security_profile(secrets.as_ref())?;
    info!(security_profile = %security_profile, "VES security profile configured");
    let mut ves_sequencer = VesSequencer::new(pool.clone(), agent_key_registry.clone());
    let mut ves_sequencer_reader = VesSequencer::new(pool.clone(), agent_key_registry.clone());
    let require_execution_binding = parse_bool_env("REQUIRE_SIGNED_EXECUTION_CONTROLS", false)?;
    ves_sequencer = ves_sequencer.with_required_execution_binding(require_execution_binding);
    ves_sequencer_reader =
        ves_sequencer_reader.with_required_execution_binding(require_execution_binding);
    ves_sequencer = ves_sequencer.with_security_profile(security_profile.clone());
    ves_sequencer_reader = ves_sequencer_reader.with_security_profile(security_profile.clone());
    if let Some(sequencer_id) = load_ves_sequencer_id(secrets.as_ref())? {
        info!("VES sequencer id configured: {}", sequencer_id);
        ves_sequencer = ves_sequencer.with_sequencer_id(sequencer_id);
        ves_sequencer_reader = ves_sequencer_reader.with_sequencer_id(sequencer_id);
    } else {
        info!("VES sequencer id not configured (set VES_SEQUENCER_ID to pin)");
    }
    if let Some(signing_key) = receipt_signing_key {
        info!("VES sequencer receipt signing enabled");

        // Build PQC-aware signing config if ML-DSA seed is available
        let signing_config = load_ves_signing_config(secrets.as_ref(), &signing_key)?;
        if let Some(ref config) = signing_config {
            info!(
                receipt_scheme = ?config.receipt_scheme,
                "VES PQC receipt signing configured"
            );
            ves_sequencer = ves_sequencer.with_signing_config(config.clone());
            ves_sequencer_reader = ves_sequencer_reader.with_signing_config(config.clone());
        }

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
    // The `event_schemas` table ships in migration 018; no runtime DDL here.
    info!("Schema registry ready");

    // Initialize x402 payment repository
    let x402_repository = Arc::new(PgX402Repository::new(pool.clone()));
    info!("x402 payment repository initialized");

    // Periodically prune expired nonce-tracking rows so the replay-protection
    // table cannot grow without bound. Retention is 2x the maximum intent
    // validity window to absorb clock skew; once a nonce is that old any replay
    // of its intent is already rejected by the expiry check at ingest.
    {
        let nonce_retention =
            Duration::from_secs(crate::domain::X402_MAX_VALIDITY_SECS.saturating_mul(2));
        let nonce_cleanup_interval = Duration::from_secs(parse_positive_u64_env(
            "X402_NONCE_CLEANUP_INTERVAL_SECS",
            3600,
        )?);
        spawn_x402_nonce_cleanup(
            x402_repository.clone(),
            nonce_cleanup_interval,
            nonce_retention,
        );
        info!(
            "x402 nonce cleanup scheduled (every {}s, retention {}s)",
            nonce_cleanup_interval.as_secs(),
            nonce_retention.as_secs()
        );
    }

    // Start x402 batch worker
    // Distributed/HA mode: when multiple sequencer nodes share this database,
    // ingest scales horizontally for free (FOR UPDATE serializes writes), but
    // the singleton workers below must run on exactly one node. Leader election
    // via PostgreSQL advisory locks enforces that, with automatic failover when
    // the leader dies. A single node wins instantly, so behavior is unchanged.
    // Set WORKER_LEADER_ELECTION=false to force the legacy run-everywhere path.
    let leader_election = parse_bool_env("WORKER_LEADER_ELECTION", true)?;
    let election_config = ElectionConfig::default();
    info!("Worker leader election: {}", leader_election);

    if leader_election {
        let repo = x402_repository.clone();
        spawn_elected_worker(
            "x402_batch_worker",
            lock_keys::X402_BATCH_WORKER,
            pool.clone(),
            election_config.clone(),
            shutdown_coordinator.signal(),
            shutdown_coordinator.clone(),
            move || {
                let (task, control) =
                    spawn_batch_worker(X402BatchWorkerConfig::from_env(), repo.clone());
                (task, move || async move {
                    let _ = control.send(BatchWorkerMessage::Shutdown).await;
                })
            },
        );
    } else {
        let (x402_batch_worker_task, x402_batch_worker_control) =
            spawn_batch_worker(X402BatchWorkerConfig::from_env(), x402_repository.clone());
        supervise_worker(
            "x402_batch_worker",
            x402_batch_worker_task,
            shutdown_coordinator.signal(),
            shutdown_coordinator.clone(),
            move || async move {
                let _ = x402_batch_worker_control
                    .send(BatchWorkerMessage::Shutdown)
                    .await;
            },
        );
    }
    info!("x402 batch worker started");

    // Materialize the built-in order, inventory, product, customer, and return
    // read models from every VES and legacy event stream. Stream discovery is
    // dynamic, and advisory-lock election guarantees one worker across an HA fleet.
    let projection_worker_enabled = parse_bool_env("PROJECTION_WORKER_ENABLED", true)?;
    if projection_worker_enabled {
        let projection_config = ProjectionWorkerConfig::from_env()
            .map_err(|e| anyhow::anyhow!("invalid projection worker configuration: {e}"))?;
        if leader_election {
            let projection_pool = pool.clone();
            let projection_event_store: Arc<dyn crate::infra::EventStore> = event_store.clone();
            let projection_ves_sequencer = ves_sequencer.clone();
            spawn_elected_worker(
                "projection_worker",
                lock_keys::PROJECTION_WORKER,
                pool.clone(),
                election_config.clone(),
                shutdown_coordinator.signal(),
                shutdown_coordinator.clone(),
                move || {
                    let (task, control) = spawn_projection_worker(
                        projection_config.clone(),
                        projection_pool.clone(),
                        projection_event_store.clone(),
                        Some(projection_ves_sequencer.clone()),
                    );
                    (task, move || async move {
                        let _ = control.send(ProjectionWorkerMessage::Shutdown).await;
                    })
                },
            );
        } else {
            let (task, control) = spawn_projection_worker(
                projection_config,
                pool.clone(),
                event_store.clone(),
                Some(ves_sequencer.clone()),
            );
            supervise_worker(
                "projection_worker",
                task,
                shutdown_coordinator.signal(),
                shutdown_coordinator.clone(),
                move || async move {
                    let _ = control.send(ProjectionWorkerMessage::Shutdown).await;
                },
            );
        }
        info!("projection worker started");
    } else {
        info!("projection worker disabled (PROJECTION_WORKER_ENABLED=false)");
    }

    // Proof generation is deliberately opt-in because it consumes substantial
    // CPU and requires an operator-selected compliance policy. Generated proofs
    // are self-verified before encrypted persistence.
    #[cfg(feature = "stark")]
    {
        let proof_worker_enabled = parse_bool_env("VES_PROOF_WORKER_ENABLED", false)?;
        if proof_worker_enabled {
            let proof_config = ProofWorkerConfig::from_env()
                .map_err(|e| anyhow::anyhow!("invalid proof worker configuration: {e}"))?;
            if leader_election {
                let proof_store = ves_compliance_proof_store.clone();
                spawn_elected_worker(
                    "proof_worker",
                    lock_keys::PROOF_WORKER,
                    pool.clone(),
                    election_config.clone(),
                    shutdown_coordinator.signal(),
                    shutdown_coordinator.clone(),
                    move || {
                        let (task, control) =
                            spawn_proof_worker(proof_config.clone(), proof_store.clone());
                        (task, move || async move {
                            let _ = control.send(ProofWorkerMessage::Shutdown).await;
                        })
                    },
                );
            } else {
                let (task, control) =
                    spawn_proof_worker(proof_config, ves_compliance_proof_store.clone());
                supervise_worker(
                    "proof_worker",
                    task,
                    shutdown_coordinator.signal(),
                    shutdown_coordinator.clone(),
                    move || async move {
                        let _ = control.send(ProofWorkerMessage::Shutdown).await;
                    },
                );
            }
            info!("STARK compliance proof worker started");
        } else {
            info!("STARK compliance proof worker disabled");
        }
    }
    #[cfg(not(feature = "stark"))]
    if parse_bool_env("VES_PROOF_WORKER_ENABLED", false)? {
        anyhow::bail!("VES_PROOF_WORKER_ENABLED requires a build with the `stark` feature");
    }

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
    let anchor_service = match AnchorConfig::from_env()? {
        Some(anchor_config) => {
            info!("Anchor service configured:");
            // RPC URLs commonly carry provider API keys in userinfo, paths, or
            // query strings. Never emit the configured URL to logs.
            info!("  RPC URL: configured (redacted)");
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

    // Start anchor worker (only if anchor service is configured)
    if let Some(ref anchor_svc) = anchor_service {
        if leader_election {
            let svc = anchor_svc.clone();
            let engine = ves_commitment_engine.clone();
            spawn_elected_worker(
                "anchor_worker",
                lock_keys::ANCHOR_WORKER,
                pool.clone(),
                election_config.clone(),
                shutdown_coordinator.signal(),
                shutdown_coordinator.clone(),
                move || {
                    let (task, control) = spawn_anchor_worker(
                        AnchorWorkerConfig::from_env(),
                        svc.clone(),
                        engine.clone(),
                    );
                    (task, move || async move {
                        let _ = control.send(AnchorWorkerMessage::Shutdown).await;
                    })
                },
            );
        } else {
            let (anchor_worker_task, anchor_worker_control) = spawn_anchor_worker(
                AnchorWorkerConfig::from_env(),
                anchor_svc.clone(),
                ves_commitment_engine.clone(),
            );
            supervise_worker(
                "anchor_worker",
                anchor_worker_task,
                shutdown_coordinator.signal(),
                shutdown_coordinator.clone(),
                move || async move {
                    let _ = anchor_worker_control
                        .send(AnchorWorkerMessage::Shutdown)
                        .await;
                },
            );
        }
        info!("Anchor worker started");
    }

    // Initialize the autonomous x402 settlement service (optional — only if the
    // settlement env vars are set). OFF BY DEFAULT. When unset the settler simply
    // does not run and the manual POST /batches/settle path remains the only way
    // to record settlement.
    let settlement_service = match SettlementConfig::from_env()? {
        Some(settlement_config) => {
            info!("x402 settlement service configured:");
            // RPC URLs commonly carry provider API keys in userinfo, paths, or
            // query strings. Never emit the configured URL to logs.
            info!("  RPC URL: configured (redacted)");
            info!("  Contract: {:?}", settlement_config.contract_address);
            info!("  Chain ID: {}", settlement_config.chain_id);
            Some(Arc::new(SettlementService::new(settlement_config)))
        }
        None => {
            info!(
                "x402 settlement service not configured (set SETTLEMENT_RPC_URL, SET_PAYMENT_BATCH_ADDRESS, SETTLER_PRIVATE_KEY to enable autonomous on-chain settlement)"
            );
            None
        }
    };

    // Start the settlement worker (only if the settlement service is configured).
    // Leader-elected like the anchor worker so exactly one node settles.
    if let Some(ref settlement_svc) = settlement_service {
        if leader_election {
            let svc = settlement_svc.clone();
            let repo = x402_repository.clone();
            spawn_elected_worker(
                "settlement_worker",
                lock_keys::SETTLEMENT_WORKER,
                pool.clone(),
                election_config.clone(),
                shutdown_coordinator.signal(),
                shutdown_coordinator.clone(),
                move || {
                    let (task, control) = spawn_settlement_worker(
                        SettlementWorkerConfig::from_env(),
                        svc.clone(),
                        repo.clone(),
                    );
                    (task, move || async move {
                        let _ = control.send(SettlementWorkerMessage::Shutdown).await;
                    })
                },
            );
        } else {
            let (settlement_worker_task, settlement_worker_control) = spawn_settlement_worker(
                SettlementWorkerConfig::from_env(),
                settlement_svc.clone(),
                x402_repository.clone(),
            );
            supervise_worker(
                "settlement_worker",
                settlement_worker_task,
                shutdown_coordinator.signal(),
                shutdown_coordinator.clone(),
                move || async move {
                    let _ = settlement_worker_control
                        .send(SettlementWorkerMessage::Shutdown)
                        .await;
                },
            );
        }
        info!("x402 settlement worker started");
    }

    let auth_state = AuthMiddlewareState {
        authenticator,
        require_auth,
        rate_limiter,
        credential_rate_limiter: credential_rate_limiter.clone(),
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
    let grpc_handle = config.grpc_addr.map(|grpc_addr| {
        self::grpc::spawn_grpc_server(&state, &auth_state, grpc_addr, &shutdown_coordinator)
    });

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
    // Payment gate for x402 premium (HTTP 402) routes; price is env-configured
    // via X402_PREMIUM_ROUTE_* (see api::middleware::payment_required).
    let payment_gate = crate::api::middleware::PaymentRequiredState::new(
        state.x402_repository.clone(),
        state.agent_key_registry.clone(),
        Arc::new(crate::api::middleware::PaymentRequiredConfig::from_env()),
    );

    let app = build_router(auth_state, admin_access_state, payment_gate)?
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

/// Initialize OpenTelemetry tracer with OTLP exporter
fn init_opentelemetry_tracer(
) -> Result<opentelemetry_sdk::trace::Tracer, Box<dyn std::error::Error>> {
    use opentelemetry::trace::TracerProvider;
    use opentelemetry_otlp::WithExportConfig;

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:4317".to_string()),
        )
        .build()?;

    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name("stateset-sequencer")
                .with_attributes([opentelemetry::KeyValue::new(
                    "service.version",
                    env!("CARGO_PKG_VERSION"),
                )])
                .build(),
        )
        .build();

    let tracer = provider.tracer("stateset-sequencer");
    // Install globally so shutdown flushes through the global handle owner.
    opentelemetry::global::set_tracer_provider(provider);
    Ok(tracer)
}
