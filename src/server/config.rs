//! Server configuration and environment parsing.
//!
//! Loads [`Config`] from the environment, validates secrets and database
//! connection options, and builds PostgreSQL connection pools with retry.

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use tracing::{info, warn};
use uuid::Uuid;

use crate::crypto::{secret_key_from_str, AgentSigningKey};
use crate::infra::{CacheManagerConfig, SecretsProvider};

/// Interval for pool health monitoring and component metrics collection.
pub(crate) const MONITORING_INTERVAL: Duration = Duration::from_secs(15);

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
    fn from_env(prefix: &str, default_max: u32) -> anyhow::Result<Self> {
        let max_name = format!("{prefix}MAX_DB_CONNECTIONS");
        let min_name = format!("{prefix}MIN_DB_CONNECTIONS");
        let max_connections = parse_positive_u32_env(&max_name, default_max)?;
        let min_connections = parse_u32_env(&min_name, 0)?;
        if min_connections > max_connections {
            anyhow::bail!(
                "{min_name} ({min_connections}) must not exceed {max_name} ({max_connections})"
            );
        }

        let acquire_timeout_ms =
            parse_optional_positive_u64(&format!("{prefix}DB_ACQUIRE_TIMEOUT_MS"))?;
        let idle_timeout_secs =
            parse_optional_positive_u64(&format!("{prefix}DB_IDLE_TIMEOUT_SECS"))?;
        let max_lifetime_secs =
            parse_optional_positive_u64(&format!("{prefix}DB_MAX_LIFETIME_SECS"))?;

        Ok(Self {
            max_connections,
            min_connections,
            acquire_timeout_ms,
            idle_timeout_secs,
            max_lifetime_secs,
        })
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
pub(crate) const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

impl DbSessionConfig {
    fn from_env() -> anyhow::Result<Self> {
        let statement_timeout_ms = Some(parse_positive_u64_env(
            "DB_STATEMENT_TIMEOUT_MS",
            DEFAULT_STATEMENT_TIMEOUT_MS,
        )?);

        let idle_in_tx_timeout_ms = Some(parse_positive_u64_env(
            "DB_IDLE_IN_TX_TIMEOUT_MS",
            DEFAULT_IDLE_IN_TX_TIMEOUT_MS,
        )?);

        let lock_timeout_ms = Some(parse_positive_u64_env(
            "DB_LOCK_TIMEOUT_MS",
            DEFAULT_LOCK_TIMEOUT_MS,
        )?);

        let application_name = std::env::var("DB_APPLICATION_NAME")
            .unwrap_or_else(|_| "stateset-sequencer".to_string());

        Ok(Self {
            statement_timeout_ms,
            idle_in_tx_timeout_ms,
            lock_timeout_ms,
            application_name,
        })
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
    fn from_env() -> anyhow::Result<Self> {
        let defaults = CacheManagerConfig::default();

        let commitment_max =
            parse_positive_usize_env("CACHE_COMMITMENT_MAX", defaults.commitment_max)?;
        let commitment_ttl_secs = parse_positive_u64_env(
            "CACHE_COMMITMENT_TTL_SECS",
            defaults.commitment_ttl.as_secs(),
        )?;

        let proof_max = parse_positive_usize_env("CACHE_PROOF_MAX", defaults.proof_max)?;
        let proof_ttl_secs =
            parse_positive_u64_env("CACHE_PROOF_TTL_SECS", defaults.proof_ttl.as_secs())?;

        let ves_commitment_max =
            parse_positive_usize_env("CACHE_VES_COMMITMENT_MAX", commitment_max)?;
        let ves_commitment_ttl_secs =
            parse_positive_u64_env("CACHE_VES_COMMITMENT_TTL_SECS", commitment_ttl_secs)?;

        let ves_proof_max = parse_positive_usize_env("CACHE_VES_PROOF_MAX", proof_max)?;
        let ves_proof_ttl_secs =
            parse_positive_u64_env("CACHE_VES_PROOF_TTL_SECS", proof_ttl_secs)?;

        let agent_key_max =
            parse_positive_usize_env("CACHE_AGENT_KEY_MAX", defaults.agent_key_max)?;
        let agent_key_ttl_secs =
            parse_positive_u64_env("CACHE_AGENT_KEY_TTL_SECS", defaults.agent_key_ttl.as_secs())?;

        let schema_max = parse_positive_usize_env("CACHE_SCHEMA_MAX", defaults.schema_max)?;
        let schema_ttl_secs =
            parse_positive_u64_env("CACHE_SCHEMA_TTL_SECS", defaults.schema_ttl.as_secs())?;

        Ok(Self {
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
        })
    }

    pub(crate) fn to_manager_config(&self) -> CacheManagerConfig {
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

fn parse_u32_env(name: &str, default: u32) -> anyhow::Result<u32> {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse::<u32>()
            .map_err(|_| anyhow::anyhow!("Invalid value for {name}: '{raw}'. Expected an integer")),
        Err(_) => Ok(default),
    }
}

fn parse_positive_u32_env(name: &str, default: u32) -> anyhow::Result<u32> {
    let value = parse_u32_env(name, default)?;
    if value == 0 {
        anyhow::bail!("Invalid value for {name}: '0'. Expected a value greater than 0");
    }
    Ok(value)
}

pub(crate) fn parse_positive_u64_env(name: &str, default: u64) -> anyhow::Result<u64> {
    match std::env::var(name) {
        Ok(raw) => {
            let value = raw.parse::<u64>().map_err(|_| {
                anyhow::anyhow!("Invalid value for {name}: '{raw}'. Expected a positive integer")
            })?;
            if value == 0 {
                anyhow::bail!("Invalid value for {name}: '{raw}'. Expected a value greater than 0");
            }
            Ok(value)
        }
        Err(_) => Ok(default),
    }
}

fn parse_positive_usize_env(name: &str, default: usize) -> anyhow::Result<usize> {
    match std::env::var(name) {
        Ok(raw) => {
            let value = raw.parse::<usize>().map_err(|_| {
                anyhow::anyhow!("Invalid value for {name}: '{raw}'. Expected a positive integer")
            })?;
            if value == 0 {
                anyhow::bail!("Invalid value for {name}: '{raw}'. Expected a value greater than 0");
            }
            Ok(value)
        }
        Err(_) => Ok(default),
    }
}

pub(crate) fn parse_bool_env(name: &str, default: bool) -> anyhow::Result<bool> {
    match std::env::var(name) {
        Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "on" | "yes" => Ok(true),
            "0" | "false" | "off" | "no" => Ok(false),
            _ => Err(anyhow::anyhow!(
                "Invalid value for {name}: '{raw}'. Expected true/false, 1/0, on/off, or yes/no"
            )),
        },
        Err(_) => Ok(default),
    }
}

fn parse_u16_env(name: &str, default: u16) -> anyhow::Result<u16> {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse::<u16>()
            .map_err(|_| anyhow::anyhow!("Invalid value for {name}: '{raw}'. Expected 0..=65535")),
        Err(_) => Ok(default),
    }
}

pub(crate) fn parse_optional_positive_u32(name: &str) -> anyhow::Result<Option<u32>> {
    match std::env::var(name) {
        Ok(raw) => {
            let value = raw.parse::<u32>().map_err(|_| {
                anyhow::anyhow!("Invalid value for {name}: '{raw}'. Expected a positive integer")
            })?;
            if value == 0 {
                return Err(anyhow::anyhow!(
                    "Invalid value for {name}: '{raw}'. Expected a value greater than 0"
                ));
            }
            Ok(Some(value))
        }
        Err(_) => Ok(None),
    }
}

pub(crate) fn parse_optional_positive_u64(name: &str) -> anyhow::Result<Option<u64>> {
    match std::env::var(name) {
        Ok(raw) => {
            let value = raw.parse::<u64>().map_err(|_| {
                anyhow::anyhow!("Invalid value for {name}: '{raw}'. Expected a positive integer")
            })?;
            if value == 0 {
                return Err(anyhow::anyhow!(
                    "Invalid value for {name}: '{raw}'. Expected a value greater than 0"
                ));
            }
            Ok(Some(value))
        }
        Err(_) => Ok(None),
    }
}

pub(crate) fn parse_optional_positive_usize(name: &str) -> anyhow::Result<Option<usize>> {
    match std::env::var(name) {
        Ok(raw) => {
            let value = raw.parse::<usize>().map_err(|_| {
                anyhow::anyhow!("Invalid value for {name}: '{raw}'. Expected a positive integer")
            })?;
            if value == 0 {
                return Err(anyhow::anyhow!(
                    "Invalid value for {name}: '{raw}'. Expected a value greater than 0"
                ));
            }
            Ok(Some(value))
        }
        Err(_) => Ok(None),
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum AuthMode {
    Required,
    Disabled,
}

pub(crate) fn parse_auth_mode() -> anyhow::Result<AuthMode> {
    let auth_mode = std::env::var("AUTH_MODE").unwrap_or_else(|_| "required".to_string());
    match auth_mode.trim().to_lowercase().as_str() {
        "required" => Ok(AuthMode::Required),
        "disabled" => Ok(AuthMode::Disabled),
        _ => Err(anyhow::anyhow!(
            "Invalid AUTH_MODE value: {auth_mode}; expected required or disabled"
        )),
    }
}

/// Whether the process is running in a production-like deployment.
///
/// Controlled by `SEQUENCER_ENV`/`ENVIRONMENT` (case-insensitive). Production
/// is the *safe* default for unknown values: an operator who misspells the
/// environment gets the strict checks rather than silently weakened ones.
/// Only the explicit non-production values disable hardening.
pub(crate) fn is_production_env() -> bool {
    let raw = std::env::var("SEQUENCER_ENV")
        .or_else(|_| std::env::var("ENVIRONMENT"))
        .unwrap_or_default();
    !matches!(
        raw.trim().to_lowercase().as_str(),
        // Empty means "unset" — treat as non-production so local/dev/CI runs
        // are not forced to provision strong secrets. Any other recognized
        // non-prod label also relaxes the checks.
        "" | "local" | "dev" | "development" | "test" | "testing" | "ci" | "staging"
    )
}

/// Minimum acceptable entropy (in characters) for HMAC/shared secrets.
pub(crate) const MIN_SECRET_LEN: usize = 32;

/// Validate that a configured secret is strong enough to use. In production a
/// weak secret is fatal; outside production it is downgraded to a warning so
/// developers are nudged without being blocked.
pub(crate) fn enforce_secret_strength(
    name: &str,
    value: &str,
    min_len: usize,
    is_production: bool,
) -> anyhow::Result<()> {
    let len = value.trim().chars().count();
    if len >= min_len {
        return Ok(());
    }
    if is_production {
        anyhow::bail!(
            "{name} is too weak for production: {len} chars, need >= {min_len}. \
             Generate a high-entropy secret (e.g. `openssl rand -hex 32`)."
        );
    }
    warn!(
        "{name} is weak ({len} chars, recommended >= {min_len}); acceptable for non-production only"
    );
    Ok(())
}

/// Server configuration.
#[derive(Clone)]
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

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("database_url", &"<redacted>")
            .field(
                "read_database_url",
                &self.read_database_url.as_ref().map(|_| "<redacted>"),
            )
            .field("listen_addr", &self.listen_addr)
            .field("grpc_addr", &self.grpc_addr)
            .field("write_pool", &self.write_pool)
            .field("read_pool", &self.read_pool)
            .field("session", &self.session)
            .field("read_session", &self.read_session)
            .field("cache", &self.cache)
            .finish()
    }
}

impl Config {
    /// Load configuration from environment variables.
    pub fn from_env() -> anyhow::Result<Self> {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/stateset_sequencer".to_string());

        let read_database_url = std::env::var("READ_DATABASE_URL")
            .ok()
            .filter(|v| !v.trim().is_empty());

        let port: u16 = parse_u16_env("PORT", 8080)?;

        let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());

        let listen_addr: SocketAddr = format!("{host}:{port}")
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid listen address '{host}:{port}': {e}"))?;

        // gRPC port configuration (defaults to HTTP port + 1, e.g., 8081 if HTTP is 8080)
        let grpc_addr: Option<SocketAddr> = if parse_bool_env("GRPC_DISABLED", false)? {
            None
        } else {
            let grpc_port: u16 = match std::env::var("GRPC_PORT") {
            Ok(raw) => raw
                .parse::<u16>()
                .map_err(|_| anyhow::anyhow!("Invalid value for GRPC_PORT: '{raw}'. Expected 0..=65535"))?,
            Err(_) => port.checked_add(1).ok_or_else(|| {
                anyhow::anyhow!(
                    "PORT is 65535 and GRPC_PORT is not set; set GRPC_PORT explicitly to avoid overflow"
                )
            })?,
        };
            Some(
                format!("{host}:{grpc_port}").parse().map_err(|e| {
                    anyhow::anyhow!("Invalid gRPC address '{host}:{grpc_port}': {e}")
                })?,
            )
        };

        let write_pool = DbPoolConfig::from_env("", 10)?;
        let read_pool = DbPoolConfig::from_env("READ_", write_pool.max_connections)?;
        let session = DbSessionConfig::from_env()?;
        let read_session_name = std::env::var("READ_DB_APPLICATION_NAME")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| format!("{}-read", session.application_name));
        let read_session = DbSessionConfig {
            application_name: read_session_name,
            ..session.clone()
        };
        let cache = CacheConfig::from_env()?;

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
    let connect_options = parse_secure_pg_connect_options(url)?;
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

    Ok(options.connect_with(connect_options).await?)
}

fn parse_secure_pg_connect_options(url: &str) -> anyhow::Result<PgConnectOptions> {
    let options = PgConnectOptions::from_str(url)?;

    match options.get_ssl_mode() {
        PgSslMode::Disable | PgSslMode::Allow | PgSslMode::Prefer
            if allow_insecure_local_db(&options)? =>
        {
            Ok(options)
        }
        PgSslMode::Disable | PgSslMode::Allow | PgSslMode::Prefer => Err(anyhow::anyhow!(
            "PostgreSQL sslmode must be require, verify-ca, or verify-full (or set ALLOW_INSECURE_LOCAL_DB=true for localhost/dev Docker)"
        )),
        PgSslMode::Require | PgSslMode::VerifyCa | PgSslMode::VerifyFull => Ok(options),
    }
}

fn allow_insecure_local_db(options: &PgConnectOptions) -> anyhow::Result<bool> {
    if !parse_bool_env("ALLOW_INSECURE_LOCAL_DB", false)? {
        return Ok(false);
    }

    Ok(is_local_db_target(options))
}

fn is_local_db_target(options: &PgConnectOptions) -> bool {
    if options.get_socket().is_some() {
        return true;
    }

    matches!(
        options.get_host(),
        "localhost" | "127.0.0.1" | "::1" | "postgres" | "host.docker.internal"
    )
}

pub(crate) fn load_ves_security_profile(secrets: &dyn SecretsProvider) -> anyhow::Result<String> {
    let profile = secrets
        .ves_sequencer_security_profile()?
        .unwrap_or_else(|| "legacy".to_string());
    let profile = profile.trim().to_ascii_lowercase();
    match profile.as_str() {
        "legacy" | "hybrid" | "pqc-strict" => Ok(profile),
        _ => Err(anyhow::anyhow!(
            "invalid VES_SEQUENCER_SECURITY_PROFILE: {profile}"
        )),
    }
}

/// Connect to PostgreSQL with retry logic for startup resilience.
///
/// This gives sidecar proxies (e.g. Cloud SQL Proxy) time to become ready
/// before the sequencer gives up.
pub(crate) async fn connect_with_retry(
    label: &str,
    url: &str,
    pool_config: &DbPoolConfig,
    session_config: &DbSessionConfig,
    max_retries: u32,
    retry_delay_secs: u64,
) -> anyhow::Result<sqlx::PgPool> {
    let mut last_err = None;
    for attempt in 1..=(max_retries + 1) {
        match build_pg_pool(url, pool_config, session_config).await {
            Ok(pool) => {
                info!("Connected to PostgreSQL ({label}) on attempt {attempt}");
                return Ok(pool);
            }
            Err(e) => {
                if attempt <= max_retries {
                    warn!(
                        attempt,
                        max_retries,
                        error = %e,
                        "Failed to connect to PostgreSQL ({label}), retrying in {retry_delay_secs}s..."
                    );
                    tokio::time::sleep(Duration::from_secs(retry_delay_secs)).await;
                } else {
                    tracing::error!(
                        attempt,
                        error = %e,
                        "Failed to connect to PostgreSQL ({label}) after all retries"
                    );
                }
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("Failed to connect to PostgreSQL ({label})")))
}

pub(crate) fn load_ves_sequencer_signing_key(
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

/// Load the PQC-aware signing configuration from env vars.
///
/// Uses `VES_SEQUENCER_ML_DSA_SEED` (hex, 32 bytes) and
/// `VES_SEQUENCER_SECURITY_PROFILE` ("legacy", "hybrid", "pqc-strict").
pub(crate) fn load_ves_signing_config(
    secrets: &dyn SecretsProvider,
    ed25519_key: &AgentSigningKey,
) -> anyhow::Result<Option<crate::crypto::pqc_signing::SequencerSigningConfig>> {
    use crate::crypto::pqc_signing::{SequencerSigningConfig, SignatureScheme};

    let profile = load_ves_security_profile(secrets)?;
    let receipt_scheme = match profile.to_lowercase().as_str() {
        "hybrid" => SignatureScheme::Ed25519MlDsa65,
        "pqc-strict" => SignatureScheme::MlDsa65,
        _ => return Ok(None), // Legacy doesn't need signing config
    };

    // Load ML-DSA-65 seed
    let ml_dsa_seed_hex = secrets
        .ves_sequencer_ml_dsa_seed()
        .map_err(|e| anyhow::anyhow!("failed to load VES_SEQUENCER_ML_DSA_SEED: {e}"))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "VES_SEQUENCER_ML_DSA_SEED is required when security profile is {profile}"
            )
        })?;

    let seed_bytes = hex::decode(
        ml_dsa_seed_hex
            .strip_prefix("0x")
            .unwrap_or(&ml_dsa_seed_hex),
    )
    .map_err(|e| anyhow::anyhow!("invalid VES_SEQUENCER_ML_DSA_SEED hex: {e}"))?;
    if seed_bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "VES_SEQUENCER_ML_DSA_SEED must be 32 bytes, got {}",
            seed_bytes.len()
        ));
    }
    let mut ml_dsa_seed = [0u8; 32];
    ml_dsa_seed.copy_from_slice(&seed_bytes);

    Ok(Some(SequencerSigningConfig {
        ed25519_key: Some(ed25519_key.clone()),
        #[cfg(feature = "pqc")]
        ml_dsa_65_seed: Some(ml_dsa_seed),
        receipt_scheme,
    }))
}

pub(crate) fn load_ves_sequencer_id(secrets: &dyn SecretsProvider) -> anyhow::Result<Option<Uuid>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn parse_secure_pg_connect_options_rejects_local_insecure_db_by_default() {
        std::env::remove_var("ALLOW_INSECURE_LOCAL_DB");

        let err = parse_secure_pg_connect_options("postgres://localhost/stateset_sequencer")
            .expect_err("localhost without SSL should be rejected by default");
        assert!(err.to_string().contains("ALLOW_INSECURE_LOCAL_DB"));
    }

    #[test]
    #[serial]
    fn parse_secure_pg_connect_options_allows_local_insecure_db_with_opt_in() {
        std::env::set_var("ALLOW_INSECURE_LOCAL_DB", "true");

        let options = parse_secure_pg_connect_options("postgres://localhost/stateset_sequencer")
            .expect("localhost without SSL should be allowed with explicit opt-in");
        assert_eq!(options.get_host(), "localhost");

        std::env::remove_var("ALLOW_INSECURE_LOCAL_DB");
    }

    #[test]
    #[serial]
    fn parse_secure_pg_connect_options_still_rejects_remote_insecure_db_with_opt_in() {
        std::env::set_var("ALLOW_INSECURE_LOCAL_DB", "true");

        let err = parse_secure_pg_connect_options("postgres://db.example.com/stateset_sequencer")
            .expect_err("remote hosts should still require SSL");
        assert!(err.to_string().contains("sslmode must be require"));

        std::env::remove_var("ALLOW_INSECURE_LOCAL_DB");
    }

    #[test]
    fn enforce_secret_strength_accepts_strong_secret() {
        let strong = "0123456789abcdef0123456789abcdef"; // 32 chars
        assert!(enforce_secret_strength("JWT_SECRET", strong, MIN_SECRET_LEN, true).is_ok());
        assert!(enforce_secret_strength("JWT_SECRET", strong, MIN_SECRET_LEN, false).is_ok());
    }

    #[test]
    fn enforce_secret_strength_rejects_weak_secret_in_production() {
        let weak = "short";
        let err = enforce_secret_strength("JWT_SECRET", weak, MIN_SECRET_LEN, true)
            .expect_err("weak secret must be fatal in production");
        assert!(err.to_string().contains("too weak for production"));
    }

    #[test]
    fn enforce_secret_strength_warns_but_allows_weak_secret_outside_production() {
        let weak = "short";
        assert!(
            enforce_secret_strength("JWT_SECRET", weak, MIN_SECRET_LEN, false).is_ok(),
            "weak secret should be allowed (with a warning) outside production"
        );
    }

    #[test]
    #[serial]
    fn db_pool_config_rejects_malformed_values() {
        std::env::set_var("TEST_MAX_DB_CONNECTIONS", "many");

        let err = DbPoolConfig::from_env("TEST_", 10)
            .expect_err("malformed pool sizes must not silently use defaults");
        assert!(err.to_string().contains("TEST_MAX_DB_CONNECTIONS"));

        std::env::remove_var("TEST_MAX_DB_CONNECTIONS");
    }

    #[test]
    #[serial]
    fn db_pool_config_rejects_minimum_above_maximum() {
        std::env::set_var("TEST_MAX_DB_CONNECTIONS", "4");
        std::env::set_var("TEST_MIN_DB_CONNECTIONS", "5");

        let err = DbPoolConfig::from_env("TEST_", 10)
            .expect_err("an impossible pool range must fail at startup");
        assert!(err.to_string().contains("must not exceed"));

        std::env::remove_var("TEST_MAX_DB_CONNECTIONS");
        std::env::remove_var("TEST_MIN_DB_CONNECTIONS");
    }

    #[test]
    #[serial]
    fn cache_config_rejects_zero_capacity() {
        std::env::set_var("CACHE_COMMITMENT_MAX", "0");

        let err = CacheConfig::from_env()
            .expect_err("zero-capacity caches must not silently become capacity one");
        assert!(err.to_string().contains("CACHE_COMMITMENT_MAX"));

        std::env::remove_var("CACHE_COMMITMENT_MAX");
    }

    #[test]
    #[serial]
    fn config_debug_redacts_database_credentials() {
        std::env::set_var(
            "DATABASE_URL",
            "postgres://db-user:db-password@example.invalid/sequencer",
        );
        std::env::set_var(
            "READ_DATABASE_URL",
            "postgres://reader:reader-password@example.invalid/sequencer",
        );

        let config = Config::from_env().expect("valid configuration");
        let debug = format!("{config:?}");
        assert!(!debug.contains("db-password"));
        assert!(!debug.contains("reader-password"));
        assert!(debug.contains("<redacted>"));

        std::env::remove_var("DATABASE_URL");
        std::env::remove_var("READ_DATABASE_URL");
    }

    #[test]
    #[serial]
    fn is_production_env_defaults_and_labels() {
        std::env::remove_var("SEQUENCER_ENV");
        std::env::remove_var("ENVIRONMENT");
        assert!(
            !is_production_env(),
            "unset env must default to non-production"
        );

        for label in ["dev", "development", "test", "ci", "staging", "LOCAL"] {
            std::env::set_var("SEQUENCER_ENV", label);
            assert!(!is_production_env(), "{label} must be non-production");
        }

        for label in ["production", "prod", "PRODUCTION", "live"] {
            std::env::set_var("SEQUENCER_ENV", label);
            assert!(is_production_env(), "{label} must be production");
        }
        std::env::remove_var("SEQUENCER_ENV");
    }
}
