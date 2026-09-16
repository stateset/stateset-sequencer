//! Shared application state for HTTP handlers and servers.

use std::sync::Arc;

use sqlx::PgPool;

use crate::anchor::AnchorService;
use crate::auth::{ApiKeyValidator, PgApiKeyStore, RateLimiter, RequestLimits};
use crate::infra::{
    CacheManager, CircuitBreakerRegistry, PgAgentKeyRegistry, PgAuditLogger, PgCommitmentEngine,
    PgEventStore, PgSchemaStore, PgSequencer, PgVesCommitmentEngine, PgVesComplianceProofStore,
    PgVesValidityProofStore, PgX402Repository, PoolMonitor, SchemaValidationMode, VesSequencer,
};
use crate::metrics::MetricsRegistry;

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

/// Permissive auth stack for router/gRPC wiring tests: no live credentials,
/// no rate limiting, no pool monitor.
#[cfg(test)]
pub(crate) fn test_auth_state() -> crate::auth::AuthMiddlewareState {
    use crate::auth::{ApiKeyValidator, Authenticator, RateLimiter, RateLimiterConfig};

    let validator = std::sync::Arc::new(ApiKeyValidator::new());
    crate::auth::AuthMiddlewareState {
        authenticator: std::sync::Arc::new(Authenticator::new(validator)),
        require_auth: false,
        rate_limiter: None,
        credential_rate_limiter: std::sync::Arc::new(RateLimiter::with_config(
            RateLimiterConfig::default(),
        )),
        pool_monitor: None,
    }
}

#[cfg(test)]
pub(crate) fn test_app_state() -> AppState {
    use sqlx::postgres::PgPoolOptions;

    use crate::auth::{ApiKeyValidator, PgApiKeyStore};
    use crate::infra::{
        CacheManager, PayloadEncryption, PgAgentKeyRegistry, PgCommitmentEngine, PgEventStore,
        PgSchemaStore, PgSequencer, PgVesCommitmentEngine, PgVesComplianceProofStore,
        PgVesValidityProofStore, PgX402Repository, SchemaValidationMode, VesSequencer,
    };
    use crate::metrics::MetricsRegistry;

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
