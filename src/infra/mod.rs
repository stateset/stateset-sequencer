//! Infrastructure layer for StateSet Sequencer
//!
//! Contains trait definitions and implementations for:
//! - Event storage (PostgreSQL, SQLite)
//! - Sequencer (canonical ordering)
//! - Projector (state projection)
//! - Commitment engine (Merkle roots)
//! - Caching (in-memory LRU)
//! - Circuit breaker (external service protection)
//! - Retry utilities (exponential backoff with jitter)
//! - Graceful shutdown (request draining)
//! - Audit logging (admin operations)
//! - Dead letter queue (failed projections)

mod anchor_worker;
mod audit;
mod batch;
mod cache;
mod circuit_breaker;
mod commitment;
mod dead_letter;
mod error;
mod graceful_shutdown;
mod leader_election;
mod net;
mod payload_encryption;
mod pool_monitor;
pub mod postgres;
mod projection_worker;
#[cfg(feature = "stark")]
mod proof_worker;
mod retry;
mod schema_validation;
mod secrets;
mod settlement_worker;
pub mod sqlite;
mod traits;
mod ves_commitment;
mod ves_compliance;
mod ves_validity;
mod x402_batch_worker;

pub use anchor_worker::{spawn_anchor_worker, AnchorWorkerConfig, AnchorWorkerMessage};
pub use audit::{AuditAction, AuditLogBuilder, AuditLogEntry, AuditQueryFilters, PgAuditLogger};
pub use batch::{
    batch_check_existing_command_ids, batch_check_existing_event_ids, batch_reserve_command_ids,
    chunked, dedupe_preserve_order, partition_for_parallel, BatchConfig, BatchStats,
    DEFAULT_BATCH_SIZE,
};
pub use cache::{
    AgentKeyCache, CacheManager, CacheManagerConfig, CacheRefreshConfig, CacheStats,
    CachedCommitment, CommitmentCache, LruCache, ProofCache, SchemaCache, VesCommitmentCache,
    CACHE_STAMPEDE_DELAY,
};
pub use circuit_breaker::{
    CircuitBreaker, CircuitBreakerConfig, CircuitBreakerError, CircuitBreakerRegistry, CircuitState,
};
pub use commitment::PgCommitmentEngine;
pub use dead_letter::{
    spawn_dlq_cleanup, DeadLetterEvent, DeadLetterReason, DeadLetterRetryConfig, DeadLetterStats,
    DeadLetterStatus, EnqueueParams, PgDeadLetterQueue,
};
pub use error::{contexts, ContextualError, ErrorContext, Result, ResultExt, SequencerError};
pub use graceful_shutdown::{
    serve_with_shutdown, shutdown_signal, spawn_until_shutdown, GracefulShutdownConfig,
    RequestGuard, RequestTracker, ShutdownCoordinator, ShutdownSignal,
};
pub use leader_election::{lock_keys, spawn_elected_worker, ElectionConfig};
pub use net::{extract_client_ip, validate_trusted_proxy_allowlist};
pub use payload_encryption::{PayloadEncryption, PayloadEncryptionMode};
pub use pool_monitor::{PoolHealthStatus, PoolMonitor, PoolMonitorConfig, PoolStats};
pub use postgres::{
    spawn_x402_nonce_cleanup, AgentCursor, AgentEventPolicy, PgAgentCursorStore,
    PgAgentEventPolicyStore, PgAgentKeyRegistry, PgEventStore, PgProjectionCheckpointStore,
    PgProjectionDocumentStore, PgProjectionEventSource, PgProjectionRejectionSink,
    PgProjectionVersionStore, PgSchemaStore, PgSequencer, PgVesProjectionEventSource,
    PgX402Repository, VesRejectionReason, VesSequencer,
};
pub use projection_worker::{
    spawn_projection_worker, ProjectionWorkerConfig, ProjectionWorkerMessage,
};
#[cfg(feature = "stark")]
pub use proof_worker::{spawn_proof_worker, ProofWorkerConfig, ProofWorkerMessage};
pub use retry::{
    is_retryable_db_error, is_transient_chain_error, retry, retry_with_config, Retry, RetryConfig,
    RetryResult,
};
pub use schema_validation::SchemaValidationMode;
pub use secrets::{EnvSecretsProvider, SecretsError, SecretsProvider};
pub use settlement_worker::{
    spawn_settlement_worker, SettlementWorker, SettlementWorkerConfig, SettlementWorkerMessage,
};
pub use sqlite::SqliteOutbox;
pub use traits::*;
pub use ves_commitment::PgVesCommitmentEngine;
pub use ves_compliance::{PgVesComplianceProofStore, VesComplianceEventInputs};
pub use ves_validity::PgVesValidityProofStore;
pub use x402_batch_worker::{
    spawn_batch_worker, BatchWorkerMessage, X402BatchWorker, X402BatchWorkerConfig,
};
