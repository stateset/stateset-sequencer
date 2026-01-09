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

mod audit;
mod batch;
mod cache;
mod circuit_breaker;
mod commitment;
mod dead_letter;
mod error;
mod graceful_shutdown;
mod payload_encryption;
mod pool_monitor;
pub mod postgres;
mod retry;
mod schema_validation;
pub mod sqlite;
mod traits;
mod ves_commitment;
mod ves_compliance;
mod ves_validity;

pub use audit::{AuditAction, AuditLogBuilder, AuditLogEntry, AuditQueryFilters, PgAuditLogger};
pub use batch::{
    batch_check_existing_command_ids, batch_check_existing_event_ids, chunked,
    dedupe_preserve_order, partition_for_parallel, BatchConfig, BatchStats, DEFAULT_BATCH_SIZE,
};
pub use cache::{
    AgentKeyCache, CacheManager, CacheRefreshConfig, CacheStats, CachedAgentKey, CachedCommitment,
    CommitmentCache, LruCache, ProofCache,
};
pub use circuit_breaker::{
    CircuitBreaker, CircuitBreakerConfig, CircuitBreakerError, CircuitBreakerRegistry, CircuitState,
};
pub use commitment::PgCommitmentEngine;
pub use dead_letter::{
    DeadLetterEvent, DeadLetterReason, DeadLetterRetryConfig, DeadLetterStats, DeadLetterStatus,
    EnqueueParams, PgDeadLetterQueue,
};
pub use error::{
    contexts, ContextualError, ErrorContext, Result, ResultExt, SequencerError,
};
pub use graceful_shutdown::{
    serve_with_shutdown, shutdown_signal, spawn_until_shutdown, GracefulShutdownConfig,
    RequestGuard, RequestTracker, ShutdownCoordinator, ShutdownSignal,
};
pub use payload_encryption::{PayloadEncryption, PayloadEncryptionMode};
pub use pool_monitor::{PoolHealthStatus, PoolMonitor, PoolMonitorConfig, PoolStats};
pub use postgres::{PgAgentKeyRegistry, PgEventStore, PgSchemaStore, PgSequencer, VesSequencer};
pub use retry::{is_retryable_db_error, retry, retry_with_config, Retry, RetryConfig, RetryResult};
pub use schema_validation::SchemaValidationMode;
pub use sqlite::SqliteOutbox;
pub use traits::*;
pub use ves_commitment::PgVesCommitmentEngine;
pub use ves_compliance::{PgVesComplianceProofStore, VesComplianceEventInputs};
pub use ves_validity::PgVesValidityProofStore;
