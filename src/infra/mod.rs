//! Infrastructure layer for StateSet Sequencer
//!
//! Contains trait definitions and implementations for:
//! - Event storage (PostgreSQL, SQLite)
//! - Sequencer (canonical ordering)
//! - Projector (state projection)
//! - Commitment engine (Merkle roots)
//! - Caching (in-memory LRU)
//! - Circuit breaker (external service protection)
//! - Graceful shutdown (request draining)
//! - Audit logging (admin operations)
//! - Dead letter queue (failed projections)

mod audit;
mod cache;
mod circuit_breaker;
mod commitment;
mod dead_letter;
mod error;
mod graceful_shutdown;
mod payload_encryption;
pub mod postgres;
mod schema_validation;
pub mod sqlite;
mod traits;
mod ves_commitment;
mod ves_compliance;
mod ves_validity;

pub use audit::{AuditAction, AuditLogBuilder, AuditLogEntry, AuditQueryFilters, PgAuditLogger};
pub use cache::{
    AgentKeyCache, CacheManager, CacheStats, CachedAgentKey, CachedCommitment, CommitmentCache,
    LruCache, ProofCache,
};
pub use circuit_breaker::{
    CircuitBreaker, CircuitBreakerConfig, CircuitBreakerError, CircuitBreakerRegistry, CircuitState,
};
pub use commitment::PgCommitmentEngine;
pub use dead_letter::{DeadLetterEvent, DeadLetterReason, DeadLetterStats, PgDeadLetterQueue};
pub use error::*;
pub use graceful_shutdown::{
    serve_with_shutdown, shutdown_signal, spawn_until_shutdown, GracefulShutdownConfig,
    RequestGuard, RequestTracker, ShutdownCoordinator, ShutdownSignal,
};
pub use payload_encryption::{PayloadEncryption, PayloadEncryptionMode};
pub use postgres::{PgAgentKeyRegistry, PgEventStore, PgSchemaStore, PgSequencer, VesSequencer};
pub use schema_validation::SchemaValidationMode;
pub use sqlite::SqliteOutbox;
pub use traits::*;
pub use ves_commitment::PgVesCommitmentEngine;
pub use ves_compliance::{PgVesComplianceProofStore, VesComplianceEventInputs};
pub use ves_validity::PgVesValidityProofStore;
