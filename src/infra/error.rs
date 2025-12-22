//! Error types for StateSet Sequencer infrastructure

use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur in the sequencer infrastructure
#[derive(Error, Debug)]
pub enum SequencerError {
    /// Database error
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Event not found
    #[error("event not found: {0}")]
    EventNotFound(Uuid),

    /// Batch not found
    #[error("batch not found: {0}")]
    BatchNotFound(Uuid),

    /// Entity not found
    #[error("entity not found: {entity_type}/{entity_id}")]
    EntityNotFound {
        entity_type: String,
        entity_id: String,
    },

    /// Version conflict during projection
    #[error("version conflict for {entity_type}/{entity_id}: expected {expected}, got {actual}")]
    VersionConflict {
        entity_type: String,
        entity_id: String,
        expected: u64,
        actual: u64,
    },

    /// Invariant violation
    #[error("invariant violation: {invariant} - {message}")]
    InvariantViolation { invariant: String, message: String },

    /// Invalid state transition
    #[error("invalid state transition for {entity_type}/{entity_id}: {from} -> {to}")]
    InvalidStateTransition {
        entity_type: String,
        entity_id: String,
        from: String,
        to: String,
    },

    /// Schema validation error
    #[error("schema validation error: {0}")]
    SchemaValidation(String),

    /// Authorization error
    #[error("authorization error: {0}")]
    Unauthorized(String),

    /// Rate limit exceeded
    #[error("rate limit exceeded")]
    RateLimited,

    /// Duplicate event
    #[error("duplicate event: {0}")]
    DuplicateEvent(Uuid),

    /// Duplicate command
    #[error("duplicate command: {0}")]
    DuplicateCommand(Uuid),

    /// Invalid payload hash
    #[error("invalid payload hash for event {0}")]
    InvalidPayloadHash(Uuid),

    /// Encryption error
    #[error("encryption error: {0}")]
    Encryption(String),

    /// Merkle tree error
    #[error("merkle tree error: {0}")]
    MerkleTree(String),

    /// Configuration error
    #[error("configuration error: {0}")]
    Configuration(String),

    /// Internal error
    #[error("internal error: {0}")]
    Internal(String),

    /// Invalid entity type
    #[error("invalid entity type: {0}")]
    InvalidEntityType(String),
}

/// Result type for sequencer operations
pub type Result<T> = std::result::Result<T, SequencerError>;
