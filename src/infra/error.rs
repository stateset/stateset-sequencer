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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_error_display() {
        // Can't easily construct sqlx::Error, but we can test the format
        let err = SequencerError::Internal("db connection failed".to_string());
        assert!(err.to_string().contains("internal error"));
    }

    #[test]
    fn test_event_not_found_error() {
        let event_id = Uuid::parse_str("12345678-1234-1234-1234-123456789abc").unwrap();
        let err = SequencerError::EventNotFound(event_id);
        assert!(err.to_string().contains("event not found"));
        assert!(err.to_string().contains("12345678-1234-1234-1234-123456789abc"));
    }

    #[test]
    fn test_batch_not_found_error() {
        let batch_id = Uuid::new_v4();
        let err = SequencerError::BatchNotFound(batch_id);
        assert!(err.to_string().contains("batch not found"));
        assert!(err.to_string().contains(&batch_id.to_string()));
    }

    #[test]
    fn test_entity_not_found_error() {
        let err = SequencerError::EntityNotFound {
            entity_type: "order".to_string(),
            entity_id: "order-123".to_string(),
        };
        assert!(err.to_string().contains("entity not found"));
        assert!(err.to_string().contains("order"));
        assert!(err.to_string().contains("order-123"));
    }

    #[test]
    fn test_version_conflict_error() {
        let err = SequencerError::VersionConflict {
            entity_type: "inventory".to_string(),
            entity_id: "sku-001".to_string(),
            expected: 5,
            actual: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains("version conflict"));
        assert!(msg.contains("inventory"));
        assert!(msg.contains("sku-001"));
        assert!(msg.contains("5"));
        assert!(msg.contains("3"));
    }

    #[test]
    fn test_invariant_violation_error() {
        let err = SequencerError::InvariantViolation {
            invariant: "positive_quantity".to_string(),
            message: "quantity cannot be negative".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("invariant violation"));
        assert!(msg.contains("positive_quantity"));
        assert!(msg.contains("quantity cannot be negative"));
    }

    #[test]
    fn test_invalid_state_transition_error() {
        let err = SequencerError::InvalidStateTransition {
            entity_type: "order".to_string(),
            entity_id: "order-456".to_string(),
            from: "pending".to_string(),
            to: "shipped".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("invalid state transition"));
        assert!(msg.contains("pending"));
        assert!(msg.contains("shipped"));
    }

    #[test]
    fn test_schema_validation_error() {
        let err = SequencerError::SchemaValidation("missing required field".to_string());
        assert!(err.to_string().contains("schema validation"));
        assert!(err.to_string().contains("missing required field"));
    }

    #[test]
    fn test_unauthorized_error() {
        let err = SequencerError::Unauthorized("invalid API key".to_string());
        assert!(err.to_string().contains("authorization error"));
        assert!(err.to_string().contains("invalid API key"));
    }

    #[test]
    fn test_rate_limited_error() {
        let err = SequencerError::RateLimited;
        assert!(err.to_string().contains("rate limit exceeded"));
    }

    #[test]
    fn test_duplicate_event_error() {
        let event_id = Uuid::new_v4();
        let err = SequencerError::DuplicateEvent(event_id);
        assert!(err.to_string().contains("duplicate event"));
        assert!(err.to_string().contains(&event_id.to_string()));
    }

    #[test]
    fn test_duplicate_command_error() {
        let cmd_id = Uuid::new_v4();
        let err = SequencerError::DuplicateCommand(cmd_id);
        assert!(err.to_string().contains("duplicate command"));
        assert!(err.to_string().contains(&cmd_id.to_string()));
    }

    #[test]
    fn test_invalid_payload_hash_error() {
        let event_id = Uuid::new_v4();
        let err = SequencerError::InvalidPayloadHash(event_id);
        assert!(err.to_string().contains("invalid payload hash"));
    }

    #[test]
    fn test_encryption_error() {
        let err = SequencerError::Encryption("key not found".to_string());
        assert!(err.to_string().contains("encryption error"));
        assert!(err.to_string().contains("key not found"));
    }

    #[test]
    fn test_merkle_tree_error() {
        let err = SequencerError::MerkleTree("invalid proof".to_string());
        assert!(err.to_string().contains("merkle tree error"));
        assert!(err.to_string().contains("invalid proof"));
    }

    #[test]
    fn test_configuration_error() {
        let err = SequencerError::Configuration("missing DATABASE_URL".to_string());
        assert!(err.to_string().contains("configuration error"));
        assert!(err.to_string().contains("DATABASE_URL"));
    }

    #[test]
    fn test_internal_error() {
        let err = SequencerError::Internal("unexpected state".to_string());
        assert!(err.to_string().contains("internal error"));
        assert!(err.to_string().contains("unexpected state"));
    }

    #[test]
    fn test_invalid_entity_type_error() {
        let err = SequencerError::InvalidEntityType("unknown_type".to_string());
        assert!(err.to_string().contains("invalid entity type"));
        assert!(err.to_string().contains("unknown_type"));
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SequencerError>();
    }

    #[test]
    fn test_error_debug_format() {
        let err = SequencerError::RateLimited;
        let debug = format!("{:?}", err);
        assert!(debug.contains("RateLimited"));
    }
}
