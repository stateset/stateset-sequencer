//! Error types for StateSet Sequencer infrastructure
//!
//! Provides structured error types with:
//! - Error classification for appropriate HTTP status codes
//! - Source tracking for error chains
//! - Context propagation for debugging
//! - Tracing integration for correlation

use std::borrow::Cow;
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

    /// Schema not found
    #[error("schema not found for event type: {0}")]
    SchemaNotFound(String),

    /// Schema version not found
    #[error("schema version {version} not found for event type: {event_type}")]
    SchemaVersionNotFound { event_type: String, version: u32 },

    /// Schema validation failed
    #[error("schema validation failed: {0}")]
    SchemaValidationFailed(String),

    /// Invalid JSON Schema definition
    #[error("invalid JSON schema: {0}")]
    InvalidJsonSchema(String),

    /// Schema compatibility violation
    #[error("schema compatibility violation: {0}")]
    SchemaCompatibilityViolation(String),
}

/// Result type for sequencer operations
pub type Result<T> = std::result::Result<T, SequencerError>;

// ============================================================================
// Error Context and Extensions
// ============================================================================

/// Additional context for errors
#[derive(Debug, Clone, Default)]
pub struct ErrorContext {
    /// Component/layer where the error originated
    pub component: Option<Cow<'static, str>>,
    /// Operation that was being performed
    pub operation: Option<Cow<'static, str>>,
    /// Tenant ID if available
    pub tenant_id: Option<Uuid>,
    /// Store ID if available
    pub store_id: Option<Uuid>,
    /// Event ID if relevant
    pub event_id: Option<Uuid>,
    /// Span ID for tracing correlation
    pub span_id: Option<String>,
    /// Additional context key-value pairs
    pub extra: Vec<(Cow<'static, str>, String)>,
}

impl ErrorContext {
    /// Create a new error context
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the component/layer
    pub fn component(mut self, component: impl Into<Cow<'static, str>>) -> Self {
        self.component = Some(component.into());
        self
    }

    /// Set the operation being performed
    pub fn operation(mut self, operation: impl Into<Cow<'static, str>>) -> Self {
        self.operation = Some(operation.into());
        self
    }

    /// Set the tenant ID
    pub fn tenant(mut self, tenant_id: Uuid) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }

    /// Set the store ID
    pub fn store(mut self, store_id: Uuid) -> Self {
        self.store_id = Some(store_id);
        self
    }

    /// Set the event ID
    pub fn event(mut self, event_id: Uuid) -> Self {
        self.event_id = Some(event_id);
        self
    }

    /// Add additional context
    pub fn with(mut self, key: impl Into<Cow<'static, str>>, value: impl ToString) -> Self {
        self.extra.push((key.into(), value.to_string()));
        self
    }

    /// Capture current tracing span
    pub fn with_current_span(mut self) -> Self {
        self.span_id = tracing::Span::current()
            .id()
            .map(|id| format!("{:x}", id.into_u64()));
        self
    }

    /// Convert to a JSON value for logging
    pub fn to_json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();

        if let Some(ref component) = self.component {
            map.insert("component".to_string(), serde_json::json!(component));
        }
        if let Some(ref operation) = self.operation {
            map.insert("operation".to_string(), serde_json::json!(operation));
        }
        if let Some(tenant_id) = self.tenant_id {
            map.insert("tenant_id".to_string(), serde_json::json!(tenant_id));
        }
        if let Some(store_id) = self.store_id {
            map.insert("store_id".to_string(), serde_json::json!(store_id));
        }
        if let Some(event_id) = self.event_id {
            map.insert("event_id".to_string(), serde_json::json!(event_id));
        }
        if let Some(ref span_id) = self.span_id {
            map.insert("span_id".to_string(), serde_json::json!(span_id));
        }
        for (key, value) in &self.extra {
            map.insert(key.to_string(), serde_json::json!(value));
        }

        serde_json::Value::Object(map)
    }
}

/// Error with additional context
#[derive(Debug)]
pub struct ContextualError {
    /// The underlying error
    pub error: SequencerError,
    /// Additional context
    pub context: ErrorContext,
}

impl std::fmt::Display for ContextualError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)?;
        if let Some(ref component) = self.context.component {
            write!(f, " [component: {}]", component)?;
        }
        if let Some(ref operation) = self.context.operation {
            write!(f, " [operation: {}]", operation)?;
        }
        Ok(())
    }
}

impl std::error::Error for ContextualError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl ContextualError {
    /// Create a new contextual error
    pub fn new(error: SequencerError, context: ErrorContext) -> Self {
        Self { error, context }
    }

    /// Log the error with context using tracing
    pub fn log(&self) {
        let context_json = self.context.to_json();

        match &self.error {
            SequencerError::Database(_) | SequencerError::Internal(_) => {
                tracing::error!(
                    error = %self.error,
                    context = %context_json,
                    "Internal error occurred"
                );
            }
            SequencerError::RateLimited => {
                tracing::warn!(
                    error = %self.error,
                    context = %context_json,
                    "Rate limit exceeded"
                );
            }
            _ => {
                tracing::info!(
                    error = %self.error,
                    context = %context_json,
                    "Error occurred"
                );
            }
        }
    }
}

/// Extension trait for adding context to Results
#[allow(clippy::result_large_err)] // ContextualError is intentionally rich with context
pub trait ResultExt<T> {
    /// Add context to an error
    fn with_context(self, context: ErrorContext) -> std::result::Result<T, ContextualError>;

    /// Add component context to an error
    fn in_component(self, component: &'static str) -> std::result::Result<T, ContextualError>;

    /// Add operation context to an error
    fn during(self, operation: &'static str) -> std::result::Result<T, ContextualError>;
}

#[allow(clippy::result_large_err)]
impl<T> ResultExt<T> for Result<T> {
    fn with_context(self, context: ErrorContext) -> std::result::Result<T, ContextualError> {
        self.map_err(|e| ContextualError::new(e, context))
    }

    fn in_component(self, component: &'static str) -> std::result::Result<T, ContextualError> {
        self.map_err(|e| {
            ContextualError::new(e, ErrorContext::new().component(component))
        })
    }

    fn during(self, operation: &'static str) -> std::result::Result<T, ContextualError> {
        self.map_err(|e| {
            ContextualError::new(e, ErrorContext::new().operation(operation))
        })
    }
}

/// Helper to create common error contexts
pub mod contexts {
    use super::*;

    /// Context for event ingestion operations
    pub fn ingest(tenant_id: Uuid, store_id: Uuid) -> ErrorContext {
        ErrorContext::new()
            .component("ingest")
            .operation("event_ingestion")
            .tenant(tenant_id)
            .store(store_id)
    }

    /// Context for sequencing operations
    pub fn sequence(tenant_id: Uuid, store_id: Uuid) -> ErrorContext {
        ErrorContext::new()
            .component("sequencer")
            .operation("sequence_events")
            .tenant(tenant_id)
            .store(store_id)
    }

    /// Context for projection operations
    pub fn project(tenant_id: Uuid, store_id: Uuid) -> ErrorContext {
        ErrorContext::new()
            .component("projector")
            .operation("apply_events")
            .tenant(tenant_id)
            .store(store_id)
    }

    /// Context for commitment operations
    pub fn commit(tenant_id: Uuid, store_id: Uuid, batch_id: Uuid) -> ErrorContext {
        ErrorContext::new()
            .component("commitment")
            .operation("create_commitment")
            .tenant(tenant_id)
            .store(store_id)
            .with("batch_id", batch_id)
    }

    /// Context for anchoring operations
    pub fn anchor(batch_id: Uuid) -> ErrorContext {
        ErrorContext::new()
            .component("anchor")
            .operation("anchor_commitment")
            .with("batch_id", batch_id)
    }

    /// Context for schema validation operations
    pub fn validate_schema(tenant_id: Uuid, event_type: &str) -> ErrorContext {
        ErrorContext::new()
            .component("schema_registry")
            .operation("validate_payload")
            .tenant(tenant_id)
            .with("event_type", event_type)
    }

    /// Context for signature verification
    pub fn verify_signature(event_id: Uuid, agent_id: Uuid) -> ErrorContext {
        ErrorContext::new()
            .component("signature")
            .operation("verify_signature")
            .event(event_id)
            .with("agent_id", agent_id)
    }

    /// Context for database operations
    pub fn database(operation: &'static str) -> ErrorContext {
        ErrorContext::new()
            .component("database")
            .operation(operation)
    }
}

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
    fn test_schema_not_found_error() {
        let err = SequencerError::SchemaNotFound("order.created".to_string());
        assert!(err.to_string().contains("schema not found"));
        assert!(err.to_string().contains("order.created"));
    }

    #[test]
    fn test_schema_version_not_found_error() {
        let err = SequencerError::SchemaVersionNotFound {
            event_type: "order.created".to_string(),
            version: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains("schema version"));
        assert!(msg.contains("3"));
        assert!(msg.contains("order.created"));
    }

    #[test]
    fn test_schema_validation_failed_error() {
        let err = SequencerError::SchemaValidationFailed("missing required field: order_id".to_string());
        assert!(err.to_string().contains("schema validation failed"));
        assert!(err.to_string().contains("order_id"));
    }

    #[test]
    fn test_invalid_json_schema_error() {
        let err = SequencerError::InvalidJsonSchema("invalid type keyword".to_string());
        assert!(err.to_string().contains("invalid JSON schema"));
        assert!(err.to_string().contains("invalid type keyword"));
    }

    #[test]
    fn test_schema_compatibility_violation_error() {
        let err = SequencerError::SchemaCompatibilityViolation("removed required field".to_string());
        assert!(err.to_string().contains("schema compatibility violation"));
        assert!(err.to_string().contains("removed required field"));
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

    // ========================================================================
    // Error context tests
    // ========================================================================

    #[test]
    fn test_error_context_builder() {
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();
        let event_id = Uuid::new_v4();

        let ctx = ErrorContext::new()
            .component("test")
            .operation("test_op")
            .tenant(tenant_id)
            .store(store_id)
            .event(event_id)
            .with("extra_key", "extra_value");

        assert_eq!(ctx.component.as_deref(), Some("test"));
        assert_eq!(ctx.operation.as_deref(), Some("test_op"));
        assert_eq!(ctx.tenant_id, Some(tenant_id));
        assert_eq!(ctx.store_id, Some(store_id));
        assert_eq!(ctx.event_id, Some(event_id));
        assert_eq!(ctx.extra.len(), 1);
        assert_eq!(ctx.extra[0].0.as_ref(), "extra_key");
        assert_eq!(ctx.extra[0].1, "extra_value");
    }

    #[test]
    fn test_error_context_to_json() {
        let tenant_id = Uuid::new_v4();

        let ctx = ErrorContext::new()
            .component("sequencer")
            .tenant(tenant_id);

        let json = ctx.to_json();
        assert!(json.get("component").is_some());
        assert!(json.get("tenant_id").is_some());
    }

    #[test]
    fn test_contextual_error_display() {
        let err = SequencerError::RateLimited;
        let ctx_err = ContextualError::new(
            err,
            ErrorContext::new().component("api").operation("ingest"),
        );

        let display = format!("{}", ctx_err);
        assert!(display.contains("rate limit exceeded"));
        assert!(display.contains("[component: api]"));
        assert!(display.contains("[operation: ingest]"));
    }

    #[test]
    fn test_result_ext_with_context() {
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();

        let result: Result<()> = Err(SequencerError::RateLimited);
        let ctx_result = result.with_context(
            ErrorContext::new().tenant(tenant_id).store(store_id),
        );

        assert!(ctx_result.is_err());
        let ctx_err = ctx_result.unwrap_err();
        assert_eq!(ctx_err.context.tenant_id, Some(tenant_id));
        assert_eq!(ctx_err.context.store_id, Some(store_id));
    }

    #[test]
    fn test_result_ext_in_component() {
        let result: Result<()> = Err(SequencerError::RateLimited);
        let ctx_result = result.in_component("api_handler");

        assert!(ctx_result.is_err());
        let ctx_err = ctx_result.unwrap_err();
        assert_eq!(ctx_err.context.component.as_deref(), Some("api_handler"));
    }

    #[test]
    fn test_result_ext_during() {
        let result: Result<()> = Err(SequencerError::RateLimited);
        let ctx_result = result.during("event_processing");

        assert!(ctx_result.is_err());
        let ctx_err = ctx_result.unwrap_err();
        assert_eq!(ctx_err.context.operation.as_deref(), Some("event_processing"));
    }

    #[test]
    fn test_contexts_helper_ingest() {
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();

        let ctx = contexts::ingest(tenant_id, store_id);
        assert_eq!(ctx.component.as_deref(), Some("ingest"));
        assert_eq!(ctx.operation.as_deref(), Some("event_ingestion"));
        assert_eq!(ctx.tenant_id, Some(tenant_id));
        assert_eq!(ctx.store_id, Some(store_id));
    }

    #[test]
    fn test_contexts_helper_sequence() {
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();

        let ctx = contexts::sequence(tenant_id, store_id);
        assert_eq!(ctx.component.as_deref(), Some("sequencer"));
        assert_eq!(ctx.operation.as_deref(), Some("sequence_events"));
    }

    #[test]
    fn test_contexts_helper_commit() {
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();
        let batch_id = Uuid::new_v4();

        let ctx = contexts::commit(tenant_id, store_id, batch_id);
        assert_eq!(ctx.component.as_deref(), Some("commitment"));
        assert!(ctx.extra.iter().any(|(k, _)| k.as_ref() == "batch_id"));
    }

    #[test]
    fn test_contextual_error_source() {
        use std::error::Error;

        let err = SequencerError::RateLimited;
        let ctx_err = ContextualError::new(err, ErrorContext::new());

        // Should have source pointing to the underlying error
        assert!(ctx_err.source().is_some());
    }
}
