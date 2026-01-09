//! Structured API error responses with error codes
//!
//! This module provides consistent error handling across all API endpoints
//! with machine-readable error codes and human-readable messages.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

// ============================================================================
// Error Codes
// ============================================================================

/// Error codes for API responses
///
/// These codes are stable and can be used by clients for programmatic error handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    // Authentication errors (1xxx)
    /// No authentication credentials provided
    AuthRequired,
    /// Invalid API key format or value
    InvalidApiKey,
    /// Invalid or expired JWT token
    InvalidToken,
    /// Token has expired
    TokenExpired,
    /// Insufficient permissions for this operation
    InsufficientPermissions,

    // Rate limiting errors (2xxx)
    /// Too many requests, rate limit exceeded
    RateLimitExceeded,
    /// Request quota exhausted
    QuotaExceeded,

    // Validation errors (3xxx)
    /// Request body is malformed
    InvalidRequestBody,
    /// Required field is missing
    MissingRequiredField,
    /// Field value is invalid
    InvalidFieldValue,
    /// Payload exceeds size limit
    PayloadTooLarge,
    /// Batch size exceeds limit
    BatchTooLarge,
    /// JSON schema validation failed
    SchemaValidationFailed,
    /// No schema registered for event type
    SchemaNotFound,

    // Resource errors (4xxx)
    /// Requested resource not found
    ResourceNotFound,
    /// Event not found
    EventNotFound,
    /// Batch/commitment not found
    BatchNotFound,
    /// Entity not found
    EntityNotFound,
    /// Agent key not found
    AgentKeyNotFound,

    // Conflict errors (5xxx)
    /// Duplicate event ID
    DuplicateEvent,
    /// Duplicate command ID
    DuplicateCommand,
    /// Version conflict during update
    VersionConflict,
    /// Resource already exists
    AlreadyExists,

    // Signature/crypto errors (6xxx)
    /// Invalid signature format
    InvalidSignature,
    /// Signature verification failed
    SignatureVerificationFailed,
    /// Invalid public key format
    InvalidPublicKey,
    /// Invalid payload hash
    InvalidPayloadHash,
    /// Encryption/decryption failed
    EncryptionError,

    // State errors (7xxx)
    /// Invalid state transition
    InvalidStateTransition,
    /// Invariant violation
    InvariantViolation,
    /// Sequence gap detected
    SequenceGap,

    // Infrastructure errors (8xxx)
    /// Database operation failed
    DatabaseError,
    /// External service unavailable
    ServiceUnavailable,
    /// Operation timed out
    Timeout,
    /// Internal server error
    InternalError,

    // Anchoring errors (9xxx)
    /// Anchor service not configured
    AnchorNotConfigured,
    /// Anchor transaction failed
    AnchorFailed,
    /// Commitment not yet anchored
    NotAnchored,
}

impl ErrorCode {
    /// Get the numeric code for this error
    pub fn numeric_code(&self) -> u32 {
        match self {
            // Auth (1xxx)
            ErrorCode::AuthRequired => 1001,
            ErrorCode::InvalidApiKey => 1002,
            ErrorCode::InvalidToken => 1003,
            ErrorCode::TokenExpired => 1004,
            ErrorCode::InsufficientPermissions => 1005,

            // Rate limiting (2xxx)
            ErrorCode::RateLimitExceeded => 2001,
            ErrorCode::QuotaExceeded => 2002,

            // Validation (3xxx)
            ErrorCode::InvalidRequestBody => 3001,
            ErrorCode::MissingRequiredField => 3002,
            ErrorCode::InvalidFieldValue => 3003,
            ErrorCode::PayloadTooLarge => 3004,
            ErrorCode::BatchTooLarge => 3005,
            ErrorCode::SchemaValidationFailed => 3006,
            ErrorCode::SchemaNotFound => 3007,

            // Resource (4xxx)
            ErrorCode::ResourceNotFound => 4001,
            ErrorCode::EventNotFound => 4002,
            ErrorCode::BatchNotFound => 4003,
            ErrorCode::EntityNotFound => 4004,
            ErrorCode::AgentKeyNotFound => 4005,

            // Conflict (5xxx)
            ErrorCode::DuplicateEvent => 5001,
            ErrorCode::DuplicateCommand => 5002,
            ErrorCode::VersionConflict => 5003,
            ErrorCode::AlreadyExists => 5004,

            // Crypto (6xxx)
            ErrorCode::InvalidSignature => 6001,
            ErrorCode::SignatureVerificationFailed => 6002,
            ErrorCode::InvalidPublicKey => 6003,
            ErrorCode::InvalidPayloadHash => 6004,
            ErrorCode::EncryptionError => 6005,

            // State (7xxx)
            ErrorCode::InvalidStateTransition => 7001,
            ErrorCode::InvariantViolation => 7002,
            ErrorCode::SequenceGap => 7003,

            // Infrastructure (8xxx)
            ErrorCode::DatabaseError => 8001,
            ErrorCode::ServiceUnavailable => 8002,
            ErrorCode::Timeout => 8003,
            ErrorCode::InternalError => 8999,

            // Anchoring (9xxx)
            ErrorCode::AnchorNotConfigured => 9001,
            ErrorCode::AnchorFailed => 9002,
            ErrorCode::NotAnchored => 9003,
        }
    }

    /// Get the HTTP status code for this error
    pub fn http_status(&self) -> StatusCode {
        match self {
            // Auth errors -> 401/403
            ErrorCode::AuthRequired => StatusCode::UNAUTHORIZED,
            ErrorCode::InvalidApiKey => StatusCode::UNAUTHORIZED,
            ErrorCode::InvalidToken => StatusCode::UNAUTHORIZED,
            ErrorCode::TokenExpired => StatusCode::UNAUTHORIZED,
            ErrorCode::InsufficientPermissions => StatusCode::FORBIDDEN,

            // Rate limiting -> 429
            ErrorCode::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::QuotaExceeded => StatusCode::TOO_MANY_REQUESTS,

            // Validation -> 400
            ErrorCode::InvalidRequestBody => StatusCode::BAD_REQUEST,
            ErrorCode::MissingRequiredField => StatusCode::BAD_REQUEST,
            ErrorCode::InvalidFieldValue => StatusCode::BAD_REQUEST,
            ErrorCode::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::BatchTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::SchemaValidationFailed => StatusCode::BAD_REQUEST,
            ErrorCode::SchemaNotFound => StatusCode::BAD_REQUEST,

            // Resource -> 404
            ErrorCode::ResourceNotFound => StatusCode::NOT_FOUND,
            ErrorCode::EventNotFound => StatusCode::NOT_FOUND,
            ErrorCode::BatchNotFound => StatusCode::NOT_FOUND,
            ErrorCode::EntityNotFound => StatusCode::NOT_FOUND,
            ErrorCode::AgentKeyNotFound => StatusCode::NOT_FOUND,

            // Conflict -> 409
            ErrorCode::DuplicateEvent => StatusCode::CONFLICT,
            ErrorCode::DuplicateCommand => StatusCode::CONFLICT,
            ErrorCode::VersionConflict => StatusCode::CONFLICT,
            ErrorCode::AlreadyExists => StatusCode::CONFLICT,

            // Crypto -> 400
            ErrorCode::InvalidSignature => StatusCode::BAD_REQUEST,
            ErrorCode::SignatureVerificationFailed => StatusCode::BAD_REQUEST,
            ErrorCode::InvalidPublicKey => StatusCode::BAD_REQUEST,
            ErrorCode::InvalidPayloadHash => StatusCode::BAD_REQUEST,
            ErrorCode::EncryptionError => StatusCode::INTERNAL_SERVER_ERROR,

            // State -> 400/409
            ErrorCode::InvalidStateTransition => StatusCode::BAD_REQUEST,
            ErrorCode::InvariantViolation => StatusCode::BAD_REQUEST,
            ErrorCode::SequenceGap => StatusCode::CONFLICT,

            // Infrastructure -> 500/503
            ErrorCode::DatabaseError => StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Timeout => StatusCode::GATEWAY_TIMEOUT,
            ErrorCode::InternalError => StatusCode::INTERNAL_SERVER_ERROR,

            // Anchoring -> various
            ErrorCode::AnchorNotConfigured => StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::AnchorFailed => StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::NotAnchored => StatusCode::BAD_REQUEST,
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code_str = match self {
            ErrorCode::AuthRequired => "AUTH_REQUIRED",
            ErrorCode::InvalidApiKey => "INVALID_API_KEY",
            ErrorCode::InvalidToken => "INVALID_TOKEN",
            ErrorCode::TokenExpired => "TOKEN_EXPIRED",
            ErrorCode::InsufficientPermissions => "INSUFFICIENT_PERMISSIONS",
            ErrorCode::RateLimitExceeded => "RATE_LIMIT_EXCEEDED",
            ErrorCode::QuotaExceeded => "QUOTA_EXCEEDED",
            ErrorCode::InvalidRequestBody => "INVALID_REQUEST_BODY",
            ErrorCode::MissingRequiredField => "MISSING_REQUIRED_FIELD",
            ErrorCode::InvalidFieldValue => "INVALID_FIELD_VALUE",
            ErrorCode::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            ErrorCode::BatchTooLarge => "BATCH_TOO_LARGE",
            ErrorCode::SchemaValidationFailed => "SCHEMA_VALIDATION_FAILED",
            ErrorCode::SchemaNotFound => "SCHEMA_NOT_FOUND",
            ErrorCode::ResourceNotFound => "RESOURCE_NOT_FOUND",
            ErrorCode::EventNotFound => "EVENT_NOT_FOUND",
            ErrorCode::BatchNotFound => "BATCH_NOT_FOUND",
            ErrorCode::EntityNotFound => "ENTITY_NOT_FOUND",
            ErrorCode::AgentKeyNotFound => "AGENT_KEY_NOT_FOUND",
            ErrorCode::DuplicateEvent => "DUPLICATE_EVENT",
            ErrorCode::DuplicateCommand => "DUPLICATE_COMMAND",
            ErrorCode::VersionConflict => "VERSION_CONFLICT",
            ErrorCode::AlreadyExists => "ALREADY_EXISTS",
            ErrorCode::InvalidSignature => "INVALID_SIGNATURE",
            ErrorCode::SignatureVerificationFailed => "SIGNATURE_VERIFICATION_FAILED",
            ErrorCode::InvalidPublicKey => "INVALID_PUBLIC_KEY",
            ErrorCode::InvalidPayloadHash => "INVALID_PAYLOAD_HASH",
            ErrorCode::EncryptionError => "ENCRYPTION_ERROR",
            ErrorCode::InvalidStateTransition => "INVALID_STATE_TRANSITION",
            ErrorCode::InvariantViolation => "INVARIANT_VIOLATION",
            ErrorCode::SequenceGap => "SEQUENCE_GAP",
            ErrorCode::DatabaseError => "DATABASE_ERROR",
            ErrorCode::ServiceUnavailable => "SERVICE_UNAVAILABLE",
            ErrorCode::Timeout => "TIMEOUT",
            ErrorCode::InternalError => "INTERNAL_ERROR",
            ErrorCode::AnchorNotConfigured => "ANCHOR_NOT_CONFIGURED",
            ErrorCode::AnchorFailed => "ANCHOR_FAILED",
            ErrorCode::NotAnchored => "NOT_ANCHORED",
        };
        write!(f, "{}", code_str)
    }
}

// ============================================================================
// Structured Error Response
// ============================================================================

/// Structured error response for API endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    /// Error details
    pub error: ErrorDetails,
}

/// Detailed error information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDetails {
    /// Machine-readable error code
    pub code: ErrorCode,

    /// Numeric error code for easy categorization
    pub numeric_code: u32,

    /// Human-readable error message
    pub message: String,

    /// Unique request ID for tracing (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,

    /// Additional error details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,

    /// Retry information for rate limiting
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,

    /// Related resource ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,

    /// Documentation link
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc_url: Option<String>,
}

impl ApiError {
    /// Create a new API error
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            error: ErrorDetails {
                code,
                numeric_code: code.numeric_code(),
                message: message.into(),
                request_id: None,
                details: None,
                retry_after: None,
                resource_id: None,
                doc_url: None,
            },
        }
    }

    /// Set the request ID
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.error.request_id = Some(request_id.into());
        self
    }

    /// Set additional details
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.error.details = Some(details);
        self
    }

    /// Set retry-after seconds (for rate limiting)
    pub fn with_retry_after(mut self, seconds: u64) -> Self {
        self.error.retry_after = Some(seconds);
        self
    }

    /// Set related resource ID
    pub fn with_resource_id(mut self, id: impl Into<String>) -> Self {
        self.error.resource_id = Some(id.into());
        self
    }

    /// Set documentation URL
    pub fn with_doc_url(mut self, url: impl Into<String>) -> Self {
        self.error.doc_url = Some(url.into());
        self
    }

    /// Get the HTTP status code
    pub fn status(&self) -> StatusCode {
        self.error.code.http_status()
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let code_str = self.error.code.to_string();
        let mut response = (status, Json(self)).into_response();

        // Add error code header for easier debugging
        if let Ok(code_value) = axum::http::HeaderValue::from_str(&code_str) {
            response.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-error-code"),
                code_value,
            );
        }

        response
    }
}

// ============================================================================
// Conversion from SequencerError
// ============================================================================

impl From<crate::infra::SequencerError> for ApiError {
    fn from(err: crate::infra::SequencerError) -> Self {
        use crate::infra::SequencerError;

        match err {
            SequencerError::Database(e) => {
                ApiError::new(ErrorCode::DatabaseError, format!("Database error: {}", e))
            }
            SequencerError::EventNotFound(id) => {
                ApiError::new(ErrorCode::EventNotFound, format!("Event not found: {}", id))
                    .with_resource_id(id.to_string())
            }
            SequencerError::BatchNotFound(id) => {
                ApiError::new(ErrorCode::BatchNotFound, format!("Batch not found: {}", id))
                    .with_resource_id(id.to_string())
            }
            SequencerError::EntityNotFound { entity_type, entity_id } => {
                ApiError::new(
                    ErrorCode::EntityNotFound,
                    format!("Entity not found: {}/{}", entity_type, entity_id)
                ).with_details(serde_json::json!({
                    "entity_type": entity_type,
                    "entity_id": entity_id
                }))
            }
            SequencerError::VersionConflict { entity_type, entity_id, expected, actual } => {
                ApiError::new(
                    ErrorCode::VersionConflict,
                    format!("Version conflict for {}/{}: expected {}, got {}",
                        entity_type, entity_id, expected, actual)
                ).with_details(serde_json::json!({
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "expected_version": expected,
                    "actual_version": actual
                }))
            }
            SequencerError::InvariantViolation { invariant, message } => {
                ApiError::new(
                    ErrorCode::InvariantViolation,
                    format!("Invariant violation: {} - {}", invariant, message)
                ).with_details(serde_json::json!({
                    "invariant": invariant,
                    "details": message
                }))
            }
            SequencerError::InvalidStateTransition { entity_type, entity_id, from, to } => {
                ApiError::new(
                    ErrorCode::InvalidStateTransition,
                    format!("Invalid state transition for {}/{}: {} -> {}",
                        entity_type, entity_id, from, to)
                ).with_details(serde_json::json!({
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "from_state": from,
                    "to_state": to
                }))
            }
            SequencerError::SchemaValidation(msg) => {
                ApiError::new(ErrorCode::SchemaValidationFailed, msg)
            }
            SequencerError::Unauthorized(msg) => {
                ApiError::new(ErrorCode::InsufficientPermissions, msg)
            }
            SequencerError::RateLimited => {
                ApiError::new(ErrorCode::RateLimitExceeded, "Rate limit exceeded")
                    .with_retry_after(60)
            }
            SequencerError::DuplicateEvent(id) => {
                ApiError::new(ErrorCode::DuplicateEvent, format!("Duplicate event: {}", id))
                    .with_resource_id(id.to_string())
            }
            SequencerError::DuplicateCommand(id) => {
                ApiError::new(ErrorCode::DuplicateCommand, format!("Duplicate command: {}", id))
                    .with_resource_id(id.to_string())
            }
            SequencerError::InvalidPayloadHash(id) => {
                ApiError::new(ErrorCode::InvalidPayloadHash, format!("Invalid payload hash for event: {}", id))
                    .with_resource_id(id.to_string())
            }
            SequencerError::Encryption(msg) => {
                ApiError::new(ErrorCode::EncryptionError, msg)
            }
            SequencerError::MerkleTree(msg) => {
                ApiError::new(ErrorCode::InternalError, format!("Merkle tree error: {}", msg))
            }
            SequencerError::Configuration(msg) => {
                ApiError::new(ErrorCode::InternalError, format!("Configuration error: {}", msg))
            }
            SequencerError::Internal(msg) => {
                ApiError::new(ErrorCode::InternalError, msg)
            }
            SequencerError::InvalidEntityType(t) => {
                ApiError::new(ErrorCode::InvalidFieldValue, format!("Invalid entity type: {}", t))
            }
            SequencerError::SchemaNotFound(event_type) => {
                ApiError::new(
                    ErrorCode::SchemaNotFound,
                    format!("No schema registered for event type: {}", event_type)
                ).with_details(serde_json::json!({
                    "event_type": event_type
                }))
            }
            SequencerError::SchemaVersionNotFound { event_type, version } => {
                ApiError::new(
                    ErrorCode::SchemaNotFound,
                    format!("Schema version {} not found for event type: {}", version, event_type)
                ).with_details(serde_json::json!({
                    "event_type": event_type,
                    "version": version
                }))
            }
            SequencerError::SchemaValidationFailed(msg) => {
                ApiError::new(ErrorCode::SchemaValidationFailed, msg)
            }
            SequencerError::InvalidJsonSchema(msg) => {
                ApiError::new(ErrorCode::InvalidFieldValue, format!("Invalid JSON schema: {}", msg))
            }
            SequencerError::SchemaCompatibilityViolation(msg) => {
                ApiError::new(ErrorCode::InvalidFieldValue, format!("Schema compatibility violation: {}", msg))
            }
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a not found error for a specific resource type
pub fn not_found(resource_type: &str, id: impl std::fmt::Display) -> ApiError {
    ApiError::new(
        ErrorCode::ResourceNotFound,
        format!("{} not found: {}", resource_type, id)
    ).with_resource_id(id.to_string())
}

/// Create a validation error with field details
pub fn validation_error(field: &str, message: impl Into<String>) -> ApiError {
    ApiError::new(
        ErrorCode::InvalidFieldValue,
        message.into()
    ).with_details(serde_json::json!({
        "field": field
    }))
}

/// Create a rate limit error with retry-after
pub fn rate_limited(retry_after_seconds: u64) -> ApiError {
    ApiError::new(ErrorCode::RateLimitExceeded, "Rate limit exceeded")
        .with_retry_after(retry_after_seconds)
}

/// Create an unauthorized error
pub fn unauthorized(message: impl Into<String>) -> ApiError {
    ApiError::new(ErrorCode::AuthRequired, message.into())
}

/// Create a forbidden error
pub fn forbidden(message: impl Into<String>) -> ApiError {
    ApiError::new(ErrorCode::InsufficientPermissions, message.into())
}

/// Create an internal error
pub fn internal_error(message: impl Into<String>) -> ApiError {
    ApiError::new(ErrorCode::InternalError, message.into())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_numeric() {
        assert_eq!(ErrorCode::AuthRequired.numeric_code(), 1001);
        assert_eq!(ErrorCode::RateLimitExceeded.numeric_code(), 2001);
        assert_eq!(ErrorCode::InvalidRequestBody.numeric_code(), 3001);
        assert_eq!(ErrorCode::EventNotFound.numeric_code(), 4002);
        assert_eq!(ErrorCode::DuplicateEvent.numeric_code(), 5001);
        assert_eq!(ErrorCode::InvalidSignature.numeric_code(), 6001);
        assert_eq!(ErrorCode::InvalidStateTransition.numeric_code(), 7001);
        assert_eq!(ErrorCode::DatabaseError.numeric_code(), 8001);
        assert_eq!(ErrorCode::InternalError.numeric_code(), 8999);
    }

    #[test]
    fn test_error_code_http_status() {
        assert_eq!(ErrorCode::AuthRequired.http_status(), StatusCode::UNAUTHORIZED);
        assert_eq!(ErrorCode::InsufficientPermissions.http_status(), StatusCode::FORBIDDEN);
        assert_eq!(ErrorCode::RateLimitExceeded.http_status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(ErrorCode::InvalidRequestBody.http_status(), StatusCode::BAD_REQUEST);
        assert_eq!(ErrorCode::EventNotFound.http_status(), StatusCode::NOT_FOUND);
        assert_eq!(ErrorCode::DuplicateEvent.http_status(), StatusCode::CONFLICT);
        assert_eq!(ErrorCode::InternalError.http_status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_api_error_builder() {
        let error = ApiError::new(ErrorCode::EventNotFound, "Event not found")
            .with_request_id("req-123")
            .with_resource_id("event-456")
            .with_details(serde_json::json!({"extra": "info"}));

        assert_eq!(error.error.code, ErrorCode::EventNotFound);
        assert_eq!(error.error.request_id, Some("req-123".to_string()));
        assert_eq!(error.error.resource_id, Some("event-456".to_string()));
        assert!(error.error.details.is_some());
    }

    #[test]
    fn test_rate_limit_error() {
        let error = rate_limited(60);
        assert_eq!(error.error.code, ErrorCode::RateLimitExceeded);
        assert_eq!(error.error.retry_after, Some(60));
    }

    #[test]
    fn test_validation_error() {
        let error = validation_error("email", "Invalid email format");
        assert_eq!(error.error.code, ErrorCode::InvalidFieldValue);
        assert!(error.error.details.is_some());
    }

    #[test]
    fn test_error_serialization() {
        let error = ApiError::new(ErrorCode::EventNotFound, "Event not found");
        let json = serde_json::to_string(&error).unwrap();

        assert!(json.contains("EVENT_NOT_FOUND"));
        assert!(json.contains("Event not found"));
        assert!(json.contains("4002")); // numeric_code
    }

    #[test]
    fn test_error_display() {
        assert_eq!(ErrorCode::EventNotFound.to_string(), "EVENT_NOT_FOUND");
        assert_eq!(ErrorCode::RateLimitExceeded.to_string(), "RATE_LIMIT_EXCEEDED");
    }
}
