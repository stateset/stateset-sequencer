//! Schema registry domain types for event payload validation.
//!
//! Provides JSON Schema support for validating event payloads before ingestion.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{EventType, TenantId};

/// Unique identifier for a schema
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SchemaId(pub Uuid);

impl SchemaId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }
}

impl Default for SchemaId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SchemaId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Schema compatibility mode for version upgrades
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaCompatibility {
    /// New schema can read data written by old schema (forward compatible)
    Forward,
    /// Old schema can read data written by new schema (backward compatible)
    Backward,
    /// Both forward and backward compatible
    Full,
    /// No compatibility checking (allows breaking changes)
    None,
}

impl Default for SchemaCompatibility {
    fn default() -> Self {
        SchemaCompatibility::Backward
    }
}

/// Schema status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaStatus {
    /// Schema is active and used for validation
    Active,
    /// Schema is deprecated but still valid for existing events
    Deprecated,
    /// Schema is archived and should not be used
    Archived,
}

impl Default for SchemaStatus {
    fn default() -> Self {
        SchemaStatus::Active
    }
}

/// A registered schema for an event type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schema {
    /// Unique schema identifier
    pub id: SchemaId,
    /// Tenant that owns this schema
    pub tenant_id: TenantId,
    /// Event type this schema validates
    pub event_type: EventType,
    /// Schema version (monotonically increasing per event type)
    pub version: u32,
    /// The JSON Schema definition
    pub schema_json: serde_json::Value,
    /// Schema status
    pub status: SchemaStatus,
    /// Compatibility mode for upgrades
    pub compatibility: SchemaCompatibility,
    /// Human-readable description
    pub description: Option<String>,
    /// When the schema was created
    pub created_at: DateTime<Utc>,
    /// When the schema was last updated
    pub updated_at: DateTime<Utc>,
    /// User who created the schema
    pub created_by: Option<String>,
}

impl Schema {
    /// Create a new schema
    pub fn new(
        tenant_id: TenantId,
        event_type: EventType,
        version: u32,
        schema_json: serde_json::Value,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: SchemaId::new(),
            tenant_id,
            event_type,
            version,
            schema_json,
            status: SchemaStatus::Active,
            compatibility: SchemaCompatibility::Backward,
            description: None,
            created_at: now,
            updated_at: now,
            created_by: None,
        }
    }

    /// Set the description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set the compatibility mode
    pub fn with_compatibility(mut self, compatibility: SchemaCompatibility) -> Self {
        self.compatibility = compatibility;
        self
    }

    /// Set the creator
    pub fn with_created_by(mut self, created_by: impl Into<String>) -> Self {
        self.created_by = Some(created_by.into());
        self
    }
}

/// Request to register a new schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterSchemaRequest {
    /// Event type this schema validates
    pub event_type: String,
    /// The JSON Schema definition
    pub schema_json: serde_json::Value,
    /// Human-readable description
    pub description: Option<String>,
    /// Compatibility mode (defaults to backward)
    pub compatibility: Option<SchemaCompatibility>,
}

/// Response when a schema is registered
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterSchemaResponse {
    /// The registered schema ID
    pub id: SchemaId,
    /// Event type
    pub event_type: String,
    /// Assigned version number
    pub version: u32,
    /// When it was created
    pub created_at: DateTime<Utc>,
}

/// Schema validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaValidationResult {
    /// Whether the payload is valid
    pub valid: bool,
    /// Schema ID used for validation
    pub schema_id: Option<SchemaId>,
    /// Schema version used
    pub schema_version: Option<u32>,
    /// Validation errors if any
    pub errors: Vec<SchemaValidationError>,
}

impl SchemaValidationResult {
    /// Create a successful validation result
    pub fn valid(schema_id: SchemaId, schema_version: u32) -> Self {
        Self {
            valid: true,
            schema_id: Some(schema_id),
            schema_version: Some(schema_version),
            errors: Vec::new(),
        }
    }

    /// Create a validation result with no schema found
    pub fn no_schema() -> Self {
        Self {
            valid: true, // No schema means validation is skipped
            schema_id: None,
            schema_version: None,
            errors: Vec::new(),
        }
    }

    /// Create a failed validation result
    pub fn invalid(schema_id: SchemaId, schema_version: u32, errors: Vec<SchemaValidationError>) -> Self {
        Self {
            valid: false,
            schema_id: Some(schema_id),
            schema_version: Some(schema_version),
            errors,
        }
    }
}

/// A single schema validation error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaValidationError {
    /// JSON path to the invalid field
    pub path: String,
    /// Error message
    pub message: String,
}

impl SchemaValidationError {
    pub fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_id_new_generates_unique() {
        let id1 = SchemaId::new();
        let id2 = SchemaId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_schema_id_from_uuid() {
        let uuid = Uuid::new_v4();
        let schema_id = SchemaId::from_uuid(uuid);
        assert_eq!(schema_id.0, uuid);
    }

    #[test]
    fn test_schema_id_display() {
        let uuid = Uuid::parse_str("12345678-1234-1234-1234-123456789abc").unwrap();
        let schema_id = SchemaId::from_uuid(uuid);
        assert_eq!(format!("{}", schema_id), "12345678-1234-1234-1234-123456789abc");
    }

    #[test]
    fn test_schema_compatibility_default() {
        assert_eq!(SchemaCompatibility::default(), SchemaCompatibility::Backward);
    }

    #[test]
    fn test_schema_status_default() {
        assert_eq!(SchemaStatus::default(), SchemaStatus::Active);
    }

    #[test]
    fn test_schema_compatibility_serialization() {
        let compat = SchemaCompatibility::Full;
        let json = serde_json::to_string(&compat).unwrap();
        assert_eq!(json, "\"full\"");

        let parsed: SchemaCompatibility = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, SchemaCompatibility::Full);
    }

    #[test]
    fn test_schema_status_serialization() {
        let status = SchemaStatus::Deprecated;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"deprecated\"");

        let parsed: SchemaStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, SchemaStatus::Deprecated);
    }

    #[test]
    fn test_schema_new() {
        let tenant_id = TenantId::new();
        let event_type = EventType::from("order.created");
        let schema_json = serde_json::json!({
            "type": "object",
            "properties": {
                "order_id": { "type": "string" }
            }
        });

        let schema = Schema::new(
            tenant_id.clone(),
            event_type.clone(),
            1,
            schema_json.clone(),
        );

        assert_eq!(schema.tenant_id, tenant_id);
        assert_eq!(schema.event_type, event_type);
        assert_eq!(schema.version, 1);
        assert_eq!(schema.schema_json, schema_json);
        assert_eq!(schema.status, SchemaStatus::Active);
        assert_eq!(schema.compatibility, SchemaCompatibility::Backward);
        assert!(schema.description.is_none());
    }

    #[test]
    fn test_schema_builder_methods() {
        let tenant_id = TenantId::new();
        let event_type = EventType::from("order.created");
        let schema_json = serde_json::json!({"type": "object"});

        let schema = Schema::new(tenant_id, event_type, 1, schema_json)
            .with_description("Order creation schema")
            .with_compatibility(SchemaCompatibility::Full)
            .with_created_by("admin@example.com");

        assert_eq!(schema.description, Some("Order creation schema".to_string()));
        assert_eq!(schema.compatibility, SchemaCompatibility::Full);
        assert_eq!(schema.created_by, Some("admin@example.com".to_string()));
    }

    #[test]
    fn test_schema_validation_result_valid() {
        let schema_id = SchemaId::new();
        let result = SchemaValidationResult::valid(schema_id, 1);

        assert!(result.valid);
        assert_eq!(result.schema_id, Some(schema_id));
        assert_eq!(result.schema_version, Some(1));
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_schema_validation_result_no_schema() {
        let result = SchemaValidationResult::no_schema();

        assert!(result.valid);
        assert!(result.schema_id.is_none());
        assert!(result.schema_version.is_none());
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_schema_validation_result_invalid() {
        let schema_id = SchemaId::new();
        let errors = vec![
            SchemaValidationError::new("/order_id", "is required"),
            SchemaValidationError::new("/amount", "must be a number"),
        ];

        let result = SchemaValidationResult::invalid(schema_id, 2, errors.clone());

        assert!(!result.valid);
        assert_eq!(result.schema_id, Some(schema_id));
        assert_eq!(result.schema_version, Some(2));
        assert_eq!(result.errors.len(), 2);
        assert_eq!(result.errors[0].path, "/order_id");
        assert_eq!(result.errors[1].message, "must be a number");
    }

    #[test]
    fn test_schema_validation_error_new() {
        let error = SchemaValidationError::new("/data/items/0", "Invalid item format");
        assert_eq!(error.path, "/data/items/0");
        assert_eq!(error.message, "Invalid item format");
    }

    #[test]
    fn test_register_schema_request_serialization() {
        let request = RegisterSchemaRequest {
            event_type: "order.created".to_string(),
            schema_json: serde_json::json!({"type": "object"}),
            description: Some("Test schema".to_string()),
            compatibility: Some(SchemaCompatibility::Forward),
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: RegisterSchemaRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.event_type, request.event_type);
        assert_eq!(parsed.description, request.description);
        assert_eq!(parsed.compatibility, Some(SchemaCompatibility::Forward));
    }

    #[test]
    fn test_schema_serialization() {
        let tenant_id = TenantId::new();
        let schema = Schema::new(
            tenant_id,
            EventType::from("test.event"),
            1,
            serde_json::json!({"type": "object"}),
        );

        let json = serde_json::to_string(&schema).unwrap();
        let parsed: Schema = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.id, schema.id);
        assert_eq!(parsed.version, schema.version);
        assert_eq!(parsed.event_type, schema.event_type);
    }
}
