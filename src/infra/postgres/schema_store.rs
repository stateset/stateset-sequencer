//! PostgreSQL-backed Schema Registry
//!
//! Production-ready implementation of the SchemaStore trait
//! using PostgreSQL for persistent storage of JSON Schema definitions.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use jsonschema::Validator;
use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::domain::{
    EventType, Schema, SchemaCompatibility, SchemaId, SchemaStatus, SchemaValidationError,
    SchemaValidationResult, TenantId,
};
use crate::infra::{Result, SchemaStore, SequencerError};

/// PostgreSQL-backed schema registry
pub struct PgSchemaStore {
    pool: PgPool,
}

impl PgSchemaStore {
    /// Create a new PostgreSQL schema store
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Initialize the database schema for the schema registry
    pub async fn initialize(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS event_schemas (
                id UUID PRIMARY KEY,
                tenant_id UUID NOT NULL,
                event_type VARCHAR(255) NOT NULL,
                version INTEGER NOT NULL,
                schema_json JSONB NOT NULL,
                status VARCHAR(16) NOT NULL DEFAULT 'active',
                compatibility VARCHAR(16) NOT NULL DEFAULT 'backward',
                description TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                created_by VARCHAR(255),
                UNIQUE (tenant_id, event_type, version)
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(SequencerError::Database)?;

        // Create indexes for efficient lookup
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_event_schemas_tenant_type
            ON event_schemas (tenant_id, event_type)
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(SequencerError::Database)?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_event_schemas_status
            ON event_schemas (tenant_id, event_type, status)
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(SequencerError::Database)?;

        // Index for finding latest version
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_event_schemas_version
            ON event_schemas (tenant_id, event_type, version DESC)
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(SequencerError::Database)?;

        Ok(())
    }

    /// Convert database row to Schema
    fn row_to_schema(
        id: Uuid,
        tenant_id: Uuid,
        event_type: String,
        version: i32,
        schema_json: serde_json::Value,
        status: String,
        compatibility: String,
        description: Option<String>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        created_by: Option<String>,
    ) -> Schema {
        Schema {
            id: SchemaId::from_uuid(id),
            tenant_id: TenantId::from_uuid(tenant_id),
            event_type: EventType::from(event_type),
            version: version as u32,
            schema_json,
            status: match status.as_str() {
                "active" => SchemaStatus::Active,
                "deprecated" => SchemaStatus::Deprecated,
                "archived" => SchemaStatus::Archived,
                _ => SchemaStatus::Active,
            },
            compatibility: match compatibility.as_str() {
                "forward" => SchemaCompatibility::Forward,
                "backward" => SchemaCompatibility::Backward,
                "full" => SchemaCompatibility::Full,
                "none" => SchemaCompatibility::None,
                _ => SchemaCompatibility::Backward,
            },
            description,
            created_at,
            updated_at,
            created_by,
        }
    }

    /// Get the next version number for an event type
    async fn next_version(&self, tenant_id: &TenantId, event_type: &EventType) -> Result<u32> {
        let row: Option<(Option<i32>,)> = sqlx::query_as(
            r#"
            SELECT MAX(version) FROM event_schemas
            WHERE tenant_id = $1 AND event_type = $2
            "#,
        )
        .bind(tenant_id.0)
        .bind(event_type.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(SequencerError::Database)?;

        Ok(row
            .and_then(|r| r.0)
            .map(|v| v as u32 + 1)
            .unwrap_or(1))
    }

    /// Validate a JSON Schema definition
    fn validate_schema_definition(schema_json: &serde_json::Value) -> Result<()> {
        // Try to compile the schema to validate it
        Validator::new(schema_json).map_err(|e| {
            SequencerError::InvalidJsonSchema(format!("Failed to compile JSON Schema: {}", e))
        })?;
        Ok(())
    }
}

#[async_trait]
impl SchemaStore for PgSchemaStore {
    async fn register(&self, mut schema: Schema) -> Result<Schema> {
        // Validate the JSON Schema definition
        Self::validate_schema_definition(&schema.schema_json)?;

        // Auto-assign version if not set or set to 0
        if schema.version == 0 {
            schema.version = self.next_version(&schema.tenant_id, &schema.event_type).await?;
        }

        let status = match schema.status {
            SchemaStatus::Active => "active",
            SchemaStatus::Deprecated => "deprecated",
            SchemaStatus::Archived => "archived",
        };

        let compatibility = match schema.compatibility {
            SchemaCompatibility::Forward => "forward",
            SchemaCompatibility::Backward => "backward",
            SchemaCompatibility::Full => "full",
            SchemaCompatibility::None => "none",
        };

        let result = sqlx::query(
            r#"
            INSERT INTO event_schemas
                (id, tenant_id, event_type, version, schema_json, status, compatibility, description, created_at, updated_at, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(schema.id.0)
        .bind(schema.tenant_id.0)
        .bind(schema.event_type.as_str())
        .bind(schema.version as i32)
        .bind(&schema.schema_json)
        .bind(status)
        .bind(compatibility)
        .bind(&schema.description)
        .bind(schema.created_at)
        .bind(schema.updated_at)
        .bind(&schema.created_by)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(schema),
            Err(e) if e.to_string().contains("duplicate key") => Err(
                SequencerError::SchemaCompatibilityViolation(format!(
                    "Schema version {} already exists for event type {}",
                    schema.version,
                    schema.event_type.as_str()
                )),
            ),
            Err(e) => Err(SequencerError::Database(e)),
        }
    }

    async fn get_latest(
        &self,
        tenant_id: &TenantId,
        event_type: &EventType,
    ) -> Result<Option<Schema>> {
        let row: Option<(
            Uuid,
            Uuid,
            String,
            i32,
            serde_json::Value,
            String,
            String,
            Option<String>,
            DateTime<Utc>,
            DateTime<Utc>,
            Option<String>,
        )> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, event_type, version, schema_json, status, compatibility, description, created_at, updated_at, created_by
            FROM event_schemas
            WHERE tenant_id = $1 AND event_type = $2 AND status = 'active'
            ORDER BY version DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_id.0)
        .bind(event_type.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(SequencerError::Database)?;

        Ok(row.map(
            |(id, tenant_id, event_type, version, schema_json, status, compatibility, description, created_at, updated_at, created_by)| {
                Self::row_to_schema(
                    id,
                    tenant_id,
                    event_type,
                    version,
                    schema_json,
                    status,
                    compatibility,
                    description,
                    created_at,
                    updated_at,
                    created_by,
                )
            },
        ))
    }

    async fn get_version(
        &self,
        tenant_id: &TenantId,
        event_type: &EventType,
        version: u32,
    ) -> Result<Option<Schema>> {
        let row: Option<(
            Uuid,
            Uuid,
            String,
            i32,
            serde_json::Value,
            String,
            String,
            Option<String>,
            DateTime<Utc>,
            DateTime<Utc>,
            Option<String>,
        )> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, event_type, version, schema_json, status, compatibility, description, created_at, updated_at, created_by
            FROM event_schemas
            WHERE tenant_id = $1 AND event_type = $2 AND version = $3
            "#,
        )
        .bind(tenant_id.0)
        .bind(event_type.as_str())
        .bind(version as i32)
        .fetch_optional(&self.pool)
        .await
        .map_err(SequencerError::Database)?;

        Ok(row.map(
            |(id, tenant_id, event_type, version, schema_json, status, compatibility, description, created_at, updated_at, created_by)| {
                Self::row_to_schema(
                    id,
                    tenant_id,
                    event_type,
                    version,
                    schema_json,
                    status,
                    compatibility,
                    description,
                    created_at,
                    updated_at,
                    created_by,
                )
            },
        ))
    }

    async fn get_by_id(&self, schema_id: SchemaId) -> Result<Option<Schema>> {
        let row: Option<(
            Uuid,
            Uuid,
            String,
            i32,
            serde_json::Value,
            String,
            String,
            Option<String>,
            DateTime<Utc>,
            DateTime<Utc>,
            Option<String>,
        )> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, event_type, version, schema_json, status, compatibility, description, created_at, updated_at, created_by
            FROM event_schemas
            WHERE id = $1
            "#,
        )
        .bind(schema_id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(SequencerError::Database)?;

        Ok(row.map(
            |(id, tenant_id, event_type, version, schema_json, status, compatibility, description, created_at, updated_at, created_by)| {
                Self::row_to_schema(
                    id,
                    tenant_id,
                    event_type,
                    version,
                    schema_json,
                    status,
                    compatibility,
                    description,
                    created_at,
                    updated_at,
                    created_by,
                )
            },
        ))
    }

    async fn list_versions(
        &self,
        tenant_id: &TenantId,
        event_type: &EventType,
    ) -> Result<Vec<Schema>> {
        let rows: Vec<(
            Uuid,
            Uuid,
            String,
            i32,
            serde_json::Value,
            String,
            String,
            Option<String>,
            DateTime<Utc>,
            DateTime<Utc>,
            Option<String>,
        )> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, event_type, version, schema_json, status, compatibility, description, created_at, updated_at, created_by
            FROM event_schemas
            WHERE tenant_id = $1 AND event_type = $2
            ORDER BY version DESC
            "#,
        )
        .bind(tenant_id.0)
        .bind(event_type.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(SequencerError::Database)?;

        Ok(rows
            .into_iter()
            .map(
                |(id, tenant_id, event_type, version, schema_json, status, compatibility, description, created_at, updated_at, created_by)| {
                    Self::row_to_schema(
                        id,
                        tenant_id,
                        event_type,
                        version,
                        schema_json,
                        status,
                        compatibility,
                        description,
                        created_at,
                        updated_at,
                        created_by,
                    )
                },
            )
            .collect())
    }

    async fn list_by_tenant(&self, tenant_id: &TenantId) -> Result<Vec<Schema>> {
        let rows: Vec<(
            Uuid,
            Uuid,
            String,
            i32,
            serde_json::Value,
            String,
            String,
            Option<String>,
            DateTime<Utc>,
            DateTime<Utc>,
            Option<String>,
        )> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, event_type, version, schema_json, status, compatibility, description, created_at, updated_at, created_by
            FROM event_schemas
            WHERE tenant_id = $1
            ORDER BY event_type ASC, version DESC
            "#,
        )
        .bind(tenant_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(SequencerError::Database)?;

        Ok(rows
            .into_iter()
            .map(
                |(id, tenant_id, event_type, version, schema_json, status, compatibility, description, created_at, updated_at, created_by)| {
                    Self::row_to_schema(
                        id,
                        tenant_id,
                        event_type,
                        version,
                        schema_json,
                        status,
                        compatibility,
                        description,
                        created_at,
                        updated_at,
                        created_by,
                    )
                },
            )
            .collect())
    }

    async fn update_status(&self, schema_id: SchemaId, status: SchemaStatus) -> Result<()> {
        let status_str = match status {
            SchemaStatus::Active => "active",
            SchemaStatus::Deprecated => "deprecated",
            SchemaStatus::Archived => "archived",
        };

        let result = sqlx::query(
            r#"
            UPDATE event_schemas
            SET status = $1, updated_at = NOW()
            WHERE id = $2
            "#,
        )
        .bind(status_str)
        .bind(schema_id.0)
        .execute(&self.pool)
        .await
        .map_err(SequencerError::Database)?;

        if result.rows_affected() == 0 {
            return Err(SequencerError::SchemaNotFound(schema_id.to_string()));
        }

        Ok(())
    }

    async fn validate(
        &self,
        tenant_id: &TenantId,
        event_type: &EventType,
        payload: &serde_json::Value,
    ) -> Result<SchemaValidationResult> {
        // Get the latest active schema for this event type
        let schema = match self.get_latest(tenant_id, event_type).await? {
            Some(s) => s,
            None => return Ok(SchemaValidationResult::no_schema()),
        };

        // Compile and validate
        let validator = Validator::new(&schema.schema_json).map_err(|e| {
            SequencerError::InvalidJsonSchema(format!("Failed to compile schema: {}", e))
        })?;

        // Use iter_errors to collect all validation errors
        let errors: Vec<SchemaValidationError> = validator
            .iter_errors(payload)
            .map(|e| {
                SchemaValidationError::new(e.instance_path.to_string(), e.to_string())
            })
            .collect();

        if errors.is_empty() {
            Ok(SchemaValidationResult::valid(schema.id, schema.version))
        } else {
            Ok(SchemaValidationResult::invalid(
                schema.id,
                schema.version,
                errors,
            ))
        }
    }

    async fn delete(&self, schema_id: SchemaId) -> Result<()> {
        let result = sqlx::query(
            r#"
            DELETE FROM event_schemas
            WHERE id = $1
            "#,
        )
        .bind(schema_id.0)
        .execute(&self.pool)
        .await
        .map_err(SequencerError::Database)?;

        if result.rows_affected() == 0 {
            return Err(SequencerError::SchemaNotFound(schema_id.to_string()));
        }

        Ok(())
    }
}

/// Extension methods for PgSchemaStore
impl PgSchemaStore {
    /// Validate a payload with a specific schema version
    pub async fn validate_with_version(
        &self,
        tenant_id: &TenantId,
        event_type: &EventType,
        version: u32,
        payload: &serde_json::Value,
    ) -> Result<SchemaValidationResult> {
        let schema = match self.get_version(tenant_id, event_type, version).await? {
            Some(s) => s,
            None => {
                return Err(SequencerError::SchemaVersionNotFound {
                    event_type: event_type.to_string(),
                    version,
                })
            }
        };

        let validator = Validator::new(&schema.schema_json).map_err(|e| {
            SequencerError::InvalidJsonSchema(format!("Failed to compile schema: {}", e))
        })?;

        // Use iter_errors to collect all validation errors
        let errors: Vec<SchemaValidationError> = validator
            .iter_errors(payload)
            .map(|e| {
                SchemaValidationError::new(e.instance_path.to_string(), e.to_string())
            })
            .collect();

        if errors.is_empty() {
            Ok(SchemaValidationResult::valid(schema.id, schema.version))
        } else {
            Ok(SchemaValidationResult::invalid(
                schema.id,
                schema.version,
                errors,
            ))
        }
    }

    /// Get distinct event types that have schemas registered for a tenant
    pub async fn list_event_types(&self, tenant_id: &TenantId) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT DISTINCT event_type
            FROM event_schemas
            WHERE tenant_id = $1
            ORDER BY event_type ASC
            "#,
        )
        .bind(tenant_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(SequencerError::Database)?;

        Ok(rows.into_iter().map(|(et,)| et).collect())
    }
}

#[cfg(test)]
mod tests {
    // Integration tests would require a PostgreSQL instance
    // See tests/schema_store_integration_test.rs
}
