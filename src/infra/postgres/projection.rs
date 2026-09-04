//! PostgreSQL adapters for the production projection runner.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use sqlx::PgPool;

use crate::domain::{EntityType, EventEnvelope, SequencedEvent, StoreId, TenantId};
use crate::infra::{EventStore, SequencerError};
use crate::infra::{PgAgentKeyRegistry, VesSequencer};
use crate::projection::{
    CheckpointStore, CustomerProjection, CustomerProjectionStore, EntityVersionStore, EventSource,
    InventoryProjection, InventoryProjectionStore, OrderProjection, OrderProjectionStore,
    ProductProjection, ProductProjectionStore, ProjectionCheckpoint, RejectionEvent, RejectionSink,
    ReturnProjection, ReturnProjectionStore,
};

fn encode_u64(value: u64, field: &str) -> Result<i64, SequencerError> {
    i64::try_from(value).map_err(|_| SequencerError::InvariantViolation {
        invariant: field.to_string(),
        message: format!("{field} must fit a PostgreSQL BIGINT"),
    })
}

fn decode_u64(value: i64, field: &str) -> Result<u64, SequencerError> {
    u64::try_from(value).map_err(|_| SequencerError::InvariantViolation {
        invariant: field.to_string(),
        message: format!("{field} must be non-negative"),
    })
}

/// Bounded event-source adapter over the canonical event store.
pub struct PgProjectionEventSource {
    event_store: Arc<dyn EventStore>,
}

impl PgProjectionEventSource {
    pub fn new(event_store: Arc<dyn EventStore>) -> Self {
        Self { event_store }
    }
}

#[async_trait]
impl EventSource for PgProjectionEventSource {
    async fn get_events_from(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        from_sequence: u64,
        limit: usize,
    ) -> Result<Vec<SequencedEvent>, SequencerError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let start = from_sequence.max(1);
        let count = u64::try_from(limit).unwrap_or(u64::MAX);
        let end = start.saturating_add(count.saturating_sub(1));
        self.event_store
            .read_range(tenant_id, store_id, start, end)
            .await
    }
}

/// VES-ledger adapter. Encrypted payload events are retained in the canonical
/// ledger but intentionally mapped to an unsupported projector type: without
/// plaintext the sequencer cannot materialize their domain state soundly.
pub struct PgVesProjectionEventSource {
    sequencer: Arc<VesSequencer<PgAgentKeyRegistry>>,
}

impl PgVesProjectionEventSource {
    pub fn new(sequencer: Arc<VesSequencer<PgAgentKeyRegistry>>) -> Self {
        Self { sequencer }
    }
}

#[async_trait]
impl EventSource for PgVesProjectionEventSource {
    async fn get_events_from(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        from_sequence: u64,
        limit: usize,
    ) -> Result<Vec<SequencedEvent>, SequencerError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let after = from_sequence.max(1).saturating_sub(1);
        let limit = u32::try_from(limit).unwrap_or(u32::MAX);
        self.sequencer
            .get_events(tenant_id, store_id, after, limit)
            .await?
            .into_iter()
            .map(|event| {
                let ves = event.envelope;
                let sequence_number = ves.sequence_number.ok_or_else(|| {
                    SequencerError::Internal("stored VES event has no sequence".to_string())
                })?;
                let sequenced_at = ves.sequenced_at.ok_or_else(|| {
                    SequencerError::Internal("stored VES event has no sequenced_at".to_string())
                })?;
                let created_at = chrono::DateTime::parse_from_rfc3339(&ves.created_at)
                    .map_err(|e| {
                        SequencerError::Internal(format!(
                            "stored VES event has invalid created_at: {e}"
                        ))
                    })?
                    .with_timezone(&chrono::Utc);
                let is_plaintext = ves.payload.is_some();
                Ok(SequencedEvent {
                    envelope: EventEnvelope {
                        envelope_version: ves.ves_version,
                        event_id: ves.event_id,
                        command_id: ves.command_id,
                        tenant_id: ves.tenant_id,
                        store_id: ves.store_id,
                        entity_type: if is_plaintext {
                            ves.entity_type
                        } else {
                            EntityType::new("__encrypted__")
                        },
                        entity_id: ves.entity_id,
                        event_type: ves.event_type,
                        payload: ves.payload.unwrap_or(serde_json::Value::Null),
                        payload_hash: ves.payload_plain_hash,
                        base_version: ves.base_version,
                        created_at,
                        sequence_number: Some(sequence_number),
                        source_agent: ves.source_agent_id,
                        signature: Some(ves.agent_signature.to_vec()),
                    },
                    sequenced_at,
                })
            })
            .collect()
    }
}

/// Durable per-stream checkpoints.
pub struct PgProjectionCheckpointStore {
    pool: PgPool,
    ves: bool,
}

impl PgProjectionCheckpointStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool, ves: false }
    }

    pub fn new_ves(pool: PgPool) -> Self {
        Self { pool, ves: true }
    }
}

#[async_trait]
impl CheckpointStore for PgProjectionCheckpointStore {
    async fn get_checkpoint(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
    ) -> Result<Option<ProjectionCheckpoint>, SequencerError> {
        let query = if self.ves {
            "SELECT last_projected_sequence, updated_at FROM ves_projection_checkpoints WHERE tenant_id = $1 AND store_id = $2"
        } else {
            "SELECT last_projected_sequence, updated_at FROM projection_checkpoints WHERE tenant_id = $1 AND store_id = $2"
        };
        let row: Option<(i64, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(query)
            .bind(tenant_id.0)
            .bind(store_id.0)
            .fetch_optional(&self.pool)
            .await?;

        row.map(|(sequence, updated_at)| {
            Ok(ProjectionCheckpoint {
                tenant_id: *tenant_id,
                store_id: *store_id,
                last_sequence: decode_u64(sequence, "projection checkpoint")?,
                updated_at,
            })
        })
        .transpose()
    }

    async fn set_checkpoint(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        sequence: u64,
    ) -> Result<(), SequencerError> {
        let query = if self.ves {
            r#"
            INSERT INTO ves_projection_checkpoints
                (tenant_id, store_id, last_projected_sequence, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (tenant_id, store_id) DO UPDATE SET
                last_projected_sequence = GREATEST(
                    ves_projection_checkpoints.last_projected_sequence,
                    EXCLUDED.last_projected_sequence
                ),
                updated_at = NOW()
            "#
        } else {
            r#"
            INSERT INTO projection_checkpoints
                (tenant_id, store_id, last_projected_sequence, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (tenant_id, store_id) DO UPDATE SET
                last_projected_sequence = GREATEST(
                    projection_checkpoints.last_projected_sequence,
                    EXCLUDED.last_projected_sequence
                ),
                updated_at = NOW()
            "#
        };
        sqlx::query(query)
            .bind(tenant_id.0)
            .bind(store_id.0)
            .bind(encode_u64(sequence, "projection checkpoint")?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

/// Projection-only entity versions; intentionally separate from sequencing OCC.
pub struct PgProjectionVersionStore {
    pool: PgPool,
    ves: bool,
}

impl PgProjectionVersionStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool, ves: false }
    }

    pub fn new_ves(pool: PgPool) -> Self {
        Self { pool, ves: true }
    }
}

#[async_trait]
impl EntityVersionStore for PgProjectionVersionStore {
    async fn get_version(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        entity_type: &str,
        entity_id: &str,
    ) -> Result<Option<u64>, SequencerError> {
        let query = if self.ves {
            "SELECT version FROM ves_projection_entity_versions WHERE tenant_id = $1 AND store_id = $2 AND entity_type = $3 AND entity_id = $4"
        } else {
            "SELECT version FROM projection_entity_versions WHERE tenant_id = $1 AND store_id = $2 AND entity_type = $3 AND entity_id = $4"
        };
        let value: Option<i64> = sqlx::query_scalar(query)
            .bind(tenant_id.0)
            .bind(store_id.0)
            .bind(entity_type)
            .bind(entity_id)
            .fetch_optional(&self.pool)
            .await?;
        value
            .map(|v| decode_u64(v, "projection entity version"))
            .transpose()
    }

    async fn set_version(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        entity_type: &str,
        entity_id: &str,
        version: u64,
    ) -> Result<(), SequencerError> {
        let query = if self.ves {
            r#"
            INSERT INTO ves_projection_entity_versions
                (tenant_id, store_id, entity_type, entity_id, version, updated_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (tenant_id, store_id, entity_type, entity_id) DO UPDATE SET
                version = EXCLUDED.version, updated_at = NOW()
            "#
        } else {
            r#"
            INSERT INTO projection_entity_versions
                (tenant_id, store_id, entity_type, entity_id, version, updated_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (tenant_id, store_id, entity_type, entity_id) DO UPDATE SET
                version = EXCLUDED.version, updated_at = NOW()
            "#
        };
        sqlx::query(query)
            .bind(tenant_id.0)
            .bind(store_id.0)
            .bind(entity_type)
            .bind(entity_id)
            .bind(encode_u64(version, "projection entity version")?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn compare_and_set_version(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        entity_type: &str,
        entity_id: &str,
        expected_version: Option<u64>,
        new_version: u64,
    ) -> Result<bool, SequencerError> {
        let new_version = encode_u64(new_version, "projection entity version")?;
        let rows = match expected_version {
            Some(expected) => {
                let query = if self.ves {
                    r#"
                    UPDATE ves_projection_entity_versions
                    SET version = $5, updated_at = NOW()
                    WHERE tenant_id = $1 AND store_id = $2
                      AND entity_type = $3 AND entity_id = $4 AND version = $6
                    "#
                } else {
                    r#"
                    UPDATE projection_entity_versions
                    SET version = $5, updated_at = NOW()
                    WHERE tenant_id = $1 AND store_id = $2
                      AND entity_type = $3 AND entity_id = $4 AND version = $6
                    "#
                };
                sqlx::query(query)
                    .bind(tenant_id.0)
                    .bind(store_id.0)
                    .bind(entity_type)
                    .bind(entity_id)
                    .bind(new_version)
                    .bind(encode_u64(expected, "expected projection entity version")?)
                    .execute(&self.pool)
                    .await?
                    .rows_affected()
            }
            None => {
                let query = if self.ves {
                    r#"
                    INSERT INTO ves_projection_entity_versions
                        (tenant_id, store_id, entity_type, entity_id, version, updated_at)
                    VALUES ($1, $2, $3, $4, $5, NOW())
                    ON CONFLICT DO NOTHING
                    "#
                } else {
                    r#"
                    INSERT INTO projection_entity_versions
                        (tenant_id, store_id, entity_type, entity_id, version, updated_at)
                    VALUES ($1, $2, $3, $4, $5, NOW())
                    ON CONFLICT DO NOTHING
                    "#
                };
                sqlx::query(query)
                    .bind(tenant_id.0)
                    .bind(store_id.0)
                    .bind(entity_type)
                    .bind(entity_id)
                    .bind(new_version)
                    .execute(&self.pool)
                    .await?
                    .rows_affected()
            }
        };
        Ok(rows == 1)
    }
}

/// Persists projection rejections for audit and operations.
pub struct PgProjectionRejectionSink {
    pool: PgPool,
}

impl PgProjectionRejectionSink {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RejectionSink for PgProjectionRejectionSink {
    async fn emit_rejection(&self, rejection: RejectionEvent) -> Result<(), SequencerError> {
        sqlx::query(
            r#"
            INSERT INTO rejected_events_log
                (event_id, sequence_number, tenant_id, store_id, entity_type,
                 entity_id, reason, message, expected_version, actual_version)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(rejection.original_event_id)
        .bind(encode_u64(
            rejection.original_sequence,
            "rejected event sequence",
        )?)
        .bind(rejection.tenant_id.0)
        .bind(rejection.store_id.0)
        .bind(rejection.entity_type)
        .bind(rejection.entity_id)
        .bind(rejection.reason_code)
        .bind(rejection.reason)
        .bind(
            rejection
                .expected_version
                .map(|v| encode_u64(v, "expected version"))
                .transpose()?,
        )
        .bind(
            rejection
                .actual_version
                .map(|v| encode_u64(v, "actual version"))
                .transpose()?,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

/// Tenant/store-scoped JSONB document store used by all built-in projectors.
pub struct PgProjectionDocumentStore {
    pool: PgPool,
    tenant_id: TenantId,
    store_id: StoreId,
    ves: bool,
}

impl PgProjectionDocumentStore {
    pub fn new(pool: PgPool, tenant_id: TenantId, store_id: StoreId) -> Self {
        Self {
            pool,
            tenant_id,
            store_id,
            ves: false,
        }
    }

    pub fn new_ves(pool: PgPool, tenant_id: TenantId, store_id: StoreId) -> Self {
        Self {
            pool,
            tenant_id,
            store_id,
            ves: true,
        }
    }

    async fn get<T: DeserializeOwned>(
        &self,
        entity_type: &str,
        entity_id: &str,
    ) -> Result<Option<T>, SequencerError> {
        let query = if self.ves {
            "SELECT document FROM ves_projection_documents WHERE tenant_id = $1 AND store_id = $2 AND entity_type = $3 AND entity_id = $4"
        } else {
            "SELECT document FROM projection_documents WHERE tenant_id = $1 AND store_id = $2 AND entity_type = $3 AND entity_id = $4"
        };
        let document: Option<serde_json::Value> = sqlx::query_scalar(query)
            .bind(self.tenant_id.0)
            .bind(self.store_id.0)
            .bind(entity_type)
            .bind(entity_id)
            .fetch_optional(&self.pool)
            .await?;
        document
            .map(|value| {
                serde_json::from_value(value).map_err(|e| {
                    SequencerError::Internal(format!(
                        "invalid {entity_type} projection document {entity_id}: {e}"
                    ))
                })
            })
            .transpose()
    }

    async fn save<T: Serialize>(
        &self,
        entity_type: &str,
        entity_id: &str,
        version: u64,
        value: &T,
    ) -> Result<(), SequencerError> {
        let document = serde_json::to_value(value)
            .map_err(|e| SequencerError::Internal(format!("serialize projection: {e}")))?;
        let query = if self.ves {
            r#"
            INSERT INTO ves_projection_documents
                (tenant_id, store_id, entity_type, entity_id, document, version, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, NOW())
            ON CONFLICT (tenant_id, store_id, entity_type, entity_id) DO UPDATE SET
                document = EXCLUDED.document,
                version = EXCLUDED.version,
                updated_at = NOW()
            "#
        } else {
            r#"
            INSERT INTO projection_documents
                (tenant_id, store_id, entity_type, entity_id, document, version, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, NOW())
            ON CONFLICT (tenant_id, store_id, entity_type, entity_id) DO UPDATE SET
                document = EXCLUDED.document,
                version = EXCLUDED.version,
                updated_at = NOW()
            "#
        };
        sqlx::query(query)
            .bind(self.tenant_id.0)
            .bind(self.store_id.0)
            .bind(entity_type)
            .bind(entity_id)
            .bind(document)
            .bind(encode_u64(version, "projection document version")?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete(&self, entity_type: &str, entity_id: &str) -> Result<(), SequencerError> {
        let query = if self.ves {
            "DELETE FROM ves_projection_documents WHERE tenant_id = $1 AND store_id = $2 AND entity_type = $3 AND entity_id = $4"
        } else {
            "DELETE FROM projection_documents WHERE tenant_id = $1 AND store_id = $2 AND entity_type = $3 AND entity_id = $4"
        };
        sqlx::query(query)
            .bind(self.tenant_id.0)
            .bind(self.store_id.0)
            .bind(entity_type)
            .bind(entity_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl OrderProjectionStore for PgProjectionDocumentStore {
    async fn get(&self, id: &str) -> Result<Option<OrderProjection>, SequencerError> {
        self.get("order", id).await
    }
    async fn save(&self, value: &OrderProjection) -> Result<(), SequencerError> {
        self.save("order", &value.order_id, value.version, value)
            .await
    }
    async fn delete(&self, id: &str) -> Result<(), SequencerError> {
        self.delete("order", id).await
    }
}

#[async_trait]
impl InventoryProjectionStore for PgProjectionDocumentStore {
    async fn get(
        &self,
        product_id: &str,
        location_id: &str,
    ) -> Result<Option<InventoryProjection>, SequencerError> {
        self.get("inventory", &format!("{product_id}:{location_id}"))
            .await
    }
    async fn save(&self, value: &InventoryProjection) -> Result<(), SequencerError> {
        self.save(
            "inventory",
            &format!("{}:{}", value.product_id, value.location_id),
            value.version,
            value,
        )
        .await
    }
}

#[async_trait]
impl ProductProjectionStore for PgProjectionDocumentStore {
    async fn get(&self, id: &str) -> Result<Option<ProductProjection>, SequencerError> {
        self.get("product", id).await
    }
    async fn save(&self, value: &ProductProjection) -> Result<(), SequencerError> {
        self.save("product", &value.product_id, value.version, value)
            .await
    }
    async fn delete(&self, id: &str) -> Result<(), SequencerError> {
        self.delete("product", id).await
    }
}

#[async_trait]
impl CustomerProjectionStore for PgProjectionDocumentStore {
    async fn get(&self, id: &str) -> Result<Option<CustomerProjection>, SequencerError> {
        self.get("customer", id).await
    }
    async fn save(&self, value: &CustomerProjection) -> Result<(), SequencerError> {
        self.save("customer", &value.customer_id, value.version, value)
            .await
    }
}

#[async_trait]
impl ReturnProjectionStore for PgProjectionDocumentStore {
    async fn get(&self, id: &str) -> Result<Option<ReturnProjection>, SequencerError> {
        self.get("return", id).await
    }
    async fn save(&self, value: &ReturnProjection) -> Result<(), SequencerError> {
        self.save("return", &value.return_id, value.version, value)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bigint_boundaries_are_checked() {
        assert_eq!(encode_u64(i64::MAX as u64, "value").unwrap(), i64::MAX);
        assert!(encode_u64(i64::MAX as u64 + 1, "value").is_err());
        assert!(decode_u64(-1, "value").is_err());
    }
}
