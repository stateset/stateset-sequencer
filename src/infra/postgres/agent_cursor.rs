//! Durable per-stream acknowledgement cursors for reconnecting agents.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::infra::{Result, SequencerError};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AgentCursor {
    pub acknowledged_sequence: i64,
    pub updated_at: DateTime<Utc>,
}

impl AgentCursor {
    pub fn sequence(&self) -> Result<u64> {
        u64::try_from(self.acknowledged_sequence).map_err(|_| SequencerError::InvariantViolation {
            invariant: "agent_cursor".to_string(),
            message: "acknowledged sequence must be non-negative".to_string(),
        })
    }
}

#[derive(Clone)]
pub struct PgAgentCursorStore {
    pool: PgPool,
}

impl PgAgentCursorStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn get(
        &self,
        tenant_id: Uuid,
        store_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Option<AgentCursor>> {
        Ok(sqlx::query_as(
            r#"
            SELECT acknowledged_sequence, updated_at
            FROM ves_agent_cursors
            WHERE tenant_id = $1 AND store_id = $2 AND agent_id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(store_id)
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Persist a cursor monotonically; stale acknowledgements cannot move it backwards.
    pub async fn acknowledge(
        &self,
        tenant_id: Uuid,
        store_id: Uuid,
        agent_id: Uuid,
        sequence: u64,
    ) -> Result<AgentCursor> {
        let sequence = i64::try_from(sequence).map_err(|_| SequencerError::InvariantViolation {
            invariant: "agent_cursor".to_string(),
            message: "acknowledged sequence exceeds PostgreSQL BIGINT".to_string(),
        })?;
        Ok(sqlx::query_as(
            r#"
            INSERT INTO ves_agent_cursors (
                tenant_id, store_id, agent_id, acknowledged_sequence
            ) VALUES ($1, $2, $3, $4)
            ON CONFLICT (tenant_id, store_id, agent_id) DO UPDATE SET
                acknowledged_sequence = GREATEST(
                    ves_agent_cursors.acknowledged_sequence,
                    EXCLUDED.acknowledged_sequence
                ),
                updated_at = NOW()
            RETURNING acknowledged_sequence, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(store_id)
        .bind(agent_id)
        .bind(sequence)
        .fetch_one(&self.pool)
        .await?)
    }
}
