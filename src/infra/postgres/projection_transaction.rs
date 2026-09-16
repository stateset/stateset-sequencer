//! One transaction for all durable effects of a bounded projection batch.
use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

use async_trait::async_trait;
use sqlx::{pool::PoolConnection, PgConnection, PgPool, Postgres, Transaction};
use tokio::sync::{MappedMutexGuard, Mutex, MutexGuard};

use crate::{
    domain::{SequencedEvent, StoreId, TenantId},
    infra::SequencerError,
    projection::{EventSource, ProjectionBatchTransaction},
};

pub struct PgProjectionTransaction {
    pool: PgPool,
    ves: bool,
    transaction: Mutex<Option<Transaction<'static, Postgres>>>,
    source: Arc<dyn EventSource>,
    batch_size: usize,
    events: Mutex<Vec<SequencedEvent>>,
}

impl PgProjectionTransaction {
    pub fn new(pool: PgPool, ves: bool, source: Arc<dyn EventSource>, batch_size: usize) -> Self {
        Self {
            pool,
            ves,
            transaction: Mutex::new(None),
            source,
            batch_size,
            events: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl ProjectionBatchTransaction for PgProjectionTransaction {
    async fn begin(&self, tenant: &TenantId, store: &StoreId) -> Result<(), SequencerError> {
        let mut slot = self.transaction.lock().await;
        if slot.is_some() {
            return Err(SequencerError::Internal(
                "projection transaction already active".into(),
            ));
        }
        let table = if self.ves {
            "ves_projection_checkpoints"
        } else {
            "projection_checkpoints"
        };
        let checkpoint: Option<i64> = sqlx::query_scalar(&format!(
            "SELECT last_projected_sequence FROM {table} WHERE tenant_id=$1 AND store_id=$2"
        ))
        .bind(tenant.0)
        .bind(store.0)
        .fetch_optional(&self.pool)
        .await?;
        let checkpoint = u64::try_from(checkpoint.unwrap_or(0))
            .map_err(|_| SequencerError::Internal("negative projection checkpoint".into()))?;
        // Fetch immutable ledger events BEFORE reserving a transaction connection.
        // Otherwise every worker could hold a connection while waiting for a
        // second one to read events, exhausting even a healthy pool. The runner
        // rereads the checkpoint under lock and discards any now-stale prefix.
        *self.events.lock().await = self
            .source
            .get_events_from(tenant, store, checkpoint.saturating_add(1), self.batch_size)
            .await?;
        let mut transaction = self.pool.begin().await?;
        // Bound lock contention and abandoned transactions; settings are local
        // so a pooled connection never leaks these limits to unrelated work.
        sqlx::query("SET LOCAL lock_timeout = '2s'")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SET LOCAL statement_timeout = '10s'")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SET LOCAL idle_in_transaction_session_timeout = '30s'")
            .execute(&mut *transaction)
            .await?;
        let table = if self.ves {
            "ves_projection_checkpoints"
        } else {
            "projection_checkpoints"
        };
        sqlx::query(&format!("INSERT INTO {table} (tenant_id, store_id, last_projected_sequence) VALUES ($1,$2,0) ON CONFLICT DO NOTHING"))
            .bind(tenant.0).bind(store.0).execute(&mut *transaction).await?;
        // All production writers lock this row BEFORE reading the checkpoint
        // or documents. A successor sees the predecessor's committed checkpoint.
        sqlx::query(&format!("SELECT last_projected_sequence FROM {table} WHERE tenant_id=$1 AND store_id=$2 FOR UPDATE"))
            .bind(tenant.0).bind(store.0).fetch_one(&mut *transaction).await?;
        *slot = Some(transaction);
        Ok(())
    }

    async fn commit(&self) -> Result<(), SequencerError> {
        let transaction =
            self.transaction.lock().await.take().ok_or_else(|| {
                SequencerError::Internal("projection transaction not active".into())
            })?;
        transaction.commit().await?;
        Ok(())
    }

    async fn rollback(&self) -> Result<(), SequencerError> {
        if let Some(transaction) = self.transaction.lock().await.take() {
            transaction.rollback().await?;
        }
        Ok(())
    }
}

#[async_trait]
impl EventSource for PgProjectionTransaction {
    async fn get_events_from(
        &self,
        tenant: &TenantId,
        store: &StoreId,
        from_sequence: u64,
        limit: usize,
    ) -> Result<Vec<SequencedEvent>, SequencerError> {
        Ok(self
            .events
            .lock()
            .await
            .iter()
            .filter(|event| {
                event.envelope.tenant_id == *tenant
                    && event.envelope.store_id == *store
                    && event.sequence_number() >= from_sequence
            })
            .take(limit)
            .cloned()
            .collect())
    }
}

pub(crate) enum ProjectionConnection<'a> {
    Pool(PoolConnection<Postgres>),
    Transaction(MappedMutexGuard<'a, Transaction<'static, Postgres>>),
}

impl Deref for ProjectionConnection<'_> {
    type Target = PgConnection;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Pool(connection) => connection,
            Self::Transaction(transaction) => transaction,
        }
    }
}

impl DerefMut for ProjectionConnection<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Pool(connection) => connection,
            Self::Transaction(transaction) => transaction,
        }
    }
}

pub(crate) async fn projection_connection<'a>(
    pool: &PgPool,
    transaction: Option<&'a PgProjectionTransaction>,
) -> Result<ProjectionConnection<'a>, SequencerError> {
    if let Some(transaction) = transaction {
        let guard = transaction.transaction.lock().await;
        let guard = MutexGuard::try_map(guard, Option::as_mut).map_err(|_| {
            SequencerError::Internal("projection write outside its transaction".into())
        })?;
        Ok(ProjectionConnection::Transaction(guard))
    } else {
        Ok(ProjectionConnection::Pool(pool.acquire().await?))
    }
}
