//! Production projection worker with dynamic stream discovery.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use tracing::{error, info};
use uuid::Uuid;

use crate::domain::{StoreId, TenantId};
use crate::infra::{
    EventStore, PgAgentKeyRegistry, PgDeadLetterQueue, PgProjectionCheckpointStore,
    PgProjectionDocumentStore, PgProjectionEventSource, PgProjectionRejectionSink,
    PgProjectionVersionStore, PgVesProjectionEventSource, SequencerError, VesSequencer,
};
use crate::projection::{
    CheckpointStore, CustomerProjector, EntityVersionStore, EventSource, InventoryProjector,
    OrderProjector, ProductProjector, ProjectionRunner, ProjectionRunnerConfig, ReturnProjector,
};

#[derive(Debug, Clone)]
pub struct ProjectionWorkerConfig {
    pub max_concurrent_streams: usize,
    pub discovery_interval: Duration,
    pub discovery_page_size: usize,
    pub runner: ProjectionRunnerConfig,
}

impl Default for ProjectionWorkerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_streams: 64,
            discovery_interval: Duration::from_secs(5),
            discovery_page_size: 1_000,
            runner: ProjectionRunnerConfig::default(),
        }
    }
}

impl ProjectionWorkerConfig {
    pub fn from_env() -> Result<Self, SequencerError> {
        let defaults = Self::default();
        Ok(Self {
            max_concurrent_streams: usize::try_from(env_positive(
                "PROJECTION_MAX_CONCURRENT_STREAMS",
                defaults.max_concurrent_streams as u64,
            )?)
            .map_err(|_| config_error("PROJECTION_MAX_CONCURRENT_STREAMS", "does not fit usize"))?,
            discovery_interval: Duration::from_millis(env_positive(
                "PROJECTION_DISCOVERY_INTERVAL_MS",
                defaults.discovery_interval.as_millis() as u64,
            )?),
            discovery_page_size: usize::try_from(env_positive(
                "PROJECTION_DISCOVERY_PAGE_SIZE",
                defaults.discovery_page_size as u64,
            )?)
            .map_err(|_| config_error("PROJECTION_DISCOVERY_PAGE_SIZE", "does not fit usize"))?,
            runner: ProjectionRunnerConfig {
                batch_size: usize::try_from(env_positive(
                    "PROJECTION_BATCH_SIZE",
                    defaults.runner.batch_size as u64,
                )?)
                .map_err(|_| config_error("PROJECTION_BATCH_SIZE", "does not fit usize"))?,
                checkpoint_interval: env_positive(
                    "PROJECTION_CHECKPOINT_INTERVAL",
                    defaults.runner.checkpoint_interval,
                )?,
                continue_on_error: env_bool(
                    "PROJECTION_CONTINUE_ON_ERROR",
                    defaults.runner.continue_on_error,
                )?,
                max_retries: u32::try_from(env_positive(
                    "PROJECTION_MAX_RETRIES",
                    defaults.runner.max_retries as u64,
                )?)
                .map_err(|_| config_error("PROJECTION_MAX_RETRIES", "does not fit u32"))?,
                retry_delay_ms: env_positive(
                    "PROJECTION_RETRY_DELAY_MS",
                    defaults.runner.retry_delay_ms,
                )?,
                poll_interval_ms: env_positive(
                    "PROJECTION_POLL_INTERVAL_MS",
                    defaults.runner.poll_interval_ms,
                )?,
            },
        })
    }
}

fn config_error(name: &str, message: &str) -> SequencerError {
    SequencerError::Configuration(format!("{name} {message}"))
}

fn env_positive(name: &str, default: u64) -> Result<u64, SequencerError> {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| config_error(name, "must be a positive integer")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(e) => Err(config_error(name, &format!("is not valid Unicode: {e}"))),
    }
}

fn env_bool(name: &str, default: bool) -> Result<bool, SequencerError> {
    match std::env::var(name) {
        Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "on" | "yes" => Ok(true),
            "0" | "false" | "off" | "no" => Ok(false),
            _ => Err(config_error(name, "must be true or false")),
        },
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(e) => Err(config_error(name, &format!("is not valid Unicode: {e}"))),
    }
}

#[derive(Debug)]
pub enum ProjectionWorkerMessage {
    Shutdown,
}

type ProjectionStores = (
    Arc<dyn EventSource>,
    Arc<dyn CheckpointStore>,
    Arc<dyn EntityVersionStore>,
    Arc<PgProjectionDocumentStore>,
);

/// Spawn a worker that discovers legacy and VES streams and continuously
/// projects every current and future tenant/store. The ledgers use isolated
/// checkpoints, versions, and documents because their sequence spaces differ.
pub fn spawn_projection_worker(
    config: ProjectionWorkerConfig,
    pool: PgPool,
    event_store: Arc<dyn EventStore>,
    ves_sequencer: Option<Arc<VesSequencer<PgAgentKeyRegistry>>>,
) -> (JoinHandle<()>, mpsc::Sender<ProjectionWorkerMessage>) {
    let (control_tx, mut control_rx) = mpsc::channel(1);

    let task = tokio::spawn(async move {
        let rejections = Arc::new(PgProjectionRejectionSink::new(pool.clone()));
        let dlq = Arc::new(PgDeadLetterQueue::new(pool.clone()));
        let mut runners: HashMap<(String, Uuid, Uuid), Arc<ProjectionRunner>> = HashMap::new();
        let mut tasks = JoinSet::new();
        let mut task_streams = HashMap::new();
        let mut discovery = tokio::time::interval(config.discovery_interval);
        discovery.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut cursor: Option<(String, Uuid, Uuid)> = None;

        loop {
            tokio::select! {
                _ = discovery.tick() => {
                    loop {
                        let available = config.max_concurrent_streams.saturating_sub(runners.len());
                        if available == 0 { break; }
                        let page_size = config.discovery_page_size.min(available);
                        let (after_source, after_tenant, after_store) = cursor
                            .as_ref()
                            .map(|(source, tenant, store)| (Some(source.as_str()), Some(*tenant), Some(*store)))
                            .unwrap_or((None, None, None));
                        let streams: Result<Vec<(String, Uuid, Uuid)>, sqlx::Error> = sqlx::query_as(
                            r#"
                            WITH streams AS (
                                SELECT 'legacy'::text AS source, tenant_id, store_id
                                FROM sequence_counters
                                UNION ALL
                                SELECT 'ves'::text AS source, tenant_id, store_id
                                FROM ves_sequence_counters
                            )
                            SELECT source, tenant_id, store_id
                            FROM streams
                            WHERE $1::text IS NULL
                               OR (source, tenant_id, store_id) > ($1::text, $2::uuid, $3::uuid)
                            ORDER BY source, tenant_id, store_id
                            LIMIT $4
                            "#,
                        )
                        .bind(after_source)
                        .bind(after_tenant)
                        .bind(after_store)
                        .bind(i64::try_from(page_size).unwrap_or(i64::MAX))
                        .fetch_all(&pool)
                        .await;

                        let streams = match streams {
                            Ok(streams) => streams,
                            Err(e) => {
                                error!(error = %e, "projection stream discovery failed");
                                break;
                            }
                        };
                        let page_len = streams.len();
                        cursor = streams.last().cloned();

                        for (source, tenant_uuid, store_uuid) in streams {
                            if runners.contains_key(&(source.clone(), tenant_uuid, store_uuid)) {
                                continue;
                            }

                            let tenant_id = TenantId::from_uuid(tenant_uuid);
                            let store_id = StoreId::from_uuid(store_uuid);
                            let (event_source, checkpoints, versions, documents): ProjectionStores =
                                if source == "ves" {
                                let Some(ves) = ves_sequencer.as_ref() else {
                                    continue;
                                };
                                (
                                    Arc::new(PgVesProjectionEventSource::new(ves.clone())),
                                    Arc::new(PgProjectionCheckpointStore::new_ves(pool.clone())),
                                    Arc::new(PgProjectionVersionStore::new_ves(pool.clone())),
                                    Arc::new(PgProjectionDocumentStore::new_ves(
                                        pool.clone(), tenant_id, store_id,
                                    )),
                                )
                            } else {
                                (
                                    Arc::new(PgProjectionEventSource::new(event_store.clone())),
                                    Arc::new(PgProjectionCheckpointStore::new(pool.clone())),
                                    Arc::new(PgProjectionVersionStore::new(pool.clone())),
                                    Arc::new(PgProjectionDocumentStore::new(
                                        pool.clone(), tenant_id, store_id,
                                    )),
                                )
                            };
                            let mut runner = ProjectionRunner::new(
                                config.runner.clone(),
                                event_source,
                                checkpoints,
                                versions,
                                rejections.clone(),
                            )
                            .with_dead_letter_queue(dlq.clone());
                            runner.register_projector(Arc::new(OrderProjector::new(documents.clone())));
                            runner.register_projector(Arc::new(InventoryProjector::new(documents.clone())));
                            runner.register_projector(Arc::new(ProductProjector::new(documents.clone())));
                            runner.register_projector(Arc::new(CustomerProjector::new(documents.clone())));
                            runner.register_projector(Arc::new(ReturnProjector::new(documents)));

                            let runner = Arc::new(runner);
                            runners.insert((source.clone(), tenant_uuid, store_uuid), runner.clone());
                            let task_source = source.clone();
                            let task = tasks.spawn(async move {
                                let result = runner.run_slice(&tenant_id, &store_id).await;
                                (task_source, tenant_uuid, store_uuid, result)
                            });
                            task_streams.insert(task.id(), (source.clone(), tenant_uuid, store_uuid));
                            info!(source, tenant_id = %tenant_uuid, store_id = %store_uuid, "projection stream started");
                        }

                        if page_len < page_size {
                            cursor = None;
                            break;
                        }
                    }
                }
                message = control_rx.recv() => {
                    if matches!(message, Some(ProjectionWorkerMessage::Shutdown) | None) {
                        for runner in runners.values() {
                            runner.stop().await;
                        }
                        while tasks.join_next().await.is_some() {}
                        info!("projection worker stopped");
                        return;
                    }
                }
                completed = tasks.join_next_with_id(), if !tasks.is_empty() => {
                    match completed {
                        Some(Ok((task_id, (source, tenant_id, store_id, Ok(()))))) => {
                            task_streams.remove(&task_id);
                            runners.remove(&(source, tenant_id, store_id));
                        }
                        Some(Ok((task_id, (source, tenant_id, store_id, Err(e))))) => {
                            task_streams.remove(&task_id);
                            runners.remove(&(source.clone(), tenant_id, store_id));
                            error!(source, %tenant_id, %store_id, error = %e, "projection stream failed");
                        }
                        Some(Err(e)) => {
                            if let Some(key) = task_streams.remove(&e.id()) { runners.remove(&key); }
                            error!(error = ?e, "projection stream task failed");
                        }
                        None => {}
                    }
                    // Failed streams retry on the next discovery pass without
                    // terminating unrelated tenants or the serving process.
                }
            }
        }
    });

    (task, control_tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_non_zero() {
        let config = ProjectionWorkerConfig::default();
        assert!(!config.discovery_interval.is_zero());
        assert!(config.discovery_page_size > 0);
        assert!(config.runner.batch_size > 0);
        assert!(config.runner.checkpoint_interval > 0);
    }
}
