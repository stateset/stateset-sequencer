//! Projection runner
//!
//! Reads sequenced events and applies them to domain projections.
//! Handles checkpointing, conflict detection, and rejection event emission.
//!
//! # Dead Letter Queue Integration
//!
//! Failed projections are automatically sent to a dead letter queue for:
//! - Later investigation and debugging
//! - Automatic retry with exponential backoff
//! - Alerting and monitoring

use super::{
    ApplyResult, CheckpointStore, DomainProjector, EntityVersionStore, ProjectionCheckpoint,
    RejectionEvent, RejectionReason,
};
use crate::domain::{SequencedEvent, StoreId, TenantId};
use crate::infra::{
    DeadLetterReason, EnqueueParams, PgDeadLetterQueue, SequencerError,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

/// Event source for the projection runner
#[async_trait]
pub trait EventSource: Send + Sync {
    /// Get events starting from a sequence number
    async fn get_events_from(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        from_sequence: u64,
        limit: usize,
    ) -> Result<Vec<SequencedEvent>, SequencerError>;
}

/// Rejection event sink
#[async_trait]
pub trait RejectionSink: Send + Sync {
    /// Emit a rejection event
    async fn emit_rejection(&self, rejection: RejectionEvent) -> Result<(), SequencerError>;
}

/// Projection runner configuration
#[derive(Debug, Clone)]
pub struct ProjectionRunnerConfig {
    /// Batch size for processing events
    pub batch_size: usize,

    /// How often to update checkpoint (in events)
    pub checkpoint_interval: u64,

    /// Whether to continue on errors (true) or stop (false)
    pub continue_on_error: bool,

    /// Maximum retries for transient errors
    pub max_retries: u32,

    /// Delay between retries (milliseconds)
    pub retry_delay_ms: u64,
}

impl Default for ProjectionRunnerConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            checkpoint_interval: 100,
            continue_on_error: true,
            max_retries: 3,
            retry_delay_ms: 100,
        }
    }
}

/// Projection runner statistics
#[derive(Debug, Default, Clone)]
pub struct ProjectionStats {
    pub events_processed: u64,
    pub events_applied: u64,
    pub events_rejected: u64,
    pub events_skipped: u64,
    pub errors: u64,
    pub last_sequence: Option<u64>,
}

/// Projection runner for a single tenant/store
pub struct ProjectionRunner {
    /// Configuration
    config: ProjectionRunnerConfig,

    /// Event source
    event_source: Arc<dyn EventSource>,

    /// Checkpoint store
    checkpoint_store: Arc<dyn CheckpointStore>,

    /// Entity version store
    version_store: Arc<dyn EntityVersionStore>,

    /// Rejection event sink
    rejection_sink: Arc<dyn RejectionSink>,

    /// Domain projectors by entity type
    projectors: HashMap<String, Arc<dyn DomainProjector>>,

    /// Running statistics
    stats: RwLock<ProjectionStats>,

    /// Whether the runner is running
    running: RwLock<bool>,

    /// Optional dead letter queue for failed projections
    dead_letter_queue: Option<Arc<PgDeadLetterQueue>>,
}

impl ProjectionRunner {
    pub fn new(
        config: ProjectionRunnerConfig,
        event_source: Arc<dyn EventSource>,
        checkpoint_store: Arc<dyn CheckpointStore>,
        version_store: Arc<dyn EntityVersionStore>,
        rejection_sink: Arc<dyn RejectionSink>,
    ) -> Self {
        Self {
            config,
            event_source,
            checkpoint_store,
            version_store,
            rejection_sink,
            projectors: HashMap::new(),
            stats: RwLock::new(ProjectionStats::default()),
            running: RwLock::new(false),
            dead_letter_queue: None,
        }
    }

    /// Set the dead letter queue for failed projection handling
    pub fn with_dead_letter_queue(mut self, dlq: Arc<PgDeadLetterQueue>) -> Self {
        self.dead_letter_queue = Some(dlq);
        self
    }

    /// Register a domain projector
    pub fn register_projector(&mut self, projector: Arc<dyn DomainProjector>) {
        let entity_type = projector.entity_type().to_string();
        self.projectors.insert(entity_type, projector);
    }

    /// Get current statistics
    pub async fn stats(&self) -> ProjectionStats {
        self.stats.read().await.clone()
    }

    /// Send a failed event to the dead letter queue
    #[instrument(skip(self, event, payload), fields(event_id = %event.event_id()))]
    async fn send_to_dead_letter_queue(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        event: &SequencedEvent,
        reason: DeadLetterReason,
        error_message: &str,
        payload: serde_json::Value,
    ) {
        if let Some(ref dlq) = self.dead_letter_queue {
            let reason_str = reason.to_string();
            let params = EnqueueParams {
                event_id: event.event_id(),
                tenant_id,
                store_id,
                event_type: event.event_type().as_str(),
                reason,
                error_message,
                payload,
                metadata: Some(serde_json::json!({
                    "sequence_number": event.sequence_number(),
                    "entity_type": event.entity_type().as_str(),
                    "entity_id": event.entity_id(),
                })),
            };

            if let Err(e) = dlq.enqueue(params).await {
                error!(
                    event_id = %event.event_id(),
                    error = %e,
                    "Failed to enqueue event to dead letter queue"
                );
            } else {
                info!(
                    event_id = %event.event_id(),
                    reason = %reason_str,
                    "Event sent to dead letter queue"
                );
            }
        }
    }

    /// Convert projection rejection reason to dead letter reason
    fn rejection_to_dlq_reason(reason: &RejectionReason) -> DeadLetterReason {
        match reason {
            RejectionReason::VersionConflict { .. } => DeadLetterReason::VersionConflict,
            RejectionReason::InvariantViolation { .. } => DeadLetterReason::InvariantViolation,
            RejectionReason::InvalidStateTransition { .. } => DeadLetterReason::InvalidStateTransition,
            RejectionReason::PayloadInvalid { .. } => DeadLetterReason::SchemaValidation,
            RejectionReason::EntityNotFound => DeadLetterReason::HandlerError,
        }
    }

    /// Run the projection loop for a tenant/store
    #[instrument(skip(self), fields(tenant_id = %tenant_id.0, store_id = %store_id.0))]
    pub async fn run(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
    ) -> Result<(), SequencerError> {
        // Check if already running
        {
            let mut running = self.running.write().await;
            if *running {
                return Err(SequencerError::Internal(
                    "Projection runner already running".to_string(),
                ));
            }
            *running = true;
        }

        info!(
            tenant_id = %tenant_id.0,
            store_id = %store_id.0,
            "Starting projection runner"
        );

        // Get starting checkpoint
        let checkpoint = self
            .checkpoint_store
            .get_checkpoint(tenant_id, store_id)
            .await?;

        let mut from_sequence = checkpoint.map(|c| c.last_sequence + 1).unwrap_or(0);
        let mut events_since_checkpoint = 0u64;

        loop {
            // Check if we should stop
            if !*self.running.read().await {
                info!("Projection runner stopping");
                break;
            }

            // Fetch next batch of events
            let events = self
                .event_source
                .get_events_from(tenant_id, store_id, from_sequence, self.config.batch_size)
                .await?;

            if events.is_empty() {
                // No more events, wait a bit before polling again
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                continue;
            }

            // Process each event
            for event in events {
                let result = self.process_event(tenant_id, store_id, &event).await;

                match result {
                    Ok(()) => {
                        from_sequence = event.sequence_number() + 1;
                        events_since_checkpoint += 1;

                        // Update stats
                        {
                            let mut stats = self.stats.write().await;
                            stats.events_processed += 1;
                            stats.last_sequence = Some(event.sequence_number());
                        }

                        // Checkpoint if needed
                        if events_since_checkpoint >= self.config.checkpoint_interval {
                            self.checkpoint_store
                                .set_checkpoint(tenant_id, store_id, event.sequence_number())
                                .await?;
                            events_since_checkpoint = 0;
                            debug!(sequence = event.sequence_number(), "Checkpoint updated");
                        }
                    }
                    Err(e) => {
                        error!(
                            event_id = %event.event_id(),
                            sequence = event.sequence_number(),
                            error = %e,
                            "Error processing event"
                        );

                        // Send to dead letter queue
                        self.send_to_dead_letter_queue(
                            tenant_id,
                            store_id,
                            &event,
                            DeadLetterReason::HandlerError,
                            &e.to_string(),
                            event.payload().clone(),
                        ).await;

                        {
                            let mut stats = self.stats.write().await;
                            stats.errors += 1;
                        }

                        if !self.config.continue_on_error {
                            return Err(e);
                        }

                        // Skip this event and continue
                        from_sequence = event.sequence_number() + 1;
                    }
                }
            }
        }

        // Final checkpoint
        if events_since_checkpoint > 0 {
            if let Some(seq) = self.stats.read().await.last_sequence {
                self.checkpoint_store
                    .set_checkpoint(tenant_id, store_id, seq)
                    .await?;
            }
        }

        Ok(())
    }

    /// Stop the projection runner
    pub async fn stop(&self) {
        *self.running.write().await = false;
    }

    /// Process a single event
    #[instrument(skip(self, event), fields(
        event_id = %event.event_id(),
        sequence = event.sequence_number(),
        entity_type = %event.entity_type().as_str()
    ))]
    async fn process_event(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        event: &SequencedEvent,
    ) -> Result<(), SequencerError> {
        let entity_type = &event.entity_type().0;

        // Find the appropriate projector
        let projector = match self.projectors.get(entity_type) {
            Some(p) => p,
            None => {
                // No projector for this entity type, skip
                debug!(
                    entity_type = entity_type,
                    event_id = %event.event_id(),
                    "No projector for entity type, skipping"
                );
                let mut stats = self.stats.write().await;
                stats.events_skipped += 1;
                return Ok(());
            }
        };

        // Get current version
        let current_version = self
            .version_store
            .get_version(tenant_id, store_id, entity_type, event.entity_id())
            .await?;

        // Check base_version for optimistic concurrency
        if let Some(expected_version) = event.base_version() {
            let actual_version = current_version.unwrap_or(0);
            if expected_version != actual_version {
                // Version conflict - emit rejection event
                let rejection = RejectionEvent {
                    original_event_id: event.event_id(),
                    original_sequence: event.sequence_number(),
                    entity_type: entity_type.clone(),
                    entity_id: event.entity_id().to_string(),
                    reason: "Version conflict".to_string(),
                    reason_code: "VERSION_CONFLICT".to_string(),
                    expected_version: Some(expected_version),
                    actual_version: Some(actual_version),
                };

                self.rejection_sink.emit_rejection(rejection).await?;

                // Send to dead letter queue for potential retry
                self.send_to_dead_letter_queue(
                    tenant_id,
                    store_id,
                    event,
                    DeadLetterReason::VersionConflict,
                    &format!("Version conflict: expected {}, got {}", expected_version, actual_version),
                    event.payload().clone(),
                ).await;

                warn!(
                    event_id = %event.event_id(),
                    expected = expected_version,
                    actual = actual_version,
                    "Event rejected due to version conflict"
                );

                let mut stats = self.stats.write().await;
                stats.events_rejected += 1;
                return Ok(());
            }
        }

        // Apply the event
        let result = projector.apply(event, current_version).await?;

        match result {
            ApplyResult::Applied { new_version } => {
                // Update version
                self.version_store
                    .set_version(
                        tenant_id,
                        store_id,
                        entity_type,
                        event.entity_id(),
                        new_version,
                    )
                    .await?;

                debug!(
                    event_id = %event.event_id(),
                    new_version = new_version,
                    "Event applied successfully"
                );

                let mut stats = self.stats.write().await;
                stats.events_applied += 1;
            }
            ApplyResult::Rejected { reason, message } => {
                // Emit rejection event
                let (expected_version, actual_version) = match &reason {
                    RejectionReason::VersionConflict { expected, actual } => {
                        (Some(*expected), Some(*actual))
                    }
                    _ => (None, None),
                };

                let rejection = RejectionEvent {
                    original_event_id: event.event_id(),
                    original_sequence: event.sequence_number(),
                    entity_type: entity_type.clone(),
                    entity_id: event.entity_id().to_string(),
                    reason: message.clone(),
                    reason_code: format!("{:?}", reason),
                    expected_version,
                    actual_version,
                };

                self.rejection_sink.emit_rejection(rejection).await?;

                // Send to dead letter queue
                let dlq_reason = Self::rejection_to_dlq_reason(&reason);
                self.send_to_dead_letter_queue(
                    tenant_id,
                    store_id,
                    event,
                    dlq_reason,
                    &message,
                    event.payload().clone(),
                ).await;

                warn!(
                    event_id = %event.event_id(),
                    reason = ?reason,
                    "Event rejected by projector"
                );

                let mut stats = self.stats.write().await;
                stats.events_rejected += 1;
            }
            ApplyResult::Skipped { reason } => {
                debug!(
                    event_id = %event.event_id(),
                    reason = reason,
                    "Event skipped"
                );

                let mut stats = self.stats.write().await;
                stats.events_skipped += 1;
            }
        }

        Ok(())
    }

    /// Rebuild a single entity from its event history
    #[instrument(skip(self, events), fields(
        tenant_id = %tenant_id.0,
        store_id = %store_id.0,
        entity_type = entity_type,
        entity_id = entity_id,
        event_count = events.len()
    ))]
    pub async fn rebuild_entity(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        entity_type: &str,
        entity_id: &str,
        events: &[SequencedEvent],
    ) -> Result<(), SequencerError> {
        let projector = self
            .projectors
            .get(entity_type)
            .ok_or_else(|| SequencerError::InvalidEntityType(entity_type.to_string()))?;

        projector
            .rebuild(tenant_id, store_id, entity_id, events)
            .await
    }
}

/// In-memory implementation of EntityVersionStore for development
pub struct InMemoryVersionStore {
    versions: RwLock<HashMap<String, u64>>,
}

impl InMemoryVersionStore {
    pub fn new() -> Self {
        Self {
            versions: RwLock::new(HashMap::new()),
        }
    }

    fn make_key(
        tenant_id: &TenantId,
        store_id: &StoreId,
        entity_type: &str,
        entity_id: &str,
    ) -> String {
        format!(
            "{}:{}:{}:{}",
            tenant_id.0, store_id.0, entity_type, entity_id
        )
    }
}

impl Default for InMemoryVersionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EntityVersionStore for InMemoryVersionStore {
    async fn get_version(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        entity_type: &str,
        entity_id: &str,
    ) -> Result<Option<u64>, SequencerError> {
        let key = Self::make_key(tenant_id, store_id, entity_type, entity_id);
        let versions = self.versions.read().await;
        Ok(versions.get(&key).copied())
    }

    async fn set_version(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        entity_type: &str,
        entity_id: &str,
        version: u64,
    ) -> Result<(), SequencerError> {
        let key = Self::make_key(tenant_id, store_id, entity_type, entity_id);
        let mut versions = self.versions.write().await;
        versions.insert(key, version);
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
        let key = Self::make_key(tenant_id, store_id, entity_type, entity_id);
        let mut versions = self.versions.write().await;

        let current = versions.get(&key).copied();
        if current == expected_version {
            versions.insert(key, new_version);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// In-memory implementation of CheckpointStore for development
pub struct InMemoryCheckpointStore {
    checkpoints: RwLock<HashMap<String, ProjectionCheckpoint>>,
}

impl InMemoryCheckpointStore {
    pub fn new() -> Self {
        Self {
            checkpoints: RwLock::new(HashMap::new()),
        }
    }

    fn make_key(tenant_id: &TenantId, store_id: &StoreId) -> String {
        format!("{}:{}", tenant_id.0, store_id.0)
    }
}

impl Default for InMemoryCheckpointStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CheckpointStore for InMemoryCheckpointStore {
    async fn get_checkpoint(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
    ) -> Result<Option<ProjectionCheckpoint>, SequencerError> {
        let key = Self::make_key(tenant_id, store_id);
        let checkpoints = self.checkpoints.read().await;
        Ok(checkpoints.get(&key).cloned())
    }

    async fn set_checkpoint(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        sequence: u64,
    ) -> Result<(), SequencerError> {
        let key = Self::make_key(tenant_id, store_id);
        let mut checkpoints = self.checkpoints.write().await;
        checkpoints.insert(
            key,
            ProjectionCheckpoint {
                tenant_id: tenant_id.clone(),
                store_id: store_id.clone(),
                last_sequence: sequence,
                updated_at: chrono::Utc::now(),
            },
        );
        Ok(())
    }
}

/// In-memory rejection sink for development
pub struct InMemoryRejectionSink {
    rejections: RwLock<Vec<RejectionEvent>>,
}

impl InMemoryRejectionSink {
    pub fn new() -> Self {
        Self {
            rejections: RwLock::new(Vec::new()),
        }
    }

    pub async fn get_rejections(&self) -> Vec<RejectionEvent> {
        self.rejections.read().await.clone()
    }
}

impl Default for InMemoryRejectionSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RejectionSink for InMemoryRejectionSink {
    async fn emit_rejection(&self, rejection: RejectionEvent) -> Result<(), SequencerError> {
        let mut rejections = self.rejections.write().await;
        rejections.push(rejection);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_version_store() {
        let store = InMemoryVersionStore::new();
        let tenant_id = TenantId(uuid::Uuid::new_v4());
        let store_id = StoreId(uuid::Uuid::new_v4());

        // Initially no version
        let version = store
            .get_version(&tenant_id, &store_id, "order", "ord-123")
            .await
            .unwrap();
        assert!(version.is_none());

        // Set version
        store
            .set_version(&tenant_id, &store_id, "order", "ord-123", 1)
            .await
            .unwrap();

        // Get version
        let version = store
            .get_version(&tenant_id, &store_id, "order", "ord-123")
            .await
            .unwrap();
        assert_eq!(version, Some(1));

        // CAS success
        let success = store
            .compare_and_set_version(&tenant_id, &store_id, "order", "ord-123", Some(1), 2)
            .await
            .unwrap();
        assert!(success);

        // CAS failure
        let success = store
            .compare_and_set_version(&tenant_id, &store_id, "order", "ord-123", Some(1), 3)
            .await
            .unwrap();
        assert!(!success);
    }

    #[tokio::test]
    async fn test_in_memory_checkpoint_store() {
        let store = InMemoryCheckpointStore::new();
        let tenant_id = TenantId(uuid::Uuid::new_v4());
        let store_id = StoreId(uuid::Uuid::new_v4());

        // Initially no checkpoint
        let checkpoint = store.get_checkpoint(&tenant_id, &store_id).await.unwrap();
        assert!(checkpoint.is_none());

        // Set checkpoint
        store
            .set_checkpoint(&tenant_id, &store_id, 100)
            .await
            .unwrap();

        // Get checkpoint
        let checkpoint = store.get_checkpoint(&tenant_id, &store_id).await.unwrap();
        assert!(checkpoint.is_some());
        assert_eq!(checkpoint.unwrap().last_sequence, 100);
    }
}
