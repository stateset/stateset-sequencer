//! Projection engine for StateSet Sequencer
//!
//! Applies sequenced events to domain projections with:
//! - Optimistic concurrency (base_version checking)
//! - Invariant validation
//! - Rejection event emission (never halts on conflict)
//! - Checkpoint tracking

mod handlers;
mod runner;

pub use handlers::*;
pub use runner::*;

use crate::domain::{SequencedEvent, StoreId, TenantId};
use crate::infra::SequencerError;
use async_trait::async_trait;
use uuid::Uuid;

/// Result of applying a single event
#[derive(Debug)]
pub enum ApplyResult {
    /// Event applied successfully, entity version updated
    Applied { new_version: u64 },

    /// Event rejected due to conflict or invariant violation
    Rejected {
        reason: RejectionReason,
        message: String,
    },

    /// Event skipped (e.g., duplicate or irrelevant)
    Skipped { reason: String },
}

/// Reasons an event can be rejected during projection
#[derive(Debug, Clone)]
pub enum RejectionReason {
    /// Version conflict (optimistic concurrency)
    VersionConflict { expected: u64, actual: u64 },

    /// Domain invariant violated
    InvariantViolation { invariant: String },

    /// Invalid state transition
    InvalidStateTransition { from: String, to: String },

    /// Entity not found (for updates/deletes)
    EntityNotFound,

    /// Payload validation failed
    PayloadInvalid { field: String, error: String },
}

/// Projection checkpoint tracking
#[derive(Debug, Clone)]
pub struct ProjectionCheckpoint {
    pub tenant_id: TenantId,
    pub store_id: StoreId,
    pub last_sequence: u64,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// System event for rejected events
#[derive(Debug, Clone, serde::Serialize)]
pub struct RejectionEvent {
    /// Original event that was rejected
    pub original_event_id: Uuid,

    /// Sequence number of the original event
    pub original_sequence: u64,

    /// Entity that was affected
    pub entity_type: String,
    pub entity_id: String,

    /// Rejection details
    pub reason: String,
    pub reason_code: String,

    /// Version conflict details (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_version: Option<u64>,
}

/// Domain projector trait for entity-specific projection logic
#[async_trait]
pub trait DomainProjector: Send + Sync {
    /// Entity type this projector handles
    fn entity_type(&self) -> &str;

    /// Apply an event to the projection
    async fn apply(
        &self,
        event: &SequencedEvent,
        current_version: Option<u64>,
    ) -> Result<ApplyResult, SequencerError>;

    /// Rebuild entity from event history
    async fn rebuild(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        entity_id: &str,
        events: &[SequencedEvent],
    ) -> Result<(), SequencerError>;
}

/// Entity version store trait
#[async_trait]
pub trait EntityVersionStore: Send + Sync {
    /// Get current version of an entity
    async fn get_version(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        entity_type: &str,
        entity_id: &str,
    ) -> Result<Option<u64>, SequencerError>;

    /// Update entity version
    async fn set_version(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        entity_type: &str,
        entity_id: &str,
        version: u64,
    ) -> Result<(), SequencerError>;

    /// Check and update version atomically (CAS operation)
    async fn compare_and_set_version(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        entity_type: &str,
        entity_id: &str,
        expected_version: Option<u64>,
        new_version: u64,
    ) -> Result<bool, SequencerError>;
}

/// Checkpoint store trait
#[async_trait]
pub trait CheckpointStore: Send + Sync {
    /// Get current checkpoint
    async fn get_checkpoint(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
    ) -> Result<Option<ProjectionCheckpoint>, SequencerError>;

    /// Update checkpoint
    async fn set_checkpoint(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        sequence: u64,
    ) -> Result<(), SequencerError>;
}
