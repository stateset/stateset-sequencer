//! Trait definitions for StateSet Sequencer core services

use async_trait::async_trait;
#[cfg(test)]
use mockall::automock;
use uuid::Uuid;

use crate::domain::{
    AgentId, BatchCommitment, EntityType, EventBatch, EventEnvelope, Hash256, IngestReceipt,
    MerkleProof, ProjectionResult, SequencedEvent, StoreId, SyncState, TenantId,
};

use super::Result;

/// Ingest service accepts events from CLI agents and production writers.
///
/// Invariant: No writes bypass the event log.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait IngestService: Send + Sync {
    /// Ingest a batch of events
    ///
    /// - Validates schema and tenant/store authorization
    /// - Deduplicates by event_id and (optional) command_id
    /// - Encrypts payloads for storage
    /// - Forwards admitted events to sequencer for ordering
    async fn ingest(&self, batch: EventBatch) -> Result<IngestReceipt>;

    /// Get sync state for an agent
    async fn get_sync_state(&self, agent_id: &AgentId) -> Result<SyncState>;

    /// Update sync state for an agent
    async fn update_sync_state(&self, state: &SyncState) -> Result<()>;
}

/// Sequencer assigns canonical ordering to events.
///
/// This is the "truth clock" - only sequence_number defines canonical order.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait Sequencer: Send + Sync {
    /// Assign sequence numbers to events
    ///
    /// Sequence numbers are monotonically increasing per (tenant_id, store_id).
    async fn sequence(&self, events: Vec<EventEnvelope>) -> Result<Vec<SequencedEvent>>;

    /// Get the current head sequence for a tenant/store
    async fn head(&self, tenant_id: &TenantId, store_id: &StoreId) -> Result<u64>;
}

/// Event store provides append-only encrypted storage for sequenced events.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait EventStore: Send + Sync {
    /// Append sequenced events to the store
    async fn append(&self, events: Vec<SequencedEvent>) -> Result<()>;

    /// Read events in a sequence range
    async fn read_range(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        start: u64,
        end: u64,
    ) -> Result<Vec<SequencedEvent>>;

    /// Read all events for a specific entity
    async fn read_entity(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        entity_type: &EntityType,
        entity_id: &str,
    ) -> Result<Vec<SequencedEvent>>;

    /// Read event by ID
    async fn read_by_id(&self, event_id: Uuid) -> Result<Option<SequencedEvent>>;

    /// Check if an event ID exists (for deduplication)
    async fn event_exists(&self, event_id: Uuid) -> Result<bool>;

    /// Check if a command ID has been processed (for deduplication)
    async fn command_exists(&self, command_id: Uuid) -> Result<bool>;
}

/// Projector applies events in sequence order to production projections.
///
/// Conflicts are handled deterministically at apply-time, not by rejecting
/// batches due to root mismatch.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait Projector: Send + Sync {
    /// Project events to production state
    ///
    /// For "hard state" (inventory, payments, order status): uses optimistic
    /// concurrency via base_version + invariants.
    ///
    /// On violation:
    /// - Does NOT delete/roll back the event log
    /// - Emits operation.failed / event.rejected with reason
    /// - Updates projections to reflect failure state
    async fn project(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        events: Vec<SequencedEvent>,
    ) -> Result<ProjectionResult>;

    /// Get current projection lag (sequences behind head)
    async fn lag(&self, tenant_id: &TenantId, store_id: &StoreId) -> Result<u64>;

    /// Get last projected sequence
    async fn checkpoint(&self, tenant_id: &TenantId, store_id: &StoreId) -> Result<u64>;

    /// Rebuild entity from event history
    async fn rebuild_entity(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        entity_type: &EntityType,
        entity_id: &str,
    ) -> Result<()>;
}

/// Commitment engine computes Merkle roots and state roots.
///
/// Proofs are generated on demand (no pre-stored proof table).
#[cfg_attr(test, automock)]
#[async_trait]
pub trait CommitmentEngine: Send + Sync {
    /// Compute events Merkle root from leaf hashes
    fn compute_events_root(&self, leaves: &[Hash256]) -> Hash256;

    /// Compute state root for a tenant/store
    async fn compute_state_root(&self, tenant_id: &TenantId, store_id: &StoreId)
        -> Result<Hash256>;

    /// Create a batch commitment
    async fn create_commitment(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        sequence_range: (u64, u64),
    ) -> Result<BatchCommitment>;

    /// Store a batch commitment
    async fn store_commitment(&self, commitment: &BatchCommitment) -> Result<()>;

    /// Get a batch commitment by ID
    async fn get_commitment(&self, batch_id: Uuid) -> Result<Option<BatchCommitment>>;

    /// List commitments that haven't been anchored on-chain
    async fn list_unanchored(&self) -> Result<Vec<BatchCommitment>>;

    /// Update commitment with chain transaction hash after on-chain anchoring
    async fn update_chain_tx(&self, batch_id: Uuid, tx_hash: Hash256) -> Result<()>;

    /// Generate inclusion proof for an event (on-demand)
    fn prove_inclusion(&self, leaf_index: usize, leaves: &[Hash256]) -> MerkleProof;

    /// Verify an inclusion proof
    fn verify_inclusion(&self, leaf: Hash256, proof: &MerkleProof, root: Hash256) -> bool;
}

/// Health check for components
#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub sequencer: ComponentHealth,
    pub event_store: ComponentHealth,
    pub projector: ComponentHealth,
    pub commitment_engine: ComponentHealth,
    pub projection_lag: u64,
}

/// Individual component health
#[derive(Debug, Clone)]
pub enum ComponentHealth {
    Healthy,
    Degraded { reason: String },
    Unhealthy { reason: String },
}

impl ComponentHealth {
    pub fn is_healthy(&self) -> bool {
        matches!(self, ComponentHealth::Healthy)
    }

    pub fn is_unhealthy(&self) -> bool {
        matches!(self, ComponentHealth::Unhealthy { .. })
    }
}

/// Health check trait
#[cfg_attr(test, automock)]
#[async_trait]
pub trait HealthCheck: Send + Sync {
    /// Check health of all components
    async fn check_health(&self) -> HealthStatus;
}
