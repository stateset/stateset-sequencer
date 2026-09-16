//! gRPC Sequencer v2 service: event push/pull/stream/sync.
//!
//! Implements the VES v1.0 Protocol with bidirectional streaming support.
//! Stateless conversions live in [`super::convert`]; shared service limits in
//! [`super`].
#![allow(clippy::result_large_err)]

use super::convert;
use super::{MAX_ENTITY_HISTORY, MAX_GRPC_BATCH_SIZE};
use crate::auth::AuthContext;
use crate::domain::{EntityType, StoreId, TenantId};
use crate::infra::{
    CacheManager, PgAgentKeyRegistry, PgVesCommitmentEngine, VesSequencer, CACHE_STAMPEDE_DELAY,
};
use crate::proto::v2::{
    self, sequencer_server::Sequencer as SequencerTrait, BatchCommitment, GetCommitmentRequest,
    GetEntityHistoryRequest, GetEntityHistoryResponse, GetInclusionProofRequest,
    GetInclusionProofResponse, GetSyncStateRequest, HealthResponse, InclusionProof,
    PullEventsRequest, PullEventsResponse, PushRequest, PushResponse, RejectedEvent,
    SequencedEvent, StreamEventsRequest, SubscribeEntityRequest, SyncMessage, SyncState,
};
use chrono::Utc;
use std::collections::HashSet;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

/// gRPC Sequencer v2 service implementation
pub struct SequencerServiceV2 {
    ves_sequencer: Arc<VesSequencer<PgAgentKeyRegistry>>,
    ves_sequencer_reader: Arc<VesSequencer<PgAgentKeyRegistry>>,
    ves_commitment_engine: Arc<PgVesCommitmentEngine>,
    ves_commitment_reader: Arc<PgVesCommitmentEngine>,
    cache_manager: Arc<CacheManager>,
    /// Broadcast channel for real-time event notifications
    event_tx: broadcast::Sender<SequencedEvent>,
}

impl SequencerServiceV2 {
    pub fn new(
        ves_sequencer: Arc<VesSequencer<PgAgentKeyRegistry>>,
        ves_commitment_engine: Arc<PgVesCommitmentEngine>,
        ves_sequencer_reader: Arc<VesSequencer<PgAgentKeyRegistry>>,
        ves_commitment_reader: Arc<PgVesCommitmentEngine>,
        cache_manager: Arc<CacheManager>,
    ) -> Self {
        // Create broadcast channel for event streaming (1024 event buffer)
        let (event_tx, _) = broadcast::channel(1024);
        Self {
            ves_sequencer,
            ves_sequencer_reader,
            ves_commitment_engine,
            ves_commitment_reader,
            cache_manager,
            event_tx,
        }
    }

    fn auth_context<T>(request: &Request<T>) -> Result<AuthContext, Status> {
        request
            .extensions()
            .get::<AuthContext>()
            .cloned()
            .ok_or_else(|| Status::unauthenticated("missing auth context"))
    }

    fn require_read(ctx: &AuthContext) -> Result<(), Status> {
        if ctx.can_read() {
            Ok(())
        } else {
            Err(Status::permission_denied("read permission required"))
        }
    }

    fn require_write(ctx: &AuthContext) -> Result<(), Status> {
        if ctx.can_write() {
            Ok(())
        } else {
            Err(Status::permission_denied("write permission required"))
        }
    }

    fn authorize_tenant_store(
        ctx: &AuthContext,
        tenant_id: &TenantId,
        store_id: &StoreId,
    ) -> Result<(), Status> {
        if !ctx.tenant_id.is_nil() && ctx.tenant_id != tenant_id.0 {
            return Err(Status::permission_denied("tenant access denied"));
        }
        if !ctx.can_access_store(&store_id.0) {
            return Err(Status::permission_denied("store access denied"));
        }
        Ok(())
    }

    /// Broadcast a new event to all subscribers
    pub fn broadcast_event(&self, event: SequencedEvent) {
        if let Err(e) = self.event_tx.send(event) {
            debug!("No active event subscribers: {}", e);
        }
    }

    async fn broadcast_range(
        ves_sequencer: &VesSequencer<PgAgentKeyRegistry>,
        event_tx: &broadcast::Sender<SequencedEvent>,
        tenant_id: &TenantId,
        store_id: &StoreId,
        start: u64,
        end: u64,
    ) -> Result<(), Status> {
        if start == 0 || end == 0 || end < start {
            return Ok(());
        }

        let events = ves_sequencer
            .read_range(tenant_id, store_id, start, end)
            .await
            .map_err(super::grpc_sequencer_error)?;

        for event in events {
            let proto_event = convert::to_proto_event(&event)?;
            let _ = event_tx.send(proto_event);
        }

        Ok(())
    }
}

#[tonic::async_trait]
impl SequencerTrait for SequencerServiceV2 {
    /// Push a batch of events for sequencing
    #[instrument(skip(self, request))]
    async fn push(&self, request: Request<PushRequest>) -> Result<Response<PushResponse>, Status> {
        let auth_ctx = Self::auth_context(&request)?;
        let req = request.into_inner();

        info!(
            agent_id = %req.agent_id,
            tenant_id = %req.tenant_id,
            store_id = %req.store_id,
            event_count = req.events.len(),
            request_id = %req.request_id,
            "Processing v2 Push request"
        );

        if req.events.is_empty() {
            return Err(Status::invalid_argument("events must not be empty"));
        }
        if req.events.len() > MAX_GRPC_BATCH_SIZE {
            return Err(Status::resource_exhausted(format!(
                "batch size {} exceeds maximum of {}",
                req.events.len(),
                MAX_GRPC_BATCH_SIZE,
            )));
        }

        let tenant_id = Uuid::parse_str(&req.tenant_id)
            .map_err(|e| Status::invalid_argument(format!("invalid tenant_id: {}", e)))?;
        let store_id = Uuid::parse_str(&req.store_id)
            .map_err(|e| Status::invalid_argument(format!("invalid store_id: {}", e)))?;
        let tenant_id = TenantId(tenant_id);
        let store_id = StoreId(store_id);

        Self::require_write(&auth_ctx)?;
        Self::authorize_tenant_store(&auth_ctx, &tenant_id, &store_id)?;

        // Parse agent ID
        let agent_id = Uuid::parse_str(&req.agent_id)
            .map_err(|e| Status::invalid_argument(format!("invalid agent_id: {}", e)))?;

        // Convert proto events to VES events
        let mut events = Vec::with_capacity(req.events.len());
        for proto_event in &req.events {
            let event = convert::from_proto_event(proto_event)?;
            if event.tenant_id.0 != tenant_id.0 || event.store_id.0 != store_id.0 {
                return Err(Status::invalid_argument(
                    "event tenant_id/store_id must match push request",
                ));
            }
            if event.source_agent_id.0 != agent_id {
                return Err(Status::invalid_argument(
                    "event source_agent must match push request agent_id",
                ));
            }
            events.push(event);
        }

        // Ingest
        match self.ves_sequencer.ingest(events).await {
            Ok(receipt) => {
                let rejections: Vec<RejectedEvent> = receipt
                    .events_rejected
                    .iter()
                    .map(|r| RejectedEvent {
                        event_id: r.event_id.to_string(),
                        reason: convert::map_rejection_reason(&r.reason) as i32,
                        message: r.message.clone(),
                    })
                    .collect();

                if receipt.events_accepted > 0 {
                    if let (Some(start), Some(end)) = (
                        receipt.assigned_sequence_start,
                        receipt.assigned_sequence_end,
                    ) {
                        if let Err(e) = Self::broadcast_range(
                            self.ves_sequencer.as_ref(),
                            &self.event_tx,
                            &tenant_id,
                            &store_id,
                            start,
                            end,
                        )
                        .await
                        {
                            warn!(error = %e, "Failed to broadcast v2 push events");
                        }
                    }
                }

                Ok(Response::new(PushResponse {
                    batch_id: receipt.batch_id.to_string(),
                    request_id: req.request_id,
                    events_accepted: receipt.events_accepted,
                    events_rejected: rejections.len() as u32,
                    sequence_start: receipt.assigned_sequence_start.unwrap_or(0),
                    sequence_end: receipt.assigned_sequence_end.unwrap_or(0),
                    head_sequence: receipt.head_sequence,
                    rejections,
                    commitment: None,
                }))
            }
            Err(e) => {
                error!(error = %e, "Push failed");
                Err(super::grpc_internal_error(e))
            }
        }
    }

    /// Pull events (unary, for simple polling)
    #[instrument(skip(self, request))]
    async fn pull_events(
        &self,
        request: Request<PullEventsRequest>,
    ) -> Result<Response<PullEventsResponse>, Status> {
        let auth_ctx = Self::auth_context(&request)?;
        let req = request.into_inner();

        debug!(
            tenant_id = %req.tenant_id,
            store_id = %req.store_id,
            from_sequence = req.from_sequence,
            limit = req.limit,
            "Processing v2 PullEvents request"
        );

        // Parse IDs
        let tenant_id = Uuid::parse_str(&req.tenant_id)
            .map_err(|e| Status::invalid_argument(format!("invalid tenant_id: {}", e)))?;
        let store_id = Uuid::parse_str(&req.store_id)
            .map_err(|e| Status::invalid_argument(format!("invalid store_id: {}", e)))?;

        let tenant_id = TenantId(tenant_id);
        let store_id = StoreId(store_id);
        let limit = if req.limit == 0 {
            100
        } else {
            req.limit.min(1000)
        } as u64;

        // Validate filter field lengths
        if req.entity_type_filter.len() > 128 {
            return Err(Status::invalid_argument(
                "entity_type_filter must not exceed 128 characters",
            ));
        }
        if req.entity_id_filter.len() > 512 {
            return Err(Status::invalid_argument(
                "entity_id_filter must not exceed 512 characters",
            ));
        }
        if req.event_type_filter.len() > 100 {
            return Err(Status::invalid_argument(
                "event_type_filter must not exceed 100 entries",
            ));
        }
        if req.agent_filter.len() > 100 {
            return Err(Status::invalid_argument(
                "agent_filter must not exceed 100 entries",
            ));
        }

        Self::require_read(&auth_ctx)?;
        Self::authorize_tenant_store(&auth_ctx, &tenant_id, &store_id)?;

        // Get head sequence
        let head = self
            .ves_sequencer
            .head(&tenant_id, &store_id)
            .await
            .map_err(super::grpc_internal_error)?;
        // Read events (replica -> primary fallback)
        let mut events = self
            .ves_sequencer_reader
            .read_range(
                &tenant_id,
                &store_id,
                req.from_sequence,
                req.from_sequence.saturating_add(limit).saturating_sub(1),
            )
            .await
            .map_err(super::grpc_sequencer_error)?;

        if events.is_empty() {
            let expected_start = if req.from_sequence == 0 {
                1
            } else {
                req.from_sequence
            };
            if head >= expected_start {
                events = self
                    .ves_sequencer
                    .read_range(
                        &tenant_id,
                        &store_id,
                        req.from_sequence,
                        req.from_sequence.saturating_add(limit).saturating_sub(1),
                    )
                    .await
                    .map_err(super::grpc_sequencer_error)?;
            }
        }

        // Apply filters if specified
        let filtered_events: Vec<_> = events
            .into_iter()
            .filter(|e| {
                // Entity type filter
                if !req.entity_type_filter.is_empty()
                    && e.entity_type().0.as_str() != req.entity_type_filter.as_str()
                {
                    return false;
                }
                // Entity ID filter
                if !req.entity_id_filter.is_empty() && e.entity_id() != req.entity_id_filter {
                    return false;
                }
                // Event type filter (any match)
                if !req.event_type_filter.is_empty()
                    && !req.event_type_filter.contains(&e.event_type().0)
                {
                    return false;
                }
                // Agent filter (any match)
                if !req.agent_filter.is_empty() {
                    let agent_str = e.envelope.source_agent_id.0.to_string();
                    if !req.agent_filter.contains(&agent_str) {
                        return false;
                    }
                }
                true
            })
            .collect();

        let end_sequence = req.from_sequence.saturating_add(limit).saturating_sub(1);
        let has_more = head > end_sequence;

        // Convert to proto events
        let proto_events: Vec<SequencedEvent> = filtered_events
            .iter()
            .map(convert::to_proto_event)
            .collect::<Result<_, _>>()?;

        // Calculate next sequence
        let next_sequence = if has_more {
            end_sequence.saturating_add(1)
        } else {
            head.saturating_add(1)
        };

        Ok(Response::new(PullEventsResponse {
            events: proto_events,
            next_sequence,
            has_more,
            head_sequence: head,
        }))
    }

    /// Get current sync state
    async fn get_sync_state(
        &self,
        request: Request<GetSyncStateRequest>,
    ) -> Result<Response<SyncState>, Status> {
        let auth_ctx = Self::auth_context(&request)?;
        let req = request.into_inner();

        let tenant_id = Uuid::parse_str(&req.tenant_id)
            .map_err(|e| Status::invalid_argument(format!("invalid tenant_id: {}", e)))?;
        let store_id = Uuid::parse_str(&req.store_id)
            .map_err(|e| Status::invalid_argument(format!("invalid store_id: {}", e)))?;

        let tenant_id = TenantId(tenant_id);
        let store_id = StoreId(store_id);

        Self::require_read(&auth_ctx)?;
        Self::authorize_tenant_store(&auth_ctx, &tenant_id, &store_id)?;

        let head = self
            .ves_sequencer
            .head(&tenant_id, &store_id)
            .await
            .map_err(super::grpc_internal_error)?;
        let acknowledged_sequence = if let Some(agent_id) = auth_ctx.agent_id {
            self.ves_sequencer
                .agent_cursor_store()
                .get(tenant_id.0, store_id.0, agent_id)
                .await
                .map_err(super::grpc_internal_error)?
                .map(|cursor| cursor.sequence())
                .transpose()
                .map_err(super::grpc_internal_error)?
                .unwrap_or(0)
        } else {
            0
        };

        let cache = &self.cache_manager.ves_commitments;
        let mut lock_acquired = false;
        let mut latest_commitment = cache.get_latest(&tenant_id.0, &store_id.0).await;
        if latest_commitment.is_none() {
            let (cached, lock) = cache.get_latest_with_lock(&tenant_id.0, &store_id.0).await;
            lock_acquired = lock;
            latest_commitment = cached;

            if latest_commitment.is_none() && !lock_acquired {
                tokio::time::sleep(CACHE_STAMPEDE_DELAY).await;
                latest_commitment = cache.get_latest(&tenant_id.0, &store_id.0).await;
            }

            if latest_commitment.is_none() {
                let fetched = match self
                    .ves_commitment_reader
                    .get_last_commitment(&tenant_id, &store_id)
                    .await
                {
                    Ok(Some(c)) => Some(c),
                    Ok(None) => match self
                        .ves_commitment_engine
                        .get_last_commitment(&tenant_id, &store_id)
                        .await
                    {
                        Ok(commitment) => commitment,
                        Err(e) => {
                            if lock_acquired {
                                cache.release_latest_lock(&tenant_id.0, &store_id.0).await;
                            }
                            return Err(super::grpc_internal_error(e));
                        }
                    },
                    Err(_) => match self
                        .ves_commitment_engine
                        .get_last_commitment(&tenant_id, &store_id)
                        .await
                    {
                        Ok(commitment) => commitment,
                        Err(e) => {
                            if lock_acquired {
                                cache.release_latest_lock(&tenant_id.0, &store_id.0).await;
                            }
                            return Err(super::grpc_internal_error(e));
                        }
                    },
                };

                if let Some(commitment) = fetched {
                    cache.insert(commitment.clone()).await;
                    latest_commitment = Some(commitment);
                }
            }
        }

        if lock_acquired {
            cache.release_latest_lock(&tenant_id.0, &store_id.0).await;
        }

        let state_root = latest_commitment
            .as_ref()
            .map(|c| c.new_state_root.to_vec())
            .unwrap_or_default();

        Ok(Response::new(SyncState {
            tenant_id: req.tenant_id,
            store_id: req.store_id,
            head_sequence: head,
            state_root,
            latest_commitment: latest_commitment.as_ref().map(convert::to_proto_commitment),
            timestamp: Some(prost_types::Timestamp {
                seconds: Utc::now().timestamp(),
                nanos: 0,
            }),
            acknowledged_sequence,
            lag: head.saturating_sub(acknowledged_sequence),
        }))
    }

    /// Get Merkle inclusion proof
    #[instrument(skip(self, request))]
    async fn get_inclusion_proof(
        &self,
        request: Request<GetInclusionProofRequest>,
    ) -> Result<Response<GetInclusionProofResponse>, Status> {
        let auth_ctx = Self::auth_context(&request)?;
        let req = request.into_inner();

        let tenant_id = Uuid::parse_str(&req.tenant_id)
            .map_err(|e| Status::invalid_argument(format!("invalid tenant_id: {}", e)))?;
        let store_id = Uuid::parse_str(&req.store_id)
            .map_err(|e| Status::invalid_argument(format!("invalid store_id: {}", e)))?;

        let tenant_id = TenantId(tenant_id);
        let store_id = StoreId(store_id);

        Self::require_read(&auth_ctx)?;
        Self::authorize_tenant_store(&auth_ctx, &tenant_id, &store_id)?;

        // Get event by selector (replica -> primary fallback)
        let event = match req.selector {
            Some(v2::get_inclusion_proof_request::Selector::EventId(ref id)) => {
                let event_id = Uuid::parse_str(id)
                    .map_err(|e| Status::invalid_argument(format!("invalid event_id: {}", e)))?;
                match self.ves_sequencer_reader.read_by_id(event_id).await {
                    Ok(Some(event)) => event,
                    Ok(None) => self
                        .ves_sequencer
                        .read_by_id(event_id)
                        .await
                        .map_err(super::grpc_internal_error)?
                        .ok_or_else(|| Status::not_found("event not found"))?,
                    Err(_) => self
                        .ves_sequencer
                        .read_by_id(event_id)
                        .await
                        .map_err(super::grpc_internal_error)?
                        .ok_or_else(|| Status::not_found("event not found"))?,
                }
            }
            Some(v2::get_inclusion_proof_request::Selector::SequenceNumber(seq)) => {
                let mut events = self
                    .ves_sequencer_reader
                    .read_range(&tenant_id, &store_id, seq, seq)
                    .await
                    .map_err(super::grpc_sequencer_error)?;
                if events.is_empty() {
                    events = self
                        .ves_sequencer
                        .read_range(&tenant_id, &store_id, seq, seq)
                        .await
                        .map_err(super::grpc_sequencer_error)?;
                }
                events
                    .into_iter()
                    .next()
                    .ok_or_else(|| Status::not_found("event not found"))?
            }
            None => {
                return Err(Status::invalid_argument("selector required"));
            }
        };

        if event.envelope.tenant_id.0 != tenant_id.0 || event.envelope.store_id.0 != store_id.0 {
            return Err(Status::not_found("event not found"));
        }

        let seq = event.sequence_number();

        // Find the commitment containing this event.
        let commitment = match self
            .ves_commitment_reader
            .get_commitment_by_sequence(&tenant_id, &store_id, seq)
            .await
        {
            Ok(Some(commitment)) => commitment,
            Ok(None) => self
                .ves_commitment_engine
                .get_commitment_by_sequence(&tenant_id, &store_id, seq)
                .await
                .map_err(super::grpc_internal_error)?
                .ok_or_else(|| Status::not_found("no commitment found"))?,
            Err(_) => self
                .ves_commitment_engine
                .get_commitment_by_sequence(&tenant_id, &store_id, seq)
                .await
                .map_err(super::grpc_internal_error)?
                .ok_or_else(|| Status::not_found("no commitment found"))?,
        };

        self.cache_manager
            .ves_commitments
            .insert(commitment.clone())
            .await;

        // Verify event is within the commitment's sequence range
        if seq < commitment.sequence_range.0 || seq > commitment.sequence_range.1 {
            return Err(Status::not_found("event not found in commitment range"));
        }

        if !req.expected_root.is_empty() && commitment.merkle_root.to_vec() != req.expected_root {
            return Err(Status::failed_precondition("commitment root mismatch"));
        }

        // Calculate leaf index within batch
        let leaf_index = (seq - commitment.sequence_range.0) as usize;

        let proof_cache = &self.cache_manager.ves_proofs;
        if let Some(proof) = proof_cache.get(&tenant_id.0, &store_id.0, seq).await {
            if self.ves_commitment_reader.verify_inclusion(
                proof.leaf_hash,
                &proof,
                commitment.merkle_root,
            ) {
                return Ok(Response::new(GetInclusionProofResponse {
                    included: true,
                    proof: Some(InclusionProof {
                        merkle_root: commitment.merkle_root.to_vec(),
                        leaf_index: proof.leaf_index as u64,
                        proof_hashes: proof.proof_path.iter().map(|h| h.to_vec()).collect(),
                        leaf_count: commitment.leaf_count as u64,
                        leaf_hash: proof.leaf_hash.to_vec(),
                    }),
                    event: Some(convert::to_proto_event(&event)?),
                }));
            }
        }

        let (cached, lock_acquired) = proof_cache
            .get_with_lock(&tenant_id.0, &store_id.0, seq)
            .await;
        if let Some(proof) = cached {
            if self.ves_commitment_reader.verify_inclusion(
                proof.leaf_hash,
                &proof,
                commitment.merkle_root,
            ) {
                return Ok(Response::new(GetInclusionProofResponse {
                    included: true,
                    proof: Some(InclusionProof {
                        merkle_root: commitment.merkle_root.to_vec(),
                        leaf_index: proof.leaf_index as u64,
                        proof_hashes: proof.proof_path.iter().map(|h| h.to_vec()).collect(),
                        leaf_count: commitment.leaf_count as u64,
                        leaf_hash: proof.leaf_hash.to_vec(),
                    }),
                    event: Some(convert::to_proto_event(&event)?),
                }));
            }
        }

        if !lock_acquired {
            tokio::time::sleep(CACHE_STAMPEDE_DELAY).await;
            if let Some(proof) = proof_cache.get(&tenant_id.0, &store_id.0, seq).await {
                if self.ves_commitment_reader.verify_inclusion(
                    proof.leaf_hash,
                    &proof,
                    commitment.merkle_root,
                ) {
                    return Ok(Response::new(GetInclusionProofResponse {
                        included: true,
                        proof: Some(InclusionProof {
                            merkle_root: commitment.merkle_root.to_vec(),
                            leaf_index: proof.leaf_index as u64,
                            proof_hashes: proof.proof_path.iter().map(|h| h.to_vec()).collect(),
                            leaf_count: commitment.leaf_count as u64,
                            leaf_hash: proof.leaf_hash.to_vec(),
                        }),
                        event: Some(convert::to_proto_event(&event)?),
                    }));
                }
            }
        }

        // Build leaves
        let start = commitment.sequence_range.0;
        let end = commitment.sequence_range.1;

        let mut leaves = match self
            .ves_commitment_reader
            .leaf_hashes_for_range(&tenant_id, &store_id, start, end)
            .await
        {
            Ok(leaves) => leaves,
            Err(e) => {
                if lock_acquired {
                    proof_cache
                        .release_lock(&tenant_id.0, &store_id.0, seq)
                        .await;
                }
                return Err(super::grpc_internal_error(e));
            }
        };

        if leaves.is_empty() {
            if lock_acquired {
                proof_cache
                    .release_lock(&tenant_id.0, &store_id.0, seq)
                    .await;
            }
            error!("commitment range contains no events");
            return Err(Status::internal("internal error"));
        }

        let computed_root = self.ves_commitment_reader.compute_merkle_root(&leaves);
        if computed_root != commitment.merkle_root {
            leaves = match self
                .ves_commitment_engine
                .leaf_hashes_for_range(&tenant_id, &store_id, start, end)
                .await
            {
                Ok(leaves) => leaves,
                Err(e) => {
                    if lock_acquired {
                        proof_cache
                            .release_lock(&tenant_id.0, &store_id.0, seq)
                            .await;
                    }
                    return Err(super::grpc_internal_error(e));
                }
            };
            let computed_root_primary = self.ves_commitment_engine.compute_merkle_root(&leaves);
            if computed_root_primary != commitment.merkle_root {
                if lock_acquired {
                    proof_cache
                        .release_lock(&tenant_id.0, &store_id.0, seq)
                        .await;
                }
                error!("commitment merkle_root does not match ves_events");
                return Err(Status::internal("internal error"));
            }
        }

        let proof = match self
            .ves_commitment_reader
            .prove_inclusion(leaf_index, &leaves)
        {
            Ok(proof) => proof,
            Err(e) => {
                if lock_acquired {
                    proof_cache
                        .release_lock(&tenant_id.0, &store_id.0, seq)
                        .await;
                }
                return Err(super::grpc_internal_error(e));
            }
        };

        proof_cache
            .insert(tenant_id.0, store_id.0, seq, proof.clone())
            .await;
        if lock_acquired {
            proof_cache
                .release_lock(&tenant_id.0, &store_id.0, seq)
                .await;
        }

        Ok(Response::new(GetInclusionProofResponse {
            included: true,
            proof: Some(InclusionProof {
                merkle_root: commitment.merkle_root.to_vec(),
                leaf_index: leaf_index as u64,
                proof_hashes: proof.proof_path.iter().map(|h| h.to_vec()).collect(),
                leaf_count: leaves.len() as u64,
                leaf_hash: proof.leaf_hash.to_vec(),
            }),
            event: Some(convert::to_proto_event(&event)?),
        }))
    }

    /// Get batch commitment
    #[instrument(skip(self, request))]
    async fn get_commitment(
        &self,
        request: Request<GetCommitmentRequest>,
    ) -> Result<Response<BatchCommitment>, Status> {
        let auth_ctx = Self::auth_context(&request)?;
        let req = request.into_inner();

        Self::require_read(&auth_ctx)?;

        let commitment = match req.selector {
            Some(v2::get_commitment_request::Selector::BatchId(ref id)) => {
                let batch_id = Uuid::parse_str(id)
                    .map_err(|e| Status::invalid_argument(format!("invalid batch_id: {}", e)))?;
                let cache = &self.cache_manager.ves_commitments;
                let mut lock_acquired = false;
                let mut fetched_from_db = false;
                let mut commitment = cache.get_by_batch_id(&batch_id).await;

                if commitment.is_none() {
                    let (cached, lock) = cache.get_by_batch_id_with_lock(&batch_id).await;
                    lock_acquired = lock;
                    commitment = cached;

                    if commitment.is_none() && !lock_acquired {
                        tokio::time::sleep(CACHE_STAMPEDE_DELAY).await;
                        commitment = cache.get_by_batch_id(&batch_id).await;
                    }

                    if commitment.is_none() {
                        let fetched =
                            match self.ves_commitment_reader.get_commitment(batch_id).await {
                                Ok(Some(commitment)) => Some(commitment),
                                Ok(None) => {
                                    match self.ves_commitment_engine.get_commitment(batch_id).await
                                    {
                                        Ok(commitment) => commitment,
                                        Err(e) => {
                                            if lock_acquired {
                                                cache.release_batch_id_lock(&batch_id).await;
                                            }
                                            return Err(super::grpc_internal_error(e));
                                        }
                                    }
                                }
                                Err(_) => {
                                    match self.ves_commitment_engine.get_commitment(batch_id).await
                                    {
                                        Ok(commitment) => commitment,
                                        Err(e) => {
                                            if lock_acquired {
                                                cache.release_batch_id_lock(&batch_id).await;
                                            }
                                            return Err(super::grpc_internal_error(e));
                                        }
                                    }
                                }
                            };

                        commitment = fetched;
                        fetched_from_db = true;
                    }
                }

                let Some(commitment) = commitment else {
                    if lock_acquired {
                        cache.release_batch_id_lock(&batch_id).await;
                    }
                    return Err(Status::not_found("commitment not found"));
                };

                if fetched_from_db {
                    cache.insert(commitment.clone()).await;
                }
                if lock_acquired {
                    cache.release_batch_id_lock(&batch_id).await;
                }
                commitment
            }
            Some(v2::get_commitment_request::Selector::SequenceNumber(seq)) => {
                if auth_ctx.tenant_id.is_nil() {
                    return Err(Status::invalid_argument(
                        "sequence_number lookup requires tenant-scoped auth",
                    ));
                }
                let store_id = match auth_ctx.store_ids.as_slice() {
                    [store_id] => StoreId(*store_id),
                    _ => {
                        return Err(Status::invalid_argument(
                            "sequence_number lookup requires single-store scope",
                        ))
                    }
                };
                let tenant_id = TenantId(auth_ctx.tenant_id);
                match self
                    .ves_commitment_reader
                    .get_commitment_by_sequence(&tenant_id, &store_id, seq)
                    .await
                {
                    Ok(Some(commitment)) => commitment,
                    Ok(None) => self
                        .ves_commitment_engine
                        .get_commitment_by_sequence(&tenant_id, &store_id, seq)
                        .await
                        .map_err(super::grpc_internal_error)?
                        .ok_or_else(|| Status::not_found("commitment not found"))?,
                    Err(_) => self
                        .ves_commitment_engine
                        .get_commitment_by_sequence(&tenant_id, &store_id, seq)
                        .await
                        .map_err(super::grpc_internal_error)?
                        .ok_or_else(|| Status::not_found("commitment not found"))?,
                }
            }
            None => {
                return Err(Status::invalid_argument("selector required"));
            }
        };

        Self::authorize_tenant_store(&auth_ctx, &commitment.tenant_id, &commitment.store_id)?;

        self.cache_manager
            .ves_commitments
            .insert(commitment.clone())
            .await;

        Ok(Response::new(convert::to_proto_commitment(&commitment)))
    }

    /// Get entity event history
    #[instrument(skip(self, request))]
    async fn get_entity_history(
        &self,
        request: Request<GetEntityHistoryRequest>,
    ) -> Result<Response<GetEntityHistoryResponse>, Status> {
        let auth_ctx = Self::auth_context(&request)?;
        let req = request.into_inner();

        let tenant_id = Uuid::parse_str(&req.tenant_id)
            .map_err(|e| Status::invalid_argument(format!("invalid tenant_id: {}", e)))?;
        let store_id = Uuid::parse_str(&req.store_id)
            .map_err(|e| Status::invalid_argument(format!("invalid store_id: {}", e)))?;

        let tenant_id = TenantId(tenant_id);
        let store_id = StoreId(store_id);

        if req.entity_type.is_empty() || req.entity_type.len() > 128 {
            return Err(Status::invalid_argument(
                "entity_type must be between 1 and 128 characters",
            ));
        }
        if req.entity_id.is_empty() || req.entity_id.len() > 512 {
            return Err(Status::invalid_argument(
                "entity_id must be between 1 and 512 characters",
            ));
        }

        let entity_type = EntityType::from(req.entity_type.as_str());

        Self::require_read(&auth_ctx)?;
        Self::authorize_tenant_store(&auth_ctx, &tenant_id, &store_id)?;

        let requested_from_version = if req.from_version == 0 {
            1
        } else {
            req.from_version
        };

        // Validate the requested range *before* touching the store: a from > to
        // range is malformed input and must be rejected regardless of the
        // entity's current version.
        if req.to_version != 0 && requested_from_version > req.to_version {
            return Err(Status::invalid_argument(
                "from_version must be less than or equal to to_version",
            ));
        }

        // Versions are 1-based ordinals in sequence order, so the page starts at
        // index from_version - 1. The window is the smaller of the requested
        // version span, the requested limit, and MAX_ENTITY_HISTORY, and it is
        // paged in SQL so a hot entity's full history is never materialised.
        let requested_limit = if req.limit == 0 {
            MAX_ENTITY_HISTORY as u64
        } else {
            u64::from(req.limit)
        };
        let span = if req.to_version == 0 {
            MAX_ENTITY_HISTORY as u64
        } else {
            req.to_version
                .saturating_sub(requested_from_version)
                .saturating_add(1)
        };
        let limit = span.min(requested_limit).min(MAX_ENTITY_HISTORY as u64) as u32;

        let page = self
            .ves_sequencer_reader
            .read_entity_page(
                &tenant_id,
                &store_id,
                &entity_type,
                &req.entity_id,
                requested_from_version - 1,
                limit,
            )
            .await
            .map_err(super::grpc_internal_error)?;
        let current_version = page.total;

        let proto_events: Vec<SequencedEvent> = page
            .events
            .iter()
            .map(convert::to_proto_event)
            .collect::<Result<_, _>>()?;

        Ok(Response::new(GetEntityHistoryResponse {
            events: proto_events,
            current_version,
        }))
    }

    /// Health check
    async fn get_health(&self, _request: Request<()>) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            healthy: true,
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: Some(prost_types::Timestamp {
                seconds: chrono::Utc::now().timestamp(),
                nanos: 0,
            }),
        }))
    }

    /// Stream type for StreamEvents
    type StreamEventsStream = Pin<Box<dyn Stream<Item = Result<SequencedEvent, Status>> + Send>>;

    /// Server-side streaming: continuous event delivery
    async fn stream_events(
        &self,
        request: Request<StreamEventsRequest>,
    ) -> Result<Response<Self::StreamEventsStream>, Status> {
        let auth_ctx = Self::auth_context(&request)?;
        let req = request.into_inner();

        info!(
            tenant_id = %req.tenant_id,
            store_id = %req.store_id,
            from_sequence = req.from_sequence,
            include_history = req.include_history,
            "Starting StreamEvents"
        );

        let tenant_id = Uuid::parse_str(&req.tenant_id)
            .map_err(|e| Status::invalid_argument(format!("invalid tenant_id: {}", e)))?;
        let store_id = Uuid::parse_str(&req.store_id)
            .map_err(|e| Status::invalid_argument(format!("invalid store_id: {}", e)))?;

        let tenant_id_clone = TenantId(tenant_id);
        let store_id_clone = StoreId(store_id);

        // Validate filter field lengths
        if req.entity_type_filter.len() > 100 {
            return Err(Status::invalid_argument(
                "entity_type_filter must not exceed 100 entries",
            ));
        }
        if req.event_type_filter.len() > 100 {
            return Err(Status::invalid_argument(
                "event_type_filter must not exceed 100 entries",
            ));
        }
        if req.agent_filter.len() > 100 {
            return Err(Status::invalid_argument(
                "agent_filter must not exceed 100 entries",
            ));
        }

        Self::require_read(&auth_ctx)?;
        Self::authorize_tenant_store(&auth_ctx, &tenant_id_clone, &store_id_clone)?;

        let (tx, rx) = mpsc::channel(128);
        let ves_sequencer = self.ves_sequencer.clone();
        let mut event_rx = self.event_tx.subscribe();

        let entity_type_filter = req.entity_type_filter.clone();
        let event_type_filter = req.event_type_filter.clone();
        let agent_filter = req.agent_filter.clone();
        let include_history = req.include_history;
        let mut from_sequence = req.from_sequence;

        tokio::spawn(async move {
            // First, send historical events if requested
            if include_history {
                loop {
                    let events = match ves_sequencer
                        .read_range(
                            &tenant_id_clone,
                            &store_id_clone,
                            from_sequence,
                            from_sequence.saturating_add(99),
                        )
                        .await
                        .map_err(super::grpc_sequencer_error)
                    {
                        Ok(e) => e,
                        Err(e) => {
                            let _ = tx.send(Err(e)).await;
                            return;
                        }
                    };

                    if events.is_empty() {
                        break;
                    }

                    let next_sequence = events
                        .last()
                        .map(|e| e.sequence_number().saturating_add(1))
                        .unwrap_or(from_sequence);

                    for event in &events {
                        if !entity_type_filter.is_empty()
                            && !entity_type_filter.contains(&event.entity_type().0)
                        {
                            continue;
                        }
                        if !event_type_filter.is_empty()
                            && !event_type_filter.contains(&event.event_type().0)
                        {
                            continue;
                        }
                        if !agent_filter.is_empty() {
                            let agent_str = event.envelope.source_agent_id.0.to_string();
                            if !agent_filter.contains(&agent_str) {
                                continue;
                            }
                        }
                        let proto_event = match convert::to_proto_event(event) {
                            Ok(proto_event) => proto_event,
                            Err(e) => {
                                let _ = tx.send(Err(e)).await;
                                return;
                            }
                        };
                        if tx.send(Ok(proto_event)).await.is_err() {
                            return;
                        }
                    }

                    from_sequence = next_sequence;
                }
            }

            // Then stream new events
            loop {
                match event_rx.recv().await {
                    Ok(event) => {
                        // Apply filters
                        if let Some(ref env) = event.envelope {
                            if env.tenant_id != tenant_id.to_string()
                                || env.store_id != store_id.to_string()
                            {
                                continue;
                            }
                            if !entity_type_filter.is_empty()
                                && !entity_type_filter.contains(&env.entity_type)
                            {
                                continue;
                            }
                            if !event_type_filter.is_empty()
                                && !event_type_filter.contains(&env.event_type)
                            {
                                continue;
                            }
                            if !agent_filter.is_empty() && !agent_filter.contains(&env.source_agent)
                            {
                                continue;
                            }
                        }

                        if tx.send(Ok(event)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("Stream lagged by {} events", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    /// Stream type for SyncStream
    type SyncStreamStream = Pin<Box<dyn Stream<Item = Result<SyncMessage, Status>> + Send>>;

    /// Bidirectional streaming: full-duplex sync
    async fn sync_stream(
        &self,
        request: Request<Streaming<SyncMessage>>,
    ) -> Result<Response<Self::SyncStreamStream>, Status> {
        let auth_ctx = Self::auth_context(&request)?;
        let mut inbound = request.into_inner();
        let (tx, rx) = mpsc::channel(128);

        let ves_sequencer = self.ves_sequencer.clone();
        let agent_cursor_store = self.ves_sequencer.agent_cursor_store().clone();
        let mut event_rx = self.event_tx.subscribe();
        let event_tx = self.event_tx.clone();
        let auth_ctx = Arc::new(auth_ctx);

        info!("Starting bidirectional SyncStream");

        tokio::spawn(async move {
            let allowed_tenant = if auth_ctx.tenant_id.is_nil() {
                None
            } else {
                Some(auth_ctx.tenant_id.to_string())
            };
            let allowed_store_ids: Option<HashSet<String>> = if auth_ctx.store_ids.is_empty() {
                None
            } else {
                Some(auth_ctx.store_ids.iter().map(|id| id.to_string()).collect())
            };

            // Handle inbound messages
            loop {
                tokio::select! {
                    msg = inbound.next() => {
                        match msg {
                            Some(Ok(sync_msg)) => {
                                match sync_msg.message {
                                    Some(v2::sync_message::Message::Push(push_req)) => {
                                        if let Err(e) = SequencerServiceV2::require_write(auth_ctx.as_ref()) {
                                            let _ = tx.send(Err(e)).await;
                                            continue;
                                        }

                                        let tenant_id = match Uuid::parse_str(&push_req.tenant_id) {
                                            Ok(id) => TenantId(id),
                                            Err(e) => {
                                                let _ = tx.send(Err(Status::invalid_argument(format!("invalid tenant_id: {}", e)))).await;
                                                continue;
                                            }
                                        };
                                        let store_id = match Uuid::parse_str(&push_req.store_id) {
                                            Ok(id) => StoreId(id),
                                            Err(e) => {
                                                let _ = tx.send(Err(Status::invalid_argument(format!("invalid store_id: {}", e)))).await;
                                                continue;
                                            }
                                        };

                                        if let Err(e) = SequencerServiceV2::authorize_tenant_store(auth_ctx.as_ref(), &tenant_id, &store_id) {
                                            let _ = tx.send(Err(e)).await;
                                            continue;
                                        }

                                        // Handle push request
                                        let agent_id = match Uuid::parse_str(&push_req.agent_id) {
                                            Ok(id) => id,
                                            Err(e) => {
                                                let _ = tx.send(Err(Status::invalid_argument(format!("invalid agent_id: {}", e)))).await;
                                                continue;
                                            }
                                        };

                                        if push_req.events.is_empty() {
                                            let _ = tx.send(Err(Status::invalid_argument("events must not be empty"))).await;
                                            continue;
                                        }
                                        if push_req.events.len() > MAX_GRPC_BATCH_SIZE {
                                            let _ = tx.send(Err(Status::invalid_argument(format!(
                                                "batch exceeds maximum size of {MAX_GRPC_BATCH_SIZE} events"
                                            )))).await;
                                            continue;
                                        }

                                        let mut events = Vec::with_capacity(push_req.events.len());
                                        let mut has_error = false;
                                        for proto_event in &push_req.events {
                                            match convert::from_proto_event(proto_event) {
                                                Ok(e) => {
                                                    if e.tenant_id.0 != tenant_id.0 || e.store_id.0 != store_id.0 {
                                                        let _ = tx.send(Err(Status::invalid_argument("event tenant_id/store_id must match push request"))).await;
                                                        has_error = true;
                                                        break;
                                                    }
                                                    if e.source_agent_id.0 != agent_id {
                                                        let _ = tx.send(Err(Status::invalid_argument("event source_agent must match push request agent_id"))).await;
                                                        has_error = true;
                                                        break;
                                                    }
                                                    events.push(e);
                                                }
                                                Err(e) => {
                                                    let _ = tx.send(Err(e)).await;
                                                    has_error = true;
                                                    break;
                                                }
                                            }
                                        }
                                        if has_error {
                                            continue;
                                        }

                                        match ves_sequencer.ingest(events).await {
                                            Ok(receipt) => {
                                                if receipt.events_accepted > 0 {
                                                    if let (Some(start), Some(end)) =
                                                        (receipt.assigned_sequence_start, receipt.assigned_sequence_end)
                                                    {
                                                        if let Err(e) = SequencerServiceV2::broadcast_range(
                                                            ves_sequencer.as_ref(),
                                                            &event_tx,
                                                            &tenant_id,
                                                            &store_id,
                                                            start,
                                                            end,
                                                        )
                                                        .await
                                                        {
                                                            warn!(error = %e, "Failed to broadcast v2 sync events");
                                                        }
                                                    }
                                                }

                                                let rejections: Vec<RejectedEvent> = receipt
                                                    .events_rejected
                                                    .iter()
                                                    .map(|r| RejectedEvent {
                                                        event_id: r.event_id.to_string(),
                                                        reason: convert::map_rejection_reason(&r.reason) as i32,
                                                        message: r.message.clone(),
                                                    })
                                                    .collect();

                                                let response = PushResponse {
                                                    batch_id: receipt.batch_id.to_string(),
                                                    request_id: push_req.request_id.clone(),
                                                    events_accepted: receipt.events_accepted,
                                                    events_rejected: rejections.len() as u32,
                                                    sequence_start: receipt.assigned_sequence_start.unwrap_or(0),
                                                    sequence_end: receipt.assigned_sequence_end.unwrap_or(0),
                                                    head_sequence: receipt.head_sequence,
                                                    rejections,
                                                    commitment: None,
                                                };
                                                let _ = tx.send(Ok(SyncMessage {
                                                    message: Some(v2::sync_message::Message::PushResponse(response)),
                                                })).await;
                                            }
                                            Err(e) => {
                                                let _ = tx.send(Err(super::grpc_internal_error(e))).await;
                                            }
                                        }
                                    }
                                    Some(v2::sync_message::Message::Pull(pull_req)) => {
                                        if let Err(e) = SequencerServiceV2::require_read(auth_ctx.as_ref()) {
                                            let _ = tx.send(Err(e)).await;
                                            continue;
                                        }

                                        // Handle pull request
                                        let tenant_id = match Uuid::parse_str(&pull_req.tenant_id) {
                                            Ok(id) => TenantId(id),
                                            Err(e) => {
                                                let _ = tx.send(Err(Status::invalid_argument(format!("invalid tenant_id: {}", e)))).await;
                                                continue;
                                            }
                                        };
                                        let store_id = match Uuid::parse_str(&pull_req.store_id) {
                                            Ok(id) => StoreId(id),
                                            Err(e) => {
                                                let _ = tx.send(Err(Status::invalid_argument(format!("invalid store_id: {}", e)))).await;
                                                continue;
                                            }
                                        };

                                        if let Err(e) = SequencerServiceV2::authorize_tenant_store(auth_ctx.as_ref(), &tenant_id, &store_id) {
                                            let _ = tx.send(Err(e)).await;
                                            continue;
                                        }

                                        let limit = if pull_req.limit == 0 { 100 } else { pull_req.limit.min(1000) } as u64;
                                        let end_sequence = pull_req
                                            .from_sequence
                                            .saturating_add(limit)
                                            .saturating_sub(1);
                                        match ves_sequencer
                                            .read_range(&tenant_id, &store_id, pull_req.from_sequence, end_sequence)
                                            .await
                                            .map_err(super::grpc_sequencer_error)
                                        {
                                            Ok(events) => {
                                                let head = match ves_sequencer.head(&tenant_id, &store_id).await {
                                                    Ok(head) => head,
                                                    Err(e) => {
                                                        let _ = tx.send(Err(super::grpc_internal_error(e))).await;
                                                        continue;
                                                    }
                                                };
                                                let filtered_events: Vec<_> = events
                                                    .into_iter()
                                                    .filter(|e| {
                                                        if !pull_req.entity_type_filter.is_empty()
                                                            && e.entity_type().0.as_str() != pull_req.entity_type_filter.as_str()
                                                        {
                                                            return false;
                                                        }
                                                        if !pull_req.entity_id_filter.is_empty()
                                                            && e.entity_id() != pull_req.entity_id_filter
                                                        {
                                                            return false;
                                                        }
                                                        if !pull_req.event_type_filter.is_empty()
                                                            && !pull_req.event_type_filter.contains(&e.event_type().0)
                                                        {
                                                            return false;
                                                        }
                                                        if !pull_req.agent_filter.is_empty() {
                                                            let agent_str = e.envelope.source_agent_id.0.to_string();
                                                            if !pull_req.agent_filter.contains(&agent_str) {
                                                                return false;
                                                            }
                                                        }
                                                        true
                                                    })
                                                    .collect();

                                                let has_more = head > end_sequence;
                                                let next_seq = if has_more {
                                                    end_sequence.saturating_add(1)
                                                } else {
                                                    head.saturating_add(1)
                                                };
                                                let proto_events: Vec<SequencedEvent> =
                                                    match filtered_events.iter().map(convert::to_proto_event).collect::<Result<_, _>>() {
                                                        Ok(events) => events,
                                                        Err(e) => {
                                                            let _ = tx.send(Err(e)).await;
                                                            continue;
                                                        }
                                                    };

                                                let response = PullEventsResponse {
                                                    events: proto_events,
                                                    next_sequence: next_seq,
                                                    has_more,
                                                    head_sequence: head,
                                                };
                                                let _ = tx.send(Ok(SyncMessage {
                                                    message: Some(v2::sync_message::Message::PullResponse(response)),
                                                })).await;
                                            }
                                            Err(e) => {
                                                let _ = tx.send(Err(e)).await;
                                            }
                                        }
                                    }
                                    Some(v2::sync_message::Message::Ack(ack)) => {
                                        if let Err(e) = SequencerServiceV2::require_read(auth_ctx.as_ref()) {
                                            let _ = tx.send(Err(e)).await;
                                            continue;
                                        }
                                        let Some(agent_id) = auth_ctx.agent_id else {
                                            let _ = tx.send(Err(Status::permission_denied(
                                                "durable acknowledgements require agent-scoped authentication",
                                            ))).await;
                                            continue;
                                        };
                                        let tenant_id = match Uuid::parse_str(&ack.tenant_id) {
                                            Ok(id) => TenantId(id),
                                            Err(e) => {
                                                let _ = tx.send(Err(Status::invalid_argument(format!("invalid ack tenant_id: {e}")))).await;
                                                continue;
                                            }
                                        };
                                        let store_id = match Uuid::parse_str(&ack.store_id) {
                                            Ok(id) => StoreId(id),
                                            Err(e) => {
                                                let _ = tx.send(Err(Status::invalid_argument(format!("invalid ack store_id: {e}")))).await;
                                                continue;
                                            }
                                        };
                                        if let Err(e) = SequencerServiceV2::authorize_tenant_store(auth_ctx.as_ref(), &tenant_id, &store_id) {
                                            let _ = tx.send(Err(e)).await;
                                            continue;
                                        }
                                        let head = match ves_sequencer.head(&tenant_id, &store_id).await {
                                            Ok(head) => head,
                                            Err(e) => {
                                                let _ = tx.send(Err(super::grpc_internal_error(e))).await;
                                                continue;
                                            }
                                        };
                                        let acknowledged_sequence = match convert::durable_ack_sequence(&ack, head) {
                                            Ok(sequence) => sequence,
                                            Err(e) => {
                                                let _ = tx.send(Err(e)).await;
                                                continue;
                                            }
                                        };
                                        let cursor = match agent_cursor_store
                                            .acknowledge(tenant_id.0, store_id.0, agent_id, acknowledged_sequence)
                                            .await
                                        {
                                            Ok(cursor) => match cursor.sequence() {
                                                Ok(sequence) => sequence,
                                                Err(e) => {
                                                    let _ = tx.send(Err(super::grpc_internal_error(e))).await;
                                                    continue;
                                                }
                                            },
                                            Err(e) => {
                                                let _ = tx.send(Err(super::grpc_internal_error(e))).await;
                                                continue;
                                            }
                                        };
                                        debug!(%agent_id, acknowledged_sequence = cursor, "Persisted agent acknowledgement");
                                        let _ = tx.send(Ok(SyncMessage {
                                            message: Some(v2::sync_message::Message::SyncState(SyncState {
                                                tenant_id: tenant_id.0.to_string(),
                                                store_id: store_id.0.to_string(),
                                                head_sequence: head,
                                                state_root: Vec::new(),
                                                latest_commitment: None,
                                                timestamp: Some(prost_types::Timestamp {
                                                    seconds: Utc::now().timestamp(),
                                                    nanos: 0,
                                                }),
                                                acknowledged_sequence: cursor,
                                                lag: head.saturating_sub(cursor),
                                            })),
                                        })).await;
                                    }
                                    Some(v2::sync_message::Message::Heartbeat(hb)) => {
                                        // Respond to heartbeat
                                        let response = v2::Heartbeat {
                                            timestamp: Some(prost_types::Timestamp {
                                                seconds: chrono::Utc::now().timestamp(),
                                                nanos: 0,
                                            }),
                                            last_seen_sequence: hb.last_seen_sequence,
                                        };
                                        let _ = tx.send(Ok(SyncMessage {
                                            message: Some(v2::sync_message::Message::ServerHeartbeat(response)),
                                        })).await;
                                    }
                                    _ => {
                                        // Server-side messages received from client are ignored
                                    }
                                }
                            }
                            Some(Err(e)) => {
                                error!("SyncStream inbound error: {}", e);
                                break;
                            }
                            None => {
                                info!("SyncStream client disconnected");
                                break;
                            }
                        }
                    }
                    event = event_rx.recv() => {
                        // Push new events to client
                        match event {
                            Ok(sequenced_event) => {
                                if let Some(ref env) = sequenced_event.envelope {
                                    if let Some(ref tenant_filter) = allowed_tenant {
                                        if &env.tenant_id != tenant_filter {
                                            continue;
                                        }
                                    }
                                    if let Some(ref store_filter) = allowed_store_ids {
                                        if !store_filter.contains(&env.store_id) {
                                            continue;
                                        }
                                    }
                                }
                                let _ = tx.send(Ok(SyncMessage {
                                    message: Some(v2::sync_message::Message::Event(sequenced_event)),
                                })).await;
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                warn!("SyncStream lagged by {} events", n);
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    /// Stream type for SubscribeEntity
    type SubscribeEntityStream = Pin<Box<dyn Stream<Item = Result<SequencedEvent, Status>> + Send>>;

    /// Subscribe to specific entity updates
    async fn subscribe_entity(
        &self,
        request: Request<SubscribeEntityRequest>,
    ) -> Result<Response<Self::SubscribeEntityStream>, Status> {
        let auth_ctx = Self::auth_context(&request)?;
        let req = request.into_inner();

        info!(
            tenant_id = %req.tenant_id,
            store_id = %req.store_id,
            entity_type = %req.entity_type,
            entity_id = %req.entity_id,
            "Starting SubscribeEntity"
        );

        let tenant_id = Uuid::parse_str(&req.tenant_id)
            .map_err(|e| Status::invalid_argument(format!("invalid tenant_id: {}", e)))?;
        let store_id = Uuid::parse_str(&req.store_id)
            .map_err(|e| Status::invalid_argument(format!("invalid store_id: {}", e)))?;

        let tenant_id_cmp = TenantId(tenant_id);
        let store_id_cmp = StoreId(store_id);

        if req.entity_type.is_empty() || req.entity_type.len() > 128 {
            return Err(Status::invalid_argument(
                "entity_type must be between 1 and 128 characters",
            ));
        }
        if req.entity_id.is_empty() || req.entity_id.len() > 512 {
            return Err(Status::invalid_argument(
                "entity_id must be between 1 and 512 characters",
            ));
        }

        let entity_type = EntityType::from(req.entity_type.as_str());

        Self::require_read(&auth_ctx)?;
        Self::authorize_tenant_store(&auth_ctx, &tenant_id_cmp, &store_id_cmp)?;

        let (tx, rx) = mpsc::channel(128);
        let ves_sequencer = self.ves_sequencer.clone();
        let mut event_rx = self.event_tx.subscribe();

        let entity_type_str = req.entity_type.clone();
        let entity_id = req.entity_id.clone();
        let include_history = req.include_history;

        tokio::spawn(async move {
            // First, replay history if requested. Streamed one page at a time
            // so the replay is bounded in memory however long the entity's
            // history is; the full history was previously loaded in one call.
            if include_history {
                let mut offset = 0u64;
                loop {
                    let page = match ves_sequencer
                        .read_entity_page(
                            &tenant_id_cmp,
                            &store_id_cmp,
                            &entity_type,
                            &entity_id,
                            offset,
                            MAX_ENTITY_HISTORY as u32,
                        )
                        .await
                    {
                        Ok(page) => page,
                        Err(e) => {
                            let _ = tx.send(Err(super::grpc_internal_error(e))).await;
                            return;
                        }
                    };
                    if page.events.is_empty() {
                        break;
                    }
                    for event in &page.events {
                        let proto_event = match convert::to_proto_event(event) {
                            Ok(proto_event) => proto_event,
                            Err(e) => {
                                let _ = tx.send(Err(e)).await;
                                return;
                            }
                        };
                        if tx.send(Ok(proto_event)).await.is_err() {
                            return;
                        }
                    }
                    offset = offset.saturating_add(page.events.len() as u64);
                    if offset >= page.total {
                        break;
                    }
                }
            }

            // Then stream new events for this entity
            loop {
                match event_rx.recv().await {
                    Ok(event) => {
                        if let Some(ref env) = event.envelope {
                            if env.tenant_id == tenant_id.to_string()
                                && env.store_id == store_id.to_string()
                                && env.entity_type == entity_type_str
                                && env.entity_id == entity_id
                                && tx.send(Ok(event)).await.is_err()
                            {
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("SubscribeEntity lagged by {} events", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}
