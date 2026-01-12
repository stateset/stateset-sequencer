//! gRPC Sequencer v2 service implementation
//!
//! Implements the VES v1.0 Protocol with bidirectional streaming support.

use std::collections::HashSet;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::auth::{AuthContext, Permissions};
use crate::crypto::legacy_commitment_leaf_hash;
use crate::domain::{AgentId, EntityType, EventBatch, EventType, StoreId, TenantId};
use crate::infra::{
    CommitmentEngine, EventStore, IngestService, PgCommitmentEngine, PgEventStore, PgSequencer,
    Sequencer,
};
use crate::proto::v2::{
    self,
    sequencer_server::Sequencer as SequencerTrait,
    key_management_server::KeyManagement as KeyManagementTrait,
    BatchCommitment, EventEnvelope, GetCommitmentRequest, GetEntityHistoryRequest,
    GetEntityHistoryResponse, GetInclusionProofRequest, GetInclusionProofResponse,
    GetSyncStateRequest, HealthResponse, InclusionProof, PullEventsRequest, PullEventsResponse,
    PushRequest, PushResponse, RejectedEvent, RejectionReason, SequencedEvent, StreamEventsRequest,
    SubscribeEntityRequest, SyncMessage, SyncState,
    // Key management types
    GetAgentKeysRequest, GetAgentKeysResponse, KeyType,
    RegisterKeyRequest, RegisterKeyResponse, RevokeKeyRequest, RevokeKeyResponse,
};

/// gRPC Sequencer v2 service implementation
pub struct SequencerServiceV2 {
    sequencer: Arc<PgSequencer>,
    event_store: Arc<PgEventStore>,
    commitment_engine: Arc<PgCommitmentEngine>,
    /// Broadcast channel for real-time event notifications
    event_tx: broadcast::Sender<SequencedEvent>,
}

impl SequencerServiceV2 {
    pub fn new(
        sequencer: Arc<PgSequencer>,
        event_store: Arc<PgEventStore>,
        commitment_engine: Arc<PgCommitmentEngine>,
    ) -> Self {
        // Create broadcast channel for event streaming (1024 event buffer)
        let (event_tx, _) = broadcast::channel(1024);
        Self {
            sequencer,
            event_store,
            commitment_engine,
            event_tx,
        }
    }

    fn auth_context<T>(request: &Request<T>) -> AuthContext {
        request
            .extensions()
            .get::<AuthContext>()
            .cloned()
            .unwrap_or(AuthContext {
                tenant_id: Uuid::nil(),
                store_ids: Vec::new(),
                agent_id: None,
                permissions: Permissions::admin(),
            })
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

    /// Convert domain event to v2 proto event
    fn to_proto_event(event: &crate::domain::SequencedEvent) -> SequencedEvent {
        SequencedEvent {
            envelope: Some(EventEnvelope {
                event_id: event.event_id().to_string(),
                command_id: event
                    .envelope
                    .command_id
                    .map(|id| id.to_string())
                    .unwrap_or_default(),
                tenant_id: event.envelope.tenant_id.0.to_string(),
                store_id: event.envelope.store_id.0.to_string(),
                entity_type: event.entity_type().0.clone(),
                entity_id: event.entity_id().to_string(),
                event_type: event.event_type().0.clone(),
                source_agent: event.envelope.source_agent.0.to_string(),
                ves_version: 1,
                payload_kind: v2::PayloadKind::Plaintext as i32,
                payload: serde_json::to_vec(event.payload()).unwrap_or_default(),
                payload_encrypted: None,
                payload_plain_hash: event.envelope.payload_hash.to_vec(),
                payload_cipher_hash: vec![0u8; 32], // Zeros for plaintext
                agent_key_id: 0, // TODO: Extract from signature
                agent_signature: event.envelope.signature.clone().unwrap_or_default(),
                base_version: event.base_version().unwrap_or(0),
                created_at: Some(prost_types::Timestamp {
                    seconds: event.created_at().timestamp(),
                    nanos: event.created_at().timestamp_subsec_nanos() as i32,
                }),
            }),
            sequence_number: event.sequence_number(),
            sequenced_at: Some(prost_types::Timestamp {
                seconds: event.sequenced_at.timestamp(),
                nanos: event.sequenced_at.timestamp_subsec_nanos() as i32,
            }),
            receipt_hash: vec![], // TODO: Compute receipt hash
        }
    }

    /// Convert v2 proto event to domain event envelope
    #[allow(clippy::result_large_err)]
    fn from_proto_event(proto: &EventEnvelope) -> Result<crate::domain::EventEnvelope, Status> {
        let event_id = Uuid::parse_str(&proto.event_id)
            .map_err(|e| Status::invalid_argument(format!("invalid event_id: {}", e)))?;

        let tenant_id = Uuid::parse_str(&proto.tenant_id)
            .map_err(|e| Status::invalid_argument(format!("invalid tenant_id: {}", e)))?;

        let store_id = Uuid::parse_str(&proto.store_id)
            .map_err(|e| Status::invalid_argument(format!("invalid store_id: {}", e)))?;

        let payload: serde_json::Value = serde_json::from_slice(&proto.payload)
            .map_err(|e| Status::invalid_argument(format!("invalid payload JSON: {}", e)))?;

        let created_at = match proto.created_at.as_ref() {
            Some(ts) => chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32)
                .ok_or_else(|| Status::invalid_argument("invalid created_at timestamp"))?,
            None => chrono::Utc::now(),
        };

        let source_agent = Uuid::parse_str(&proto.source_agent)
            .map_err(|e| Status::invalid_argument(format!("invalid source_agent: {}", e)))?;

        let command_id = if proto.command_id.is_empty() {
            None
        } else {
            Some(
                Uuid::parse_str(&proto.command_id)
                    .map_err(|e| Status::invalid_argument(format!("invalid command_id: {}", e)))?,
            )
        };

        // Use payload_plain_hash if available, otherwise compute legacy hash.
        let payload_hash: [u8; 32] = match proto.payload_plain_hash.len() {
            0 => crate::domain::EventEnvelope::compute_payload_hash(&payload),
            32 => proto
                .payload_plain_hash
                .as_slice()
                .try_into()
                .map_err(|_| Status::invalid_argument("payload_plain_hash must be 32 bytes"))?,
            _ => {
                return Err(Status::invalid_argument(
                    "payload_plain_hash must be 32 bytes",
                ))
            }
        };

        Ok(crate::domain::EventEnvelope {
            event_id,
            command_id,
            tenant_id: TenantId(tenant_id),
            store_id: StoreId(store_id),
            entity_type: EntityType::from(proto.entity_type.as_str()),
            entity_id: proto.entity_id.clone(),
            event_type: EventType(proto.event_type.clone()),
            payload,
            payload_hash,
            base_version: if proto.base_version > 0 {
                Some(proto.base_version)
            } else {
                None
            },
            created_at,
            sequence_number: None,
            source_agent: AgentId(source_agent),
            signature: if proto.agent_signature.is_empty() {
                None
            } else {
                Some(proto.agent_signature.clone())
            },
        })
    }

    /// Convert domain commitment to v2 proto commitment
    fn to_proto_commitment(commitment: &crate::domain::BatchCommitment) -> BatchCommitment {
        BatchCommitment {
            batch_id: commitment.batch_id.to_string(),
            merkle_root: commitment.events_root.to_vec(),
            start_sequence: commitment.sequence_range.0,
            end_sequence: commitment.sequence_range.1,
            event_count: commitment.event_count,
            committed_at: Some(prost_types::Timestamp {
                seconds: commitment.committed_at.timestamp(),
                nanos: commitment.committed_at.timestamp_subsec_nanos() as i32,
            }),
            previous_root: vec![], // TODO: Chain linking
        }
    }

    /// Broadcast a new event to all subscribers
    pub fn broadcast_event(&self, event: SequencedEvent) {
        if let Err(e) = self.event_tx.send(event) {
            debug!("No active event subscribers: {}", e);
        }
    }

    async fn broadcast_range(
        event_store: &PgEventStore,
        event_tx: &broadcast::Sender<SequencedEvent>,
        tenant_id: &TenantId,
        store_id: &StoreId,
        start: u64,
        end: u64,
    ) -> Result<(), Status> {
        if start == 0 || end == 0 || end < start {
            return Ok(());
        }

        let events = event_store
            .read_range(tenant_id, store_id, start, end)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        for event in events {
            let proto_event = Self::to_proto_event(&event);
            let _ = event_tx.send(proto_event);
        }

        Ok(())
    }
}

#[tonic::async_trait]
impl SequencerTrait for SequencerServiceV2 {
    /// Push a batch of events for sequencing
    async fn push(&self, request: Request<PushRequest>) -> Result<Response<PushResponse>, Status> {
        let auth_ctx = Self::auth_context(&request);
        let req = request.into_inner();

        info!(
            agent_id = %req.agent_id,
            tenant_id = %req.tenant_id,
            store_id = %req.store_id,
            event_count = req.events.len(),
            request_id = %req.request_id,
            "Processing v2 Push request"
        );

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

        // Convert proto events to domain events
        let mut events = Vec::with_capacity(req.events.len());
        for proto_event in &req.events {
            let event = Self::from_proto_event(proto_event)?;
            if event.tenant_id.0 != tenant_id.0 || event.store_id.0 != store_id.0 {
                return Err(Status::invalid_argument(
                    "event tenant_id/store_id must match push request",
                ));
            }
            events.push(event);
        }

        // Create batch
        let batch = EventBatch::new(AgentId(agent_id), events);

        // Ingest
        match self.sequencer.ingest(batch).await {
            Ok(receipt) => {
                let rejections: Vec<RejectedEvent> = receipt
                    .events_rejected
                    .iter()
                    .map(|r| RejectedEvent {
                        event_id: r.event_id.to_string(),
                        reason: match r.reason {
                            crate::domain::RejectionReason::DuplicateEventId => {
                                RejectionReason::DuplicateEvent as i32
                            }
                            crate::domain::RejectionReason::DuplicateCommandId => {
                                RejectionReason::DuplicateCommand as i32
                            }
                            crate::domain::RejectionReason::VersionConflict => {
                                RejectionReason::VersionConflict as i32
                            }
                            crate::domain::RejectionReason::SchemaValidation => {
                                RejectionReason::InvalidFormat as i32
                            }
                            _ => RejectionReason::Unspecified as i32,
                        },
                        message: r.message.clone(),
                    })
                    .collect();

                // Get commitment if available
                let commitment = if let Ok(Some(c)) = self
                    .commitment_engine
                    .get_commitment(receipt.batch_id)
                    .await
                {
                    Some(Self::to_proto_commitment(&c))
                } else {
                    None
                };

                if receipt.events_accepted > 0 {
                    if let (Some(start), Some(end)) =
                        (receipt.assigned_sequence_start, receipt.assigned_sequence_end)
                    {
                        if let Err(e) = Self::broadcast_range(
                            self.event_store.as_ref(),
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
                    commitment,
                }))
            }
            Err(e) => {
                error!(error = %e, "Push failed");
                Err(Status::internal(e.to_string()))
            }
        }
    }

    /// Pull events (unary, for simple polling)
    async fn pull_events(
        &self,
        request: Request<PullEventsRequest>,
    ) -> Result<Response<PullEventsResponse>, Status> {
        let auth_ctx = Self::auth_context(&request);
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
        let limit = if req.limit == 0 { 100 } else { req.limit.min(1000) } as u64;

        Self::require_read(&auth_ctx)?;
        Self::authorize_tenant_store(&auth_ctx, &tenant_id, &store_id)?;

        // Get head sequence
        let head = self
            .sequencer
            .head(&tenant_id, &store_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Read events
        let events = self
            .event_store
            .read_range(
                &tenant_id,
                &store_id,
                req.from_sequence,
                req.from_sequence
                    .saturating_add(limit)
                    .saturating_sub(1),
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

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
                    let agent_str = e.envelope.source_agent.0.to_string();
                    if !req.agent_filter.contains(&agent_str) {
                        return false;
                    }
                }
                true
            })
            .collect();

        let end_sequence = req
            .from_sequence
            .saturating_add(limit)
            .saturating_sub(1);
        let has_more = head > end_sequence;

        // Convert to proto events
        let proto_events: Vec<SequencedEvent> =
            filtered_events.iter().map(Self::to_proto_event).collect();

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
        let auth_ctx = Self::auth_context(&request);
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
            .sequencer
            .head(&tenant_id, &store_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let latest_commitment = self
            .commitment_engine
            .get_last_commitment(&tenant_id, &store_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .map(|c| Self::to_proto_commitment(&c));

        Ok(Response::new(SyncState {
            tenant_id: req.tenant_id,
            store_id: req.store_id,
            head_sequence: head,
            state_root: vec![], // TODO: Compute state root
            latest_commitment,
            timestamp: Some(prost_types::Timestamp {
                seconds: chrono::Utc::now().timestamp(),
                nanos: 0,
            }),
        }))
    }

    /// Get Merkle inclusion proof
    async fn get_inclusion_proof(
        &self,
        request: Request<GetInclusionProofRequest>,
    ) -> Result<Response<GetInclusionProofResponse>, Status> {
        let auth_ctx = Self::auth_context(&request);
        let req = request.into_inner();

        let tenant_id = Uuid::parse_str(&req.tenant_id)
            .map_err(|e| Status::invalid_argument(format!("invalid tenant_id: {}", e)))?;
        let store_id = Uuid::parse_str(&req.store_id)
            .map_err(|e| Status::invalid_argument(format!("invalid store_id: {}", e)))?;

        let tenant_id = TenantId(tenant_id);
        let store_id = StoreId(store_id);

        Self::require_read(&auth_ctx)?;
        Self::authorize_tenant_store(&auth_ctx, &tenant_id, &store_id)?;

        // Get event by selector
        let event = match req.selector {
            Some(v2::get_inclusion_proof_request::Selector::EventId(ref id)) => {
                let event_id = Uuid::parse_str(id)
                    .map_err(|e| Status::invalid_argument(format!("invalid event_id: {}", e)))?;
                self.event_store
                    .read_by_id(event_id)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?
                    .ok_or_else(|| Status::not_found("event not found"))?
            }
            Some(v2::get_inclusion_proof_request::Selector::SequenceNumber(seq)) => {
                let events = self
                    .event_store
                    .read_range(&tenant_id, &store_id, seq, seq)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?;
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
        let commitment = self
            .commitment_engine
            .get_commitment_by_sequence(&tenant_id, &store_id, seq)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("no commitment found"))?;

        // Verify event is within the commitment's sequence range
        if seq < commitment.sequence_range.0 || seq > commitment.sequence_range.1 {
            return Err(Status::not_found("event not found in commitment range"));
        }

        if !req.expected_root.is_empty() && commitment.events_root.to_vec() != req.expected_root {
            return Err(Status::failed_precondition("commitment root mismatch"));
        }

        // Calculate leaf index within batch
        let leaf_index = (seq - commitment.sequence_range.0) as usize;

        // Build leaves
        let start = commitment.sequence_range.0;
        let end = commitment.sequence_range.1;

        let leaf_inputs = self
            .event_store
            .get_leaf_inputs(&tenant_id, &store_id, start, end)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        if leaf_inputs.is_empty() {
            return Err(Status::internal("commitment range contains no events"));
        }

        // Compute leaves using domain-separated hashing
        let leaves: Vec<[u8; 32]> = leaf_inputs
            .iter()
            .map(|i| {
                legacy_commitment_leaf_hash(
                    &tenant_id.0,
                    &store_id.0,
                    i.sequence_number,
                    &i.payload_hash,
                    &i.entity_type,
                    &i.entity_id,
                )
            })
            .collect();

        let proof = self.commitment_engine.prove_inclusion(leaf_index, &leaves);

        Ok(Response::new(GetInclusionProofResponse {
            included: true,
            proof: Some(InclusionProof {
                merkle_root: commitment.events_root.to_vec(),
                leaf_index: leaf_index as u64,
                proof_hashes: proof.proof_path.iter().map(|h| h.to_vec()).collect(),
                leaf_count: leaves.len() as u64,
                leaf_hash: leaves[leaf_index].to_vec(),
            }),
            event: Some(Self::to_proto_event(&event)),
        }))
    }

    /// Get batch commitment
    async fn get_commitment(
        &self,
        request: Request<GetCommitmentRequest>,
    ) -> Result<Response<BatchCommitment>, Status> {
        let auth_ctx = Self::auth_context(&request);
        let req = request.into_inner();

        Self::require_read(&auth_ctx)?;

        let commitment = match req.selector {
            Some(v2::get_commitment_request::Selector::BatchId(ref id)) => {
                let batch_id = Uuid::parse_str(id)
                    .map_err(|e| Status::invalid_argument(format!("invalid batch_id: {}", e)))?;
                self.commitment_engine
                    .get_commitment(batch_id)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?
                    .ok_or_else(|| Status::not_found("commitment not found"))?
            }
            Some(v2::get_commitment_request::Selector::SequenceNumber(_seq)) => {
                // TODO: Implement lookup by sequence number
                return Err(Status::unimplemented(
                    "lookup by sequence number not yet implemented",
                ));
            }
            None => {
                return Err(Status::invalid_argument("selector required"));
            }
        };

        Ok(Response::new(Self::to_proto_commitment(&commitment)))
    }

    /// Get entity event history
    async fn get_entity_history(
        &self,
        request: Request<GetEntityHistoryRequest>,
    ) -> Result<Response<GetEntityHistoryResponse>, Status> {
        let auth_ctx = Self::auth_context(&request);
        let req = request.into_inner();

        let tenant_id = Uuid::parse_str(&req.tenant_id)
            .map_err(|e| Status::invalid_argument(format!("invalid tenant_id: {}", e)))?;
        let store_id = Uuid::parse_str(&req.store_id)
            .map_err(|e| Status::invalid_argument(format!("invalid store_id: {}", e)))?;

        let tenant_id = TenantId(tenant_id);
        let store_id = StoreId(store_id);
        let entity_type = EntityType::from(req.entity_type.as_str());

        Self::require_read(&auth_ctx)?;
        Self::authorize_tenant_store(&auth_ctx, &tenant_id, &store_id)?;

        let events = self
            .event_store
            .read_entity(&tenant_id, &store_id, &entity_type, &req.entity_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let current_version = events.len() as u64;

        // Apply version range filter
        let filtered_events: Vec<_> = events
            .into_iter()
            .enumerate()
            .filter(|(version, _)| {
                let v = (*version + 1) as u64;
                (req.from_version == 0 || v >= req.from_version)
                    && (req.to_version == 0 || v <= req.to_version)
            })
            .take(if req.limit > 0 { req.limit as usize } else { 100 })
            .map(|(_, e)| e)
            .collect();

        let proto_events: Vec<SequencedEvent> =
            filtered_events.iter().map(Self::to_proto_event).collect();

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
        let auth_ctx = Self::auth_context(&request);
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

        Self::require_read(&auth_ctx)?;
        Self::authorize_tenant_store(&auth_ctx, &tenant_id_clone, &store_id_clone)?;

        let (tx, rx) = mpsc::channel(128);
        let event_store = self.event_store.clone();
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
                    let events = match event_store
                        .read_range(
                            &tenant_id_clone,
                            &store_id_clone,
                            from_sequence,
                            from_sequence.saturating_add(99),
                        )
                        .await
                    {
                        Ok(e) => e,
                        Err(e) => {
                            let _ = tx.send(Err(Status::internal(e.to_string()))).await;
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
                            let agent_str = event.envelope.source_agent.0.to_string();
                            if !agent_filter.contains(&agent_str) {
                                continue;
                            }
                        }
                        let proto_event = SequencerServiceV2::to_proto_event(event);
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
        let auth_ctx = Self::auth_context(&request);
        let mut inbound = request.into_inner();
        let (tx, rx) = mpsc::channel(128);

        let sequencer = self.sequencer.clone();
        let event_store = self.event_store.clone();
        let _commitment_engine = self.commitment_engine.clone();
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
                Some(
                    auth_ctx
                        .store_ids
                        .iter()
                        .map(|id| id.to_string())
                        .collect(),
                )
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

                                        let mut events = Vec::with_capacity(push_req.events.len());
                                        let mut has_error = false;
                                        for proto_event in &push_req.events {
                                            match SequencerServiceV2::from_proto_event(proto_event) {
                                                Ok(e) => {
                                                    if e.tenant_id.0 != tenant_id.0 || e.store_id.0 != store_id.0 {
                                                        let _ = tx.send(Err(Status::invalid_argument("event tenant_id/store_id must match push request"))).await;
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

                                        let batch = EventBatch::new(AgentId(agent_id), events);
                                        match sequencer.ingest(batch).await {
                                            Ok(receipt) => {
                                                if receipt.events_accepted > 0 {
                                                    if let (Some(start), Some(end)) =
                                                        (receipt.assigned_sequence_start, receipt.assigned_sequence_end)
                                                    {
                                                        if let Err(e) = SequencerServiceV2::broadcast_range(
                                                            event_store.as_ref(),
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

                                                let response = PushResponse {
                                                    batch_id: receipt.batch_id.to_string(),
                                                    request_id: push_req.request_id.clone(),
                                                    events_accepted: receipt.events_accepted,
                                                    events_rejected: receipt.events_rejected.len() as u32,
                                                    sequence_start: receipt.assigned_sequence_start.unwrap_or(0),
                                                    sequence_end: receipt.assigned_sequence_end.unwrap_or(0),
                                                    head_sequence: receipt.head_sequence,
                                                    rejections: vec![],
                                                    commitment: None,
                                                };
                                                let _ = tx.send(Ok(SyncMessage {
                                                    message: Some(v2::sync_message::Message::PushResponse(response)),
                                                })).await;
                                            }
                                            Err(e) => {
                                                let _ = tx.send(Err(Status::internal(e.to_string()))).await;
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
                                        match event_store.read_range(&tenant_id, &store_id, pull_req.from_sequence, end_sequence).await {
                                            Ok(events) => {
                                                let head = sequencer.head(&tenant_id, &store_id).await.unwrap_or(0);
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
                                                            let agent_str = e.envelope.source_agent.0.to_string();
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
                                                    filtered_events.iter().map(SequencerServiceV2::to_proto_event).collect();

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
                                                let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                                            }
                                        }
                                    }
                                    Some(v2::sync_message::Message::Ack(_ack)) => {
                                        // Acknowledge received - could track for flow control
                                        debug!("Received ack from client");
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
        let auth_ctx = Self::auth_context(&request);
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
        let entity_type = EntityType::from(req.entity_type.as_str());

        Self::require_read(&auth_ctx)?;
        Self::authorize_tenant_store(&auth_ctx, &tenant_id_cmp, &store_id_cmp)?;

        let (tx, rx) = mpsc::channel(128);
        let event_store = self.event_store.clone();
        let mut event_rx = self.event_tx.subscribe();

        let entity_type_str = req.entity_type.clone();
        let entity_id = req.entity_id.clone();
        let include_history = req.include_history;

        tokio::spawn(async move {
            // First, send historical events if requested
            if include_history {
                match event_store
                    .read_entity(&tenant_id_cmp, &store_id_cmp, &entity_type, &entity_id)
                    .await
                {
                    Ok(events) => {
                        for event in &events {
                            let proto_event = SequencerServiceV2::to_proto_event(event);
                            if tx.send(Ok(proto_event)).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                        return;
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
                            {
                                if tx.send(Ok(event)).await.is_err() {
                                    break;
                                }
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

/// Key Management service implementation
pub struct KeyManagementServiceV2 {
    // TODO: Add key store backend
}

impl KeyManagementServiceV2 {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for KeyManagementServiceV2 {
    fn default() -> Self {
        Self::new()
    }
}

#[tonic::async_trait]
impl KeyManagementTrait for KeyManagementServiceV2 {
    async fn register_agent_key(
        &self,
        request: Request<RegisterKeyRequest>,
    ) -> Result<Response<RegisterKeyResponse>, Status> {
        let req = request.into_inner();

        info!(
            tenant_id = %req.tenant_id,
            agent_id = %req.agent_id,
            key_id = req.key_id,
            key_type = ?KeyType::try_from(req.key_type).unwrap_or(KeyType::Unspecified),
            "Registering agent key"
        );

        // TODO: Implement key registration with database backend
        // For now, return success

        Ok(Response::new(RegisterKeyResponse {
            success: true,
            message: "Key registered successfully".to_string(),
            registered_at: Some(prost_types::Timestamp {
                seconds: chrono::Utc::now().timestamp(),
                nanos: 0,
            }),
        }))
    }

    async fn get_agent_keys(
        &self,
        request: Request<GetAgentKeysRequest>,
    ) -> Result<Response<GetAgentKeysResponse>, Status> {
        let req = request.into_inner();

        info!(
            tenant_id = %req.tenant_id,
            agent_id = %req.agent_id,
            "Getting agent keys"
        );

        // TODO: Implement key retrieval from database
        // For now, return empty list

        Ok(Response::new(GetAgentKeysResponse { keys: vec![] }))
    }

    async fn revoke_agent_key(
        &self,
        request: Request<RevokeKeyRequest>,
    ) -> Result<Response<RevokeKeyResponse>, Status> {
        let req = request.into_inner();

        info!(
            tenant_id = %req.tenant_id,
            agent_id = %req.agent_id,
            key_id = req.key_id,
            reason = %req.reason,
            "Revoking agent key"
        );

        // TODO: Implement key revocation with database backend
        // For now, return success

        Ok(Response::new(RevokeKeyResponse {
            success: true,
            revoked_at: Some(prost_types::Timestamp {
                seconds: chrono::Utc::now().timestamp(),
                nanos: 0,
            }),
        }))
    }
}
