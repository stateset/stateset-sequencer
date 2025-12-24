//! gRPC Sequencer service implementation
//!
//! Implements the Sequencer gRPC service trait.

use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info};
use uuid::Uuid;

/// Convert domain event to proto event (free function for use in async blocks)
fn to_proto_event(event: &crate::domain::SequencedEvent) -> crate::proto::SequencedEvent {
    crate::proto::SequencedEvent {
        envelope: Some(crate::proto::EventEnvelope {
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
            payload: serde_json::to_vec(event.payload()).unwrap_or_default(),
            payload_hash: event.envelope.payload_hash.to_vec(),
            base_version: event.base_version().unwrap_or(0),
            created_at: Some(prost_types::Timestamp {
                seconds: event.created_at().timestamp(),
                nanos: event.created_at().timestamp_subsec_nanos() as i32,
            }),
            source_agent: event.envelope.source_agent.0.to_string(),
            signature: event.envelope.signature.clone().unwrap_or_default(),
        }),
        sequence_number: event.sequence_number(),
        sequenced_at: Some(prost_types::Timestamp {
            seconds: event.sequenced_at.timestamp(),
            nanos: event.sequenced_at.timestamp_subsec_nanos() as i32,
        }),
    }
}

use crate::crypto::legacy_commitment_leaf_hash;
use crate::domain::{AgentId, EntityType, EventBatch, EventType, StoreId, TenantId};
use crate::infra::{
    CommitmentEngine, EventStore, IngestService, PgCommitmentEngine, PgEventStore, PgSequencer,
    Sequencer,
};
use crate::proto::{
    sequencer_server::Sequencer as SequencerTrait, BatchCommitment, EventEnvelope,
    GetCommitmentRequest, GetCommitmentResponse, GetEntityHistoryRequest, GetEntityHistoryResponse,
    GetHeadRequest, GetHeadResponse, GetInclusionProofRequest, GetInclusionProofResponse,
    InclusionProof, PullRequest, PullResponse, PushRequest, PushResponse, RejectedEvent,
    SequencedEvent,
};

/// gRPC Sequencer service implementation
pub struct SequencerService {
    sequencer: Arc<PgSequencer>,
    event_store: Arc<PgEventStore>,
    commitment_engine: Arc<PgCommitmentEngine>,
}

impl SequencerService {
    pub fn new(
        sequencer: Arc<PgSequencer>,
        event_store: Arc<PgEventStore>,
        commitment_engine: Arc<PgCommitmentEngine>,
    ) -> Self {
        Self {
            sequencer,
            event_store,
            commitment_engine,
        }
    }

    /// Convert domain event to proto event
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
                payload: serde_json::to_vec(event.payload()).unwrap_or_default(),
                payload_hash: event.envelope.payload_hash.to_vec(),
                base_version: event.base_version().unwrap_or(0),
                created_at: Some(prost_types::Timestamp {
                    seconds: event.created_at().timestamp(),
                    nanos: event.created_at().timestamp_subsec_nanos() as i32,
                }),
                source_agent: event.envelope.source_agent.0.to_string(),
                signature: event.envelope.signature.clone().unwrap_or_default(),
            }),
            sequence_number: event.sequence_number(),
            sequenced_at: Some(prost_types::Timestamp {
                seconds: event.sequenced_at.timestamp(),
                nanos: event.sequenced_at.timestamp_subsec_nanos() as i32,
            }),
        }
    }

    /// Convert proto event to domain event envelope
    ///
    /// Note: tonic::Status is an external type with fixed size.
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

        let created_at = proto
            .created_at
            .as_ref()
            .map(|ts| {
                chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32)
                    .unwrap_or_else(chrono::Utc::now)
            })
            .unwrap_or_else(chrono::Utc::now);

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

        let payload_hash: [u8; 32] = proto
            .payload_hash
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("payload_hash must be 32 bytes"))?;

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
            signature: if proto.signature.is_empty() {
                None
            } else {
                Some(proto.signature.clone())
            },
        })
    }

    /// Convert domain commitment to proto commitment
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
        }
    }
}

#[tonic::async_trait]
impl SequencerTrait for SequencerService {
    /// Push a batch of events for sequencing
    async fn push(&self, request: Request<PushRequest>) -> Result<Response<PushResponse>, Status> {
        let req = request.into_inner();

        info!(
            agent_id = %req.agent_id,
            event_count = req.events.len(),
            "Processing Push request"
        );

        // Parse agent ID
        let agent_id = Uuid::parse_str(&req.agent_id)
            .map_err(|e| Status::invalid_argument(format!("invalid agent_id: {}", e)))?;

        // Convert proto events to domain events
        let mut events = Vec::with_capacity(req.events.len());
        for proto_event in &req.events {
            events.push(Self::from_proto_event(proto_event)?);
        }

        // Create batch
        let batch = EventBatch::new(AgentId(agent_id), events);

        // Ingest
        match self.sequencer.ingest(batch).await {
            Ok(receipt) => {
                let rejected: Vec<RejectedEvent> = receipt
                    .events_rejected
                    .iter()
                    .map(|r| RejectedEvent {
                        event_id: r.event_id.to_string(),
                        reason_code: format!("{:?}", r.reason),
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

                Ok(Response::new(PushResponse {
                    batch_id: receipt.batch_id.to_string(),
                    events_accepted: receipt.events_accepted,
                    events_rejected: rejected,
                    assigned_sequence_start: receipt.assigned_sequence_start.unwrap_or(0),
                    assigned_sequence_end: receipt.assigned_sequence_end.unwrap_or(0),
                    head_sequence: receipt.head_sequence,
                    commitment,
                }))
            }
            Err(e) => {
                error!(error = %e, "Push failed");
                Err(Status::internal(e.to_string()))
            }
        }
    }

    /// Stream type for Pull
    type PullStream = Pin<Box<dyn Stream<Item = Result<PullResponse, Status>> + Send>>;

    /// Pull events starting from a cursor (streaming)
    async fn pull(
        &self,
        request: Request<PullRequest>,
    ) -> Result<Response<Self::PullStream>, Status> {
        let req = request.into_inner();

        debug!(
            tenant_id = %req.tenant_id,
            store_id = %req.store_id,
            from_sequence = req.from_sequence,
            batch_size = req.batch_size,
            "Processing Pull request"
        );

        // Parse IDs
        let tenant_id = Uuid::parse_str(&req.tenant_id)
            .map_err(|e| Status::invalid_argument(format!("invalid tenant_id: {}", e)))?;
        let store_id = Uuid::parse_str(&req.store_id)
            .map_err(|e| Status::invalid_argument(format!("invalid store_id: {}", e)))?;

        let tenant_id = TenantId(tenant_id);
        let store_id = StoreId(store_id);
        let batch_size = req.batch_size.clamp(1, 1000) as usize;
        let mut from_sequence = req.from_sequence;

        // Clone for async move
        let event_store = self.event_store.clone();
        let sequencer = self.sequencer.clone();

        // Create channel for streaming
        let (tx, rx) = mpsc::channel(16);

        // Spawn task to fetch and stream events
        tokio::spawn(async move {
            loop {
                // Get head sequence
                let head = match sequencer.head(&tenant_id, &store_id).await {
                    Ok(h) => h,
                    Err(e) => {
                        let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                        break;
                    }
                };

                // Read events
                let events = match event_store
                    .read_range(
                        &tenant_id,
                        &store_id,
                        from_sequence,
                        from_sequence + batch_size as u64,
                    )
                    .await
                {
                    Ok(e) => e,
                    Err(e) => {
                        let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                        break;
                    }
                };

                let event_count = events.len();
                let has_more =
                    event_count == batch_size && (from_sequence + event_count as u64) < head;

                // Convert to proto events
                let proto_events: Vec<SequencedEvent> = events.iter().map(to_proto_event).collect();

                // Calculate next sequence
                let next_sequence = if events.is_empty() {
                    from_sequence
                } else {
                    events
                        .last()
                        .map(|e| e.sequence_number() + 1)
                        .unwrap_or(from_sequence)
                };

                // Send response
                let response = PullResponse {
                    events: proto_events,
                    next_sequence,
                    has_more,
                    head_sequence: head,
                };

                if tx.send(Ok(response)).await.is_err() {
                    break;
                }

                // If no more events or not waiting for new, stop streaming
                if !has_more {
                    break;
                }

                from_sequence = next_sequence;
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    /// Get the current head sequence number
    async fn get_head(
        &self,
        request: Request<GetHeadRequest>,
    ) -> Result<Response<GetHeadResponse>, Status> {
        let req = request.into_inner();

        let tenant_id = Uuid::parse_str(&req.tenant_id)
            .map_err(|e| Status::invalid_argument(format!("invalid tenant_id: {}", e)))?;
        let store_id = Uuid::parse_str(&req.store_id)
            .map_err(|e| Status::invalid_argument(format!("invalid store_id: {}", e)))?;

        let tenant_id = TenantId(tenant_id);
        let store_id = StoreId(store_id);

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

        Ok(Response::new(GetHeadResponse {
            head_sequence: head,
            latest_commitment,
        }))
    }

    /// Get Merkle inclusion proof for an event
    async fn get_inclusion_proof(
        &self,
        request: Request<GetInclusionProofRequest>,
    ) -> Result<Response<GetInclusionProofResponse>, Status> {
        let req = request.into_inner();

        let batch_id = Uuid::parse_str(&req.batch_id)
            .map_err(|e| Status::invalid_argument(format!("invalid batch_id: {}", e)))?;

        let event_id = Uuid::parse_str(&req.event_id)
            .map_err(|e| Status::invalid_argument(format!("invalid event_id: {}", e)))?;

        // Get commitment
        let commitment = self
            .commitment_engine
            .get_commitment(batch_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("commitment not found"))?;

        // Get the event by ID
        let event = self
            .event_store
            .read_by_id(event_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("event not found"))?;

        // Verify event is within the batch's sequence range
        let seq = event.sequence_number();
        if seq < commitment.sequence_range.0 || seq > commitment.sequence_range.1 {
            return Err(Status::not_found("event not in specified batch"));
        }

        // Calculate leaf index within batch
        let leaf_index = (seq - commitment.sequence_range.0) as usize;

        // Build leaves (supporting legacy commitments that used payload hashes directly).
        let tenant_id = &commitment.tenant_id;
        let store_id = &commitment.store_id;
        let start = commitment.sequence_range.0;
        let end = commitment.sequence_range.1;

        let leaf_inputs = self
            .event_store
            .get_leaf_inputs(tenant_id, store_id, start, end)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        if leaf_inputs.is_empty() {
            return Err(Status::internal("commitment range contains no events"));
        }

        let expected_len = end
            .checked_sub(start)
            .and_then(|d| d.checked_add(1))
            .ok_or_else(|| Status::invalid_argument("invalid sequence range"))?;

        if leaf_inputs.len() as u64 != expected_len {
            return Err(Status::internal(format!(
                "commitment range {}..={} contains {} events but expected {}",
                start,
                end,
                leaf_inputs.len(),
                expected_len
            )));
        }

        if leaf_index >= leaf_inputs.len() {
            return Err(Status::invalid_argument("invalid leaf index"));
        }

        if leaf_inputs[leaf_index].sequence_number != seq {
            return Err(Status::internal(
                "non-contiguous sequence numbers in commitment range",
            ));
        }

        let leaves_v0: Vec<[u8; 32]> = leaf_inputs.iter().map(|i| i.payload_hash).collect();
        let leaves_v1: Vec<[u8; 32]> = leaf_inputs
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

        let root_v0 = self.commitment_engine.compute_events_root(&leaves_v0);
        let root_v1 = self.commitment_engine.compute_events_root(&leaves_v1);

        let leaves = if root_v1 == commitment.events_root {
            &leaves_v1
        } else if root_v0 == commitment.events_root {
            &leaves_v0
        } else {
            return Err(Status::internal(
                "commitment events_root does not match events table",
            ));
        };

        let proof = self
            .commitment_engine
            .prove_inclusion(leaf_index, leaves);

        let proof_hashes: Vec<Vec<u8>> = proof
            .proof_path
            .iter()
            .map(|h| h.to_vec())
            .collect();

        // Return the event, commitment info, and full proof path.
        let proof_response = GetInclusionProofResponse {
            event: Some(Self::to_proto_event(&event)),
            proof: Some(InclusionProof {
                merkle_root: commitment.events_root.to_vec(),
                leaf_index: leaf_index as u64,
                proof_hashes,
                leaf_count: leaves.len() as u64,
            }),
            commitment: Some(Self::to_proto_commitment(&commitment)),
        };

        Ok(Response::new(proof_response))
    }

    /// Get a batch commitment by ID
    async fn get_commitment(
        &self,
        request: Request<GetCommitmentRequest>,
    ) -> Result<Response<GetCommitmentResponse>, Status> {
        let req = request.into_inner();

        let batch_id = Uuid::parse_str(&req.batch_id)
            .map_err(|e| Status::invalid_argument(format!("invalid batch_id: {}", e)))?;

        let commitment = self
            .commitment_engine
            .get_commitment(batch_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("commitment not found"))?;

        Ok(Response::new(GetCommitmentResponse {
            commitment: Some(Self::to_proto_commitment(&commitment)),
        }))
    }

    /// Get entity event history
    async fn get_entity_history(
        &self,
        request: Request<GetEntityHistoryRequest>,
    ) -> Result<Response<GetEntityHistoryResponse>, Status> {
        let req = request.into_inner();

        let tenant_id = Uuid::parse_str(&req.tenant_id)
            .map_err(|e| Status::invalid_argument(format!("invalid tenant_id: {}", e)))?;
        let store_id = Uuid::parse_str(&req.store_id)
            .map_err(|e| Status::invalid_argument(format!("invalid store_id: {}", e)))?;

        let tenant_id = TenantId(tenant_id);
        let store_id = StoreId(store_id);
        let entity_type = EntityType::from(req.entity_type.as_str());

        let events = self
            .event_store
            .read_entity(&tenant_id, &store_id, &entity_type, &req.entity_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let current_version = events.len() as u64;
        let proto_events: Vec<SequencedEvent> = events.iter().map(Self::to_proto_event).collect();

        Ok(Response::new(GetEntityHistoryResponse {
            events: proto_events,
            current_version,
        }))
    }
}
