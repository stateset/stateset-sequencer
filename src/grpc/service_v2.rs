//! gRPC Sequencer v2 service implementation
//!
//! Implements the VES v1.0 Protocol with bidirectional streaming support.

use std::collections::HashSet;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::auth::{
    AgentKeyEntry, AgentKeyError, AgentKeyLookup, AgentKeyRegistry, AuthContext,
    KeyStatus as DomainKeyStatus, Permissions,
};
use crate::crypto::{
    base64_url_decode, base64_url_encode, compute_cipher_hash_from_encrypted,
    compute_payload_aad, compute_receipt_hash, payload_plain_hash, HpkeParams, PayloadAadParams,
    PayloadEncrypted, Recipient, NONCE_SIZE, TAG_SIZE,
};
use crate::domain::{
    AgentId, AgentKeyId, EntityType, EventType, PayloadKind, SequencedVesEvent, StoreId, TenantId,
    VesBatchCommitment, VesEventEnvelope, VES_VERSION, ZERO_HASH,
};
use crate::infra::{
    postgres::VesRejectionReason, CacheManager, PgAgentKeyRegistry, PgVesCommitmentEngine,
    VesSequencer,
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

    fn map_rejection_reason(reason: &VesRejectionReason) -> RejectionReason {
        match reason {
            VesRejectionReason::DuplicateEventId => RejectionReason::DuplicateEvent,
            VesRejectionReason::DuplicateCommandId => RejectionReason::DuplicateCommand,
            VesRejectionReason::InvalidPayloadHash | VesRejectionReason::InvalidCipherHash => {
                RejectionReason::InvalidHash
            }
            VesRejectionReason::InvalidSignature => RejectionReason::InvalidSignature,
            VesRejectionReason::AgentKeyInvalid(message) => {
                if message.to_ascii_lowercase().contains("revoked") {
                    RejectionReason::RevokedKey
                } else {
                    RejectionReason::UnknownKey
                }
            }
            VesRejectionReason::UnsupportedVersion | VesRejectionReason::SchemaValidation(_) => {
                RejectionReason::InvalidFormat
            }
            VesRejectionReason::VersionConflict { .. } => RejectionReason::VersionConflict,
        }
    }

    fn timestamp_to_rfc3339(ts: &prost_types::Timestamp) -> Result<String, Status> {
        if ts.nanos < 0 || ts.nanos > 999_999_999 {
            return Err(Status::invalid_argument("invalid created_at nanos"));
        }
        let dt = DateTime::<Utc>::from_timestamp(ts.seconds, ts.nanos as u32)
            .ok_or_else(|| Status::invalid_argument("invalid created_at timestamp"))?;
        Ok(dt.to_rfc3339())
    }

    fn rfc3339_to_timestamp(value: &str) -> Result<prost_types::Timestamp, Status> {
        let dt = DateTime::parse_from_rfc3339(value)
            .map_err(|e| Status::internal(format!("invalid created_at: {}", e)))?;
        let dt = dt.with_timezone(&Utc);
        Ok(prost_types::Timestamp {
            seconds: dt.timestamp(),
            nanos: dt.timestamp_subsec_nanos() as i32,
        })
    }

    fn payload_kind_from_proto(value: i32) -> Result<PayloadKind, Status> {
        match v2::PayloadKind::try_from(value).unwrap_or(v2::PayloadKind::Unspecified) {
            v2::PayloadKind::Plaintext => Ok(PayloadKind::Plaintext),
            v2::PayloadKind::Encrypted => Ok(PayloadKind::Encrypted),
            v2::PayloadKind::Unspecified => Err(Status::invalid_argument("payload_kind required")),
        }
    }

    fn encrypted_from_proto(payload: &v2::EncryptedPayload) -> Result<PayloadEncrypted, Status> {
        let enc_version = if payload.enc_version == 0 {
            1
        } else {
            payload.enc_version
        };
        if enc_version != 1 {
            return Err(Status::invalid_argument("enc_version must be 1"));
        }
        if payload.nonce.len() != NONCE_SIZE {
            return Err(Status::invalid_argument("nonce must be 12 bytes"));
        }
        if payload.tag.len() != TAG_SIZE {
            return Err(Status::invalid_argument("tag must be 16 bytes"));
        }

        let hpke = payload
            .hpke
            .as_ref()
            .map(|params| HpkeParams {
                mode: params.mode.clone(),
                kem: params.kem.clone(),
                kdf: params.kdf.clone(),
                aead: params.aead.clone(),
            })
            .unwrap_or_default();

        let recipients = payload
            .recipients
            .iter()
            .map(|recipient| Recipient {
                recipient_kid: recipient.recipient_kid,
                enc_b64u: base64_url_encode(&recipient.ephemeral_public_key),
                ct_b64u: base64_url_encode(&recipient.wrapped_dek),
            })
            .collect();

        Ok(PayloadEncrypted {
            enc_version,
            aead: payload.aead.clone(),
            nonce_b64u: base64_url_encode(&payload.nonce),
            ciphertext_b64u: base64_url_encode(&payload.ciphertext),
            tag_b64u: base64_url_encode(&payload.tag),
            hpke,
            recipients,
        })
    }

    fn encrypted_to_proto(payload: &PayloadEncrypted) -> Result<v2::EncryptedPayload, Status> {
        let nonce = base64_url_decode(&payload.nonce_b64u)
            .map_err(|_| Status::internal("invalid encrypted nonce"))?;
        if nonce.len() != NONCE_SIZE {
            return Err(Status::internal("invalid encrypted nonce length"));
        }
        let tag = base64_url_decode(&payload.tag_b64u)
            .map_err(|_| Status::internal("invalid encrypted tag"))?;
        if tag.len() != TAG_SIZE {
            return Err(Status::internal("invalid encrypted tag length"));
        }
        let ciphertext = base64_url_decode(&payload.ciphertext_b64u)
            .map_err(|_| Status::internal("invalid encrypted ciphertext"))?;

        let mut recipients = Vec::with_capacity(payload.recipients.len());
        for recipient in &payload.recipients {
            let enc = base64_url_decode(&recipient.enc_b64u)
                .map_err(|_| Status::internal("invalid recipient enc"))?;
            let wrapped = base64_url_decode(&recipient.ct_b64u)
                .map_err(|_| Status::internal("invalid recipient wrapped_dek"))?;
            recipients.push(v2::RecipientKey {
                recipient_kid: recipient.recipient_kid,
                ephemeral_public_key: enc,
                wrapped_dek: wrapped,
            });
        }

        Ok(v2::EncryptedPayload {
            enc_version: payload.enc_version,
            aead: payload.aead.clone(),
            nonce,
            ciphertext,
            tag,
            hpke: Some(v2::HpkeParams {
                mode: payload.hpke.mode.clone(),
                kem: payload.hpke.kem.clone(),
                kdf: payload.hpke.kdf.clone(),
                aead: payload.hpke.aead.clone(),
            }),
            recipients,
        })
    }

    /// Convert domain event to v2 proto event
    fn to_proto_event(event: &SequencedVesEvent) -> Result<SequencedEvent, Status> {
        let envelope = &event.envelope;
        let payload_kind = match envelope.payload_kind {
            PayloadKind::Plaintext => v2::PayloadKind::Plaintext as i32,
            PayloadKind::Encrypted => v2::PayloadKind::Encrypted as i32,
        };

        let (payload, payload_encrypted) = match envelope.payload_kind {
            PayloadKind::Plaintext => {
                let payload = envelope
                    .payload
                    .as_ref()
                    .ok_or_else(|| Status::internal("missing plaintext payload"))?;
                (
                    serde_json::to_vec(payload)
                        .map_err(|e| Status::internal(format!("payload encode error: {}", e)))?,
                    None,
                )
            }
            PayloadKind::Encrypted => {
                let encrypted = envelope
                    .payload_encrypted
                    .as_ref()
                    .ok_or_else(|| Status::internal("missing encrypted payload"))?;
                (Vec::new(), Some(Self::encrypted_to_proto(encrypted)?))
            }
        };

        let created_at = Self::rfc3339_to_timestamp(&envelope.created_at)?;
        let sequenced_at = envelope.sequenced_at.unwrap_or_else(Utc::now);
        let receipt_hash = compute_receipt_hash(
            &envelope.tenant_id.0,
            &envelope.store_id.0,
            &envelope.event_id,
            event.sequence_number(),
            &event.compute_signing_hash(),
        );

        Ok(SequencedEvent {
            envelope: Some(EventEnvelope {
                event_id: envelope.event_id.to_string(),
                command_id: envelope
                    .command_id
                    .map(|id| id.to_string())
                    .unwrap_or_default(),
                tenant_id: envelope.tenant_id.0.to_string(),
                store_id: envelope.store_id.0.to_string(),
                entity_type: envelope.entity_type.0.clone(),
                entity_id: envelope.entity_id.clone(),
                event_type: envelope.event_type.0.clone(),
                source_agent: envelope.source_agent_id.0.to_string(),
                ves_version: envelope.ves_version,
                payload_kind,
                payload,
                payload_encrypted,
                payload_plain_hash: envelope.payload_plain_hash.to_vec(),
                payload_cipher_hash: envelope.payload_cipher_hash.to_vec(),
                agent_key_id: envelope.agent_key_id.as_u32(),
                agent_signature: envelope.agent_signature.to_vec(),
                base_version: envelope.base_version.unwrap_or(0),
                created_at: Some(created_at),
            }),
            sequence_number: event.sequence_number(),
            sequenced_at: Some(prost_types::Timestamp {
                seconds: sequenced_at.timestamp(),
                nanos: sequenced_at.timestamp_subsec_nanos() as i32,
            }),
            receipt_hash: receipt_hash.to_vec(),
        })
    }

    /// Convert v2 proto event to VES event envelope
    #[allow(clippy::result_large_err)]
    fn from_proto_event(proto: &EventEnvelope) -> Result<VesEventEnvelope, Status> {
        let ves_version = if proto.ves_version == 0 {
            VES_VERSION
        } else {
            proto.ves_version
        };
        if ves_version != VES_VERSION {
            return Err(Status::invalid_argument("unsupported ves_version"));
        }

        let event_id = Uuid::parse_str(&proto.event_id)
            .map_err(|e| Status::invalid_argument(format!("invalid event_id: {}", e)))?;
        let tenant_id = Uuid::parse_str(&proto.tenant_id)
            .map_err(|e| Status::invalid_argument(format!("invalid tenant_id: {}", e)))?;
        let store_id = Uuid::parse_str(&proto.store_id)
            .map_err(|e| Status::invalid_argument(format!("invalid store_id: {}", e)))?;
        let source_agent = Uuid::parse_str(&proto.source_agent)
            .map_err(|e| Status::invalid_argument(format!("invalid source_agent: {}", e)))?;

        let payload_kind = Self::payload_kind_from_proto(proto.payload_kind)?;

        let created_at = match proto.created_at.as_ref() {
            Some(ts) => Self::timestamp_to_rfc3339(ts)?,
            None => return Err(Status::invalid_argument("created_at required")),
        };

        let command_id = if proto.command_id.is_empty() {
            None
        } else {
            Some(
                Uuid::parse_str(&proto.command_id)
                    .map_err(|e| Status::invalid_argument(format!("invalid command_id: {}", e)))?,
            )
        };

        let payload = match payload_kind {
            PayloadKind::Plaintext => {
                let payload: serde_json::Value = serde_json::from_slice(&proto.payload)
                    .map_err(|e| Status::invalid_argument(format!("invalid payload JSON: {}", e)))?;
                Some(payload)
            }
            PayloadKind::Encrypted => None,
        };

        if payload_kind == PayloadKind::Plaintext && proto.payload_encrypted.is_some() {
            return Err(Status::invalid_argument(
                "payload_encrypted must be omitted for plaintext events",
            ));
        }
        if payload_kind == PayloadKind::Encrypted && !proto.payload.is_empty() {
            return Err(Status::invalid_argument(
                "payload must be omitted for encrypted events",
            ));
        }

        let payload_encrypted = match payload_kind {
            PayloadKind::Encrypted => {
                let encrypted = proto.payload_encrypted.as_ref().ok_or_else(|| {
                    Status::invalid_argument("payload_encrypted required for encrypted events")
                })?;
                Some(Self::encrypted_from_proto(encrypted)?)
            }
            PayloadKind::Plaintext => None,
        };

        let payload_plain_hash: [u8; 32] = match proto.payload_plain_hash.len() {
            0 => {
                if let Some(ref payload) = payload {
                    payload_plain_hash(payload)
                } else {
                    return Err(Status::invalid_argument(
                        "payload_plain_hash required for encrypted events",
                    ));
                }
            }
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

        let payload_aad = payload_encrypted.as_ref().map(|_| {
            compute_payload_aad(&PayloadAadParams {
                tenant_id: &tenant_id,
                store_id: &store_id,
                event_id: &event_id,
                source_agent_id: &source_agent,
                agent_key_id: proto.agent_key_id,
                entity_type: proto.entity_type.as_str(),
                entity_id: &proto.entity_id,
                event_type: proto.event_type.as_str(),
                created_at: &created_at,
                payload_plain_hash: &payload_plain_hash,
            })
        });

        let payload_cipher_hash: [u8; 32] = match proto.payload_cipher_hash.len() {
            0 => {
                if let Some(ref encrypted) = payload_encrypted {
                    let payload_aad = payload_aad
                        .as_ref()
                        .ok_or_else(|| Status::invalid_argument("invalid payload_encrypted"))?;
                    compute_cipher_hash_from_encrypted(encrypted, payload_aad)
                        .map_err(|_| Status::invalid_argument("invalid payload_encrypted"))?
                } else {
                    ZERO_HASH
                }
            }
            32 => proto
                .payload_cipher_hash
                .as_slice()
                .try_into()
                .map_err(|_| Status::invalid_argument("payload_cipher_hash must be 32 bytes"))?,
            _ => {
                return Err(Status::invalid_argument(
                    "payload_cipher_hash must be 32 bytes",
                ))
            }
        };

        let agent_signature: [u8; 64] = proto
            .agent_signature
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("agent_signature must be 64 bytes"))?;

        Ok(VesEventEnvelope {
            ves_version,
            event_id,
            tenant_id: TenantId(tenant_id),
            store_id: StoreId(store_id),
            source_agent_id: AgentId(source_agent),
            agent_key_id: AgentKeyId::new(proto.agent_key_id),
            entity_type: EntityType::from(proto.entity_type.as_str()),
            entity_id: proto.entity_id.clone(),
            event_type: EventType(proto.event_type.clone()),
            created_at,
            payload_kind,
            payload,
            payload_encrypted,
            payload_plain_hash,
            payload_cipher_hash,
            agent_signature,
            sequence_number: None,
            sequenced_at: None,
            command_id,
            base_version: if proto.base_version > 0 {
                Some(proto.base_version)
            } else {
                None
            },
        })
    }

    /// Convert VES commitment to v2 proto commitment
    fn to_proto_commitment(commitment: &VesBatchCommitment) -> BatchCommitment {
        let previous_root = if commitment.prev_state_root == [0u8; 32] {
            Vec::new()
        } else {
            commitment.prev_state_root.to_vec()
        };

        BatchCommitment {
            batch_id: commitment.batch_id.to_string(),
            merkle_root: commitment.merkle_root.to_vec(),
            start_sequence: commitment.sequence_range.0,
            end_sequence: commitment.sequence_range.1,
            event_count: commitment.leaf_count,
            committed_at: Some(prost_types::Timestamp {
                seconds: commitment.committed_at.timestamp(),
                nanos: commitment.committed_at.timestamp_subsec_nanos() as i32,
            }),
            previous_root,
        }
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
            .map_err(|e| Status::internal(e.to_string()))?;

        for event in events {
            let proto_event = Self::to_proto_event(&event)?;
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

        if req.events.is_empty() {
            return Err(Status::invalid_argument("events must not be empty"));
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
            let event = Self::from_proto_event(proto_event)?;
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
                        reason: Self::map_rejection_reason(&r.reason) as i32,
                        message: r.message.clone(),
                    })
                    .collect();

                if receipt.events_accepted > 0 {
                    if let (Some(start), Some(end)) =
                        (receipt.assigned_sequence_start, receipt.assigned_sequence_end)
                    {
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
            .ves_sequencer
            .head(&tenant_id, &store_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Read events (replica -> primary fallback)
        let mut events = self
            .ves_sequencer_reader
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

        if events.is_empty() {
            let expected_start = if req.from_sequence == 0 { 1 } else { req.from_sequence };
            if head >= expected_start {
                events = self
                    .ves_sequencer
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

        let end_sequence = req
            .from_sequence
            .saturating_add(limit)
            .saturating_sub(1);
        let has_more = head > end_sequence;

        // Convert to proto events
        let proto_events: Vec<SequencedEvent> = filtered_events
            .iter()
            .map(Self::to_proto_event)
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
            .ves_sequencer
            .head(&tenant_id, &store_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let cache = &self.cache_manager.ves_commitments;
        let mut lock_acquired = false;
        let mut latest_commitment = cache.get_latest(&tenant_id.0, &store_id.0).await;
        if latest_commitment.is_none() {
            let (cached, lock) = cache
                .get_latest_with_lock(&tenant_id.0, &store_id.0)
                .await;
            lock_acquired = lock;
            latest_commitment = cached;

            if latest_commitment.is_none() && !lock_acquired {
                tokio::time::sleep(Duration::from_millis(25)).await;
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
                                cache
                                    .release_latest_lock(&tenant_id.0, &store_id.0)
                                    .await;
                            }
                            return Err(Status::internal(e.to_string()));
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
                                cache
                                    .release_latest_lock(&tenant_id.0, &store_id.0)
                                    .await;
                            }
                            return Err(Status::internal(e.to_string()));
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
            cache
                .release_latest_lock(&tenant_id.0, &store_id.0)
                .await;
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
            latest_commitment: latest_commitment.as_ref().map(Self::to_proto_commitment),
            timestamp: Some(prost_types::Timestamp {
                seconds: Utc::now().timestamp(),
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
                        .map_err(|e| Status::internal(e.to_string()))?
                        .ok_or_else(|| Status::not_found("event not found"))?,
                    Err(_) => self
                        .ves_sequencer
                        .read_by_id(event_id)
                        .await
                        .map_err(|e| Status::internal(e.to_string()))?
                        .ok_or_else(|| Status::not_found("event not found"))?,
                }
            }
            Some(v2::get_inclusion_proof_request::Selector::SequenceNumber(seq)) => {
                let mut events = self
                    .ves_sequencer_reader
                    .read_range(&tenant_id, &store_id, seq, seq)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?;
                if events.is_empty() {
                    events = self
                        .ves_sequencer
                        .read_range(&tenant_id, &store_id, seq, seq)
                        .await
                        .map_err(|e| Status::internal(e.to_string()))?;
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
                .map_err(|e| Status::internal(e.to_string()))?
                .ok_or_else(|| Status::not_found("no commitment found"))?,
            Err(_) => self
                .ves_commitment_engine
                .get_commitment_by_sequence(&tenant_id, &store_id, seq)
                .await
                .map_err(|e| Status::internal(e.to_string()))?
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
            if self
                .ves_commitment_reader
                .verify_inclusion(proof.leaf_hash, &proof, commitment.merkle_root)
            {
                return Ok(Response::new(GetInclusionProofResponse {
                    included: true,
                    proof: Some(InclusionProof {
                        merkle_root: commitment.merkle_root.to_vec(),
                        leaf_index: proof.leaf_index as u64,
                        proof_hashes: proof.proof_path.iter().map(|h| h.to_vec()).collect(),
                        leaf_count: commitment.leaf_count as u64,
                        leaf_hash: proof.leaf_hash.to_vec(),
                    }),
                    event: Some(Self::to_proto_event(&event)?),
                }));
            }
        }

        let (cached, lock_acquired) = proof_cache
            .get_with_lock(&tenant_id.0, &store_id.0, seq)
            .await;
        if let Some(proof) = cached {
            if self
                .ves_commitment_reader
                .verify_inclusion(proof.leaf_hash, &proof, commitment.merkle_root)
            {
                return Ok(Response::new(GetInclusionProofResponse {
                    included: true,
                    proof: Some(InclusionProof {
                        merkle_root: commitment.merkle_root.to_vec(),
                        leaf_index: proof.leaf_index as u64,
                        proof_hashes: proof.proof_path.iter().map(|h| h.to_vec()).collect(),
                        leaf_count: commitment.leaf_count as u64,
                        leaf_hash: proof.leaf_hash.to_vec(),
                    }),
                    event: Some(Self::to_proto_event(&event)?),
                }));
            }
        }

        if !lock_acquired {
            tokio::time::sleep(Duration::from_millis(25)).await;
            if let Some(proof) = proof_cache.get(&tenant_id.0, &store_id.0, seq).await {
                if self
                    .ves_commitment_reader
                    .verify_inclusion(proof.leaf_hash, &proof, commitment.merkle_root)
                {
                    return Ok(Response::new(GetInclusionProofResponse {
                        included: true,
                        proof: Some(InclusionProof {
                            merkle_root: commitment.merkle_root.to_vec(),
                            leaf_index: proof.leaf_index as u64,
                            proof_hashes: proof.proof_path.iter().map(|h| h.to_vec()).collect(),
                            leaf_count: commitment.leaf_count as u64,
                            leaf_hash: proof.leaf_hash.to_vec(),
                        }),
                        event: Some(Self::to_proto_event(&event)?),
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
                return Err(Status::internal(e.to_string()));
            }
        };

        if leaves.is_empty() {
            if lock_acquired {
                proof_cache
                    .release_lock(&tenant_id.0, &store_id.0, seq)
                    .await;
            }
            return Err(Status::internal("commitment range contains no events"));
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
                    return Err(Status::internal(e.to_string()));
                }
            };
            let computed_root_primary = self.ves_commitment_engine.compute_merkle_root(&leaves);
            if computed_root_primary != commitment.merkle_root {
                if lock_acquired {
                    proof_cache
                        .release_lock(&tenant_id.0, &store_id.0, seq)
                        .await;
                }
                return Err(Status::internal(
                    "commitment merkle_root does not match ves_events",
                ));
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
                return Err(Status::internal(e.to_string()));
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
            event: Some(Self::to_proto_event(&event)?),
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
                let cache = &self.cache_manager.ves_commitments;
                let mut lock_acquired = false;
                let mut fetched_from_db = false;
                let mut commitment = cache.get_by_batch_id(&batch_id).await;

                if commitment.is_none() {
                    let (cached, lock) = cache.get_by_batch_id_with_lock(&batch_id).await;
                    lock_acquired = lock;
                    commitment = cached;

                    if commitment.is_none() && !lock_acquired {
                        tokio::time::sleep(Duration::from_millis(25)).await;
                        commitment = cache.get_by_batch_id(&batch_id).await;
                    }

                    if commitment.is_none() {
                        let fetched = match self.ves_commitment_reader.get_commitment(batch_id).await
                        {
                            Ok(Some(commitment)) => Some(commitment),
                            Ok(None) => match self
                                .ves_commitment_engine
                                .get_commitment(batch_id)
                                .await
                            {
                                Ok(commitment) => commitment,
                                Err(e) => {
                                    if lock_acquired {
                                        cache.release_batch_id_lock(&batch_id).await;
                                    }
                                    return Err(Status::internal(e.to_string()));
                                }
                            },
                            Err(_) => match self
                                .ves_commitment_engine
                                .get_commitment(batch_id)
                                .await
                            {
                                Ok(commitment) => commitment,
                                Err(e) => {
                                    if lock_acquired {
                                        cache.release_batch_id_lock(&batch_id).await;
                                    }
                                    return Err(Status::internal(e.to_string()));
                                }
                            },
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
                        .map_err(|e| Status::internal(e.to_string()))?
                        .ok_or_else(|| Status::not_found("commitment not found"))?,
                    Err(_) => self
                        .ves_commitment_engine
                        .get_commitment_by_sequence(&tenant_id, &store_id, seq)
                        .await
                        .map_err(|e| Status::internal(e.to_string()))?
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
            .ves_sequencer_reader
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

        let proto_events: Vec<SequencedEvent> = filtered_events
            .iter()
            .map(Self::to_proto_event)
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
                            let agent_str = event.envelope.source_agent_id.0.to_string();
                            if !agent_filter.contains(&agent_str) {
                                continue;
                            }
                        }
                        let proto_event = match SequencerServiceV2::to_proto_event(event) {
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
        let auth_ctx = Self::auth_context(&request);
        let mut inbound = request.into_inner();
        let (tx, rx) = mpsc::channel(128);

        let ves_sequencer = self.ves_sequencer.clone();
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

                                        if push_req.events.is_empty() {
                                            let _ = tx.send(Err(Status::invalid_argument("events must not be empty"))).await;
                                            continue;
                                        }

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
                                                        reason: SequencerServiceV2::map_rejection_reason(&r.reason) as i32,
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
                                        match ves_sequencer.read_range(&tenant_id, &store_id, pull_req.from_sequence, end_sequence).await {
                                            Ok(events) => {
                                                let head = match ves_sequencer.head(&tenant_id, &store_id).await {
                                                    Ok(head) => head,
                                                    Err(e) => {
                                                        let _ = tx.send(Err(Status::internal(e.to_string()))).await;
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
                                                    match filtered_events.iter().map(SequencerServiceV2::to_proto_event).collect::<Result<_, _>>() {
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
        let ves_sequencer = self.ves_sequencer.clone();
        let mut event_rx = self.event_tx.subscribe();

        let entity_type_str = req.entity_type.clone();
        let entity_id = req.entity_id.clone();
        let include_history = req.include_history;

        tokio::spawn(async move {
            // First, send historical events if requested
            if include_history {
                match ves_sequencer
                    .read_entity(&tenant_id_cmp, &store_id_cmp, &entity_type, &entity_id)
                    .await
                {
                    Ok(events) => {
                        for event in &events {
                            let proto_event = match SequencerServiceV2::to_proto_event(event) {
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
    registry: Arc<PgAgentKeyRegistry>,
}

impl KeyManagementServiceV2 {
    pub fn new(registry: Arc<PgAgentKeyRegistry>) -> Self {
        Self { registry }
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

    fn require_admin(ctx: &AuthContext) -> Result<(), Status> {
        if ctx.is_admin() {
            Ok(())
        } else {
            Err(Status::permission_denied("admin permission required"))
        }
    }

    fn authorize_tenant(ctx: &AuthContext, tenant_id: &TenantId) -> Result<(), Status> {
        if !ctx.tenant_id.is_nil() && ctx.tenant_id != tenant_id.0 {
            return Err(Status::permission_denied("tenant access denied"));
        }
        Ok(())
    }

    fn timestamp_to_datetime(
        ts: &prost_types::Timestamp,
        field: &str,
    ) -> Result<DateTime<Utc>, Status> {
        if ts.nanos < 0 || ts.nanos > 999_999_999 {
            return Err(Status::invalid_argument(format!(
                "invalid {} nanos",
                field
            )));
        }
        DateTime::<Utc>::from_timestamp(ts.seconds, ts.nanos as u32).ok_or_else(|| {
            Status::invalid_argument(format!("invalid {} timestamp", field))
        })
    }

    fn datetime_to_timestamp(dt: &DateTime<Utc>) -> prost_types::Timestamp {
        prost_types::Timestamp {
            seconds: dt.timestamp(),
            nanos: dt.timestamp_subsec_nanos() as i32,
        }
    }
}

#[tonic::async_trait]
impl KeyManagementTrait for KeyManagementServiceV2 {
    async fn register_agent_key(
        &self,
        request: Request<RegisterKeyRequest>,
    ) -> Result<Response<RegisterKeyResponse>, Status> {
        let auth_ctx = Self::auth_context(&request);
        let req = request.into_inner();

        info!(
            tenant_id = %req.tenant_id,
            agent_id = %req.agent_id,
            key_id = req.key_id,
            key_type = ?KeyType::try_from(req.key_type).unwrap_or(KeyType::Unspecified),
            "Registering agent key"
        );

        Self::require_admin(&auth_ctx)?;

        let tenant_id = Uuid::parse_str(&req.tenant_id)
            .map_err(|e| Status::invalid_argument(format!("invalid tenant_id: {}", e)))?;
        let agent_id = Uuid::parse_str(&req.agent_id)
            .map_err(|e| Status::invalid_argument(format!("invalid agent_id: {}", e)))?;

        let tenant_id = TenantId(tenant_id);
        Self::authorize_tenant(&auth_ctx, &tenant_id)?;

        let key_type = KeyType::try_from(req.key_type).unwrap_or(KeyType::Unspecified);
        if key_type != KeyType::Signing {
            return Err(Status::unimplemented(
                "only signing keys are supported",
            ));
        }

        if req.public_key.len() != 32 {
            return Err(Status::invalid_argument("public_key must be 32 bytes"));
        }
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&req.public_key);

        let valid_from = match req.valid_from.as_ref() {
            Some(ts) => Some(Self::timestamp_to_datetime(ts, "valid_from")?),
            None => None,
        };
        let valid_to = match req.valid_to.as_ref() {
            Some(ts) => Some(Self::timestamp_to_datetime(ts, "valid_to")?),
            None => None,
        };
        if let (Some(from), Some(to)) = (valid_from.as_ref(), valid_to.as_ref()) {
            if from > to {
                return Err(Status::invalid_argument(
                    "valid_from must be less than or equal to valid_to",
                ));
            }
        }

        let mut entry = AgentKeyEntry::new(public_key);
        entry.valid_from = valid_from;
        entry.valid_to = valid_to;

        let lookup = AgentKeyLookup {
            tenant_id: tenant_id.0,
            agent_id,
            key_id: req.key_id,
        };

        self.registry
            .register_key(&lookup, entry)
            .await
            .map_err(|e| match e {
                AgentKeyError::KeyAlreadyExists => {
                    Status::already_exists("key already exists")
                }
                _ => Status::internal(e.to_string()),
            })?;

        Ok(Response::new(RegisterKeyResponse {
            success: true,
            message: "Key registered successfully".to_string(),
            registered_at: Some(prost_types::Timestamp {
                seconds: Utc::now().timestamp(),
                nanos: 0,
            }),
        }))
    }

    async fn get_agent_keys(
        &self,
        request: Request<GetAgentKeysRequest>,
    ) -> Result<Response<GetAgentKeysResponse>, Status> {
        let auth_ctx = Self::auth_context(&request);
        let req = request.into_inner();

        info!(
            tenant_id = %req.tenant_id,
            agent_id = %req.agent_id,
            "Getting agent keys"
        );

        Self::require_admin(&auth_ctx)?;

        let tenant_id = Uuid::parse_str(&req.tenant_id)
            .map_err(|e| Status::invalid_argument(format!("invalid tenant_id: {}", e)))?;
        let agent_id = Uuid::parse_str(&req.agent_id)
            .map_err(|e| Status::invalid_argument(format!("invalid agent_id: {}", e)))?;
        let tenant_id = TenantId(tenant_id);
        Self::authorize_tenant(&auth_ctx, &tenant_id)?;

        let key_type_filter = KeyType::try_from(req.key_type_filter).unwrap_or(KeyType::Unspecified);
        if key_type_filter == KeyType::Encryption {
            return Ok(Response::new(GetAgentKeysResponse { keys: vec![] }));
        }

        let now = Utc::now();
        let entries = self
            .registry
            .list_agent_keys(&tenant_id.0, &agent_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let mut keys = Vec::with_capacity(entries.len());
        for (key_id, entry) in entries {
            let status = entry.status_at(now);
            if !req.include_revoked && status == DomainKeyStatus::Revoked {
                continue;
            }
            let proto_status = match status {
                DomainKeyStatus::Active => v2::KeyStatus::Active,
                DomainKeyStatus::Expired => v2::KeyStatus::Expired,
                DomainKeyStatus::Revoked => v2::KeyStatus::Revoked,
                DomainKeyStatus::NotYetValid => v2::KeyStatus::Unspecified,
            };

            keys.push(v2::AgentKey {
                key_id,
                key_type: KeyType::Signing as i32,
                public_key: entry.public_key.to_vec(),
                status: proto_status as i32,
                created_at: Some(Self::datetime_to_timestamp(&entry.created_at)),
                valid_from: entry.valid_from.as_ref().map(Self::datetime_to_timestamp),
                valid_to: entry.valid_to.as_ref().map(Self::datetime_to_timestamp),
                revoked_at: entry.revoked_at.as_ref().map(Self::datetime_to_timestamp),
            });
        }

        Ok(Response::new(GetAgentKeysResponse { keys }))
    }

    async fn revoke_agent_key(
        &self,
        request: Request<RevokeKeyRequest>,
    ) -> Result<Response<RevokeKeyResponse>, Status> {
        let auth_ctx = Self::auth_context(&request);
        let req = request.into_inner();

        info!(
            tenant_id = %req.tenant_id,
            agent_id = %req.agent_id,
            key_id = req.key_id,
            reason = %req.reason,
            "Revoking agent key"
        );

        Self::require_admin(&auth_ctx)?;

        let tenant_id = Uuid::parse_str(&req.tenant_id)
            .map_err(|e| Status::invalid_argument(format!("invalid tenant_id: {}", e)))?;
        let agent_id = Uuid::parse_str(&req.agent_id)
            .map_err(|e| Status::invalid_argument(format!("invalid agent_id: {}", e)))?;

        let tenant_id = TenantId(tenant_id);
        Self::authorize_tenant(&auth_ctx, &tenant_id)?;

        let lookup = AgentKeyLookup {
            tenant_id: tenant_id.0,
            agent_id,
            key_id: req.key_id,
        };

        self.registry
            .revoke_key(&lookup)
            .await
            .map_err(|e| match e {
                AgentKeyError::KeyNotFound { .. } => Status::not_found("key not found"),
                _ => Status::internal(e.to_string()),
            })?;

        Ok(Response::new(RevokeKeyResponse {
            success: true,
            revoked_at: Some(prost_types::Timestamp {
                seconds: Utc::now().timestamp(),
                nanos: 0,
            }),
        }))
    }
}
