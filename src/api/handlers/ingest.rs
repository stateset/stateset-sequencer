//! Event ingestion handlers.

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::api::auth_helpers::ensure_write;
use crate::api::types::{
    IngestRequest, IngestResponse, RejectionInfo, VesIngestRequest, VesIngestResponse,
    VesReceiptResponse,
};
use crate::auth::{AuthContextExt, RequestLimits};
use crate::domain::{
    AgentId, EventBatch, EventEnvelope, RejectedEvent, RejectionReason, TenantId, VesEventEnvelope,
};
use crate::infra::{IngestService, SchemaStore, Sequencer};
use crate::server::AppState;

/// Validate events against registered schemas.
///
/// Returns (valid_events, rejected_events) based on schema validation results.
async fn validate_events_against_schemas(
    state: &AppState,
    events: Vec<EventEnvelope>,
) -> (Vec<EventEnvelope>, Vec<RejectedEvent>) {
    let validation_mode = state.schema_validation_mode;

    // If validation is disabled, return all events as valid
    if !validation_mode.should_validate() {
        return (events, Vec::new());
    }

    let mut valid_events = Vec::new();
    let mut rejected_events = Vec::new();

    for event in events {
        let tenant_id = TenantId::from_uuid(event.tenant_id.0);

        // Validate payload against schema
        let validation_result = match state
            .schema_store
            .validate(&tenant_id, &event.event_type, &event.payload)
            .await
        {
            Ok(result) => result,
            Err(e) => {
                // Schema store error - log and treat as no schema depending on mode
                tracing::warn!(
                    event_id = %event.event_id,
                    event_type = %event.event_type,
                    error = %e,
                    "Schema validation error"
                );

                if validation_mode.should_reject_missing_schema() {
                    rejected_events.push(RejectedEvent {
                        event_id: event.event_id,
                        reason: RejectionReason::SchemaValidation,
                        message: format!("Schema validation error: {}", e),
                    });
                    continue;
                }

                valid_events.push(event);
                continue;
            }
        };

        // Check if schema exists
        if validation_result.schema_id.is_none() {
            // No schema registered for this event type
            if validation_mode.should_reject_missing_schema() {
                rejected_events.push(RejectedEvent {
                    event_id: event.event_id,
                    reason: RejectionReason::SchemaValidation,
                    message: format!(
                        "No schema registered for event type '{}'",
                        event.event_type.as_str()
                    ),
                });
                continue;
            }

            // Log warning if in warn mode
            if matches!(validation_mode, crate::infra::SchemaValidationMode::WarnOnly) {
                tracing::warn!(
                    event_id = %event.event_id,
                    event_type = %event.event_type,
                    "No schema registered for event type"
                );
            }

            valid_events.push(event);
            continue;
        }

        // Schema exists, check validation result
        if validation_result.valid {
            valid_events.push(event);
        } else {
            // Validation failed
            let error_messages: Vec<String> = validation_result
                .errors
                .iter()
                .map(|e| format!("{}: {}", e.path, e.message))
                .collect();

            let message = format!(
                "Schema validation failed for event type '{}': {}",
                event.event_type.as_str(),
                error_messages.join("; ")
            );

            if validation_mode.should_reject_on_failure() {
                rejected_events.push(RejectedEvent {
                    event_id: event.event_id,
                    reason: RejectionReason::SchemaValidation,
                    message,
                });
            } else {
                // Warn mode - log and accept
                tracing::warn!(
                    event_id = %event.event_id,
                    event_type = %event.event_type,
                    errors = ?error_messages,
                    "Schema validation failed (warn mode)"
                );
                valid_events.push(event);
            }
        }
    }

    (valid_events, rejected_events)
}

fn enforce_batch_limit(limits: &RequestLimits, events_len: usize) -> Result<(), (StatusCode, String)> {
    if events_len > limits.max_events_per_batch {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "Batch exceeds max_events_per_batch ({} > {})",
                events_len, limits.max_events_per_batch
            ),
        ));
    }
    Ok(())
}

fn enforce_payload_limit(
    limits: &RequestLimits,
    event_id: Uuid,
    payload_len: usize,
) -> Result<(), (StatusCode, String)> {
    if payload_len > limits.max_event_payload_size {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "Event {} payload exceeds max_event_payload_size ({} > {})",
                event_id, payload_len, limits.max_event_payload_size
            ),
        ));
    }
    Ok(())
}

fn enforce_legacy_limits(
    limits: &RequestLimits,
    events: &[EventEnvelope],
) -> Result<(), (StatusCode, String)> {
    if events.is_empty() {
        return Ok(());
    }

    enforce_batch_limit(limits, events.len())?;

    for event in events {
        let payload_len = serde_json::to_vec(&event.payload)
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Event {} payload serialization failed: {}", event.event_id, e),
                )
            })?
            .len();
        enforce_payload_limit(limits, event.event_id, payload_len)?;
    }

    Ok(())
}

fn enforce_ves_limits(
    limits: &RequestLimits,
    events: &[VesEventEnvelope],
) -> Result<(), (StatusCode, String)> {
    if events.is_empty() {
        return Ok(());
    }

    enforce_batch_limit(limits, events.len())?;

    for event in events {
        let payload_bytes = if event.is_plaintext() {
            let payload = event.payload.as_ref().ok_or((
                StatusCode::BAD_REQUEST,
                format!(
                    "Event {} missing payload for plaintext payload_kind",
                    event.event_id
                ),
            ))?;
            serde_json::to_vec(payload)
        } else if event.is_encrypted() {
            let payload = event.payload_encrypted.as_ref().ok_or((
                StatusCode::BAD_REQUEST,
                format!(
                    "Event {} missing payload_encrypted for encrypted payload_kind",
                    event.event_id
                ),
            ))?;
            serde_json::to_vec(payload)
        } else {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Event {} has unsupported payload_kind", event.event_id),
            ));
        };

        let payload_bytes = payload_bytes.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Event {} payload serialization failed: {}", event.event_id, e),
            )
        })?;

        enforce_payload_limit(limits, event.event_id, payload_bytes.len())?;
    }

    Ok(())
}

/// POST /api/v1/events/ingest - Ingest events (legacy API).
pub async fn ingest_events(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(request): Json<IngestRequest>,
) -> Result<Json<IngestResponse>, (StatusCode, String)> {
    // Require tenant/store consistency and authorization.
    let (tenant_id, store_id) = request
        .events
        .first()
        .map(|e| (e.tenant_id.0, e.store_id.0))
        .unwrap_or((Uuid::nil(), Uuid::nil()));

    if !request.events.is_empty() {
        for e in &request.events {
            if e.tenant_id.0 != tenant_id || e.store_id.0 != store_id {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "All events in a batch must share the same tenant_id and store_id".to_string(),
                ));
            }
        }

        // If auth is scoped to an agent, require it matches the request agent_id.
        if let Some(agent_id) = auth.agent_id {
            if agent_id != request.agent_id {
                return Err((StatusCode::FORBIDDEN, "Agent mismatch".to_string()));
            }
        }

        ensure_write(&auth, tenant_id, store_id)?;
    }

    enforce_legacy_limits(&state.request_limits, &request.events)?;

    // Perform schema validation before sequencing
    let (valid_events, schema_rejections) =
        validate_events_against_schemas(&state, request.events).await;

    // If all events were rejected by schema validation, return early
    if valid_events.is_empty() && !schema_rejections.is_empty() {
        let head = state
            .sequencer
            .head(
                &TenantId::from_uuid(tenant_id),
                &crate::domain::StoreId::from_uuid(store_id),
            )
            .await
            .unwrap_or(0);

        let rejections: Vec<RejectionInfo> = schema_rejections
            .iter()
            .map(|r| RejectionInfo {
                event_id: r.event_id,
                reason: format!("{:?}", r.reason),
                message: r.message.clone(),
            })
            .collect();

        return Ok(Json(IngestResponse {
            batch_id: Uuid::new_v4(),
            events_accepted: 0,
            events_rejected: schema_rejections.len() as u32,
            assigned_sequence_start: None,
            assigned_sequence_end: None,
            head_sequence: head,
            rejections,
        }));
    }

    let batch = EventBatch::new(AgentId::from_uuid(request.agent_id), valid_events);

    match state.sequencer.ingest(batch).await {
        Ok(receipt) => {
            // Combine schema rejections with sequencer rejections
            let mut all_rejections: Vec<RejectionInfo> = schema_rejections
                .iter()
                .map(|r| RejectionInfo {
                    event_id: r.event_id,
                    reason: format!("{:?}", r.reason),
                    message: r.message.clone(),
                })
                .collect();

            all_rejections.extend(receipt.events_rejected.iter().map(|r| RejectionInfo {
                event_id: r.event_id,
                reason: format!("{:?}", r.reason),
                message: r.message.clone(),
            }));

            Ok(Json(IngestResponse {
                batch_id: receipt.batch_id,
                events_accepted: receipt.events_accepted,
                events_rejected: all_rejections.len() as u32,
                assigned_sequence_start: receipt.assigned_sequence_start,
                assigned_sequence_end: receipt.assigned_sequence_end,
                head_sequence: receipt.head_sequence,
                rejections: all_rejections,
            }))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, e.to_string())),
    }
}

/// POST /api/v1/ves/events/ingest - Ingest VES events with signature verification.
pub async fn ingest_ves_events(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(request): Json<VesIngestRequest>,
) -> Result<Json<VesIngestResponse>, (StatusCode, String)> {
    if !request.events.is_empty() {
        let first = &request.events[0];
        let tenant_id = first.tenant_id.0;
        let store_id = first.store_id.0;

        for e in &request.events {
            if e.tenant_id.0 != tenant_id || e.store_id.0 != store_id {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "All events in a batch must share the same tenantId and storeId".to_string(),
                ));
            }
        }

        // If auth is scoped to an agent, require it matches the request.
        if let Some(agent_id) = auth.agent_id {
            if agent_id != request.agent_id {
                return Err((StatusCode::FORBIDDEN, "Agent mismatch".to_string()));
            }
        }

        ensure_write(&auth, tenant_id, store_id)?;
    }

    enforce_ves_limits(&state.request_limits, &request.events)?;

    match state.ves_sequencer.ingest(request.events).await {
        Ok(receipt) => {
            let rejections: Vec<RejectionInfo> = receipt
                .events_rejected
                .iter()
                .map(|r| RejectionInfo {
                    event_id: r.event_id,
                    reason: r.reason.to_string(),
                    message: r.message.clone(),
                })
                .collect();

            let receipts: Vec<VesReceiptResponse> = receipt
                .receipts
                .iter()
                .map(|r| VesReceiptResponse {
                    sequencer_id: r.sequencer_id,
                    event_id: r.event_id,
                    sequence_number: r.sequence_number,
                    sequenced_at: r.sequenced_at.to_rfc3339(),
                    receipt_hash: hex::encode(r.receipt_hash),
                    signature_alg: r.signature_alg.clone(),
                    sequencer_signature: r
                        .sequencer_signature
                        .as_ref()
                        .map(hex::encode)
                        .unwrap_or_default(),
                })
                .collect();

            Ok(Json(VesIngestResponse {
                batch_id: receipt.batch_id,
                events_accepted: receipt.events_accepted,
                events_rejected: receipt.events_rejected.len() as u32,
                sequence_start: receipt.assigned_sequence_start,
                sequence_end: receipt.assigned_sequence_end,
                head_sequence: receipt.head_sequence,
                rejections,
                receipts,
            }))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, e.to_string())),
    }
}
