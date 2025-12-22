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
use crate::auth::AuthContextExt;
use crate::domain::{AgentId, EventBatch};
use crate::infra::IngestService;
use crate::server::AppState;

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
        ensure_write(&auth, tenant_id, store_id)?;
    }

    let batch = EventBatch::new(AgentId::from_uuid(request.agent_id), request.events);

    match state.sequencer.ingest(batch).await {
        Ok(receipt) => {
            let rejections: Vec<RejectionInfo> = receipt
                .events_rejected
                .iter()
                .map(|r| RejectionInfo {
                    event_id: r.event_id,
                    reason: format!("{:?}", r.reason),
                    message: r.message.clone(),
                })
                .collect();

            Ok(Json(IngestResponse {
                batch_id: receipt.batch_id,
                events_accepted: receipt.events_accepted,
                events_rejected: receipt.events_rejected.len() as u32,
                assigned_sequence_start: receipt.assigned_sequence_start,
                assigned_sequence_end: receipt.assigned_sequence_end,
                head_sequence: receipt.head_sequence,
                rejections,
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
                    sequencer_signature: hex::encode(r.sequencer_signature),
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
