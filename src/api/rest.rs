//! REST API endpoints for StateSet Sequencer.

use axum::extract::Extension;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{AgentKeyRegistry, AuthContext, AuthContextExt};
use crate::crypto::{
    canonical_json_hash, compute_ves_compliance_policy_hash, legacy_commitment_leaf_hash,
};
use crate::domain::{
    AgentId, EntityType, EventBatch, EventEnvelope, Hash256, StoreId, TenantId, VesBatchCommitment,
    VesEventEnvelope,
};
use crate::infra::{CommitmentEngine, EventStore, IngestService, Sequencer};
use crate::server::AppState;

/// Build the `/api` router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/events/ingest", post(ingest_events))
        // VES v1.0 endpoint with signature verification
        .route("/v1/ves/events/ingest", post(ingest_ves_events))
        // VES commitments + proofs
        .route("/v1/ves/commitments", get(list_ves_commitments))
        .route("/v1/ves/commitments", post(create_ves_commitment))
        .route(
            "/v1/ves/commitments/anchor",
            post(commit_and_anchor_ves_commitment),
        )
        .route("/v1/ves/commitments/:batch_id", get(get_ves_commitment))
        // VES validity proofs (externally generated)
        .route(
            "/v1/ves/validity/:batch_id/inputs",
            get(get_ves_validity_public_inputs),
        )
        .route(
            "/v1/ves/validity/:batch_id/proofs",
            get(list_ves_validity_proofs),
        )
        .route(
            "/v1/ves/validity/:batch_id/proofs",
            post(submit_ves_validity_proof),
        )
        .route(
            "/v1/ves/validity/proofs/:proof_id",
            get(get_ves_validity_proof),
        )
        .route(
            "/v1/ves/validity/proofs/:proof_id/verify",
            get(verify_ves_validity_proof),
        )
        // VES compliance proofs (per-event, encrypted payloads)
        .route(
            "/v1/ves/compliance/:event_id/inputs",
            post(get_ves_compliance_public_inputs),
        )
        .route(
            "/v1/ves/compliance/:event_id/proofs",
            get(list_ves_compliance_proofs),
        )
        .route(
            "/v1/ves/compliance/:event_id/proofs",
            post(submit_ves_compliance_proof),
        )
        .route(
            "/v1/ves/compliance/proofs/:proof_id",
            get(get_ves_compliance_proof),
        )
        .route(
            "/v1/ves/compliance/proofs/:proof_id/verify",
            get(verify_ves_compliance_proof),
        )
        .route(
            "/v1/ves/proofs/:sequence_number",
            get(get_ves_inclusion_proof),
        )
        .route("/v1/ves/proofs/verify", post(verify_ves_proof))
        // VES anchoring
        .route("/v1/ves/anchor", post(anchor_ves_commitment))
        .route(
            "/v1/ves/anchor/:batch_id/verify",
            get(verify_ves_anchor_onchain),
        )
        .route("/v1/events", get(list_events))
        .route("/v1/head", get(get_head))
        .route("/v1/commitments", get(list_commitments))
        .route("/v1/commitments", post(create_commitment))
        .route("/v1/commitments/:batch_id", get(get_commitment))
        .route("/v1/proofs/:sequence_number", get(get_inclusion_proof))
        .route("/v1/proofs/verify", post(verify_proof))
        .route(
            "/v1/entities/:entity_type/:entity_id",
            get(get_entity_history),
        )
        // Anchor endpoints
        .route("/v1/anchor/status", get(get_anchor_status))
        .route("/v1/anchor", post(anchor_commitment))
        .route("/v1/anchor/:batch_id/verify", get(verify_anchor_onchain))
        // Agent key management
        .route("/v1/agents/keys", post(register_agent_key))
}

/// Minimal root-level compatibility router for Set Chain's separate anchor service.
///
/// The `set/anchor` service expects these routes without the `/api` prefix.
pub fn anchor_compat_router() -> Router<AppState> {
    Router::new()
        .route("/v1/commitments/pending", get(list_pending_ves_commitments))
        .route(
            "/v1/commitments/:batch_id/anchored",
            post(notify_ves_commitment_anchored),
        )
}

fn is_bootstrap_admin(auth: &AuthContext) -> bool {
    auth.is_admin() && auth.tenant_id.is_nil()
}

fn ensure_tenant_store(
    auth: &AuthContext,
    tenant_id: Uuid,
    store_id: Uuid,
) -> Result<(), (StatusCode, String)> {
    if is_bootstrap_admin(auth) {
        return Ok(());
    }

    if auth.tenant_id != tenant_id {
        return Err((StatusCode::FORBIDDEN, "Tenant access denied".to_string()));
    }

    if !store_id.is_nil() && !auth.can_access_store(&store_id) {
        return Err((StatusCode::FORBIDDEN, "Store access denied".to_string()));
    }

    Ok(())
}

fn ensure_read(
    auth: &AuthContext,
    tenant_id: Uuid,
    store_id: Uuid,
) -> Result<(), (StatusCode, String)> {
    if !auth.can_read() {
        return Err((
            StatusCode::FORBIDDEN,
            "Read permission required".to_string(),
        ));
    }
    ensure_tenant_store(auth, tenant_id, store_id)
}

fn ensure_write(
    auth: &AuthContext,
    tenant_id: Uuid,
    store_id: Uuid,
) -> Result<(), (StatusCode, String)> {
    if !auth.can_write() {
        return Err((
            StatusCode::FORBIDDEN,
            "Write permission required".to_string(),
        ));
    }
    ensure_tenant_store(auth, tenant_id, store_id)
}

fn ensure_admin(
    auth: &AuthContext,
    tenant_id: Uuid,
    store_id: Uuid,
) -> Result<(), (StatusCode, String)> {
    if !auth.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            "Admin permission required".to_string(),
        ));
    }
    ensure_tenant_store(auth, tenant_id, store_id)
}

#[derive(Debug, Deserialize)]
struct PendingCommitmentsQuery {
    limit: Option<u32>,
}

async fn list_pending_ves_commitments(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Query(query): Query<PendingCommitmentsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !is_bootstrap_admin(&auth) {
        return Err((
            StatusCode::FORBIDDEN,
            "Bootstrap admin permission required".to_string(),
        ));
    }

    let limit = query.limit.unwrap_or(1000).min(5000) as usize;
    let commitments = state
        .ves_commitment_engine
        .list_unanchored_global(limit)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let commitments: Vec<serde_json::Value> = commitments
        .into_iter()
        .map(|c| {
            serde_json::json!({
                "batch_id": c.batch_id,
                "tenant_id": c.tenant_id.0,
                "store_id": c.store_id.0,
                "prev_state_root": format!("0x{}", hex::encode(c.prev_state_root)),
                "new_state_root": format!("0x{}", hex::encode(c.new_state_root)),
                "events_root": format!("0x{}", hex::encode(c.merkle_root)),
                "sequence_start": c.sequence_range.0,
                "sequence_end": c.sequence_range.1,
                "event_count": c.leaf_count,
                "committed_at": c.committed_at,
                "chain_tx_hash": c.chain_tx_hash.map(|h| format!("0x{}", hex::encode(h))),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "commitments": commitments,
        "total": commitments.len(),
    })))
}

#[derive(Debug, Deserialize)]
struct AnchorNotificationRequest {
    chain_tx_hash: String,
    chain_id: u64,
    block_number: Option<u64>,
    gas_used: Option<u64>,
}

async fn notify_ves_commitment_anchored(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(batch_id): Path<Uuid>,
    Json(request): Json<AnchorNotificationRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !is_bootstrap_admin(&auth) {
        return Err((
            StatusCode::FORBIDDEN,
            "Bootstrap admin permission required".to_string(),
        ));
    }

    let commitment = state
        .ves_commitment_engine
        .get_commitment(batch_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Commitment not found".to_string()))?;

    let chain_id: u32 = request.chain_id.try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "chain_id must fit in u32".to_string(),
        )
    })?;

    let tx_hash_str = request.chain_tx_hash.trim();
    if tx_hash_str.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "chain_tx_hash must not be empty".to_string(),
        ));
    }
    let tx_hash_str = tx_hash_str.strip_prefix("0x").unwrap_or(tx_hash_str);
    let tx_hash_bytes = hex::decode(tx_hash_str).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid chain_tx_hash: {e}"),
        )
    })?;
    let tx_hash: Hash256 = tx_hash_bytes.try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "chain_tx_hash must be 32 bytes".to_string(),
        )
    })?;

    if commitment.is_anchored() {
        let existing = commitment
            .chain_tx_hash
            .expect("is_anchored implies tx hash");
        if existing == tx_hash {
            return Ok(Json(serde_json::json!({
                "batch_id": batch_id,
                "status": "already_anchored",
            })));
        }

        return Err((
            StatusCode::CONFLICT,
            "commitment already anchored with different tx hash".to_string(),
        ));
    }

    state
        .ves_commitment_engine
        .update_chain_tx(batch_id, chain_id, tx_hash, request.block_number)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let _ = request.gas_used;

    Ok(Json(serde_json::json!({
        "batch_id": batch_id,
        "status": "anchored",
        "chain_tx_hash": format!("0x{}", hex::encode(tx_hash)),
        "chain_id": chain_id,
        "block_number": request.block_number,
    })))
}

// ============================================================================
// Ingest
// ============================================================================

#[derive(Debug, Deserialize)]
struct IngestRequest {
    agent_id: Uuid,
    events: Vec<EventEnvelope>,
}

#[derive(Debug, Serialize)]
struct IngestResponse {
    batch_id: Uuid,
    events_accepted: u32,
    events_rejected: u32,
    assigned_sequence_start: Option<u64>,
    assigned_sequence_end: Option<u64>,
    head_sequence: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rejections: Vec<RejectionInfo>,
}

#[derive(Debug, Serialize)]
struct RejectionInfo {
    event_id: Uuid,
    reason: String,
    message: String,
}

async fn ingest_events(
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

// ============================================================================
// VES v1.0 ingest
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VesIngestRequest {
    agent_id: Uuid,
    events: Vec<VesEventEnvelope>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VesReceiptResponse {
    sequencer_id: Uuid,
    event_id: Uuid,
    sequence_number: u64,
    sequenced_at: String,
    receipt_hash: String,
    signature_alg: String,
    sequencer_signature: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VesIngestResponse {
    batch_id: Uuid,
    events_accepted: u32,
    events_rejected: u32,
    sequence_start: Option<u64>,
    sequence_end: Option<u64>,
    head_sequence: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rejections: Vec<RejectionInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    receipts: Vec<VesReceiptResponse>,
}

async fn ingest_ves_events(
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

// ============================================================================
// Agent keys
// ============================================================================

/// Request body for agent key registration.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterAgentKeyRequest {
    tenant_id: Uuid,
    agent_id: Uuid,
    key_id: u32,
    /// Hex-encoded Ed25519 public key.
    public_key: String,
    /// ISO timestamp.
    valid_from: Option<String>,
    /// ISO timestamp.
    valid_to: Option<String>,
}

async fn register_agent_key(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(request): Json<RegisterAgentKeyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    use crate::auth::{AgentKeyEntry, AgentKeyLookup};

    // Admin-only operation (manages signing keys).
    ensure_admin(&auth, request.tenant_id, Uuid::nil())?;

    // Parse the hex-encoded public key
    let public_key_hex = request
        .public_key
        .strip_prefix("0x")
        .unwrap_or(&request.public_key);
    let public_key_bytes = hex::decode(public_key_hex).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid public key hex: {}", e),
        )
    })?;

    if public_key_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Public key must be 32 bytes".to_string(),
        ));
    }

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&public_key_bytes);

    // Parse validity timestamps if provided
    let valid_from = if let Some(ref ts) = request.valid_from {
        Some(
            chrono::DateTime::parse_from_rfc3339(ts)
                .map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Invalid valid_from timestamp: {}", e),
                    )
                })?
                .with_timezone(&chrono::Utc),
        )
    } else {
        None
    };

    let valid_to = if let Some(ref ts) = request.valid_to {
        Some(
            chrono::DateTime::parse_from_rfc3339(ts)
                .map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Invalid valid_to timestamp: {}", e),
                    )
                })?
                .with_timezone(&chrono::Utc),
        )
    } else {
        None
    };

    // Create lookup and entry
    let lookup = AgentKeyLookup {
        tenant_id: request.tenant_id,
        agent_id: request.agent_id,
        key_id: request.key_id,
    };

    let mut entry = AgentKeyEntry::new(public_key);
    entry.valid_from = valid_from;
    entry.valid_to = valid_to;

    // Register the key
    state
        .agent_key_registry
        .register_key(&lookup, entry)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "success": true,
        "tenantId": request.tenant_id,
        "agentId": request.agent_id,
        "keyId": request.key_id,
        "message": "Agent key registered successfully"
    })))
}

// ============================================================================
// Events
// ============================================================================

#[derive(Debug, Deserialize)]
struct ListEventsQuery {
    tenant_id: Uuid,
    store_id: Uuid,
    from: Option<u64>,
    limit: Option<u32>,
}

async fn list_events(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Query(query): Query<ListEventsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tenant_id = TenantId::from_uuid(query.tenant_id);
    let store_id = StoreId::from_uuid(query.store_id);
    let from = query.from.unwrap_or(0);
    let limit = query.limit.unwrap_or(100).min(1000) as u64;

    ensure_read(&auth, tenant_id.0, store_id.0)?;

    if limit == 0 {
        return Ok(Json(serde_json::json!({
            "events": [],
            "count": 0,
        })));
    }

    let end = from.saturating_add(limit.saturating_sub(1));

    match state
        .event_store
        .read_range(&tenant_id, &store_id, from, end)
        .await
    {
        Ok(events) => Ok(Json(serde_json::json!({
            "events": events,
            "count": events.len(),
        }))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

#[derive(Debug, Deserialize)]
struct HeadQuery {
    tenant_id: Uuid,
    store_id: Uuid,
}

async fn get_head(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Query(query): Query<HeadQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tenant_id = TenantId::from_uuid(query.tenant_id);
    let store_id = StoreId::from_uuid(query.store_id);

    ensure_read(&auth, tenant_id.0, store_id.0)?;

    match state.sequencer.head(&tenant_id, &store_id).await {
        Ok(head) => Ok(Json(serde_json::json!({ "head_sequence": head }))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

// ============================================================================
// Commitments
// ============================================================================

async fn get_commitment(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(batch_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.commitment_engine.get_commitment(batch_id).await {
        Ok(Some(commitment)) => {
            ensure_read(&auth, commitment.tenant_id.0, commitment.store_id.0)?;
            Ok(Json(serde_json::json!(commitment)))
        }
        Ok(None) => Err((StatusCode::NOT_FOUND, "Commitment not found".to_string())),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

#[derive(Debug, Deserialize)]
struct CreateCommitmentRequest {
    tenant_id: Uuid,
    store_id: Uuid,
    sequence_start: u64,
    sequence_end: u64,
}

async fn create_commitment(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(request): Json<CreateCommitmentRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    ensure_write(&auth, request.tenant_id, request.store_id)?;

    let tenant_id = TenantId::from_uuid(request.tenant_id);
    let store_id = StoreId::from_uuid(request.store_id);

    // Create the commitment
    let commitment = state
        .commitment_engine
        .create_commitment(
            &tenant_id,
            &store_id,
            (request.sequence_start, request.sequence_end),
        )
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Store it
    state
        .commitment_engine
        .store_commitment(&commitment)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "batch_id": commitment.batch_id,
        "tenant_id": commitment.tenant_id.0,
        "store_id": commitment.store_id.0,
        "prev_state_root": hex::encode(commitment.prev_state_root),
        "new_state_root": hex::encode(commitment.new_state_root),
        "events_root": hex::encode(commitment.events_root),
        "event_count": commitment.event_count,
        "sequence_start": commitment.sequence_range.0,
        "sequence_end": commitment.sequence_range.1,
        "committed_at": commitment.committed_at,
    })))
}

async fn list_commitments(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Query(query): Query<HeadQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    ensure_read(&auth, query.tenant_id, query.store_id)?;

    // List all unanchored commitments for now, then filter by tenant/store.
    let commitments = state
        .commitment_engine
        .list_unanchored()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let response: Vec<serde_json::Value> = commitments
        .iter()
        .filter(|c| c.tenant_id.0 == query.tenant_id && c.store_id.0 == query.store_id)
        .map(|c| {
            serde_json::json!({
                "batch_id": c.batch_id,
                "tenant_id": c.tenant_id.0,
                "store_id": c.store_id.0,
                "events_root": hex::encode(c.events_root),
                "event_count": c.event_count,
                "sequence_start": c.sequence_range.0,
                "sequence_end": c.sequence_range.1,
                "committed_at": c.committed_at,
                "is_anchored": c.is_anchored(),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "commitments": response,
        "count": response.len(),
    })))
}

#[derive(Debug, Deserialize)]
struct ProofQuery {
    tenant_id: Uuid,
    store_id: Uuid,
    batch_id: Uuid,
}

async fn get_inclusion_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(sequence_number): Path<u64>,
    Query(query): Query<ProofQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tenant_id = TenantId::from_uuid(query.tenant_id);
    let store_id = StoreId::from_uuid(query.store_id);

    ensure_read(&auth, tenant_id.0, store_id.0)?;

    // Get the commitment
    let commitment = state
        .commitment_engine
        .get_commitment(query.batch_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Commitment not found".to_string()))?;

    if commitment.tenant_id.0 != tenant_id.0 || commitment.store_id.0 != store_id.0 {
        return Err((
            StatusCode::FORBIDDEN,
            "Commitment access denied".to_string(),
        ));
    }

    // Verify sequence is in range
    if sequence_number < commitment.sequence_range.0
        || sequence_number > commitment.sequence_range.1
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Sequence number not in commitment range".to_string(),
        ));
    }

    let start = commitment.sequence_range.0;
    let end = commitment.sequence_range.1;

    // Get leaf inputs for the commitment range.
    let leaf_inputs = state
        .event_store
        .get_leaf_inputs(&tenant_id, &store_id, start, end)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if leaf_inputs.is_empty() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Commitment range contains no events".to_string(),
        ));
    }

    let expected_len = end
        .checked_sub(start)
        .and_then(|d| d.checked_add(1))
        .ok_or((
            StatusCode::BAD_REQUEST,
            "Invalid sequence range".to_string(),
        ))?;

    if leaf_inputs.len() as u64 != expected_len {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "Commitment range {}..={} contains {} events but expected {}",
                start,
                end,
                leaf_inputs.len(),
                expected_len
            ),
        ));
    }

    // Find the leaf index
    let leaf_index = (sequence_number - start) as usize;
    if leaf_index >= leaf_inputs.len() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid sequence number".to_string(),
        ));
    }

    if leaf_inputs[leaf_index].sequence_number != sequence_number {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Non-contiguous sequence numbers in commitment range".to_string(),
        ));
    }

    // Build leaves (supporting legacy commitments that used payload hashes directly).
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

    let root_v0 = state.commitment_engine.compute_events_root(&leaves_v0);
    let root_v1 = state.commitment_engine.compute_events_root(&leaves_v1);

    let leaves = if root_v1 == commitment.events_root {
        &leaves_v1
    } else if root_v0 == commitment.events_root {
        &leaves_v0
    } else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Commitment events_root does not match events table".to_string(),
        ));
    };

    // Generate proof
    let proof = state.commitment_engine.prove_inclusion(leaf_index, leaves);

    Ok(Json(serde_json::json!({
        "sequence_number": sequence_number,
        "batch_id": commitment.batch_id,
        "events_root": hex::encode(commitment.events_root),
        "leaf_hash": hex::encode(proof.leaf_hash),
        "leaf_index": proof.leaf_index,
        "proof_path": proof.proof_path.iter().map(hex::encode).collect::<Vec<_>>(),
        "directions": proof.directions,
    })))
}

#[derive(Debug, Deserialize)]
struct VerifyProofRequest {
    leaf_hash: String,
    events_root: String,
    proof_path: Vec<String>,
    leaf_index: usize,
}

async fn verify_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(request): Json<VerifyProofRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    use crate::domain::MerkleProof;

    if !auth.can_read() && !auth.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            "Read permission required".to_string(),
        ));
    }

    // Parse hex strings
    let leaf_hash: [u8; 32] = hex::decode(&request.leaf_hash)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid leaf_hash: {}", e)))?
        .try_into()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "leaf_hash must be 32 bytes".to_string(),
            )
        })?;

    let events_root: [u8; 32] = hex::decode(&request.events_root)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid events_root: {}", e),
            )
        })?
        .try_into()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "events_root must be 32 bytes".to_string(),
            )
        })?;

    let proof_path: Vec<[u8; 32]> = request
        .proof_path
        .iter()
        .map(|h| {
            hex::decode(h)
                .map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Invalid proof hash: {}", e),
                    )
                })
                .and_then(|bytes| {
                    bytes.try_into().map_err(|_| {
                        (
                            StatusCode::BAD_REQUEST,
                            "Each proof hash must be 32 bytes".to_string(),
                        )
                    })
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let proof = MerkleProof::new(leaf_hash, proof_path, request.leaf_index);

    let valid = state
        .commitment_engine
        .verify_inclusion(leaf_hash, &proof, events_root);

    Ok(Json(serde_json::json!({
        "valid": valid,
        "leaf_hash": request.leaf_hash,
        "events_root": request.events_root,
    })))
}

// ============================================================================
// VES commitments + proofs
// ============================================================================

fn ves_validity_public_inputs(commitment: &VesBatchCommitment) -> serde_json::Value {
    serde_json::json!({
        "batchId": commitment.batch_id,
        "tenantId": commitment.tenant_id.0,
        "storeId": commitment.store_id.0,
        "vesVersion": commitment.ves_version,
        "treeDepth": commitment.tree_depth,
        "leafCount": commitment.leaf_count,
        "paddedLeafCount": commitment.padded_leaf_count,
        "merkleRoot": hex::encode(commitment.merkle_root),
        "prevStateRoot": hex::encode(commitment.prev_state_root),
        "newStateRoot": hex::encode(commitment.new_state_root),
        "sequenceStart": commitment.sequence_range.0,
        "sequenceEnd": commitment.sequence_range.1,
    })
}

fn decode_base64_any(s: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    let trimmed = s.trim();
    base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid base64: {e}")))
}

async fn get_ves_validity_public_inputs(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(batch_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let commitment = state
        .ves_commitment_engine
        .get_commitment(batch_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Commitment not found".to_string()))?;

    ensure_read(&auth, commitment.tenant_id.0, commitment.store_id.0)?;

    let public_inputs = ves_validity_public_inputs(&commitment);
    let public_inputs_hash = canonical_json_hash(&public_inputs);

    Ok(Json(serde_json::json!({
        "batch_id": commitment.batch_id,
        "public_inputs": public_inputs,
        "public_inputs_hash": hex::encode(public_inputs_hash),
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubmitVesValidityProofRequest {
    proof_type: String,
    #[serde(default = "default_proof_version")]
    proof_version: u32,
    proof_b64: String,
    public_inputs: Option<serde_json::Value>,
}

fn default_proof_version() -> u32 {
    1
}

fn default_policy_params() -> serde_json::Value {
    serde_json::json!({})
}

fn ves_compliance_public_inputs(
    inputs: &crate::infra::VesComplianceEventInputs,
    policy_id: &str,
    policy_params: &serde_json::Value,
    policy_hash: &Hash256,
) -> serde_json::Value {
    serde_json::json!({
        "eventId": inputs.event_id,
        "tenantId": inputs.tenant_id.0,
        "storeId": inputs.store_id.0,
        "sequenceNumber": inputs.sequence_number,
        "payloadKind": inputs.payload_kind,
        "payloadPlainHash": hex::encode(inputs.payload_plain_hash),
        "payloadCipherHash": hex::encode(inputs.payload_cipher_hash),
        "eventSigningHash": hex::encode(inputs.event_signing_hash),
        "policyId": policy_id,
        "policyParams": policy_params,
        "policyHash": hex::encode(policy_hash),
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VesComplianceInputsRequest {
    policy_id: String,
    #[serde(default = "default_policy_params")]
    policy_params: serde_json::Value,
}

async fn get_ves_compliance_public_inputs(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(event_id): Path<Uuid>,
    Json(request): Json<VesComplianceInputsRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let inputs = state
        .ves_compliance_proof_store
        .get_event_inputs(event_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Event not found".to_string()))?;

    ensure_read(&auth, inputs.tenant_id.0, inputs.store_id.0)?;

    let policy_id = request.policy_id.trim();
    if policy_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "policyId must not be empty".to_string(),
        ));
    }
    if policy_id.len() > 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            "policyId must be <= 64 characters".to_string(),
        ));
    }

    let policy_hash = compute_ves_compliance_policy_hash(policy_id, &request.policy_params);
    let public_inputs =
        ves_compliance_public_inputs(&inputs, policy_id, &request.policy_params, &policy_hash);
    let public_inputs_hash = canonical_json_hash(&public_inputs);

    Ok(Json(serde_json::json!({
        "event_id": inputs.event_id,
        "public_inputs": public_inputs,
        "public_inputs_hash": hex::encode(public_inputs_hash),
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubmitVesComplianceProofRequest {
    proof_type: String,
    #[serde(default = "default_proof_version")]
    proof_version: u32,
    policy_id: String,
    #[serde(default = "default_policy_params")]
    policy_params: serde_json::Value,
    proof_b64: String,
    public_inputs: Option<serde_json::Value>,
}

async fn submit_ves_compliance_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(event_id): Path<Uuid>,
    Json(request): Json<SubmitVesComplianceProofRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let inputs = state
        .ves_compliance_proof_store
        .get_event_inputs(event_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Event not found".to_string()))?;

    ensure_write(&auth, inputs.tenant_id.0, inputs.store_id.0)?;

    let proof_type = request.proof_type.trim();
    if proof_type.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "proofType must not be empty".to_string(),
        ));
    }
    if proof_type.len() > 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            "proofType must be <= 32 characters".to_string(),
        ));
    }
    if request.proof_version < 1 {
        return Err((
            StatusCode::BAD_REQUEST,
            "proofVersion must be >= 1".to_string(),
        ));
    }

    let policy_id = request.policy_id.trim();
    if policy_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "policyId must not be empty".to_string(),
        ));
    }
    if policy_id.len() > 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            "policyId must be <= 64 characters".to_string(),
        ));
    }

    let proof = decode_base64_any(&request.proof_b64)?;
    if proof.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "proofB64 must not be empty".to_string(),
        ));
    }

    let policy_hash = compute_ves_compliance_policy_hash(policy_id, &request.policy_params);
    let canonical_inputs =
        ves_compliance_public_inputs(&inputs, policy_id, &request.policy_params, &policy_hash);

    let public_inputs = match request.public_inputs {
        Some(v) if v != canonical_inputs => {
            return Err((
                StatusCode::BAD_REQUEST,
                "publicInputs must match the sequencer's canonical inputs for this event and policy"
                    .to_string(),
            ));
        }
        Some(v) => Some(v),
        None => Some(canonical_inputs),
    };

    let summary = state
        .ves_compliance_proof_store
        .submit_proof(
            &inputs.tenant_id,
            &inputs.store_id,
            event_id,
            proof_type,
            request.proof_version,
            policy_id,
            request.policy_params,
            proof,
            public_inputs,
        )
        .await
        .map_err(|e| match e {
            crate::infra::SequencerError::EventNotFound(_) => {
                (StatusCode::NOT_FOUND, e.to_string())
            }
            crate::infra::SequencerError::Unauthorized(_) => (StatusCode::FORBIDDEN, e.to_string()),
            crate::infra::SequencerError::InvariantViolation { .. } => {
                (StatusCode::CONFLICT, e.to_string())
            }
            crate::infra::SequencerError::Encryption(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
            crate::infra::SequencerError::Database(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
            _ => (StatusCode::BAD_REQUEST, e.to_string()),
        })?;

    Ok(Json(serde_json::json!({
        "proof_id": summary.proof_id,
        "event_id": summary.event_id,
        "tenant_id": summary.tenant_id.0,
        "store_id": summary.store_id.0,
        "proof_type": summary.proof_type,
        "proof_version": summary.proof_version,
        "policy_id": summary.policy_id,
        "policy_params": summary.policy_params,
        "policy_hash": hex::encode(summary.policy_hash),
        "proof_hash": hex::encode(summary.proof_hash),
        "public_inputs": summary.public_inputs,
        "submitted_at": summary.submitted_at,
    })))
}

async fn list_ves_compliance_proofs(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(event_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let inputs = state
        .ves_compliance_proof_store
        .get_event_inputs(event_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Event not found".to_string()))?;

    ensure_read(&auth, inputs.tenant_id.0, inputs.store_id.0)?;

    let proofs = state
        .ves_compliance_proof_store
        .list_proofs_for_event(event_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let proofs: Vec<serde_json::Value> = proofs
        .into_iter()
        .map(|p| {
            serde_json::json!({
                "proof_id": p.proof_id,
                "event_id": p.event_id,
                "tenant_id": p.tenant_id.0,
                "store_id": p.store_id.0,
                "proof_type": p.proof_type,
                "proof_version": p.proof_version,
                "policy_id": p.policy_id,
                "policy_params": p.policy_params,
                "policy_hash": hex::encode(p.policy_hash),
                "proof_hash": hex::encode(p.proof_hash),
                "public_inputs": p.public_inputs,
                "submitted_at": p.submitted_at,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "event_id": event_id,
        "proofs": proofs,
        "count": proofs.len(),
    })))
}

async fn get_ves_compliance_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(proof_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let proof = state
        .ves_compliance_proof_store
        .get_proof(proof_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((
            StatusCode::NOT_FOUND,
            "Compliance proof not found".to_string(),
        ))?;

    ensure_read(&auth, proof.tenant_id.0, proof.store_id.0)?;

    Ok(Json(serde_json::json!({
        "proof_id": proof.proof_id,
        "event_id": proof.event_id,
        "tenant_id": proof.tenant_id.0,
        "store_id": proof.store_id.0,
        "proof_type": proof.proof_type,
        "proof_version": proof.proof_version,
        "policy_id": proof.policy_id,
        "policy_params": proof.policy_params,
        "policy_hash": hex::encode(proof.policy_hash),
        "proof_hash": hex::encode(proof.proof_hash),
        "proof_b64": base64::engine::general_purpose::STANDARD.encode(proof.proof),
        "public_inputs": proof.public_inputs,
        "submitted_at": proof.submitted_at,
    })))
}

async fn verify_ves_compliance_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(proof_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let proof = state
        .ves_compliance_proof_store
        .get_proof(proof_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((
            StatusCode::NOT_FOUND,
            "Compliance proof not found".to_string(),
        ))?;

    ensure_read(&auth, proof.tenant_id.0, proof.store_id.0)?;

    let inputs = state
        .ves_compliance_proof_store
        .get_event_inputs(proof.event_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Event not found for compliance proof".to_string(),
        ))?;

    if inputs.tenant_id.0 != proof.tenant_id.0 || inputs.store_id.0 != proof.store_id.0 {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Compliance proof stream does not match event".to_string(),
        ));
    }

    let computed_policy_hash =
        compute_ves_compliance_policy_hash(&proof.policy_id, &proof.policy_params);

    let canonical_public_inputs = ves_compliance_public_inputs(
        &inputs,
        &proof.policy_id,
        &proof.policy_params,
        &computed_policy_hash,
    );
    let canonical_public_inputs_hash = canonical_json_hash(&canonical_public_inputs);

    let public_inputs_match = proof
        .public_inputs
        .as_ref()
        .is_some_and(|v| *v == canonical_public_inputs);

    let stored_policy_hash_ok = proof.policy_hash == computed_policy_hash;

    let public_inputs_hash = proof.public_inputs.as_ref().map(|v| {
        let hash = canonical_json_hash(v);
        hex::encode(hash)
    });

    let (valid, reason) = if proof.public_inputs.is_none() {
        (false, Some("missing_public_inputs"))
    } else if !stored_policy_hash_ok {
        (false, Some("policy_hash_mismatch"))
    } else if !public_inputs_match {
        (false, Some("public_inputs_mismatch"))
    } else {
        (true, None)
    };

    Ok(Json(serde_json::json!({
        "proof_id": proof.proof_id,
        "event_id": proof.event_id,
        "tenant_id": proof.tenant_id.0,
        "store_id": proof.store_id.0,
        "proof_type": proof.proof_type,
        "proof_version": proof.proof_version,
        "policy_id": proof.policy_id,
        "policy_hash": hex::encode(proof.policy_hash),
        "proof_hash": hex::encode(proof.proof_hash),
        "public_inputs_hash": public_inputs_hash,
        "canonical_public_inputs_hash": hex::encode(canonical_public_inputs_hash),
        "public_inputs_match": public_inputs_match,
        "valid": valid,
        "reason": reason,
    })))
}

async fn submit_ves_validity_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(batch_id): Path<Uuid>,
    Json(request): Json<SubmitVesValidityProofRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let commitment = state
        .ves_commitment_engine
        .get_commitment(batch_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Commitment not found".to_string()))?;

    ensure_admin(&auth, commitment.tenant_id.0, commitment.store_id.0)?;

    let proof_type = request.proof_type.trim();
    if proof_type.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "proofType must not be empty".to_string(),
        ));
    }
    if proof_type.len() > 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            "proofType must be <= 32 characters".to_string(),
        ));
    }
    if request.proof_version < 1 {
        return Err((
            StatusCode::BAD_REQUEST,
            "proofVersion must be >= 1".to_string(),
        ));
    }

    let proof = decode_base64_any(&request.proof_b64)?;
    if proof.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "proofB64 must not be empty".to_string(),
        ));
    }

    let canonical_inputs = ves_validity_public_inputs(&commitment);
    let public_inputs = match request.public_inputs {
        Some(v) if v != canonical_inputs => {
            return Err((
                StatusCode::BAD_REQUEST,
                "publicInputs must match the sequencer's canonical inputs for this batch"
                    .to_string(),
            ));
        }
        Some(v) => Some(v),
        None => Some(canonical_inputs),
    };

    let summary = state
        .ves_validity_proof_store
        .submit_proof(
            &commitment.tenant_id,
            &commitment.store_id,
            batch_id,
            proof_type,
            request.proof_version,
            proof,
            public_inputs,
        )
        .await
        .map_err(|e| match e {
            crate::infra::SequencerError::BatchNotFound(_) => {
                (StatusCode::NOT_FOUND, e.to_string())
            }
            crate::infra::SequencerError::Unauthorized(_) => (StatusCode::FORBIDDEN, e.to_string()),
            crate::infra::SequencerError::InvariantViolation { .. } => {
                (StatusCode::CONFLICT, e.to_string())
            }
            crate::infra::SequencerError::Encryption(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
            crate::infra::SequencerError::Database(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
            _ => (StatusCode::BAD_REQUEST, e.to_string()),
        })?;

    Ok(Json(serde_json::json!({
        "proof_id": summary.proof_id,
        "batch_id": summary.batch_id,
        "tenant_id": summary.tenant_id.0,
        "store_id": summary.store_id.0,
        "proof_type": summary.proof_type,
        "proof_version": summary.proof_version,
        "proof_hash": hex::encode(summary.proof_hash),
        "public_inputs": summary.public_inputs,
        "submitted_at": summary.submitted_at,
    })))
}

async fn list_ves_validity_proofs(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(batch_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let commitment = state
        .ves_commitment_engine
        .get_commitment(batch_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Commitment not found".to_string()))?;

    ensure_read(&auth, commitment.tenant_id.0, commitment.store_id.0)?;

    let proofs = state
        .ves_validity_proof_store
        .list_proofs_for_batch(batch_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let proofs: Vec<serde_json::Value> = proofs
        .into_iter()
        .map(|p| {
            serde_json::json!({
                "proof_id": p.proof_id,
                "batch_id": p.batch_id,
                "tenant_id": p.tenant_id.0,
                "store_id": p.store_id.0,
                "proof_type": p.proof_type,
                "proof_version": p.proof_version,
                "proof_hash": hex::encode(p.proof_hash),
                "public_inputs": p.public_inputs,
                "submitted_at": p.submitted_at,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "batch_id": batch_id,
        "proofs": proofs,
        "count": proofs.len(),
    })))
}

async fn get_ves_validity_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(proof_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let proof = state
        .ves_validity_proof_store
        .get_proof(proof_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((
            StatusCode::NOT_FOUND,
            "Validity proof not found".to_string(),
        ))?;

    ensure_read(&auth, proof.tenant_id.0, proof.store_id.0)?;

    Ok(Json(serde_json::json!({
        "proof_id": proof.proof_id,
        "batch_id": proof.batch_id,
        "tenant_id": proof.tenant_id.0,
        "store_id": proof.store_id.0,
        "proof_type": proof.proof_type,
        "proof_version": proof.proof_version,
        "proof_hash": hex::encode(proof.proof_hash),
        "proof_b64": base64::engine::general_purpose::STANDARD.encode(proof.proof),
        "public_inputs": proof.public_inputs,
        "submitted_at": proof.submitted_at,
    })))
}

async fn verify_ves_validity_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(proof_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let proof = state
        .ves_validity_proof_store
        .get_proof(proof_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((
            StatusCode::NOT_FOUND,
            "Validity proof not found".to_string(),
        ))?;

    ensure_read(&auth, proof.tenant_id.0, proof.store_id.0)?;

    let commitment = state
        .ves_commitment_engine
        .get_commitment(proof.batch_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Commitment not found".to_string()))?;

    if commitment.tenant_id.0 != proof.tenant_id.0 || commitment.store_id.0 != proof.store_id.0 {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Validity proof stream does not match commitment".to_string(),
        ));
    }

    let canonical_public_inputs = ves_validity_public_inputs(&commitment);
    let canonical_public_inputs_hash = canonical_json_hash(&canonical_public_inputs);

    let public_inputs_match = proof
        .public_inputs
        .as_ref()
        .is_some_and(|v| *v == canonical_public_inputs);

    let public_inputs_hash = proof.public_inputs.as_ref().map(|v| {
        let hash = canonical_json_hash(v);
        hex::encode(hash)
    });

    let (valid, reason) = if proof.public_inputs.is_none() {
        (false, Some("missing_public_inputs"))
    } else if !public_inputs_match {
        (false, Some("public_inputs_mismatch"))
    } else {
        (true, None)
    };

    Ok(Json(serde_json::json!({
        "proof_id": proof.proof_id,
        "batch_id": proof.batch_id,
        "tenant_id": proof.tenant_id.0,
        "store_id": proof.store_id.0,
        "proof_type": proof.proof_type,
        "proof_version": proof.proof_version,
        "proof_hash": hex::encode(proof.proof_hash),
        "public_inputs_hash": public_inputs_hash,
        "canonical_public_inputs_hash": hex::encode(canonical_public_inputs_hash),
        "public_inputs_match": public_inputs_match,
        "valid": valid,
        "reason": reason,
    })))
}

async fn get_ves_commitment(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(batch_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match state.ves_commitment_engine.get_commitment(batch_id).await {
        Ok(Some(commitment)) => {
            ensure_read(&auth, commitment.tenant_id.0, commitment.store_id.0)?;
            Ok(Json(serde_json::json!({
                "batch_id": commitment.batch_id,
                "tenant_id": commitment.tenant_id.0,
                "store_id": commitment.store_id.0,
                "ves_version": commitment.ves_version,
                "tree_depth": commitment.tree_depth,
                "leaf_count": commitment.leaf_count,
                "padded_leaf_count": commitment.padded_leaf_count,
                "merkle_root": hex::encode(commitment.merkle_root),
                "prev_state_root": hex::encode(commitment.prev_state_root),
                "new_state_root": hex::encode(commitment.new_state_root),
                "sequence_start": commitment.sequence_range.0,
                "sequence_end": commitment.sequence_range.1,
                "committed_at": commitment.committed_at,
                "chain_id": commitment.chain_id,
                "chain_tx_hash": commitment.chain_tx_hash.map(hex::encode),
                "chain_block_number": commitment.chain_block_number,
                "anchored_at": commitment.anchored_at,
                "is_anchored": commitment.is_anchored(),
            })))
        }
        Ok(None) => Err((StatusCode::NOT_FOUND, "Commitment not found".to_string())),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

async fn list_ves_commitments(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Query(query): Query<HeadQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    ensure_read(&auth, query.tenant_id, query.store_id)?;

    let tenant_id = TenantId::from_uuid(query.tenant_id);
    let store_id = StoreId::from_uuid(query.store_id);

    let commitments = state
        .ves_commitment_engine
        .list_unanchored(&tenant_id, &store_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let response: Vec<serde_json::Value> = commitments
        .iter()
        .map(|c| {
            serde_json::json!({
                "batch_id": c.batch_id,
                "tenant_id": c.tenant_id.0,
                "store_id": c.store_id.0,
                "ves_version": c.ves_version,
                "tree_depth": c.tree_depth,
                "leaf_count": c.leaf_count,
                "padded_leaf_count": c.padded_leaf_count,
                "merkle_root": hex::encode(c.merkle_root),
                "prev_state_root": hex::encode(c.prev_state_root),
                "new_state_root": hex::encode(c.new_state_root),
                "sequence_start": c.sequence_range.0,
                "sequence_end": c.sequence_range.1,
                "committed_at": c.committed_at,
                "is_anchored": c.is_anchored(),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "commitments": response,
        "count": response.len(),
    })))
}

async fn create_ves_commitment(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(request): Json<CreateCommitmentRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    ensure_write(&auth, request.tenant_id, request.store_id)?;

    let tenant_id = TenantId::from_uuid(request.tenant_id);
    let store_id = StoreId::from_uuid(request.store_id);

    let commitment = state
        .ves_commitment_engine
        .create_and_store_commitment(
            &tenant_id,
            &store_id,
            (request.sequence_start, request.sequence_end),
        )
        .await
        .map_err(|e| match e {
            crate::infra::SequencerError::Database(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
            _ => (StatusCode::BAD_REQUEST, e.to_string()),
        })?;

    Ok(Json(serde_json::json!({
        "batch_id": commitment.batch_id,
        "tenant_id": commitment.tenant_id.0,
        "store_id": commitment.store_id.0,
        "ves_version": commitment.ves_version,
        "tree_depth": commitment.tree_depth,
        "leaf_count": commitment.leaf_count,
        "padded_leaf_count": commitment.padded_leaf_count,
        "merkle_root": hex::encode(commitment.merkle_root),
        "prev_state_root": hex::encode(commitment.prev_state_root),
        "new_state_root": hex::encode(commitment.new_state_root),
        "sequence_start": commitment.sequence_range.0,
        "sequence_end": commitment.sequence_range.1,
        "committed_at": commitment.committed_at,
    })))
}

#[derive(Debug, Deserialize)]
struct CommitAndAnchorVesRequest {
    tenant_id: Uuid,
    store_id: Uuid,
    sequence_start: Option<u64>,
    sequence_end: Option<u64>,
    max_events: Option<u64>,
}

async fn commit_and_anchor_ves_commitment(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(request): Json<CommitAndAnchorVesRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let anchor_service = state.anchor_service.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Anchor service not configured".to_string(),
    ))?;

    ensure_admin(&auth, request.tenant_id, request.store_id)?;

    let tenant_id = TenantId::from_uuid(request.tenant_id);
    let store_id = StoreId::from_uuid(request.store_id);

    let (start, end) = match (request.sequence_start, request.sequence_end) {
        (Some(start), Some(end)) => (start, end),
        (None, None) => {
            let head = state
                .ves_sequencer
                .head(&tenant_id, &store_id)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            if head == 0 {
                return Err((StatusCode::BAD_REQUEST, "no events to commit".to_string()));
            }

            let last_end = state
                .ves_commitment_engine
                .last_sequence_end(&tenant_id, &store_id)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let start = last_end.map(|v| v.saturating_add(1)).unwrap_or(1);
            if start > head {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("no new events to commit (head_sequence={head})"),
                ));
            }

            let max_events = request.max_events.unwrap_or(1024).max(1);
            let end = start
                .checked_add(max_events.saturating_sub(1))
                .unwrap_or(u64::MAX)
                .min(head);
            (start, end)
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "sequence_start and sequence_end must be provided together".to_string(),
            ))
        }
    };

    let commitment = state
        .ves_commitment_engine
        .create_and_store_commitment(&tenant_id, &store_id, (start, end))
        .await
        .map_err(|e| match e {
            crate::infra::SequencerError::Database(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
            _ => (StatusCode::BAD_REQUEST, e.to_string()),
        })?;

    if commitment.is_anchored() {
        return Ok(Json(serde_json::json!({
            "batch_id": commitment.batch_id,
            "status": "already_anchored",
            "chain_id": commitment.chain_id,
            "chain_tx_hash": commitment.chain_tx_hash.map(hex::encode),
            "chain_block_number": commitment.chain_block_number,
            "merkle_root": hex::encode(commitment.merkle_root),
            "prev_state_root": hex::encode(commitment.prev_state_root),
            "new_state_root": hex::encode(commitment.new_state_root),
            "sequence_start": commitment.sequence_range.0,
            "sequence_end": commitment.sequence_range.1,
        })));
    }

    let (tx_hash, chain_block_number) = anchor_service
        .anchor_ves_commitment(&commitment)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state
        .ves_commitment_engine
        .update_chain_tx(
            commitment.batch_id,
            anchor_service.chain_id() as u32,
            tx_hash,
            chain_block_number,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "batch_id": commitment.batch_id,
        "status": "anchored",
        "chain_id": anchor_service.chain_id(),
        "chain_tx_hash": hex::encode(tx_hash),
        "chain_block_number": chain_block_number,
        "merkle_root": hex::encode(commitment.merkle_root),
        "prev_state_root": hex::encode(commitment.prev_state_root),
        "new_state_root": hex::encode(commitment.new_state_root),
        "sequence_start": commitment.sequence_range.0,
        "sequence_end": commitment.sequence_range.1,
    })))
}

async fn get_ves_inclusion_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(sequence_number): Path<u64>,
    Query(query): Query<ProofQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tenant_id = TenantId::from_uuid(query.tenant_id);
    let store_id = StoreId::from_uuid(query.store_id);

    ensure_read(&auth, tenant_id.0, store_id.0)?;

    let commitment = state
        .ves_commitment_engine
        .get_commitment(query.batch_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Commitment not found".to_string()))?;

    if commitment.tenant_id.0 != tenant_id.0 || commitment.store_id.0 != store_id.0 {
        return Err((
            StatusCode::FORBIDDEN,
            "Commitment access denied".to_string(),
        ));
    }

    if sequence_number < commitment.sequence_range.0
        || sequence_number > commitment.sequence_range.1
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Sequence number not in commitment range".to_string(),
        ));
    }

    let start = commitment.sequence_range.0;
    let end = commitment.sequence_range.1;
    let leaf_index = (sequence_number - start) as usize;

    let leaves = state
        .ves_commitment_engine
        .leaf_hashes_for_range(&tenant_id, &store_id, start, end)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let computed_root = state.ves_commitment_engine.compute_merkle_root(&leaves);
    if computed_root != commitment.merkle_root {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Commitment merkle_root does not match ves_events".to_string(),
        ));
    }

    let proof = state
        .ves_commitment_engine
        .prove_inclusion(leaf_index, &leaves)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "sequence_number": sequence_number,
        "batch_id": commitment.batch_id,
        "merkle_root": hex::encode(commitment.merkle_root),
        "leaf_hash": hex::encode(proof.leaf_hash),
        "leaf_index": proof.leaf_index,
        "proof_path": proof.proof_path.iter().map(hex::encode).collect::<Vec<_>>(),
        "directions": proof.directions,
    })))
}

#[derive(Debug, Deserialize)]
struct VerifyVesProofRequest {
    leaf_hash: String,
    merkle_root: String,
    proof_path: Vec<String>,
    leaf_index: usize,
}

async fn verify_ves_proof(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(request): Json<VerifyVesProofRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    use crate::domain::MerkleProof;

    if !auth.can_read() && !auth.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            "Read permission required".to_string(),
        ));
    }

    let leaf_hash: [u8; 32] = hex::decode(&request.leaf_hash)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid leaf_hash: {}", e)))?
        .try_into()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "leaf_hash must be 32 bytes".to_string(),
            )
        })?;

    let merkle_root: [u8; 32] = hex::decode(&request.merkle_root)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid merkle_root: {}", e),
            )
        })?
        .try_into()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "merkle_root must be 32 bytes".to_string(),
            )
        })?;

    let proof_path: Vec<[u8; 32]> = request
        .proof_path
        .iter()
        .map(|h| {
            hex::decode(h)
                .map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Invalid proof hash: {}", e),
                    )
                })
                .and_then(|bytes| {
                    bytes.try_into().map_err(|_| {
                        (
                            StatusCode::BAD_REQUEST,
                            "Each proof hash must be 32 bytes".to_string(),
                        )
                    })
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let proof = MerkleProof::new(leaf_hash, proof_path, request.leaf_index);
    let valid = state
        .ves_commitment_engine
        .verify_inclusion(leaf_hash, &proof, merkle_root);

    Ok(Json(serde_json::json!({
        "valid": valid,
        "leaf_hash": request.leaf_hash,
        "merkle_root": request.merkle_root,
    })))
}

async fn anchor_ves_commitment(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(request): Json<AnchorRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let anchor_service = state.anchor_service.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Anchor service not configured".to_string(),
    ))?;

    let commitment = state
        .ves_commitment_engine
        .get_commitment(request.batch_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Commitment not found".to_string()))?;

    ensure_admin(&auth, commitment.tenant_id.0, commitment.store_id.0)?;

    if commitment.is_anchored() {
        return Ok(Json(serde_json::json!({
            "batch_id": commitment.batch_id,
            "status": "already_anchored",
            "chain_tx_hash": commitment.chain_tx_hash.map(hex::encode),
        })));
    }

    let (tx_hash, chain_block_number) = anchor_service
        .anchor_ves_commitment(&commitment)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state
        .ves_commitment_engine
        .update_chain_tx(
            request.batch_id,
            anchor_service.chain_id() as u32,
            tx_hash,
            chain_block_number,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "batch_id": commitment.batch_id,
        "status": "anchored",
        "chain_tx_hash": hex::encode(tx_hash),
        "chain_block_number": chain_block_number,
        "merkle_root": hex::encode(commitment.merkle_root),
        "sequence_start": commitment.sequence_range.0,
        "sequence_end": commitment.sequence_range.1,
    })))
}

async fn verify_ves_anchor_onchain(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(batch_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let anchor_service = state.anchor_service.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Anchor service not configured".to_string(),
    ))?;

    let is_anchored = anchor_service
        .verify_anchored(batch_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if let Ok(Some(commitment)) = state.ves_commitment_engine.get_commitment(batch_id).await {
        ensure_read(&auth, commitment.tenant_id.0, commitment.store_id.0)?;
    } else if !auth.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            "Commitment access denied".to_string(),
        ));
    }

    Ok(Json(serde_json::json!({
        "batch_id": batch_id,
        "anchored_on_chain": is_anchored,
    })))
}

// ============================================================================
// Entity history
// ============================================================================

async fn get_entity_history(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path((entity_type, entity_id)): Path<(String, String)>,
    Query(query): Query<HeadQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tenant_id = TenantId::from_uuid(query.tenant_id);
    let store_id = StoreId::from_uuid(query.store_id);
    let entity_type = EntityType::from(entity_type.as_str());

    ensure_read(&auth, tenant_id.0, store_id.0)?;

    match state
        .event_store
        .read_entity(&tenant_id, &store_id, &entity_type, &entity_id)
        .await
    {
        Ok(events) => Ok(Json(serde_json::json!({
            "entity_type": entity_type.as_str(),
            "entity_id": entity_id,
            "events": events,
            "count": events.len(),
        }))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

// ============================================================================
// Anchoring
// ============================================================================

#[derive(Debug, Deserialize)]
struct AnchorRequest {
    batch_id: Uuid,
}

async fn anchor_commitment(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(request): Json<AnchorRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Check if anchor service is configured
    let anchor_service = state.anchor_service.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Anchor service not configured".to_string(),
    ))?;

    // Get the commitment
    let commitment = state
        .commitment_engine
        .get_commitment(request.batch_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Commitment not found".to_string()))?;

    ensure_admin(&auth, commitment.tenant_id.0, commitment.store_id.0)?;

    // Check if already anchored
    if commitment.is_anchored() {
        return Ok(Json(serde_json::json!({
            "batch_id": commitment.batch_id,
            "status": "already_anchored",
            "chain_tx_hash": commitment.chain_tx_hash.map(|h| hex::encode(h)),
        })));
    }

    // Anchor on-chain
    let tx_hash = anchor_service
        .anchor_commitment(&commitment)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Update commitment with chain tx hash
    state
        .commitment_engine
        .update_chain_tx(request.batch_id, tx_hash)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "batch_id": commitment.batch_id,
        "status": "anchored",
        "chain_tx_hash": hex::encode(tx_hash),
        "events_root": hex::encode(commitment.events_root),
        "sequence_start": commitment.sequence_range.0,
        "sequence_end": commitment.sequence_range.1,
    })))
}

async fn get_anchor_status(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !auth.can_read() && !auth.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            "Read permission required".to_string(),
        ));
    }

    let anchor_configured = state.anchor_service.is_some();

    Ok(Json(serde_json::json!({
        "anchor_enabled": anchor_configured,
        "message": if anchor_configured {
            "Anchor service is configured and ready"
        } else {
            "Anchor service not configured. Set L2_RPC_URL, SET_REGISTRY_ADDRESS, SEQUENCER_PRIVATE_KEY"
        }
    })))
}

async fn verify_anchor_onchain(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(batch_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Check if anchor service is configured
    let anchor_service = state.anchor_service.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Anchor service not configured".to_string(),
    ))?;

    let is_anchored = anchor_service
        .verify_anchored(batch_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // If we can find a local commitment, enforce tenant/store access.
    if let Ok(Some(commitment)) = state.commitment_engine.get_commitment(batch_id).await {
        ensure_read(&auth, commitment.tenant_id.0, commitment.store_id.0)?;
    } else if !auth.is_admin() {
        return Err((
            StatusCode::FORBIDDEN,
            "Commitment access denied".to_string(),
        ));
    }

    Ok(Json(serde_json::json!({
        "batch_id": batch_id,
        "anchored_on_chain": is_anchored,
    })))
}
