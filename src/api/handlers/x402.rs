//! x402 Payment Protocol API Handlers
//!
//! HTTP handlers for x402 payment intent submission, batching, and settlement.
//!
//! # Endpoints
//!
//! - `POST /api/v1/x402/payments` - Submit payment intent
//! - `GET /api/v1/x402/payments/:intent_id` - Get payment status
//! - `GET /api/v1/x402/payments/:intent_id/receipt` - Get payment receipt
//! - `GET /api/v1/x402/batches/:batch_id` - Get batch status
//! - `POST /api/v1/x402/batches/settle` - Submit or confirm batch settlement
//!
//! # Flow
//!
//! 1. AI Agent signs payment intent off-chain
//! 2. Agent submits intent via `POST /payments`
//! 3. Sequencer validates signature and assigns sequence number
//! 4. Intents are batched periodically or on threshold
//! 5. Batch is committed (Merkle root computed)
//! 6. Batch is settled on Set Chain L2 via SetPaymentBatch contract
//! 7. Agent can fetch receipt with inclusion proof

use std::collections::HashSet;

use axum::extract::{Extension, Path, Query, State};
use axum::Json;
use chrono::Utc;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use crate::api::auth_helpers::{ensure_admin, ensure_read, ensure_write};
use crate::api::error::{ApiError, ErrorCode};
use crate::auth::{AgentKeyRegistry, AuthContextExt};
use crate::domain::{
    AgentId, AgentKeyId, GetX402BatchResponse, GetX402ReceiptResponse, Hash256, Signature64,
    StoreId, SubmitX402PaymentRequest, SubmitX402PaymentResponse, TenantId, X402BatchStatus,
    X402_DEFAULT_BATCH_SIZE, X402IntentStatus, X402Network, X402_MAX_BATCH_SIZE,
    X402PaymentBatch, X402PaymentIntent, X402PaymentIntentFilter, X402_MAX_VALIDITY_SECS,
};
use crate::infra::PgX402Repository;
use crate::server::AppState;

const X402_DEFAULT_LIST_LIMIT: u32 = X402_DEFAULT_BATCH_SIZE as u32;
const X402_MAX_LIST_LIMIT: u32 = X402_MAX_BATCH_SIZE as u32;
const X402_MAX_LIST_OFFSET: u32 = 10_000;
const X402_MAX_ADDRESS_LEN: usize = 66;
const X402_MAX_STRING_FIELD_LEN: usize = 1024;
const X402_MAX_IDEMPOTENCY_KEY_LEN: usize = 255;
const X402_MAX_URI_LEN: usize = 4096;
const X402_MAX_DESCRIPTION_LEN: usize = 8192;

// =============================================================================
// Submit Payment Intent
// =============================================================================

/// Submit an x402 payment intent for sequencing
///
/// # Request
///
/// ```json
/// {
///   "tenant_id": "uuid",
///   "store_id": "uuid",
///   "agent_id": "uuid",
///   "payer_address": "0x...",
///   "payee_address": "0x...",
///   "amount": 1000000,
///   "asset": "usdc",
///   "network": "set_chain",
///   "valid_until": 1705320000,
///   "nonce": 42,
///   "signing_hash": "0x...",
///   "payer_signature": "0x..."
/// }
/// ```
///
/// # Response
///
/// ```json
/// {
///   "intent_id": "uuid",
///   "status": "sequenced",
///   "sequence_number": 123,
///   "sequenced_at": "2024-01-15T10:30:00Z"
/// }
/// ```
#[instrument(skip(state, payload), fields(tenant_id = ?payload.tenant_id, amount = payload.amount))]
pub async fn submit_payment_intent(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(payload): Json<SubmitX402PaymentRequest>,
) -> Result<Json<SubmitX402PaymentResponse>, ApiError> {
    info!(
        payer = %payload.payer_address,
        payee = %payload.payee_address,
        amount = payload.amount,
        asset = ?payload.asset,
        network = ?payload.network,
        "Received x402 payment intent"
    );

    let tenant_id = TenantId::from_uuid(payload.tenant_id);
    let store_id = StoreId::from_uuid(payload.store_id);
    let amount = payload.amount;
    let now_unix = Utc::now().timestamp() as u64;

    if payload.tenant_id.is_nil() {
        return Err(ApiError::new(
            ErrorCode::InvalidFieldValue,
            "tenant_id cannot be nil",
        ));
    }

    if payload.store_id.is_nil() {
        return Err(ApiError::new(
            ErrorCode::InvalidFieldValue,
            "store_id cannot be nil",
        ));
    }

    if payload.agent_id.is_nil() {
        return Err(ApiError::new(
            ErrorCode::InvalidFieldValue,
            "agent_id cannot be nil",
        ));
    }

    if amount == 0 {
        return Err(ApiError::new(
            ErrorCode::InvalidFieldValue,
            "amount must be greater than 0",
        ));
    }

    validate_hex_string(&payload.payer_address, "payer_address", X402_MAX_ADDRESS_LEN)?;
    validate_hex_string(&payload.payee_address, "payee_address", X402_MAX_ADDRESS_LEN)?;

    if payload.payer_address == payload.payee_address {
        return Err(ApiError::new(
            ErrorCode::InvalidFieldValue,
            "payer_address and payee_address cannot be the same",
        ));
    }

    if let Some(agent_key_id) = payload.agent_key_id {
        if agent_key_id == 0 {
            return Err(ApiError::new(
                ErrorCode::InvalidFieldValue,
                "agent_key_id must be greater than 0",
            ));
        }
    }

    if let Some(ref idempotency_key) = payload.idempotency_key {
        validate_length(
            idempotency_key,
            "idempotency_key",
            X402_MAX_IDEMPOTENCY_KEY_LEN,
        )?;
    }

    if let Some(ref resource_uri) = payload.resource_uri {
        validate_length(resource_uri, "resource_uri", X402_MAX_URI_LEN)?;
    }

    if let Some(ref description) = payload.description {
        validate_length(description, "description", X402_MAX_DESCRIPTION_LEN)?;
    }

    if let Some(ref merchant_id) = payload.merchant_id {
        validate_length(merchant_id, "merchant_id", X402_MAX_STRING_FIELD_LEN)?;
    }

    ensure_write(&auth, tenant_id.0, store_id.0)
        .map_err(|(_, msg)| ApiError::new(ErrorCode::InsufficientPermissions, msg))?;

    // Check expiry
    if payload.valid_until < now_unix {
        return Err(ApiError::new(
            ErrorCode::InvalidFieldValue,
            "Payment intent has expired",
        ));
    }
    if payload.valid_until > now_unix.saturating_add(X402_MAX_VALIDITY_SECS) {
        return Err(ApiError::new(
            ErrorCode::InvalidFieldValue,
            "Payment intent validity exceeds maximum window",
        ));
    }

    // Parse signing hash
    let signing_hash = parse_hash256(&payload.signing_hash).map_err(|e| {
        ApiError::new(
            ErrorCode::InvalidFieldValue,
            format!("Invalid signing_hash: {}", e),
        )
    })?;

    // Parse signature
    let payer_signature = parse_signature64(&payload.payer_signature).map_err(|e| {
        ApiError::new(
            ErrorCode::InvalidFieldValue,
            format!("Invalid payer_signature: {}", e),
        )
    })?;

    // Parse optional public key
    let payer_public_key = if let Some(ref pk) = payload.payer_public_key {
        Some(parse_hash256(pk).map_err(|e| {
            ApiError::new(
                ErrorCode::InvalidFieldValue,
                format!("Invalid payer_public_key: {}", e),
            )
        })?)
    } else {
        None
    };

    // Check for duplicate via idempotency key
    if let Some(ref key) = payload.idempotency_key {
        if let Ok(Some(existing)) = state
            .x402_repository
            .get_intent_by_idempotency(&tenant_id, &store_id, key)
            .await
        {
            debug!(
                idempotency_key = %key,
                intent_id = %existing.intent_id,
                "Returning existing intent for idempotency key"
            );
            return Ok(Json(SubmitX402PaymentResponse {
                intent_id: existing.intent_id,
                status: existing.status,
                sequence_number: existing.sequence_number,
                sequenced_at: existing.sequenced_at,
                batch_id: existing.batch_id,
            }));
        }
    }

    // Compute expected signing hash
    let expected_hash = PgX402Repository::compute_signing_hash(
        &payload.payer_address,
        &payload.payee_address,
        amount,
        &payload.asset,
        &payload.network,
        payload.network.chain_id(),
        payload.valid_until,
        payload.nonce,
    );

    // Verify signing hash matches
    if signing_hash != expected_hash {
        warn!(
            provided = %hex::encode(signing_hash),
            expected = %hex::encode(expected_hash),
            "Signing hash mismatch"
        );
        return Err(ApiError::new(
            ErrorCode::InvalidFieldValue,
            "Signing hash does not match payment parameters",
        ));
    }

    // Verify signature if public key provided
    if let Some(ref pk) = payer_public_key {
        if !PgX402Repository::verify_signature(&signing_hash, &payer_signature, pk) {
            return Err(ApiError::new(
                ErrorCode::SignatureVerificationFailed,
                "Payer signature verification failed",
            ));
        }
    } else {
        // Look up agent key from registry if no public key provided
        let lookup = crate::auth::AgentKeyLookup::new(
            &tenant_id,
            &AgentId::from_uuid(payload.agent_id),
            AgentKeyId::new(payload.agent_key_id.unwrap_or(1)),
        );

        match state
            .agent_key_registry
            .get_verifying_key_at(&lookup, Utc::now())
            .await
        {
            Ok(verifying_key) => {
                let pk_bytes = verifying_key.to_bytes();
                if !PgX402Repository::verify_signature(&signing_hash, &payer_signature, &pk_bytes) {
                    return Err(ApiError::new(
                        ErrorCode::SignatureVerificationFailed,
                        "Payer signature verification failed",
                    ));
                }
            }
            Err(e) => {
                warn!(error = ?e, "Failed to look up agent key for signature verification");
                return Err(ApiError::new(
                    ErrorCode::AgentKeyNotFound,
                    "Agent key not found; provide payer_public_key for verification",
                ));
            }
        }
    }

    // Create the payment intent
    let intent_id = Uuid::new_v4();
    let now = Utc::now();

    let intent = X402PaymentIntent {
        intent_id,
        x402_version: 1,
        status: X402IntentStatus::Pending,
        tenant_id: tenant_id.clone(),
        store_id: store_id.clone(),
        source_agent_id: AgentId::from_uuid(payload.agent_id),
        agent_key_id: AgentKeyId::new(payload.agent_key_id.unwrap_or(1)),
        payer_address: payload.payer_address,
        payee_address: payload.payee_address,
        amount,
        asset: payload.asset,
        network: payload.network,
        chain_id: payload.network.chain_id(),
        token_address: payload
            .asset
            .token_address(payload.network)
            .map(String::from),
        created_at_unix: now_unix,
        valid_until: payload.valid_until,
        nonce: payload.nonce,
        idempotency_key: payload.idempotency_key,
        resource_uri: payload.resource_uri,
        description: payload.description,
        order_id: payload.order_id,
        merchant_id: payload.merchant_id,
        signing_hash,
        payer_signature,
        payer_public_key,
        sequence_number: None,
        sequenced_at: None,
        batch_id: None,
        tx_hash: None,
        block_number: None,
        settled_at: None,
        metadata: payload.metadata,
        created_at: now,
        updated_at: now,
    };

    // Persist intent and reserve nonce atomically
    let mut tx = state.x402_repository.pool().begin().await.map_err(|e| {
        ApiError::new(
            ErrorCode::InternalError,
            format!("Failed to start transaction: {}", e),
        )
    })?;

    state
        .x402_repository
        .insert_intent_tx(&mut tx, &intent)
        .await
        .map_err(|e| {
            ApiError::new(
                ErrorCode::InternalError,
                format!("Failed to persist payment intent: {}", e),
            )
        })?;

    let reserved = state
        .x402_repository
        .reserve_nonce(
            &mut tx,
            &tenant_id,
            &store_id,
            &intent.payer_address,
            intent.nonce,
            intent_id,
        )
        .await
        .map_err(|e| {
            ApiError::new(
                ErrorCode::InternalError,
                format!("Failed to reserve nonce: {}", e),
            )
        })?;

    if !reserved {
        return Err(ApiError::new(
            ErrorCode::InvalidFieldValue,
            "Nonce already used for this payer",
        ));
    }

    tx.commit().await.map_err(|e| {
        ApiError::new(
            ErrorCode::InternalError,
            format!("Failed to commit payment intent: {}", e),
        )
    })?;

    // Assign sequence number atomically
    let sequence_number = state
        .x402_repository
        .assign_sequence_number(intent_id, &tenant_id, &store_id)
        .await
        .map_err(|e| {
            ApiError::new(
                ErrorCode::InternalError,
                format!("Failed to assign sequence number: {}", e),
            )
        })?;

    let sequenced_at = Utc::now();

    info!(
        intent_id = %intent_id,
        sequence_number = sequence_number,
        "x402 payment intent sequenced"
    );

    Ok(Json(SubmitX402PaymentResponse {
        intent_id,
        status: X402IntentStatus::Sequenced,
        sequence_number: Some(sequence_number),
        sequenced_at: Some(sequenced_at),
        batch_id: None,
    }))
}

// =============================================================================
// Get Payment Intent Status
// =============================================================================

/// Get the status of a payment intent
#[instrument(skip(state), fields(intent_id = %intent_id))]
pub async fn get_payment_intent(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(intent_id): Path<Uuid>,
) -> Result<Json<SubmitX402PaymentResponse>, ApiError> {
    debug!(intent_id = %intent_id, "Getting payment intent status");

    let intent = state
        .x402_repository
        .get_intent(intent_id)
        .await
        .map_err(|e| {
            ApiError::new(
                ErrorCode::InternalError,
                format!("Failed to fetch intent: {}", e),
            )
        })?;

    match intent {
        Some(intent) => {
            ensure_read(&auth, intent.tenant_id.0, intent.store_id.0)
                .map_err(|(_, msg)| ApiError::new(ErrorCode::InsufficientPermissions, msg))?;
            Ok(Json(SubmitX402PaymentResponse {
                intent_id: intent.intent_id,
                status: intent.status,
                sequence_number: intent.sequence_number,
                sequenced_at: intent.sequenced_at,
                batch_id: intent.batch_id,
            }))
        }
        None => Err(ApiError::new(
            ErrorCode::ResourceNotFound,
            format!("Payment intent {} not found", intent_id),
        )),
    }
}

// =============================================================================
// Get Payment Receipt
// =============================================================================

/// Get payment receipt with inclusion proof
#[instrument(skip(state), fields(intent_id = %intent_id))]
pub async fn get_payment_receipt(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(intent_id): Path<Uuid>,
) -> Result<Json<GetX402ReceiptResponse>, ApiError> {
    debug!(intent_id = %intent_id, "Getting payment receipt");

    let intent = state
        .x402_repository
        .get_intent(intent_id)
        .await
        .map_err(|e| {
            ApiError::new(
                ErrorCode::InternalError,
                format!("Failed to fetch intent: {}", e),
            )
        })?;

    let intent = intent.ok_or_else(|| {
        ApiError::new(
            ErrorCode::ResourceNotFound,
            format!("Payment intent {} not found", intent_id),
        )
    })?;

    ensure_read(&auth, intent.tenant_id.0, intent.store_id.0)
        .map_err(|(_, msg)| ApiError::new(ErrorCode::InsufficientPermissions, msg))?;

    let receipt = state
        .x402_repository
        .generate_receipt(intent_id)
        .await
        .map_err(|e| {
            ApiError::new(
                ErrorCode::InternalError,
                format!("Failed to generate receipt: {}", e),
            )
        })?;

    match receipt {
        Some(receipt) => Ok(Json(GetX402ReceiptResponse { receipt })),
        None => Err(ApiError::new(
            ErrorCode::ResourceNotFound,
            format!("Payment receipt for {} not found", intent_id),
        )),
    }
}

// =============================================================================
// List Payment Intents
// =============================================================================

/// List payment intents with optional filtering
#[instrument(skip(state, filter))]
pub async fn list_payment_intents(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Query(filter): Query<X402PaymentIntentFilter>,
) -> Result<Json<Vec<X402PaymentIntent>>, ApiError> {
    debug!(?filter, "Listing payment intents");

    let mut filter = filter;

    let tenant_id = filter
        .tenant_id
        .ok_or_else(|| ApiError::new(ErrorCode::MissingRequiredField, "tenant_id is required"))?;
    if filter.store_id.is_none() && !auth.store_ids.is_empty() {
        return Err(ApiError::new(
            ErrorCode::MissingRequiredField,
            "store_id is required for store-scoped keys",
        ));
    }
    let store_id = filter.store_id.unwrap_or_else(Uuid::nil);

    if let (Some(from_date), Some(to_date)) = (filter.from_date.as_ref(), filter.to_date.as_ref()) {
        if from_date > to_date {
            return Err(ApiError::new(
                ErrorCode::InvalidFieldValue,
                "from_date must be <= to_date",
            ));
        }
    }

    let requested_limit = filter.limit.unwrap_or(X402_DEFAULT_LIST_LIMIT);
    if requested_limit == 0 {
        return Err(ApiError::new(
            ErrorCode::InvalidFieldValue,
            "limit must be greater than 0",
        ));
    }
    if requested_limit > X402_MAX_LIST_LIMIT {
        return Err(ApiError::new(
            ErrorCode::BatchTooLarge,
            format!("limit exceeds maximum of {}", X402_MAX_LIST_LIMIT),
        ));
    }
    filter.limit = Some(requested_limit);

    let requested_offset = filter.offset.unwrap_or(0);
    if requested_offset > X402_MAX_LIST_OFFSET {
        return Err(ApiError::new(
            ErrorCode::InvalidFieldValue,
            format!(
                "offset exceeds platform maximum of {}",
                X402_MAX_LIST_OFFSET
            ),
        ));
    }
    filter.offset = Some(requested_offset);

    ensure_read(&auth, tenant_id, store_id)
        .map_err(|(_, msg)| ApiError::new(ErrorCode::InsufficientPermissions, msg))?;

    let intents = state
        .x402_repository
        .list_intents(&filter)
        .await
        .map_err(|e| {
            ApiError::new(
                ErrorCode::InternalError,
                format!("Failed to list intents: {}", e),
            )
        })?;

    Ok(Json(intents))
}

// =============================================================================
// Get Batch Status
// =============================================================================

/// Get batch status and details
#[instrument(skip(state), fields(batch_id = %batch_id))]
pub async fn get_batch(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(batch_id): Path<Uuid>,
) -> Result<Json<GetX402BatchResponse>, ApiError> {
    debug!(batch_id = %batch_id, "Getting batch status");

    let batch = state
        .x402_repository
        .get_batch(batch_id)
        .await
        .map_err(|e| {
            ApiError::new(
                ErrorCode::InternalError,
                format!("Failed to fetch batch: {}", e),
            )
        })?;

    match batch {
        Some(batch) => {
            ensure_read(&auth, batch.tenant_id.0, batch.store_id.0)
                .map_err(|(_, msg)| ApiError::new(ErrorCode::InsufficientPermissions, msg))?;
            Ok(Json(GetX402BatchResponse { batch }))
        }
        None => Err(ApiError::new(
            ErrorCode::BatchNotFound,
            format!("Batch {} not found", batch_id),
        )),
    }
}

// =============================================================================
// Trigger Batch Settlement
// =============================================================================

/// Trigger batch submission/settlement
#[derive(Debug, serde::Deserialize)]
pub struct SettleBatchRequest {
    pub batch_id: Uuid,
    pub tx_hash: Option<String>,
    pub block_number: Option<u64>,
    pub gas_used: Option<u64>,
}

#[derive(Debug, serde::Serialize)]
pub struct SettleBatchResponse {
    pub batch_id: Uuid,
    pub status: X402BatchStatus,
    pub tx_hash: Option<String>,
    pub block_number: Option<u64>,
    pub gas_used: Option<u64>,
    pub message: String,
}

#[instrument(skip(state, payload))]
pub async fn settle_batch(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(payload): Json<SettleBatchRequest>,
) -> Result<Json<SettleBatchResponse>, ApiError> {
    let batch_id = payload.batch_id;
    let tx_hash = payload
        .tx_hash
        .as_ref()
        .map(|hash| {
            parse_hash256(hash).map_err(|e| {
                ApiError::new(
                    ErrorCode::InvalidFieldValue,
                    format!("Invalid tx_hash: {}", e),
                )
            })?;
            Ok::<_, ApiError>(hash.clone())
        })
        .transpose()?;

    info!(
        batch_id = %batch_id,
        has_tx_hash = payload.tx_hash.is_some(),
        "Triggering batch settlement"
    );

    // Fetch batch from database
    let batch = state.x402_repository.get_batch(batch_id).await.map_err(|e| {
        ApiError::new(
            ErrorCode::InternalError,
            format!("Failed to fetch batch: {}", e),
        )
    })?;

    let batch = batch.ok_or_else(|| {
        ApiError::new(ErrorCode::BatchNotFound, format!("Batch {} not found", batch_id))
    })?;

    ensure_admin(&auth, batch.tenant_id.0, batch.store_id.0)
        .map_err(|(_, msg)| ApiError::new(ErrorCode::InsufficientPermissions, msg))?;

    match batch.status {
        X402BatchStatus::Committed => {
            let tx_hash = tx_hash.ok_or_else(|| {
                ApiError::new(
                    ErrorCode::InvalidFieldValue,
                    "tx_hash is required when batch is 'committed'",
                )
            })?;

            state
                .x402_repository
                .submit_batch(batch_id, &tx_hash)
                .await
                .map_err(|e| ApiError::from(e))?;

            if let Some(block_number) = payload.block_number {
                state
                    .x402_repository
                    .settle_batch(batch_id, &tx_hash, block_number, payload.gas_used)
                    .await
                    .map_err(|e| ApiError::from(e))?;

                Ok(Json(SettleBatchResponse {
                    batch_id,
                    status: X402BatchStatus::Settled,
                    tx_hash: Some(tx_hash),
                    block_number: payload.block_number,
                    gas_used: payload.gas_used,
                    message: "Batch submitted and settled".to_string(),
                }))
            } else {
                Ok(Json(SettleBatchResponse {
                    batch_id,
                    status: X402BatchStatus::Submitted,
                    tx_hash: Some(tx_hash),
                    block_number: None,
                    gas_used: None,
                    message: "Batch submission recorded".to_string(),
                }))
            }
        }
        X402BatchStatus::Submitted => {
            let tx_hash = match (tx_hash.clone(), batch.tx_hash.clone()) {
                (Some(provided), Some(stored)) => {
                    if provided != stored {
                        return Err(ApiError::new(
                            ErrorCode::InvalidFieldValue,
                            "tx_hash does not match already submitted batch",
                        ));
                    }
                    provided
                }
                (Some(provided), None) => provided,
                (None, Some(stored)) => stored,
                (None, None) => {
                    return Err(ApiError::new(
                        ErrorCode::InvalidFieldValue,
                        "tx_hash is required when batch is 'submitted'",
                    ))
                }
            };

            let block_number = payload.block_number.ok_or_else(|| {
                ApiError::new(
                    ErrorCode::InvalidFieldValue,
                    "block_number is required when batch is 'submitted'",
                )
            })?;

            state
                .x402_repository
                .settle_batch(batch_id, &tx_hash, block_number, payload.gas_used)
                .await
                .map_err(|e| ApiError::from(e))?;

            Ok(Json(SettleBatchResponse {
                batch_id,
                status: X402BatchStatus::Settled,
                tx_hash: Some(tx_hash),
                block_number: Some(block_number),
                gas_used: payload.gas_used,
                message: "Batch settlement confirmed".to_string(),
            }))
        }
        X402BatchStatus::Settled => {
            if let Some(provided_tx_hash) = tx_hash {
                if let Some(stored_tx_hash) = batch.tx_hash.as_ref() {
                    if provided_tx_hash != *stored_tx_hash {
                        return Err(ApiError::new(
                            ErrorCode::InvalidFieldValue,
                            "tx_hash does not match existing settled batch",
                        ));
                    }
                }
            }
            if let Some(provided_block_number) = payload.block_number {
                if let Some(stored_block_number) = batch.block_number {
                    if provided_block_number != stored_block_number {
                        return Err(ApiError::new(
                            ErrorCode::InvalidFieldValue,
                            "block_number does not match existing settled batch",
                        ));
                    }
                }
            }
            if let Some(provided_gas_used) = payload.gas_used {
                if let Some(stored_gas_used) = batch.gas_used {
                    if provided_gas_used != stored_gas_used {
                        return Err(ApiError::new(
                            ErrorCode::InvalidFieldValue,
                            "gas_used does not match existing settled batch",
                        ));
                    }
                }
            }

            Ok(Json(SettleBatchResponse {
                batch_id,
                status: X402BatchStatus::Settled,
                tx_hash: batch.tx_hash,
                block_number: batch.block_number,
                gas_used: batch.gas_used,
                message: "Batch already settled".to_string(),
            }))
        }
        _ => Err(ApiError::new(
            ErrorCode::InvalidStateTransition,
            format!(
                "Batch settlement is only valid for committed, submitted, or settled batches, current status: {:?}",
                batch.status
            ),
        )),
    }
}

// =============================================================================
// Create/Commit Batch
// =============================================================================

/// Request to create and commit a new batch
#[derive(Debug, serde::Deserialize)]
pub struct CreateBatchRequest {
    pub tenant_id: Uuid,
    pub store_id: Uuid,
    pub network: X402Network,
    /// Intent IDs to include in batch (if empty, auto-select pending intents)
    pub intent_ids: Option<Vec<Uuid>>,
    /// Maximum number of intents to include
    pub max_size: Option<usize>,
}

#[derive(Debug, serde::Serialize)]
pub struct CreateBatchResponse {
    pub batch_id: Uuid,
    pub status: X402BatchStatus,
    pub payment_count: u32,
    pub merkle_root: Option<String>,
    pub sequence_range: (u64, u64),
}

#[instrument(skip(state, payload))]
pub async fn create_batch(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(payload): Json<CreateBatchRequest>,
) -> Result<Json<CreateBatchResponse>, ApiError> {
    info!(
        tenant_id = %payload.tenant_id,
        store_id = %payload.store_id,
        network = ?payload.network,
        "Creating payment batch"
    );

    let tenant_id = TenantId::from_uuid(payload.tenant_id);
    let store_id = StoreId::from_uuid(payload.store_id);
    let max_size = payload.max_size.unwrap_or(X402_DEFAULT_BATCH_SIZE);
    if max_size == 0 {
        return Err(ApiError::new(
            ErrorCode::InvalidFieldValue,
            "max_size must be greater than 0",
        ));
    }
    if max_size > X402_MAX_BATCH_SIZE {
        return Err(ApiError::new(
            ErrorCode::BatchTooLarge,
            format!("max_size exceeds maximum of {}", X402_MAX_BATCH_SIZE),
        ));
    }

    ensure_admin(&auth, tenant_id.0, store_id.0)
        .map_err(|(_, msg)| ApiError::new(ErrorCode::InsufficientPermissions, msg))?;

    let intents = if let Some(payload_intent_ids) =
        payload.intent_ids.as_ref().filter(|ids| !ids.is_empty())
    {
        if payload_intent_ids.len() > max_size {
            return Err(ApiError::new(
                ErrorCode::BatchTooLarge,
                "Requested intent_ids exceed batch size limit",
            ));
        }

        let mut seen = HashSet::with_capacity(payload_intent_ids.len());
        let mut intent_ids = Vec::with_capacity(payload_intent_ids.len());
        for intent_id in payload_intent_ids {
            if !seen.insert(*intent_id) {
                return Err(ApiError::new(
                    ErrorCode::InvalidFieldValue,
                    "Duplicate intent_id in intent_ids",
                ));
            }
            intent_ids.push(*intent_id);
        }

        let mut intents = Vec::with_capacity(intent_ids.len());
        for intent_id in &intent_ids {
            let intent = state
                .x402_repository
                .get_intent(*intent_id)
                .await
                .map_err(|e| {
                    ApiError::new(
                        ErrorCode::InternalError,
                        format!("Failed to fetch intent: {}", e),
                    )
                })?
                .ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::ResourceNotFound,
                        format!("Intent {} not found", intent_id),
                    )
                })?;

            if intent.tenant_id != tenant_id || intent.store_id != store_id {
                return Err(ApiError::new(
                    ErrorCode::InvalidFieldValue,
                    "Intent tenant/store mismatch",
                ));
            }
            if intent.network != payload.network {
                return Err(ApiError::new(
                    ErrorCode::InvalidFieldValue,
                    "Intent network mismatch",
                ));
            }
            if intent.status != X402IntentStatus::Sequenced {
                return Err(ApiError::new(
                    ErrorCode::InvalidFieldValue,
                    "Only sequenced intents can be batched",
                ));
            }
            intents.push(intent);
        }

        intents.sort_by_key(|i| i.sequence_number.unwrap_or(0));
        intents
    } else {
        // Fetch pending intents for this tenant/store/network
        state
            .x402_repository
            .get_pending_intents_for_batch(&tenant_id, &store_id, payload.network, max_size as u32)
            .await
            .map_err(|e| {
                ApiError::new(
                    ErrorCode::InternalError,
                    format!("Failed to fetch pending intents: {}", e),
                )
            })?
    };

    if intents.is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidFieldValue,
            "No pending intents found for batching",
        ));
    }

    // Create new batch
    let mut batch = X402PaymentBatch::new(tenant_id.clone(), store_id.clone(), payload.network);

    // Add intents to batch
    for intent in &intents {
        batch.add_payment(intent);
    }

    // Persist batch
    state
        .x402_repository
        .insert_batch(&batch)
        .await
        .map_err(|e| {
            ApiError::new(
                ErrorCode::InternalError,
                format!("Failed to persist batch: {}", e),
            )
        })?;

    // Compute Merkle root + commit batch
    let (merkle_root, _state_root) = match state
        .x402_repository
        .commit_batch_with_merkle(batch.batch_id, &tenant_id, &store_id)
        .await
    {
        Ok(result) => result,
        Err(e) => {
            let _ = state
                .x402_repository
                .mark_batch_failed_if_pending(batch.batch_id)
                .await;
            return Err(ApiError::new(
                ErrorCode::InternalError,
                format!("Failed to commit batch: {}", e),
            ));
        }
    };

    Ok(Json(CreateBatchResponse {
        batch_id: batch.batch_id,
        status: X402BatchStatus::Committed,
        payment_count: batch.payment_count,
        merkle_root: Some(format!("0x{}", hex::encode(merkle_root))),
        sequence_range: (batch.sequence_start, batch.sequence_end),
    }))
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Parse a hex string into a 32-byte hash
fn parse_hash256(s: &str) -> Result<Hash256, String> {
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    bytes
        .try_into()
        .map_err(|_| "Expected 32 bytes for hash".to_string())
}

fn validate_length(value: &str, field_name: &str, max_len: usize) -> Result<(), ApiError> {
    if value.len() > max_len {
        return Err(ApiError::new(
            ErrorCode::PayloadTooLarge,
            format!("{} must be at most {} characters", field_name, max_len),
        ));
    }

    if value.trim().is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidFieldValue,
            format!("{} cannot be empty", field_name),
        ));
    }

    Ok(())
}

fn validate_hex_string(
    value: &str,
    field_name: &str,
    max_len: usize,
) -> Result<(), ApiError> {
    if value.len() > max_len {
        return Err(ApiError::new(
            ErrorCode::PayloadTooLarge,
            format!(
                "{} exceeds maximum length of {} characters",
                field_name, max_len
            ),
        ));
    }

    let value = value.trim();
    if value.is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidFieldValue,
            format!("{} cannot be empty", field_name),
        ));
    }

    let hex_part = value.strip_prefix("0x").unwrap_or(value);
    if hex_part.is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidFieldValue,
            format!(
                "{} must be a hexadecimal string",
                field_name
            ),
        ));
    }

    if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::new(
            ErrorCode::InvalidFieldValue,
            format!("{} must be a valid hex string", field_name),
        ));
    }

    if hex_part.len() % 2 != 0 {
        return Err(ApiError::new(
            ErrorCode::InvalidFieldValue,
            format!("{} hex length must be even", field_name),
        ));
    }

    Ok(())
}

/// Parse a hex string into a 64-byte signature
/// Supports both Ed25519 (64 bytes) and Ethereum ECDSA (65 bytes with recovery byte)
fn parse_signature64(s: &str) -> Result<Signature64, String> {
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;

    match bytes.len() {
        64 => bytes
            .try_into()
            .map_err(|_| "Failed to convert 64 bytes to signature".to_string()),
        65 => {
            // Ethereum ECDSA signature: r (32) || s (32) || v (1)
            // Strip the recovery byte and use r || s
            let sig_bytes: [u8; 64] = bytes[..64]
                .try_into()
                .map_err(|_| "Failed to extract 64 bytes from ECDSA signature".to_string())?;
            Ok(sig_bytes)
        }
        n => Err(format!("Expected 64 or 65 bytes for signature, got {}", n)),
    }
}

// =============================================================================
// Router
// =============================================================================

use axum::{
    routing::{get, post},
    Router,
};

/// Create the x402 payment router
pub fn x402_router() -> Router<AppState> {
    Router::new()
        .route("/payments", post(submit_payment_intent))
        .route("/payments", get(list_payment_intents))
        .route("/payments/:intent_id", get(get_payment_intent))
        .route("/payments/:intent_id/receipt", get(get_payment_receipt))
        .route("/batches", post(create_batch))
        .route("/batches/:batch_id", get(get_batch))
        .route("/batches/settle", post(settle_batch))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hash256() {
        let hash = "0x0101010101010101010101010101010101010101010101010101010101010101";
        let result = parse_hash256(hash).unwrap();
        assert_eq!(result, [0x01; 32]);
    }

    #[test]
    fn test_parse_hash256_no_prefix() {
        let hash = "0202020202020202020202020202020202020202020202020202020202020202";
        let result = parse_hash256(hash).unwrap();
        assert_eq!(result, [0x02; 32]);
    }

    #[test]
    fn test_parse_signature64() {
        let sig = "0x".to_owned() + &"03".repeat(64);
        let result = parse_signature64(&sig).unwrap();
        assert_eq!(result, [0x03; 64]);
    }

    #[test]
    fn test_parse_hash256_invalid() {
        assert!(parse_hash256("invalid").is_err());
        assert!(parse_hash256("0x0102").is_err()); // too short
    }

    #[test]
    fn test_validate_length() {
        assert!(validate_length("abc", "field", 4).is_ok());
        assert!(validate_length("", "field", 4).is_err());
        assert!(validate_length("abcde", "field", 4).is_err());
    }

    #[test]
    fn test_validate_hex_string() {
        assert!(
            validate_hex_string("0xabcdef", "address", X402_MAX_ADDRESS_LEN).is_ok()
        );
        assert!(
            validate_hex_string("abcdef", "address", X402_MAX_ADDRESS_LEN).is_ok()
        );
        assert!(validate_hex_string("0x", "address", X402_MAX_ADDRESS_LEN).is_err());
        assert!(validate_hex_string("0xxyz", "address", X402_MAX_ADDRESS_LEN).is_err());
        assert!(validate_hex_string("abc", "address", X402_MAX_ADDRESS_LEN).is_err());
    }
}
