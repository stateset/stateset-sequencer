//! HTTP 402 Payment Required challenge/response integration tests.
//!
//! Exercises the x402 payment-gated route flow end to end:
//!
//! 1. `GET <paid resource>` without `X-Payment` -> 402 + JSON payment requirements
//! 2. Agent signs a payment intent (Ed25519, domain `X402_PAYMENT_V1`)
//! 3. `GET <paid resource>` with `X-Payment: base64(JSON intent)` -> 200 +
//!    `X-Payment-Receipt` header
//! 4. Replaying the same intent (same nonce) is rejected
//!
//! These tests require DATABASE_URL to be set; they skip gracefully otherwise.

#![allow(clippy::clone_on_copy)]

mod common;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

use stateset_sequencer::api::middleware::{
    PaymentRequiredConfig, PaymentRequiredState, X_PAYMENT_HEADER, X_PAYMENT_RECEIPT_HEADER,
};
use stateset_sequencer::auth::{
    ApiKeyRecord, ApiKeyValidator, AuthMiddlewareState, Authenticator, Permissions, RateLimiter,
    RequestLimits,
};
use stateset_sequencer::domain::{X402Asset, X402Network};
use stateset_sequencer::infra::{
    PayloadEncryption, PgAgentKeyRegistry, PgCommitmentEngine, PgEventStore, PgSequencer,
    PgVesCommitmentEngine, PgVesComplianceProofStore, PgVesValidityProofStore, PgX402Repository,
    SchemaValidationMode, VesSequencer,
};
use stateset_sequencer::metrics::MetricsRegistry;
use stateset_sequencer::server::AppState;

const TEST_ADMIN_KEY: &str = "ss_test_x402_gate_key_12345";
const PREMIUM_PATH: &str = "/api/v1/x402/premium/insights";
const PRICE: u64 = 10_000; // 0.01 USDC
const PAY_TO: &str = "0x0000000000000000000000000000000000000402";

// ============================================================================
// Test Helpers
// ============================================================================

/// Serialize migration setup: tests run concurrently in one process, and
/// concurrent `CREATE EXTENSION` / migrator runs race on system catalogs.
static MIGRATIONS: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

async fn connect_db() -> Option<sqlx::PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&url)
        .await
        .ok()?;
    // Idempotent; makes the tests runnable against a fresh database.
    MIGRATIONS
        .get_or_init(|| async {
            stateset_sequencer::migrations::run_postgres(&pool)
                .await
                .expect("failed to run migrations");
        })
        .await;
    Some(pool)
}

/// Create full application state for testing (mirrors api_integration_test.rs).
async fn create_test_state(pool: sqlx::PgPool) -> AppState {
    let payload_encryption = Arc::new(PayloadEncryption::disabled());
    let api_key_validator = Arc::new(ApiKeyValidator::new());
    let api_key_store = Arc::new(stateset_sequencer::auth::PgApiKeyStore::new(pool.clone()));

    let sequencer = Arc::new(PgSequencer::new(pool.clone(), payload_encryption.clone()));
    let event_store = Arc::new(PgEventStore::new(pool.clone(), payload_encryption.clone()));
    let commitment_engine = Arc::new(PgCommitmentEngine::new(pool.clone()));
    let commitment_reader = Arc::new(PgCommitmentEngine::new(pool.clone()));
    let ves_commitment_engine = Arc::new(PgVesCommitmentEngine::new(pool.clone()));
    let ves_commitment_reader = Arc::new(PgVesCommitmentEngine::new(pool.clone()));
    let ves_validity_proof_store = Arc::new(PgVesValidityProofStore::new(
        pool.clone(),
        payload_encryption.clone(),
    ));
    let ves_compliance_proof_store = Arc::new(PgVesComplianceProofStore::new(
        pool.clone(),
        payload_encryption,
    ));

    let cache_manager = Arc::new(stateset_sequencer::infra::CacheManager::new());
    let agent_key_registry = Arc::new(PgAgentKeyRegistry::new(pool.clone()));
    let ves_sequencer = Arc::new(VesSequencer::new(pool.clone(), agent_key_registry.clone()));
    let ves_sequencer_reader =
        Arc::new(VesSequencer::new(pool.clone(), agent_key_registry.clone()));
    let schema_store = Arc::new(stateset_sequencer::infra::PgSchemaStore::new(pool.clone()));
    let x402_repository = Arc::new(PgX402Repository::new(pool.clone()));
    let metrics = Arc::new(MetricsRegistry::new());

    AppState {
        read_pool: pool.clone(),
        sequencer,
        event_store,
        commitment_engine,
        commitment_reader,
        ves_commitment_engine,
        ves_commitment_reader,
        ves_validity_proof_store,
        ves_compliance_proof_store,
        anchor_service: None,
        ves_sequencer,
        ves_sequencer_reader,
        agent_key_registry,
        schema_store,
        metrics,
        cache_manager,
        x402_repository,
        schema_validation_mode: SchemaValidationMode::Disabled,
        request_limits: RequestLimits::default(),
        pool_monitor: None,
        circuit_breaker_registry: None,
        api_key_validator,
        api_key_store,
        public_registration_enabled: true,
        public_registration_limiter: None,
        trust_proxy_headers: false,
        audit_logger: None,
    }
}

fn test_gate_config() -> PaymentRequiredConfig {
    PaymentRequiredConfig {
        amount: PRICE,
        asset: X402Asset::Usdc,
        network: X402Network::SetChain,
        pay_to: PAY_TO.to_string(),
        description: Some("Premium x402 insights".to_string()),
    }
}

/// Build a router with the x402 payment-gated premium route mounted, behind
/// the normal auth middleware (same shape as server.rs `build_router`).
fn create_paid_router(state: AppState, config: PaymentRequiredConfig) -> axum::Router<()> {
    let api_key_validator = Arc::new(ApiKeyValidator::new());
    let key_hash = ApiKeyValidator::hash_key(TEST_ADMIN_KEY);
    api_key_validator.register_key(ApiKeyRecord {
        key_hash,
        tenant_id: Uuid::nil(),
        store_ids: vec![],
        permissions: Permissions::admin(),
        agent_id: None,
        active: true,
        rate_limit: None,
    });

    let authenticator = Arc::new(Authenticator::new(api_key_validator));
    let auth_state = AuthMiddlewareState {
        authenticator,
        require_auth: true,
        rate_limiter: None,
        credential_rate_limiter: Arc::new(RateLimiter::new(1000)),
        pool_monitor: None,
    };

    let gate = PaymentRequiredState::new(
        state.x402_repository.clone(),
        state.agent_key_registry.clone(),
        Arc::new(config),
    );

    let api = stateset_sequencer::api::router()
        .merge(stateset_sequencer::api::premium_router(gate))
        .layer(axum::middleware::from_fn_with_state(
            auth_state,
            stateset_sequencer::auth::auth_middleware,
        ));

    axum::Router::new().nest("/api", api).with_state::<()>(state)
}

/// Send a request and return status, headers, and parsed JSON body.
async fn send_request(
    app: &axum::Router<()>,
    method: Method,
    uri: &str,
    x_payment: Option<&str>,
) -> (StatusCode, HeaderMap, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("ApiKey {}", TEST_ADMIN_KEY));

    if let Some(payment) = x_payment {
        builder = builder.header(X_PAYMENT_HEADER, payment);
    }

    let mut request = builder.body(Body::from(Vec::new())).unwrap();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
    request.extensions_mut().insert(ConnectInfo(addr));

    let response = app
        .clone()
        .into_service::<Body>()
        .oneshot(request)
        .await
        .unwrap();

    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();

    let json = if bytes.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }))
    };

    (status, headers, json)
}

struct SignedPayment {
    header_value: String,
}

/// Build a signed x402 payment intent and encode it as an `X-Payment` header
/// value: base64(JSON), where the JSON is the same `SubmitX402PaymentRequest`
/// shape that `POST /api/v1/x402/payments` accepts (see cli/src/x402/client.js).
#[allow(clippy::too_many_arguments)]
fn build_signed_payment(
    signing_key: &SigningKey,
    tenant_id: Uuid,
    store_id: Uuid,
    agent_id: Uuid,
    payee: &str,
    amount: u64,
    nonce: u64,
    valid_until: u64,
) -> SignedPayment {
    let public_key = signing_key.verifying_key();
    let payer_address = format!("0x{}", hex::encode(public_key.as_bytes()));

    let signing_hash = PgX402Repository::compute_signing_hash(
        &payer_address,
        payee,
        amount,
        &X402Asset::Usdc,
        &X402Network::SetChain,
        X402Network::SetChain.chain_id(),
        valid_until,
        nonce,
    );
    let signature = signing_key.sign(&signing_hash);

    let body = json!({
        "tenant_id": tenant_id,
        "store_id": store_id,
        "agent_id": agent_id,
        "payer_address": payer_address,
        "payee_address": payee,
        "amount": amount,
        "asset": "usdc",
        "network": "set_chain",
        "valid_until": valid_until,
        "nonce": nonce,
        "signing_hash": format!("0x{}", hex::encode(signing_hash)),
        "payer_signature": format!("0x{}", hex::encode(signature.to_bytes())),
        "payer_public_key": format!("0x{}", hex::encode(public_key.to_bytes())),
        "description": "402 challenge payment",
    });

    let header_value =
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&body).unwrap());

    SignedPayment { header_value }
}

fn fresh_nonce() -> u64 {
    (Utc::now().timestamp_millis() as u64) * 1000 + (rand::random::<u64>() % 1000)
}

// ============================================================================
// 402 Challenge Tests
// ============================================================================

#[tokio::test]
async fn test_paid_route_without_payment_returns_402_with_requirements() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };
    let state = create_test_state(pool).await;
    let app = create_paid_router(state, test_gate_config());

    let (status, headers, body) = send_request(&app, Method::GET, PREMIUM_PATH, None).await;

    assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "body: {}", body);
    assert_eq!(body["error"]["code"], "PAYMENT_REQUIRED");
    assert_eq!(
        headers
            .get("x-error-code")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        "PAYMENT_REQUIRED"
    );

    // The challenge must advertise the payment requirements.
    let req = &body["error"]["details"];
    assert_eq!(req["amount"], PRICE, "requirements: {}", req);
    assert_eq!(req["asset"], "usdc");
    assert_eq!(req["network"], "set_chain");
    assert_eq!(req["pay_to"], PAY_TO);
    assert_eq!(req["resource"], PREMIUM_PATH);
    assert_eq!(req["chain_id"], X402Network::SetChain.chain_id());
    assert!(req["x402_version"].is_u64());
}

#[tokio::test]
async fn test_paid_route_with_malformed_header_returns_402() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };
    let state = create_test_state(pool).await;
    let app = create_paid_router(state, test_gate_config());

    // Not valid base64
    let (status, _, body) =
        send_request(&app, Method::GET, PREMIUM_PATH, Some("!!not-base64!!")).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "body: {}", body);
    assert_eq!(body["error"]["code"], "PAYMENT_REQUIRED");

    // Valid base64, not valid JSON
    let garbage = base64::engine::general_purpose::STANDARD.encode(b"not json");
    let (status, _, body) =
        send_request(&app, Method::GET, PREMIUM_PATH, Some(garbage.as_str())).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "body: {}", body);
    assert_eq!(body["error"]["code"], "PAYMENT_REQUIRED");
    // Challenge is re-issued so the agent can retry.
    assert_eq!(body["error"]["details"]["amount"], PRICE);
}

#[tokio::test]
async fn test_paid_route_with_bad_signature_rejected() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };
    let state = create_test_state(pool).await;
    let app = create_paid_router(state, test_gate_config());

    let signing_key = SigningKey::generate(&mut OsRng);
    let now = Utc::now().timestamp() as u64;
    let payment = build_signed_payment(
        &signing_key,
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        PAY_TO,
        PRICE,
        fresh_nonce(),
        now + 3600,
    );

    // Corrupt the signature (flip bytes inside payer_signature hex).
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&payment.header_value)
        .unwrap();
    let mut intent: Value = serde_json::from_slice(&decoded).unwrap();
    let sig = intent["payer_signature"].as_str().unwrap().to_string();
    let mut sig_bytes = hex::decode(sig.trim_start_matches("0x")).unwrap();
    sig_bytes[10] ^= 0xff;
    intent["payer_signature"] = json!(format!("0x{}", hex::encode(sig_bytes)));
    let tampered = base64::engine::general_purpose::STANDARD
        .encode(serde_json::to_vec(&intent).unwrap());

    let (status, _, body) =
        send_request(&app, Method::GET, PREMIUM_PATH, Some(tampered.as_str())).await;

    // Matches the existing submit endpoint's taxonomy for a failed signature.
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {}", body);
    assert_eq!(body["error"]["code"], "SIGNATURE_VERIFICATION_FAILED");
}

#[tokio::test]
async fn test_paid_route_with_insufficient_amount_rejected() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };
    let state = create_test_state(pool).await;
    let app = create_paid_router(state, test_gate_config());

    let signing_key = SigningKey::generate(&mut OsRng);
    let now = Utc::now().timestamp() as u64;
    // Correctly signed, but for less than the advertised price.
    let payment = build_signed_payment(
        &signing_key,
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        PAY_TO,
        PRICE - 1,
        fresh_nonce(),
        now + 3600,
    );

    let (status, _, body) = send_request(
        &app,
        Method::GET,
        PREMIUM_PATH,
        Some(payment.header_value.as_str()),
    )
    .await;

    assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "body: {}", body);
    assert_eq!(body["error"]["code"], "PAYMENT_REQUIRED");
    // Re-issued requirements tell the agent the correct price.
    assert_eq!(body["error"]["details"]["amount"], PRICE);
}

#[tokio::test]
async fn test_paid_route_with_wrong_recipient_rejected() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };
    let state = create_test_state(pool).await;
    let app = create_paid_router(state, test_gate_config());

    let signing_key = SigningKey::generate(&mut OsRng);
    let now = Utc::now().timestamp() as u64;
    let payment = build_signed_payment(
        &signing_key,
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        "0x00000000000000000000000000000000000000ff", // not the configured pay_to
        PRICE,
        fresh_nonce(),
        now + 3600,
    );

    let (status, _, body) = send_request(
        &app,
        Method::GET,
        PREMIUM_PATH,
        Some(payment.header_value.as_str()),
    )
    .await;

    assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "body: {}", body);
    assert_eq!(body["error"]["code"], "PAYMENT_REQUIRED");
}

#[tokio::test]
async fn test_paid_route_with_expired_intent_rejected() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };
    let state = create_test_state(pool).await;
    let app = create_paid_router(state, test_gate_config());

    let signing_key = SigningKey::generate(&mut OsRng);
    let now = Utc::now().timestamp() as u64;
    let payment = build_signed_payment(
        &signing_key,
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        PAY_TO,
        PRICE,
        fresh_nonce(),
        now - 10, // already expired
    );

    let (status, _, body) = send_request(
        &app,
        Method::GET,
        PREMIUM_PATH,
        Some(payment.header_value.as_str()),
    )
    .await;

    // Same taxonomy as the submit endpoint's expiry check.
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {}", body);
    assert_eq!(body["error"]["code"], "INVALID_FIELD_VALUE");
}

// ============================================================================
// Successful Payment + Receipt Tests
// ============================================================================

#[tokio::test]
async fn test_paid_route_with_valid_payment_returns_200_and_receipt() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };
    let state = create_test_state(pool.clone()).await;
    let app = create_paid_router(state, test_gate_config());

    let signing_key = SigningKey::generate(&mut OsRng);
    let now = Utc::now().timestamp() as u64;
    let payment = build_signed_payment(
        &signing_key,
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        PAY_TO,
        PRICE,
        fresh_nonce(),
        now + 3600,
    );

    let (status, headers, body) = send_request(
        &app,
        Method::GET,
        PREMIUM_PATH,
        Some(payment.header_value.as_str()),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {}", body);
    // The premium resource itself is served.
    assert_eq!(body["tier"], "premium");

    // The receipt header is present and decodes to a structured receipt.
    let receipt_header = headers
        .get(X_PAYMENT_RECEIPT_HEADER)
        .and_then(|v| v.to_str().ok())
        .expect("X-Payment-Receipt header missing");
    let receipt_bytes = base64::engine::general_purpose::STANDARD
        .decode(receipt_header)
        .expect("receipt header is not valid base64");
    let receipt: Value = serde_json::from_slice(&receipt_bytes).expect("receipt is not JSON");

    assert_eq!(receipt["status"], "sequenced", "receipt: {}", receipt);
    assert!(receipt["sequence_number"].as_u64().unwrap() >= 1);
    let intent_id = receipt["intent_id"].as_str().expect("intent_id missing");
    let intent_uuid = Uuid::parse_str(intent_id).expect("intent_id is not a UUID");
    assert!(receipt["receipt_url"]
        .as_str()
        .unwrap()
        .contains(&format!("/api/v1/x402/payments/{}/receipt", intent_id)));

    // The intent entered the normal pipeline: it is persisted and sequenced.
    let repo = PgX402Repository::new(pool);
    let stored = repo
        .get_intent(intent_uuid)
        .await
        .expect("failed to fetch intent")
        .expect("paid intent was not persisted");
    assert_eq!(stored.amount, PRICE);
    assert_eq!(stored.payee_address, PAY_TO);
    assert!(stored.sequence_number.is_some());
    assert_eq!(stored.resource_uri.as_deref(), Some(PREMIUM_PATH));
}

// ============================================================================
// Replay Protection Tests
// ============================================================================

#[tokio::test]
async fn test_paid_route_replayed_nonce_rejected() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };
    let state = create_test_state(pool).await;
    let app = create_paid_router(state, test_gate_config());

    let signing_key = SigningKey::generate(&mut OsRng);
    let now = Utc::now().timestamp() as u64;
    let payment = build_signed_payment(
        &signing_key,
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        PAY_TO,
        PRICE,
        fresh_nonce(),
        now + 3600,
    );

    // First presentation succeeds.
    let (status, headers, body) = send_request(
        &app,
        Method::GET,
        PREMIUM_PATH,
        Some(payment.header_value.as_str()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {}", body);
    assert!(headers.get(X_PAYMENT_RECEIPT_HEADER).is_some());

    // Replaying the exact same signed intent must be rejected: the nonce is
    // burned. Same taxonomy as the submit endpoint's nonce conflict.
    let (status, headers, body) = send_request(
        &app,
        Method::GET,
        PREMIUM_PATH,
        Some(payment.header_value.as_str()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {}", body);
    assert_eq!(body["error"]["code"], "INVALID_FIELD_VALUE");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("nonce"),
        "body: {}",
        body
    );
    assert!(headers.get(X_PAYMENT_RECEIPT_HEADER).is_none());
}

// ============================================================================
// Unpaid Routes Unaffected
// ============================================================================

#[tokio::test]
async fn test_unpaid_routes_do_not_require_payment() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };
    let state = create_test_state(pool).await;
    let app = create_paid_router(state, test_gate_config());

    // A normal (non-gated) x402 endpoint still works without X-Payment.
    let tenant = Uuid::new_v4();
    let (status, _, body) = send_request(
        &app,
        Method::GET,
        &format!("/api/v1/x402/payments?tenant_id={}", tenant),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {}", body);
}
