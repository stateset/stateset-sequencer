//! REST API integration tests for StateSet Sequencer.
//!
//! These tests verify the HTTP endpoints work correctly with the full application stack.
//! They require DATABASE_URL to be set and run with `cargo test -- --ignored`.

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

use stateset_sequencer::auth::{
    ApiKeyRecord, ApiKeyValidator, AuthMiddlewareState, Authenticator, Permissions, RateLimiter,
    RequestLimits,
};
use stateset_sequencer::domain::{
    AgentId, EntityType, EventBatch, EventEnvelope, EventType, StoreId, TenantId,
};
use stateset_sequencer::infra::{
    IngestService, PayloadEncryption, PgAgentKeyRegistry,
    PgCommitmentEngine, PgEventStore, PgSequencer, PgVesCommitmentEngine,
    PgVesComplianceProofStore, PgVesValidityProofStore, SchemaValidationMode, VesSequencer,
};
use stateset_sequencer::metrics::MetricsRegistry;
use stateset_sequencer::server::AppState;

use common::*;

// ============================================================================
// Test Helpers
// ============================================================================

async fn connect_db() -> Option<sqlx::PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&url)
        .await
        .ok()?;
    Some(pool)
}

/// Create full application state for testing.
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
    let ves_sequencer_reader = Arc::new(VesSequencer::new(pool.clone(), agent_key_registry.clone()));
    let schema_store = Arc::new(stateset_sequencer::infra::PgSchemaStore::new(pool.clone()));
    let x402_repository = Arc::new(stateset_sequencer::infra::PgX402Repository::new(pool.clone()));
    let metrics = Arc::new(MetricsRegistry::new());

    AppState {
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
        // Use disabled mode for tests by default (to not break existing tests)
        schema_validation_mode: SchemaValidationMode::Disabled,
        request_limits: RequestLimits::default(),
        pool_monitor: None,
        circuit_breaker_registry: None,
        api_key_validator,
        api_key_store,
        public_registration_enabled: true,
        public_registration_limiter: None,
        audit_logger: None,
    }
}

/// Create a test router with optional authentication.
fn create_test_router(state: AppState, require_auth: bool) -> axum::Router<()> {
    let api_key_validator = Arc::new(ApiKeyValidator::new());

    // Register a test admin API key
    let test_key = "sk_test_integration_key_12345";
    let key_hash = ApiKeyValidator::hash_key(test_key);
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
        require_auth,
        rate_limiter: None,
    };

    let public_api = stateset_sequencer::api::public_router();
    let api = stateset_sequencer::api::router().layer(axum::middleware::from_fn_with_state(
        auth_state,
        stateset_sequencer::auth::auth_middleware,
    ));

    axum::Router::new()
        .nest("/api", public_api)
        .nest("/api", api)
        .with_state::<()>(state)
}

/// Send a request to the test router.
async fn send_request(
    app: &axum::Router<()>,
    method: Method,
    uri: &str,
    body: Option<serde_json::Value>,
    api_key: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(uri);

    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }

    if let Some(key) = api_key {
        builder = builder.header("authorization", format!("ApiKey {}", key));
    }

    let body = body
        .map(|v| Body::from(serde_json::to_vec(&v).unwrap()))
        .unwrap_or_else(|| Body::from(Vec::new()));

    let response = app
        .clone()
        .into_service::<Body>()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();

    let status = response.status();
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
        serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }))
    };

    (status, json)
}

/// Insert test events directly into the database.
async fn seed_test_events(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    store_id: Uuid,
    count: usize,
) -> Vec<Uuid> {
    let payload_encryption = Arc::new(PayloadEncryption::disabled());
    let sequencer = PgSequencer::new(pool.clone(), payload_encryption);

    let agent_id = AgentId::new();
    let events: Vec<EventEnvelope> = (0..count)
        .map(|i| {
            EventEnvelope::new(
                TenantId::from_uuid(tenant_id),
                StoreId::from_uuid(store_id),
                EntityType::order(),
                format!("ord-test-{}", i),
                EventType::new("order.created"),
                json!({ "index": i, "amount": (i + 1) * 100 }),
                agent_id.clone(),
            )
        })
        .collect();

    let event_ids: Vec<Uuid> = events.iter().map(|e| e.event_id).collect();
    let batch = EventBatch::new(agent_id, events);
    sequencer.ingest(batch).await.unwrap();

    event_ids
}

// ============================================================================
// Health & Readiness Endpoint Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_public_agent_registration_rate_limited() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let mut state = create_test_state(pool).await;
    state.public_registration_limiter = Some(Arc::new(RateLimiter::new(1)));
    let app = create_test_router(state, true);

    let payload = json!({
        "name": "public-agent"
    });

    let (status, body) = send_request(
        &app,
        Method::POST,
        "/api/v1/agents/register",
        Some(payload.clone()),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], true);

    let (status, _) = send_request(
        &app,
        Method::POST,
        "/api/v1/agents/register",
        Some(payload),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
#[ignore]
async fn test_public_agent_registration_rejects_tenant_id() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let state = create_test_state(pool).await;
    let app = create_test_router(state, true);

    let payload = json!({
        "name": "public-agent",
        "tenantId": Uuid::new_v4()
    });

    let (status, body) = send_request(
        &app,
        Method::POST,
        "/api/v1/agents/register",
        Some(payload),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "TENANT_ID_NOT_ALLOWED");
}

#[tokio::test]
#[ignore]
async fn test_x402_list_requires_auth_and_tenant() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let state = create_test_state(pool).await;
    let app = create_test_router(state, true);

    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();
    let uri = format!(
        "/api/v1/x402/payments?tenant_id={}&store_id={}",
        tenant_id, store_id
    );

    let (status, _) = send_request(&app, Method::GET, &uri, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) =
        send_request(&app, Method::GET, "/api/v1/x402/payments", None, Some("sk_test_integration_key_12345"))
            .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "MISSING_REQUIRED_FIELD");

    let (status, _) =
        send_request(&app, Method::GET, &uri, None, Some("sk_test_integration_key_12345")).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
#[ignore]
async fn test_health_endpoint_returns_healthy() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let state = create_test_state(pool).await;
    let app = axum::Router::new()
        .route("/health", axum::routing::get(|| async {
            axum::Json(json!({ "status": "healthy" }))
        }))
        .with_state::<()>(state);

    let (status, body) = send_request(&app, Method::GET, "/health", None, None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "healthy");
}

// ============================================================================
// Event Ingestion Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_ingest_events_success() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let state = create_test_state(pool).await;
    let app = create_test_router(state, false);

    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();
    let agent_id = Uuid::new_v4();

    let event = TestEventBuilder::new()
        .tenant_id(tenant_id)
        .store_id(store_id)
        .source_agent(agent_id)
        .entity_type("order")
        .entity_id("ord-001")
        .event_type("order.created")
        .payload(order_created_payload("cust-123", 199.99))
        .build_json();

    let request_body = json!({
        "agent_id": agent_id.to_string(),
        "events": [event]
    });

    let (status, body) = send_request(
        &app,
        Method::POST,
        "/api/v1/events/ingest",
        Some(request_body),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {:?}", body);
    assert_eq!(body["events_accepted"], 1);
    assert_eq!(body["events_rejected"], 0);
    assert!(body["batch_id"].as_str().is_some());
    assert_eq!(body["assigned_sequence_start"], 1);
    assert_eq!(body["assigned_sequence_end"], 1);
    assert_eq!(body["head_sequence"], 1);
}

#[tokio::test]
#[ignore]
async fn test_ingest_events_batch_success() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let state = create_test_state(pool).await;
    let app = create_test_router(state, false);

    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();
    let agent_id = Uuid::new_v4();

    let events: Vec<serde_json::Value> = (0..10)
        .map(|i| {
            TestEventBuilder::new()
                .tenant_id(tenant_id)
                .store_id(store_id)
                .source_agent(agent_id)
                .entity_type("order")
                .entity_id(&format!("ord-{:03}", i))
                .event_type("order.created")
                .payload(order_created_payload(&format!("cust-{}", i), (i + 1) as f64 * 10.0))
                .build_json()
        })
        .collect();

    let request_body = json!({
        "agent_id": agent_id.to_string(),
        "events": events
    });

    let (status, body) = send_request(
        &app,
        Method::POST,
        "/api/v1/events/ingest",
        Some(request_body),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {:?}", body);
    assert_eq!(body["events_accepted"], 10);
    assert_eq!(body["events_rejected"], 0);
    assert_eq!(body["assigned_sequence_start"], 1);
    assert_eq!(body["assigned_sequence_end"], 10);
    assert_eq!(body["head_sequence"], 10);
}

#[tokio::test]
#[ignore]
async fn test_ingest_events_rejects_duplicate_event_id() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let state = create_test_state(pool).await;
    let app = create_test_router(state, false);

    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();
    let agent_id = Uuid::new_v4();
    let event_id = Uuid::new_v4();

    let event = TestEventBuilder::new()
        .event_id(event_id)
        .tenant_id(tenant_id)
        .store_id(store_id)
        .source_agent(agent_id)
        .build_json();

    let request_body = json!({
        "agent_id": agent_id.to_string(),
        "events": [event]
    });

    // First ingestion
    let (status, _) = send_request(
        &app,
        Method::POST,
        "/api/v1/events/ingest",
        Some(request_body.clone()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Second ingestion with same event_id
    let (status, body) = send_request(
        &app,
        Method::POST,
        "/api/v1/events/ingest",
        Some(request_body),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["events_accepted"], 0);
    assert_eq!(body["events_rejected"], 1);
    assert!(body["rejections"].as_array().unwrap().len() == 1);
}

#[tokio::test]
#[ignore]
async fn test_ingest_events_rejects_mixed_tenant_store() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let state = create_test_state(pool).await;
    let app = create_test_router(state, false);

    let agent_id = Uuid::new_v4();
    let tenant1 = Uuid::new_v4();
    let tenant2 = Uuid::new_v4();
    let store_id = Uuid::new_v4();

    let event1 = TestEventBuilder::new()
        .tenant_id(tenant1)
        .store_id(store_id)
        .source_agent(agent_id)
        .build_json();

    let event2 = TestEventBuilder::new()
        .tenant_id(tenant2)
        .store_id(store_id)
        .source_agent(agent_id)
        .build_json();

    let request_body = json!({
        "agent_id": agent_id.to_string(),
        "events": [event1, event2]
    });

    let (status, body) = send_request(
        &app,
        Method::POST,
        "/api/v1/events/ingest",
        Some(request_body),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {:?}", body);
}

// ============================================================================
// Event List & Head Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_list_events_success() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();

    // Seed events
    seed_test_events(&pool, tenant_id, store_id, 5).await;

    let state = create_test_state(pool).await;
    let app = create_test_router(state, false);

    let uri = format!(
        "/api/v1/events?tenant_id={}&store_id={}&from=1&limit=10",
        tenant_id, store_id
    );

    let (status, body) = send_request(&app, Method::GET, &uri, None, None).await;

    assert_eq!(status, StatusCode::OK, "body: {:?}", body);
    assert_eq!(body["count"], 5);
    assert!(body["events"].as_array().unwrap().len() == 5);
}

#[tokio::test]
#[ignore]
async fn test_list_events_pagination() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();

    // Seed 20 events
    seed_test_events(&pool, tenant_id, store_id, 20).await;

    let state = create_test_state(pool).await;
    let app = create_test_router(state, false);

    // First page
    let uri = format!(
        "/api/v1/events?tenant_id={}&store_id={}&from=1&limit=5",
        tenant_id, store_id
    );
    let (status, body) = send_request(&app, Method::GET, &uri, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["count"], 5);

    // Second page
    let uri = format!(
        "/api/v1/events?tenant_id={}&store_id={}&from=6&limit=5",
        tenant_id, store_id
    );
    let (status, body) = send_request(&app, Method::GET, &uri, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["count"], 5);
}

#[tokio::test]
#[ignore]
async fn test_get_head_success() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();

    // Seed 7 events
    seed_test_events(&pool, tenant_id, store_id, 7).await;

    let state = create_test_state(pool).await;
    let app = create_test_router(state, false);

    let uri = format!("/api/v1/head?tenant_id={}&store_id={}", tenant_id, store_id);
    let (status, body) = send_request(&app, Method::GET, &uri, None, None).await;

    assert_eq!(status, StatusCode::OK, "body: {:?}", body);
    assert_eq!(body["head_sequence"], 7);
}

#[tokio::test]
#[ignore]
async fn test_get_head_returns_zero_for_empty_store() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let state = create_test_state(pool).await;
    let app = create_test_router(state, false);

    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();

    let uri = format!("/api/v1/head?tenant_id={}&store_id={}", tenant_id, store_id);
    let (status, body) = send_request(&app, Method::GET, &uri, None, None).await;

    assert_eq!(status, StatusCode::OK, "body: {:?}", body);
    assert_eq!(body["head_sequence"], 0);
}

// ============================================================================
// Entity History Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_get_entity_history_success() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();
    let entity_id = "ord-history-test";

    // Create multiple events for the same entity
    let payload_encryption = Arc::new(PayloadEncryption::disabled());
    let sequencer = PgSequencer::new(pool.clone(), payload_encryption);
    let agent_id = AgentId::new();

    let events: Vec<EventEnvelope> = vec![
        EventEnvelope::new(
            TenantId::from_uuid(tenant_id),
            StoreId::from_uuid(store_id),
            EntityType::order(),
            entity_id.to_string(),
            EventType::new("order.created"),
            json!({ "status": "pending" }),
            agent_id.clone(),
        ),
        EventEnvelope::new(
            TenantId::from_uuid(tenant_id),
            StoreId::from_uuid(store_id),
            EntityType::order(),
            entity_id.to_string(),
            EventType::new("order.confirmed"),
            json!({ "status": "confirmed" }),
            agent_id.clone(),
        ),
        EventEnvelope::new(
            TenantId::from_uuid(tenant_id),
            StoreId::from_uuid(store_id),
            EntityType::order(),
            entity_id.to_string(),
            EventType::new("order.shipped"),
            json!({ "status": "shipped" }),
            agent_id.clone(),
        ),
    ];

    sequencer
        .ingest(EventBatch::new(agent_id, events))
        .await
        .unwrap();

    let state = create_test_state(pool).await;
    let app = create_test_router(state, false);

    let uri = format!(
        "/api/v1/entities/order/{}?tenant_id={}&store_id={}",
        entity_id, tenant_id, store_id
    );
    let (status, body) = send_request(&app, Method::GET, &uri, None, None).await;

    assert_eq!(status, StatusCode::OK, "body: {:?}", body);
    assert_eq!(body["entity_type"], "order");
    assert_eq!(body["entity_id"], entity_id);
    assert_eq!(body["count"], 3);
}

// ============================================================================
// Commitment Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_create_commitment_success() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();

    // Seed events
    seed_test_events(&pool, tenant_id, store_id, 10).await;

    let state = create_test_state(pool).await;
    let app = create_test_router(state, false);

    let request_body = json!({
        "tenant_id": tenant_id,
        "store_id": store_id,
        "sequence_start": 1,
        "sequence_end": 10
    });

    let (status, body) = send_request(
        &app,
        Method::POST,
        "/api/v1/commitments",
        Some(request_body),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {:?}", body);
    assert!(body["batch_id"].as_str().is_some());
    assert!(body["events_root"].as_str().is_some());
    assert_eq!(body["event_count"], 10);
}

#[tokio::test]
#[ignore]
async fn test_get_commitment_by_id() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();

    seed_test_events(&pool, tenant_id, store_id, 5).await;

    let state = create_test_state(pool).await;
    let app = create_test_router(state, false);

    // Create commitment
    let request_body = json!({
        "tenant_id": tenant_id,
        "store_id": store_id,
        "sequence_start": 1,
        "sequence_end": 5
    });

    let (status, body) = send_request(
        &app,
        Method::POST,
        "/api/v1/commitments",
        Some(request_body),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let batch_id = body["batch_id"].as_str().unwrap();

    // Get commitment by ID
    let uri = format!("/api/v1/commitments/{}", batch_id);
    let (status, body) = send_request(&app, Method::GET, &uri, None, None).await;

    assert_eq!(status, StatusCode::OK, "body: {:?}", body);
    assert_eq!(body["batch_id"], batch_id);
    assert_eq!(body["event_count"], 5);
}

#[tokio::test]
#[ignore]
async fn test_list_commitments() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();

    seed_test_events(&pool, tenant_id, store_id, 20).await;

    let state = create_test_state(pool).await;
    let app = create_test_router(state, false);

    // Create two commitments
    for (start, end) in [(1, 10), (11, 20)] {
        let request_body = json!({
            "tenant_id": tenant_id,
            "store_id": store_id,
            "sequence_start": start,
            "sequence_end": end
        });
        send_request(
            &app,
            Method::POST,
            "/api/v1/commitments",
            Some(request_body),
            None,
        )
        .await;
    }

    // List commitments
    let uri = format!(
        "/api/v1/commitments?tenant_id={}&store_id={}",
        tenant_id, store_id
    );
    let (status, body) = send_request(&app, Method::GET, &uri, None, None).await;

    assert_eq!(status, StatusCode::OK, "body: {:?}", body);
    assert!(body["commitments"].as_array().is_some());
}

// ============================================================================
// Inclusion Proof Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_get_inclusion_proof() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();

    seed_test_events(&pool, tenant_id, store_id, 10).await;

    let state = create_test_state(pool).await;
    let app = create_test_router(state, false);

    // Create commitment first
    let request_body = json!({
        "tenant_id": tenant_id,
        "store_id": store_id,
        "sequence_start": 1,
        "sequence_end": 10
    });

    let (status, body) = send_request(
        &app,
        Method::POST,
        "/api/v1/commitments",
        Some(request_body),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let batch_id = body["batch_id"].as_str().unwrap();

    // Get inclusion proof for sequence 5
    let uri = format!(
        "/api/v1/proofs/5?tenant_id={}&store_id={}&batch_id={}",
        tenant_id, store_id, batch_id
    );
    let (status, body) = send_request(&app, Method::GET, &uri, None, None).await;

    assert_eq!(status, StatusCode::OK, "body: {:?}", body);
    assert!(body["leaf_hash"].as_str().is_some());
    assert!(body["proof_path"].as_array().is_some());
    assert!(body["events_root"].as_str().is_some());
}

// ============================================================================
// Authentication Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_auth_required_rejects_unauthenticated() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let state = create_test_state(pool).await;
    let app = create_test_router(state, true); // require_auth = true

    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();

    let uri = format!("/api/v1/head?tenant_id={}&store_id={}", tenant_id, store_id);
    let (status, _) = send_request(&app, Method::GET, &uri, None, None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore]
async fn test_auth_accepts_valid_api_key() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let state = create_test_state(pool).await;
    let app = create_test_router(state, true);

    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();

    let uri = format!("/api/v1/head?tenant_id={}&store_id={}", tenant_id, store_id);
    let (status, body) = send_request(
        &app,
        Method::GET,
        &uri,
        None,
        Some("sk_test_integration_key_12345"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {:?}", body);
}

#[tokio::test]
#[ignore]
async fn test_auth_rejects_invalid_api_key() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let state = create_test_state(pool).await;
    let app = create_test_router(state, true);

    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();

    let uri = format!("/api/v1/head?tenant_id={}&store_id={}", tenant_id, store_id);
    let (status, _) = send_request(
        &app,
        Method::GET,
        &uri,
        None,
        Some("sk_invalid_key"),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ============================================================================
// Agent Key Registration Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_register_agent_key_success() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let state = create_test_state(pool).await;
    let app = create_test_router(state, false);

    let tenant_id = Uuid::new_v4();
    let agent_id = Uuid::new_v4();

    // Generate a test Ed25519 public key (32 bytes)
    let public_key = hex::encode([1u8; 32]);

    let request_body = json!({
        "tenantId": tenant_id,
        "agentId": agent_id,
        "keyId": 1,
        "publicKey": public_key,
        "validFrom": "2025-01-01T00:00:00Z"
    });

    let (status, body) = send_request(
        &app,
        Method::POST,
        "/api/v1/agents/keys",
        Some(request_body),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {:?}", body);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_invalid_uuid_returns_bad_request() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let state = create_test_state(pool).await;
    let app = create_test_router(state, false);

    let uri = "/api/v1/head?tenant_id=not-a-uuid&store_id=also-not-a-uuid";
    let (status, _) = send_request(&app, Method::GET, uri, None, None).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore]
async fn test_missing_required_params_returns_bad_request() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let state = create_test_state(pool).await;
    let app = create_test_router(state, false);

    // Missing store_id
    let uri = format!("/api/v1/head?tenant_id={}", Uuid::new_v4());
    let (status, _) = send_request(&app, Method::GET, &uri, None, None).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore]
async fn test_invalid_json_body_returns_bad_request() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let state = create_test_state(pool).await;
    let app = create_test_router(state, false);

    // Send malformed JSON
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/events/ingest")
        .header("content-type", "application/json")
        .body(Body::from(b"{ invalid json }".to_vec()))
        .unwrap();

    let response = app
        .into_service::<Body>()
        .oneshot(request)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ============================================================================
// VES Commitment Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_create_ves_commitment_success() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();
    let agent_id = Uuid::new_v4();

    // Insert VES events directly
    let created_at = chrono::Utc::now();
    let created_at_str = created_at.to_rfc3339();

    for seq in 1..=5_i64 {
        let event_id = Uuid::new_v4();
        let payload = json!({ "seq": seq });
        let payload_plain_hash = vec![seq as u8; 32];
        let payload_cipher_hash = vec![0u8; 32];
        let event_signing_hash = vec![seq as u8; 32];
        let agent_signature = vec![seq as u8; 64];

        sqlx::query(
            r#"
            INSERT INTO ves_events (
                event_id, command_id, ves_version, tenant_id, store_id,
                source_agent_id, agent_key_id, entity_type, entity_id, event_type,
                created_at, created_at_str, payload_kind, payload, payload_encrypted,
                payload_plain_hash, payload_cipher_hash, event_signing_hash,
                agent_signature, sequence_number, base_version
            ) VALUES (
                $1, NULL, 1, $2, $3, $4, 1, 'order', $5, 'order.created',
                $6, $7, 0, $8, NULL, $9, $10, $11, $12, $13, NULL
            )
            "#,
        )
        .bind(event_id)
        .bind(tenant_id)
        .bind(store_id)
        .bind(agent_id)
        .bind(format!("ord-{seq}"))
        .bind(created_at)
        .bind(&created_at_str)
        .bind(payload)
        .bind(payload_plain_hash)
        .bind(payload_cipher_hash)
        .bind(event_signing_hash)
        .bind(agent_signature)
        .bind(seq)
        .execute(&pool)
        .await
        .unwrap();
    }

    let state = create_test_state(pool).await;
    let app = create_test_router(state, false);

    let request_body = json!({
        "tenant_id": tenant_id,
        "store_id": store_id,
        "sequence_start": 1,
        "sequence_end": 5
    });

    let (status, body) = send_request(
        &app,
        Method::POST,
        "/api/v1/ves/commitments",
        Some(request_body),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {:?}", body);
    assert!(body["batch_id"].as_str().is_some());
    assert!(body["events_root"].as_str().is_some());
}

// ============================================================================
// Cross-Tenant Access Denial Tests (Security Regression Tests)
// ============================================================================

/// Create a test router with tenant-scoped authentication.
fn create_tenant_scoped_router(
    state: AppState,
    tenant_id: Uuid,
    store_ids: Vec<Uuid>,
    agent_id: Option<Uuid>,
) -> (axum::Router<()>, String) {
    let api_key_validator = Arc::new(ApiKeyValidator::new());

    // Generate a unique test key for this tenant
    let test_key = format!("sk_test_tenant_{}_{}", tenant_id, Uuid::new_v4());
    let key_hash = ApiKeyValidator::hash_key(&test_key);
    api_key_validator.register_key(ApiKeyRecord {
        key_hash,
        tenant_id,
        store_ids,
        permissions: Permissions::read_write(),
        agent_id,
        active: true,
        rate_limit: None,
    });

    let authenticator = Arc::new(Authenticator::new(api_key_validator));
    let auth_state = AuthMiddlewareState {
        authenticator,
        require_auth: true,
        rate_limiter: None,
    };

    let api = stateset_sequencer::api::router().layer(axum::middleware::from_fn_with_state(
        auth_state,
        stateset_sequencer::auth::auth_middleware,
    ));

    let router = axum::Router::new()
        .nest("/api", api)
        .with_state::<()>(state);

    (router, test_key)
}

#[tokio::test]
#[ignore]
async fn test_cross_tenant_schema_read_denied() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();

    // Create a schema for tenant_a directly in the database
    let schema_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO schemas (id, tenant_id, event_type, version, schema_json, status, compatibility, created_at, updated_at)
        VALUES ($1, $2, 'order.created', 1, '{"type": "object"}', 'active', 'backward', NOW(), NOW())
        "#,
    )
    .bind(schema_id)
    .bind(tenant_a)
    .execute(&pool)
    .await
    .unwrap();

    let state = create_test_state(pool).await;

    // Create router scoped to tenant_b
    let (app, api_key) = create_tenant_scoped_router(state, tenant_b, vec![], None);

    // Tenant B tries to read tenant A's schema by ID
    let uri = format!("/api/v1/schemas/{}", schema_id);
    let (status, body) = send_request(&app, Method::GET, &uri, None, Some(&api_key)).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "Cross-tenant schema read should be denied: {:?}",
        body
    );
}

#[tokio::test]
#[ignore]
async fn test_cross_tenant_schema_list_denied() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();

    let state = create_test_state(pool).await;

    // Create router scoped to tenant_b
    let (app, api_key) = create_tenant_scoped_router(state, tenant_b, vec![], None);

    // Tenant B tries to list tenant A's schemas
    let uri = format!("/api/v1/schemas?tenant_id={}", tenant_a);
    let (status, body) = send_request(&app, Method::GET, &uri, None, Some(&api_key)).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "Cross-tenant schema listing should be denied: {:?}",
        body
    );
}

#[tokio::test]
#[ignore]
async fn test_cross_tenant_schema_delete_denied() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();

    // Create a schema for tenant_a
    let schema_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO schemas (id, tenant_id, event_type, version, schema_json, status, compatibility, created_at, updated_at)
        VALUES ($1, $2, 'order.created', 1, '{"type": "object"}', 'active', 'backward', NOW(), NOW())
        "#,
    )
    .bind(schema_id)
    .bind(tenant_a)
    .execute(&pool)
    .await
    .unwrap();

    let state = create_test_state(pool).await;

    // Create router scoped to tenant_b with admin permissions
    let api_key_validator = Arc::new(ApiKeyValidator::new());
    let test_key = format!("sk_test_admin_{}", Uuid::new_v4());
    let key_hash = ApiKeyValidator::hash_key(&test_key);
    api_key_validator.register_key(ApiKeyRecord {
        key_hash,
        tenant_id: tenant_b,
        store_ids: vec![],
        permissions: Permissions::admin(), // Even admin of tenant B shouldn't delete tenant A's schema
        agent_id: None,
        active: true,
        rate_limit: None,
    });

    let authenticator = Arc::new(Authenticator::new(api_key_validator));
    let auth_state = AuthMiddlewareState {
        authenticator,
        require_auth: true,
        rate_limiter: None,
    };

    let api = stateset_sequencer::api::router().layer(axum::middleware::from_fn_with_state(
        auth_state,
        stateset_sequencer::auth::auth_middleware,
    ));

    let app = axum::Router::new()
        .nest("/api", api)
        .with_state::<()>(state);

    // Tenant B tries to delete tenant A's schema
    let uri = format!("/api/v1/schemas/{}", schema_id);
    let (status, body) = send_request(&app, Method::DELETE, &uri, None, Some(&test_key)).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "Cross-tenant schema deletion should be denied: {:?}",
        body
    );
}

#[tokio::test]
#[ignore]
async fn test_cross_tenant_schema_update_status_denied() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();

    // Create a schema for tenant_a
    let schema_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO schemas (id, tenant_id, event_type, version, schema_json, status, compatibility, created_at, updated_at)
        VALUES ($1, $2, 'order.created', 1, '{"type": "object"}', 'active', 'backward', NOW(), NOW())
        "#,
    )
    .bind(schema_id)
    .bind(tenant_a)
    .execute(&pool)
    .await
    .unwrap();

    let state = create_test_state(pool).await;

    // Create router scoped to tenant_b
    let (app, api_key) = create_tenant_scoped_router(state, tenant_b, vec![], None);

    // Tenant B tries to update tenant A's schema status
    let uri = format!("/api/v1/schemas/{}/status", schema_id);
    let (status, body) = send_request(
        &app,
        Method::PUT,
        &uri,
        Some(json!({ "status": "deprecated" })),
        Some(&api_key),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "Cross-tenant schema update should be denied: {:?}",
        body
    );
}

#[tokio::test]
#[ignore]
async fn test_agent_scoped_ingest_denies_mismatched_agent() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();
    let agent_a = Uuid::new_v4();
    let agent_b = Uuid::new_v4();

    let state = create_test_state(pool).await;

    // Create router scoped to agent_a
    let (app, api_key) = create_tenant_scoped_router(state, tenant_id, vec![store_id], Some(agent_a));

    // Try to ingest events claiming to be from agent_b
    let event = TestEventBuilder::new()
        .tenant_id(tenant_id)
        .store_id(store_id)
        .source_agent(agent_b) // Mismatched agent
        .build_json();

    let request_body = json!({
        "agent_id": agent_b, // Claiming to be agent_b
        "events": [event]
    });

    let (status, body) = send_request(
        &app,
        Method::POST,
        "/api/v1/events/ingest",
        Some(request_body),
        Some(&api_key),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "Agent-scoped ingest with mismatched agent should be denied: {:?}",
        body
    );
    assert!(
        body["error"]
            .as_str()
            .map(|s| s.contains("Agent mismatch"))
            .unwrap_or(false),
        "Expected 'Agent mismatch' error, got: {:?}",
        body
    );
}

#[tokio::test]
#[ignore]
async fn test_agent_scoped_ingest_allows_matching_agent() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();
    let agent_id = Uuid::new_v4();

    let state = create_test_state(pool).await;

    // Create router scoped to the correct agent
    let (app, api_key) = create_tenant_scoped_router(state, tenant_id, vec![store_id], Some(agent_id));

    // Ingest events with matching agent
    let event = TestEventBuilder::new()
        .tenant_id(tenant_id)
        .store_id(store_id)
        .source_agent(agent_id)
        .build_json();

    let request_body = json!({
        "agent_id": agent_id,
        "events": [event]
    });

    let (status, body) = send_request(
        &app,
        Method::POST,
        "/api/v1/events/ingest",
        Some(request_body),
        Some(&api_key),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Agent-scoped ingest with matching agent should succeed: {:?}",
        body
    );
    assert_eq!(body["events_accepted"], 1);
}

#[tokio::test]
#[ignore]
async fn test_cross_tenant_event_ingest_denied() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    let store_id = Uuid::new_v4();
    let agent_id = Uuid::new_v4();

    let state = create_test_state(pool).await;

    // Create router scoped to tenant_b
    let (app, api_key) = create_tenant_scoped_router(state, tenant_b, vec![store_id], None);

    // Try to ingest events for tenant_a
    let event = TestEventBuilder::new()
        .tenant_id(tenant_a) // Different tenant
        .store_id(store_id)
        .source_agent(agent_id)
        .build_json();

    let request_body = json!({
        "agent_id": agent_id,
        "events": [event]
    });

    let (status, body) = send_request(
        &app,
        Method::POST,
        "/api/v1/events/ingest",
        Some(request_body),
        Some(&api_key),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "Cross-tenant event ingest should be denied: {:?}",
        body
    );
}

#[tokio::test]
#[ignore]
async fn test_cross_tenant_event_list_denied() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    let store_id = Uuid::new_v4();

    // Seed events for tenant_a
    seed_test_events(&pool, tenant_a, store_id, 5).await;

    let state = create_test_state(pool).await;

    // Create router scoped to tenant_b
    let (app, api_key) = create_tenant_scoped_router(state, tenant_b, vec![], None);

    // Tenant B tries to list tenant A's events
    let uri = format!(
        "/api/v1/events?tenant_id={}&store_id={}&from=1&limit=10",
        tenant_a, store_id
    );
    let (status, body) = send_request(&app, Method::GET, &uri, None, Some(&api_key)).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "Cross-tenant event listing should be denied: {:?}",
        body
    );
}
