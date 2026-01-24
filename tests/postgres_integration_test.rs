//! Postgres-backed integration tests.
//!
//! These are ignored by default and are intended to run in CI (or locally)
//! with `DATABASE_URL` set.

use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use uuid::Uuid;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::Engine;
use http_body_util::BodyExt;
use tower::ServiceExt;

use stateset_sequencer::auth::{ApiKeyValidator, AuthMiddlewareState, Authenticator, RequestLimits};
use stateset_sequencer::crypto::{is_payload_at_rest_encrypted, StaticKeyManager};
use stateset_sequencer::domain::{
    AgentId, EntityType, EventBatch, EventEnvelope, EventType, StoreId, TenantId,
};
use stateset_sequencer::infra::{
    EventStore, IngestService, PayloadEncryption, PayloadEncryptionMode, PgAgentKeyRegistry,
    PgCommitmentEngine, PgEventStore, PgSequencer, PgVesCommitmentEngine,
    PgVesComplianceProofStore, PgVesValidityProofStore, SchemaValidationMode, Sequencer,
    VesSequencer,
};
use stateset_sequencer::server::AppState;

async fn connect_db() -> Option<sqlx::PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&url)
        .await
        .ok()?;
    Some(pool)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn postgres_sequencer_concurrent_ingest_has_no_gaps() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let payload_encryption = Arc::new(PayloadEncryption::disabled());
    let sequencer = Arc::new(PgSequencer::new(pool.clone(), payload_encryption.clone()));

    let tenant_id = TenantId::new();
    let store_id = StoreId::new();

    let tasks: usize = 8;
    let per_task: usize = 25;
    let expected_total = (tasks * per_task) as u64;

    let mut handles = Vec::with_capacity(tasks);
    for task_idx in 0..tasks {
        let sequencer = sequencer.clone();
        let tenant_id = tenant_id.clone();
        let store_id = store_id.clone();
        handles.push(tokio::spawn(async move {
            let agent_id = AgentId::new();
            let events: Vec<EventEnvelope> = (0..per_task)
                .map(|i| {
                    EventEnvelope::new(
                        tenant_id.clone(),
                        store_id.clone(),
                        EntityType::order(),
                        format!("ord-{task_idx}-{i}"),
                        EventType::new("order.created"),
                        json!({ "task": task_idx, "i": i }),
                        agent_id.clone(),
                    )
                })
                .collect();

            let batch = EventBatch::new(agent_id, events);
            sequencer.ingest(batch).await.unwrap()
        }));
    }

    let mut accepted_total: u64 = 0;
    for handle in handles {
        let receipt = handle.await.unwrap();
        accepted_total += receipt.events_accepted as u64;
        assert_eq!(
            receipt.events_rejected.len(),
            0,
            "expected no rejections in concurrent ingest"
        );
    }
    assert_eq!(accepted_total, expected_total);

    let head = sequencer.head(&tenant_id, &store_id).await.unwrap();
    assert_eq!(head, expected_total);

    let store = PgEventStore::new(pool, payload_encryption);
    let events = store
        .read_range(&tenant_id, &store_id, 1, head)
        .await
        .unwrap();
    assert_eq!(events.len() as u64, expected_total);

    for (idx, event) in events.iter().enumerate() {
        assert_eq!(event.sequence_number(), (idx as u64) + 1);
    }
}

#[tokio::test]
#[ignore]
async fn postgres_sequencer_rejects_duplicate_event_id_without_advancing_head() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let payload_encryption = Arc::new(PayloadEncryption::disabled());
    let sequencer = PgSequencer::new(pool.clone(), payload_encryption);

    let tenant_id = TenantId::new();
    let store_id = StoreId::new();
    let agent_id = AgentId::new();
    let event_id = Uuid::new_v4();

    let mut event = EventEnvelope::new(
        tenant_id.clone(),
        store_id.clone(),
        EntityType::order(),
        "ord-dup",
        EventType::new("order.created"),
        json!({ "kind": "first" }),
        agent_id.clone(),
    );
    event.event_id = event_id;

    let receipt1 = sequencer
        .ingest(EventBatch::new(agent_id.clone(), vec![event]))
        .await
        .unwrap();
    assert_eq!(receipt1.events_accepted, 1);
    assert_eq!(receipt1.events_rejected.len(), 0);
    assert_eq!(receipt1.head_sequence, 1);

    let mut dup = EventEnvelope::new(
        tenant_id.clone(),
        store_id.clone(),
        EntityType::order(),
        "ord-dup",
        EventType::new("order.created"),
        json!({ "kind": "retry" }),
        agent_id.clone(),
    );
    dup.event_id = event_id;

    let receipt2 = sequencer
        .ingest(EventBatch::new(agent_id, vec![dup]))
        .await
        .unwrap();
    assert_eq!(receipt2.events_accepted, 0);
    assert_eq!(receipt2.assigned_sequence_start, None);
    assert_eq!(receipt2.assigned_sequence_end, None);
    assert_eq!(receipt2.head_sequence, 1);
    assert_eq!(receipt2.events_rejected.len(), 1);
    assert_eq!(receipt2.events_rejected[0].event_id, event_id);

    let head = sequencer.head(&tenant_id, &store_id).await.unwrap();
    assert_eq!(head, 1);
}

#[tokio::test]
#[ignore]
async fn postgres_sequencer_rejects_duplicate_command_id() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let payload_encryption = Arc::new(PayloadEncryption::disabled());
    let sequencer = PgSequencer::new(pool.clone(), payload_encryption);

    let tenant_id = TenantId::new();
    let store_id = StoreId::new();
    let agent_id = AgentId::new();
    let command_id = Uuid::new_v4();

    let event1 = EventEnvelope::new(
        tenant_id.clone(),
        store_id.clone(),
        EntityType::order(),
        "ord-1",
        EventType::new("order.created"),
        json!({ "kind": "first" }),
        agent_id.clone(),
    )
    .with_command_id(command_id);

    let receipt1 = sequencer
        .ingest(EventBatch::new(agent_id.clone(), vec![event1]))
        .await
        .unwrap();
    assert_eq!(receipt1.events_accepted, 1);
    assert_eq!(receipt1.events_rejected.len(), 0);
    assert_eq!(receipt1.head_sequence, 1);

    let event2 = EventEnvelope::new(
        tenant_id.clone(),
        store_id.clone(),
        EntityType::order(),
        "ord-2",
        EventType::new("order.created"),
        json!({ "kind": "retry" }),
        agent_id.clone(),
    )
    .with_command_id(command_id);

    let receipt2 = sequencer
        .ingest(EventBatch::new(agent_id, vec![event2]))
        .await
        .unwrap();
    assert_eq!(receipt2.events_accepted, 0);
    assert_eq!(receipt2.head_sequence, 1);
    assert_eq!(receipt2.events_rejected.len(), 1);

    let head = sequencer.head(&tenant_id, &store_id).await.unwrap();
    assert_eq!(head, 1);
}

#[tokio::test]
#[ignore]
async fn postgres_ves_validity_proofs_rest_flow() {
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

    let created_at = chrono::Utc::now();
    let created_at_str = created_at.to_rfc3339();

    for seq in 1..=3_i64 {
        let event_id = Uuid::new_v4();
        let payload = json!({ "seq": seq });
        let payload_plain_hash = vec![seq as u8; 32];
        let payload_cipher_hash = vec![0u8; 32];
        let event_signing_hash = vec![seq as u8; 32];
        let agent_signature = vec![seq as u8; 64];

        sqlx::query(
            r#"
            INSERT INTO ves_events (
                event_id,
                command_id,
                ves_version,
                tenant_id,
                store_id,
                source_agent_id,
                agent_key_id,
                entity_type,
                entity_id,
                event_type,
                created_at,
                created_at_str,
                payload_kind,
                payload,
                payload_encrypted,
                payload_plain_hash,
                payload_cipher_hash,
                event_signing_hash,
                agent_signature,
                sequence_number,
                base_version
            ) VALUES (
                $1,NULL,1,$2,$3,$4,1,'order',$5,'order.created',$6,$7,0,$8,NULL,$9,$10,$11,$12,$13,$14,NULL
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

    let payload_encryption_events = Arc::new(PayloadEncryption::disabled());
    let payload_encryption_proofs = Arc::new(PayloadEncryption::new(
        PayloadEncryptionMode::Required,
        Arc::new(StaticKeyManager::new([7u8; 32])),
    ));

    let sequencer = Arc::new(PgSequencer::new(
        pool.clone(),
        payload_encryption_events.clone(),
    ));
    let event_store = Arc::new(PgEventStore::new(pool.clone(), payload_encryption_events));
    let commitment_engine = Arc::new(PgCommitmentEngine::new(pool.clone()));
    let ves_commitment_engine = Arc::new(PgVesCommitmentEngine::new(pool.clone()));
    let ves_validity_proof_store = Arc::new(PgVesValidityProofStore::new(
        pool.clone(),
        payload_encryption_proofs.clone(),
    ));
    let ves_compliance_proof_store = Arc::new(PgVesComplianceProofStore::new(
        pool.clone(),
        payload_encryption_proofs,
    ));

    let agent_key_registry = Arc::new(PgAgentKeyRegistry::new(pool.clone()));
    let ves_sequencer = Arc::new(VesSequencer::new(pool.clone(), agent_key_registry.clone()));
    let schema_store = Arc::new(stateset_sequencer::infra::PgSchemaStore::new(pool.clone()));
    let x402_repository = Arc::new(stateset_sequencer::infra::PgX402Repository::new(pool.clone()));

    let metrics = Arc::new(stateset_sequencer::metrics::MetricsRegistry::new());

    let state = AppState {
        sequencer,
        event_store,
        commitment_engine,
        ves_commitment_engine,
        ves_validity_proof_store,
        ves_compliance_proof_store,
        anchor_service: None,
        ves_sequencer,
        agent_key_registry,
        schema_store,
        metrics,
        x402_repository,
        schema_validation_mode: SchemaValidationMode::Disabled,
        request_limits: RequestLimits::default(),
        pool_monitor: None,
        circuit_breaker_registry: None,
    };

    let api_key_validator = Arc::new(ApiKeyValidator::new());
    let authenticator = Arc::new(Authenticator::new(api_key_validator));
    let auth_state = AuthMiddlewareState {
        authenticator,
        require_auth: false,
        rate_limiter: None,
    };

    let api = stateset_sequencer::api::router().layer(axum::middleware::from_fn_with_state(
        auth_state,
        stateset_sequencer::auth::auth_middleware,
    ));
    let app = axum::Router::new()
        .nest("/api", api)
        .with_state::<()>(state);

    async fn send(app: &axum::Router<()>, request: Request<Body>) -> (StatusCode, Vec<u8>) {
        let response = app
            .clone()
            .into_service::<Body>()
            .oneshot(request)
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
        (status, bytes)
    }

    let create_commitment_body = json!({
        "tenant_id": tenant_id,
        "store_id": store_id,
        "sequence_start": 1,
        "sequence_end": 3
    });

    let (status, body) = send(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/ves/commitments")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&create_commitment_body).unwrap(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let commitment_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let batch_id = Uuid::parse_str(commitment_json["batch_id"].as_str().unwrap()).unwrap();

    let (status, body) = send(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/api/v1/ves/validity/{batch_id}/inputs"))
            .body(Body::from(Vec::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let inputs_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        inputs_json["batch_id"].as_str().unwrap(),
        batch_id.to_string()
    );
    assert!(inputs_json["public_inputs_hash"].as_str().is_some());

    let proof_bytes = b"proof-bytes-1".to_vec();
    let proof_b64 = base64::engine::general_purpose::STANDARD.encode(&proof_bytes);

    let submit_body = json!({
        "proofType": "groth16",
        "proofVersion": 1,
        "proofB64": proof_b64
    });

    let (status, body) = send(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri(format!("/api/v1/ves/validity/{batch_id}/proofs"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&submit_body).unwrap()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let submit_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let proof_id = Uuid::parse_str(submit_json["proof_id"].as_str().unwrap()).unwrap();

    let (ciphertext,): (Vec<u8>,) =
        sqlx::query_as("SELECT proof FROM ves_validity_proofs WHERE proof_id = $1")
            .bind(proof_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(is_payload_at_rest_encrypted(&ciphertext));

    let (status, body) = send(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/api/v1/ves/validity/{batch_id}/proofs"))
            .body(Body::from(Vec::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let list_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(list_json["count"].as_u64().unwrap(), 1);

    let (status, body) = send(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/api/v1/ves/validity/proofs/{proof_id}"))
            .body(Body::from(Vec::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let proof_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let roundtrip = base64::engine::general_purpose::STANDARD
        .decode(proof_json["proof_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(roundtrip, proof_bytes);

    let (status, body) = send(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/api/v1/ves/validity/proofs/{proof_id}/verify"))
            .body(Body::from(Vec::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let verify_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(verify_json["valid"].as_bool().unwrap());
    assert!(verify_json["public_inputs_match"].as_bool().unwrap());

    let conflict_body = json!({
        "proofType": "groth16",
        "proofVersion": 1,
        "proofB64": base64::engine::general_purpose::STANDARD.encode(b"different")
    });

    let (status, body) = send(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri(format!("/api/v1/ves/validity/{batch_id}/proofs"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&conflict_body).unwrap()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "body={}",
        String::from_utf8_lossy(&body)
    );
}

#[tokio::test]
#[ignore]
async fn postgres_ves_compliance_proofs_rest_flow() {
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

    let event_id = Uuid::new_v4();
    let created_at = chrono::Utc::now();
    let created_at_str = created_at.to_rfc3339();

    let payload_encrypted = json!({
        "vesEncVersion": 1,
        "ciphertext": "AA==",
        "recipients": [],
    });
    let payload_plain_hash = vec![1u8; 32];
    let payload_cipher_hash = vec![2u8; 32];
    let event_signing_hash = vec![3u8; 32];
    let agent_signature = vec![4u8; 64];

    sqlx::query(
        r#"
        INSERT INTO ves_events (
            event_id,
            command_id,
            ves_version,
            tenant_id,
            store_id,
            source_agent_id,
            agent_key_id,
            entity_type,
            entity_id,
            event_type,
            created_at,
            created_at_str,
            payload_kind,
            payload,
            payload_encrypted,
            payload_plain_hash,
            payload_cipher_hash,
            event_signing_hash,
            agent_signature,
            sequence_number,
            base_version
        ) VALUES (
            $1,NULL,1,$2,$3,$4,1,'order','ord-1','order.created',$5,$6,1,NULL,$7,$8,$9,$10,$11,1,NULL
        )
        "#,
    )
    .bind(event_id)
    .bind(tenant_id)
    .bind(store_id)
    .bind(agent_id)
    .bind(created_at)
    .bind(&created_at_str)
    .bind(payload_encrypted)
    .bind(payload_plain_hash)
    .bind(payload_cipher_hash)
    .bind(event_signing_hash)
    .bind(agent_signature)
    .execute(&pool)
    .await
    .unwrap();

    let payload_encryption_events = Arc::new(PayloadEncryption::disabled());
    let payload_encryption_proofs = Arc::new(PayloadEncryption::new(
        PayloadEncryptionMode::Required,
        Arc::new(StaticKeyManager::new([7u8; 32])),
    ));

    let sequencer = Arc::new(PgSequencer::new(
        pool.clone(),
        payload_encryption_events.clone(),
    ));
    let event_store = Arc::new(PgEventStore::new(pool.clone(), payload_encryption_events));
    let commitment_engine = Arc::new(PgCommitmentEngine::new(pool.clone()));
    let ves_commitment_engine = Arc::new(PgVesCommitmentEngine::new(pool.clone()));
    let ves_validity_proof_store = Arc::new(PgVesValidityProofStore::new(
        pool.clone(),
        payload_encryption_proofs.clone(),
    ));
    let ves_compliance_proof_store = Arc::new(PgVesComplianceProofStore::new(
        pool.clone(),
        payload_encryption_proofs,
    ));

    let agent_key_registry = Arc::new(PgAgentKeyRegistry::new(pool.clone()));
    let ves_sequencer = Arc::new(VesSequencer::new(pool.clone(), agent_key_registry.clone()));
    let schema_store = Arc::new(stateset_sequencer::infra::PgSchemaStore::new(pool.clone()));
    let x402_repository = Arc::new(stateset_sequencer::infra::PgX402Repository::new(pool.clone()));

    let metrics = Arc::new(stateset_sequencer::metrics::MetricsRegistry::new());

    let state = AppState {
        sequencer,
        event_store,
        commitment_engine,
        ves_commitment_engine,
        ves_validity_proof_store,
        ves_compliance_proof_store,
        anchor_service: None,
        ves_sequencer,
        agent_key_registry,
        schema_store,
        metrics,
        x402_repository,
        schema_validation_mode: SchemaValidationMode::Disabled,
        request_limits: RequestLimits::default(),
        pool_monitor: None,
        circuit_breaker_registry: None,
    };

    let api_key_validator = Arc::new(ApiKeyValidator::new());
    let authenticator = Arc::new(Authenticator::new(api_key_validator));
    let auth_state = AuthMiddlewareState {
        authenticator,
        require_auth: false,
        rate_limiter: None,
    };

    let api = stateset_sequencer::api::router().layer(axum::middleware::from_fn_with_state(
        auth_state,
        stateset_sequencer::auth::auth_middleware,
    ));
    let app = axum::Router::new()
        .nest("/api", api)
        .with_state::<()>(state);

    async fn send(app: &axum::Router<()>, request: Request<Body>) -> (StatusCode, Vec<u8>) {
        let response = app
            .clone()
            .into_service::<Body>()
            .oneshot(request)
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
        (status, bytes)
    }

    let inputs_body = json!({
        "policyId": "aml.threshold",
        "policyParams": { "threshold": 10000 }
    });

    let (status, body) = send(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri(format!("/api/v1/ves/compliance/{event_id}/inputs"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&inputs_body).unwrap()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "body={}",
        String::from_utf8_lossy(&body)
    );

    let inputs_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(inputs_json["public_inputs_hash"].as_str().is_some());

    let proof_bytes = b"stark-proof-bytes-1".to_vec();
    let proof_b64 = base64::engine::general_purpose::STANDARD.encode(&proof_bytes);

    let submit_body = json!({
        "proofType": "stark",
        "proofVersion": 1,
        "policyId": "aml.threshold",
        "policyParams": { "threshold": 10000 },
        "proofB64": proof_b64
    });

    let (status, body) = send(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri(format!("/api/v1/ves/compliance/{event_id}/proofs"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&submit_body).unwrap()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "body={}",
        String::from_utf8_lossy(&body)
    );

    let submit_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let proof_id = Uuid::parse_str(submit_json["proof_id"].as_str().unwrap()).unwrap();

    let (ciphertext,): (Vec<u8>,) =
        sqlx::query_as("SELECT proof FROM ves_compliance_proofs WHERE proof_id = $1")
            .bind(proof_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(is_payload_at_rest_encrypted(&ciphertext));

    let (status, body) = send(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/api/v1/ves/compliance/{event_id}/proofs"))
            .body(Body::from(Vec::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "body={}",
        String::from_utf8_lossy(&body)
    );
    let list_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(list_json["count"].as_u64().unwrap(), 1);

    let (status, body) = send(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/api/v1/ves/compliance/proofs/{proof_id}"))
            .body(Body::from(Vec::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "body={}",
        String::from_utf8_lossy(&body)
    );
    let proof_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let roundtrip = base64::engine::general_purpose::STANDARD
        .decode(proof_json["proof_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(roundtrip, proof_bytes);

    let (status, body) = send(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/api/v1/ves/compliance/proofs/{proof_id}/verify"))
            .body(Body::from(Vec::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "body={}",
        String::from_utf8_lossy(&body)
    );
    let verify_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(verify_json["valid"].as_bool().unwrap());
    assert!(verify_json["public_inputs_match"].as_bool().unwrap());

    let conflict_body = json!({
        "proofType": "stark",
        "proofVersion": 1,
        "policyId": "aml.threshold",
        "policyParams": { "threshold": 10000 },
        "proofB64": base64::engine::general_purpose::STANDARD.encode(b"different")
    });

    let (status, body) = send(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri(format!("/api/v1/ves/compliance/{event_id}/proofs"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&conflict_body).unwrap()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "body={}",
        String::from_utf8_lossy(&body)
    );
}
