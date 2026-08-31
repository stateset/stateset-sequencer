//! Postgres-backed integration tests.
//!
//! These are ignored by default and are intended to run in CI (or locally)
//! with `DATABASE_URL` set.

#![allow(clippy::clone_on_copy)]
// Several imports are used only by the STARK-gated proof-flow tests below; when
// the `stark` feature is off those tests are compiled out, leaving the imports
// unused. The imports are genuinely used when the feature is on.
#![cfg_attr(not(feature = "stark"), allow(unused_imports))]

use serde_json::json;
use std::sync::Arc;
use tokio::sync::Barrier;
use uuid::Uuid;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::Engine;
use http_body_util::BodyExt;
use tower::ServiceExt;

use stateset_sequencer::auth::{
    AgentKeyEntry, AgentKeyLookup, AgentKeyRegistry, ApiKeyValidator, AuthMiddlewareState,
    Authenticator, RateLimiter, RequestLimits,
};
use stateset_sequencer::crypto::{is_payload_at_rest_encrypted, AgentSigningKey, StaticKeyManager};
use stateset_sequencer::domain::{
    AgentId, AgentKeyId, EntityType, EventBatch, EventEnvelope, EventType, StoreId, TenantId,
    VesEventEnvelope,
};
use stateset_sequencer::infra::{
    EventStore, IngestService, PayloadEncryption, PayloadEncryptionMode, PgAgentKeyRegistry,
    PgCommitmentEngine, PgEventStore, PgSequencer, PgVesCommitmentEngine,
    PgVesComplianceProofStore, PgVesValidityProofStore, SchemaValidationMode, Sequencer,
    SequencerError, VesSequencer,
};
use stateset_sequencer::server::AppState;

mod common;

async fn connect_db() -> Option<sqlx::PgPool> {
    common::connect_test_db(20).await
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
async fn postgres_ves_read_range_reports_gap_when_window_is_empty() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let tenant_id = TenantId::new();
    let store_id = StoreId::new();
    let source_agent_id = Uuid::new_v4();
    let payload = json!({ "kind": "ves-gap" });
    let created_at = chrono::Utc::now();
    let created_at_str = created_at.to_rfc3339();

    for seq in [1_i64, 3_i64] {
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
                $1,NULL,1,$2,$3,$4,1,'order',$5,'order.created',$6,$7,0,$8,NULL,$9,$10,$11,$12,$13,NULL
            )
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(source_agent_id)
        .bind(format!("ord-{seq}"))
        .bind(created_at)
        .bind(&created_at_str)
        .bind(&payload)
        .bind(&payload_plain_hash)
        .bind(&payload_cipher_hash)
        .bind(&event_signing_hash)
        .bind(&agent_signature)
        .bind(seq)
        .execute(&pool)
        .await
        .unwrap();
    }

    let registry = Arc::new(PgAgentKeyRegistry::new(pool.clone()));
    let ves_sequencer = VesSequencer::new(pool.clone(), registry);
    let err = ves_sequencer
        .read_range(&tenant_id, &store_id, 2, 2)
        .await
        .unwrap_err();

    match err {
        SequencerError::InvariantViolation { invariant, message } => {
            assert_eq!(invariant, "sequence_range");
            assert!(message.contains("sequence gap in range 2..=2"));
        }
        other => panic!("expected sequence_range invariant, got {other:?}"),
    }

    let empty = ves_sequencer
        .read_range(&tenant_id, &store_id, 10, 10)
        .await
        .unwrap();
    assert!(empty.is_empty());
}

/// VES entity history is paged in SQL with a repository-enforced cap; see the
/// legacy-store counterpart in postgres_persistence_test.rs for the rationale.
#[tokio::test]
#[ignore]
async fn postgres_ves_read_entity_page_bounds_rows_and_reports_total() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };
    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let tenant_id = TenantId::new();
    let store_id = StoreId::new();
    let source_agent_id = Uuid::new_v4();
    let created_at = chrono::Utc::now();
    let created_at_str = created_at.to_rfc3339();
    let payload = json!({ "kind": "ves-page" });

    // Five events on one entity, one on another, contiguous sequence numbers.
    for seq in 1_i64..=6 {
        let entity = if seq <= 5 { "ord-paged" } else { "ord-other" };
        sqlx::query(
            r#"
            INSERT INTO ves_events (
                event_id, command_id, ves_version, tenant_id, store_id, source_agent_id,
                agent_key_id, entity_type, entity_id, event_type, created_at, created_at_str,
                payload_kind, payload, payload_encrypted, payload_plain_hash, payload_cipher_hash,
                event_signing_hash, agent_signature, sequence_number, base_version
            ) VALUES (
                $1,NULL,1,$2,$3,$4,1,'order',$5,'order.created',$6,$7,0,$8,NULL,$9,$10,$11,$12,$13,NULL
            )
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(source_agent_id)
        .bind(entity)
        .bind(created_at)
        .bind(&created_at_str)
        .bind(&payload)
        .bind(vec![seq as u8; 32])
        .bind(vec![0u8; 32])
        .bind(vec![seq as u8; 32])
        .bind(vec![seq as u8; 64])
        .bind(seq)
        .execute(&pool)
        .await
        .unwrap();
    }

    let registry = Arc::new(PgAgentKeyRegistry::new(pool.clone()));
    let ves = VesSequencer::new(pool.clone(), registry);
    let order = stateset_sequencer::domain::EntityType::order();

    let page = ves
        .read_entity_page(&tenant_id, &store_id, &order, "ord-paged", 1, 2)
        .await
        .unwrap();
    assert_eq!(page.total, 5);
    let seqs: Vec<u64> = page.events.iter().map(|e| e.sequence_number()).collect();
    assert_eq!(seqs, vec![2, 3]);

    let past_end = ves
        .read_entity_page(&tenant_id, &store_id, &order, "ord-paged", 9, 2)
        .await
        .unwrap();
    assert_eq!(past_end.total, 5);
    assert!(past_end.events.is_empty());

    let clamped = ves
        .read_entity_page(&tenant_id, &store_id, &order, "ord-paged", 0, u32::MAX)
        .await
        .unwrap();
    assert_eq!(clamped.events.len(), 5);
}

#[tokio::test]
#[ignore]
async fn postgres_ves_read_range_rejects_oversized_span() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };
    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let registry = Arc::new(PgAgentKeyRegistry::new(pool.clone()));
    let ves = VesSequencer::new(pool, registry);
    let tenant_id = TenantId::new();
    let store_id = StoreId::new();
    let max = stateset_sequencer::domain::MAX_READ_RANGE_SPAN;

    let err = ves
        .read_range(&tenant_id, &store_id, 1, max + 1)
        .await
        .expect_err("a span of MAX_READ_RANGE_SPAN + 1 must be rejected");
    assert!(err.to_string().contains("span"), "got: {err}");
}

#[tokio::test]
#[ignore]
async fn postgres_sequencer_scopes_sequences_by_tenant_and_store() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let payload_encryption = Arc::new(PayloadEncryption::disabled());
    let sequencer = PgSequencer::new(pool.clone(), payload_encryption.clone());
    let store = PgEventStore::new(pool, payload_encryption);

    let tenant_a = TenantId::new();
    let tenant_b = TenantId::new();
    let store_one = StoreId::new();
    let store_two = StoreId::new();

    let agent_a = AgentId::new();
    let agent_b = AgentId::new();

    let events_a1: Vec<EventEnvelope> = (0..2)
        .map(|i| {
            EventEnvelope::new(
                tenant_a.clone(),
                store_one.clone(),
                EntityType::order(),
                format!("a1-ord-{i}"),
                EventType::new("order.created"),
                json!({ "tenant": "a", "store": "one", "i": i }),
                agent_a.clone(),
            )
        })
        .collect();
    sequencer
        .ingest(EventBatch::new(agent_a.clone(), events_a1))
        .await
        .unwrap();

    let events_a2: Vec<EventEnvelope> = (0..1)
        .map(|i| {
            EventEnvelope::new(
                tenant_a.clone(),
                store_two.clone(),
                EntityType::order(),
                format!("a2-ord-{i}"),
                EventType::new("order.created"),
                json!({ "tenant": "a", "store": "two", "i": i }),
                agent_a.clone(),
            )
        })
        .collect();
    sequencer
        .ingest(EventBatch::new(agent_a, events_a2))
        .await
        .unwrap();

    let events_b1: Vec<EventEnvelope> = (0..3)
        .map(|i| {
            EventEnvelope::new(
                tenant_b.clone(),
                store_one.clone(),
                EntityType::order(),
                format!("b1-ord-{i}"),
                EventType::new("order.created"),
                json!({ "tenant": "b", "store": "one", "i": i }),
                agent_b.clone(),
            )
        })
        .collect();
    sequencer
        .ingest(EventBatch::new(agent_b, events_b1))
        .await
        .unwrap();

    let head_a_one = sequencer.head(&tenant_a, &store_one).await.unwrap();
    let head_a_two = sequencer.head(&tenant_a, &store_two).await.unwrap();
    let head_b_one = sequencer.head(&tenant_b, &store_one).await.unwrap();

    assert_eq!(head_a_one, 2);
    assert_eq!(head_a_two, 1);
    assert_eq!(head_b_one, 3);

    let events_a_one = store
        .read_range(&tenant_a, &store_one, 1, head_a_one)
        .await
        .unwrap();
    for (idx, event) in events_a_one.iter().enumerate() {
        assert_eq!(event.sequence_number(), (idx as u64) + 1);
    }

    let events_a_two = store
        .read_range(&tenant_a, &store_two, 1, head_a_two)
        .await
        .unwrap();
    for (idx, event) in events_a_two.iter().enumerate() {
        assert_eq!(event.sequence_number(), (idx as u64) + 1);
    }

    let events_b_one = store
        .read_range(&tenant_b, &store_one, 1, head_b_one)
        .await
        .unwrap();
    for (idx, event) in events_b_one.iter().enumerate() {
        assert_eq!(event.sequence_number(), (idx as u64) + 1);
    }
}

#[cfg(feature = "stark")]
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
                $1,NULL,1,$2,$3,$4,1,'order',$5,'order.created',$6,$7,0,$8,NULL,$9,$10,$11,$12,$13,NULL
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
    let commitment_reader = Arc::new(PgCommitmentEngine::new(pool.clone()));
    let ves_commitment_engine = Arc::new(PgVesCommitmentEngine::new(pool.clone()));
    let ves_commitment_reader = Arc::new(PgVesCommitmentEngine::new(pool.clone()));
    let ves_validity_proof_store = Arc::new(PgVesValidityProofStore::new(
        pool.clone(),
        payload_encryption_proofs.clone(),
    ));
    let ves_compliance_proof_store = Arc::new(PgVesComplianceProofStore::new(
        pool.clone(),
        payload_encryption_proofs,
    ));

    let cache_manager = Arc::new(stateset_sequencer::infra::CacheManager::new());
    let agent_key_registry = Arc::new(PgAgentKeyRegistry::new(pool.clone()));
    let ves_sequencer = Arc::new(VesSequencer::new(pool.clone(), agent_key_registry.clone()));
    let ves_sequencer_reader =
        Arc::new(VesSequencer::new(pool.clone(), agent_key_registry.clone()));
    let schema_store = Arc::new(stateset_sequencer::infra::PgSchemaStore::new(pool.clone()));
    let x402_repository = Arc::new(stateset_sequencer::infra::PgX402Repository::new(
        pool.clone(),
    ));

    let metrics = Arc::new(stateset_sequencer::metrics::MetricsRegistry::new());
    let api_key_validator = Arc::new(ApiKeyValidator::new());
    let api_key_store = Arc::new(stateset_sequencer::auth::PgApiKeyStore::new(pool.clone()));

    let state = AppState {
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
        api_key_validator: api_key_validator.clone(),
        api_key_store,
        public_registration_enabled: true,
        public_registration_limiter: None,
        trust_proxy_headers: false,
        audit_logger: None,
    };

    let authenticator = Arc::new(Authenticator::new(api_key_validator));
    let auth_state = AuthMiddlewareState {
        authenticator,
        require_auth: false,
        rate_limiter: None,
        credential_rate_limiter: Arc::new(RateLimiter::new(1000)),
        pool_monitor: None,
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
async fn postgres_migrations_accept_max_length_identifiers() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let entity_type = "t".repeat(128);
    let entity_id = "i".repeat(512);
    let event_type = "e".repeat(256);

    let payload_encryption = Arc::new(PayloadEncryption::disabled());
    let sequencer = PgSequencer::new(pool.clone(), payload_encryption.clone());
    let event_store = PgEventStore::new(pool.clone(), payload_encryption);

    let tenant_id = TenantId::new();
    let store_id = StoreId::new();
    let agent_id = AgentId::new();

    let event = EventEnvelope::new(
        tenant_id.clone(),
        store_id.clone(),
        EntityType::new(entity_type.clone()),
        entity_id.clone(),
        EventType::new(event_type.clone()),
        json!({ "kind": "legacy" }),
        agent_id.clone(),
    );

    let receipt = sequencer
        .ingest(EventBatch::new(agent_id.clone(), vec![event]))
        .await
        .unwrap();
    assert_eq!(receipt.events_accepted, 1);

    let stored = event_store
        .read_range(&tenant_id, &store_id, 1, 1)
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].envelope.entity_type.as_str(), entity_type);
    assert_eq!(stored[0].envelope.entity_id, entity_id);
    assert_eq!(stored[0].envelope.event_type.as_str(), event_type);

    let ves_tenant_id = TenantId::new();
    let ves_store_id = StoreId::new();
    let ves_agent_id = AgentId::new();
    let signing_key = AgentSigningKey::generate();
    let agent_key_registry = Arc::new(PgAgentKeyRegistry::new(pool.clone()));
    let lookup = AgentKeyLookup::new(&ves_tenant_id, &ves_agent_id, AgentKeyId::default());
    agent_key_registry
        .register_key(&lookup, AgentKeyEntry::new(signing_key.public_key_bytes()))
        .await
        .unwrap();
    let ves_sequencer = VesSequencer::new(pool, agent_key_registry);

    let ves_event = VesEventEnvelope::new_plaintext(
        ves_tenant_id.clone(),
        ves_store_id.clone(),
        ves_agent_id,
        AgentKeyId::default(),
        EntityType::new(entity_type.clone()),
        entity_id.clone(),
        EventType::new(event_type.clone()),
        json!({ "kind": "ves" }),
        &signing_key,
    );

    let ves_receipt = ves_sequencer.ingest(vec![ves_event]).await.unwrap();
    assert_eq!(ves_receipt.events_accepted, 1);

    let ves_events = ves_sequencer
        .read_range(&ves_tenant_id, &ves_store_id, 1, 1)
        .await
        .unwrap();
    assert_eq!(ves_events.len(), 1);
    assert_eq!(ves_events[0].envelope.entity_type.as_str(), entity_type);
    assert_eq!(ves_events[0].envelope.entity_id, entity_id);
    assert_eq!(ves_events[0].envelope.event_type.as_str(), event_type);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn postgres_ves_sequencer_concurrent_exact_replay_returns_existing_receipt() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let tenant_id = TenantId::new();
    let store_id = StoreId::new();
    let agent_id = AgentId::new();
    let signing_key = AgentSigningKey::generate();

    let agent_key_registry = Arc::new(PgAgentKeyRegistry::new(pool.clone()));
    let lookup = AgentKeyLookup::new(&tenant_id, &agent_id, AgentKeyId::default());
    agent_key_registry
        .register_key(&lookup, AgentKeyEntry::new(signing_key.public_key_bytes()))
        .await
        .unwrap();

    let ves_sequencer = Arc::new(VesSequencer::new(pool, agent_key_registry));
    let event = VesEventEnvelope::new_plaintext(
        tenant_id.clone(),
        store_id.clone(),
        agent_id,
        AgentKeyId::default(),
        EntityType::order(),
        "ord-replay",
        EventType::new("order.updated"),
        json!({ "replayed": true }),
        &signing_key,
    )
    .with_command_id(Uuid::new_v4());
    let event_id = event.event_id;

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::with_capacity(2);
    for _ in 0..2 {
        let sequencer = ves_sequencer.clone();
        let barrier = barrier.clone();
        let event = event.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            sequencer.ingest(vec![event]).await.unwrap()
        }));
    }

    let mut receipts = Vec::new();
    let mut accepted_total = 0u32;
    let mut rejected_total = 0usize;
    for handle in handles {
        let result = handle.await.unwrap();
        accepted_total += result.events_accepted;
        rejected_total += result.events_rejected.len();
        receipts.extend(result.receipts);
    }

    assert_eq!(accepted_total, 1);
    assert_eq!(rejected_total, 0);
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].event_id, event_id);
    assert_eq!(receipts[1].event_id, event_id);
    assert_eq!(receipts[0].sequence_number, receipts[1].sequence_number);
    assert_eq!(receipts[0].receipt_hash, receipts[1].receipt_hash);

    let stored = ves_sequencer
        .read_range(&tenant_id, &store_id, 1, 1)
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].event_id(), event_id);
}

/// N callers migrating a *fresh* database at once must all succeed.
/// `run_postgres` created the pgcrypto extension outside the migrator's
/// advisory lock, and Postgres's CREATE EXTENSION IF NOT EXISTS is not
/// concurrency-safe -- two sessions can both pass the existence check and one
/// then fails on pg_extension_name_index. Every parallel test binary (and any
/// multi-node deployment racing on first boot) could hit it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn postgres_concurrent_first_migration_is_race_free() {
    let Some(admin) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };
    let base = std::env::var("DATABASE_URL").unwrap();

    for round in 0..10 {
        let dbname = format!(
            "mig_race_{round}_{}",
            &Uuid::new_v4().simple().to_string()[..8]
        );
        sqlx::query(&format!("CREATE DATABASE {dbname}"))
            .execute(&admin)
            .await
            .unwrap();
        let url = {
            let idx = base.rfind('/').unwrap();
            format!("{}/{}", &base[..idx], dbname)
        };

        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let url = url.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                let pool = sqlx::postgres::PgPoolOptions::new()
                    .max_connections(2)
                    .connect(&url)
                    .await
                    .unwrap();
                barrier.wait().await;
                stateset_sequencer::migrations::run_postgres(&pool).await
            }));
        }
        for h in handles {
            h.await.unwrap().unwrap_or_else(|e| {
                panic!("round {round}: concurrent first migration failed: {e}")
            });
        }

        sqlx::query(&format!("DROP DATABASE {dbname} WITH (FORCE)"))
            .execute(&admin)
            .await
            .unwrap();
    }
}

/// Two batches that share command_ids and submit them in opposite orders must
/// both complete -- one wins each command, the other gets DuplicateCommandId.
/// Reserving command_ids in hash-set (i.e. arbitrary) order let the two
/// transactions take the `ves_command_dedupe` row locks in opposite orders,
/// and PostgreSQL resolved the resulting deadlock (40P01) by killing one whole
/// ingest. Reservation is now in sorted order, which is deadlock-free by
/// construction. Repeated because the interleaving is scheduler-dependent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn postgres_ves_concurrent_batches_with_shared_command_ids_never_deadlock() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };
    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();
    let tenant_id = TenantId::new();
    let store_id = StoreId::new();
    let agent_id = AgentId::new();
    let key = AgentSigningKey::generate();
    let registry = Arc::new(PgAgentKeyRegistry::new(pool.clone()));
    registry
        .register_key(
            &AgentKeyLookup::new(&tenant_id, &agent_id, AgentKeyId::default()),
            AgentKeyEntry::new(key.public_key_bytes()),
        )
        .await
        .unwrap();
    let ves = Arc::new(VesSequencer::new(pool, registry));

    let mk = |round: usize, tag: &str, cmd: Uuid| {
        VesEventEnvelope::new_plaintext(
            tenant_id.clone(),
            store_id.clone(),
            agent_id.clone(),
            AgentKeyId::default(),
            EntityType::order(),
            format!("ord-{round}-{tag}"),
            EventType::new("order.updated"),
            json!({ "round": round, "tag": tag }),
            &key,
        )
        .with_command_id(cmd)
    };

    for round in 0..30 {
        let cmds: Vec<Uuid> = (0..6).map(|_| Uuid::new_v4()).collect();
        let a: Vec<_> = cmds
            .iter()
            .enumerate()
            .map(|(i, c)| mk(round, &format!("a{i}"), *c))
            .collect();
        let b: Vec<_> = cmds
            .iter()
            .rev()
            .enumerate()
            .map(|(i, c)| mk(round, &format!("b{i}"), *c))
            .collect();
        let barrier = Arc::new(Barrier::new(2));
        let hs: Vec<_> = [a, b]
            .into_iter()
            .map(|events| {
                let ves = ves.clone();
                let barrier = barrier.clone();
                tokio::spawn(async move {
                    barrier.wait().await;
                    ves.ingest(events).await
                })
            })
            .collect();
        let mut accepted = 0u32;
        for h in hs {
            let r = h
                .await
                .unwrap()
                .unwrap_or_else(|e| panic!("round {round}: ingest failed: {e}"));
            accepted += r.events_accepted;
        }
        assert_eq!(
            accepted, 6,
            "round {round}: each command must be honoured exactly once"
        );
    }
}

/// Randomised concurrent ingest. The product invariant is that per stream the
/// sequence is contiguous from 1, every accepted event has exactly one
/// sequence number, exact replays return the original receipt rather than a
/// new number, and a command_id is honoured exactly once -- under *any*
/// interleaving of batches. The fixed-shape test above checks one
/// interleaving; this one draws batch sizes, stream choice, replay duplicates
/// and command_id collisions from a seeded RNG so a failure reproduces.
///
/// Reproduce a failure with `SEQ_TEST_SEED=<printed seed>`.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn postgres_ves_concurrent_ingest_randomized_preserves_sequence_invariants() {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use stateset_sequencer::infra::VesRejectionReason;
    use std::collections::{HashMap, HashSet};

    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };
    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let seed: u64 = std::env::var("SEQ_TEST_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(rand::random);
    eprintln!("SEQ_TEST_SEED={seed}");
    let mut rng = StdRng::seed_from_u64(seed);

    let registry = Arc::new(PgAgentKeyRegistry::new(pool.clone()));
    let ves = Arc::new(VesSequencer::new(pool.clone(), registry.clone()));

    // Three independent streams, each with its own registered signing key.
    struct Stream {
        tenant_id: TenantId,
        store_id: StoreId,
        agent_id: AgentId,
        key: AgentSigningKey,
    }
    let mut streams = Vec::new();
    for _ in 0..3 {
        let tenant_id = TenantId::new();
        let store_id = StoreId::new();
        let agent_id = AgentId::new();
        let key = AgentSigningKey::generate();
        registry
            .register_key(
                &AgentKeyLookup::new(&tenant_id, &agent_id, AgentKeyId::default()),
                AgentKeyEntry::new(key.public_key_bytes()),
            )
            .await
            .unwrap();
        streams.push(Stream {
            tenant_id,
            store_id,
            agent_id,
            key,
        });
    }

    // Build batches. Each event is fresh, a replay of an event in an earlier
    // batch (same envelope), or a *different* event reusing an earlier
    // command_id (must lose the dedupe race).
    let batches_n = 16;
    let mut batches: Vec<(usize, Vec<VesEventEnvelope>)> = Vec::new();
    let mut fresh_by_stream: Vec<Vec<VesEventEnvelope>> = vec![Vec::new(); streams.len()];
    let mut used_commands_by_stream: Vec<Vec<Uuid>> = vec![Vec::new(); streams.len()];
    let mut replayed: HashSet<Uuid> = HashSet::new();
    let mut command_collisions: HashMap<Uuid, Vec<Uuid>> = HashMap::new(); // command -> event_ids
    for b in 0..batches_n {
        let si = rng.gen_range(0..streams.len());
        let st = &streams[si];
        let size = rng.gen_range(1..=20);
        let mut events = Vec::with_capacity(size);
        for i in 0..size {
            let roll: f64 = rng.gen();
            if roll < 0.15 && !fresh_by_stream[si].is_empty() {
                let idx = rng.gen_range(0..fresh_by_stream[si].len());
                let e = fresh_by_stream[si][idx].clone();
                replayed.insert(e.event_id);
                events.push(e);
                continue;
            }
            let command_id = if roll < 0.30 && !used_commands_by_stream[si].is_empty() {
                let idx = rng.gen_range(0..used_commands_by_stream[si].len());
                used_commands_by_stream[si][idx]
            } else {
                Uuid::new_v4()
            };
            let e = VesEventEnvelope::new_plaintext(
                st.tenant_id.clone(),
                st.store_id.clone(),
                st.agent_id.clone(),
                AgentKeyId::default(),
                EntityType::order(),
                format!("ord-{b}-{i}"),
                EventType::new("order.updated"),
                json!({ "b": b, "i": i, "seed": seed }),
                &st.key,
            )
            .with_command_id(command_id);
            command_collisions
                .entry(command_id)
                .or_default()
                .push(e.event_id);
            used_commands_by_stream[si].push(command_id);
            fresh_by_stream[si].push(e.clone());
            events.push(e);
        }
        batches.push((si, events));
    }

    // Fire everything at once.
    let barrier = Arc::new(Barrier::new(batches.len()));
    let mut handles = Vec::new();
    for (si, events) in batches.clone() {
        let ves = ves.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            (si, ves.ingest(events).await.unwrap())
        }));
    }

    let mut seq_of: HashMap<Uuid, u64> = HashMap::new();
    let mut accepted_by_stream: Vec<HashSet<Uuid>> = vec![HashSet::new(); streams.len()];
    let mut ranges_by_stream: Vec<Vec<(u64, u64)>> = vec![Vec::new(); streams.len()];
    let mut rejected: HashMap<Uuid, VesRejectionReason> = HashMap::new();
    for h in handles {
        let (si, r) = h.await.unwrap();
        // A receipt must give one and only one sequence number per event id.
        for rc in &r.receipts {
            if let Some(prev) = seq_of.insert(rc.event_id, rc.sequence_number) {
                assert_eq!(
                    prev, rc.sequence_number,
                    "event {} got two sequence numbers",
                    rc.event_id
                );
            }
        }
        if let (Some(s), Some(e)) = (r.assigned_sequence_start, r.assigned_sequence_end) {
            assert!(s <= e, "seed {seed}: inverted assigned range {s}..={e}");
            assert_eq!(
                (e - s + 1) as u32,
                r.events_accepted,
                "seed {seed}: assigned range must be exactly the accepted count"
            );
            ranges_by_stream[si].push((s, e));
        } else {
            assert_eq!(
                r.events_accepted, 0,
                "seed {seed}: accepted events without a range"
            );
        }
        for rj in &r.events_rejected {
            rejected.insert(rj.event_id, rj.reason.clone());
        }
        // Everything in a receipt that is not rejected was accepted (or replayed).
        for rc in &r.receipts {
            accepted_by_stream[si].insert(rc.event_id);
        }
    }

    for (si, st) in streams.iter().enumerate() {
        let head = ves.head(&st.tenant_id, &st.store_id).await.unwrap();
        let stored = ves
            .read_range(&st.tenant_id, &st.store_id, 1, head.max(1))
            .await
            .unwrap();
        // Contiguous from 1, no gaps, no duplicates.
        assert_eq!(
            stored.len() as u64,
            head,
            "seed {seed}: stream {si} head/rows mismatch"
        );
        for (i, ev) in stored.iter().enumerate() {
            assert_eq!(
                ev.sequence_number(),
                i as u64 + 1,
                "seed {seed}: stream {si} gap at {i}"
            );
        }
        let ids: HashSet<Uuid> = stored.iter().map(|e| e.event_id()).collect();
        assert_eq!(
            ids.len(),
            stored.len(),
            "seed {seed}: duplicate event stored in stream {si}"
        );
        // Accepted batch ranges are disjoint and tile 1..=head exactly.
        let mut rs = ranges_by_stream[si].clone();
        rs.sort_unstable();
        let mut expect = 1u64;
        for (s, e) in &rs {
            assert_eq!(
                *s, expect,
                "seed {seed}: stream {si} ranges do not tile: {rs:?}"
            );
            expect = e + 1;
        }
        assert_eq!(
            expect - 1,
            head,
            "seed {seed}: stream {si} ranges do not reach head: {rs:?}"
        );
        // Every stored event has a receipt with the matching number.
        for ev in &stored {
            assert_eq!(
                seq_of.get(&ev.event_id()),
                Some(&ev.sequence_number()),
                "seed {seed}"
            );
        }
    }

    // Command-id collisions: exactly one event per command is stored; the rest
    // were rejected as DuplicateCommandId (never silently dropped).
    let stored_ids: HashSet<Uuid> = seq_of.keys().copied().collect();
    for (cmd, ids) in command_collisions.iter().filter(|(_, v)| v.len() > 1) {
        let winners: Vec<_> = ids.iter().filter(|id| stored_ids.contains(id)).collect();
        assert_eq!(
            winners.len(),
            1,
            "seed {seed}: command {cmd} should win exactly once, got {ids:?}"
        );
        for id in ids.iter().filter(|id| !stored_ids.contains(id)) {
            assert_eq!(
                rejected.get(id),
                Some(&VesRejectionReason::DuplicateCommandId),
                "seed {seed}: loser {id} of command {cmd} must be rejected as DuplicateCommandId"
            );
        }
    }
    eprintln!(
        "seed {seed}: {} replays, {} command collisions, all invariants held",
        replayed.len(),
        command_collisions.values().filter(|v| v.len() > 1).count()
    );
}

#[cfg(feature = "stark")]
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

    // Plaintext event carrying a canonical integer minor-unit amount.
    //
    // A STARK compliance proof commits to an amount; the sequencer
    // independently re-derives that amount from the payload it stored at
    // ingest and rejects proofs committing to a different one. An encrypted
    // payload cannot be re-extracted (the plain hash is salted), so it is
    // refused unless VES_STARK_ALLOW_UNVERIFIED_AMOUNT_BINDING is set. Both
    // branches are unit-tested in api::handlers::ves::amount_binding; this
    // test drives the full REST flow over the strong path, where the binding
    // is genuinely verified.
    let payload = json!({ "total_amount": 5_000u64 });
    let payload_plain_hash = stateset_sequencer::crypto::payload_plain_hash(&payload).to_vec();
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
            $1,NULL,1,$2,$3,$4,1,'order','ord-1','order.created',$5,$6,0,$7,NULL,$8,$9,$10,$11,1,NULL
        )
        "#,
    )
    .bind(event_id)
    .bind(tenant_id)
    .bind(store_id)
    .bind(agent_id)
    .bind(created_at)
    .bind(&created_at_str)
    .bind(&payload)
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
    let commitment_reader = Arc::new(PgCommitmentEngine::new(pool.clone()));
    let ves_commitment_engine = Arc::new(PgVesCommitmentEngine::new(pool.clone()));
    let ves_commitment_reader = Arc::new(PgVesCommitmentEngine::new(pool.clone()));
    let ves_validity_proof_store = Arc::new(PgVesValidityProofStore::new(
        pool.clone(),
        payload_encryption_proofs.clone(),
    ));
    let ves_compliance_proof_store = Arc::new(PgVesComplianceProofStore::new(
        pool.clone(),
        payload_encryption_proofs,
    ));

    let cache_manager = Arc::new(stateset_sequencer::infra::CacheManager::new());
    let agent_key_registry = Arc::new(PgAgentKeyRegistry::new(pool.clone()));
    let ves_sequencer = Arc::new(VesSequencer::new(pool.clone(), agent_key_registry.clone()));
    let ves_sequencer_reader =
        Arc::new(VesSequencer::new(pool.clone(), agent_key_registry.clone()));
    let schema_store = Arc::new(stateset_sequencer::infra::PgSchemaStore::new(pool.clone()));
    let x402_repository = Arc::new(stateset_sequencer::infra::PgX402Repository::new(
        pool.clone(),
    ));

    let metrics = Arc::new(stateset_sequencer::metrics::MetricsRegistry::new());
    let api_key_validator = Arc::new(ApiKeyValidator::new());
    let api_key_store = Arc::new(stateset_sequencer::auth::PgApiKeyStore::new(pool.clone()));

    let state = AppState {
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
        api_key_validator: api_key_validator.clone(),
        api_key_store,
        public_registration_enabled: true,
        public_registration_limiter: None,
        trust_proxy_headers: false,
        audit_logger: None,
    };

    let authenticator = Arc::new(Authenticator::new(api_key_validator));
    let auth_state = AuthMiddlewareState {
        authenticator,
        require_auth: false,
        rate_limiter: None,
        credential_rate_limiter: Arc::new(RateLimiter::new(1000)),
        pool_monitor: None,
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

    let public_inputs: ves_stark_primitives::public_inputs::CompliancePublicInputs =
        serde_json::from_value(inputs_json["public_inputs"].clone()).unwrap();
    let witness = ves_stark_prover::ComplianceWitness::new(5000, public_inputs);

    let prover = ves_stark_prover::ComplianceProver::with_policy(
        ves_stark_prover::Policy::aml_threshold(10000),
    );
    let proof = prover.prove(&witness).unwrap();

    let proof_bytes = proof.proof_bytes.clone();
    let proof_b64 = base64::engine::general_purpose::STANDARD.encode(&proof_bytes);

    let submit_body = json!({
        "proofType": "stark",
        "proofVersion": ves_stark_verifier::PROOF_VERSION,
        "policyId": "aml.threshold",
        "policyParams": { "threshold": 10000 },
        "proofB64": proof_b64,
        "witnessCommitment": proof.witness_commitment,
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

    // Re-submitting the identical proof is idempotent, not a conflict.
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
        "resubmitting the same proof should be idempotent: body={}",
        String::from_utf8_lossy(&body)
    );
    let replay_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        replay_json["proof_id"].as_str().unwrap(),
        proof_id.to_string(),
        "idempotent resubmit must return the original proof_id"
    );

    // Soundness: a prover committing to a different amount than the stored
    // payload holds must be rejected outright, not merely recorded. This is
    // the mechanism that stops a 50_000 payment being proved as 5_000 to duck
    // a reporting threshold: the sequencer re-extracts the amount from the
    // payload it stored at ingest and compares it against the submitted
    // witness commitment, before the proof is verified or persisted.
    //
    // (This replaces an older assertion that submitted a second *valid* proof
    // for a different amount to force a 409. Public inputs are now bound to
    // the payload amount, so such a witness can no longer be constructed at
    // all -- the fraud is refused a layer earlier than it used to be.)
    let mismatched_commitment =
        ves_stark_primitives::payload_amount::amount_witness_commitment(4_000);
    let mismatched_body = json!({
        "proofType": "stark",
        "proofVersion": ves_stark_verifier::PROOF_VERSION,
        "policyId": "aml.threshold",
        "policyParams": { "threshold": 10000 },
        "proofB64": proof_b64,
        "witnessCommitment": mismatched_commitment,
    });

    let (status, body) = send(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri(format!("/api/v1/ves/compliance/{event_id}/proofs"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&mismatched_body).unwrap()))
            .unwrap(),
    )
    .await;
    let body_text = String::from_utf8_lossy(&body);
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a witness commitment disagreeing with the payload amount must be rejected: \
         body={body_text}"
    );
    assert!(
        body_text.contains("Payload amount binding rejected"),
        "rejection should name the amount binding: body={body_text}"
    );
}
