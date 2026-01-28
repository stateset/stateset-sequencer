//! gRPC service integration tests.
//!
//! Tests for the gRPC Sequencer service implementation.
//! Run with: `cargo test -- --ignored`

mod common;

use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use uuid::Uuid;

use stateset_sequencer::domain::{
    AgentId, EntityType, EventBatch, EventEnvelope, EventType, StoreId, TenantId,
};
use stateset_sequencer::grpc::SequencerService;
use stateset_sequencer::infra::{
    CommitmentEngine, IngestService, PayloadEncryption, PgCommitmentEngine, PgEventStore,
    PgSequencer,
};
use stateset_sequencer::proto::sequencer_server::Sequencer as SequencerTrait;
use stateset_sequencer::proto::{
    GetCommitmentRequest, GetEntityHistoryRequest, GetHeadRequest, GetInclusionProofRequest,
    PushRequest,
};

use tonic::Request;

// Note: common module provides test helpers but not all are used here
#[allow(unused_imports)]
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

async fn create_grpc_service(pool: sqlx::PgPool) -> SequencerService {
    let payload_encryption = Arc::new(PayloadEncryption::disabled());
    let sequencer = Arc::new(PgSequencer::new(pool.clone(), payload_encryption.clone()));
    let event_store = Arc::new(PgEventStore::new(pool.clone(), payload_encryption));
    let commitment_engine = Arc::new(PgCommitmentEngine::new(pool.clone()));
    let cache_manager = Arc::new(stateset_sequencer::infra::CacheManager::new());

    SequencerService::new(
        sequencer,
        event_store,
        commitment_engine.clone(),
        commitment_engine,
        cache_manager,
    )
}

fn create_test_event(
    tenant_id: &TenantId,
    store_id: &StoreId,
    agent_id: &AgentId,
    entity_id: &str,
) -> EventEnvelope {
    EventEnvelope::new(
        tenant_id.clone(),
        store_id.clone(),
        EntityType::order(),
        entity_id.to_string(),
        EventType::new("order.created"),
        json!({ "test": true, "entity_id": entity_id }),
        agent_id.clone(),
    )
}

async fn seed_events_for_test(
    pool: &sqlx::PgPool,
    tenant_id: &TenantId,
    store_id: &StoreId,
    count: usize,
) {
    let payload_encryption = Arc::new(PayloadEncryption::disabled());
    let sequencer = PgSequencer::new(pool.clone(), payload_encryption);
    let agent_id = AgentId::new();

    let events: Vec<EventEnvelope> = (0..count)
        .map(|i| create_test_event(tenant_id, store_id, &agent_id, &format!("ord-grpc-{}", i)))
        .collect();

    sequencer
        .ingest(EventBatch::new(agent_id, events))
        .await
        .unwrap();
}

// ============================================================================
// gRPC Push (Ingest) Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_grpc_push_events_success() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let service = create_grpc_service(pool).await;

    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();
    let agent_id = Uuid::new_v4();

    let payload = json!({ "customer_id": "cust-001", "total": 99.99 });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let payload_hash = stateset_sequencer::crypto::canonical_json_hash(&payload);

    let request = Request::new(PushRequest {
        agent_id: agent_id.to_string(),
        events: vec![stateset_sequencer::proto::EventEnvelope {
            event_id: Uuid::new_v4().to_string(),
            command_id: String::new(),
            tenant_id: tenant_id.to_string(),
            store_id: store_id.to_string(),
            entity_type: "order".to_string(),
            entity_id: "ord-grpc-001".to_string(),
            event_type: "order.created".to_string(),
            payload: payload_bytes,
            payload_hash: payload_hash.to_vec(),
            base_version: 0,
            created_at: Some(prost_types::Timestamp {
                seconds: chrono::Utc::now().timestamp(),
                nanos: 0,
            }),
            source_agent: agent_id.to_string(),
            signature: vec![],
        }],
    });

    let response = service.push(request).await.unwrap();
    let response = response.into_inner();

    assert_eq!(response.events_accepted, 1);
    assert_eq!(response.events_rejected.len(), 0);
    assert!(!response.batch_id.is_empty());
    assert_eq!(response.assigned_sequence_start, 1);
    assert_eq!(response.assigned_sequence_end, 1);
}

#[tokio::test]
#[ignore]
async fn test_grpc_push_batch_success() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let service = create_grpc_service(pool).await;

    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();
    let agent_id = Uuid::new_v4();

    let events: Vec<stateset_sequencer::proto::EventEnvelope> = (0..5)
        .map(|i| {
            let payload = json!({ "index": i });
            let payload_bytes = serde_json::to_vec(&payload).unwrap();
            let payload_hash = stateset_sequencer::crypto::canonical_json_hash(&payload);

            stateset_sequencer::proto::EventEnvelope {
                event_id: Uuid::new_v4().to_string(),
                command_id: String::new(),
                tenant_id: tenant_id.to_string(),
                store_id: store_id.to_string(),
                entity_type: "order".to_string(),
                entity_id: format!("ord-batch-{}", i),
                event_type: "order.created".to_string(),
                payload: payload_bytes,
                payload_hash: payload_hash.to_vec(),
                base_version: 0,
                created_at: Some(prost_types::Timestamp {
                    seconds: chrono::Utc::now().timestamp(),
                    nanos: 0,
                }),
                source_agent: agent_id.to_string(),
                signature: vec![],
            }
        })
        .collect();

    let request = Request::new(PushRequest {
        agent_id: agent_id.to_string(),
        events,
    });

    let response = service.push(request).await.unwrap();
    let response = response.into_inner();

    assert_eq!(response.events_accepted, 5);
    assert_eq!(response.events_rejected.len(), 0);
    assert_eq!(response.assigned_sequence_start, 1);
    assert_eq!(response.assigned_sequence_end, 5);
}

#[tokio::test]
#[ignore]
async fn test_grpc_push_rejects_duplicate() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let service = create_grpc_service(pool).await;

    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();
    let agent_id = Uuid::new_v4();
    let event_id = Uuid::new_v4();

    let payload = json!({ "test": true });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let payload_hash = stateset_sequencer::crypto::canonical_json_hash(&payload);

    let event = stateset_sequencer::proto::EventEnvelope {
        event_id: event_id.to_string(),
        command_id: String::new(),
        tenant_id: tenant_id.to_string(),
        store_id: store_id.to_string(),
        entity_type: "order".to_string(),
        entity_id: "ord-dup".to_string(),
        event_type: "order.created".to_string(),
        payload: payload_bytes.clone(),
        payload_hash: payload_hash.to_vec(),
        base_version: 0,
        created_at: Some(prost_types::Timestamp {
            seconds: chrono::Utc::now().timestamp(),
            nanos: 0,
        }),
        source_agent: agent_id.to_string(),
        signature: vec![],
    };

    // First push
    let request = Request::new(PushRequest {
        agent_id: agent_id.to_string(),
        events: vec![event.clone()],
    });
    let response = service.push(request).await.unwrap().into_inner();
    assert_eq!(response.events_accepted, 1);

    // Second push (duplicate)
    let request = Request::new(PushRequest {
        agent_id: agent_id.to_string(),
        events: vec![event],
    });
    let response = service.push(request).await.unwrap().into_inner();
    assert_eq!(response.events_accepted, 0);
    assert_eq!(response.events_rejected.len(), 1);
}

// ============================================================================
// gRPC Pull Tests
// ============================================================================
// Note: Pull returns a streaming response which requires more complex test setup.
// The streaming tests are tested via the REST API integration tests instead.
// Here we test the non-streaming endpoints thoroughly.

// ============================================================================
// gRPC GetHead Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_grpc_get_head_success() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let tenant_id = TenantId::new();
    let store_id = StoreId::new();

    seed_events_for_test(&pool, &tenant_id, &store_id, 7).await;

    let service = create_grpc_service(pool).await;

    let request = Request::new(GetHeadRequest {
        tenant_id: tenant_id.0.to_string(),
        store_id: store_id.0.to_string(),
    });

    let response = service.get_head(request).await.unwrap().into_inner();

    assert_eq!(response.head_sequence, 7);
}

#[tokio::test]
#[ignore]
async fn test_grpc_get_head_empty_store() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let service = create_grpc_service(pool).await;

    let request = Request::new(GetHeadRequest {
        tenant_id: Uuid::new_v4().to_string(),
        store_id: Uuid::new_v4().to_string(),
    });

    let response = service.get_head(request).await.unwrap().into_inner();

    assert_eq!(response.head_sequence, 0);
}

// ============================================================================
// gRPC GetEntityHistory Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_grpc_get_entity_history_success() {
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
    let target_entity = "ord-history-grpc";

    // Create multiple events for the same entity
    let events = vec![
        EventEnvelope::new(
            tenant_id.clone(),
            store_id.clone(),
            EntityType::order(),
            target_entity.to_string(),
            EventType::new("order.created"),
            json!({ "status": "created" }),
            agent_id.clone(),
        ),
        EventEnvelope::new(
            tenant_id.clone(),
            store_id.clone(),
            EntityType::order(),
            target_entity.to_string(),
            EventType::new("order.confirmed"),
            json!({ "status": "confirmed" }),
            agent_id.clone(),
        ),
        EventEnvelope::new(
            tenant_id.clone(),
            store_id.clone(),
            EntityType::order(),
            "ord-other".to_string(),
            EventType::new("order.created"),
            json!({ "status": "created" }),
            agent_id.clone(),
        ),
    ];

    sequencer
        .ingest(EventBatch::new(agent_id, events))
        .await
        .unwrap();

    let service = create_grpc_service(pool).await;

    let request = Request::new(GetEntityHistoryRequest {
        tenant_id: tenant_id.0.to_string(),
        store_id: store_id.0.to_string(),
        entity_type: "order".to_string(),
        entity_id: target_entity.to_string(),
        from_version: 0,
        to_version: 0, // 0 means no upper limit
    });

    let response = service.get_entity_history(request).await.unwrap().into_inner();

    assert_eq!(response.events.len(), 2);
    for event in &response.events {
        let envelope = event.envelope.as_ref().unwrap();
        assert_eq!(envelope.entity_id, target_entity);
    }
}

// ============================================================================
// gRPC GetCommitment Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_grpc_get_commitment_success() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let payload_encryption = Arc::new(PayloadEncryption::disabled());
    let sequencer = PgSequencer::new(pool.clone(), payload_encryption);
    let commitment_engine = PgCommitmentEngine::new(pool.clone());

    let tenant_id = TenantId::new();
    let store_id = StoreId::new();
    let agent_id = AgentId::new();

    // Seed events
    let events: Vec<EventEnvelope> = (0..5)
        .map(|i| create_test_event(&tenant_id, &store_id, &agent_id, &format!("ord-commit-{}", i)))
        .collect();

    sequencer
        .ingest(EventBatch::new(agent_id, events))
        .await
        .unwrap();

    // Create commitment
    let commitment = commitment_engine
        .create_commitment(&tenant_id, &store_id, (1, 5))
        .await
        .unwrap();

    commitment_engine.store_commitment(&commitment).await.unwrap();

    let service = create_grpc_service(pool).await;

    let request = Request::new(GetCommitmentRequest {
        batch_id: commitment.batch_id.to_string(),
    });

    let response = service.get_commitment(request).await.unwrap().into_inner();
    let commitment_resp = response.commitment.unwrap();

    assert_eq!(commitment_resp.batch_id, commitment.batch_id.to_string());
    assert_eq!(commitment_resp.event_count, 5);
    assert_eq!(commitment_resp.start_sequence, 1);
    assert_eq!(commitment_resp.end_sequence, 5);
}

#[tokio::test]
#[ignore]
async fn test_grpc_get_commitment_not_found() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let service = create_grpc_service(pool).await;

    let request = Request::new(GetCommitmentRequest {
        batch_id: Uuid::new_v4().to_string(),
    });

    let result = service.get_commitment(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
}

// ============================================================================
// gRPC GetInclusionProof Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_grpc_get_inclusion_proof_success() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let payload_encryption = Arc::new(PayloadEncryption::disabled());
    let sequencer = PgSequencer::new(pool.clone(), payload_encryption);
    let commitment_engine = PgCommitmentEngine::new(pool.clone());

    let tenant_id = TenantId::new();
    let store_id = StoreId::new();
    let agent_id = AgentId::new();

    // Seed events and capture event IDs
    let events: Vec<EventEnvelope> = (0..8)
        .map(|i| create_test_event(&tenant_id, &store_id, &agent_id, &format!("ord-proof-{}", i)))
        .collect();

    let event_id = events[3].event_id; // Get the 4th event's ID

    sequencer
        .ingest(EventBatch::new(agent_id, events))
        .await
        .unwrap();

    // Create commitment
    let commitment = commitment_engine
        .create_commitment(&tenant_id, &store_id, (1, 8))
        .await
        .unwrap();

    commitment_engine.store_commitment(&commitment).await.unwrap();

    let service = create_grpc_service(pool).await;

    // Get proof for the event using batch_id and event_id
    let request = Request::new(GetInclusionProofRequest {
        batch_id: commitment.batch_id.to_string(),
        event_id: event_id.to_string(),
    });

    let response = service.get_inclusion_proof(request).await.unwrap().into_inner();
    let proof = response.proof.unwrap();

    assert!(!proof.merkle_root.is_empty());
    assert!(!proof.proof_hashes.is_empty());
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_grpc_invalid_uuid_returns_error() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let service = create_grpc_service(pool).await;

    let request = Request::new(GetHeadRequest {
        tenant_id: "not-a-uuid".to_string(),
        store_id: "also-not-a-uuid".to_string(),
    });

    let result = service.get_head(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
#[ignore]
async fn test_grpc_empty_events_batch() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let service = create_grpc_service(pool).await;

    let request = Request::new(PushRequest {
        agent_id: Uuid::new_v4().to_string(),
        events: vec![],
    });

    let response = service.push(request).await.unwrap().into_inner();

    assert_eq!(response.events_accepted, 0);
    assert_eq!(response.events_rejected.len(), 0);
}
