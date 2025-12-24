//! PostgreSQL persistence layer tests.
//!
//! Tests for the core persistence operations:
//! - Sequencer: monotonic ordering, concurrent writes
//! - EventStore: append, read, entity queries
//! - CommitmentEngine: Merkle tree operations
//!
//! Run with: `cargo test -- --ignored`

mod common;

use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use uuid::Uuid;

use stateset_sequencer::domain::{
    AgentId, EntityType, EventBatch, EventEnvelope, EventType, Hash256, StoreId, TenantId,
};
use stateset_sequencer::infra::{
    CommitmentEngine, EventStore, IngestService, PayloadEncryption, PgCommitmentEngine,
    PgEventStore, PgSequencer, Sequencer,
};


// ============================================================================
// Test Helpers
// ============================================================================

async fn connect_db() -> Option<sqlx::PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&url)
        .await
        .ok()?;
    Some(pool)
}

fn create_test_event(
    tenant_id: TenantId,
    store_id: StoreId,
    agent_id: AgentId,
    entity_id: &str,
) -> EventEnvelope {
    EventEnvelope::new(
        tenant_id,
        store_id,
        EntityType::order(),
        entity_id.to_string(),
        EventType::new("order.created"),
        json!({ "test": true }),
        agent_id,
    )
}

// ============================================================================
// Sequencer Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_sequencer_assigns_monotonic_sequences() {
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

    // Ingest 3 batches
    for batch_num in 0..3 {
        let events: Vec<EventEnvelope> = (0..5)
            .map(|i| {
                create_test_event(
                    tenant_id.clone(),
                    store_id.clone(),
                    agent_id.clone(),
                    &format!("ord-{}-{}", batch_num, i),
                )
            })
            .collect();

        let batch = EventBatch::new(agent_id.clone(), events);
        let receipt = sequencer.ingest(batch).await.unwrap();

        assert_eq!(receipt.events_accepted, 5);
        assert_eq!(receipt.events_rejected.len(), 0);
    }

    let head = sequencer.head(&tenant_id, &store_id).await.unwrap();
    assert_eq!(head, 15);
}

#[tokio::test]
#[ignore]
async fn test_sequencer_independent_streams() {
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
    let store_id_1 = StoreId::new();
    let store_id_2 = StoreId::new();
    let agent_id = AgentId::new();

    // Ingest to store 1
    let events1: Vec<EventEnvelope> = (0..10)
        .map(|i| {
            create_test_event(
                tenant_id.clone(),
                store_id_1.clone(),
                agent_id.clone(),
                &format!("ord-s1-{}", i),
            )
        })
        .collect();
    sequencer
        .ingest(EventBatch::new(agent_id.clone(), events1))
        .await
        .unwrap();

    // Ingest to store 2
    let events2: Vec<EventEnvelope> = (0..5)
        .map(|i| {
            create_test_event(
                tenant_id.clone(),
                store_id_2.clone(),
                agent_id.clone(),
                &format!("ord-s2-{}", i),
            )
        })
        .collect();
    sequencer
        .ingest(EventBatch::new(agent_id, events2))
        .await
        .unwrap();

    // Verify independent sequences
    let head1 = sequencer.head(&tenant_id, &store_id_1).await.unwrap();
    let head2 = sequencer.head(&tenant_id, &store_id_2).await.unwrap();

    assert_eq!(head1, 10);
    assert_eq!(head2, 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn test_sequencer_concurrent_writes_no_gaps() {
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

    let num_tasks = 10;
    let events_per_task = 20;
    let expected_total = (num_tasks * events_per_task) as u64;

    let mut handles = Vec::with_capacity(num_tasks);

    for task_idx in 0..num_tasks {
        let sequencer = sequencer.clone();
        let tenant_id = tenant_id.clone();
        let store_id = store_id.clone();

        handles.push(tokio::spawn(async move {
            let agent_id = AgentId::new();
            let events: Vec<EventEnvelope> = (0..events_per_task)
                .map(|i| {
                    EventEnvelope::new(
                        tenant_id.clone(),
                        store_id.clone(),
                        EntityType::order(),
                        format!("ord-{}-{}", task_idx, i),
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

    let mut total_accepted = 0u64;
    for handle in handles {
        let receipt = handle.await.unwrap();
        total_accepted += receipt.events_accepted as u64;
        assert!(receipt.events_rejected.is_empty());
    }

    assert_eq!(total_accepted, expected_total);

    let head = sequencer.head(&tenant_id, &store_id).await.unwrap();
    assert_eq!(head, expected_total);

    // Verify no gaps by reading all events
    let event_store = PgEventStore::new(pool, payload_encryption);
    let events = event_store
        .read_range(&tenant_id, &store_id, 1, head)
        .await
        .unwrap();

    assert_eq!(events.len() as u64, expected_total);

    // Verify monotonic sequences
    for (idx, event) in events.iter().enumerate() {
        assert_eq!(
            event.sequence_number(),
            (idx as u64) + 1,
            "Gap detected at index {}: expected {}, got {}",
            idx,
            idx + 1,
            event.sequence_number()
        );
    }
}

#[tokio::test]
#[ignore]
async fn test_sequencer_deduplication_by_event_id() {
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

    // First event
    let mut event1 = create_test_event(
        tenant_id.clone(),
        store_id.clone(),
        agent_id.clone(),
        "ord-dup",
    );
    event1.event_id = event_id;

    let receipt1 = sequencer
        .ingest(EventBatch::new(agent_id.clone(), vec![event1]))
        .await
        .unwrap();

    assert_eq!(receipt1.events_accepted, 1);
    assert_eq!(receipt1.head_sequence, 1);

    // Duplicate event (same event_id)
    let mut event2 = create_test_event(
        tenant_id.clone(),
        store_id.clone(),
        agent_id.clone(),
        "ord-dup",
    );
    event2.event_id = event_id;

    let receipt2 = sequencer
        .ingest(EventBatch::new(agent_id, vec![event2]))
        .await
        .unwrap();

    assert_eq!(receipt2.events_accepted, 0);
    assert_eq!(receipt2.events_rejected.len(), 1);
    assert_eq!(receipt2.head_sequence, 1); // Head didn't advance

    let head = sequencer.head(&tenant_id, &store_id).await.unwrap();
    assert_eq!(head, 1);
}

#[tokio::test]
#[ignore]
async fn test_sequencer_deduplication_by_command_id() {
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

    // First event with command_id
    let event1 = create_test_event(
        tenant_id.clone(),
        store_id.clone(),
        agent_id.clone(),
        "ord-cmd-1",
    )
    .with_command_id(command_id);

    let receipt1 = sequencer
        .ingest(EventBatch::new(agent_id.clone(), vec![event1]))
        .await
        .unwrap();

    assert_eq!(receipt1.events_accepted, 1);

    // Second event with same command_id (different event_id)
    let event2 = create_test_event(
        tenant_id.clone(),
        store_id.clone(),
        agent_id.clone(),
        "ord-cmd-2",
    )
    .with_command_id(command_id);

    let receipt2 = sequencer
        .ingest(EventBatch::new(agent_id, vec![event2]))
        .await
        .unwrap();

    assert_eq!(receipt2.events_accepted, 0);
    assert_eq!(receipt2.events_rejected.len(), 1);
}

// ============================================================================
// Event Store Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_event_store_read_range() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let payload_encryption = Arc::new(PayloadEncryption::disabled());
    let sequencer = PgSequencer::new(pool.clone(), payload_encryption.clone());
    let event_store = PgEventStore::new(pool.clone(), payload_encryption);

    let tenant_id = TenantId::new();
    let store_id = StoreId::new();
    let agent_id = AgentId::new();

    // Ingest events
    let events: Vec<EventEnvelope> = (0..20)
        .map(|i| {
            create_test_event(
                tenant_id.clone(),
                store_id.clone(),
                agent_id.clone(),
                &format!("ord-{}", i),
            )
        })
        .collect();

    sequencer
        .ingest(EventBatch::new(agent_id, events))
        .await
        .unwrap();

    // Read range
    let events = event_store
        .read_range(&tenant_id, &store_id, 5, 15)
        .await
        .unwrap();

    assert_eq!(events.len(), 11); // 5..=15 inclusive
    assert_eq!(events.first().unwrap().sequence_number(), 5);
    assert_eq!(events.last().unwrap().sequence_number(), 15);
}

#[tokio::test]
#[ignore]
async fn test_event_store_read_entity() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let payload_encryption = Arc::new(PayloadEncryption::disabled());
    let sequencer = PgSequencer::new(pool.clone(), payload_encryption.clone());
    let event_store = PgEventStore::new(pool.clone(), payload_encryption);

    let tenant_id = TenantId::new();
    let store_id = StoreId::new();
    let agent_id = AgentId::new();
    let target_entity = "ord-target";

    // Create events for multiple entities
    let mut events = Vec::new();

    // 3 events for target entity
    for event_type in ["order.created", "order.confirmed", "order.shipped"] {
        events.push(EventEnvelope::new(
            tenant_id.clone(),
            store_id.clone(),
            EntityType::order(),
            target_entity.to_string(),
            EventType::new(event_type),
            json!({ "type": event_type }),
            agent_id.clone(),
        ));
    }

    // 5 events for other entities
    for i in 0..5 {
        events.push(create_test_event(
            tenant_id.clone(),
            store_id.clone(),
            agent_id.clone(),
            &format!("ord-other-{}", i),
        ));
    }

    sequencer
        .ingest(EventBatch::new(agent_id, events))
        .await
        .unwrap();

    // Query entity history
    let entity_events = event_store
        .read_entity(&tenant_id, &store_id, &EntityType::order(), target_entity)
        .await
        .unwrap();

    assert_eq!(entity_events.len(), 3);
    for event in &entity_events {
        assert_eq!(event.entity_id(), target_entity);
    }
}

#[tokio::test]
#[ignore]
async fn test_event_store_read_by_id() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let payload_encryption = Arc::new(PayloadEncryption::disabled());
    let sequencer = PgSequencer::new(pool.clone(), payload_encryption.clone());
    let event_store = PgEventStore::new(pool.clone(), payload_encryption);

    let tenant_id = TenantId::new();
    let store_id = StoreId::new();
    let agent_id = AgentId::new();

    let event = create_test_event(
        tenant_id.clone(),
        store_id.clone(),
        agent_id.clone(),
        "ord-by-id",
    );
    let event_id = event.event_id;

    sequencer
        .ingest(EventBatch::new(agent_id, vec![event]))
        .await
        .unwrap();

    // Read by ID
    let found = event_store.read_by_id(event_id).await.unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().envelope.event_id, event_id);

    // Non-existent ID
    let not_found = event_store.read_by_id(Uuid::new_v4()).await.unwrap();
    assert!(not_found.is_none());
}

#[tokio::test]
#[ignore]
async fn test_event_store_event_exists() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let payload_encryption = Arc::new(PayloadEncryption::disabled());
    let sequencer = PgSequencer::new(pool.clone(), payload_encryption.clone());
    let event_store = PgEventStore::new(pool.clone(), payload_encryption);

    let tenant_id = TenantId::new();
    let store_id = StoreId::new();
    let agent_id = AgentId::new();

    let event = create_test_event(tenant_id.clone(), store_id.clone(), agent_id.clone(), "ord-exists");
    let event_id = event.event_id;

    sequencer
        .ingest(EventBatch::new(agent_id, vec![event]))
        .await
        .unwrap();

    assert!(event_store.event_exists(event_id).await.unwrap());
    assert!(!event_store.event_exists(Uuid::new_v4()).await.unwrap());
}

// ============================================================================
// Commitment Engine Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_commitment_engine_create_commitment() {
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

    // Ingest events
    let events: Vec<EventEnvelope> = (0..10)
        .map(|i| {
            create_test_event(
                tenant_id.clone(),
                store_id.clone(),
                agent_id.clone(),
                &format!("ord-commit-{}", i),
            )
        })
        .collect();

    sequencer
        .ingest(EventBatch::new(agent_id, events))
        .await
        .unwrap();

    // Create commitment
    let commitment = commitment_engine
        .create_commitment(&tenant_id, &store_id, (1, 10))
        .await
        .unwrap();

    assert_eq!(commitment.event_count, 10);
    assert_eq!(commitment.sequence_start(), 1);
    assert_eq!(commitment.sequence_end(), 10);
    assert!(!commitment.is_anchored());

    // Verify events_root is non-zero
    assert_ne!(commitment.events_root, [0u8; 32]);
}

#[tokio::test]
#[ignore]
async fn test_commitment_engine_store_and_retrieve() {
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

    // Ingest events
    let events: Vec<EventEnvelope> = (0..5)
        .map(|i| {
            create_test_event(
                tenant_id.clone(),
                store_id.clone(),
                agent_id.clone(),
                &format!("ord-store-{}", i),
            )
        })
        .collect();

    sequencer
        .ingest(EventBatch::new(agent_id, events))
        .await
        .unwrap();

    // Create and store commitment
    let commitment = commitment_engine
        .create_commitment(&tenant_id, &store_id, (1, 5))
        .await
        .unwrap();

    commitment_engine.store_commitment(&commitment).await.unwrap();

    // Retrieve by ID
    let retrieved = commitment_engine
        .get_commitment(commitment.batch_id)
        .await
        .unwrap();

    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.batch_id, commitment.batch_id);
    assert_eq!(retrieved.events_root, commitment.events_root);
    assert_eq!(retrieved.event_count, 5);
}

#[tokio::test]
#[ignore]
async fn test_commitment_engine_inclusion_proof() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let commitment_engine = PgCommitmentEngine::new(pool.clone());

    // Create test leaves (8 for a balanced tree)
    let leaves: Vec<Hash256> = (0..8).map(|i| [i as u8; 32]).collect();

    // Compute root
    let root = commitment_engine.compute_events_root(&leaves);

    // Generate and verify proofs for each leaf
    for (idx, leaf) in leaves.iter().enumerate() {
        let proof = commitment_engine.prove_inclusion(idx, &leaves);

        assert_eq!(proof.leaf_index, idx);
        assert!(!proof.proof_path.is_empty());

        let valid = commitment_engine.verify_inclusion(*leaf, &proof, root);
        assert!(valid, "Proof verification failed for leaf {}", idx);
    }
}

#[tokio::test]
#[ignore]
async fn test_commitment_engine_update_chain_tx() {
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

    // Ingest events
    let events: Vec<EventEnvelope> = (0..3)
        .map(|i| {
            create_test_event(
                tenant_id.clone(),
                store_id.clone(),
                agent_id.clone(),
                &format!("ord-anchor-{}", i),
            )
        })
        .collect();

    sequencer
        .ingest(EventBatch::new(agent_id, events))
        .await
        .unwrap();

    // Create and store commitment
    let commitment = commitment_engine
        .create_commitment(&tenant_id, &store_id, (1, 3))
        .await
        .unwrap();

    commitment_engine.store_commitment(&commitment).await.unwrap();

    // Update with chain tx hash
    let tx_hash: Hash256 = [0xAB; 32];
    commitment_engine
        .update_chain_tx(commitment.batch_id, tx_hash)
        .await
        .unwrap();

    // Verify update
    let updated = commitment_engine
        .get_commitment(commitment.batch_id)
        .await
        .unwrap()
        .unwrap();

    assert!(updated.is_anchored());
    assert_eq!(updated.chain_tx_hash, Some(tx_hash));
}

#[tokio::test]
#[ignore]
async fn test_commitment_engine_list_unanchored() {
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

    // Ingest events
    let events: Vec<EventEnvelope> = (0..20)
        .map(|i| {
            create_test_event(
                tenant_id.clone(),
                store_id.clone(),
                agent_id.clone(),
                &format!("ord-unanchored-{}", i),
            )
        })
        .collect();

    sequencer
        .ingest(EventBatch::new(agent_id, events))
        .await
        .unwrap();

    // Create multiple commitments
    for (start, end) in [(1, 5), (6, 10), (11, 15), (16, 20)] {
        let commitment = commitment_engine
            .create_commitment(&tenant_id, &store_id, (start, end))
            .await
            .unwrap();
        commitment_engine.store_commitment(&commitment).await.unwrap();
    }

    // List unanchored
    let unanchored = commitment_engine.list_unanchored().await.unwrap();
    assert!(unanchored.len() >= 4);

    // Anchor one
    let first = &unanchored[0];
    commitment_engine
        .update_chain_tx(first.batch_id, [0xFF; 32])
        .await
        .unwrap();

    // List again - should have one less
    let unanchored_after = commitment_engine.list_unanchored().await.unwrap();
    assert_eq!(unanchored_after.len(), unanchored.len() - 1);
}

// ============================================================================
// Payload Encryption Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_event_store_with_encryption() {
    use stateset_sequencer::crypto::StaticKeyManager;
    use stateset_sequencer::infra::PayloadEncryptionMode;

    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let key_manager = Arc::new(StaticKeyManager::new([7u8; 32]));
    let payload_encryption = Arc::new(PayloadEncryption::new(
        PayloadEncryptionMode::Required,
        key_manager,
    ));

    let sequencer = PgSequencer::new(pool.clone(), payload_encryption.clone());
    let event_store = PgEventStore::new(pool.clone(), payload_encryption);

    let tenant_id = TenantId::new();
    let store_id = StoreId::new();
    let agent_id = AgentId::new();

    let original_payload = json!({
        "secret": "sensitive data",
        "amount": 12345.67
    });

    let event = EventEnvelope::new(
        tenant_id.clone(),
        store_id.clone(),
        EntityType::order(),
        "ord-encrypted".to_string(),
        EventType::new("order.created"),
        original_payload.clone(),
        agent_id.clone(),
    );
    let event_id = event.event_id;

    sequencer
        .ingest(EventBatch::new(agent_id, vec![event]))
        .await
        .unwrap();

    // Read back and verify decryption
    let retrieved = event_store.read_by_id(event_id).await.unwrap().unwrap();
    assert_eq!(retrieved.envelope.payload, original_payload);
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_empty_batch_ingestion() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let payload_encryption = Arc::new(PayloadEncryption::disabled());
    let sequencer = PgSequencer::new(pool.clone(), payload_encryption);

    let agent_id = AgentId::new();
    let batch = EventBatch::new(agent_id, vec![]);

    let receipt = sequencer.ingest(batch).await.unwrap();

    assert_eq!(receipt.events_accepted, 0);
    assert_eq!(receipt.events_rejected.len(), 0);
    assert!(receipt.assigned_sequence_start.is_none());
    assert!(receipt.assigned_sequence_end.is_none());
}

#[tokio::test]
#[ignore]
async fn test_large_payload_event() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let payload_encryption = Arc::new(PayloadEncryption::disabled());
    let sequencer = PgSequencer::new(pool.clone(), payload_encryption.clone());
    let event_store = PgEventStore::new(pool.clone(), payload_encryption);

    let tenant_id = TenantId::new();
    let store_id = StoreId::new();
    let agent_id = AgentId::new();

    // Create a large payload (100KB of data)
    let large_data: String = (0..100_000).map(|_| 'x').collect();
    let large_payload = json!({
        "data": large_data,
        "size": large_data.len()
    });

    let event = EventEnvelope::new(
        tenant_id.clone(),
        store_id.clone(),
        EntityType::order(),
        "ord-large".to_string(),
        EventType::new("order.created"),
        large_payload.clone(),
        agent_id.clone(),
    );
    let event_id = event.event_id;

    let receipt = sequencer
        .ingest(EventBatch::new(agent_id, vec![event]))
        .await
        .unwrap();

    assert_eq!(receipt.events_accepted, 1);

    // Verify retrieval
    let retrieved = event_store.read_by_id(event_id).await.unwrap().unwrap();
    assert_eq!(retrieved.envelope.payload["size"], large_payload["size"]);
}

#[tokio::test]
#[ignore]
async fn test_unicode_payload() {
    let Some(pool) = connect_db().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();

    let payload_encryption = Arc::new(PayloadEncryption::disabled());
    let sequencer = PgSequencer::new(pool.clone(), payload_encryption.clone());
    let event_store = PgEventStore::new(pool.clone(), payload_encryption);

    let tenant_id = TenantId::new();
    let store_id = StoreId::new();
    let agent_id = AgentId::new();

    let unicode_payload = json!({
        "greeting": "Hello, 世界! 🌍",
        "japanese": "こんにちは",
        "emoji": "🚀💰📦",
        "arabic": "مرحبا",
        "special": "null\t\n\r\"\\/"
    });

    let event = EventEnvelope::new(
        tenant_id.clone(),
        store_id.clone(),
        EntityType::order(),
        "ord-unicode".to_string(),
        EventType::new("order.created"),
        unicode_payload.clone(),
        agent_id.clone(),
    );
    let event_id = event.event_id;

    sequencer
        .ingest(EventBatch::new(agent_id, vec![event]))
        .await
        .unwrap();

    // Verify roundtrip
    let retrieved = event_store.read_by_id(event_id).await.unwrap().unwrap();
    assert_eq!(retrieved.envelope.payload, unicode_payload);
}
