//! Integration tests for the sequencer service
//!
//! Tests the core event sequencing flow:
//! - Event ingestion
//! - Sequence number assignment
//! - Event storage and retrieval
//! - Commitment creation

mod common;

use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use common::*;

// ============================================================================
// Unit Tests for Domain Types
// ============================================================================

#[test]
fn test_entity_type_creation() {
    use stateset_sequencer::domain::EntityType;

    let order = EntityType::order();
    assert_eq!(order.as_str(), "order");

    let inventory = EntityType::inventory();
    assert_eq!(inventory.as_str(), "inventory");

    let custom = EntityType::from("custom_entity");
    assert_eq!(custom.as_str(), "custom_entity");
}

#[test]
fn test_event_type_creation() {
    use stateset_sequencer::domain::EventType;

    let created = EventType::new("order.created");
    assert_eq!(created.0, "order.created");
    assert_eq!(created.as_str(), "order.created");

    let custom = EventType::new("my.event.type");
    assert_eq!(custom.0, "my.event.type");
}

#[test]
fn test_tenant_store_id_creation() {
    use stateset_sequencer::domain::{StoreId, TenantId};

    let tenant = TenantId::new();
    assert!(!tenant.0.is_nil());

    let store = StoreId::new();
    assert!(!store.0.is_nil());

    let specific_tenant = TenantId::from_uuid(test_tenant_id());
    assert_eq!(specific_tenant.0, test_tenant_id());
}

#[test]
fn test_event_envelope_creation() {
    use stateset_sequencer::domain::{
        AgentId, EntityType, EventEnvelope, EventType, StoreId, TenantId,
    };

    let payload = order_created_payload("cust-123", 99.99);
    let payload_hash = compute_payload_hash(&payload);

    let envelope = EventEnvelope {
        event_id: Uuid::new_v4(),
        command_id: Some(Uuid::new_v4()),
        tenant_id: TenantId::from_uuid(test_tenant_id()),
        store_id: StoreId::from_uuid(test_store_id()),
        entity_type: EntityType::order(),
        entity_id: "ord-001".to_string(),
        event_type: EventType::new("order.created"),
        payload: payload.clone(),
        payload_hash,
        base_version: None,
        created_at: Utc::now(),
        sequence_number: None,
        source_agent: AgentId::from_uuid(test_agent_id()),
        signature: None,
    };

    assert_eq!(envelope.entity_type.as_str(), "order");
    assert_eq!(envelope.entity_id, "ord-001");
    assert!(envelope.sequence_number.is_none());
}

#[test]
fn test_sequenced_event_creation() {
    use stateset_sequencer::domain::{
        AgentId, EntityType, EventEnvelope, EventType, SequencedEvent, StoreId, TenantId,
    };

    let payload = json!({"test": "data"});
    let payload_hash = compute_payload_hash(&payload);

    let envelope = EventEnvelope {
        event_id: Uuid::new_v4(),
        command_id: None,
        tenant_id: TenantId::from_uuid(test_tenant_id()),
        store_id: StoreId::from_uuid(test_store_id()),
        entity_type: EntityType::order(),
        entity_id: "ord-001".to_string(),
        event_type: EventType::new("order.created"),
        payload,
        payload_hash,
        base_version: None,
        created_at: Utc::now(),
        sequence_number: None,
        source_agent: AgentId::from_uuid(test_agent_id()),
        signature: None,
    };

    let sequenced = SequencedEvent::new(envelope, 42);

    assert_eq!(sequenced.sequence_number(), 42);
    assert_eq!(sequenced.entity_id(), "ord-001");
    assert!(sequenced.envelope.sequence_number.is_some());
}

#[test]
fn test_event_batch_creation() {
    use stateset_sequencer::domain::{
        AgentId, EntityType, EventBatch, EventEnvelope, EventType, StoreId, TenantId,
    };

    let agent_id = AgentId::from_uuid(test_agent_id());

    let events: Vec<EventEnvelope> = (0..5)
        .map(|i| {
            let payload = json!({"index": i});
            let payload_hash = compute_payload_hash(&payload);

            EventEnvelope {
                event_id: Uuid::new_v4(),
                command_id: None,
                tenant_id: TenantId::from_uuid(test_tenant_id()),
                store_id: StoreId::from_uuid(test_store_id()),
                entity_type: EntityType::order(),
                entity_id: format!("ord-{:03}", i),
                event_type: EventType::new("order.created"),
                payload,
                payload_hash,
                base_version: None,
                created_at: Utc::now(),
                sequence_number: None,
                source_agent: agent_id.clone(),
                signature: None,
            }
        })
        .collect();

    let batch = EventBatch::new(agent_id, events);

    assert_eq!(batch.len(), 5);
    assert!(!batch.is_empty());
}

// ============================================================================
// Crypto Tests
// ============================================================================

#[test]
fn test_canonical_json_hashing() {
    use stateset_sequencer::crypto::{canonical_json_hash, canonicalize_json};

    // Test that key order doesn't affect hash
    let json1 = json!({"a": 1, "b": 2, "c": 3});
    let json2 = json!({"c": 3, "a": 1, "b": 2});

    let hash1 = canonical_json_hash(&json1);
    let hash2 = canonical_json_hash(&json2);

    assert_eq!(
        hash1, hash2,
        "Canonical hash should be independent of key order"
    );

    // Test canonical form
    let canonical = canonicalize_json(&json1);
    assert!(canonical.contains("\"a\":1"));
    assert!(canonical.contains("\"b\":2"));
    assert!(canonical.contains("\"c\":3"));
}

#[test]
fn test_event_leaf_hash() {
    use stateset_sequencer::crypto::{
        compute_event_signing_hash, compute_leaf_hash, EventSigningParams, LeafHashParams,
    };

    let event_id = Uuid::new_v4();
    let payload_plain_hash = [0u8; 32];
    let payload_cipher_hash = [0u8; 32];
    let agent_signature = [0u8; 64];
    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();
    let source_agent_id = Uuid::new_v4();

    // First compute the event signing hash
    let signing_params1 = EventSigningParams {
        ves_version: 1,
        event_id: &event_id,
        tenant_id: &tenant_id,
        store_id: &store_id,
        source_agent_id: &source_agent_id,
        agent_key_id: 1,
        entity_type: "order",
        entity_id: "ord-1",
        event_type: "order.created",
        created_at: "2025-01-15T10:30:00Z",
        payload_kind: 0,
        payload_plain_hash: &payload_plain_hash,
        payload_cipher_hash: &payload_cipher_hash,
    };
    let event_signing_hash1 = compute_event_signing_hash(&signing_params1);

    // Then compute the leaf hash
    let params1 = LeafHashParams {
        tenant_id: &tenant_id,
        store_id: &store_id,
        sequence_number: 1,
        event_signing_hash: &event_signing_hash1,
        agent_signature: &agent_signature,
    };
    let hash1 = compute_leaf_hash(&params1);

    // Same inputs should produce same hash
    let params2 = LeafHashParams {
        tenant_id: &tenant_id,
        store_id: &store_id,
        sequence_number: 1,
        event_signing_hash: &event_signing_hash1,
        agent_signature: &agent_signature,
    };
    let hash2 = compute_leaf_hash(&params2);

    assert_eq!(hash1, hash2, "Same inputs should produce same hash");

    // Different sequence number should produce different hash
    let params3 = LeafHashParams {
        tenant_id: &tenant_id,
        store_id: &store_id,
        sequence_number: 2,
        event_signing_hash: &event_signing_hash1,
        agent_signature: &agent_signature,
    };
    let hash3 = compute_leaf_hash(&params3);
    assert_ne!(
        hash1, hash3,
        "Different sequence should produce different hash"
    );
}

#[test]
fn test_encryption_roundtrip() {
    use stateset_sequencer::crypto::{decrypt_payload, encrypt_payload, generate_key};

    let key = generate_key();
    let plaintext = b"Hello, World! This is a test message.";

    let ciphertext = encrypt_payload(&key, plaintext).expect("Encryption should succeed");
    assert_ne!(
        &ciphertext[..],
        plaintext,
        "Ciphertext should differ from plaintext"
    );

    let decrypted = decrypt_payload(&key, &ciphertext).expect("Decryption should succeed");
    assert_eq!(&decrypted[..], plaintext, "Decrypted should match original");
}

#[test]
fn test_encryption_different_keys() {
    use stateset_sequencer::crypto::{decrypt_payload, encrypt_payload, generate_key};

    let key1 = generate_key();
    let key2 = generate_key();
    let plaintext = b"Secret message";

    let ciphertext = encrypt_payload(&key1, plaintext).expect("Encryption should succeed");

    // Decryption with wrong key should fail
    let result = decrypt_payload(&key2, &ciphertext);
    assert!(result.is_err(), "Decryption with wrong key should fail");
}

// ============================================================================
// Auth Tests
// ============================================================================

#[test]
fn test_api_key_generation() {
    use stateset_sequencer::auth::{ApiKeyValidator, API_KEY_PREFIX};

    let tenant_id = test_tenant_id();
    let (key, hash) = ApiKeyValidator::generate_key(&tenant_id);

    assert!(
        key.starts_with(API_KEY_PREFIX),
        "Key should start with prefix"
    );
    assert_eq!(hash.len(), 64, "Hash should be 64 hex chars (SHA-256)");

    // Verify hash is reproducible
    let hash2 = ApiKeyValidator::hash_key(&key);
    assert_eq!(hash, hash2, "Hash should be deterministic");
}

#[test]
fn test_api_key_validation() {
    use stateset_sequencer::auth::{ApiKeyRecord, ApiKeyValidator, Permissions};

    let validator = ApiKeyValidator::new();
    let tenant_id = test_tenant_id();

    let (key, hash) = ApiKeyValidator::generate_key(&tenant_id);

    // Register the key
    validator.register_key(ApiKeyRecord {
        key_hash: hash.clone(),
        tenant_id,
        store_ids: vec![],
        permissions: Permissions::read_write(),
        agent_id: None,
        active: true,
        rate_limit: None,
    });

    // Validate should succeed
    let context = validator.validate(&key).expect("Validation should succeed");
    assert_eq!(context.tenant_id, tenant_id);
    assert!(context.can_read());
    assert!(context.can_write());
    assert!(!context.is_admin());
}

#[test]
fn test_api_key_revocation() {
    use stateset_sequencer::auth::{ApiKeyRecord, ApiKeyValidator, Permissions};

    let validator = ApiKeyValidator::new();
    let tenant_id = test_tenant_id();

    let (key, hash) = ApiKeyValidator::generate_key(&tenant_id);

    validator.register_key(ApiKeyRecord {
        key_hash: hash.clone(),
        tenant_id,
        store_ids: vec![],
        permissions: Permissions::read_only(),
        agent_id: None,
        active: true,
        rate_limit: None,
    });

    // Key works initially
    assert!(validator.validate(&key).is_ok());

    // Revoke the key
    validator.revoke(&hash);

    // Key no longer works
    assert!(validator.validate(&key).is_err());
}

#[test]
fn test_jwt_issue_and_validate() {
    use chrono::Duration;
    use stateset_sequencer::auth::{JwtValidator, Permissions};

    let validator = JwtValidator::new(
        b"test-secret-key-for-testing",
        "test-issuer",
        "test-audience",
    );

    let tenant_id = test_tenant_id();
    let store_id = test_store_id();

    let token = validator
        .issue(
            &tenant_id,
            &[store_id],
            None,
            &Permissions::admin(),
            Duration::hours(1),
        )
        .expect("Token issuance should succeed");

    let context = validator
        .validate(&token)
        .expect("Token validation should succeed");

    assert_eq!(context.tenant_id, tenant_id);
    assert!(context.store_ids.contains(&store_id));
    assert!(context.is_admin());
}

#[test]
fn test_jwt_expired_token() {
    use chrono::Duration;
    use stateset_sequencer::auth::{AuthError, JwtValidator, Permissions};

    let validator = JwtValidator::new(
        b"test-secret-key-for-testing",
        "test-issuer",
        "test-audience",
    );

    let tenant_id = test_tenant_id();

    // Issue an already-expired token (use -120s to exceed 60s leeway in jsonwebtoken)
    let token = validator
        .issue(
            &tenant_id,
            &[],
            None,
            &Permissions::read_only(),
            Duration::seconds(-120),
        )
        .expect("Token issuance should succeed");

    let result = validator.validate(&token);
    assert!(matches!(result, Err(AuthError::TokenExpired)));
}

#[test]
fn test_rate_limiter() {
    use stateset_sequencer::auth::{AuthError, RateLimiter};

    let limiter = RateLimiter::new(3);
    let key = "test-key";

    // First 3 requests should succeed
    assert!(limiter.check(key).is_ok());
    assert!(limiter.check(key).is_ok());
    assert!(limiter.check(key).is_ok());

    // 4th request should be rate limited
    let result = limiter.check(key);
    assert!(matches!(result, Err(AuthError::RateLimited)));

    // Check remaining
    assert_eq!(limiter.remaining(key), 0);
}

// ============================================================================
// Projection Tests
// ============================================================================

#[test]
fn test_apply_result_variants() {
    use stateset_sequencer::projection::{ApplyResult, RejectionReason};

    let applied = ApplyResult::Applied { new_version: 1 };
    assert!(matches!(applied, ApplyResult::Applied { new_version: 1 }));

    let rejected = ApplyResult::Rejected {
        reason: RejectionReason::EntityNotFound,
        message: "Not found".to_string(),
    };
    assert!(matches!(rejected, ApplyResult::Rejected { .. }));

    let skipped = ApplyResult::Skipped {
        reason: "Unknown event type".to_string(),
    };
    assert!(matches!(skipped, ApplyResult::Skipped { .. }));
}

#[test]
fn test_rejection_reason_variants() {
    use stateset_sequencer::projection::RejectionReason;

    let conflict = RejectionReason::VersionConflict {
        expected: 1,
        actual: 2,
    };
    assert!(matches!(
        conflict,
        RejectionReason::VersionConflict {
            expected: 1,
            actual: 2
        }
    ));

    let invariant = RejectionReason::InvariantViolation {
        invariant: "quantity >= 0".to_string(),
    };
    assert!(matches!(
        invariant,
        RejectionReason::InvariantViolation { .. }
    ));
}

#[tokio::test]
async fn test_in_memory_version_store() {
    use stateset_sequencer::domain::{StoreId, TenantId};
    use stateset_sequencer::projection::{EntityVersionStore, InMemoryVersionStore};

    let store = InMemoryVersionStore::new();
    let tenant_id = TenantId::from_uuid(test_tenant_id());
    let store_id = StoreId::from_uuid(test_store_id());

    // Initially no version
    let version = store
        .get_version(&tenant_id, &store_id, "order", "ord-123")
        .await
        .unwrap();
    assert!(version.is_none());

    // Set version
    store
        .set_version(&tenant_id, &store_id, "order", "ord-123", 1)
        .await
        .unwrap();

    let version = store
        .get_version(&tenant_id, &store_id, "order", "ord-123")
        .await
        .unwrap();
    assert_eq!(version, Some(1));

    // Compare-and-set
    let success = store
        .compare_and_set_version(&tenant_id, &store_id, "order", "ord-123", Some(1), 2)
        .await
        .unwrap();
    assert!(success);

    let success = store
        .compare_and_set_version(&tenant_id, &store_id, "order", "ord-123", Some(1), 3)
        .await
        .unwrap();
    assert!(!success); // Version is now 2, not 1
}

#[tokio::test]
async fn test_in_memory_checkpoint_store() {
    use stateset_sequencer::domain::{StoreId, TenantId};
    use stateset_sequencer::projection::{CheckpointStore, InMemoryCheckpointStore};

    let store = InMemoryCheckpointStore::new();
    let tenant_id = TenantId::from_uuid(test_tenant_id());
    let store_id = StoreId::from_uuid(test_store_id());

    // Initially no checkpoint
    let checkpoint = store.get_checkpoint(&tenant_id, &store_id).await.unwrap();
    assert!(checkpoint.is_none());

    // Set checkpoint
    store
        .set_checkpoint(&tenant_id, &store_id, 100)
        .await
        .unwrap();

    let checkpoint = store.get_checkpoint(&tenant_id, &store_id).await.unwrap();
    assert!(checkpoint.is_some());
    assert_eq!(checkpoint.unwrap().last_sequence, 100);
}

// ============================================================================
// Commitment Tests
// ============================================================================

#[test]
fn test_batch_commitment_creation() {
    use stateset_sequencer::domain::{BatchCommitment, StoreId, TenantId};

    let commitment = BatchCommitment::new(
        TenantId::from_uuid(test_tenant_id()),
        StoreId::from_uuid(test_store_id()),
        [0u8; 32],
        [1u8; 32],
        [2u8; 32],
        10,
        (1, 10),
    );

    assert_eq!(commitment.event_count, 10);
    assert_eq!(commitment.sequence_start(), 1);
    assert_eq!(commitment.sequence_end(), 10);
    assert!(!commitment.is_anchored());
}

#[test]
fn test_batch_commitment_anchoring() {
    use stateset_sequencer::domain::{BatchCommitment, StoreId, TenantId};

    let commitment = BatchCommitment::new(
        TenantId::from_uuid(test_tenant_id()),
        StoreId::from_uuid(test_store_id()),
        [0u8; 32],
        [1u8; 32],
        [2u8; 32],
        5,
        (1, 5),
    )
    .with_chain_tx([3u8; 32]);

    assert!(commitment.is_anchored());
    assert_eq!(commitment.chain_tx_hash, Some([3u8; 32]));
}

#[test]
fn test_merkle_proof_creation() {
    use stateset_sequencer::domain::MerkleProof;

    let proof = MerkleProof::new([0u8; 32], vec![[1u8; 32], [2u8; 32], [3u8; 32]], 5);

    assert_eq!(proof.leaf_index, 5);
    assert_eq!(proof.proof_path.len(), 3);
    assert_eq!(proof.directions.len(), 3);
}

// ============================================================================
// Metrics Tests
// ============================================================================

#[tokio::test]
async fn test_metrics_counter() {
    use stateset_sequencer::metrics::MetricsRegistry;

    let registry = MetricsRegistry::new();

    registry.inc_counter("test.events.count").await;
    registry.inc_counter("test.events.count").await;
    registry.add_counter("test.events.count", 8).await;

    let count = registry.get_counter("test.events.count").await;
    assert_eq!(count, 10);
}

#[tokio::test]
async fn test_metrics_gauge() {
    use stateset_sequencer::metrics::MetricsRegistry;

    let registry = MetricsRegistry::new();

    registry.set_gauge("test.connections", 5).await;
    assert_eq!(registry.get_gauge("test.connections").await, 5);

    registry.set_gauge("test.connections", 3).await;
    assert_eq!(registry.get_gauge("test.connections").await, 3);
}

#[tokio::test]
async fn test_metrics_histogram() {
    use stateset_sequencer::metrics::MetricsRegistry;

    let registry = MetricsRegistry::new();

    registry.observe_histogram("test.latency", 0.001).await;
    registry.observe_histogram("test.latency", 0.05).await;
    registry.observe_histogram("test.latency", 0.5).await;

    let json = registry.to_json().await;
    let histograms = json.get("histograms").unwrap();
    let latency = histograms.get("test.latency").unwrap();

    assert_eq!(latency.get("count").unwrap().as_u64().unwrap(), 3);
}

#[tokio::test]
async fn test_metrics_prometheus_export() {
    use stateset_sequencer::metrics::MetricsRegistry;

    let registry = MetricsRegistry::new();

    registry.inc_counter("test_counter").await;
    registry.set_gauge("test_gauge", 42).await;

    let prometheus = registry.to_prometheus().await;

    assert!(prometheus.contains("test_counter 1"));
    assert!(prometheus.contains("test_gauge 42"));
    assert!(prometheus.contains("sequencer_uptime_seconds"));
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_sequencer_error_display() {
    use stateset_sequencer::infra::SequencerError;

    let event_not_found = SequencerError::EventNotFound(Uuid::new_v4());
    assert!(event_not_found.to_string().contains("event not found"));

    let version_conflict = SequencerError::VersionConflict {
        entity_type: "order".to_string(),
        entity_id: "ord-123".to_string(),
        expected: 1,
        actual: 2,
    };
    assert!(version_conflict.to_string().contains("version conflict"));

    let duplicate = SequencerError::DuplicateEvent(Uuid::new_v4());
    assert!(duplicate.to_string().contains("duplicate event"));
}

// ============================================================================
// Event Builder Tests
// ============================================================================

#[test]
fn test_event_builder_defaults() {
    let event = TestEventBuilder::new().build_json();

    assert!(event.get("event_id").is_some());
    assert!(event.get("tenant_id").is_some());
    assert!(event.get("store_id").is_some());
    assert!(event.get("entity_type").is_some());
    assert!(event.get("entity_id").is_some());
    assert!(event.get("event_type").is_some());
    assert!(event.get("payload_hash").is_some());
    assert!(event.get("created_at").is_some());
}

#[test]
fn test_event_builder_customization() {
    let custom_tenant = Uuid::new_v4();
    let custom_store = Uuid::new_v4();

    let event = TestEventBuilder::new()
        .tenant_id(custom_tenant)
        .store_id(custom_store)
        .entity_type("product")
        .entity_id("prod-001")
        .event_type("product.created")
        .payload(product_created_payload("SKU-001", "Test Product", 29.99))
        .build_json();

    assert_eq!(event["tenant_id"], custom_tenant.to_string());
    assert_eq!(event["store_id"], custom_store.to_string());
    assert_eq!(event["entity_type"], "product");
    assert_eq!(event["entity_id"], "prod-001");
    assert_eq!(event["event_type"], "product.created");
    assert_eq!(event["payload"]["sku"], "SKU-001");
}
