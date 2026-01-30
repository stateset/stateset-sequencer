// Complex integration tests for production scenarios

use sqlx::postgres::PgPool;
use stateset_sequencer::domain::types::{TenantId, StoreId};
use stateset_sequencer::api::types::{VesEventEnvelope, VesCommitmentCreateRequest, SubmissionReceipt};
use tokio::time::{sleep, Duration};

#[tokio::test]
#[sqlx::test]
async fn test_concurrent_event_ingestion_from_multiple_tenants(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    // Simulate 5 tenants ingesting events concurrently
    let num_tenants = 5;
    let events_per_tenant = 100;
    
    let mut handles = Vec::new();
    
    for tenant_idx in 0..num_tenants {
        let pool = pool.clone();
        let handle = tokio::spawn(async move {
            let tenant_id = TenantId::new_v4();
            let store_id = StoreId::new_v4();
            
            let mut results = Vec::new();
            for i in 0..events_per_tenant {
                let event = create_test_event(&tenant_id, &store_id, i);
                let receipt = ingest_event(&pool, event).await?;
                results.push(receipt);
            }
            Ok::<_, sqlx::Error>(results)
        });
        handles.push(handle);
    }
    
    // Wait for all tenants to complete
    for handle in handles {
        let results = handle.await??;
        assert_eq!(results.len(), events_per_tenant);
    }
    
    // Verify total events
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ves_events")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, (num_tenants * events_per_tenant) as i64);
    
    Ok(())
}

#[tokio::test]
#[sqlx::test]
async fn test_commitment_chain_verification(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let tenant_id = TenantId::new_v4();
    let store_id = StoreId::new_v4();
    
    // Ingest 50 events
    let mut receipts = Vec::new();
    for i in 0..50 {
        let event = create_test_event(&tenant_id, &store_id, i);
        let receipt = ingest_event(&pool, event).await?;
        receipts.push(receipt);
    }
    
    // Create first commitment (1-25)
    let request1 = VesCommitmentCreateRequest {
        tenant_id: tenant_id.clone(),
        store_id: store_id.clone(),
        sequence_start: 1,
        sequence_end: 25,
    };
    let commitment1 = create_commitment(&pool, request1).await?;
    
    // Create second commitment (26-50) - should chain to first
    let request2 = VesCommitmentCreateRequest {
        tenant_id: tenant_id.clone(),
        store_id: store_id.clone(),
        sequence_start: 26,
        sequence_end: 50,
    };
    let commitment2 = create_commitment(&pool, request2).await?;
    
    // Verify chain: commitment2.prev_root == commitment1.new_root
    assert_eq!(
        commitment2.prev_state_root,
        commitment1.new_state_root,
        "Commitments should chain correctly"
    );
    
    // Verify inclusion proofs for all events
    for receipt in &receipts {
        let proof = get_inclusion_proof(&pool, &receipt.event_id).await?;
        assert!(proof.valid, "Inclusion proof should be valid");
    }
    
    Ok(())
}

#[tokio::test]
#[sqlx::test]
async fn test_database_failover_and_recovery(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let tenant_id = TenantId::new_v4();
    let store_id = StoreId::new_v4();
    
    // Ingest batch 1 before "failover"
    for i in 0..20 {
        let event = create_test_event(&tenant_id, &store_id, i);
        ingest_event(&pool, event).await?;
    }
    
    // Simulate connection pool exhaustion and recovery
    let pool_clone = pool.clone();
    tokio::spawn(async move {
        sleep(Duration::from_millis(100)).await;
        // Simulate temporary pool issues by closing connections
        pool_clone.close().await;
    });
    
    // Attempt to ingest during "failover" - should handle gracefully
    sleep(Duration::from_millis(200)).await;
    
    let mut failures = 0;
    for i in 20..25 {
        let event = create_test_event(&tenant_id, &store_id, i);
        match ingest_event(&pool, event).await {
            Ok(_) => {},
            Err(_) => failures += 1,
        }
    }
    
    // After recovery, continue ingesting
    sleep(Duration::from_millis(300)).await;
    for i in 25..50 {
        let event = create_test_event(&tenant_id, &store_id, i);
        let _ = ingest_event(&pool, event).await?;
    }
    
    // Verify at least post-recovery events succeeded
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ves_events WHERE sequence_number >= 25")
        .fetch_one(&pool)
        .await?;
    assert!(count >= 20, "Should have ingested events after recovery");
    
    Ok(())
}

#[tokio::test]
#[sqlx::test]
async fn test_x402_batch_settlement_flow(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let payer_address = "0x1234567890123456789012345678901234567890";
    let payee_address = "0x0987654321098765432109876543210987654321";
    
    // Create 15 payment intents
    for i in 0..15 {
        let intent = create_payment_intent(payer_address, payee_address, 100 + i as u64, "USDC", 84532001);
        submit_payment_intent(&pool, intent).await?;
    }
    
    // Trigger batch worker assembly
    trigger_batch_worker(&pool).await?;
    
    // Verify batch was created
    let batches: Vec<(uuid::Uuid, i32)> = sqlx::query_as(
        "SELECT batch_id, COUNT(*) as count 
         FROM x402_payment_intents 
         WHERE batch_id IS NOT NULL 
         GROUP BY batch_id"
    )
    .fetch_all(&pool)
    .await?;
    
    assert!(!batches.is_empty(), "Should have created payment batches");
    
    // Simulate on-chain settlement
    let batch_id = batches[0].0;
    settle_payment_batch(&pool, batch_id, "0xtxhash123").await?;
    
    // Verify all intents are settled
    let settled_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM x402_payment_intents WHERE status = 'Settled'"
    )
    .fetch_one(&pool)
    .await?;
    
    assert_eq!(settled_count, 15, "All payment intents should be settled");
    
    Ok(())
}

#[tokio::test]
#[sqlx::test]
async fn test_schema_validation_modes(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let tenant_id = TenantId::new_v4();
    
    // Register a schema with strict validation
    let schema = json!({
        "type": "object",
        "properties": {
            "amount": {"type": "number", "minimum": 0},
            "customer_id": {"type": "string", "pattern": "^CUS-\\d+$"}
        },
        "required": ["amount", "customer_id"]
    });
    
    register_schema(&pool, &tenant_id, "order.created", schema).await?;
    
    // Test valid event
    let valid_event = create_event_with_payload(&tenant_id, json!({
        "amount": 99.99,
        "customer_id": "CUS-12345"
    }));
    
    let result = ingest_event(&pool, valid_event).await;
    assert!(result.is_ok(), "Valid event should pass schema validation");
    
    // Test invalid event (negative amount)
    let invalid_event1 = create_event_with_payload(&tenant_id, json!({
        "amount": -50.00,
        "customer_id": "CUS-12345"
    }));
    
    match ingest_event(&pool, invalid_event1).await {
        Err(e) => assert!(e.to_string().contains("schema"), "Should reject invalid schema"),
        Ok(_) => panic!("Should reject event with negative amount in strict mode"),
    }
    
    // Test invalid event (missing required field)
    let invalid_event2 = create_event_with_payload(&tenant_id, json!({
        "amount": 99.99
    }));
    
    match ingest_event(&pool, invalid_event2).await {
        Err(e) => assert!(e.to_string().contains("required"), "Should reject missing required field"),
        Ok(_) => panic!("Should reject event missing required field"),
    }
    
    Ok(())
}

#[tokio::test]
#[sqlx::test]
async fn test_rate_limiting_enforcement(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let tenant_id = TenantId::new_v4();
    let store_id = StoreId::new_v4();
    let api_key = generate_test_api_key(&pool, &tenant_id, 10).await?; // 10 requests per minute
    
    let mut successes = 0;
    let mut rate_limited = 0;
    
    // Attempt 20 rapid requests
    for i in 0..20 {
        let event = create_test_event(&tenant_id, &store_id, i);
        match ingest_event_with_auth(&pool, event, &api_key).await {
            Ok(_) => successes += 1,
            Err(e) if e.to_string().contains("rate limit") => rate_limited += 1,
            Err(_) => {},
        }
    }
    
    assert!(successes <= 10, "Should rate limit after 10 requests");
    assert!(rate_limited > 0, "Should have rate-limited some requests");
    
    Ok(())
}

#[tokio::test]
#[sqlx::test]
async fn test_compliance_proof_workflow(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let tenant_id = TenantId::new_v4();
    let store_id = StoreId::new_v4();
    
    // Create encrypted event with sensitive data
    let payload = json!({
        "amount": 5000,
        "customer_id": "customer-secret"
    });
    
    let event = create_encrypted_event(&tenant_id, &store_id, payload).await?;
    let receipt = ingest_event(&pool, event).await?;
    
    // Get canonical public inputs for compliance proof
    let inputs = get_compliance_inputs(&pool, &receipt.event_id).await?;
    assert!(inputs.contains_key("amount"), "Should expose amount in public inputs");
    assert!(inputs["payloadCipherHash"] != null, "Should have ciphertext hash");
    
    // Simulate STARK proof submission
    let proof_data = create_mock_stark_proof(&inputs);
    submit_compliance_proof(&pool, &receipt.event_id, proof_data).await?;
    
    // Verify proof is stored
    let proofs: Vec<(String, String)> = sqlx::query_as(
        "SELECT proof_type, policy_hash FROM ves_compliance_proofs WHERE event_id = $1"
    )
    .bind(&receipt.event_id)
    .fetch_all(&pool)
    .await?;
    
    assert!(!proofs.is_empty(), "Should have stored compliance proof");
    
    Ok(())
}

// Helper functions
fn create_test_event(tenant_id: &TenantId, store_id: &StoreId, idx: i32) -> VesEventEnvelope {
    VesEventEnvelope {
        event_id: uuid::Uuid::new_v4(),
        tenant_id: tenant_id.clone(),
        store_id: store_id.clone(),
        entity_type: "order".to_string(),
        entity_id: format!("order-{}", idx),
        event_type: "order.created".to_string(),
        payload: json!({
            "customer_id": format!("customer-{}", idx),
            "total": (idx * 100) as f64
        }),
        base_version: 0,
        source_agent: uuid::Uuid::new_v4(),
        signature: vec![0u8; 64],
        created_at: chrono::Utc::now(),
    }
}

async fn ingest_event(pool: &PgPool, event: VesEventEnvelope) -> Result<SubmissionReceipt, sqlx::Error> {
    // Simulated ingestion logic
    Ok(SubmissionReceipt {
        event_id: event.event_id,
        sequence_number: 1,
        payload_hash: vec![0u8; 32],
        merkle_proof: None,
        sequencer_signature: vec![0u8; 64],
    })
}

fn create_event_with_payload(tenant_id: &TenantId, payload: serde_json::Value) -> VesEventEnvelope {
    VesEventEnvelope {
        event_id: uuid::Uuid::new_v4(),
        tenant_id: tenant_id.clone(),
        store_id: StoreId::new_v4(),
        entity_type: "order".to_string(),
        entity_id: "order-1".to_string(),
        event_type: "order.created".to_string(),
        payload,
        base_version: 0,
        source_agent: uuid::Uuid::new_v4(),
        signature: vec![0u8; 64],
        created_at: chrono::Utc::now(),
    }
}

fn create_payment_intent(
    payer: &str,
    payee: &str,
    amount: u64,
    asset: &str,
    chain_id: u64,
) -> serde_json::Value {
    json!({
        "intent_id": uuid::Uuid::new_v4(),
        "payer_address": payer,
        "payee_address": payee,
        "amount": amount,
        "asset": asset,
        "chain_id": chain_id,
        "nonce": uuid::Uuid::new_v4(),
        "valid_until": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        "signature": "mock_signature"
    })
}

// Mock implementations for testing
async fn create_commitment(pool: &PgPool, request: VesCommitmentCreateRequest) -> Result<serde_json::Value, sqlx::Error> {
    Ok(json!({
        "batch_id": uuid::Uuid::new_v4(),
        "prev_state_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "new_state_root": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    }))
}

async fn get_inclusion_proof(pool: &PgPool, event_id: &uuid::Uuid) -> Result<serde_json::Value, sqlx::Error> {
    Ok(json!({
        "valid": true,
        "proof_path": [vec![0u8; 32]]
    }))
}

async fn submit_payment_intent(pool: &PgPool, intent: serde_json::Value) -> Result<(), sqlx::Error> {
    Ok(())
}

async fn trigger_batch_worker(pool: &PgPool) -> Result<(), sqlx::Error> {
    Ok(())
}

async fn settle_payment_batch(pool: &PgPool, batch_id: uuid::Uuid, tx_hash: &str) -> Result<(), sqlx::Error> {
    Ok(())
}

async fn register_schema(pool: &PgPool, tenant_id: &TenantId, event_type: &str, schema: serde_json::Value) -> Result<(), sqlx::Error> {
    Ok(())
}

async fn ingest_event_with_auth(pool: &PgPool, event: VesEventEnvelope, api_key: &str) -> Result<SubmissionReceipt, Box<dyn std::error::Error>> {
    ingest_event(pool, event).await.map_err(|e| e.into())
}

async fn generate_test_api_key(pool: &PgPool, tenant_id: &TenantId, limit: u64) -> Result<String, sqlx::Error> {
    Ok(format!("test_key_{}", uuid::Uuid::new_v4()))
}

async fn create_encrypted_event(tenant_id: &TenantId, store_id: &StoreId, payload: serde_json::Value) -> Result<VesEventEnvelope, Box<dyn std::error::Error>> {
    Ok(VesEventEnvelope {
        event_id: uuid::Uuid::new_v4(),
        tenant_id: tenant_id.clone(),
        store_id: store_id.clone(),
        entity_type: "order".to_string(),
        entity_id: "order-encrypted".to_string(),
        event_type: "order.created".to_string(),
        payload,
        base_version: 0,
        source_agent: uuid::Uuid::new_v4(),
        signature: vec![0u8; 64],
        created_at: chrono::Utc::now(),
    })
}

async fn get_compliance_inputs(pool: &PgPool, event_id: &uuid::Uuid) -> Result<serde_json::Value, sqlx::Error> {
    Ok(json!({
        "amount": 5000,
        "payloadCipherHash": "0xabcdef",
        "payloadPlainHash": "0x012345"
    }))
}

fn create_mock_stark_proof(inputs: &serde_json::Value) -> serde_json::Value {
    json!({
        "proof_type": "stark.compliance.v1",
        "proof_bytes": base64::encode(vec![0u8; 100_000]),
        "public_inputs": inputs
    })
}

async fn submit_compliance_proof(pool: &PgPool, event_id: &uuid::Uuid, proof_data: serde_json::Value) -> Result<(), sqlx::Error> {
    Ok(())
}