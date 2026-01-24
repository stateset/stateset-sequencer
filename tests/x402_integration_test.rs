//! x402 Payment Protocol Integration Tests
//!
//! Tests the full x402 payment flow:
//! 1. Payment intent submission with Ed25519 signature
//! 2. Sequence number assignment
//! 3. Batch creation and Merkle root computation
//! 4. Receipt generation with inclusion proofs

mod common;

use chrono::Utc;
use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use stateset_sequencer::domain::{
    AgentId, AgentKeyId, StoreId, TenantId, X402Asset, X402IntentStatus, X402Network,
    X402PaymentBatch, X402PaymentIntent, X402_DOMAIN_SEPARATOR,
};
use stateset_sequencer::infra::PgX402Repository;

/// Compute signing hash matching the sequencer's implementation
fn compute_signing_hash(
    payer: &str,
    payee: &str,
    amount: u64,
    asset: &str,
    network: &str,
    chain_id: u64,
    valid_until: u64,
    nonce: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Domain separator
    hasher.update(X402_DOMAIN_SEPARATOR.as_bytes());

    // Payment parameters
    hasher.update(payer.as_bytes());
    hasher.update(payee.as_bytes());
    hasher.update(&amount.to_be_bytes());
    hasher.update(asset.as_bytes());
    hasher.update(network.as_bytes());
    hasher.update(&chain_id.to_be_bytes());
    hasher.update(&valid_until.to_be_bytes());
    hasher.update(&nonce.to_be_bytes());

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Create a signed payment intent for testing
fn create_test_intent(
    signing_key: &SigningKey,
    tenant_id: TenantId,
    store_id: StoreId,
    payee: &str,
    amount: u64,
) -> X402PaymentIntent {
    let payer_pubkey = signing_key.verifying_key();
    let payer_address = format!("0x{}", hex::encode(payer_pubkey.as_bytes()));
    let now = Utc::now().timestamp() as u64;
    let valid_until = now + 3600; // 1 hour validity
    let nonce = now * 1000 + (rand::random::<u64>() % 1000);

    // Compute signing hash
    let signing_hash = compute_signing_hash(
        &payer_address,
        payee,
        amount,
        "usdc",
        "set_chain",
        84532001,
        valid_until,
        nonce,
    );

    // Sign the hash
    let signature = signing_key.sign(&signing_hash);

    X402PaymentIntent {
        intent_id: Uuid::new_v4(),
        x402_version: 1,
        status: X402IntentStatus::Pending,
        tenant_id,
        store_id,
        source_agent_id: AgentId::new(),
        agent_key_id: AgentKeyId::new(1),
        payer_address,
        payee_address: payee.to_string(),
        amount,
        asset: X402Asset::Usdc,
        network: X402Network::SetChain,
        chain_id: 84532001,
        token_address: None,
        created_at_unix: now,
        valid_until,
        nonce,
        idempotency_key: None,
        resource_uri: None,
        description: Some("Test payment".to_string()),
        order_id: None,
        merchant_id: None,
        signing_hash,
        payer_signature: signature.to_bytes(),
        payer_public_key: Some(payer_pubkey.to_bytes()),
        sequence_number: None,
        sequenced_at: None,
        batch_id: None,
        tx_hash: None,
        block_number: None,
        settled_at: None,
        metadata: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

// =============================================================================
// Unit Tests (no database required)
// =============================================================================

#[test]
fn test_signing_hash_computation() {
    let hash = compute_signing_hash(
        "0x1234567890123456789012345678901234567890",
        "0x0987654321098765432109876543210987654321",
        1_000_000,
        "usdc",
        "set_chain",
        84532001,
        1705320000,
        42,
    );

    // Hash should be deterministic
    let hash2 = compute_signing_hash(
        "0x1234567890123456789012345678901234567890",
        "0x0987654321098765432109876543210987654321",
        1_000_000,
        "usdc",
        "set_chain",
        84532001,
        1705320000,
        42,
    );

    assert_eq!(hash, hash2);
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_signing_hash_changes_with_amount() {
    let hash1 = compute_signing_hash(
        "0x1234",
        "0x5678",
        1_000_000,
        "usdc",
        "set_chain",
        84532001,
        1705320000,
        42,
    );

    let hash2 = compute_signing_hash(
        "0x1234",
        "0x5678",
        2_000_000, // Different amount
        "usdc",
        "set_chain",
        84532001,
        1705320000,
        42,
    );

    assert_ne!(hash1, hash2);
}

#[test]
fn test_ed25519_signature() {
    // Generate a keypair
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Compute a signing hash
    let signing_hash = compute_signing_hash(
        "0x1234",
        "0x5678",
        1_000_000,
        "usdc",
        "set_chain",
        84532001,
        1705320000,
        42,
    );

    // Sign and verify
    let signature = signing_key.sign(&signing_hash);
    assert!(verifying_key.verify_strict(&signing_hash, &signature).is_ok());
}

#[test]
fn test_create_test_intent() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let tenant_id = TenantId::new();
    let store_id = StoreId::new();

    let intent = create_test_intent(
        &signing_key,
        tenant_id.clone(),
        store_id.clone(),
        "0x742d35Cc6634C0532925a3b844Bc9e7595f12345",
        1_000_000,
    );

    assert_eq!(intent.amount, 1_000_000);
    assert_eq!(intent.asset, X402Asset::Usdc);
    assert_eq!(intent.network, X402Network::SetChain);
    assert_eq!(intent.status, X402IntentStatus::Pending);
    assert!(intent.payer_public_key.is_some());

    // Verify the signature
    let verifying_key = signing_key.verifying_key();
    let signature = ed25519_dalek::Signature::from_bytes(&intent.payer_signature);
    assert!(verifying_key
        .verify_strict(&intent.signing_hash, &signature)
        .is_ok());
}

#[test]
fn test_batch_creation() {
    let tenant_id = TenantId::new();
    let store_id = StoreId::new();

    let mut batch = X402PaymentBatch::new(tenant_id.clone(), store_id.clone(), X402Network::SetChain);

    assert_eq!(batch.status, stateset_sequencer::domain::X402BatchStatus::Pending);
    assert_eq!(batch.payment_count, 0);
    assert!(batch.can_accept(100));
}

#[test]
fn test_batch_add_payment() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let tenant_id = TenantId::new();
    let store_id = StoreId::new();

    let mut batch = X402PaymentBatch::new(tenant_id.clone(), store_id.clone(), X402Network::SetChain);

    // Create and add intents with sequence numbers
    for i in 0..5 {
        let mut intent = create_test_intent(
            &signing_key,
            tenant_id.clone(),
            store_id.clone(),
            &format!("0x{:040x}", i + 1),
            1_000_000 * (i + 1),
        );
        intent.sequence_number = Some(i + 1);
        batch.add_payment(&intent);
    }

    assert_eq!(batch.payment_count, 5);
    assert_eq!(batch.intent_ids.len(), 5);
    assert_eq!(batch.sequence_start, 1);
    assert_eq!(batch.sequence_end, 5);

    // Check total amounts
    assert_eq!(batch.total_amounts.len(), 1);
    assert_eq!(batch.total_amounts[0].asset, X402Asset::Usdc);
    assert_eq!(batch.total_amounts[0].total_amount, 15_000_000); // 1+2+3+4+5 million
}

#[test]
fn test_merkle_tree_computation() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let tenant_id = TenantId::new();
    let store_id = StoreId::new();

    // Create test intents with sequence numbers
    let mut intents: Vec<X402PaymentIntent> = (0..4)
        .map(|i| {
            let mut intent = create_test_intent(
                &signing_key,
                tenant_id.clone(),
                store_id.clone(),
                &format!("0x{:040x}", i + 1),
                1_000_000,
            );
            intent.sequence_number = Some(i + 1);
            intent
        })
        .collect();

    // Compute Merkle root
    let merkle_root = PgX402Repository::compute_merkle_root(&intents);
    assert!(merkle_root.is_some());

    let root = merkle_root.unwrap();
    assert_ne!(root, [0u8; 32]);

    // Verify Merkle root is deterministic
    let merkle_root2 = PgX402Repository::compute_merkle_root(&intents);
    assert_eq!(root, merkle_root2.unwrap());
}

#[test]
fn test_merkle_proof_generation() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let tenant_id = TenantId::new();
    let store_id = StoreId::new();

    // Create test intents
    let intents: Vec<X402PaymentIntent> = (0..4)
        .map(|i| {
            let mut intent = create_test_intent(
                &signing_key,
                tenant_id.clone(),
                store_id.clone(),
                &format!("0x{:040x}", i + 1),
                1_000_000,
            );
            intent.sequence_number = Some(i + 1);
            intent
        })
        .collect();

    // Generate proof for leaf 0
    let proof = PgX402Repository::prove_inclusion(&intents, 0);
    assert!(proof.is_some());

    let proof_hashes = proof.unwrap();
    // For 4 leaves, we expect 2 proof elements (log2(4) = 2)
    assert_eq!(proof_hashes.len(), 2);
}

#[test]
fn test_merkle_proof_verification() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let tenant_id = TenantId::new();
    let store_id = StoreId::new();

    // Create test intents
    let intents: Vec<X402PaymentIntent> = (0..4)
        .map(|i| {
            let mut intent = create_test_intent(
                &signing_key,
                tenant_id.clone(),
                store_id.clone(),
                &format!("0x{:040x}", i + 1),
                1_000_000,
            );
            intent.sequence_number = Some(i + 1);
            intent
        })
        .collect();

    let merkle_root = PgX402Repository::compute_merkle_root(&intents).unwrap();
    let proof = PgX402Repository::prove_inclusion(&intents, 0).unwrap();
    let leaf = PgX402Repository::compute_intent_leaf(&intents[0]);

    // Verify the proof
    let verified = PgX402Repository::verify_inclusion(leaf, &proof, 0, intents.len(), merkle_root);
    assert!(verified);
}

#[test]
fn test_intent_leaf_deterministic() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let tenant_id = TenantId::new();
    let store_id = StoreId::new();

    let intent = create_test_intent(
        &signing_key,
        tenant_id,
        store_id,
        "0x742d35Cc6634C0532925a3b844Bc9e7595f12345",
        1_000_000,
    );

    let leaf1 = PgX402Repository::compute_intent_leaf(&intent);
    let leaf2 = PgX402Repository::compute_intent_leaf(&intent);

    assert_eq!(leaf1, leaf2);
}

#[test]
fn test_network_chain_ids() {
    assert_eq!(X402Network::SetChain.chain_id(), 84532001);
    assert_eq!(X402Network::SetChainTestnet.chain_id(), 84532002);
    assert_eq!(X402Network::Base.chain_id(), 8453);
    assert_eq!(X402Network::BaseSepolia.chain_id(), 84532);
    assert_eq!(X402Network::Ethereum.chain_id(), 1);
}

#[test]
fn test_asset_decimals() {
    assert_eq!(X402Asset::Usdc.decimals(), 6);
    assert_eq!(X402Asset::Usdt.decimals(), 6);
    assert_eq!(X402Asset::SsUsd.decimals(), 6);
    assert_eq!(X402Asset::Dai.decimals(), 18);
}

#[test]
fn test_intent_status_transitions() {
    assert_eq!(X402IntentStatus::Pending.to_string(), "pending");
    assert_eq!(X402IntentStatus::Sequenced.to_string(), "sequenced");
    assert_eq!(X402IntentStatus::Batched.to_string(), "batched");
    assert_eq!(X402IntentStatus::Settled.to_string(), "settled");
}

// =============================================================================
// Integration Tests (require database)
// =============================================================================

#[cfg(feature = "integration")]
mod integration {
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use std::sync::Arc;

    async fn get_test_pool() -> sqlx::PgPool {
        let database_url =
            std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for integration tests");

        PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("Failed to connect to database")
    }

    #[tokio::test]
    async fn test_intent_persistence() {
        let pool = get_test_pool().await;
        let repo = Arc::new(PgX402Repository::new(pool));

        let signing_key = SigningKey::generate(&mut OsRng);
        let tenant_id = TenantId::new();
        let store_id = StoreId::new();

        let intent = create_test_intent(
            &signing_key,
            tenant_id.clone(),
            store_id.clone(),
            "0x742d35Cc6634C0532925a3b844Bc9e7595f12345",
            1_000_000,
        );

        // Insert intent
        repo.insert_intent(&intent).await.expect("Failed to insert intent");

        // Retrieve intent
        let retrieved = repo
            .get_intent(intent.intent_id)
            .await
            .expect("Failed to get intent")
            .expect("Intent not found");

        assert_eq!(retrieved.intent_id, intent.intent_id);
        assert_eq!(retrieved.amount, 1_000_000);
        assert_eq!(retrieved.payer_address, intent.payer_address);
    }

    #[tokio::test]
    async fn test_sequence_assignment() {
        let pool = get_test_pool().await;
        let repo = Arc::new(PgX402Repository::new(pool));

        let signing_key = SigningKey::generate(&mut OsRng);
        let tenant_id = TenantId::new();
        let store_id = StoreId::new();

        // Create and insert multiple intents
        let mut intents = Vec::new();
        for i in 0..3 {
            let intent = create_test_intent(
                &signing_key,
                tenant_id.clone(),
                store_id.clone(),
                &format!("0x{:040x}", i + 1),
                1_000_000,
            );
            repo.insert_intent(&intent).await.expect("Failed to insert intent");
            intents.push(intent);
        }

        // Assign sequence numbers
        for intent in &intents {
            let seq = repo
                .assign_sequence_number(intent.intent_id, &tenant_id, &store_id)
                .await
                .expect("Failed to assign sequence number");
            assert!(seq > 0);
        }

        // Verify sequence numbers are sequential
        let retrieved = repo.get_intent(intents[0].intent_id).await.unwrap().unwrap();
        let seq1 = retrieved.sequence_number.expect("Should have sequence number");

        let retrieved = repo.get_intent(intents[1].intent_id).await.unwrap().unwrap();
        let seq2 = retrieved.sequence_number.expect("Should have sequence number");

        assert_eq!(seq2, seq1 + 1);
    }

    #[tokio::test]
    async fn test_full_batch_flow() {
        let pool = get_test_pool().await;
        let repo = Arc::new(PgX402Repository::new(pool));

        let signing_key = SigningKey::generate(&mut OsRng);
        let tenant_id = TenantId::new();
        let store_id = StoreId::new();

        // Create, insert, and sequence intents
        let mut intents = Vec::new();
        for i in 0..4 {
            let intent = create_test_intent(
                &signing_key,
                tenant_id.clone(),
                store_id.clone(),
                &format!("0x{:040x}", i + 1),
                1_000_000,
            );
            repo.insert_intent(&intent).await.expect("Failed to insert intent");
            repo.assign_sequence_number(intent.intent_id, &tenant_id, &store_id)
                .await
                .expect("Failed to assign sequence number");
            intents.push(intent);
        }

        // Fetch pending intents
        let pending = repo
            .get_pending_intents_for_batch(&tenant_id, &store_id, X402Network::SetChain, 100)
            .await
            .expect("Failed to get pending intents");

        assert_eq!(pending.len(), 4);

        // Create batch
        let mut batch = X402PaymentBatch::new(tenant_id.clone(), store_id.clone(), X402Network::SetChain);
        for intent in &pending {
            batch.add_payment(intent);
        }

        repo.insert_batch(&batch).await.expect("Failed to insert batch");

        // Commit batch with Merkle root
        let (merkle_root, state_root) = repo
            .commit_batch_with_merkle(batch.batch_id, &tenant_id, &store_id)
            .await
            .expect("Failed to commit batch");

        assert_ne!(merkle_root, [0u8; 32]);
        assert_ne!(state_root, [0u8; 32]);

        // Verify batch was updated
        let committed_batch = repo
            .get_batch(batch.batch_id)
            .await
            .expect("Failed to get batch")
            .expect("Batch not found");

        assert_eq!(
            committed_batch.status,
            stateset_sequencer::domain::X402BatchStatus::Committed
        );
        assert_eq!(committed_batch.merkle_root, Some(merkle_root));
    }
}
