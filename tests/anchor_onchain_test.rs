//! On-chain anchoring against a local EVM. Skipped unless the env is set:
//!   ANCHOR_RPC_URL, SET_REGISTRY_ADDRESS, ANCHOR_PRIVATE_KEY (authorized sequencer)
//! Deploy with set/contracts `DeployX402Test.s.sol`; the SetRegistry proxy is
//! the first ERC1967Proxy in the broadcast.

use std::str::FromStr;

use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use stateset_sequencer::anchor::{AnchorConfig, AnchorService, ALREADY_ANCHORED_TX_HASH};
use stateset_sequencer::domain::{StoreId, TenantId, VesBatchCommitment};
use uuid::Uuid;

fn env3() -> Option<(String, String, String)> {
    Some((
        std::env::var("ANCHOR_RPC_URL").ok()?,
        std::env::var("SET_REGISTRY_ADDRESS").ok()?,
        std::env::var("ANCHOR_PRIVATE_KEY").ok()?,
    ))
}

/// A commitment anchored on-chain whose local record was lost must be
/// reconciled on the next attempt -- as a read, without a transaction, and
/// quickly. Before this the worker only reconciled commitments that already
/// carried a tx hash, so such a commitment was re-sent every tick, reverted
/// with BatchAlreadyCommitted, and (because the revert arrived wrapped in a
/// "failed to send" error the retry classifier treated as transient) ground
/// through ~5 minutes of retries each time. Forever.
#[tokio::test]
async fn anchoring_is_idempotent_across_a_lost_local_record() {
    let (rpc_url, registry, key) = match env3() {
        Some(v) => v,
        None => {
            eprintln!("anchor env not set; skipping on-chain anchor test");
            return;
        }
    };

    let service = AnchorService::new(AnchorConfig {
        rpc_url: rpc_url.clone(),
        registry_address: Address::from_str(&registry).expect("registry address"),
        private_key: key.clone(),
        chain_id: 31337,
    });

    let now = chrono::Utc::now();
    let commitment = VesBatchCommitment {
        batch_id: Uuid::new_v4(),
        tenant_id: TenantId::new(),
        store_id: StoreId::new(),
        ves_version: 1,
        tree_depth: 1,
        leaf_count: 1,
        padded_leaf_count: 2,
        merkle_root: [0x11u8; 32],
        prev_state_root: [0u8; 32],
        new_state_root: [0x22u8; 32],
        sequence_range: (1, 1),
        committed_at: now,
        chain_id: None,
        chain_tx_hash: None,
        chain_block_number: None,
        anchored_at: None,
    };

    let (first_tx, _) = service
        .anchor_ves_commitment(&commitment)
        .await
        .expect("first anchor succeeds");
    assert_ne!(
        first_tx, ALREADY_ANCHORED_TX_HASH,
        "first attempt must send"
    );

    let signer = PrivateKeySigner::from_str(key.trim_start_matches("0x")).expect("key");
    let probe = ProviderBuilder::new().on_http(rpc_url.parse().expect("rpc"));
    let nonce_before = probe
        .get_transaction_count(signer.address())
        .await
        .expect("nonce");

    // Local record lost; same commitment comes around again.
    let started = std::time::Instant::now();
    let (second_tx, _) = service
        .anchor_ves_commitment(&commitment)
        .await
        .expect("second attempt must reconcile, not fail");
    let took = started.elapsed();

    assert_eq!(
        second_tx, ALREADY_ANCHORED_TX_HASH,
        "must report already-anchored"
    );
    assert!(
        took < std::time::Duration::from_secs(15),
        "reconciling an already-anchored commitment must be a quick read, took {took:?}"
    );
    let nonce_after = probe
        .get_transaction_count(signer.address())
        .await
        .expect("nonce");
    assert_eq!(
        nonce_after, nonce_before,
        "reconciliation must not submit a transaction"
    );
    assert!(service
        .verify_anchored(commitment.batch_id)
        .await
        .expect("verify"));
}
