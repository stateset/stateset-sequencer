//! On-chain settlement send-path test against a local EVM (e.g. anvil).
//!
//! This exercises the exact alloy machinery [`SettlementService::settle_batch`]
//! uses — provider construction, `ISetPaymentBatch` binding, `settleBatch`
//! encoding, transaction submission and receipt handling — end to end against a
//! real deployed `SetPaymentBatch`.
//!
//! It is skipped unless all three env vars are set, so normal `cargo test` is
//! unaffected:
//!   SETTLEMENT_RPC_URL        e.g. http://127.0.0.1:8545
//!   SET_PAYMENT_BATCH_ADDRESS deployed proxy address
//!   SETTLER_PRIVATE_KEY       the authorized sequencer key (settleBatch is onlySequencer)
//!
//! Deploy the contract first (from set/contracts):
//!   anvil &
//!   forge script script/DeployX402Test.s.sol:DeployX402TestScript \
//!     --tc DeployX402TestScript --rpc-url http://127.0.0.1:8545 --broadcast
//!
//! The baseline cases carry an empty authorization, which the contract's
//! `SignatureChecker` rejects — so the payment is *skipped* (PaymentFailed) while
//! the batch still settles. That is enough to prove the send path works without
//! needing a full EIP-712 signature (the contract's auth logic is covered by the
//! Foundry suite). The opt-in funded fixture instead signs a real EIP-712
//! authorization and verifies balances and destination-enforced replay guards.

use std::str::FromStr;

use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use stateset_sequencer::settlement::ISetPaymentBatch;

alloy::sol! {
    struct PaymentAuthorization {
        bytes32 intentId;
        address payer;
        address payee;
        address token;
        uint256 amount;
        uint64 nonce;
        uint64 validAfter;
        uint64 validBefore;
    }
    #[sol(rpc)]
    interface TestToken {
        function balanceOf(address account) external view returns (uint256);
    }
}

fn env3() -> Option<(String, String, String)> {
    Some((
        std::env::var("SETTLEMENT_RPC_URL").ok()?,
        std::env::var("SET_PAYMENT_BATCH_ADDRESS").ok()?,
        std::env::var("SETTLER_PRIVATE_KEY").ok()?,
    ))
}

/// A fresh 32-byte id with a recognizable prefix.
/// A fresh random 32-byte ID, so tests stay rerunnable against a chain that
/// remembers every settled batch and intent.
fn rand32() -> FixedBytes<32> {
    FixedBytes::from(rand::random::<[u8; 32]>())
}

fn id32(seed: u8) -> FixedBytes<32> {
    let mut b = [0u8; 32];
    b[0] = seed;
    b[31] = seed;
    FixedBytes::from(b)
}

#[tokio::test]
async fn settle_batch_send_path_settles_batch_and_skips_unauthorized_payment() {
    let (rpc_url, pb_addr, key) = match env3() {
        Some(v) => v,
        None => {
            eprintln!(
                "SETTLEMENT_RPC_URL / SET_PAYMENT_BATCH_ADDRESS / SETTLER_PRIVATE_KEY not set; \
                 skipping on-chain settlement test"
            );
            return;
        }
    };

    let signer = PrivateKeySigner::from_str(key.trim_start_matches("0x"))
        .expect("valid settler private key");
    let provider = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer))
        .connect_http(rpc_url.parse().expect("valid rpc url"));

    let address = Address::from_str(&pb_addr).expect("valid contract address");
    let contract = ISetPaymentBatch::new(address, &provider);

    // Fresh IDs per run: the contract records settled batches and intents
    // permanently, so fixed IDs make the test single-use against any chain
    // that outlives it (a long-running anvil, a shared devnet).
    let batch_id = rand32();
    let payment = ISetPaymentBatch::PaymentIntent {
        intentId: rand32(),
        payer: Address::from_str("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC").unwrap(), // anvil #2
        payee: Address::from_str("0x90F79bf6EB2c4f870365E785982E1f101E93b906").unwrap(), // anvil #3
        amount: U256::from(1_000_000u64),
        token: Address::from_str("0x5FbDB2315678afecb367f032d93F642f64180aa3").unwrap(), // mock USDC (deterministic)
        nonce: 1,
        validAfter: 0,
        validUntil: 4_000_000_000,
        signingHash: id32(0x00),
        authorization: Bytes::new(), // empty -> SignatureChecker rejects -> payment skipped
    };

    // merkleRoot must be non-zero; tenant/store key and sequence bounds are free.
    let receipt = contract
        .settleBatch(
            batch_id,
            id32(0xFF), // merkleRoot (non-zero)
            id32(0x7E), // tenantStoreKey
            1,
            1,
            vec![payment],
        )
        .send()
        .await
        .expect("settleBatch transaction submits")
        .get_receipt()
        .await
        .expect("settleBatch receipt");

    assert!(
        receipt.status(),
        "settleBatch transaction must succeed on-chain"
    );

    // The batch is now recorded on-chain (settledAt != 0), proving the send path
    // reached and mutated the contract.
    let batch = contract
        .getBatch(batch_id)
        .call()
        .await
        .expect("getBatch call");
    assert_ne!(batch.settledAt, 0, "batch must be marked settled on-chain");
}

/// Double-settle safety, end to end. A batch settled on-chain whose local
/// record was never written (crash between send and record, or leader
/// failover mid-tick) must be *reconciled* on the next attempt, not sent again.
///
/// This drives [`SettlementService::settle_batch`] itself: the first call sends
/// the transaction; the second finds `getBatch(id).settledAt != 0` and returns
/// `already_settled` with a zero tx hash and no transaction. If the pre-check
/// were removed, the second call would submit a transaction that the contract
/// reverts with `BatchAlreadySettled` and this test would fail.
#[tokio::test]
async fn settle_batch_is_idempotent_across_a_lost_local_record() {
    check_lost_record_replay(false).await;
}

/// Driven only by the loopback-only disposable EVM harness.
#[tokio::test]
async fn funded_settlement_is_replay_safe() {
    if std::env::var("SEQUENCER_LOCAL_SETTLEMENT_DRILL").as_deref() != Ok("1") {
        eprintln!("Run scripts/run_settlement_drill.sh for the funded replay drill");
        return;
    }
    check_lost_record_replay(true).await;
}

async fn check_lost_record_replay(funded: bool) {
    use stateset_sequencer::domain::{
        AgentId, AgentKeyId, StoreId, TenantId, X402Asset, X402IntentStatus, X402Network,
        X402PaymentBatch, X402PaymentIntent,
    };
    use stateset_sequencer::settlement::{SettlementConfig, SettlementService};
    use uuid::Uuid;

    let (rpc_url, pb_addr, key) = match env3() {
        Some(v) => v,
        None => {
            assert!(!funded, "funded drill requires settlement configuration");
            eprintln!("settlement env not set; skipping on-chain idempotency test");
            return;
        }
    };

    let service_config = SettlementConfig {
        rpc_url: rpc_url.clone(),
        contract_address: Address::from_str(&pb_addr).expect("valid contract address"),
        private_key: key.clone(),
        chain_id: 31337,
    };
    let service = SettlementService::new(service_config.clone());

    let tenant_id = TenantId::new();
    let store_id = StoreId::new();
    let now = chrono::Utc::now();
    let mut intent = X402PaymentIntent {
        intent_id: Uuid::new_v4(),
        x402_version: 1,
        status: X402IntentStatus::Batched,
        tenant_id,
        store_id,
        source_agent_id: AgentId::new(),
        agent_key_id: AgentKeyId::new(1),
        payer_address: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".into(), // anvil #2
        payee_address: "0x90F79bf6EB2c4f870365E785982E1f101E93b906".into(), // anvil #3
        amount: 1_000_000,
        asset: X402Asset::Usdc,
        network: X402Network::SetChain,
        chain_id: 31337,
        token_address: Some("0x5FbDB2315678afecb367f032d93F642f64180aa3".into()),
        created_at_unix: now.timestamp() as u64,
        valid_until: 4_000_000_000,
        valid_after: 0,
        nonce: 1,
        idempotency_key: None,
        eip712_authorization: None, // rejected by SignatureChecker -> payment skipped, batch still settles
        resource_uri: None,
        description: None,
        order_id: None,
        merchant_id: None,
        signing_hash: [0u8; 32],
        payer_signature: [0u8; 64],
        payer_public_key: None,
        sequence_number: Some(1),
        sequenced_at: Some(now),
        batch_id: None,
        tx_hash: None,
        block_number: None,
        settled_at: None,
        metadata: None,
        created_at: now,
        updated_at: now,
    };

    let probe = ProviderBuilder::new().connect_http(rpc_url.parse().expect("rpc url"));
    let mut balances = None;
    if funded {
        use alloy::{providers::Provider, signers::SignerSync, sol_types::SolStruct};
        let url: reqwest::Url = rpc_url.parse().unwrap();
        assert!(
            matches!(
                url.host_str(),
                Some("127.0.0.1") | Some("localhost") | Some("::1")
            ),
            "funded tests are loopback-only"
        );
        assert_eq!(
            probe.get_chain_id().await.unwrap(),
            31337,
            "funded tests require local chain ID"
        );
        let payer: PrivateKeySigner = std::env::var("SETTLEMENT_TEST_PAYER_KEY")
            .expect("test payer key")
            .parse()
            .unwrap();
        let token: Address = std::env::var("SETTLEMENT_TEST_TOKEN_ADDRESS")
            .expect("test token")
            .parse()
            .unwrap();
        intent.payer_address = payer.address().to_string();
        intent.token_address = Some(token.to_string());
        intent.nonce = u64::from(rand::random::<u32>());
        let mut id = [0u8; 32];
        id[..16].copy_from_slice(intent.intent_id.as_bytes());
        let payee: Address = intent.payee_address.parse().unwrap();
        let authorization = PaymentAuthorization {
            intentId: FixedBytes::from(id),
            payer: payer.address(),
            payee,
            token,
            amount: U256::from(intent.amount),
            nonce: intent.nonce,
            validAfter: intent.valid_after,
            validBefore: intent.valid_until,
        };
        let domain = alloy::sol_types::eip712_domain! {
            name: "SetPaymentBatch", version: "1", chain_id: 31337,
            verifying_contract: Address::from_str(&pb_addr).unwrap(),
        };
        intent.eip712_authorization = Some(
            payer
                .sign_hash_sync(&authorization.eip712_signing_hash(&domain))
                .unwrap()
                .as_bytes()
                .to_vec(),
        );
        let contract = TestToken::new(token, probe.clone());
        balances = Some((
            token,
            payer.address(),
            payee,
            contract.balanceOf(payer.address()).call().await.unwrap(),
            contract.balanceOf(payee).call().await.unwrap(),
        ));
    }

    let mut batch = X402PaymentBatch::new(tenant_id, store_id, X402Network::SetChain);
    batch.add_payment(&intent);
    batch.merkle_root = Some([0x42u8; 32]);
    batch.sequence_start = 1;
    batch.sequence_end = 1;
    let intents = vec![intent];

    // First attempt: really settles on-chain.
    let first = service
        .settle_batch(&batch, &intents)
        .await
        .expect("first settlement succeeds");
    assert!(
        !first.already_settled,
        "first attempt must send a transaction"
    );
    assert_ne!(
        first.tx_hash, [0u8; 32],
        "first attempt must have a tx hash"
    );
    if funded {
        assert_eq!(first.settled_ids, vec![intents[0].intent_id]);
        assert!(
            first.failed_ids.is_empty(),
            "the test must actually transfer funds"
        );
    }

    // The settler's nonce is the ground truth for "did we send a transaction":
    // even a reverted transaction consumes one. The send-failure fallback in
    // settle_batch also reconciles, so asserting on `already_settled` alone
    // would pass with the pre-check removed -- after burning a mined revert
    // and two minutes of retries. The nonce must not move.
    let signer = PrivateKeySigner::from_str(key.trim_start_matches("0x")).expect("key");
    let nonce_before = alloy::providers::Provider::get_transaction_count(&probe, signer.address())
        .await
        .expect("nonce");

    // Simulate the local record being lost: nothing is written, the same batch
    // comes around again on the next tick.
    //
    // Reconciliation must be a *read*, not a retry storm. Without the
    // `getBatch` pre-check the send path fails at gas estimation (the contract
    // reverts with BatchAlreadySettled), the retry policy then grinds on that
    // guaranteed revert for minutes, and only the send-failure fallback finally
    // reconciles -- same answer, ~150s later, with the settlement worker's
    // entire tick (and every batch queued behind this one) stalled meanwhile.
    let started = std::time::Instant::now();
    let recovered_service = SettlementService::new(service_config);
    let second = recovered_service
        .settle_batch(&batch, &intents)
        .await
        .expect("second attempt must reconcile, not fail");
    let took = started.elapsed();
    assert!(
        took < std::time::Duration::from_secs(15),
        "reconciling an already-settled batch must be a quick read, took {took:?}"
    );
    assert!(
        second.already_settled,
        "second attempt must detect the on-chain settlement and reconcile"
    );
    assert_eq!(
        second.tx_hash, [0u8; 32],
        "reconciliation must not send a second transaction"
    );
    assert_eq!(
        second.failed_ids, first.failed_ids,
        "reconciled per-payment outcome must match the original"
    );
    assert_eq!(second.settled_ids, first.settled_ids);
    let nonce_after = alloy::providers::Provider::get_transaction_count(&probe, signer.address())
        .await
        .expect("nonce");
    assert_eq!(
        nonce_after, nonce_before,
        "reconciliation must not submit any transaction, not even a reverting one"
    );
    if let Some((token, payer, payee, payer_before, payee_before)) = balances {
        let contract = TestToken::new(token, probe.clone());
        let amount = U256::from(intents[0].amount);
        assert_eq!(
            contract.balanceOf(payer).call().await.unwrap(),
            payer_before - amount
        );
        assert_eq!(
            contract.balanceOf(payee).call().await.unwrap(),
            payee_before + amount
        );

        // Bypass the service's pre-check, as a stale worker could. Force a
        // mined transaction rather than allowing gas estimation to reject it.
        let mut batch_bytes = [0u8; 32];
        batch_bytes[..16].copy_from_slice(batch.batch_id.as_bytes());
        let mut intent_bytes = [0u8; 32];
        intent_bytes[..16].copy_from_slice(intents[0].intent_id.as_bytes());
        let stale_provider = ProviderBuilder::new()
            .wallet(alloy::network::EthereumWallet::from(signer))
            .connect_http(rpc_url.parse().unwrap());
        let destination =
            ISetPaymentBatch::new(Address::from_str(&pb_addr).unwrap(), stale_provider);
        let batch_id = FixedBytes::from(batch_bytes);
        let recorded = destination.getBatch(batch_id).call().await.unwrap();
        let duplicate_payment = ISetPaymentBatch::PaymentIntent {
            intentId: FixedBytes::from(intent_bytes),
            payer,
            payee,
            amount,
            token,
            nonce: intents[0].nonce,
            validAfter: intents[0].valid_after,
            validUntil: intents[0].valid_until,
            signingHash: FixedBytes::from(intents[0].signing_hash),
            authorization: Bytes::from(intents[0].eip712_authorization.clone().unwrap()),
        };
        let stale_receipt = destination
            .settleBatch(
                batch_id,
                recorded.merkleRoot,
                recorded.tenantStoreKey,
                recorded.sequenceStart,
                recorded.sequenceEnd,
                vec![duplicate_payment],
            )
            .gas(500_000)
            .send()
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap();
        assert!(
            !stale_receipt.status(),
            "destination must revert a stale duplicate batch"
        );
        assert_eq!(
            contract.balanceOf(payer).call().await.unwrap(),
            payer_before - amount
        );
        assert_eq!(
            contract.balanceOf(payee).call().await.unwrap(),
            payee_before + amount
        );

        // A second batch can bypass batch-ID deduplication but not the
        // destination's per-intent replay protection. No second transfer.
        let mut other_batch = batch.clone();
        other_batch.batch_id = Uuid::new_v4();
        let duplicate = service.settle_batch(&other_batch, &intents).await.unwrap();
        assert!(!duplicate.already_settled);
        assert_eq!(
            contract.balanceOf(payer).call().await.unwrap(),
            payer_before - amount
        );
        assert_eq!(
            contract.balanceOf(payee).call().await.unwrap(),
            payee_before + amount
        );
        println!("FUNDED_REPLAY_VERIFIED: one transfer; fresh-service retry sent no transaction; stale duplicate batch reverted on-chain; duplicate intent under a new batch moved no funds");
    }
}
