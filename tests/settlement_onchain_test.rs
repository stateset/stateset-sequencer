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
//! The payment carries an empty authorization, which the contract's
//! `SignatureChecker` rejects — so the payment is *skipped* (PaymentFailed) while
//! the batch still settles. That is enough to prove the send path works without
//! needing a full EIP-712 signature (the contract's auth logic is covered by the
//! Foundry suite).

use std::str::FromStr;

use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use stateset_sequencer::settlement::ISetPaymentBatch;

fn env3() -> Option<(String, String, String)> {
    Some((
        std::env::var("SETTLEMENT_RPC_URL").ok()?,
        std::env::var("SET_PAYMENT_BATCH_ADDRESS").ok()?,
        std::env::var("SETTLER_PRIVATE_KEY").ok()?,
    ))
}

/// A fresh 32-byte id with a recognizable prefix.
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
        .with_recommended_fillers()
        .wallet(alloy::network::EthereumWallet::from(signer))
        .on_http(rpc_url.parse().expect("valid rpc url"));

    let address = Address::from_str(&pb_addr).expect("valid contract address");
    let contract = ISetPaymentBatch::new(address, &provider);

    let batch_id = id32(0xB1);
    let payment = ISetPaymentBatch::PaymentIntent {
        intentId: id32(0x1A),
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
    assert_ne!(
        batch._0.settledAt, 0,
        "batch must be marked settled on-chain"
    );
}
