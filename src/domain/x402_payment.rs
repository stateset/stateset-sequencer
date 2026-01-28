//! x402 Payment Protocol for StateSet Sequencer
//!
//! Implements off-chain payment signing and batching for x402 protocol.
//! Payment intents are sequenced as VES events and batched for gas-efficient
//! settlement on Set Chain L2.
//!
//! ## Architecture
//!
//! ```text
//! AI Agent (stateset-icommerce)
//!     |
//!     | Creates X402PaymentIntent
//!     v
//! Sequencer (this module)
//!     |
//!     | 1. Validates signature
//!     | 2. Assigns sequence number
//!     | 3. Batches into X402PaymentBatch
//!     v
//! Set Chain L2 (SetPaymentBatch contract)
//!     |
//!     | Executes aggregated transfers
//!     v
//! Settlement complete
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    hash256_hex_0x, option_hash256_hex, signature64_hex_0x, AgentId, AgentKeyId, EntityType,
    EventType, Hash256, Signature64, StoreId, TenantId,
};

// =============================================================================
// x402 Protocol Constants
// =============================================================================

/// x402 protocol version
pub const X402_VERSION: u32 = 1;

/// Domain separator for x402 payment signing
pub const X402_DOMAIN_SEPARATOR: &str = "X402_PAYMENT_V1";

/// Maximum payment validity window (24 hours)
pub const X402_MAX_VALIDITY_SECS: u64 = 86400;

/// Default batch size for payment batching
pub const X402_DEFAULT_BATCH_SIZE: usize = 100;

/// Maximum batch size
pub const X402_MAX_BATCH_SIZE: usize = 1000;

// =============================================================================
// x402 Network & Asset Types
// =============================================================================

/// Supported blockchain networks for x402 payments
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum X402Network {
    /// Set Chain L2 (StateSet native) - primary network
    #[default]
    SetChain,
    /// Set Chain testnet
    SetChainTestnet,
    /// Arc L2 (Circle stablecoin-native)
    Arc,
    /// Arc testnet
    ArcTestnet,
    /// Base L2 (Coinbase)
    Base,
    /// Base Sepolia testnet
    BaseSepolia,
    /// Ethereum mainnet
    Ethereum,
    /// Ethereum Sepolia testnet
    EthereumSepolia,
    /// Arbitrum One
    Arbitrum,
    /// Optimism
    Optimism,
}

impl X402Network {
    /// Get the chain ID
    pub fn chain_id(&self) -> u64 {
        match self {
            Self::SetChain => 84532001,
            Self::SetChainTestnet => 84532002,
            Self::Arc => 5042001,        // Arc mainnet (placeholder)
            Self::ArcTestnet => 5042002, // Arc testnet
            Self::Base => 8453,
            Self::BaseSepolia => 84532,
            Self::Ethereum => 1,
            Self::EthereumSepolia => 11155111,
            Self::Arbitrum => 42161,
            Self::Optimism => 10,
        }
    }

    /// Check if this is a testnet
    pub fn is_testnet(&self) -> bool {
        matches!(
            self,
            Self::SetChainTestnet
                | Self::ArcTestnet
                | Self::BaseSepolia
                | Self::EthereumSepolia
        )
    }
}

impl std::fmt::Display for X402Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SetChain => write!(f, "set_chain"),
            Self::SetChainTestnet => write!(f, "set_chain_testnet"),
            Self::Arc => write!(f, "arc"),
            Self::ArcTestnet => write!(f, "arc_testnet"),
            Self::Base => write!(f, "base"),
            Self::BaseSepolia => write!(f, "base_sepolia"),
            Self::Ethereum => write!(f, "ethereum"),
            Self::EthereumSepolia => write!(f, "ethereum_sepolia"),
            Self::Arbitrum => write!(f, "arbitrum"),
            Self::Optimism => write!(f, "optimism"),
        }
    }
}

/// Supported payment assets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum X402Asset {
    /// USD Coin (USDC)
    #[default]
    Usdc,
    /// Tether (USDT)
    Usdt,
    /// StateSet USD (ssUSD) - yield-bearing
    #[serde(rename = "ssusd", alias = "ss_usd")]
    SsUsd,
    /// Wrapped StateSet USD (ERC-4626)
    #[serde(rename = "wssusd", alias = "wss_usd")]
    WssUsd,
    /// DAI stablecoin
    Dai,
    /// Native ETH (for gas)
    Eth,
}

impl X402Asset {
    /// Get decimals for this asset
    pub fn decimals(&self) -> u8 {
        match self {
            Self::Usdc | Self::Usdt | Self::SsUsd | Self::WssUsd => 6,
            Self::Dai | Self::Eth => 18,
        }
    }

    /// Get token address for network
    pub fn token_address(&self, network: X402Network) -> Option<&'static str> {
        match (self, network) {
            // Set Chain
            (Self::Usdc, X402Network::SetChain) => {
                Some("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
            }
            (Self::SsUsd, X402Network::SetChain) => {
                Some("0x0000000000000000000000000000000000001001")
            }
            // Arc (USDC is native gas token with ERC-20 interface)
            (Self::Usdc, X402Network::Arc | X402Network::ArcTestnet) => {
                Some("0x3600000000000000000000000000000000000000")
            }
            // Base
            (Self::Usdc, X402Network::Base) => {
                Some("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
            }
            // Ethereum
            (Self::Usdc, X402Network::Ethereum) => {
                Some("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
            }
            (Self::Usdt, X402Network::Ethereum) => {
                Some("0xdAC17F958D2ee523a2206206994597C13D831ec7")
            }
            (Self::Dai, X402Network::Ethereum) => {
                Some("0x6B175474E89094C44Da98b954Ee4606eB48")
            }
            // Native ETH has no contract
            (Self::Eth, _) => None,
            _ => None,
        }
    }
}

impl std::fmt::Display for X402Asset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usdc => write!(f, "USDC"),
            Self::Usdt => write!(f, "USDT"),
            Self::SsUsd => write!(f, "ssUSD"),
            Self::WssUsd => write!(f, "wssUSD"),
            Self::Dai => write!(f, "DAI"),
            Self::Eth => write!(f, "ETH"),
        }
    }
}

// =============================================================================
// x402 Payment Intent Status
// =============================================================================

/// Status of an x402 payment intent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum X402IntentStatus {
    /// Intent received, pending validation
    #[default]
    Pending,
    /// Intent validated and sequenced
    Sequenced,
    /// Intent included in batch
    Batched,
    /// Intent settled on-chain
    Settled,
    /// Intent expired
    Expired,
    /// Intent failed
    Failed,
}

impl std::fmt::Display for X402IntentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Sequenced => write!(f, "sequenced"),
            Self::Batched => write!(f, "batched"),
            Self::Settled => write!(f, "settled"),
            Self::Expired => write!(f, "expired"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

// =============================================================================
// x402 Payment Intent (Sequencer's View)
// =============================================================================

/// x402 Payment Intent as received by the sequencer
///
/// This represents a signed payment authorization from an AI agent.
/// The sequencer validates the signature, assigns a sequence number,
/// and batches intents for settlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402PaymentIntent {
    // =========================================================================
    // Identity
    // =========================================================================
    /// Unique intent ID
    pub intent_id: Uuid,

    /// x402 protocol version
    pub x402_version: u32,

    /// Current status
    pub status: X402IntentStatus,

    /// Tenant ID (for multi-tenancy)
    pub tenant_id: TenantId,

    /// Store ID (within tenant)
    pub store_id: StoreId,

    /// Source agent ID
    pub source_agent_id: AgentId,

    /// Agent key ID used for signing
    pub agent_key_id: AgentKeyId,

    // =========================================================================
    // Payment Parameters (signed)
    // =========================================================================
    /// Payer wallet address (sender)
    pub payer_address: String,

    /// Payee wallet address (recipient)
    pub payee_address: String,

    /// Payment amount in smallest unit (e.g., 1000000 = 1 USDC)
    pub amount: u64,

    /// Payment asset
    pub asset: X402Asset,

    /// Target network
    pub network: X402Network,

    /// Chain ID
    pub chain_id: u64,

    /// Token contract address
    pub token_address: Option<String>,

    // =========================================================================
    // Validity & Replay Protection
    // =========================================================================
    /// Unix timestamp when created
    pub created_at_unix: u64,

    /// Unix timestamp when expires
    pub valid_until: u64,

    /// Nonce for replay protection
    pub nonce: u64,

    /// Idempotency key
    pub idempotency_key: Option<String>,

    // =========================================================================
    // Resource Context
    // =========================================================================
    /// Resource URI this payment unlocks
    pub resource_uri: Option<String>,

    /// Description
    pub description: Option<String>,

    /// Associated order ID
    pub order_id: Option<Uuid>,

    /// Merchant ID
    pub merchant_id: Option<String>,

    // =========================================================================
    // Cryptographic Fields
    // =========================================================================
    /// Signing hash (SHA-256)
    #[serde(with = "hash256_hex_0x")]
    pub signing_hash: Hash256,

    /// Payer's Ed25519 signature
    #[serde(with = "signature64_hex_0x")]
    pub payer_signature: Signature64,

    /// Payer's public key (for verification without agent key lookup)
    #[serde(with = "option_hash256_hex", skip_serializing_if = "Option::is_none")]
    pub payer_public_key: Option<Hash256>,

    // =========================================================================
    // Sequencer-Assigned Fields
    // =========================================================================
    /// Sequence number (assigned by sequencer)
    pub sequence_number: Option<u64>,

    /// When sequenced
    pub sequenced_at: Option<DateTime<Utc>>,

    /// Batch ID
    pub batch_id: Option<Uuid>,

    // =========================================================================
    // Settlement Fields
    // =========================================================================
    /// On-chain transaction hash
    pub tx_hash: Option<String>,

    /// Block number
    pub block_number: Option<u64>,

    /// When settled
    pub settled_at: Option<DateTime<Utc>>,

    // =========================================================================
    // Metadata
    // =========================================================================
    /// Additional metadata
    pub metadata: Option<serde_json::Value>,

    /// Created timestamp
    pub created_at: DateTime<Utc>,

    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
}

impl X402PaymentIntent {
    /// Check if the intent has expired
    pub fn is_expired(&self) -> bool {
        let now = Utc::now().timestamp() as u64;
        now > self.valid_until
    }

    /// Check if the intent is sequenced
    pub fn is_sequenced(&self) -> bool {
        self.sequence_number.is_some()
    }

    /// Check if the intent is settled
    pub fn is_settled(&self) -> bool {
        self.status == X402IntentStatus::Settled && self.tx_hash.is_some()
    }

    /// Convert to VES event entity type
    pub fn entity_type() -> EntityType {
        EntityType::new("x402_payment")
    }

    /// Convert to VES event type for creation
    pub fn event_type_created() -> EventType {
        EventType::new("x402_payment.created")
    }

    /// Convert to VES event type for sequencing
    pub fn event_type_sequenced() -> EventType {
        EventType::new("x402_payment.sequenced")
    }

    /// Convert to VES event type for settlement
    pub fn event_type_settled() -> EventType {
        EventType::new("x402_payment.settled")
    }
}

// =============================================================================
// x402 Payment Batch
// =============================================================================

/// Status of a payment batch
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum X402BatchStatus {
    /// Batch is being assembled
    #[default]
    Pending,
    /// Batch is committed (Merkle root computed)
    Committed,
    /// Batch submitted to chain
    Submitted,
    /// Batch confirmed on-chain
    Settled,
    /// Batch failed
    Failed,
}

/// x402 Payment Batch - A collection of payment intents for batch settlement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402PaymentBatch {
    /// Batch ID
    pub batch_id: Uuid,

    /// Batch status
    pub status: X402BatchStatus,

    /// Tenant ID
    pub tenant_id: TenantId,

    /// Store ID
    pub store_id: StoreId,

    /// Target network
    pub network: X402Network,

    /// Number of payments in batch
    pub payment_count: u32,

    /// Total amounts by asset
    pub total_amounts: Vec<X402BatchTotal>,

    /// Merkle root of payment intents
    #[serde(with = "option_hash256_hex", skip_serializing_if = "Option::is_none")]
    pub merkle_root: Option<Hash256>,

    /// Previous state root
    #[serde(with = "option_hash256_hex", skip_serializing_if = "Option::is_none")]
    pub prev_state_root: Option<Hash256>,

    /// New state root after this batch
    #[serde(with = "option_hash256_hex", skip_serializing_if = "Option::is_none")]
    pub new_state_root: Option<Hash256>,

    /// Sequence range [start, end]
    pub sequence_start: u64,
    pub sequence_end: u64,

    /// Payment intent IDs in this batch
    pub intent_ids: Vec<Uuid>,

    // =========================================================================
    // Settlement Fields
    // =========================================================================
    /// On-chain transaction hash
    pub tx_hash: Option<String>,

    /// Block number
    pub block_number: Option<u64>,

    /// Gas used
    pub gas_used: Option<u64>,

    // =========================================================================
    // Timestamps
    // =========================================================================
    pub created_at: DateTime<Utc>,
    pub committed_at: Option<DateTime<Utc>>,
    pub submitted_at: Option<DateTime<Utc>>,
    pub settled_at: Option<DateTime<Utc>>,
}

/// Total amount for an asset in a batch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402BatchTotal {
    pub asset: X402Asset,
    pub total_amount: u64,
    pub payment_count: u32,
}

impl X402PaymentBatch {
    /// Create a new empty batch
    pub fn new(tenant_id: TenantId, store_id: StoreId, network: X402Network) -> Self {
        Self {
            batch_id: Uuid::new_v4(),
            status: X402BatchStatus::Pending,
            tenant_id,
            store_id,
            network,
            payment_count: 0,
            total_amounts: Vec::new(),
            merkle_root: None,
            prev_state_root: None,
            new_state_root: None,
            sequence_start: 0,
            sequence_end: 0,
            intent_ids: Vec::new(),
            tx_hash: None,
            block_number: None,
            gas_used: None,
            created_at: Utc::now(),
            committed_at: None,
            submitted_at: None,
            settled_at: None,
        }
    }

    /// Check if batch can accept more payments
    pub fn can_accept(&self, max_size: usize) -> bool {
        self.status == X402BatchStatus::Pending && (self.payment_count as usize) < max_size
    }

    /// Add payment to batch
    pub fn add_payment(&mut self, intent: &X402PaymentIntent) {
        self.payment_count += 1;
        self.intent_ids.push(intent.intent_id);

        // Update or add total for this asset
        if let Some(total) = self
            .total_amounts
            .iter_mut()
            .find(|t| t.asset == intent.asset)
        {
            total.total_amount += intent.amount;
            total.payment_count += 1;
        } else {
            self.total_amounts.push(X402BatchTotal {
                asset: intent.asset,
                total_amount: intent.amount,
                payment_count: 1,
            });
        }

        // Update sequence range
        if let Some(seq) = intent.sequence_number {
            if self.sequence_start == 0 || seq < self.sequence_start {
                self.sequence_start = seq;
            }
            if seq > self.sequence_end {
                self.sequence_end = seq;
            }
        }
    }

    /// Mark batch as committed
    pub fn commit(&mut self, merkle_root: Hash256, new_state_root: Hash256) {
        self.merkle_root = Some(merkle_root);
        self.new_state_root = Some(new_state_root);
        self.status = X402BatchStatus::Committed;
        self.committed_at = Some(Utc::now());
    }

    /// Mark batch as submitted
    pub fn submit(&mut self, tx_hash: String) {
        self.tx_hash = Some(tx_hash);
        self.status = X402BatchStatus::Submitted;
        self.submitted_at = Some(Utc::now());
    }

    /// Mark batch as settled
    pub fn settle(&mut self, block_number: u64, gas_used: u64) {
        self.block_number = Some(block_number);
        self.gas_used = Some(gas_used);
        self.status = X402BatchStatus::Settled;
        self.settled_at = Some(Utc::now());
    }
}

// =============================================================================
// x402 Payment Receipt
// =============================================================================

/// x402 Payment Receipt - Proof of payment for verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402PaymentReceipt {
    /// Receipt ID
    pub receipt_id: Uuid,

    /// Original intent ID
    pub intent_id: Uuid,

    /// Sequence number
    pub sequence_number: u64,

    /// Batch ID
    pub batch_id: Uuid,

    /// Merkle root
    #[serde(with = "hash256_hex_0x")]
    pub merkle_root: Hash256,

    /// Merkle inclusion proof
    pub inclusion_proof: Vec<String>,

    /// Leaf index
    pub leaf_index: u32,

    /// Total leaves in batch
    pub total_leaves: u32,

    /// Payment details
    pub payer_address: String,
    pub payee_address: String,
    pub amount: u64,
    pub asset: X402Asset,
    pub network: X402Network,
    pub chain_id: u64,
    pub nonce: u64,
    pub valid_until: u64,
    /// Signing hash (SHA-256)
    #[serde(with = "hash256_hex_0x")]
    pub signing_hash: Hash256,
    /// Payer's Ed25519 signature
    #[serde(with = "signature64_hex_0x")]
    pub payer_signature: Signature64,

    /// Settlement details
    pub tx_hash: Option<String>,
    pub block_number: Option<u64>,

    /// Timestamp
    pub created_at: DateTime<Utc>,
}

// =============================================================================
// API Request/Response Types
// =============================================================================

/// Request to submit an x402 payment intent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitX402PaymentRequest {
    /// Tenant ID
    pub tenant_id: Uuid,

    /// Store ID
    pub store_id: Uuid,

    /// Agent ID
    pub agent_id: Uuid,

    /// Agent key ID
    pub agent_key_id: Option<u32>,

    /// Payment parameters
    pub payer_address: String,
    pub payee_address: String,
    pub amount: u64,
    pub asset: X402Asset,
    pub network: X402Network,

    /// Validity
    pub valid_until: u64,
    pub nonce: u64,

    /// Cryptographic fields
    pub signing_hash: String,
    pub payer_signature: String,
    pub payer_public_key: Option<String>,

    /// Context
    pub resource_uri: Option<String>,
    pub description: Option<String>,
    pub order_id: Option<Uuid>,
    pub merchant_id: Option<String>,
    pub idempotency_key: Option<String>,

    /// Metadata
    pub metadata: Option<serde_json::Value>,
}

/// Response after submitting payment intent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitX402PaymentResponse {
    /// Intent ID
    pub intent_id: Uuid,

    /// Status
    pub status: X402IntentStatus,

    /// Sequence number (if sequenced)
    pub sequence_number: Option<u64>,

    /// Sequenced timestamp
    pub sequenced_at: Option<DateTime<Utc>>,

    /// Batch ID (if batched)
    pub batch_id: Option<Uuid>,
}

/// Request to get batch settlement status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetX402BatchRequest {
    pub batch_id: Uuid,
}

/// Response with batch details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetX402BatchResponse {
    pub batch: X402PaymentBatch,
}

/// Request to get payment receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetX402ReceiptRequest {
    pub intent_id: Uuid,
}

/// Response with payment receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetX402ReceiptResponse {
    pub receipt: X402PaymentReceipt,
}

/// Filter for listing payment intents
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct X402PaymentIntentFilter {
    pub tenant_id: Option<Uuid>,
    pub store_id: Option<Uuid>,
    pub payer_address: Option<String>,
    pub payee_address: Option<String>,
    pub status: Option<X402IntentStatus>,
    pub network: Option<X402Network>,
    pub asset: Option<X402Asset>,
    pub batch_id: Option<Uuid>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

// =============================================================================
// Entity & Event Type Extensions
// =============================================================================

impl EntityType {
    /// x402 payment intent entity type
    pub fn x402_payment() -> Self {
        Self("x402_payment".to_string())
    }

    /// x402 payment batch entity type
    pub fn x402_batch() -> Self {
        Self("x402_batch".to_string())
    }
}

impl EventType {
    // x402 Payment Intent events
    pub const X402_PAYMENT_CREATED: &'static str = "x402_payment.created";
    pub const X402_PAYMENT_SEQUENCED: &'static str = "x402_payment.sequenced";
    pub const X402_PAYMENT_BATCHED: &'static str = "x402_payment.batched";
    pub const X402_PAYMENT_SETTLED: &'static str = "x402_payment.settled";
    pub const X402_PAYMENT_FAILED: &'static str = "x402_payment.failed";
    pub const X402_PAYMENT_EXPIRED: &'static str = "x402_payment.expired";

    // x402 Batch events
    pub const X402_BATCH_CREATED: &'static str = "x402_batch.created";
    pub const X402_BATCH_COMMITTED: &'static str = "x402_batch.committed";
    pub const X402_BATCH_SUBMITTED: &'static str = "x402_batch.submitted";
    pub const X402_BATCH_SETTLED: &'static str = "x402_batch.settled";
    pub const X402_BATCH_FAILED: &'static str = "x402_batch.failed";
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x402_network_chain_ids() {
        assert_eq!(X402Network::SetChain.chain_id(), 84532001);
        assert_eq!(X402Network::Base.chain_id(), 8453);
        assert_eq!(X402Network::Ethereum.chain_id(), 1);
    }

    #[test]
    fn test_x402_asset_decimals() {
        assert_eq!(X402Asset::Usdc.decimals(), 6);
        assert_eq!(X402Asset::Dai.decimals(), 18);
    }

    #[test]
    fn test_x402_batch_creation() {
        let batch = X402PaymentBatch::new(
            TenantId::new(),
            StoreId::new(),
            X402Network::SetChain,
        );

        assert_eq!(batch.status, X402BatchStatus::Pending);
        assert_eq!(batch.payment_count, 0);
        assert!(batch.can_accept(100));
    }

    #[test]
    fn test_x402_intent_status_display() {
        assert_eq!(X402IntentStatus::Pending.to_string(), "pending");
        assert_eq!(X402IntentStatus::Settled.to_string(), "settled");
    }

    #[test]
    fn test_x402_entity_event_types() {
        assert_eq!(EntityType::x402_payment().as_str(), "x402_payment");
        assert_eq!(EventType::X402_PAYMENT_CREATED, "x402_payment.created");
        assert_eq!(EventType::X402_BATCH_SETTLED, "x402_batch.settled");
    }
}
