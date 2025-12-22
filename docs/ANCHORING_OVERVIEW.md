# On-Chain Anchoring System Overview

## What We Built

A complete on-chain anchoring system that cryptographically commits batches of commerce events to the Set Chain (an EVM-compatible L2). This provides **verifiable proof** that events occurred in a specific order at a specific time.

### Two Deployment Modes

- **Embedded anchoring (this repo):** the sequencer submits commitments on-chain directly when `L2_RPC_URL`, `SET_REGISTRY_ADDRESS`, and `SEQUENCER_PRIVATE_KEY` are configured.
- **External anchoring (`icommerce-app/set/anchor`):** a separate service submits commitments on-chain and notifies the sequencer via:
  - `GET /v1/commitments/pending`
  - `POST /v1/commitments/{batch_id}/anchored`

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Client Applications                              │
│                    (CLI, Web Apps, Mobile Apps)                          │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        StateSet Sequencer                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │   Ingest    │  │  Sequencer  │  │ Commitment  │  │   Anchor    │    │
│  │   Service   │──│   Engine    │──│   Engine    │──│   Service   │    │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘    │
│        │                │                │                │             │
│        ▼                ▼                ▼                ▼             │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                      PostgreSQL Database                         │   │
│  │   events │ commitments │ entity_versions │ api_keys              │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼ (Anchor Transaction)
┌─────────────────────────────────────────────────────────────────────────┐
│                           Set Chain (L2)                                 │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                     StateSetAnchor Contract                      │   │
│  │   - anchor(): Store batch commitment                             │   │
│  │   - verifyEventsRoot(): Verify an anchored root                  │   │
│  │   - getLatestSequence(): Latest sequence per tenant/store        │   │
│  │   - isAnchored(): Check batch existence                          │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

## How It Works

### 1. Event Ingestion
Events flow from client applications into the sequencer via the REST API:

```bash
POST /api/v1/events/ingest
{
  "agent_id": "...",
  "events": [
    {
      "event_type": "OrderCreated",
      "entity_type": "Order",
      "entity_id": "order-123",
      "payload": { ... },
      "payload_hash": "abc123..."
    }
  ]
}
```

### 2. Global Sequencing
Each event receives a **globally unique, monotonically increasing sequence number**. This guarantees deterministic ordering across all tenants and stores.

### 3. Commitment Creation
When ready to anchor, create a commitment for a range of events:

```bash
POST /api/v1/commitments
{
  "tenant_id": "00000000-0000-0000-0000-000000000001",
  "store_id": "00000000-0000-0000-0000-000000000001",
  "sequence_start": 15,
  "sequence_end": 18
}
```

This generates:
- **events_root**: Merkle root of all event hashes in the batch
- **prev_state_root**: State root before this batch
- **new_state_root**: State root after applying this batch

### 4. On-Chain Anchoring
Anchor the commitment to the blockchain:

```bash
POST /api/v1/anchor
{
  "batch_id": "0e22804e-c668-49de-b0be-d05e6f77e879"
}
```

Response:
```json
{
  "batch_id": "0e22804e-c668-49de-b0be-d05e6f77e879",
  "chain_tx_hash": "c9a9b970031a425c944fbf645328f431c7e074484618dc6e3ae25fb961cc3952",
  "events_root": "7be81e1593830f42a9da669cd12395c6e9eba0936d7e51cccd6161cdc9e26574",
  "sequence_start": 15,
  "sequence_end": 18,
  "status": "anchored"
}
```

### 5. Verification
Verify the commitment is on-chain:

```bash
GET /api/v1/anchor/{batch_id}/verify
```

Response:
```json
{
  "batch_id": "0e22804e-c668-49de-b0be-d05e6f77e879",
  "anchored_on_chain": true
}
```

## Key Components

### Sequencer (Rust)

**`src/anchor.rs`** - The anchor service that interacts with the blockchain:

```rust
pub struct AnchorService {
    config: AnchorConfig,  // RPC URL, contract address, private key
}

impl AnchorService {
    // Submit commitment to blockchain
    pub async fn anchor_commitment(&self, commitment: &BatchCommitment) -> Result<Hash256>;

    // Verify commitment exists on-chain
    pub async fn verify_anchored(&self, batch_id: Uuid) -> Result<bool>;

    // Get on-chain head sequence for a tenant/store
    pub async fn get_chain_head(&self, tenant_id: Uuid, store_id: Uuid) -> Result<u64>;
}
```

### StateSetAnchor Contract (Solidity)

**`contracts/src/StateSetAnchor.sol`** - Stores commitments on-chain:

```solidity
function anchor(
    bytes32 batchId,
    bytes32 tenantId,
    bytes32 storeId,
    bytes32 eventsRoot,
    bytes32 stateRoot,
    uint64 sequenceStart,
    uint64 sequenceEnd,
    uint32 eventCount
) external;

function isAnchored(bytes32 batchId) external view returns (bool);

function getLatestSequence(bytes32 tenantId, bytes32 storeId) external view returns (uint64);

function verifyEventsRoot(bytes32 batchId, bytes32 eventsRoot) external view returns (bool);
```

## Data Flow Example

```
1. Client pushes 4 order events
   ┌──────────────────────────────────────┐
   │ OrderCreated      → sequence: 15     │
   │ OrderStatusChanged → sequence: 16    │
   │ OrderShipped      → sequence: 17     │
   │ OrderDelivered    → sequence: 18     │
   └──────────────────────────────────────┘
                    │
                    ▼
2. Create commitment for sequences 15-18
   ┌──────────────────────────────────────┐
   │ batch_id: 0e22804e-...               │
   │ events_root: 7be81e15...             │
   │ sequence_range: (15, 18)             │
   │ event_count: 4                       │
   └──────────────────────────────────────┘
                    │
                    ▼
3. Anchor to Set Chain
   ┌──────────────────────────────────────┐
   │ Transaction sent to StateSetAnchor   │
   │ tx_hash: c9a9b970...                 │
   │ Block: included in next block        │
   └──────────────────────────────────────┘
                    │
                    ▼
4. Commitment is now immutable on-chain!
   Anyone can verify events were committed
   at this point in time.
```

## Why This Matters

### Auditability
- Every commerce event has a cryptographic proof of existence
- Auditors can verify the complete event history
- Timestamps are blockchain-guaranteed, not self-reported

### Dispute Resolution
- Prove exactly what happened and when
- Merkle proofs show specific events were part of a batch
- On-chain data is immutable and tamper-evident

### Compliance
- SOC2, GDPR, and other compliance requirements
- Immutable audit trail for financial transactions
- Third-party verifiable without trusting the sequencer

### Cross-System Verification
- Multiple parties can verify the same data
- No need to trust any single system
- Cryptographic guarantees instead of contractual ones

## Configuration

### Environment Variables

```bash
# L2 Chain Connection
L2_RPC_URL=http://localhost:8545
L2_CHAIN_ID=84532001

# Contract Address (deployed StateSetAnchor)
SET_REGISTRY_ADDRESS=0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512

# Sequencer Wallet (must be authorized in contract)
SEQUENCER_PRIVATE_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
```

### Docker Compose

```yaml
services:
  sequencer:
    environment:
      - L2_RPC_URL=http://host.docker.internal:8545
      - SET_REGISTRY_ADDRESS=0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
      - SEQUENCER_PRIVATE_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
      - L2_CHAIN_ID=84532001
    extra_hosts:
      - "host.docker.internal:host-gateway"
```

## Local Development Setup

### 1. Start the Set Chain (Anvil)

```bash
docker run -d --name set-chain --rm -p 8545:8545 \
  ghcr.io/foundry-rs/foundry "anvil --host 0.0.0.0 --chain-id 84532001"
```

### 2. Deploy StateSetAnchor

```bash
cd /home/dom/icommerce-app/set/contracts
docker run --rm -v $(pwd):/app -w /app --network host \
  ghcr.io/foundry-rs/foundry \
  "forge script script/Deploy.s.sol:DeployRegistryScript \
   --rpc-url http://localhost:8545 --broadcast"
```

### 3. Start the Sequencer

```bash
cd /home/dom/icommerce-app/stateset-sequencer
docker-compose up -d
```

### 4. Test the Flow

```bash
# Check anchor status
curl -H "Authorization: ApiKey dev_admin_key" http://localhost:8080/api/v1/anchor/status

# Push events (via CLI)
cd /home/dom/stateset-icommerce/cli
node test-commitment.mjs
node bin/stateset-sync.js push

# Create commitment
curl -X POST http://localhost:8080/api/v1/commitments \
  -H "Authorization: ApiKey dev_admin_key" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "00000000-0000-0000-0000-000000000001",
    "store_id": "00000000-0000-0000-0000-000000000001",
    "sequence_start": 1,
    "sequence_end": 4
  }'

# Anchor it
curl -X POST http://localhost:8080/api/v1/anchor \
  -H "Authorization: ApiKey dev_admin_key" \
  -H "Content-Type: application/json" \
  -d '{"batch_id": "<batch_id_from_above>"}'

# Verify
curl -H "Authorization: ApiKey dev_admin_key" http://localhost:8080/api/v1/anchor/<batch_id>/verify
```

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/anchor/status` | GET | Check if anchoring is enabled |
| `/api/v1/anchor` | POST | Anchor a commitment on-chain |
| `/api/v1/anchor/:batch_id/verify` | GET | Verify commitment is on-chain |
| `/api/v1/commitments` | POST | Create a new commitment |
| `/api/v1/commitments` | GET | List commitments |
| `/api/v1/proofs/:sequence` | GET | Get inclusion proof for an event |
| `/api/v1/proofs/verify` | POST | Verify an inclusion proof |

## Security Considerations

1. **Private Key Security**: The sequencer private key should be stored securely (HSM, KMS, or secure vault in production)

2. **Authorized Sequencers**: Only authorized addresses can submit commitments to the contract

3. **State Continuity**: The contract enforces that batches are contiguous (no gaps in sequence numbers)

4. **Strict Mode**: When enabled, the contract verifies state root continuity between batches

## Future Enhancements

- [ ] Automatic batching and anchoring based on time/count thresholds
- [ ] Multi-chain anchoring (Ethereum mainnet, other L2s)
- [ ] Zero-knowledge proofs for privacy-preserving verification
- [ ] Batch compression for gas optimization
- [ ] Webhook notifications when anchoring completes
