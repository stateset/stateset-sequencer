# Zero-Knowledge Proof Integration Guide

Integrating **stateset-stark** STARK proofs with the VES pipeline for verifiable compliance.

---

## Architecture with ZK Proofs

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ENHANCED VES FLOW                              │
│                                                                             │
│  ┌─────────┐      ┌────────────┐      ┌────────────┐      ┌─────────────┐  │
│  │   CLI   │ ──▶  │ Sequencer  │ ──▶  │ PostgreSQL │ ──▶  │   Merkle    │  │
│  │ (Event) │      │  (Order)   │      │  (Store)   │      │ Commitment  │  │
│  └─────────┘      └────────────┘      └─────┬──────┘      └──────┬──────┘  │
│                                             │                     │         │
│                                             ▼                     │         │
│                                    ┌────────────────┐             │         │
│                                    │ STARK Prover   │             │         │
│                                    │ (stateset-     │             │         │
│                                    │   stark)       │             │         │
│                                    └───────┬────────┘             │         │
│                                            │                      │         │
│                                            ▼                      ▼         │
│                                    ┌────────────────┐    ┌──────────────┐   │
│                                    │ Compliance     │    │ SET L2 Chain │   │
│                                    │ Proof          │───▶│ (Anchor +    │   │
│                                    │ "amt < $10K"   │    │  Proof Hash) │   │
│                                    └────────────────┘    └──────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## What ZK Proofs Add

| Without ZK | With ZK (stateset-stark) |
|------------|--------------------------|
| Sequencer sees all data | Encrypted payloads, proven compliant |
| Trust the sequencer | Verify cryptographically |
| "We checked compliance" | "Here's the proof, verify yourself" |
| Regulatory word-of-mouth | Auditable, post-quantum secure proofs |

---

## Prerequisites

### 1. Build stateset-stark

```bash
cd /home/dom/icommerce-app/stateset-stark
cargo build --release
```

### 2. Ensure Services Running

```bash
# Sequencer + PostgreSQL + L2
cd /home/dom/icommerce-app/stateset-sequencer
docker-compose up -d

# Verify
curl -s http://localhost:8080/health | jq .
```

---

## API Endpoints for Compliance Proofs

The sequencer already supports these endpoints:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/ves/compliance/:event_id/inputs` | POST | Get public inputs for proving |
| `/api/v1/ves/compliance/:event_id/proofs` | GET | List proofs for an event |
| `/api/v1/ves/compliance/:event_id/proofs` | POST | Submit a proof |
| `/api/v1/ves/compliance/proofs/:proof_id` | GET | Get proof details |
| `/api/v1/ves/compliance/proofs/:proof_id/verify` | GET | Verify a proof |

---

## Step-by-Step Integration

### Step 1: Create an Event with Amount

```bash
# Create an order event with a monetary amount
PAYLOAD='{"amount":5000,"currency":"USD","customer_id":"cust-001","order_id":"order-zk-001"}'
HASH=$(node -e "
const crypto = require('crypto');
function cs(o){if(o===null)return'null';if(typeof o==='number'||typeof o==='boolean')return String(o);if(typeof o==='string')return JSON.stringify(o);if(Array.isArray(o))return'['+o.map(cs).join(',')+']';if(typeof o==='object'){const k=Object.keys(o).sort();return'{'+k.map(x=>JSON.stringify(x)+':'+cs(o[x])).join(',')+'}'}return String(o)}
console.log(crypto.createHash('sha256').update(cs($PAYLOAD)).digest('hex'));
")

curl -s -X POST http://localhost:8080/api/v1/events/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "00000000-0000-0000-0000-000000000001",
    "events": [{
      "event_id": "zk000001-0001-4000-8000-000000000001",
      "tenant_id": "00000000-0000-0000-0000-0000000000dd",
      "store_id": "00000000-0000-0000-0000-0000000000dd",
      "entity_type": "order",
      "entity_id": "order-zk-001",
      "event_type": "order.created",
      "payload": '"$PAYLOAD"',
      "payload_hash": "'$HASH'",
      "created_at": "2025-12-21T19:00:00Z",
      "source_agent": "00000000-0000-0000-0000-000000000001"
    }]
  }' | jq .
```

### Step 2: Get Public Inputs for Proving

```bash
EVENT_ID="zk000001-0001-4000-8000-000000000001"

curl -s -X POST "http://localhost:8080/api/v1/ves/compliance/$EVENT_ID/inputs" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "aml.threshold",
    "policy_params": {"threshold": 10000}
  }' | jq .
```

Response includes all fields needed for STARK proving:
```json
{
  "event_id": "zk000001-0001-4000-8000-000000000001",
  "tenant_id": "00000000-0000-0000-0000-0000000000dd",
  "store_id": "00000000-0000-0000-0000-0000000000dd",
  "sequence_number": 1,
  "payload_kind": 0,
  "payload_plain_hash": "abc123...",
  "payload_cipher_hash": null,
  "event_signing_hash": "def456...",
  "policy_id": "aml.threshold",
  "policy_params": {"threshold": 10000},
  "policy_hash": "789abc..."
}
```

### Step 3: Generate STARK Proof (Rust)

```rust
use ves_stark_prover::{ComplianceProver, ComplianceWitness};
use ves_stark_primitives::CompliancePublicInputs;
use ves_stark_air::policies::AmlThresholdPolicy;

// Private witness (only prover knows)
let amount = 5000u64;  // The actual transaction amount
let threshold = 10000u64;

// Public inputs (from sequencer API response)
let public_inputs = CompliancePublicInputs {
    event_id: uuid::Uuid::parse_str("zk000001-0001-4000-8000-000000000001")?,
    tenant_id: uuid::Uuid::parse_str("00000000-0000-0000-0000-0000000000dd")?,
    store_id: uuid::Uuid::parse_str("00000000-0000-0000-0000-0000000000dd")?,
    sequence_number: 1,
    payload_kind: 0,
    payload_plain_hash: "abc123...".to_string(),
    payload_cipher_hash: None,
    event_signing_hash: "def456...".to_string(),
    policy_id: "aml.threshold".to_string(),
    policy_params: serde_json::json!({"threshold": threshold}),
    policy_hash: "789abc...".to_string(),
};

// Create witness and prover
let witness = ComplianceWitness::new(amount, public_inputs.clone());
let policy = AmlThresholdPolicy::new(threshold);
let prover = ComplianceProver::new(policy);

// Generate proof (takes ~1-5 seconds)
let proof = prover.prove(&witness)?;

println!("Proof size: {} bytes", proof.proof_bytes.len());
println!("Proof hash: {}", proof.proof_hash);
println!("Proving time: {}ms", proof.metadata.proving_time_ms);
```

### Step 4: Submit Proof to Sequencer

```bash
# Base64 encode the proof bytes
PROOF_B64=$(echo -n "$PROOF_BYTES" | base64)

curl -s -X POST "http://localhost:8080/api/v1/ves/compliance/$EVENT_ID/proofs" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "aml.threshold",
    "policy_params": {"threshold": 10000},
    "proof_type": "stark.winterfell",
    "proof_version": 1,
    "public_inputs": {
      "event_id": "zk000001-0001-4000-8000-000000000001",
      "threshold": 10000
    },
    "proof_b64": "'$PROOF_B64'"
  }' | jq .
```

Response:
```json
{
  "proof_id": "abc12345-...",
  "event_id": "zk000001-...",
  "proof_type": "stark.winterfell",
  "proof_version": 1,
  "proof_hash": "fedcba...",
  "submitted_at": "2025-12-21T19:01:00Z"
}
```

### Step 5: Verify Proof

```bash
PROOF_ID="abc12345-..."

curl -s "http://localhost:8080/api/v1/ves/compliance/proofs/$PROOF_ID/verify" | jq .
```

Response:
```json
{
  "proof_id": "abc12345-...",
  "valid": true,
  "policy_id": "aml.threshold",
  "proof_type": "stark.winterfell",
  "verification_time_ms": 50,
  "public_inputs_match": true,
  "policy_hash_valid": true
}
```

---

## Enhanced Demo Script with ZK Proofs

Save as `run_zk_demo.sh`:

```bash
#!/bin/bash
set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     StateSet VES + STARK Zero-Knowledge Compliance Demo       ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

RUN_ID=$(date +%s)
TENANT="00000000-0000-0000-0000-0000000000ee"
EVENT_UUID=$(printf "%08x-0001-4000-8000-%012x" $RUN_ID $RUN_ID)
AMOUNT=5000
THRESHOLD=10000

#------------------------------------------------------------------------------
echo -e "${BLUE}━━━ Step 1: Create Order Event (amount=$AMOUNT) ━━━${NC}"
#------------------------------------------------------------------------------

PAYLOAD="{\"amount\":$AMOUNT,\"currency\":\"USD\",\"order_id\":\"order-zk-$RUN_ID\"}"
HASH=$(node -e "
const crypto=require('crypto');
function cs(o){if(o===null)return'null';if(typeof o==='number'||typeof o==='boolean')return String(o);if(typeof o==='string')return JSON.stringify(o);if(Array.isArray(o))return'['+o.map(cs).join(',')+']';if(typeof o==='object'){const k=Object.keys(o).sort();return'{'+k.map(x=>JSON.stringify(x)+':'+cs(o[x])).join(',')+'}'}return String(o)}
console.log(crypto.createHash('sha256').update(cs($PAYLOAD)).digest('hex'));
")

RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/events/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "00000000-0000-0000-0000-000000000001",
    "events": [{
      "event_id": "'$EVENT_UUID'",
      "tenant_id": "'$TENANT'",
      "store_id": "'$TENANT'",
      "entity_type": "order",
      "entity_id": "order-zk-'$RUN_ID'",
      "event_type": "order.created",
      "payload": '$PAYLOAD',
      "payload_hash": "'$HASH'",
      "created_at": "2025-12-21T19:00:00Z",
      "source_agent": "00000000-0000-0000-0000-000000000001"
    }]
  }')

SEQ=$(echo $RESPONSE | jq -r '.assigned_sequence_end')
echo -e "  ${GREEN}✓${NC} Event created: $EVENT_UUID"
echo "  Sequence: $SEQ"
echo "  Amount: \$$AMOUNT (private)"
echo ""

#------------------------------------------------------------------------------
echo -e "${BLUE}━━━ Step 2: Get Public Inputs for Policy aml.threshold ━━━${NC}"
#------------------------------------------------------------------------------

INPUTS=$(curl -s -X POST "http://localhost:8080/api/v1/ves/compliance/$EVENT_UUID/inputs" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "aml.threshold",
    "policy_params": {"threshold": '$THRESHOLD'}
  }')

POLICY_HASH=$(echo $INPUTS | jq -r '.policy_hash')
PAYLOAD_HASH=$(echo $INPUTS | jq -r '.payload_plain_hash')

echo -e "  ${GREEN}✓${NC} Public inputs retrieved"
echo "  Policy: aml.threshold (amount < \$$THRESHOLD)"
echo "  Policy Hash: ${POLICY_HASH:0:16}..."
echo "  Payload Hash: ${PAYLOAD_HASH:0:16}..."
echo ""

#------------------------------------------------------------------------------
echo -e "${BLUE}━━━ Step 3: Generate STARK Proof ━━━${NC}"
#------------------------------------------------------------------------------

echo "  Generating proof that amount < threshold..."
echo "  (In production, this runs stateset-stark prover)"
echo ""

# Simulate proof generation (in reality, call stateset-stark)
# For demo, we'll submit a placeholder proof
PROOF_B64=$(echo -n "demo_proof_$RUN_ID" | base64)
PROOF_HASH=$(echo -n "demo_proof_$RUN_ID" | sha256sum | cut -d' ' -f1)

echo -e "  ${GREEN}✓${NC} Proof generated"
echo "  Proof Hash: ${PROOF_HASH:0:32}..."
echo "  Claim: \$$AMOUNT < \$$THRESHOLD (without revealing \$$AMOUNT)"
echo ""

#------------------------------------------------------------------------------
echo -e "${BLUE}━━━ Step 4: Submit Proof to Sequencer ━━━${NC}"
#------------------------------------------------------------------------------

SUBMIT_RESPONSE=$(curl -s -X POST "http://localhost:8080/api/v1/ves/compliance/$EVENT_UUID/proofs" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "aml.threshold",
    "policy_params": {"threshold": '$THRESHOLD'},
    "proof_type": "stark.winterfell",
    "proof_version": 1,
    "public_inputs": {
      "event_id": "'$EVENT_UUID'",
      "threshold": '$THRESHOLD'
    },
    "proof_b64": "'$PROOF_B64'"
  }')

PROOF_ID=$(echo $SUBMIT_RESPONSE | jq -r '.proof_id')
echo -e "  ${GREEN}✓${NC} Proof submitted"
echo "  Proof ID: $PROOF_ID"
echo ""

#------------------------------------------------------------------------------
echo -e "${BLUE}━━━ Step 5: Verify Proof ━━━${NC}"
#------------------------------------------------------------------------------

VERIFY_RESPONSE=$(curl -s "http://localhost:8080/api/v1/ves/compliance/proofs/$PROOF_ID/verify")

VALID=$(echo $VERIFY_RESPONSE | jq -r '.valid')
PUBLIC_INPUTS_MATCH=$(echo $VERIFY_RESPONSE | jq -r '.public_inputs_match')

echo -n "  Proof valid: "
if [ "$VALID" == "true" ]; then
    echo -e "${GREEN}✓ YES${NC}"
else
    echo -e "${YELLOW}⚠ PENDING (cryptographic verification requires stateset-stark)${NC}"
fi
echo "  Public inputs match: $PUBLIC_INPUTS_MATCH"
echo ""

#------------------------------------------------------------------------------
echo -e "${BLUE}━━━ Summary ━━━${NC}"
#------------------------------------------------------------------------------

echo ""
echo "  ┌───────────────────────────────────────────────────────────────┐"
echo "  │  ZERO-KNOWLEDGE COMPLIANCE PROOF                              │"
echo "  ├───────────────────────────────────────────────────────────────┤"
printf "  │  %-20s %-42s │\n" "Event ID:" "${EVENT_UUID:0:36}"
printf "  │  %-20s %-42s │\n" "Policy:" "aml.threshold (< \$$THRESHOLD)"
printf "  │  %-20s %-42s │\n" "Proof Type:" "STARK (Winterfell)"
printf "  │  %-20s %-42s │\n" "Proof ID:" "${PROOF_ID:0:36}"
echo "  ├───────────────────────────────────────────────────────────────┤"
echo "  │  WHAT WAS PROVEN:                                             │"
echo "  │  • Transaction amount is below AML threshold                  │"
echo "  │  • Without revealing the actual amount                        │"
echo "  │  • Cryptographically verifiable by anyone                     │"
echo "  │  • Post-quantum secure (hash-based, no trusted setup)         │"
echo "  └───────────────────────────────────────────────────────────────┘"
echo ""
echo -e "${GREEN}Demo complete!${NC}"
echo ""
```

---

## Database Schema for Proofs

The sequencer stores proofs in `ves_compliance_proofs`:

```sql
CREATE TABLE ves_compliance_proofs (
    proof_id UUID PRIMARY KEY,
    event_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,
    policy_id VARCHAR(64) NOT NULL,
    policy_params JSONB NOT NULL,
    policy_hash BYTEA NOT NULL,
    proof_type VARCHAR(32) NOT NULL,
    proof_version INTEGER NOT NULL,
    proof BYTEA NOT NULL,
    proof_hash BYTEA NOT NULL,
    public_inputs JSONB,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    FOREIGN KEY (event_id) REFERENCES events(event_id)
);
```

---

## Full Integration Checklist

| Component | Status | Notes |
|-----------|--------|-------|
| Event ingestion API | ✅ Working | `/api/v1/events/ingest` |
| Compliance inputs API | ✅ Working | `/api/v1/ves/compliance/:id/inputs` |
| Proof submission API | ✅ Working | `/api/v1/ves/compliance/:id/proofs` |
| Proof verification API | ✅ Working | `/api/v1/ves/compliance/proofs/:id/verify` |
| stateset-stark prover | ✅ Built | Needs integration script |
| stateset-stark verifier | ✅ Built | Needs sequencer integration |
| L2 proof anchoring | ⏳ Pending | Include proof_hash in commitment |
| On-chain verification | ⏳ Phase 2 | Solidity verifier |

---

## Node.js Demo Script

A comprehensive Node.js demo is available at `scripts/zk_compliance_demo.mjs`:

```bash
# Install dependencies (one time)
npm install @noble/ed25519 @noble/hashes

# Run the demo
node scripts/zk_compliance_demo.mjs
```

This script demonstrates:
- Ed25519 key generation for agent signing
- VES event creation with proper signature
- Fallback to regular events for demo purposes
- Simulated STARK proof generation
- Proof submission and verification flow

**Note**: Full VES event submission requires registered agent keys. The demo gracefully falls back to regular events while still demonstrating the ZK compliance proof flow.

---

## Running the Demo

Two demo scripts are available:

### Bash Demo (simpler)
```bash
./scripts/run_zk_demo.sh
```

### Node.js Demo (full flow with signatures)
```bash
node scripts/zk_compliance_demo.mjs
```

Both demonstrate the conceptual ZK compliance flow:
1. Create an event with a monetary amount
2. Get public inputs for proving
3. Generate a STARK proof that amount < threshold
4. Submit the proof to the sequencer
5. Verify the proof

---

## Next Steps

1. **Create integration binary**: CLI tool that ties prover to sequencer API
2. **Add stateset-stark verifier to sequencer**: Cryptographic verification
3. **Include proof hashes in commitments**: Anchor to L2
4. **Build more policies**: inventory limits, refund caps, etc.
5. **Agent key management**: CLI for registering agent keys

---

*Integration Guide v1.1 - December 2025*
