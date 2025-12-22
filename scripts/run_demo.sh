#!/bin/bash
#
# StateSet VES Demo Script
# Demonstrates the full event flow: CLI -> Sequencer -> L2 Chain
#
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         StateSet Verifiable Event Sync (VES) Demo             ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Generate unique IDs for this run
RUN_ID=$(date +%s)
TENANT="00000000-0000-0000-0000-0000000000bb"
STORE="00000000-0000-0000-0000-0000000000bb"

echo -e "${YELLOW}Run ID: $RUN_ID${NC}"
echo ""

#------------------------------------------------------------------------------
# Step 1: Check Services
#------------------------------------------------------------------------------
echo -e "${BLUE}━━━ Step 1: Checking Services ━━━${NC}"

echo -n "  Sequencer: "
HEALTH=$(curl -s http://localhost:8080/health 2>/dev/null | jq -r '.status' 2>/dev/null || echo "error")
if [ "$HEALTH" == "healthy" ]; then
    echo -e "${GREEN}✓ healthy${NC}"
else
    echo -e "${RED}✗ not running${NC}"
    echo "  Run: cd stateset-sequencer && docker-compose up -d"
    exit 1
fi

echo -n "  PostgreSQL: "
PGREADY=$(PGPASSWORD=sequencer psql -h localhost -p 5433 -U sequencer -d stateset_sequencer -c "SELECT 1" 2>/dev/null | grep -c "1 row" || echo "0")
if [ "$PGREADY" -gt 0 ]; then
    echo -e "${GREEN}✓ connected${NC}"
else
    echo -e "${RED}✗ not available${NC}"
    exit 1
fi

echo -n "  L2 Chain: "
BLOCK=$(curl -s http://localhost:8545 -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null | jq -r '.result' 2>/dev/null || echo "error")
if [ "$BLOCK" != "error" ] && [ "$BLOCK" != "null" ]; then
    echo -e "${GREEN}✓ block $((BLOCK))${NC}"
else
    echo -e "${RED}✗ not running${NC}"
    exit 1
fi

echo ""

#------------------------------------------------------------------------------
# Step 2: Create Hash Helper
#------------------------------------------------------------------------------
echo -e "${BLUE}━━━ Step 2: Setting Up ━━━${NC}"

cat > /tmp/canonical_hash.js << 'EOF'
const crypto = require("crypto");

function canonicalStringify(obj) {
    if (obj === null) return "null";
    if (typeof obj === "number" || typeof obj === "boolean") return String(obj);
    if (typeof obj === "string") return JSON.stringify(obj);
    if (Array.isArray(obj)) {
        return "[" + obj.map(canonicalStringify).join(",") + "]";
    }
    if (typeof obj === "object") {
        const keys = Object.keys(obj).sort();
        const pairs = keys.map(k => JSON.stringify(k) + ":" + canonicalStringify(obj[k]));
        return "{" + pairs.join(",") + "}";
    }
    return String(obj);
}

const payload = JSON.parse(process.argv[2]);
const canonical = canonicalStringify(payload);
const hash = crypto.createHash("sha256").update(canonical).digest("hex");
console.log(hash);
EOF

echo "  Created canonical hash helper"
echo ""

#------------------------------------------------------------------------------
# Step 3: Send Events
#------------------------------------------------------------------------------
echo -e "${BLUE}━━━ Step 3: Sending Events to Sequencer ━━━${NC}"

EVENT_COUNT=0
FIRST_SEQ=0
LAST_SEQ=0

send_event() {
    local EVENT_NUM=$1
    local ENTITY_TYPE=$2
    local ENTITY_ID=$3
    local EVENT_TYPE=$4
    local PAYLOAD=$5
    local TIMESTAMP=$6

    HASH=$(node /tmp/canonical_hash.js "$PAYLOAD")
    # Generate a valid UUID format using hex
    EVENT_UUID=$(printf "%08x-%04x-4%03x-8%03x-%012x" $RUN_ID $EVENT_NUM $EVENT_NUM $EVENT_NUM $EVENT_NUM)

    RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/events/ingest \
        -H "Content-Type: application/json" \
        -d '{
            "agent_id": "00000000-0000-0000-0000-000000000001",
            "events": [{
                "event_id": "'"$EVENT_UUID"'",
                "tenant_id": "'"$TENANT"'",
                "store_id": "'"$STORE"'",
                "entity_type": "'"$ENTITY_TYPE"'",
                "entity_id": "'"$ENTITY_ID"'",
                "event_type": "'"$EVENT_TYPE"'",
                "payload": '"$PAYLOAD"',
                "payload_hash": "'"$HASH"'",
                "created_at": "'"$TIMESTAMP"'",
                "source_agent": "00000000-0000-0000-0000-000000000001"
            }]
        }')

    ACCEPTED=$(echo $RESPONSE | jq -r '.events_accepted')
    SEQ=$(echo $RESPONSE | jq -r '.assigned_sequence_end // .head_sequence')

    if [ "$ACCEPTED" == "1" ]; then
        echo -e "  ${GREEN}✓${NC} Event $EVENT_NUM: $EVENT_TYPE → Sequence #$SEQ"
        EVENT_COUNT=$((EVENT_COUNT + 1))
        if [ $FIRST_SEQ -eq 0 ]; then
            FIRST_SEQ=$SEQ
        fi
        LAST_SEQ=$SEQ
    else
        REASON=$(echo $RESPONSE | jq -r '.rejections[0].reason // "unknown"')
        echo -e "  ${RED}✗${NC} Event $EVENT_NUM: $EVENT_TYPE → Rejected ($REASON)"
    fi
}

# Scenario: Customer places a flash sale order

echo "  Scenario: Flash Sale Order"
echo ""

send_event 1 "customer" "cust-$RUN_ID" "customer.registered" \
    '{"customer_id":"cust-'"$RUN_ID"'","email":"flash-'"$RUN_ID"'@demo.com","name":"Demo Customer"}' \
    "2025-12-21T18:00:00Z"

send_event 2 "cart" "cart-$RUN_ID" "cart.created" \
    '{"cart_id":"cart-'"$RUN_ID"'","customer_id":"cust-'"$RUN_ID"'"}' \
    "2025-12-21T18:00:10Z"

send_event 3 "cart" "cart-$RUN_ID" "cart.item_added" \
    '{"cart_id":"cart-'"$RUN_ID"'","item":{"price":89.99,"quantity":2,"sku":"DEMO-ITEM-001"}}' \
    "2025-12-21T18:00:20Z"

send_event 4 "order" "order-$RUN_ID" "order.created" \
    '{"customer_id":"cust-'"$RUN_ID"'","items":[{"price":89.99,"quantity":2,"sku":"DEMO-ITEM-001"}],"order_id":"order-'"$RUN_ID"'","total":179.98}' \
    "2025-12-21T18:00:30Z"

send_event 5 "inventory" "inv-$RUN_ID" "inventory.reserved" \
    '{"order_id":"order-'"$RUN_ID"'","quantity":2,"sku":"DEMO-ITEM-001"}' \
    "2025-12-21T18:00:35Z"

send_event 6 "payment" "pay-$RUN_ID" "payment.captured" \
    '{"amount":179.98,"order_id":"order-'"$RUN_ID"'","payment_id":"pay-'"$RUN_ID"'"}' \
    "2025-12-21T18:00:40Z"

send_event 7 "order" "order-$RUN_ID" "order.confirmed" \
    '{"order_id":"order-'"$RUN_ID"'","status":"confirmed"}' \
    "2025-12-21T18:00:45Z"

send_event 8 "shipment" "ship-$RUN_ID" "shipment.created" \
    '{"carrier":"FastShip","order_id":"order-'"$RUN_ID"'","shipment_id":"ship-'"$RUN_ID"'","tracking":"TRACK123456"}' \
    "2025-12-21T18:01:00Z"

echo ""
echo "  Events submitted: $EVENT_COUNT"
echo "  Sequence range: $FIRST_SEQ - $LAST_SEQ"
echo ""

#------------------------------------------------------------------------------
# Step 4: Verify in Database
#------------------------------------------------------------------------------
echo -e "${BLUE}━━━ Step 4: Verifying in PostgreSQL ━━━${NC}"

DB_COUNT=$(PGPASSWORD=sequencer psql -h localhost -p 5433 -U sequencer -d stateset_sequencer -t -c \
    "SELECT COUNT(*) FROM events WHERE tenant_id = '$TENANT'" 2>/dev/null | tr -d ' ')

echo "  Events in database for this tenant: $DB_COUNT"
echo ""

#------------------------------------------------------------------------------
# Step 5: Generate Merkle Commitment
#------------------------------------------------------------------------------
echo -e "${BLUE}━━━ Step 5: Generating Merkle Commitment ━━━${NC}"

# Get the actual sequence range from the database
SEQ_RANGE=$(PGPASSWORD=sequencer psql -h localhost -p 5433 -U sequencer -d stateset_sequencer -t -c \
    "SELECT MIN(sequence_number), MAX(sequence_number) FROM events WHERE tenant_id = '$TENANT'" 2>/dev/null | tr -d ' ')

SEQ_START=$(echo $SEQ_RANGE | cut -d'|' -f1)
SEQ_END=$(echo $SEQ_RANGE | cut -d'|' -f2)

COMMIT_RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/commitments \
    -H "Content-Type: application/json" \
    -d '{
        "tenant_id": "'"$TENANT"'",
        "store_id": "'"$STORE"'",
        "sequence_start": '"$SEQ_START"',
        "sequence_end": '"$SEQ_END"'
    }')

BATCH_ID=$(echo $COMMIT_RESPONSE | jq -r '.batch_id')
EVENTS_ROOT=$(echo $COMMIT_RESPONSE | jq -r '.events_root')
STATE_ROOT=$(echo $COMMIT_RESPONSE | jq -r '.new_state_root')
COMMIT_COUNT=$(echo $COMMIT_RESPONSE | jq -r '.event_count')

echo "  Batch ID:     $BATCH_ID"
echo "  Events Root:  ${EVENTS_ROOT:0:16}...${EVENTS_ROOT: -16}"
echo "  State Root:   ${STATE_ROOT:0:16}...${STATE_ROOT: -16}"
echo "  Event Count:  $COMMIT_COUNT"
echo "  Seq Range:    $SEQ_START - $SEQ_END"
echo ""

#------------------------------------------------------------------------------
# Step 6: Anchor to L2 Chain
#------------------------------------------------------------------------------
echo -e "${BLUE}━━━ Step 6: Anchoring to SET L2 Chain ━━━${NC}"

# Convert UUID to bytes32 (remove dashes, pad to 64 hex chars)
BATCH_BYTES32="0x$(echo $BATCH_ID | tr -d '-')00000000000000000000000000000000"
TENANT_BYTES32="0x$(echo $TENANT | tr -d '-')00000000000000000000000000000000"

CONTRACT="0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

echo "  Submitting transaction..."

TX_OUTPUT=$(docker exec set-chain cast send \
    --private-key $PRIVATE_KEY \
    $CONTRACT \
    "anchor(bytes32,bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint32)" \
    "$BATCH_BYTES32" \
    "$TENANT_BYTES32" \
    "$TENANT_BYTES32" \
    "0x$EVENTS_ROOT" \
    "0x$STATE_ROOT" \
    $SEQ_START $SEQ_END $COMMIT_COUNT 2>&1)

TX_HASH=$(echo "$TX_OUTPUT" | grep "^transactionHash" | awk '{print $2}')
TX_BLOCK=$(echo "$TX_OUTPUT" | grep "^blockNumber" | head -1 | awk '{print $2}')
TX_STATUS=$(echo "$TX_OUTPUT" | grep "^status" | awk '{print $2}')

if [ "$TX_STATUS" == "1" ]; then
    echo -e "  ${GREEN}✓${NC} Transaction successful"
    echo "  Transaction: ${TX_HASH:0:20}...${TX_HASH: -20}"
    echo "  Block: $TX_BLOCK"
else
    echo -e "  ${RED}✗${NC} Transaction failed"
    echo "$TX_OUTPUT"
fi
echo ""

#------------------------------------------------------------------------------
# Step 7: Verify On-Chain
#------------------------------------------------------------------------------
echo -e "${BLUE}━━━ Step 7: On-Chain Verification ━━━${NC}"

IS_ANCHORED=$(docker exec set-chain cast call \
    $CONTRACT \
    "isAnchored(bytes32)(bool)" \
    "$BATCH_BYTES32" 2>&1 | grep -v "Warning" | tail -1)

ANCHORED_COUNT=$(docker exec set-chain cast call \
    $CONTRACT \
    "getAnchoredCount()(uint256)" 2>&1 | grep -v "Warning" | tail -1)

echo -n "  Commitment anchored: "
if [ "$IS_ANCHORED" == "true" ]; then
    echo -e "${GREEN}✓ YES${NC}"
else
    echo -e "${RED}✗ NO${NC}"
fi

echo "  Total anchored batches: $ANCHORED_COUNT"
echo ""

#------------------------------------------------------------------------------
# Summary
#------------------------------------------------------------------------------
echo -e "${BLUE}━━━ Summary ━━━${NC}"
echo ""
BLOCK_NUM=$(echo "$TX_BLOCK" | tr -d '\n' | head -c 10)
echo "  ┌─────────────────────────────────────────────────────────────┐"
printf "  │  %-20s %-38s │\n" "Events Created:" "$EVENT_COUNT"
printf "  │  %-20s %-38s │\n" "Events Sequenced:" "$COMMIT_COUNT"
printf "  │  %-20s %-38s │\n" "Merkle Root:" "${EVENTS_ROOT:0:20}..."
printf "  │  %-20s %-38s │\n" "L2 Block:" "$BLOCK_NUM"
printf "  │  %-20s %-38s │\n" "On-Chain Verified:" "$IS_ANCHORED"
echo "  └─────────────────────────────────────────────────────────────┘"
echo ""
echo -e "${GREEN}Demo complete!${NC} The flash sale order is now cryptographically"
echo "committed and anchored to the blockchain."
echo ""
echo "To query the events:"
echo "  PGPASSWORD=sequencer psql -h localhost -p 5433 -U sequencer -d stateset_sequencer \\"
echo "    -c \"SELECT sequence_number, event_type, entity_id FROM events WHERE tenant_id = '$TENANT' ORDER BY sequence_number\""
echo ""
