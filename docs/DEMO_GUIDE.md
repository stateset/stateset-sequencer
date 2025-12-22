# StateSet VES Demo Guide

A hands-on demonstration of the Verifiable Event Sync pipeline using a realistic e-commerce scenario.

---

## Scenario: Flash Sale Order Processing

A customer places an order during a flash sale. We'll track:
1. Customer registration
2. Product inventory check
3. Order creation
4. Inventory reservation
5. Payment confirmation
6. Order fulfillment

All events will be sequenced, committed to a Merkle tree, and anchored to the blockchain.

---

## Prerequisites

Ensure all services are running:

```bash
# Check services
docker ps | grep -E "sequencer|postgres|set-chain"

# Expected output:
# stateset-sequencer_sequencer_1  - port 8080
# postgres                        - port 5433
# set-chain                       - port 8545
```

If not running:
```bash
cd /home/dom/icommerce-app/stateset-sequencer
docker-compose up -d
```

---

## Part 1: Verify System Health

```bash
# Check sequencer health
curl -s http://localhost:8080/health | jq .

# Expected:
# {
#   "service": "stateset-sequencer",
#   "status": "healthy",
#   "version": "0.1.0"
# }

# Check L2 chain
curl -s http://localhost:8545 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' | jq .

# Check anchor service
curl -s http://localhost:8080/api/v1/anchor/status | jq .
```

---

## Part 2: Create Commerce Data via CLI

```bash
# Create a flash sale customer
stateset-direct --json customers create "flashsale@demo.com" "Flash" "Buyer"

# Create products for the sale
stateset-direct --json inventory create "FLASH-HOODIE-BLK" "Limited Edition Black Hoodie" 50
stateset-direct --json inventory create "FLASH-SNEAKER-WHT" "Exclusive White Sneakers" 25

# Verify inventory
stateset-direct --json inventory stock "FLASH-HOODIE-BLK"
stateset-direct --json inventory stock "FLASH-SNEAKER-WHT"
```

---

## Part 3: Generate Events with Proper Hashing

Create a helper script to compute canonical payload hashes:

```bash
cat > /tmp/hash_payload.js << 'EOF'
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
```

---

## Part 4: Send Flash Sale Events to Sequencer

### Event 1: Customer Registered

```bash
PAYLOAD='{"customer_id":"flash-001","email":"flashsale@demo.com","first_name":"Flash","last_name":"Buyer","registered_at":"2025-12-21T18:00:00Z"}'
HASH=$(node /tmp/hash_payload.js "$PAYLOAD")

curl -s -X POST http://localhost:8080/api/v1/events/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "00000000-0000-0000-0000-000000000001",
    "events": [{
      "event_id": "aaaaaaaa-0001-0001-0001-000000000001",
      "tenant_id": "00000000-0000-0000-0000-000000000099",
      "store_id": "00000000-0000-0000-0000-000000000099",
      "entity_type": "customer",
      "entity_id": "flash-001",
      "event_type": "customer.registered",
      "payload": '"$PAYLOAD"',
      "payload_hash": "'$HASH'",
      "created_at": "2025-12-21T18:00:00Z",
      "source_agent": "00000000-0000-0000-0000-000000000001"
    }]
  }' | jq .
```

### Event 2: Cart Created

```bash
PAYLOAD='{"cart_id":"cart-flash-001","customer_id":"flash-001","created_at":"2025-12-21T18:01:00Z","items":[]}'
HASH=$(node /tmp/hash_payload.js "$PAYLOAD")

curl -s -X POST http://localhost:8080/api/v1/events/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "00000000-0000-0000-0000-000000000001",
    "events": [{
      "event_id": "aaaaaaaa-0001-0001-0001-000000000002",
      "tenant_id": "00000000-0000-0000-0000-000000000099",
      "store_id": "00000000-0000-0000-0000-000000000099",
      "entity_type": "cart",
      "entity_id": "cart-flash-001",
      "event_type": "cart.created",
      "payload": '"$PAYLOAD"',
      "payload_hash": "'$HASH'",
      "created_at": "2025-12-21T18:01:00Z",
      "source_agent": "00000000-0000-0000-0000-000000000001"
    }]
  }' | jq .
```

### Event 3: Items Added to Cart

```bash
PAYLOAD='{"cart_id":"cart-flash-001","items":[{"price":89.99,"quantity":1,"sku":"FLASH-HOODIE-BLK"},{"price":149.99,"quantity":1,"sku":"FLASH-SNEAKER-WHT"}],"subtotal":239.98}'
HASH=$(node /tmp/hash_payload.js "$PAYLOAD")

curl -s -X POST http://localhost:8080/api/v1/events/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "00000000-0000-0000-0000-000000000001",
    "events": [{
      "event_id": "aaaaaaaa-0001-0001-0001-000000000003",
      "tenant_id": "00000000-0000-0000-0000-000000000099",
      "store_id": "00000000-0000-0000-0000-000000000099",
      "entity_type": "cart",
      "entity_id": "cart-flash-001",
      "event_type": "cart.items_added",
      "payload": '"$PAYLOAD"',
      "payload_hash": "'$HASH'",
      "created_at": "2025-12-21T18:02:00Z",
      "source_agent": "00000000-0000-0000-0000-000000000001"
    }]
  }' | jq .
```

### Event 4: Order Created

```bash
PAYLOAD='{"currency":"USD","customer_id":"flash-001","items":[{"price":89.99,"quantity":1,"sku":"FLASH-HOODIE-BLK"},{"price":149.99,"quantity":1,"sku":"FLASH-SNEAKER-WHT"}],"order_id":"order-flash-001","status":"pending","subtotal":239.98,"tax":19.20,"total":259.18}'
HASH=$(node /tmp/hash_payload.js "$PAYLOAD")

curl -s -X POST http://localhost:8080/api/v1/events/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "00000000-0000-0000-0000-000000000001",
    "events": [{
      "event_id": "aaaaaaaa-0001-0001-0001-000000000004",
      "tenant_id": "00000000-0000-0000-0000-000000000099",
      "store_id": "00000000-0000-0000-0000-000000000099",
      "entity_type": "order",
      "entity_id": "order-flash-001",
      "event_type": "order.created",
      "payload": '"$PAYLOAD"',
      "payload_hash": "'$HASH'",
      "created_at": "2025-12-21T18:03:00Z",
      "source_agent": "00000000-0000-0000-0000-000000000001"
    }]
  }' | jq .
```

### Event 5: Inventory Reserved

```bash
PAYLOAD='{"order_id":"order-flash-001","reservations":[{"quantity":1,"sku":"FLASH-HOODIE-BLK"},{"quantity":1,"sku":"FLASH-SNEAKER-WHT"}]}'
HASH=$(node /tmp/hash_payload.js "$PAYLOAD")

curl -s -X POST http://localhost:8080/api/v1/events/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "00000000-0000-0000-0000-000000000001",
    "events": [{
      "event_id": "aaaaaaaa-0001-0001-0001-000000000005",
      "tenant_id": "00000000-0000-0000-0000-000000000099",
      "store_id": "00000000-0000-0000-0000-000000000099",
      "entity_type": "inventory",
      "entity_id": "reservation-flash-001",
      "event_type": "inventory.reserved",
      "payload": '"$PAYLOAD"',
      "payload_hash": "'$HASH'",
      "created_at": "2025-12-21T18:03:30Z",
      "source_agent": "00000000-0000-0000-0000-000000000001"
    }]
  }' | jq .
```

### Event 6: Payment Confirmed

```bash
PAYLOAD='{"amount":259.18,"currency":"USD","order_id":"order-flash-001","payment_id":"pay-flash-001","payment_method":"card","status":"confirmed"}'
HASH=$(node /tmp/hash_payload.js "$PAYLOAD")

curl -s -X POST http://localhost:8080/api/v1/events/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "00000000-0000-0000-0000-000000000001",
    "events": [{
      "event_id": "aaaaaaaa-0001-0001-0001-000000000006",
      "tenant_id": "00000000-0000-0000-0000-000000000099",
      "store_id": "00000000-0000-0000-0000-000000000099",
      "entity_type": "payment",
      "entity_id": "pay-flash-001",
      "event_type": "payment.confirmed",
      "payload": '"$PAYLOAD"',
      "payload_hash": "'$HASH'",
      "created_at": "2025-12-21T18:04:00Z",
      "source_agent": "00000000-0000-0000-0000-000000000001"
    }]
  }' | jq .
```

### Event 7: Order Confirmed

```bash
PAYLOAD='{"confirmed_at":"2025-12-21T18:04:30Z","order_id":"order-flash-001","status":"confirmed"}'
HASH=$(node /tmp/hash_payload.js "$PAYLOAD")

curl -s -X POST http://localhost:8080/api/v1/events/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "00000000-0000-0000-0000-000000000001",
    "events": [{
      "event_id": "aaaaaaaa-0001-0001-0001-000000000007",
      "tenant_id": "00000000-0000-0000-0000-000000000099",
      "store_id": "00000000-0000-0000-0000-000000000099",
      "entity_type": "order",
      "entity_id": "order-flash-001",
      "event_type": "order.confirmed",
      "payload": '"$PAYLOAD"',
      "payload_hash": "'$HASH'",
      "created_at": "2025-12-21T18:04:30Z",
      "source_agent": "00000000-0000-0000-0000-000000000001"
    }]
  }' | jq .
```

---

## Part 5: Verify Events in PostgreSQL

```bash
PGPASSWORD=sequencer psql -h localhost -p 5433 -U sequencer -d stateset_sequencer -c "
SELECT
  sequence_number,
  entity_type,
  entity_id,
  event_type,
  created_at
FROM events
WHERE tenant_id = '00000000-0000-0000-0000-000000000099'
ORDER BY sequence_number;
"
```

Expected output:
```
 sequence_number | entity_type |      entity_id       |     event_type      |       created_at
-----------------+-------------+----------------------+---------------------+------------------------
               1 | customer    | flash-001            | customer.registered | 2025-12-21 18:00:00+00
               2 | cart        | cart-flash-001       | cart.created        | 2025-12-21 18:01:00+00
               3 | cart        | cart-flash-001       | cart.items_added    | 2025-12-21 18:02:00+00
               4 | order       | order-flash-001      | order.created       | 2025-12-21 18:03:00+00
               5 | inventory   | reservation-flash-001| inventory.reserved  | 2025-12-21 18:03:30+00
               6 | payment     | pay-flash-001        | payment.confirmed   | 2025-12-21 18:04:00+00
               7 | order       | order-flash-001      | order.confirmed     | 2025-12-21 18:04:30+00
```

---

## Part 6: Generate Merkle Commitment

```bash
curl -s -X POST http://localhost:8080/api/v1/commitments \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "00000000-0000-0000-0000-000000000099",
    "store_id": "00000000-0000-0000-0000-000000000099",
    "sequence_start": 1,
    "sequence_end": 7
  }' | jq .
```

Save the response - you'll need `batch_id`, `events_root`, and `new_state_root` for anchoring.

---

## Part 7: Anchor to SET L2 Chain

Using the values from the commitment response:

```bash
# Replace these with actual values from Part 6
BATCH_ID="<batch_id from response>"
EVENTS_ROOT="<events_root from response>"
STATE_ROOT="<new_state_root from response>"

# Convert batch_id UUID to bytes32 (remove dashes, pad to 64 chars)
# Example: 12345678-1234-1234-1234-123456789abc -> 0x123456781234123412341234567890bc0000...

# Anchor using cast
docker exec set-chain cast send \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0 \
  "anchor(bytes32,bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint32)" \
  <BATCH_ID_BYTES32> \
  0x0000000000000000000000000000009900000000000000000000000000000000 \
  0x0000000000000000000000000000009900000000000000000000000000000000 \
  0x${EVENTS_ROOT} \
  0x${STATE_ROOT} \
  1 7 7
```

---

## Part 8: Verify On-Chain Anchor

```bash
# Check if anchored
docker exec set-chain cast call \
  0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0 \
  "isAnchored(bytes32)(bool)" \
  <BATCH_ID_BYTES32>

# Get anchored count
docker exec set-chain cast call \
  0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0 \
  "getAnchoredCount()(uint256)"
```

---

## Quick Demo Script

Save this as `run_demo.sh` for a one-command demo:

```bash
#!/bin/bash
set -e

echo "=== StateSet VES Demo ==="
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}[1/5] Checking services...${NC}"
curl -s http://localhost:8080/health | jq -r '.status'

echo -e "${BLUE}[2/5] Creating hash helper...${NC}"
cat > /tmp/hash_payload.js << 'HASHEOF'
const crypto = require("crypto");
function canonicalStringify(obj) {
  if (obj === null) return "null";
  if (typeof obj === "number" || typeof obj === "boolean") return String(obj);
  if (typeof obj === "string") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonicalStringify).join(",") + "]";
  if (typeof obj === "object") {
    const keys = Object.keys(obj).sort();
    return "{" + keys.map(k => JSON.stringify(k) + ":" + canonicalStringify(obj[k])).join(",") + "}";
  }
  return String(obj);
}
const payload = JSON.parse(process.argv[2]);
console.log(crypto.createHash("sha256").update(canonicalStringify(payload)).digest("hex"));
HASHEOF

echo -e "${BLUE}[3/5] Sending demo events...${NC}"

# Generate unique IDs for this run
RUN_ID=$(date +%s)
TENANT="00000000-0000-0000-0000-0000000000aa"

send_event() {
  local EVENT_NUM=$1
  local ENTITY_TYPE=$2
  local ENTITY_ID=$3
  local EVENT_TYPE=$4
  local PAYLOAD=$5

  HASH=$(node /tmp/hash_payload.js "$PAYLOAD")

  RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/events/ingest \
    -H "Content-Type: application/json" \
    -d '{
      "agent_id": "00000000-0000-0000-0000-000000000001",
      "events": [{
        "event_id": "demo'$RUN_ID'-000'$EVENT_NUM'-0000-0000-000000000000",
        "tenant_id": "'$TENANT'",
        "store_id": "'$TENANT'",
        "entity_type": "'$ENTITY_TYPE'",
        "entity_id": "'$ENTITY_ID'",
        "event_type": "'$EVENT_TYPE'",
        "payload": '$PAYLOAD',
        "payload_hash": "'$HASH'",
        "created_at": "2025-12-21T18:0'$EVENT_NUM':00Z",
        "source_agent": "00000000-0000-0000-0000-000000000001"
      }]
    }')

  ACCEPTED=$(echo $RESPONSE | jq -r '.events_accepted')
  SEQ=$(echo $RESPONSE | jq -r '.assigned_sequence_end')
  echo "  Event $EVENT_NUM: $EVENT_TYPE -> Sequence $SEQ"
}

send_event 1 "customer" "cust-$RUN_ID" "customer.registered" \
  '{"customer_id":"cust-'$RUN_ID'","email":"demo@test.com"}'

send_event 2 "order" "order-$RUN_ID" "order.created" \
  '{"customer_id":"cust-'$RUN_ID'","order_id":"order-'$RUN_ID'","total":99.99}'

send_event 3 "order" "order-$RUN_ID" "order.confirmed" \
  '{"order_id":"order-'$RUN_ID'","status":"confirmed"}'

echo -e "${BLUE}[4/5] Creating Merkle commitment...${NC}"
COMMIT_RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/commitments \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "'$TENANT'",
    "store_id": "'$TENANT'",
    "sequence_start": 1,
    "sequence_end": 100
  }')

BATCH_ID=$(echo $COMMIT_RESPONSE | jq -r '.batch_id')
EVENTS_ROOT=$(echo $COMMIT_RESPONSE | jq -r '.events_root')
EVENT_COUNT=$(echo $COMMIT_RESPONSE | jq -r '.event_count')

echo "  Batch ID: $BATCH_ID"
echo "  Events Root: $EVENTS_ROOT"
echo "  Event Count: $EVENT_COUNT"

echo -e "${BLUE}[5/5] Anchoring to L2...${NC}"

# Convert UUID to bytes32
BATCH_BYTES32="0x$(echo $BATCH_ID | tr -d '-')00000000000000000000000000000000"
TENANT_BYTES32="0x$(echo $TENANT | tr -d '-')00000000000000000000000000000000"

TX_RESULT=$(docker exec set-chain cast send \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0 \
  "anchor(bytes32,bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint32)" \
  "$BATCH_BYTES32" \
  "$TENANT_BYTES32" \
  "$TENANT_BYTES32" \
  "0x$EVENTS_ROOT" \
  "0x$EVENTS_ROOT" \
  1 100 $EVENT_COUNT 2>&1)

TX_HASH=$(echo "$TX_RESULT" | grep "transactionHash" | awk '{print $2}')
BLOCK=$(echo "$TX_RESULT" | grep "blockNumber" | awk '{print $2}')

echo "  Transaction: $TX_HASH"
echo "  Block: $BLOCK"

# Verify
ANCHORED=$(docker exec set-chain cast call \
  0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0 \
  "isAnchored(bytes32)(bool)" \
  "$BATCH_BYTES32" 2>&1 | tail -1)

echo ""
echo -e "${GREEN}=== Demo Complete ===${NC}"
echo "  Events Sequenced: $EVENT_COUNT"
echo "  Merkle Root: $EVENTS_ROOT"
echo "  On-Chain Anchor: $ANCHORED"
echo ""
```

Make it executable:
```bash
chmod +x run_demo.sh
./run_demo.sh
```

---

## Troubleshooting

### Events Rejected with "InvalidPayloadHash"
- Ensure payload JSON keys are alphabetically sorted
- Use the `hash_payload.js` helper script
- Check for trailing whitespace or formatting differences

### Anchor Transaction Reverts
- Verify contract address: `0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0`
- Check if batch was already anchored (duplicate)
- Ensure sequence range is valid (end >= start)

### Connection Refused
```bash
# Restart services
cd stateset-sequencer
docker-compose down
docker-compose up -d

# Wait for health
sleep 10
curl http://localhost:8080/health
```

---

## What You Just Proved

1. **Deterministic Ordering**: Events received sequence numbers in submission order
2. **Data Integrity**: Payload hashes validated against canonical JSON
3. **Cryptographic Commitment**: Merkle tree root computed over all events
4. **Blockchain Anchor**: Commitment permanently recorded on L2
5. **Verifiability**: Anyone can call `isAnchored()` to verify

---

## Next: Try These Experiments

1. **Submit duplicate event_id** - Watch it get rejected
2. **Modify payload after hashing** - See hash validation fail
3. **Query event history** - Use PostgreSQL to trace entity timeline
4. **Verify Merkle proof** - (API coming soon)

---

*Demo Version: 1.0*
*Last Updated: 2025-12-21*
