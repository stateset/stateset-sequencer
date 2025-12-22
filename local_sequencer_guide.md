# Local Sequencer Guide

This guide covers running the StateSet Sequencer locally for development and testing.

## Overview

The StateSet Sequencer provides:
- **Event ingestion** with global sequence ordering
- **Merkle commitments** for cryptographic verification
- **Inclusion proofs** for audit trails
- **Entity history** queries

## Quick Start

### 1. Start the Sequencer

```bash
docker-compose up -d
```

This starts:
- **PostgreSQL** on port 5433
- **Sequencer** on port 8080

Verify it's running:

```bash
curl http://localhost:8080/health
```

### 2. Initialize CLI Sync

From the CLI directory (`/home/dom/stateset-icommerce/cli`):

```bash
node bin/stateset-sync.js init \
  --sequencer-url http://localhost:8080 \
  --tenant-id 00000000-0000-0000-0000-000000000001 \
  --store-id 00000000-0000-0000-0000-000000000001 \
  --db ./store.db
```

### 3. Push Events

```bash
node bin/stateset-sync.js push --db ./store.db
```

### 4. Check Status

```bash
node bin/stateset-sync.js status --db ./store.db
```

## API Reference

### Health & Readiness

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/ready` | GET | Readiness check (verifies DB) |

### Events

#### Ingest Events

```bash
curl -X POST http://localhost:8080/api/v1/events/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "da557926-5c7b-422e-8222-c1a5db1a91d7",
    "events": [{
      "event_id": "550e8400-e29b-41d4-a716-446655440000",
      "tenant_id": "00000000-0000-0000-0000-000000000001",
      "store_id": "00000000-0000-0000-0000-000000000001",
      "entity_type": "order",
      "entity_id": "order-123",
      "event_type": "OrderCreated",
      "payload": {"orderId": "order-123", "total": 99.99},
      "payload_hash": "abc123...",
      "created_at": "2025-01-01T00:00:00Z",
      "source_agent": "da557926-5c7b-422e-8222-c1a5db1a91d7"
    }]
  }'
```

Response:
```json
{
  "batch_id": "6d4e8ba1-98b7-40fd-bd17-3a40ab16e88f",
  "events_accepted": 1,
  "events_rejected": 0,
  "assigned_sequence_start": 1,
  "assigned_sequence_end": 1,
  "head_sequence": 1
}
```

#### List Events

```bash
curl "http://localhost:8080/api/v1/events?tenant_id=00000000-0000-0000-0000-000000000001&store_id=00000000-0000-0000-0000-000000000001&from=0&limit=100"
```

#### Get Head Sequence

```bash
curl "http://localhost:8080/api/v1/head?tenant_id=00000000-0000-0000-0000-000000000001&store_id=00000000-0000-0000-0000-000000000001"
```

#### Get Entity History

```bash
curl "http://localhost:8080/api/v1/entities/order/order-123?tenant_id=00000000-0000-0000-0000-000000000001&store_id=00000000-0000-0000-0000-000000000001"
```

### Commitments

#### Create Commitment

Creates a Merkle commitment for a range of sequenced events.

```bash
curl -X POST http://localhost:8080/api/v1/commitments \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "00000000-0000-0000-0000-000000000001",
    "store_id": "00000000-0000-0000-0000-000000000001",
    "sequence_start": 1,
    "sequence_end": 10
  }'
```

Response:
```json
{
  "batch_id": "d982e688-bc8e-4cb3-ba26-b7777a98c526",
  "tenant_id": "00000000-0000-0000-0000-000000000001",
  "store_id": "00000000-0000-0000-0000-000000000001",
  "prev_state_root": "0000000000000000000000000000000000000000000000000000000000000000",
  "new_state_root": "9cd6bbc0a23986dd53c47c3585d2e8a40c448de81bc7d74e31495890c6112652",
  "events_root": "ce694bac1d476fec1445505848e9d16904547899f5a7edb9a8ee1f89c9b40313",
  "event_count": 10,
  "sequence_start": 1,
  "sequence_end": 10,
  "committed_at": "2025-01-01T00:00:00Z"
}
```

#### List Commitments

```bash
curl "http://localhost:8080/api/v1/commitments?tenant_id=00000000-0000-0000-0000-000000000001&store_id=00000000-0000-0000-0000-000000000001"
```

#### Get Commitment

```bash
curl "http://localhost:8080/api/v1/commitments/d982e688-bc8e-4cb3-ba26-b7777a98c526"
```

### Proofs

#### Get Inclusion Proof

Get a Merkle proof that an event is included in a commitment.

```bash
curl "http://localhost:8080/api/v1/proofs/5?tenant_id=00000000-0000-0000-0000-000000000001&store_id=00000000-0000-0000-0000-000000000001&batch_id=d982e688-bc8e-4cb3-ba26-b7777a98c526"
```

Response:
```json
{
  "sequence_number": 5,
  "batch_id": "d982e688-bc8e-4cb3-ba26-b7777a98c526",
  "events_root": "ce694bac1d476fec1445505848e9d16904547899f5a7edb9a8ee1f89c9b40313",
  "leaf_hash": "019a566348525aee5a742aeaaf619914891652f76cf094040c6b95eb435134ea",
  "leaf_index": 4,
  "proof_path": [
    "2d3142a28511720823df9d1f3aa5b46795c4a050db76759e54f53ec4df757393",
    "6aa004d3714c7a0b7853149ba164f72b04174e62160b665c71a98efbd250a904"
  ],
  "directions": [false, true]
}
```

#### Verify Proof

Verify a Merkle inclusion proof.

```bash
curl -X POST http://localhost:8080/api/v1/proofs/verify \
  -H "Content-Type: application/json" \
  -d '{
    "leaf_hash": "019a566348525aee5a742aeaaf619914891652f76cf094040c6b95eb435134ea",
    "events_root": "ce694bac1d476fec1445505848e9d16904547899f5a7edb9a8ee1f89c9b40313",
    "proof_path": [
      "2d3142a28511720823df9d1f3aa5b46795c4a050db76759e54f53ec4df757393",
      "6aa004d3714c7a0b7853149ba164f72b04174e62160b665c71a98efbd250a904"
    ],
    "leaf_index": 4
  }'
```

Response:
```json
{
  "valid": true,
  "leaf_hash": "019a566348525aee...",
  "events_root": "ce694bac1d476fec..."
}
```

## CLI Sync Commands

### Initialize Sync

```bash
stateset-sync init \
  --sequencer-url http://localhost:8080 \
  --tenant-id <uuid> \
  --store-id <uuid> \
  --db ./store.db
```

### Check Status

```bash
stateset-sync status --db ./store.db
```

### Push Events

```bash
stateset-sync push --db ./store.db
```

### View History

```bash
stateset-sync history --db ./store.db
```

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   CLI Agent     │     │   Sequencer     │     │   PostgreSQL    │
│   (SQLite)      │────▶│   (Rust/Axum)   │────▶│   (Events)      │
│                 │     │                 │     │                 │
│  - Outbox       │     │  - Ingest       │     │  - events       │
│  - Sync State   │     │  - Sequence     │     │  - commitments  │
│  - Pulled Events│     │  - Commit       │     │  - entity_ver.  │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

### Event Flow

1. **Local Creation**: Events created locally, stored in SQLite outbox
2. **Push to Sequencer**: CLI pushes pending events via REST API
3. **Sequencing**: Sequencer assigns global sequence numbers
4. **Commitment**: Batch of events committed with Merkle root
5. **Proof**: Any event can be proven against the commitment

### Merkle Tree Structure

```
                    Root (events_root)
                   /                  \
              Hash01                  Hash23
             /      \                /      \
         Hash0    Hash1          Hash2    Hash3
           |        |              |        |
        Event1   Event2        Event3   Event4
```

## Development

### Rebuild Sequencer

```bash
docker-compose build sequencer
docker-compose up -d
```

### View Logs

```bash
docker-compose logs -f sequencer
```

### Stop Services

```bash
docker-compose down
```

### Reset Database

```bash
docker-compose down -v
docker-compose up -d
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgres://localhost/stateset_sequencer` | PostgreSQL connection |
| `PORT` | `8080` | HTTP server port |
| `HOST` | `0.0.0.0` | HTTP server host |
| `MAX_DB_CONNECTIONS` | `10` | Connection pool size |

### Docker Compose Ports

| Service | Internal | External |
|---------|----------|----------|
| PostgreSQL | 5432 | 5433 |
| Sequencer | 8080 | 8080 |

## Troubleshooting

### Port Already in Use

If port 5432 is in use, the docker-compose maps PostgreSQL to 5433 externally.

### Events Not Syncing

1. Check sync status: `stateset-sync status --db ./store.db`
2. Verify sequencer health: `curl http://localhost:8080/health`
3. Check for pending events: `stateset-sync history --db ./store.db`

### Commitment Creation Fails

Ensure events exist in the specified sequence range:

```bash
curl "http://localhost:8080/api/v1/events?tenant_id=<uuid>&store_id=<uuid>&from=0&limit=100"
```

### Proof Verification Fails

- Ensure `leaf_hash` matches the event's `payload_hash`
- Verify `events_root` matches the commitment's root
- Check `leaf_index` is correct (0-indexed within batch)
