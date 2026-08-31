# StateSet Sequencer

![Rust](https://img.shields.io/badge/rust-1.90%2B-orange.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![codecov](https://codecov.io/gh/stateset/stateset-sequencer/branch/master/graph/badge.svg)

**Minimum supported Rust version: 1.90**, declared as `rust-version` in
`Cargo.toml` and enforced by a CI job that builds the default feature set on
exactly that toolchain. The floor is set by the `ves-stark-*` crates, which
require 1.90. CI also runs `cargo fmt`, `clippy -D warnings`, the full test
suite against PostgreSQL, `cargo audit` and `cargo deny` on every push.

Verifiable Event Sync (VES) v1.0 service for deterministic event ordering, state projection, cryptographic commitments, and zero-knowledge compliance proofs.

## Overview

The StateSet Sequencer is the **central truth clock** for distributed commerce systems, bridging AI agents with cryptographically verifiable infrastructure. It implements the complete VES v1.0 protocol specification.

### Key Features

- **Deterministic Event Ordering**: Monotonic sequence numbers per (tenant, store) pair
- **Exactly-Once Delivery**: Idempotent event ingestion with event_id and command_id deduplication
- **Cryptographic Commitments**: Merkle trees with domain-separated hashing for audit trails
- **Agent Signatures**: Ed25519 signature verification for event authenticity
- **STARK Compliance Proofs**: Zero-knowledge proofs for regulatory compliance
- **On-Chain Anchoring**: Ethereum L2 commitment anchoring for trustless verification
- **Offline-First**: SQLite outbox pattern for local CLI agents
- **Payload Encryption**: AES-GCM encryption at rest with key rotation support
- **Schema Validation**: JSON Schema validation for event payloads
- **x402 Payments**: Payment intents, nonce-replay protection, Merkle-batched
  settlement, and HTTP `402 Payment Required` gating for metered routes
- **Autonomous Settlement**: Optional worker that settles committed payment
  batches on-chain via the `SetPaymentBatch` contract
- **Distributed / HA**: Multiple nodes may run against one database; singleton
  workers (anchoring, batching, settlement) are leader-elected through
  PostgreSQL advisory locks with automatic failover

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              API Layer (Axum)                               │
│  POST /api/v1/ves/events/ingest  │  GET /api/v1/ves/commitments            │
│  POST /api/v1/ves/validity-proofs │  POST /api/v1/ves/compliance-proofs    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
┌─────────────────────────────────────────────────────────────────────────────┐
│                             Service Layer                                   │
│  Sequencer │ EventStore │ CommitmentEngine │ Projector │ AgentKeyRegistry  │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
┌─────────────────────────────────────────────────────────────────────────────┐
│                      PostgreSQL (Source of Truth)                           │
│  events │ ves_events │ sequence_counters │ batch_commitments │ api_keys    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
           ┌───────────────┐               ┌───────────────┐
           │ STARK Prover  │               │ Ethereum L2   │
           │ (ZK Proofs)   │               │ (Anchoring)   │
           └───────────────┘               └───────────────┘
```

### Data Flow

```
CLI Agent / AI Agent                 Sequencer                     PostgreSQL
       │                                │                              │
       │── POST /ves/events/ingest ────▶│                              │
       │   (signed event envelope)      │                              │
       │                                │── Verify Ed25519 signature ──│
       │                                │── SELECT FOR UPDATE ────────▶│
       │                                │   (atomic sequence assign)   │
       │                                │── INSERT ves_event ─────────▶│
       │                                │                              │
       │◀── IngestReceipt ─────────────│                              │
       │    (sequence #, merkle proof)  │                              │
```

## Quick Start

### Using Docker Compose

```bash
# Start the sequencer and PostgreSQL
docker-compose up -d

# Check health
curl http://localhost:8080/health

# Check readiness (verifies database connectivity)
curl http://localhost:8080/ready

# Example: Get head sequence (with bootstrap admin key)
curl -H "Authorization: ApiKey dev_admin_key" \
  "http://localhost:8080/api/v1/head?tenant_id=<uuid>&store_id=<uuid>"
```

### Local Development

```bash
# Build the project
cargo build

# Set required environment variables
export DATABASE_URL="postgres://sequencer:sequencer@localhost:5433/stateset_sequencer"
export BOOTSTRAP_ADMIN_API_KEY="dev_admin_key"
export ALLOW_INSECURE_LOCAL_DB=true

# Run the server (migrations run automatically)
cargo run

# Or run migrations manually
cargo run --bin stateset-sequencer-admin -- migrate

# Backfill VES state roots (if upgrading from older versions)
cargo run --bin stateset-sequencer-admin -- backfill-ves-state-roots
```

### Cargo features

The default build enables `full`. Notable feature flags:

| Feature | Enables |
|---------|---------|
| `pqc` | Post-quantum crypto (ML-DSA-65, ML-KEM-768) |
| `stark` | STARK validity/compliance proof verification |
| `integration` | Test-only modules that need a live database |

gRPC, OpenTelemetry, L2 anchoring, JSON Schema validation and the SQLite outbox
are **always compiled in** and are not behind feature flags. They were once
listed as flags, but each was an empty feature that gated no code, so turning
one "off" changed nothing about the resulting binary. They were removed rather
than left as no-ops.

**The `stark` feature** depends on the `ves-stark-*` crates in the separate
[`stateset-stark`](https://github.com/stateset/stateset-stark) workspace, expected
at `../stateset-stark`. They are **path dependencies that cargo must resolve even
when the feature is off**, so that checkout must be present to build at all.

To build/test the core sequencer **without** the STARK proof endpoints (e.g. if
you don't have `stateset-stark` checked out alongside this repo, the proof
endpoints are simply not mounted):

```bash
cargo build --no-default-features --features pqc
```

### Upgrading the STARK dependency

`stateset-stark` is a **path dependency on a separate repository**, so its
commits are not captured by this repo's `Cargo.lock` on their own. CI pins it to
an exact commit via the `STARK_REF` variable in `.github/workflows/ci.yml`.

Tracking its default branch instead meant every upstream commit silently
invalidated `Cargo.lock` and turned every `--locked` CI job red, with no change
in this repository. Upgrade deliberately, in a single commit:

```bash
# 1. Move the local checkout to the commit you want
git -C ../stateset-stark checkout <new-sha>

# 2. Re-resolve the ves-stark-* crates
cargo update -p ves-stark-prover -p ves-stark-verifier \
             -p ves-stark-primitives -p ves-stark-batch

# 3. Verify, then commit Cargo.lock and the new STARK_REF together
cargo test --locked --all-targets
```

> **CI note:** because the `ves-stark-*` crates live in a private repo, CI fetches
> `stateset-stark` using a `STARK_REPO_TOKEN` repository secret (a token with read
> access to `stateset/stateset-stark`). Add it under **Settings → Secrets and
> variables → Actions**. The lint/test/coverage jobs build with the core feature
> set (no `stark`) so they don't compile the private crates.

## API Endpoints

### VES Event Ingestion

```bash
POST /api/v1/ves/events/ingest
Authorization: ApiKey <key>
Content-Type: application/json

{
  "events": [
    {
      "event_id": "uuid",
      "tenant_id": "uuid",
      "store_id": "uuid",
      "entity_type": "order",
      "entity_id": "order-123",
      "event_type": "order.created",
      "payload": { "customer_id": "cust-456", "total": 99.99 },
      "base_version": 0,
      "source_agent": "uuid",
      "signature": "base64-encoded-ed25519-signature",
      "created_at": "2025-01-01T00:00:00Z"
    }
  ]
}
```
Note: `events` must contain at least one event.

**Response:**
```json
{
  "receipts": [
    {
      "event_id": "uuid",
      "sequence_number": 42,
      "payload_hash": "sha256-hex",
      "merkle_proof": { ... },
      "sequencer_signature": "base64-encoded"
    }
  ]
}
```

### VES Commitments

```bash
# List commitments
GET /api/v1/ves/commitments?tenant_id=<uuid>&store_id=<uuid>

# Create commitment for sequence range
POST /api/v1/ves/commitments
{
  "tenant_id": "uuid",
  "store_id": "uuid",
  "sequence_start": 1,
  "sequence_end": 100
}

# Anchor commitment on-chain
POST /api/v1/ves/commitments/{batch_id}/anchor
```

### VES Proofs

```bash
# Submit validity proof (batch ZK proof)
POST /api/v1/ves/validity-proofs
{
  "batch_id": "uuid",
  "proof_type": "stark",
  "proof_data": "base64-encoded-proof",
  "public_inputs": { ... }
}

# Submit compliance proof (per-event encrypted proof)
POST /api/v1/ves/compliance-proofs
{
  "event_id": "uuid",
  "proof_type": "stark",
  "encrypted_payload": "base64-encoded",
  "public_inputs": { ... }
}

# Get inclusion proof for an event
GET /api/v1/ves/inclusion-proofs/{event_id}
```

### Agent Key Management

```bash
# Register agent public key
POST /api/v1/agent-keys
{
  "tenant_id": "uuid",
  "agent_id": "uuid",
  "public_key": "base64-encoded-ed25519-public-key",
  "valid_from": "2025-01-01T00:00:00Z",
  "valid_until": "2026-01-01T00:00:00Z"
}

# List agent keys
GET /api/v1/agent-keys?tenant_id=<uuid>&agent_id=<uuid>

# Revoke agent key
DELETE /api/v1/agent-keys/{key_id}
```

### Legacy Endpoints

```bash
# Get events (legacy format)
GET /api/v1/events?tenant_id=<uuid>&store_id=<uuid>&from=0&limit=100

# Get head sequence
GET /api/v1/head?tenant_id=<uuid>&store_id=<uuid>

# Get entity history
GET /api/v1/entities/{entity_type}/{entity_id}?tenant_id=<uuid>&store_id=<uuid>
```

### x402 Payments

```bash
# Submit a payment intent (sequenced atomically with its nonce reservation)
POST /api/v1/x402/payments
curl -X POST http://localhost:8080/api/v1/x402/payments \
  -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
  -d @intent.json

# List / fetch intents
GET  /api/v1/x402/payments
GET  /api/v1/x402/payments/:intent_id
GET  /api/v1/x402/payments/:intent_id/receipt   # Merkle inclusion receipt

# Batches
POST /api/v1/x402/batches                       # create a batch
GET  /api/v1/x402/batches/:batch_id
POST /api/v1/x402/batches/settle                # settle a committed batch
```

A batch is committed atomically: its intents are claimed (`sequenced` →
`batched`), read back in sequence order, hashed into a Merkle root, and the
batch marked committed in one transaction — so a crash cannot strand intents
under an uncommitted batch.

### Metered Routes (HTTP 402)

Routes can be gated behind payment. The bundled example returns
`402 Payment Required` with the payment requirements until a valid intent is
presented:

```bash
GET /api/v1/x402/premium/insights
```

Configure via the `X402_PREMIUM_ROUTE_*` variables below.

### Health & Metrics

```bash
GET /health     # Basic health check
GET /ready      # Readiness check (database connectivity)
GET /metrics    # Prometheus metrics
```

## Supported Event Types

| Domain | Event Types |
|--------|-------------|
| **Orders** | `order.created`, `order.confirmed`, `order.shipped`, `order.delivered`, `order.cancelled` |
| **Inventory** | `inventory.initialized`, `inventory.adjusted`, `inventory.reserved`, `inventory.released` |
| **Products** | `product.created`, `product.updated`, `product.deactivated` |
| **Customers** | `customer.created`, `customer.updated`, `customer.address_added` |
| **Returns** | `return.requested`, `return.approved`, `return.received`, `return.refunded` |

## Configuration

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgres://localhost/stateset_sequencer` | PostgreSQL connection URL. For the bundled `docker-compose.yml`, use `postgres://sequencer:sequencer@localhost:5433/stateset_sequencer` |
| `READ_DATABASE_URL` | (unset) | Optional read replica URL (routes read traffic to a separate pool) |
| `HOST` | `0.0.0.0` | Server bind address |
| `PORT` | `8080` | Server port |
| `MAX_DB_CONNECTIONS` | `10` | Write pool max connections |
| `MIN_DB_CONNECTIONS` | `0` | Write pool minimum idle connections |
| `READ_MAX_DB_CONNECTIONS` | `MAX_DB_CONNECTIONS` | Read pool max connections (if `READ_DATABASE_URL` set) |
| `READ_MIN_DB_CONNECTIONS` | `0` | Read pool minimum idle connections |
| `DB_APPLICATION_NAME` | `stateset-sequencer` | PostgreSQL `application_name` for write pool |
| `READ_DB_APPLICATION_NAME` | `${DB_APPLICATION_NAME}-read` | PostgreSQL `application_name` for read pool |
| `DB_MIGRATE_ON_STARTUP` | `true` | Auto-run SQL migrations on startup |
| `PUBLIC_AGENT_REGISTRATION_ENABLED` | `false` | Enable public agent self-registration |
| `TRUST_PROXY_HEADERS` | `false` | Trust `X-Forwarded-For` / `Forwarded` / `X-Real-IP` when extracting client IPs (only enable behind a trusted proxy/LB) |

### Database Pool Tuning

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_ACQUIRE_TIMEOUT_MS` | (unset) | Write pool connection acquisition timeout |
| `DB_IDLE_TIMEOUT_SECS` | (unset) | Write pool idle connection timeout |
| `DB_MAX_LIFETIME_SECS` | (unset) | Write pool max connection lifetime |
| `READ_DB_ACQUIRE_TIMEOUT_MS` | (unset) | Read pool connection acquisition timeout |
| `READ_DB_IDLE_TIMEOUT_SECS` | (unset) | Read pool idle connection timeout |
| `READ_DB_MAX_LIFETIME_SECS` | (unset) | Read pool max connection lifetime |

### Database Session Timeouts

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_STATEMENT_TIMEOUT_MS` | (unset) | PostgreSQL `statement_timeout` (ms) |
| `DB_IDLE_IN_TX_TIMEOUT_MS` | (unset) | PostgreSQL `idle_in_transaction_session_timeout` (ms) |
| `DB_LOCK_TIMEOUT_MS` | (unset) | PostgreSQL `lock_timeout` (ms) |

### Cache Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `CACHE_COMMITMENT_MAX` | `1000` | Max legacy commitment cache entries |
| `CACHE_COMMITMENT_TTL_SECS` | `300` | Legacy commitment cache TTL (seconds) |
| `CACHE_PROOF_MAX` | `5000` | Max legacy proof cache entries |
| `CACHE_PROOF_TTL_SECS` | `600` | Legacy proof cache TTL (seconds) |
| `CACHE_VES_COMMITMENT_MAX` | `CACHE_COMMITMENT_MAX` | Max VES commitment cache entries |
| `CACHE_VES_COMMITMENT_TTL_SECS` | `CACHE_COMMITMENT_TTL_SECS` | VES commitment cache TTL (seconds) |
| `CACHE_VES_PROOF_MAX` | `CACHE_PROOF_MAX` | Max VES proof cache entries |
| `CACHE_VES_PROOF_TTL_SECS` | `CACHE_PROOF_TTL_SECS` | VES proof cache TTL (seconds) |
| `CACHE_AGENT_KEY_MAX` | `1000` | Max agent key cache entries |
| `CACHE_AGENT_KEY_TTL_SECS` | `3600` | Agent key cache TTL (seconds) |
| `CACHE_SCHEMA_MAX` | `1000` | Max schema cache entries |
| `CACHE_SCHEMA_TTL_SECS` | `600` | Schema cache TTL (seconds) |

### Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_MODE` | `required` | `required` or `disabled` |
| `ALLOW_AUTH_DISABLED` | `false` | Set to `true` to explicitly allow `AUTH_MODE=disabled` |
| `BOOTSTRAP_ADMIN_API_KEY` | (unset) | Admin API key for bootstrap/dev |
| `JWT_SECRET` | (unset) | HMAC secret for JWT validation |
| `JWT_ISSUER` | `stateset-sequencer` | Expected JWT issuer claim |
| `JWT_AUDIENCE` | `stateset-api` | Expected JWT audience claim |
| `ADMIN_IP_ALLOWLIST` | (unset) | Comma-separated IPs/CIDRs allowed to access admin + metrics (e.g. `203.0.113.10,10.0.0.0/8`) |

### Client IP and Proxies

| Variable | Default | Description |
|----------|---------|-------------|
| `TRUST_PROXY_HEADERS` | `false` | Honour `x-forwarded-for` / `x-real-ip` / `forwarded` when determining the client IP |
| `TRUST_PROXY_ALLOWLIST` | RFC1918 + loopback + link-local | Comma-separated IPs/CIDRs whose forwarded headers are believed |

The client IP decides three things: the `ADMIN_IP_ALLOWLIST` check, the
public-registration rate-limit key, and the IP recorded in audit logs.

**Enable `TRUST_PROXY_HEADERS` only when this service is genuinely behind a
proxy you control**, and make sure `TRUST_PROXY_ALLOWLIST` covers that proxy
and nothing else. Headers are consulted only when the socket peer is itself
inside a trusted network, so an arbitrary host can never assert its own
address. Within `x-forwarded-for` the chain is read **from the right**, past
any hops that are themselves trusted proxies, because the header grows
left-to-right — each proxy appends the address it received from, so only the
rightmost entries are attested by infrastructure you trust and the leftmost is
merely what the client claimed.

Behind an ingress you generally must enable this: without it every request
presents as the ingress address, which collapses per-IP rate limiting into one
global bucket and makes an IP allowlist meaningless.

### Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_PER_MINUTE` | (unset) | Global per-tenant rate limit |
| `RATE_LIMIT_MAX_ENTRIES` | `10000` | Max tracked rate limit entries |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate limit window duration |
| `PUBLIC_AGENT_REGISTRATION_RATE_LIMIT_PER_MINUTE` | (unset) | Per-IP rate limit for public agent registration |
| `PUBLIC_AGENT_REGISTRATION_MAX_ENTRIES` | `10000` | Max tracked public registration rate limit entries |
| `PUBLIC_AGENT_REGISTRATION_WINDOW_SECONDS` | `60` | Public registration rate limit window duration |

### Request Limits

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_BODY_SIZE_BYTES` | `10485760` | Maximum request body size (10MB) |
| `MAX_EVENTS_PER_BATCH` | `1000` | Maximum events per ingest batch |
| `MAX_EVENT_PAYLOAD_SIZE` | `1048576` | Maximum payload size per event (1MB) |

### Payload Encryption

| Variable | Default | Description |
|----------|---------|-------------|
| `PAYLOAD_ENCRYPTION_MODE` | `required` | `disabled`, `optional`, or `required` |
| `PAYLOAD_ENCRYPTION_KEY` | (unset) | Single 32-byte key (hex or base64) |
| `PAYLOAD_ENCRYPTION_KEYS` | (unset) | Comma-separated keyring (current first) |
| `PAYLOAD_ENCRYPTION_KEYS_BY_TENANT` | (unset) | JSON map of tenant-specific keyrings |

### VES Sequencer

| Variable | Default | Description |
|----------|---------|-------------|
| `VES_SEQUENCER_SIGNING_KEY` | (unset) | Ed25519 private key for receipt signing |
| `SCHEMA_VALIDATION_MODE` | `warn` | `disabled`, `warn`, or `strict` |

### On-Chain Anchoring

| Variable | Default | Description |
|----------|---------|-------------|
| `L2_RPC_URL` | (unset) | Ethereum L2 RPC endpoint |
| `SET_REGISTRY_ADDRESS` | (unset) | StateSet registry contract address |
| `SEQUENCER_PRIVATE_KEY` | (unset) | Private key for anchor transactions |
| `L2_CHAIN_ID` | (unset) | L2 chain ID |
| `ANCHOR_INTERVAL_SECS` | | How often the anchor worker runs |
| `ANCHOR_BATCH_THRESHOLD` | | Commitments to accumulate before anchoring |
| `ANCHOR_FINALITY_CONFIRMATIONS` | | Confirmations before an anchor is final |
| `ANCHOR_FINALITY_POLL_SECS` | | Poll interval while awaiting finality |
| `ANCHOR_RECONCILE_SECS` | | Interval for reconciling anchor state |

### x402 Payments

| Variable | Default | Description |
|----------|---------|-------------|
| `X402_BATCH_AUTO_COMMIT` | `true` | Batch worker claims and commits batches atomically. `false` disables the worker's batching entirely (batching is then done via `POST /api/v1/x402/batches`) |
| `X402_BATCH_INTERVAL_SECS` | | Batch worker tick interval |
| `X402_BATCH_MIN_SIZE` | | Minimum intents before committing a batch |
| `X402_BATCH_MAX_SIZE` | `100` | Maximum intents per batch (clamped to the hard cap of 1000) |
| `X402_BATCH_MAX_WAIT_SECS` | | Commit a partial batch after this long |
| `X402_BATCH_NETWORKS` | | Networks the batch worker services |

Metered-route (HTTP 402) settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `X402_PREMIUM_ROUTE_PRICE` | (unset) | Price required for the premium route; unset disables gating |
| `X402_PREMIUM_ROUTE_ASSET` | | Asset the price is denominated in |
| `X402_PREMIUM_ROUTE_NETWORK` | | Network the payment must settle on |
| `X402_PREMIUM_ROUTE_PAY_TO` | | Recipient address |
| `X402_PREMIUM_ROUTE_DESCRIPTION` | | Human-readable description in the 402 response |

### Autonomous Settlement

Settles committed payment batches on-chain. The worker starts **only** when all
three required variables are set, and is leader-elected so exactly one node
settles.

| Variable | Default | Description |
|----------|---------|-------------|
| `SETTLEMENT_RPC_URL` | (unset) | **Required.** RPC endpoint for the settlement chain |
| `SET_PAYMENT_BATCH_ADDRESS` | (unset) | **Required.** `SetPaymentBatch` contract address |
| `SETTLER_PRIVATE_KEY` | (unset) | **Required.** Settler wallet key; must be an authorized sequencer |
| `SETTLEMENT_CHAIN_ID` | `84532001` | Settlement chain ID (defaults to Set Chain) |
| `SETTLEMENT_INTERVAL_SECS` | | Settlement worker tick interval |
| `SETTLEMENT_BATCH_THRESHOLD` | | Batches to accumulate before settling |

### Distributed / High Availability

Several workers must run on exactly one node. Leader election via PostgreSQL
advisory locks enforces that, with automatic failover when the leader dies. A
single node wins instantly, so single-node behaviour is unchanged.

| Variable | Default | Description |
|----------|---------|-------------|
| `WORKER_LEADER_ELECTION` | `true` | Leader-elect the singleton workers (anchoring, x402 batching, settlement) |

### STARK Proof Verification

| Variable | Default | Description |
|----------|---------|-------------|
| `VES_STARK_VERIFY_ON_SUBMIT` | `true` | Verify STARK proofs at submission time |
| `VES_STARK_ALLOW_UNVERIFIED_AMOUNT_BINDING` | `false` | Accept prover-attested amounts when the sequencer cannot re-extract the amount from the payload |

> `VES_STARK_ALLOW_UNVERIFIED_AMOUNT_BINDING=1` **weakens proof soundness to
> prover honesty.** The sequencer normally re-derives the amount from the
> payload it stored at ingest and rejects proofs committing to a different one,
> which is what stops a large payment being proved as a small one to duck a
> reporting threshold. Encrypted payloads cannot be re-extracted (the plain
> hash is salted), so this flag is the only way to accept proofs over them.

### Server & Runtime

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | | Bind address for the HTTP server |
| `GRPC_PORT` | | gRPC listen port |
| `GRPC_DISABLED` | `false` | Disable the gRPC server |
| `REQUEST_TIMEOUT_SECS` | `30` | HTTP request timeout |
| `GRPC_REQUEST_TIMEOUT_SECS` | `30` | gRPC request timeout |
| `ENVIRONMENT` / `SEQUENCER_ENV` | | Deployment environment label; `production` tightens secret-strength checks |
| `ALLOW_INSECURE_LOCAL_DB` | `false` | Permit a non-TLS database connection to a local address |
| `DB_STARTUP_MAX_RETRIES` | | Connection attempts at startup (for Cloud SQL Proxy sidecars) |
| `DB_STARTUP_RETRY_DELAY_SECS` | | Delay between startup connection attempts |
| `AUDIT_LOG_ENABLED` | | Enable the audit log |
| `VES_STRICT_FORMAT_VALIDATION` | | Strict VES envelope format validation |

### Observability

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Log level filter |
| `LOG_LEVEL` | `info` | Log level when `RUST_LOG` is unset |
| `LOG_FORMAT` | (unset) | Set to `json` for JSON logging |
| `LOG_JSON` | | Force JSON log output |
| `LOG_CONSOLE` | | Force human-readable console output |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | (unset) | OpenTelemetry OTLP endpoint |
| `OTEL_SERVICE_NAME` | | Service name reported in traces |
| `OTEL_SERVICE_VERSION` | | Service version reported in traces |
| `OTEL_SAMPLE_RATE` | | Trace sampling rate |
| `CORS_ALLOW_ORIGINS` | (unset) | CORS origins (`*` or comma-separated) |

`GET /metrics` returns Prometheus text exposition and requires an **admin**
credential. It is additionally subject to `ADMIN_IP_ALLOWLIST` when that is set.

## Project Structure

```
stateset-sequencer/
├── src/
│   ├── main.rs                 # Binary entry point
│   ├── lib.rs                  # Library exports
│   ├── server.rs               # HTTP server bootstrap
│   ├── anchor.rs               # On-chain anchoring service
│   ├── settlement.rs           # On-chain x402 batch settlement
│   ├── migrations.rs           # Migration runner
│   ├── api/                    # REST API layer
│   │   ├── mod.rs              # Router configuration
│   │   ├── types.rs            # Request/response types
│   │   ├── auth_helpers.rs     # Auth extraction helpers
│   │   └── handlers/           # Endpoint handlers
│   │       ├── ingest.rs       # Event ingestion
│   │       ├── events.rs       # Event queries
│   │       ├── commitments.rs  # Batch commitments
│   │       ├── agent_keys.rs   # Agent key management
│   │       ├── schemas.rs      # Schema registry
│   │       ├── x402.rs         # x402 payment intents & batches
│   │       └── ves/            # VES v1.0 endpoints
│   │   └── middleware/
│   │       └── payment_required.rs  # HTTP 402 gating for metered routes
│   ├── auth/                   # Authentication
│   │   ├── api_key.rs          # API key validation & storage
│   │   ├── jwt.rs              # JWT validation
│   │   ├── middleware.rs       # Auth middleware & rate limiting
│   │   └── agent_keys.rs       # Agent key types
│   ├── crypto/                 # Cryptographic utilities
│   │   ├── hash.rs             # Domain-separated SHA-256
│   │   ├── signing.rs          # Ed25519 signatures
│   │   └── encrypt.rs          # HPKE encryption
│   ├── domain/                 # Core domain types
│   │   ├── types.rs            # TenantId, StoreId, AgentId, Hash256
│   │   ├── event.rs            # EventEnvelope, SequencedEvent
│   │   ├── ves_event.rs        # VES v1.0 event types
│   │   ├── commitment.rs       # BatchCommitment, MerkleProof
│   │   ├── ves_commitment.rs   # VES commitment types
│   │   ├── ves_validity.rs     # Validity proof types
│   │   ├── ves_compliance.rs   # Compliance proof types
│   │   └── schema.rs           # Schema definitions
│   ├── infra/                  # Infrastructure implementations
│   │   ├── traits.rs           # Service trait definitions
│   │   ├── error.rs            # Error types
│   │   ├── net.rs              # Trusted-proxy client IP resolution
│   │   ├── x402_batch_worker.rs     # Payment batching worker
│   │   ├── settlement_worker.rs     # On-chain settlement worker
│   │   ├── postgres/           # PostgreSQL implementations
│   │   │   ├── sequencer.rs    # Atomic sequence assignment
│   │   │   ├── ves_sequencer.rs # VES v1.0 sequencer
│   │   │   ├── event_store.rs  # Event storage
│   │   │   ├── agent_keys.rs   # Agent key registry
│   │   │   └── schema_store.rs # Schema storage
│   │   ├── sqlite/             # SQLite implementations
│   │   │   └── outbox.rs       # Local agent outbox
│   │   ├── commitment.rs       # Merkle tree engine
│   │   ├── ves_commitment.rs   # VES commitment engine
│   │   ├── ves_validity.rs     # Validity proof storage
│   │   ├── ves_compliance.rs   # Compliance proof storage
│   │   ├── payload_encryption.rs # AES-GCM encryption
│   │   └── schema_validation.rs  # JSON Schema validation
│   ├── projection/             # Event projection
│   │   ├── runner.rs           # Projection runner
│   │   └── handlers.rs         # Domain-specific handlers
│   ├── grpc/                   # gRPC service (optional)
│   ├── proto/                  # Protocol buffer definitions
│   └── metrics/                # Observability
├── migrations/
│   ├── postgres/               # PostgreSQL migrations (9 files)
│   │   ├── 001_production_postgres.sql
│   │   ├── 002_ves_v1_tables.sql
│   │   ├── 003_constraints.sql
│   │   ├── 004_ves_validity_proofs.sql
│   │   ├── 005_ves_compliance_proofs.sql
│   │   ├── 006_key_rotation_policies.sql
│   │   ├── 007_encryption_groups.sql
│   │   ├── 008_command_dedupe.sql
│   │   └── 009_api_keys.sql
│   └── sqlite/                 # SQLite migrations (local agents)
├── tests/                      # Integration tests
├── benches/                    # Performance benchmarks
├── contracts/                  # Smart contracts (Ethereum L2)
├── schemas/                    # Event schema definitions
├── docs/                       # Additional documentation
├── Dockerfile
├── docker-compose.yml
└── Cargo.toml
```

## Security Features

| Feature | Implementation |
|---------|----------------|
| **API Key Hashing** | SHA-256 (never stored in plaintext) |
| **Agent Signatures** | Ed25519 with key rotation support |
| **Payload Encryption** | AES-256-GCM with per-tenant keyrings |
| **Rate Limiting** | Per-tenant with bounded memory (LRU eviction) |
| **Request Limits** | Configurable body size and batch limits |
| **STARK Proofs** | Zero-knowledge compliance verification |
| **Amount Binding** | Compliance proofs are rejected unless the committed amount matches the amount re-derived from the stored payload |
| **Client IP Resolution** | Forwarded headers honoured only from trusted proxies, and read from the right of the chain (see [Client IP and Proxies](#client-ip-and-proxies)) |
| **Admin IP Allowlist** | Optional IP/CIDR restriction on admin and metrics routes, layered on top of admin authentication |
| **Replay Protection** | Event/command ID deduplication and x402 nonce reservation, both inside the sequencing transaction |

## Cryptographic Guarantees

1. **Gap-Free Sequences**: No missing sequence numbers within a stream
2. **Linearizable Ordering**: Total ordering via PostgreSQL `SELECT FOR UPDATE`
3. **Verifiable History**: Merkle proofs for event inclusion verification
4. **Domain Separation**: All hashes include domain separators per VES spec
5. **Immutable Log**: Append-only event storage with no mutations

## Testing

```bash
# Unit tests and any integration test that needs no database
cargo test

# Everything, including the database-backed tests
export DATABASE_URL=postgres://user:pass@localhost:5432/stateset_sequencer
cargo test --tests -- --include-ignored

# Run with output
cargo test -- --nocapture

# Benchmarks (Criterion; see docs/PERFORMANCE_BENCHMARKS.md for recorded results)
cargo bench
```

Database-backed tests **skip** when `DATABASE_URL` is unset, and **fail** when
it is set but the database cannot be reached — a test is never allowed to pass
merely because its database was missing. Set `SEQUENCER_REQUIRE_DB_TESTS=1` (as
CI does) to turn a missing `DATABASE_URL` into a failure too, so a
misconfigured environment cannot be mistaken for a green run.

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | (unset) | Database for the database-backed tests; unset skips them |
| `SEQUENCER_REQUIRE_DB_TESTS` | `false` | Fail rather than skip when `DATABASE_URL` is absent |

## Admin CLI

A second binary, `stateset-sequencer-admin`, handles operational tasks. Every
command takes `--database-url` (defaulting to `DATABASE_URL`).

```bash
cargo run --bin stateset-sequencer-admin -- <command> [options]
cargo run --bin stateset-sequencer-admin -- help <command>   # per-command help
```

| Command | Purpose |
|---------|---------|
| `migrate` | Run database migrations |
| `verify-proof` | Verify a Merkle inclusion proof |
| `export-events` | Export events to a JSON/NDJSON file |
| `rotate-keys` | Rotate agent signing keys |
| `list-agent-keys` | List agent keys for a tenant |
| `reencrypt-events` | Re-encrypt event payloads under a new key |
| `reencrypt-ves-validity-proofs` | Re-encrypt stored validity proofs |
| `reencrypt-ves-compliance-proofs` | Re-encrypt stored compliance proofs |
| `backfill-ves-state-roots` | Backfill VES state roots (upgrades from older versions) |
| `ves-commit-and-anchor` | Create a VES commitment and anchor it on-chain |
| `commands` | List available commands |

```bash
# Run migrations
cargo run --bin stateset-sequencer-admin -- migrate

# Backfill VES state roots
cargo run --bin stateset-sequencer-admin -- backfill-ves-state-roots

# Preview changes without writing
cargo run --bin stateset-sequencer-admin -- backfill-ves-state-roots --dry-run
```

## License

MIT
