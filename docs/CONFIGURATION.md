# Configuration Reference

Every environment variable the sequencer reads, grouped by subsystem. All are
optional unless marked required; defaults are shown where the code defines one.

This file is the authoritative reference; the README carries only the handful
needed to boot a dev instance.

## Core Settings

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

## Database Pool Tuning

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_ACQUIRE_TIMEOUT_MS` | (unset) | Write pool connection acquisition timeout |
| `DB_IDLE_TIMEOUT_SECS` | (unset) | Write pool idle connection timeout |
| `DB_MAX_LIFETIME_SECS` | (unset) | Write pool max connection lifetime |
| `READ_DB_ACQUIRE_TIMEOUT_MS` | (unset) | Read pool connection acquisition timeout |
| `READ_DB_IDLE_TIMEOUT_SECS` | (unset) | Read pool idle connection timeout |
| `READ_DB_MAX_LIFETIME_SECS` | (unset) | Read pool max connection lifetime |

## Database Session Timeouts

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_STATEMENT_TIMEOUT_MS` | (unset) | PostgreSQL `statement_timeout` (ms) |
| `DB_IDLE_IN_TX_TIMEOUT_MS` | (unset) | PostgreSQL `idle_in_transaction_session_timeout` (ms) |
| `DB_LOCK_TIMEOUT_MS` | (unset) | PostgreSQL `lock_timeout` (ms) |

## Cache Settings

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

## Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_MODE` | `required` | `required` or `disabled` |
| `ALLOW_AUTH_DISABLED` | `false` | Set to `true` to explicitly allow `AUTH_MODE=disabled` |
| `BOOTSTRAP_ADMIN_API_KEY` | (unset) | Admin API key for bootstrap/dev |
| `JWT_SECRET` | (unset) | HMAC secret for JWT validation |
| `JWT_ISSUER` | `stateset-sequencer` | Expected JWT issuer claim |
| `JWT_AUDIENCE` | `stateset-api` | Expected JWT audience claim |
| `ADMIN_IP_ALLOWLIST` | (unset) | Comma-separated IPs/CIDRs allowed to access admin + metrics (e.g. `203.0.113.10,10.0.0.0/8`) |

## Client IP and Proxies

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

## Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_PER_MINUTE` | (unset) | Global per-tenant rate limit |
| `RATE_LIMIT_MAX_ENTRIES` | `10000` | Max tracked rate limit entries |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate limit window duration |
| `PUBLIC_AGENT_REGISTRATION_RATE_LIMIT_PER_MINUTE` | (unset) | Per-IP rate limit for public agent registration |
| `PUBLIC_AGENT_REGISTRATION_MAX_ENTRIES` | `10000` | Max tracked public registration rate limit entries |
| `PUBLIC_AGENT_REGISTRATION_WINDOW_SECONDS` | `60` | Public registration rate limit window duration |

## Request Limits

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_BODY_SIZE_BYTES` | `10485760` | Maximum request body size (10MB) |
| `MAX_EVENTS_PER_BATCH` | `1000` | Maximum events per ingest batch |
| `MAX_EVENT_PAYLOAD_SIZE` | `1048576` | Maximum payload size per event (1MB) |

## Payload Encryption

| Variable | Default | Description |
|----------|---------|-------------|
| `PAYLOAD_ENCRYPTION_MODE` | `required` | `disabled`, `optional`, or `required` |
| `PAYLOAD_ENCRYPTION_KEY` | (unset) | Single 32-byte key (hex or base64) |
| `PAYLOAD_ENCRYPTION_KEYS` | (unset) | Comma-separated keyring (current first) |
| `PAYLOAD_ENCRYPTION_KEYS_BY_TENANT` | (unset) | JSON map of tenant-specific keyrings |

## VES Sequencer

| Variable | Default | Description |
|----------|---------|-------------|
| `VES_SEQUENCER_SIGNING_KEY` | (unset) | Ed25519 private key for receipt signing |
| `SCHEMA_VALIDATION_MODE` | `warn` | `disabled`, `warn`, or `strict` |

## On-Chain Anchoring

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

## x402 Payments

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

## Autonomous Settlement

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

## Distributed / High Availability

Several workers must run on exactly one node. Leader election via PostgreSQL
advisory locks enforces that, with automatic failover when the leader dies. A
single node wins instantly, so single-node behaviour is unchanged.

| Variable | Default | Description |
|----------|---------|-------------|
| `WORKER_LEADER_ELECTION` | `true` | Leader-elect the singleton workers (anchoring, x402 batching, settlement) |

## STARK Proof Verification

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

## Server & Runtime

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

## Observability

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

