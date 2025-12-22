# Security Guide

This document covers security best practices for deploying and operating the StateSet Sequencer.

## Threat Model

### Assets to Protect

1. **Event Data**: Business-critical event payloads
2. **Agent Private Keys**: Ed25519 signing keys
3. **Sequencer Private Key**: Ethereum transaction signing
4. **Database Credentials**: PostgreSQL access
5. **Merkle Roots**: Cryptographic commitments

### Threat Actors

| Actor | Capability | Goal |
|-------|------------|------|
| External Attacker | Network access | Data theft, service disruption |
| Malicious Agent | Valid credentials | Forge events, corrupt data |
| Insider | System access | Data exfiltration |
| Compromised Dependency | Code execution | Supply chain attack |

### Attack Vectors

1. **Network**: MITM, eavesdropping, replay attacks
2. **Application**: Injection, authentication bypass
3. **Cryptographic**: Key compromise, weak algorithms
4. **Infrastructure**: Container escape, privilege escalation

## Cryptographic Security

### Algorithm Choices

| Purpose | Algorithm | Key Size | Notes |
|---------|-----------|----------|-------|
| Agent Signing | Ed25519 | 256-bit | Fast, secure, deterministic |
| Hashing | SHA-256 | 256-bit | Domain-separated |
| Payload Encryption | AES-256-GCM | 256-bit | AEAD, nonce-misuse resistant |
| Key Exchange | X25519 | 256-bit | For HPKE |

### Encryption-at-Rest (Legacy `events` Table)

The legacy `events` table stores payloads as `payload_encrypted` bytes. Configure encryption-at-rest via:

- `PAYLOAD_ENCRYPTION_MODE=required|optional|disabled` (recommend `required` in production)
- `PAYLOAD_ENCRYPTION_KEYS` (comma-separated keyring; current key first; 32-byte keys in hex or base64)
- `PAYLOAD_ENCRYPTION_KEY` (single-key fallback; 32 bytes, hex or base64)
- `PAYLOAD_ENCRYPTION_KEYS_BY_TENANT` (optional JSON overrides per tenant)

Use a secrets manager (KMS/Vault) to provision and rotate the key; do not commit it to source control.

#### Key Rotation + Backfill

If your database contains legacy plaintext rows (e.g., from `PAYLOAD_ENCRYPTION_MODE=disabled`) or you are rotating keys, run a backfill before switching to `PAYLOAD_ENCRYPTION_MODE=required`:

```bash
# Put the new key first, keep old key(s) for decryption during migration
export PAYLOAD_ENCRYPTION_KEYS="0x<new>,0x<old>"

# Backfill tool always decrypts in optional mode
cargo run --bin stateset-sequencer-admin -- reencrypt-events --dry-run
cargo run --bin stateset-sequencer-admin -- reencrypt-events

# After backfill completes, enforce encryption-at-rest reads
export PAYLOAD_ENCRYPTION_MODE="required"
```

### Encryption-at-Rest (VES Validity Proofs)

If you use VES validity proofs, the `ves_validity_proofs.proof` column is also stored encrypted at rest using the same keyring and AEAD framing (`SSE1` + AES-256-GCM with context-bound AAD).

Key rotation/backfill uses the same pattern as events:

```bash
export PAYLOAD_ENCRYPTION_KEYS="0x<new>,0x<old>"
cargo run --bin stateset-sequencer-admin -- reencrypt-ves-validity-proofs --dry-run
cargo run --bin stateset-sequencer-admin -- reencrypt-ves-validity-proofs
```

### Domain Separation

All hash operations use domain separators to prevent cross-protocol attacks:

```rust
// Event signing hash
"VES_EVENTSIG_V1" || event_data

// Merkle leaf
"VES_LEAF_V1" || payload_hash

// Merkle node
"VES_NODE_V1" || left || right

// Receipt hash
"VES_RECEIPT_V1" || receipt_data
```

### Key Derivation

Never use raw keys directly. Always derive purpose-specific keys:

```rust
// Example KDF usage
let derived = HKDF::derive(
    master_key,
    salt,
    b"stateset-sequencer-v1-encryption",
    32
);
```

## Agent Key Management

### Key Generation

Generate keys using cryptographically secure random number generators:

```javascript
// Node.js - Use @noble/ed25519
import * as ed from '@noble/ed25519';

// Generate keypair
const privateKey = ed.utils.randomPrivateKey();
const publicKey = await ed.getPublicKeyAsync(privateKey);

// Store private key securely (e.g., encrypted at rest)
```

```rust
// Rust - Use ed25519-dalek with OsRng
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

let signing_key = SigningKey::generate(&mut OsRng);
```

### Key Storage

**DO:**
- Store private keys in hardware security modules (HSM)
- Use encrypted key storage (AWS KMS, HashiCorp Vault)
- Implement key access logging
- Use environment variables or secrets managers

**DON'T:**
- Hardcode keys in source code
- Store keys in plaintext files
- Log key material
- Share keys between environments

### Key Rotation

Implement regular key rotation:

```javascript
// Register new key before rotating
await client.registerAgentKey({
  tenantId: tenant,
  agentId: agent,
  keyId: currentKeyId + 1,  // Increment key ID
  publicKey: newPublicKey,
  validFrom: new Date(),
});

// Grace period: both keys valid
// After grace period, revoke old key
```

Recommended rotation schedule:
- Agent keys: Every 90 days
- Sequencer key: Every 180 days
- Emergency rotation: Immediately on suspected compromise

### Key Revocation

Revoke compromised keys immediately:

```bash
# Mark key as revoked
curl -X POST https://sequencer.example.com/api/v1/agents/keys/revoke \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{
    "tenantId": "...",
    "agentId": "...",
    "keyId": 1,
    "reason": "suspected_compromise"
  }'
```

After revocation:
- Events signed with revoked key are rejected
- Audit log entry created
- Alert triggered to security team

## Authentication & Authorization

### API Authentication

Support multiple authentication methods:

```rust
// API Key authentication
Authorization: Bearer sk_live_xxxxx

// JWT authentication
Authorization: Bearer eyJhbGciOiJFZDI1NTE5...
```

### JWT Configuration

```rust
// JWT claims structure
{
  "sub": "agent-uuid",           // Agent ID
  "tenant": "tenant-uuid",       // Tenant ID
  "iat": 1705312200,             // Issued at
  "exp": 1705315800,             // Expires (1 hour)
  "scope": ["events:write", "events:read"]
}
```

### Role-Based Access Control

| Role | Permissions |
|------|-------------|
| `agent` | `events:write`, `events:read` |
| `reader` | `events:read`, `commitments:read` |
| `admin` | `*` (all permissions) |
| `anchor` | `commitments:*`, `anchor:*` |

### Rate Limiting

Implement rate limits to prevent abuse:

```yaml
# Rate limit configuration
rate_limits:
  events_ingest:
    requests_per_second: 100
    burst: 500
  events_read:
    requests_per_second: 1000
    burst: 2000
  commitments:
    requests_per_second: 10
    burst: 50
```

## Network Security

### TLS Configuration

Enforce TLS 1.3 with strong cipher suites:

```nginx
# nginx.conf
ssl_protocols TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers on;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_stapling on;
ssl_stapling_verify on;

# HSTS
add_header Strict-Transport-Security "max-age=63072000" always;
```

### Certificate Management

```bash
# Generate certificate with Let's Encrypt
certbot certonly --standalone -d sequencer.stateset.io

# Auto-renewal
certbot renew --quiet
```

### Network Policies (Kubernetes)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sequencer-network-policy
  namespace: stateset
spec:
  podSelector:
    matchLabels:
      app: sequencer
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgres
    ports:
    - port: 5432
  - to:  # Allow external L2 RPC
    - ipBlock:
        cidr: 0.0.0.0/0
    ports:
    - port: 443
```

### Firewall Rules

```bash
# Allow only necessary ports
ufw allow 443/tcp   # HTTPS
ufw allow 22/tcp    # SSH (restrict to admin IPs)
ufw deny 5432/tcp   # Block direct Postgres access
```

## Database Security

### Connection Security

```yaml
# Always use SSL for database connections
DATABASE_URL: "postgres://user:pass@host:5432/db?sslmode=verify-full"
```

### Access Control

```sql
-- Create restricted user for application
CREATE USER sequencer_app WITH PASSWORD 'strong_password';
GRANT CONNECT ON DATABASE stateset_sequencer TO sequencer_app;
GRANT USAGE ON SCHEMA public TO sequencer_app;
GRANT SELECT, INSERT ON events TO sequencer_app;
GRANT SELECT, INSERT, UPDATE ON sequence_counters TO sequencer_app;
GRANT SELECT, INSERT ON batch_commitments TO sequencer_app;
GRANT SELECT, INSERT ON agent_keys TO sequencer_app;

-- Deny destructive operations
REVOKE DELETE ON events FROM sequencer_app;
REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM sequencer_app;
```

### Encryption at Rest

```sql
-- PostgreSQL transparent data encryption (enterprise)
-- Or use filesystem-level encryption

-- For sensitive columns, use pgcrypto
CREATE EXTENSION pgcrypto;

-- Encrypt payload at application level before storage
```

### Audit Logging

```sql
-- Enable audit logging
CREATE EXTENSION pgaudit;

-- Log all data modifications
ALTER SYSTEM SET pgaudit.log = 'write';
ALTER SYSTEM SET pgaudit.log_catalog = off;
```

## Sequencer Private Key Security

The sequencer private key is used for on-chain anchoring. Protect it carefully:

### Storage Options

1. **HSM (Recommended for Production)**
   ```
   Use AWS CloudHSM, Azure Key Vault HSM, or GCP Cloud HSM
   ```

2. **Kubernetes Secrets with Encryption**
   ```yaml
   apiVersion: v1
   kind: Secret
   metadata:
     name: sequencer-anchor-key
   type: Opaque
   data:
     SEQUENCER_PRIVATE_KEY: <base64-encoded-encrypted-key>
   ```

3. **HashiCorp Vault**
   ```bash
   vault kv put secret/sequencer/anchor private_key="0x..."
   ```

### Access Restrictions

- Only anchor service should access the key
- Use separate service account for anchor operations
- Implement key usage logging

## Input Validation

### Event Validation

```rust
// Validate all event fields
fn validate_event(event: &VesEventEnvelope) -> Result<(), ValidationError> {
    // VES version check
    if event.ves_version != 1 {
        return Err(ValidationError::UnsupportedVersion);
    }

    // UUID format
    Uuid::parse_str(&event.event_id)?;
    Uuid::parse_str(&event.tenant_id)?;

    // Entity type whitelist
    if !ALLOWED_ENTITY_TYPES.contains(&event.entity_type) {
        return Err(ValidationError::InvalidEntityType);
    }

    // Payload size limit
    if event.payload.len() > MAX_PAYLOAD_SIZE {
        return Err(ValidationError::PayloadTooLarge);
    }

    // Timestamp validation (not too far in future)
    let occurred = DateTime::parse_from_rfc3339(&event.occurred_at)?;
    if occurred > Utc::now() + Duration::hours(1) {
        return Err(ValidationError::FutureTimestamp);
    }

    Ok(())
}
```

### SQL Injection Prevention

Always use parameterized queries:

```rust
// GOOD - Parameterized query
sqlx::query!(
    "SELECT * FROM events WHERE tenant_id = $1 AND sequence_number = $2",
    tenant_id,
    sequence_number
)

// BAD - String interpolation (NEVER DO THIS)
// format!("SELECT * FROM events WHERE tenant_id = '{}'", tenant_id)
```

## Incident Response

### Detection

Monitor for:
- Failed authentication attempts
- Unusual event volumes
- Signature verification failures
- Database connection anomalies
- Anchor transaction failures

### Response Procedures

1. **Key Compromise**
   - Immediately revoke compromised key
   - Rotate all affected keys
   - Audit events signed with compromised key
   - Notify affected tenants

2. **Data Breach**
   - Isolate affected systems
   - Preserve evidence
   - Assess scope of breach
   - Notify affected parties
   - Engage incident response team

3. **Service Disruption**
   - Activate runbook
   - Scale resources if needed
   - Communicate status to stakeholders

### Security Contacts

Define escalation paths:
- Security team: security@stateset.io
- On-call engineer: PagerDuty
- Legal/compliance: compliance@stateset.io

## Compliance Considerations

### Data Residency

Configure deployment for data residency requirements:

```yaml
# Deploy to specific regions
regions:
  - us-east-1  # US data
  - eu-west-1  # EU data (GDPR)
```

### Audit Trail

Maintain immutable audit trail:
- All events are append-only
- Merkle commitments provide tamper evidence
- On-chain anchoring for non-repudiation

### Data Retention

```sql
-- Implement retention policy (if required)
-- Note: Events are immutable by design

-- Archive old events to cold storage
CREATE TABLE events_archive (LIKE events);

INSERT INTO events_archive
SELECT * FROM events
WHERE created_at < NOW() - INTERVAL '7 years';
```

## Security Checklist

### Development
- [ ] Dependency scanning (cargo audit)
- [ ] Static analysis (clippy, rust-analyzer)
- [ ] Secret scanning in CI/CD
- [ ] Code review for security issues

### Deployment
- [ ] TLS certificates valid and auto-renewing
- [ ] Database credentials in secrets manager
- [ ] Network policies configured
- [ ] Rate limiting enabled
- [ ] Health checks configured

### Operations
- [ ] Log aggregation and monitoring
- [ ] Alerting for security events
- [ ] Regular key rotation scheduled
- [ ] Backup encryption enabled
- [ ] Incident response plan tested

### Compliance
- [ ] Data residency requirements met
- [ ] Audit logging enabled
- [ ] Access controls documented
- [ ] Security training completed
