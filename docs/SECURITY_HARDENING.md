# Security Hardening Guide

This guide provides comprehensive security hardening recommendations for the StateSet Sequencer in production environments.

## Table of Contents

1. [Infrastructure Security](#infrastructure-security)
2. [Network Security](#network-security)
3. [Authentication & Authorization](#authentication--authorization)
4. [Data Protection](#data-protection)
5. [Cryptography](#cryptography)
6. [Secrets Management](#secrets-management)
7. [Monitoring & Alerting](#monitoring--alerting)
8. [Audit Trail](#audit-trail)
9. [Incident Response](#incident-response)
10. [Compliance](#compliance)

---

## Infrastructure Security

### Kubernetes Hardening

```yaml
# Recommended pod security context
securityContext:
  runAsNonRoot: true
  runAsUser: 65534  # nobody
  fsGroup: 65534
  seccompProfile:
    type: RuntimeDefault
  capabilities:
    drop:
      - ALL
  allowedHostPaths: []
```

**Requirements:**
- ✅ Enable PodSecurityPolicy or Pod Security Standards
- ✅ Use read-only root filesystem
- ✅ Disable privilege escalation
- ✅ Remove ALL Linux capabilities
- ✅ Network policies to restrict egress traffic

```yaml
# Example NetworkPolicy
spec:
  podSelector:
    matchLabels:
      app: stateset-sequencer
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: postgres
    ports:
    - port: 5432
      protocol: TCP
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgres
    ports:
    - port: 5432
      protocol: TCP
  - to:
    - namespaceSelector: {}  # Allow DNS
    ports:
    - port: 53
      protocol: UDP
```

### PostgreSQL Hardening

```sql
-- Connection security
ALTER SYSTEM SET ssl = on;
ALTER SYSTEM SET ssl_min_protocol_version = 'TLSv1.3';
ALTER SYSTEM SET hba_file = '/etc/postgresql/pg_hba.conf';
SELECT pg_reload_conf();

-- Connection timeout
ALTER SYSTEM SET statement_timeout = '30s';
ALTER SYSTEM SET idle_in_transaction_session_timeout = '10s';
ALTER SYSTEM SET lock_timeout = '5s';

-- Logging security events
ALTER SYSTEM SET log_connections = on;
ALTER SYSTEM SET log_disconnections = on;
ALTER SYSTEM SET log_statement = 'ddl';
```

**pg_hba.conf requirements:**
```conf
# TYPE  DATABASE        USER            ADDRESS                 METHOD
host    all             all             10.0.0.0/8              scram-sha-256
host    all             all             172.16.0.0/12           scram-sha-256
host    all             all             192.168.0.0/16          scram-sha-256
# Reject all IPv4
host    all             all             0.0.0.0/0               reject
```

---

## Network Security

### TLS Configuration

**Minimum Requirements:**
- TLS 1.3 only (no TLS 1.2/1.1/1.0)
- Strong cipher suites only
- Perfect Forward Secrecy
- HSTS enabled

```nginx
# Nginx TLS configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;

# HSTS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
```

**Rust Axum TLS:**
```rust
use axum_server::tls_rustls::RustlsConfig;

let config = RustlsConfig::from_pem_file(
    "cert.pem",
    "key.pem"
).await?;

// Force TLS 1.3
let config = RustlsConfig::from_config(
    rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?
);
```

### Firewall Rules

**Minimum required ports:**
| Port | Protocol | Purpose | Source |
|------|----------|---------|--------|
| 8080 | TCP | HTTP API | Clients, load balancer |
| 8081 | TCP | gRPC API | Agents, load balancer |
| 5432 | TCP | PostgreSQL | Application tier only |
| 9090 | TCP | Prometheus metrics | Monitoring stack |
| 4317 | TCP | OTLP gRPC | Observability backends |

**Example iptables rules:**
```bash
#!/bin/bash
# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow HTTP/gRPC from trusted networks
iptables -A INPUT -s 10.0.0.0/8 -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -s 10.0.0.0/8 -p tcp --dport 8081 -j ACCEPT

# Allow metrics from Prometheus
iptables -A INPUT -s 10.0.0.0/8 -p tcp --dport 9090 -j ACCEPT

# Drop everything else
iptables -A INPUT -j DROP
```

---

## Authentication & Authorization

### API Key Security

**Requirements:**
- Minimum 32 characters (256 bits)
- Generated with CSPRNG
- SHA-256 hashed in database
- Never logged or exposed in errors
- Rotation every 90 days
- Expiration dates enforced

```bash
# Generate secure API key
openssl rand -base64 32

# Expected format: stateset_<16-char-random>
# Example: stateset_k9XmN3pQ7tR2vW5yZ8bA1cD4eF6gH0j
```

**API Key Validation:**
```rust
// Validate API key strength
const MIN_API_KEY_LENGTH: usize = 32;

pub fn validate_api_key(key: &str) -> Result<(), AuthError> {
  if !key.starts_with("stateset_") {
    return Err(AuthError::InvalidFormat);
  }
  if key.len() < MIN_API_KEY_LENGTH {
    return Err(AuthError::TooWeak);
  }
  // Check for strong entropy
  let entropy = calculate_entropy(key);
  if entropy < 4.0 {
    return Err(AuthError::InsufficientEntropy);
  }
  Ok(())
}
```

### JWT Configuration

**Best Practices:**
- Minimum 256-bit signing key
- 15-minute token lifetime
- Refresh token support
- JWE encryption for sensitive claims

```rust
const JWT_ISSUER: &str = "stateset-sequencer";
const JWT_AUDIENCE: &str = "stateset-api";
const JWT_EXPIRATION_MINUTES: i64 = 15;

// Token claims
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
  sub: String,           // Subject (user ID)
  exp: i64,              // Expiration time
  iat: i64,              // Issued at
  nbf: i64,              // Not before
  iss: String,           // Issuer
  aud: String,           // Audience
  tenant_id: TenantId,   // Tenant scope
  permissions: Vec<String>, // Scopes
}
```

### Agent Key Management

**Key Rotation:**
```sql
-- Key rotation policy: Every 90 days
CREATE TABLE agent_keys (
  key_id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL,
  agent_id UUID NOT NULL,
  public_key BYTEA NOT NULL,
  key_type VARCHAR(16) NOT NULL, -- 'signing', 'encryption'
  status VARCHAR(16) NOT NULL,    -- 'active', 'revoked', 'expired'
  valid_from TIMESTAMPTZ NOT NULL,
  valid_to TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  CONSTRAINT valid_key CHECK (
    status = 'revoked' OR 
    (valid_from <= NOW() AND valid_to > NOW())
  )
);

CREATE INDEX idx_agent_keys_active ON agent_keys(tenant_id, agent_id, status) 
WHERE status = 'active';

CALL rotate_agent_keys('tenant_uuid', 'agent_uuid');
```

---

## Data Protection

### Encryption-at-Rest

**AES-256-GCM Configuration:**
```bash
# Generate encryption key
openssl rand -hex 32

# Environment variable
export PAYLOAD_ENCRYPTION_MODE=required
export PAYLOAD_ENCRYPTION_KEYS=0:base64key1,1:base64key2,2:base64key3

# First key is current, others for decryption of old data
```

**Key Rotation:**
```sql
-- Add new key version
INSERT INTO encryption_keys (
  version, key_hash, key_algorithm, created_at, status
) VALUES (
  2, 
  'sha256_hash', 
  'AES-256-GCM',
  NOW(),
  'active'
);

-- Mark old key as deprecated
UPDATE encryption_keys 
SET status = 'deprecated' 
WHERE version = 1;

-- Re-encrypt payloads with new key
CALL reencrypt_payloads('tenant_uuid', 'old_version', 'new_version');
```

### Data Retention

```sql
-- Data retention policy: 7 years for events (compliance)
CREATE EXTENSION IF NOT EXISTS pg_cron;

-- Archive old events
CREATE OR REPLACE FUNCTION archive_old_events()
RETURNS void AS $$
BEGIN
  -- Move events older than 7 years to cold storage
  INSERT INTO events_archive
  SELECT * FROM events WHERE created_at < NOW() - INTERVAL '7 years';
  
  -- Delete archived events from main table
  DELETE FROM events WHERE created_at < NOW() - INTERVAL '7 years';
END;
$$ LANGUAGE plpgsql;

-- Schedule weekly job
SELECT cron.schedule('0 2 * * 0', 'SELECT archive_old_events()');
```

---

## Cryptography

### Hash Functions

```rust
// Domain-separated hashing (per VES v1.0)
use sha2::{Sha256, Digest};
use serde_json_canonicalizer::canonicalize;

pub fn ves_signing_hash(event: &VESEvent) -> [u8; 32] {
  let mut hasher = Sha256::new();
  hasher.update("VES_EVENTSIG_V1".as_bytes());
  hasher.update(event.event_id.as_bytes());
  hasher.update(event.tenant_id.as_bytes());
  hasher.update(event.store_id.as_bytes());
  hasher.update(event.agent_id.as_bytes());
  hasher.update(entity_type.as_bytes());
  hasher.update(event.entity_id.as_bytes());
  hasher.update(event.event_type.as_bytes());
  hasher.update(&event.payload_plain_hash);
  hasher.update(event.occurred_at.timestamp().to_be_bytes());
  hasher.finalize().into()
}
```

### HPKE Encryption

```rust
use hpke::Hpke;

const HPKE_MODE: hpke::Mode = hpke::Mode::Base;
const HPKE_KEM: hpke::kem::Kem = hpke::kem::X25519HkdfSha256;
const HPKE_KDF: hpke::kdf::Kdf = hpke::kdf::HkdfSha256;
const HPKE_AEAD: hpke::aead::Aead = hpke::aead::AesGcm256;

pub fn encrypt_payload(
  plaintext: &[u8],
  recipient_public_key: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
  let hpke = Hpke::new(HPKE_MODE, HPKE_KEM, HPKE_KDF, HPKE_AEAD);
  let (encapsulated_key, mut ctx) = hpke.setup_sender(
    recipient_public_key,
    b"VES-ENC-1", // Info string
    b"",          // AEAD associated data
  )?;
  
  let mut ciphertext = ctx.seal(plaintext, b"")?;
  ciphertext.extend_from_slice(&encapsulated_key);
  Ok(ciphertext)
}
```

### STARK Proofs

```rust
// Reuse existing stateset-stark PROOF_SIZE constant
const STARK_PROOF_SIZE: usize = 200_000; // ~200KB

// Validate proof structure
pub fn validate_stark_proof(proof: &[u8]) -> Result<(), Error> {
  if proof.len() > STARK_PROOF_SIZE {
    return Err(Error::ProofTooLarge);
  }
  
  // Verify proof hash
  let proof_hash = sha256(proof);
  if proof_hash != expected_hash {
    return Err(Error::InvalidProof);
  }
  
  // Verify public inputs match event
  // (Delegated to stateset-stark verifier)
  Ok(())
}
```

---

## Secrets Management

### Environment Variables

```bash
# Required secrets (never commit these)
DATABASE_URL=postgres://user:pass@host/db
BOOTSTRAP_ADMIN_API_KEY=stateset_<secure_random>
JWT_SECRET=<32-byte-base64>
PAYLOAD_ENCRYPTION_KEYS=0:<base64>
VES_SEQUENCER_SIGNING_KEY=<base64-ed25519-private-key>
SEQUENCER_PRIVATE_KEY=<base64-ethereum-private-key>
L2_RPC_URL=https://l2-rpc.example.com
SET_REGISTRY_ADDRESS=0x...

# Never in code or version control
```

### Kubernetes Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: stateset-sequencer-secrets
type: Opaque
stringData:
  database-url: "postgres://user:pass@host/db"
  bootstrap-admin-api-key: "stateset_..."
  jwt-secret: "..."
  payload-encryption-keys: "0:..."
  ves-sequencer-signing-key: "..."
  sequencer-private-key: "..."
---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: stateset-sequencer-secrets
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    creationPolicy: Owner
  data:
    - secretKey: database-url
      remoteRef:
        key: stateset/sequencer/database-url
```

### Secret Rotation

```bash
#!/bin/bash
# Rotate secrets via Kubernetes External Secrets

# 1. Update secret in external store
aws secretsmanager put-secret-value \
  --secret-id stateset/sequencer/jwt-secret \
  --secret-string "$(openssl rand -base64 32)"

# 2. Trigger secret refresh (External Secret Operator will auto-refresh)
kubectl annotate secret stateset-sequencer-secrets \
  reconcile-secrets="true" \
  --overwrite

# 3. Wait for rollout
kubectl rollout status deployment/stateset-sequencer
```

---

## Monitoring & Alerting

### Security Metrics

```rust
// In src/metrics/security.rs
use prometheus::{IntCounter, IntGauge};

pub struct SecurityMetrics {
  pub failed_auth_attempts: IntCounter,
  pub revoked_api_keys: IntCounter,
  pub revoked_agent_keys: IntCounter,
  pub signature_failures: IntCounter,
  pub encryption_key_rotations: IntCounter,
  pub active_connections: IntGauge,
  pub suspicious_requests: IntCounter,
}

lazy_static! {
  static ref SECURITY_METRICS: SecurityMetrics = SecurityMetrics {
    failed_auth_attempts: register_int_counter!(
      "security_failed_auth_attempts_total",
      "Total failed authentication attempts"
    ).unwrap(),
    
    revoked_api_keys: register_int_counter!(
      "security_revoked_api_keys_total",
      "Total revoked API keys"
    ).unwrap(),
  };
}
```

### Prometheus Alerting Rules

```yaml
# alerts/alerts.yml
groups:
- name: security_alerts
  rules:
  - alert: HighFailedAuthRate
    expr: rate(security_failed_auth_attempts_total[5m]) > 10
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "High rate of failed authentication attempts"
      description: "{{$labels.instance}} has {{ $value }} failed auth attempts per minute"
      
  - alert: RevokedKeyAccessAttempts
    expr: security_revoked_api_keys_total > 0
    labels:
      severity: warning
    annotations:
      summary: "Access attempts with revoked keys detected"
      
  - alert: ApkKeyLeakDetected
    expr: |
      (
        sum(rate(security_failed_auth_attempts_total[5m])) by (tenant_id)
        /
        sum(rate(api_requests_total[5m])) by (tenant_id)
      ) > 0.5
    for: 10m
    labels:
      severity: critical
    annotations:
      summary: "Possible API key leak detected"
```

---

## Audit Trail

### Audit Logging

```rust
// In src/infra/audit.rs
use tracing::{info, instrument};

#[derive(Debug, Serialize)]
pub struct AuditEvent {
  pub event_type: String,
  pub tenant_id: TenantId,
  pub user_id: Option<String>,
  pub resource_type: String,
  pub resource_id: String,
  pub action: String,
  pub outcome: String,
  pub timestamp: DateTime<Utc>,
  pub ip_address: Option<String>,
  pub user_agent: Option<String>,
  pub metadata: Option<serde_json::Value>,
}

#[instrument(skip(event))]
pub async fn log_audit_event(event: AuditEvent) -> Result<(), Error> {
  // Log to structured log system
  info!(
    event_type = %event.event_type,
    tenant_id = %event.tenant_id,
    resource_type = %event.resource_type,
    resource_id = %event.resource_id,
    action = %event.action,
    outcome = %event.outcome,
    "Audit event logged"
  );
  
  // Persist to audit_events table
  sqlx::query!(
    r#"
    INSERT INTO audit_events (
      event_type, tenant_id, user_id, resource_type, 
      resource_id, action, outcome, timestamp, 
      ip_address, user_agent, metadata
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    "#,
    event.event_type,
    event.tenant_id,
    event.user_id,
    event.resource_type,
    event.resource_id,
    event.action,
    event.outcome,
    event.timestamp,
    event.ip_address,
    event.user_agent,
    event.metadata
  )
  .execute(pool)
  .await?;
  
  Ok(())
}
```

### Audit Queries

```sql
-- Audit retention: 5 years
CREATE TABLE audit_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type VARCHAR(64) NOT NULL,
  tenant_id UUID NOT NULL,
  user_id TEXT,
  resource_type VARCHAR(64) NOT NULL,
  resource_id TEXT NOT NULL,
  action VARCHAR(64) NOT NULL,
  outcome VARCHAR(16) NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ip_address INET,
  user_agent TEXT,
  metadata JSONB
);

CREATE INDEX idx_audit_events_tenant ON audit_events(tenant_id, timestamp DESC);
CREATE INDEX idx_audit_events_resource ON audit_events(resource_type, resource_id, timestamp DESC);
CREATE INDEX idx_audit_events_user ON audit_events(user_id, timestamp DESC);
```

---

## Incident Response

### Incident Playbook

```markdown
# Security Incident Response Plan

## Phases

### 1. Detection (0-15 minutes)
- Alert triggered via Prometheus/PagerDuty
- On-call engineer acknowledges
- Initial triage: scope and severity assessment

### 2. Containment (15-60 minutes)
- Block malicious IP addresses
- Revoke compromised API keys
- Enable rate limiting
- Scale up monitoring

### 3. Eradication (1-4 hours)
- Patch vulnerabilities
- Rotate secrets/keys
- Clean up malicious accounts

### 4. Recovery (4-24 hours)
- Restore from backups if needed
- Verify system integrity
- Gradual user access restoration

### 5. Post-Incident (24-72 hours)
- Root cause analysis
- Update documentation
- Improve monitoring
- Lessons learned meeting
```

### Escalation Matrix

```yaml
# Incident severity levels
Severity:
  P0:
    - Service permanently down
    - Customer data confirmed exposed
    - Impact: Critical customers
    - Response time: 15 minutes
    - Escalation: CTO, CEO
    
  P1:
    - Major functionality degraded
    - Potential data exposure
    - Impact: Multiple customers
    - Response time: 30 minutes
    - Escalation: VP Engineering, Legal
    
  P2:
    - Minor functionality affected
    - No data exposure
    - Impact: Single customer
    - Response time: 1 hour
    - Escalation: Engineering Manager
    
  P3:
    - Cosmetic issues
    - No customer impact
    - Response time: 4 hours
    - Escalation: Team Lead
```

---

## Compliance

### SOC 2 Controls

```markdown
## Relevant Controls

### CC6.1 - Logical and Physical Access Controls
- [ ] MFA for all administrative access
- [ ] API key rotation every 90 days
- [ ] IP allowlisting for admin endpoints
- [ ] Session timeout after 15 minutes

### CC6.2 - System Monitoring and Performance
- [ ] 24/7 monitoring with alerting
- [ ] Security metrics dashboard
- [ ] Log retention 90 days
- [ ] Real-time alerting for anomalies

### CC6.6 - Change Management
- [ ] Code review required for all changes
- [ ] Automated testing coverage > 70%
- [ ] Deployment approvals
- [ ] Rollback procedures documented

### CC6.8 - Data Loss Prevention
- [ ] Encryption at rest (AES-256-GCM)
- [ ] Encryption in transit (TLS 1.3)
- [ ] Backup encryption
- [ ] Data retention policies enforced
```

### GDPR Compliance

```markdown
## GDPR Requirements

### Data Protection Measures
- [ ] Data minimization: Store only necessary data
- [ ] Pseudonymization: Use tenant_id, not direct PII
- [ ] Right to deletion: Data retention 7 years
- [ ] Data portability: Export endpoint for tenant data
- [ ] Consent management: Opt-in for data processing

### Data Subject Rights
- [ ] API endpoint for data access requests: `GET /api/v1/tenant/:tenant_id/data`
- [ ] API endpoint for data deletion: `DELETE /api/v1/tenant/:tenant_id/data`
- [ ] Response time: 30 days

### Breach Notification
- [ ] Detection time: < 24 hours
- [ ] Notification to authorities: < 72 hours
- [ ] Notification to affected parties: Without undue delay
```

---

## Security Checklist

### Pre-Deployment

```bash
#!/bin/bash
# security-checklist.sh

echo "Running security checklist..."

# 1. Verify secrets are not in code
echo "Checking for secrets in code..."
git grep -i "password" -- "*.rs" "*.yml" "*.env*" && exit 1
git grep -i "secret" -- "*.rs" "*.yml" "*.env*" && exit 1
git grep -i "api_key" -- "*.rs" "*.yml" "*.env*" && exit 1

# 2. Verify TLS configuration
echo "Checking TLS configuration..."
openssl s_client -connect localhost:8080 -tls1_3 2>/dev/null | grep "Protocol.*TLSv1.3" || exit 1

# 3. Run security audit
echo "Running cargo audit..."
cargo audit || exit 1

# 4. Check dependencies
echo "Running cargo deny..."
cargo deny check advisories || exit 1

# 7. Check API key strength
echo "Validating API key strength..."
if [[ ${#BOOTSTRAP_ADMIN_API_KEY} -lt 32 ]]; then
  echo "ERROR: API key too short"
  exit 1
fi

echo "All security checks passed!"
```

### On-Going Monitoring

```bash
#!/bin/bash
# daily-security-scan.sh

# 1. Check for failed auth bursts
QUERY="SELECT COUNT(*) FROM audit_events 
WHERE event_type = 'auth_failed' 
AND timestamp > NOW() - INTERVAL '1 hour'"
FAILED_AUTH=$(psql -c "$QUERY" -t)
if [ "$FAILED_AUTH" -gt 100 ]; then
  echo "ALERT: High number of failed auth attempts: $FAILED_AUTH"
  # Trigger alert...
fi

# 2. Check for revoked key usage
QUERY="SELECT COUNT(*) FROM audit_events 
WHERE event_type = 'auth_failed' 
AND metadata->>'reason' = 'revoked_key'"
REVOKED=$(psql -c "$QUERY" -t)
if [ "$REVOKED" -gt 0 ]; then
  echo "ALERT: Revoked key access attempts: $REVOKED"
  # Trigger alert...
fi

# 3. Check signature failures
QUERY="SELECT COUNT(*) FROM audit_events 
WHERE event_type = 'signature_failed'"
SIG_FAILS=$(psql -c "$QUERY" -t)
if [ "$SIG_FAILS" -gt 10 ]; then
  echo "ALERT: Signature failures: $SIG_FAILS"
  # Trigger alert...
fi
```

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Kubernetes Benchmarks](https://www.cisecurity.org/benchmark/kubernetes)
- [SOC 2 Trust Services Criteria](https://www.aicpa.org/soc4so)
- [GDPR Text](https://gdpr-info.eu/)

---

**Last Updated:** 2026-01-29
**Version:** 1.0
**Reviewed By:** Security Team