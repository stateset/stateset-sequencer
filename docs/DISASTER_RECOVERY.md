# Disaster Recovery Guide

This guide provides procedures for disaster recovery, backup, and restoration of the StateSet Sequencer.

## Table of Contents

- [Overview](#overview)
- [RTO/RPO Targets](#rtorpo-targets)
- [Backup Strategy](#backup-strategy)
- [Recovery Procedures](#recovery-procedures)
- [Failover Scenarios](#failover-scenarios)
- [Testing](#testing)

---

## Overview

The StateSet Sequencer is designed for high availability with multiple recovery options:

- **PostgreSQL**: Primary source of truth for all sequenced events
- **SQLite Outboxes**: Local agent backup for offline-first operation
- **On-Chain Anchors**: Immutable commitment verification

### Critical Data

| Data Type | Storage | Recovery Priority |
|-----------|---------|-------------------|
| PostgreSQL Event Log | PostgreSQL | CRITICAL |
| Sequence Counters | PostgreSQL | CRITICAL |
| Agent Key Registry | PostgreSQL | HIGH |
| Commitments | PostgreSQL | HIGH |
| Compliance Proofs | PostgreSQL | MEDIUM |
| Compliance Proofs | MEDIUM |
| Local Outboxes | SQLite | MEDIUM |
| On-Chain Anchors | Ethereum L2 | LOW (verification only) |

---

## RTO/RPO Targets

| Metric | Target | Description |
|--------|--------|-------------|
| **RTO** (Recovery Time Objective) | 1-4 hours | Maximum acceptable downtime |
| **RPO** (Recovery Point Objective) | 0-5 minutes | Maximum data loss tolerance |

### SLO Breakdown

| Component | Availability Target | Recovery Priority |
|-----------|-------------------|-------------------|
| API Endpoints | 99.5% uptime | P0 |
| Database | 99.9% uptime | P0 |
| gRPC Services | 99.5% uptime | P1 |
| Anchoring Service | 99.0% uptime | P2 |

---

## Backup Strategy

### PostgreSQL Backups

#### Automatic Daily Backups

Configure pgBackRest or WAL archiving:

```bash
# pgBackRest configuration (/etc/pgbackrest/pgbackrest.conf)
[global]
repo1-path=/var/lib/pgbackrest
repo1-retention-full=30
repo1-retention-diff=7

[my-stanza]
pg1-path=/var/lib/postgresql/data
pg1-port=5432
pg1-user=postgres

# Schedule backups (cron)
# Daily full backup at 2 AM
0 2 * * * pgbackrest --stanza=my-stanza --type=full backup
# Hourly incremental backup
0 * * * * pgbackrest --stanza=my-stanza --type=incr backup
```

#### WAL Archive Configuration

```sql
-- postgresql.conf
wal_level = replica
archive_mode = on
archive_command = 'pgbackrest --stanza=my-stanza archive-push %p'
max_wal_senders = 3
wal_keep_size = 512MB
```

#### Manual Backup Command

```bash
# Full backup with pg_dump
pg_dump -Fc -f sequencer_dump_$(date +%Y%m%d).dump stateset_sequencer

# Schema-only backup
pg_dump -s -f sequencer_schema_$(date +%Y%m%d).sql stateset_sequencer
```

### SQLite Outbox Backups

Local agent SQLite databases should be backed up automatically:

```bash
# Nightly backup of outbox
cp .sequencer/outbox.db .sequencer/outbox.db.backup.$(date +%Y%m%d)

# Using rsync for agents
rsync -avz ~/.sequencer/ backup-server:~/.sequencer-backups/
```

### Agent Keys Backup

**CRITICAL**: Agent private keys must be backed up securely:

```bash
# Backup to encrypted archive
tar -czf agent_keys.tar.gz ~/.sequencer/keys/
gpg --cipher-algo AES256 --symmetric agent_keys.tar.gz

# Store in secrets manager (AWS Secrets Manager, Azure Key Vault, etc.)
aws secretsmanager create-secret \
  --name stateset/agent-keys \
  --secret-binary fileb://agent_keys.tar.gz.gpg
```

### Environment Variables Backup

```bash
# Export .env file
cat .env | jq > env_backup_$(date +%Y%m%d).json

# Use secrets manager for production
aws secretsmanager create-secret \
  --name stateset/sequencer/env \
  --secret-string file://env.json
```

---

## Recovery Procedures

### Level 1: In-Place Recovery (0-5 min恢复)

适用于临时故障、重启或配置更改等情况的快速恢复

Goal: Service恢复最小的数据损失

#### Restart Services

```bash
# Kubernetes
kubectl rollout restart deployment/stateset-sequencer

# Docker Compose
docker-compose down && docker-compose up -d

# Systemd
sudo systemctl restart stateset-sequencer
```

#### Database Connection Issues

```bash
# Check database connectivity
psql -h localhost -U sequencer -d stateset_sequencer -c "SELECT 1"

# Restart PostgreSQL
kubectl rollout restart statefulset/postgres

# Check connection pool metrics
curl http://localhost:8080/health/detailed | jq '.database'
```

#### Clear Cache

```bash
# Flush Redis cache (if used)
redis-cli FLUSHALL

# Restart sequencer to rebuild in-memory cache
kubectl rollout restart deployment/stateset-sequencer
```

### Level 2: Rollback Recovery (15-30 min)

适用于最近的部署、schema更改或config变更导致的问题

#### Database Rollback

```bash
# Restore from pgBackRest
pgbackrest --stanza=my-stanza --delta restore --type=full

# Restore SQL dump
pg_restore -d stateset_sequencer -Fc sequencer_dump_20250128.dump

# Rollback specific migration
down migration rollback --migration_number 009
```

#### Application Rollback

```bash
# Kubernetes - roll back to previous revision
kubectl rollout undo deployment/stateset-sequencer

# Docker - pull previous image
docker pull ghcr.io/stateset/stateset-sequencer:previous-tag
docker-compose up -d

# Check rollback status
kubectl rollout status deployment/stateset-sequencer
```

#### Schema Reversion

```bash
# Run rollback migration
down migration rollback

# Verify schema
sqlx database create --database-url postgres://...
sqlx migrate run --database-url postgres://...
```

### Level 3: Point-in-Time Recovery (PITR) (1-2 hours)

适用于数据库损坏、意外删除或数据损坏

#### PostgreSQL Point-in-Time Recovery

```bash
# Stop PostgreSQL
sudo systemctl stop postgresql

# Identify the recovery point
# Use WAL archives to find the target time or transaction ID

# Configure recovery.conf (or postgresql.conf for PostgreSQL 12+)
cat >> /var/lib/postgresql/data/recovery.conf <<EOF
restore_command = 'cp /var/lib/pgbackrest/wal/%f %p'
recovery_target_time = '2025-01-28 14:30:00 UTC'
# OR
recovery_target_xid = '123456789'  # Use transaction ID
EOF

# Start PostgreSQL
sudo systemctl start postgresql

# Monitor recovery logs
tail -f /var/log/postgresql/*.log | grep "database system is ready to accept connections"
```

#### Restore Events from Agent Outboxes

如果PostgreSQL恢复不可用，可以从local SQLite outboxes重建：

```bash
# On each agent, export unsynced events
sequencer-cli export-events \
  --output events_backup_$(date +%Y%m%d).json \
  --status unsynced

# Bulk ingest into recovered database
sequencer-cli bulk-ingest \
  --file events_backup_20250128.json \
  --url http://recovered-sequencer:8080 \
  --api-key recovery-api-key
```

#### Verify Sequence Continuity

After PITR, verify no sequence gaps:

```sql
-- Check for gaps per (tenant_id, store_id) stream
SELECT
    tenant_id,
    store_id,
    ARRAY_AGG(sequence_number) AS missing_sequences
FROM (
    SELECT
        tenant_id,
        store_id,
        sequence_number,
        LAG(sequence_number) OVER (
            PARTITION BY tenant_id, store_id
            ORDER BY sequence_number
        ) AS prev_seq
    FROM ves_events
) t
WHERE prev_seq IS NOT NULL AND sequence_number != prev_seq + 1
GROUP BY tenant_id, store_id;
```

如果有gaps, them rebuild sequence counters:

```sql
-- Update sequence counter to latest
UPDATE sequence_counters
SET current_sequence = (
    SELECT MAX(sequence_number)
    FROM ves_events
    WHERE ves_events.tenant_id = sequence_counters.tenant_id
        AND ves_events.store_id = sequence_counters.store_id
);
```

### Level 4: Full Disaster Recovery (2-4 hours)

适用于完整站点故障、区域故障或 catastrophic failure

## Failover Scenarios

### Scenario 1: PostgreSQL Primary Failure

**Detection:**
```bash
# Health check failures
kubectl get pods -l app=postgres

# Database connection errors in logs
kubectl logs -f deployment/stateset-sequencer | grep "database.*error"
```

**Recovery:**

1. **Promote standby to primary**:
```bash
kubectl exec -it postgres-read-0 -- pg_promote
kubectl label pod postgres-read-0 role=primary --overwrite
```

2. **Reconfigure application connections**:
```yaml
# Update ConfigMap
apiVersion: v1
kind: ConfigMap
data:
  DATABASE_URL: "postgres://sequencer:password@postgres-read-0:5432/stateset_sequencer"
```

3. **Resume operations**:
```bash
kubectl rollout restart deployment/stateset-sequencer
```

### Scenario 2: Sequencer Instance Failure

**Detection:**
```bash
# Pod crashed or not responding
kubectl get pods -l app=stateset-sequencer

# High error rate in metrics
curl http://localhost:8080/metrics | grep "http_requests_total{status=\"5xx\"}"
```

**Recovery:**

Due to stateless design, simply scale up:
```bash
# Scale horizontally
kubectl scale deployment/stateset-sequencer --replicas=5

# Or roll restart
kubectl rollout restart deployment/stateset-sequencer
```

### Scenario 3: Regional Failure

**Detection:**
```bash
# All pods in region unhealthy
kubectl get pods --all-namespaces -l region=us-east-1

# Network partition detected
ping monitoring-service
```

**Recovery:**

1. **Activate disaster recovery region**:
```bash
# Update DNS to point to DR region
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890ABC \
  --change-batch file://dr-failover.json
```

2. **Scale DR services**:
```bash
kubectl --context=dr-cluster scale deployment/stateset-sequencer --replicas=5
```

3. **Verify failover**:
```bash
curl https://sequencer.stateset.io/health
```

### Scenario 4: Data Corruption

**Detection:**
```bash
# Checksum failures
sha256sum events_backup_20250128.dump

# Data integrity checks
sequencer-cli verify-events --tenant-id <uuid> --store-id <uuid>

# On-chain verification
curl https://api.stateset.io/commitments/verify \
  -d '{"batch_id": "<uuid>", "chain_tx_hash": "0x..."}'
```

**Recovery:**

1. **Identify corrupted data**:
```sql
SELECT event_id, sequence_number
FROM ves_events
WHERE payload_hash IS NULL
   OR created_at IS NULL
   OR tenant_id IS NULL;
```

2. **Restore from backup**:
```bash
pg_restore -d stateset_sequencer_restored -Fc clean_backup.dump
```

3. **Selective sync from agents**:
```bash
# Reingest events from specific time range
sequencer-cli sync-agent \
  --start-time "2025-01-28T10:00:00Z" \
  --end-time "2025-01-28T14:30:00Z"
```

---

## Testing

### Backup Verification

每周验证backup可以成功restore:

```bash
# Create test restore using pgBackRest
pgbackrest --stanza=my-stanza --delta restore --type=full

# Verify data integrity
psql -d stateset_sequencer_test -c "
SELECT COUNT(*) FROM ves_events;
SELECT MAX(sequence_number) FROM sequence_counters;
"
```

### DR Drill Quarterly

每季度进行完整的灾难恢复演练:

1. **Failover to DR environment**
2. **Restore from backup**
3. **Verify functionality**:
   - Event ingestion works
   - Sequence counters correct
   - Agent connections successful
   - Commitments can be created
4. **Fallback to production**

### Runbook Validation

每月验证runbook中的所有命令:

```bash
# Example script to validate commands
#!/bin/bash
set -e

echo "✓ Testing backup command"
pgbackrest --stanza=my-stanza --repo1-type=fast --type=full backup

echo "✓ Testing restore (dry-run)"
pgbackrest --stanza=my-stanza --repo1-type=fast --type=full --delta restore --recovery-option=standby_mode=on

echo "✓ Testing hornc scale"
kubectl scale deployment/stateset-sequencer --replicas=3

echo "✓ Rollback scale"
kubectl scale deployment/stateset-sequencer --replicas=1

echo "✓ All runbook commands validated"
```

---

## Post-Recovery Checklist

After any recovery, complete these steps:

- [ ] All services are healthy (`/health` returns 200)
- [ ] Database connectivity verified
- [ ] Sequence counters synchronized
- [ ] No missing sequences detected
- [ ] Agent connections restored
- [ ] Commitments can be created
- [ ] Historical events are queryable
- [ ] Alerts resolved (or acknowledged)
- [ ] Post-mortem documented
- [ ] Recovery time metrics recorded

---

## Escalation Contact

| Severity | Response SLA | Contact |
|----------|--------------|---------|
| P0: Service Down | 15 min | On-call https://pagerduty.com/stateset |
| P1: Data Loss Risk | 1 hour | Team Lead team-lead@stateset.io |
| P2: Performance Degraded | 4 hours | Engineering engineering@stateset.io |
| P3: Non-Critical Issue | 1 business day | Support support@stateset.io |

---

## Additional Resources

- [Architecture Documentation](/ARCHITECTURE.md)
- [System Overview](/SYSTEM_OVERVIEW.md)
- [Runbook](/docs/RUNBOOK.md)
- [Anchoring Overview](/docs/ANCHORING_OVERVIEW.md)