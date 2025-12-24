# StateSet Sequencer Operations Runbook

This document provides operational procedures for common incidents and maintenance tasks.

## Table of Contents

1. [Health Checks](#health-checks)
2. [Common Incidents](#common-incidents)
3. [Database Operations](#database-operations)
4. [Performance Issues](#performance-issues)
5. [Recovery Procedures](#recovery-procedures)

---

## Health Checks

### Basic Health Check

```bash
curl http://localhost:8080/health
```

Expected response:
```json
{"status": "healthy", "service": "stateset-sequencer", "version": "0.1.1"}
```

### Readiness Check (Database Connectivity)

```bash
curl http://localhost:8080/ready
```

Expected response:
```json
{"status": "ready", "database": "connected"}
```

### Metrics Endpoint

```bash
curl http://localhost:8080/metrics
```

Returns Prometheus-format metrics.

---

## Common Incidents

### Incident: High Latency on Event Ingestion

**Symptoms:**
- Ingest endpoint response time > 500ms
- `sequencer.ingest.latency_seconds` histogram shows high p99

**Investigation:**

1. Check database connection pool:
   ```bash
   curl http://localhost:8080/metrics | grep db_pool
   ```

2. Check for lock contention:
   ```sql
   SELECT pid, now() - pg_stat_activity.query_start AS duration, query
   FROM pg_stat_activity
   WHERE state != 'idle'
   ORDER BY duration DESC;
   ```

3. Check sequence counter locks:
   ```sql
   SELECT * FROM pg_locks
   WHERE relation = 'sequence_counters'::regclass;
   ```

**Resolution:**

- If pool exhausted: Increase `MAX_DB_CONNECTIONS`
- If lock contention: Consider batching events or partitioning hot streams
- If slow queries: Check indexes on `events` table

### Incident: Rate Limit Exceeded Errors

**Symptoms:**
- HTTP 429 responses
- `sequencer.ratelimit.rejected` counter increasing

**Investigation:**

```bash
curl http://localhost:8080/metrics | grep ratelimit
```

**Resolution:**

1. Identify high-volume tenant:
   ```sql
   SELECT tenant_id, COUNT(*)
   FROM events
   WHERE created_at > NOW() - INTERVAL '1 hour'
   GROUP BY tenant_id
   ORDER BY COUNT(*) DESC;
   ```

2. Adjust rate limits:
   ```bash
   # Increase global limit
   export RATE_LIMIT_PER_MINUTE=10000

   # Or implement per-tenant limits in API key
   ```

### Incident: Signature Verification Failures

**Symptoms:**
- Events rejected with "signature verification failed"
- High `sequencer.events.rejected` counter

**Investigation:**

1. Check agent key registration:
   ```sql
   SELECT * FROM agent_keys
   WHERE agent_id = '<agent-id>' AND active = true;
   ```

2. Verify key rotation:
   ```sql
   SELECT agent_id, key_id, created_at
   FROM agent_keys
   ORDER BY created_at DESC
   LIMIT 10;
   ```

**Resolution:**

- Ensure agent is using the correct key
- Check clock synchronization (for timestamp validation)
- Verify agent is computing signing hash correctly

### Incident: Sequence Gap Detected

**Symptoms:**
- Commitment creation fails with "non-contiguous sequence"
- Events missing from expected range

**Investigation:**

```sql
-- Find gaps in sequence
WITH seq AS (
  SELECT sequence_number,
         LAG(sequence_number) OVER (ORDER BY sequence_number) as prev_seq
  FROM events
  WHERE tenant_id = '<tenant>' AND store_id = '<store>'
)
SELECT * FROM seq WHERE sequence_number != prev_seq + 1;
```

**Resolution:**

This should NEVER happen in normal operation. If it does:

1. Stop event ingestion for the affected stream
2. Investigate database logs for failed transactions
3. Contact engineering - this may indicate a bug

---

## Database Operations

### Run Migrations

```bash
# Via admin CLI
./stateset-sequencer-admin migrate

# Or set environment variable
export DB_MIGRATE_ON_STARTUP=true
```

### Backup Database

```bash
pg_dump -Fc stateset_sequencer > backup_$(date +%Y%m%d).dump
```

### Restore Database

```bash
pg_restore -d stateset_sequencer backup_20251224.dump
```

### Vacuum and Analyze

```bash
psql -d stateset_sequencer -c "VACUUM ANALYZE events;"
psql -d stateset_sequencer -c "VACUUM ANALYZE ves_events;"
psql -d stateset_sequencer -c "VACUUM ANALYZE commitments;"
```

### Check Index Usage

```sql
SELECT schemaname, tablename, indexname, idx_scan, idx_tup_read
FROM pg_stat_user_indexes
ORDER BY idx_scan DESC;
```

---

## Performance Issues

### High Memory Usage

**Investigation:**

```bash
# Check connection count
psql -c "SELECT count(*) FROM pg_stat_activity;"

# Check cache sizes
curl http://localhost:8080/metrics | grep cache
```

**Resolution:**

- Reduce `MAX_DB_CONNECTIONS`
- Reduce cache sizes
- Check for memory leaks with profiling

### Slow Commitment Creation

**Investigation:**

1. Check event count in range:
   ```sql
   SELECT COUNT(*) FROM events
   WHERE tenant_id = '<tenant>'
     AND store_id = '<store>'
     AND sequence_number BETWEEN <start> AND <end>;
   ```

2. Check Merkle tree size:
   - Large batches (>10,000 events) can be slow
   - Consider smaller commitment windows

**Resolution:**

- Use smaller batch sizes for commitments
- Ensure events table has proper indexes
- Consider async commitment generation

### Database Connection Exhaustion

**Symptoms:**
- "too many connections" errors
- `/ready` endpoint returns 503

**Resolution:**

1. Check connection usage:
   ```sql
   SELECT count(*) FROM pg_stat_activity
   WHERE datname = 'stateset_sequencer';
   ```

2. Kill idle connections:
   ```sql
   SELECT pg_terminate_backend(pid)
   FROM pg_stat_activity
   WHERE datname = 'stateset_sequencer'
     AND state = 'idle'
     AND query_start < NOW() - INTERVAL '10 minutes';
   ```

3. Increase max connections:
   ```sql
   ALTER SYSTEM SET max_connections = 200;
   -- Requires restart
   ```

---

## Recovery Procedures

### Recover from Corrupt Commitment

If a commitment was stored with incorrect data:

1. **DO NOT** delete the commitment (breaks chain)
2. Create a correcting commitment that references the bad one
3. Mark the bad commitment in metadata

### Recover from Dead Letter Events

1. List dead letter events:
   ```sql
   SELECT * FROM dead_letter_events
   ORDER BY created_at DESC
   LIMIT 100;
   ```

2. Investigate failure reason and fix underlying issue

3. Retry via admin endpoint or manual re-ingestion

4. Delete from dead letter queue after successful retry

### Recover from Anchor Service Failure

If L2 anchoring fails:

1. Check circuit breaker status:
   ```bash
   curl http://localhost:8080/metrics | grep circuit
   ```

2. Verify L2 RPC connectivity:
   ```bash
   curl $L2_RPC_URL -X POST \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
   ```

3. Commitments remain unanchored but valid locally

4. Retry anchoring when service recovers:
   ```bash
   curl -X POST http://localhost:8080/api/v1/ves/anchor \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"batch_id": "<batch-id>"}'
   ```

---

## Maintenance Tasks

### Daily

- [ ] Check `/health` and `/ready` endpoints
- [ ] Review error logs for anomalies
- [ ] Check dead letter queue count

### Weekly

- [ ] Review metrics dashboards
- [ ] Check database table sizes
- [ ] Verify backup integrity

### Monthly

- [ ] Run VACUUM ANALYZE on all tables
- [ ] Review and rotate logs
- [ ] Update dependencies (security patches)
- [ ] Test disaster recovery procedures

---

## Contact

- **On-call**: Check PagerDuty rotation
- **Security Issues**: security@stateset.io
- **Documentation**: https://github.com/stateset/stateset-sequencer
