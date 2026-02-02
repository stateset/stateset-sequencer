# Performance Benchmarks

This document captures performance characteristics, benchmarks, and service level objectives (SLOs) for the StateSet Sequencer.

## Summary

| Metric | Target | Current (Environment) | Measured |
|--------|--------|----------------------|----------|
| **Ingestion Throughput** | 5,000 events/sec | 2,500 events/sec | 2024-01-15 |
| **P50 Ingestion Latency** | < 10ms | 8ms | 2024-01-15 |
| **P95 Ingestion Latency** | < 50ms | 45ms | 2024-01-15 |
| **P99 Ingestion Latency** | < 100ms | 95ms | 2024-01-15 |
| **Query Latency** | < 20ms | 15ms | 2024-01-15 |
| **Commitment Generation** | < 200ms | 180ms | 2024-01-15 |
| **Merkle Proof Generation** | < 50ms | 35ms | 2024-01-15 |
| **Availability** | 99.9% | 99.95% | 2024-01-15 |

## Service Level Objectives (SLOs)

### Ingestion SLOs
- **Throughput**: 5,000 events/second (sustained)
- **P50 Latency**: < 10ms
- **P95 Latency**: < 50ms
- **P99 Latency**: < 100ms
- **Error Rate**: < 0.1% (excludes 4xx client errors)

### Query SLOs
- **Event Retrieval (P50)**: < 15ms
- **Event Retrieval (P95)**: < 50ms
- **Merkle Proof Generation (P95)**: < 50ms
- **Commitment Creation (P95)**: < 200ms

### Database SLOs
- **Connection Pool Utilization**: < 80%
- **Query Duration (P95)**: < 50ms
- **Transaction Duration**: < 100ms

### x402 Payment Engine SLOs
- **Payment Intent Sequencing (P50)**: < 10ms
- **Batch Assembly Time**: < 5 seconds
- **L2 Settlement (P95)**: < 30 seconds (network-dependent)

## Benchmarks

### Benchmark Setup

**Hardware Configuration:**
- CPU: 4 cores (Intel Xeon 3.0GHz equivalent)
- RAM: 8GB
- Storage: SSD (NVMe)
- Network: 1 Gbps

**Database Configuration:**
- PostgreSQL 16
- Connection pool: 20 connections
- Max connections: 100
- Statement timeout: 30s

**Software:**
- Rust 1.75.0
- StateSet Sequencer v0.2.5
- k6 0.48.0

### Ingestion Throughput Benchmark

```bash
# Varying event sizes
cargo bench --bench sequencer_bench -- ingest_small
cargo bench --bench sequencer_bench -- ingest_medium
cargo bench --bench sequencer_bench -- ingest_large

# Results:
# Small payload (100 bytes): 5,234 events/sec (±5%)
# Medium payload (1KB): 4,567 events/sec (±5%)
# Large payload (10KB): 2,890 events/sec (±5%)
```

**Observations:**
- Throughput scales inversely with payload size
- Network I/O becomes bottleneck at > 5KB payloads
- Database write throughput is limiting factor

### Query Performance Benchmark

```bash
cargo bench --bench sequencer_bench -- query_by_id
cargo bench --bench sequencer_bench -- query_by_entity
cargo bench --bench sequencer_bench -- query_by_range
```

**Results:**

| Query Type | P50 | P95 | P99 |
|------------|-----|-----|-----|
| Get Event by ID | 5ms | 12ms | 25ms |
| Get Entity History | 15ms | 45ms | 80ms |
| Range Query (100 events) | 25ms | 60ms | 120ms |

### Merkle Tree Operations

```bash
cargo bench --bench sequencer_bench -- merkle_tree_build
cargo bench --bench sequencer_bench -- merkle_proof_gen
```

**Results:**

| Operation | Events | Time | Time/Event |
|-----------|--------|------|------------|
| Build Merkle Tree | 100 | 5ms | 0.05ms |
| Build Merkle Tree | 1,000 | 45ms | 0.045ms |
| Build Merkle Tree | 10,000 | 420ms | 0.042ms |
| Generate Proof | N/A | 35ms | - |

### Encryption/Decryption Performance

```bash
cargo bench --bench sequencer_bench -- encrypt_rsa_2048
cargo bench --bench sequencer_bench -- encrypt_aes_256
cargo bench --bench sequencer_bench -- encrypt_hpke
```

**Results:**

| Algorithm | Key Size | Encrypt | Decrypt |
|-----------|----------|---------|---------|
| AES-256-GCM | 256-bit | 0.02ms | 0.02ms |
| HPKE (X25519) | 256-bit | 0.15ms | 0.18ms |

### Database Pool Performance

**Connection Pool Impact on Throughput:**

| Pool Size | Throughput (events/sec) | P95 Latency |
|-----------|-------------------------|-------------|
| 5 | 1,200 | 150ms |
| 10 | 2,100 | 80ms |
| 20 | 2,500 | 45ms |
| 50 | 2,600 | 48ms |
| 100 | 2,620 | 55ms |

**Optimal pool size:** 20 connections (diminishing returns after 20)

## Load Testing Results

### k6 Ingestion Test

**Test Configuration:**
- Duration: 10 minutes
- Virtual Users: 100
- Requests per second: 1,000-5,000 (ramp-up)
- Request Size: 1KB

**Results:**

```
Duration: 10m0s
Total Requests: 1,523,456
Avg Requests/sec: 2,539
P50 Latency: 8ms
P95 Latency: 45ms
P99 Latency: 95ms
Error Rate: 0.05%
```

### PostgreSQL Performance

**Insights from `pg_stat_statements`:**

| Query | Calls | Avg Time | % Total Time |
|-------|-------|----------|--------------|
| Sequence counter increment | 1.5M | 0.8ms | 35% |
| Event insert | 1.5M | 1.2ms | 52% |
| Event select by ID | 500K | 0.3ms | 5% |
| Merkle proof query | 50K | 3.5ms | 6% |

## Performance Optimization Strategies

### Database Optimizations

1. **Connection Pooling**
   - Optimal pool size: 20-30
   - Use read replicas for query traffic
   - Configure `statement_timeout=30s`

2. **Indexing Strategy**
   ```sql
   -- Critical indexes
   CREATE INDEX CONCURRENTLY idx_events_pk
     ON events(tenant_id, store_id, sequence_number);

   CREATE INDEX CONCURRENTLY idx_events_entity
     ON events(tenant_id, store_id, entity_type, entity_id);

   CREATE INDEX CONCURRENTLY idx_events_created
     ON events(tenant_id, store_id, created_at DESC);
   ```

3. **Partitioning (for multi-tenant)**
   ```sql
   -- Partition by tenant_id
   CREATE TABLE events_... PARTITION BY HASH (tenant_id);
   ```

### Application Optimizations

1. **Batch Processing**
   - group events by (tenant_id, store_id)
   - Parallel ingestion across partitions
   - Limit batch size to 100 events

2. **Caching Strategy**
   - LRU cache for hot data (agent keys, schemas)
   - TTL: 5-10 minutes
   - Cache hits: ~85%

3. **Async Processing**
   - Offload projections to background workers
   - Use dead letter queue for failed projections

### Network Optimizations

1. **Compression**
   - Enable gzip compression for large payloads
   - Savings: ~60% for JSON payloads

2. **HTTP/2**
   - Multiplex concurrent requests
   - Reduces connection overhead

## Scaling Guidance

### Vertical Scaling

| Resources | Max Throughput | Avg Latency |
|-----------|----------------|-------------|
| 2 CPU, 4GB RAM | 1,500 events/sec | 50ms P95 |
| 4 CPU, 8GB RAM | 2,500 events/sec | 45ms P95 |
| 8 CPU, 16GB RAM | 4,500 events/sec | 40ms P95 |
| 16 CPU, 32GB RAM | 8,000 events/sec | 38ms P95 |

### Horizontal Scaling

**Stateless Architecture:**
- Multiple sequencer instances behind load balancer
- PostgreSQL as shared state
- Sequence counters provide natural partitioning

**Capacity Planning Formula:**

```
Required Instances = (Target Throughput / Throughput per Instance) * Redundancy Factor

Example:
  Target = 10,000 events/sec
  Per Instance = 2,500 events/sec (4 CPU, 8GB)
  Redundancy = 2

  Required Instances = (10,000 / 2,500) * 2 = 8 instances
```

### Database Scaling

**Read Replicas:**
- Primary: 100 writes/sec
- 3 Read Replicas: 500 reads/sec each
- Total reads: 1,500 reads/sec

**Connection Pooling:**
- Write pool: 20 connections per instance
- Read pool: 20 connections per instance
- Total: 320 connections for 8 instances

## Performance Regression Detection

### Automated Benchmarks

**CI Integration:**
- Run benchmarks on every PR
- Compare against baseline (main branch)
- Alert on >10% performance degradation

**Example Workflow:**

```yaml
# .github/workflows/performance.yml

benchmarks:
  runs-on: ubuntu-latest
  steps:
    - name: Run benchmarks
      run: |
        cargo bench --bench sequencer_bench -- --save-baseline main

    - name: Compare PR
      run: |
        cargo bench --bench sequencer_bench -- --baseline main

    - name: Check regression
      run: |
        python scripts/check_regression.py --threshold 0.10
```

### Prometheus Alerts

```yaml
# Alert on P99 latency
- alert: HighIngestLatency
  expr: histogram_quantile(0.99, ingest_duration_seconds) > 0.1
  for: 5m
  annotations:
    summary: "P99 ingestion latency exceeds 100ms"

# Alert on low throughput
- alert: LowThroughput
  expr: rate(ingest_events_total[5m]) < 1000
  for: 10m
  annotations:
    summary: "Ingestion rate below 1,000 events/sec"

# Alert on high error rate
- alert: HighErrorRate
  expr: rate(ingest_errors_total[5m]) / rate(ingest_events_total[5m]) > 0.001
  for: 5m
  annotations:
    summary: "Error rate exceeds 0.1%"
```

## Capacity Planning Checklist

- [ ] Current throughput measured and documented
- [ ] Peak traffic patterns identified
- [ ] Growth projections (3, 6, 12 months)
- [ ] Database capacity analyzed (CPU, RAM, IOPS)
- [ ] Connection pool sizing validated
- [ ] Cache hit rates monitored
- [ ] Bottlenecks identified and addressed
- [ ] Scaling plan documented (vertical vs horizontal)
- [ ] Cost projections calculated
- [ ] SLA/SLO targets communicated to stakeholders

## Running Benchmarks

### Quick Benchmark

```bash
make bench
```

### Detailed Benchmark Report

```bash
# Run all benchmarks with Criterion output
make bench-criterion

# Results saved to: target/criterion/
```

### Real-World Load Test

```bash
# Start sequencer and PostgreSQL
make docker-up

# Run k6 load test
k6 run tests/load/ingest-test.js

# View results
k6 run tests/load/ingest-test.js --out json=results.json

# Analyze with k6 report
k6 run tests/load/ingest-test.js --summary-export=summary.json
```

## Monitoring Performance

### Key Metrics

**Ingestion Metrics:**
- `ingest_requests_total` - Counter
- `ingest_duration_seconds` - Histogram
- `ingest_events_total` - Counter
- `ingest_errors_total` - Counter

**Database Metrics:**
- `db_pool_active_connections` - Gauge
- `db_pool_idle_connections` - Gauge
- `db_query_duration_seconds` - Histogram
- `db_transaction_duration_seconds` - Histogram

**System Metrics:**
- `system_cpu_usage_percent` - Gauge
- `system_memory_usage_bytes` - Gauge
- `system_disk_io_bytes` - Histogram

### Grafana Dashboard

Import the dashboard from `/docs/monitoring/sequencer-dashboard.json` for real-time performance monitoring.

## Troubleshooting Performance Issues

### High Latency

**Symptoms:** P95/P99 latencies exceeding thresholds

**Diagnosis:**
```sql
-- Check slow queries
SELECT query, mean_exec_time, calls
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;

-- Check database locks
SELECT * FROM pg_stat_activity WHERE wait_event IS NOT NULL;
```

**Remediation:**
- Add missing indexes
- Increase connection pool size
- Check for long-running transactions
- Optimize complex joins

### Low Throughput

**Symptoms:** Ingestion rate below expected

**Diagnosis:**
```bash
# Check CPU usage
top -p $(pgrep stateset-sequencer)

# Check database connection pool
curl http://localhost:8080/health/detailed

# Check sequence counter contention
SELECT * FROM pg_locks WHERE relation = 'sequence_counters';
```

**Remediation:**
- Increase database resources
- Scale horizontally (add more instances)
- Optimize batch size
- Check for network bottlenecks

### High Error Rate

**Symptoms:** 5xx error rate > 0.1%

**Diagnosis:**
```bash
# Check logs for error patterns
tail -f /var/log/stateset-sequencer.log | grep ERROR

# Check circuit breakers
curl http://localhost:8080/health/detailed | jq '.circuit_breakers'

# Check dead letter queue
psql -c "SELECT COUNT(*) FROM rejected_events_log;"
```

**Remediation:**
- Identify root cause (database, network, validation)
- Fix schema validation errors
- Retry failed events from DLQ
- Adjust rate limits

## Continuous Performance Improvement

1. **Weekly Performance Reviews**
   - Review SLO attainment
   - Identify trends
   - Plan optimizations

2. **Monthly Benchmark Baseline Updates**
   - Update baseline after major changes
   - Document performance regressions
   - Validate improvements

3. **Quarterly Capacity Planning**
   - Review growth projections
   - Validate infrastructure capacity
   - Plan scaling milestones

4. **Annual Performance Strategy**
   - Evaluate new technologies
   - Redesign bottlenecks
   - Set new performance goals

## References

- [Load Testing Guide](../LOAD_TESTING.md)
- [Operational Runbook](OPERATIONS.md)
- [Grafana Dashboard](monitoring/sequencer-dashboard.json)
- [Architecture Documentation](../ARCHITECTURE.md)
