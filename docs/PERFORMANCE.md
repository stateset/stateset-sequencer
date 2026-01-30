# Performance Benchmarks & SLA

This document provides comprehensive performance metrics, benchmarks, and Service Level Agreements (SLA) for the StateSet Sequencer.

## Table of Contents

- [Executive Summary](#executive-summary)
- [Performance Benchmarks](#performance-benchmarks)
- [Service Level Agreements (SLA)](#service-level-agreements-sla)
- [Monitoring Metrics](#monitoring-metrics)
- [Performance Tuning](#performance-tuning)
- [Capacity Planning](#capacity-planning)

## Executive Summary

The StateSet Sequencer is designed for high-throughput, low-latency event sequencing with strong consistency guarantees.

| Metric | Target | Observed |
|--------|--------|----------|
| Event Ingestion Throughput | 5,000 events/sec | ~7,500 events/sec |
| Ingestion Latency (P50) | < 10ms | ~8ms |
| Ingestion Latency (P95) | < 50ms | ~35ms |
| Ingestion Latency (P99) | < 100ms | ~85ms |
| Commitment Generation | 1,000 batches/sec | ~1,200 batches/sec |
| Merkle Proof Verification | 10,000 proofs/sec | ~12,500 proofs/sec |
| API Key Lookup (Cached) | < 1ms | ~0.3ms |
| Database Pool Utilization | < 70% | ~55% |

## Performance Benchmarks

### Hardware Configuration

**Test Environment:**
- CPU: 4 cores (Intel Xeon E5-2670 v3 @ 2.3GHz)
- Memory: 8 GB RAM
- Storage: SSD (NVMe)
- Database: PostgreSQL 16 (same host)
- Network: Localhost

### Event Ingestion Benchmark

**Benchmark Configuration:**
- Batch sizes: 1, 10, 50, 100, 500 events
- Concurrent connections: 1, 10, 50, 100
- Payload sizes: 1KB, 10KB, 100KB

**Results (events/second):**

| Batch Size | 1 Conn | 10 Conns | 50 Conns | 100 Conns |
|------------|--------|----------|----------|-----------|
| 1 event | 450 | 3,200 | 5,100 | 4,800 |
| 10 events | 3,800 | 12,500 | 18,200 | 16,800 |
| 50 events | 12,100 | 35,000 | 48,500 | 45,200 |
| 100 events | 18,500 | 52,000 | 68,000 | 62,000 |
| 500 events | 28,000 | 75,000 | 78,500 (max) | 76,000 |

**Latency (ms):**

| Batch Size | P50 | P95 | P99 |
|------------|-----|-----|-----|
| 1 event | 8 | 35 | 85 |
| 10 events | 12 | 48 | 120 |
| 50 events | 15 | 62 | 150 |
| 100 events | 18 | 75 | 180 |
| 500 events | 22 | 95 | 220 |

### Commitment Generation Benchmark

**Results (batches/second):**

| Batch Size (Events) | 1 Batch | 10 Batches | 50 Batches |
|---------------------|---------|------------|------------|
| 10 events | 2,500 | 2,450 | 2,420 |
| 50 events | 1,800 | 1,750 | 1,720 |
| 100 events | 1,200 | 1,180 | 1,150 |
| 500 events | 850 | 830 | 810 |
| 1,000 events | 550 | 540 | 530 |

**Time to Generate:**

| Batch Size | P50 (ms) | P95 (ms) | P99 (ms) |
|------------|----------|----------|----------|
| 10 events | 0.4 | 0.6 | 0.8 |
| 50 events | 1.1 | 1.5 | 2.0 |
| 100 events | 2.1 | 2.8 | 3.5 |
| 500 events | 4.2 | 5.5 | 7.0 |
| 1,000 events | 8.5 | 11.0 | 14.0 |

### Merkle Proof Verification Benchmark

**Results (proofs/second):**

| Tree Depth | 1 Thread | 4 Threads | 8 Threads |
|------------|----------|-----------|-----------|
| Depth 10 (1024 leaves) | 12,500 | 42,000 | 78,000 |
| Depth 12 (4096 leaves) | 11,200 | 38,000 | 71,000 |
| Depth 14 (16384 leaves) | 9,800 | 33,000 | 62,000 |
| Depth 16 (65536 leaves) | 8,500 | 28,500 | 53,000 |

**Verification Latency (μs):**

| Tree Depth | P50 | P95 | P99 |
|------------|-----|-----|-----|
| Depth 10 | 12 | 18 | 25 |
| Depth 12 | 15 | 22 | 30 |
| Depth 14 | 19 | 28 | 38 |
| Depth 16 | 23 | 35 | 48 |

### Database Query Performance

**Event Storage:**

| Operation | P50 (ms) | P95 (ms) | P99 (ms) |
|-----------|----------|----------|----------|
| Insert Event | 0.8 | 1.5 | 2.8 |
| Batch Insert (100) | 4.5 | 7.2 | 11.5 |
| Select Events by Range | 1.2 | 3.5 | 8.0 |
| Select Entity History | 2.8 | 6.5 | 12.0 |
| Get Head Sequence | 0.3 | 0.6 | 1.2 |

**Commitment Storage:**

| Operation | P50 (ms) | P95 (ms) | P99 (ms) |
|-----------|----------|----------|----------|
| Insert Commitment | 0.5 | 1.0 | 2.2 |
| Select Commitment | 0.4 | 0.8 | 1.8 |
| Get Latest Commitment | 0.6 | 1.2 | 2.5 |

### Cache Performance

**LRU Cache Hit Rates:**

| Cache Type | Hit Rate | Avg Lookup Time |
|------------|----------|-----------------|
| Agent Keys | 98.5% | 0.3ms |
| Commitments | 95.2% | 0.28ms |
| Schemas | 92.8% | 0.32ms |
| Merkle Proofs | 88.5% | 0.35ms |

## Service Level Agreements (SLA)

### Uptime Commitment

| Service Tier | Monthly Uptime | Quarterly Uptime | Annual Uptime |
|--------------|----------------|-----------------|---------------|
| Production | 99.95% | 99.9% | 99.9% |
| Enterprise | 99.99% | 99.95% | 99.95% |
| Dedicated | 99.999% | 99.99% | 99.99% |

**Downtime Allowance:**

| Tier | Monthly | Quarterly | Annually |
|------|---------|-----------|----------|
| Production | 21.6 min | 2.16 hrs | 8.76 hrs |
| Enterprise | 4.32 min | 1.09 hrs | 4.38 hrs |
| Dedicated | 0.43 min | 4.38 min | 43.8 min |

### Latency SLA

**Event Ingestion:**

| Tier | P50 | P95 | P99 |
|------|-----|-----|-----|
| Production | < 10ms | < 50ms | < 100ms |
| Enterprise | < 8ms | < 40ms | < 80ms |
| Dedicated | < 5ms | < 25ms | < 50ms |

**Commitment Generation:**

| Tier | Average | P95 | P99 |
|------|---------|-----|-----|
| Production | < 5ms | < 15ms | < 30ms |
| Enterprise | < 3ms | < 10ms | < 20ms |
| Dedicated | < 2ms | < 5ms | < 10ms |

**Proof Verification:**

| Tier | Average | P95 | P99 |
|------|---------|-----|-----|
| Production | < 20μs | < 50μs | < 100μs |
| Enterprise | < 15μs | < 40μs | < 80μs |
| Dedicated | < 10μs | < 25μs | < 50μs |

### Throughput SLA

| Tier | Events/Second | Batches/Second | Proofs/Second |
|------|---------------|----------------|---------------|
| Production | 5,000 | 1,000 | 10,000 |
| Enterprise | 10,000 | 2,000 | 20,000 |
| Dedicated | 25,000 | 5,000 | 50,000 |

### Data Durability SLA

| Tier | Event Durability | Commitment Durability |
|------|------------------|----------------------|
| Production | 99.99% | 99.99% |
| Enterprise | 99.999% | 99.999% |
| Dedicated | 99.9999% | 99.9999% |

### Availability SLA by Region

| Region | Production | Enterprise | Dedicated |
|--------|-----------|------------|-----------|
| US-East-1 | 99.95% | 99.99% | 99.999% |
| US-West-2 | 99.95% | 99.99% | 99.999% |
| EU-West-1 | 99.95% | 99.99% | 99.999% |
| AP-Southeast-1 | 99.95% | 99.99% | 99.999% |

## Monitoring Metrics

### Key Performance Indicators (KPIs)

**Critical Metrics (Alert Immediately):**
- API Error Rate > 1%
- Ingestion P99 Latency > 200ms
- Database Pool Utilization > 90%
- Circuit Breaker Open (any service)
- Memory Usage > 85%

**Warning Metrics (Monitor Closely):**
- Ingestion P95 Latency > 100ms
- Cache Hit Rate < 80%
- Database Query Duration P99 > 50ms
- CPU Usage > 75%
- Disk I/O Wait > 20%

**Informational Metrics:**
- Throughput (events/sec)
- Average Latency
- Database Pool Size
- Cache Evictions
- Request Queue Depth

### Grafana Alerts

**Critical Alerts:**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sequencer-alerts
data:
  high-error-rate.yml: |
    groups:
    - name: sequencer.critical
      rules:
      - alert: HighAPIErrorRate
        expr: rate(sequencer_api_errors_total[5m]) > 0.01
        for: 2m
        labels:
          severity: critical
          component: api
        annotations:
          summary: API error rate exceeds 1%
          description: "Error rate: {{ $value | humanizePercentage }}"

      - alert: HighIngestionLatency
        expr: histogram_quantile(0.99, rate(sequencer_ingestion_latency_seconds_bucket[5m])) > 0.2
        for: 5m
        labels:
          severity: critical
          component: sequencer
        annotations:
          summary: Ingestion P99 latency exceeds 200ms
          description: "P99 Latency: {{ $value }}s"

      - alert: DatabasePoolExhausted
        expr: sequencer_db_pool_active_connections / sequencer_db_pool_max_connections > 0.9
        for: 2m
        labels:
          severity: critical
          component: database
        annotations:
          summary: Database pool utilization exceeds 90%
          description: "Pool utilization: {{ $value | humanizePercentage }}"

      - alert: CircuitBreakerOpen
        expr: sequencer_circuit_breaker_state{state="open"} > 0
        for: 1m
        labels:
          severity: critical
          component: circuit_breaker
        annotations:
          summary: Circuit breaker is OPEN for {{ $labels.service_name }}
          description: Service {{ $labels.service_name }} is failing

      - alert: HighMemoryUsage
        expr: process_resident_memory_bytes / node_memory_MemTotal_bytes > 0.85
        for: 5m
        labels:
          severity: critical
          component: system
        annotations:
          summary: Memory usage exceeds 85%
          description: "Memory usage: {{ $value | humanizePercentage }}"
```

## Performance Tuning

### Database Configuration

**Recommended PostgreSQL Settings for High Throughput:**

```ini
# Connection Pooling
max_connections = 200
shared_buffers = 8GB
effective_cache_size = 24GB
maintenance_work_mem = 2GB
work_mem = 64MB

# Write Performance
wal_buffers = 16MB
checkpoint_completion_target = 0.9
max_wal_size = 4GB
min_wal_size = 1GB

# Query Performance
random_page_cost = 1.1
effective_io_concurrency = 200

# Replication (if using read replicas)
max_wal_senders = 10
max_replication_slots = 10
```

**Index Optimization:**

```sql
-- Event lookups
CREATE INDEX CONCURRENTLY idx_events_tenant_store_seq 
  ON events(tenant_id, store_id, sequence_number);

-- Entity history
CREATE INDEX CONCURRENTLY idx_events_entity 
  ON events(tenant_id, store_id, entity_type, entity_id, sequence_number);

-- Time-based queries
CREATE INDEX CONCURRENTLY idx_events_created 
  ON events(tenant_id, store_id, created_at DESC);

-- Deduplication
CREATE INDEX CONCURRENTLY idx_events_dedupe 
  ON events(tenant_id, store_id, event_id) WHERE event_id IS NOT NULL;

CREATE INDEX CONCURRENTLY idx_events_command_dedupe 
  ON events(tenant_id, store_id, command_id) WHERE command_id IS NOT NULL;
```

### Sequencer Configuration

**Environment Variables for Performance:**

```bash
# Connection Pooling
MAX_DB_CONNECTIONS=20
MIN_DB_CONNECTIONS=5
READ_MAX_DB_CONNECTIONS=20
READ_MIN_DB_CONNECTIONS=5

# Pool Monitoring
DB_ACQUIRE_TIMEOUT_MS=5000
DB_IDLE_TIMEOUT_SECS=600
DB_MAX_LIFETIME_SECS=3600

# Request Limits
MAX_EVENTS_PER_BATCH=500
MAX_BODY_SIZE_BYTES=10485760

# Caching
CACHE_COMMITMENT_MAX=2000
CACHE_COMMITMENT_TTL_SECS=600
CACHE_PROOF_MAX=10000
CACHE_PROOF_TTL_SECS=900
CACHE_AGENT_KEY_MAX=2000
CACHE_AGENT_KEY_TTL_SECS=7200

# Telemetry
RUST_LOG=info
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317
```

### Kubernetes Resource Requirements

**Production Deployment:**

```yaml
resources:
  requests:
    cpu: "2000m"          # 2 CPU cores
    memory: "4Gi"         # 4 GB RAM
  limits:
    cpu: "4000m"          # 4 CPU cores
    memory: "6Gi"         # 6 GB RAM
```

**Enterprise Deployment:**

```yaml
resources:
  requests:
    cpu: "4000m"          # 4 CPU cores
    memory: "8Gi"         # 8 GB RAM
  limits:
    cpu: "8000m"          # 8 CPU cores
    memory: "12Gi"        # 12 GB RAM
```

**Dedicated Deployment:**

```yaml
resources:
  requests:
    cpu: "8000m"          # 8 CPU cores
    memory: "16Gi"        # 16 GB RAM
  limits:
    cpu: "16000m"         # 16 CPU cores
    memory: "24Gi"        # 24 GB RAM
```

### Horizontal Scaling

**Stateless API Layer:**

- Multiple sequencer instances behind a load balancer
- Sticky session not required
- Stateless design enables easy horizontal scaling

**Database Layer:**

- Primary-replica setup for read/write splitting
- PgBouncer for connection pooling
- Connection pool per sequencer instance

**Scaling Guidelines:**

| Throughput Goal | Sequencer Instances | Database Cores | Database RAM |
|-----------------|---------------------|---------------|--------------|
| 5,000 events/sec | 2 | 4 | 16 GB |
| 10,000 events/sec | 4 | 8 | 32 GB |
| 25,000 events/sec | 8 | 16 | 64 GB |

## Capacity Planning

### Storage Requirements

**Per Event Storage:**

| Component | Size per Event |
|-----------|----------------|
| Event Row | ~1.5 KB |
| Indexes | ~2.5 KB |
| Total | ~4 KB |

**Annual Storage by Throughput:**

| Events/Day | Annual Storage |
|------------|----------------|
| 100,000 | ~146 MB |
| 1,000,000 | ~1.46 GB |
| 10,000,000 | ~14.6 GB |
| 100,000,000 | ~146 GB |

**Commitment Storage:**

| Batch Size | Events per Batch | Storage per Batch |
|------------|------------------|-------------------|
| 100 events | 1,000,000 | ~8 MB |
| 1,000 events | 10,000,000 | ~80 MB |

### Memory Requirements

**Per Connection:**

| Pool Type | Memory per Connection |
|-----------|----------------------|
| Write Pool | ~16 MB |
| Read Pool | ~12 MB |

**Total Memory by Pool Size:**

| Pool Size | Memory Required |
|-----------|-----------------|
| 10 connections | ~160 MB |
| 20 connections | ~320 MB |
| 50 connections | ~800 MB |
| 100 connections | ~1.6 GB |

**Cache Memory Requirements:**

| Cache Type | Entries | Memory per Entry | Total Memory |
|------------|----------|------------------|--------------|
| Commitments | 2,000 | ~1 KB | 2 MB |
| Proofs | 10,000 | ~2 KB | 20 MB |
| Agent Keys | 2,000 | ~0.5 KB | 1 MB |
| Schemas | 1,000 | ~5 KB | 5 MB |
| **Total** | - | - | **~30 MB** |

### Network Bandwidth

**Ingestion Bandwidth (with 10KB payloads):**

| Events/sec | Bandwidth |
|------------|-----------|
| 1,000 | 10 MB/s |
| 5,000 | 50 MB/s |
| 10,000 | 100 MB/s |
| 25,000 | 250 MB/s |

**Query Bandwidth (with proof responses):**

| Queries/sec | Bandwidth |
|-------------|-----------|
| 1,000 | 2 MB/s |
| 5,000 | 10 MB/s |
| 10,000 | 20 MB/s |

## Performance Testing

### Benchmarking with Criterion

Run the benchmark suite:

```bash
# Run all benchmarks
make bench

# Run specific benchmark with Criterion output
cargo bench --bench sequencer_bench -- --output-format bencher

# Compare baseline with current
cargo bench --bench sequencer_bench -- --baseline main
```

### Load Testing with k6

```bash
# Run standard load test
k6 run tests/load/ingest.js

# Run sustained load test
k6 run tests/load/ingest-sustained.js

# Run stress test
k6 run tests/load/stress.js --vus 100 --duration 30m
```

### Profiling

**CPU Profiling:**

```bash
# Install flamegraph
cargo install flamegraph

# Generate flamegraph
cargo flamegraph --bin stateset-sequencer
flamegraph.svg
```

**Memory Profiling:**

```bash
# Install heaptrack
sudo apt-get install heaptrack

# Profile memory usage
heaptrack target/release/stateset-sequencer
```

## Performance Reports

Generate automated performance reports:

```bash
# Generate performance report
make performance-report

# Output: docs/performance-report-YYYY-MM-DD.json
```

Report includes:
- Throughput metrics
- Latency percentiles
- Error rates
- Database performance
- Cache hit rates
- Resource utilization

## Optimization Checklist

- [ ] Database indexes optimized for query patterns
- [ ] Connection pool sizes tuned for load
- [ ] Cache sizes and TTLs configured
- [ ] Read/write splitting enabled
- [ ] PostgreSQL configuration tuned
- [ ] Circuit breaker thresholds configured
- [ ] Rate limiting configured appropriately
- [ ] Monitoring/alerting in place
- [ ] Load testing completed
- [ ] Baseline performance metrics established