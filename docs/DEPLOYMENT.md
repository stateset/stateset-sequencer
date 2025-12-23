# Deployment Guide

This guide covers deploying the StateSet Sequencer to production environments.

## Deployment Options

1. **Docker Compose** - Single-node deployment (development/staging)
2. **Kubernetes** - Production-grade orchestration
3. **Bare Metal** - Direct binary deployment

## Prerequisites

- PostgreSQL 14+ (16 recommended)
- 4+ GB RAM
- SSD storage (100+ GB recommended)
- TLS certificates for HTTPS

## Docker Compose Deployment

### Basic Setup

```yaml
# docker-compose.yml
version: '3.8'

services:
  sequencer:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgres://sequencer:${DB_PASSWORD}@postgres:5432/stateset_sequencer
      - RUST_LOG=info
      - HOST=0.0.0.0
      - PORT=8080
      - MAX_DB_CONNECTIONS=20
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 10s

  postgres:
    image: postgres:16-alpine
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_USER=sequencer
      - POSTGRES_PASSWORD=${DB_PASSWORD}
      - POSTGRES_DB=stateset_sequencer
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U sequencer -d stateset_sequencer"]
      interval: 5s
      timeout: 5s
      retries: 5

volumes:
  postgres_data:
```

The sequencer runs SQL migrations automatically on startup (disable with `DB_MIGRATE_ON_STARTUP=0` and run `stateset-sequencer-admin migrate` as a separate deploy step if you prefer).

### With TLS and Anchoring

```yaml
version: '3.8'

services:
  sequencer:
    build: .
    ports:
      - "443:8080"
    environment:
      - DATABASE_URL=postgres://sequencer:${DB_PASSWORD}@postgres:5432/stateset_sequencer
      - RUST_LOG=info
      - HOST=0.0.0.0
      - PORT=8080
      - MAX_DB_CONNECTIONS=20
      # Anchoring configuration
      - L2_RPC_URL=${L2_RPC_URL}
      - SET_REGISTRY_ADDRESS=${SET_REGISTRY_ADDRESS}
      - SEQUENCER_PRIVATE_KEY=${SEQUENCER_PRIVATE_KEY}
      - L2_CHAIN_ID=${L2_CHAIN_ID:-84532001}
    volumes:
      - ./certs:/app/certs:ro
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - sequencer
```

## Kubernetes Deployment

### Namespace and ConfigMap

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: stateset
---
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sequencer-config
  namespace: stateset
data:
  HOST: "0.0.0.0"
  PORT: "8080"
  RUST_LOG: "info"
  MAX_DB_CONNECTIONS: "20"
  # Rate limiting
  RATE_LIMIT_PER_MINUTE: "100"
  RATE_LIMIT_MAX_ENTRIES: "10000"
  RATE_LIMIT_WINDOW_SECONDS: "60"
  # Request size limits
  MAX_BODY_SIZE_BYTES: "10485760"       # 10MB
  MAX_EVENTS_PER_BATCH: "1000"
  MAX_EVENT_PAYLOAD_SIZE: "1048576"     # 1MB
  # Schema validation
  SCHEMA_VALIDATION_MODE: "enforce"      # disabled|warn|enforce|required
```

### Secrets

```yaml
# secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: sequencer-secrets
  namespace: stateset
type: Opaque
stringData:
  DATABASE_URL: "postgres://sequencer:password@postgres-service:5432/stateset_sequencer"
  SEQUENCER_PRIVATE_KEY: "0x..."  # Only if using anchoring
```

### Deployment

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sequencer
  namespace: stateset
  labels:
    app: sequencer
spec:
  replicas: 3
  selector:
    matchLabels:
      app: sequencer
  template:
    metadata:
      labels:
        app: sequencer
    spec:
      containers:
      - name: sequencer
        image: stateset/sequencer:latest
        ports:
        - containerPort: 8080
        envFrom:
        - configMapRef:
            name: sequencer-config
        - secretRef:
            name: sequencer-secrets
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchLabels:
                  app: sequencer
              topologyKey: kubernetes.io/hostname
```

### Service

```yaml
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: sequencer-service
  namespace: stateset
spec:
  selector:
    app: sequencer
  ports:
  - port: 80
    targetPort: 8080
  type: ClusterIP
---
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: sequencer-ingress
  namespace: stateset
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - sequencer.stateset.io
    secretName: sequencer-tls
  rules:
  - host: sequencer.stateset.io
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: sequencer-service
            port:
              number: 80
```

### PostgreSQL StatefulSet

```yaml
# postgres-statefulset.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: stateset
spec:
  serviceName: postgres-service
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:16-alpine
        ports:
        - containerPort: 5432
        env:
        - name: POSTGRES_USER
          value: sequencer
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secrets
              key: password
        - name: POSTGRES_DB
          value: stateset_sequencer
        - name: PGDATA
          value: /var/lib/postgresql/data/pgdata
        volumeMounts:
        - name: postgres-data
          mountPath: /var/lib/postgresql/data
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
  volumeClaimTemplates:
  - metadata:
      name: postgres-data
    spec:
      accessModes: ["ReadWriteOnce"]
      storageClassName: ssd
      resources:
        requests:
          storage: 100Gi
```

### Horizontal Pod Autoscaler

```yaml
# hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: sequencer-hpa
  namespace: stateset
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: sequencer
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## PostgreSQL Configuration

### Production Settings

```ini
# postgresql.conf

# Memory
shared_buffers = 4GB
effective_cache_size = 12GB
work_mem = 64MB
maintenance_work_mem = 1GB

# Connections
max_connections = 200

# WAL
wal_level = replica
max_wal_size = 4GB
min_wal_size = 1GB
checkpoint_completion_target = 0.9

# Query Planning
random_page_cost = 1.1  # SSD
effective_io_concurrency = 200

# Logging
log_min_duration_statement = 1000  # Log queries > 1s
log_checkpoints = on
log_connections = on
log_disconnections = on

# Autovacuum
autovacuum_vacuum_scale_factor = 0.05
autovacuum_analyze_scale_factor = 0.025
```

### Backup Strategy

```bash
#!/bin/bash
# backup.sh - Daily backup script

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR=/backups/postgres
PGHOST=localhost
PGUSER=sequencer
PGDATABASE=stateset_sequencer

# Full backup
pg_dump -Fc -f ${BACKUP_DIR}/sequencer_${DATE}.dump

# WAL archiving (for point-in-time recovery)
pg_basebackup -D ${BACKUP_DIR}/base_${DATE} -Ft -z -P

# Cleanup old backups (keep 7 days)
find ${BACKUP_DIR} -name "*.dump" -mtime +7 -delete
find ${BACKUP_DIR} -name "base_*" -mtime +7 -exec rm -rf {} \;
```

## Monitoring

### Prometheus Metrics

Add to your Prometheus configuration:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'sequencer'
    static_configs:
      - targets: ['sequencer-service:8080']
    metrics_path: /metrics
```

### Grafana Dashboard

Key metrics to monitor:

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `sequencer_events_ingested_total` | Total events ingested | - |
| `sequencer_events_rejected_total` | Rejected events | > 10/min |
| `sequencer_sequence_head` | Current sequence number | - |
| `sequencer_ingest_latency_ms` | Ingest latency | p99 > 500ms |
| `sequencer_db_connections` | Active DB connections | > 80% pool |

### Health Check Endpoints

```bash
# Liveness - Is the service running?
curl http://sequencer:8080/health

# Readiness - Is the service ready to accept traffic?
curl http://sequencer:8080/ready
```

### Log Aggregation

Configure structured logging:

```bash
export RUST_LOG=info,stateset_sequencer=debug
```

Example log format:
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "target": "stateset_sequencer::api",
  "message": "Event batch ingested",
  "batch_id": "abc-123",
  "events_accepted": 10,
  "events_rejected": 0
}
```

## Environment Variables

### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgres://user:pass@host:5432/db` |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `8080` | HTTP port |
| `MAX_DB_CONNECTIONS` | `10` | Connection pool size |
| `RUST_LOG` | `info` | Log level |
| `MAX_BODY_SIZE_BYTES` | `10485760` | Max request body size (bytes) |
| `MAX_EVENTS_PER_BATCH` | `1000` | Max events per ingest batch |
| `MAX_EVENT_PAYLOAD_SIZE` | `1048576` | Max per-event payload size (bytes) |
| `VES_SEQUENCER_SIGNING_KEY` | (none) | 32-byte Ed25519 secret key for VES receipt signing (hex or base64) |

### Anchoring (Optional)

| Variable | Description |
|----------|-------------|
| `L2_RPC_URL` | Ethereum L2 RPC endpoint |
| `SET_REGISTRY_ADDRESS` | SetRegistry contract address |
| `SEQUENCER_PRIVATE_KEY` | Private key for anchor transactions |
| `L2_CHAIN_ID` | Target chain ID |

## Security Checklist

- [ ] TLS/HTTPS enabled for all external traffic
- [ ] Database credentials in secrets management
- [ ] Network policies restricting pod communication
- [ ] Resource limits set on all containers
- [ ] Non-root user in Docker image
- [ ] Regular security updates applied
- [ ] Backup encryption enabled
- [ ] Audit logging enabled
- [ ] Rate limiting configured

## Disaster Recovery

### RTO/RPO Targets

| Scenario | RTO | RPO |
|----------|-----|-----|
| Pod failure | < 1 min | 0 (no data loss) |
| Node failure | < 5 min | 0 |
| Database failure | < 30 min | < 5 min |
| Region failure | < 4 hours | < 1 hour |

### Recovery Procedures

**Database Recovery:**
```bash
# Restore from backup
pg_restore -d stateset_sequencer /backups/sequencer_latest.dump

# Point-in-time recovery
pg_restore --target-time="2024-01-15 10:00:00" ...
```

**Application Recovery:**
```bash
# Scale up replicas
kubectl scale deployment sequencer --replicas=5

# Force pod restart
kubectl rollout restart deployment sequencer
```

## Performance Tuning

### Connection Pooling

Recommended settings for high-throughput:

```yaml
environment:
  - MAX_DB_CONNECTIONS=50  # Per instance
  - PGBOUNCER_MAX_CONNECTIONS=200  # If using PgBouncer
```

### Batch Sizing

For optimal throughput, batch events:

```javascript
// Client-side batching
const batch = [];
for (const event of events) {
  batch.push(event);
  if (batch.length >= 100) {
    await client.ingest(batch);
    batch.length = 0;
  }
}
```

### Database Indexes

Ensure these indexes exist:

```sql
-- Event queries
CREATE INDEX CONCURRENTLY idx_events_tenant_store_seq
ON events(tenant_id, store_id, sequence_number);

CREATE INDEX CONCURRENTLY idx_events_entity
ON events(tenant_id, store_id, entity_type, entity_id);

-- Commitment queries
CREATE INDEX CONCURRENTLY idx_commitments_unanchored
ON batch_commitments(tenant_id, store_id)
WHERE chain_tx_hash IS NULL;
```

## Troubleshooting

### Common Issues

**Connection pool exhausted:**
```
Error: "too many connections for role"
```
Solution: Increase `MAX_DB_CONNECTIONS` or add PgBouncer.

**Slow queries:**
```sql
-- Check slow queries
SELECT * FROM pg_stat_statements
ORDER BY total_time DESC
LIMIT 10;
```

**High memory usage:**
```bash
# Check container memory
kubectl top pods -n stateset
```

### Debug Mode

Enable debug logging:
```bash
export RUST_LOG=debug,sqlx=debug
```
