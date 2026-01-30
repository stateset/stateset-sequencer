# StateSet Sequencer Monitoring Guide

This guide explains how to set up monitoring for the StateSet Sequencer using the provided Grafana dashboards.

## Prerequisites

- Kubernetes cluster with Helm installed
- Prometheus Operator installed
- Grafana installed and accessible
- StateSet Sequencer deployed via Helm chart

## Setup

### 1. Deploy the Helm Chart

Deploy the sequencer with metrics enabled (default):

```bash
# Set your database credentials
export DATABASE_URL="postgres://user:password@postgres:5432/stateset_sequencer"
export BOOTSTRAP_ADMIN_API_KEY="your-api-key"

# Install the Helm chart
helm install sequencer ./charts/stateset-sequencer \
  --set env[0].name=DATABASE_URL \
  --set env[0].value=$DATABASE_URL \
  --set env[1].name=BOOTSTRAP_ADMIN_API_KEY \
  --set env[1].value=$BOOTSTRAP_ADMIN_API_KEY
```

### 2. Import the Dashboard

Option 1: Import via Grafana UI
1. Open Grafana
2. Navigate to Dashboards → Import
3. Upload `docs/monitoring/stateset-sequencer-dashboard.json`
4. Select your Prometheus data source

Option 2: Import via Grafana API

```bash
GRAFANA_URL="http://grafana:3000"
GRAFANA_API_KEY="your-api-key"
DATASOURCE_UID="your-prometheus-uid"

curl -X POST "$GRAFANA_URL/api/dashboards/db" \
  -H "Authorization: Bearer $GRAFANA_API_KEY" \
  -H "Content-Type: application/json" \
  -d @docs/monitoring/stateset-sequencer-dashboard.json | \
  jq -r '.datasources[] |= .uid = "'$DATASOURCE_UID'"' | \
  curl -X POST "$GRAFANA_URL/api/dashboards/db" \
    -H "Authorization: Bearer $GRAFANA_API_KEY" \
    -H "Content-Type: application/json" \
    -d @-
```

### 3. Configure Prometheus ServiceMonitor

The Helm chart creates a ServiceMonitor for the Prometheus Operator. Ensure your Prometheus is configured to pick it up:

```bash
# Verify ServiceMonitor was created
kubectl get servicemonitor -n <namespace>
```

### 4. Create Alerts

Add alert rules to your Prometheus configuration:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: sequencer-alerts
  namespace: <namespace>
spec:
  groups:
    - name: sequencer
      rules:
        - alert: SequencerHighErrorRate
          expr: |
            rate(stateset_sequencer_errors_total[5m]) > 0.1
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: High error rate detected
            description: "Error rate is {{ $value }} errors/sec"

        - alert: SequencerHighLatency
          expr: |
            histogram_quantile(0.95, rate(stateset_sequencer_request_duration_seconds_bucket[5m])) > 1
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: High request latency detected
            description: "P95 latency is {{ $value }}s"

        - alert: SequencerDatabasePoolExhausted
          expr: |
            stateset_sequencer_db_pool_active_connections / stateset_sequencer_db_pool_max_connections > 0.9
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: Database pool nearly exhausted
            description: "Pool usage at {{ $value }}"

        - alert: SequencerCircuitBreakerOpen
          expr: |
            stateset_sequencer_circuit_breaker_state{state="open"} == 1
          for: 1m
          labels:
            severity: critical
          annotations:
            summary: Circuit breaker is open
            description: "Circuit breaker for service {{ $labels.service }} is open"

        - alert: SequencerLowThroughput
          expr: |
            rate(stateset_sequencer_events_ingested_total[5m]) < 10
          for: 10m
          labels:
            severity: warning
          annotations:
            summary: Low event throughput
            description: "Events per sec is {{ $value }}"
```

## Dashboard Panels

### Overview Panel
- **Status**: Each service color-coded health status
- **Events/Sec**: Real-time ingestion rate
- **Avg Latency**: P50/P95/P99 latency
- **Error Rate**: Errors per second
- **Pool Usage**: Database connection pool percentage

### Ingestion Rate
- Events ingested per second (total and rates)
- Partitioned by tenant/store

### Request Latency
- Request duration histograms
- P50, P95, P99 quantiles
- Latency trends

### Error Rate
- Total errors
- Errors by category
- Error spikes

### Database Pool
- Active/idle connections
- Pool usage percentage
- Pool health status

### Circuit Breakers
- State for each circuit breaker (Open/Closed/HalfOpen)
- Slow call rate
- Failure rate

### Event Throughput
- Events ingested over time
- Throughput by entity type

### API Key Usage
- Requests per API key
- Rate limit violations

## Troubleshooting

### High Latency
1. Check the Request Latency panel for P95/P99
2. Verify Database Pool Usage
3. Check if circuit breakers are open
4. Review system metrics (CPU, Memory)

### High Error Rate
1. Check Error Breakdown panel
2. Review error types (auth, validation, database)
3. Check database health
4. Review circuit breaker states

### Database Pool Exhaustion
1. Check active connections in Database Pool panel
2. Increase `database.maxConnections` in Helm chart
3. Review slow queries
4. Check for connection leaks

### Circuit Breaker Open
1. Identify which circuit breaker is open
2. Check if external service (L2 chain) is healthy
3. Review failure rates and slow calls
4. Check if service is under attack (rate limiting)

## Performance Tuning

### Database Connection Pool
```yaml
# In values.yaml
database:
  maxConnections: 20
  minIdleConnections: 5
  acquireTimeoutMs: 10000
  idleTimeoutSecs: 600
  maxLifetimeSecs: 1800
```

### Rate Limiting
```yaml
rateLimit:
  perMinute: 1000
  maxEntries: 10000
```

### Circuit Breaker
```yaml
circuitBreaker:
  failureThreshold: 5
  successThreshold: 2
  timeout: 30s
  maxWait: 60s
```

## Additional Resources

- [Grafana Documentation](https://grafana.com/docs/)
- [Prometheus Documentation](https://prometheus.io/docs/)
- [Kubernetes Metrics](https://kubernetes.io/docs/tasks/debug/debug-cluster/resource-usage-monitoring/)
- [Helm Chart Configuration](HELM_DEPLOYMENT.md)