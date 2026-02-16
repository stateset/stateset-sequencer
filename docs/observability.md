# Observability and SLOs

StateSet Sequencer exposes Prometheus‑compatible metrics and health endpoints, and ships
starter alert rules for production SLOs.

## Endpoints

- `GET /health` — liveness check
- `GET /ready` — readiness check
- `GET /health/detailed` — authenticated readiness + DB health
- `GET /metrics` — Prometheus metrics (admin only, see below)

## Metrics Access Control

Metrics and admin endpoints are protected by auth and optional IP allowlisting.

Environment variables:

- `AUTH_MODE=required` (default), or `AUTH_MODE=disabled` with `ALLOW_AUTH_DISABLED=true`
- `BOOTSTRAP_ADMIN_API_KEY` or JWT for admin access
- `ADMIN_IP_ALLOWLIST` — comma‑separated list of IPs or CIDRs (e.g. `203.0.113.10,10.0.0.0/8`)
- `TRUST_PROXY_HEADERS=true` — trust `x-forwarded-for`, `x-real-ip`, `forwarded` (only behind trusted proxies)

## Suggested SLOs (baseline)

See `docs/SLO.md` for the current initial targets and review cadence.

## Alert Rules

GKE (Google Managed Prometheus):

`k8s/gmp/rules.yaml`

Prometheus Operator:

- Use `docs/monitoring/MONITORING_GUIDE.md` as a starting point for a `PrometheusRule`

They cover:

- 5xx error‑rate spikes
- p95 latency for ingest and read paths
- DB pool saturation and timeouts

## Useful Metrics (Prometheus names)

HTTP:

- `sequencer_http_requests_total{method,path,status}`
- `sequencer_http_request_latency_seconds_bucket{method,path,status,le}`

DB Pool:

- `sequencer_pool_utilization`
- `sequencer_pool_timed_out_acquisitions`
- `sequencer_pool_acquisition_latency_ms_bucket`

Ingest + Commitments:

- `sequencer_events_ingested`
- `sequencer_events_sequenced`
- `sequencer_commitments_created`

## Dashboards

Recommended panels:

- Request rate, error rate, latency (p50/p95/p99)
- DB pool utilization + acquire latency
- Sequencer head growth vs projection lag
- Anchoring success/failures (if enabled)

If you want, we can generate a Grafana dashboard JSON with these panels.
