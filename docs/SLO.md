# Service Level Objectives (SLOs)

This document defines the initial SLOs for the StateSet Sequencer. Targets should be validated
against real traffic and adjusted as production data matures.

## Scope

- REST API endpoints under `/api/v1/*`
- Public health endpoints `/health` and `/ready`
- Ingestion endpoints: `/v1/events/ingest`, `/v1/ves/events/ingest`

## SLIs

### Availability

**SLI:** Successful requests / total requests

- Success: HTTP 2xx/3xx
- Failure: HTTP 5xx

### Latency

**SLI:** Request duration measured at the server for primary endpoints

- Metric: `sequencer_http_request_latency_seconds` (histogram, labeled by `method`, `path`, `status`)

## SLO Targets (Initial)

| SLO | Target | Window |
|-----|--------|--------|
| API availability | 99.9% | 30 days |
| Readiness availability (`/ready`) | 99.9% | 30 days |
| Ingest latency p95 (`/v1/events/ingest`) | ≤ 500ms | 7 days |
| VES ingest latency p95 (`/v1/ves/events/ingest`) | ≤ 750ms | 7 days |
| Read latency p95 (`/v1/head`, `/v1/events`) | ≤ 200ms | 7 days |

## Error Budget

For a 30‑day window with 99.9% availability:

- Error budget = 0.1% of total requests
- Budget burn alerting should page when > 50% budget is consumed in 24h

## Alerting

See `docs/monitoring/MONITORING_GUIDE.md` for example Prometheus rules. Alerts should cover:

- Availability drop below SLO
- p95 latency breach for ingestion and read endpoints
- Database pool saturation

## Review Cadence

- Monthly review of SLO compliance
- Quarterly adjustment of targets based on observed performance
