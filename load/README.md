# Sequencer load tests

The k6 workloads exercise the legacy HTTP event API and head query on a
disposable PostgreSQL service. They measure request behavior for a specified
profile; they do not establish production capacity or a VES signed-ingest SLO.

## Workloads

| Script | Requests per iteration | Notes |
| --- | --- | --- |
| `sequencer_ingest.js` | One legacy event ingest | One new event ID and entity per request; no VES signature. |
| `sequencer_query.js` | One head query | Reads the configured tenant and store. |
| `mixed_workload.js` | One request, about 70% ingest and 30% head query | Sleeps 100 ms after each iteration. Reports operation counts and latency separately. |
| `agents_register.js` | Public agent registration | Requires `ALLOW_PUBLIC_REGISTRATION_LOAD=true`; use only on an authorized test target. |

The mixed workload records `ingest_requests`, `head_requests`,
`ingest_duration`, and `head_duration` in addition to k6's HTTP metrics. It
tags each request with `operation=ingest` or `operation=head`. A successful HTTP
response is not by itself proof that a signed VES event was accepted.

## Profiles and execution

| Profile | Load | Duration |
| --- | --- | --- |
| `ci.json` | 5 virtual users | 20 seconds |
| `smoke.json` | 5 virtual users | 1 minute |
| `sustained.json` | Ramp to 25, then 50, then zero | 14 minutes |
| `stress.json` | Ramp to 50, 100, 200, then zero | 6 minutes |

The JSON thresholds are regression gates for these fixtures, not agreed
production SLOs. The scheduled `performance` workflow runs `mixed_workload.js`
with `sustained.json` on a single GitHub hosted runner, with authentication and
payload encryption disabled and one configured tenant and store. It uploads
the k6 summary and server log. Pull requests run the shorter `ci.json` ingest
profile against the release binary.

To run with a local k6 installation and an authorized test service:

```sh
export SEQUENCER_BASE_URL=http://localhost:8080
export API_KEY=your_test_api_key
export TENANT_ID=10000000-0000-4000-8000-000000000001
export STORE_ID=20000000-0000-4000-8000-000000000002
export AGENT_ID=30000000-0000-4000-8000-000000000003
./scripts/run_load_test.sh load/mixed_workload.js sustained
```

The helper writes a k6 summary and raw time series to `load/results/`.

## Existing measured run

The [2026-09-21 sustained workflow](https://github.com/stateset/stateset-sequencer/actions/runs/35596164261)
passed at commit `360203c9f59cd25b9218e536428fa0b959e6c34d`: 256,470 HTTP
requests in 14 minutes (305.3 requests/s overall), 28.12 ms overall p95
response time, and zero HTTP failures. This was the 70/30 legacy ingest and
head workload, capped at 50 virtual users. The result does not measure signed
VES ingest throughput, production replica behavior, hot tenants, failover,
memory use, database connection pressure, or projection lag. The new separate
operation metrics will first appear in a run using this updated script.
