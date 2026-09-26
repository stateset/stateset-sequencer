# Performance evidence

Use the workload, commit, environment, and raw result together. A CPU benchmark,
an HTTP smoke test, and a production SLO answer different questions. The target
values in [SLO.md](SLO.md) are objectives, not measured service capacity.

## Reproducible measurements

| Evidence | Result | Scope |
| --- | --- | --- |
| [2026-09-21 sustained run](https://github.com/stateset/stateset-sequencer/actions/runs/35596164261), commit `360203c9f59cd25b9218e536428fa0b959e6c34d` | 256,470 HTTP requests in 14 minutes; 305.3 requests/s; overall p95 28.12 ms; zero HTTP failures | 70% legacy ingest and 30% head reads, one tenant/store, at most 50 virtual users. Authentication and payload encryption were disabled. This does not measure signed VES ingest. |
| Release-binary signed VES smoke | Result is uploaded as `load-smoke-evidence/ves-signed-load-summary.json` by CI on each commit after this harness was added. | One hot tenant/store and a disposable PostgreSQL service. The Node SDK signs V2 events with bound command ID and base version; the harness checks acceptance, each sequencer receipt signature, contiguous sequences, rejection of invalid signatures and unbound V1 controls, and exact replay. It measures HTTP ingest after client signing. |
| Criterion CPU benchmarks | Run `cargo bench --bench sequencer_bench` and retain `target/criterion/` with the machine and commit. | Payload hashing, signing bytes, event construction, and Merkle hashing in process. These timings exclude the API, database, network, and disk. |

The CI signed VES test is a **regression gate**, not a capacity claim. Its
default duration is 10 seconds with four concurrent clients, at least 20
accepted events, zero failures, and a 750 ms p95 limit. It runs after the
legacy k6 smoke against the same release binary and disposable database, but
uses its own tenant and store. It does not measure projection lag, failover,
production authentication, encryption, or network latency.

The scheduled `performance` workflow also runs the signed harness for five
minutes after the legacy k6 workload and uploads both summaries. The same
single-runner and disabled-authentication limits apply. This provides a trend
for the core signed path without presenting it as deployed capacity.

## Run the signed VES workload

Install the Node SDK dependencies with `npm ci --prefix cli` and start an
authorized, isolated test sequencer with
`REQUIRE_SIGNED_EXECUTION_CONTROLS=true`. Give `API_KEY` an admin credential capable
of registering the temporary signing key. The trusted receipt public key must
come from the target configuration, not from a value returned by the target.
The harness creates a fresh tenant, store, and agent unless IDs are supplied.

```sh
export SEQUENCER_BASE_URL=http://127.0.0.1:8080
export API_KEY=your_test_admin_key
export VES_RECEIPT_PUBLIC_KEY=trusted_32_byte_ed25519_public_key_hex
export VES_LOAD_DURATION_MS=10000
export VES_LOAD_CONCURRENCY=4
export VES_LOAD_SUMMARY=load/results/ves-signed-load-summary.json
node cli/bench/ves-signed-load.mjs
```

Use only an isolated target: the harness expects that no other writer advances
its newly created stream. It checks that every accepted event has exactly one
distinct sequence number and that the final head equals the initial head plus
the number accepted. `VES_LOAD_MIN_ACCEPTED` and `VES_LOAD_MAX_P95_MS` can set
explicit regression thresholds. The summary contains counts, throughput, p50,
p95, p99, and verification results; it contains no private keys.

## Evidence needed for a production capacity claim

Run a sustained, representative signed VES profile on the proposed deployment
with production authentication, payload encryption, rate limits, and projected
state enabled. Record the exact commit and configuration, event sizes, tenant
distribution, throughput, p50/p95/p99 ingest latency, rejection and error
rates, projection lag, memory, database connection use, and PostgreSQL load.
Include hot streams, multiple replicas, a failed replica, and recovery. Compare
those measurements with agreed SLOs and publish the raw artifacts before
assigning a capacity grade. The existing local and CI fixtures do not establish
those results.

For the legacy k6 workloads and their limitations, see [load tests](../load/README.md).
