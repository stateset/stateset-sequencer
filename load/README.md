# k6 Load Test Configuration for StateSet Sequencer

This directory contains load tests for the StateSet Sequencer API.

## Prerequisites

```bash
# Install k6 (macOS)
brew install k6

# Install k6 (Linux)
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6
```

## Running Tests

### Quick Test (Default: 10 VUs for 30s)

```bash
k6 run load/sequencer_ingest.js
```

### Custom Configuration

```bash
k6 run load/sequencer_ingest.js --opts load/runner.json
```

### Environment Variables

Set environment variables before running:

```bash
export SEQUENCER_BASE_URL=http://localhost:8080
export API_KEY=your_test_api_key
export TENANT_ID=00000000-0000-0000-0000-000000000000
export STORE_ID=00000000-0000-0000-0000-000000000000

k6 run load/sequencer_ingest.js
```

## Test Scenarios

### 1. Event Ingestion (sequencer_ingest.js)

Tests the `/api/v1/ves/events/ingest` endpoint with:
- Batch sizes: 10, 50, 100, 500 events
- Concurrent users: 10, 50, 100 VUs
- Duration: 30s - 5m

### 2. Query Performance (sequencer_query.js)

Tests read endpoints:
- `/api/v1/events` - Event listing
- `/api/v1/head` - Head sequence
- `/api/v1/entities/{type}/{id}` - Entity history
- `/api/v1/ves/commitments` - Commitments

### 3. Mixed Workload (mixed_workload.js)

Tests realistic production traffic patterns:
- 70% event ingestion
- 20% queries
- 10% commitments/proof generation

## Interpreting Results

Key metrics to monitor:

- **http_req_duration**: Request latency (p95, p99)
- **http_req_failed**: Failed requests (should be 0)
- **vus**: Active virtual users
- **iterations_completed**: Total iterations

### Example Output

```
✓ checks....................................... 100%  ✓ 45096  ✗ 0

     data_received......................: 55 MB  2.0 MB/s
     data_sent..........................: 82 MB  3.0 MB/s
     http_req_blocked....................: avg=2.34ms min=1µs    med=2µs    max=342ms   p(90)=5µs    p(95)=6µs
     http_req_connecting.................: avg=2.32ms min=0s     med=0s     max=341ms   p(90)=0s     p(95)=0s
     http_req_duration...................: avg=23.4ms  min=15.6ms med=22.3ms max=876ms   p(90)=34.2ms p(95)=42.1ms
       { expected_response:true }..........: avg=23.4ms  min=15.6ms med=22.3ms max=876ms   p(90)=34.2ms p(95)=42.1ms
     http_req_failed......................: 0.00%  ✓ 0     ✗ 45096
     http_req_receiving...................: avg=450µs  min=54µs   med=345µs  max=12.3ms  p(90)=890µs  p(95)=1.1ms
     http_req_sending.....................: avg=23.1ms  min=1.2ms  med=21.3ms max=123ms   p(90)=32ms   p(95)=38ms
     http_req_tls_handshaking.............: avg=0s      min=0s     med=0s     max=0s      p(90)=0s     p(95)=0s
     http_req_waiting.....................: avg=160µs  min=123µs  med=158µs  max=2.3ms   p(90)=210µs  p(95)=245µs
     http_reqs...........................: 45096  1669/s
     iteration_duration...................: avg=601ms   min=16.5ms med=602ms  max=980ms   p(90)=765ms  p(95)=834ms
     iterations...........................: 45096  1669/s
     vus..................................: 100    min=100 max=100
```

## Benchmark Targets

For production readiness:

| Metric | Target | Notes |
|--------|--------|-------|
| P50 latency | < 20ms | Average response time |
| P95 latency | < 50ms | 95th percentile |
| P99 latency | < 100ms | 99th percentile |
| Error rate | 0% | No failed requests |
| TPS | 1000+ | Transactions per second |
| Batch size | 100 events | Optimal batch size |

## CI/CD Integration

Add to GitHub Actions:

```yaml
- name: Run load tests
  run: |
    docker run --rm -i \
      --network host \
      -v $PWD:/workdir \
      -w /workdir \
      grafana/k6:latest \
      run --out json=load-test-results.json load/sequencer_ingest.js

- name: Upload load test results
  uses: actions/upload-artifact@v4
  with:
    name: load-test-results
    path: load-test-results.json
```

## Troubleshooting

### Connection Refused

```bash
# Ensure sequencer is running
docker-compose ps
curl http://localhost:8080/health
```

### Rate Limiting

Adjust `RATE_LIMIT_PER_MINUTE` in your sequencer configuration:

```bash
export RATE_LIMIT_PER_MINUTE=10000
```

### Database Connection Pool

If seeing connection errors, increase pool size:

```bash
export MAX_DB_CONNECTIONS=20
export MIN_DB_CONNECTIONS=5
```