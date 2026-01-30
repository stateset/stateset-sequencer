import http from 'k6/http';
import { check, sleep } from 'k6';
import { SharedArray } from 'k6/data';

// Configuration
export const options = {
  stages: [
    { duration: '30s', target: 10 },   // Ramp up to 10 users
    { duration: '1m', target: 10 },    // Stay at 10 users
    { duration: '30s', target: 50 },   // Ramp up to 50 users
    { duration: '1m', target: 50 },    // Stay at 50 users
    { duration: '30s', target: 100 },  // Ramp up to 100 users
    { duration: '1m', target: 100 },   // Stay at 100 users
    { duration: '30s', target: 0 },    // Ramp down to 0
  ],
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'], // 95% of requests under 500ms, 99% under 1s
    http_req_failed: ['rate<0.01'],                 // <1% error rate
  },
};

// Constants
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const API_KEY = __ENV.API_KEY || 'dev_admin_key';
const TENANT_ID = __ENV.TENANT_ID || '00000000-0000-0000-0000-000000000001';
const STORE_ID = __ENV.STORE_ID || '00000000-0000-0000-0000-000000000001';

// Generate VES event payload
function generateVesEvent() {
  return {
    event_id: crypto.randomUUID(),
    tenant_id: TENANT_ID,
    store_id: STORE_ID,
    entity_type: "order",
    entity_id: `order-${Math.floor(Math.random() * 1000000)}`,
    event_type: "order.created",
    payload: {
      customer_id: `customer-${Math.floor(Math.random() * 1000)}`,
      total: Math.floor(Math.random() * 1000000) / 100, // Random amount up to $10000
      currency: "USD"
    },
    base_version: 0,
    source_agent: "00000000-0000-0000-0000-000000000001",
    created_at: new Date().toISOString()
  };
}

// Health check
export function setup() {
  const response = http.get(`${BASE_URL}/health`);
  if (response.status !== 200) {
    throw new Error('Health check failed - sequencer is not ready');
  }
  return { ready: true };
}

// Main test scenarios
export default function (data) {
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `ApiKey ${API_KEY}`,
  };

  // Scenario 1: Health check (20% of requests)
  if (Math.random() < 0.2) {
    const healthRes = http.get(`${BASE_URL}/health`, { headers });
    check(healthRes, {
      'health status is 200': (r) => r.status === 200,
    });
    return;
  }

  // Scenario 2: Get head sequence (20% of requests)
  if (Math.random() < 0.25) {
    const headRes = http.get(
      `${BASE_URL}/api/v1/head?tenant_id=${TENANT_ID}&store_id=${STORE_ID}`,
      { headers }
    );
    check(headRes, {
      'head status is 200': (r) => r.status === 200,
      'head response time < 100ms': (r) => r.timings.duration < 100,
    });
    return;
  }

  // Scenario 3: Ingest VES event (55% of requests)
  const event = generateVesEvent();
  const ingestRes = http.post(
    `${BASE_URL}/api/v1/events/ingest`,
    JSON.stringify({ events: [event] }),
    { headers }
  );

  check(ingestRes, {
    'ingest status is 200': (r) => r.status === 200,
    'ingest has receipts': (r) => {
      const body = r.json();
      return body && body.receipts && body.receipts.length > 0;
    },
    'ingest response time < 500ms': (r) => r.timings.duration < 500,
    'ingest has sequence number': (r) => {
      const body = r.json();
      return body && body.receipts && typeof body.receipts[0].sequence_number === 'number';
    },
  });

  // Small pause between requests
  sleep(Math.random() * 0.5 + 0.1);
}

// Teardown
export function teardown(data) {
  console.log('Load test completed successfully');
}