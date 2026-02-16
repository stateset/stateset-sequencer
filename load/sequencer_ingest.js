import http from 'k6/http';
import { check, sleep } from 'k6';
import crypto from 'k6/crypto';

const BASE_URL = __ENV.SEQUENCER_BASE_URL || 'http://localhost:8080';
const API_KEY = __ENV.API_KEY;
const TENANT_ID = __ENV.TENANT_ID || '00000000-0000-0000-0000-000000000000';
const STORE_ID = __ENV.STORE_ID || '00000000-0000-0000-0000-000000000000';
const AGENT_ID = __ENV.AGENT_ID || '00000000-0000-0000-0000-000000000000';

export const options = {
  vus: 10,
  duration: '30s',
};

function uuidv4() {
  const bytes = crypto.randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes).map((b) => (`0${b.toString(16)}`).slice(-2)).join('');
  return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}

export default function () {
  if (!API_KEY) {
    throw new Error('API_KEY is required');
  }

  const eventId = uuidv4();
  const now = new Date().toISOString();
  const payload = {
    agent_id: AGENT_ID,
    events: [
      {
        event_id: eventId,
        tenant_id: TENANT_ID,
        store_id: STORE_ID,
        entity_type: 'order',
        entity_id: `order-${eventId}`,
        event_type: 'order.created',
        payload: {
          order_id: eventId,
          total: 42,
        },
        created_at: now,
      },
    ],
  };

  const res = http.post(`${BASE_URL}/api/v1/events/ingest`, JSON.stringify(payload), {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `ApiKey ${API_KEY}`,
    },
  });

  check(res, {
    'status is 200': (r) => r.status === 200,
  });

  sleep(0.1);
}
