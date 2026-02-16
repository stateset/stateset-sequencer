import http from 'k6/http';
import { check, sleep } from 'k6';
import crypto from 'k6/crypto';

const BASE_URL = __ENV.SEQUENCER_BASE_URL || 'http://localhost:8080';
const ALLOW = __ENV.ALLOW_PUBLIC_REGISTRATION_LOAD === 'true';

export const options = {
  vus: 5,
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
  if (!ALLOW) {
    throw new Error('Set ALLOW_PUBLIC_REGISTRATION_LOAD=true to run this test');
  }

  const suffix = uuidv4();
  const payload = {
    name: `load-agent-${suffix}`,
    description: 'load test agent registration',
    readOnly: true,
  };

  const res = http.post(`${BASE_URL}/api/v1/agents/register`, JSON.stringify(payload), {
    headers: {
      'Content-Type': 'application/json',
    },
  });

  check(res, {
    'status is 200/403/429': (r) => [200, 403, 429].includes(r.status),
  });

  sleep(0.2);
}
