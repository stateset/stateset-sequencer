import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE_URL = __ENV.SEQUENCER_BASE_URL || 'http://localhost:8080';
const API_KEY = __ENV.API_KEY;
const TENANT_ID = __ENV.TENANT_ID || '00000000-0000-0000-0000-000000000000';
const STORE_ID = __ENV.STORE_ID || '00000000-0000-0000-0000-000000000000';

export const options = {
  vus: 10,
  duration: '30s',
};

export default function () {
  if (!API_KEY) {
    throw new Error('API_KEY is required');
  }

  const url = `${BASE_URL}/api/v1/head?tenant_id=${TENANT_ID}&store_id=${STORE_ID}`;
  const res = http.get(url, {
    headers: {
      Authorization: `ApiKey ${API_KEY}`,
    },
  });

  check(res, {
    'status is 200': (r) => r.status === 200,
  });

  sleep(0.1);
}
