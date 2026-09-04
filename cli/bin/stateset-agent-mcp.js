#!/usr/bin/env node

import { createInterface } from 'node:readline';
import { VesClient, loadVesPrivateKey } from '../src/ves/client.js';
import { createMcpRequestHandler } from '../src/agent/mcp.js';

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} environment variable is required`);
  return value;
}

const client = new VesClient({
  baseUrl: process.env.STATESET_SEQUENCER_URL,
  tenantId: required('STATESET_TENANT_ID'),
  storeId: required('STATESET_STORE_ID'),
  agentId: required('STATESET_AGENT_ID'),
  keyId: process.env.STATESET_AGENT_KEY_ID
    ? Number(process.env.STATESET_AGENT_KEY_ID)
    : 1,
  privateKey: loadVesPrivateKey(),
  apiKey: process.env.STATESET_API_KEY,
  bearerToken: process.env.STATESET_BEARER_TOKEN,
});

const allowedEventTypes = process.env.STATESET_ALLOWED_EVENT_TYPES
  ?.split(',')
  .map((value) => value.trim())
  .filter(Boolean);
const handleRequest = createMcpRequestHandler(client, {
  // MCP is safe by default: reads work immediately, writes require an explicit
  // event-type grant in the tool host's environment.
  allowedEventTypes: allowedEventTypes || [],
  requireBaseVersion: process.env.STATESET_REQUIRE_BASE_VERSION !== 'false',
});

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  if (!line.trim()) continue;
  let response;
  try {
    response = await handleRequest(JSON.parse(line));
  } catch {
    response = { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } };
  }
  if (response) process.stdout.write(`${JSON.stringify(response)}\n`);
}
