import test from 'node:test';
import assert from 'node:assert/strict';
import * as ed from '@noble/ed25519';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils';

import {
  VesClient,
  canonicalizeJson,
  computeEventSigningHash,
  computePayloadPlainHash,
} from '../src/ves/client.js';
import { createSequencerToolExecutor, sequencerTools } from '../src/agent/toolkit.js';
import { createMcpRequestHandler } from '../src/agent/mcp.js';

const ids = {
  tenantId: '64527dd3-a654-4410-9327-e58a1492ce77',
  storeId: '91def158-819a-4461-b5c9-7759750ad157',
  eventId: '861910c9-7a1d-4b6f-83d6-51bbf4ae2849',
  agentId: '80441726-74e2-430a-95ae-97ce21c6351b',
  commandId: '8af726e2-40e9-4cb6-b7d0-ea463765a9a7',
};

test('event signing hash matches the Rust cross-platform vector', () => {
  const hash = computeEventSigningHash({
    vesVersion: 1,
    tenantId: ids.tenantId,
    storeId: ids.storeId,
    eventId: ids.eventId,
    sourceAgentId: ids.agentId,
    agentKeyId: 1,
    entityType: 'order',
    entityId: 'ORD-001',
    eventType: 'order.created',
    createdAt: '2025-12-20T17:51:10.243Z',
    payloadKind: 0,
    payloadPlainHash: hexToBytes(
      '7777c3fef466a0e9df7e07ea4ff13dc8ffbb9e487098f1b65530cdce7b6bbbe7',
    ),
    payloadCipherHash: new Uint8Array(32),
  });

  assert.equal(bytesToHex(hash), 'e970dfc9ffc285c2c0ba59be5d9c653eee2d1ae4db9b7a02ea3cd62b8e7cf92b');
});

test('canonical payload hashing is independent of object insertion order', () => {
  const first = { z: [3, { b: true, a: null }], a: 'value' };
  const second = { a: 'value', z: [3, { a: null, b: true }] };
  assert.equal(canonicalizeJson(first), canonicalizeJson(second));
  assert.deepEqual(computePayloadPlainHash(first), computePayloadPlainHash(second));
});

test('recordAction signs the event and authenticates an idempotent ingest', async () => {
  const requests = [];
  const privateKey = new Uint8Array(32).fill(7);
  const client = new VesClient({
    baseUrl: 'https://sequencer.example',
    tenantId: ids.tenantId,
    storeId: ids.storeId,
    agentId: ids.agentId,
    privateKey,
    apiKey: 'test-api-key',
    maxRetries: 0,
    fetch: async (url, init) => {
      requests.push({ url, init });
      const submitted = JSON.parse(init.body).events[0];
      return new Response(
        JSON.stringify({
          eventsAccepted: 1,
          eventsRejected: 0,
          receipts: [{ eventId: submitted.event_id, sequenceNumber: 42 }],
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    },
  });

  const { event, receipt } = await client.recordAction({
    eventId: ids.eventId,
    commandId: ids.commandId,
    createdAt: '2026-09-04T12:00:00.000Z',
    entityType: 'order',
    entityId: 'ORD-001',
    eventType: 'order.confirmed',
    payload: { approved: true },
    baseVersion: 1,
  });

  const signingHash = computeEventSigningHash({
    vesVersion: 1,
    tenantId: ids.tenantId,
    storeId: ids.storeId,
    eventId: ids.eventId,
    sourceAgentId: ids.agentId,
    agentKeyId: 1,
    entityType: event.entity_type,
    entityId: event.entity_id,
    eventType: event.event_type,
    createdAt: event.created_at,
    payloadKind: 0,
    payloadPlainHash: hexToBytes(event.payload_plain_hash.slice(2)),
    payloadCipherHash: hexToBytes(event.payload_cipher_hash.slice(2)),
  });
  const publicKey = await ed.getPublicKeyAsync(privateKey);

  assert.equal(
    await ed.verifyAsync(hexToBytes(event.agent_signature.slice(2)), signingHash, publicKey),
    true,
  );
  assert.equal(receipt.sequenceNumber, 42);
  assert.equal(requests[0].url, 'https://sequencer.example/api/v1/ves/events/ingest');
  assert.equal(requests[0].init.headers.Authorization, 'ApiKey test-api-key');
  assert.equal(JSON.parse(requests[0].init.body).agentId, ids.agentId);
  assert.equal(event.payload_kind, 0);
  assert.equal(event.command_id, ids.commandId);
  assert.equal(event.base_version, 1);
});

test('agent tool executor exposes reads and signed actions without leaking the key', async () => {
  const calls = [];
  const client = {
    getEntityHistory: async (...args) => (calls.push(['history', ...args]), { events: [] }),
    recordAction: async (args) => (calls.push(['record', args]), { receipt: { sequenceNumber: 9 } }),
    getInclusionProof: async (sequence) => (calls.push(['proof', sequence]), { included: true }),
    getCursor: async () => ({ acknowledgedSequence: 4, lag: 5 }),
    acknowledge: async (sequence) => ({ acknowledgedSequence: sequence }),
  };
  const execute = createSequencerToolExecutor(client);

  assert.deepEqual(
    await execute(
      'stateset_get_entity_history',
      '{"entityType":"order","entityId":"O-1","from":2,"limit":10}',
    ),
    { events: [] },
  );
  assert.deepEqual(await execute('stateset_get_cursor', {}), {
    acknowledgedSequence: 4,
    lag: 5,
  });
  assert.deepEqual(await execute('stateset_acknowledge', { sequenceNumber: 9 }), {
    acknowledgedSequence: 9,
  });
  assert.equal(sequencerTools.length, 7);
  assert.deepEqual(calls, [['history', 'order', 'O-1', { from: 2, limit: 10 }]]);
});

test('agent policy rejects unauthorized event types before they reach the client', async () => {
  let called = false;
  const execute = createSequencerToolExecutor(
    { recordAction: async () => (called = true) },
    {
      allowedEventTypes: ['order.*'],
      allowedEntityTypes: ['order'],
      requireBaseVersion: true,
      maxPayloadBytes: 1024,
    },
  );

  await assert.rejects(
    execute('stateset_record_action', {
      entityType: 'order',
      entityId: 'O-1',
      eventType: 'inventory.refunded',
      commandId: ids.commandId,
      payload: {},
      baseVersion: 2,
    }),
    /not allowed/,
  );
  assert.equal(called, false);
});

test('agent tool boundary rejects malformed model arguments before signing', async () => {
  let called = false;
  const execute = createSequencerToolExecutor({ recordAction: async () => (called = true) });

  await assert.rejects(
    execute('stateset_record_action', {
      entityType: 'order',
      entityId: 'O-1',
      eventType: 'order.refunded',
      commandId: 'invent-a-command-id',
      payload: {},
    }),
    /commandId must be a UUID/,
  );
  assert.equal(called, false);
});

test('MCP handler lists tools and returns tool failures as MCP results', async () => {
  const handler = createMcpRequestHandler({
    getHead: async () => ({ headSequence: 12 }),
    recordAction: async () => {
      throw new Error('policy denied');
    },
  });
  const listed = await handler({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
  const failed = await handler({
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/call',
    params: {
      name: 'stateset_record_action',
      arguments: {
        entityType: 'order',
        entityId: 'O-1',
        eventType: 'order.confirmed',
        commandId: ids.commandId,
        payload: {},
      },
    },
  });

  assert.equal(listed.result.tools.length, 7);
  assert.equal(failed.result.isError, true);
  assert.equal(failed.result.content[0].text, 'policy denied');
});

test('durable cursor methods use the scoped monotonic cursor API', async () => {
  const requests = [];
  const client = new VesClient({
    tenantId: ids.tenantId,
    storeId: ids.storeId,
    agentId: ids.agentId,
    privateKey: new Uint8Array(32).fill(9),
    maxRetries: 0,
    fetch: async (url, init) => {
      requests.push({ url, init });
      return new Response(JSON.stringify({ acknowledgedSequence: 7, lag: 0 }), { status: 200 });
    },
  });

  await client.acknowledge(7);
  await client.getCursor();
  await client.setAgentPolicy({
    tenantId: '00000000-0000-0000-0000-000000000000',
    allowedEventTypes: ['order.*'],
    allowedEntityTypes: ['order'],
  });
  await client.getAgentPolicy();

  assert.equal(requests[0].init.method, 'PUT');
  assert.equal(JSON.parse(requests[0].init.body).sequenceNumber, 7);
  assert.match(requests[1].url, /tenant_id=.*store_id=/);
  assert.equal(JSON.parse(requests[2].init.body).tenantId, ids.tenantId);
  assert.match(requests[3].url, /\/agents\/.*\/policy\?tenant_id=/);
});
