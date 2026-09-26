/**
 * Bounded signed VES load against an isolated sequencer/database.
 * Uses the shipped SDK so event canonicalization and signatures match clients.
 */
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { performance } from 'node:perf_hooks';
import { randomBytes, randomUUID } from 'node:crypto';
import * as ed from '@noble/ed25519';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { VesClient } from '../src/ves/client.js';

function positiveInteger(name, fallback) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer`);
  return value;
}

function hashBytes(value, length) {
  const bytes = hexToBytes(value.replace(/^0x/, ''));
  if (bytes.length !== length) throw new Error(`Expected ${length} bytes of hex`);
  return bytes;
}

function percentile(sorted, percent) {
  return sorted[Math.ceil((percent / 100) * sorted.length) - 1];
}

async function main() {
  const baseUrl = (process.env.SEQUENCER_BASE_URL || 'http://127.0.0.1:8080').replace(/\/$/, '');
  const tenantId = process.env.TENANT_ID || randomUUID();
  const storeId = process.env.STORE_ID || randomUUID();
  const agentId = process.env.AGENT_ID || randomUUID();
  const apiKey = process.env.API_KEY;
  const durationMs = positiveInteger('VES_LOAD_DURATION_MS', 10_000);
  const concurrency = positiveInteger('VES_LOAD_CONCURRENCY', 4);
  const minAccepted = positiveInteger('VES_LOAD_MIN_ACCEPTED', 20);
  const maxP95Ms = positiveInteger('VES_LOAD_MAX_P95_MS', 750);
  const receiptPublicKey = hashBytes(process.env.VES_RECEIPT_PUBLIC_KEY || '', 32);
  const privateKey = randomBytes(32);
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  const registration = await fetch(`${baseUrl}/api/v1/agents/keys`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(apiKey ? { Authorization: `ApiKey ${apiKey}` } : {}) },
    body: JSON.stringify({ tenantId, agentId, keyId: 1, publicKey: bytesToHex(publicKey) }),
  });
  assert.equal(registration.status, 200, `key registration failed: ${await registration.text()}`);

  const client = new VesClient({ baseUrl, tenantId, storeId, agentId, privateKey,
    apiKey, signingVersion: 2, maxRetries: 0 });
  const initialHead = (await client.getHead()).head_sequence;
  assert.ok(Number.isSafeInteger(initialHead));

  // A malformed signature must be rejected without advancing the stream.
  const invalid = await client.createEvent({ entityType: 'order', entityId: randomUUID(),
    eventType: 'order.created', payload: { amount: 1 }, commandId: randomUUID(), baseVersion: 0 });
  const changed = hashBytes(invalid.agent_signature, 64);
  changed[0] ^= 1;
  invalid.agent_signature = `0x${bytesToHex(changed)}`;
  const denied = await client.ingest([invalid]);
  assert.equal(denied.eventsAccepted, 0, 'invalid signature was accepted');
  assert.equal(denied.eventsRejected, 1, 'invalid signature was not rejected');
  assert.equal((await client.getHead()).head_sequence, initialHead);

  // The target must enforce signed V2 execution controls, not merely accept them.
  const legacyClient = new VesClient({ baseUrl, tenantId, storeId, agentId, privateKey,
    apiKey, signingVersion: 1, maxRetries: 0 });
  const unbound = await legacyClient.createEvent({ entityType: 'order', entityId: randomUUID(),
    eventType: 'order.created', payload: { amount: 1 } });
  const unboundResult = await legacyClient.ingest([unbound]);
  assert.equal(unboundResult.eventsAccepted, 0, 'unbound V1 event was accepted');
  assert.equal(unboundResult.eventsRejected, 1, 'unbound V1 event was not rejected');
  assert.equal((await client.getHead()).head_sequence, initialHead);

  const latencies = [];
  const sequences = new Set();
  const errors = [];
  let accepted = 0;
  let first;
  const started = performance.now();
  const deadline = started + durationMs;

  async function worker() {
    while (performance.now() < deadline && errors.length === 0) {
      try {
        const event = await client.createEvent({ entityType: 'order', entityId: randomUUID(),
          eventType: 'order.created', payload: { amount: 42, currency: 'USD' },
          commandId: randomUUID(), baseVersion: 0 });
        const requestStart = performance.now();
        const result = await client.ingest([event]);
        latencies.push(performance.now() - requestStart);
        assert.equal(result.eventsAccepted, 1);
        assert.equal(result.eventsRejected, 0);
        assert.equal(result.receipts?.length, 1);
        const receipt = result.receipts[0];
        assert.equal(receipt.eventId, event.event_id);
        assert.ok(Number.isSafeInteger(receipt.sequenceNumber));
        assert.equal(await ed.verifyAsync(hashBytes(receipt.sequencerSignature, 64),
          hashBytes(receipt.receiptHash, 32), receiptPublicKey), true,
        'invalid sequencer receipt signature');
        assert.equal(sequences.has(receipt.sequenceNumber), false, 'duplicate sequence');
        sequences.add(receipt.sequenceNumber);
        accepted += 1;
        first ??= { event, receipt };
      } catch (error) {
        errors.push(String(error));
      }
    }
  }

  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  const elapsedSeconds = (performance.now() - started) / 1_000;
  const finalHead = (await client.getHead()).head_sequence;
  if (errors.length) throw new Error(`signed VES load failed: ${errors[0]}`);
  assert.ok(accepted >= minAccepted, `only ${accepted} events accepted`);
  assert.equal(finalHead, initialHead + accepted, 'head did not match accepted events');
  assert.equal(sequences.size, accepted);
  for (let sequence = initialHead + 1; sequence <= finalHead; sequence += 1) {
    assert.equal(sequences.has(sequence), true, `sequence ${sequence} is missing`);
  }

  const replay = await client.ingest([first.event]);
  assert.equal(replay.eventsAccepted, 0, 'replay inserted another event');
  assert.equal(replay.receipts?.length, 1);
  assert.equal(replay.receipts[0].receiptHash, first.receipt.receiptHash);
  assert.equal(replay.receipts[0].sequenceNumber, first.receipt.sequenceNumber);
  assert.equal((await client.getHead()).head_sequence, finalHead);

  latencies.sort((a, b) => a - b);
  const summary = {
    workload: 'signed VES v2 ingest, one hot tenant/store, isolated database',
    duration_seconds: Number(elapsedSeconds.toFixed(3)), concurrency, accepted,
    requests_per_second: Number((accepted / elapsedSeconds).toFixed(2)),
    ingest_p50_ms: Number(percentile(latencies, 50).toFixed(2)),
    ingest_p95_ms: Number(percentile(latencies, 95).toFixed(2)),
    ingest_p99_ms: Number(percentile(latencies, 99).toFixed(2)),
    invalid_signature_rejected: true, unsigned_controls_rejected: true,
    receipt_signatures_verified: accepted,
    replay_preserved_receipt: true, contiguous_sequence_verified: true,
    initial_head: initialHead, final_head: finalHead,
    scope: 'SDK signing occurs before latency timing; no projection lag, failover, or production network measured',
  };
  if (process.env.VES_LOAD_SUMMARY) {
    mkdirSync(dirname(process.env.VES_LOAD_SUMMARY), { recursive: true });
    writeFileSync(process.env.VES_LOAD_SUMMARY, `${JSON.stringify(summary, null, 2)}\n`);
  }
  console.log(JSON.stringify(summary, null, 2));
  assert.ok(summary.ingest_p95_ms <= maxP95Ms,
    `signed VES p95 ${summary.ingest_p95_ms}ms exceeds ${maxP95Ms}ms`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
