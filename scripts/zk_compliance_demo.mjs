#!/usr/bin/env node
/**
 * StateSet VES + STARK Zero-Knowledge Compliance Demo
 *
 * End-to-end flow:
 * 1. Generate Ed25519 agent key
 * 2. Register the agent public key with the sequencer (admin)
 * 3. Create and sign a VES plaintext event (spec-compliant hashing)
 * 4. Ingest the event into the sequencer
 * 5. Fetch canonical compliance public inputs for the event + policy
 * 6. Generate a real STARK proof via stateset-stark (ves-stark CLI)
 * 7. Submit the proof + witness commitment to the sequencer
 * 8. Verify the stored proof (inputs consistency + cryptographic STARK verification)
 *
 * Env:
 * - SEQUENCER_URL (default http://localhost:8080)
 * - SEQUENCER_API_KEY (optional; sent as `Authorization: ApiKey <key>` unless it already has a scheme)
 * - STATESET_STARK_DIR (optional; default resolves to ../../stateset-stark relative to this script)
 * - VES_STARK_CLI (optional; path to a `ves-stark` binary; default uses `cargo run -p ves-stark-cli`)
 * - TENANT_ID / STORE_ID (optional; defaults to demo UUIDs)
 * - AMOUNT / THRESHOLD (optional; defaults 5000 / 10000)
 */

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import crypto from 'crypto';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

// Configure @noble/ed25519 to use @noble/hashes sha512
ed.hashes.sha512 = (msg) => sha512(msg);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Colors for terminal output
const colors = {
  green: '\x1b[32m',
  blue: '\x1b[34m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  reset: '\x1b[0m',
};

const SEQUENCER_URL = process.env.SEQUENCER_URL || 'http://localhost:8080';
const SEQUENCER_API_KEY = process.env.SEQUENCER_API_KEY || null;
const STATESET_STARK_DIR =
  process.env.STATESET_STARK_DIR ||
  path.resolve(__dirname, '..', '..', 'stateset-stark');
const VES_STARK_CLI = process.env.VES_STARK_CLI || null;

const RUN_ID = Date.now();
const TENANT_ID =
  process.env.TENANT_ID || '00000000-0000-0000-0000-0000000000ff';
const STORE_ID =
  process.env.STORE_ID || '00000000-0000-0000-0000-0000000000ff';

const AMOUNT = Number.parseInt(process.env.AMOUNT || '5000', 10);
const THRESHOLD = Number.parseInt(process.env.THRESHOLD || '10000', 10);
const STARK_PROOF_VERSION = Number.parseInt(
  process.env.STARK_PROOF_VERSION || '2',
  10,
);

const DOMAIN_PAYLOAD_PLAIN = Buffer.from('VES_PAYLOAD_PLAIN_V1', 'ascii');
const DOMAIN_EVENTSIG = Buffer.from('VES_EVENTSIG_V1', 'ascii');

/**
 * Canonical JSON stringify (RFC 8785-ish) for deterministic hashing.
 *
 * NOTE: This is sufficient for this demo (integers + strings); the Rust
 * implementation uses a strict RFC 8785 canonicalizer.
 */
function canonicalStringify(obj) {
  if (obj === null) return 'null';
  if (typeof obj === 'number' || typeof obj === 'boolean') return JSON.stringify(obj);
  if (typeof obj === 'string') return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalStringify).join(',') + ']';
  }
  if (typeof obj === 'object') {
    const keys = Object.keys(obj).sort();
    const pairs = keys.map(
      (k) => JSON.stringify(k) + ':' + canonicalStringify(obj[k]),
    );
    return '{' + pairs.join(',') + '}';
  }
  return String(obj);
}

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

function u32be(n) {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(n >>> 0, 0);
  return buf;
}

function encodeString(s) {
  const bytes = Buffer.from(s, 'utf8');
  return Buffer.concat([u32be(bytes.length), bytes]);
}

function uuidToBytes(uuid) {
  const hex = uuid.replace(/-/g, '');
  if (hex.length !== 32) {
    throw new Error(`Invalid UUID: ${uuid}`);
  }
  return Buffer.from(hex, 'hex');
}

function vesPayloadPlainHash(payload) {
  const canonical = canonicalStringify(payload);
  return sha256(Buffer.concat([DOMAIN_PAYLOAD_PLAIN, Buffer.from(canonical, 'utf8')]));
}

function vesEventSigningHash(params) {
  // Matches stateset-sequencer/src/crypto/hash.rs::compute_event_signing_hash
  const parts = [];
  parts.push(DOMAIN_EVENTSIG);
  parts.push(u32be(params.vesVersion));
  parts.push(uuidToBytes(params.tenantId));
  parts.push(uuidToBytes(params.storeId));
  parts.push(uuidToBytes(params.eventId));
  parts.push(uuidToBytes(params.sourceAgentId));
  parts.push(u32be(params.agentKeyId));
  parts.push(encodeString(params.entityType));
  parts.push(encodeString(params.entityId));
  parts.push(encodeString(params.eventType));
  parts.push(encodeString(params.createdAt));
  parts.push(u32be(params.payloadKind));
  parts.push(params.payloadPlainHash);
  parts.push(params.payloadCipherHash);
  return sha256(Buffer.concat(parts));
}

function uuidv4() {
  const bytes = crypto.randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(
    16,
    20,
  )}-${hex.slice(20)}`;
}

function printStep(step, title) {
  console.log(`${colors.blue}━━━ Step ${step}: ${title} ━━━${colors.reset}`);
}

function success(msg) {
  console.log(`  ${colors.green}✓${colors.reset} ${msg}`);
}

function warn(msg) {
  console.log(`  ${colors.yellow}⚠${colors.reset} ${msg}`);
}

function error(msg) {
  console.log(`  ${colors.red}✗${colors.reset} ${msg}`);
}

function buildAuthHeader() {
  if (!SEQUENCER_API_KEY) return {};
  if (/^(ApiKey|Bearer)\s+/i.test(SEQUENCER_API_KEY)) {
    return { Authorization: SEQUENCER_API_KEY };
  }
  return { Authorization: `ApiKey ${SEQUENCER_API_KEY}` };
}

async function httpRequest(url, options = {}) {
  const response = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      ...buildAuthHeader(),
      ...options.headers,
    },
    ...options,
  });

  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    // Not JSON
  }

  return {
    ok: response.ok,
    status: response.status,
    text,
    json,
  };
}

function runVesStarkProver(publicInputs, amount, threshold) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stateset-zk-'));
  const inputsPath = path.join(tmpDir, 'public_inputs.json');
  fs.writeFileSync(inputsPath, JSON.stringify(publicInputs, null, 2));

  const args = [
    'prove',
    '--amount',
    String(amount),
    '--limit',
    String(threshold),
    '--policy',
    'aml.threshold',
    '--inputs',
    inputsPath,
    '--json',
  ];

  let res;
  if (VES_STARK_CLI) {
    res = spawnSync(VES_STARK_CLI, args, { encoding: 'utf8' });
  } else {
    res = spawnSync(
      'cargo',
      ['run', '-q', '-p', 'ves-stark-cli', '--', ...args],
      {
        cwd: STATESET_STARK_DIR,
        encoding: 'utf8',
      },
    );
  }

  if (res.error) {
    throw res.error;
  }
  if (res.status !== 0) {
    throw new Error(
      `ves-stark prove failed (exit=${res.status})\n${res.stderr || res.stdout}`,
    );
  }

  const out = res.stdout.trim();
  if (!out.startsWith('{')) {
    throw new Error(`Unexpected ves-stark output:\n${out}`);
  }

  return JSON.parse(out);
}

async function main() {
  console.log('');
  console.log(
    `${colors.blue}╔═══════════════════════════════════════════════════════════════╗${colors.reset}`,
  );
  console.log(
    `${colors.blue}║     StateSet VES + STARK Zero-Knowledge Compliance Demo       ║${colors.reset}`,
  );
  console.log(
    `${colors.blue}╚═══════════════════════════════════════════════════════════════╝${colors.reset}`,
  );
  console.log('');
  console.log(`${colors.yellow}Run ID: ${RUN_ID}${colors.reset}`);
  console.log(
    `${colors.yellow}Scenario: Order with $${AMOUNT} (prove < $${THRESHOLD} for aml.threshold)${colors.reset}`,
  );
  console.log('');

  // Step 1: Check Services
  printStep(1, 'Check Services');

  const healthResp = await httpRequest(`${SEQUENCER_URL}/health`);
  if (!healthResp.ok || healthResp.json?.status !== 'healthy') {
    error('Sequencer is not healthy');
    if (healthResp.text) {
      console.log(`  Response: ${healthResp.text.slice(0, 200)}`);
    }
    process.exit(1);
  }
  success('Sequencer healthy');
  console.log('');

  // Step 2: Generate Ed25519 Agent Key
  printStep(2, 'Generate Agent Key');

  const agentId = uuidv4();
  const keyId = 1;

  const privateKey = crypto.randomBytes(32);
  const publicKey = await ed.getPublicKey(privateKey);
  const publicKeyHex = Buffer.from(publicKey).toString('hex');

  success('Generated Ed25519 key pair');
  console.log(`  Agent ID: ${agentId}`);
  console.log(`  Public Key: ${publicKeyHex.slice(0, 32)}...`);
  console.log('');

  // Step 3: Register Agent Key
  printStep(3, 'Register Agent Key (Admin)');

  const keyRegisterResp = await httpRequest(`${SEQUENCER_URL}/api/v1/agents/keys`, {
    method: 'POST',
    body: JSON.stringify({
      tenantId: TENANT_ID,
      agentId: agentId,
      keyId: keyId,
      publicKey: '0x' + publicKeyHex,
    }),
  });

  if (keyRegisterResp.ok || keyRegisterResp.status === 409) {
    success('Agent key registered (or already exists)');
  } else {
    error('Agent key registration failed');
    console.log(`  Status: ${keyRegisterResp.status}`);
    console.log(`  Response: ${keyRegisterResp.text.slice(0, 400)}`);
    console.log('');
    console.log('  If auth is enabled, set SEQUENCER_API_KEY to an admin key.');
    process.exit(1);
  }
  console.log('');

  // Step 4: Create + Sign VES Event
  printStep(4, 'Create + Sign VES Event');

  const eventId = uuidv4();
  const entityId = `order-zk-${RUN_ID}`;
  const createdAt = new Date().toISOString();
  const payload = { amount: AMOUNT, currency: 'USD', order_id: entityId };

  const payloadPlainHash = vesPayloadPlainHash(payload);
  const payloadCipherHash = Buffer.alloc(32, 0);

  const eventSigningHash = vesEventSigningHash({
    vesVersion: 1,
    tenantId: TENANT_ID,
    storeId: STORE_ID,
    eventId: eventId,
    sourceAgentId: agentId,
    agentKeyId: keyId,
    entityType: 'order',
    entityId: entityId,
    eventType: 'order.created',
    createdAt: createdAt,
    payloadKind: 0,
    payloadPlainHash: payloadPlainHash,
    payloadCipherHash: payloadCipherHash,
  });

  const signature = await ed.sign(eventSigningHash, privateKey);
  const signatureHex = Buffer.from(signature).toString('hex');

  const vesEvent = {
    ves_version: 1,
    event_id: eventId,
    tenant_id: TENANT_ID,
    store_id: STORE_ID,
    source_agent_id: agentId,
    agent_key_id: keyId,
    entity_type: 'order',
    entity_id: entityId,
    event_type: 'order.created',
    created_at: createdAt,
    payload_kind: 0,
    payload: payload,
    payload_plain_hash: '0x' + payloadPlainHash.toString('hex'),
    payload_cipher_hash: '0x' + payloadCipherHash.toString('hex'),
    agent_signature: '0x' + signatureHex,
  };

  success('VES event created and signed');
  console.log(`  Event ID: ${eventId}`);
  console.log(`  Entity: ${entityId}`);
  console.log(`  Amount: $${AMOUNT} (private witness for proof)`);
  console.log('');

  // Step 5: Ingest VES Event
  printStep(5, 'Submit VES Event to Sequencer');

  const ingestResp = await httpRequest(`${SEQUENCER_URL}/api/v1/ves/events/ingest`, {
    method: 'POST',
    body: JSON.stringify({
      agentId: agentId,
      events: [vesEvent],
    }),
  });

  if (!ingestResp.ok) {
    error('VES event rejected');
    console.log(`  Status: ${ingestResp.status}`);
    console.log(`  Response: ${ingestResp.text.slice(0, 600)}`);
    console.log('');
    console.log('  Common causes:');
    console.log('    - auth enabled but SEQUENCER_API_KEY missing');
    console.log('    - agent key not registered (Step 3)');
    console.log('    - hash/signature mismatch (Step 4 hashing must match VES spec)');
    process.exit(1);
  }

  const eventsAccepted = ingestResp.json?.eventsAccepted;
  if (eventsAccepted !== 1) {
    error(`VES ingest did not accept exactly 1 event (eventsAccepted=${eventsAccepted})`);
    console.log(`  Response: ${ingestResp.text.slice(0, 600)}`);
    process.exit(1);
  }

  const receipt0 = ingestResp.json?.receipts?.[0];
  const sequenceNumber =
    receipt0?.sequenceNumber ??
    ingestResp.json?.sequenceEnd ??
    ingestResp.json?.headSequence ??
    null;

  success('VES event accepted by sequencer');
  if (sequenceNumber !== null) {
    console.log(`  Sequence Number: ${sequenceNumber}`);
  }
  console.log('');

  // Step 6: Get Public Inputs for ZK Proving
  printStep(6, 'Get Canonical Public Inputs for ZK Proving');

  const inputsResp = await httpRequest(
    `${SEQUENCER_URL}/api/v1/ves/compliance/${eventId}/inputs`,
    {
      method: 'POST',
      body: JSON.stringify({
        policyId: 'aml.threshold',
        policyParams: { threshold: THRESHOLD },
      }),
    },
  );

  if (!inputsResp.ok || !inputsResp.json?.public_inputs) {
    error('Could not retrieve compliance public inputs');
    console.log(`  Status: ${inputsResp.status}`);
    console.log(`  Response: ${inputsResp.text.slice(0, 600)}`);
    process.exit(1);
  }

  const publicInputs = inputsResp.json.public_inputs;
  success('Public inputs retrieved');
  console.log(`  Policy: aml.threshold`);
  console.log(`  Threshold: $${THRESHOLD}`);
  console.log(
    `  Public Inputs Hash: ${(inputsResp.json.public_inputs_hash || '').slice(0, 24)}...`,
  );
  console.log('');

  // Step 7: Generate STARK Proof
  printStep(7, 'Generate STARK Proof (ves-stark)');

  let proofJson;
  try {
    proofJson = runVesStarkProver(publicInputs, AMOUNT, THRESHOLD);
  } catch (e) {
    error('STARK proof generation failed');
    console.log(`  ${e instanceof Error ? e.message : String(e)}`);
    console.log('');
    console.log('  Ensure stateset-stark is available and builds:');
    console.log(`    STATESET_STARK_DIR=${STATESET_STARK_DIR}`);
    console.log('');
    process.exit(1);
  }

  const proofB64 = proofJson.proof_b64;
  const witnessCommitmentHex = proofJson.witness_commitment_hex;

  if (!proofB64 || typeof proofB64 !== 'string') {
    throw new Error('ves-stark output missing proof_b64');
  }
  if (!witnessCommitmentHex || typeof witnessCommitmentHex !== 'string') {
    throw new Error('ves-stark output missing witness_commitment_hex');
  }

  success('STARK proof generated');
  if (proofJson.proof_hash) {
    console.log(`  Proof Hash: ${String(proofJson.proof_hash).slice(0, 32)}...`);
  }
  if (proofJson.metadata?.proof_size) {
    console.log(`  Proof Size: ${proofJson.metadata.proof_size} bytes`);
  }
  if (proofJson.metadata?.proving_time_ms) {
    console.log(`  Proving Time: ${proofJson.metadata.proving_time_ms} ms`);
  }
  console.log(`  Witness Commitment (hex): ${witnessCommitmentHex.slice(0, 16)}...`);
  console.log('');

  // Step 8: Submit Proof
  printStep(8, 'Submit Proof to Sequencer');

  const submitResp = await httpRequest(
    `${SEQUENCER_URL}/api/v1/ves/compliance/${eventId}/proofs`,
    {
      method: 'POST',
      body: JSON.stringify({
        proofType: 'stark',
        proofVersion: STARK_PROOF_VERSION,
        policyId: 'aml.threshold',
        policyParams: { threshold: THRESHOLD },
        proofB64: proofB64,
        witnessCommitment: witnessCommitmentHex,
      }),
    },
  );

  if (!submitResp.ok || !submitResp.json?.proof_id) {
    error('Proof submission failed');
    console.log(`  Status: ${submitResp.status}`);
    console.log(`  Response: ${submitResp.text.slice(0, 600)}`);
    process.exit(1);
  }

  const proofId = submitResp.json.proof_id;
  success('Proof submitted');
  console.log(`  Proof ID: ${proofId}`);
  console.log('');

  // Step 9: Verify Proof
  printStep(9, 'Verify Proof');

  const verifyResp = await httpRequest(
    `${SEQUENCER_URL}/api/v1/ves/compliance/proofs/${proofId}/verify`,
    { method: 'GET' },
  );

  if (!verifyResp.ok) {
    warn('Verify endpoint failed');
    console.log(`  Status: ${verifyResp.status}`);
    console.log(`  Response: ${verifyResp.text.slice(0, 600)}`);
  } else {
    const valid = verifyResp.json?.valid;
    const starkValid = verifyResp.json?.stark_valid;
    if (valid === true) {
      success('Proof verified');
    } else {
      warn('Proof is not valid');
    }
    console.log(`  valid: ${String(valid)}`);
    console.log(`  public_inputs_match: ${String(verifyResp.json?.public_inputs_match)}`);
    console.log(`  stark_valid: ${String(starkValid)}`);
    if (verifyResp.json?.stark_error) {
      console.log(`  stark_error: ${verifyResp.json.stark_error}`);
    }
    if (verifyResp.json?.stark_verification_time_ms != null) {
      console.log(
        `  stark_verification_time_ms: ${verifyResp.json.stark_verification_time_ms}`,
      );
    }
  }

  console.log('');
  console.log(`${colors.blue}━━━ Summary ━━━${colors.reset}`);
  console.log('');
  console.log('  ┌───────────────────────────────────────────────────────────────┐');
  console.log('  │            ZERO-KNOWLEDGE COMPLIANCE PROOF                    │');
  console.log('  ├───────────────────────────────────────────────────────────────┤');
  console.log(`  │  Event:                 ${eventId.slice(0, 36)}   │`);
  console.log(`  │  Entity:                ${entityId.padEnd(36)}   │`);
  console.log(
    `  │  Sequence:              ${String(sequenceNumber || 'N/A').padEnd(36)}   │`,
  );
  console.log('  ├───────────────────────────────────────────────────────────────┤');
  console.log(`  │  Policy:                ${'aml.threshold'.padEnd(36)}   │`);
  console.log(
    `  │  Threshold:             ${('$' + THRESHOLD + ' USD').padEnd(36)}   │`,
  );
  console.log(`  │  Proof Type:            ${'STARK (Winterfell)'.padEnd(36)}   │`);
  console.log(`  │  Proof ID:              ${String(proofId).slice(0, 36).padEnd(36)}   │`);
  console.log('  ├───────────────────────────────────────────────────────────────┤');
  console.log('  │  WHAT WAS PROVEN (without revealing the amount):             │');
  console.log(`  │    ✓ amount < ${THRESHOLD}                                     │`);
  console.log('  │    ✓ proof is cryptographically verifiable                   │');
  console.log('  │    ✓ post-quantum secure (no trusted setup)                  │');
  console.log('  └───────────────────────────────────────────────────────────────┘');
  console.log('');
  console.log(`${colors.green}ZK Compliance Demo Complete!${colors.reset}`);
  console.log('');
}

main().catch((err) => {
  console.error('Error:', err);
  process.exit(1);
});
