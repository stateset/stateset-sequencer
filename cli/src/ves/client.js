/**
 * Agent-native VES client for StateSet Sequencer.
 *
 * The cryptographic encoding mirrors `src/crypto/hash.rs`. Event IDs are
 * generated before submission, so retrying a timed-out ingest is safe: the
 * sequencer deduplicates the same event rather than applying it twice.
 */

import * as ed from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { randomUUID } from 'node:crypto';

const encoder = new TextEncoder();
const DOMAIN_PAYLOAD_PLAIN = encoder.encode('VES_PAYLOAD_PLAIN_V1');
const DOMAIN_EVENTSIG = encoder.encode('VES_EVENTSIG_V1');
const ZERO_HASH = new Uint8Array(32);

export class SequencerApiError extends Error {
  constructor(message, { status = 0, code, requestId, retryAfter, cause } = {}) {
    super(message, { cause });
    this.name = 'SequencerApiError';
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.retryAfter = retryAfter;
  }
}

/** RFC 8785-compatible JSON serialization for JSON-domain values. */
export function canonicalizeJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('JSON numbers must be finite');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalizeJson).join(',')}]`;
  }
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalizeJson(value[key])}`)
      .join(',')}}`;
  }
  throw new TypeError(`Unsupported JSON value: ${typeof value}`);
}

export function computePayloadPlainHash(payload) {
  return sha256(concatBytes(DOMAIN_PAYLOAD_PLAIN, encoder.encode(canonicalizeJson(payload))));
}

export function computeEventSigningHash(params) {
  return sha256(
    concatBytes(
      DOMAIN_EVENTSIG,
      u32be(params.vesVersion),
      uuidBytes(params.tenantId),
      uuidBytes(params.storeId),
      uuidBytes(params.eventId),
      uuidBytes(params.sourceAgentId),
      u32be(params.agentKeyId),
      encodedString(params.entityType),
      encodedString(params.entityId),
      encodedString(params.eventType),
      encodedString(params.createdAt),
      u32be(params.payloadKind),
      params.payloadPlainHash,
      params.payloadCipherHash,
    ),
  );
}

export class VesClient {
  constructor(options) {
    for (const field of ['tenantId', 'storeId', 'agentId']) {
      if (!options?.[field]) throw new TypeError(`${field} is required`);
      uuidBytes(options[field]);
    }
    if (!(options.privateKey instanceof Uint8Array) || options.privateKey.length !== 32) {
      throw new TypeError('privateKey must be a 32-byte Uint8Array');
    }

    this.baseUrl = (options.baseUrl || 'http://localhost:8080').replace(/\/$/, '');
    this.tenantId = options.tenantId;
    this.storeId = options.storeId;
    this.agentId = options.agentId;
    this.keyId = options.keyId ?? 1;
    if (!Number.isSafeInteger(this.keyId) || this.keyId < 0 || this.keyId > 0xffffffff) {
      throw new TypeError('keyId must be an unsigned 32-bit integer');
    }
    this.privateKey = options.privateKey;
    this.apiKey = options.apiKey;
    this.bearerToken = options.bearerToken;
    if (this.apiKey && this.bearerToken) {
      throw new TypeError('Configure either apiKey or bearerToken, not both');
    }
    this.fetch = options.fetch || globalThis.fetch;
    this.maxRetries = options.maxRetries ?? 3;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    if (typeof this.fetch !== 'function') throw new TypeError('A fetch implementation is required');
  }

  async createEvent(params) {
    const eventId = params.eventId || randomUUID();
    const createdAt = params.createdAt || new Date().toISOString();
    const payloadPlainHash = computePayloadPlainHash(params.payload);
    const signingHash = computeEventSigningHash({
      vesVersion: 1,
      tenantId: this.tenantId,
      storeId: this.storeId,
      eventId,
      sourceAgentId: this.agentId,
      agentKeyId: this.keyId,
      entityType: params.entityType,
      entityId: params.entityId,
      eventType: params.eventType,
      createdAt,
      payloadKind: 0,
      payloadPlainHash,
      payloadCipherHash: ZERO_HASH,
    });
    const signature = await ed.signAsync(signingHash, this.privateKey);

    return compactObject({
      ves_version: 1,
      event_id: eventId,
      tenant_id: this.tenantId,
      store_id: this.storeId,
      source_agent_id: this.agentId,
      agent_key_id: this.keyId,
      entity_type: params.entityType,
      entity_id: params.entityId,
      event_type: params.eventType,
      created_at: createdAt,
      // PayloadKind uses serde's numeric representation in the Rust API.
      payload_kind: 0,
      payload: params.payload,
      payload_plain_hash: toHex(payloadPlainHash),
      payload_cipher_hash: toHex(ZERO_HASH),
      agent_signature: toHex(signature),
      command_id: params.commandId,
      base_version: params.baseVersion,
    });
  }

  async ingest(events) {
    if (!Array.isArray(events) || events.length === 0) {
      throw new TypeError('events must be a non-empty array');
    }
    return this.request('/api/v1/ves/events/ingest', {
      method: 'POST',
      body: { agentId: this.agentId, events },
      retryable: true,
    });
  }

  async recordAction(params) {
    const event = await this.createEvent(params);
    const result = await this.ingest([event]);
    const rejection = result.rejections?.find((item) => item.event_id === event.event_id);
    if (rejection) {
      throw new SequencerApiError(rejection.message, { code: rejection.reason });
    }
    return { event, receipt: result.receipts?.[0], result };
  }

  getHead() {
    return this.request(`/api/v1/ves/head?${this.scopeQuery()}`);
  }

  listEvents({ from = 1, limit = 100 } = {}) {
    const query = new URLSearchParams({
      tenant_id: this.tenantId,
      store_id: this.storeId,
      from: String(from),
      limit: String(limit),
    });
    return this.request(`/api/v1/ves/events?${query}`);
  }

  getEntityHistory(entityType, entityId, { from = 0, limit = 100 } = {}) {
    const query = new URLSearchParams({
      tenant_id: this.tenantId,
      store_id: this.storeId,
      from: String(from),
      limit: String(limit),
    });
    return this.request(
      `/api/v1/ves/entities/${encodeURIComponent(entityType)}/${encodeURIComponent(entityId)}?${query}`,
    );
  }

  getProjection(entityType, entityId, source = 'ves') {
    if (source !== 'ves' && source !== 'legacy') {
      throw new Error('source must be "ves" or "legacy"');
    }
    return this.request(
      `/api/v1/projections/${encodeURIComponent(entityType)}/${encodeURIComponent(entityId)}?${this.scopeQuery()}&source=${source}`,
    );
  }

  getInclusionProof(sequenceNumber) {
    return this.request(
      `/api/v1/ves/proofs/${encodeURIComponent(sequenceNumber)}?${this.scopeQuery()}`,
    );
  }

  verifyInclusionProof(proof) {
    return this.request('/api/v1/ves/proofs/verify', { method: 'POST', body: proof });
  }

  getCursor() {
    return this.request(
      `/api/v1/ves/cursors/${encodeURIComponent(this.agentId)}?${this.scopeQuery()}`,
    );
  }

  acknowledge(sequenceNumber) {
    if (!Number.isSafeInteger(sequenceNumber) || sequenceNumber < 0) {
      throw new TypeError('sequenceNumber must be a non-negative integer');
    }
    return this.request(`/api/v1/ves/cursors/${encodeURIComponent(this.agentId)}`, {
      method: 'PUT',
      body: {
        tenantId: this.tenantId,
        storeId: this.storeId,
        sequenceNumber,
      },
      retryable: true,
    });
  }

  getAgentPolicy(agentId = this.agentId) {
    const query = new URLSearchParams({ tenant_id: this.tenantId });
    return this.request(`/api/v1/agents/${encodeURIComponent(agentId)}/policy?${query}`);
  }

  setAgentPolicy(policy, agentId = this.agentId) {
    return this.request(`/api/v1/agents/${encodeURIComponent(agentId)}/policy`, {
      method: 'PUT',
      body: { ...policy, tenantId: this.tenantId },
      retryable: true,
    });
  }

  async waitForEvent(predicate, options = {}) {
    let cursor = options.from ?? 1;
    const pollIntervalMs = options.pollIntervalMs ?? 1_000;
    const deadline = Date.now() + (options.timeoutMs ?? 60_000);
    while (Date.now() < deadline) {
      if (options.signal?.aborted) throw options.signal.reason || new Error('Aborted');
      const page = await this.listEvents({ from: cursor, limit: options.limit ?? 100 });
      const events = page.events || page;
      for (const event of events) {
        if (await predicate(event)) return event;
      }
      cursor = page.next_sequence ?? page.nextSequence ?? nextCursor(events, cursor);
      await delay(Math.min(pollIntervalMs, Math.max(0, deadline - Date.now())), options.signal);
    }
    throw new SequencerApiError('Timed out waiting for a matching event', { code: 'TIMEOUT' });
  }

  scopeQuery() {
    return new URLSearchParams({ tenant_id: this.tenantId, store_id: this.storeId }).toString();
  }

  async request(path, options = {}) {
    const method = options.method || 'GET';
    const attempts = options.retryable || method === 'GET' ? this.maxRetries + 1 : 1;
    let lastError;
    for (let attempt = 0; attempt < attempts; attempt++) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
      const abortFromCaller = () => controller.abort(options.signal?.reason);
      options.signal?.addEventListener('abort', abortFromCaller, { once: true });
      try {
        const response = await this.fetch(`${this.baseUrl}${path}`, {
          method,
          headers: this.headers(options.headers),
          body: options.body === undefined ? undefined : JSON.stringify(options.body),
          signal: controller.signal,
        });
        const payload = await parseResponse(response);
        if (response.ok) return payload;

        const error = new SequencerApiError(
          payload?.message || payload?.error || `Sequencer request failed with ${response.status}`,
          {
            status: response.status,
            code: payload?.code,
            requestId: response.headers.get('x-request-id'),
            retryAfter: response.headers.get('retry-after'),
          },
        );
        if (!isRetryableStatus(response.status) || attempt + 1 === attempts) throw error;
        lastError = error;
      } catch (error) {
        if (error instanceof SequencerApiError && !isRetryableStatus(error.status)) throw error;
        lastError = error;
        if (attempt + 1 === attempts) {
          throw error instanceof SequencerApiError
            ? error
            : new SequencerApiError('Sequencer request failed', { cause: error });
        }
      } finally {
        clearTimeout(timeout);
        options.signal?.removeEventListener('abort', abortFromCaller);
      }
      await delay(Math.min(250 * 2 ** attempt, 2_000), options.signal);
    }
    throw lastError;
  }

  headers(extra = {}) {
    const headers = { Accept: 'application/json', 'Content-Type': 'application/json', ...extra };
    if (this.apiKey) headers.Authorization = `ApiKey ${this.apiKey}`;
    if (this.bearerToken) headers.Authorization = `Bearer ${this.bearerToken}`;
    return headers;
  }
}

export function loadVesPrivateKey(envVar = 'VES_PRIVATE_KEY') {
  const value = process.env[envVar];
  if (!value) throw new Error(`${envVar} environment variable not set`);
  const bytes = hexToBytes(value.replace(/^0x/, ''));
  if (bytes.length !== 32) throw new Error(`${envVar} must contain a 32-byte Ed25519 key`);
  return bytes;
}

function compactObject(value) {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined));
}

function toHex(value) {
  return `0x${bytesToHex(value)}`;
}

function u32be(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    throw new RangeError('Expected an unsigned 32-bit integer');
  }
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

function encodedString(value) {
  const bytes = encoder.encode(value);
  return concatBytes(u32be(bytes.length), bytes);
}

function uuidBytes(value) {
  const hex = value.replaceAll('-', '');
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) throw new TypeError(`Invalid UUID: ${value}`);
  return hexToBytes(hex);
}

function concatBytes(...parts) {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function isRetryableStatus(status) {
  return status === 408 || status === 425 || status === 429 || status >= 500;
}

async function parseResponse(response) {
  if (response.status === 204) return undefined;
  const text = await response.text();
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return { message: text };
  }
}

function nextCursor(events, fallback) {
  if (!events.length) return fallback;
  const last = events.at(-1);
  return (last.sequence_number ?? last.sequenceNumber ?? fallback) + 1;
}

function delay(ms, signal) {
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        reject(signal.reason || new Error('Aborted'));
      },
      { once: true },
    );
  });
}
