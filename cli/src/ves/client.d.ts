export interface VesClientOptions {
  baseUrl?: string;
  tenantId: string;
  storeId: string;
  agentId: string;
  keyId?: number;
  privateKey: Uint8Array;
  apiKey?: string;
  bearerToken?: string;
  fetch?: typeof globalThis.fetch;
  maxRetries?: number;
  timeoutMs?: number;
}

export interface CreateEventParams {
  entityType: string;
  entityId: string;
  eventType: string;
  payload: Record<string, unknown>;
  commandId?: string;
  baseVersion?: number;
  eventId?: string;
  createdAt?: string;
}

export interface WaitForEventOptions {
  from?: number;
  limit?: number;
  pollIntervalMs?: number;
  timeoutMs?: number;
  signal?: AbortSignal;
}

export class SequencerApiError extends Error {
  status: number;
  code?: string;
  requestId?: string;
  retryAfter?: string;
}

export class VesClient {
  constructor(options: VesClientOptions);
  createEvent(params: CreateEventParams): Promise<Record<string, unknown>>;
  ingest(events: Array<Record<string, unknown>>): Promise<Record<string, unknown>>;
  recordAction(params: CreateEventParams): Promise<{
    event: Record<string, unknown>;
    receipt?: Record<string, unknown>;
    result: Record<string, unknown>;
  }>;
  getHead(): Promise<Record<string, unknown>>;
  listEvents(options?: { from?: number; limit?: number }): Promise<Record<string, unknown>>;
  getEntityHistory(
    entityType: string,
    entityId: string,
    options?: { from?: number; limit?: number },
  ): Promise<Record<string, unknown>>;
  getProjection(
    entityType: string,
    entityId: string,
    source?: 'ves' | 'legacy',
  ): Promise<Record<string, unknown>>;
  getInclusionProof(sequenceNumber: number): Promise<Record<string, unknown>>;
  verifyInclusionProof(proof: unknown): Promise<Record<string, unknown>>;
  getCursor(): Promise<Record<string, unknown>>;
  acknowledge(sequenceNumber: number): Promise<Record<string, unknown>>;
  getAgentPolicy(agentId?: string): Promise<Record<string, unknown>>;
  setAgentPolicy(
    policy: {
      allowedEventTypes: string[];
      allowedEntityTypes: string[];
      requireBaseVersion?: boolean;
      maxPayloadBytes?: number;
      enabled?: boolean;
    },
    agentId?: string,
  ): Promise<Record<string, unknown>>;
  waitForEvent(
    predicate: (event: Record<string, unknown>) => boolean | Promise<boolean>,
    options?: WaitForEventOptions,
  ): Promise<Record<string, unknown>>;
}

export function canonicalizeJson(value: unknown): string;
export function computePayloadPlainHash(payload: unknown): Uint8Array;
export function computeEventSigningHash(params: {
  vesVersion: number;
  tenantId: string;
  storeId: string;
  eventId: string;
  sourceAgentId: string;
  agentKeyId: number;
  entityType: string;
  entityId: string;
  eventType: string;
  createdAt: string;
  payloadKind: number;
  payloadPlainHash: Uint8Array;
  payloadCipherHash: Uint8Array;
}): Uint8Array;
export function loadVesPrivateKey(envVar?: string): Uint8Array;
