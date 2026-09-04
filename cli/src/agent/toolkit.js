/** OpenAI-compatible function tools backed by a {@link VesClient}. */

export const sequencerTools = [
  {
    type: 'function',
    function: {
      name: 'stateset_get_head',
      description: 'Get the authoritative latest sequence for the configured tenant and store.',
      parameters: { type: 'object', additionalProperties: false, properties: {} },
    },
  },
  {
    type: 'function',
    function: {
      name: 'stateset_get_entity_history',
      description: 'Read the authoritative ordered history for a commerce entity.',
      parameters: {
        type: 'object',
        additionalProperties: false,
        required: ['entityType', 'entityId'],
        properties: {
          entityType: { type: 'string', description: 'For example order or inventory.' },
          entityId: { type: 'string' },
          from: { type: 'integer', minimum: 0, default: 0 },
          limit: { type: 'integer', minimum: 1, maximum: 100, default: 100 },
        },
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'stateset_get_projection',
      description:
        'Read the latest durable materialized state for a commerce entity. Use history when causality is needed and projection when current state is needed.',
      parameters: {
        type: 'object',
        additionalProperties: false,
        required: ['entityType', 'entityId'],
        properties: {
          entityType: { type: 'string', description: 'For example order or inventory.' },
          entityId: { type: 'string' },
        },
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'stateset_record_action',
      description:
        'Sign and append an idempotent action to the authoritative event stream. Supply baseVersion when modifying an existing entity.',
      parameters: {
        type: 'object',
        additionalProperties: false,
        required: ['entityType', 'entityId', 'eventType', 'payload', 'commandId'],
        properties: {
          entityType: { type: 'string' },
          entityId: { type: 'string' },
          eventType: { type: 'string' },
          payload: { type: 'object' },
          commandId: { type: 'string', format: 'uuid', description: 'Stable UUID for safe retries.' },
          baseVersion: { type: 'integer', minimum: 0 },
        },
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'stateset_get_inclusion_proof',
      description: 'Get cryptographic proof that a sequence is included in a committed batch.',
      parameters: {
        type: 'object',
        additionalProperties: false,
        required: ['sequenceNumber'],
        properties: { sequenceNumber: { type: 'integer', minimum: 1 } },
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'stateset_get_cursor',
      description: 'Read this agent’s durable acknowledged sequence and current stream lag.',
      parameters: { type: 'object', additionalProperties: false, properties: {} },
    },
  },
  {
    type: 'function',
    function: {
      name: 'stateset_acknowledge',
      description:
        'Persist the highest sequence this agent has durably processed. Call only after side effects and state updates succeed.',
      parameters: {
        type: 'object',
        additionalProperties: false,
        required: ['sequenceNumber'],
        properties: { sequenceNumber: { type: 'integer', minimum: 0 } },
      },
    },
  },
  {
    type: 'function',
    function: {
      name: 'stateset_wait_for_event',
      description: 'Wait briefly for a matching event, starting at an explicit durable cursor.',
      parameters: {
        type: 'object',
        additionalProperties: false,
        required: ['from'],
        properties: {
          from: { type: 'integer', minimum: 1 },
          entityType: { type: 'string' },
          entityId: { type: 'string' },
          eventType: { type: 'string' },
          timeoutMs: { type: 'integer', minimum: 1, maximum: 30000, default: 15000 },
        },
      },
    },
  },
];

export function createSequencerToolExecutor(client, options = {}) {
  async function recordAction(args) {
    if (options.allowedEventTypes && !matchesAny(options.allowedEventTypes, args.eventType)) {
      throw new Error(`Event type is not allowed for this agent: ${args.eventType}`);
    }
    if (options.allowedEntityTypes && !matchesAny(options.allowedEntityTypes, args.entityType)) {
      throw new Error(`Entity type is not allowed for this agent: ${args.entityType}`);
    }
    if (
      options.requireBaseVersion &&
      !args.eventType.endsWith('.created') &&
      args.baseVersion === undefined
    ) {
      throw new Error('baseVersion is required when modifying an existing entity');
    }
    if (
      options.maxPayloadBytes !== undefined &&
      new TextEncoder().encode(JSON.stringify(args.payload)).byteLength > options.maxPayloadBytes
    ) {
      throw new Error(`Payload exceeds this agent's ${options.maxPayloadBytes} byte policy limit`);
    }
    await options.validateAction?.(args);
    return client.recordAction(args);
  }

  const handlers = {
    stateset_get_head: () => client.getHead(),
    stateset_get_entity_history: ({ entityType, entityId, from, limit }) =>
      client.getEntityHistory(entityType, entityId, { from, limit }),
    stateset_get_projection: ({ entityType, entityId }) =>
      client.getProjection(entityType, entityId),
    stateset_record_action: recordAction,
    stateset_get_inclusion_proof: ({ sequenceNumber }) =>
      client.getInclusionProof(sequenceNumber),
    stateset_get_cursor: () => client.getCursor(),
    stateset_acknowledge: ({ sequenceNumber }) => client.acknowledge(sequenceNumber),
    stateset_wait_for_event: ({ from, entityType, entityId, eventType, timeoutMs }) =>
      client.waitForEvent(
        (event) => {
          const envelope = event.envelope || event;
          return (
            (!entityType || (envelope.entity_type ?? envelope.entityType) === entityType) &&
            (!entityId || (envelope.entity_id ?? envelope.entityId) === entityId) &&
            (!eventType || (envelope.event_type ?? envelope.eventType) === eventType)
          );
        },
        { from, timeoutMs: Math.min(timeoutMs ?? 15000, 30000) },
      ),
  };

  return async function executeSequencerTool(name, argumentsJson) {
    const handler = handlers[name];
    if (!handler) throw new Error(`Unknown StateSet tool: ${name}`);
    const args = typeof argumentsJson === 'string' ? JSON.parse(argumentsJson) : argumentsJson;
    const normalized = args || {};
    validateToolArguments(name, normalized);
    return handler(normalized);
  };
}

/** Validate model-provided arguments at the trusted tool boundary. */
export function validateToolArguments(name, args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) {
    throw new TypeError('Tool arguments must be a JSON object');
  }

  if (
    name === 'stateset_get_entity_history' ||
    name === 'stateset_get_projection' ||
    name === 'stateset_record_action'
  ) {
    boundedString(args.entityType, 'entityType', 128);
    boundedString(args.entityId, 'entityId', 512);
  }
  if (name === 'stateset_get_entity_history') {
    optionalInteger(args.from, 'from', 0);
    optionalInteger(args.limit, 'limit', 1, 100);
  }
  if (name === 'stateset_record_action') {
    boundedString(args.eventType, 'eventType', 256);
    if (!args.payload || typeof args.payload !== 'object' || Array.isArray(args.payload)) {
      throw new TypeError('payload must be a JSON object');
    }
    if (!isUuid(args.commandId)) throw new TypeError('commandId must be a UUID');
    optionalInteger(args.baseVersion, 'baseVersion', 0);
  }
  if (name === 'stateset_get_inclusion_proof') {
    requiredInteger(args.sequenceNumber, 'sequenceNumber', 1);
  }
  if (name === 'stateset_acknowledge') {
    requiredInteger(args.sequenceNumber, 'sequenceNumber', 0);
  }
  if (name === 'stateset_wait_for_event') {
    requiredInteger(args.from, 'from', 1);
    if (args.entityType !== undefined) boundedString(args.entityType, 'entityType', 128);
    if (args.entityId !== undefined) boundedString(args.entityId, 'entityId', 512);
    if (args.eventType !== undefined) boundedString(args.eventType, 'eventType', 256);
    optionalInteger(args.timeoutMs, 'timeoutMs', 1, 30000);
  }
}

function matchesAny(patterns, value) {
  return patterns.some(
    (pattern) =>
      pattern === '*' ||
      pattern === value ||
      (pattern.endsWith('*') && value.startsWith(pattern.slice(0, -1))),
  );
}

function boundedString(value, name, maxLength) {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) {
    throw new TypeError(`${name} must be a non-empty string of at most ${maxLength} characters`);
  }
}

function requiredInteger(value, name, minimum, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
}

function optionalInteger(value, name, minimum, maximum) {
  if (value !== undefined) requiredInteger(value, name, minimum, maximum);
}

function isUuid(value) {
  return (
    typeof value === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      value,
    )
  );
}

export function asMcpTools(tools = sequencerTools) {
  return tools.map(({ function: tool }) => ({
    name: tool.name,
    description: tool.description,
    inputSchema: tool.parameters,
  }));
}
