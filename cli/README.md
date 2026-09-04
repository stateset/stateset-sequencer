# StateSet agent SDK

The package provides a VES client, model-tool definitions, an MCP stdio server,
and the existing x402 CLI. It requires Node.js 18 or newer.

```bash
cd cli
npm ci
```

## Record a signed action

```js
import { VesClient, loadVesPrivateKey } from '@stateset/x402-cli';

const sequencer = new VesClient({
  baseUrl: process.env.STATESET_SEQUENCER_URL,
  tenantId: process.env.STATESET_TENANT_ID,
  storeId: process.env.STATESET_STORE_ID,
  agentId: process.env.STATESET_AGENT_ID,
  keyId: Number(process.env.STATESET_AGENT_KEY_ID || 1),
  apiKey: process.env.STATESET_API_KEY,
  privateKey: loadVesPrivateKey(),
});

const result = await sequencer.recordAction({
  entityType: 'order',
  entityId: 'ORD-123',
  eventType: 'order.confirmed',
  commandId: crypto.randomUUID(),
  baseVersion: 1,
  payload: { approvedBy: 'fulfillment-agent' },
});
```

`commandId` should identify the logical action, not an individual network
attempt. Reuse it when retrying so the sequencer can return the original result
without applying the action twice.

After an agent has durably processed events, persist its monotonic server-side
cursor. A stale acknowledgement cannot move the cursor backwards:

```js
await sequencer.acknowledge(lastProcessedSequence);
const { acknowledgedSequence, lag } = await sequencer.getCursor();
```

Administrators can configure a second, authoritative policy boundary with
`getAgentPolicy()` and `setAgentPolicy()`. Server policies apply equally to
REST, gRPC, SDK, and MCP writes; local MCP allowlists remain useful as an
additional least-privilege boundary.

## Give tools to a model

```js
import {
  createSequencerToolExecutor,
  sequencerTools,
} from '@stateset/x402-cli/agent-tools';

const execute = createSequencerToolExecutor(sequencer, {
  allowedEventTypes: ['order.confirmed', 'order.cancelled'],
  requireBaseVersion: true,
  validateAction: async (action) => {
    if (action.eventType === 'order.cancelled' && !action.payload.reason) {
      throw new Error('Cancellation reason is required');
    }
  },
});

// Pass `sequencerTools` to an OpenAI-compatible model. When it returns a tool
// call, execute it outside the model and return the result to the conversation.
const output = await execute(toolCall.function.name, toolCall.function.arguments);
```

Keep the private key and API credential in the tool host. Never put either one
in model context.

## MCP server

The package includes a newline-delimited JSON-RPC MCP stdio server:

```json
{
  "mcpServers": {
    "stateset": {
      "command": "stateset-agent-mcp",
      "env": {
        "STATESET_SEQUENCER_URL": "https://sequencer.example.com",
        "STATESET_TENANT_ID": "<tenant-uuid>",
        "STATESET_STORE_ID": "<store-uuid>",
        "STATESET_AGENT_ID": "<agent-uuid>",
        "STATESET_AGENT_KEY_ID": "1",
        "STATESET_API_KEY": "<secret>",
        "VES_PRIVATE_KEY": "<32-byte-ed25519-key-hex>",
        "STATESET_ALLOWED_EVENT_TYPES": "order.confirmed,order.cancelled",
        "STATESET_REQUIRE_BASE_VERSION": "true"
      }
    }
  }
}
```

Available tools read entity history and stream heads, record signed actions,
wait from an explicit cursor, and retrieve inclusion proofs. Write tools enforce
the local event-type and entity-version policy before contacting the server.
If `STATESET_ALLOWED_EVENT_TYPES` is absent, the MCP server is read-only.
