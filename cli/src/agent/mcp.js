import { asMcpTools, createSequencerToolExecutor, sequencerTools } from './toolkit.js';

const PROTOCOL_VERSION = '2025-06-18';

export function createMcpRequestHandler(client, policy = {}) {
  const execute = createSequencerToolExecutor(client, policy);

  return async function handleRequest(request) {
    if (!request || request.jsonrpc !== '2.0' || typeof request.method !== 'string') {
      return rpcError(request?.id ?? null, -32600, 'Invalid Request');
    }
    if (request.id === undefined) return null;

    try {
      switch (request.method) {
        case 'initialize':
          return rpcResult(request.id, {
            protocolVersion: PROTOCOL_VERSION,
            capabilities: { tools: { listChanged: false } },
            serverInfo: { name: 'stateset-sequencer', version: '0.8.6' },
          });
        case 'ping':
          return rpcResult(request.id, {});
        case 'tools/list':
          return rpcResult(request.id, { tools: asMcpTools(sequencerTools) });
        case 'tools/call': {
          const name = request.params?.name;
          if (!name) return rpcError(request.id, -32602, 'Tool name is required');
          try {
            const result = await execute(name, request.params?.arguments || {});
            return rpcResult(request.id, {
              content: [{ type: 'text', text: JSON.stringify(result) }],
            });
          } catch (error) {
            return rpcResult(request.id, {
              isError: true,
              content: [{ type: 'text', text: safeErrorMessage(error) }],
            });
          }
        }
        default:
          return rpcError(request.id, -32601, `Method not found: ${request.method}`);
      }
    } catch (error) {
      return rpcError(request.id, -32603, safeErrorMessage(error));
    }
  };
}

function rpcResult(id, result) {
  return { jsonrpc: '2.0', id, result };
}

function rpcError(id, code, message) {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

function safeErrorMessage(error) {
  if (error && typeof error === 'object' && error.status >= 500) {
    return `Sequencer request failed with status ${error.status}`;
  }
  return error instanceof Error ? error.message : 'Unknown error';
}
