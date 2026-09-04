import {
  VesClient,
  createSequencerToolExecutor,
  loadVesPrivateKey,
  sequencerTools,
} from '../cli/src/index.js';

const sequencer = new VesClient({
  baseUrl: process.env.STATESET_SEQUENCER_URL,
  tenantId: process.env.STATESET_TENANT_ID,
  storeId: process.env.STATESET_STORE_ID,
  agentId: process.env.STATESET_AGENT_ID,
  keyId: Number(process.env.STATESET_AGENT_KEY_ID || 1),
  apiKey: process.env.STATESET_API_KEY,
  privateKey: loadVesPrivateKey(),
});

export const tools = sequencerTools;
export const executeTool = createSequencerToolExecutor(sequencer, {
  allowedEventTypes: (process.env.STATESET_ALLOWED_EVENT_TYPES || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean),
  requireBaseVersion: true,
});
