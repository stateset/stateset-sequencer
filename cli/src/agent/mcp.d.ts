import type { VesClient } from '../ves/client.js';
import type { SequencerToolPolicy } from './toolkit.js';

export function createMcpRequestHandler(
  client: VesClient,
  policy?: SequencerToolPolicy,
): (request: Record<string, unknown>) => Promise<Record<string, unknown> | null>;
