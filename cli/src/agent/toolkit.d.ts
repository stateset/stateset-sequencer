import type { VesClient } from '../ves/client.js';

export interface SequencerToolPolicy {
  allowedEventTypes?: string[];
  requireBaseVersion?: boolean;
  validateAction?: (action: Record<string, unknown>) => void | Promise<void>;
}

export interface FunctionTool {
  type: 'function';
  function: {
    name: string;
    description: string;
    parameters: Record<string, unknown>;
  };
}

export const sequencerTools: FunctionTool[];
export function createSequencerToolExecutor(
  client: VesClient,
  options?: SequencerToolPolicy,
): (name: string, argumentsJson: string | Record<string, unknown>) => Promise<unknown>;
export function validateToolArguments(name: string, args: Record<string, unknown>): void;
export function asMcpTools(tools?: FunctionTool[]): Array<{
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}>;
