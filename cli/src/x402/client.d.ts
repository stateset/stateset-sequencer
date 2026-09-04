export class X402Client {
  constructor(options: Record<string, unknown>);
  computeSigningHash(params: Record<string, unknown>): Uint8Array;
  signPaymentIntent(params: Record<string, unknown>): Promise<Record<string, unknown>>;
  submitPayment(params: Record<string, unknown>): Promise<Record<string, unknown>>;
  getStatus(intentId: string): Promise<Record<string, unknown>>;
  getReceipt(intentId: string): Promise<Record<string, unknown>>;
  listPayments(filter?: Record<string, unknown>): Promise<Record<string, unknown>>;
  createBatch(options?: Record<string, unknown>): Promise<Record<string, unknown>>;
  getBatch(batchId: string): Promise<Record<string, unknown>>;
}
