-- x402 on-chain settlement: per-payment EIP-712 payer authorization.
--
-- Adds the two fields the SetPaymentBatch.settleBatch calldata requires beyond
-- the existing StateSet Ed25519 scheme:
--
--   * valid_after            -- EIP-712 `validAfter` lower validity bound
--   * eip712_authorization   -- payer's EIP-712 signature over
--                               PaymentAuthorization(intentId,payer,payee,token,
--                               amount,nonce,validAfter,validBefore)
--
-- Both are OPTIONAL / backward-compatible: intents ingested before this
-- migration (or without an authorization) keep working exactly as before and
-- are simply not on-chain-settleable. NULL eip712_authorization = not settleable.

ALTER TABLE x402_payment_intents
    ADD COLUMN IF NOT EXISTS valid_after BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS eip712_authorization BYTEA;

-- The autonomous settlement worker selects committed batches that contain at
-- least one on-chain-authorized payment. This partial index keeps that EXISTS
-- probe cheap.
CREATE INDEX IF NOT EXISTS idx_x402_intents_authorized
    ON x402_payment_intents (batch_id)
    WHERE eip712_authorization IS NOT NULL AND batch_id IS NOT NULL;
