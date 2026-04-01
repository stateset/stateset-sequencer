-- PQC migration: add algorithm-aware key registration and signature fields
-- VES-PQC-1: supports legacy, hybrid (ed25519+mldsa65), and pqc-strict (mldsa65) profiles

-- 1. Extend agent_signing_keys with algorithm metadata and PQC key bundles
ALTER TABLE agent_signing_keys
  ADD COLUMN IF NOT EXISTS key_algorithm SMALLINT NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS public_key_bundle BYTEA,
  ADD COLUMN IF NOT EXISTS proof_of_possession BYTEA,
  ADD COLUMN IF NOT EXISTS proof_of_possession_bundle BYTEA;

-- key_algorithm values:
--   1 = ED25519 (legacy signing)
--   2 = X25519 (legacy encryption)
--   3 = ML_DSA_65 (pqc-strict signing)
--   4 = ML_KEM_768 (pqc-strict encryption)
--   5 = ED25519_ML_DSA_65 (hybrid signing)
--   6 = X25519_ML_KEM_768 (hybrid encryption)

COMMENT ON COLUMN agent_signing_keys.key_algorithm IS 'KeyAlgorithm enum: 1=ED25519, 3=ML_DSA_65, 5=ED25519_ML_DSA_65';
COMMENT ON COLUMN agent_signing_keys.public_key_bundle IS 'Serialized PublicKeyBundle for algorithm-aware keys';
COMMENT ON COLUMN agent_signing_keys.proof_of_possession IS 'Legacy Ed25519 PoP signature';
COMMENT ON COLUMN agent_signing_keys.proof_of_possession_bundle IS 'Serialized ProofOfPossessionBundle for hybrid/strict PoP';

-- 2. Extend ves_events with PQC signature metadata
ALTER TABLE ves_events
  ADD COLUMN IF NOT EXISTS agent_signature_scheme SMALLINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS agent_signature_bundle BYTEA;

-- agent_signature_scheme values:
--   0 = UNSPECIFIED (legacy Ed25519, uses agent_signature column)
--   1 = ED25519
--   2 = ML_DSA_65
--   3 = ED25519_ML_DSA_65

COMMENT ON COLUMN ves_events.agent_signature_scheme IS 'SignatureScheme enum for PQC migration';
COMMENT ON COLUMN ves_events.agent_signature_bundle IS 'Serialized SignatureBundle with PQC signature material';

-- 3. Extend ves_sequencer_receipts with PQC receipt signature fields
ALTER TABLE ves_sequencer_receipts
  ADD COLUMN IF NOT EXISTS receipt_signature_scheme SMALLINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS receipt_signature_bundle BYTEA;

COMMENT ON COLUMN ves_sequencer_receipts.receipt_signature_scheme IS 'SignatureScheme for PQC receipt signing (VES-RECEIPT-2)';
COMMENT ON COLUMN ves_sequencer_receipts.receipt_signature_bundle IS 'Serialized SignatureBundle with PQC receipt signature material';

-- 4. Index for filtering by key algorithm (useful for migration tracking)
CREATE INDEX IF NOT EXISTS idx_agent_keys_algorithm
  ON agent_signing_keys (tenant_id, key_algorithm);
