-- Migration 013: Widen entity_versions columns + add receipt key version
--
-- The entity_versions table was created in 001 with VARCHAR(64)/VARCHAR(256)
-- for entity_type/entity_id. VES v1.0 spec allows 128/512 respectively.
-- This migration aligns the schema with the VES constants.
--
-- Also adds sequencer_key_version to ves_sequencer_receipts for receipt
-- verification by third parties (yellowpaper Section 10.3).

-- Widen entity_versions to match VES limits
ALTER TABLE entity_versions
    ALTER COLUMN entity_type TYPE VARCHAR(128),
    ALTER COLUMN entity_id TYPE VARCHAR(512);

-- Add sequencer_key_version to receipts
ALTER TABLE ves_sequencer_receipts
    ADD COLUMN IF NOT EXISTS sequencer_key_version INTEGER NOT NULL DEFAULT 0;
