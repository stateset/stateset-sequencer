-- Migration 014: widen event identifier columns to match runtime validation.
--
-- Runtime validation accepts:
-- - entity_type up to 128 chars
-- - entity_id up to 512 chars
-- - event_type up to 256 chars
--
-- Earlier migrations created narrower columns in events/ves_events and related
-- helper tables, which allowed requests to pass validation and then fail at
-- insert time. This migration aligns the persisted schema with the runtime.

ALTER TABLE IF EXISTS events
    ALTER COLUMN entity_type TYPE VARCHAR(128),
    ALTER COLUMN entity_id TYPE VARCHAR(512),
    ALTER COLUMN event_type TYPE VARCHAR(256);

ALTER TABLE IF EXISTS ves_events
    ALTER COLUMN entity_type TYPE VARCHAR(128),
    ALTER COLUMN entity_id TYPE VARCHAR(512),
    ALTER COLUMN event_type TYPE VARCHAR(256);

ALTER TABLE IF EXISTS rejected_events_log
    ALTER COLUMN entity_type TYPE VARCHAR(128),
    ALTER COLUMN entity_id TYPE VARCHAR(512);

CREATE OR REPLACE FUNCTION update_entity_version(
    p_tenant_id UUID,
    p_store_id UUID,
    p_entity_type VARCHAR(128),
    p_entity_id VARCHAR(512),
    p_expected_version BIGINT
) RETURNS BIGINT AS $$
DECLARE
    v_current_version BIGINT;
    v_new_version BIGINT;
BEGIN
    SELECT version INTO v_current_version
    FROM entity_versions
    WHERE tenant_id = p_tenant_id
      AND store_id = p_store_id
      AND entity_type = p_entity_type
      AND entity_id = p_entity_id
    FOR UPDATE;

    IF v_current_version IS NOT NULL AND p_expected_version IS NOT NULL THEN
        IF v_current_version != p_expected_version THEN
            RETURN -v_current_version;
        END IF;
    END IF;

    v_new_version := COALESCE(v_current_version, 0) + 1;

    INSERT INTO entity_versions (tenant_id, store_id, entity_type, entity_id, version, updated_at)
    VALUES (p_tenant_id, p_store_id, p_entity_type, p_entity_id, v_new_version, NOW())
    ON CONFLICT (tenant_id, store_id, entity_type, entity_id)
    DO UPDATE SET
        version = v_new_version,
        updated_at = NOW();

    RETURN v_new_version;
END;
$$ LANGUAGE plpgsql;
