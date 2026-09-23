CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    tenant_id UUID,
    resource_type TEXT,
    resource_id TEXT,
    request_id TEXT,
    ip_address TEXT,
    user_agent TEXT,
    details JSONB,
    success BOOLEAN NOT NULL DEFAULT TRUE,
    error_message TEXT
);

ALTER TABLE audit_log ADD COLUMN chain_seq BIGINT;
ALTER TABLE audit_log ADD COLUMN previous_hash BYTEA;
ALTER TABLE audit_log ADD COLUMN entry_hash BYTEA;

-- Backfill legacy rows deterministically before installing append-only guards.
DO $$
DECLARE
    item RECORD;
    next_seq BIGINT := 0;
    previous BYTEA := decode(repeat('00', 32), 'hex');
    current_hash BYTEA;
BEGIN
    FOR item IN SELECT * FROM audit_log ORDER BY timestamp, id LOOP
        next_seq := next_seq + 1;
        UPDATE audit_log SET chain_seq = next_seq, previous_hash = previous
            WHERE id = item.id;
        SELECT digest(previous || convert_to(
            (to_jsonb(a) - 'previous_hash' - 'entry_hash')::text, 'UTF8'),
            'sha256') INTO current_hash FROM audit_log a WHERE a.id = item.id;
        UPDATE audit_log SET entry_hash = current_hash WHERE id = item.id;
        previous := current_hash;
    END LOOP;
END;
$$;

ALTER TABLE audit_log ALTER COLUMN chain_seq SET NOT NULL;
ALTER TABLE audit_log ALTER COLUMN previous_hash SET NOT NULL;
ALTER TABLE audit_log ALTER COLUMN entry_hash SET NOT NULL;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_chain_seq_unique UNIQUE (chain_seq);
ALTER TABLE audit_log ADD CONSTRAINT audit_log_hash_lengths CHECK (
    octet_length(previous_hash) = 32 AND octet_length(entry_hash) = 32
);

CREATE FUNCTION sequencer_audit_append() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    tail_seq BIGINT;
    tail_hash BYTEA;
BEGIN
    IF NEW.chain_seq IS NOT NULL OR NEW.previous_hash IS NOT NULL
       OR NEW.entry_hash IS NOT NULL THEN
        RAISE EXCEPTION 'audit chain fields are server-managed';
    END IF;
    PERFORM pg_advisory_xact_lock(6004514665705169237);
    SELECT chain_seq, entry_hash INTO tail_seq, tail_hash
        FROM audit_log ORDER BY chain_seq DESC LIMIT 1;
    NEW.chain_seq := COALESCE(tail_seq, 0) + 1;
    NEW.previous_hash := COALESCE(tail_hash, decode(repeat('00', 32), 'hex'));
    NEW.entry_hash := digest(NEW.previous_hash || convert_to(
        (to_jsonb(NEW) - 'previous_hash' - 'entry_hash')::text, 'UTF8'),
        'sha256');
    RETURN NEW;
END;
$$;

CREATE FUNCTION sequencer_audit_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit log is append-only';
END;
$$;

CREATE TRIGGER audit_log_append BEFORE INSERT ON audit_log
    FOR EACH ROW EXECUTE FUNCTION sequencer_audit_append();
CREATE TRIGGER audit_log_immutable BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION sequencer_audit_immutable();

CREATE FUNCTION sequencer_verify_audit_chain() RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE
    item RECORD;
    expected_seq BIGINT := 0;
    previous BYTEA := decode(repeat('00', 32), 'hex');
BEGIN
    FOR item IN SELECT * FROM audit_log ORDER BY chain_seq LOOP
        expected_seq := expected_seq + 1;
        IF item.chain_seq <> expected_seq OR item.previous_hash <> previous
           OR item.entry_hash <> digest(previous || convert_to(
               (to_jsonb(item) - 'previous_hash' - 'entry_hash')::text,
               'UTF8'), 'sha256') THEN
            RETURN FALSE;
        END IF;
        previous := item.entry_hash;
    END LOOP;
    RETURN TRUE;
END;
$$;
