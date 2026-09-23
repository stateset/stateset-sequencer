-- Every mutation of the durable privileged registries emits an audit entry in
-- the same transaction. The API may add an actor-rich entry after commit, but
-- this system entry survives a crash between the write and that API call.
CREATE FUNCTION sequencer_audit_privileged_change() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    row_data JSONB;
    tenant UUID;
BEGIN
    row_data := CASE WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
    tenant := NULLIF(row_data->>'tenant_id', '')::UUID;
    IF tenant IS NULL AND TG_TABLE_NAME = 'encryption_key_group_members' THEN
        SELECT tenant_id INTO tenant FROM encryption_key_groups
            WHERE group_id = (row_data->>'group_id')::UUID;
    END IF;
    INSERT INTO audit_log (
        id, action, actor, actor_type, tenant_id, resource_type,
        resource_id, details, success
    ) VALUES (
        gen_random_uuid(),
        TG_TABLE_NAME || '_' || lower(TG_OP),
        current_user, 'database', tenant, TG_TABLE_NAME,
        COALESCE(row_data->>'id', row_data->>'agent_id',
                 row_data->>'group_id', row_data->>'key_hash'),
        jsonb_build_object('operation', lower(TG_OP)), TRUE
    );
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER event_schemas_transaction_audit
    AFTER INSERT OR UPDATE OR DELETE ON event_schemas
    FOR EACH ROW EXECUTE FUNCTION sequencer_audit_privileged_change();
CREATE TRIGGER agent_policies_transaction_audit
    AFTER INSERT OR UPDATE OR DELETE ON agent_event_policies
    FOR EACH ROW EXECUTE FUNCTION sequencer_audit_privileged_change();
CREATE TRIGGER agent_signing_keys_transaction_audit
    AFTER INSERT OR UPDATE OR DELETE ON agent_signing_keys
    FOR EACH ROW EXECUTE FUNCTION sequencer_audit_privileged_change();
CREATE TRIGGER agent_encryption_keys_transaction_audit
    AFTER INSERT OR UPDATE OR DELETE ON agent_encryption_keys
    FOR EACH ROW EXECUTE FUNCTION sequencer_audit_privileged_change();
CREATE TRIGGER encryption_groups_transaction_audit
    AFTER INSERT OR UPDATE OR DELETE ON encryption_key_groups
    FOR EACH ROW EXECUTE FUNCTION sequencer_audit_privileged_change();
CREATE TRIGGER encryption_group_members_transaction_audit
    AFTER INSERT OR UPDATE OR DELETE ON encryption_key_group_members
    FOR EACH ROW EXECUTE FUNCTION sequencer_audit_privileged_change();
CREATE TRIGGER api_keys_transaction_audit
    AFTER INSERT OR UPDATE OR DELETE ON api_keys
    FOR EACH ROW EXECUTE FUNCTION sequencer_audit_privileged_change();
