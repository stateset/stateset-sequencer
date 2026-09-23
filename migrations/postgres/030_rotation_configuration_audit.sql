-- Rotation policy and schedule changes must enter the audit chain in the
-- same transaction as the configuration change.
CREATE TRIGGER key_rotation_policies_transaction_audit
    AFTER INSERT OR UPDATE OR DELETE ON key_rotation_policies
    FOR EACH ROW EXECUTE FUNCTION sequencer_audit_privileged_change();

CREATE TRIGGER scheduled_key_rotations_transaction_audit
    AFTER INSERT OR UPDATE OR DELETE ON scheduled_key_rotations
    FOR EACH ROW EXECUTE FUNCTION sequencer_audit_privileged_change();
