-- x402 nonce-tracking retention support
--
-- Nonce rows only need to outlive the window in which a replayed intent could
-- still be accepted. Submission caps valid_until at created_at +
-- X402_MAX_VALIDITY_SECS, and ingest rejects any intent whose valid_until is in
-- the past, so a nonce older than the maximum validity window can be pruned: a
-- replay of its intent is already rejected by the expiry check. The background
-- sweep (spawn_x402_nonce_cleanup) deletes by created_at; this index keeps that
-- DELETE from scanning the whole table.

CREATE INDEX IF NOT EXISTS idx_x402_nonce_created_at
  ON x402_nonce_tracking (created_at);

COMMENT ON INDEX idx_x402_nonce_created_at IS
  'Supports periodic pruning of expired x402 nonce rows by created_at';
