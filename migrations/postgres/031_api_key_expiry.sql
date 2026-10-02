-- Optional hard expiry for API keys; NULL keeps existing keys non-expiring.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
