-- Per-user 2FA brute-force protection and replay prevention
ALTER TABLE users ADD COLUMN totp_failed_attempts INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN totp_locked_until TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN totp_last_step BIGINT;
