-- 2FA lockout moved to the in-memory rate limiter (escalating bans, shared with login)
ALTER TABLE users DROP COLUMN totp_failed_attempts;
ALTER TABLE users DROP COLUMN totp_locked_until;
