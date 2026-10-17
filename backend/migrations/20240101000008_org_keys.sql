-- Key hierarchy (see src/keys.rs). Nullable: an organization created by an older
-- beta has no key, and Cléa refuses to start with a clear message in that case.
-- Organization key locked with the master key ("k1:" format)
ALTER TABLE organizations ADD COLUMN locked_key TEXT;
-- Same organization key, locked for the recovery key pair, and the recovery public key
ALTER TABLE organizations ADD COLUMN recovery_locked_key TEXT;
ALTER TABLE organizations ADD COLUMN recovery_public_key TEXT;

-- When and how the current recovery key was created, shown in Mon profil so the owner
-- knows when the server admin replaced it. Not encrypted: technical data that does not
-- help to open anything.
ALTER TABLE organizations ADD COLUMN recovery_created_at TIMESTAMPTZ;
ALTER TABLE organizations ADD COLUMN recovery_source TEXT
    CHECK (recovery_source IN ('setup', 'profile', 'recover', 'new-recovery-key'));

-- Owner warning (Mon profil box + notification on every page) after the recovery key was
-- recreated on the server. Cleared when the owner replaces the key, checks it, or closes it.
ALTER TABLE organizations ADD COLUMN recovery_notice_pending BOOLEAN NOT NULL DEFAULT FALSE;
