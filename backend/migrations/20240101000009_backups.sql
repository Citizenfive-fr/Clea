-- Encrypted backups (one row max, like setup_state). The files live in BACKUP_DIR.
CREATE TABLE backup_settings (
    id              INT PRIMARY KEY DEFAULT 1,
    -- Organization that created the backup key (an instance holds one organization)
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    -- Public part of the backup key (`b1:` + hex). The private part is never stored.
    public_key      TEXT,
    key_created_at  TIMESTAMPTZ,
    frequency       TEXT NOT NULL DEFAULT 'daily'
                    CHECK (frequency IN ('daily', 'weekly', 'monthly', 'manual')),
    -- Day of the month for 'monthly' (up to 28: the date exists every month)
    month_day       INT NOT NULL DEFAULT 1 CHECK (month_day BETWEEN 1 AND 28),
    -- Day of the week for 'weekly' (1 = Monday ... 7 = Sunday)
    week_day        INT NOT NULL DEFAULT 1 CHECK (week_day BETWEEN 1 AND 7),
    retention_days  INT NOT NULL DEFAULT 30 CHECK (retention_days BETWEEN 1 AND 3650),
    -- Kept here and not read from the files: an expired backup deleted early must not
    -- trigger a new one before its time
    last_backup_at  TIMESTAMPTZ,
    CONSTRAINT single_row CHECK (id = 1)
);
INSERT INTO backup_settings (id) VALUES (1);
