CREATE TABLE news_favorites (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    added_by        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    link            TEXT NOT NULL,
    source          TEXT NOT NULL,
    title           TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(organization_id, link)
);
CREATE INDEX news_favorites_organization_id_idx ON news_favorites(organization_id);
