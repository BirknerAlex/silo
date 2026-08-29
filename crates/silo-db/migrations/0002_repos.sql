-- Per-repo visibility.
--
-- A repo previously existed only implicitly, as whatever distinct `repo`
-- values `packages` happened to contain. This gives it a real row, so
-- there's somewhere to hang a per-repo setting: whether it's readable
-- without a credential. A row is created the moment a repo is first
-- published to (private by default) or the moment an admin sets its mode
-- ahead of that.
CREATE TABLE repos (
    repo       TEXT PRIMARY KEY,
    public     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
