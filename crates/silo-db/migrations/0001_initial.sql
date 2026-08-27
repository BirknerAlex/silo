-- Initial schema.
--
-- Silo keeps package *bytes* in object storage and everything else here.
-- The package table in particular exists so a publish never has to LIST
-- the bucket to find out what else is in a repo/channel: index
-- regeneration reads rows, not objects.

CREATE TABLE users (
    id            UUID PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    -- argon2id PHC string. NULL for users that authenticate via OIDC only.
    password_hash TEXT,
    -- OIDC `sub` claim, which is the only stable per-issuer identifier.
    oidc_subject  TEXT UNIQUE,
    is_admin      BOOLEAN NOT NULL DEFAULT FALSE,
    disabled      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ
);

-- Tokens are never stored in a recoverable form. `prefix` is the public
-- half used to find the row; `secret_hash` is SHA-256 over
-- salt || secret || server pepper. See silo-db/src/tokens.rs for why a
-- fast hash is the right choice for 256-bit random secrets.
CREATE TABLE tokens (
    id           UUID PRIMARY KEY,
    name         TEXT NOT NULL,
    prefix       TEXT NOT NULL UNIQUE,
    salt         BYTEA NOT NULL,
    secret_hash  BYTEA NOT NULL,
    -- 'read' | 'write' | 'admin'
    permission   TEXT NOT NULL,
    -- 'api' (long-lived, created explicitly) | 'session' (issued by login)
    kind         TEXT NOT NULL DEFAULT 'api',
    -- TRUE grants every repo; otherwise `repos` enumerates the grants.
    scope_all    BOOLEAN NOT NULL DEFAULT FALSE,
    repos        TEXT[] NOT NULL DEFAULT '{}',
    user_id      UUID REFERENCES users (id) ON DELETE CASCADE,
    created_by   UUID REFERENCES users (id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- NULL means the token never expires.
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);

CREATE INDEX tokens_user_idx ON tokens (user_id);

CREATE TABLE packages (
    id                 BIGSERIAL PRIMARY KEY,
    repo               TEXT NOT NULL,
    channel            TEXT NOT NULL,
    format             TEXT NOT NULL,
    -- Which index this package belongs to: '' for rpm (one repodata per
    -- channel), the arch for apk, the package name for npm.
    index_group        TEXT NOT NULL DEFAULT '',
    name               TEXT NOT NULL,
    epoch              INTEGER NOT NULL DEFAULT 0,
    version            TEXT NOT NULL,
    release            TEXT NOT NULL DEFAULT '',
    arch               TEXT NOT NULL DEFAULT '',
    filename           TEXT NOT NULL,
    storage_key        TEXT NOT NULL,
    size_bytes         BIGINT NOT NULL,
    sha256             TEXT NOT NULL,
    -- Format-specific fields the index needs (APKINDEX record fields, the
    -- npm package.json). Stored verbatim so index regeneration is a pure
    -- function of this table.
    metadata           JSONB NOT NULL DEFAULT '{}'::jsonb,
    published_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_by_token UUID REFERENCES tokens (id) ON DELETE SET NULL,
    published_by_user  UUID REFERENCES users (id) ON DELETE SET NULL,
    -- Republishing the same NEVRA/version replaces the row rather than
    -- accumulating duplicates the index would then list twice.
    UNIQUE (repo, channel, format, storage_key)
);

CREATE INDEX packages_group_idx ON packages (repo, channel, format, index_group);
CREATE INDEX packages_name_idx ON packages (repo, channel, name);

CREATE TABLE audit_log (
    id          BIGSERIAL PRIMARY KEY,
    at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    action      TEXT NOT NULL,
    -- 'token' | 'user' | 'anonymous' | 'system'
    actor_kind  TEXT NOT NULL,
    actor_name  TEXT,
    token_id    UUID REFERENCES tokens (id) ON DELETE SET NULL,
    user_id     UUID REFERENCES users (id) ON DELETE SET NULL,
    repo        TEXT,
    channel     TEXT,
    target      TEXT,
    success     BOOLEAN NOT NULL DEFAULT TRUE,
    remote_addr TEXT,
    detail      JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX audit_log_at_idx ON audit_log (at DESC);
CREATE INDEX audit_log_action_idx ON audit_log (action, at DESC);
CREATE INDEX audit_log_repo_idx ON audit_log (repo, at DESC);
