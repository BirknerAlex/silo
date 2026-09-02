-- Pull-through cache: upstream sources a repo/channel can mirror, and the
-- synced view of what each upstream has.
--
-- `upstreams` and `packages` are deliberately separate concerns from
-- `upstream_packages`: a `packages` row (tagged via `origin_upstream_id`
-- below) means "this repo actually serves these bytes"; an
-- `upstream_packages` row means "the upstream claims to have this,
-- unfetched". Conflating them would make every synced-but-never-requested
-- upstream package show up in `silo list`/the rendered index/prune as if
-- it were already locally servable.
CREATE TABLE upstreams (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo                    TEXT NOT NULL,
    channel                 TEXT NOT NULL,
    name                    TEXT NOT NULL,
    format                  TEXT NOT NULL,
    base_url                TEXT NOT NULL,
    cache_mode              TEXT NOT NULL,
    cache_index_in_memory   BOOLEAN NOT NULL DEFAULT false,
    -- apk/pacman: which architectures to sync. deb: suite + components,
    -- alongside `arches` for its per-arch `Packages` files. Unused
    -- (empty) for rpm/npm, whose upstream layout has no such axis.
    arches                  TEXT[] NOT NULL DEFAULT '{}',
    suite                   TEXT,
    components              TEXT[] NOT NULL DEFAULT '{}',
    auth_kind               TEXT,
    auth_username            TEXT,
    -- AES-256-GCM ciphertext/nonce of the upstream password or bearer
    -- token, keyed by a server-only config secret (see
    -- `silo_core::secret_box`) that is never itself stored in the
    -- database. NULL together iff `auth_kind IS NULL`.
    auth_secret_ciphertext   BYTEA,
    auth_secret_nonce        BYTEA,
    status                  TEXT NOT NULL DEFAULT 'pending',
    last_sync_at            TIMESTAMPTZ,
    last_sync_error         TEXT,
    last_success_at         TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (repo, channel, name),
    CONSTRAINT upstreams_cache_mode_valid CHECK (cache_mode IN ('cache', 'no_cache')),
    CONSTRAINT upstreams_status_valid CHECK (status IN ('pending', 'ok', 'error')),
    CONSTRAINT upstreams_auth_kind_valid CHECK (auth_kind IS NULL OR auth_kind IN ('basic', 'bearer')),
    CONSTRAINT upstreams_auth_secret_matches_kind CHECK (
        (auth_kind IS NULL AND auth_secret_ciphertext IS NULL AND auth_secret_nonce IS NULL)
        OR (auth_kind IS NOT NULL AND auth_secret_ciphertext IS NOT NULL AND auth_secret_nonce IS NOT NULL)
    )
);

-- The synced index cache: one row per (upstream, package identity), fully
-- replaced on every sync (upsert current, delete what's gone) rather than
-- accumulated forever.
CREATE TABLE upstream_packages (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    upstream_id   UUID NOT NULL REFERENCES upstreams(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    epoch         INTEGER NOT NULL DEFAULT 0,
    version       TEXT NOT NULL,
    release       TEXT NOT NULL DEFAULT '',
    arch          TEXT NOT NULL DEFAULT '',
    filename      TEXT NOT NULL,
    download_url  TEXT NOT NULL,
    size_bytes    BIGINT,
    sha256        TEXT,
    metadata      JSONB NOT NULL DEFAULT '{}',
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (upstream_id, name, epoch, version, release, arch)
);
CREATE INDEX upstream_packages_upstream_name_idx ON upstream_packages (upstream_id, name);

-- NULL means locally published — every existing row stays valid with no
-- backfill. Non-NULL identifies which upstream a pulled-through package
-- came from. `SET NULL` on upstream removal (rather than `CASCADE`) is
-- deliberate: removing an upstream must not silently delete packages
-- clients may already depend on; `RemoveUpstream --prune` deletes them
-- explicitly first, through the normal delete-package path, before the
-- row itself goes.
ALTER TABLE packages
    ADD COLUMN origin_upstream_id UUID REFERENCES upstreams(id) ON DELETE SET NULL;

-- Which packages a prune rule considers: everything, only locally
-- published packages, or only ones pulled through from an upstream.
-- Existing rows default to 'all', preserving current behavior exactly.
ALTER TABLE prune_rules
    ADD COLUMN origin_scope TEXT NOT NULL DEFAULT 'all';
ALTER TABLE prune_rules
    ADD CONSTRAINT prune_rules_origin_scope_valid CHECK (origin_scope IN ('all', 'local', 'upstream'));
