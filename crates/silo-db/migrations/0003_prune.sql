-- Per-(repo, channel) retention rules and per-package exemptions.
--
-- A row in `prune_rules` only exists once someone has configured a rule
-- for that repo/channel — absence means "nothing to prune here", same
-- no-row-means-default convention as `repos`. `keep_last_n` and
-- `max_age_days` are independent and combinable: a version is pruned if
-- it violates either configured rule (a NULL column means that rule
-- isn't set). At least one of the two must be set, so clearing a rule is
-- a row delete rather than nulling both columns.
CREATE TABLE prune_rules (
    repo            TEXT NOT NULL,
    channel         TEXT NOT NULL,
    keep_last_n     INTEGER,
    max_age_days    INTEGER,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (repo, channel),
    CONSTRAINT prune_rules_keep_last_n_positive CHECK (keep_last_n IS NULL OR keep_last_n > 0),
    CONSTRAINT prune_rules_max_age_positive CHECK (max_age_days IS NULL OR max_age_days > 0),
    CONSTRAINT prune_rules_at_least_one_rule CHECK (keep_last_n IS NOT NULL OR max_age_days IS NOT NULL)
);

-- Exempts every version of `name` within (repo, channel) from both rules
-- above, regardless of which format/arch it happens to be published
-- under.
CREATE TABLE prune_exemptions (
    repo       TEXT NOT NULL,
    channel    TEXT NOT NULL,
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (repo, channel, name)
);
