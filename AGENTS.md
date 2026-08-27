# Working on silo

Notes for anyone — human or agent — changing this repository.

## Documentation describes the present, never the past

The README, every doc comment, every config comment and every commented
example describe **what silo does now**. They do not describe what it used
to do, what changed, or what something replaced.

Write:

> Publishes take a Postgres advisory lock keyed on the index group.
> Without it, two concurrent publishes would each regenerate the index
> from their own view of the bucket, and the loser's package would
> silently vanish.

Not:

> This fixes the race the old version had, where two concurrent
> publishes...

Both sentences justify the lock. Only the first is still true a year from
now, and only the first is useful to a reader who has never seen the old
version — which is every reader.

The rule applies to prose, not to history-keeping tools. Commit messages,
changelog entries and pull request descriptions are *supposed* to describe
change over time; that is what they are for. Keep the narrative there.

Practical consequences:

- No "MVP", "previously", "used to", "no longer", "superseded",
  "legacy", "deprecated" or "we now ..." in documentation about silo's own
  design. These words are fine when they describe something external and
  still true — npm's legacy clients, rpm's deprecated signature tags.
- A regression test's doc comment states the invariant it protects, not
  the bug that motivated it. "Index pruning must not delete the package
  files beside it" beats "index pruning used to delete the package files".
- When you change behaviour, rewrite the surrounding prose to describe the
  new behaviour. Do not append a note saying it changed.

## The version lives in one number

`[workspace.package] version` in the root `Cargo.toml` is silo's version.
Member crates inherit it with `version.workspace = true`, `silo-core`
re-exports it as `silo_core::VERSION`, and the chart's `version` and
`appVersion` carry the same number. `ci/check-chart.py` fails if the
chart, the workspace or the `silo-*` entries in `Cargo.lock` drift apart.

Nothing bumps any of it by hand. release-please rewrites the workspace
version, those lockfile entries and the two chart fields together, driven
by Conventional Commits.

It is configured with `release-type: simple` and explicit `extra-files`
rather than `rust`, which looks like the obvious choice and is not: the
Rust strategy applies a `[package]` updater to the root `Cargo.toml`, and
this root is a virtual workspace with no `[package]` section, so it fails
the whole release run. `include-component-in-tag: false` matters just as
much — without it the tag is `silo-v0.3.0`, and `release.yml` only
triggers on `v*.*.*`.

The lockfile entry is not cosmetic: `release.yml` builds with
`cargo build --release --locked`, so a lock left behind by a version bump
fails the release rather than the pull request that caused it.

## Checks before pushing

CI runs five jobs — `lint`, `proto`, `test`, `helm`, `e2e`. All of them
run locally:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets \
    --features silo-core/test-util,silo-pkg/test-util -- -D warnings
cargo machete --with-metadata
shellcheck ci/*.sh ci/e2e/*.sh .devcontainer/*.sh
SILO_TEST_DATABASE_URL=postgres://silo:silo@localhost:55432/silo \
    cargo test --workspace --features silo-core/test-util,silo-pkg/test-util
ci/check-chart.py
ci/e2e.sh
```

CI's clippy tracks the current stable release, which is usually ahead of a
local toolchain; `rustup run stable cargo clippy ...` matches it.

The database-backed tests **skip** rather than fail without
`SILO_TEST_DATABASE_URL`, which is right for a laptop and wrong for a real
run — it silently drops most of the coverage. Start one with:

```sh
docker run -d --name silo-test-pg -p 55432:5432 \
    -e POSTGRES_USER=silo -e POSTGRES_PASSWORD=silo -e POSTGRES_DB=silo \
    postgres:16-alpine
```

## Verify against the real thing

The e2e suite exists because unit tests cannot tell you whether `dnf`,
`apk` and `npm` accept what silo serves. Anything touching the HTTP
surface, the index formats or signing needs `ci/e2e.sh` run, not just
`cargo test`.

The same goes for the compose stacks: `docker compose up` and check it
works, rather than checking that the YAML parses. A health check that can
never pass leaves every dependent service waiting forever, and it renders
perfectly.

## Commits

Conventional Commits, because release-please derives the version and the
changelog from them. `feat:` and `fix:` are user-visible; use `chore:`,
`ci:` or `test:` for work that changes nothing an operator would notice.
