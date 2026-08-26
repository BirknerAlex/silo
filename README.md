# Silo

Self-hosted, S3-backed RPM package registry. Publish `.rpm` packages over
gRPC; `dnf`/`yum` consume them as a real repo (proper `repodata`, version
resolution) over plain HTTP.

## Why

GitLab's native RPM registry needs a paid tier. Pulp is heavier than this
needs. Nexus dropped real yum/rpm support from its open-source line. Silo
is a small, stateless alternative: it shells out to `createrepo_c` for
repodata generation rather than reimplementing that format, and keeps all
durable state in S3 so the server itself is trivially horizontally
replicable.

## Architecture

```
crates/
  silo-proto   generated tonic/prost code from proto/silo/v1 (published to buf.build)
  silo-rpm     RPM parsing/validation (the `rpm` crate) + the PackageFormat seam
  silo-core    config, S3 storage (object_store), createrepo_c runner, GPG signing
  silo-server  gRPC (publish/read) + HTTP (dnf/yum-facing) binary
  silo-cli     thin gRPC client — never touches S3 credentials or the GPG key
```

- **Format scope**: RPM only. `silo_rpm::PackageFormat` and the
  `PackageParser` trait are the seam a future format (deb, generic) would
  implement against — there's no abstraction for formats that don't exist
  yet beyond that seam.
- **Storage layout**: `{repo}/{channel}/Packages/{name-version-release.arch.rpm}`
  and `{repo}/{channel}/repodata/*`.
- **Repodata**: on every publish, the server downloads the repo/channel's
  current packages + repodata into a scratch dir, shells out to
  `createrepo_c` (`--update` if repodata already exists), and uploads the
  result back to S3.
- **HTTP surface for dnf/yum**: `repodata/*` is proxied directly through
  the server (small, frequently polled). Package downloads (`Packages/*`)
  302-redirect to a presigned S3 URL when the backend supports presigning,
  falling back to proxying bytes otherwise (e.g. non-S3 test backends).
  This keeps package bandwidth off the server for real S3/MinIO backends
  while still working everywhere.
- **Auth**: two hardcoded bearer tokens (publish, read) — no user system.
  gRPC checks `authorization: Bearer <token>`. The HTTP surface checks the
  read token as an HTTP Basic-auth password (dnf's `.repo` `username=`/
  `password=` fields translate to Basic auth, so no custom header is
  needed on the client side).

## Known limitation: no distributed locking

The server is stateless and holds no locks. Two concurrent publishes to
the *same* repo/channel (possibly on different replicas) can race on the
repodata regeneration step — last write to `repodata/` wins, and a
package upload from a losing race can end up excluded from the repodata
that "won." This is an accepted MVP limitation for low publish
concurrency, not something the publish flow tries to work around. If this
becomes a real problem, the fix is an S3-based lock (e.g. conditional
put/lease object) around `regenerate_repodata`.

## Quickstart

```sh
cp config.example.yaml config.yaml   # edit storage/auth/gpg
SILO_CONFIG=./config.yaml cargo run -p silo-server

cp client.example.yaml ~/.config/silo/client.yaml   # edit server_addr/tokens
cargo run -p silo-cli -- publish ./my-package-1.0.0-1.x86_64.rpm --repo myrepo --channel stable
cargo run -p silo-cli -- list --repo myrepo --channel stable
```

Point `dnf` at it:

```ini
# /etc/yum.repos.d/silo.repo
[silo-myrepo-stable]
name=Silo myrepo/stable
baseurl=http://silo.internal:8080/myrepo/stable
username=silo
password=change-me-read-token
enabled=1
gpgcheck=0   # set to 1 and point gpgkey= at your public key if gpg signing is configured
```

## Development

```sh
cargo test --workspace --features silo-core/test-util,silo-rpm/test-util
cargo clippy --workspace --all-targets --features silo-core/test-util,silo-rpm/test-util -- -D warnings
cargo fmt --all
```

Repodata-generation tests shell out to the real `createrepo_c` binary and
skip gracefully if it isn't on `PATH` (it isn't packaged for macOS via
Homebrew) — CI runs them for real on Linux via `apt install createrepo-c`.

## Distribution

- **Docker**: `docker build -t silo .` — multi-stage build, runtime image
  is `debian:bookworm-slim` + `createrepo-c`. Published to Docker Hub as
  `birkneralex/silo` on push to `main`/tags via `.github/workflows/docker.yml`.
- **Helm**: `charts/silo` — plain Deployment + Service, no PVC/StatefulSet
  since all state lives in S3. Published as an OCI artifact to GHCR
  (`ghcr.io/birkneralex/charts/silo`) on changes under `charts/`, via
  `.github/workflows/helm-release.yml`. GitHub Pages was the original
  plan but isn't available on this repo's plan while it's private, so
  OCI/GHCR is used instead — it needs no extra setup beyond the
  workflow's own `GITHUB_TOKEN` and works the same for private repos.
  ```sh
  helm install silo oci://ghcr.io/birkneralex/charts/silo -f my-values.yaml
  ```
- **Proto**: `proto/silo/v1` is a buf module (`buf.build/birkner/silo`),
  pushed on changes via `.github/workflows/ci.yml`'s `buf-push` job.

### Required CI secrets

- `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` — Docker Hub push
- `BUF_TOKEN` — buf.build push
- `GITHUB_TOKEN` is provided automatically for the Helm GHCR push job

## Out of scope for the MVP

Web UI, package formats beyond RPM, distributed locking/coordination,
retention/dedup policies, a user/permissions system beyond the two
hardcoded tokens.
