# Silo

<p align="center"><img src="https://raw.githubusercontent.com/BirknerAlex/silo/main/assets/silo-logo.png"/></p>

Self-hosted package registry for **RPM**, **Alpine APK**, and **npm**.
Publish over gRPC; `dnf`, `apk` and `npm` consume the results as real
repositories over plain HTTP. Packages live in S3-compatible object
storage, everything else lives in Postgres.

## Why

GitLab's native RPM registry needs a paid tier. Pulp is heavier than this
needs. Nexus dropped real yum/rpm support from its open-source line. Silo
is a small alternative that keeps no local state, so replicas are
interchangeable and horizontal scaling is just `replicaCount`.

## Architecture

```
crates/
  silo-proto   generated tonic/prost code from proto/silo/v1
  silo-pkg     the format seam: rpm | apk | npm parsing, layout, index rendering
  silo-db      Postgres: package index, tokens, users, audit log, advisory locks
  silo-core    config, object storage, publish orchestration, signing, OIDC
  silo-server  gRPC (publish/read/auth/admin) + HTTP (package-manager-facing)
  silo-cli     `silo` — publishing and administration; never touches S3 or keys
```

### The format seam

Adding a format means adding one `impl Format` and one enum variant.
Nothing else in the codebase matches on which format it's handling.

| | storage layout | index unit ("group") |
|---|---|---|
| rpm | `{repo}/{ch}/Packages/{file}` | the whole channel |
| apk | `{repo}/{ch}/apk/{arch}/{file}` | one architecture |
| npm | `{repo}/{ch}/npm/{name}/-/{file}` | one package name |

The **index group** is what makes those three the same shape: a publish
invalidates exactly one group, and a group is the unit that gets locked.
Two apk architectures, or two npm packages, publish concurrently without
ever contending.

apk has the one wrinkle: a `noarch` package belongs in *every*
architecture's index, because apk-tools only ever fetches its own. So
`noarch` is a group that other groups read from, and publishing into it
rewrites them all — the single case where one publish touches more than
one index.

**Every index is a pure function of the database.** Whatever a format's
index needs beyond the common columns — APKINDEX records, an npm
`package.json`, the dependencies and file lists and header byte ranges
`primary.xml` carries — is extracted once at publish and stored on the
row, so regenerating an index never reads a package back out of object
storage. A publish is a constant number of object-storage operations, not
one per package already in the repo.

RPM repodata (`repomd.xml`, `primary`, `filelists`, `other`) is generated
in-process: silo does not shell out to `createrepo_c`, and the server
image carries no package tooling.

### Distributed locking

Publishes take a **Postgres transaction-scoped advisory lock**
(`pg_advisory_xact_lock`) keyed on the index group. Without it, two
concurrent publishes would each regenerate the index from their own view
of the bucket, and the loser's package would silently vanish from the
index that won.

Transaction-scoped rather than session-scoped is deliberate: a session
lock leaks if the holder is SIGKILLed mid-publish or if a pooled
connection is returned without an unlock. A transaction lock is released
by the same machinery that rolls the transaction back, including when the
backend notices the client is gone. There is no path that strands a lock.

The lock also composes with the publish transaction — the same transaction
inserts the package row and reads back the group, so the index is rendered
from a consistent snapshot and a failed publish takes its row with it.

**Ordering.** Bytes are written to object storage before the row commits,
so a client following a fresh index never 404s. The cost is that a crash
between the two leaves orphaned bytes that no row references; they're
unreachable and the next publish of the same file overwrites them. The
opposite order would trade that for a committed row pointing at bytes that
aren't there — a 404 for real clients, which is worse.

### Why the database

Index regeneration reads rows, never a bucket listing, so a publish never
has to GET every package already in the repo just to learn what is there.
For apk and npm the publish path touches object storage exactly twice
(write the package, write the index), and `silo list` never touches it at
all.

## Quickstart

```sh
docker compose up -d
docker compose logs silo | grep -A 12 'SILO BOOTSTRAP'
```

That brings up Silo, Postgres, and SeaweedFS. On the first start against an
empty database, Silo mints an admin token and an admin user and prints
them **once** — they're stored only as hashes.

```sh
silo login --server http://localhost:8080
silo publish ./my-package-1.0.0-1.x86_64.rpm --repo myrepo --channel stable
silo publish ./hello-1.0-r0.apk             --repo myrepo --channel edge
silo publish ./widget-1.0.0.tgz             --repo myrepo --channel stable
silo list --repo myrepo --channel stable
```

The format is inferred from the file extension; pass `--format` to be
explicit.

### Consuming

```ini
# /etc/yum.repos.d/silo.repo
[silo-myrepo-stable]
name=Silo myrepo/stable
baseurl=http://silo.internal:8080/myrepo/stable
username=silo
password=silo_xxxxxxxxxxxx_yyyy...
enabled=1
gpgcheck=0   # see Signing for the gpgcheck=1 form
```

```sh
# Alpine. apk appends /$arch/APKINDEX.tar.gz itself, so the entry stops
# at .../apk — naming the architecture here would double it.
echo "http://silo:TOKEN@silo.internal:8080/myrepo/edge/apk" \
  >> /etc/apk/repositories
# Without signing.apk configured, apk needs --allow-untrusted.
```

`noarch` packages need no special handling. apk-tools only ever fetches
`$repo/$hostarch/APKINDEX.tar.gz` and will not look in a `noarch`
directory of its own accord, so silo answers for noarch content under
whichever architecture asks: every architecture's index lists the
channel's noarch packages, a channel holding *only* noarch packages still
serves an index to any architecture, and the package file itself is stored
once rather than copied into every prefix.

```sh
# npm
npm config set @acme:registry http://silo.internal:8080/myrepo/stable/npm/
npm config set //silo.internal:8080/myrepo/stable/npm/:_authToken silo_xxx...
```

## Authentication

Everything authenticates with **one kind of credential**: a database-backed
token. It reaches the server through two envelopes because the clients
can't agree on one — gRPC and npm send `Authorization: Bearer`, while dnf
and apk can only do HTTP Basic (the token goes in the password field; the
username is ignored). Both converge on the same check.

### Tokens

```sh
silo token create --name ci --permission write --repo myrepo
silo token create --name readonly --permission read           # all repos
silo token create --name temp --permission write --repo a --repo b \
                  --expires-in-days 30
silo token list
silo token revoke --name ci
```

- **Permissions** are ordered: `read` < `write` < `admin`.
- **Scope** is either every repo or an explicit list. One repo is just the
  single-element case.
- **Expiry** is optional; omit it for a token that never expires.
- An admin cannot create a token with a wider scope than their own.

The secret is shown once, at creation, and is unrecoverable afterwards.

#### How tokens are stored

Tokens are `silo_<prefix>_<secret>`. The prefix is a public lookup handle,
so verification is one indexed lookup rather than a scan. The secret is
stored as `SHA-256(salt ‖ secret ‖ pepper)` with a per-token random salt
and an optional server-side pepper from config that is never written to
the database.

Not argon2 — deliberately. Passwords get argon2id (see below) because
humans choose low-entropy secrets. Tokens are 256-bit values from the OS
CSPRNG and are presented on *every* request: a memory-hard KDF wouldn't
meaningfully raise the cost of brute-forcing 2²⁵⁶, but it would land on the
hot path of every `dnf makecache`. The salt defeats precomputation; the
pepper means a database dump alone yields nothing usable; comparison is
constant-time.

### Users and login

```sh
silo user create --username alice --admin
silo user list
silo user disable --username bob
silo login              # prompts, saves a session token to ~/.config/silo
silo whoami
```

Passwords are argon2id with per-password salts. `silo login` issues a
session token carrying the user's own permission level and an expiry, so a
stale laptop credential doesn't stay valid forever.

### OIDC

Configure `oidc.issuer` and `oidc.client_id` and `silo login` runs the
**device authorization grant** directly against the identity provider. The
server never handles the user's credentials, and no client secret is
needed for a public client. Users are provisioned on first login, matched
by `sub` and falling back to username so an existing local account gets
linked rather than shadowed. Set `oidc.exclusive: true` to disable password
login once SSO is in place.

### CI and other non-interactive callers

Nothing about the CLI assumes a terminal. Every credential has an
environment-variable form, and a pipeline never has to write a file that
outlives the job it belongs to.

**An API token is the simplest option.** No login step at all:

```sh
export SILO_SERVER=https://silo.example.com:8080
export SILO_TOKEN="$SILO_PUBLISH_TOKEN"     # from your CI secret store
silo publish ./dist/mypkg-1.0.0-1.x86_64.rpm --repo myrepo --channel stable
```

`SILO_TOKEN` takes precedence over any config file and works without one,
so the same command runs identically on a runner and on a laptop.

**Username and password**, when you'd rather issue short-lived sessions
than a standing token:

```sh
export SILO_TOKEN=$(SILO_USERNAME=ci SILO_PASSWORD="$SILO_CI_PASSWORD" \
  silo login --server https://silo.example.com:8080 --print-token)
```

`--print-token` writes only the token to stdout and nothing to disk;
progress goes to stderr. The password can also be piped in on stdin
(`echo "$PW" | silo login --username ci`) to keep it out of the process
list.

**OIDC without a stored secret**, if your CI provider can mint ID tokens —
GitHub Actions, GitLab CI and Kubernetes all can. Pass the token straight
in and the device flow is skipped:

```yaml
# GitHub Actions
permissions:
  id-token: write
steps:
  - run: |
      SILO_OIDC_TOKEN=$(curl -sH "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=silo" | jq -r .value) \
      silo login --server "$SILO_SERVER" --print-token
```

`--oidc-token-file` reads it from a path instead, which is the shape
Kubernetes projected service-account tokens arrive in.

A prompt is never issued when there is no terminal to answer it. Running
`silo login` with no credentials on a runner fails immediately, naming the
variable that was missing, rather than hanging until the job times out.

## Audit log

Every mutating action and every authenticated package download is
recorded: who, what, which repo, from where, and whether it succeeded.
Entries are denormalized, so the log still names the actor after that
token is revoked and that user deleted.

```sh
silo audit --limit 20
silo audit --action package.publish --repo myrepo
silo audit --failures                # rejected attempts only
silo audit --json | jq
```

Index and repodata fetches are **not** audited — `dnf makecache` across a
fleet would bury everything else. Package downloads can be turned off with
`audit.log_downloads: false`. Entries older than `audit.retention_days`
are pruned hourly.

## Metrics

Prometheus metrics on `/metrics`: publish counts and latency
by format, download counts split by redirect vs proxy, auth failures by
reason, package counts and bytes per repo/channel/format, and a
`silo_database_up` gauge. Labels are deliberately low-cardinality — no
package names.

`/healthz` is a liveness probe; `/readyz` also pings the database, so a
replica that loses Postgres is pulled from the Service instead of serving
errors.

## Signing

- **RPM** — `signing.gpg` signs packages in place and writes a detached
  `repomd.xml.asc`, so both `gpgcheck=1` and `repo_gpgcheck=1` work.
- **APKINDEX** — `signing.apk` signs the index with RSA PKCS#1 v1.5 over
  SHA-1 and prepends the `.SIGN.RSA.<key_name>` member apk-tools expects.
  `key_name` must match the filename the public key is deployed to under
  `/etc/apk/keys`.
- **npm** — nothing to sign. npm clients verify the `integrity` hashes in
  the packument, which Silo computes at publish time and serves over TLS.

### The public key

`GET /RPM-GPG-KEY-silo` returns the armored **public** half of the
configured `signing.gpg` key, so a `.repo` file can point `gpgkey=` at
Silo instead of the key having to reach every machine some other way:

```ini
# /etc/yum.repos.d/silo.repo
[silo-myrepo-stable]
name=Silo myrepo/stable
baseurl=https://silo.example.com/myrepo/stable
username=silo
password=silo_xxxxxxxxxxxx_yyyy...
enabled=1
gpgcheck=1        # verify package signatures
repo_gpgcheck=1   # verify repomd.xml against repomd.xml.asc
gpgkey=https://silo.example.com/RPM-GPG-KEY-silo
```

The public key is derived from the configured private key rather than
configured separately, so the two can never disagree. The endpoint is
**unauthenticated** — it is a public key, and dnf fetches `gpgkey=`
outside the credentialed repo session, so a token requirement here would
break `repo_gpgcheck=1` for everyone. It is global, not per-repo, because
`signing.gpg` is: one key signs every repo this server serves. With no
signing key configured it returns 404.

## Administration

```sh
silo repos                                              # what exists
silo delete --id 42                                     # remove a package
silo index rebuild --repo myrepo --channel stable --format apk
```

`index rebuild` regenerates from the database alone, which is the repair
path after restoring a bucket from backup or a crash mid-publish. Omit
`--group` to rebuild every group of that format.

### Versions

```sh
silo version            # client and server, side by side
curl -s https://silo.example.com/version
```

The version lives in one place — the workspace `Cargo.toml` — and
`silo-core` re-exports it as `silo_core::VERSION`, so every binary, the
`GetVersion` RPC, the `/version` endpoint and the chart's `appVersion`
follow from a single bump. Builds also carry the git commit they came from
(with a `-dirty` marker for an unclean worktree), which is what tells you
whether a `latest` tag is the commit you think it is.

`silo version` reports both ends because version skew between a CLI and a
server is a common cause of confusing failures. It never fails on an
unreachable server: not being able to connect is exactly when you most
want to know what your client is.

## Deployment

### Helm

```sh
helm install silo oci://ghcr.io/birkneralex/charts/silo -f my-values.yaml
```

A database is required, and the chart refuses to render without exactly
one of:

```yaml
# Production: a managed instance.
externalPostgres:
  existingSecret: silo-db      # Secret with a `url` key
```

```yaml
# Development only: a bundled single-replica Postgres.
# No replication, no backups, no pooling.
postgres:
  enabled: true
```

Secrets can stay out of values.yaml entirely — the server expands
`${VAR}` and `${VAR:-default}` in its config file from the environment, so
the chart writes placeholders and injects the real values from Secrets. An
unset variable with no default is a startup error rather than an empty
string.

#### Ingress

One Ingress covers both the CLI's gRPC calls and the dnf/apk/npm HTTP
surface — they share a Service port, and silo tells them apart itself
(by path, and by per-connection protocol detection), so the only thing
the ingress controller needs to do is speak real HTTP/2 to the backend
instead of downgrading to HTTP/1.1. Off by default.

```yaml
ingress:
  enabled: true
  className: traefik
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    external-dns.alpha.kubernetes.io/hostname: packages.example.com
    traefik.ingress.kubernetes.io/service.serversscheme: h2c
  hosts:
    - host: packages.example.com
      paths: [{path: /, pathType: Prefix}]
  tls:
    - secretName: silo-tls
      hosts: [packages.example.com]
```

**Traefik** is what we recommend, and the annotation above is all it
needs: `h2c` just tells Traefik to dial the backend over cleartext HTTP/2,
and it forwards whatever it gets — gRPC or plain REST — without caring
which.

**nginx** can do the same thing, but only through plain `proxy_pass` with
`proxy_http_version 2`, which nginx open source has supported only since
**1.29.4** (December 2025). Earlier versions could reach a backend over
HTTP/2 solely through the gRPC-specific `grpc_pass` module, which cannot
carry the dnf/apk/npm traffic and would force a second Ingress back. If
your ingress-nginx build doesn't expose `proxy_http_version 2` through a
plain annotation yet, force it with a snippet:

```yaml
annotations:
  nginx.ingress.kubernetes.io/configuration-snippet: |
    proxy_http_version 2;
```

If you're stuck on an nginx older than 1.29.4 and can't take the snippet,
we'd consider nginx's gRPC-to-backend story effectively deprecated here —
switch controllers rather than reintroduce a second Ingress. Traefik
(above) needs no version floor for this.

#### Labels and annotations

`commonLabels` and `commonAnnotations` reach every resource the chart
creates. Per-resource `labels`/`annotations` are merged on top, for keys
that only make sense on one object:

```yaml
commonLabels:
  team: platform
commonAnnotations:
  example.com/owner: platform-team

serviceAccount:
  annotations:
    # IRSA or Workload Identity, which removes the need for static S3
    # credentials entirely.
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/silo
```

`commonLabels` deliberately does not touch any `spec.selector`. That field
is immutable, so folding user labels into it would make *adding* one break
every subsequent `helm upgrade`, with an error that names nothing useful.
`ci/check-chart.py` asserts this, along with the inverse — that every
selector still matches the pods it is supposed to.

### Docker

`docker build -t silo .` — multi-stage, runtime is `debian:bookworm-slim`
plus `ca-certificates`, running as an unprivileged user with nothing on
disk to write to. The `silo` CLI ships
in the same image, so `kubectl exec` can manage tokens without a second
image. Published to Docker Hub as `tyrola/silo`.

### Migrations

Migrations are embedded in the binary and applied on startup. sqlx takes
its own advisory lock, so every replica running them simultaneously during
a rolling deploy is safe. `silo-server --migrate-only` applies them and
exits, for deployments that prefer a separate Job.

## Development

### Dev container

The fastest way in. Open the repo in VS Code and "Reopen in Container", or
`devcontainer up --workspace-folder .` — you get a Rust toolchain, `protoc`,
a Postgres and a SeaweedFS, with the bucket created and
`SILO_TEST_DATABASE_URL` already pointing at the database, so the
integration tests run rather than skip.

```sh
# Everything below already works on first open.
cargo test --workspace --features silo-core/test-util,silo-pkg/test-util
SILO_CONFIG=.devcontainer/config.yaml cargo run -p silo-server
cargo run -p silo-cli -- login --username admin   # password prints once, in the server log
```

Postgres is `postgres:5432` and SeaweedFS serves S3 on `seaweedfs:8333`,
with the filer's web UI on 8888 for browsing the bucket; both are
forwarded to the host. The cargo registry and `target/` live
in named volumes, so a container rebuild doesn't mean a cold build.

### Without a dev container

```sh
cargo test --workspace --features silo-core/test-util,silo-pkg/test-util
cargo clippy --workspace --all-targets --features silo-core/test-util,silo-pkg/test-util -- -D warnings
cargo fmt --all
```

The database-backed integration tests skip rather than fail when no
database is configured, so the suite is usable on any machine:

```sh
# Database-backed integration tests (migrations, transactions, locking).
docker run -d --name silo-test-pg -p 55432:5432 \
  -e POSTGRES_USER=silo -e POSTGRES_PASSWORD=silo -e POSTGRES_DB=silo \
  postgres:16-alpine
export SILO_TEST_DATABASE_URL=postgres://silo:silo@localhost:55432/silo
```

Queries are runtime-checked rather than `sqlx::query!`-checked, so
`cargo build` needs neither a live database nor a checked-in offline cache.

The Helm chart has its own checks, which need `helm` and `pyyaml`:

```sh
helm lint charts/silo
ci/check-chart.py
```

### End-to-end suite

```sh
ci/e2e.sh            # ~5 minutes; needs docker
KEEP=1 ci/e2e.sh     # leave the stack up afterwards
```

This is the only suite that tests silo against software we do not control.
It builds a package per format with that ecosystem's own tooling
(`rpmbuild`, `abuild`, `npm pack`), publishes all three to a real silo
backed by a real Postgres and a real SeaweedFS, and then installs them with
real `dnf`, `apk` and `npm` in their own distro containers.

Signing is on throughout: `gpgcheck=1` **and** `repo_gpgcheck=1` for dnf,
and a signed APKINDEX for apk — which is not optional anyway, since
apk-tools will not use an unsigned index and cannot be talked out of it.
The suite reads the signature back off the installed RPM rather than
trusting that the install succeeded.

It also re-runs the dnf half after `silo index rebuild`, because the
documented recovery path has to produce an index a real client accepts,
not merely one that renders.

The example packages live in [`examples/`](examples/).

## CI/CD

| workflow | when | what |
|---|---|---|
| `ci` | push, PR | lint, proto compatibility, tests, chart checks, e2e |
| `edge` | push to main | an `edge` image on GHCR, tagged with the commit |
| `release-please` | push to main | keeps a release PR open with the next version and changelog |
| `release` | a `v*` tag | binaries, multi-arch images, the chart, the protos |

### Cutting a release

Nothing is tagged by hand, and merging a feature PR does not release
anything. There are two merges:

1. **Merge your PR to `main`.** release-please works out the next version
   from the commit messages since the last release —
   [Conventional Commits](https://www.conventionalcommits.org/): `fix:`
   patch, `feat:` minor, `feat!:` or `BREAKING CHANGE` major — and opens a
   *release PR* ("chore: release 0.3.0") carrying the changelog and the
   version bumps to `Cargo.toml`, `Cargo.lock`, `Chart.yaml` and the
   release manifest. It keeps that PR up to date as more lands on main.
2. **Merge the release PR.** That is the release decision, and the only
   manual step. release-please tags `v0.3.0`, publishes the GitHub
   Release, and kicks off `release` — binaries, images, chart, protos.

One number covers everything: the workspace `Cargo.toml` version, the
chart's `version` and `appVersion`, and therefore `silo_core::VERSION` and
every surface that reports it. `ci/check-chart.py` fails if they drift.

#### Two repository settings this depends on

Both live under **Settings → Actions → General**, and neither is on by
default:

- **Allow GitHub Actions to create and approve pull requests.** Without
  it, release-please cannot open the release PR and step 1 does nothing.
- Workflow permissions may stay on **read-only**. Every workflow that
  needs more asks for it explicitly, which is why the CI jobs run with a
  token that can do nothing but read.

A tag pushed by `GITHUB_TOKEN` deliberately does not start a workflow, so
`release` is triggered by an explicit `workflow_dispatch` from
release-please rather than by its own `on: push: tags`. That trigger is
kept as well, for tags pushed by a human.

### Required CI secrets

- `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` — Docker Hub push
- `BUF_TOKEN` — buf.build push
- `GITHUB_TOKEN` is provided automatically for the GHCR image and chart
  pushes and for release-please

## Out of scope

Web UI; package formats beyond rpm/apk/npm; retention and dedup policies;
mirroring or upstream proxying; per-package ACLs finer than repo scope.
