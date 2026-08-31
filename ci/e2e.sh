#!/usr/bin/env bash
# End-to-end test: build real packages, publish them to a real silo, then
# install them with the real package managers.
#
# What this covers that the unit and integration tests cannot: whether
# `dnf`, `apk`, `npm` and `pacman` — none of which we control — actually
# accept what silo serves. Everything below the wire is already tested
# elsewhere; this is about the wire.
#
# The shape is deliberate at both ends:
#
#   * Packages are built by rpmbuild, abuild, npm pack and makepkg, not by
#     silo's own fixtures. Testing our encoder against our decoder proves
#     nothing.
#   * Packages are installed by dnf, apk, npm and pacman in their own
#     distro containers, not by parsing the index ourselves.
#
# Signing is on for every format that supports it. apk-tools requires a
# signed index and cannot be talked out of it, so an unsigned run would not
# resemble any real deployment; RPM's gpgcheck/repo_gpgcheck path and
# pacman's database signature check are each only reachable with a real
# key.
#
# Usage:
#   ci/e2e.sh              # build, run, verify, tear down
#   KEEP=1 ci/e2e.sh       # leave the stack up afterwards for poking at
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$(pwd)

PROJECT=silo-e2e
WORK=${WORK:-$ROOT/target/e2e}
COMPOSE="docker compose -f ci/e2e/docker-compose.yaml -p $PROJECT"

# The host port the stack binds. Deliberately not 8080: a developer
# running this locally very likely has something on that already.
HTTP_PORT=18190

# Exported before anything can fail, because the EXIT trap runs
# `docker compose down` and compose refuses to parse its own file with
# these unset.
export SILO_E2E_CONFIG_DIR="$WORK/config"
export SILO_E2E_HTTP_PORT="$HTTP_PORT"

REPO=example
CHANNEL=stable

log()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32mok\033[0m  %s\n' "$*"; }
fail() { printf '    \033[31mFAIL\033[0m  %s\n' "$*" >&2; exit 1; }

cleanup() {
    local status=$?
    if [ -n "${KEEP:-}" ]; then
        printf '\nKEEP is set; leaving the stack up.\n'
        printf '  silo  http://localhost:%s  (gRPC and HTTP share the port)\n' "$HTTP_PORT"
        printf '  tear down with: %s down -v\n' "$COMPOSE"
        return
    fi
    if [ $status -ne 0 ]; then
        log "silo server log (the run failed)"
        $COMPOSE logs --no-color --tail 80 silo || true
    fi
    $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$WORK"
mkdir -p "$WORK/packages" "$WORK/keys" "$WORK/out"

# --------------------------------------------------------------- signing

log "generating signing keys"

# APK: a plain RSA keypair. The public key's *filename* is what apk matches
# against, and it has to be the same name silo puts in the index's
# `.SIGN.RSA.<name>` member — hence one name, used in both places.
APK_KEY_NAME="silo-e2e@example.com-1a2b3c4d.rsa.pub"
docker run --rm -v "$WORK/keys:/keys" alpine:3.20 sh -c "
    apk add --no-cache openssl >/dev/null
    openssl genrsa -out /keys/apk.pem 2048 2>/dev/null
    openssl rsa -in /keys/apk.pem -pubout -out '/keys/$APK_KEY_NAME' 2>/dev/null
    chmod 644 /keys/*
"
[ -s "$WORK/keys/apk.pem" ] || fail "apk key generation produced nothing"
ok "apk RSA keypair ($APK_KEY_NAME)"

# RPM: a real OpenPGP key. `--quick-gen-key` with an empty passphrase is
# the only non-interactive way to get one, and silo wants it armored.
docker run --rm -v "$WORK/keys:/keys" alpine:3.20 sh -c '
    apk add --no-cache gnupg >/dev/null
    export GNUPGHOME=/tmp/gnupg && mkdir -p $GNUPGHOME && chmod 700 $GNUPGHOME
    gpg --batch --pinentry-mode loopback --passphrase "" \
        --quick-gen-key "silo e2e <silo@example.com>" rsa2048 sign never >/dev/null 2>&1
    gpg --batch --pinentry-mode loopback --passphrase "" \
        --armor --export-secret-keys > /keys/gpg-private.asc
    gpg --armor --export > /keys/gpg-public.asc
    chmod 644 /keys/gpg-*.asc
'
grep -q "BEGIN PGP PRIVATE KEY BLOCK" "$WORK/keys/gpg-private.asc" \
    || fail "gpg key generation produced no private key"
ok "rpm OpenPGP keypair"

# pacman: its own OpenPGP key, deliberately separate from RPM's — silo
# supports signing the two with different keys, and using the same one
# here would not exercise that.
docker run --rm -v "$WORK/keys:/keys" alpine:3.20 sh -c '
    apk add --no-cache gnupg >/dev/null
    export GNUPGHOME=/tmp/gnupg && mkdir -p $GNUPGHOME && chmod 700 $GNUPGHOME
    gpg --batch --pinentry-mode loopback --passphrase "" \
        --quick-gen-key "silo e2e pacman <silo@example.com>" rsa2048 sign never >/dev/null 2>&1
    gpg --batch --pinentry-mode loopback --passphrase "" \
        --armor --export-secret-keys > /keys/pacman-gpg-private.asc
    chmod 644 /keys/pacman-gpg-private.asc
'
grep -q "BEGIN PGP PRIVATE KEY BLOCK" "$WORK/keys/pacman-gpg-private.asc" \
    || fail "pacman gpg key generation produced no private key"
ok "pacman OpenPGP keypair"

# ------------------------------------------------------- example packages

log "building example packages with their native tooling"

# RPM, via rpmbuild in Fedora.
docker run --rm -v "$ROOT/examples/rpm:/spec:ro" -v "$WORK/packages:/out" fedora:41 bash -c '
    set -e
    dnf -q -y install rpm-build >/dev/null 2>&1
    rpmbuild -bb --define "_topdir /tmp/rpmbuild" /spec/silo-hello.spec >/dev/null 2>&1
    cp /tmp/rpmbuild/RPMS/*/*.rpm /out/
' >/dev/null 2>&1 || fail "rpmbuild failed (rerun with bash -x ci/e2e.sh to see why)"
RPM_FILE=$(ls "$WORK"/packages/*.rpm)
ok "rpm  $(basename "$RPM_FILE")"

# APK, via abuild in Alpine. abuild insists on signing what it builds, so
# it gets its own throwaway key — unrelated to the one silo signs the
# index with.
docker run --rm -v "$ROOT/examples/apk:/src:ro" -v "$WORK/packages:/out" alpine:3.20 sh -c '
    set -e
    apk add --no-cache alpine-sdk >/dev/null
    adduser -D builder >/dev/null && addgroup builder abuild
    mkdir -p /home/builder/pkg && cp /src/APKBUILD /home/builder/pkg/
    chown -R builder:builder /home/builder

    # abuild also tries to build a local index and sign it with the
    # throwaway key it just generated, which its own apk does not trust.
    # That step failing is expected and irrelevant — the .apk itself is
    # already written by then — so the package file is what we check for,
    # not the exit status.
    su builder -c "cd /home/builder/pkg && abuild-keygen -a -n -q && abuild -F -q -P /home/builder/out" \
        >/dev/null 2>&1 || true

    # abuild files noarch packages under the *build host* arch directory,
    # so the path is not predictable; the .PKGINFO inside still says
    # noarch, which is what silo indexes on.
    built=$(find /home/builder/out -name "*.apk" ! -name "*.doc.apk" | head -1)
    [ -n "$built" ] || { echo "abuild produced no .apk" >&2; exit 1; }
    cp "$built" /out/
' >/dev/null 2>&1 || fail "abuild failed (rerun with bash -x ci/e2e.sh to see why)"
APK_FILE=$(ls "$WORK"/packages/*.apk)
ok "apk  $(basename "$APK_FILE")"

# npm, via npm pack.
docker run --rm -v "$ROOT/examples/npm:/src:ro" -v "$WORK/packages:/out" node:22-alpine sh -c '
    set -e
    cp -r /src /tmp/pkg && cd /tmp/pkg
    npm pack --pack-destination /out >/dev/null
' >/dev/null 2>&1 || fail "npm pack failed (rerun with bash -x ci/e2e.sh to see why)"
NPM_FILE=$(ls "$WORK"/packages/*.tgz)
ok "npm  $(basename "$NPM_FILE")"

# pacman, via makepkg in Arch Linux. makepkg refuses to run as root, so it
# gets its own throwaway builder user, same as abuild above.
docker run --rm -v "$ROOT/examples/pacman:/src:ro" -v "$WORK/packages:/out" archlinux:base-devel sh -c '
    set -e
    useradd -m builder
    mkdir -p /home/builder/pkg && cp /src/PKGBUILD /home/builder/pkg/
    chown -R builder:builder /home/builder
    su builder -c "cd /home/builder/pkg && makepkg --nosign" >/dev/null 2>&1
    cp /home/builder/pkg/*.pkg.tar.zst /out/
' >/dev/null 2>&1 || fail "makepkg failed (rerun with bash -x ci/e2e.sh to see why)"
# Exactly one expected: PKGBUILD declares no split packages, so more than
# one *.pkg.tar.zst here means makepkg picked up something unexpected
# (e.g. a stale file from a previous run) rather than a real ambiguity to
# silently pick the first of.
PACMAN_CANDIDATES=$(ls "$WORK"/packages/*.pkg.tar.zst)
[ "$(echo "$PACMAN_CANDIDATES" | wc -l)" -eq 1 ] \
    || fail "expected exactly one pacman package, found: $PACMAN_CANDIDATES"
PACMAN_FILE=$PACMAN_CANDIDATES
ok "pacman  $(basename "$PACMAN_FILE")"

# deb, via dpkg-deb in Debian. examples/deb is already laid out as the
# payload tree dpkg-deb expects (a DEBIAN/control alongside the files to
# install), so there is no separate "source" format to unpack first.
#
# Architecture is rewritten to whatever this host's dpkg actually reports
# rather than trusting the checked-in "amd64": a package built for the
# wrong architecture is invisible to apt (silo only folds an `all`
# package into an architecture that has had a real publish of its own —
# see deb.rs), and this suite has to pass on both amd64 and arm64
# development machines, not just amd64 CI runners.
docker run --rm -v "$ROOT/examples/deb:/src:ro" -v "$WORK/packages:/out" debian:12 bash -c '
    set -e
    apt-get -qq update >/dev/null 2>&1
    apt-get -qq -y install dpkg-dev >/dev/null 2>&1
    cp -r /src /tmp/pkg
    ARCH=$(dpkg --print-architecture)
    sed -i "s/^Architecture: .*/Architecture: $ARCH/" /tmp/pkg/DEBIAN/control
    dpkg-deb --build --root-owner-group /tmp/pkg "/out/silo-hello_1.2.3-4_${ARCH}.deb"
' >/dev/null 2>&1 || fail "dpkg-deb failed (rerun with bash -x ci/e2e.sh to see why)"
DEB_FILE=$(ls "$WORK"/packages/*.deb)
DEB_ARCH=$(basename "$DEB_FILE" .deb)
DEB_ARCH=${DEB_ARCH##*_}
ok "deb  $(basename "$DEB_FILE")  (arch: $DEB_ARCH)"

# ------------------------------------------------------------- the server

log "starting silo (postgres + seaweedfs + server)"

# The config is written here rather than checked in because it embeds the
# keys generated above, which are different on every run.
mkdir -p "$WORK/config"
cp "$WORK/keys/apk.pem" "$WORK/config/apk.pem"
cp "$WORK/keys/gpg-private.asc" "$WORK/config/gpg-private.asc"
cp "$WORK/keys/pacman-gpg-private.asc" "$WORK/config/pacman-gpg-private.asc"
cat > "$WORK/config/config.yaml" <<EOF
addr: "0.0.0.0:8080"
# npm packuments embed absolute tarball URLs, so the server has to know
# the address the *client* reaches it on, not its own.
public_base_url: "http://silo:8080"

database:
  url: "postgres://silo:silo@postgres:5432/silo"

storage:
  bucket: "silo"
  region: "us-east-1"
  access_key_id: "siloadmin"
  secret_access_key: "siloadmin"
  endpoint: "http://seaweedfs:8333"
  allow_http: true

auth:
  bootstrap: true

audit:
  log_downloads: true
  retention_days: 90

metrics:
  enabled: true
  require_auth: false

signing:
  gpg:
    key_path: /etc/silo/gpg-private.asc
  apk:
    key_path: /etc/silo/apk.pem
    key_name: "$APK_KEY_NAME"
  pacman:
    key_path: /etc/silo/pacman-gpg-private.asc
EOF

$COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
$COMPOSE up -d --build >/dev/null

log "waiting for silo to become ready"
for i in $(seq 1 90); do
    if curl -fsS "http://localhost:$HTTP_PORT/readyz" >/dev/null 2>&1; then break; fi
    if [ "$i" = 90 ]; then
        $COMPOSE logs --no-color --tail 50 silo
        fail "silo did not become ready within 90s"
    fi
    sleep 1
done
ok "ready"

# The version endpoint is the cheapest possible check that we are talking
# to the build we just made, not a stale image.
SERVER_VERSION=$(curl -fsS "http://localhost:$HTTP_PORT/version")
ok "version  $SERVER_VERSION"

# ---------------------------------------------------------- authenticate

log "authenticating"

# The bootstrap password is printed exactly once, to the log, on the first
# start against an empty database.
BOOTSTRAP_PASSWORD=""
for _ in $(seq 1 30); do
    BOOTSTRAP_PASSWORD=$($COMPOSE logs --no-color silo 2>/dev/null \
        | sed -n 's/.*password: *\([A-Za-z0-9]*\).*/\1/p' | head -1)
    [ -n "$BOOTSTRAP_PASSWORD" ] && break
    sleep 1
done
[ -n "$BOOTSTRAP_PASSWORD" ] || fail "could not find the bootstrap password in the server log"

silo() { $COMPOSE exec -T silo /usr/local/bin/silo "$@"; }

# Exactly the flow a pipeline uses: credentials from the environment, the
# token on stdout, nothing written to disk.
ADMIN_TOKEN=$($COMPOSE exec -T \
    -e SILO_USERNAME=admin -e "SILO_PASSWORD=$BOOTSTRAP_PASSWORD" \
    silo /usr/local/bin/silo login --server http://localhost:8080 --print-token 2>/dev/null | tr -d '\r')
[ -n "$ADMIN_TOKEN" ] || fail "login produced no token"
ok "logged in as admin"

# A scoped write token, so publishing exercises the same permission path a
# real CI job would rather than admin's blanket access.
PUBLISH_TOKEN=$($COMPOSE exec -T -e "SILO_TOKEN=$ADMIN_TOKEN" silo \
    /usr/local/bin/silo --server http://localhost:8080 \
    token create --name e2e-publisher --permission write --repo "$REPO" --json 2>/dev/null \
    | tr -d '\r' | sed -n 's/.*"token": *"\([^"]*\)".*/\1/p')
[ -n "$PUBLISH_TOKEN" ] || fail "token create produced no token"
ok "created a write token scoped to $REPO"

# A read token for the package managers, which authenticate over HTTP.
READ_TOKEN=$($COMPOSE exec -T -e "SILO_TOKEN=$ADMIN_TOKEN" silo \
    /usr/local/bin/silo --server http://localhost:8080 \
    token create --name e2e-reader --permission read --repo "$REPO" --json 2>/dev/null \
    | tr -d '\r' | sed -n 's/.*"token": *"\([^"]*\)".*/\1/p')
[ -n "$READ_TOKEN" ] || fail "read token create produced no token"
ok "created a read token"

# -------------------------------------------------------------- publish

log "publishing"

docker cp "$WORK/packages/." "$($COMPOSE ps -q silo)":/tmp/packages/ 2>/dev/null \
    || { $COMPOSE exec -T silo mkdir -p /tmp/packages; docker cp "$WORK/packages/." "$($COMPOSE ps -q silo)":/tmp/packages/; }

publish() {
    local file=$1
    $COMPOSE exec -T -e "SILO_TOKEN=$PUBLISH_TOKEN" -e SILO_SERVER=http://localhost:8080 silo \
        /usr/local/bin/silo publish "/tmp/packages/$file" --repo "$REPO" --channel "$CHANNEL"
}

publish "$(basename "$RPM_FILE")" | sed 's/^/    /'
publish "$(basename "$APK_FILE")" | sed 's/^/    /'
publish "$(basename "$NPM_FILE")" | sed 's/^/    /'
publish "$(basename "$PACMAN_FILE")" | sed 's/^/    /'
publish "$(basename "$DEB_FILE")" | sed 's/^/    /'

# Five packages, five formats, all in one repo/channel.
LISTED=$($COMPOSE exec -T -e "SILO_TOKEN=$ADMIN_TOKEN" -e SILO_SERVER=http://localhost:8080 silo \
    /usr/local/bin/silo list --repo "$REPO" --channel "$CHANNEL" --json | tr -d '\r')
for format in rpm apk npm pacman deb; do
    echo "$LISTED" | grep -q "\"format\": \"$format\"" \
        || fail "$format is missing from the package list"
done
ok "all five formats are indexed"

# pacman's downloader does not send Basic-auth credentials embedded in a
# Server URL the way dnf's and apk's do (verified empirically — it just
# never presents one), so a private repo is unreachable for it no matter
# what's in pacman.conf. Every other verifier below still authenticates
# with a real token regardless of this.
$COMPOSE exec -T -e "SILO_TOKEN=$ADMIN_TOKEN" -e SILO_SERVER=http://localhost:8080 silo \
    /usr/local/bin/silo repo set "$REPO" --mode=public | sed 's/^/    /'
ok "repo is public (required for the pacman verifier)"

# -------------------------------------------------------------- consume

# Each verifier runs in its own distro container on the compose network,
# so it reaches silo by service name over the same HTTP surface a real
# client would.
verify() {
    local name=$1 image=$2 script=$3
    log "verifying with real $name"
    docker run --rm \
        --network "${PROJECT}_silo" \
        -e "SILO_TOKEN=$READ_TOKEN" \
        -e "SILO_PUBLISH_TOKEN=$PUBLISH_TOKEN" \
        -e "REPO=$REPO" -e "CHANNEL=$CHANNEL" \
        -e "APK_KEY_NAME=$APK_KEY_NAME" \
        -e "DEB_ARCH=$DEB_ARCH" \
        -v "$ROOT/ci/e2e:/verify:ro" \
        -v "$WORK/keys:/keys:ro" \
        "$image" sh "/verify/$script" 2>&1 | sed 's/^/    /' \
        || fail "$name verification failed"
    ok "$name installed and ran the package silo served"
}

verify dnf    fedora:41        verify-dnf.sh
verify apk    alpine:3.20      verify-apk.sh
verify npm    node:22-alpine   verify-npm.sh
verify pacman archlinux:base   verify-pacman.sh
verify apt    debian:12        verify-apt.sh

# ---------------------------------------------------------------- repair

log "verifying index repair"

# `silo index rebuild` is the documented recovery path after a bucket
# restore. It has to produce an index good enough for a real client, not
# just one that renders — so it is checked the same way as the rest.
$COMPOSE exec -T -e "SILO_TOKEN=$ADMIN_TOKEN" -e SILO_SERVER=http://localhost:8080 silo \
    /usr/local/bin/silo index rebuild --repo "$REPO" --channel "$CHANNEL" --format rpm \
    | sed 's/^/    /'
verify "dnf (after an index rebuild)" fedora:41 verify-dnf.sh

$COMPOSE exec -T -e "SILO_TOKEN=$ADMIN_TOKEN" -e SILO_SERVER=http://localhost:8080 silo \
    /usr/local/bin/silo index rebuild --repo "$REPO" --channel "$CHANNEL" --format pacman \
    | sed 's/^/    /'
verify "pacman (after an index rebuild)" archlinux:base verify-pacman.sh

$COMPOSE exec -T -e "SILO_TOKEN=$ADMIN_TOKEN" -e SILO_SERVER=http://localhost:8080 silo \
    /usr/local/bin/silo index rebuild --repo "$REPO" --channel "$CHANNEL" --format deb \
    | sed 's/^/    /'
verify "apt (after an index rebuild)" debian:12 verify-apt.sh

log "end-to-end suite passed"
