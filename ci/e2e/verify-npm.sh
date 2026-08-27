#!/bin/sh
# Verifies silo's packuments with a real npm client.
#
# The package is scoped (`@silo-example/hello`) on purpose: a scope puts a
# slash inside what npm treats as a single path segment, and silo's npm
# route has to handle both the encoded and unencoded forms. That is the
# part most likely to break.
set -eu

: "${SILO_TOKEN:?}" "${REPO:?}" "${CHANNEL:?}"

REGISTRY="http://silo:8080/$REPO/$CHANNEL/npm/"

echo "configuring the registry"
# npm uses Bearer, not Basic — the one client of the three that does.
cat > /root/.npmrc <<EOF
@silo-example:registry=$REGISTRY
//silo:8080/$REPO/$CHANNEL/npm/:_authToken=$SILO_TOKEN
EOF

echo "== view: can npm read the packument?"
viewed=$(npm view @silo-example/hello version)
echo "  version $viewed"
[ "$viewed" = "1.2.3" ] || {
    echo "unexpected version: $viewed" >&2
    exit 1
}

echo "== the packument carries the manifest fields npm needs"
license=$(npm view @silo-example/hello license)
[ "$license" = "MIT" ] || { echo "license did not round-trip: $license" >&2; exit 1; }
# An absolute tarball URL is not optional: npm fetches exactly what the
# packument says, so a relative or wrong-host URL makes install fail even
# though `view` works.
tarball=$(npm view @silo-example/hello dist.tarball)
echo "  tarball $tarball"
case "$tarball" in
    http://silo:8080/*) ;;
    *) echo "packument has a tarball URL npm cannot fetch: $tarball" >&2; exit 1 ;;
esac

echo "== the integrity hash is present, so npm will verify the download"
integrity=$(npm view @silo-example/hello dist.integrity 2>/dev/null || true)
shasum=$(npm view @silo-example/hello dist.shasum 2>/dev/null || true)
[ -n "$integrity" ] || [ -n "$shasum" ] || {
    echo "packument has neither dist.integrity nor dist.shasum; npm would" >&2
    echo "install the tarball without verifying it" >&2
    exit 1
}
echo "  integrity ${integrity:-<none>} shasum ${shasum:-<none>}"

echo "== install: download, verify integrity, unpack"
mkdir -p /tmp/consumer && cd /tmp/consumer
npm init -y >/dev/null 2>&1
# `npm install` fails loudly if the tarball's hash does not match the
# packument, so a corrupted publish path cannot pass this.
npm install @silo-example/hello 2>&1 | tail -3

echo "== run the installed program"
output=$(./node_modules/.bin/silo-hello)
echo "  $output"
[ "$output" = "hello from silo npm 1.2.3" ] || {
    echo "installed program printed the wrong thing" >&2; exit 1; }

echo "== the scope survived into the installed tree"
[ -f node_modules/@silo-example/hello/package.json ] || {
    echo "the scoped package did not install under its scope" >&2; exit 1; }

echo "npm verification passed"
