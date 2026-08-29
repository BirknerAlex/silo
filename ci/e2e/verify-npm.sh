#!/bin/sh
# Verifies silo's packuments with a real npm client.
#
# The package is scoped (`@silo-example/hello`) on purpose: a scope puts a
# slash inside what npm treats as a single path segment, and silo's npm
# route has to handle both the encoded and unencoded forms. That is the
# part most likely to break.
set -eu

: "${SILO_TOKEN:?}" "${REPO:?}" "${CHANNEL:?}" "${SILO_PUBLISH_TOKEN:?}"

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

# Everything above proves silo's *reads* satisfy a real npm client, using a
# fixture published through the `silo` CLI's gRPC path. This proves the
# other direction: a real `npm publish` writing straight to silo's HTTP
# endpoint, not the CLI. It gets its own package name so it can't collide
# with the fixture, and its own npmrc so the write-scoped token used here
# never mixes with the read-scoped one used above.
echo "== publish: can a real npm client publish over HTTP?"
cat > /root/.npmrc-publish <<EOF
//silo:8080/$REPO/$CHANNEL/npm/:_authToken=$SILO_PUBLISH_TOKEN
EOF
export NPM_CONFIG_USERCONFIG=/root/.npmrc-publish

mkdir -p /tmp/publisher && cd /tmp/publisher
npm init -y >/dev/null 2>&1
npm pkg set name=silo-e2e-http-publish version=1.0.0 >/dev/null 2>&1
if ! publish_out=$(npm publish --registry "$REGISTRY" 2>&1); then
    echo "$publish_out" | tail -20
    echo "npm publish failed" >&2
    exit 1
fi
echo "$publish_out" | tail -5

echo "== the http-published package is indexed"
published_version=$(npm view silo-e2e-http-publish version --registry "$REGISTRY")
echo "  version $published_version"
[ "$published_version" = "1.0.0" ] || {
    echo "unexpected version after an http publish: $published_version" >&2
    exit 1
}

echo "== the http-published package installs, same as any other"
mkdir -p /tmp/consumer-http && cd /tmp/consumer-http
npm init -y >/dev/null 2>&1
if ! install_out=$(npm install silo-e2e-http-publish --registry "$REGISTRY" 2>&1); then
    echo "$install_out" | tail -20
    echo "npm install of the http-published package failed" >&2
    exit 1
fi
echo "$install_out" | tail -3
[ -f node_modules/silo-e2e-http-publish/package.json ] || {
    echo "the http-published package did not install" >&2; exit 1; }

echo "npm verification passed"
