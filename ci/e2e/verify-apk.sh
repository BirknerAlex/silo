#!/bin/sh
# Verifies silo's APKINDEX with real apk-tools, in a real Alpine.
#
# apk is the strictest of the three clients: it will not use a repository
# whose index is not signed by a key it already trusts, and there is no
# flag that makes it merely warn. So this run is necessarily the signed
# path — which is also the only path any real deployment uses.
set -eu

: "${SILO_TOKEN:?}" "${REPO:?}" "${CHANNEL:?}" "${APK_KEY_NAME:?}"

ARCH=$(apk --print-arch)

echo "trusting silo's index key"
# The filename is load-bearing. apk looks up the key by the name recorded
# in the index's `.SIGN.RSA.<name>` member, so this has to match the
# `key_name` silo was configured with, exactly.
cp "/keys/$APK_KEY_NAME" /etc/apk/keys/

# apk takes HTTP Basic credentials in the URL. The username is ignored;
# the token goes in the password field.
BASE="http://silo:$SILO_TOKEN@silo:8080/$REPO/$CHANNEL/apk"

echo "== update: fetch and verify the signed index"
# This fails if the signature is missing, malformed, or made with a key
# that isn't the one installed above.
echo "$BASE" > /etc/apk/repositories.silo
apk update --repositories-file /etc/apk/repositories.silo 2>&1 | tail -3

# Every command goes through here so it can only ever see silo's
# repository, never Alpine's — a package resolving from the wrong one
# would look like a pass.
silo_apk() {
    apk --repositories-file /etc/apk/repositories.silo "$@"
}

echo "== a noarch package is reachable from this host's architecture"
# The example declares arch=noarch, and apk only ever fetches
# $repo/$hostarch/APKINDEX.tar.gz — it will not look in a noarch directory
# on its own. Finding the package at all means silo listed it in this
# architecture's index; installing it means silo also served the file from
# this architecture's path, where it is not actually stored.
echo "  host arch: $ARCH"
# busybox wget, since a bare Alpine has no curl. The URL carries the
# credentials the same way the repositories file does.
wget -q -O /dev/null "http://silo:$SILO_TOKEN@silo:8080/$REPO/$CHANNEL/apk/$ARCH/APKINDEX.tar.gz" || {
    echo "no APKINDEX served for $ARCH; a noarch-only channel must still" >&2
    echo "answer for whatever architecture asks" >&2
    exit 1
}
# ...and the package file, which is stored under noarch and nowhere else.
wget -q -O /dev/null "http://silo:$SILO_TOKEN@silo:8080/$REPO/$CHANNEL/apk/$ARCH/silo-hello-1.2.3-r0.apk" || {
    echo "the noarch package is not served from the $ARCH path apk will use" >&2
    exit 1
}

echo "== search: what does apk see?"
found=$(silo_apk search -x silo-hello)
echo "  $found"
[ "$found" = "silo-hello-1.2.3-r0" ] || {
    echo "unexpected package version: $found" >&2
    exit 1
}

echo "== info: did the metadata round-trip through the index?"
info=$(silo_apk info --description silo-hello 2>/dev/null || true)
echo "$info" | grep -qi "end-to-end tests" || {
    echo "the package description did not round-trip:" >&2
    echo "$info" >&2
    exit 1
}

echo "== depends: did the dependency survive the index?"
depends=$(silo_apk info --depends silo-hello 2>/dev/null || true)
echo "$depends" | grep -q busybox || {
    echo "the 'busybox' dependency did not round-trip:" >&2
    echo "$depends" >&2
    exit 1
}

echo "== add: download, verify the package hash, install"
# No --allow-untrusted anywhere: the index signature was verified above,
# and the index's per-package checksum is what apk verifies the download
# against.
silo_apk add silo-hello 2>&1 | tail -3

echo "== run the installed program"
output=$(/usr/bin/silo-hello)
echo "  $output"
[ "$output" = "hello from silo apk 1.2.3" ] || {
    echo "installed program printed the wrong thing" >&2; exit 1; }

echo "== apk considers the package installed and intact"
apk info -e silo-hello | grep -q silo-hello || {
    echo "apk does not consider silo-hello installed" >&2; exit 1; }
# Catches a package whose recorded file list disagrees with what landed on
# disk — i.e. a publish path that corrupted the .apk in transit.
apk audit --system 2>&1 | grep -q "silo-hello" && {
    echo "apk audit reports silo-hello as modified" >&2; exit 1; }

echo "apk verification passed"
