#!/bin/sh
# Verifies silo's pacman database with real pacman, in a real Arch Linux.
#
# The database is signed (db-only, per silo's signing model — package
# files themselves are not); the package is `arch=any`, which is the case
# most likely to regress since pacman only ever fetches its own
# architecture's database and never looks in an `any` tree on its own.
#
# No credential anywhere in this script, unlike the other verifiers:
# pacman's downloader does not send Basic-auth credentials embedded in a
# Server URL, so `$REPO` has to already be public by the time this runs —
# see e2e.sh, which flips it public right after publishing.
set -eu

: "${REPO:?}" "${CHANNEL:?}"

SILO="http://silo:8080"
KEY_URL="$SILO/pacman-signing-key"

echo "== the signing key silo serves"
# Deliberately *not* pre-imported from a mounted file. Fetching it from
# silo over an unauthenticated endpoint and importing that is the thing
# being tested.
curl -fsS "$KEY_URL" -o /tmp/silo-pacman-key.asc || {
    echo "silo did not serve $KEY_URL" >&2; exit 1; }
head -1 /tmp/silo-pacman-key.asc | grep -q "BEGIN PGP PUBLIC KEY BLOCK" || {
    echo "$KEY_URL did not return an armored public key:" >&2
    head -3 /tmp/silo-pacman-key.asc >&2
    exit 1; }
grep -q "PRIVATE KEY" /tmp/silo-pacman-key.asc && {
    echo "the key endpoint served private key material" >&2; exit 1; }

echo "== trusting silo's key"
pacman-key --init >/dev/null 2>&1
pacman-key --add /tmp/silo-pacman-key.asc >/dev/null 2>&1
# Read the fingerprint from the downloaded key file itself rather than the
# populated keyring — pacman-key --init seeds it with distro trust-anchor
# keys, so picking "the first fingerprint in the keyring" would silently
# lsign the wrong key the moment that seed is non-empty.
FPR=$(gpg --with-colons --show-keys /tmp/silo-pacman-key.asc \
    | awk -F: '/^fpr:/ {print $10; exit}')
[ -n "$FPR" ] || { echo "could not find the imported key's fingerprint" >&2; exit 1; }
pacman-key --lsign-key "$FPR" >/dev/null 2>&1

echo "== configuring pacman.conf to talk only to silo"
# Real Arch mirrors are neither reachable nor relevant here, so the
# default repos are dropped rather than left to fail resolving.
#
# DatabaseRequired without PackageRequired: silo signs the database only
# (see the Signing section of README.md), so a package-level signature
# check would fail every install regardless of whether silo served
# anything correctly.
cat > /etc/pacman.conf <<EOF
[options]
Architecture = auto

[silo]
SigLevel = PackageOptional DatabaseRequired
Server = http://silo:8080/$REPO/$CHANNEL/pacman/\$arch
EOF

echo "== Sy: fetch and verify the signed database"
# Fails outright if the database or its detached signature is missing or
# malformed, or was signed by a key other than the one imported above.
pacman -Sy 2>&1 | tail -5

echo "== Si: did the metadata round-trip through the database?"
info=$(pacman -Si silo-hello)
echo "$info" | grep -qi "end-to-end tests" || {
    echo "the package description did not round-trip:" >&2
    echo "$info" >&2
    exit 1
}

echo "== depends: did the dependency survive the database?"
echo "$info" | grep -q "Depends On *: .*bash" || {
    echo "the 'bash' dependency did not round-trip:" >&2
    echo "$info" >&2
    exit 1
}

echo "== S: download, verify, install"
# The package itself is arch=any; reaching it at all under this host's own
# architecture means silo both listed it in this architecture's database
# and served the file from this architecture's path, where it is not
# actually stored.
pacman -S --noconfirm silo-hello 2>&1 | tail -5

echo "== run the installed program"
output=$(/usr/bin/silo-hello)
echo "  $output"
[ "$output" = "hello from silo pacman 1.2.3" ] || {
    echo "installed program printed the wrong thing" >&2; exit 1; }

echo "== pacman considers the package installed"
pacman -Qi silo-hello | grep -q silo-hello || {
    echo "pacman does not consider silo-hello installed" >&2; exit 1; }

echo "pacman verification passed"
