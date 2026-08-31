#!/bin/sh
# Verifies silo's Packages/Release/InRelease with real apt, in a real Debian.
#
# apt is the strictest of the clients about the shape of what it's given:
# a malformed Release, a signature that doesn't verify, or a Packages
# stanza apt can't parse each fail loudly rather than silently degrading,
# so installing at all is most of the proof this format works.
set -eu

: "${SILO_TOKEN:?}" "${REPO:?}" "${CHANNEL:?}" "${DEB_ARCH:?}"

export DEBIAN_FRONTEND=noninteractive

SILO="http://silo:8080"
GPGKEY_URL="$SILO/RPM-GPG-KEY-silo"

apt-get -qq update >/dev/null 2>&1
apt-get -qq -y install curl gnupg >/dev/null 2>&1

echo "== the signing key silo serves"
# apt reuses the same key dnf does (see signing.rs) — silo has no apt-
# specific key of its own, so this is the same endpoint verify-dnf.sh
# fetches from, just dearmored into the binary keyring apt's
# `signed-by=` expects.
curl -fsS "$GPGKEY_URL" -o /tmp/silo-gpg-key.asc || {
    echo "silo did not serve $GPGKEY_URL" >&2; exit 1; }
head -1 /tmp/silo-gpg-key.asc | grep -q "BEGIN PGP PUBLIC KEY BLOCK" || {
    echo "$GPGKEY_URL did not return an armored public key:" >&2
    head -3 /tmp/silo-gpg-key.asc >&2
    exit 1; }

mkdir -p /etc/apt/keyrings
gpg --dearmor < /tmp/silo-gpg-key.asc > /etc/apt/keyrings/silo.gpg

# apt speaks HTTP Basic when credentials are embedded in the source URL;
# silo takes the token in the password field and ignores the username,
# the same convention verify-dnf.sh's `.repo` and verify-apk.sh's
# repositories file use.
#
# Replaces /etc/apt/sources.list entirely rather than adding a file
# alongside it: every query below has to resolve only through silo, never
# through Debian's own mirrors, or a package resolving from the wrong
# repository would look like a pass.
echo "deb [signed-by=/etc/apt/keyrings/silo.gpg] http://silo:$SILO_TOKEN@silo:8080/$REPO/$CHANNEL $CHANNEL main" \
    > /etc/apt/sources.list
rm -f /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list 2>/dev/null || true

echo "== update: fetch and verify the signed Release"
# Fails if InRelease/Release.gpg is missing, malformed, or made with a key
# that isn't the one imported above — apt does not have a flag that
# merely warns about that, the same as apk.
apt-get update 2>&1 | tail -8

echo "== policy: what does apt see?"
policy=$(apt-cache policy silo-hello)
echo "$policy" | sed 's/^/  /'
echo "$policy" | grep -q '1\.2\.3-4' || {
    echo "unexpected package version in: $policy" >&2
    exit 1; }

echo "== show: did the metadata round-trip through Packages?"
info=$(apt-cache show silo-hello)
echo "$info" | grep -qi "end-to-end tests" || {
    echo "the package description did not round-trip:" >&2
    echo "$info" >&2
    exit 1; }
echo "$info" | grep -q '^Depends: bash$' || {
    echo "the 'bash' dependency did not round-trip:" >&2
    echo "$info" >&2
    exit 1; }
echo "$info" | grep -q "^Architecture: $DEB_ARCH\$" || {
    echo "expected architecture $DEB_ARCH in:" >&2
    echo "$info" >&2
    exit 1; }

echo "== install: download, verify the package hash, install"
# No --allow-unauthenticated anywhere: the Release signature was verified
# above, and the Packages entry's SHA256 is what apt verifies the
# download against.
apt-get install -y silo-hello 2>&1 | tail -8

echo "== run the installed program"
output=$(/usr/bin/silo-hello)
echo "  $output"
[ "$output" = "hello from silo deb 1.2.3" ] || {
    echo "installed program printed the wrong thing" >&2; exit 1; }

echo "== dpkg considers the package installed"
dpkg-query -W -f '${Status}\n' silo-hello | grep -q "install ok installed" || {
    echo "dpkg does not consider silo-hello installed" >&2; exit 1; }

echo "apt verification passed"
