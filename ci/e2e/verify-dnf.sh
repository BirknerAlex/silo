#!/bin/sh
# Verifies silo's repodata with real dnf, in a real Fedora.
#
# This is the check that matters most for the RPM format, because silo
# generates repodata itself rather than shelling out to createrepo_c.
# Everything else is testing our code against our code; this is testing it
# against the tool that has to read it.
set -eu

: "${SILO_TOKEN:?}" "${REPO:?}" "${CHANNEL:?}"

SILO="http://silo:8080"
BASE="$SILO/$REPO/$CHANNEL"
GPGKEY_URL="$SILO/RPM-GPG-KEY-silo"

echo "== the signing key silo serves"
# Deliberately *not* `rpm --import /keys/gpg-public.asc`. Pointing
# `gpgkey=` at silo and letting dnf fetch it is the thing being tested:
# with the key pre-imported, the endpoint could be broken and every check
# below would still pass.
#
# The endpoint is unauthenticated, and this fetch carries no credential,
# which is the other half of what makes it usable — dnf fetches `gpgkey=`
# independently of the repo's own credentials.
curl -fsS "$GPGKEY_URL" -o /tmp/silo-gpg-key.asc || {
    echo "silo did not serve $GPGKEY_URL" >&2; exit 1; }
head -1 /tmp/silo-gpg-key.asc | grep -q "BEGIN PGP PUBLIC KEY BLOCK" || {
    echo "$GPGKEY_URL did not return an armored public key:" >&2
    head -3 /tmp/silo-gpg-key.asc >&2
    exit 1; }
grep -q "PRIVATE KEY" /tmp/silo-gpg-key.asc && {
    echo "the key endpoint served private key material" >&2; exit 1; }
echo "  $(wc -c < /tmp/silo-gpg-key.asc) bytes of armored public key"

# dnf speaks HTTP Basic; silo takes the token in the password field and
# ignores the username.
#
# `gpgcheck=1` verifies package signatures, `repo_gpgcheck=1` verifies
# repomd.xml against the detached signature silo writes beside it. Both
# resolve through `gpgkey=`, which is a URL on silo itself — exactly what
# a real `.repo` file would carry.
cat > /etc/yum.repos.d/silo.repo <<EOF
[silo]
name=silo e2e
baseurl=$BASE
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=$GPGKEY_URL
username=silo
password=$SILO_TOKEN
metadata_expire=0
EOF

# Every query goes through here so it can only ever see silo's repo, never
# Fedora's — otherwise a package resolving from the wrong repository would
# look like a pass.
#
# `-y` matters beyond convenience: with repo_gpgcheck on, dnf prompts to
# import the repo's key on first use and would otherwise block forever on
# a container with no tty.
silo_dnf() {
    dnf -y --disablerepo='*' --enablerepo=silo "$@"
}

echo "== repoquery: what does dnf see?"
# Fails outright if repomd.xml, its signature, or primary.xml is malformed.
found=$(silo_dnf -q repoquery --qf '%{name}|%{version}|%{release}|%{arch}|%{license}' silo-hello)
echo "  $found"
[ "$found" = "silo-hello|1.2.3|4|noarch|MIT" ] || {
    echo "unexpected package metadata: $found" >&2
    exit 1
}

echo "== requires: did the dependency survive primary.xml?"
requires=$(silo_dnf -q repoquery --requires silo-hello)
echo "$requires" | grep -q '^bash$' || {
    echo "the 'bash' dependency did not round-trip:" >&2
    echo "$requires" >&2
    exit 1
}
# rpmlib() entries are dropped on purpose: no repository can ever provide
# them, so leaving them in sends every depsolve chasing a phantom.
echo "$requires" | grep -q 'rpmlib(' && {
    echo "rpmlib() requires leaked into primary.xml:" >&2
    echo "$requires" >&2
    exit 1
}

echo "== filelists: is the full file list separately available?"
files=$(silo_dnf -q repoquery -l silo-hello)
echo "$files" | grep -q '^/usr/bin/silo-hello$' || {
    echo "/usr/bin/silo-hello missing from filelists.xml" >&2; exit 1; }
echo "$files" | grep -q '^/usr/share/silo-hello/README$' || {
    echo "/usr/share/silo-hello/README missing from filelists.xml" >&2; exit 1; }

echo "== changelog: did other.xml round-trip?"
changelog=$(silo_dnf -q repoquery --changelogs silo-hello 2>/dev/null || true)
echo "$changelog" | grep -qi 'changelog entry' || {
    echo "the changelog did not round-trip through other.xml:" >&2
    echo "$changelog" >&2
    exit 1
}

echo "== whatprovides: is the file index usable for resolution?"
# /usr/bin/... is a primary file, so this resolves without dnf having to
# download filelists at all.
silo_dnf -q repoquery --whatprovides /usr/bin/silo-hello | grep -q silo-hello || {
    echo "dnf could not resolve /usr/bin/silo-hello to its package" >&2; exit 1; }

echo "== install: download, verify signature, install"
silo_dnf install silo-hello 2>&1 | tail -5

echo "== run the installed program"
output=$(/usr/bin/silo-hello)
echo "  $output"
[ "$output" = "hello from silo rpm 1.2.3" ] || {
    echo "installed program printed the wrong thing" >&2; exit 1; }

echo "== dnf imported the key from silo, not from anywhere else"
# rpm records every imported public key as a `gpg-pubkey` package. The
# suite's key is a throwaway generated minutes ago, so its presence here
# can only have come from the URL configured above.
rpm -q gpg-pubkey --qf '%{version}-%{release} %{summary}\n' | sed 's/^/  /'
rpm -q gpg-pubkey --qf '%{summary}\n' | grep -q 'silo e2e' || {
    echo "silo's key is not in rpm's keyring; nothing fetched it" >&2
    exit 1; }

echo "== the package really was signature-verified"
# Installing at all under gpgcheck=1 is most of the proof, but an
# unsigned package can still slip through a misconfigured repo, so the
# signature is read back explicitly.
#
# `rpm -qi` rather than a --qf on a signature tag: which tag holds it
# moved between rpm 4 and rpm 6 (SIGPGP/SIGGPG -> RSAHEADER -> OPENPGP),
# and querying the wrong one returns empty rather than failing, which
# would make this check quietly meaningless.
sig=$(rpm -qi silo-hello | sed -n 's/^Signature *: *//p')
echo "  signature: ${sig:-<none>}"
case "$sig" in
    ""|*"(none)"*)
        echo "package was installed unsigned; gpgcheck did nothing" >&2
        exit 1 ;;
esac

echo "dnf verification passed"
