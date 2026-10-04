#!/bin/sh
# Verifies a silo OSTree remote with the real flatpak, in a real Fedora.
#
# flatpak is the strictest client here about what it is given: it checks the
# remote's signed `summary`, every commit's signature, each object's
# checksum, and its own idea of what a well-formed summary looks like, and
# fails the whole install on any of them. Installing and running an app is
# most of the proof the remote works.
#
# One script, several scenarios, picked with PHASE:
#
#   install    add the remote from its .flatpakrepo, install the app and the
#              runtime it needs from silo alone, run it, check the result
#   update     the app was republished; `flatpak update` has to find it
#   ref        install from the per-app .flatpakref URL
#   signature  a remote trusting a different key has to be refused
#   flathub    install a real Flathub app that silo re-hosts, and check it is
#              the very commit Flathub serves
#
# `install` and `update` share a HOME (a volume the caller mounts) so that
# `update` finds what `install` put there.
set -eu

: "${REPO:?}" "${FLATPAK_CHANNEL:?}" "${PHASE:?}"

SILO="http://silo:8080"
REMOTE="$SILO/$REPO/$FLATPAK_CHANNEL"
APP=org.silo.Hello

dnf -q -y install flatpak ostree gnupg2 >/dev/null 2>&1

export HOME="${FLATPAK_HOME:-/root}"
mkdir -p "$HOME"

fail() { echo "$*" >&2; exit 1; }

# Runs the installed app and checks what it prints. flatpak run builds a
# sandbox, which needs user namespaces; the caller runs this container
# privileged for that.
run_app() {
    expected=$1
    output=$(flatpak --user run "$APP" 2>&1) || {
        echo "$output" >&2
        fail "flatpak run $APP failed"
    }
    echo "  $output"
    [ "$output" = "$expected" ] || fail "expected '$expected', the app printed '$output'"
}

# Every object in what flatpak deployed has to match its checksum.
fsck_installation() {
    out=$(ostree --repo="$HOME/.local/share/flatpak/repo" fsck 2>&1 | tail -1)
    echo "  $out"
    echo "$out" | grep -q "no errors found" || fail "ostree fsck: $out"
}

case "$PHASE" in
install)
    echo "== the .flatpakrepo silo serves"
    curl -fsS "$REMOTE/silo.flatpakrepo" -o /tmp/silo.flatpakrepo
    sed "s/^GPGKey=.*/GPGKey=<omitted>/" /tmp/silo.flatpakrepo | sed "s/^/  /"
    grep -q '^GPGKey=' /tmp/silo.flatpakrepo || fail "the .flatpakrepo carries no GPGKey"
    grep -q "^Url=$REMOTE/ostree" /tmp/silo.flatpakrepo || fail "the .flatpakrepo has the wrong Url"

    echo "== remote-add: flatpak imports the key and trusts the remote"
    flatpak --user remote-add --if-not-exists silo /tmp/silo.flatpakrepo
    flatpak --user remotes -d | sed 's/^/  /'

    echo "== remote-ls: the signed summary verifies and lists what was published"
    listing=$(flatpak --user remote-ls silo --columns=application,branch)
    echo "$listing" | sed 's/^/  /'
    echo "$listing" | grep -q "$APP" || fail "$APP is not in the remote's summary"

    echo "== remote-info: sizes and commit round-trip through the summary"
    info=$(flatpak --user remote-info silo "$APP")
    echo "$info" | sed 's/^/  /'
    echo "$info" | grep -q "Ref: app/$APP/" || fail "remote-info does not name the ref"
    echo "$info" | grep -q "Runtime: org.silo.Platform/" || fail "remote-info lost the runtime"

    echo "== install: the app and its runtime, both from silo"
    flatpak --user install -y --noninteractive silo "$APP" 2>&1 | tail -6
    installed=$(flatpak --user list --columns=application,origin)
    echo "$installed" | sed 's/^/  /'
    echo "$installed" | grep -q "$APP.*silo" || fail "$APP was not installed from silo"
    echo "$installed" | grep -q "org.silo.Platform.*silo" \
        || fail "the runtime was not installed from silo"

    echo "== run the installed app"
    run_app "hello from silo flatpak ${EXPECTED_VERSION:-1.0.0}"

    echo "== the deployment is intact"
    fsck_installation
    ;;

update)
    echo "== update: flatpak finds the republished app"
    flatpak --user update -y --noninteractive 2>&1 | tail -6
    echo "== run the updated app"
    run_app "hello from silo flatpak 2.0.0"
    fsck_installation
    ;;

ref)
    echo "== the per-app .flatpakref"
    curl -fsS "$REMOTE/flatpakref/$APP.flatpakref" -o /tmp/app.flatpakref
    sed 's/^GPGKey=.*/GPGKey=<omitted>/' /tmp/app.flatpakref | sed 's/^/  /'
    grep -q "^Name=$APP\$" /tmp/app.flatpakref || fail "the .flatpakref names the wrong app"
    grep -q "^RuntimeRepo=$REMOTE/silo.flatpakrepo\$" /tmp/app.flatpakref \
        || fail "the .flatpakref does not say where the runtime is"

    echo "== install straight from the .flatpakref URL"
    # The ref names the remote, and its RuntimeRepo says where the runtime
    # is — flatpak does not look in the remote the ref itself names — so one
    # command gets both.
    flatpak --user install -y --noninteractive "$REMOTE/flatpakref/$APP.flatpakref" 2>&1 | tail -6
    flatpak --user list --columns=application,origin | sed 's/^/  /'
    flatpak --user list --columns=application | grep -q "$APP" || fail "$APP was not installed"
    run_app "hello from silo flatpak 1.0.0"
    ;;

signature)
    echo "== a remote that trusts a different key must be refused"
    # An unrelated OpenPGP key: if signatures were not actually checked, a
    # remote pinned to the wrong key would work as well as the right one.
    export GNUPGHOME=/tmp/wrong-gnupg
    mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME"
    gpg --batch --pinentry-mode loopback --passphrase "" \
        --quick-gen-key "somebody else <else@example.com>" rsa2048 sign never >/dev/null 2>&1
    gpg --export > /tmp/wrong.gpg
    [ -s /tmp/wrong.gpg ] || fail "could not generate the unrelated key"

    # flatpak reads the summary when a remote is added, so the refusal can
    # come there or, for a remote that was added anyway, when it is used.
    if out=$(flatpak --user remote-add --if-not-exists --gpg-import=/tmp/wrong.gpg \
        silo-wrongkey "$REMOTE/ostree" 2>&1); then
        if out=$(flatpak --user remote-ls silo-wrongkey 2>&1); then
            echo "$out" >&2
            fail "a remote pinned to the wrong key listed its apps"
        fi
        echo "  refused when its summary was read"
        if inst=$(flatpak --user install -y --noninteractive silo-wrongkey "$APP" 2>&1); then
            echo "$inst" >&2
            fail "an install from a remote pinned to the wrong key succeeded"
        fi
        echo "  install refused"
    else
        echo "  refused when the remote was added"
    fi
    echo "$out" | sed 's/^/  /'
    echo "$out" | grep -qi "signature\|gpg\|key" \
        || fail "the refusal did not mention the signature: $out"
    if flatpak --user list --columns=application | grep -q "$APP"; then
        fail "$APP got installed anyway"
    fi
    ;;

flathub)
    : "${FLATHUB_APP:?}" "${FLATHUB_COMMIT:?}"
    echo "== remote-add"
    flatpak --user remote-add --if-not-exists silo "$REMOTE/silo.flatpakrepo"
    flatpak --user remote-ls silo --columns=application,branch | sed 's/^/  /'

    echo "== install $FLATHUB_APP, as published by Flathub, from silo"
    # --no-deps: the app's GNOME runtime is hundreds of megabytes and says
    # nothing about silo.
    flatpak --user install -y --noninteractive --no-deps silo "$FLATHUB_APP" 2>&1 | tail -4

    commit=$(flatpak --user info --show-commit "$FLATHUB_APP")
    echo "  silo served commit    $commit"
    echo "  flathub's commit was  $FLATHUB_COMMIT"
    [ "$commit" = "$FLATHUB_COMMIT" ] || fail "the commit differs from Flathub's"

    origin=$(flatpak --user info --show-origin "$FLATHUB_APP")
    [ "$origin" = silo ] || fail "installed from '$origin', not silo"

    echo "== the deployment is intact"
    fsck_installation
    ;;

*)
    fail "unknown PHASE '$PHASE'"
    ;;
esac

echo "flatpak verification ($PHASE) passed"
