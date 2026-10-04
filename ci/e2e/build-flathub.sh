#!/bin/sh
# Fetches a real app from Flathub and lays it out the two ways silo takes it.
#
# Runs in a Fedora container with network access. Outputs under /out:
#
#   repo/           an archive repository holding the app's commit
#   app.flatpak     the same app as a bundle
#   ref             the ref, e.g. app/com.github.tchx84.Flatseal/x86_64/stable
#   commit          the commit checksum Flathub serves for it
#
# The app is installed with `flatpak` and exported from its installation
# rather than pulled with `ostree`: Flathub's CDN answers the user agent
# libostree sends with a 403, and flatpak sends its own.
set -eu

APP=${FLATHUB_APP:-com.github.tchx84.Flatseal}

dnf -q -y install flatpak ostree >/dev/null 2>&1

export HOME=/tmp/flathub-home
mkdir -p "$HOME"
flatpak --user remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
flatpak --user install -y --no-deps flathub "$APP" >/dev/null

installed=$HOME/.local/share/flatpak/repo
ref=app/$APP/$(flatpak --default-arch)/stable
commit=$(ostree --repo="$installed" rev-parse "flathub:$ref")

flatpak build-bundle "$installed" /out/app.flatpak "$APP" stable

ostree --repo=/out/repo init --mode=archive-z2
ostree --repo=/out/repo pull-local "$installed" "$commit" >/dev/null
ostree --repo=/out/repo refs --create="$ref" "$commit"

echo "$ref" > /out/ref
echo "$commit" > /out/commit
chmod -R a+rwX /out
echo "$ref $commit"
