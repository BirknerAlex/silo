#!/bin/sh
# Builds the example Flatpak runtime and app with the real flatpak tooling.
#
# Runs in a Fedora container. Inputs: /src is examples/flatpak, and
# /out/busybox is a static busybox. Outputs, all under /out:
#
#   repo-v1/           an archive repository with the runtime and app 1.0.0
#   repo-v2/           a second one holding only app 2.0.0, for the update test
#   hello.flatpak      the app 1.0.0 as a bundle
#   hello-v2.flatpak   the app 2.0.0 as a bundle
#   platform.flatpak   the runtime as a bundle
#
# Both a repository and bundles are produced because silo takes both, and
# each is a different upload path.
set -eu

dnf -q -y install flatpak ostree >/dev/null 2>&1

ARCH=$(flatpak --default-arch)
export HOME=/tmp/build-home
mkdir -p "$HOME"

# The runtime: a static busybox is the whole of /usr, which is enough for
# a `#!/usr/bin/sh` script to run inside the sandbox.
rt=/tmp/platform
mkdir -p "$rt/files" "$rt/var" "$rt/usr/bin" "$rt/usr/lib" "$rt/usr/etc"
cp /out/busybox "$rt/usr/bin/busybox"
for applet in sh echo cat; do ln -s busybox "$rt/usr/bin/$applet"; done
sed "s/@ARCH@/$ARCH/g" /src/platform/metadata > "$rt/metadata"
flatpak build-finish "$rt" >/dev/null
flatpak build-export /out/repo-v1 "$rt" 1 >/dev/null

# The app, in two versions that differ in what they print.
build_app() {
    version=$1 repo=$2
    app=/tmp/hello-$version
    mkdir -p "$app/files/bin" "$app/var"
    sed "s/@ARCH@/$ARCH/g" /src/hello/metadata > "$app/metadata"
    sed "s/@VERSION@/$version/g" /src/hello/files/bin/hello > "$app/files/bin/hello"
    chmod 755 "$app/files/bin/hello"
    flatpak build-finish "$app" --command=hello >/dev/null
    flatpak build-export "$repo" "$app" stable >/dev/null
}
build_app 1.0.0 /out/repo-v1
build_app 2.0.0 /out/repo-v2

flatpak build-bundle --runtime /out/repo-v1 /out/platform.flatpak org.silo.Platform 1
flatpak build-bundle /out/repo-v1 /out/hello.flatpak org.silo.Hello stable
flatpak build-bundle /out/repo-v2 /out/hello-v2.flatpak org.silo.Hello stable

# What the repositories hold, for the log.
ostree --repo=/out/repo-v1 refs
ostree --repo=/out/repo-v2 refs
chmod -R a+rwX /out
