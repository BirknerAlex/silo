# Flatpak example

A runtime and an app that depends on it, small enough to build and install
on every push.

- `platform/` is `org.silo.Platform`, a runtime holding nothing but a static
  `busybox` and the `sh`, `echo` and `cat` applets, which the build adds to
  `usr/bin`.
- `hello/` is `org.silo.Hello`, an app whose only file is a shell script
  that prints a line.

The app runs against the runtime in this directory rather than a
Freedesktop one, so installing and running it needs nothing from Flathub.
`@ARCH@` and `@VERSION@` in the templates are filled in by
`ci/e2e/build-flatpak.sh`.
