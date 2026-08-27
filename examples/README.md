# Example packages

Three tiny packages, one per format silo supports. They exist for the
end-to-end suite (`ci/e2e.sh`), which publishes them to a real silo and
then installs them with real `dnf`, `apk` and `npm`.

They are built with each ecosystem's own tooling — `rpmbuild`, `abuild`,
`npm pack` — deliberately. Building them with silo's own test fixtures
would test silo's encoder against silo's decoder and prove nothing about
whether a package manager can actually read what silo serves.

Each one installs a single script that prints a line, so the suite can
assert on the *installed* result rather than only on the metadata:

| | package | installs |
|---|---|---|
| rpm | `silo-hello` | `/usr/bin/silo-hello` |
| apk | `silo-hello` | `/usr/bin/silo-hello` |
| npm | `@silo-example/hello` | a `silo-hello` bin |

Keeping them small is the point: the suite runs on every push, and these
are here to exercise the publish/index/serve path, not to be interesting
packages.
