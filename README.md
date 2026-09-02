<img src="https://raw.githubusercontent.com/BirknerAlex/silo/main/assets/silo.png" width="88" align="left" alt="Silo" />

# Silo

Self-hosted package registry for **RPM**, **Alpine APK**, **npm**,
**pacman** (Arch Linux), and **Debian** (`apt`). Publish over gRPC; `dnf`,
`apk`, `npm`, `pacman` and `apt` consume the results as real repositories
over plain HTTP. Packages live in S3-compatible object storage, everything
else lives in Postgres. A repo/channel can also pull through one or more
upstream registries per format, optionally caching what it fetches, so it
doubles as a local mirror in front of the public registries.

<br clear="left"/>

## Why

GitLab's native RPM registry needs a paid tier. Pulp is heavier than this
needs. Nexus dropped real yum/rpm support from its open-source line. Silo
is a small alternative that keeps no local state, so replicas are
interchangeable and horizontal scaling is just `replicaCount`.

## Quickstart

```sh
docker compose up -d
docker compose logs silo | grep -A 12 'SILO BOOTSTRAP'
```

That brings up Silo, Postgres, and SeaweedFS. On the first start against an
empty database, Silo mints an admin token and an admin user and prints
them **once** — they're stored only as hashes.

```sh
silo login --server http://localhost:8080
silo publish ./my-package-1.0.0-1.x86_64.rpm --repo myrepo --channel stable
silo publish ./hello-1.0-r0.apk             --repo myrepo --channel edge
silo publish ./widget-1.0.0.tgz             --repo myrepo --channel stable
silo publish ./hello-1.0-1-x86_64.pkg.tar.zst --repo myrepo --channel arch
silo publish ./hello_1.0-1_amd64.deb        --repo myrepo --channel stable
silo list --repo myrepo --channel stable
```

The format is inferred from the file extension; pass `--format` to be
explicit.

## Documentation

The [wiki](https://github.com/BirknerAlex/silo/wiki) has the full docs:

- [Introduction](https://github.com/BirknerAlex/silo/wiki/Introduction) — architecture, the format seam, distributed locking
- [Installation](https://github.com/BirknerAlex/silo/wiki/Installation) — installing the `silo` CLI itself: deb/rpm/apk/pacman, Homebrew, or the GitHub release
- [Setup](https://github.com/BirknerAlex/silo/wiki/Setup) — Docker Compose and Helm deployment, the `config.yaml` schema
- [Usage](https://github.com/BirknerAlex/silo/wiki/Usage) — tokens, repo public/private mode, administration
  - [RPM](https://github.com/BirknerAlex/silo/wiki/Usage-RPM), [APK](https://github.com/BirknerAlex/silo/wiki/Usage-APK), [npm](https://github.com/BirknerAlex/silo/wiki/Usage-npm), [pacman](https://github.com/BirknerAlex/silo/wiki/Usage-Pacman), [Deb](https://github.com/BirknerAlex/silo/wiki/Usage-Deb) — per-client config, with and without auth, signing
- [Maintenance](https://github.com/BirknerAlex/silo/wiki/Maintenance) — background jobs and retention-based package pruning
- [Contributing](https://github.com/BirknerAlex/silo/wiki/Contributing) — dev container, local builds, CI checks

## Contributing

Contributions are welcome from anyone — bug fixes, docs, and new package
formats alike. RPM, APK, npm, pacman, and Deb all hang off the same
`PackageFormat` seam, so adding another one is additive, not a rewrite.
See [Contributing](https://github.com/BirknerAlex/silo/wiki/Contributing)
for the dev container, local builds, and the checks CI runs.

## License

[MIT](LICENSE)
