#!/usr/bin/env python3
"""Renders the Helm chart in every meaningful configuration and asserts the
properties that `helm lint` does not check.

`helm lint` verifies that a chart renders. It does not verify that what it
renders is *correct*, and the three things checked here are exactly the
ones that fail in production rather than in CI:

  1. Every optional block renders. A template gated behind a flag nobody
     sets in CI is a template nobody has ever rendered.
  2. No user-supplied label reaches a `spec.selector`. That field is
     immutable, so a label leaking into it turns the next `helm upgrade`
     into a rejection whose error names nothing useful.
  3. The rendered `config.yaml` is the shape silo's config loader expects.
     Getting this wrong produces a CrashLoopBackOff, which is a slow and
     annoying way to find out about a typo in a template.

Run it directly to check the chart in the working tree:

    ci/check-chart.py
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

import yaml

CHART = Path(__file__).resolve().parent.parent / "charts" / "silo"


def render(*args: str) -> list[dict]:
    """Renders the chart and returns its documents, or raises with helm's
    own error message — which is far more useful than a traceback."""
    result = subprocess.run(
        ["helm", "template", "test", str(CHART), *args],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"helm template failed for {' '.join(args)}:\n{result.stderr}"
        )
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


def refuses(*args: str) -> None:
    result = subprocess.run(
        ["helm", "template", "test", str(CHART), *args],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0, f"chart should have refused: {' '.join(args)}"


def check(name: str, fn) -> None:
    fn()
    print(f"  ok  {name}")


def database_modes() -> None:
    """Three ways to configure a database, and two ways to get it wrong."""
    render("--set", "postgres.enabled=true")
    render("--set", "externalPostgres.url=postgres://silo@db/silo")
    render("--set", "externalPostgres.existingSecret=pgcreds")

    refuses()  # no database configured at all
    refuses(
        "--set", "postgres.enabled=true",
        "--set", "externalPostgres.url=postgres://silo@db/silo",
    )  # both at once


EVERYTHING = [
    "--set", "postgres.enabled=true",
    "--set", "ingress.enabled=true",
    "--set", "serviceMonitor.enabled=true",
    # /metrics requires an admin token by default, and the chart refuses to
    # render a ServiceMonitor that would only ever collect 401s.
    "--set", "serviceMonitor.bearerTokenSecret=prometheus-token",
    "--set", r"serviceAccount.annotations.eks\.amazonaws\.com/role-arn=arn:test",
    "--set", "commonLabels.team=platform",
    "--set", r"commonAnnotations.example\.com/owner=ci",
    "--set", "config.oidc.issuer=https://id.example.com",
    "--set", "config.oidc.clientId=silo",
    "--set", "config.signing.gpg.existingSecret=gpgkey",
    "--set", "config.signing.apk.existingSecret=apkkey",
    "--set", "config.storage.existingSecret=s3creds",
    "--set", "config.auth.tokenPepperExistingSecret=pepper",
    "--set", "podLabels.tier=backend",
    "--set", "extraEnv[0].name=RUST_LOG",
    "--set", "extraEnv[0].value=debug",
]


def every_optional_feature() -> None:
    docs = render(*EVERYTHING)
    kinds = [doc["kind"] for doc in docs]
    for expected in ("Deployment", "Service", "Ingress", "ServiceAccount",
                     "ServiceMonitor", "StatefulSet", "Secret"):
        assert expected in kinds, f"{expected} was not rendered: {kinds}"
    # One Ingress covers both gRPC and HTTP: they share a Service port and
    # silo dispatches between them itself, so the controller only needs to
    # speak real HTTP/2 to the backend, not understand gRPC specifically.
    assert kinds.count("Ingress") == 1, kinds


def common_metadata_reaches_everything() -> None:
    docs = render(*EVERYTHING)
    for doc in docs:
        meta = doc["metadata"]
        name = f"{doc['kind']} {meta['name']}"
        assert (meta.get("labels") or {}).get("team") == "platform", \
            f"{name} is missing commonLabels"
        assert (meta.get("annotations") or {}).get("example.com/owner") == "ci", \
            f"{name} is missing commonAnnotations"

    deployment = next(d for d in docs if d["kind"] == "Deployment")
    pod_meta = deployment["spec"]["template"]["metadata"]
    assert pod_meta["labels"].get("team") == "platform", "pods missed commonLabels"
    assert pod_meta["labels"].get("tier") == "backend", "pods missed podLabels"
    assert pod_meta["annotations"].get("example.com/owner") == "ci", \
        "pods missed commonAnnotations"
    assert "checksum/config" in pod_meta["annotations"], \
        "the config checksum must survive user annotations, or a config-only \
upgrade silently leaves the old config running"


def selectors_stay_immutable() -> None:
    """A user label must never reach a field Kubernetes will not let us
    change later."""
    docs = render(*EVERYTHING)
    for doc in docs:
        selector = (doc.get("spec") or {}).get("selector")
        if not isinstance(selector, dict):
            continue
        labels = selector.get("matchLabels", selector)
        for forbidden in ("team", "tier"):
            assert forbidden not in labels, (
                f"{doc['kind']} {doc['metadata']['name']} put a user label in "
                f"its selector; spec.selector is immutable, so this breaks the "
                f"next helm upgrade"
            )
        # And the selector still has to actually select something.
        assert labels.get("app.kubernetes.io/instance") == "test", labels


def pods_match_their_selectors() -> None:
    """The other half of the above: narrowing a selector without noticing
    would produce a Deployment that never becomes ready."""
    docs = render("--set", "postgres.enabled=true", "--set", "commonLabels.team=platform")
    for doc in docs:
        if doc["kind"] not in ("Deployment", "StatefulSet"):
            continue
        selector = doc["spec"]["selector"]["matchLabels"]
        pod_labels = doc["spec"]["template"]["metadata"]["labels"]
        missing = {k: v for k, v in selector.items() if pod_labels.get(k) != v}
        assert not missing, (
            f"{doc['kind']} {doc['metadata']['name']} selects on {missing}, "
            f"which its pods do not carry"
        )

    services = [d for d in docs if d["kind"] == "Service"]
    workloads = [d for d in docs if d["kind"] in ("Deployment", "StatefulSet")]
    for service in services:
        selector = service["spec"]["selector"]
        assert any(
            all(w["spec"]["template"]["metadata"]["labels"].get(k) == v
                for k, v in selector.items())
            for w in workloads
        ), f"Service {service['metadata']['name']} selects no pods in this chart"


def rendered_config_is_valid() -> None:
    docs = render(
        "--set", "postgres.enabled=true",
        "--set", "config.publicBaseUrl=https://silo.example.com",
        "--set", "config.storage.existingSecret=s3creds",
    )
    secret = next(
        d for d in docs
        if d["kind"] == "Secret" and "config.yaml" in (d.get("stringData") or {})
    )
    cfg = yaml.safe_load(secret["stringData"]["config.yaml"])

    # The database URL is a placeholder on purpose: it is filled from an
    # env var so a password never lands in Helm release history.
    assert cfg["database"]["url"] == "${SILO_DATABASE_URL}", cfg["database"]
    assert cfg["storage"]["access_key_id"] == "${SILO_STORAGE_ACCESS_KEY_ID}", cfg["storage"]
    assert cfg["public_base_url"] == "https://silo.example.com", cfg
    assert cfg["storage"]["bucket"], cfg["storage"]
    assert isinstance(cfg["auth"]["session_ttl_hours"], int), cfg["auth"]

    # Every placeholder the config references must be an env var the
    # Deployment actually sets, or the server refuses to start.
    deployment = next(d for d in docs if d["kind"] == "Deployment")
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    provided = {env["name"] for env in container["env"]}
    referenced = {
        part.split("}")[0].split(":-")[0]
        for part in secret["stringData"]["config.yaml"].split("${")[1:]
    }
    assert referenced <= provided, (
        f"config.yaml references {referenced - provided}, which the Deployment "
        f"does not set"
    )


def a_hand_written_config_needs_nothing_else() -> None:
    """`configOverride` replaces the rendered config wholesale, so it also
    carries its own `database.url`. Demanding postgres.enabled or
    externalPostgres on top of it makes a hand-written config impossible
    to deploy, and it fails as a template error — which is the one failure
    shape none of the other checks here would notice."""
    override = textwrap.dedent(
        """\
        addr: "0.0.0.0:8080"
        database:
          url: "postgres://silo:silo@my-own-pg:5432/silo"
        storage:
          bucket: "silo"
          region: "us-east-1"
          access_key_id: "k"
          secret_access_key: "s"
        """
    )
    with tempfile.NamedTemporaryFile("w", suffix=".yaml") as fh:
        fh.write(override)
        fh.flush()
        docs = render("--set-file", f"configOverride={fh.name}")

    secret = next(
        d for d in docs
        if d["kind"] == "Secret" and "config.yaml" in (d.get("stringData") or {})
    )
    cfg = yaml.safe_load(secret["stringData"]["config.yaml"])
    assert cfg["database"]["url"] == "postgres://silo:silo@my-own-pg:5432/silo", cfg
    # Nothing from the structured defaults may leak back in alongside it.
    assert "auth" not in cfg, f"configOverride was merged, not substituted: {cfg}"

    # An existing Secret is the other way to bring your own config, and it
    # has to be equally self-sufficient.
    render("--set", "existingConfigSecret=my-silo-config")


def versions_stay_in_lockstep() -> None:
    """The chart version, the app version and the workspace's Cargo
    version are one number, bumped together by release-please. Drift here
    means a chart that deploys an image built from different source than
    it claims."""
    chart = yaml.safe_load((CHART / "Chart.yaml").read_text())
    cargo = (CHART.parent.parent / "Cargo.toml").read_text()
    workspace_version = cargo.split("[workspace.package]")[1].split("version = ")[1] \
        .split("\n")[0].strip().strip('"')

    assert str(chart["appVersion"]) == workspace_version, (
        f"chart appVersion {chart['appVersion']} != workspace version "
        f"{workspace_version}"
    )
    assert str(chart["version"]) == workspace_version, (
        f"chart version {chart['version']} != workspace version {workspace_version}"
    )

    # Cargo.lock records a version for each workspace member, and the
    # release build runs `cargo build --locked`, so a lock left behind by a
    # version bump fails the release rather than the PR that caused it.
    # release-please rewrites these six entries; this is what catches it
    # if that ever silently stops matching.
    lock = (CHART.parent.parent / "Cargo.lock").read_text()
    entries = re.findall(
        r'name = "(silo-[a-z]+)"\nversion = "([^"]+)"', lock
    )
    assert entries, "found no silo-* entries in Cargo.lock"
    for name, locked in entries:
        assert locked == workspace_version, (
            f"Cargo.lock has {name} at {locked}, workspace is "
            f"{workspace_version} — run `cargo update --workspace`"
        )


def image_tag_follows_the_chart() -> None:
    docs = render("--set", "postgres.enabled=true")
    deployment = next(d for d in docs if d["kind"] == "Deployment")
    image = deployment["spec"]["template"]["spec"]["containers"][0]["image"]
    chart = yaml.safe_load((CHART / "Chart.yaml").read_text())
    assert image.endswith(f":{chart['appVersion']}"), (
        f"image {image} should default to appVersion {chart['appVersion']}"
    )

    docs = render("--set", "postgres.enabled=true", "--set", "image.tag=pinned")
    deployment = next(d for d in docs if d["kind"] == "Deployment")
    assert deployment["spec"]["template"]["spec"]["containers"][0]["image"].endswith(":pinned")


def a_scrape_cannot_be_configured_to_collect_401s() -> None:
    """/metrics needs an admin token by default, so a ServiceMonitor without
    one scrapes nothing — and a monitoring gap looks identical to a quiet
    system. The chart refuses the combination rather than rendering it."""
    refuses(
        "--set", "postgres.enabled=true",
        "--set", "serviceMonitor.enabled=true",
    )  # requireAuth on, no token
    refuses(
        "--set", "postgres.enabled=true",
        "--set", "serviceMonitor.enabled=true",
        "--set", "serviceMonitor.bearerTokenSecret=tok",
        "--set", "config.metrics.enabled=false",
    )  # nothing to scrape at all

    # Both ways out of it render.
    render(
        "--set", "postgres.enabled=true",
        "--set", "serviceMonitor.enabled=true",
        "--set", "serviceMonitor.bearerTokenSecret=tok",
    )
    render(
        "--set", "postgres.enabled=true",
        "--set", "serviceMonitor.enabled=true",
        "--set", "config.metrics.requireAuth=false",
    )

    # An override replaces the whole config, so `config.metrics` describes
    # nothing the server will do and cannot be used to decide whether the
    # scrape needs a credential. The chart asks for one either way.
    for override in ("configOverride=addr: \"0.0.0.0:8080\"",
                     "existingConfigSecret=my-config"):
        refuses(
            "--set", "postgres.enabled=true",
            "--set", "serviceMonitor.enabled=true",
            "--set", "config.metrics.requireAuth=false",
            "--set-string", override,
        )
        render(
            "--set", "postgres.enabled=true",
            "--set", "serviceMonitor.enabled=true",
            "--set", "serviceMonitor.bearerTokenSecret=tok",
            "--set-string", override,
        )


CHECKS = [
    ("database modes", database_modes),
    ("a scrape cannot be configured to collect 401s", a_scrape_cannot_be_configured_to_collect_401s),
    ("every optional feature renders", every_optional_feature),
    ("common labels and annotations reach every resource", common_metadata_reaches_everything),
    ("no user label reaches an immutable selector", selectors_stay_immutable),
    ("every selector matches the pods it should", pods_match_their_selectors),
    ("rendered config.yaml is what the server expects", rendered_config_is_valid),
    ("a hand-written configOverride needs nothing else", a_hand_written_config_needs_nothing_else),
    ("image tag defaults to appVersion", image_tag_follows_the_chart),
    ("chart, app, cargo and lockfile versions are one number", versions_stay_in_lockstep),
]


def main() -> int:
    print(f"checking {CHART}")
    failures = 0
    for name, fn in CHECKS:
        try:
            check(name, fn)
        except AssertionError as e:
            failures += 1
            print(f"  FAIL  {name}\n        {e}", file=sys.stderr)
    if failures:
        print(f"\n{failures} chart check(s) failed", file=sys.stderr)
        return 1
    print(f"\nall {len(CHECKS)} chart checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
