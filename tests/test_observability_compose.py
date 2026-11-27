"""#190: Prometheus and Grafana are in-stack, digest-pinned and off the edge.

Metrics are not a control (ADR-015), but the dashboard is a new surface: it must
keep bounded labels, require a login and have no edge route.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_PATH = ROOT / "compose.yaml"
SCRAPE_PATH = ROOT / "docker/prometheus/prometheus.yml"
RULES_PATH = ROOT / "docker/prometheus/rules/citadel.yml"
DASHBOARD_PATH = ROOT / "docker/grafana/dashboards/citadel.json"
METRICS_DOC = ROOT / "docs/architecture/metrics.md"


def _service_block(compose: str, name: str) -> str:
    lines = compose.splitlines()
    for index, line in enumerate(lines):
        if line == f"  {name}:":
            block: list[str] = []
            for following in lines[index + 1 :]:
                if following[:2] == "  " and following[:4] != "    " and following.strip():
                    break
                block.append(following)
            return "\n".join(block)
    raise AssertionError(f"service {name!r} not found in compose.yaml")


def test_both_images_are_pinned_by_digest() -> None:
    compose = COMPOSE_PATH.read_text(encoding="utf-8")
    for name, tag in (
        ("prometheus", "prom/prometheus:v3.16.0"),
        ("grafana", "grafana/grafana:13.2.6"),
    ):
        block = _service_block(compose, name)
        assert re.search(
            rf"^    image: {re.escape(tag)}@sha256:[0-9a-f]{{64}}$", block, re.MULTILINE
        ), f"{name} must be pinned by digest, not by tag alone"


def test_grafana_is_off_the_edge_and_not_published() -> None:
    block = _service_block(COMPOSE_PATH.read_text(encoding="utf-8"), "grafana")
    networks = re.search(r"^    networks:\n((?:      - \S+\n)+)", block, re.MULTILINE)
    assert networks is not None, "grafana must declare its networks explicitly"
    assert re.findall(r"- (\S+)", networks.group(1)) == ["internal"], (
        "grafana must not join edge; it has no Keycloak proxy in front of it"
    )
    assert "ports:" not in block, (
        "Docker binds no port on an internal network, so a ports: line here is a "
        "silent no-op; the documented loopback sidecar is the access path"
    )
    assert re.search(r"^      GF_AUTH_ANONYMOUS_ENABLED: \"false\"$", block, re.MULTILINE), (
        "anonymous dashboards are a hole; keep anonymous access off"
    )
    doc = METRICS_DOC.read_text(encoding="utf-8")
    assert "make grafana-ui" in doc and "127.0.0.1:13000" in doc, (
        "the access path must be documented, not guessed"
    )
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "grafana-ui:" in makefile and "tcp-connect:grafana:3000" in makefile, (
        "the documented make target must actually forward to grafana"
    )


def test_prometheus_has_no_published_port_and_scrapes_every_endpoint() -> None:
    compose = COMPOSE_PATH.read_text(encoding="utf-8")
    block = _service_block(compose, "prometheus")
    assert "ports:" not in block, "Prometheus needs no host port; Grafana proxies it"
    assert re.search(r"^      - --storage\.tsdb\.retention\.time=\d+d$", block, re.MULTILINE), (
        "retention must be explicit, not the 15d default by accident"
    )
    assert "metrics_token" in block, "the scrape must use the shared bearer secret"

    scrape = SCRAPE_PATH.read_text(encoding="utf-8")
    targets = set(re.findall(r"^          - (\S+)$", scrape, re.MULTILINE))
    assert targets == {
        "api:8000",
        "worker-orchestrator:9100",
        "worker-docker:9100",
        "worker-github:9100",
        "worker-researcher:9100",
    }, "every process exports its own registry; a missing target is a blind spot"
    assert "credentials_file: /run/secrets/metrics_token" in scrape


def test_the_admin_password_is_a_secret_file_not_an_env_value() -> None:
    compose = COMPOSE_PATH.read_text(encoding="utf-8")
    block = _service_block(compose, "grafana")
    assert "GF_SECURITY_ADMIN_PASSWORD__FILE: /run/secrets/grafana_admin_password" in block
    assert not re.search(r"GF_SECURITY_ADMIN_PASSWORD:", block), (
        "a password in Config.Env is exposed by the Docker API"
    )
    assert "${CITADEL_SECRETS_DIR:-./secrets}/grafana_admin_password" in compose, (
        "the service mounts a secret compose.yaml never declares"
    )
    provision = (ROOT / "scripts/provision-secrets.sh").read_text(encoding="utf-8")
    assert "grafana_admin_password" in provision, "make up would fail with a missing secret file"


def test_the_refusal_alert_is_loaded_and_documented() -> None:
    """A sustained 429 rate must surface without a human watching the dashboard."""
    scrape = SCRAPE_PATH.read_text(encoding="utf-8")
    assert "rule_files:" in scrape
    assert "- /etc/prometheus/rules/*.yml" in scrape, (
        "a rule file Prometheus never loads is documentation, not an alert"
    )
    block = _service_block(COMPOSE_PATH.read_text(encoding="utf-8"), "prometheus")
    assert "./docker/prometheus/rules:/etc/prometheus/rules:ro" in block, (
        "rule_files points at a path the container does not mount"
    )

    rules = RULES_PATH.read_text(encoding="utf-8")
    alert = re.search(r"^      - alert: (\S+)$", rules, re.MULTILINE)
    assert alert is not None, "the rule file defines no alert"
    name = alert.group(1)
    assert name == "CitadelRunRefusalsSustained"
    assert "sum(rate(citadel_runs_refused_total[5m])) * 60 > 5" in rules, (
        "the alert must read the ingress refusal counter, in per-minute units"
    )
    assert re.search(r"^        for: \d+m$", rules, re.MULTILINE), (
        "without for:, a two-scrape blip pages someone"
    )
    assert re.search(r"^          severity: warning$", rules, re.MULTILINE)

    doc = METRICS_DOC.read_text(encoding="utf-8")
    assert f"`{name}`" in doc, "an alert nobody can look up is a dead end"
    assert "| `citadel_runs_refused_total` |" in doc, (
        "the metric the alert reads must stay in the documented table"
    )


def test_the_dashboard_uses_only_documented_bounded_metrics() -> None:
    documented = set(
        re.findall(r"\| `(citadel_[a-z0-9_]+)` \|", METRICS_DOC.read_text(encoding="utf-8"))
    )
    assert documented, "the metrics table must name the series; this test is asleep"

    dashboard = json.loads(DASHBOARD_PATH.read_text(encoding="utf-8"))
    expressions = [
        target["expr"] for panel in dashboard["panels"] for target in panel.get("targets", [])
    ]
    assert expressions, "the dashboard has no queries"

    for expression in expressions:
        for name in re.findall(r"\bcitadel_[a-z0-9_]+", expression):
            family = re.sub(r"_(bucket|count|sum)$", "", name)
            assert family in documented, f"{name} is not in docs/architecture/metrics.md"
        labelled = re.findall(
            r"\b(tenant|tenant_id|user|user_id|run|run_id|prompt|tool|tool_call)\s*(?:=~|!~|!?=)",
            expression,
        )
        assert not labelled, f"{expression} groups by an unbounded label: {labelled}"
