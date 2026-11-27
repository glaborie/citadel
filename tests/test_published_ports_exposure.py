"""Issue #219: nothing in the stack publishes a port off loopback.

The host has no firewall of its own in the repository, so a published port is
the whole network policy. `temporal-ui`, `mlflow` and `grafana-ui` already bound
`127.0.0.1`; this guard covers the rest of the file, so the next service cannot
reintroduce `0.0.0.0` by copying an older block.

A remote operator gets one authenticating hop (`tailscale serve`, a Cloudflare
tunnel), never another open port. An intentional exception is listed in
`EXEMPT` with its reason; the list is empty today.
"""

from __future__ import annotations

from pathlib import Path

COMPOSE = Path(__file__).resolve().parents[1] / "compose.yaml"

LOOPBACK = "127.0.0.1"
# "service: entry" -> why this one may answer off loopback. Keep it empty.
EXEMPT: dict[str, str] = {}


def published_ports(compose: str) -> list[tuple[str, str]]:
    """Every `ports:` entry in every service, as (service, entry).

    Text rather than YAML: PyYAML is not a dependency of this repository and one
    more parser is not worth the exposure for a file this shape.
    """
    found: list[tuple[str, str]] = []
    service = ""
    in_ports = False
    ports_indent = 0
    for line in compose.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 2 and stripped.endswith(":"):
            service = stripped[:-1]
            in_ports = False
            continue
        if stripped == "ports:":
            in_ports, ports_indent = True, indent
            continue
        if not in_ports:
            continue
        if indent <= ports_indent:
            in_ports = False
            continue
        if stripped.startswith("- "):
            found.append((service, stripped[2:].strip().strip("\"'")))
    return found


def host_ip(entry: str) -> str:
    """The host address a short-form mapping binds, or "" for every interface.

    Long-form entries are refused rather than guessed: a shape this guard does
    not read could publish `0.0.0.0` while the test passes.
    """
    assert not entry.startswith("{"), f"long-form ports entry: teach the guard {entry!r}"
    parts = entry.split(":")
    return parts[0] if len(parts) >= 3 else ""


def off_loopback(compose: str) -> list[str]:
    return [
        f"{service}: {entry}"
        for service, entry in published_ports(compose)
        if host_ip(entry) != LOOPBACK and f"{service}: {entry}" not in EXEMPT
    ]


def test_no_service_publishes_a_port_off_loopback() -> None:
    open_ports = off_loopback(COMPOSE.read_text(encoding="utf-8"))

    assert not open_ports, (
        "these ports answer on every interface; bind 127.0.0.1 and give a remote "
        f"operator an authenticating hop instead: {open_ports}"
    )


def test_the_four_user_facing_services_bind_loopback() -> None:
    """The services #219 names, so a silent removal of a binding is visible here."""
    entries = dict(published_ports(COMPOSE.read_text(encoding="utf-8")))
    for service in ("api", "approval-ui", "keycloak", "omniroute"):
        assert entries.get(service, "").startswith(f"{LOOPBACK}:"), (
            f"{service} must publish on loopback only, has {entries.get(service)!r}"
        )


OPEN = """\
services:
  keycloak:
    image: example
    ports:
      - "18081:8080"
    environment:
      PORTS: not-a-ports-key
  api:
    image: example
    ports:
      - "127.0.0.1:18000:8000"
"""


def test_the_guard_notices_an_open_port() -> None:
    assert published_ports(OPEN) == [
        ("keycloak", "18081:8080"),
        ("api", "127.0.0.1:18000:8000"),
    ], "the extractor must see only real ports entries"
    assert host_ip("18081:8080") == ""
    assert host_ip("127.0.0.1:18000:8000") == LOOPBACK
    assert off_loopback(OPEN) == ["keycloak: 18081:8080"]
