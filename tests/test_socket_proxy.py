"""The Docker socket proxy must not turn container listing into a file read."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]


def template() -> str:
    return (ROOT / "docker" / "haproxy.cfg.template").read_text(encoding="utf-8")


def rules() -> list[str]:
    return [
        line.strip() for line in template().splitlines() if line.strip().startswith("http-request")
    ]


def containers_allows() -> list[str]:
    return [
        rule
        for rule in rules()
        if rule.startswith("http-request allow")
        and "/containers" in rule
        and "{ env(CONTAINERS) -m bool }" in rule
    ]


def test_archive_and_export_are_denied_before_the_containers_allow() -> None:
    all_rules = rules()
    deny = next(
        i for i, rule in enumerate(all_rules) if "deny" in rule and "archive|export" in rule
    )
    allows = [i for i, rule in enumerate(all_rules) if rule in containers_allows()]
    assert allows, "CONTAINERS=1 would still allow the filesystem endpoints"
    assert deny < min(allows), "CONTAINERS=1 would still allow the filesystem endpoints"


def test_only_citadel_names_and_the_list_endpoint_are_allowed() -> None:
    allows = containers_allows()
    assert len(allows) == 2, f"container scope must be name + list only, got {allows}"
    scoped = next(rule for rule in allows if "citadel-" in rule)
    listing = next(rule for rule in allows if "citadel-" not in rule)
    found = re.search(r"-m reg -i (\S+)", scoped)
    assert found, scoped
    pattern = re.compile(found.group(1), re.IGNORECASE)
    assert pattern.search("/containers/citadel-api-1/json")
    assert pattern.search("/v1.43/containers/citadel-postgres-1/logs")
    assert not pattern.search("/containers/bastion-db/json")
    assert not pattern.search("/containers/" + "a" * 64 + "/json")
    assert re.search(r"/containers/json\$", listing)


def test_the_template_is_mounted_over_the_image_default() -> None:
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    assert "./docker/haproxy.cfg.template:/usr/local/etc/haproxy/haproxy.cfg.template:ro" in compose


# Names that would put a credential in Config.Env, which the proxy exposes.
SENSITIVE_ENV = {
    "POSTGRES_PASSWORD",
    "CITADEL_DB_PASSWORD",
    "KC_DB_PASSWORD",
    "KC_BOOTSTRAP_ADMIN_PASSWORD",
    "POSTGRES_PWD",
    "OPENROUTER_API_KEY",
    "OMNIROUTE_JWT_SECRET",
    "OMNIROUTE_API_KEY_SECRET",
    "OMNIROUTE_STORAGE_ENCRYPTION_KEY",
    "OMNIROUTE_ADMIN_PASSWORD",
    "OMNIROUTE_API_KEY",
}


def test_no_service_puts_a_credential_in_its_environment() -> None:
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    env_names = {
        line.strip().split(":", 1)[0]
        for line in compose.splitlines()
        if line.strip() and line[0].isspace() and ":" in line
    }
    assert not env_names & SENSITIVE_ENV
