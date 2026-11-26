"""The Docker socket proxy must not turn container listing into a file read."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[1]


def template() -> str:
    return (ROOT / "docker" / "haproxy.cfg.template").read_text(encoding="utf-8")


def test_archive_and_export_are_denied_before_the_containers_allow() -> None:
    rules = [
        line.strip() for line in template().splitlines() if line.strip().startswith("http-request")
    ]
    deny = next(i for i, rule in enumerate(rules) if "deny" in rule and "archive|export" in rule)
    blanket = next(
        i
        for i, rule in enumerate(rules)
        if rule.startswith("http-request allow") and rule.endswith("{ env(CONTAINERS) -m bool }")
    )
    assert deny < blanket, "CONTAINERS=1 would still allow the filesystem endpoints"


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
