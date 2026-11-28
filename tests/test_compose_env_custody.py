"""#221: no credential sits in a service's `environment:` block.

`docker compose config` renders every environment entry into Config.Env, and
Config.Env is what the Docker API — and through it the socket proxy — exposes
to any caller that can inspect a container. The custody model in
docs/security/secrets.md is therefore file-only: a credential reaches a
container as a Docker secret, and the service either points at it with a
`*_FILE` variable or its entrypoint exports it from the mounted file at
runtime, because exports are not part of Config.Env. This is the guard for
that rule, starting with the Keycloak bootstrap admin password: the console it
unlocks is the root of trust for the whole stack, and the placeholder that
once travelled through `.env` while 18081 answered on `0.0.0.0`
(docs/implementation-notes/v0.1-verification.md, "Credential exposure found
and fixed") must never come back as an environment entry.
"""

from __future__ import annotations

import re
from pathlib import Path

COMPOSE = Path(__file__).resolve().parents[1] / "compose.yaml"

# An environment name matching any of these is a credential in the custody
# model's sense. The two escapes below are the sanctioned shapes.
CREDENTIALISH = re.compile(r"PASSWORD|PRIVATE_KEY|SECRET|TOKEN|API_KEY")
# A pointer at a mounted file, not the value: `CITADEL_DB_PASSWORD_FILE`.
FILE_POINTER = "_FILE"
# Verify-only material published on purpose: `CITADEL_RUN_TOKEN_PUBLIC_KEY`
# rides the worker, operator and tool-runner environments by design.
PUBLIC = "PUBLIC_KEY"
# "service: name" -> why this one is not a credential. Keep it minimal.
EXEMPT: dict[str, str] = {
    # The socket proxy's upstream API-category switch, not a value:
    # SECRETS=0 is what denies the /secrets endpoint, like POST=0 denies POST.
    "docker-socket-proxy: SECRETS": "an API-category switch, not a credential",
}


def service_texts(compose: str) -> dict[str, str]:
    """Every service block with the `<<: *alias` anchors it references inlined.

    Text rather than YAML: PyYAML is not a dependency of this repository and one
    more parser is not worth the exposure for a file this shape.
    """
    anchors: dict[str, list[str]] = {}
    services: dict[str, list[str]] = {}
    mode: str | None = None
    current: list[str] | None = None

    for line in compose.splitlines():
        if not line.strip():
            continue
        if not line.startswith(" "):
            anchor = re.match(r"^(x-[a-z0-9_-]+): &([a-z0-9_-]+)", line)
            if anchor:
                mode = "anchors"
                current = anchors.setdefault(anchor.group(2), [])
            elif line.startswith("services:"):
                mode = "services"
                current = None
            else:
                mode = None
                current = None
            continue
        if mode == "anchors" and current is not None:
            current.append(line)
        elif mode == "services":
            service = re.match(r"^  ([a-z0-9_-]+):", line)
            if service:
                current = services.setdefault(service.group(1), [])
            elif current is not None:
                current.append(line)

    return {
        name: "\n".join(
            [
                line
                for alias in re.findall(
                    r"^\s*<<: \*([a-z0-9_-]+)$", "\n".join(block), re.MULTILINE
                )
                for line in anchors[alias]
            ]
            + block
        )
        for name, block in services.items()
    }


def environment_entries(text: str) -> dict[str, str]:
    """A service's `environment:` entries as name -> raw entry.

    Shapes this parser cannot read are refused rather than guessed, so an
    unreadable entry cannot carry a credential past the guard.
    """
    entries: dict[str, str] = {}
    in_env = False
    env_indent = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if stripped == "environment:":
            in_env, env_indent = True, indent
            continue
        if not in_env:
            continue
        if indent <= env_indent:
            in_env = False
            continue
        mapping = re.match(r"([A-Za-z_][A-Za-z0-9_]*):", stripped)
        listed = re.match(r"- ([A-Za-z_][A-Za-z0-9_]*)=", stripped)
        match = mapping if mapping is not None else listed
        assert match is not None, (
            f"unreadable environment entry; teach this guard: {stripped!r}"
        )
        entries[match.group(1)] = stripped
    return entries


def environments(compose: str) -> dict[str, dict[str, str]]:
    return {
        name: environment_entries(text)
        for name, text in service_texts(compose).items()
    }


def credential_entries(found: dict[str, dict[str, str]]) -> list[str]:
    return [
        f"{service}: {name}"
        for service, entries in found.items()
        for name in entries
        if CREDENTIALISH.search(name)
        and not name.endswith(FILE_POINTER)
        and PUBLIC not in name
        and f"{service}: {name}" not in EXEMPT
    ]


def test_no_service_environment_holds_a_credential() -> None:
    found = environments(COMPOSE.read_text(encoding="utf-8"))
    assert len(found) > 20, "the parser is asleep; it found almost nothing"

    offenders = credential_entries(found)
    assert not offenders, (
        "these environment entries are credentials, and Config.Env is exposed "
        "through the Docker API; mount a Docker secret and read it through a "
        f"*_FILE variable or the entrypoint instead: {offenders}"
    )


def test_keycloak_environment_holds_the_bootstrap_user_but_not_its_password() -> None:
    """The #221 acceptance, named: the credential surface stays out of Config.Env."""
    keycloak = environments(COMPOSE.read_text(encoding="utf-8"))["keycloak"]

    assert "KC_BOOTSTRAP_ADMIN_USERNAME" in keycloak, (
        "the bootstrap user is configuration and stays readable in the environment"
    )
    passwords = [name for name in keycloak if "PASSWORD" in name]
    assert not passwords, (
        f"the Keycloak admin password must not sit in the environment: {passwords}"
    )


def test_the_bootstrap_password_arrives_as_a_docker_secret_instead() -> None:
    """The allow side: the secret is mounted and the entrypoint reads the file."""
    keycloak = service_texts(COMPOSE.read_text(encoding="utf-8"))["keycloak"]

    assert "keycloak_admin_password:" in COMPOSE.read_text(encoding="utf-8"), (
        "compose must define the keycloak_admin_password secret"
    )
    assert "- keycloak_admin_password" in keycloak, (
        "the keycloak service must mount the keycloak_admin_password secret"
    )
    assert "/run/secrets/keycloak_admin_password" in keycloak, (
        "the entrypoint must export the bootstrap password from the mounted file"
    )


FIXTURE = """\
x-app: &app
  security_opt:
    - no-new-privileges:true
services:
  keycloak:
    image: example
    environment:
      KC_BOOTSTRAP_ADMIN_USERNAME: admin
      KC_BOOTSTRAP_ADMIN_PASSWORD: REPLACE_WITH_LOCAL_DEV_VALUE
      KC_DB_PASSWORD_FILE: /run/secrets/postgres_password
  operator:
    <<: *app
    environment:
      CITADEL_RUN_TOKEN_PUBLIC_KEY: mcow
      GH_TOKEN_FILE: /run/secrets/gh_write_token
"""


def test_the_guard_notices_a_credential_and_its_sanctioned_shapes() -> None:
    found = environments(FIXTURE)
    assert found["keycloak"] == {
        "KC_BOOTSTRAP_ADMIN_USERNAME": "KC_BOOTSTRAP_ADMIN_USERNAME: admin",
        "KC_BOOTSTRAP_ADMIN_PASSWORD": (
            "KC_BOOTSTRAP_ADMIN_PASSWORD: REPLACE_WITH_LOCAL_DEV_VALUE"
        ),
        "KC_DB_PASSWORD_FILE": "KC_DB_PASSWORD_FILE: /run/secrets/postgres_password",
    }, "the extractor must see the whole environment block"

    assert credential_entries(found) == ["keycloak: KC_BOOTSTRAP_ADMIN_PASSWORD"], (
        "a bare password is flagged; *_FILE pointers and public keys are exempt"
    )
