"""The secret store stays ciphertext, and the example stays synthetic.

`docs/security/secrets.md` calls `secrets/citadel.env` the one tracked file in
that directory. This test is the guard: a plaintext value, a stray materialised
file or a real value in `.env.example` fails here before it reaches a commit.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).parents[1]
SOPS_FILE = ROOT / "secrets" / "citadel.env"
EXAMPLE = ROOT / ".env.example"
PLACEHOLDER = "REPLACE_WITH_LOCAL_DEV_VALUE"

# Only credentials. Users, realms, URLs and model aliases are configuration and
# may carry a readable default.
CREDENTIALS = {
    "KEYCLOAK_ADMIN_PASSWORD",
    "POSTGRES_PASSWORD",
    "OMNIROUTE_API_KEY",
    "OMNIROUTE_JWT_SECRET",
    "OMNIROUTE_API_KEY_SECRET",
    "OMNIROUTE_STORAGE_ENCRYPTION_KEY",
    "OMNIROUTE_ADMIN_PASSWORD",
    "CITADEL_DB_PASSWORD",
    "CITADEL_RUN_TOKEN_PRIVATE_KEY",
    "CITADEL_RUN_TOKEN_PUBLIC_KEY",
    "CITADEL_DEV_PASSWORD",
    "CITADEL_CONSOLE_SESSION_KEY",
    "GH_READ_TOKEN",
    "GH_WRITE_TOKEN",
}


def assignments(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        name, sep, value = line.partition("=")
        if sep:
            found[name] = value
    return found


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout


def test_the_secret_file_holds_only_sops_ciphertext() -> None:
    values = assignments(SOPS_FILE.read_text(encoding="utf-8"))
    plaintext = sorted(
        name
        for name, value in values.items()
        if not name.startswith("sops_") and not value.startswith("ENC[")
    )
    assert not plaintext, f"plaintext values in {SOPS_FILE}: {plaintext}"
    assert values.get("sops_version"), "the file is not a SOPS document"
    encrypted = [name for name, value in values.items() if value.startswith("ENC[")]
    assert len(encrypted) >= 20, "the secret set shrank unexpectedly"


def test_the_example_has_a_placeholder_for_every_credential() -> None:
    values = assignments(EXAMPLE.read_text(encoding="utf-8"))
    wrong = {name: values.get(name) for name in CREDENTIALS if values.get(name) != PLACEHOLDER}
    assert not wrong, f".env.example must keep placeholders, found: {wrong}"


def test_only_the_ciphertext_is_tracked_under_secrets() -> None:
    tracked = git("ls-files", "secrets/").splitlines()
    assert tracked == ["secrets/citadel.env"], tracked
    assert ".env" not in git("ls-files").splitlines()
