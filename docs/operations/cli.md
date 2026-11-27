# `citadel`, the operator CLI

One entry point for the operations in this repository, for people and for agents. The
contract is ADR-026; this page is the map.

```bash
uv run citadel doctor          # or: make doctor
uv run citadel doctor --json   # one document, nothing else
```

## The contract

| promise | why an agent needs it |
| --- | --- |
| `--json` prints **one** document and nothing else | no scraping prose, no stripping banners |
| exit `0` ok · `1` failed · `2` usage · `3` refused · `4` dependency unavailable | "denied" and "broken" are different decisions |
| nothing prompts; destructive commands take `--yes` / `--dry-run` | a prompt blocks an agent forever |
| idempotent by default | retrying is safe |
| every failure carries a hint | the next action travels with the error |

## Commands

| command | what it answers |
| --- | --- |
| `citadel doctor [--json]` | does each dependency answer: docker, the API, MLflow, Keycloak, the Temporal UI |

## What each check means

`doctor` reports one line per dependency with a hint when it is down, and exits `4` if any
of them is. It reads only what is already running: it never starts a container, opens a
connection it would not otherwise need, or asks for a credential.

```
citadel doctor: healthy
  ok    compose      14/14 running
  ok    api          http://127.0.0.1:18000 -> {}
  DOWN  mlflow       http://localhost:5000 -> URLError
        -> make mlflow-ui (the UI is loopback-only)
```

## Coming next

The scripts in `scripts/` become subcommands one at a time, each landing with its test and
its line here; none is deleted before its replacement has been run against a live stack.

| planned | from |
| --- | --- |
| `citadel run --task … [--wait]` | `scripts/start-run.py` |
| `citadel token` | the same script's `--token-only` |
| `citadel samples [--replay] [--html]` | `scripts/read-eval-samples.py` |
| `citadel audit verify --tenant …` | `scripts/audit-verify.py` |
| `citadel mlflow ui --on/--off/--status` | `scripts/mlflow-ui.sh` |
| `citadel mlflow gateway` | `scripts/mlflow-gateway-bootstrap.py` |
