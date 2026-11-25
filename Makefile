# Targets that need secrets unwrap secrets/citadel.env through sops, so no
# plaintext copy is written to disk. Accepted trade-off for now: the values
# exist in the compose process environment (see the SOPS decision note).
.PHONY: up

up:
	sops exec-env secrets/citadel.env 'docker compose up -d'

# OpenFGA CLI pinned by digest; only needed to regenerate the model JSON.
POLICY_CLI = openfga/cli:latest@sha256:7a7f9fb0a27a788a0fa7907eb5fc751c3134ca0776245578308e011606b61091

.PHONY: policy-model policy-bootstrap

# model.fga is the source of truth; model.json is the generated artifact the
# container loads, so the api image never needs the OpenFGA CLI.
policy-model:
	docker run --rm -v "$(PWD)/policy:/w" -w /w $(POLICY_CLI) \
		model transform --file=model.fga --output-format=json > policy/model.json

policy-bootstrap:
	docker compose exec -T api python -m citadel.policy.bootstrap

.PHONY: migrate

# Migrations are applied by the postgres init scripts on a fresh volume; this
# target re-applies them to an existing database. Statements are idempotent.
migrate:
	set -a; . ./.env; set +a; \
	for f in migrations/*.sql; do \
		echo "applying $$f"; \
		docker compose exec -T postgres psql -U "$$POSTGRES_USER" -d "$$POSTGRES_DB" -v ON_ERROR_STOP=1 -f "/$$f" || exit 1; \
	done

.PHONY: eval

# Deterministic grading of the committed trajectory fixtures.
eval:
	uv run python -m citadel.evals

.PHONY: mlflow-bootstrap

# One-time per fresh MLflow volume: create the traces experiment the OTLP
# exporter names via MLFLOW_EXPERIMENT_ID.
mlflow-bootstrap:
	docker compose exec -T api python -m citadel.mlflow_bootstrap

# Red-team pack: manifest lint always, case execution once fixtures exist.
# Uses the project venv explicitly so it does not depend on an activated shell.
.PHONY: redteam
redteam:
	.venv/bin/python -m pytest -m redteam -v

# Red-team report: regenerates docs/evals/red-team-report.md from a real run.
.PHONY: redteam-report
redteam-report:
	CITADEL_REDTEAM_REPORT=1 .venv/bin/python -m pytest -m redteam -q

# Live cases: needs the compose stack up (make up) and its .env readable.
.PHONY: redteam-live
redteam-live:
	CITADEL_LIVE=1 .venv/bin/python -m pytest -m live -v
