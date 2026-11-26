.DEFAULT_GOAL := help

.PHONY: help
help:  ## List the targets and what they do
	@grep -hE '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | sort | awk -F':.*## ' '{printf "  %-18s %s\n", $$1, $$2}'

# Targets that need secrets unwrap secrets/citadel.env through sops, so no
# plaintext copy is written to disk. Accepted trade-off for now: the values
# exist in the compose process environment (see the SOPS decision note).
.PHONY: up

up:  ## Start the stack, unwrapping secrets through sops
	chmod +x scripts/provision-secrets.sh
	sops exec-env secrets/citadel.env 'scripts/provision-secrets.sh && docker compose up -d'

.PHONY: rebuild

# `up` never builds, so a checkout that has new code keeps running the old
# image until something changes the tag. This is the target to use after a pull.
rebuild:  ## Rebuild images from the checkout, then restart the stack
	chmod +x scripts/provision-secrets.sh
	sops exec-env secrets/citadel.env 'scripts/provision-secrets.sh && docker compose up -d --build'

# OpenFGA CLI pinned by digest; only needed to regenerate the model JSON.
POLICY_CLI = openfga/cli:latest@sha256:7a7f9fb0a27a788a0fa7907eb5fc751c3134ca0776245578308e011606b61091

.PHONY: skills-lock
skills-lock:  ## Re-hash the skill packs after editing (bump their version too)
	uv run python -m citadel.skills

.PHONY: policy-model policy-bootstrap

# model.fga is the source of truth; model.json is the generated artifact the
# container loads, so the api image never needs the OpenFGA CLI.
policy-model:  ## Regenerate policy/model.json from model.fga
	docker run --rm -v "$(PWD)/policy:/w" -w /w $(POLICY_CLI) \
		model transform --file=model.fga --output-format=json > policy/model.json

policy-bootstrap:  ## Load the OpenFGA model and seed relations
	docker compose exec -T api python -m citadel.policy.bootstrap

.PHONY: migrate

# Migrations are applied by the postgres init scripts on a fresh volume; this
# target re-applies them to an existing database. Statements are idempotent.
migrate:  ## Re-apply migrations/*.sql to an existing database
	set -a; . ./.env; set +a; \
	for f in migrations/*.sql; do \
		echo "applying $$f"; \
		docker compose exec -T postgres psql -U "$$POSTGRES_USER" -d "$$POSTGRES_DB" -v ON_ERROR_STOP=1 -f "/$$f" || exit 1; \
	done

.PHONY: test

# The offline suite: live tests skip themselves unless CITADEL_LIVE_TESTS is set.
test:  ## Run the test suite (live tests skip themselves)
	uv run pytest

.PHONY: eval

# Deterministic grading of the committed trajectory fixtures.
eval:  ## Grade the committed trajectory fixtures
	uv run python -m citadel.evals

.PHONY: eval-table
eval-table:  ## Print the baseline table as markdown
	uv run python -m citadel.evals --table

.PHONY: eval-gate
eval-gate:  ## Fail when a grader is below its recorded baseline
	uv run python -m citadel.evals --gate

.PHONY: eval-record
eval-record:  ## Record this run as a baseline row (fails rather than rewriting one)
	uv run python -m citadel.evals --record

.PHONY: calibration-sample
calibration-sample:  ## Rebuild the judge-calibration sample from the goldens
	uv run python scripts/build-calibration-sample.py

.PHONY: calibration-sheet
calibration-sheet:  ## Write the blind labelling sheet for the human rater
	uv run python scripts/label-sheet.py

.PHONY: calibration-check
calibration-check:  ## Sample, sheet and labels agree with what is committed
	uv run python scripts/build-calibration-sample.py --check
	uv run python scripts/label-sheet.py --check
	uv run python scripts/label-merge.py --check

.PHONY: calibration-judge
calibration-judge:  ## Judge the sample (needs the stack up; records scores, not a verdict)
	uv run python scripts/judge-sample.py --alias $${JUDGE_ALIAS:-auto/best-reasoning}

.PHONY: calibration-kappa
calibration-kappa:  ## Pair labels with scores and measure kappa per dimension
	uv run python scripts/label-merge.py
	for dim in plan grounding recovery escalation; do \
		uv run python scripts/cohens_kappa.py evals/calibration/labels/$$dim.json; \
	done

.PHONY: mlflow-bootstrap

# One-time per fresh MLflow volume: create the traces experiment the OTLP
# exporter names via MLFLOW_EXPERIMENT_ID.
mlflow-bootstrap:  ## Create the MLflow traces experiment on a fresh volume
	docker compose exec -T api python -m citadel.mlflow_bootstrap

# Red-team pack: manifest lint always, case execution once fixtures exist.
# Uses the project venv explicitly so it does not depend on an activated shell.
.PHONY: redteam
redteam:  ## Run the red-team pack: manifest plus executed cases
	.venv/bin/python -m pytest -m redteam -v

# Red-team report: regenerates docs/evals/red-team-report.md from a real run.
.PHONY: redteam-report
redteam-report:  ## Regenerate docs/evals/red-team-report.md
	CITADEL_REDTEAM_REPORT=1 .venv/bin/python -m pytest -m redteam -q

# Live cases: needs the compose stack up (make up) and its .env readable.
.PHONY: redteam-live
redteam-live:  ## Run the live red-team cases (stack must be up)
	CITADEL_LIVE=1 .venv/bin/python -m pytest -m live -v

# One real completion through the gateway. Runs inside the compose network,
# where OmniRoute and Presidio are both reachable, and prints tokens and cost.
.PHONY: model-smoke
model-smoke:
	cd $$HOME/projects/citadel && docker compose run --rm --no-deps \
		-v $(CURDIR):/repo:ro -e PYTHONPATH=/repo/src \
		api python /repo/scripts/model_smoke.py

# The report as evidence: offline cases plus the live ones. Requires the
# stack; live cases skip loudly when it is not reachable.
.PHONY: redteam-report-live
redteam-report-live:
	CITADEL_LIVE=1 CITADEL_REDTEAM_REPORT=1 .venv/bin/python -m pytest -m "redteam or live" -q

# One worktree per branch; this retires the ones whose work already landed. It
# removes a tree only when its HEAD is an ancestor of origin/master and it has
# no uncommitted changes, and deletes the branch only once its commits are
# confirmed in origin/master. A tree touched in the last 15 minutes is skipped,
# because another session may be in it. ARGS=--dry-run to see the decisions first.
.PHONY: worktree-prune

worktree-prune:  ## Remove worktrees whose branch is already merged
	scripts/worktree-prune.sh $(ARGS)

# The ledger checks the red-team pack depends on, run against a live database:
# the hash chain, and the tool calls that left no event behind. TENANT=lab-b to
# check another one. Non-zero exit on a broken chain or a gap.
.PHONY: audit-verify

audit-verify:  ## Verify a tenant's audit chain and report unaudited tool calls
	uv run python scripts/audit-verify.py $(or $(TENANT),lab-a)
# Retention for the offloaded tool output. Only the body expires: `tool.call` keeps
# the digest, the byte count and the stream, so the record still says bytes existed.
# Needs a DSN that can see every tenant - the app role cannot, by design.
.PHONY: outputs-purge

outputs-purge:  ## Delete stored tool output past its retention period (DAYS=90)
	uv run python scripts/tool-outputs-purge.py $(DAYS)

# Ingestion is a one-shot container: it needs the knowledge mount and the
# GitHub read token, and neither belongs to a long-running service.
.PHONY: ingest

ingest:  ## Ingest knowledge/ and CITADEL_INGEST_REPOS into a tenant's collection (TENANT=lab-a)
	docker compose --profile tools run --rm ingest --tenant $(or $(TENANT),lab-a) $(ARGS)
