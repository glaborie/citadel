VERSION ?= 1
.DEFAULT_GOAL := help

.PHONY: help
help:  ## List the targets and what they do
	@grep -hE '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | sort | awk -F':.*## ' '{printf "  %-18s %s\n", $$1, $$2}'

# Targets that need secrets unwrap secrets/citadel.env through sops, so no
# plaintext copy is written to disk. Accepted trade-off for now: the values
# exist in the compose process environment (see docs/security/secrets.md).
.PHONY: up

up:  ## Start the stack, unwrapping secrets through sops
	chmod +x scripts/provision-secrets.sh scripts/reconcile-mounts.py
	sops exec-env secrets/citadel.env 'scripts/provision-secrets.sh \
		&& scripts/reconcile-mounts.py \
		&& docker compose up -d'

.PHONY: rebuild

# `up` never builds, so a checkout that has new code keeps running the old
# image until something changes the tag. This is the target to use after a pull.
# `--build` alone trusts the layer cache: it reported "Built" while the containers kept
# running the previous code, which reads exactly like a fix that did not work. `up` has no
# `--no-cache` of its own, so the build is its own step.
rebuild:  ## Rebuild images from scratch (no cache), then restart the stack
	chmod +x scripts/provision-secrets.sh scripts/reconcile-mounts.py
	sops exec-env secrets/citadel.env 'scripts/provision-secrets.sh \
		&& scripts/reconcile-mounts.py \
		&& docker compose build --no-cache \
		&& docker compose up -d'

# The smell gate's version lives with its hashes, so `make check` and the smell-check
# job cannot drift apart (#41). Blank if the requirements file is malformed, which is a
# loud failure the first time the gate runs.
SMELCHECK_VERSION := $(shell sed -n 's/^smellcheck==\([0-9][0-9.]*\).*/\1/p' \
	.github/requirements-smellcheck.txt)

# OpenFGA CLI pinned by digest; only needed to regenerate the model JSON.
POLICY_CLI = openfga/cli:latest@sha256:7a7f9fb0a27a788a0fa7907eb5fc751c3134ca0776245578308e011606b61091

.PHONY: skills-lock
skills-lock:  ## Re-hash the skill packs after editing (bump their version too)
	uv run python -m citadel.skills

.PHONY: policy-model policy-bootstrap policy-drift

# model.fga is the source of truth; model.json is the generated artifact the
# container loads, so the api image never needs the OpenFGA CLI.
policy-model:  ## Regenerate policy/model.json from model.fga
	docker run --rm -v "$(PWD)/policy:/w" -w /w $(POLICY_CLI) \
		model transform --file=model.fga --output-format=json > policy/model.json

# A one-shot service, not `exec api`: the Keycloak admin password is mounted for
# this run only, and the always-on api never carries it (#273).
policy-bootstrap:  ## Load the OpenFGA model and seed relations
	docker compose --profile tools run --rm policy-bootstrap

# Read-only, unlike the bootstrap: it compares the store with `policy/model.fga`,
# the catalog and the versioned tuple set, so it is safe on a live stack and in
# cron. Exit 1 is drift, 2 is "could not compare" (#277).
policy-drift:  ## Report drift between the OpenFGA store and the versioned policy
	docker compose --profile tools run --rm policy-bootstrap \
		python -m citadel.policy.drift

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

.PHONY: check

# What CI runs, in the same order, plus the smell gate at info severity. The
# smell-check job only fails on warnings, so a warning-only local run lets new
# info-level findings merge; this target is the stricter local gate.
check:  ## Run the CI gates locally before a push
	uv run ruff check .
	uv run mypy
	uv run pytest
	uvx smellcheck==$(SMELCHECK_VERSION) src/ --min-severity info \
		--baseline .smellcheck-baseline.json --fail-on info

.PHONY: eval

# Deterministic grading of the committed trajectory fixtures.
doctor:  ## Report whether each dependency answers (same as `citadel doctor`)
	@uv run --quiet citadel doctor

run:  ## Start a run: make run TASK="call inspect_containers, then name one container"
	@set -a; . ./.env; set +a; scripts/start-run.py --task "$(TASK)" --wait

token:  ## Print a bearer token for the API (curl / HTTP clients)
	@set -a; . ./.env; set +a; scripts/start-run.py --token-only

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
# Read the sampled runs back out of the MLflow eval dataset. The dataset id is not
# discoverable by name - MLflow answers {} to every dataset search - so the script reads
# the id the sampler recorded on the eval.sample audit events, then the rows.
.PHONY: eval-samples
mlflow-gateway:  ## Give the AI Gateway one OmniRoute endpoint and point the assistant at it
	@docker cp scripts/mlflow-gateway-bootstrap.py citadel-mlflow-1:/tmp/gateway.py
	@docker exec citadel-mlflow-1 python3 /tmp/gateway.py

mlflow-ui:  ## Open the MLflow UI on loopback:5000 (inspection only, loopback bound)
	scripts/mlflow-ui.sh --on

mlflow-ui-off:  ## Close the MLflow UI sidecar
	scripts/mlflow-ui.sh --off

eval-samples:  ## Read the sampled runs back from the MLflow eval dataset
	mkdir -p $(CURDIR)/.eval-out
	cd $$HOME/projects/citadel && docker compose run --rm --no-deps \
		--user $(shell id -u):$(shell id -g) \
		-v $(CURDIR):/repo:ro -v $(CURDIR)/.eval-out:/out \
		-e PYTHONPATH=/repo/src \
		api python /repo/scripts/read-eval-samples.py $(ARGS)

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
	uv run python scripts/judge-sample.py --alias $${JUDGE_ALIAS:-auto/best-reasoning} --version $(VERSION)

.PHONY: calibration-kappa
calibration-kappa:  ## Pair labels with scores and measure kappa per dimension
	uv run python scripts/label-merge.py --version $(VERSION)
	for dim in plan grounding recovery escalation; do \
		uv run python scripts/cohens_kappa.py evals/calibration/labels/$$dim.json; \
	done

.PHONY: grafana-ui grafana-ui-off

# Grafana is internal-only, and Docker binds no port on an internal network. This
# is the loopback sidecar documented in docs/architecture/metrics.md, the same
# pattern as scripts/mlflow-ui.sh: the UI never joins edge.
grafana-ui:  ## Open Grafana on loopback:13000 through a socat sidecar
	@docker rm -f citadel-grafana-ui >/dev/null 2>&1 || true
	docker run -d --name citadel-grafana-ui --restart unless-stopped \
		--pids-limit 64 --security-opt no-new-privileges \
		--network bridge -p 127.0.0.1:13000:13000 alpine/socat \
		tcp-listen:13000,fork,reuseaddr tcp-connect:grafana:3000
	docker network connect citadel_internal citadel-grafana-ui
	@echo "open http://localhost:13000 (admin / secrets/grafana_admin_password)"

grafana-ui-off:  ## Close the Grafana loopback sidecar
	@docker rm -f citadel-grafana-ui >/dev/null && echo "closed" || echo "already down"

.PHONY: mlflow-bootstrap

# `make up` runs this as a one-shot before any worker starts; the target stays for an
# existing stack whose experiment was removed by hand. Idempotent either way.
mlflow-bootstrap:  ## Create the MLflow traces experiment if it is absent
	docker compose run --rm --no-deps mlflow-bootstrap

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

.PHONY: knowledge-sync
knowledge-sync:  ## Regenerate the host inventory, ingest, and prune what the corpus no longer has
	@set -a; . ./.env; set +a; scripts/knowledge-sync.py --tenant $(or $(TENANT),lab-a) $(ARGS)

ingest:  ## Ingest knowledge/ and CITADEL_INGEST_REPOS into a tenant's collection (TENANT=lab-a)
	docker compose --profile tools run --rm ingest --tenant $(or $(TENANT),lab-a) $(ARGS)
