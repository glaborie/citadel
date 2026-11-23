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
