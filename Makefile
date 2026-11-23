# Targets that need secrets unwrap secrets/citadel.env through sops, so no
# plaintext copy is written to disk. Accepted trade-off for now: the values
# exist in the compose process environment (see the SOPS decision note).
.PHONY: up

up:
	sops exec-env secrets/citadel.env 'docker compose up -d'
