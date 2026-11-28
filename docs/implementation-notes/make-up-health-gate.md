# `make up` waits for health (#280)

`make up` ended with `docker compose up -d`, which returns 0 once the containers
exist. A service whose healthcheck never passes left the stack half-up behind a
green target; the recorded instance is the reranker OOM in #269, where
`docker compose up -d --wait reranker` exited 1 but `make up` had already
reported success. The symptom then showed up on the first run, as a tool or a
model call with no healthy dependency behind it.

## Change

`up` and `rebuild` now finish with:

```
docker compose up -d --wait --wait-timeout 300
```

`--wait` blocks until every service is running and every healthcheck has passed,
and exits non-zero when one cannot. `--wait-timeout 300` bounds it: a service
that hangs in `starting` fails the target instead of hanging it. 300 s is above
every recorded cold start (Keycloak, MLflow and the reranker's model warmup are
the slow ones), and the timeout only matters on a stack that is already broken.

`tests/test_makefile_up.py` guards both recipes and fails if any target starts
the stack with `up -d` and no `--wait`, so a future target cannot reopen the same
silent half-up.

## Measured, 2026-11-28

Healthy stack, 24 service definitions (22 long-running, 2 one-shots):

```
$ sops exec-env secrets/citadel.env 'docker compose up -d --wait --wait-timeout 180'
… citadel-api-1 Healthy … citadel-reranker-1 Healthy … citadel-openfga-migrate-1 Exited
healthy_exit=0
```

Negative control, a throwaway Compose project whose only service has
`healthcheck: test: ["CMD", "false"]`:

```
$ docker compose -f /tmp/waitcheck/compose.yaml up -d --wait --wait-timeout 20
container waitcheck-never-healthy-1 is unhealthy
unhealthy_exit=1
```

So the failure is loud, names the container, and carries a non-zero status into
`make`: the shell recipe runs under `sops exec-env …` in single quotes, and the
non-zero exit of the last command in that string propagates to the target.

## What this does not catch

- **A service with no healthcheck.** Compose has nothing to wait for, so a
  container that starts and then dies is still "up" as far as `--wait` is
  concerned. The contract is the healthcheck: every long-running service in
  `compose.yaml` has one, and `tests/test_compose_hardening.py` is where that
  stays true.
- **A service that is healthy but useless** — a reranker answering 200 with an
  empty model, for example. Health is a liveness signal, not a correctness one;
  the live tests and the eval gate cover the second.
