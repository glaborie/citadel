# Issue #269 — reranker memory ceiling

**Decision:** raise the `reranker` service's `mem_limit` from `1024m` to
`1792m`. The OOM was a stale measurement, not a leak: nothing about the image,
the model revision or the request path changed.

## Symptom

`citadel-reranker-1` sat in `Exited (137)` with `OOMKilled=true`; the log ended
at `Warming up model`. `docker compose up -d --wait reranker` exited 1, yet
`make up` still succeeded and every other service reported healthy, because no
service lists the reranker as a health condition. Retrieval therefore lost its
cross-encoder (ADR-016) silently.

## Measured

Same image (`citadel-reranker:0.1.0`), same command and hardening flags; only
`--memory` differs. Peak is the container's cgroup `memory.peak`; warmup is
complete when the TCP probe on 8080 answers.

| memory limit | warmup | peak after a 50-candidate `/rerank` | outcome |
| --- | --- | --- | --- |
| `1024m` (before) | OOM during warmup | — | `exit 137`, `OOMKilled=true` |
| `3g` | 1365 MiB (1431302144 B) | 1366 MiB (1432698880 B) | healthy |
| `1792m` | healthy after 4 s | 1284 MiB (1346486272 B) | healthy, no OOM |

A full `CANDIDATES = 50` batch (`src/citadel/retrieval/types.py`) adds about
1 MiB over warmup, so warmup sets the budget, not request load. Steady
footprint is about 1.29 GiB.

The comment the old value carried ("TEI's warmup spikes past 512m …; the steady
footprint is well under this") was measured at 512m and never re-checked when
the ceiling became 1024m. 1024m sits 341 MiB under the measured warmup peak.

## Verified on the live stack

- `docker update --memory 1792m citadel-reranker-1` then
  `docker compose up -d --wait reranker`: healthy after 5 s, `OOMKilled=false`.
- The 50-candidate `/rerank` from inside `citadel_internal` answered 200 and
  returned scores for every candidate.
- `tests/test_reranker_exposure.py` now fails if `mem_limit` drops below 1536m,
  so the value cannot walk back under the measurement unnoticed.
