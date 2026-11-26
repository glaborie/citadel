# Issue #148 — reranker model provisioning

**Decision:** option 2 from the issue. The model is baked into a derived image
(`docker/reranker.Dockerfile`) at a pinned revision. The `reranker` service no
longer fetches at startup, no longer has a model volume and keeps its
internal-only network.

Pinned revision: `cross-encoder/ms-marco-MiniLM-L-6-v2` at
`233902d25c440f23af6f7d6e94d2946bac0bee0a`. The four files TEI needs for the
ONNX backend are checked by sha256 at build time (`config.json`,
`tokenizer.json`, `tokenizer_config.json`, `onnx/model.onnx`); a changed byte
fails the build rather than being served.

## Measured

- `docker compose build reranker` completed in 6.3 s on the warm base image and
  all four checksums passed.
- `docker run --network none citadel-reranker:0.1.0 --model-id /models` served
  `/rerank` in 4 s with no DNS or network:
  `{"index":0,"score":0.9997321},{"index":1,"score":0.000011780722}` for
  `restart nginx` against `restart the nginx unit` / `make coffee`.
- On the live stack, `docker compose up -d --no-deps --force-recreate reranker`
  recreated `citadel-reranker-1` from `citadel-reranker:0.1.0` (the old
  bind-to-volume container was replaced); it reported healthy after 8 s and the
  API container reached it over Compose DNS with the same scores.
- `docker compose config --quiet` exits 0.
- `uv run pytest` passes; `tests/test_reranker_exposure.py` guards that the
  service publishes no port, attaches only to `internal`, has no model volume,
  and that the Dockerfile pins a 40-character revision.

## Cost

`make up` builds this image when it is absent (the first run on a fresh host).
The model adds ~91 MB to the image. Rebuilding after a revision bump needs
`make rebuild` or `docker compose build reranker`.
