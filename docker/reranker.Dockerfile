# syntax=docker/dockerfile:1
# Reranker image: TEI with the model baked in at a pinned revision (issue #148).
# The service therefore needs no egress and stays internal-only at runtime.
FROM ghcr.io/huggingface/text-embeddings-inference:cpu-1.8.1@sha256:c112c540b399592e42cd6383d5d80ec9c9d0a9aabfbbf5a7496ee6a15b8d0b32

ARG MODEL_REVISION=233902d25c440f23af6f7d6e94d2946bac0bee0a

RUN set -eux; \
    mkdir -p /models/onnx; \
    cd /models; \
    for f in config.json tokenizer.json tokenizer_config.json onnx/model.onnx; do \
      curl -fsSL "https://huggingface.co/cross-encoder/ms-marco-MiniLM-L-6-v2/resolve/${MODEL_REVISION}/${f}" -o "$f"; \
    done; \
    printf '%s\n' \
      '380e02c93f431831be65d99a4e7e5f67c133985bf2e77d9d4eba46847190bacc  config.json' \
      'd241a60d5e8f04cc1b2b3e9ef7a4921b27bf526d9f6050ab90f9267a1f9e5c66  tokenizer.json' \
      'a5c2e5a7b1a29a0702cd28c08a399b5ecc110c263009d17f7e3b415f25905fd8  tokenizer_config.json' \
      '5d3e70fd0c9ff14b9b5169a51e957b7a9c74897afd0a35ce4bd318150c1d4d4a  onnx/model.onnx' \
      | sha256sum -c -; \
    groupadd --system --gid 10001 tei; \
    useradd --system --uid 10001 --gid 10001 --home-dir /tmp --shell /usr/sbin/nologin tei; \
    chown -R 10001:10001 /models

# Issue #227: the model directory is read at startup and never written, so the
# server runs unprivileged. TEI's default port 80 needs CAP_NET_BIND_SERVICE,
# which a capability-dropped user cannot hold — the service serves 8080
# instead (compose.yaml and CITADEL_RERANKER_URL follow).
ENV HOME=/tmp
USER 10001:10001
