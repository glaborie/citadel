# syntax=docker/dockerfile:1
# Base images are pinned by digest; see docs/implementation-notes/v0.1-verification.md.
FROM ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff AS uv

# Docker CLI. Only the operator and the sandbox get it (ADR-023).
FROM docker:29-cli@sha256:34507eb5069d8be82c95dd3b6987d4250fd5fee49b82e2509b7d7a7030740d6d AS dockercli

# GitHub CLI, pinned by version and verified against the published checksum.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS ghcli
ARG GH_VERSION=2.105.0
ARG GH_SHA256=79e7ab5db738c48777b696e374f8b428f0647debfb424f44d2f426370407fe2f
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && curl -fsSL -o /tmp/gh.tgz \
      "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_amd64.tar.gz" \
 && echo "${GH_SHA256}  /tmp/gh.tgz" | sha256sum -c - \
 && tar -xzf /tmp/gh.tgz -C /tmp \
 && install -m 0755 "/tmp/gh_${GH_VERSION}_linux_amd64/bin/gh" /usr/local/bin/gh \
 && rm -rf /tmp/gh* /var/lib/apt/lists/*

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

# Shared runtime. Deliberately carries no CLI binaries.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS runtime
RUN useradd --create-home --uid 10001 citadel
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
COPY policy /app/policy
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1
USER citadel

# API, approval console and workers: no docker, no gh.
FROM runtime AS app
EXPOSE 8000
CMD ["uvicorn", "citadel.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]

# The only T1 writer. Holds the docker and gh CLIs; the write token lives here.
FROM runtime AS operator
USER root
# gh shells out to git even when --repo/--base/--head are all explicit. It is
# only used for that lookup: no checkout exists and `git` is not allowlisted.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=ghcli /usr/local/bin/gh /usr/local/bin/gh
USER citadel
EXPOSE 8030
CMD ["uvicorn", "citadel.operator.app:app", "--host", "0.0.0.0", "--port", "8030"]

# The sandbox. Both CLIs, no socket, no egress except the proxy.
FROM runtime AS sandbox
USER root
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=ghcli /usr/local/bin/gh /usr/local/bin/gh
USER citadel
EXPOSE 8020
CMD ["uvicorn", "citadel.tools.runner:app", "--host", "0.0.0.0", "--port", "8020"]
