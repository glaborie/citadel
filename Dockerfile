# syntax=docker/dockerfile:1
# Base images are pinned by digest; see docs/implementation-notes/v0.1-verification.md.
FROM ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff AS uv

# Docker CLI for the sandbox only (ADR-023). The worker image never gets it.
FROM docker:29-cli@sha256:34507eb5069d8be82c95dd3b6987d4250fd5fee49b82e2509b7d7a7030740d6d AS dockercli

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
RUN useradd --create-home --uid 10001 citadel
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY policy /app/policy
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1
USER citadel
EXPOSE 8000
CMD ["uvicorn", "citadel.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
