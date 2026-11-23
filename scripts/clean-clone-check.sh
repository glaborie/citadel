#!/usr/bin/env bash
# Milestone exit criterion: a clean clone with no hidden files installs and passes all tests.
set -euo pipefail

repo=$(git rev-parse --show-toplevel)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

git clone --quiet "$repo" "$tmp/citadel"
cd "$tmp/citadel"

# A clean clone must carry nothing ignored or untracked; otherwise "it works on my machine".
if [[ -n $(git status --porcelain --ignored) ]]; then
    echo "clean-clone check failed: clone is not clean" >&2
    git status --porcelain --ignored >&2
    exit 1
fi

uv sync --frozen
uv run ruff check .
uv run mypy
uv run pytest
