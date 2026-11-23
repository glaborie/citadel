"""Packaging hygiene: the distribution must resolve and import from src/."""

import citadel


def test_package_is_importable_with_semver() -> None:
    parts = citadel.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
