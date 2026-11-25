"""Offline trajectory evaluation.

Grade committed golden trajectories with deterministic hard assertions:

    uv run python -m citadel.evals [path/to/golden.json]
"""

from citadel.evals.graders import Grade, grade
from citadel.evals.schema import Case, DatasetError, load_cases

__all__ = ["Case", "DatasetError", "Grade", "grade", "load_cases"]
