"""Every script this repository asks a person to run has to be runnable.

`make mlflow-ui` calls `scripts/mlflow-ui.sh` by path, and the file shipped mode 100644 - so
the one command it exists for failed with "Permission denied" on a fresh clone. A shebang
without the exec bit is a bug no other gate here sees: ruff, mypy and pytest all import or read
the file, and none of them execute it.
"""

from __future__ import annotations

import os
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = sorted((ROOT / "scripts").iterdir())


def test_every_shell_script_is_executable() -> None:
    unexecutable = [
        path.name
        for path in SCRIPTS
        if path.suffix == ".sh" and path.read_text(encoding="utf-8").startswith("#!")
        and not os.access(path, os.X_OK)
    ]
    assert not unexecutable, f"git index mode must be 100755: {unexecutable}"


def test_every_python_script_is_executable() -> None:
    unexecutable = [
        path.name
        for path in SCRIPTS
        if path.suffix == ".py" and path.read_text(encoding="utf-8").startswith("#!")
        and not os.access(path, os.X_OK)
    ]
    assert not unexecutable, f"git index mode must be 100755: {unexecutable}"
