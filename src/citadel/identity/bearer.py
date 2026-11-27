"""Bearer run-token authentication for the tool services.

The sandbox runner and the operator take identity from a signed run token and
from nothing else: no header-free route, no tenant from the body. Both services
used to differ here and the operator had no credential at all (issue #237), so
the dependency is shared - one refusal order, one message per reason.
"""

from __future__ import annotations

import os
from typing import Annotated

from fastapi import Header, HTTPException, status

from citadel.identity import IdentityError
from citadel.identity.run_token import RunContext, public_key_from_env, verify_run_token


def require_run_token(
    authorization: Annotated[str | None, Header()] = None,
) -> RunContext:
    """The caller's identity, taken from a signed run token and nowhere else."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="run token required"
        )
    try:
        key = public_key_from_env(os.environ["CITADEL_RUN_TOKEN_PUBLIC_KEY"])
    except (KeyError, IdentityError, ValueError) as exc:
        # A service with no usable verification key is a broken deployment, not
        # a bad caller: refuse rather than act unauthenticated.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="cannot verify run tokens"
        ) from exc
    try:
        return verify_run_token(authorization.removeprefix("Bearer ").strip(), key)
    except IdentityError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="invalid run token"
        ) from exc
