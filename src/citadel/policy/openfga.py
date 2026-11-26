"""OpenFGA client construction and store resolution."""

from __future__ import annotations

from typing import Any

from openfga_sdk.client.models import ClientCheckRequest
from openfga_sdk.sync import OpenFgaClient

from citadel.policy import PolicyError


class OpenFgaChecker:
    def __init__(self, client: OpenFgaClient) -> None:
        self._client = client

    def can_call(self, *, user: str, obj: str) -> bool:
        return self._check(user=user, relation="can_call", obj=obj)

    def can_approve(self, *, agent: str, obj: str) -> bool:
        return self._check(user=agent, relation="can_approve", obj=obj)

    def _check(self, *, user: str, relation: str, obj: str) -> bool:
        try:
            response: Any = self._client.check(
                ClientCheckRequest(user=user, relation=relation, object=obj)
            )
        except Exception as exc:  # noqa: BLE001 - transport errors must not allow
            raise PolicyError(f"openfga check failed: {exc}") from exc
        return bool(response.allowed)


def configuration(api_url: str, store_id: str | None = None) -> Any:
    from openfga_sdk.client.configuration import ClientConfiguration

    return ClientConfiguration(api_url=api_url, store_id=store_id)


def resolve_store_id(api_url: str, store_name: str) -> str:
    """Find the store by name so nothing has to be copied into config."""
    client = OpenFgaClient(configuration(api_url))
    try:
        response = client.list_stores()
    except Exception as exc:  # noqa: BLE001
        raise PolicyError(f"cannot list openfga stores: {exc}") from exc
    for store in response.stores or []:
        if store.name == store_name:
            return str(store.id)
    raise PolicyError(f"openfga store {store_name!r} does not exist; run the policy bootstrap")


def build_checker(api_url: str, store_name: str) -> OpenFgaChecker:
    return OpenFgaChecker(
        OpenFgaClient(configuration(api_url, resolve_store_id(api_url, store_name)))
    )
