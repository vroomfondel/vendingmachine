from typing import Optional, Tuple
from uuid import UUID

from fastapi import status
from fastapi.testclient import TestClient

import pytest
from httpx import AsyncClient, Response


# This is the same as using the @pytest.mark.anyio on all test functions in the module
pytestmark = pytest.mark.anyio


async def test_deposit_wrong_method(fastapi_client: AsyncClient, create_buyer: Tuple[str, str, str, UUID]) -> None:
    response: Response = await fastapi_client.get("/deposit/5", headers={"Authorization": f"Bearer {create_buyer[0]}"})
    response_json: dict = response.json()
    print(response_json)

    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED


async def test_deposit_wrong_coin(fastapi_client: AsyncClient, create_buyer: Tuple[str, str, str, UUID]) -> None:
    response: Response = await fastapi_client.patch(
        "/deposit/6", headers={"Authorization": f"Bearer {create_buyer[0]}"}
    )

    response_json: dict = response.json()
    print(response_json)
    msg = response_json["detail"][0]["msg"]
    assert msg.startswith("value is not a valid enumeration member")
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


async def test_deposit_success(fastapi_client: AsyncClient, create_buyer: Tuple[str, str, str, UUID]) -> None:
    response: Response = await fastapi_client.patch(
        "/deposit/5", headers={"Authorization": f"Bearer {create_buyer[0]}"}
    )
    response_json: dict = response.json()
    print(response_json)

    assert response.status_code == status.HTTP_200_OK
    assert response_json["deposit"] == 5  # multiple-calls would fail here!!!
    assert response_json["username"] == create_buyer[2]


async def test_deposit_reset(fastapi_client: AsyncClient, create_buyer: Tuple[str, str, str, UUID]) -> None:
    response: Response = await fastapi_client.patch("/reset", headers={"Authorization": f"Bearer {create_buyer[0]}"})
    response_json: dict = response.json()
    print(response_json)

    assert response.status_code == status.HTTP_200_OK
    assert response_json["deposit"] == 0
    assert response_json["username"] == create_buyer[2]
