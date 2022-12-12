from typing import Optional, Tuple
from uuid import UUID

from fastapi import status
from fastapi.testclient import TestClient

import pytest
from httpx import AsyncClient, Response


# This is the same as using the @pytest.mark.anyio on all test functions in the module
pytestmark = pytest.mark.anyio


async def test_me(fastapi_client: AsyncClient, create_buyer: Tuple[str, str, str, UUID]) -> None:
    response: Response = await fastapi_client.get("/users/me", headers={"Authorization": f"Bearer {create_buyer[0]}"})
    response_json: dict = response.json()
    print(response_json)

    assert response.status_code == status.HTTP_200_OK
