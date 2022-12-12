from typing import Optional, cast

from fastapi import FastAPI, status
from fastapi.testclient import TestClient

import pytest
from httpx import AsyncClient, Response


# This is the same as using the @pytest.mark.anyio on all test functions in the module
pytestmark = pytest.mark.anyio(scope="session")


async def test_health_json(fastapi_client: AsyncClient) -> None:
    response: Response = await fastapi_client.get("/healthz", headers={"Accept": "application/json"})

    assert response.status_code == status.HTTP_200_OK
    assert response.headers.get("Content-Type") == "application/json"
    response_json: dict = response.json()
    assert response_json["status"] == "alive"


async def test_health_plaintext(fastapi_client: AsyncClient) -> None:
    response: Response = await fastapi_client.get("/healthz", headers={"Accept": "text/plain"})

    assert response.status_code == status.HTTP_200_OK
    assert cast(str, response.headers.get("Content-Type")).startswith("text/plain")
    assert response.text == "status: alive"


async def test_ready_json(fastapi_client: AsyncClient) -> None:
    response: Response = await fastapi_client.get("/ready", headers={"Accept": "application/json"})

    assert response.status_code == status.HTTP_200_OK
    assert response.headers.get("Content-Type") == "application/json"
    response_json: dict = response.json()
    assert response_json["status"] == "ready"


async def test_ready_plaintext(fastapi_client: AsyncClient) -> None:
    response: Response = await fastapi_client.get("/ready", headers={"Accept": "text/plain"})

    assert response.status_code == status.HTTP_200_OK
    assert cast(str, response.headers.get("Content-Type")).startswith("text/plain")
    assert response.text == "status: ready"


async def test_exception(fastapi_client: AsyncClient) -> None:
    response: Response = await fastapi_client.get("/exceptme")
    data: Optional[dict[str, str | int | dict]] = response.json()
    assert data is not None
    assert response.status_code == 500
    assert data["detail"] == "intentionally thrown"
