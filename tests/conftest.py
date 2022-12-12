import asyncio
import json
import os
import platform
from typing import Generator, Tuple
from uuid import UUID

from fastapi import FastAPI, HTTPException, status
from fastapi.testclient import TestClient
from loguru import logger

from vendingmachine.app import app, shutdown_event, startup_event
from vendingmachine.utils.configuration import settings

import pytest
from httpx import AsyncClient, Response


if not settings.DETA_PROJECT_KEY:
    print("DETA_PROJECT_KEY NOT SET AND IS NEEDED FOR 'DETA-BASE' -> FAIL")
    print("TO GET ONE FOR FREE (AT THE MOMENT AT LEAST) HOP OVER TO: https://docs.deta.sh/docs/base/about")
    exit(123)


@pytest.fixture(scope="session")
def anyio_backend():
    """needed to also session-scope the anyio-backend"""
    return "trio"  # backend == asyncio causes report-errors in conjunction with python 3.9 and exceptiongroups


# This is the same as using the @pytest.mark.anyio on all test functions in the module
pytestmark = pytest.mark.anyio


@pytest.fixture(scope="session")
async def fapi() -> FastAPI:
    logger.disable("vendingmachine")  # muting logger for everything in+below vendingmachine-package

    fapi = app

    await startup_event()

    @fapi.get("/exceptme")  # exception-ping-endpoint
    async def exceptme() -> None:
        raise HTTPException(detail="intentionally thrown", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    yield fapi

    await shutdown_event()
    ## teardown-code for fapp goes here


@pytest.fixture(scope="session")
async def fastapi_client(fapi: FastAPI) -> AsyncClient:  # TestClient:
    return AsyncClient(app=fapi, base_url="http://test")


@pytest.fixture(scope="module")
async def get_new_access_token(
    fastapi_client: AsyncClient, create_buyer_modulescoped: Tuple[str, str, str, UUID]
) -> str:

    refresh_request_json: dict = {"refresh_token": create_buyer_modulescoped[1]}

    refresh_response: Response = await fastapi_client.post(
        "/users/token/refresh",
        headers={"Authorization": f"Bearer {create_buyer_modulescoped[0]}", "content-type": "application/json"},
        json=refresh_request_json,
    )

    refresh_response_json: dict = refresh_response.json()
    logger.trace("RESPONSE::")
    logger.trace(json.dumps(refresh_response_json, indent=4, default=str))

    assert refresh_response.status_code == status.HTTP_201_CREATED
    assert "access_token" in refresh_response_json
    assert "refresh_token" in refresh_response_json
    assert "token_type" in refresh_response_json and refresh_response_json["token_type"] == "bearer"

    new_access_token: str = refresh_response_json["access_token"]

    return new_access_token


@pytest.fixture(scope="module")
async def create_buyer_modulescoped(fastapi_client: AsyncClient) -> Tuple[str, str, str, UUID]:
    """returns tuple (access_token, refresh_token, username, userid)"""
    pf: str = f"{platform.node()}-{os.getpid()}!"
    username: str = f"PYTEST-BUYER-MODULE-{pf}"
    usertype: str = "BUYER"
    password: str = "MEissECRE4ddd!"
    response: Response = await fastapi_client.post(
        "/users",
        json={"username": username, "usertype": usertype, "password": password},
        headers={"content-type": "application/json"},
    )

    # logger.trace(response.text)
    response_data = response.json()
    # logger.trace(response_data)

    assert response.status_code == 201
    assert "username" in response_data and response_data["username"] == username
    assert "usertype" in response_data and response_data["usertype"] == usertype
    assert "deposit" in response_data and response_data["deposit"] == 0  # ?!
    assert "id" in response_data

    userid: UUID = UUID(response_data["id"])

    response = await fastapi_client.post(
        "/users/token",
        data={
            "username": username,
            "password": password,
            "grant_type": "password",
            "scope": f"users:{usertype.lower()}",  # scope currently not appreciated
        },
        headers={"content-type": "application/x-www-form-urlencoded"},
    )

    assert response.status_code == status.HTTP_201_CREATED
    response_data = response.json()
    # print(response_data)
    assert "access_token" in response_data
    assert "refresh_token" in response_data
    assert "token_type" in response_data and response_data["token_type"] == "bearer"

    yield response_data["access_token"], response_data["refresh_token"], username, userid

    response_del: Response = await fastapi_client.delete(
        "/users/me", headers={"Authorization": f"Bearer {response_data['access_token']}"}
    )


# @pytest.mark.parametrize("test_input, expected", [(1,1), (2,4), (3,9), (4,16)])
@pytest.fixture(scope="session")
async def create_buyer(fastapi_client: AsyncClient) -> Tuple[str, str, str, UUID]:
    """returns tuple (access_token, refresh_token, username, userid)"""
    pf: str = f"{platform.node()}-{os.getpid()}!"
    username: str = f"PYTEST-BUYER-{pf}"
    usertype: str = "BUYER"
    password: str = "MEissECRE4ddd!"
    response: Response = await fastapi_client.post(
        "/users",
        json={"username": username, "usertype": usertype, "password": password},
        headers={"content-type": "application/json"},
    )

    # logger.trace(response.text)
    response_data = response.json()
    # logger.trace(response_data)

    assert response.status_code == 201
    assert "username" in response_data and response_data["username"] == username
    assert "usertype" in response_data and response_data["usertype"] == usertype
    assert "deposit" in response_data and response_data["deposit"] == 0  # ?!
    assert "id" in response_data

    userid: UUID = UUID(response_data["id"])

    response = await fastapi_client.post(
        "/users/token",
        data={
            "username": username,
            "password": password,
            "grant_type": "password",
            "scope": f"users:{usertype.lower()}",  # scope currently not appreciated
        },
        headers={"content-type": "application/x-www-form-urlencoded"},
    )

    assert response.status_code == status.HTTP_201_CREATED
    response_data = response.json()
    # print(response_data)
    assert "access_token" in response_data
    assert "refresh_token" in response_data
    assert "token_type" in response_data and response_data["token_type"] == "bearer"

    yield response_data["access_token"], response_data["refresh_token"], username, userid

    response_del: Response = await fastapi_client.delete(
        "/users/me", headers={"Authorization": f"Bearer {response_data['access_token']}"}
    )


@pytest.fixture(scope="session")
async def create_seller(fastapi_client: AsyncClient) -> Tuple[str, str, str, UUID]:
    """returns tuple (access_token, refresh_token, username, userid)"""
    pf: str = f"{platform.node()}-{os.getpid()}!"
    username: str = f"PYTEST-SELLER-{pf}"
    usertype: str = "SELLER"
    password: str = "MEissECRE4ddd!"
    response: Response = await fastapi_client.post(
        "/users",
        json={"username": username, "usertype": usertype, "password": password},
        headers={"content-type": "application/json"},
    )

    # logger.trace(response.text)
    response_data = response.json()
    # logger.trace(response_data)

    assert response.status_code == 201
    assert "username" in response_data and response_data["username"] == username
    assert "usertype" in response_data and response_data["usertype"] == usertype
    assert "id" in response_data
    assert not "deposit" in response_data

    userid: UUID = UUID(response_data["id"])

    response = await fastapi_client.post(
        "/users/token",
        data={
            "username": username,
            "password": password,
            "grant_type": "password",
            "scope": f"users:{usertype.lower()}",  # scope currently not appreciated
        },
        headers={"content-type": "application/x-www-form-urlencoded"},
    )

    assert response.status_code == status.HTTP_201_CREATED
    response_data = response.json()
    # print(response_data)
    assert "access_token" in response_data
    assert "refresh_token" in response_data
    assert "token_type" in response_data and response_data["token_type"] == "bearer"

    yield response_data["access_token"], response_data["refresh_token"], username, userid

    response_del: Response = await fastapi_client.delete(
        "/users/me", headers={"Authorization": f"Bearer {response_data['access_token']}"}
    )


@pytest.fixture(scope="session")
async def create_product(fastapi_client: AsyncClient, create_seller: Tuple[str, str, str, UUID]) -> dict:
    from vendingmachine.utils.datapersistence import (
        generate_pseudo_product_data,
    )

    gen: dict[str, dict] = generate_pseudo_product_data(
        seller_id=create_seller[3], amount=1, amt_available=123, cost=10
    )
    product_data: dict = next(iter(gen.values()))
    del product_data["id"]  # has id in pseudo-gen!
    # print(json.dumps(product_data, indent=4, default=str))

    response: Response = await fastapi_client.post(
        "/products",
        json=json.loads(json.dumps(product_data, default=str)),
        headers={"Authorization": f"Bearer {create_seller[0]}", "content-type": "application/json"},
    )
    response_json: dict = response.json()
    # print(response_json)

    assert response.status_code == status.HTTP_201_CREATED
    assert response_json["cost"] == product_data["cost"]
    assert (
        response_json["amountAvailable"] == product_data["amount_available"]
    )  #! response-model vs. (pseudo)data-model
    assert "id" in response_json

    productid: UUID = UUID(response_json["id"])

    yield response_json, productid

    response_del: Response = await fastapi_client.delete(
        f"/products/{productid}", headers={"Authorization": f"Bearer {create_seller[0]}"}
    )
