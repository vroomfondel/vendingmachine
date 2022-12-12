import json
from typing import Optional, Tuple
from uuid import UUID

from fastapi import status
from loguru import logger

import pytest
from httpx import AsyncClient, Response


# This is the same as using the @pytest.mark.anyio on all test functions in the module
pytestmark = pytest.mark.anyio


async def test_new_access_token(
    fastapi_client: AsyncClient,
    create_buyer_modulescoped: Tuple[str, str, str, UUID],
    get_new_access_token: str,
) -> None:

    # trying new request with new access_token
    me_response_success: Response = await fastapi_client.get(
        "/users/me", headers={"Authorization": f"Bearer {get_new_access_token}"}
    )

    me_response_success_json: dict = me_response_success.json()
    logger.trace("ME_RESPONSE_SUCCESS::")
    logger.trace(json.dumps(me_response_success_json, indent=4, default=str))

    assert me_response_success.status_code == status.HTTP_200_OK
    assert UUID(me_response_success_json["id"]) == create_buyer_modulescoped[3]


async def test_old_access_token(
    fastapi_client: AsyncClient,
    create_buyer_modulescoped: Tuple[str, str, str, UUID],
    get_new_access_token: str,
) -> None:

    # trying request with old access_token
    me_response_fail: Response = await fastapi_client.get(
        "/users/me", headers={"Authorization": f"Bearer {create_buyer_modulescoped[1]}"}
    )

    me_response_success_json: dict = me_response_fail.json()
    logger.trace("ME_RESPONSE_FAIL::")
    logger.trace(json.dumps(me_response_fail, indent=4, default=str))

    assert me_response_fail.status_code == status.HTTP_401_UNAUTHORIZED


async def test_new_access_token_with_old_refreshtoken(
    fastapi_client: AsyncClient,
    create_buyer_modulescoped: Tuple[str, str, str, UUID],
    get_new_access_token: str,
) -> None:

    # trying re-use the old refresh-token with the NEW access_token
    refresh_request_fail_json: dict = {"refresh_token": create_buyer_modulescoped[1]}

    refresh_response_fail: Response = await fastapi_client.post(
        "/users/token/refresh",
        headers={"Authorization": f"Bearer {get_new_access_token}", "content-type": "application/json"},
        json=refresh_request_fail_json,
    )

    refresh_response_fail_json: dict = refresh_response_fail.json()
    logger.trace("RESPONSE::")
    logger.trace(json.dumps(refresh_response_fail_json, indent=4, default=str))

    assert refresh_response_fail.status_code == status.HTTP_401_UNAUTHORIZED
