import json
from typing import Optional, Tuple
from uuid import UUID

from fastapi import status
from fastapi.testclient import TestClient

from vendingmachine.utils.datapersistence import generate_pseudo_product_data

import pytest
from httpx import AsyncClient, Response


# This is the same as using the @pytest.mark.anyio on all test functions in the module
pytestmark = pytest.mark.anyio


async def test_product_change(
    fastapi_client: AsyncClient,
    create_seller: Tuple[str, str, str, UUID],
    create_product: Tuple[dict, UUID],
) -> None:
    productid: UUID = create_product[1]
    sellerid: UUID = create_seller[3]

    gen: dict[str, dict] = generate_pseudo_product_data(seller_id=sellerid, amount=1, amt_available=445, cost=15)
    update_data: dict = next(iter(gen.values()))
    del update_data["id"]  # pseudo-gen-model has this data...

    response_put: Response = await fastapi_client.put(
        f"/products/{productid}",
        headers={"Authorization": f"Bearer {create_seller[0]}", "content-type": "application/json"},
        json=json.loads(json.dumps(update_data, default=str)),
    )

    response_put_json: dict = response_put.json()
    # print("RESPONSE:\n")
    # print(json.dumps(response_put_json, indent=4))

    assert response_put.status_code == status.HTTP_200_OK
    assert response_put_json["productName"] == update_data["product_name"]  # pydantic-alias!
    assert UUID(response_put_json["sellerId"]) == update_data["seller_id"]  # pydantic-alias!
    assert response_put_json["cost"] == update_data["cost"]
    assert UUID(response_put_json["id"]) == UUID(create_product[0]["id"])
