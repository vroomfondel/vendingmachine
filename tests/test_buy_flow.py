from typing import Optional, Tuple
from uuid import UUID

from fastapi import status
from fastapi.testclient import TestClient

from vendingmachine.datastructures.models_and_schemas import CoinType

import pytest
from httpx import AsyncClient, Response


# This is the same as using the @pytest.mark.anyio on all test functions in the module
pytestmark = pytest.mark.anyio


async def test_product_buy(
    fastapi_client: AsyncClient,
    create_buyer: Tuple[str, str, str, UUID],
    create_seller: Tuple[str, str, str, UUID],
    create_product: Tuple[dict, UUID],
) -> None:
    # reset funds
    response_reset: Response = await fastapi_client.patch(
        "/reset", headers={"Authorization": f"Bearer {create_buyer[0]}"}
    )

    # ensure funds
    deposit_in: int = 100  # 5, 10, 20, 50, 100
    response_funds: Response = await fastapi_client.patch(
        f"/deposit/{deposit_in}", headers={"Authorization": f"Bearer {create_buyer[0]}"}
    )
    response_json_funds: dict = response_funds.json()
    print(response_json_funds)

    assert response_funds.status_code == status.HTTP_200_OK
    assert response_json_funds["deposit"] == deposit_in
    assert response_json_funds["username"] == create_buyer[2]

    # buy product
    productid: UUID = create_product[1]
    amt_buy: int = 1

    response: Response = await fastapi_client.post(
        f"/buy/{productid}",
        params={"amount": amt_buy},  # as query param!
        headers={"Authorization": f"Bearer {create_buyer[0]}"},
    )
    response_json: dict = response.json()
    print(response_json)

    prod_created: dict = create_product[0]

    assert response.status_code == status.HTTP_201_CREATED
    assert response_json["total_costs"] == prod_created["cost"] * amt_buy  # multiple-calls would fail here!!!
    assert "product_purchased" in response_json

    total_costs: int = response_json["total_costs"]

    prod_purchased: dict = response_json["product_purchased"]
    assert prod_purchased["amountAvailable"] == prod_created["amountAvailable"] - amt_buy
    for k in ["productName", "id", "sellerId"]:
        assert prod_purchased[k] == prod_created[k]

    assert "change_returned_from_deposit" in response_json
    change_sum: int = 0
    for i, c in enumerate(response_json["change_returned_from_deposit"]):
        change_sum += list(CoinType)[i] * c

    print(f"change_sum: {change_sum}")

    assert change_sum == deposit_in - total_costs
