from typing import List, Optional, Union, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from loguru import logger

from vendingmachine.datastructures.models_and_schemas import (
    Buyer,
    CoinType,
    ProductWithID,
    Receipt,
    Seller,
    UserSelf,
    UserType,
)
from vendingmachine.utils.auth import CredentialsException, get_current_user


router = APIRouter(
    tags=["buy"],
    responses={
        404: {"description": "Not found."},
        403: {"description": "Only Buyers can buy products."},
        402: {"description": "Not enough funds."},
        401: {"class": CredentialsException},
    },
)


@router.post(
    "/{productid}", status_code=status.HTTP_201_CREATED, response_model=Receipt, response_model_exclude_none=True
)  # "Creates" a purchase
async def buy_product(
    productid: UUID, amount: int = Query(gt=0, lt=1000), me: Union[Buyer, Seller] = Depends(get_current_user)
) -> Receipt:
    """
    buys a product and CREATES a receipt => returns amount of coins in an array [ 5, 10, 20, 50, 100 ]
    """
    logger.debug(f"{type(me)=}")
    if me.usertype != UserType.BUYER:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only a Buyer buys what a Seller sells.")

    me = cast(Buyer, me)
    product: Optional[ProductWithID] = await ProductWithID.get_product_from_db(productid)
    if not product:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Product with id {productid} not found.")

    if amount > product.amount_available:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Product with id {productid} has only {product.amount_available} amt available, but you requested for {amount}.",
        )
    # 3. get mutex

    total_costs: int = int(amount * product.cost)
    if me.deposit < total_costs:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=f"{amount} times product costs of {product.cost} each exceeds your current deposit of {me.deposit}.",
        )

    me.deposit -= total_costs

    changeregister: List[int] = []  # optimal assumption, vendingmachine has ALL the coins in any amount
    while me.deposit > 0:
        for coinvalue in CoinType._member_map_.values().__reversed__():
            logger.debug(f"{coinvalue=} {CoinType._value2member_map_[coinvalue]=} {me.deposit=}")
            amtthiscoin: int = me.deposit // coinvalue.value
            changeregister.insert(0, amtthiscoin)  # prepend
            me.deposit -= amtthiscoin * coinvalue.value

    # 5, 10, 20, 50 and 100
    logger.debug(f"{changeregister=}")

    # perhaps mutex for these objects

    product.amount_available -= amount

    receipt: Receipt = Receipt(
        total_costs=total_costs, product_purchased=product, change_returned_from_deposit=changeregister
    )

    await product.save()  # new amount_available saved
    await me.save()  # new deposit=0 saved

    return receipt
