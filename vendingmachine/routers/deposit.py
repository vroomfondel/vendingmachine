from typing import Optional, Union, cast

from fastapi import APIRouter, Depends, HTTPException, status
from loguru import logger

from vendingmachine.datastructures.models_and_schemas import (
    Buyer,
    CoinType,
    Seller,
    UserSelf,
    UserType,
)
from vendingmachine.utils.auth import CredentialsException, get_current_user


router = APIRouter(
    tags=["deposit"],
    responses={
        403: {"description": "Only Buyers have a deposit to fill up."},
        401: {"class": CredentialsException},
    },
)


@router.patch("/{coin_inserted}", response_model=UserSelf, response_model_exclude_none=True)
async def insert_coin(coin_inserted: CoinType, me: Union[Buyer, Seller] = Depends(get_current_user)) -> Optional[Buyer]:
    """resets user credits and retuns myself as user-object"""
    # logger.debug(f"{type(me)=}")
    if me.usertype != UserType.BUYER:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only Buyers have a deposit to fill up.")

    me = cast(Buyer, me)
    me.deposit += coin_inserted.value
    me.check()  # checks for validity -> multiple of 5 and such not entirely necessary since CoinType is already checked.
    me_new: Optional[Union[Buyer, Seller]] = await me.save()
    if me_new:
        return cast(Buyer, me_new)

    return None
