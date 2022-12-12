from typing import Optional, Union, cast

from fastapi import APIRouter, Depends, HTTPException, status
from loguru import logger

from vendingmachine.datastructures.models_and_schemas import (
    Buyer,
    Seller,
    UserSelf,
    UserType,
)
from vendingmachine.utils.auth import CredentialsException, get_current_user


router = APIRouter(
    tags=["reset"],
    # dependencies=[Depends(get_token_header)],
    responses={
        403: {"description": "Only Buyers have a deposit to reset."},
        401: {"class": CredentialsException},
    },
)


@router.patch("", response_model=UserSelf, response_model_exclude_none=True)
async def reset_user_credits(me: Union[Buyer, Seller] = Depends(get_current_user)) -> Optional[Union[Buyer, Seller]]:
    """resets user credits and retuns myself as user-object"""
    logger.debug(f"{type(me)=}")
    if me.usertype != UserType.BUYER:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only Buyers have a deposit to reset.")

    me = cast(Buyer, me)
    me.deposit = 0
    me_new: Optional[Union[Buyer, Seller]] = await me.save()

    if me_new:
        return me_new

    return None
