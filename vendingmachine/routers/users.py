import datetime
from typing import List, Optional, Tuple, Union
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, status
from loguru import logger

from ..datastructures.models_and_schemas import (
    Buyer,
    KeyDesignation,
    ProductWithID,
    RefreshToken,
    Seller,
    TokenWithRefreshToken,
    TokenWithRefreshTokenAndMessage,
    UserName,
    UserOther,
    UserSelf,
    UserType,
    UserWithPassword,
    UserWithPasswordHashAndID,
    UserPassword,
)

from vendingmachine.utils.auth import (
    CredentialsException,
    ScopedOAuth2PasswordRequestForm,
    check_if_user_has_session,
    clean_tokens_by_access_tokenid,
    clean_tokens_by_refresh_tokenid,
    clean_tokens_by_userid,
    get_current_user,
    get_current_user_n_payload,
    get_PROBABLYEXPIRED_current_user_with_payload,
    get_user_with_payload_from_token,
    myratelimit,
    responses_401,
    responses_403_429,
    verify_password,
    create_refresh_token,
    create_access_token,
    create_password_hash,
)
from ..utils.configuration import settings
from starlette.background import BackgroundTasks
from starlette.responses import JSONResponse


router = APIRouter(tags=["user"])


# @router.post("/", response_model=UserSelf, response_model_exclude_none=True, dependencies=[Depends(myratelimit)])
@router.post(
    "",
    dependencies=[Depends(myratelimit)],
    response_model=UserSelf,
    response_model_exclude_none=True,
    status_code=status.HTTP_201_CREATED,
    responses=responses_403_429,
)
async def create_user(userregisterdata: UserWithPassword) -> Optional[Union[Buyer, Seller]]:
    """used to create a user
    -> should check for maximum users on the system to avoid overload
    -> limiting this endpoint via ip-filters seems futile in the realms of ipv6.
    -> anyhow, implementing a rudimentary, very adaptable, version using
    cachetools (and not using slowapi or such) "for fun and profit"
    """

    hashed_pw: str = create_password_hash(userregisterdata.password)
    datadict: dict
    new_user_db: Optional[Union[Buyer, Seller]]
    try:
        if userregisterdata.usertype == UserType.BUYER:  # could move this "switch" to generator in models...
            new_buyer: Buyer = Buyer(username=userregisterdata.username, password_hashed=hashed_pw, deposit=0)
            new_user_db = await new_buyer.create_new()
        else:
            new_seller: Seller = Seller(username=userregisterdata.username, password_hashed=hashed_pw)
            new_user_db = await new_seller.create_new()

        return new_user_db
    except ValueError as ex:
        logger.debug(ex)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(ex))


@router.get(
    "", response_model=List[Union[UserSelf, UserOther]], response_model_exclude_none=True, responses=responses_401
)
async def read_users(me: Union[Buyer, Seller] = Depends(get_current_user)) -> List[Union[UserSelf, UserOther]]:
    """get all users currently in 'DB' and print their userid+usertype; print full self-data for user-self"""
    dd: List[Union[Buyer, Seller]] = await UserWithPasswordHashAndID.get_all_users_from_db()
    return [UserOther(**ud.dict()) if ud.id != me.id else UserSelf(**ud.dict()) for ud in dd]


@router.post(
    "/token/refresh", response_model=TokenWithRefreshToken, status_code=status.HTTP_201_CREATED, responses=responses_401
)
async def refresh_token(
    background_tasks: BackgroundTasks,  # trigger backgroud task to cleanse old tokens
    refresh_token_supplied: RefreshToken,
    me_n_payload_PROBABLYEXPIRED: Tuple[Union[Buyer, Seller], dict] = Depends(
        get_PROBABLYEXPIRED_current_user_with_payload
    ),
) -> dict:
    """get new request-token, access-token pair and kill the old refresh-tokens alltogether"""

    me: Union[Buyer, Seller] = me_n_payload_PROBABLYEXPIRED[0]
    current_token_payload: dict = me_n_payload_PROBABLYEXPIRED[1]

    logger.debug(f"{me=}")
    logger.debug(f"{current_token_payload=}")
    logger.debug(f"{refresh_token_supplied=}")

    refresh_token_user: Union[Buyer, Seller]
    refresh_token_payload: dict
    refresh_token_user, refresh_token_payload = await get_user_with_payload_from_token(
        refresh_token_supplied.refresh_token, verify_exp=True
    )  # throws-exception if anything goes wrong!

    if refresh_token_user.id != me.id:
        raise CredentialsException()

    refresh_token_new: str
    refresh_token_new_id: UUID
    refresh_token_new, refresh_token_new_id = await create_refresh_token(me.id)

    access_token_new: str
    access_token_new_id: UUID
    access_token_new, access_token_new_id = await create_access_token(me.id)

    refresh_token_expires_dt: datetime.datetime = datetime.datetime.fromtimestamp(int(refresh_token_payload["exp"]))

    if settings.deta_runtime_detected():
        await clean_tokens_by_refresh_tokenid(
            userid=me.id,
            refresh_tokenid_used=refresh_token_payload["tokenid"],
            refresh_token_expires_at=refresh_token_expires_dt,
        )
    else:
        background_tasks.add_task(
            clean_tokens_by_refresh_tokenid,
            userid=me.id,
            refresh_tokenid_used=refresh_token_payload["tokenid"],
            refresh_token_expires_at=refresh_token_expires_dt,
        )

    return {
        "access_token": access_token_new,
        "token_type": "bearer",
        "refresh_token": refresh_token_new,
    }  # check -> also scoping on this level


@router.delete("/token", status_code=status.HTTP_204_NO_CONTENT, responses=responses_401)
async def logout_this_token(
    me_n_payload: Tuple[Union[Buyer, Seller], dict] = Depends(get_current_user_n_payload)
) -> None:
    """this is a "logout" mimic for token-based-auth"""
    me: Union[Buyer, Seller] = me_n_payload[0]
    payload: dict = me_n_payload[1]

    await clean_tokens_by_access_tokenid(me.id, UUID(payload["tokenid"]))


@router.delete("/token/all", status_code=status.HTTP_204_NO_CONTENT, responses=responses_401)
async def logout_this_and_all_my_other_tokens(me: Union[Buyer, Seller] = Depends(get_current_user)) -> None:
    """this is a "logout-all" mimic for token-based-auth"""

    await clean_tokens_by_userid(me.id)


@router.post(
    "/token",
    response_model=TokenWithRefreshTokenAndMessage,
    response_model_exclude_none=True,
    responses=responses_401,
    status_code=status.HTTP_201_CREATED,
)
async def login_for_access_token(form_data: ScopedOAuth2PasswordRequestForm = Depends()) -> dict:
    logger.debug(f"{form_data.username=} {form_data.password=}")
    user: Optional[Union[Buyer, Seller]] = await UserWithPasswordHashAndID.get_user_from_db(
        UserName(username=form_data.username)
    )
    logger.debug(f"Return USER: {user}")
    if not user or not verify_password(form_data.password, user.password_hashed):
        raise CredentialsException()

    msg: Optional[str] = None
    has_sessions: bool = await check_if_user_has_session(user.id)
    if has_sessions:
        msg = "There is already an active session [access_token] using your account"

    refresh_token: str
    refresh_token_id: UUID
    refresh_token, refresh_token_id = await create_refresh_token(user.id)

    access_token: str
    access_token_id: UUID
    access_token, access_token_id = await create_access_token(user.id)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token,
        "message": msg,
    }  # check -> also scoping on this level


@router.get("/me", response_model=UserSelf, response_model_exclude_none=True, responses=responses_401)
async def read_user_me(me: Union[Buyer, Seller] = Depends(get_current_user)) -> UserSelf:
    """get myself"""
    return UserSelf(**me.dict())


@router.patch("/me", response_model=UserSelf, response_model_exclude_none=True, responses=responses_401)
async def update_user(
    userpass: UserPassword, me: Union[Buyer, Seller] = Depends(get_current_user)
) -> Optional[Union[Buyer, Seller]]:
    """updates the user - in this regard only changeable data atm is password."""

    hashed_pw: str = create_password_hash(userpass.password)
    me.password_hashed = hashed_pw

    saved_user: Optional[Union[Seller, Buyer]] = me.copy(update=me.dict())
    if saved_user:
        return await saved_user.save()

    return None


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT, response_model_exclude_none=True, responses=responses_401)
async def delete_user(me: Union[Buyer, Seller] = Depends(get_current_user)) -> None:
    """delete this user - users can only delete themselves.
    => deletes also all products if user deleted is/was a seller
    => cleans all access-tokens+refresh-tokens in db
    """
    if me.usertype == UserType.SELLER:
        await ProductWithID.delete_all_products_from_db_belonging_to_seller(me.id)

    await clean_tokens_by_userid(me.id)  # clean all access-tokens...
    await me.delete_me()
