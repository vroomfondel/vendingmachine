import hashlib
import math
from base64 import b64encode
from datetime import datetime, timedelta, tzinfo
from functools import partial
from secrets import token_bytes
from typing import Any, Callable, List, Literal, Optional, Tuple, Union, cast
from uuid import UUID, uuid4

from cachetools import TTLCache
from fastapi import Depends, Form, HTTPException, status
from fastapi.datastructures import Headers
from fastapi.requests import Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from loguru import logger

from vendingmachine.datastructures.models_and_schemas import (
    Buyer,
    KeyDesignation,
    KeyDictEntry,
    Seller,
    UserType,
    UserWithPasswordHashAndID,
    RS256JWKSet,
    RS256JWKSetKey,
)
from vendingmachine.utils import datapersistence

import jwtjwkhelper
import pytz
from ..utils.datapersistence import (
    check_valid_tokens_access_token_or_refresh_token,
    get_key_by_id_and_designation,
    get_key_ids_by_designation,
    save_issued_token,
    get_valid_RS256_pubkey_pems_and_keyids,
)

from .configuration import settings
import vendingmachine.utils.configuration as conf
from anyio import Lock  # :-)
from passlib.context import CryptContext


_oauth2_scheme = OAuth2PasswordBearer(tokenUrl=settings.JWT_TOKEN_URL)

_tzberlin: tzinfo = pytz.timezone(
    "Europe/Berlin"
)  # should not be necessary since TZ is set in ENV, but anyhow, better explicit than implicit :-]


class CredentialsException(HTTPException):
    """exception class for handling specific unauthorized-exceptions"""

    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


responses_401: dict = {401: {"class": CredentialsException}}
responses_403: dict = {403: {"class": HTTPException}}
responses_404: dict = {404: {"class": HTTPException}}
responses_429: dict = {429: {"class": HTTPException}}
responses_401_403: dict = responses_401 | responses_403
responses_401_404: dict = responses_401 | responses_404
responses_403_429: dict = responses_403 | responses_429


class ScopedOAuth2PasswordRequestForm(OAuth2PasswordRequestForm):
    """pre-fitted subclass with fixed password, given regex for username and password and the list of possible scopes of OAuth2PasswordRequestForm"""

    def __init__(
        self,
        grant_type: Literal["password"] = "password",
        username: str = Form(regex=settings.USERNAME_PATTERN),
        password: str = Form(regex=settings.PASSWORD_PATTERN),
        scope: Literal["user:buyer", "user:seller"] = "user:buyer",
        client_id: Literal[None] = None,
        client_secret: Literal[None] = None,
    ) -> None:

        super().__init__(grant_type, username, password, scope, client_id, client_secret)  #


_pwd_context: CryptContext = CryptContext(schemes=["bcrypt"], deprecated="auto")


_cache: dict[str, TTLCache] = {}  # str, dict[str, str]]
_cache_lock = Lock()


async def _addCache(key: str, sub: str, subsub: str = "IGNORED") -> int:
    """used to add an entry to the cache -> creates TTLCache for the relevant key-value"""
    async with _cache_lock:
        ret: int
        mecache: Optional[TTLCache]
        mecache = _cache.get(key)
        if mecache is None:
            mecache = TTLCache(maxsize=math.inf, ttl=60)  # "per minute" is hard-coded here!
            _cache[key] = mecache

        mecache[sub] = subsub  # to avoid sub-second-spamming, use a sub-key with enough resolution!
        ret = len(mecache)

        if len(_cache) % 100 == 99:
            removekeys: list[str] = []
            for themkey, themcache in _cache.items():
                if len(themcache) == 0:
                    removekeys.append(themkey)
            for k in removekeys:
                del _cache[k]
    return ret


async def getBestGuessedRemoteAddress(request: Request) -> Optional[str]:
    """
    used to best-guess the IP-Address if a 'Cf-Connecting-Ip'-header is found
    => not relevant here (deta is not running behind cloudflare afaik), but just to show where to hook in
    """
    if not request.client:
        return None

    raddress: Optional[str] = request.client.host
    headers: Headers = request.headers

    if "Cf-Connecting-Ip" in headers:
        raddress = headers.get("Cf-Connecting-Ip")

    # for k, values in headers.items():
    #     logger.debug(f"{k=} {values=}")

    return raddress


async def myratelimit(remote_addr: str = Depends(getBestGuessedRemoteAddress)) -> None:
    """
    implementation for a simple ip-address-based rate-limiter based on the functionality of an TTLCache
    => ip-address-based does not make toooooo much sense in times of IPv6
    """
    key: str = datetime.now(tz=_tzberlin).isoformat()  # has nano-second-resolution
    count: int = await _addCache(remote_addr, key)

    logger.debug(f"myratelimit {remote_addr=} {key=} {count=}")

    if count >= 5:  # meaning moreorequal than 5 per minute => "per minute" is fixed in cache-creation
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests towards this endpoint from that 'IP'",
        )


async def retrieve_AUTO_keyid(keydesignation: KeyDesignation = KeyDesignation.HS256) -> Optional[str]:
    """
    get one keyid matching the desired keydesignation
    """

    keyids: List[str] = await get_key_ids_by_designation(keydesignation=keydesignation.value)
    logger.debug(f"Found {len(keyids)} Keys matching the desired keydesignation {keydesignation}")
    if len(keyids) > 0:
        return keyids[0]

    return None


async def retrieve_all_valid_RS256_keys() -> RS256JWKSet:
    """
    get all not invalidated RS256 designated keys
    """

    key_list: List[RS256JWKSetKey] = []

    pubkeys_ids: List[Tuple[str, str]] = await get_valid_RS256_pubkey_pems_and_keyids()
    logger.debug(f"Found {len(pubkeys_ids)} Keys matching the desired keydesignation RS256 and being valid.")

    for pubkey, kid in pubkeys_ids:
        jwkdict: dict = jwtjwkhelper.get_pubkey_as_jwksetkeyentry(pubkey, kid)
        me_key: RS256JWKSetKey = RS256JWKSetKey(**jwkdict)
        key_list.append(me_key)

    return RS256JWKSet(keys=key_list)


async def retrieve_key(keyid: str, keydesignation: KeyDesignation = KeyDesignation.HS256) -> Optional[KeyDictEntry]:
    """
    not entirely correct to name it keytype, hence named it "keydesignation"
    HS256 (HMAC with SHA-256)
    RS256 (RSA Signature with SHA-256)
    """

    keydict: Optional[dict] = await get_key_by_id_and_designation(
        keyid, keydesignation.value
    )  # lookup per Literal-alg!
    if keydict is None:
        return None

    return KeyDictEntry(**keydict)


def get_hash_of_str(input: str) -> str:
    """generates the sha256-hash of the str-input and returns its hexdigest as str"""
    return hashlib.sha256(input.encode("utf-8")).hexdigest()


def generate_random_bytes(nbytes: int = 32) -> str:
    """generates a string containing random bytes wrapped in base64"""
    rand_bytes: bytes = token_bytes(nbytes)
    rand_bytes_b64str: str = b64encode(rand_bytes).decode()

    return rand_bytes_b64str


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    tries to verify the hashed-password to the plan_password by comparing both within the pre-set password-hashing-context

    :return: True if match - False otherwise
    """
    return _pwd_context.verify(plain_password, hashed_password)


def create_password_hash(password: str) -> str:
    """creates a password-hash using the pre-set password-hasing-context

    :return: str being the password-hash
    """
    return _pwd_context.hash(password)


async def check_if_user_has_session(userid: UUID) -> bool:
    """
    checks if for the given userid there are valid access-tokens issued (and not deleted since then)
    => this all "deleted" access-token is just to mimic usual login-session-behaviour/expectancy
    """
    valid_access_tokens: int
    valid_refresh_tokens: int
    valid_access_tokens, valid_refresh_tokens = await check_valid_tokens_access_token_or_refresh_token(userid)

    logger.debug(f"{userid=} {valid_access_tokens=} {valid_refresh_tokens=}")

    return valid_access_tokens > 0  # imho relevant that current access-tokens are there


async def ensure_startup_event_triggered() -> None:
    if conf._startup_event_called:
        return

    if settings.deta_runtime_detected() and conf._startup_event_callable:
        await conf._startup_event_callable()  # btw.: multiple calls do no harm...
        conf._startup_event_callable = None


async def create_refresh_token(userid: UUID, request_url_base: str) -> Tuple[str, UUID]:
    _payload: dict = {"sub": userid}

    await ensure_startup_event_triggered()

    return await create_token_longform(
        _payload,
        keyid=settings.JWT_KEYID,
        key_designation=KeyDesignation[settings.JWT_ALGORITHM],
        jwt_token_expire_minutes=settings.JWT_REFRESH_TOKEN_EXPIRE_MINUTES,
        request_url_base=request_url_base,
    )


async def create_access_token(userid: UUID, request_url_base: str) -> Tuple[str, UUID]:
    _payload: dict = {"sub": userid}

    await ensure_startup_event_triggered()

    return await create_token_longform(
        _payload,
        keyid=settings.JWT_KEYID,
        key_designation=KeyDesignation[settings.JWT_ALGORITHM],
        jwt_token_expire_minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
        request_url_base=request_url_base,
    )


async def create_token_longform(
    payload: dict,
    keyid: str,
    key_designation: KeyDesignation,
    request_url_base: str,
    jwt_token_expire_minutes: int = 10,
    refresh_token_id: Optional[UUID] = None,  # is None for refresh-token itself
) -> Tuple[str, UUID]:
    """
    creates a RS256|HS256 token AND saves it to "DB"
    """
    kde: Optional[KeyDictEntry] = await retrieve_key(keyid, key_designation)
    if kde is None:
        raise Exception(f"Key not found {keyid=} {key_designation=}")

    encrypter: Callable = jwtjwkhelper.create_jwt_rs256  # , jwtjwkhelper.create_jwt_hs256]
    keyid_calculated: str

    tokenid: UUID = uuid4()

    jku: Optional[str] = None

    if kde.keydesignation == KeyDesignation.RS256 and kde.public:
        encrypter = jwtjwkhelper.create_jwt_rs256
        keyid_calculated = get_hash_of_str(kde.public)
        logger.trace(f"{kde.public=} {keyid=} {keyid_calculated=}")

        jku = settings.JKU_URL
        if jku == "AUTO":
            jku = f"{request_url_base}/.well-known/jwks.json"
            jku = jku.replace("//", "/")  # replace double-slashes with single slash
        if jku:
            encrypter = partial(jwtjwkhelper.create_jwt_rs256, jku=jku)

    elif kde.keydesignation == KeyDesignation.HS256 and kde.private:
        encrypter = jwtjwkhelper.create_jwt_hs256
        keyid_calculated = get_hash_of_str(kde.private)
        logger.trace(f"{kde.private=} {keyid=} {keyid_calculated=}")

    payload_aug: dict = payload.copy()
    payload_aug["tokenid"] = tokenid  # could be omitted -> would need to calculate hash on signed-payload then for "ID"

    now: datetime = datetime.now()
    td: timedelta = timedelta(minutes=jwt_token_expire_minutes)

    encoded_jwt: str = encrypter(payload_aug, keyid, kde.private, expiration_delta=td)

    await save_issued_token(
        tokenid=payload_aug["tokenid"],
        userid=payload["sub"],
        keyid=keyid,
        expires_at=now + td,
        issued_at=now,
        refresh_token_id=refresh_token_id,
    )

    return encoded_jwt, tokenid


async def get_user_with_payload_from_token(token: str, verify_exp: bool = True) -> Tuple[Union[Seller, Buyer], dict]:
    """
    trying to get the current user based on the access_token presented; also returns the payload from within the token

    NOTE: if verify_exp is False, could also return "properly" when being presented expired tokens!!!

    :returns: User if valid access_token and user found in 'DB', payload from within the token
    :raises CredentialsException if access_token invalid and/or user not found in 'DB'

    """

    userid_uuid: Optional[UUID]
    payload: Optional[dict]
    try:
        header_unverified: dict = jwtjwkhelper.get_unverified_header(jwttoken=token)
        keyid: str = header_unverified["kid"]
        alg: KeyDesignation = (
            KeyDesignation.RS256 if header_unverified["alg"] == KeyDesignation.RS256.value else KeyDesignation.HS256
        )
        kde: Optional[KeyDictEntry] = await retrieve_key(keyid=keyid, keydesignation=alg)
        if not kde or not kde.private:
            raise Exception()

        key: str = cast(str, kde.private if alg == KeyDesignation.HS256 else kde.public)

        payload = jwtjwkhelper.get_verified_payload_rs256hs256(jwttoken=token, verify_exp=verify_exp, key=key)

        if not payload or "sub" not in payload or "tokenid" not in payload:
            raise Exception()

        userid_uuid = UUID(payload.get("sub"))
        if userid_uuid is None:
            raise Exception()

        in_deleted_db: bool = await datapersistence.is_token_in_deleted_tokens_db(UUID(payload["tokenid"]))
        if in_deleted_db:
            raise Exception()

    except Exception as ex:
        # logger.exception(token, exception=ex)
        raise CredentialsException()

    user: Optional[Union[Buyer, Seller]] = await UserWithPasswordHashAndID.get_user_from_db(userid=userid_uuid)
    if user is None:
        raise CredentialsException()

    return user, payload


async def get_current_user(token: str = Depends(_oauth2_scheme)) -> Union[Seller, Buyer]:
    """
    trying to get the current user based on the access_token presented;
    :returns: User if valid access_token and user found in 'DB'
    :raises CredentialsException if access_token invalid and/or user not found in 'DB'
    """
    user, payload = await get_user_with_payload_from_token(token, verify_exp=True)

    return user


async def get_current_user_n_payload(token: str = Depends(_oauth2_scheme)) -> Tuple[Union[Seller, Buyer], dict]:
    """
    trying to get the current user based on the access_token presented;
    :returns: User if valid access_token and user found in 'DB' + payload as dict in Tuple
    :raises CredentialsException if access_token invalid and/or user not found in 'DB'
    """
    return await get_user_with_payload_from_token(token, verify_exp=True)


async def get_PROBABLYEXPIRED_current_user_with_payload(
    token: str = Depends(_oauth2_scheme),
) -> Tuple[Union[Seller, Buyer], dict]:
    """
    special use-case function to be used in the context of being used with a refresh-token
    while the access-token probably expired
    => could have also used partial binding to the base-function
    """
    user, payload = await get_user_with_payload_from_token(token, verify_exp=False)

    return user, payload


async def clean_tokens_by_refresh_tokenid(
    userid: UUID, refresh_tokenid_used: UUID, refresh_token_expires_at: datetime
) -> None:
    """
    removes tokens (and marks them "deleted")  from issued-token-db based/related
    to the given refresh_tokenid and userid (and the refresh_token with that id as well)
    """
    await datapersistence.clean_tokens_by_refresh_tokenid(userid, refresh_tokenid_used, refresh_token_expires_at)


async def clean_tokens_by_access_tokenid(userid: UUID, access_tokenid_used: UUID) -> None:
    """
    removes the token (and marks it "deleted") relating to the given tokenid and userid from issued-token-db
    """
    await datapersistence.clean_tokens_by_access_tokenid(userid, access_tokenid_used)


async def get_refresh_tokenid_from_access_tokenid(userid: UUID, access_tokenid_used: UUID) -> Optional[UUID]:
    """
    retrieves the refresh-tokenid for the given access_tokenid and userid
    """
    return await datapersistence.get_refresh_tokenid_from_access_tokenid(userid, access_tokenid_used)


async def clean_tokens_by_userid(userid: UUID) -> None:
    """BIG RESET-SWITCH for tokens/sessions/refresh-tokens
    removes tokens (and marks them "deleted") from issued-token-db based/related
    to the given userid
    """
    return await datapersistence.clean_tokens_by_userid(userid)


async def get_current_user_ensure_sellertype(me: Union[Buyer, Seller] = Depends(get_current_user)) -> Seller:
    """gets the current user based on access-token supplied and ensures, the user is Seller"""
    if me.usertype != UserType.SELLER:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only Sellers may access this realm.")

    return cast(Seller, me)


async def get_current_user_ensure_buyertype(me: Union[Buyer, Seller] = Depends(get_current_user)) -> Buyer:
    """gets the current user based on access-token supplied and ensures, the user is Buyer"""
    if me.usertype != UserType.BUYER:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only Buyers may access this realm.")

    return cast(Buyer, me)


# async def get_current_active_user(current_user: User = Depends(get_current_user)):
#     if current_user.disabled:
#         raise HTTPException(status_code=400, detail="Inactive user")
#     return current_user
