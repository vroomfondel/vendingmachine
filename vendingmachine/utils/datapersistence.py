from __future__ import annotations

from vendingmachine.utils.configuration import settings

import asyncio
import datetime
from typing import List, Literal, Optional, Set, Tuple, Union
from uuid import UUID

from loguru import logger

import pytz
from vendingmachine.utils.detadbwrapper import (
    AvailableDBS,
    create_new_entry,
    delete_entry,
    get_all_data,
    get_data_by_field,
    get_data_by_fields,
    get_data_by_key,
    update_data,
)


_tzberlin: datetime.tzinfo = pytz.timezone("Europe/Berlin")

"""semantic layer for mangling data from 'here' to deta-base and vice versa => there is no orm for deta amd anyway, 
a semantic layer might be beneficial"""


async def check_valid_tokens_access_token_or_refresh_token(userid: UUID) -> Tuple[int, int]:
    valid_access_tokens_found: int = 0
    valid_refresh_tokens_found: int = 0

    now: datetime.datetime = datetime.datetime.now(tz=_tzberlin)

    deltokenids: List[UUID] = []

    for tokendata in await get_data_by_field(db=AvailableDBS.tokens_issued, fieldname="userid", fieldvalue=userid):
        expires_at: datetime.datetime = datetime.datetime.fromisoformat(tokendata["expires_at"])
        is_refresh_token: bool = tokendata["refresh_token_id"] is None
        is_valid: bool = expires_at.timestamp() > now.timestamp()
        if is_valid:
            valid_access_tokens_found += 0 if is_refresh_token else 1
            valid_refresh_tokens_found += 1 if is_refresh_token else 0

        logger.debug(f"{userid=} {type(expires_at)=} {expires_at=} {is_valid=} {is_refresh_token=}")
    return (valid_access_tokens_found, valid_refresh_tokens_found)


async def save_issued_token(
    tokenid: UUID,
    userid: UUID,
    keyid: str,
    expires_at: datetime.datetime,
    issued_at: datetime.datetime,
    refresh_token_id: Optional[UUID] = None,
) -> None:

    newentry: dict = {
        "id": tokenid,
        "refresh_token_id": refresh_token_id,
        "userid": userid,
        "keyid": keyid,
        "expires_at": expires_at,
        "issued_at": issued_at,
    }
    await create_new_entry(
        db=AvailableDBS.tokens_issued,
        key=tokenid,
        data=newentry,
        # expire_at=expires_at.timestamp()  # :-))
    )


async def get_refresh_tokenid_from_access_tokenid(userid: UUID, access_tokenid_used: UUID) -> Optional[UUID]:
    for tokendata in await get_data_by_fields(
        db=AvailableDBS.tokens_issued,
        fieldnames=["userid", "id"],
        fieldvalues=[userid, access_tokenid_used],
    ):  # könnte hier auch als query machen!
        return tokendata["refresh_token_id"]

    return None


### the following seems horribly redundant -> but when using a "real" db, this will only be one line each...
async def _clean_tokens_by_list(deltokenids: List[Tuple[UUID, str]]) -> None:
    for tokenid, expires_at in deltokenids:
        logger.debug(f"deleting token: {tokenid=}")

        newentry: dict[str, Union[str, UUID]] = {"id": tokenid, "expires_at": expires_at}
        await create_new_entry(
            db=AvailableDBS.tokens_deleted,
            key=tokenid,
            data=newentry,
            # expire_at=expires_at.timestamp()  # :-))
        )

        await delete_entry(db=AvailableDBS.tokens_issued, key=tokenid)


async def clean_tokens_by_access_tokenid(userid: UUID, access_tokenid_used: UUID) -> None:
    deltokenids: List[Tuple[UUID, str]] = []
    for tokendata in await get_data_by_fields(
        db=AvailableDBS.tokens_issued,
        fieldnames=["userid", "id"],
        fieldvalues=[userid, access_tokenid_used],
    ):  # könnte hier auch als query machen!:

        deltokenids.append((UUID(tokendata["id"]), tokendata["expires_at"]))
    await _clean_tokens_by_list(deltokenids)


async def clean_tokens_by_refresh_tokenid(
    userid: UUID, refresh_tokenid_used: UUID, refresh_tokenid_expires_at: datetime.datetime
) -> None:
    deltokenids: List[Tuple[UUID, str]] = []
    deltokenids.append((refresh_tokenid_used, refresh_tokenid_expires_at.isoformat()))

    for tokendata in await get_data_by_fields(
        db=AvailableDBS.tokens_issued,
        fieldnames=["userid", "refresh_token_id"],
        fieldvalues=[userid, refresh_tokenid_used],
    ):  # könnte hier auch als query machen!:

        deltokenids.append((UUID(tokendata["id"]), tokendata["expires_at"]))

    await _clean_tokens_by_list(deltokenids)


async def clean_tokens_by_userid(userid: UUID) -> None:
    deltokenids: List[Tuple[UUID, str]] = []
    for tokendata in await get_data_by_fields(
        db=AvailableDBS.tokens_issued, fieldnames=["userid"], fieldvalues=[userid]
    ):  # könnte hier auch als query machen!:

        deltokenids.append((UUID(tokendata["id"]), tokendata["expires_at"]))

    await _clean_tokens_by_list(deltokenids)


async def get_key_ids_by_designation(keydesignation: Literal["HS256", "RS256"] = "HS256") -> List[str]:
    ret: List[str] = []

    for keydata in await get_data_by_field(db=AvailableDBS.keys, fieldname="keydesignation", fieldvalue=keydesignation):
        ret.append(keydata["id"])

    return ret


async def get_valid_RS256_pubkey_pems_and_keyids() -> List[Tuple[str, str]]:
    ret: List[Tuple[str, str]] = []

    for keydata in await get_data_by_field(db=AvailableDBS.keys, fieldname="keydesignation", fieldvalue="RS256"):
        invalidated: Optional[str] = keydata["invalidated_at"]
        if invalidated:
            logger.debug(f'INVALID KEY: {keydata["id"]=} {keydata["invalidated_at"]=}')
            continue

        ret.append((keydata["public"], keydata["id"]))

    return ret


async def is_token_in_deleted_tokens_db(tokenid: UUID) -> bool:
    _ret: List[dict] = await get_data_by_key(db=AvailableDBS.tokens_deleted, keyvalue=tokenid)

    return len(_ret) > 0


async def get_key_by_id_and_designation(
    keyid: str, keydesignation: Literal["HS256", "RS256"] = "HS256"
) -> Optional[dict]:
    keydata: dict
    for keydata in await get_data_by_fields(
        db=AvailableDBS.keys, fieldnames=["keydesignation", "id"], fieldvalues=[keydesignation, keyid]
    ):
        return keydata

    return None


async def get_user_from_db_by_username(username: str) -> Optional[dict]:
    userdata: dict
    for userdata in await get_data_by_field(db=AvailableDBS.users, fieldname="username", fieldvalue=username):
        return userdata

    return None


async def get_user_from_db_by_id(id: UUID) -> Optional[dict]:
    userdata: dict
    for userdata in await get_data_by_key(db=AvailableDBS.users, keyvalue=id):
        return userdata

    return None


async def get_product_from_db_by_id(id: UUID) -> Optional[dict]:
    productdata: dict
    for productdata in await get_data_by_key(db=AvailableDBS.products, keyvalue=id):
        return productdata

    return None


async def get_all_products_from_db() -> List[dict]:
    ret: List[dict] = []
    productdata: dict
    for productdata in await get_all_data(db=AvailableDBS.products):
        ret.append(productdata)

    return ret


async def save_product(id: UUID, data: dict, new_product: bool = False) -> dict:
    logger.debug(f"{id=} {data=} {new_product=}")

    ret: dict

    if new_product:
        ret = await create_new_entry(db=AvailableDBS.products, key=id, data=data)
        return ret

    prev_data: List[dict] = await get_data_by_key(db=AvailableDBS.products, keyvalue=id)

    prev_data[0].update(**data)

    del prev_data[0]["key"]

    logger.debug(f"trying update with {prev_data[0]=} on {id=}")
    await update_data(db=AvailableDBS.products, key=id, full_data=prev_data[0])

    return prev_data[0]


async def delete_product(id: UUID) -> None:
    await delete_entry(db=AvailableDBS.products, key=id)


async def delete_user(id: UUID) -> None:
    await delete_entry(db=AvailableDBS.users, key=id)


async def save_user(id: UUID, username: str, data: dict, new_user: bool = False) -> dict:
    logger.debug(f"{id=} {data=} {new_user=}")

    ret: dict

    if new_user:
        user_exists: Optional[dict] = await get_user_from_db_by_username(username)

        if user_exists:
            raise ValueError(f"USER WITH THAT USERNAME ALREADY EXISTS! {username=}")

        ret = await create_new_entry(db=AvailableDBS.users, key=id, data=data)
        return ret

    prev_data: List[dict] = await get_data_by_key(AvailableDBS.users, keyvalue=id)
    # prev_data: List[dict] = await get_data_by_fields(db=AvailableDBS.users, fieldnames=["username", "id"], fieldvalues=[username, id])
    if len(prev_data) == 0 or prev_data[0]["username"] != username:
        raise RuntimeError(f"USERID,USERNAME MISMATCH IN DB! {id=} {username=}")

    prev_data[0].update(**data)

    del prev_data[0]["key"]

    await update_data(db=AvailableDBS.users, key=id, full_data=prev_data[0])

    return prev_data[0]


async def get_all_users_from_db() -> List[dict]:
    ret: List[dict] = []
    userdata: dict
    for userdata in await get_all_data(db=AvailableDBS.users):
        ret.append(userdata)

    return ret


def generate_pseudo_user_data() -> dict:
    import urllib.parse as ul
    from uuid import uuid4

    from vendingmachine.utils.auth import (
        create_password_hash,
        generate_random_bytes,
    )

    from faker import Faker
    from faker.providers.misc.en_US import Provider as MProvider
    from faker.providers.person.en_GB import Provider as PProvider

    fake = Faker()
    fake.add_provider(MProvider)
    fake.add_provider(PProvider)

    tt: str = ""  # ugly, but logging messes this up (at least) if loglevel is DEBUG
    ret: dict = {}
    for i in range(0, 10):
        pw: str = (
            fake.password(length=9, special_chars=False, digits=True, upper_case=True, lower_case=True) + f"-{i:02}"
        )
        hash: str = create_password_hash(pw)
        userid: UUID = uuid4()
        username: str = f"{fake.unique.name().replace(' ', '')}-{i:02}"

        line: dict = {
            "id": userid,
            "password_hashed": hash,
            "username": username,
            "usertype": "SELLER" if i % 4 == 3 else "BUYER",
            "password_plain_not_in_real_db": pw,
        }
        ret[userid] = line

        lstr: str = f'"{username}": {line}, \t#  \t{ul.quote_plus(pw)}'

        tt += lstr + "\n"

    print(tt)

    return ret


def generate_pseudo_keydata() -> dict:
    import vendingmachine.utils.auth as auth
    from vendingmachine.utils.auth import generate_random_bytes

    import jwtjwkhelper

    now: datetime.datetime = datetime.datetime.now(_tzberlin)

    tt: str = ""  # ugly, but logging messes this up (at least) if loglevel is DEBUG

    ret: dict = {}

    for i in range(0, 2):
        rsa: jwtjwkhelper.RSAKeyPairPEM = jwtjwkhelper.create_rsa_key_pairs_return_as_pem(amount=1)[0]
        keyid: str = auth.get_hash_of_str(
            rsa.publickey_pem
        )  # getting it from public part since that should als be able for anyone not possessing the private key-part

        line: dict = {
            "id": keyid,
            "created_at": now.isoformat(),
            "invalidated_at": None,
            "keydesignation": "RS256",
            "public": rsa.publickey_pem,
            "private": rsa.privatekey_pem,
            "password_encrypted": False,
        }
        ret[keyid] = line

        lstr: str = f'"{keyid}": {line},\n'
        tt += lstr

    for i in range(0, 2):
        key: str = generate_random_bytes()
        hkeyid: str = auth.get_hash_of_str(key)

        hline: dict = {
            "id": hkeyid,
            "created_at": now.isoformat(),
            "invalidated_at": None,
            "keydesignation": "HS256",
            "public": None,
            "private": key,
            "password_encrypted": False,
        }
        ret[hkeyid] = hline

        hlstr: str = f'"{hkeyid}": {hline},\n'
        tt += hlstr

    print(tt)

    return ret


def generate_pseudo_product_data(
    seller_id: UUID, amount: int = 5, amt_available: int = -1, cost: int = -1
) -> dict[str, dict]:
    from uuid import uuid4

    import faker_commerce
    from faker import Faker
    from faker.generator import random

    fake = Faker()

    fake.add_provider(faker_commerce.Provider)

    tt: str = ""  # ugly, but logging messes this up (at least) if loglevel is DEBUG

    ret: dict = {}

    for i in range(0, amount):
        productid: UUID = uuid4()
        product_name: str = fake.unique.ecommerce_name()

        _cost: int = random.choice([5, 10, 15, 20, 25])
        _amt: int = random.randint(0, 100)
        if amt_available > 0:
            _amt = amt_available

        if cost > 0:
            _cost = cost

        line: dict = {
            "id": productid,
            "amount_available": _amt,
            "product_name": product_name,
            "seller_id": seller_id,
            "cost": _cost,
        }

        ret[productid] = line

        lstr: str = f'"{productid}": {line},\n'
        tt += lstr

    print(tt)

    return ret


async def generate_pseudo_data_to_db() -> None:
    _pseudo_key_db = generate_pseudo_keydata()
    for key, values in _pseudo_key_db.items():
        await create_new_entry(db=AvailableDBS.keys, key=key, data=values)

    _pseudo_user_db = generate_pseudo_user_data()
    for key, values in _pseudo_user_db.items():
        logger.debug(f"{key=} {values=}")
        await create_new_entry(db=AvailableDBS.users, key=key, data=values)

    _pseudo_product_db = {}
    for us in _pseudo_user_db.values():
        if us["usertype"] == "SELLER":
            _me: dict = generate_pseudo_product_data(us["id"])
            _pseudo_product_db.update(_me)

    for key, values in _pseudo_product_db.items():
        await create_new_entry(db=AvailableDBS.products, key=key, data=values)


if __name__ == "__main__":
    asyncio.run(generate_pseudo_data_to_db())
