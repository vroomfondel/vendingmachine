from vendingmachine.utils.configuration import settings

import datetime
import json
from enum import Enum, auto
from typing import Any, List, Optional, Union, cast
from uuid import UUID

from loguru import logger

import pytz
from deta import Deta
from deta.base import FetchResponse, _Base


logger.disable("vendingmachine.utils.detadbwrapper")

_tzberlin: datetime.tzinfo = pytz.timezone("Europe/Berlin")

deta = Deta(project_key=settings.DETA_PROJECT_KEY)


class ComplexEncoder(json.JSONEncoder):
    def default(self, obj: Any) -> Any:
        if hasattr(obj, "reprJSON"):
            return obj.reprJSON()
        elif type(obj) == UUID:
            obj = cast(UUID, obj)
            return str(obj)
        elif type(obj) == datetime.datetime:
            obj = cast(datetime.datetime, obj)
            return obj.isoformat()  # .strftime("%Y-%m-%d %H:%M:%S %Z")
        elif type(obj) == datetime.date:
            obj = cast(datetime.date, obj)
            return obj.strftime("%Y-%m-%d")
        elif type(obj) == datetime.timedelta:
            obj = cast(datetime.timedelta, obj)
            return str(obj)
        else:
            return json.JSONEncoder.default(self, obj)


class MStrEnum(str, Enum):
    """StrEnum is introduced in 3.11 and not available in runtime 3.9"""

    @staticmethod
    def _generate_next_value_(name: str, start: int, count: int, last_values: list) -> Any:
        return name


class AvailableDBS(MStrEnum):
    users: str = cast(str, auto())
    products: str = cast(str, auto())
    tokens_issued: str = cast(str, auto())
    tokens_deleted: str = cast(str, auto())
    keys: str = cast(str, auto())


_db_map: dict[str, _Base] = {}

m: AvailableDBS
for m in AvailableDBS:
    _db_map[m.name] = deta.Base(m.name)


def mangle(data: dict) -> dict:
    return json.loads(json.dumps(data, cls=ComplexEncoder))


async def update_data(
    db: AvailableDBS,
    key: Union[str, UUID],
    full_data: dict,
    expire_in: Optional[int] = None,
    expire_at: Optional[float] = None,
) -> None:
    _db: _Base = _db_map[db.name]
    _db.update(key=str(key), updates=mangle(full_data), expire_in=expire_in, expire_at=expire_at)


async def create_new_entry(
    db: AvailableDBS,
    key: Union[str, UUID],
    data: dict,
    expire_in: Optional[int] = None,
    expire_at: Optional[float] = None,
) -> Any:
    _db: _Base = _db_map[db.name]
    ret: Any = _db.insert(key=str(key), data=mangle(data), expire_in=expire_in, expire_at=expire_at)
    logger.debug(f"{type(ret)=} {ret=}")
    return ret


async def delete_entry(db: AvailableDBS, key: Union[str, UUID]) -> None:
    _db: _Base = _db_map[db.name]
    _db.delete(key=str(key))


async def get_data_by_field(db: AvailableDBS, fieldname: str, fieldvalue: Union[str, int, float, UUID]) -> List[dict]:
    return await get_data_by_fields(db=db, fieldnames=[fieldname], fieldvalues=[fieldvalue])


async def get_all_data(db: AvailableDBS) -> List[dict]:
    # qdict: dict[str, Union[int, float, str]] = {"key?ne": "___"}
    # logger.debug(f"{qdict=}")

    fetch_res: FetchResponse = _db_map[db.name].fetch()  # qdict)

    ret: List[dict] = []
    for item in fetch_res.items:
        logger.debug(f"{type(item)=} {item=}")
        ret.append(item)

    logger.debug(f" -> {len(ret)=}")

    return ret


async def get_data_by_fields(
    db: AvailableDBS, fieldnames: List[str], fieldvalues: List[Union[int, float, str, UUID]]
) -> List[dict]:
    qdict: dict[str, Union[int, float, str, UUID]] = {}
    for name, value in zip(fieldnames, fieldvalues):
        if type(value) == UUID:
            qdict[name] = str(value)
        else:
            qdict[name] = value

    logger.debug(f"{qdict=}")
    fetch_res: FetchResponse = _db_map[db.name].fetch(qdict)

    ret: List[dict] = []
    for item in fetch_res.items:
        logger.debug(f"{type(item)=} {item=}")
        ret.append(item)

    logger.debug(f" -> {len(ret)=}")

    return ret


async def get_data_by_key(db: AvailableDBS, keyvalue: Union[str, UUID]) -> List[dict]:
    fetch_res: FetchResponse = _db_map[db.name].get(str(keyvalue))
    logger.debug(f"{type(fetch_res)=}  {fetch_res=}")

    ret: List[dict] = []
    if fetch_res == None:
        return ret

    if type(fetch_res) == dict:
        ret.append(cast(dict, fetch_res))
    else:
        for item in fetch_res.items:
            logger.debug(f"{type(item)=} {item=}")
            ret.append(item)

    logger.debug(f" -> {len(ret)=}")

    return ret


# https://docs.deta.sh/docs/base/queries


def rekey_db(db: AvailableDBS, newkeyfieldname: str) -> None:
    """changes the key to the column's value of 'newkeyfieldname':
    => deletes the 'old' entry and insert the old entry under a new key
    """
    dbh: _Base = _db_map[db]

    fetch_res = dbh.fetch()

    todeletekeys: List[str] = []
    adds: List[dict] = []
    for item in fetch_res.items:
        todeletekeys.append(item["key"])
        del item["key"]
        adds.append(item)

    logger.debug(json.dumps(todeletekeys, indent=4))
    for key in todeletekeys:
        dbh.delete(key)

    logger.debug(json.dumps(adds, indent=4))
    for add in adds:
        dbh.insert(key=add[newkeyfieldname], data=add)


def clean_db(db: AvailableDBS) -> None:
    """deletes all rows from db"""
    dbh: _Base = _db_map[db]

    fetch_res = dbh.fetch()

    todeletekeys: List[str] = []
    adds: List[dict] = []
    for item in fetch_res.items:
        todeletekeys.append(item["key"])
        del item["key"]
        adds.append(item)

    logger.debug(json.dumps(todeletekeys, indent=4))
    for key in todeletekeys:
        dbh.delete(key)


if __name__ == "__main__":
    # rekey_db(AvailableDBS.users, "id")
    # clean_db(AvailableDBS.users)
    # exit(1)

    print("WOOHOO")
    # detabasetest()

    fetch_res = _db_map[AvailableDBS.users].fetch()

    for item in fetch_res.items:
        dd = None
        if "datetime" in item:
            dd = datetime.datetime.fromisoformat(item["datetime"])
        print(f"{item=} {dd}")
        # users.delete(item["key"])
