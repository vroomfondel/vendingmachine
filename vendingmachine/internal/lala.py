import os
from typing import List, Optional, Tuple, Union
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.encoders import jsonable_encoder
from fastapi.requests import Request
from fastapi.responses import ORJSONResponse, PlainTextResponse
from loguru import logger

import pytz
from ..datastructures.models_and_schemas import RefreshToken


router = APIRouter(tags=["internal"], include_in_schema=False)


@router.post("/echojson")
async def echo(request: Request) -> dict:
    """echo back json received"""
    return await request.json()


# @router.get("")
# async def read_users(request: Request) -> Union[JSONResponse, PlainTextResponse]:
#     """get all users currently in 'DB'"""
#     ah: Optional[str] = request.headers.get("Accept")
#     if ah and ah == "application/json":
#         ret: List[dict] = []
#         values: dict
#         for values in await datapersistence.get_all_users_from_db():
#             ret.append(values.copy())
#
#         return JSONResponse(content=jsonable_encoder(ret))
#     else:
#         rets = ""
#         for values in await datapersistence.get_all_users_from_db():
#             for k, v in values.items():
#                 rets += f"{k}={v}\t"
#             rets += f"\n"
#
#         return PlainTextResponse(content=rets)
