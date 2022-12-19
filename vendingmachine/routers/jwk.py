from typing import List, Optional, Union, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status, Request
from loguru import logger

from vendingmachine.datastructures.models_and_schemas import RS256JWKSet, RS256JWKSetKey
from vendingmachine.utils.auth import retrieve_all_valid_RS256_keys

router = APIRouter(
    tags=["jwk"],
    responses={404: {"description": "Not found."}},
)


@router.get("/jwks.json", status_code=status.HTTP_200_OK, response_model=RS256JWKSet, response_model_exclude_none=True)
async def get_jwks(request: Request) -> RS256JWKSet:
    """
    returns jwkset
    """

    me_keyset: RS256JWKSet = await retrieve_all_valid_RS256_keys()

    return me_keyset
