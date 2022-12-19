from __future__ import annotations

import datetime
import re
from enum import Enum, IntEnum, auto
from typing import Any, List, Literal, Optional, Union, cast
from uuid import UUID, uuid4

from loguru import logger
from pydantic import BaseModel, Field, root_validator, validate_model, validator

from vendingmachine.utils.datapersistence import (
    delete_product,
    delete_user,
    get_all_products_from_db,
    get_all_users_from_db,
    get_product_from_db_by_id,
    get_user_from_db_by_id,
    get_user_from_db_by_username,
    save_product,
    save_user,
)
from vendingmachine.utils.configuration import settings


# usermododel -> buyer, seller and ADMIN ?!

_password_pattern = settings.PASSWORD_PATTERN
_password_pattern_compiled = re.compile(_password_pattern)

_username_pattern = settings.USERNAME_PATTERN
_username_pattern_compiled = re.compile(_username_pattern)


class MStrEnum(str, Enum):
    """StrEnum is introduced in 3.11 and not available in runtime 3.9"""

    @staticmethod
    def _generate_next_value_(name: str, start: int, count: int, last_values: list) -> Any:
        return name.upper()


class CoinType(IntEnum):
    """enum for the possible coins"""

    FIVE = 5
    TEN = 10
    TWENTY = 20
    FIFTY = 50
    HUNDRED = 100


class UserType(MStrEnum):
    """possible user-roles"""

    BUYER = auto()
    SELLER = auto()


class KeyDesignation(MStrEnum):
    """possible key-designations"""

    RS256 = auto()
    HS256 = auto()


class KeyDictEntry(BaseModel):
    """entry-format for the key-'database'"""

    id: str
    created_at: datetime.datetime
    invalidated_at: Optional[datetime.datetime]
    keydesignation: KeyDesignation
    public: Optional[str]
    private: Optional[str]
    password_encrypted: bool

    @root_validator(skip_on_failure=True)
    def check_private_or_public_key_present(cls, values: dict) -> dict:
        # logger.debug(values)
        assert values.get("private") or values.get("public")

        return values


# https://www.rfc-editor.org/rfc/rfc7517#section-4
class RS256JWKSetKey(BaseModel):
    alg: Literal["RS256"] = "RS256"
    kty: Literal["RSA"] = "RSA"
    use: Literal["sig"] = "sig"
    n: str
    e: str
    kid: str


class RS256JWKSet(BaseModel):
    keys: List[RS256JWKSetKey]


class RefreshToken(BaseModel):
    """just a model containing the 'refresh_token'"""

    refresh_token: str


class TokenWithRefreshToken(BaseModel):
    """
    the targeted token-format with access_token, refresh_token and
    token_type (which is assumed to always be 'Bearer')
    """

    access_token: str
    token_type: str
    refresh_token: str

    # scope: Literal['user:buyer', 'user:seller']  # check -> also scoping on this level


class TokenWithRefreshTokenAndMessage(TokenWithRefreshToken):
    """
    extension of the targeted token-format for being able to convey an additional 'message' to the api-user
    """

    message: Optional[str]


class UserSelf(BaseModel):
    """model for retrieving user-data which represents the user himitherself | more data visible"""

    id: UUID
    usertype: UserType
    username: str
    deposit: Optional[int] = None
    # products: Optional[List[Product]] = None


class UserOther(BaseModel):
    """restricted model for retrieving user-data which represents users not being the user himitherself"""

    id: UUID
    usertype: UserType


def _pydantic_username_validator(value: str) -> str:
    """extra validator for username-validation"""
    if not _username_pattern_compiled.match(value):
        raise ValueError("username pattern does not match")
    return value


class CheckableBaseModel(BaseModel):
    """
    base-model for pydantic-models being able to call the
    check-method anytime during the runtime/after their instantiation

    extended to be able to use field-name-alias as well as field-names for de-serializing
    """

    def check(self) -> None:
        *_, validation_error = validate_model(self.__class__, self.__dict__)
        if validation_error:
            raise validation_error

    class Config:
        allow_population_by_field_name = True


class UserName(CheckableBaseModel):
    """just a username-schema containing the pattern and limits"""

    username: str = Field(min_length=8, max_length=42, regex=_username_pattern)

    _username_validator = validator("username", pre=False, allow_reuse=True)(_pydantic_username_validator)


class UserPassword(CheckableBaseModel):
    """
    just a password
    """

    password: str = Field(min_length=7, max_length=42, regex=_password_pattern)


class UserWithNameAndType(UserName):
    """extension of the username-schema/model to also convey the user-type"""

    usertype: UserType


class UserWithPassword(UserWithNameAndType):
    """
    extension of the username+type-schema/model
    """

    password: str = Field(min_length=7, max_length=42, regex=_password_pattern)


class UserWithPasswordHashAndID(UserWithNameAndType):
    """the main representation for a user from DB"""

    id: UUID = Field(default_factory=uuid4)
    password_hashed: str

    @staticmethod
    def get_typed_user_from_dict(user: dict) -> Optional[Union[Buyer, Seller]]:
        if user["usertype"] == "BUYER":
            return Buyer(**user)
        elif user["usertype"] == "SELLER":
            return Seller(**user)
        else:
            return None

    @staticmethod
    async def get_user_from_db(
        username: Optional[UserName] = None, userid: Optional[UUID] = None
    ) -> Optional[Union[Buyer, Seller]]:  # sanitizes lookup via pydantic + validator
        assert (username and not userid) or (userid and not username), f"username XOR userid may be supplied"

        userdict: Optional[dict] = None
        if username:
            userdict = await get_user_from_db_by_username(username.username)
        elif userid:
            userdict = await get_user_from_db_by_id(userid)

        if userdict:
            return UserWithPasswordHashAndID.get_typed_user_from_dict(userdict)
        else:
            return None

    @staticmethod
    async def get_all_users_from_db() -> List[Union[Buyer, Seller]]:
        userdicts: List[dict] = await get_all_users_from_db()

        ret: List[Union[Buyer, Seller]] = []
        for ud in userdicts:
            r: Optional[Union[Seller, Buyer]] = UserWithPasswordHashAndID.get_typed_user_from_dict(ud)
            if r:
                ret.append(r)
            else:
                logger.error("UNKNOWN USERTYPE IN DB FOUND!!!")
        return ret

    async def save(self) -> Optional[Union[Buyer, Seller]]:
        data_saved: dict = await save_user(self.id, self.username, self.dict())

        if data_saved["usertype"] == "BUYER":
            retb: Buyer = cast(Buyer, self.copy(update=data_saved))
            return retb
        elif data_saved["usertype"] == "SELLER":
            rets: Seller = cast(Seller, self.copy(update=data_saved))
            return rets
        else:
            return None

    async def create_new(self) -> Optional[Union[Buyer, Seller]]:
        data_saved: dict = await save_user(self.id, self.username, self.dict(), new_user=True)

        if data_saved["usertype"] == "BUYER":
            retb: Buyer = cast(Buyer, self.copy(update=data_saved))
            return retb
        elif data_saved["usertype"] == "SELLER":
            rets: Seller = cast(Seller, self.copy(update=data_saved))
            return rets
        else:
            return None

    async def delete_me(self) -> None:
        await delete_user(self.id)


class Buyer(UserWithPasswordHashAndID):
    """
    buyer-usertype as extension to the base-user-db-type to
    also the users deposit and the fixed usertype-property
    """

    usertype: Literal[UserType.BUYER] = UserType.BUYER
    deposit: int = Field(
        0,
        ge=0,
        le=1000,  # The $1 coin is made of 92% copper, 6% aluminium and 2% nickel. It is circular in shape and has an interrupted milled edge. It weighs 9 grams and is 25 millimetres in diameter. => this already would weigh 9KGs MINIMUM
    )

    async def create_buyer(self) -> Buyer:
        ret: Buyer = cast(Buyer, await self.create_new())
        return ret


class Seller(UserWithPasswordHashAndID):
    """
    seller-usertype as extension to the base-user-db-type to
    also the users deposit and the fixed usertype-property
    """

    usertype: Literal[UserType.SELLER] = UserType.SELLER

    async def create_seller(self) -> Seller:
        ret: Seller = cast(Seller, await self.create_new())
        return ret


class Product(CheckableBaseModel):
    """product datatype for posting/patching product data"""

    amount_available: int = Field(0, ge=0, alias="amountAvailable")
    product_name: str = Field(min_length=2, max_length=1024, alias="productName", regex="^([a-zA-Z0-9]).*$")
    cost: int = Field(5, ge=5, multiple_of=5.0)


class ProductWithID(Product):
    """
    product datatype for usage from/to db
    """

    id: UUID = Field(default_factory=uuid4)
    seller_id: UUID = Field(alias="sellerId")

    @staticmethod
    async def get_product_from_db(productid: UUID) -> Optional[ProductWithID]:
        product_dict: Optional[dict] = await get_product_from_db_by_id(productid)
        logger.debug(f"{product_dict=}")
        if not product_dict:
            return None

        return ProductWithID(**product_dict)

    @staticmethod
    async def get_all_products_from_db() -> List[ProductWithID]:
        productdicts: List[dict] = await get_all_products_from_db()

        ret: List[ProductWithID] = []
        for pd in productdicts:
            p: ProductWithID = ProductWithID(**pd)
            ret.append(p)
        return ret

    @staticmethod
    async def delete_all_products_from_db_belonging_to_seller(sellerid: UUID) -> None:
        productdicts: List[dict] = await get_all_products_from_db()

        to_delete_products: List[ProductWithID] = []
        for pd in productdicts:
            p: ProductWithID = ProductWithID(**pd)
            if p.seller_id == sellerid:
                to_delete_products.append(p)
        for delprod in to_delete_products:
            await delprod.delete()

    async def save(self) -> ProductWithID:
        data_saved: dict = await save_product(self.id, self.dict())
        ret: ProductWithID = self.copy(update=data_saved)
        return ret

    async def delete(self) -> None:
        await delete_product(self.id)

    async def create_new(self) -> ProductWithID:
        data_saved: dict = await save_product(self.id, self.dict(), new_product=True)
        ret: ProductWithID = self.copy(update=data_saved)
        return ret


class Receipt(BaseModel):
    """
    data schema/model being used as the response for buying a product in
    multiple amounts and getting the remainder from the buyers-user deposit back
    """

    total_costs: int
    product_purchased: ProductWithID  # = Field(exclude={"amount_available"})  # exclude will not be excluded from documentation!
    change_returned_from_deposit: List[int] = Field(
        max_items=5, min_items=5
    )  # change returned (in an array of 5, 10, 20, 50 and 100 cent coins IN THAT ORDER!)
