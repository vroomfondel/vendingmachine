import os
from typing import Any, Dict, List, Optional, Union

from fastapi import Depends, FastAPI
from fastapi.encoders import jsonable_encoder
from fastapi.requests import Request
from fastapi.responses import JSONResponse, PlainTextResponse
from loguru import logger

from vendingmachine import routers

import vendingmachine.utils.configuration as conf

from vendingmachine.utils.configuration import settings


# logger.add(sys.stderr, filter=lambda record: record["module"] == __name__, level="DEBUG")    # TRACE | DEBUG | INFO | WARN | ERROR |  FATAL

__app_description = """
API-design for a vending machine, allowing users with a “seller” role to add, update or remove products, while users with a “buyer” 
role can deposit coins into the machine and make purchases. The vending machine only accepts 5, 10, 20, 50 and 100 cent coins.

- Used this as a basis for a fastapi-demo-app using OAUTH2-authorization with HS256 and/or RS256 signed JWT tokens with the 
possibiility of rotating keys and (in case of RS256) edge-verification of the JWT with only possessing the public-key.
- Used this to try out https://web.deta.sh/ as a simple demo-runtime-platform.

Tried to adhere:
- GET	A GET method (or GET request) is used to retrieve a representation of a resource. It should be used SOLELY for retrieving data and should not alter.
- PUT	A PUT method (or PUT request) is used to update a resource. For instance, if you know that a blog post resides at http://www.example.com/blogs/123, you can update this specific post
- by using the PUT method to put a new resource representation of the post.
- POST	A POST method (or POST request) is used to create a resource. For instance, when you want to add a new blog post but have no idea
- where to store it, you can use the POST method to post it to a URL and let the server decide the URL.
- PATCH	A PATCH method (or PATCH request) is used to modify a resource. It contains the changes to the resource, instead of the complete resource.
- DELETE	A DELETE method (or DELETE request) is used to delete a resource identified by a URI.

"""

__app_tags_metadata: List[Dict[str, Any]] = []


app = FastAPI(
    title="FastapiVendingMachine",
    description=__app_description,
    version="0.0.1",
    contact={"name": "Henning Thieß", "url": "https://github.com/vroomfondel"},
    license_info={"name": "MIT", "url": "https://github.com/vroomfondel/vendingmachine/LICENSE.txt"},
    openapi_tags=__app_tags_metadata,
)


@app.on_event("startup")
async def startup_event() -> None:
    if conf._startup_event_called:
        return None

    conf._startup_event_called = True

    logger.info("Calling startup event")

    from vendingmachine.datastructures.models_and_schemas import KeyDesignation
    from vendingmachine.utils import auth

    logger.debug(f"DETA_RUNTIME_DETECTED: {settings.deta_runtime_detected()}")
    logger.debug(f"TIMZEONE SET: {settings.TZ} || {os.getenv('TZ')}")

    if settings.JWT_KEYID == "AUTO":  # AUTO-setting matching keyid if KEYID is set to "AUTO"
        kdes: KeyDesignation = KeyDesignation[settings.JWT_ALGORITHM]
        keyid: Optional[str] = await auth.retrieve_AUTO_keyid(kdes)
        if not keyid:
            raise RuntimeError(f"Key with ID {keyid} and designation {kdes.value} not found.")
        settings.JWT_KEYID = keyid  # overwrite with selected...
        logger.info(f"AUTO-SELECTED KEYID={keyid} for JWT_ALGORITHM={kdes}")


if settings.deta_runtime_detected():
    conf._startup_event_callable = startup_event


app.include_router(routers.users, prefix="/users")
# app.include_router(routers.users, prefix="/user", deprecated=True)  # alias-"mount" - just because...

app.include_router(routers.deposit, prefix="/deposit")
app.include_router(routers.reset, prefix="/reset")

app.include_router(routers.products, prefix="/products")
# app.include_router(routers.products, prefix="/product", deprecated=True)  # alias-"mount"

app.include_router(routers.buy, prefix="/buy")


def _wants_explicitly_json_response(request: Request) -> bool:
    """little helper function to check the accept-header for accepting json"""
    ah: Optional[str] = request.headers.get("Accept")
    if ah and ah == "application/json":
        return True
    return False


@app.get("/healthz", tags=["k8s"])  # health-ping-endpoint | e.g. for k8s-deployment
async def healthz(
    wants_explicitly_json_response: bool = Depends(_wants_explicitly_json_response),
) -> Union[JSONResponse, PlainTextResponse]:
    """retuns alive => to be used as liveness-probe"""
    if wants_explicitly_json_response:
        return JSONResponse(content=jsonable_encoder({"status": "alive"}))
    else:
        # assuming plain/text
        return PlainTextResponse(content="status: alive")


@app.get("/ready", tags=["k8s"])  # ready-ping-endpoint | e.g. for k8s-deployment
async def health(
    wants_explicitly_json_response: bool = Depends(_wants_explicitly_json_response),
) -> Union[JSONResponse, PlainTextResponse]:
    """retuns ready => to be used as ready-probe"""
    if wants_explicitly_json_response:
        return JSONResponse(content=jsonable_encoder({"status": "ready"}))
    else:
        # assuming plain/text
        return PlainTextResponse(content="status: ready")


app.include_router(routers.ROOT)


@app.on_event("shutdown")
async def shutdown_event() -> None:
    logger.info("Calling shutdown event")
