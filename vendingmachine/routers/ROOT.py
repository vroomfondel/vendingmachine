import pathlib

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse, PlainTextResponse, RedirectResponse
from loguru import logger

from vendingmachine.utils.auth import responses_404

import aiofiles


mepath: pathlib.Path = pathlib.Path(__file__)
medir: pathlib.Path = mepath.parent
parentdir: pathlib.Path = medir.parent
startdir: pathlib.Path = parentdir.parent

logger.debug(f"{mepath=}\n{medir=}\n{parentdir=}\n{startdir=}")

router = APIRouter(default_response_class=PlainTextResponse)


@router.get("/", include_in_schema=False)
async def root_redirect() -> RedirectResponse:
    return RedirectResponse("/docs", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    # app.url_path_for(name='homepage')


license_path: pathlib.Path = pathlib.Path(startdir, "LICENSE.txt")
if license_path.exists() and license_path.is_file():

    @router.get("/license", tags=["license"], responses=responses_404)
    async def license() -> PlainTextResponse:
        """returns license file from directory as plain text"""
        async with aiofiles.open(license_path.absolute(), "r") as lfd:
            return PlainTextResponse(await lfd.read())

    logger.debug(f"ADDED /license to server PlainTextResponse from {license_path.absolute()}")
else:
    logger.debug(f"{license_path.absolute()} does not exist -> NOT mounting to /license")


static_path: pathlib.Path = pathlib.Path(parentdir, "static")
if static_path.exists() and static_path.is_dir():

    @router.get("/static/{file_path:path}", tags=["staticdir"], responses=responses_404)
    async def serve_static_file(file_path: str) -> FileResponse:
        f: pathlib.Path = pathlib.Path(static_path, file_path)
        if static_path in f.parents:
            if f.exists() and f.is_file():
                return FileResponse(f)
            else:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN
            )  # return forbidden if trying to break out of path

    logger.debug(f"ADDED /static to serve static content from {static_path.absolute()}")
else:
    logger.debug(f"{static_path.absolute()} does not exist -> NOT mounting to /static")
