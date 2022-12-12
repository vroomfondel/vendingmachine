import os
import pathlib
from pathlib import Path
from typing import Literal, Optional

from loguru import logger
from pydantic import BaseSettings, Field

import pytz


# logger.remove()
# logger.add(sys.stderr, level="INFO") # or sys.stdout or other file object

mepath: pathlib.Path = pathlib.Path(__file__)
medir: pathlib.Path = mepath.parent
parentdir: pathlib.Path = medir.parent
startdir: pathlib.Path = parentdir.parent

logger.debug(f"{mepath=}\n{medir=}\n{parentdir=}\n{startdir=}")


class Settings(BaseSettings):
    # https://pydantic-docs.helpmanual.io/usage/settings/
    JWT_TOKEN_URL: str = Field(default="/users/token")
    JWT_KEYID: str = Field(default="AUTO")  # aff575eed5ae0b2f3c3974e64e325b6391ddb6607491bdf28446a8dfde680692")
    JWT_ALGORITHM: Literal["HS256", "RS256"] = Field(default="RS256")
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30)
    JWT_REFRESH_TOKEN_EXPIRE_MINUTES: int = Field(default=10080)  # 1w
    LOGURU_LEVEL: str = Field(default="DEBUG")  # explicitely setting log-level to DEBUG if not set in ENV
    TZ: str = Field(default="Europe/Berlin")  # explicitely setting TZ in ENV to Europe/Berlin if unset
    DETA_RUNTIME: str = Field(default="False")
    DETA_PROJECT_KEY: Optional[str]

    def deta_runtime_detected(self) -> bool:
        print(f"{self.DETA_RUNTIME=}")
        return self.DETA_RUNTIME == "true"

    class Config:
        case_sensitive = True
        env_file = Path(startdir, ".detaSECRET")  # can be multiple files -> os.ENV has priority!


settings: Settings = Settings(TZ="Europe/Berlin")
if settings.deta_runtime_detected():
    logger.debug("DETA RUNTIME DETECTED.")

os.environ["TZ"] = settings.TZ
pytz.timezone(settings.TZ)  # ensure via error-raise, that TZ actually exists and is well-understood
