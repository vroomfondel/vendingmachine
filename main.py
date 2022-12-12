import asyncio
import os

import vendingmachine
from vendingmachine import app
from vendingmachine.utils.configuration import settings

print(f"{type(app)=} {app=}")
print(f"{os.getenv('DETA_RUNTIME')=} {settings.deta_runtime_detected()=}")


def run_in_uvicorn() -> None:
    import uvicorn

    # mqtt.ensureConnect()
    uvicorn.run(
        "vendingmachine:app",
        proxy_headers=True,  # forwarded_allow_ips needed
        forwarded_allow_ips="*",  # Comma separated list of IPs to trust with proxy headers.
        # Defaults to the $FORWARDED_ALLOW_IPS
        # environment variable if available, or '127.0.0.1'. A wildcard '*' means always trust.
        host="0.0.0.0",
        port=18889,
        log_level="info",
        reload=True,
    )


if __name__ == "__main__":
    run_in_uvicorn()
