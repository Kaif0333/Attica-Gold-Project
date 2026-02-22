import logging
import time
import uuid
from typing import Callable

from fastapi import Request

from app.settings import get_settings


def configure_logging() -> logging.Logger:
    settings = get_settings()
    level = getattr(logging, settings.log_level, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    return logging.getLogger("attica")


def request_logging_middleware(logger: logging.Logger) -> Callable:
    settings = get_settings()
    request_id_header = settings.request_id_header

    async def middleware(request: Request, call_next):
        request_id = request.headers.get(request_id_header) or str(uuid.uuid4())
        request.state.request_id = request_id
        started = time.perf_counter()
        response = await call_next(request)
        duration_ms = (time.perf_counter() - started) * 1000
        response.headers[request_id_header] = request_id
        logger.info(
            "request_id=%s method=%s path=%s status=%s duration_ms=%.2f",
            request_id,
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
        )
        return response

    return middleware
