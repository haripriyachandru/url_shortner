"""FastAPI application entry point."""
from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import Response

from app.config import get_settings
from app.database import Base, SessionLocal, engine
from app.routers import links, redirect
from app.services import links as link_service
from app.services.cache import get_cache

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("safelink")


def _purge_once() -> int:
    with SessionLocal() as db:
        return link_service.purge_expired(db)


async def _purge_loop(interval: int) -> None:
    while True:
        await asyncio.sleep(interval)
        try:
            removed = await asyncio.to_thread(_purge_once)
            if removed:
                log.info("Purged %d expired links", removed)
        except Exception:
            log.exception("Purge job failed")


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    Base.metadata.create_all(engine)  # use Alembic migrations in a real production system
    settings = get_settings()
    if settings.secret_salt == "dev-only-change-me":
        log.warning("SECRET_SALT is the default value. Set a random one in production.")
    task = asyncio.create_task(_purge_loop(settings.purge_interval_seconds))
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


app = FastAPI(
    title="SafeLink",
    description="URL shortener with abuse protection: SSRF guard, risk scoring, blocklist, "
    "rate limiting, caching and click analytics.",
    version="1.0.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def security_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    if request.url.path.startswith("/api"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    return {"status": "ok", "cache": get_cache().kind}


app.include_router(links.router)
app.include_router(redirect.router)  # last: its /{code} route is a catch-all
