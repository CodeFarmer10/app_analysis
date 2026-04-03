import asyncio
import logging
from contextlib import suppress

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.auth import router as auth_router
from api.dashboard import router as dashboard_router
from api.devices import router as devices_router
from api.tasks import router as tasks_router
from api.users import router as users_router
from core.config import settings
from core.response import success_response
from services.device_service import (
    HEARTBEAT_REFRESH_INTERVAL_SECONDS,
    refresh_all_device_heartbeats,
)
from services.storage_service import storage_service


logger = logging.getLogger(__name__)


app = FastAPI(
    title="Fraud APP Analysis Platform",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


async def _device_heartbeat_loop():
    while True:
        try:
            await asyncio.to_thread(refresh_all_device_heartbeats)
        except Exception as exc:  # pragma: no cover - runtime dependent
            logger.warning("device heartbeat loop error: %s", exc)
        await asyncio.sleep(HEARTBEAT_REFRESH_INTERVAL_SECONDS)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"code": exc.status_code, "message": exc.detail, "data": None},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"code": 422, "message": "validation error", "data": exc.errors()},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception: %s", exc)
    return JSONResponse(
        status_code=500,
        content={"code": 500, "message": "internal server error", "data": None},
    )


@app.on_event("startup")
async def startup_event():
    try:
        storage_service.ensure_buckets()
    except Exception as exc:
        logger.warning("Storage bootstrap skipped: %s", exc)
    app.state.device_heartbeat_task = asyncio.create_task(_device_heartbeat_loop())


@app.on_event("shutdown")
async def shutdown_event():
    heartbeat_task = getattr(app.state, "device_heartbeat_task", None)
    if heartbeat_task:
        heartbeat_task.cancel()
        with suppress(asyncio.CancelledError):
            await heartbeat_task


@app.get("/health")
async def health_check():
    return {"status": "ok"}


app.include_router(auth_router)
app.include_router(users_router)
app.include_router(tasks_router)
app.include_router(devices_router)
app.include_router(dashboard_router)
