import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.auth import router as auth_router
from api.dashboard import router as dashboard_router
from api.devices import router as devices_router
from api.tasks import router as tasks_router
from core.config import settings
from core.response import success_response
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


@app.get("/health")
async def health_check():
    return {"status": "ok"}


app.include_router(auth_router)
app.include_router(tasks_router)
app.include_router(devices_router)
app.include_router(dashboard_router)
