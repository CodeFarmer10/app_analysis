from fastapi import APIRouter

from core.response import success_response


router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.get("/ping")
async def auth_ping():
    return success_response({"module": "auth", "status": "ready"})
