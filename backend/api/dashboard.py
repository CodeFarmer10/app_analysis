from fastapi import APIRouter

from core.response import success_response


router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/ping")
async def dashboard_ping():
    return success_response({"module": "dashboard", "status": "ready"})
