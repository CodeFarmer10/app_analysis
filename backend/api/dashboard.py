from fastapi import APIRouter, Depends

from core.response import success_response
from core.security import get_current_user


router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/ping")
async def dashboard_ping(current_user: dict = Depends(get_current_user)):
    _ = current_user
    return success_response({"module": "dashboard", "status": "ready"})
