from fastapi import APIRouter, Depends

from core.response import success_response
from core.security import get_current_user


router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.get("/ping")
async def devices_ping(current_user: dict = Depends(get_current_user)):
    _ = current_user
    return success_response({"module": "devices", "status": "ready"})
