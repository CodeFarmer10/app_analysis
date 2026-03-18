from fastapi import APIRouter

from core.response import success_response


router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.get("/ping")
async def devices_ping():
    return success_response({"module": "devices", "status": "ready"})
