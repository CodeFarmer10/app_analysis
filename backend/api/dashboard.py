from fastapi import APIRouter, Depends, HTTPException, Query, status

from core.response import success_response
from core.security import get_current_user
from repositories.dashboard_repo import get_stats, get_trend


router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/ping")
async def dashboard_ping(current_user: dict = Depends(get_current_user)):
    _ = current_user
    return success_response({"module": "dashboard", "status": "ready"})


@router.get("/stats")
async def dashboard_stats(current_user: dict = Depends(get_current_user)):
    _ = current_user
    return success_response(get_stats())


@router.get("/trend")
async def dashboard_trend(
    days: int = Query(default=7, ge=1, le=30),
    current_user: dict = Depends(get_current_user),
):
    _ = current_user
    if days not in {7, 30}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="days 仅支持 7 或 30",
        )
    return success_response({"days": days, "items": get_trend(days), "total": days})
