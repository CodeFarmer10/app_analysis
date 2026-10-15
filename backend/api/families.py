from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status

from core.response import success_response
from core.security import get_current_user
from repositories import family_repo
from services.storage_service import storage_service


router = APIRouter(prefix="/api/families", tags=["families"])
logger = logging.getLogger(__name__)


def _owner_user_id(current_user: dict) -> str | None:
    if str(current_user.get("role") or "").strip().lower() == "admin":
        return None
    user_id = str(current_user.get("id") or "").strip()
    if not user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="无权限访问任务")
    return user_id


def _member_for_table(item: dict) -> dict:
    row = dict(item)
    icon_path = row.pop("icon_path", None)
    row["can_download_apk"] = bool(row.pop("apk_path", None))
    row["can_download_report"] = bool(row.pop("report_path", None))
    row["can_download_pcap"] = bool(row.pop("pcap_path", None))
    row["icon_url"] = None
    if icon_path:
        try:
            row["icon_url"] = storage_service.get_download_url(icon_path)
        except Exception as exc:  # pragma: no cover - storage runtime dependent
            logger.warning("build family member icon url failed task_id=%s: %s", row.get("id"), exc)
    return row


@router.get("")
async def list_families(
    keyword: str | None = Query(default=None),
    type: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=9, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
):
    items, total = family_repo.list_families(
        owner_user_id=_owner_user_id(current_user),
        keyword=(keyword or "").strip() or None,
        fraud_type=(type or "").strip() or None,
        page=page,
        size=size,
    )
    return success_response({"items": items, "total": total, "page": page, "size": size})


@router.get("/types")
async def list_family_types(current_user: dict = Depends(get_current_user)):
    _owner_user_id(current_user)
    return success_response({"items": family_repo.list_family_types()})


@router.get("/{model_id}")
async def get_family(model_id: str, current_user: dict = Depends(get_current_user)):
    family = family_repo.get_family(model_id, _owner_user_id(current_user))
    if not family:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="家族不存在")
    return success_response(family)


@router.get("/{model_id}/members")
async def list_family_members(
    model_id: str,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
):
    owner_user_id = _owner_user_id(current_user)
    if not family_repo.get_family(model_id, owner_user_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="家族不存在")
    items, total = family_repo.list_family_members(model_id, owner_user_id, page, size)
    return success_response({
        "items": [_member_for_table(item) for item in items],
        "total": total,
        "page": page,
        "size": size,
    })
