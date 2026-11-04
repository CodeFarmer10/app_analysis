from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from core.response import success_response
from core.security import get_current_admin, get_current_user
from repositories import family_recommendation_repo, family_repo
from services.family_recommendation import FRAUD_TYPES
from services.storage_service import storage_service
from workers.celery_app import celery_app
from workers.family_recommendations import generate_family_recommendations


router = APIRouter(prefix="/api/families", tags=["families"])
logger = logging.getLogger(__name__)


class RecommendationReview(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=500)
    type_code: str


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


@router.get("/recommendations/types")
async def list_recommendation_types(_admin: dict = Depends(get_current_admin)):
    return success_response({"items": [{"code": code, "name": name} for code, name in FRAUD_TYPES.items()]})


@router.get("/recommendations")
async def list_recommendations(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=9, ge=1, le=100),
    _current_user: dict = Depends(get_current_user),
):
    items, total = family_recommendation_repo.list_candidates(page, size)
    return success_response({"items": items, "total": total, "page": page, "size": size})


@router.post("/recommendations/generate")
async def generate_recommendations(_admin: dict = Depends(get_current_admin)):
    task = generate_family_recommendations.apply_async(queue="queue_family")
    return success_response({"jobId": task.id})


@router.get("/recommendations/jobs/{job_id}")
async def get_recommendation_job(job_id: str, _admin: dict = Depends(get_current_admin)):
    task = celery_app.AsyncResult(job_id)
    return success_response({
        "jobId": job_id,
        "status": task.state,
        "result": task.result if task.successful() else None,
        "progress": task.info if task.state == "PROGRESS" else None,
        "error": str(task.result)[:500] if task.failed() else None,
    })


@router.get("/recommendations/{recommendation_id}")
async def get_recommendation(recommendation_id: str, _current_user: dict = Depends(get_current_user)):
    candidate = family_recommendation_repo.get_candidate(recommendation_id)
    if not candidate:
        raise HTTPException(status_code=404, detail="候选家族不存在")
    return success_response(candidate)


@router.get("/recommendations/{recommendation_id}/members")
async def list_recommendation_members(
    recommendation_id: str,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
    _current_user: dict = Depends(get_current_user),
):
    if not family_recommendation_repo.get_candidate(recommendation_id):
        raise HTTPException(status_code=404, detail="候选家族不存在")
    items, total = family_recommendation_repo.list_candidate_members(recommendation_id, page, size)
    return success_response({
        "items": [_member_for_table(item) for item in items],
        "total": total, "page": page, "size": size,
    })


@router.post("/recommendations/{recommendation_id}/approve")
async def approve_recommendation(
    recommendation_id: str,
    draft: RecommendationReview,
    admin: dict = Depends(get_current_admin),
):
    name = draft.name.strip()
    description = draft.description.strip()
    if not name or draft.type_code not in FRAUD_TYPES:
        raise HTTPException(status_code=422, detail="模型名称或诈骗类型无效")
    try:
        model_id = family_recommendation_repo.approve_candidate(
            recommendation_id, str(admin["id"]), name, description,
            draft.type_code, FRAUD_TYPES[draft.type_code],
        )
    except family_recommendation_repo.RecommendationConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return success_response({"modelId": model_id})


@router.post("/recommendations/{recommendation_id}/reject")
async def reject_recommendation(recommendation_id: str, admin: dict = Depends(get_current_admin)):
    try:
        family_recommendation_repo.reject_candidate(recommendation_id, str(admin["id"]))
    except family_recommendation_repo.RecommendationConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return success_response({"status": "rejected"})


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
