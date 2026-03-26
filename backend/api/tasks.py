from fastapi import APIRouter, Depends, File, Query, UploadFile
from fastapi.responses import RedirectResponse

from core.response import success_response
from core.security import get_current_user
from schemas.task import TaskListResponse, TaskStatusResponse, UrlSubmitRequest
from services.task_service import (
    create_upload_tasks,
    get_task_dynamic_result,
    get_task_file_download_url,
    create_url_tasks,
    get_task_detail,
    get_task_list,
    get_task_screenshot_redirect_url,
    get_task_static_result,
    get_task_status,
    parse_datetime_filter,
)


router = APIRouter(prefix="/api/tasks", tags=["tasks"])


@router.get("/ping")
async def tasks_ping(current_user: dict = Depends(get_current_user)):
    _ = current_user
    return success_response({"module": "tasks", "status": "ready"})


@router.post("/upload")
async def upload_tasks(
    files: list[UploadFile] = File(...),
    current_user: dict = Depends(get_current_user),
):
    results = create_upload_tasks(files, current_user["id"])
    return success_response({"items": results, "total": len(results)})


@router.post("/url")
async def submit_task_urls(
    payload: UrlSubmitRequest,
    current_user: dict = Depends(get_current_user),
):
    results = create_url_tasks(payload.urls, current_user["id"])
    task_ids = [item["task_id"] for item in results if item.get("success")]
    return success_response({"task_ids": task_ids, "items": results, "total": len(results)})


@router.get("")
async def list_task_items(
    md5: str | None = Query(default=None),
    name: str | None = Query(default=None),
    package: str | None = Query(default=None),
    status: str | None = Query(default=None),
    start: str | None = Query(default=None),
    end: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
):
    _ = current_user
    filters = {
        "md5": md5,
        "name": name,
        "package": package,
        "status": status,
        "start": parse_datetime_filter(start, "start"),
        "end": parse_datetime_filter(end, "end"),
    }
    items, total, normalized_page, normalized_size = get_task_list(filters, page, size)
    data = TaskListResponse(
        items=items,
        total=total,
        page=normalized_page,
        size=normalized_size,
    ).model_dump()
    return success_response(data)


@router.get("/{task_id}")
async def get_task(task_id: str, current_user: dict = Depends(get_current_user)):
    _ = current_user
    return success_response(get_task_detail(task_id))


@router.get("/{task_id}/status")
async def get_task_current_status(task_id: str, current_user: dict = Depends(get_current_user)):
    _ = current_user
    data = TaskStatusResponse(**get_task_status(task_id)).model_dump()
    return success_response(data)


@router.get("/{task_id}/dynamic")
async def get_task_dynamic(
    task_id: str,
    dynamic_page: int = Query(default=1, ge=1),
    dynamic_size: int = Query(default=20, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
):
    _ = current_user
    return success_response(
        get_task_dynamic_result(
            task_id=task_id,
            dynamic_page=dynamic_page,
            dynamic_size=dynamic_size,
        )
    )


@router.get("/{task_id}/screenshots/{seq}")
async def redirect_task_screenshot(
    task_id: str,
    seq: int,
    current_user: dict = Depends(get_current_user),
):
    _ = current_user
    url = get_task_screenshot_redirect_url(task_id, seq)
    return RedirectResponse(url=url, status_code=302)


@router.get("/{task_id}/static")
async def get_task_static(task_id: str, current_user: dict = Depends(get_current_user)):
    _ = current_user
    return success_response(get_task_static_result(task_id))


@router.get("/{task_id}/apk")
async def get_task_apk_download(task_id: str, current_user: dict = Depends(get_current_user)):
    _ = current_user
    return success_response(get_task_file_download_url(task_id, "apk"))


@router.get("/{task_id}/report")
async def get_task_report_download(task_id: str, current_user: dict = Depends(get_current_user)):
    _ = current_user
    return success_response(get_task_file_download_url(task_id, "report"))


@router.get("/{task_id}/pcap")
async def get_task_pcap_download(task_id: str, current_user: dict = Depends(get_current_user)):
    _ = current_user
    return success_response(get_task_file_download_url(task_id, "pcap"))
