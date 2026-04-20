from fastapi import APIRouter

from core.response import success_response
from schemas.task import BackendImportRequest
from services.task_service import create_backend_import_tasks


router = APIRouter(prefix="/api/internal/tasks", tags=["internal-tasks"])


@router.post("/import")
async def import_backend_tasks(payload: BackendImportRequest):
    batch_id, results = create_backend_import_tasks(
        [item.model_dump() for item in payload.items]
    )
    task_ids = [item["task_id"] for item in results if item.get("success")]
    return success_response(
        {
            "batch_id": batch_id,
            "task_ids": task_ids,
            "items": results,
            "total": len(results),
        }
    )
