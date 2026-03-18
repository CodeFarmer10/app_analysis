from fastapi import APIRouter

from core.response import success_response


router = APIRouter(prefix="/api/tasks", tags=["tasks"])


@router.get("/ping")
async def tasks_ping():
    return success_response({"module": "tasks", "status": "ready"})
