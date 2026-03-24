from __future__ import annotations

import logging

from repositories.task_repo import get_task_by_id, update_task
from services.report_service import generate_pdf
from workers.celery_app import celery_app


logger = logging.getLogger(__name__)


@celery_app.task(name="workers.report.generate_report")
def generate_report(task_id: str):
    task = get_task_by_id(task_id)
    if not task:
        logger.warning("report task ignored: task_id=%s not found", task_id)
        return {"task_id": task_id, "accepted": False, "reason": "task_not_found"}

    try:
        report_path = generate_pdf(task_id)
        update_task(
            task_id,
            {
                "report_path": report_path,
                "error_message": None,
            },
        )
        return {
            "task_id": task_id,
            "status": "ok",
            "report_path": report_path,
        }
    except Exception as exc:  # pragma: no cover - runtime dependent
        logger.exception("report generation failed task_id=%s", task_id)
        update_task(
            task_id,
            {
                "error_message": f"报告生成失败: {str(exc).strip() or '未知错误'}",
            },
        )
        return {
            "task_id": task_id,
            "status": "failed",
            "error": str(exc),
        }
