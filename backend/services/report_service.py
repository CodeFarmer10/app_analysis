from __future__ import annotations

import base64
import logging
import mimetypes
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from repositories.task_repo import (
    get_static_result,
    get_task_by_id,
    list_dynamic_results,
    list_traffic_logs,
)
from services.storage_service import storage_service


logger = logging.getLogger(__name__)

TEMPLATE_NAME = "report.html"
TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "templates"


def _guess_image_content_type(object_name: str) -> str:
    guessed, _ = mimetypes.guess_type(object_name)
    if guessed and guessed.startswith("image/"):
        return guessed
    return "image/png"


def _build_image_data_uri(object_name: str | None) -> str | None:
    if not object_name:
        return None
    try:
        raw = storage_service.get_object_bytes(object_name)
    except Exception as exc:  # pragma: no cover - runtime dependent
        logger.warning("load screenshot failed: object=%s err=%s", object_name, exc)
        return None

    encoded = base64.b64encode(raw).decode("utf-8")
    content_type = _guess_image_content_type(object_name)
    return f"data:{content_type};base64,{encoded}"


def _format_datetime(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    text = str(value).strip()
    return text or "-"


def _build_report_context(task_id: str) -> dict[str, Any]:
    task = get_task_by_id(task_id)
    if not task:
        raise ValueError("任务不存在")

    static_result = get_static_result(task_id) or {}
    dynamic_results = list_dynamic_results(task_id)
    traffic_logs = list_traffic_logs(task_id)

    dynamic_items: list[dict[str, Any]] = []
    for item in dynamic_results:
        dynamic_items.append(
            {
                **item,
                "action_time_text": _format_datetime(item.get("action_time")),
                "screenshot_before_data_uri": _build_image_data_uri(item.get("screenshot_before")),
                "screenshot_after_data_uri": _build_image_data_uri(item.get("screenshot_after")),
            }
        )

    return {
        "task": task,
        "task_id": task_id,
        "file_md5": task.get("file_md5") or "-",
        "analysis_time": _format_datetime(task.get("updated_at") or task.get("created_at")),
        "static_result": static_result,
        "dynamic_results": dynamic_items,
        "traffic_logs": traffic_logs,
        "generated_at": _format_datetime(datetime.now()),
    }


def _render_report_html(context: dict[str, Any]) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template(TEMPLATE_NAME)
    return template.render(**context)


def generate_pdf(task_id: str) -> str:
    context = _build_report_context(task_id)
    rendered_html = _render_report_html(context)

    from weasyprint import HTML  # 延迟导入，避免运行环境缺少系统库时影响服务启动

    pdf_bytes = HTML(string=rendered_html, base_url=str(TEMPLATE_DIR)).write_pdf()

    object_name = storage_service.build_task_object_name(
        task_id,
        "report",
        f"{task_id}.pdf",
    )
    storage_service.upload_bytes(
        object_name=object_name,
        data=pdf_bytes,
        content_type="application/pdf",
    )
    return object_name
