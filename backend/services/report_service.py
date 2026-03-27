from __future__ import annotations

import base64
import io
import logging
import mimetypes
from datetime import datetime
from html import escape
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


def _text(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    text = str(value).strip()
    return text or "-"


def _build_pdf_with_reportlab(context: dict[str, Any]) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()
    body_style = styles["BodyText"]
    heading_style = styles["Heading2"]
    title_style = styles["Title"]

    # Prefer a built-in CJK font so Chinese text can be rendered without extra system fonts.
    font_name = "Helvetica"
    try:
        pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
        font_name = "STSong-Light"
    except Exception:  # pragma: no cover - runtime dependent
        pass

    for style in (body_style, heading_style, title_style):
        style.fontName = font_name

    task = context.get("task") or {}
    static_result = context.get("static_result") or {}
    dynamic_results = context.get("dynamic_results") or []
    traffic_logs = context.get("traffic_logs") or []

    story = [
        Paragraph("诈骗APP分析报告", title_style),
        Spacer(1, 12),
        Paragraph("任务信息", heading_style),
        Paragraph(f"任务ID: {escape(_text(task.get('id')))}", body_style),
        Paragraph(f"样本MD5: {escape(_text(context.get('file_md5')))}", body_style),
        Paragraph(f"任务状态: {escape(_text(task.get('status')))}", body_style),
        Paragraph(f"分析时间: {escape(_text(context.get('analysis_time')))}", body_style),
        Spacer(1, 10),
        Paragraph("静态结果", heading_style),
        Paragraph(f"应用名: {escape(_text(static_result.get('app_name')))}", body_style),
        Paragraph(f"包名: {escape(_text(static_result.get('package_name')))}", body_style),
        Paragraph(f"版本: {escape(_text(static_result.get('version_name')))}", body_style),
        Paragraph(f"权限数量: {len(static_result.get('permissions') or [])}", body_style),
        Spacer(1, 10),
        Paragraph("动态结果", heading_style),
        Paragraph(f"步骤数量: {len(dynamic_results)}", body_style),
    ]

    for item in dynamic_results[:80]:
        story.append(
            Paragraph(
                f"Step {escape(_text(item.get('seq')))} | "
                f"{escape(_text(item.get('action')))} | "
                f"{escape(_text(item.get('action_result')))}",
                body_style,
            )
        )

    story.extend(
        [
            Spacer(1, 10),
            Paragraph("流量日志", heading_style),
            Paragraph(f"记录数量: {len(traffic_logs)}", body_style),
        ]
    )

    for packet in traffic_logs[:120]:
        story.append(
            Paragraph(
                f"{escape(_text(packet.get('src_ip')))}:{escape(_text(packet.get('src_port')))}"
                f" -> {escape(_text(packet.get('dst_ip')))}:{escape(_text(packet.get('dst_port')))}"
                f" | {escape(_text(packet.get('protocol')))} | {escape(_text(packet.get('domain')))}",
                body_style,
            )
        )

    story.extend(
        [
            Spacer(1, 14),
            Paragraph(f"生成时间: {escape(_text(context.get('generated_at')))}", body_style),
            Paragraph("注: 当前报告为兼容模式生成。", body_style),
        ]
    )

    doc.build(story)
    return buffer.getvalue()


def generate_pdf(task_id: str) -> str:
    context = _build_report_context(task_id)
    rendered_html = _render_report_html(context)
    pdf_bytes: bytes
    try:
        from weasyprint import HTML  # 延迟导入，避免运行环境缺少系统库时影响服务启动

        pdf_bytes = HTML(string=rendered_html, base_url=str(TEMPLATE_DIR)).write_pdf()
    except Exception as exc:  # pragma: no cover - runtime dependent
        logger.warning("weasyprint unavailable, fallback to reportlab: %s", exc)
        pdf_bytes = _build_pdf_with_reportlab(context)

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
