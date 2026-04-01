from __future__ import annotations

import base64
import io
import logging
import mimetypes
from collections import defaultdict
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


def _load_object_bytes(object_name: str | None, *, log_prefix: str) -> bytes | None:
    if not object_name:
        return None
    try:
        return storage_service.get_object_bytes(object_name)
    except Exception as exc:  # pragma: no cover - runtime dependent
        logger.warning("%s failed: object=%s err=%s", log_prefix, object_name, exc)
        return None


def _build_image_data_uri(object_name: str | None) -> str | None:
    raw = _load_object_bytes(object_name, log_prefix="load screenshot")
    if raw is None or not object_name:
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


def _build_operation_screenshot_object_name(item: dict[str, Any]) -> str | None:
    return item.get("screenshot_after") or item.get("screenshot_before")


def _safe_positive_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _build_step_traffic_logs(
    dynamic_results: list[dict[str, Any]],
    traffic_logs: list[dict[str, Any]],
) -> dict[int, list[dict[str, Any]]]:
    dynamic_id_to_seq: dict[str, int] = {}
    valid_seqs: set[int] = set()
    for item in dynamic_results:
        seq_num = _safe_positive_int(item.get("seq"))
        if seq_num is None:
            continue
        valid_seqs.add(seq_num)
        dynamic_id = str(item.get("id") or "").strip()
        if dynamic_id:
            dynamic_id_to_seq[dynamic_id] = seq_num

    step_logs: dict[int, list[dict[str, Any]]] = defaultdict(list)
    seen_packet_ids: dict[int, set[str]] = defaultdict(set)
    for packet in traffic_logs:
        step_seq = None
        dynamic_result_id = str(packet.get("dynamic_result_id") or "").strip()
        if dynamic_result_id:
            step_seq = dynamic_id_to_seq.get(dynamic_result_id)
        if step_seq is None:
            seq_num = _safe_positive_int(packet.get("seq"))
            if seq_num is not None and seq_num in valid_seqs:
                step_seq = seq_num
        if step_seq is None:
            continue

        packet_id = str(packet.get("id") or "").strip()
        if packet_id and packet_id in seen_packet_ids[step_seq]:
            continue
        if packet_id:
            seen_packet_ids[step_seq].add(packet_id)

        step_logs[step_seq].append(
            {
                **packet,
                "src_endpoint": f"{_text(packet.get('src_ip'))}:{_text(packet.get('src_port'))}",
                "dst_endpoint": f"{_text(packet.get('dst_ip'))}:{_text(packet.get('dst_port'))}",
            }
        )

    return dict(step_logs)


def _build_report_context(task_id: str) -> dict[str, Any]:
    task = get_task_by_id(task_id)
    if not task:
        raise ValueError("任务不存在")

    static_result = get_static_result(task_id) or {}
    dynamic_results = list_dynamic_results(task_id)
    traffic_logs = list_traffic_logs(task_id)
    step_traffic_logs = _build_step_traffic_logs(dynamic_results, traffic_logs)
    permissions = static_result.get("permissions") or []
    if not isinstance(permissions, list):
        permissions = []

    dynamic_items: list[dict[str, Any]] = []
    for item in dynamic_results:
        seq_num = _safe_positive_int(item.get("seq"))
        screenshot_object_name = _build_operation_screenshot_object_name(item)
        mapped_logs = step_traffic_logs.get(seq_num if seq_num is not None else -1, [])
        dynamic_items.append(
            {
                **item,
                "action_time_text": _format_datetime(item.get("action_time")),
                "screenshot_object_name": screenshot_object_name,
                "operation_screenshot_data_uri": _build_image_data_uri(screenshot_object_name),
                "step_traffic_logs": mapped_logs,
                "step_traffic_log_count": len(mapped_logs),
            }
        )

    return {
        "task": task,
        "task_id": task_id,
        "file_md5": task.get("file_md5") or "-",
        "analysis_time": _format_datetime(task.get("updated_at") or task.get("created_at")),
        "static_result": {
            **static_result,
            "icon_data_uri": _build_image_data_uri(static_result.get("icon_path")),
            "permissions": permissions,
            "permissions_count": len(permissions),
        },
        "dynamic_results": dynamic_items,
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
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.utils import ImageReader
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont
    from reportlab.pdfbase.ttfonts import TTFont

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
    small_style = styles["BodyText"].clone("SmallBodyText")
    small_style.fontSize = 9
    small_style.leading = 12
    small_style.spaceAfter = 3
    meta_style = styles["BodyText"].clone("MetaBodyText")
    meta_style.fontSize = 10
    meta_style.leading = 14
    meta_style.spaceAfter = 2
    section_label_style = styles["Heading3"].clone("SectionLabel")
    section_label_style.fontSize = 12
    section_label_style.leading = 15
    section_label_style.spaceBefore = 6
    section_label_style.spaceAfter = 6

    # Prefer system Chinese fonts so section titles can use a visibly bolder weight.
    font_name = "Helvetica"
    heading_font_name = "Helvetica-Bold"
    preferred_font_pairs = [
        (
            "SystemChineseRegular",
            "/System/Library/Fonts/STHeiti Light.ttc",
            0,
            "SystemChineseBold",
            "/System/Library/Fonts/STHeiti Medium.ttc",
            0,
        ),
        (
            "SystemSongtiRegular",
            "/System/Library/Fonts/Supplemental/Songti.ttc",
            0,
            "SystemSongtiBold",
            "/System/Library/Fonts/Supplemental/Songti.ttc",
            1,
        ),
    ]
    for regular_name, regular_path, regular_index, bold_name, bold_path, bold_index in preferred_font_pairs:
        try:
            pdfmetrics.registerFont(TTFont(regular_name, regular_path, subfontIndex=regular_index))
            pdfmetrics.registerFont(TTFont(bold_name, bold_path, subfontIndex=bold_index))
            font_name = regular_name
            heading_font_name = bold_name
            break
        except Exception:  # pragma: no cover - runtime dependent
            continue
    try:
        if font_name == "Helvetica":
            pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
            font_name = "STSong-Light"
            heading_font_name = "STSong-Light"
    except Exception:  # pragma: no cover - runtime dependent
        pass

    title_style.fontSize = 20
    heading_style.fontSize = 15
    heading_style.leading = 18
    heading_style.backColor = colors.HexColor("#1d4ed8")
    heading_style.textColor = colors.white
    heading_style.borderPadding = 6
    heading_style.spaceBefore = 10
    heading_style.spaceAfter = 10
    body_style.fontSize = 11
    body_style.leading = 15
    body_style.spaceAfter = 3
    section_label_style.backColor = colors.HexColor("#dbeafe")
    section_label_style.textColor = colors.HexColor("#1e3a8a")
    section_label_style.borderPadding = 5
    section_label_style.spaceBefore = 8
    section_label_style.spaceAfter = 8
    for style in (body_style, small_style, meta_style):
        style.fontName = font_name
    for style in (heading_style, title_style, section_label_style):
        style.fontName = heading_font_name
    title_style.textColor = colors.HexColor("#111827")

    def _build_reportlab_image(
        object_name: str | None,
        title: str,
        *,
        max_width_mm: float,
        max_height_mm: float,
    ) -> list[Any]:
        if not object_name:
            return [Paragraph(f"{title}: 未采集到截图", small_style)]

        raw = _load_object_bytes(object_name, log_prefix="load screenshot for fallback pdf")
        if raw is None:
            return [Paragraph(f"{title}: 图片加载失败", small_style)]

        try:
            image_reader = ImageReader(io.BytesIO(raw))
            width, height = image_reader.getSize()
        except Exception as exc:  # pragma: no cover - runtime dependent
            logger.warning("decode screenshot failed: object=%s err=%s", object_name, exc)
            return [Paragraph(f"{title}: 图片解码失败", small_style)]

        max_width = max_width_mm * mm
        max_height = max_height_mm * mm
        scale = min(max_width / width, max_height / height, 1)
        flowable = Image(io.BytesIO(raw), width=width * scale, height=height * scale)
        flowable.hAlign = "LEFT"
        return [
            Paragraph(title, small_style),
            Spacer(1, 4),
            flowable,
        ]

    def _build_step_traffic_table(step_logs: list[dict[str, Any]]) -> Table:
        rows: list[list[Any]] = [
            [
                Paragraph("协议", small_style),
                Paragraph("域名/URL", small_style),
                Paragraph("源地址", small_style),
                Paragraph("目的地址", small_style),
            ]
        ]
        for packet in step_logs:
            rows.append(
                [
                    Paragraph(escape(_text(packet.get("protocol"))), small_style),
                    Paragraph(
                        escape(_text(packet.get("domain")))
                        + "<br/>"
                        + escape(_text(packet.get("url"))),
                        small_style,
                    ),
                    Paragraph(escape(_text(packet.get("src_endpoint"))), small_style),
                    Paragraph(escape(_text(packet.get("dst_endpoint"))), small_style),
                ]
            )

        table = Table(rows, colWidths=[18 * mm, 78 * mm, 38 * mm, 38 * mm], repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        return table

    def _build_kv_table(rows: list[tuple[str, str]], col_widths: list[float]) -> Table:
        table = Table(
            [
                [
                    Paragraph(escape(label), small_style),
                    Paragraph(escape(value), meta_style),
                ]
                for label, value in rows
            ],
            colWidths=col_widths,
        )
        table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
                ]
            )
        )
        return table

    def _build_permissions_paragraph(permissions: list[dict[str, Any]]) -> Paragraph:
        items: list[str] = []
        for permission in permissions:
            if not isinstance(permission, dict):
                continue
            name = _text(permission.get("name"))
            if permission.get("is_dangerous"):
                name = f"{name}(危险)"
            items.append(name)
        if not items:
            items.append("无")
        return Paragraph("<br/>".join(escape(item) for item in items), meta_style)

    task = context.get("task") or {}
    static_result = context.get("static_result") or {}
    dynamic_results = context.get("dynamic_results") or []

    story = [
        Paragraph("诈骗APP分析报告", title_style),
        Spacer(1, 12),
        Paragraph("任务信息", heading_style),
        _build_kv_table(
            [
                ("任务ID", _text(task.get("id"))),
                ("样本MD5", _text(context.get("file_md5"))),
                ("任务状态", _text(task.get("status"))),
                ("分析时间", _text(context.get("analysis_time"))),
            ],
            [28 * mm, 142 * mm],
        ),
        Spacer(1, 10),
        Paragraph("静态结果", heading_style),
    ]

    icon_section = _build_reportlab_image(
        static_result.get("icon_path"),
        "应用图标",
        max_width_mm=28,
        max_height_mm=28,
    )
    static_summary_table = _build_kv_table(
        [
            ("应用名称", _text(static_result.get("app_name"))),
            ("包名", _text(static_result.get("package_name"))),
            ("版本", f"{_text(static_result.get('version_name'))} ({_text(static_result.get('version_code'))})"),
            ("权限数量", _text(static_result.get("permissions_count"))),
        ],
        [28 * mm, 142 * mm],
    )
    story.extend(
        [
            *icon_section,
            Spacer(1, 8),
            static_summary_table,
            Spacer(1, 8),
            _build_kv_table(
                [
                    ("证书MD5", _text(static_result.get("cert_md5"))),
                    ("证书SHA1", _text(static_result.get("cert_sha1"))),
                    ("证书SHA256", _text(static_result.get("cert_sha256"))),
                ],
                [28 * mm, 142 * mm],
            ),
            Spacer(1, 8),
            Paragraph("权限信息", body_style),
            _build_permissions_paragraph(static_result.get("permissions") or []),
            Spacer(1, 10),
            Paragraph("动态结果", heading_style),
            Paragraph(f"步骤数量: {len(dynamic_results)}", body_style),
        ]
    )

    for item in dynamic_results[:80]:
        story.extend(
            [
                Spacer(1, 8),
                Paragraph(
                    f"步骤 {escape(_text(item.get('seq')))}  {escape(_text(item.get('action')))}",
                    body_style,
                ),
                _build_kv_table(
                    [
                        ("执行结果", _text(item.get("action_result"))),
                        ("执行时间", _text(item.get("action_time_text"))),
                        ("执行状态", "成功" if item.get("is_success") else "失败"),
                        ("关联流量日志", f"{_text(item.get('step_traffic_log_count'))} 条"),
                    ],
                    [28 * mm, 142 * mm],
                ),
                Spacer(1, 6),
            ]
        )
        story.extend(
            _build_reportlab_image(
                item.get("screenshot_object_name"),
                "操作截图",
                max_width_mm=120,
                max_height_mm=150,
            )
        )
        story.extend(
            [
                Spacer(1, 8),
                Paragraph("关联流量日志", section_label_style),
            ]
        )
        if item.get("step_traffic_logs"):
            story.append(_build_step_traffic_table(item.get("step_traffic_logs") or []))
        else:
            story.append(Paragraph("当前步骤无关联流量日志", meta_style))

    story.extend(
        [
            Spacer(1, 14),
            Paragraph(f"生成时间: {escape(_text(context.get('generated_at')))}", body_style),
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
