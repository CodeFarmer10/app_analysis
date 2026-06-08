from __future__ import annotations

import base64
import io
import logging
import mimetypes
import re
import shutil
import subprocess
import tempfile
import time
from collections import Counter, defaultdict
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
from services.ip_geo_service import is_uplink_flow, pick_non_local_ip
from services.storage_service import storage_service


logger = logging.getLogger(__name__)

TEMPLATE_NAME = "report.html"
TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "templates"
CHROME_CANDIDATE_PATHS = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
]


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
    raw = _load_object_bytes(object_name, log_prefix="load image")
    if raw is None or not object_name:
        return None
    encoded = base64.b64encode(raw).decode("utf-8")
    return f"data:{_guess_image_content_type(object_name)};base64,{encoded}"


def _text(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    text = str(value).strip()
    return text or "-"


def _inline_text(value: Any) -> str:
    text = _text(value)
    if text == "-":
        return text
    sanitized = text.replace("\r\n", "\n").replace("\r", "\n")
    sanitized = "".join(
        ch if ch in "\n\t" or ord(ch) >= 32 else " "
        for ch in sanitized
    )
    sanitized = sanitized.replace("\n", " ").replace("\t", " ")
    sanitized = re.sub(r"\s+", " ", sanitized).strip()
    return sanitized or "-"


def _format_datetime(value: Any) -> str:
    return _text(value)


def _format_file_size(size: Any) -> str:
    try:
        value = float(size)
    except (TypeError, ValueError):
        return "-"
    if value < 0:
        return "-"
    units = ["B", "KB", "MB", "GB", "TB"]
    index = 0
    while value >= 1024 and index < len(units) - 1:
        value /= 1024
        index += 1
    if index == 0:
        return f"{int(value)} {units[index]}"
    return f"{value:.2f} {units[index]}"


def _format_source(task: dict[str, Any]) -> str:
    source_type_map = {
        "apk_upload": "APK上传",
        "url_download": "URL下载",
    }
    source_type = source_type_map.get(str(task.get("source_type") or "").strip(), "-")
    source_name = str(task.get("source_name") or "").strip()
    if source_name:
        return f"{source_type} / {source_name}"
    return source_type


def _safe_positive_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _build_operation_screenshot_object_name(item: dict[str, Any]) -> str | None:
    return item.get("screenshot_after") or item.get("screenshot_before")


def _is_uplink_packet(packet: dict[str, Any]) -> bool:
    raw_is_up = packet.get("is_up")
    if raw_is_up is not None:
        return bool(raw_is_up)
    src_ip = str(packet.get("src_ip") or "").strip()
    dst_ip = str(packet.get("dst_ip") or "").strip()
    return is_uplink_flow(src_ip, dst_ip)


def _normalize_permission_item(item: Any) -> dict[str, Any] | None:
    if isinstance(item, dict):
        name = str(item.get("name") or "").strip()
        if not name:
            return None
        return {
            "name": name,
            "is_dangerous": bool(item.get("is_dangerous")),
        }
    text = str(item or "").strip()
    if not text:
        return None
    return {
        "name": text,
        "is_dangerous": False,
    }


def _normalize_named_items(items: Any) -> list[str]:
    if not isinstance(items, list):
        return []
    results: list[str] = []
    seen: set[str] = set()
    for item in items:
        if isinstance(item, dict):
            name = str(item.get("name") or "").strip()
        else:
            name = str(item or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        results.append(name)
    return results


def _build_ratio_items(values: list[str], *, fallback_label: str, top_n: int = 10) -> list[dict[str, Any]]:
    normalized = [str(item or "").strip() or fallback_label for item in values]
    total = len(normalized)
    if total == 0:
        return []
    counter = Counter(normalized)
    sorted_items = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    if len(sorted_items) > top_n:
        head = sorted_items[:top_n]
        others_count = sum(count for _, count in sorted_items[top_n:])
        sorted_items = head + [("其他", others_count)]

    ratio_items: list[dict[str, Any]] = []
    for label, count in sorted_items:
        percent = round(count * 100 / total, 1)
        ratio_items.append(
            {
                "label": label,
                "count": count,
                "percent": percent,
                "percent_text": f"{percent:.1f}%",
                "bar_width": max(percent, 3),
            }
        )
    return ratio_items


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
        if not _is_uplink_packet(packet):
            continue

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
                "ip_country_text": _text(packet.get("ip_country")),
                "is_real_controller_text": "是" if packet.get("is_real_controller") else "否",
            }
        )

    for logs in step_logs.values():
        logs.sort(
            key=lambda item: (
                _safe_positive_int(item.get("seq")) or 0,
                str(item.get("id") or ""),
            )
        )
        for index, packet in enumerate(logs, start=1):
            packet["row_no"] = index
    return dict(step_logs)


def _build_real_controller_summary(traffic_logs: list[dict[str, Any]]) -> dict[str, Any]:
    targets: list[dict[str, Any]] = []
    seen_targets: set[tuple[str, str, str]] = set()

    for packet in traffic_logs:
        if not packet.get("is_real_controller"):
            continue

        domain_text = str(packet.get("domain") or "").strip() or "-"
        ip_text = str(
            pick_non_local_ip(packet.get("src_ip"), packet.get("dst_ip"))
            or packet.get("dst_ip")
            or ""
        ).strip() or "-"
        country_text = str(packet.get("ip_country") or "").strip() or "-"
        if domain_text == "-" and ip_text == "-":
            continue

        dedupe_key = (domain_text, ip_text, country_text)
        if dedupe_key in seen_targets:
            continue
        seen_targets.add(dedupe_key)
        targets.append(
            {
                "domain_text": domain_text,
                "ip_text": ip_text,
                "country_text": country_text,
            }
        )

    for index, item in enumerate(targets, start=1):
        item["row_no"] = index

    return {
        "targets": targets,
        "target_count": len(targets),
    }


def _build_report_context(task_id: str) -> dict[str, Any]:
    task = get_task_by_id(task_id)
    if not task:
        raise ValueError("任务不存在")

    static_result = get_static_result(task_id) or {}
    dynamic_results = sorted(list_dynamic_results(task_id), key=lambda item: _safe_positive_int(item.get("seq")) or 0)
    raw_traffic_logs = list_traffic_logs(task_id)
    uplink_traffic_logs = [item for item in raw_traffic_logs if _is_uplink_packet(item)]
    step_traffic_logs = _build_step_traffic_logs(dynamic_results, uplink_traffic_logs)
    real_controller_summary = _build_real_controller_summary(uplink_traffic_logs)

    permissions = []
    for raw_permission in static_result.get("permissions") or []:
        normalized_permission = _normalize_permission_item(raw_permission)
        if normalized_permission:
            permissions.append(normalized_permission)
    dangerous_permissions = [item for item in permissions if item.get("is_dangerous")]
    normal_permissions = [item for item in permissions if not item.get("is_dangerous")]

    activities = _normalize_named_items(static_result.get("activities"))
    services = _normalize_named_items(static_result.get("services"))
    providers = _normalize_named_items(static_result.get("providers"))
    so_files = _normalize_named_items(static_result.get("so_files"))

    operation_items: list[dict[str, Any]] = []
    success_step_count = 0
    failed_step_count = 0
    for item in dynamic_results:
        seq_num = _safe_positive_int(item.get("seq"))
        screenshot_object_name = _build_operation_screenshot_object_name(item)
        mapped_logs = step_traffic_logs.get(seq_num if seq_num is not None else -1, [])
        is_success = bool(item.get("is_success"))
        if is_success:
            success_step_count += 1
        else:
            failed_step_count += 1
        operation_items.append(
            {
                **item,
                "seq_text": _text(item.get("seq")),
                "action_text": _text(item.get("action")),
                "action_time_text": _format_datetime(item.get("action_time")),
                "status_text": "成功" if is_success else "失败",
                "status_class": "success" if is_success else "failed",
                "action_result_text": _text(item.get("action_result")),
                "screenshot_object_name": screenshot_object_name,
                "operation_screenshot_data_uri": _build_image_data_uri(screenshot_object_name),
                "step_traffic_logs": mapped_logs,
                "step_traffic_log_count": len(mapped_logs),
            }
        )

    protocol_ratio_items = _build_ratio_items(
        [str(item.get("protocol") or "").strip() for item in uplink_traffic_logs],
        fallback_label="-",
    )
    domain_ratio_items = _build_ratio_items(
        [str(item.get("domain") or "").strip() for item in uplink_traffic_logs],
        fallback_label="直接IP",
    )
    ip_ratio_items = _build_ratio_items(
        [str(item.get("dst_ip") or "").strip() for item in uplink_traffic_logs],
        fallback_label="-",
    )

    return {
        "task": task,
        "task_info": {
            "task_id": task_id,
            "file_md5": task.get("file_md5") or "-",
            "source": _format_source(task),
            "file_size": _format_file_size(task.get("file_size")),
            "status": _text(task.get("status")),
            "analysis_time": _format_datetime(task.get("updated_at") or task.get("created_at")),
        },
        "static_info": {
            "icon_path": static_result.get("icon_path"),
            "icon_data_uri": _build_image_data_uri(static_result.get("icon_path")),
            "app_name": _inline_text(static_result.get("app_name")),
            "package_name": _text(static_result.get("package_name")),
            "version_name": _text(static_result.get("version_name")),
            "version_code": _text(static_result.get("version_code")),
            "cert_md5": _text(static_result.get("cert_md5")),
            "cert_sha1": _text(static_result.get("cert_sha1")),
            "cert_sha256": _text(static_result.get("cert_sha256")),
            "dangerous_permissions": dangerous_permissions,
            "normal_permissions": normal_permissions,
            "activities": activities,
            "services": services,
            "providers": providers,
            "so_files": so_files,
            "activity_count": len(activities),
            "service_count": len(services),
            "provider_count": len(providers),
            "so_count": len(so_files),
        },
        "dynamic_summary": {
            "step_count": len(operation_items),
            "success_step_count": success_step_count,
            "failed_step_count": failed_step_count,
            "uplink_log_count": len(uplink_traffic_logs),
            "protocol_ratio_items": protocol_ratio_items,
            "domain_ratio_items": domain_ratio_items,
            "ip_ratio_items": ip_ratio_items,
            "real_controller_targets": real_controller_summary["targets"],
            "real_controller_target_count": real_controller_summary["target_count"],
        },
        "operation_items": operation_items,
        "appendix": {
            "dangerous_permissions": dangerous_permissions,
            "normal_permissions": normal_permissions,
            "activities": activities,
            "services": services,
            "providers": providers,
            "so_files": so_files,
        },
        "generated_at": _format_datetime(datetime.now()),
    }


def _render_report_html(context: dict[str, Any]) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template(TEMPLATE_NAME)
    return template.render(**context)


def _find_headless_browser() -> str | None:
    for candidate in CHROME_CANDIDATE_PATHS:
        if Path(candidate).is_file():
            return candidate
    for binary_name in ("google-chrome", "chromium", "chromium-browser", "msedge", "brave-browser"):
        resolved = shutil.which(binary_name)
        if resolved:
            return resolved
    return None


def _build_pdf_with_headless_browser(rendered_html: str) -> bytes:
    browser_path = _find_headless_browser()
    if not browser_path:
        raise RuntimeError("未找到可用的 Chromium/Chrome 浏览器")

    with tempfile.TemporaryDirectory(prefix="report_pdf_") as temp_dir:
        temp_root = Path(temp_dir)
        html_path = temp_root / "report.html"
        pdf_path = temp_root / "report.pdf"
        user_data_dir = temp_root / "chrome-profile"
        html_path.write_text(rendered_html, encoding="utf-8")

        cmd = [
            browser_path,
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-default-apps",
            "--disable-sync",
            "--metrics-recording-only",
            "--mute-audio",
            "--no-first-run",
            "--no-default-browser-check",
            "--allow-file-access-from-files",
            "--run-all-compositor-stages-before-draw",
            "--virtual-time-budget=2000",
            f"--user-data-dir={user_data_dir}",
            f"--print-to-pdf={pdf_path}",
            "--no-pdf-header-footer",
            html_path.resolve().as_uri(),
        ]
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        stable_rounds = 0
        previous_size = -1
        max_rounds = 120
        try:
            for _ in range(max_rounds):
                if pdf_path.exists():
                    current_size = pdf_path.stat().st_size
                    if current_size > 0 and current_size == previous_size:
                        stable_rounds += 1
                    else:
                        stable_rounds = 0
                    previous_size = current_size
                    if stable_rounds >= 2:
                        break
                if process.poll() is not None:
                    break
                time.sleep(1)

            if pdf_path.exists() and pdf_path.stat().st_size > 0:
                try:
                    process.terminate()
                except Exception:
                    pass
                try:
                    process.wait(timeout=5)
                except Exception:
                    try:
                        process.kill()
                    except Exception:
                        pass
                return pdf_path.read_bytes()

            stdout_text, stderr_text = process.communicate(timeout=5)
            error_text = (stderr_text or stdout_text or "").strip()
            raise RuntimeError(f"headless browser print failed: {error_text or 'PDF 文件未生成'}")
        finally:
            if process.poll() is None:
                try:
                    process.kill()
                except Exception:
                    pass


def _build_pdf_with_reportlab(context: dict[str, Any]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.lib.utils import ImageReader
    from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
    )

    styles = getSampleStyleSheet()
    body_style = styles["BodyText"]
    title_style = styles["Title"]
    small_style = ParagraphStyle("SmallText", parent=body_style, fontSize=9, leading=12, textColor=colors.HexColor("#334155"))
    meta_style = ParagraphStyle("MetaText", parent=body_style, fontSize=10, leading=14, textColor=colors.HexColor("#111827"))
    section_style = ParagraphStyle(
        "SectionTitle",
        parent=styles["Heading2"],
        fontSize=15,
        leading=18,
        textColor=colors.white,
        backColor=colors.HexColor("#1d4ed8"),
        borderPadding=6,
        spaceBefore=8,
        spaceAfter=10,
    )
    block_style = ParagraphStyle(
        "BlockTitle",
        parent=styles["Heading3"],
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#1e3a8a"),
        backColor=colors.HexColor("#e8f0ff"),
        borderPadding=5,
        spaceBefore=6,
        spaceAfter=6,
    )

    font_name = "Helvetica"
    heading_font_name = "Helvetica-Bold"
    try:
        pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
        font_name = "STSong-Light"
        heading_font_name = "STSong-Light"
    except Exception as exc:  # pragma: no cover - runtime dependent
        logger.warning("register reportlab cid font failed, fallback to Helvetica: %s", exc)

    for style in (body_style, small_style, meta_style):
        style.fontName = font_name
    for style in (title_style, section_style, block_style):
        style.fontName = heading_font_name

    title_style.fontSize = 20
    title_style.leading = 24
    title_style.textColor = colors.HexColor("#0f172a")

    def build_kv_table(rows: list[tuple[str, str]], label_width_mm: float = 28) -> Table:
        table = Table(
            [
                [Paragraph(escape(label), small_style), Paragraph(escape(value), meta_style)]
                for label, value in rows
            ],
            colWidths=[label_width_mm * mm, (182 - label_width_mm) * mm],
        )
        table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d7deea")),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        return table

    def build_list_paragraph(items: list[str], empty_text: str = "无") -> Paragraph:
        safe_items = items or [empty_text]
        html = "<br/>".join(escape(item) for item in safe_items)
        return Paragraph(html, meta_style)

    def build_ratio_table(title: str, items: list[dict[str, Any]]) -> list[Any]:
        story_items: list[Any] = [Paragraph(title, block_style)]
        rows = [[Paragraph("名称", small_style), Paragraph("数量", small_style), Paragraph("占比", small_style)]]
        for item in items or []:
            rows.append(
                [
                    Paragraph(escape(_text(item.get("label"))), small_style),
                    Paragraph(escape(_text(item.get("count"))), small_style),
                    Paragraph(escape(_text(item.get("percent_text"))), small_style),
                ]
            )
        if len(rows) == 1:
            rows.append([Paragraph("-", small_style), Paragraph("0", small_style), Paragraph("0.0%", small_style)])
        table = Table(rows, colWidths=[98 * mm, 24 * mm, 24 * mm], repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d7deea")),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story_items.extend([table, Spacer(1, 6)])
        return story_items

    def build_real_controller_table(title: str, items: list[dict[str, Any]]) -> list[Any]:
        story_items: list[Any] = [Paragraph(title, block_style)]
        rows = [
            [
                Paragraph("域名", small_style),
                Paragraph("IP", small_style),
                Paragraph("归属地", small_style),
            ]
        ]
        for item in items or []:
            rows.append(
                [
                    Paragraph(escape(_text(item.get("domain_text"))), small_style),
                    Paragraph(escape(_text(item.get("ip_text"))), small_style),
                    Paragraph(escape(_text(item.get("country_text"))), small_style),
                ]
            )
        if len(rows) == 1:
            rows.append(
                [
                    Paragraph("-", small_style),
                    Paragraph("-", small_style),
                    Paragraph("-", small_style),
                ]
            )
        table = Table(rows, colWidths=[62 * mm, 50 * mm, 34 * mm], repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d7deea")),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story_items.extend([table, Spacer(1, 6)])
        return story_items

    def build_image(object_name: str | None, max_width_mm: float, max_height_mm: float) -> list[Any]:
        if not object_name:
            return [Paragraph("未采集到截图", small_style)]
        raw = _load_object_bytes(object_name, log_prefix="load image for fallback pdf")
        if raw is None:
            return [Paragraph("图片加载失败", small_style)]
        try:
            image_reader = ImageReader(io.BytesIO(raw))
            width, height = image_reader.getSize()
        except Exception as exc:  # pragma: no cover - runtime dependent
            logger.warning("decode image failed object=%s err=%s", object_name, exc)
            return [Paragraph("图片解码失败", small_style)]
        scale = min((max_width_mm * mm) / width, (max_height_mm * mm) / height, 1)
        flowable = Image(io.BytesIO(raw), width=width * scale, height=height * scale)
        flowable.hAlign = "LEFT"
        return [flowable]

    def build_traffic_table(logs: list[dict[str, Any]]) -> Table:
        rows = [
            [
                Paragraph("序号", small_style),
                Paragraph("协议", small_style),
                Paragraph("源IP端口", small_style),
                Paragraph("目的IP端口", small_style),
                Paragraph("域名", small_style),
                Paragraph("归属地", small_style),
                Paragraph("URL", small_style),
                Paragraph("主控", small_style),
            ]
        ]
        for item in logs:
            rows.append(
                [
                    Paragraph(escape(_text(item.get("row_no"))), small_style),
                    Paragraph(escape(_text(item.get("protocol"))), small_style),
                    Paragraph(escape(_text(item.get("src_endpoint"))), small_style),
                    Paragraph(escape(_text(item.get("dst_endpoint"))), small_style),
                    Paragraph(escape(_text(item.get("domain"))), small_style),
                    Paragraph(escape(_text(item.get("ip_country_text"))), small_style),
                    Paragraph(escape(_text(item.get("url"))), small_style),
                    Paragraph(escape(_text(item.get("is_real_controller_text"))), small_style),
                ]
            )
        if len(rows) == 1:
            rows.append(
                [
                    Paragraph("-", small_style),
                    Paragraph("-", small_style),
                    Paragraph("-", small_style),
                    Paragraph("-", small_style),
                    Paragraph("-", small_style),
                    Paragraph("-", small_style),
                    Paragraph("当前步骤无关联流量日志", small_style),
                    Paragraph("-", small_style),
                ]
            )
        table = Table(
            rows,
            colWidths=[10 * mm, 16 * mm, 24 * mm, 24 * mm, 24 * mm, 16 * mm, 52 * mm, 10 * mm],
            repeatRows=1,
        )
        table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d7deea")),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        return table

    task_info = context.get("task_info") or {}
    static_info = context.get("static_info") or {}
    dynamic_summary = context.get("dynamic_summary") or {}
    operation_items = context.get("operation_items") or []
    appendix = context.get("appendix") or {}

    story: list[Any] = [
        Paragraph("APP分析报告", title_style),
        Spacer(1, 8),
        Paragraph("任务信息", section_style),
        build_kv_table(
            [
                ("任务ID", _text(task_info.get("task_id"))),
                ("样本MD5", _text(task_info.get("file_md5"))),
                ("来源", _text(task_info.get("source"))),
                ("大小", _text(task_info.get("file_size"))),
                ("任务状态", _text(task_info.get("status"))),
                ("分析时间", _text(task_info.get("analysis_time"))),
            ]
        ),
        Spacer(1, 10),
        Paragraph("静态信息", section_style),
    ]

    if static_info.get("icon_data_uri"):
        story.extend(build_image(static_info.get("icon_path"), 30, 30))
        story.append(Spacer(1, 6))

    story.extend(
        [
            build_kv_table(
                [
                    ("应用名称", _text(static_info.get("app_name"))),
                    ("包名", _text(static_info.get("package_name"))),
                    ("版本名", _text(static_info.get("version_name"))),
                    ("版本号", _text(static_info.get("version_code"))),
                    ("证书MD5", _text(static_info.get("cert_md5"))),
                    ("证书SHA1", _text(static_info.get("cert_sha1"))),
                    ("证书SHA256", _text(static_info.get("cert_sha256"))),
                ]
            ),
            Spacer(1, 6),
            Paragraph("权限清单（危险权限）", block_style),
            build_list_paragraph([item.get("name", "-") for item in static_info.get("dangerous_permissions") or []]),
            Spacer(1, 6),
            Paragraph("权限清单（普通权限）", block_style),
            build_list_paragraph([item.get("name", "-") for item in static_info.get("normal_permissions") or []]),
            Spacer(1, 6),
            build_kv_table(
                [
                    ("Activity 数量", _text(static_info.get("activity_count"))),
                    ("Service 数量", _text(static_info.get("service_count"))),
                    ("Provider 数量", _text(static_info.get("provider_count"))),
                    ("so 文件数量", _text(static_info.get("so_count"))),
                ]
            ),
            Spacer(1, 12),
            Paragraph("动态溯源", section_style),
            build_kv_table(
                [
                    ("步骤总数", _text(dynamic_summary.get("step_count"))),
                    ("成功步骤数", _text(dynamic_summary.get("success_step_count"))),
                    ("失败步骤数", _text(dynamic_summary.get("failed_step_count"))),
                    ("上行流量总条数", _text(dynamic_summary.get("uplink_log_count"))),
                    ("诈骗主控目标数", _text(dynamic_summary.get("real_controller_target_count"))),
                ]
            ),
            Spacer(1, 6),
        ]
    )

    story.extend(build_ratio_table("协议占比", dynamic_summary.get("protocol_ratio_items") or []))
    story.extend(build_ratio_table("域名占比", dynamic_summary.get("domain_ratio_items") or []))
    story.extend(build_ratio_table("IP占比", dynamic_summary.get("ip_ratio_items") or []))
    story.extend(
        build_real_controller_table(
            "诈骗主控（域名 / IP / 归属地）",
            dynamic_summary.get("real_controller_targets") or [],
        )
    )

    for item in operation_items:
        story.extend(
            [
                Spacer(1, 12),
                Paragraph("操作明细", section_style),
                Paragraph(f"步骤 {escape(_text(item.get('seq_text')))} / {escape(_text(item.get('action_text')))}", block_style),
                Spacer(1, 4),
            ]
        )
        story.extend(build_image(item.get("screenshot_object_name"), 120, 130))
        story.extend(
            [
                Spacer(1, 6),
                build_traffic_table(item.get("step_traffic_logs") or []),
            ]
        )

    story.extend(
        [
            Spacer(1, 12),
            Paragraph("附录", section_style),
            Paragraph("Activity 列表", block_style),
            build_list_paragraph(appendix.get("activities") or []),
            Spacer(1, 6),
            Paragraph("Service 列表", block_style),
            build_list_paragraph(appendix.get("services") or []),
            Spacer(1, 6),
            Paragraph("Provider 列表", block_style),
            build_list_paragraph(appendix.get("providers") or []),
            Spacer(1, 6),
            Paragraph("so 文件列表", block_style),
            build_list_paragraph(appendix.get("so_files") or []),
            Spacer(1, 12),
            Paragraph(f"生成时间：{escape(_text(context.get('generated_at')))}", small_style),
        ]
    )

    doc.build(story)
    return buffer.getvalue()


def generate_pdf(task_id: str) -> str:
    context = _build_report_context(task_id)
    rendered_html = _render_report_html(context)
    pdf_bytes = _build_pdf_with_headless_browser(rendered_html)

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S") + f"{int(time.time() * 1000) % 1000:03d}"
    object_name = storage_service.build_task_object_name(task_id, "report", f"{task_id}-{timestamp}.pdf")
    storage_service.upload_bytes(
        object_name=object_name,
        data=pdf_bytes,
        content_type="application/pdf",
    )
    return storage_service.build_object_url(object_name)
