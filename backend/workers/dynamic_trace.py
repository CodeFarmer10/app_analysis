from __future__ import annotations

import json
import logging
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from core.config import settings
from core.database import fetch_one, get_connection
from multi_main import Logger, run_task_with_planning
from phone_agent import PlanAgentConfig
from phone_agent.agent import AgentConfig
from phone_agent.adb.device import install_apk, uninstall_apk
from phone_agent.model import ModelConfig
from repositories.task_repo import get_static_result, get_task_by_id, update_task
from services.ip_geo_service import resolve_non_local_ip_country
from services.storage_service import storage_service
from workers.celery_app import celery_app
from workers.real_controller_tagging import run_real_controller_tagging
from workers.report import generate_report


logger = logging.getLogger(__name__)


def _format_dynamic_error(exc: Exception) -> str:
    """将异常对象格式化为动态溯源统一错误信息。"""
    text = str(exc).strip()
    return f"动态溯源失败: {text}" if text else "动态溯源失败: 未知错误"


def _clip_text(value: Any, limit: int) -> str | None:
    """将文本裁剪到数据库字段长度上限。"""
    if value is None:
        return None
    text = str(value)
    return text if len(text) <= limit else text[:limit]


def _parse_action_time(value: Any) -> datetime | None:
    """解析操作时间字符串为 datetime。"""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _parse_frida_event_time(value: Any) -> datetime | None:
    """解析 Frida 事件时间戳（秒级）为 datetime。"""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        timestamp = float(value)
    except (TypeError, ValueError):
        return None
    if timestamp <= 0:
        return None
    # 兼容潜在毫秒级时间戳
    if timestamp > 1_000_000_000_000:
        timestamp = timestamp / 1000.0
    try:
        return datetime.fromtimestamp(timestamp)
    except (OverflowError, OSError, ValueError):
        return None


def _to_json_text(value: Any) -> str | None:
    """将任意值转换为 JSON 文本，失败时退化为字符串 JSON。"""
    if value is None:
        return None
    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return json.dumps(str(value), ensure_ascii=False)


def _to_port(value: Any) -> int | None:
    """将端口字段安全转换为整数。"""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        port = int(text)
    except ValueError:
        return None
    if port < 0 or port > 65535:
        return None
    return port


def _fetch_device_serial(device_id: str) -> str | None:
    """按设备ID查询设备序列号。"""
    sql = """
        SELECT serial
        FROM devices
        WHERE id = %s
        LIMIT 1
    """
    row = fetch_one(sql, (device_id,))
    if not row:
        return None
    serial = str(row.get("serial") or "").strip()
    return serial or None


def _set_device_online(device_id: str) -> None:
    """释放设备占用状态，恢复为 online。"""
    with get_connection() as conn:
        with conn.cursor() as cursor:
            try:
                conn.begin()
                cursor.execute(
                    """
                    UPDATE devices
                    SET status = 'online',
                        current_task_id = NULL
                    WHERE id = %s
                    """,
                    (device_id,),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise


def _mark_task_failed(task_id: str, message: str) -> None:
    """将任务更新为 dynamic_failed 并记录错误。"""
    update_task(
        task_id,
        {
            "status": "dynamic_failed",
            "error_message": message,
        },
    )


def _resolve_result_root() -> Path:
    """获取动态溯源结果根目录，并确保目录存在。"""
    root = Path(settings.DYNAMIC_TRACE_RESULT_DIR)
    if not root.is_absolute():
        root = Path(__file__).resolve().parents[1] / root
    root.mkdir(parents=True, exist_ok=True)
    return root


def _prepare_result_dir(task_id: str) -> Path:
    """创建任务专属结果目录（已存在则重建）。"""
    result_dir = _resolve_result_root() / task_id
    if result_dir.exists():
        shutil.rmtree(result_dir, ignore_errors=True)
    result_dir.mkdir(parents=True, exist_ok=True)
    return result_dir


def _cleanup_downloaded_apk(local_apk_path: str) -> None:
    """清理下载到本地临时目录的 APK 文件。"""
    if not local_apk_path:
        return
    path = Path(local_apk_path)
    if path.exists():
        path.unlink(missing_ok=True)
    if path.parent.exists():
        shutil.rmtree(path.parent, ignore_errors=True)


def _load_operation_results(result_dir: Path) -> list[dict]:
    """读取并解析 operation_results.json。"""
    operation_file = result_dir / "operation_results.json"
    if not operation_file.exists():
        raise FileNotFoundError(f"未找到结果文件: {operation_file}")
    with operation_file.open("r", encoding="utf-8") as file_obj:
        payload = json.load(file_obj)
    if not isinstance(payload, list):
        raise ValueError("operation_results.json 格式错误，必须是数组")
    return payload


def _upload_result_file(
    task_id: str,
    file_type: str,
    file_path: Path | str | None,
) -> str | None:
    """将单个本地文件上传至 MinIO 并返回对象路径。"""
    if file_path is None:
        return None
    raw_text = str(file_path).strip()
    if not raw_text:
        return None

    target = Path(raw_text).resolve()
    if not target.exists() or not target.is_file():
        return None
    return storage_service.upload_task_file(task_id, file_type, str(target))


def _build_result_file_path(result_dir: Path, raw_path: Any) -> Path | None:
    """将截图路径组装为本地文件绝对路径（相对路径按 result_dir 拼接）。"""
    if raw_path is None:
        return None
    raw_text = str(raw_path).strip()
    if not raw_text:
        return None
    target = Path(raw_text)
    if not target.is_absolute():
        target = result_dir / target
    return target.resolve()


def _persist_trace_results(
    task_id: str,
    pcap_path: str | None,
    run_log_path: str | None,
    dynamic_rows: list[dict],
    traffic_rows: list[dict],
    frida_rows: list[dict],
) -> None:
    """在单事务中写入动态结果、流量日志并更新任务状态。"""
    dynamic_insert_sql = """
        INSERT INTO dynamic_results (
            id,
            task_id,
            seq,
            action,
            action_result,
            action_time,
            screenshot_before,
            screenshot_after,
            is_success
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    traffic_insert_sql = """
        INSERT INTO traffic_logs (
            id,
            task_id,
            dynamic_result_id,
            seq,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            domain,
            url,
            resolved_ip,
            ip_country,
            is_real_controller
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    frida_insert_sql = """
        INSERT INTO frida_logs (
            id,
            task_id,
            dynamic_result_id,
            seq,
            event_time,
            rule_id,
            class_name,
            method_name,
            signature,
            arg_index,
            arg_value,
            retval
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    with get_connection() as conn:
        with conn.cursor() as cursor:
            try:
                conn.begin()
                cursor.execute("DELETE FROM dynamic_results WHERE task_id = %s", (task_id,))
                cursor.execute("DELETE FROM traffic_logs WHERE task_id = %s", (task_id,))
                cursor.execute("DELETE FROM frida_logs WHERE task_id = %s", (task_id,))

                if dynamic_rows:
                    cursor.executemany(
                        dynamic_insert_sql,
                        [
                            (
                                item["id"],
                                item["task_id"],
                                item["seq"],
                                item["action"],
                                item["action_result"],
                                item["action_time"],
                                item["screenshot_before"],
                                item["screenshot_after"],
                                item["is_success"],
                            )
                            for item in dynamic_rows
                        ],
                    )
                if traffic_rows:
                    cursor.executemany(
                        traffic_insert_sql,
                        [
                            (
                                item["id"],
                                item["task_id"],
                                item["dynamic_result_id"],
                                item["seq"],
                                item["src_ip"],
                                item["dst_ip"],
                                item["src_port"],
                                item["dst_port"],
                                item["protocol"],
                                item["domain"],
                                item["url"],
                                item["resolved_ip"],
                                item["ip_country"],
                                item["is_real_controller"],
                            )
                            for item in traffic_rows
                        ],
                    )
                if frida_rows:
                    cursor.executemany(
                        frida_insert_sql,
                        [
                            (
                                item["id"],
                                item["task_id"],
                                item["dynamic_result_id"],
                                item["seq"],
                                item["event_time"],
                                item["rule_id"],
                                item["class_name"],
                                item["method_name"],
                                item["signature"],
                                item["arg_index"],
                                item["arg_value"],
                                item["retval"],
                            )
                            for item in frida_rows
                        ],
                    )
                cursor.execute(
                    """
                    UPDATE tasks
                    SET status = 'completed',
                        pcap_path = %s,
                        run_log_path = %s,
                        error_message = NULL
                    WHERE id = %s
                    """,
                    (pcap_path, run_log_path, task_id),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise


def _parse_operation_results(
    task_id: str,
    operation_results: list[dict],
    result_dir: Path,
) -> tuple[list[dict], list[dict], list[dict]]:
    """解析 operation_results 为 dynamic_rows、traffic_rows、frida_rows。"""
    dynamic_rows: list[dict] = []
    traffic_rows: list[dict] = []
    frida_rows: list[dict] = []

    for index, item in enumerate(operation_results):
        if not isinstance(item, dict):
            continue
        raw_seq = item.get("step_num", index)
        try:
            seq = int(raw_seq)
        except (TypeError, ValueError):
            seq = index

        before_path = _build_result_file_path(result_dir, item.get("before_screenshot_path"))
        after_path = _build_result_file_path(result_dir, item.get("after_screenshot_path"))
        screenshot_before = _upload_result_file(task_id, "screenshot", before_path)
        screenshot_after = _upload_result_file(task_id, "screenshot", after_path)

        dynamic_rows.append(
            {
                "id": str(uuid4()),
                "task_id": task_id,
                "seq": seq,
                "action": _clip_text(str(item.get("step") or f"step_{seq}"), 256) or f"step_{seq}",
                "action_result": _clip_text(item.get("message"), 512),
                "action_time": _parse_action_time(item.get("start_time")),
                "screenshot_before": screenshot_before,
                "screenshot_after": screenshot_after,
                "is_success": 1 if bool(item.get("successed", True)) else 0,
            }
        )
        dynamic_result_id = dynamic_rows[-1]["id"]

        traffic_logs = item.get("traffic_logs") or []
        if isinstance(traffic_logs, list):
            for packet in traffic_logs:
                if not isinstance(packet, dict):
                    continue
                src_ip = str(packet.get("src_ip") or "").strip()
                dst_ip = str(packet.get("dst_ip") or "").strip()
                if not src_ip or not dst_ip:
                    continue
                protocol = _clip_text(str(packet.get("protocol") or "UNKNOWN"), 32) or "UNKNOWN"
                ip_country = resolve_non_local_ip_country(src_ip, dst_ip)
                traffic_rows.append(
                    {
                        "id": str(uuid4()),
                        "task_id": task_id,
                        "dynamic_result_id": dynamic_result_id,
                        "seq": seq,
                        "src_ip": _clip_text(src_ip, 45),
                        "dst_ip": _clip_text(dst_ip, 45),
                        "src_port": _to_port(packet.get("src_port")),
                        "dst_port": _to_port(packet.get("dst_port")),
                        "protocol": protocol,
                        "domain": _clip_text(packet.get("domain"), 512),
                        "url": packet.get("url"),
                        "resolved_ip": _clip_text(packet.get("dns_ip"), 45),
                        "ip_country": _clip_text(ip_country, 128),
                        "is_real_controller": 0,
                    }
                )

        frida_events = item.get("frida_events") or []
        if isinstance(frida_events, list):
            for event in frida_events:
                if not isinstance(event, dict):
                    continue
                raw_arg_index = event.get("arg_index")
                try:
                    parsed_arg_index = int(raw_arg_index)
                except (TypeError, ValueError):
                    parsed_arg_index = None
                if parsed_arg_index is not None and parsed_arg_index < 0:
                    parsed_arg_index = None
                raw_arg_value = event.get("args")
                if isinstance(raw_arg_value, (dict, list)):
                    arg_value = _clip_text(_to_json_text(raw_arg_value), 65535)
                else:
                    arg_value = _clip_text(raw_arg_value, 65535)
                frida_rows.append(
                    {
                        "id": str(uuid4()),
                        "task_id": task_id,
                        "dynamic_result_id": dynamic_result_id,
                        "seq": seq,
                        "event_time": _parse_frida_event_time(event.get("timestamp")),
                        "rule_id": _clip_text(event.get("rule_id"), 128),
                        "class_name": _clip_text(event.get("class_name"), 256),
                        "method_name": _clip_text(event.get("method_name"), 128),
                        "signature": _clip_text(event.get("signature"), 512),
                        "arg_index": parsed_arg_index,
                        "arg_value": arg_value,
                        "retval": _clip_text(event.get("retval"), 65535),
                    }
                )

    if not dynamic_rows:
        raise ValueError("未解析到动态操作记录")
    return dynamic_rows, traffic_rows, frida_rows


def _raise_if_launch_crash(dynamic_rows: list[dict]) -> None:
    if not dynamic_rows:
        return
    first_row = dynamic_rows[0]
    action = str(first_row.get("action") or "").strip()
    action_result = str(first_row.get("action_result") or "").strip()
    is_success = int(first_row.get("is_success") or 0)
    if action == "打开应用" and is_success == 0 and "APP闪退" in action_result:
        raise RuntimeError("打开应用闪退")


def _upload_trace_files(task_id: str, result_dir: Path) -> tuple[str | None, str | None]:
    """上传动态流程产物文件并返回关键对象路径。"""
    _upload_result_file(task_id, "dynamic", result_dir / "operation_results.json")
    _upload_result_file(task_id, "dynamic", result_dir / "frida_events.json")
    _upload_result_file(task_id, "dynamic", result_dir / "real_controller_tagging.json")
    pcap_path = _upload_result_file(task_id, "pcap", result_dir / "capture.pcap")
    run_log_path = _upload_result_file(task_id, "log", result_dir / "run.log")
    return pcap_path, run_log_path


def _run_task_with_log(
    task_text: str,
    package_name: str,
    adb_device_id: str,
    result_dir: Path,
) -> str:
    """执行规划任务并将 stdout 写入 run.log。"""
    plan_model_config = ModelConfig(
        base_url=settings.PLAN_AGENT_BASE_URL,
        api_key=settings.PLAN_AGENT_API_KEY,
        model_name=settings.PLAN_AGENT_MODEL,
        extra_body={
            "enable_thinking": settings.PLAN_AGENT_ENABLE_THINKING,
            "thinking_budget": settings.PLAN_AGENT_THINKING_BUDGET,
        },
    )
    plan_agent_config = PlanAgentConfig(
        max_steps=settings.PLAN_AGENT_MAX_PLAN_STEPS,
        device_id=adb_device_id,
        result_dir=str(result_dir),
    )
    phone_model_config = ModelConfig(
        base_url=settings.PHONE_AGENT_BASE_URL,
        api_key=settings.PHONE_AGENT_API_KEY,
        model_name=settings.PHONE_AGENT_MODEL,
    )
    phone_agent_config = AgentConfig(
        max_steps=settings.PHONE_AGENT_MAX_STEPS,
        device_id=adb_device_id,
    )

    logger_output = Logger(str(result_dir / "run.log"))
    original_stdout = sys.stdout
    try:
        sys.stdout = logger_output
        return run_task_with_planning(
            task=task_text,
            package=package_name,
            plan_model_config=plan_model_config,
            plan_agent_config=plan_agent_config,
            phone_model_config=phone_model_config,
            phone_agent_config=phone_agent_config,
        )
    finally:
        sys.stdout = original_stdout
        logger_output.close()


def _extract_trace_context(task_id: str, task: dict, device_id: str) -> tuple[str, str, str]:
    """提取动态溯源所需的包名、APK路径和设备序列号。"""
    static_result = get_static_result(task_id) or {}
    package_name = str(static_result.get("package_name") or "").strip()
    apk_object_path = str(task.get("apk_path") or "").strip()
    adb_device_id = _fetch_device_serial(device_id)

    if not package_name:
        raise ValueError("静态结果缺少包名")
    if not apk_object_path:
        raise ValueError("任务缺少APK存储路径")
    if not adb_device_id:
        raise ValueError("设备缺少ADB序列号")
    return package_name, apk_object_path, adb_device_id


@celery_app.task(name="workers.dynamic_trace.trace_task")
def trace_task(task_id: str, device_id: str):
    """动态溯源主任务：执行、解析、入库、触发报告。"""
    task = get_task_by_id(task_id)
    if not task:
        logger.warning("dynamic trace ignored: task_id=%s not found", task_id)
        _set_device_online(device_id)
        return {"task_id": task_id, "device_id": device_id, "accepted": False, "reason": "task_not_found"}

    local_apk_path = ""
    package_name = ""
    adb_device_id = ""
    result_dir: Path | None = None
    app_installed = False

    try:
        package_name, apk_object_path, adb_device_id = _extract_trace_context(task_id, task, device_id)
        result_dir = _prepare_result_dir(task_id)
        local_apk_path = storage_service.download_to_temp(apk_object_path)

        install_ok, install_msg = install_apk(local_apk_path, device_id=adb_device_id, replace_existing=True)
        if not install_ok:
            raise RuntimeError(f"安装APK失败: {install_msg}")
        app_installed = True

        trace_result = _run_task_with_log(
            task_text=settings.DYNAMIC_TRACE_TASK_TEXT,
            package_name=package_name,
            adb_device_id=adb_device_id,
            result_dir=result_dir,
        )

        operation_results = _load_operation_results(result_dir)
        dynamic_rows, traffic_rows, frida_rows = _parse_operation_results(task_id, operation_results, result_dir)
        _raise_if_launch_crash(dynamic_rows)
        tagging_result, matched_traffic_count = run_real_controller_tagging(
            operation_results=operation_results,
            traffic_rows=traffic_rows,
            result_dir=result_dir,
            enabled=settings.REAL_CONTROLLER_TAGGING_ENABLED,
            model_base_url=settings.REAL_CONTROLLER_TAGGING_BASE_URL,
            model_api_key=settings.REAL_CONTROLLER_TAGGING_API_KEY,
            model_name=settings.REAL_CONTROLLER_TAGGING_MODEL,
        )
        pcap_path, run_log_path = _upload_trace_files(task_id, result_dir)
        _persist_trace_results(
            task_id=task_id,
            pcap_path=pcap_path,
            run_log_path=run_log_path,
            dynamic_rows=dynamic_rows,
            traffic_rows=traffic_rows,
            frida_rows=frida_rows,
        )
        try:
            generate_report.delay(task_id)
        except Exception as exc:  # pragma: no cover - runtime dependent
            logger.exception("dispatch report task failed task_id=%s err=%s", task_id, exc)

        return {
            "task_id": task_id,
            "device_id": device_id,
            "status": "completed",
            "result": trace_result,
            "c2_domains": tagging_result.get("c2_domains") or [],
            "c2_domain_reasons": tagging_result.get("c2_domain_reasons") or [],
            "real_controller_match_count": matched_traffic_count,
        }
    except Exception as exc:  # pragma: no cover - runtime dependent
        logger.exception("dynamic trace failed task_id=%s device_id=%s", task_id, device_id)
        _mark_task_failed(task_id, _format_dynamic_error(exc))
        return {
            "task_id": task_id,
            "device_id": device_id,
            "status": "dynamic_failed",
            "error": str(exc),
        }
    finally:
        if local_apk_path:
            _cleanup_downloaded_apk(local_apk_path)

        if result_dir and result_dir.exists():
            shutil.rmtree(result_dir, ignore_errors=True)

        if app_installed:
            uninstall_ok, uninstall_msg = uninstall_apk(package_name=package_name, device_id=adb_device_id)
            if not uninstall_ok:
                logger.warning(
                    "uninstall apk failed task_id=%s package=%s err=%s",
                    task_id,
                    package_name,
                    uninstall_msg,
                )

        _set_device_online(device_id)
