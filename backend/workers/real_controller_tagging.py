from __future__ import annotations

import csv
import ipaddress
import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

from openai import OpenAI
from services.ip_geo_service import pick_non_local_ip


logger = logging.getLogger(__name__)
_WHITE_DOMAIN_PATH = Path(__file__).resolve().parents[1] / "tools" / "white_domain.csv"
_EXCLUDED_IP_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "142.250.0.0/15",
        "172.217.0.0/16",
        "173.194.0.0/16",
        "209.85.128.0/17",
        "216.58.192.0/19",
        "216.239.32.0/19",
    )
)


def _clip_text(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if len(text) <= limit else text[:limit]


def _normalize_domain(value: Any) -> str:
    return str(value or "").strip().strip(".").lower()


@lru_cache(maxsize=1)
def _load_white_domains() -> frozenset[str]:
    if not _WHITE_DOMAIN_PATH.exists():
        logger.warning("white domain csv not found: %s", _WHITE_DOMAIN_PATH)
        return frozenset()

    domains: set[str] = set()
    try:
        with _WHITE_DOMAIN_PATH.open("r", encoding="utf-8-sig", newline="") as file_obj:
            reader = csv.reader(file_obj)
            for row in reader:
                if not row:
                    continue
                domain = _normalize_domain(row[0])
                if not domain or domain == "domain":
                    continue
                domains.add(domain)
    except Exception as exc:  # pragma: no cover - runtime dependent
        logger.warning("load white domains failed path=%s err=%s", _WHITE_DOMAIN_PATH, exc)
        return frozenset()
    return frozenset(domains)


def _is_white_domain(value: Any) -> bool:
    domain = _normalize_domain(value)
    if not domain:
        return False

    white_domains = _load_white_domains()
    parts = domain.split(".")
    for index in range(len(parts)):
        candidate = ".".join(parts[index:])
        if candidate in white_domains:
            return True
    return False


def _normalize_country_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_ip_text(value: Any) -> str:
    return str(value or "").strip()


def _is_excluded_ip(value: Any) -> bool:
    ip_text = _normalize_ip_text(value)
    if not ip_text:
        return False
    try:
        parsed_ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    return any(parsed_ip in network for network in _EXCLUDED_IP_NETWORKS)


def _is_foreign_country(country_value: Any) -> bool:
    country = _normalize_country_text(country_value)
    if not country or country == "-":
        return False

    normalized = country.lower()
    domestic_names = {
        "中国",
        "中华人民共和国",
        "china",
        "people's republic of china",
        "cn",
    }
    return normalized not in domestic_names


def _is_tls_protocol(protocol_value: Any) -> bool:
    protocol = str(protocol_value or "").strip().upper()
    return "TLS" in protocol


def _safe_port(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if 0 <= parsed <= 65535 else None


def _pick_remote_port(packet: dict[str, Any]) -> int | None:
    src_ip = packet.get("src_ip")
    dst_ip = packet.get("dst_ip")
    target_ip = pick_non_local_ip(src_ip, dst_ip)
    src_text = str(src_ip or "").strip()
    dst_text = str(dst_ip or "").strip()
    if not target_ip:
        return None
    if target_ip == dst_text:
        return _safe_port(packet.get("dst_port"))
    if target_ip == src_text:
        return _safe_port(packet.get("src_port"))
    return None


_CRITICAL_OPERATION_KEYWORDS = (
    "打开",
    "注册",
    "登录",
    "登陆",
    "启动",
    "开始",
    "加入",
    "tab",
    "联系人",
    "首页",
    "我的",
    "下一步",
    "完成",
    "继续",
)


def _normalize_operation_text(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _is_critical_operation_text(value: Any) -> bool:
    text = _normalize_operation_text(value)
    if not text:
        return False
    return any(keyword in text for keyword in _CRITICAL_OPERATION_KEYWORDS)


def _build_step_operation_map(operation_results: list[dict[str, Any]]) -> dict[int, str]:
    step_map: dict[int, str] = {}
    for index, raw_step in enumerate(operation_results, start=1):
        if not isinstance(raw_step, dict):
            continue
        try:
            seq = int(raw_step.get("step_num"))
        except (TypeError, ValueError):
            seq = index
        operation_text = _clip_text(raw_step.get("step"), 256) or ""
        action_result = _clip_text(raw_step.get("message"), 512) or ""
        step_map[seq] = operation_text or action_result
    return step_map


def _build_real_controller_prompt(
    operation_results: list[dict],
) -> tuple[str, list[str], list[dict[str, Any]], str]:
    rare_tlds = [
        ".top",
        ".xyz",
        ".cc",
        ".pw",
        ".tk",
        ".icu",
        ".cyou",
        ".quest",
        ".sbs",
        ".click",
    ]
    step_summaries: list[dict[str, Any]] = []
    formatted_steps: list[str] = []
    candidate_domain_set: set[str] = set()

    for raw_step in operation_results:
        if not isinstance(raw_step, dict):
            continue
        try:
            seq = int(raw_step.get("step_num"))
        except (TypeError, ValueError):
            seq = len(step_summaries) + 1

        traffic_evidence: list[dict[str, str | int | None]] = []
        seen_traffic_keys: set[tuple[str, str]] = set()
        traffic_logs = raw_step.get("traffic_logs") or []
        if not isinstance(traffic_logs, list):
            traffic_logs = []
        for packet in traffic_logs:
            if not isinstance(packet, dict):
                continue
            domain = _clip_text(packet.get("domain"), 512)
            url = _clip_text(packet.get("url"), 1024)
            normalized_domain = (domain or "").strip()
            normalized_url = (url or "").strip()
            if not normalized_domain:
                continue
            if _is_white_domain(normalized_domain):
                continue
            candidate_domain_set.add(normalized_domain)
            dedup_key = (normalized_domain, normalized_url)
            if dedup_key in seen_traffic_keys:
                continue
            seen_traffic_keys.add(dedup_key)
            remote_ip = pick_non_local_ip(packet.get("src_ip"), packet.get("dst_ip"))
            remote_country = _clip_text(packet.get("ip_country"), 128)
            remote_port = _pick_remote_port(packet)
            protocol = _clip_text(packet.get("protocol"), 64)
            traffic_evidence.append(
                {
                    "domain": normalized_domain,
                    "url": normalized_url or None,
                    "ip": _clip_text(remote_ip, 45),
                    "country": remote_country,
                    "protocol": protocol,
                    "remote_port": remote_port,
                }
            )
            if len(traffic_evidence) >= 30:
                break

        hook_evidence: list[str] = []
        seen_hook_values: set[str] = set()
        frida_events = raw_step.get("frida_events") or []
        if not isinstance(frida_events, list):
            frida_events = []
        for event in frida_events[:120]:
            if not isinstance(event, dict):
                continue
            arg_value = _clip_text(event.get("args") or event.get("arg_value"), 1024)
            normalized_arg_value = (arg_value or "").strip()
            if not normalized_arg_value:
                continue
            if normalized_arg_value in seen_hook_values:
                continue
            seen_hook_values.add(normalized_arg_value)
            hook_evidence.append(normalized_arg_value)
            if len(hook_evidence) >= 40:
                break

        step_summary = {
            "seq": seq,
            "operation_step": _clip_text(raw_step.get("step"), 256),
            "traffic_logs": traffic_evidence,
            "frida_hooks": hook_evidence,
        }
        step_summaries.append(step_summary)

        traffic_lines: list[str] = []
        for idx, item in enumerate(traffic_evidence, start=1):
            traffic_lines.append(
                "  - "
                f"[{idx}] domain={item.get('domain') or '-'}"
                f" | ip={item.get('ip') or '-'}"
                f" | country={item.get('country') or '-'}"
                f" | protocol={item.get('protocol') or '-'}"
                f" | remote_port={item.get('remote_port') or '-'}"
                f" | url={item.get('url') or '-'}"
            )
        if not traffic_lines:
            traffic_lines.append("  - (无)")

        frida_lines: list[str] = []
        for idx, hook_arg_value in enumerate(hook_evidence, start=1):
            frida_lines.append(
                f"  - [{idx}] hook_value={hook_arg_value or '-'}"
            )
        if not frida_lines:
            frida_lines.append("  - (无)")

        formatted_steps.append(
            "\n".join(
                [
                    f"[Step {seq}]",
                    f"operation_step: {step_summary.get('operation_step') or '-'}",
                    "traffic_logs:",
                    *traffic_lines,
                    "frida_hooks:",
                    *frida_lines,
                ]
            )
        )

    candidate_domains: list[str] = sorted(candidate_domain_set)
    formatted_observations = "\n\n".join(formatted_steps) if formatted_steps else "(无步骤数据)"
    prompt = (
        "# Role\n"
        "你是一名资深反诈安全专家与流量分析工程师，负责识别App中的真实涉诈主控（C2）域名。\n\n"
        "# Task\n"
        "基于步骤操作、流量日志和Frida Hook数据，输出真实涉诈主控域名及每个域名的判定原因。\n\n"
        "# Decision Rules\n"
        "请按下列标准综合研判，命中越多越可疑：\n"
        "1. 语义强相关：在注册/登录/提交信息等关键步骤中，URL路径或Hook值出现 login/register/api/submit/user/token 等关键词。\n"
        "2. 高危后缀：域名后缀命中小众高危TLD（如 .top/.xyz/.cc/.pw/.tk/.click/.icu等）。\n"
        "3. 境外归属地增强：若域名对应的远端IP归属地为境外，则该域名作为涉诈主控的可能性更大。\n"
        "4. DGA特征：域名主体呈现随机字母数字混合、高熵、不可读等特征。\n"
        "5. 排除白名单：剔除系统流量与常见第三方SDK（百度地图/极光/微信/阿里云等）背景请求。\n\n"
        "# Hard Constraints\n"
        "1. 只能从给定 candidate_domains 中选择，不允许输出候选集外的域名。\n"
        "2. 每个输出域名必须给出非空 reason，且 reason 必须引用至少一条观测证据（步骤语义、URL、Hook值、IP或归属地）。\n"
        "3. 如果无有效目标，输出空数组。\n\n"
        "# Input Data（字段说明和值同块）\n"
        f"- rare_tlds（小众高危后缀列表）= {json.dumps(rare_tlds, ensure_ascii=False)}\n"
        f"- candidate_domains（候选域名，仅可从该列表中选择）= {json.dumps(candidate_domains, ensure_ascii=False)}\n"
        "- steps（按步骤对齐的观测数据；每步包含 operation_step / traffic_logs / frida_hooks）=\n"
        f"{formatted_observations}\n\n"
        "# Output Format constraints (严格遵守)\n"
        "1. 你的输出将被直接用于代码解析，绝不能包含任何解释性文本、推理过程或多余的标点。\n"
        "2. 绝不能使用 Markdown 的代码块标记（如 ```json 和 ```）。\n"
        "3. 必须输出严格、合法的 JSON 格式；如果未发现主控域名，也必须输出 {\"c2_domains\":[]}。\n"
        "4. c2_domains 必须是“对象数组”，每一项都必须包含 domain 与 reason 两个字段。\n"
        "5. reason 必须是明确的研判依据，不得为空，且包含至少一个具体证据点。\n"
        "6. 严禁输出字符串数组格式（例如 {\"c2_domains\":[\"a.top\"]} 这种是错误格式）。\n\n"
        "输出必须严格匹配以下 JSON Schema：\n"
        '{"c2_domains":[{"domain":"example1.top","reason":"命中登录接口且为高危后缀"},{"domain":"random88.xyz","reason":"步骤2登录接口命中且存在随机生成特征"}]}\n'
        '{"c2_domains":[]}\n'
    )
    return prompt, candidate_domains, step_summaries, formatted_observations


def _collect_white_domain_mapped_ips(traffic_rows: list[dict[str, Any]]) -> set[str]:
    excluded_ips: set[str] = set()
    for row in traffic_rows:
        domain = row.get("domain")
        if not _is_white_domain(domain):
            continue
        remote_ip = pick_non_local_ip(row.get("src_ip"), row.get("dst_ip"))
        remote_ip_text = _normalize_ip_text(remote_ip)
        if remote_ip_text:
            excluded_ips.add(remote_ip_text)
        resolved_ip_text = _normalize_ip_text(row.get("resolved_ip"))
        if resolved_ip_text:
            excluded_ips.add(resolved_ip_text)
    return excluded_ips


def _infer_real_controller_ips(
    traffic_rows: list[dict[str, Any]],
    *,
    operation_results: list[dict[str, Any]],
    excluded_ips: set[str],
) -> list[dict[str, str]]:
    grouped: dict[str, dict[str, Any]] = {}
    step_operation_map = _build_step_operation_map(operation_results)

    for row in traffic_rows:
        remote_ip = pick_non_local_ip(row.get("src_ip"), row.get("dst_ip"))
        if not remote_ip:
            continue
        if remote_ip in excluded_ips:
            continue
        if _is_excluded_ip(remote_ip):
            continue

        remote_country = _normalize_country_text(row.get("ip_country")) or "-"
        entry = grouped.setdefault(
            remote_ip,
            {
                "ip": remote_ip,
                "country": remote_country,
                "score": 0,
                "packet_count": 0,
                "flags": {
                    "foreign": False,
                    "udp": False,
                    "tls_non_443": False,
                },
                "critical_steps": [],
                "critical_operation_keys": set(),
            },
        )
        entry["packet_count"] += 1
        if entry["country"] == "-" and remote_country != "-":
            entry["country"] = remote_country

        if _is_foreign_country(remote_country) and not entry["flags"]["foreign"]:
            entry["flags"]["foreign"] = True
            entry["score"] += 1

        protocol = str(row.get("protocol") or "").strip().upper()
        if protocol == "UDP" and not entry["flags"]["udp"]:
            entry["flags"]["udp"] = True
            entry["score"] += 1

        remote_port = _pick_remote_port(row)
        if _is_tls_protocol(protocol) and remote_port not in {None, 443} and not entry["flags"]["tls_non_443"]:
            entry["flags"]["tls_non_443"] = True
            entry["score"] += 1

        seq_value = row.get("seq")
        try:
            seq_num = int(seq_value)
        except (TypeError, ValueError):
            seq_num = None
        operation_text = step_operation_map.get(seq_num or -1, "")
        if seq_num is not None and operation_text and _is_critical_operation_text(operation_text):
            operation_key = _normalize_operation_text(operation_text)
            step_label = f"步骤{seq_num}"
            step_reason = f"{step_label}（{_clip_text(operation_text, 80) or '-'}）"
            if operation_key and operation_key not in entry["critical_operation_keys"]:
                entry["critical_operation_keys"].add(operation_key)
                entry["critical_steps"].append(step_reason)
                entry["score"] += 2 if len(entry["critical_steps"]) == 1 else 1

    ip_reasons: list[dict[str, str]] = []
    sorted_candidates = sorted(
        grouped.values(),
        key=lambda item: (-int(item["score"]), -int(item["packet_count"]), str(item["ip"])),
    )
    for item in sorted_candidates:
        if int(item["score"]) <= 3:
            continue

        country_text = str(item["country"] or "-")
        if item["flags"]["foreign"]:
            reasons = [f"IP归属地为境外（{country_text}）"]
        else:
            reasons = [f"IP归属地为{country_text}"]
        if item["flags"]["udp"]:
            reasons.append("命中过UDP协议")
        if item["flags"]["tls_non_443"]:
            reasons.append("命中过TLS协议且远端端口不为443")
        if item["critical_steps"]:
            reasons.append(
                "出现在关键操作步骤"
                f"（{'、'.join(str(step) for step in item['critical_steps'][:3])}）"
            )

        ip_reasons.append(
            {
                "ip": str(item["ip"]),
                "country": str(item["country"] or "-"),
                "reason": "；".join(reasons),
            }
        )

    return ip_reasons


def _parse_real_controller_response(
    raw_content: str,
    candidate_domains: list[str],
) -> tuple[list[str], list[dict[str, str]]]:
    content = (raw_content or "").strip()
    if not content:
        return [], []

    parsed: dict[str, Any] | None = None
    try:
        maybe = json.loads(content)
        if isinstance(maybe, dict):
            parsed = maybe
    except json.JSONDecodeError:
        start = content.find("{")
        end = content.rfind("}")
        if start >= 0 and end > start:
            try:
                maybe = json.loads(content[start : end + 1])
                if isinstance(maybe, dict):
                    parsed = maybe
            except json.JSONDecodeError:
                parsed = None

    raw_domains: Any = []
    if parsed:
        raw_domains = parsed.get("c2_domains") or []

    if not isinstance(raw_domains, list):
        raw_domains = []

    candidate_set = {item for item in candidate_domains if item}
    domains: list[str] = []
    domain_reasons: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in raw_domains:
        if not isinstance(item, dict):
            continue
        domain = str(item.get("domain") or "").strip()
        reason = _clip_text(item.get("reason"), 2048) or ""
        if not domain or domain in seen:
            continue
        if not reason:
            continue
        if domain in candidate_set:
            domains.append(domain)
            domain_reasons.append({"domain": domain, "reason": reason})
            seen.add(domain)
    return domains[:5], domain_reasons[:5]


def _infer_real_controller_domains(
    operation_results: list[dict],
    *,
    enabled: bool,
    model_base_url: str,
    model_api_key: str,
    model_name: str,
) -> dict[str, Any]:
    if not enabled:
        return {
            "enabled": False,
            "status": "disabled",
            "c2_domains": [],
            "c2_domain_reasons": [],
            "candidate_domains": [],
            "formatted_observations": "",
            "model_output": "",
        }
    if not operation_results:
        return {
            "enabled": True,
            "status": "no_operation_results",
            "c2_domains": [],
            "c2_domain_reasons": [],
            "candidate_domains": [],
            "formatted_observations": "",
            "model_output": "",
        }

    prompt, candidate_domains, step_summaries, formatted_observations = _build_real_controller_prompt(
        operation_results=operation_results,
    )
    if not candidate_domains:
        return {
            "enabled": True,
            "status": "no_domain_candidates",
            "c2_domains": [],
            "c2_domain_reasons": [],
            "candidate_domains": [],
            "formatted_observations": formatted_observations,
            "model_output": "",
            "step_count": len(step_summaries),
        }

    try:
        client = OpenAI(
            base_url=model_base_url,
            api_key=model_api_key,
        )
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "你是严谨的反诈安全分析专家，仅输出JSON结果。"
                        "c2_domains必须为对象数组，每个对象都必须含domain与reason，"
                        "禁止输出字符串数组。"
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            top_p=0.9,
            extra_body={"enable_thinking": False},
        )
        raw_content = _clip_text(
            (response.choices[0].message.content if response and response.choices else "") or "",
            65535,
        ) or ""
        domains, domain_reasons = _parse_real_controller_response(
            raw_content=raw_content,
            candidate_domains=candidate_domains,
        )
        return {
            "enabled": True,
            "status": "ok",
            "c2_domains": domains,
            "c2_domain_reasons": domain_reasons,
            "candidate_domains": candidate_domains,
            "formatted_observations": formatted_observations,
            "model_output": raw_content,
            "step_count": len(step_summaries),
        }
    except Exception as exc:  # pragma: no cover - runtime dependent
        logger.warning("real controller inference failed: %s", exc)
        return {
            "enabled": True,
            "status": "inference_failed",
            "c2_domains": [],
            "c2_domain_reasons": [],
            "candidate_domains": candidate_domains,
            "formatted_observations": formatted_observations,
            "model_output": "",
            "error": _clip_text(str(exc), 2048),
            "step_count": len(step_summaries),
        }


def _tag_traffic_rows_with_real_controller(
    traffic_rows: list[dict[str, Any]],
    c2_domains: list[str],
    c2_ips: list[str],
) -> int:
    c2_domain_set = {str(item).strip() for item in c2_domains if str(item).strip()}
    c2_ip_set = {str(item).strip() for item in c2_ips if str(item).strip()}
    if not traffic_rows:
        return 0

    matched_count = 0
    for row in traffic_rows:
        domain = str(row.get("domain") or "").strip()
        if c2_domain_set:
            if domain and domain in c2_domain_set:
                matched_count += 1
                row["is_real_controller"] = 1
            else:
                row["is_real_controller"] = 0
        else:
            remote_ip = pick_non_local_ip(row.get("src_ip"), row.get("dst_ip"))
            if remote_ip and remote_ip in c2_ip_set:
                matched_count += 1
                row["is_real_controller"] = 1
            else:
                row["is_real_controller"] = 0
    return matched_count


def _write_real_controller_tagging_result(result_dir: Path, payload: dict[str, Any]) -> None:
    output = result_dir / "real_controller_tagging.json"
    file_payload = {
        "candidate_domains": payload.get("candidate_domains") or [],
        "formatted_observations": payload.get("formatted_observations") or "",
        "model_output": payload.get("model_output") or "",
        "c2_domains": payload.get("c2_domains") or [],
        "c2_domain_reasons": payload.get("c2_domain_reasons") or [],
        "c2_ips": payload.get("c2_ips") or [],
        "c2_ip_reasons": payload.get("c2_ip_reasons") or [],
        "tagging_basis": payload.get("tagging_basis") or "",
    }
    output.write_text(json.dumps(file_payload, ensure_ascii=False, indent=2), encoding="utf-8")


def run_real_controller_tagging(
    *,
    operation_results: list[dict],
    traffic_rows: list[dict[str, Any]],
    result_dir: Path,
    enabled: bool,
    model_base_url: str,
    model_api_key: str,
    model_name: str,
) -> tuple[dict[str, Any], int]:
    """执行主控打标：推理 + 命中标记 + 结果落盘（异常不抛出）。"""
    tagging_result: dict[str, Any] = {
        "status": "skipped",
        "c2_domains": [],
        "c2_domain_reasons": [],
        "c2_ips": [],
        "c2_ip_reasons": [],
        "tagging_basis": "",
    }
    matched_traffic_count = 0

    try:
        tagging_result = _infer_real_controller_domains(
            operation_results=operation_results,
            enabled=enabled,
            model_base_url=model_base_url,
            model_api_key=model_api_key,
            model_name=model_name,
        )
        c2_domains = tagging_result.get("c2_domains") or []
        c2_ip_reasons: list[dict[str, str]] = []
        c2_ips: list[str] = []
        excluded_ips = _collect_white_domain_mapped_ips(traffic_rows)
        if c2_domains:
            tagging_result["tagging_basis"] = "domain"
        else:
            c2_ip_reasons = _infer_real_controller_ips(
                traffic_rows,
                operation_results=operation_results,
                excluded_ips=excluded_ips,
            )
            c2_ips = [str(item.get("ip") or "").strip() for item in c2_ip_reasons if str(item.get("ip") or "").strip()]
            tagging_result["c2_ips"] = c2_ips
            tagging_result["c2_ip_reasons"] = c2_ip_reasons
            tagging_result["tagging_basis"] = "ip" if c2_ips else "empty"

        matched_traffic_count = _tag_traffic_rows_with_real_controller(
            traffic_rows=traffic_rows,
            c2_domains=c2_domains,
            c2_ips=c2_ips,
        )
        tagging_result["matched_traffic_count"] = matched_traffic_count
        tagging_result["traffic_total"] = len(traffic_rows)
    except Exception as tagging_exc:  # pragma: no cover - runtime dependent
        logger.warning("real controller tagging skipped err=%s", tagging_exc)
        tagging_result = {
            "enabled": bool(enabled),
            "status": "tagging_failed",
            "c2_domains": [],
            "c2_domain_reasons": [],
            "c2_ips": [],
            "c2_ip_reasons": [],
            "candidate_domains": [],
            "formatted_observations": "",
            "model_output": "",
            "tagging_basis": "",
            "matched_traffic_count": 0,
            "traffic_total": len(traffic_rows),
            "error": _clip_text(str(tagging_exc), 2048),
        }
        matched_traffic_count = 0

    try:
        _write_real_controller_tagging_result(result_dir, tagging_result)
    except Exception:  # pragma: no cover - runtime dependent
        pass

    return tagging_result, matched_traffic_count
