from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from openai import OpenAI


logger = logging.getLogger(__name__)


def _clip_text(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if len(text) <= limit else text[:limit]


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

    for raw_step in operation_results[:30]:
        if not isinstance(raw_step, dict):
            continue
        try:
            seq = int(raw_step.get("step_num"))
        except (TypeError, ValueError):
            seq = len(step_summaries) + 1

        traffic_evidence: list[dict[str, str | None]] = []
        seen_traffic_keys: set[tuple[str, str]] = set()
        traffic_logs = raw_step.get("traffic_logs") or []
        if not isinstance(traffic_logs, list):
            traffic_logs = []
        for packet in traffic_logs[:80]:
            if not isinstance(packet, dict):
                continue
            domain = _clip_text(packet.get("domain"), 512)
            url = _clip_text(packet.get("url"), 1024)
            normalized_domain = (domain or "").strip()
            normalized_url = (url or "").strip()
            if not normalized_domain:
                continue
            candidate_domain_set.add(normalized_domain)
            dedup_key = (normalized_domain, normalized_url)
            if dedup_key in seen_traffic_keys:
                continue
            seen_traffic_keys.add(dedup_key)
            traffic_evidence.append(
                {
                    "domain": normalized_domain,
                    "url": normalized_url or None,
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
                f"  - [{idx}] domain={item.get('domain') or '-'} | url={item.get('url') or '-'}"
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
        "2. 高危后缀：域名后缀命中小众高危TLD（如 .top/.xyz/.cc/.pw/.tk）。\n"
        "3. DGA特征：域名主体呈现随机字母数字混合、高熵、不可读等特征。\n"
        "4. 排除白名单：剔除系统流量与常见第三方SDK（百度地图/极光/微信/阿里云等）背景请求。\n\n"
        "# Hard Constraints\n"
        "1. 只能从给定 candidate_domains 中选择，不允许输出候选集外的域名。\n"
        "2. 每个输出域名必须给出非空 reason，且 reason 必须引用至少一条观测证据（步骤语义、URL、或Hook值）。\n"
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
) -> int:
    c2_domain_set = {str(item).strip() for item in c2_domains if str(item).strip()}
    if not traffic_rows:
        return 0

    matched_count = 0
    for row in traffic_rows:
        domain = str(row.get("domain") or "").strip()
        if domain and domain in c2_domain_set:
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
    tagging_result: dict[str, Any] = {"status": "skipped", "c2_domains": [], "c2_domain_reasons": []}
    matched_traffic_count = 0

    try:
        tagging_result = _infer_real_controller_domains(
            operation_results=operation_results,
            enabled=enabled,
            model_base_url=model_base_url,
            model_api_key=model_api_key,
            model_name=model_name,
        )
        matched_traffic_count = _tag_traffic_rows_with_real_controller(
            traffic_rows=traffic_rows,
            c2_domains=tagging_result.get("c2_domains") or [],
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
            "candidate_domains": [],
            "formatted_observations": "",
            "model_output": "",
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
