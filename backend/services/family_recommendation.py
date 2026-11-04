from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Callable
from uuid import uuid4

from analyzers.model_matcher import evaluate_model_expression
from core.config import settings
from repositories import family_recommendation_repo
from services.family_clustering import ClusterCandidate, build_apps, cluster_candidates


logger = logging.getLogger(__name__)

FRAUD_TYPES = {
    "1002": "虚假贷款",
    "1003": "虚假投资",
    "1057": "刷单返利",
    "1058": "聊天",
    "1059": "会议",
}


@dataclass(frozen=True)
class ModelMetadata:
    name: str
    confidence: float
    description: str
    type_code: str
    type_name: str


def validate_metadata(value: dict[str, Any]) -> ModelMetadata:
    name = str(value.get("model_name") or "").strip()
    description = str(value.get("evidence_summary") or "").strip()
    code = str(value.get("fraud_type_code") or "").strip()
    type_name = re.sub(rf"^{re.escape(code)}\s*[-:：]\s*", "", str(value.get("fraud_type") or "").strip())
    if not name or len(name) > 10:
        raise ValueError("模型名称必须为 1-10 个字符")
    if not description:
        raise ValueError("证据摘要不能为空")
    if code not in FRAUD_TYPES or type_name != FRAUD_TYPES[code]:
        raise ValueError("诈骗类型编码和名称不匹配")
    try:
        confidence = float(value.get("confidence"))
    except (TypeError, ValueError) as exc:
        raise ValueError("置信度不是数字") from exc
    if not 0 <= confidence <= 1:
        raise ValueError("置信度必须在 0 到 1 之间")
    return ModelMetadata(name, confidence, description[:500], code, type_name)


def parse_metadata_response(content: str) -> ModelMetadata:
    text = content.strip()
    fence = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text, flags=re.IGNORECASE | re.DOTALL)
    return validate_metadata(json.loads(fence.group(1) if fence else text))


def infer_metadata(family: ClusterCandidate, members: list[Any]) -> ModelMetadata:
    from openai import OpenAI

    if not settings.REAL_CONTROLLER_TAGGING_BASE_URL or not settings.REAL_CONTROLLER_TAGGING_API_KEY or not settings.REAL_CONTROLLER_TAGGING_MODEL:
        raise RuntimeError("未配置模型推荐所需的大模型服务")
    common_so = set(members[0].so_files)
    for app in members[1:]:
        common_so &= set(app.so_files)
    evidence = {
        "framework": family.framework_name,
        "cluster_stage": family.stage,
        "member_count": len(members),
        "fingerprint_kind": "representative_aot_4grams" if family.stage == "aot_opcode_4grams" else "strict_common_fingerprints",
        "fingerprints": list(family.fingerprints[:80]),
        "min_pair_similarity": family.min_pair_similarity,
        "common_so_files": sorted(common_so),
        "app_samples": [
            {"name": app.app_name, "package": app.package_name}
            for app in members[:20]
        ],
    }
    allowed = "、".join(f"{code}-{name}" for code, name in FRAUD_TYPES.items())
    client = OpenAI(
        base_url=settings.REAL_CONTROLLER_TAGGING_BASE_URL.rstrip("/"),
        api_key=settings.REAL_CONTROLLER_TAGGING_API_KEY,
        max_retries=2,
    )
    response = client.chat.completions.create(
        model=settings.REAL_CONTROLLER_TAGGING_MODEL,
        messages=[
            {"role": "system", "content": (
                "你是移动应用诈骗家族分析员。只能依据给定静态证据推断，"
                "不要编造诈骗行为。返回 JSON 对象，字段为 model_name、confidence、"
                "evidence_summary、fraud_type_code、fraud_type。model_name 不超过10个字符，"
                f"confidence 为0到1，诈骗类型只能从以下列表选择：{allowed}。"
            )},
            {"role": "user", "content": json.dumps(evidence, ensure_ascii=False)},
        ],
        temperature=0.1,
        response_format={"type": "json_object"},
        timeout=90,
    )
    content = response.choices[0].message.content
    if not content:
        raise ValueError("大模型返回空内容")
    return parse_metadata_response(content)


def generate_recommendations(
    inferer: Callable[[ClusterCandidate, list[Any]], ModelMetadata] = infer_metadata,
    interval_seconds: float = 0,
    progress: Callable[[dict[str, int]], None] | None = None,
) -> dict[str, Any]:
    rows = family_recommendation_repo.load_unmatched_ga_apps()
    apps, task_ids_by_md5 = build_apps(rows)
    families = cluster_candidates(apps, rows)
    batch_id = str(uuid4())
    created = 0
    failed = 0
    conflicts = 0
    rows_by_task = {str(row["task_id"]): row for row in rows}
    if progress:
        progress({"processedFamilies": 0, "totalFamilies": len(families), "savedCandidates": 0})
    for family_index, family in enumerate(families):
        if family_index and interval_seconds > 0:
            time.sleep(interval_seconds)
        members = [apps[index] for index in family.members]
        all_task_ids = [task_id for app in members for task_id in task_ids_by_md5[app.md5]]
        matching_task_ids = [
            task_id
            for task_id in all_task_ids
            if evaluate_model_expression(family.rule_expression, rows_by_task[task_id])
        ]
        metadata = None
        failure_reason = None
        try:
            for member in members:
                if not evaluate_model_expression(family.rule_expression, rows_by_task[member.task_id]):
                    raise ValueError(f"规则未命中家族成员 {member.md5}")
            metadata = inferer(family, members)
        except Exception as exc:
            failure_reason = str(exc)[:2000]
            logger.warning("family recommendation inference failed family=%s: %s", family.family_key, exc)
        candidate = {
            "id": str(uuid4()),
            "batch_id": batch_id,
            "family_key": family.family_key,
            "framework_name": family.framework_name,
            "cluster_strategy": family.strategy,
            "cluster_stage": family.stage,
            "member_count": len(members),
            "representative_task_id": apps[family.center_index].task_id if family.center_index is not None else None,
            "min_pair_similarity": family.min_pair_similarity,
            "fingerprints_json": json.dumps(family.fingerprints, ensure_ascii=False),
            "rule_expression": family.rule_expression,
            "model_name": metadata.name if metadata else None,
            "family_description": metadata.description if metadata else None,
            "model_type_code": metadata.type_code if metadata else None,
            "model_type_name": metadata.type_name if metadata else None,
            "confidence": metadata.confidence if metadata else None,
            "status": "pending" if metadata else "inference_failed",
            "failure_reason": failure_reason,
        }
        try:
            saved = family_recommendation_repo.save_candidate(
                candidate, matching_task_ids if metadata else all_task_ids
            )
        except family_recommendation_repo.RecommendationConflict:
            conflicts += 1
            if progress:
                progress({"processedFamilies": family_index + 1, "totalFamilies": len(families), "savedCandidates": created})
            continue
        if saved:
            created += 1
            failed += metadata is None
        if progress:
            progress({"processedFamilies": family_index + 1, "totalFamilies": len(families), "savedCandidates": created})
    return {
        "batchId": batch_id,
        "eligibleApps": len(apps),
        "clusteredFamilies": len(families),
        "savedCandidates": created,
        "inferenceFailed": failed,
        "conflicts": conflicts,
    }
