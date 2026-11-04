from __future__ import annotations

from typing import Any, Sequence
from uuid import uuid4

from analyzers.model_matcher import evaluate_model_expression
from core.database import fetch_all, fetch_one, get_connection


class RecommendationConflict(ValueError):
    pass


INPUT_SQL = """
SELECT sr.task_id, LOWER(TRIM(t.file_md5)) AS file_md5,
       sr.app_name, sr.package_name, sr.framework_name, sr.components,
       sr.so_libraries, sr.dcloud_pages, sr.dcloud_api_routes,
       sr.flutter_primary_package, sr.flutter_library_uris,
       sr.flutter_primary_package_classes, sr.flutter_aot_opcode_4grams
FROM static_results sr
JOIN tasks t ON t.id = sr.task_id
LEFT JOIN family_recommendations fr ON fr.id = sr.family_recommendation_id
WHERE t.task_description LIKE %s
  AND sr.model_id IS NULL
  AND t.file_md5 IS NOT NULL AND TRIM(t.file_md5) <> ''
  AND sr.framework_name IS NOT NULL AND TRIM(sr.framework_name) <> ''
  AND (fr.id IS NULL OR fr.status IN ('rejected', 'inference_failed'))
ORDER BY LOWER(TRIM(t.file_md5)), t.updated_at DESC, t.created_at DESC, sr.task_id DESC
"""


def load_unmatched_ga_apps() -> list[dict[str, Any]]:
    return fetch_all(INPUT_SQL, ("ga%",))


def save_candidate(candidate: dict[str, Any], task_ids: Sequence[str]) -> str | None:
    if not task_ids:
        return None
    unique_ids = sorted(set(task_ids))
    placeholders = ",".join(["%s"] * len(unique_ids))
    with get_connection() as conn:
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO family_recommendations (
                        id, batch_id, family_key, framework_name, cluster_strategy,
                        cluster_stage, member_count, representative_task_id,
                        min_pair_similarity, fingerprints_json, rule_expression,
                        model_name, family_description, model_type_code, model_type_name,
                        confidence, status, failure_reason
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE id=id
                    """,
                    tuple(candidate[key] for key in (
                        "id", "batch_id", "family_key", "framework_name", "cluster_strategy",
                        "cluster_stage", "member_count", "representative_task_id",
                        "min_pair_similarity", "fingerprints_json", "rule_expression",
                        "model_name", "family_description", "model_type_code", "model_type_name",
                        "confidence", "status", "failure_reason",
                    )),
                )
                cursor.execute(
                    "SELECT id, status FROM family_recommendations WHERE family_key = %s FOR UPDATE",
                    (candidate["family_key"],),
                )
                existing = cursor.fetchone()
                recommendation_id = existing["id"]
                if existing["status"] == "approved":
                    conn.rollback()
                    return None
                if existing["status"] == "pending" and recommendation_id != candidate["id"]:
                    conn.rollback()
                    return None
                if existing["status"] in {"rejected", "inference_failed"}:
                    cursor.execute(
                        """
                        UPDATE static_results SET family_recommendation_id=NULL
                        WHERE family_recommendation_id=%s AND model_id IS NULL
                        """,
                        (recommendation_id,),
                    )
                    cursor.execute(
                        """
                        UPDATE family_recommendations
                        SET batch_id=%s, framework_name=%s, cluster_strategy=%s,
                            cluster_stage=%s, member_count=%s, representative_task_id=%s,
                            min_pair_similarity=%s, fingerprints_json=%s,
                            rule_expression=%s, model_name=%s, family_description=%s,
                            model_type_code=%s, model_type_name=%s, confidence=%s,
                            status=%s, failure_reason=%s, reviewed_by=NULL, reviewed_at=NULL
                        WHERE id=%s
                        """,
                        (
                            candidate["batch_id"], candidate["framework_name"],
                            candidate["cluster_strategy"], candidate["cluster_stage"],
                            candidate["member_count"], candidate["representative_task_id"],
                            candidate["min_pair_similarity"], candidate["fingerprints_json"],
                            candidate["rule_expression"], candidate["model_name"],
                            candidate["family_description"], candidate["model_type_code"],
                            candidate["model_type_name"], candidate["confidence"],
                            candidate["status"], candidate["failure_reason"], recommendation_id,
                        ),
                    )
                cursor.execute(
                    f"""
                    SELECT sr.task_id, sr.model_id, t.task_description,
                           sr.family_recommendation_id, fr.status AS old_status
                    FROM static_results sr
                    JOIN tasks t ON t.id = sr.task_id
                    LEFT JOIN family_recommendations fr ON fr.id = sr.family_recommendation_id
                    WHERE sr.task_id IN ({placeholders}) FOR UPDATE
                    """,
                    tuple(unique_ids),
                )
                locked = cursor.fetchall()
                if len(locked) != len(unique_ids) or any(
                    row["model_id"] is not None
                    or not str(row["task_description"] or "").lower().startswith("ga")
                    or (row["old_status"] in {"pending", "approved"} and row["family_recommendation_id"] != recommendation_id)
                    for row in locked
                ):
                    raise RecommendationConflict("候选 APP 的模型或推荐状态已变化，请重新生成")
                cursor.execute(
                    f"UPDATE static_results SET family_recommendation_id=%s WHERE task_id IN ({placeholders})",
                    (recommendation_id, *unique_ids),
                )
            conn.commit()
            return recommendation_id
        except Exception:
            conn.rollback()
            raise


def list_candidates(page: int, size: int) -> tuple[list[dict], int]:
    total_row = fetch_one("SELECT COUNT(*) AS total FROM family_recommendations WHERE status IN ('pending', 'inference_failed')")
    items = fetch_all(
        """
        SELECT fr.id, COALESCE(fr.model_name, CONCAT('待推断 ', LEFT(fr.family_key, 8))) AS name,
               fr.family_description AS description,
               fr.model_type_name AS type, fr.framework_name AS frameworkName,
               fr.cluster_stage AS clusterStage, fr.cluster_strategy AS clusterStrategy,
               fr.member_count AS count, fr.confidence, fr.status,
               fr.min_pair_similarity AS minPairSimilarity, fr.failure_reason AS failureReason,
               fr.created_at AS createdAt, MAX(t.created_at) AS latestTaskAt
        FROM family_recommendations fr
        LEFT JOIN static_results sr ON sr.family_recommendation_id = fr.id
        LEFT JOIN tasks t ON t.id = sr.task_id
        WHERE fr.status IN ('pending', 'inference_failed')
        GROUP BY fr.id
        ORDER BY fr.created_at DESC, fr.id DESC
        LIMIT %s OFFSET %s
        """,
        (size, (page - 1) * size),
    )
    return items, int(total_row["total"]) if total_row else 0


def get_candidate(recommendation_id: str) -> dict | None:
    return fetch_one(
        """
        SELECT id, batch_id AS batchId, family_key AS familyKey,
               COALESCE(model_name, CONCAT('待推断 ', LEFT(family_key, 8))) AS name,
               family_description AS description,
               model_type_code AS typeCode, model_type_name AS type,
               framework_name AS frameworkName, cluster_strategy AS clusterStrategy,
               cluster_stage AS clusterStage, member_count AS count,
               representative_task_id AS representativeTaskId,
               min_pair_similarity AS minPairSimilarity, confidence,
               fingerprints_json AS fingerprintsJson, rule_expression AS rule,
               failure_reason AS failureReason, status, model_id AS modelId,
               created_at AS createdAt, updated_at AS updatedAt,
               (SELECT MAX(t.created_at)
                FROM static_results sr JOIN tasks t ON t.id = sr.task_id
                WHERE sr.family_recommendation_id = fr.id) AS latestTaskAt
        FROM family_recommendations fr WHERE id = %s
        """,
        (recommendation_id,),
    )


def list_candidate_members(recommendation_id: str, page: int, size: int) -> tuple[list[dict], int]:
    total_row = fetch_one(
        "SELECT COUNT(*) AS total FROM static_results WHERE family_recommendation_id = %s",
        (recommendation_id,),
    )
    items = fetch_all(
        """
        SELECT t.id, t.task_description, t.priority, t.source_type, t.source_name,
               sr.app_name, sr.package_name, sr.icon_path, sr.model_type_name,
               t.file_md5, t.status, t.apk_path, t.report_path, t.pcap_path,
               t.device_id, d.serial AS device_serial, t.created_at, t.updated_at
        FROM static_results sr
        JOIN tasks t ON t.id = sr.task_id
        LEFT JOIN devices d ON d.id = t.device_id
        WHERE sr.family_recommendation_id = %s
        ORDER BY t.created_at DESC, t.id DESC
        LIMIT %s OFFSET %s
        """,
        (recommendation_id, size, (page - 1) * size),
    )
    return items, int(total_row["total"]) if total_row else 0


def approve_candidate(recommendation_id: str, user_id: str, name: str, description: str, type_code: str, type_name: str) -> str:
    model_id = str(uuid4())
    with get_connection() as conn:
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM family_recommendations WHERE id=%s FOR UPDATE",
                    (recommendation_id,),
                )
                candidate = cursor.fetchone()
                if not candidate or candidate["status"] != "pending":
                    raise RecommendationConflict("候选不存在或已审核")
                cursor.execute(
                    """
                    SELECT sr.task_id, sr.model_id, t.file_md5, sr.components,
                           sr.dcloud_pages, sr.dcloud_api_routes, sr.flutter_aot_opcode_4grams
                    FROM static_results sr JOIN tasks t ON t.id=sr.task_id
                    WHERE sr.family_recommendation_id=%s FOR UPDATE
                    """,
                    (recommendation_id,),
                )
                members = cursor.fetchall()
                if len({str(row["file_md5"] or "").lower() for row in members}) < 5:
                    raise RecommendationConflict("候选家族不足 5 个 APP")
                if any(row["model_id"] is not None or not evaluate_model_expression(candidate["rule_expression"], row) for row in members):
                    raise RecommendationConflict("候选 APP 特征或模型匹配状态已变化，请重新生成")
                cursor.execute(
                    """
                    INSERT INTO models (model_id, model_name, family_description,
                                        model_type_code, model_type_name, model_expression, status)
                    VALUES (%s, %s, %s, %s, %s, %s, 1)
                    """,
                    (model_id, name, description, type_code, type_name, candidate["rule_expression"]),
                )
                cursor.execute(
                    """
                    UPDATE static_results
                    SET model_id=%s, model_name=%s, model_type_name=%s
                    WHERE family_recommendation_id=%s AND model_id IS NULL
                    """,
                    (model_id, name, type_name, recommendation_id),
                )
                if cursor.rowcount != len(members):
                    raise RecommendationConflict("候选 APP 关联数已变化，请重新审核")
                cursor.execute(
                    """
                    UPDATE family_recommendations
                    SET status='approved', model_id=%s, model_name=%s,
                        family_description=%s, model_type_code=%s, model_type_name=%s,
                        reviewed_by=%s, reviewed_at=NOW()
                    WHERE id=%s
                    """,
                    (model_id, name, description, type_code, type_name, user_id, recommendation_id),
                )
            conn.commit()
            return model_id
        except Exception:
            conn.rollback()
            raise


def reject_candidate(recommendation_id: str, user_id: str) -> None:
    with get_connection() as conn:
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE family_recommendations SET status='rejected',
                        reviewed_by=%s, reviewed_at=NOW()
                    WHERE id=%s AND status IN ('pending', 'inference_failed')
                    """,
                    (user_id, recommendation_id),
                )
                if cursor.rowcount != 1:
                    raise RecommendationConflict("候选不存在或已审核")
            conn.commit()
        except Exception:
            conn.rollback()
            raise
