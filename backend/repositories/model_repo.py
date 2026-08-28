from __future__ import annotations

from core.database import fetch_all


def get_active_models_ordered() -> list[dict]:
    return fetch_all(
        """
        SELECT
            model_id,
            model_name,
            model_type_name,
            model_expression
        FROM models
        WHERE status = 1
        ORDER BY created_at DESC, model_id DESC
        """
    )
