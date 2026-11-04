from __future__ import annotations

from core.config import settings
from services.family_recommendation import generate_recommendations
from workers.celery_app import celery_app


@celery_app.task(bind=True, name="workers.family_recommendations.generate")
def generate_family_recommendations(self):
    return generate_recommendations(
        interval_seconds=settings.FAMILY_RECOMMENDATION_LLM_INTERVAL_SECONDS,
        progress=lambda state: self.update_state(state="PROGRESS", meta=state),
    )
