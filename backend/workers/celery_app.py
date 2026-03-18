from celery import Celery
from kombu import Queue

from core.config import settings


celery_app = Celery(
    "fraud_app",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="Asia/Shanghai",
    enable_utc=False,
    task_default_queue="queue_download",
    task_queues=(
        Queue("queue_download"),
        Queue("queue_static"),
        Queue("queue_dynamic"),
    ),
    task_routes={
        "workers.download.*": {"queue": "queue_download"},
        "workers.static_analysis.*": {"queue": "queue_static"},
        "workers.dynamic_trace.*": {"queue": "queue_dynamic"},
    },
)
