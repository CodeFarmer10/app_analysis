from workers.celery_app import celery_app


@celery_app.task(name="workers.download.download_apk")
def download_apk(task_id: str, url: str):
    # 阶段五仅提供任务入口占位，下载实现放在阶段六。
    return {"task_id": task_id, "url": url, "accepted": True}
