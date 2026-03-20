from workers.celery_app import celery_app


@celery_app.task(name="workers.static_analysis.analyze_apk")
def analyze_apk(task_id: str):
    # 阶段五仅提供任务入口占位，静态分析实现放在阶段七。
    return {"task_id": task_id, "accepted": True}
