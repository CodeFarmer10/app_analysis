from workers.celery_app import celery_app


@celery_app.task(name="workers.dynamic_trace.trace_task")
def trace_task(task_id: str, device_id: str):
    # 阶段六由调度器触发，动态溯源主体实现在阶段八。
    return {"task_id": task_id, "device_id": device_id, "accepted": True}
