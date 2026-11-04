# 家族自动推荐

在“新增家族”的“自动推荐”标签中，所有登录用户可查看候选家族及其 APP，候选与正式家族复用同一详情页面。仅管理员可启动聚类任务、审核模型或拒绝候选。

候选来源为 `tasks.task_description LIKE 'ga%'` 且 `static_results.model_id IS NULL` 的静态分析结果。按 APK MD5 去重后，至少 5 个 APP 才生成候选。Flutter 使用 AOT Opcode 4-gram Jaccard 完整链接聚类，家族内任意两款 APP 的相似度均须严格大于 0.8；其他框架使用 `backend/services/family_cluster_reference.py` 中的参考算法。候选模型规则会逐成员验证。大模型推断失败的候选保留为 `inference_failed`，可重新生成或拒绝。

候选元数据存于 `family_recommendations`；具体 APP 通过 `static_results.family_recommendation_id` 关联。审核通过时，在同一事务中创建 `models` 记录并设置成员的 `static_results.model_id`。重复任务的 MD5 可以对应多条静态结果，但家族规模按不同 MD5 计算。

部署时执行独立迁移 `backend/migrations/v2_family_recommendations.sql`，安装更新后的后端依赖，并启动 `queue_family` Celery worker。Docker Compose 中对应服务名为 `worker_family`。推荐大模型沿用 `REAL_CONTROLLER_TAGGING_BASE_URL`、`REAL_CONTROLLER_TAGGING_API_KEY` 和 `REAL_CONTROLLER_TAGGING_MODEL`，调用间隔由 `FAMILY_RECOMMENDATION_LLM_INTERVAL_SECONDS` 控制，默认 30 秒。候选生成仅由管理员在页面上触发。
