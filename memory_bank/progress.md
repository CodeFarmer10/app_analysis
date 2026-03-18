# Progress Log

## 2026-03-18

已完成阶段一（环境与工程初始化，排除 Docker 运行）：

- 创建项目目录结构：backend、frontend、infra、docs
- 创建后端骨架与占位文件（含 __init__.py）、requirements.txt、Dockerfile、.env.example
- 创建前端工程并修正目录结构与规划一致（router、stores、api、views、components、utils），App.vue 仅保留 router-view
- 创建 infra/docker-compose.yml 与 infra/.env.example（仅文件，未启动服务）
- 更新 .gitignore 与 README.md
- 创建后端虚拟环境 backend/.venv 并安装 requirements.txt 依赖
- 初始化前端项目（Vite + Vue 3）并安装依赖：ant-design-vue、pinia、vue-router、axios、echarts、vue-echarts
- 安装开发环境工具：adb（android-platform-tools）与 tshark（wireshark CLI）

说明：Docker 仅创建文件，未进行容器启动或依赖服务安装。

已完成阶段二（数据库设计与初始化，按最新约定调整）：

- 完成 `backend/migrations/v1_init.sql` 表结构：所有主键统一为 `VARCHAR(36)`（UUID），并同步外键字段类型
- `tasks` 增加 `user_id` 与 `run_log_path` 字段，建立用户外键与索引
- `dynamic_results` 增加 `action_time`、`screenshot_before`、`screenshot_after`、`is_success` 字段，移除旧 `screenshot_path`
- `traffic_logs`、`static_results`、`devices` 等表字段类型统一为字符串 ID
- 实现数据库连接层：`core/config.py`（读取 `backend/.env`）、`core/database.py`（PooledDB 连接池与基础查询）
- 补充连接测试脚本 `backend/scripts/db_test.py` 并修复包导入路径
- 依赖补齐 `python-dotenv`，确保 `.env` 生效
- 已验证虚拟环境数据库连接，`db_test.py` 输出 MySQL 版本 `5.7.25`

已完成阶段三（后端框架搭建，已通过验证）：

- 完成 `core/config.py` 配置项补全：DB、Redis、MinIO、JWT、CORS，并提供 `settings` 单例
- 新增 `core/response.py`，统一 `success_response` 返回结构
- 完成 `main.py`：FastAPI 实例、CORS 中间件、全局异常处理、`GET /health`、路由统一注册、启动时存储初始化
- 完成 `api/auth.py`、`api/tasks.py`、`api/devices.py`、`api/dashboard.py` 路由分组骨架（便于 `/docs` 分组验证）
- 完成 `services/storage_service.py`：MinIO 客户端、Bucket 初始化、上传/下载、预签名 URL、任务级对象路径封装
- 完成 `workers/celery_app.py`：Celery 初始化、JSON 序列化、3 个队列（`queue_download`、`queue_static`、`queue_dynamic`）与路由映射
- 存储策略调整为单一 Bucket：`BUCKET_TASK_FILES`；对象路径统一为 `{task_id}/{file_type}/{file_name}`，同一任务下集中存放 APK、图标、截图、PCAP、报告、运行日志
- 已同步更新 `backend/.env` 与 `backend/.env.example`
- 已同步更新实施计划文档中 MinIO 相关内容，清理旧多 Bucket 口径

阶段三验证结果（2026-03-18）：

- FastAPI 启动成功，`GET /health` 返回 `{"status":"ok"}`，`/docs` 返回 `200`
- Celery worker 启动并确认监听 3 个队列：`queue_download`、`queue_static`、`queue_dynamic`
- 说明：Docker 相关仅创建文件用于未来一键部署，未执行容器启动
