# Architecture Notes

## Overview

系统采用前后端分离架构：

- 前端（Vue 3 + Vite）负责任务提交、状态展示、结果查看、设备管理和看板展示。
- 后端（FastAPI + Celery）提供 API、任务调度与分析流程编排。
- 分析引擎分为静态分析（androguard）与动态溯源（adb + tcpdump + tshark）。
- 数据库使用 MySQL，异步队列使用 Redis + Celery，对象存储使用 MinIO。

## Architecture Insights

- 数据库主键统一为字符串 UUID，便于跨模块生成和后续扩展。
- 任务与用户通过 `tasks.user_id` 关联，为权限和审计扩展预留空间。
- 动态结果采用“操作前/后截图 + 操作时间 + 成功标记”结构，保证可追溯性。
- 文件存储采用单一 Bucket（`BUCKET_TASK_FILES`）策略，按任务目录前缀组织：
  - `{task_id}/apk/...`
  - `{task_id}/icon/...`
  - `{task_id}/screenshots/...`
  - `{task_id}/pcap/...`
  - `{task_id}/report/...`
  - `{task_id}/run_logs/...`
- Docker 文件仅用于后续一键部署准备，当前开发阶段不依赖容器运行。

## Backend Files

- `backend/main.py`
  - FastAPI 入口；注册 CORS、全局异常处理、健康检查、路由；启动时初始化存储。
- `backend/core/config.py`
  - 环境配置读取（`.env`）；集中定义 DB/Redis/MinIO/JWT/CORS 配置项。
- `backend/core/database.py`
  - MySQL 连接池与基础 SQL 执行封装（`execute`、`fetch_one`、`fetch_all`）。
- `backend/core/response.py`
  - 统一成功响应结构函数 `success_response`。
- `backend/core/security.py`
  - 认证与安全能力预留文件（阶段四实现核心逻辑）。
- `backend/api/auth.py`
  - 认证路由分组（`/api/auth`）入口骨架。
- `backend/api/tasks.py`
  - 任务相关路由分组（`/api/tasks`）入口骨架。
- `backend/api/devices.py`
  - 设备相关路由分组（`/api/devices`）入口骨架。
- `backend/api/dashboard.py`
  - 看板相关路由分组（`/api/dashboard`）入口骨架。
- `backend/schemas/auth.py`
  - 认证请求/响应模型预留。
- `backend/schemas/task.py`
  - 任务请求/响应模型预留。
- `backend/schemas/device.py`
  - 设备请求/响应模型预留。
- `backend/repositories/user_repo.py`
  - 用户数据访问层预留。
- `backend/repositories/task_repo.py`
  - 任务数据访问层预留。
- `backend/repositories/device_repo.py`
  - 设备数据访问层预留。
- `backend/repositories/dashboard_repo.py`
  - 看板统计数据访问层预留。
- `backend/services/storage_service.py`
  - MinIO 服务封装：单 Bucket 初始化、对象上传下载、预签名 URL、任务路径构建。
- `backend/services/task_service.py`
  - 任务业务逻辑层预留。
- `backend/services/device_service.py`
  - 设备业务逻辑层预留。
- `backend/services/report_service.py`
  - 报告生成业务层预留。
- `backend/workers/celery_app.py`
  - Celery 应用初始化，配置 Redis broker/backend 与 3 个业务队列。
- `backend/workers/download.py`
  - URL 下载异步任务预留。
- `backend/workers/static_analysis.py`
  - 静态分析异步任务预留。
- `backend/workers/dynamic_trace.py`
  - 动态溯源异步任务预留。
- `backend/workers/report.py`
  - 报告生成异步任务预留。
- `backend/workers/scheduler.py`
  - 设备调度进程预留。
- `backend/analyzers/apk_parser.py`
  - APK 静态解析组件预留。
- `backend/analyzers/adb_controller.py`
  - ADB 操作封装预留。
- `backend/analyzers/pcap_parser.py`
  - PCAP 解析组件预留。
- `backend/migrations/v1_init.sql`
  - 数据库初始化脚本（核心业务表结构与索引）。
- `backend/templates/report.html`
  - PDF 报告模板预留。
- `backend/scripts/db_test.py`
  - 数据库连接自检脚本。
- `backend/requirements.txt`
  - 后端依赖版本清单。
- `backend/.env.example`
  - 环境变量模板（示例值）。
- `backend/.env`
  - 本地开发环境变量（敏感信息，不提交版本库）。
- `backend/Dockerfile`
  - 后端镜像构建文件（仅用于后续部署）。

## Frontend Files

- `frontend/src/main.js`
  - 前端应用入口，注册路由、状态管理与 UI 组件库。
- `frontend/src/App.vue`
  - 根组件，承载 `router-view`。
- `frontend/src/router/index.js`
  - 路由定义与守卫预留。
- `frontend/src/stores/auth.js`
  - 登录态与 Token 状态管理预留。
- `frontend/src/stores/task.js`
  - 任务状态管理预留。
- `frontend/src/stores/device.js`
  - 设备状态管理预留。
- `frontend/src/stores/dashboard.js`
  - 看板状态管理预留。
- `frontend/src/api/request.js`
  - axios 实例与拦截器预留。
- `frontend/src/api/auth.js`
  - 认证接口封装预留。
- `frontend/src/api/tasks.js`
  - 任务接口封装预留。
- `frontend/src/api/devices.js`
  - 设备接口封装预留。
- `frontend/src/api/dashboard.js`
  - 看板接口封装预留。
- `frontend/src/views/Login.vue`
  - 登录页预留。
- `frontend/src/views/Dashboard.vue`
  - 看板页预留。
- `frontend/src/views/TaskList.vue`
  - 任务列表页预留。
- `frontend/src/views/TaskDetail.vue`
  - 任务详情页预留。
- `frontend/src/views/DeviceList.vue`
  - 设备管理页预留。
- `frontend/src/components/AppLayout.vue`
  - 全局布局组件预留。
- `frontend/src/components/TaskStatusTag.vue`
  - 任务状态标签组件预留。
- `frontend/src/components/TaskUploadModal.vue`
  - 任务提交弹窗组件预留。
- `frontend/src/components/StaticResult.vue`
  - 静态结果展示组件预留。
- `frontend/src/components/DynamicResult.vue`
  - 动态结果展示组件预留。
- `frontend/src/components/TrafficLogTable.vue`
  - 流量日志表格组件预留。
- `frontend/src/components/ScreenshotViewer.vue`
  - 截图查看组件预留。
- `frontend/src/utils/polling.js`
  - 轮询工具预留。
- `frontend/src/utils/format.js`
  - 格式化工具预留。

## Infra And Docs

- `infra/docker-compose.yml`
  - 一键部署编排文件（开发阶段不启动）。
- `infra/.env.example`
  - 部署环境变量模板。
- `README.md`
  - 项目说明与快速开始。
- `memory_bank/progress.md`
  - 阶段性实施与验证记录。
- `memory_bank/诈骗APP分析系统_需求文档说明书.md`
  - 需求定义。
- `memory_bank/诈骗APP分析系统_技术栈方案.md`
  - 技术选型依据。
- `memory_bank/诈骗APP分析系统_全栈实施计划.md`
  - 实施阶段与交付路径。
- `memory_bank/architector.md`
  - 早期架构记录（保留兼容，后续以 `architecture.md` 为主）。
