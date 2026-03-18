# Architecture Notes

## Overview

系统采用前后端分离架构：

- 前端（Vue 3 + Vite）负责任务提交、状态展示、结果查看、设备管理和看板展示。
- 后端（FastAPI + Celery）提供 API、任务调度与分析流程编排。
- 分析引擎分为静态分析（androguard）与动态溯源（adb + tcpdump + tshark）。
- 文件存储采用 MinIO 对象存储，数据库采用 MySQL，异步任务采用 Celery + Redis。

## Architecture Insights

- 数据库主键统一为字符串（UUID），便于跨服务生成、离线预分配与后续分库分表扩展。
- 任务与用户建立关联（`tasks.user_id`），为权限控制、审计统计与多租户扩展预留基础。
- 动态溯源结果采用“操作前/后截图 + 操作时间 + 成功标记”建模，保证可追溯与可解释性。
- 任务运行日志路径独立字段（`tasks.run_log_path`），便于集中存储与问题追踪。

## Backend Structure

- backend/main.py
  - FastAPI 入口，注册中间件与路由，提供健康检查与启动钩子。
- backend/core/config.py
  - 环境变量与配置集中读取（pydantic-settings），从 `backend/.env` 加载。
- backend/core/database.py
  - MySQL 连接池与基础查询封装。
- backend/core/security.py
  - 密码哈希、JWT 生成与校验、鉴权依赖。
- backend/api/
  - 路由层，负责参数校验与调用服务层。
  - auth.py：登录与退出接口。
  - tasks.py：任务上传、列表、详情、状态、结果与下载接口。
  - devices.py：设备管理 CRUD。
  - dashboard.py：看板统计与趋势接口。
- backend/schemas/
  - Pydantic 请求/响应模型。
- backend/repositories/
  - 数据访问层，集中管理 SQL。
  - user_repo.py：用户查询。
  - task_repo.py：任务数据与结果查询。
  - device_repo.py：设备数据查询与更新。
  - dashboard_repo.py：看板统计数据聚合。
- backend/services/
  - 业务逻辑层。
  - task_service.py：任务创建与状态流转封装。
  - device_service.py：设备管理相关业务逻辑。
  - storage_service.py：MinIO 上传、下载、预签名 URL。
  - report_service.py：报告生成与存储。
- backend/workers/
  - Celery 异步任务。
  - celery_app.py：队列与 Broker 配置。
  - download.py：URL 下载任务。
  - static_analysis.py：静态分析任务。
  - dynamic_trace.py：动态溯源任务。
  - report.py：报告生成任务。
  - scheduler.py：设备调度与任务分配。
- backend/analyzers/
  - 分析引擎逻辑。
  - apk_parser.py：androguard 静态解析封装。
  - adb_controller.py：adb 操作封装。
  - pcap_parser.py：tshark 解析封装。
- backend/templates/report.html
  - PDF 报告模板。
- backend/migrations/v1_init.sql
  - 数据库初始化脚本（字符串主键、任务-用户关联、动态溯源结果扩展字段）。
- backend/requirements.txt
  - 后端依赖清单。
- backend/Dockerfile
  - 后端容器构建文件（仅用于后续一键部署）。
- backend/.env.example
  - 环境变量示例清单。
- backend/.env
  - 本地开发环境配置（不应提交到版本控制）。
- backend/scripts/db_test.py
  - 数据库连接测试脚本。

## Frontend Structure

- frontend/src/main.js
  - 应用入口，注册路由、状态管理、UI 组件库。
- frontend/src/App.vue
  - 根组件，渲染 router-view。
- frontend/src/router/index.js
  - 路由定义与登录守卫。
- frontend/src/stores/
  - Pinia 状态管理。
  - auth.js：登录状态与 Token 管理。
  - task.js：任务列表与轮询状态。
  - device.js：设备数据。
  - dashboard.js：看板数据。
- frontend/src/api/
  - API 请求封装。
  - request.js：axios 实例与拦截器。
  - auth.js、tasks.js、devices.js、dashboard.js：模块接口调用。
- frontend/src/views/
  - 页面级组件。
  - Login.vue、Dashboard.vue、TaskList.vue、TaskDetail.vue、DeviceList.vue。
- frontend/src/components/
  - 复用业务组件。
  - AppLayout.vue、TaskStatusTag.vue、TaskUploadModal.vue、StaticResult.vue、DynamicResult.vue、TrafficLogTable.vue、ScreenshotViewer.vue。
- frontend/src/utils/
  - 通用工具函数。
  - polling.js：轮询控制。
  - format.js：格式化函数。

## Infrastructure

- infra/docker-compose.yml
  - 生产一键部署的服务编排文件（开发阶段不运行）。
- infra/.env.example
  - 生产环境变量示例。

## Docs

- docs/
  - 预留文档目录，后续存放需求、技术栈、实施计划等。

## Memory Bank

- memory_bank/诈骗APP分析系统_需求文档说明书.md
  - 需求与功能规范。
- memory_bank/诈骗APP分析系统_技术栈方案.md
  - 技术选型与数据流说明。
- memory_bank/诈骗APP分析系统_全栈实施计划.md
  - 迭代阶段与交付物清单。
- memory_bank/progress.md
  - 阶段性完成记录。
- memory_bank/architector.md
  - 架构说明与文件职责索引。
