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

## 2026-03-20

已完成阶段四（认证模块）并通过联调验证：

- 完成 `backend/core/security.py`：
  - 实现密码哈希与校验、JWT 签发与解码、`get_current_user` 鉴权依赖
  - 新增 `get_current_admin` 管理员鉴权依赖
  - 兼容本地运行环境，密码算法实现由 `passlib` 调整为直接使用 `bcrypt`，消除登录 500 问题
- 完成 `backend/repositories/user_repo.py`：
  - `get_user_by_username`、`get_user_by_id`
  - `list_users`、`create_user`、`delete_user`、`update_password`、`count_admin_users`
- 完成 `backend/schemas/auth.py`：
  - `LoginRequest`、`LoginResponse`
  - `ChangePasswordRequest`
- 新增 `backend/schemas/user.py`：
  - `UserCreateRequest`、`UserListItem`
- 完成 `backend/api/auth.py`：
  - `POST /api/auth/login`
  - `POST /api/auth/logout`
  - `POST /api/auth/change-password`（旧密码校验 + 新旧密码不可相同）
- 新增 `backend/api/users.py`（管理员用户管理）：
  - `GET /api/users`
  - `POST /api/users`
  - `DELETE /api/users/{user_id}`
  - 删除约束：不可删除当前登录管理员、至少保留一个管理员
- 完成 `backend/main.py` 路由注册：新增 `users_router`
- 更新 `backend/migrations/v1_init.sql`：
  - `users` 表新增 `role ENUM('admin','user') DEFAULT 'user'`
  - 增加幂等补字段/补索引逻辑，兼容已存在数据库
- 更新受保护占位接口：
  - `backend/api/tasks.py`、`backend/api/devices.py`、`backend/api/dashboard.py` 的 `ping` 路由注入登录鉴权依赖

认证与权限实测结果（2026-03-20）：

- `POST /api/auth/login`（admin）返回 `200` 并成功获取 token
- 带 token 访问 `GET /api/tasks/ping` 返回 `200`
- 不带 token 访问 `GET /api/tasks/ping` 返回 `401`
- 带 admin token 访问 `GET /api/users` 返回 `200` 并正确返回用户列表

文档同步更新：

- 已更新 `memory_bank/诈骗APP分析系统_需求文档说明书.md`：
  - 增加管理员新增/删除用户、普通用户修改密码需求
  - 增加 `/api/auth/change-password` 与 `/api/users` 相关接口说明
- 已更新 `memory_bank/诈骗APP分析系统_全栈实施计划.md`：
  - 阶段四扩展为“登录、JWT、鉴权依赖、用户管理与改密”
  - 增加管理员接口、改密接口、`users.role` 字段、验证项与交付物描述

说明：本轮未开始阶段五实现。Docker 相关仍保持“仅创建文件用于未来一键部署，不执行容器操作”。

已完成阶段五（任务管理模块）并通过接口验证：

- 完成 `backend/schemas/task.py`：
  - 新增 `UrlSubmitRequest`、`TaskStatusResponse`、`TaskListItem`、`TaskListResponse`
- 完成 `backend/repositories/task_repo.py`：
  - 新增 `create_task`、`get_task_by_id`、`get_task_by_md5`、`update_task`、`list_tasks`
  - 新增详情接口所需查询：`get_static_result`、`list_dynamic_results`、`list_traffic_logs`
- 完成 `backend/services/task_service.py`：
  - 实现 APK 批量上传流程：大小限制（500MB）、MIME 校验、MD5 计算、重复检测、MinIO 上传、任务创建与更新
  - 实现 URL 批量提交流程：URL 校验、任务创建、异步下载触发
  - 实现任务列表过滤、任务详情聚合、任务状态查询
  - 增加 `python-magic` 不可用时的 MIME 检测回退逻辑（避免运行环境缺少 `libmagic` 时服务启动失败）
- 完成 `backend/api/tasks.py` 阶段五接口：
  - `POST /api/tasks/upload`
  - `POST /api/tasks/url`
  - `GET /api/tasks`
  - `GET /api/tasks/{task_id}`
  - `GET /api/tasks/{task_id}/status`
- 更新队列入口占位（不进入阶段六实现）：
  - `backend/workers/download.py` 新增 `download_apk` Celery Task 占位
  - `backend/workers/static_analysis.py` 新增 `analyze_apk` Celery Task 占位

阶段五验证结果（2026-03-20）：

- URL 提交验证通过：
  - `http://1u79p9.syhold.com.cn/pub/tFe9Vngi4ggq.apk`
  - `http://1u79p9.syhold.com.cn/pub/qgcqbngimdf9.apk`
  - 接口返回 2 个任务 ID，状态均为 `downloading`
- 文件上传验证通过（使用项目内测试文件 `backend/tmp/test_1.apk`、`backend/tmp/test_2.apk`）：
  - 上传接口返回 `200`，创建 2 个任务，状态均为 `static_analyzing`
  - 数据库回查确认 `file_md5`、`file_size`、`apk_path` 均正确落库
  - `apk_path` 符合规则：`{task_id}/apk/{md5}.apk`

说明：

- 本轮严格停在阶段五，未开始阶段六下载执行、重试策略与调度器实现。
- Docker 相关仍仅创建/更新文件用于后续一键部署，未执行容器运行操作。

## 2026-03-23

已完成阶段六（Celery 任务队列）并通过联调验证（第六步验证通过）：

- 完成 `backend/workers/download.py` 下载任务实现：
  - 实现 `download_apk`：`httpx` 流式下载、超时控制、500MB 大小限制
  - 下载后执行 MIME 校验与 MD5 去重
  - 成功时上传 MinIO，并回写 `tasks.apk_path`、`file_md5`、`file_size`
  - 成功流转为 `static_analyzing` 并触发静态分析任务；失败流转为 `download_failed`
  - 增加网络异常自动重试（最多 3 次，指数退避）与 `on_failure` 最终失败落库
- 完成 `backend/workers/scheduler.py` 调度器实现：
  - 10 秒轮询 `waiting_device` 任务与空闲设备
  - 使用事务 + `FOR UPDATE` 行锁执行任务/设备配对
  - 配对成功后更新任务状态为 `dynamic_tracing`、设备状态为 `busy`，并触发动态溯源任务
  - 动态任务分发异常时回滚配对，恢复任务到 `waiting_device`、设备到 `online`
- 队列运行口径补充：
  - Worker 启动时需确保加载任务模块（如 `workers.download`），否则任务不会注册到 Celery 消费端

阶段六验证结果（2026-03-23）：

- Redis 连通性验证通过：`redis://10.12.130.100:6379/0`，`PING=True`
- 失败路径验证通过（URL 不可用场景）：
  - `http://z51sb1.chelushi.com.cn/pub/yru0nngKicMf.apk`
  - 任务 `9116d58e-1c3c-42bb-95d7-9b700310e365` 从 `downloading` 流转为 `download_failed`
  - `error_message` 正确记录 `404 Not Found`
- 成功路径验证通过（URL 可用场景）：
  - `http://10.128.5.44:1241/app-down/7b738c1b48e917609b7b6c85de60de06.apk`
  - 任务 `7f387a73-d99b-41c5-a05c-1b2e0c375f9b` 从 `downloading` 流转为 `static_analyzing`
  - `file_md5=7b738c1b48e917609b7b6c85de60de06`
  - `file_size=87287495`
  - `apk_path=7f387a73-d99b-41c5-a05c-1b2e0c375f9b/apk/7b738c1b48e917609b7b6c85de60de06.apk`

说明：

- 阶段六仅覆盖队列下载与调度能力；静态分析主体逻辑仍按计划在阶段七继续实现。

已完成阶段七（静态分析模块）并通过验证：

- 完成 `backend/analyzers/apk_parser.py`：
  - 实现 `parse_apk(apk_path)`，使用 androguard 提取 `app_name`、`package_name`、`version_name`、`version_code`
  - 提取证书摘要 `cert_md5`、`cert_sha1`、`cert_sha256`
  - 提取并结构化 `permissions`（含 `is_dangerous`）、`activities`（含 `is_launcher`）、`services`、`providers`、`so_files`
  - 提取图标二进制 `icon_bytes` 与图标资源名，补充证书/图标提取失败容错
- 完成 `backend/workers/static_analysis.py`：
  - 实现 `analyze_apk(task_id)`：从 MinIO 下载 APK、调用解析器、上传图标到 `{task_id}/icon/...`
  - 新增静态结果写库与任务状态流转：成功更新为 `waiting_device`，失败更新为 `static_failed` 并写入 `error_message`
  - 增加本地临时文件与临时目录清理，避免残留
- 完成 `backend/repositories/task_repo.py`：
  - 新增 `upsert_static_result(task_id, data)`，用于静态结果入库/更新
  - 增强 `get_static_result(task_id)`，对 JSON 字段进行反序列化返回
- 完成 `backend/services/task_service.py`：
  - 新增 `get_task_static_result(task_id)`，统一组装静态结果并为 `icon_path` 生成预签名 URL
- 完成 `backend/api/tasks.py`：
  - 新增 `GET /api/tasks/{task_id}/static` 静态结果接口（登录态鉴权）

阶段七验证结果（2026-03-23）：

- 使用 `backend/tmp/test_1.apk`、`backend/tmp/test_2.apk` 验证：
  - 静态解析成功，应用名/包名/版本/权限/组件/SO/图标/证书摘要均可提取
- 通过截断样本构造损坏 APK 验证失败路径：
  - 解析异常可正确触发失败分支（用于支撑 `static_failed` 错误落库逻辑）
- 用户回归验证结论：**验证通过**

说明：

- 本阶段仅创建/修改代码与文档，未执行任何 Docker 容器运行操作。

## 2026-03-24

已完成阶段八关键实现（动态溯源链路重构 + 8.4 动态结果接口）：

- 重构 `backend/workers/dynamic_trace.py`：
  - 优化函数命名与职责拆分，统一异常处理与失败落库
  - 精简重复校验分支，收敛上下文提取逻辑
  - 为每个函数补充中文注释
  - 动态过程截图统一通过 `_upload_result_file(task_id, "screenshot", file_path)` 上传
  - 动态结果写库改为事务化：`tasks`、`dynamic_results`、`traffic_logs` 在同事务内更新，保证关联一致性
- 调整调度器 `backend/workers/scheduler.py`：
  - 分配顺序调整为“先查空闲设备，再取等待任务”
  - 状态更新顺序调整为“先设备 busy，再任务 dynamic_tracing，再派发”
- 完成实施计划 8.4（动态溯源结果接口）：
  - `repositories/task_repo.py` 新增分页查询：`get_dynamic_results`、`get_traffic_logs`，并新增 `get_dynamic_result_by_seq`
  - `services/task_service.py` 新增动态结果聚合服务与截图重定向 URL 服务
  - `api/tasks.py` 新增：
    - `GET /api/tasks/{task_id}/dynamic`（动态记录与流量日志分页，截图预签名 URL）
    - `GET /api/tasks/{task_id}/screenshots/{seq}`（302 重定向到截图预签名 URL）
- 本地校验通过：
  - `python3 -m compileall backend/workers/dynamic_trace.py`
  - `python3 -m compileall backend/repositories/task_repo.py backend/services/task_service.py backend/api/tasks.py`

已完成阶段九（文件下载与报告模块）代码实现（按用户要求跳过本轮验证）：

- 完成 `backend/templates/report.html`：
  - 基于 Jinja2 的 PDF 报告模板落地，含封面（任务ID、MD5、分析时间、报告生成时间）
  - 输出静态分析摘要、动态溯源步骤（含前后截图）、流量日志汇总表
  - 样式采用内联 CSS，兼容 WeasyPrint 渲染
- 完成 `backend/services/report_service.py`：
  - 实现 `generate_pdf(task_id: str) -> str`
  - 聚合任务、静态结果、动态结果、流量日志数据
  - 通过 MinIO 读取截图二进制并转 base64 内嵌 HTML，避免外链失效
  - 渲染 HTML 并使用 WeasyPrint 生成 PDF bytes，上传至 `{task_id}/report/{task_id}.pdf`
- 完成 `backend/workers/report.py`：
  - 实现 Celery 任务 `workers.report.generate_report`
  - 生成成功后回写 `tasks.report_path`，失败时回写 `error_message`
- 完成 `backend/workers/celery_app.py`：
  - 新增 `queue_report`
  - 新增 `workers.report.*` 任务路由
  - 显式导入 `workers.report`，确保 worker 启动即注册任务
- 完成 `backend/workers/dynamic_trace.py`：
  - 报告触发改为常量任务名 `workers.report.generate_report`
  - `_trigger_report_task` 显式指定 `queue="queue_report"` 投递
- 完成 `backend/services/storage_service.py`：
  - 新增 `get_object_bytes(object_name)`，支持报告服务直接读取对象二进制
- 完成 `backend/services/task_service.py`：
  - 新增 `get_task_file_download_url(task_id, file_type)`
  - 统一处理 APK/REPORT/PCAP 文件存在性校验与预签名 URL 生成
- 完成 `backend/api/tasks.py`：
  - 新增 `GET /api/tasks/{task_id}/apk`
  - 新增 `GET /api/tasks/{task_id}/report`
  - 新增 `GET /api/tasks/{task_id}/pcap`
- 调整 `backend/core/config.py`：
  - 移除 `DYNAMIC_TRACE_REPORT_TASK_NAME` 配置项，报告任务名不再依赖环境变量

说明：

- 按用户要求，本轮跳过接口联调与下载/报告打开验证；待后续回归测试确认。
- 本轮仅创建/修改代码与文档，未执行任何 Docker 容器运行操作。

已完成阶段十（设备管理与看板模块）并通过用户验证：

- 完成 `backend/repositories/device_repo.py`：
  - 实现 `create_device`、`get_device_by_id`、`get_device_by_serial`、`list_devices`、`update_device`、`delete_device`、`get_available_devices`
  - 新增 `count_in_progress_tasks`，用于删除设备前进行中任务校验
- 完成 `backend/services/device_service.py`：
  - 实现设备管理业务编排：列表、详情、新增、改名、删除
  - 新增设备可达性校验：`adb connect`（IP:Port 场景）+ `adb -s <serial> get-state`
  - 新增设备基础信息采集：`getprop` 获取型号/系统版本、`wm size` 获取分辨率
  - 删除设备前增加保护：若设备存在 `current_task_id` 或进行中动态任务则拒绝删除
- 完成 `backend/schemas/device.py`：
  - 新增 `DeviceCreateRequest`、`DeviceUpdateRequest`、`DeviceItem`
- 完成 `backend/api/devices.py`：
  - 新增 `GET /api/devices`
  - 新增 `GET /api/devices/{device_id}`
  - 新增 `POST /api/devices`
  - 新增 `PUT /api/devices/{device_id}`
  - 新增 `DELETE /api/devices/{device_id}`
- 完成 `backend/repositories/dashboard_repo.py`：
  - 新增 `get_stats()`，输出总任务数、今日提交、今日完成、分析中数量、在线设备数、成功率
  - 新增 `get_trend(days)`，输出近 N 天提交/完成趋势并按日期补齐空缺天
- 完成 `backend/api/dashboard.py`：
  - 新增 `GET /api/dashboard/stats`
  - 新增 `GET /api/dashboard/trend?days=7|30`（限制仅允许 7 或 30）
- 本地代码自检通过：
  - `python3 -m compileall backend/repositories/device_repo.py backend/services/device_service.py backend/schemas/device.py backend/repositories/dashboard_repo.py backend/api/devices.py backend/api/dashboard.py`

阶段十验证结果（2026-03-24）：

- 用户联调验证结论：**验证通过**

说明：

- 本阶段仅创建/修改代码与文档，未执行任何 Docker 容器运行操作。
