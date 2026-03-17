# 诈骗APP分析系统 全栈实施计划

*Fraud APP Analysis Platform — Implementation Plan*

| 文档版本 | 编写日期 | 状态 |
|---|---|---|
| V1.0 | 2026年3月 | 进行中 |

---

## 阶段总览

| 阶段 | 名称 | 主要内容 | 前置依赖 |
|---|---|---|---|
| 一 | 环境与工程初始化 | 开发环境、目录结构、Docker 基础设施 | 无 |
| 二 | 数据库设计与初始化 | 表结构设计、迁移脚本、连接层 | 阶段一 |
| 三 | 后端框架搭建 | FastAPI 骨架、配置管理、公共层 | 阶段一 |
| 四 | 认证模块 | 登录、JWT、鉴权依赖 | 阶段二、三 |
| 五 | 任务管理模块 | 上传、URL提交、任务列表、搜索、状态查询 | 阶段四 |
| 六 | Celery 任务队列 | 队列初始化、下载任务、调度器 | 阶段五 |
| 七 | 静态分析模块 | APK 解析、结果写库、状态流转 | 阶段六 |
| 八 | 动态溯源模块 | ADB 控制、截图、流量采集、tshark 解析 | 阶段七 |
| 九 | 文件下载与报告模块 | APK/PCAP/PDF 下载、报告生成 | 阶段八 |
| 十 | 设备管理与看板模块 | 设备 CRUD、状态监控、看板统计 | 阶段三 |
| 十一 | 前端工程初始化 | Vue3 骨架、路由、Pinia、axios 封装 | 阶段四 |
| 十二 | 前端认证与布局 | 登录页、全局布局、导航 | 阶段十一 |
| 十三 | 前端任务模块 | 任务列表、上传弹窗、搜索、状态轮询 | 阶段十二 |
| 十四 | 前端结果展示模块 | 任务详情、静态/动态结果、截图查看器 | 阶段十三 |
| 十五 | 前端设备与看板模块 | 设备管理页、看板统计与图表 | 阶段十四 |
| 十六 | 联调与集成测试 | 全链路通测、边界场景验证 | 阶段十五 |
| 十七 | 部署与收尾 | 生产环境配置、Nginx、文档整理 | 阶段十六 |

---

## 阶段一：环境与工程初始化

### 1.1 开发环境准备

- 确认本机已安装 Python 3.11+、Node.js 18+、Docker Desktop（或 Docker Engine + Docker Compose）
- 在服务器或本机安装 `adb`，执行 `adb version` 验证安装成功
- 在服务器或本机安装 `tshark`，执行 `tshark --version` 验证安装成功
- 准备至少一台 Android 真机或模拟器（已开启开发者选项与 USB 调试），执行 `adb devices` 确认设备可被识别

### 1.2 代码仓库初始化

- 创建 Git 仓库，根目录下建立 `backend/`、`frontend/`、`infra/`、`docs/` 四个子目录
- 在根目录创建 `.gitignore`，排除 `__pycache__`、`.env`、`node_modules`、`dist`、`*.pyc`、`tmp/`
- 创建根目录 `README.md`，说明项目简介、技术栈概览与快速启动方式

### 1.3 后端目录结构创建

在 `backend/` 下创建完整目录骨架，所有 Python 目录下放置空的 `__init__.py`：

```
backend/
├── main.py
├── core/
│   ├── config.py
│   ├── database.py
│   └── security.py
├── schemas/
│   ├── auth.py
│   ├── task.py
│   └── device.py
├── api/
│   ├── auth.py
│   ├── tasks.py
│   ├── devices.py
│   └── dashboard.py
├── repositories/
│   ├── user_repo.py
│   ├── task_repo.py
│   ├── device_repo.py
│   └── dashboard_repo.py
├── services/
│   ├── task_service.py
│   ├── device_service.py
│   ├── storage_service.py
│   └── report_service.py
├── workers/
│   ├── celery_app.py
│   ├── download.py
│   ├── static_analysis.py
│   ├── dynamic_trace.py
│   ├── report.py
│   └── scheduler.py
├── analyzers/
│   ├── apk_parser.py
│   ├── adb_controller.py
│   └── pcap_parser.py
├── templates/
│   └── report.html
├── migrations/
│   └── v1_init.sql
├── tmp/
├── requirements.txt
├── Dockerfile
└── .env.example
```

### 1.4 后端依赖文件准备

- 在 `requirements.txt` 中列出所有依赖包及版本（固定小版本号，确保环境可复现）：
  - Web 框架：`fastapi`、`uvicorn[standard]`、`python-multipart`
  - 数据库：`pymysql`、`cryptography`、`dbutils`
  - 任务队列：`celery`、`redis`
  - 文件存储：`minio`
  - 静态分析：`androguard`、`python-magic`
  - 动态溯源/流量：通过 `subprocess` 调用系统工具，无需额外 Python 包
  - 报告生成：`weasyprint`、`jinja2`
  - 认证：`python-jose[cryptography]`、`passlib[bcrypt]`
  - 配置：`pydantic-settings`
  - HTTP 客户端：`httpx`（用于 URL 任务异步下载）
- 创建 Python 虚拟环境，执行 `pip install -r requirements.txt`，确认全部安装无报错

### 1.5 前端目录结构创建

- 在 `frontend/` 目录下执行 `npm create vite@latest . -- --template vue`，初始化 Vue 3 + Vite 项目
- 执行 `npm install ant-design-vue pinia vue-router axios echarts vue-echarts` 安装依赖
- 删除 Vite 默认生成的示例文件
- 按以下结构创建空目录和占位文件：

```
frontend/src/
├── router/index.js
├── stores/
│   ├── auth.js
│   ├── task.js
│   ├── device.js
│   └── dashboard.js
├── api/
│   ├── request.js
│   ├── auth.js
│   ├── tasks.js
│   ├── devices.js
│   └── dashboard.js
├── views/
│   ├── Login.vue
│   ├── Dashboard.vue
│   ├── TaskList.vue
│   ├── TaskDetail.vue
│   └── DeviceList.vue
├── components/
│   ├── AppLayout.vue
│   ├── TaskStatusTag.vue
│   ├── TaskUploadModal.vue
│   ├── StaticResult.vue
│   ├── DynamicResult.vue
│   ├── TrafficLogTable.vue
│   └── ScreenshotViewer.vue
└── utils/
    ├── polling.js
    └── format.js
```

### 1.6 基础设施 Docker Compose 编排

- 在 `infra/` 下创建 `docker-compose.yml`，定义以下七个服务：

| 服务 | 镜像 | 说明 |
|---|---|---|
| `mysql` | `mysql:8.0` | 字符集 utf8mb4，挂载数据卷，暴露 3306 |
| `redis` | `redis:7-alpine` | 挂载数据卷，暴露 6379 |
| `minio` | `minio/minio` | 挂载数据卷，暴露 9000（API）和 9001（Console） |
| `api` | 基于后端 Dockerfile 构建 | 启动命令 `uvicorn main:app`，暴露 8000 |
| `worker` | 与 api 共用镜像 | 启动命令 `celery -A workers.celery_app worker` |
| `scheduler` | 与 api 共用镜像 | 启动命令 `python workers/scheduler.py` |
| `nginx` | `nginx:alpine` | 暴露 80，代理前端静态资源和后端 API（阶段十七补全） |

- `api`、`worker`、`scheduler` 均依赖 `mysql`、`redis`、`minio`，配置 `depends_on`
- 在 `backend/` 下创建 `Dockerfile`：基于 `python:3.11-slim`，安装系统依赖（`android-tools-adb`、`tshark`），复制代码，安装 Python 依赖，设置工作目录
- 在 `infra/` 下创建 `.env.example`，列出所有需要配置的环境变量名（不填真实值）

### 1.7 验证基础设施启动

- 执行 `docker compose up mysql redis minio -d`，等待容器健康
- 用 MySQL 客户端连接，确认可以正常登录
- 访问 `http://localhost:9001`（MinIO Console），确认可以正常登录
- 执行 `redis-cli ping`，确认返回 `PONG`
- 将验证步骤记录在 `README.md` 中

---

## 阶段二：数据库设计与初始化

### 2.1 设计 users 表

在 `migrations/v1_init.sql` 中定义 `users` 表，字段包含：

- `id`：主键，自增整型
- `username`：VARCHAR(64)，唯一索引，不可为空
- `password_hash`：VARCHAR(255)，存储 bcrypt 哈希，不可为空
- `created_at`：DATETIME，默认当前时间

### 2.2 设计 devices 表

在 `v1_init.sql` 中定义 `devices` 表，字段包含：

- `id`：主键，自增整型
- `name`：VARCHAR(128)，设备自定义名称
- `serial`：VARCHAR(128)，ADB 连接地址或序列号，唯一索引，不可为空
- `android_version`：VARCHAR(32)
- `model`：VARCHAR(128)，品牌型号
- `resolution`：VARCHAR(32)，屏幕分辨率
- `status`：ENUM(`online`, `offline`, `busy`)，默认 `online`，建立索引
- `current_task_id`：INT，外键关联 tasks 表，可为空
- `last_heartbeat_at`：DATETIME
- `created_at`：DATETIME，默认当前时间

### 2.3 设计 tasks 表

在 `v1_init.sql` 中定义 `tasks` 表，字段包含：

- `id`：主键，自增整型
- `source_type`：ENUM(`apk_upload`, `url_download`)，不可为空
- `source_name`：VARCHAR(512)，APK 原始文件名或下载 URL
- `file_md5`：VARCHAR(32)，建立索引，可为空（下载完成前为空）
- `file_size`：BIGINT，文件字节大小，可为空
- `status`：ENUM(`downloading`, `download_failed`, `static_analyzing`, `static_failed`, `waiting_device`, `dynamic_tracing`, `dynamic_failed`, `completed`)，建立索引
- `error_message`：TEXT，失败原因，可为空
- `apk_path`：VARCHAR(512)，MinIO 中的 APK 对象路径，可为空
- `pcap_path`：VARCHAR(512)，MinIO 中的 PCAP 对象路径，可为空
- `report_path`：VARCHAR(512)，MinIO 中的 PDF 报告对象路径，可为空
- `device_id`：INT，分配的设备 ID，可为空
- `created_at`：DATETIME，默认当前时间，建立索引
- `updated_at`：DATETIME，每次更新自动刷新

### 2.4 设计 static_results 表

在 `v1_init.sql` 中定义 `static_results` 表，与 tasks 表一对一关联：

- `task_id`：主键，同时作为外键关联 tasks 表
- `app_name`：VARCHAR(256)
- `package_name`：VARCHAR(256)，建立索引
- `version_name`：VARCHAR(64)
- `version_code`：VARCHAR(32)
- `icon_path`：VARCHAR(512)，MinIO 路径
- `cert_md5`、`cert_sha1`、`cert_sha256`：VARCHAR(128)
- `permissions`：JSON，权限列表（每项含 name 和 is_dangerous 标识）
- `activities`：JSON，Activity 列表（每项含 name 和 is_launcher 标识）
- `services`：JSON
- `providers`：JSON
- `so_files`：JSON

### 2.5 设计 dynamic_results 表

在 `v1_init.sql` 中定义 `dynamic_results` 表，存储逐步操作记录：

- `id`：主键，自增整型
- `task_id`：INT，外键关联 tasks，建立索引
- `seq`：INT，操作序号，与 task_id 组合唯一
- `action`：VARCHAR(256)，操作描述
- `action_result`：VARCHAR(512)，操作结果
- `screenshot_path`：VARCHAR(512)，截图 MinIO 路径，可为空

### 2.6 设计 traffic_logs 表

在 `v1_init.sql` 中定义 `traffic_logs` 表：

- `id`：主键，自增整型
- `task_id`：INT，外键关联 tasks，建立索引
- `seq`：INT，流量记录序号
- `src_ip`：VARCHAR(45)（兼容 IPv6）
- `dst_ip`：VARCHAR(45)
- `src_port`：SMALLINT UNSIGNED，可为空
- `dst_port`：SMALLINT UNSIGNED，可为空
- `protocol`：VARCHAR(32)
- `domain`：VARCHAR(512)，可为空
- `url`：TEXT，可为空
- `resolved_ip`：VARCHAR(45)，可为空

### 2.7 执行初始化脚本

- 所有建表语句加 `CREATE TABLE IF NOT EXISTS`，保证脚本幂等可重复执行
- 连接 MySQL 执行 `v1_init.sql`，确认所有 6 张表创建成功
- 手动执行 INSERT 语句，插入一条初始管理员用户记录，密码字段填入预先用 bcrypt 工具生成的哈希值
- 在 `README.md` 中记录此初始化步骤

### 2.8 实现数据库连接层

- 在 `core/config.py` 中使用 `pydantic-settings` 读取数据库连接配置（host、port、user、password、database）
- 在 `core/database.py` 中使用 `dbutils.pooled_db.PooledDB` 创建 PyMySQL 连接池
- 封装 `get_connection()` 上下文管理器，使用 `with` 语句自动获取和归还连接
- 封装三个基础查询函数，均使用参数化查询防止 SQL 注入：
  - `execute(sql, params)` → 执行写操作，返回影响行数和 lastrowid
  - `fetch_one(sql, params)` → 返回单条记录字典或 None
  - `fetch_all(sql, params)` → 返回记录字典列表
- 编写连接测试脚本，执行 `SELECT VERSION()` 并打印结果，确认连接正常

---

## 阶段三：后端框架搭建

### 3.1 配置管理

- 在 `core/config.py` 中的 `Settings` 类中声明所有配置项：
  - 数据库：`DB_HOST`、`DB_PORT`、`DB_USER`、`DB_PASSWORD`、`DB_NAME`
  - Redis：`REDIS_URL`
  - MinIO：`MINIO_ENDPOINT`、`MINIO_ACCESS_KEY`、`MINIO_SECRET_KEY`、`MINIO_SECURE`
  - MinIO Bucket 名称：`BUCKET_APK`、`BUCKET_ICONS`、`BUCKET_SCREENSHOTS`、`BUCKET_PCAP`、`BUCKET_REPORTS`
  - JWT：`JWT_SECRET_KEY`、`JWT_ALGORITHM`、`JWT_EXPIRE_MINUTES`
  - CORS：`ALLOWED_ORIGINS`
- 创建单例 `settings = Settings()`，全项目统一通过 `from core.config import settings` 使用
- 创建本地 `.env` 文件（基于 `.env.example`），填入开发环境配置值

### 3.2 FastAPI 应用入口

- 在 `main.py` 中创建 `FastAPI` 实例，配置标题、版本号
- 注册 `CORSMiddleware`，允许 `settings.ALLOWED_ORIGINS` 中的域名跨域
- 注册全局异常处理器：`HTTPException` 和未捕获异常均返回统一 JSON 格式错误响应
- 封装 `success_response(data)` 辅助函数，统一返回 `{"code": 0, "message": "ok", "data": data}`
- 添加 `GET /health` 路由，返回 `{"status": "ok"}`

### 3.3 路由注册

- 在每个 `api/` 文件中创建 `APIRouter`，配置 `prefix` 和 `tags`：
  - `auth.py`：prefix `/api/auth`
  - `tasks.py`：prefix `/api/tasks`
  - `devices.py`：prefix `/api/devices`
  - `dashboard.py`：prefix `/api/dashboard`
- 在 `main.py` 中统一 `include_router` 注册所有路由
- 启动 FastAPI（`uvicorn main:app --reload`），访问 `/docs` 确认四个路由分组正常显示

### 3.4 MinIO 存储服务初始化

- 在 `services/storage_service.py` 中创建 `StorageService` 类，`__init__` 方法中初始化 MinIO 客户端
- 实现 `ensure_buckets()`：检查并创建所有必要的 Bucket（`BUCKET_APK`、`BUCKET_ICONS`、`BUCKET_SCREENSHOTS`、`BUCKET_PCAP`、`BUCKET_REPORTS`），若已存在则跳过
- 实现 `upload_file(bucket, object_name, file_path)`、`upload_bytes(bucket, object_name, data, content_type)`、`get_presigned_url(bucket, object_name, expires_seconds=3600)`、`download_to_temp(bucket, object_name)`
- 在 `main.py` 的 `startup` 事件中调用 `ensure_buckets()`
- 登录 MinIO Console 确认 5 个 Bucket 均已创建

### 3.5 Celery 初始化

- 在 `workers/celery_app.py` 中创建 Celery 实例，Broker 和 Backend 均使用 `settings.REDIS_URL`
- 配置任务序列化格式为 JSON
- 定义三个队列：`queue_download`、`queue_static`、`queue_dynamic`，将不同 Task 分配到对应队列
- 启动 Celery Worker，确认日志中显示正在监听三个队列

### 3.6 验证后端框架骨架

- 访问 `GET /health`，确认返回正常
- 访问 `GET /docs`，确认四个路由分组全部显示
- 查看 MinIO Console，确认五个 Bucket 存在
- 查看 Celery Worker 日志，确认监听三个队列

---

## 阶段四：认证模块

### 4.1 密码工具

- 在 `core/security.py` 中使用 `passlib` 的 `CryptContext`，schemes 设为 `["bcrypt"]`
- 实现 `hash_password(plain: str) -> str`
- 实现 `verify_password(plain: str, hashed: str) -> bool`

### 4.2 JWT 工具

- 实现 `create_access_token(user_id: int) -> str`：payload 含 `sub`（str 类型用户ID）和 `exp`
- 实现 `decode_access_token(token: str) -> dict`：解码 Token，失败时抛出 `HTTPException(401)`

### 4.3 用户 Repository

- 在 `repositories/user_repo.py` 中实现 `get_user_by_username(username: str) -> dict | None`

### 4.4 Schemas 定义

- 在 `schemas/auth.py` 中定义 `LoginRequest`（username、password）和 `LoginResponse`（token、username）

### 4.5 登录接口

- 在 `api/auth.py` 中实现 `POST /api/auth/login`：验证用户名密码，成功返回 Token

### 4.6 退出登录接口

- 在 `api/auth.py` 中实现 `POST /api/auth/logout`，无状态 JWT，仅返回成功响应

### 4.7 鉴权依赖

- 在 `core/security.py` 中实现 `get_current_user` 依赖函数：从 Token 提取 user_id，查库确认用户存在，返回用户字典
- 后续所有需要登录的路由注入此依赖

### 4.8 验证认证模块

- 正确凭据登录确认返回 Token，错误密码返回 401
- 不携带 Token 访问受保护接口确认返回 401

---

## 阶段五：任务管理模块

### 5.1 任务 Repository

在 `repositories/task_repo.py` 中实现：

- `create_task(data: dict) -> int`：INSERT 任务记录，返回 lastrowid
- `get_task_by_id(task_id: int) -> dict | None`
- `get_task_by_md5(md5: str) -> dict | None`
- `update_task(task_id: int, fields: dict)`：动态更新指定字段
- `list_tasks(filters: dict, page: int, size: int) -> tuple[list, int]`：多条件过滤分页查询

### 5.2 Schemas 定义

- 在 `schemas/task.py` 中定义 `UrlSubmitRequest`、`TaskStatusResponse`、`TaskListItem`、`TaskListResponse`

### 5.3 APK 批量上传接口

- 在 `api/tasks.py` 中实现 `POST /api/tasks/upload`，接收 `files: list[UploadFile]`：
  - 对每个文件用 `python-magic` 校验 MIME 类型，非 APK 则跳过
  - 计算 MD5，调用 `get_task_by_md5` 检查重复
  - 上传 APK 到 MinIO `BUCKET_APK`，object_name 使用 `{md5}.apk`
  - 调用 `create_task` 创建记录，状态设为 `static_analyzing`
  - 触发 Celery 静态分析 Task
  - 返回每个文件的处理结果列表

### 5.4 URL 批量提交接口

- 在 `api/tasks.py` 中实现 `POST /api/tasks/url`：
  - 遍历每条 URL，校验格式
  - 调用 `create_task` 创建记录，状态设为 `downloading`
  - 触发 Celery 下载 Task，立即返回所有 task_id 列表

### 5.5 任务列表与搜索接口

- 在 `api/tasks.py` 中实现 `GET /api/tasks`，支持 md5、name、package、status、start、end、page、size 过滤

### 5.6 任务详情接口

- 在 `api/tasks.py` 中实现 `GET /api/tasks/{task_id}`：根据 status 决定是否附带静态结果、动态结果、流量日志

### 5.7 任务状态接口

- 在 `api/tasks.py` 中实现 `GET /api/tasks/{task_id}/status`：仅返回 status、device_id、error_message 三个字段

### 5.8 验证任务管理模块

- 上传单个 APK 确认返回 task_id，上传同一 APK 确认触发重复检测
- 上传非 APK 文件确认被拒绝，提交 2 条 URL 确认立即返回 2 个 task_id
- 测试列表接口按状态、MD5 过滤，确认结果正确

---

## 阶段六：Celery 任务队列

### 6.1 下载 Task

在 `workers/download.py` 中实现 Celery Task `download_apk(task_id: int, url: str)`：

- 用 `httpx` 流式下载文件到 `tmp/{task_id}_download.apk`，设置合理超时
- 下载失败时更新状态为 `download_failed`，记录 error_message，Task 返回
- 下载成功后用 `python-magic` 校验 MIME 类型，非 APK 则标记 `download_failed`
- 计算 MD5，检查重复
- 上传到 MinIO，更新 `tasks.apk_path`、`file_md5`、`file_size`
- 更新状态为 `static_analyzing`，触发静态分析 Task，清理临时文件

### 6.2 设备调度器

在 `workers/scheduler.py` 中实现设备调度逻辑：

- 以无限循环方式运行，每次循环间隔 10 秒
- 查询 `waiting_device` 任务和 `online` 设备，按序配对，更新状态
- 为每个配对成功的任务触发动态溯源 Task

### 6.3 错误重试策略

- 对网络相关异常自动重试，最多 3 次，指数退避
- 最终失败时在 `on_failure` 回调中更新任务状态为对应失败状态

### 6.4 验证任务队列

- 提交合法 URL，确认下载 Task 被触发，状态流转为 `static_analyzing`
- 提交无效 URL，确认任务状态变为 `download_failed` 且有 error_message

---

## 阶段七：静态分析模块

### 7.1 APK 解析器

在 `analyzers/apk_parser.py` 中实现 `parse_apk(apk_path: str) -> dict`，使用 androguard 提取：

- `app_name`、`package_name`、`version_name`、`version_code`
- `cert_md5`、`cert_sha1`、`cert_sha256`
- `permissions`（列表，每项含 name 和 is_dangerous，参考 Android 危险权限列表）
- `activities`（列表，每项含 name 和 is_launcher）、`services`、`providers`
- `so_files`（列表）
- `icon_bytes`（图标二进制数据）

### 7.2 静态分析 Celery Task

在 `workers/static_analysis.py` 中实现 Celery Task `analyze(task_id: int)`：

- 从数据库查询 `apk_path`，从 MinIO 下载 APK 到临时目录
- 调用 `apk_parser.parse_apk` 解析
- 将图标上传到 MinIO `BUCKET_ICONS`，获取 `icon_path`
- 将解析结果（含 icon_path）写入 `static_results` 表
- 更新任务状态为 `waiting_device`
- 异常时更新状态为 `static_failed`，记录 error_message，清理临时文件

### 7.3 静态结果接口

- 在 `repositories/task_repo.py` 中新增 `get_static_result(task_id: int) -> dict | None`
- 在 `api/tasks.py` 中实现 `GET /api/tasks/{task_id}/static`：对 icon_path 生成预签名 URL，返回完整静态分析结果

### 7.4 验证静态分析模块

- 上传真实 APK，等待完成，调用静态结果接口确认所有字段返回正确
- 使用损坏的 APK，确认状态变为 `static_failed` 且有 error_message

---

## 阶段八：动态溯源模块

### 8.1 ADB 控制器

在 `analyzers/adb_controller.py` 中使用 `subprocess` 封装以下方法：

- `is_device_online(serial)`、`get_device_info(serial)`
- `install_apk(serial, apk_path)`、`launch_app(serial, package, activity)`
- `take_screenshot(serial, remote_path, local_path)`
- `start_tcpdump(serial, remote_pcap_path)` → 返回 PID
- `stop_tcpdump(serial, pid)`、`pull_file(serial, remote_path, local_path)`
- `uninstall_apk(serial, package)`、`clear_remote_file(serial, remote_path)`

### 8.2 PCAP 解析器

在 `analyzers/pcap_parser.py` 中实现 `parse_pcap(pcap_path: str) -> list[dict]`：使用 `subprocess` 调用 `tshark -T json`，提取8个流量字段，返回结构化列表

### 8.3 动态溯源 Celery Task

在 `workers/dynamic_trace.py` 中实现 Celery Task `trace(task_id: int, device_id: int)`：

- 查询任务和设备信息，从 MinIO 下载 APK
- 安装 APK，启动 tcpdump 采集流量
- 执行模拟操作序列，每步截图并上传到 MinIO，写入 `dynamic_results` 表
- 停止 tcpdump，拉取 PCAP，上传到 MinIO，更新 `tasks.pcap_path`
- 调用 `pcap_parser.parse_pcap` 解析，批量写入 `traffic_logs` 表
- 卸载 APK，清理设备临时文件
- 更新设备状态为 `online`，更新任务状态为 `completed`
- 触发报告生成 Task
- 任何步骤异常：更新任务状态为 `dynamic_failed`，恢复设备状态，清理临时文件

### 8.4 动态溯源结果接口

- 在 `repositories/task_repo.py` 中新增 `get_dynamic_results` 和 `get_traffic_logs`（均支持分页）
- 在 `api/tasks.py` 中实现 `GET /api/tasks/{task_id}/dynamic`：为截图生成预签名 URL，返回操作记录和流量日志
- 在 `api/tasks.py` 中实现 `GET /api/tasks/{task_id}/screenshots/{seq}`：生成截图预签名 URL，302 重定向

### 8.5 验证动态溯源模块

- 上传 APK，等待调度器分配设备，确认动态溯源执行
- MinIO 中 screenshots 和 pcap Bucket 均有文件
- 调用动态结果接口，确认操作记录和流量日志数据正确

---

## 阶段九：文件下载与报告模块

### 9.1 PDF 报告模板

- 在 `templates/report.html` 中用 Jinja2 编写报告模板，包含：封面（任务ID、MD5、分析时间）、静态分析摘要、动态溯源记录（含内嵌截图）、流量日志汇总
- 所有 CSS 内联，兼容 WeasyPrint

### 9.2 报告生成服务

- 在 `services/report_service.py` 中实现 `generate_pdf(task_id: int) -> str`：
  - 从数据库查询所有所需数据
  - 截图通过 MinIO SDK 直接读取二进制转 base64 内嵌 HTML
  - Jinja2 渲染模板，WeasyPrint 生成 PDF bytes
  - 上传到 MinIO `BUCKET_REPORTS`，返回存储路径

### 9.3 报告生成 Celery Task

- 在 `workers/report.py` 中实现 Celery Task `generate(task_id: int)`：调用 `generate_pdf`，成功后将路径写入 `tasks.report_path`

### 9.4 文件下载接口

在 `api/tasks.py` 中实现三个下载接口，均生成预签名 URL 返回：

- `GET /api/tasks/{task_id}/apk`：查询 `tasks.apk_path`，生成预签名 URL
- `GET /api/tasks/{task_id}/report`：查询 `tasks.report_path`，为空则返回 404
- `GET /api/tasks/{task_id}/pcap`：查询 `tasks.pcap_path`，为空则返回 404

### 9.5 验证下载与报告模块

- 等待任务完成，依次测试三个下载接口，确认均可正常下载
- 打开 PDF，确认内容完整（权限、证书、截图内嵌、流量日志）

---

## 阶段十：设备管理与看板模块

### 10.1 设备 Repository

在 `repositories/device_repo.py` 中实现 `create_device`、`get_device_by_id`、`get_device_by_serial`、`list_devices`、`update_device`、`delete_device`、`get_available_devices`

### 10.2 设备管理接口

在 `api/devices.py` 中实现：

- `GET /api/devices`、`GET /api/devices/{device_id}`
- `POST /api/devices`：验证设备可达，检查重复，获取设备信息，写入数据库
- `PUT /api/devices/{device_id}`：更新设备名称
- `DELETE /api/devices/{device_id}`：检查是否有进行中任务后删除

### 10.3 看板 Repository 与接口

- 在 `repositories/dashboard_repo.py` 中实现 `get_stats()` 和 `get_trend(days: int)`
- 在 `api/dashboard.py` 中实现 `GET /api/dashboard/stats` 和 `GET /api/dashboard/trend`

### 10.4 验证设备与看板模块

- 添加真实设备确认返回型号和版本信息，添加重复 serial 确认报错
- 看板统计数字与数据库实际数量一致，趋势接口返回正确格式

---

## 阶段十一：前端工程初始化

### 11.1 清理与基础配置

- 清空 `src/App.vue`，仅保留 `<router-view />`
- 在 `vite.config.js` 中配置 `/api` 代理到 `http://localhost:8000`

### 11.2 全局注册

- 在 `src/main.js` 中依次注册：Vue app → Pinia → Vue Router → Ant Design Vue → 挂载 `#app`

### 11.3 axios 封装

- 在 `src/api/request.js` 中创建 axios 实例
- 请求拦截器：读取 `useAuthStore().token`，设置 `Authorization: Bearer {token}` 请求头
- 响应拦截器：解包 `response.data.data`；401 时清除登录跳转 `/login`；其他错误展示 `message.error`

### 11.4 API 模块

在 `src/api/` 各文件中导出对应接口调用函数：`auth.js`、`tasks.js`（含上传/提交/列表/详情/状态/静态结果/动态结果/三个下载）、`devices.js`、`dashboard.js`

### 11.5 路由配置

- 定义路由表，所有页面懒加载
- 全局前置守卫：目标路由需要登录且无 Token 则跳转 `/login`，携带 `redirect` 参数

### 11.6 Pinia Store 初始化

- `useAuthStore`：state 含 `token`（从 localStorage 读取初始值）、`username`；actions 含 `login`、`logout`
- `useTaskStore`、`useDeviceStore`、`useDashboardStore`：创建基础结构，后续阶段填充

### 11.7 工具函数

- `polling.js`：`usePolling(fetchFn, intervalMs)` 返回 `{start, stop}`，终态常量 `['completed', 'download_failed', 'static_failed', 'dynamic_failed']`
- `format.js`：`formatFileSize(bytes)` 和 `formatDateTime(isoString)`

### 11.8 验证前端初始化

- `npm run dev` 启动无报错，访问自动重定向到 `/login`，`/api` 请求代理到后端正常

---

## 阶段十二：前端认证与全局布局

### 12.1 登录页面

- 实现 `src/views/Login.vue`：Form 校验（用户名/密码必填）、loading 状态、错误提示
- 登录成功后由 Store action 负责跳转，页面本身不处理路由

### 12.2 全局布局组件

- 实现 `src/components/AppLayout.vue`：左侧导航（看板/任务管理/设备管理）、Header 显示用户名和退出按钮
- 路由切换时菜单自动高亮

### 12.3 验证

- 登录确认跳转、布局正常，退出确认 token 清除

---

## 阶段十三：前端任务模块

### 13.1 TaskStatusTag 组件

- 实现 `src/components/TaskStatusTag.vue`：接收 `status` prop，映射8种状态的颜色和中文标签，使用 Ant Design `Tag` 渲染

### 13.2 TaskUploadModal 组件

- 实现 `src/components/TaskUploadModal.vue`：两个 Tab（APK 批量上传 / URL 批量提交），提交成功后 emit `success` 触发父组件刷新

### 13.3 任务 Store

- 完善 `src/stores/task.js`：state（tasks、total、page、size、filters、loading）；actions（fetchTasks、setFilters、setPage、refreshTaskStatus）

### 13.4 任务列表页面

- 实现 `src/views/TaskList.vue`：
  - 搜索区：MD5、名称、包名、状态下拉、时间范围选择器
  - 「上传/提交分析」按钮打开 `TaskUploadModal`
  - 任务表格列：图标、APP名称/包名、来源、MD5、提交时间、状态（`TaskStatusTag`）、分配设备、操作
  - 操作列：「查看」始终显示；`completed` 时显示「下载APK」「下载报告」「下载PCAP」
  - 对非终态任务启动 `usePolling` 轮询，终态后停止并刷新行数据

### 13.5 验证任务模块

- 上传 APK 确认列表出现新行，状态实时更新
- 搜索功能按状态、MD5、名称过滤结果正确
- 已完成任务操作列有三个下载按钮

---

## 阶段十四：前端结果展示模块

### 14.1 StaticResult 组件

- 实现 `src/components/StaticResult.vue`：图标、基础信息（MD5/大小/名称/包名/版本）、证书三项、权限清单（危险权限标红）、组件列表（Collapse）、SO 文件

### 14.2 TrafficLogTable 组件

- 实现 `src/components/TrafficLogTable.vue`：8列流量表格，协议列支持筛选，URL 列截断+Tooltip+一键复制

### 14.3 ScreenshotViewer 组件

- 实现 `src/components/ScreenshotViewer.vue`：缩略图网格，点击打开 `Image.PreviewGroup` 大图预览，支持键盘左右切换

### 14.4 DynamicResult 组件

- 实现 `src/components/DynamicResult.vue`：操作记录 Table（展开行显示截图）+ 下方流量日志（`TrafficLogTable`）

### 14.5 任务详情页面

- 实现 `src/views/TaskDetail.vue`：
  - 基础信息卡片：文件名/URL、MD5、文件大小、提交时间、状态、分配设备；失败时红色 Alert 显示 error_message
  - 下载操作行：下载APK、下载报告、下载PCAP，按状态显隐
  - 结果 Tabs：「静态分析」（`StaticResult`）、「动态溯源」（`DynamicResult`）
  - 非终态时显示进度提示，启动轮询，终态后刷新

### 14.6 验证结果展示模块

- 静态分析 Tab：图标、权限标红、证书、组件列表均正常
- 动态溯源 Tab：操作记录展开有截图，流量日志8列正确
- 三个下载按钮均可正常下载

---

## 阶段十五：前端设备与看板模块

### 15.1 设备管理页面

- 实现 `src/views/DeviceList.vue`：添加设备 Modal、设备列表（状态 Badge、当前任务、最后心跳）、删除二次确认、每30秒自动刷新

### 15.2 看板页面

- 实现 `src/views/Dashboard.vue`：6 个统计卡片（Statistic）、任务趋势折线图（ECharts，7天/30天切换）、统计数据每30秒自动刷新

### 15.3 看板 Store

- 完善 `src/stores/dashboard.js`：`fetchStats()`、`fetchTrend(days)`、`setTrendDays(days)`

### 15.4 验证

- 看板统计与数据库一致，趋势图切换正常，设备管理增删改查正常

---

## 阶段十六：联调与集成测试

### 16.1 全链路通测——APK 上传路径

1. 前端上传真实 APK，确认列表出现新任务
2. 状态依次流转：`static_analyzing` → `waiting_device` → `dynamic_tracing` → `completed`
3. 进入详情，确认静态分析和动态溯源结果完整
4. 下载三个文件，确认 APK 可安装、PCAP 可用 Wireshark 打开、PDF 内容完整

### 16.2 全链路通测——URL 提交路径

- 提交真实 APK 下载链接，确认任务立即创建（`downloading`），后续流转与 APK 路径一致

### 16.3 边界场景测试

- 上传超 500MB 文件，确认被拒绝
- 上传非 APK 文件（.zip），确认被拒绝
- 同时提交 5 条 URL，确认 5 个任务独立执行
- 所有设备离线时上传 APK，确认任务停留 `waiting_device`，上线后自动调度
- 动态溯源中断开 ADB，确认任务变为 `dynamic_failed`，设备恢复 `online`
- 查询不存在的 task_id，确认返回 404

### 16.4 性能基线验证

- 静态分析耗时 ≤ 5 分钟，动态溯源耗时 ≤ 30 分钟，任务列表页面首次加载 ≤ 3 秒

### 16.5 数据一致性验证

- 抽查 5 个 completed 任务，核对前端展示 = 数据库记录 = MinIO 文件存在
- 确认 `devices` 表无状态 `busy` 但任务已完成的脏数据

---

## 阶段十七：部署与收尾

### 17.1 后端生产镜像优化

- 优化 Dockerfile 构建层级，固定 `adb`、`tshark` 版本
- 设置 `PYTHONDONTWRITEBYTECODE=1` 和 `PYTHONUNBUFFERED=1`
- `tmp/` 目录通过 Docker Volume 挂载

### 17.2 前端生产构建

- 创建 `frontend/Dockerfile`：多阶段构建（builder 执行 `npm run build`，runner 基于 `nginx:alpine`）
- `frontend/.env.production` 中 `VITE_API_BASE_URL` 设为空字符串

### 17.3 Nginx 配置

- 在 `infra/nginx.conf` 中配置：
  - `location /` → 前端静态文件，`try_files $uri $uri/ /index.html`
  - `location /api/` → 反向代理到 `http://api:8000`，`proxy_read_timeout 300s`
  - `client_max_body_size 600m`，开启 gzip 压缩

### 17.4 生产环境配置

- 创建 `infra/.env.prod`（不提交 Git）：强随机 JWT 密钥、强密码、生产域名 CORS
- 数据卷配置绝对路径挂载，所有服务配置 `restart: unless-stopped`

### 17.5 日志与备份

- FastAPI 日志输出 stdout，Docker 配置 `max-size: 100m`，`max-file: 3`
- `infra/backup.sh`：mysqldump 全量备份，gzip 压缩，保留7天，crontab 每日凌晨3点执行

### 17.6 文档整理

- 完善 `README.md`：项目简介、技术栈、外部依赖安装、本地开发启动步骤、数据库初始化、生产部署、环境变量说明
- 将需求说明书、技术栈方案、实施计划三份文档移入 `docs/`

### 17.7 最终验收

- 全新环境按 `README.md` 从零启动，确认文档步骤完整
- 执行阶段十六全链路通测
- Swagger UI 所有接口有清晰文档
- 确认各 MinIO Bucket 权限正确，文件通过预签名 URL 访问

---

## 附录：各阶段交付物清单

| 阶段 | 主要交付物 |
|---|---|
| 一 | Git 仓库骨架、docker-compose.yml、Dockerfile、requirements.txt、package.json、.env.example |
| 二 | v1_init.sql（6张表）、database.py 连接层 |
| 三 | main.py、core/ 配置与公共层、Celery 初始化、MinIO Bucket 初始化、健康检查接口 |
| 四 | security.py、user_repo.py、登录/退出接口、鉴权 Depends |
| 五 | task_repo.py、schemas/task.py、5个任务相关接口 |
| 六 | workers/download.py、workers/scheduler.py、错误重试配置 |
| 七 | analyzers/apk_parser.py、workers/static_analysis.py、静态结果接口 |
| 八 | analyzers/adb_controller.py、analyzers/pcap_parser.py、workers/dynamic_trace.py、动态结果接口、截图接口 |
| 九 | templates/report.html、services/report_service.py、workers/report.py、三个下载接口 |
| 十 | repositories/device_repo.py、api/devices.py、repositories/dashboard_repo.py、api/dashboard.py |
| 十一 | 前端骨架、request.js、api/ 模块、router/index.js、stores/ 基础结构、utils/ 工具函数 |
| 十二 | Login.vue、AppLayout.vue |
| 十三 | TaskStatusTag.vue、TaskUploadModal.vue、TaskList.vue、task Store 完善 |
| 十四 | StaticResult.vue、TrafficLogTable.vue、ScreenshotViewer.vue、DynamicResult.vue、TaskDetail.vue |
| 十五 | DeviceList.vue、Dashboard.vue、dashboard Store 完善 |
| 十六 | 全链路测试报告、边界问题修复记录 |
| 十七 | 生产 Dockerfile、nginx.conf、backup.sh、完整 README.md |
