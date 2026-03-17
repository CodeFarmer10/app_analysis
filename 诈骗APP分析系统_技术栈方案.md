# 诈骗APP分析系统 技术栈方案

*Fraud APP Analysis Platform — Tech Stack*

| 文档版本 | 编写日期 | 状态 |
|---|---|---|
| V1.0 | 2026年3月 | 已确认 |

---

## 目录

1. [总体原则](#1-总体原则)
2. [后端技术栈](#2-后端技术栈)
3. [前端技术栈](#3-前端技术栈)
4. [基础设施](#4-基础设施)
5. [项目结构](#5-项目结构)
6. [关键数据流](#6-关键数据流)
7. [技术栈汇总](#7-技术栈汇总)

---

## 1. 总体原则

- **最简原则**：每个功能场景只选一个最成熟的库，不引入同类竞品
- **模块化**：按业务职责拆分模块，各模块边界清晰，依赖单向
- **轻依赖**：尽量减少对外部系统二进制工具的依赖，降低部署复杂度；确需外部工具的（ADB、tshark）在文档中明确说明
- **易维护**：数据库结构与代码解耦，迁移和变更不依赖 ORM 框架约束

---

## 2. 后端技术栈

### 2.1 Web 框架

**FastAPI**

原生支持异步，适合任务状态轮询、文件上传等 I/O 密集场景。自动生成 OpenAPI 文档，接口定义即文档，减少额外维护成本。使用 Pydantic 做请求与响应的数据校验，减少手写验证逻辑。

### 2.2 数据库访问

**PyMySQL（直接执行 SQL）**

不引入 ORM 框架，数据库结构与业务代码解耦。所有 SQL 集中在各模块的 Repository 层统一管理，业务逻辑层不直接接触 SQL。数据库结构变更通过手动维护迁移脚本实现，版本可控、行为透明。

数据库选型为 **MySQL 8**。

### 2.3 任务队列

**Celery + Redis**

异步下载、静态分析、动态溯源均为耗时任务，必须走队列异步执行，不阻塞 HTTP 响应。Redis 同时承担 Celery Broker 和任务结果缓存两个角色，无需额外引入 RabbitMQ。每个分析阶段对应一个独立的 Celery Task，任务状态变更直接写入 MySQL。

### 2.4 文件存储

**minio-py（MinIO 官方 Python SDK）**

封装为统一的 `StorageService`，对外暴露上传、下载、生成预签名 URL 三个核心方法，覆盖所有文件操作场景。APK 样本、运行截图、PCAP 流量包、PDF 报告分存不同 Bucket，便于权限管理与生命周期策略配置。

### 2.5 静态分析

**androguard**

纯 Python 实现，解析 APK 无需调用外部进程，无额外环境依赖。可提取 AndroidManifest.xml 中的权限声明、Activity/Service/Provider 组件列表、签名证书（MD5/SHA1/SHA256）、SO 文件列表、版本信息等全部静态分析所需字段。

补充 **python-magic** 做文件类型校验，拒绝非 APK 格式文件进入分析流程。

### 2.6 动态溯源

**subprocess 调用 ADB**

通过 Python 标准库 `subprocess` 直接调用系统安装的 `adb` 命令行工具，控制 Android 真机或模拟器完成以下操作：

- 安装 APK 到目标设备
- 启动应用并模拟用户操作（点击、输入、滑动等）
- 截图并通过 ADB pull 回传至服务端
- 在设备端启动 `tcpdump` 进行流量采集，完成后将 PCAP 文件 pull 回服务端

设备调度逻辑由 `scheduler` 模块实现，轮询 MySQL 中处于 `waiting_device` 状态的任务，匹配空闲设备后更新任务状态与设备状态，触发动态溯源 Celery Task。

> **部署要求**：运行 Worker 的服务器需预先安装 `adb`，且与分析设备处于同一网络，支持 ADB over TCP/IP 连接。

### 2.7 流量解析

**subprocess 调用 tshark**

通过 `subprocess` 调用 `tshark`（Wireshark 命令行版本）解析 PCAP 文件，以 JSON 格式输出结构化流量数据，提取以下字段：

- 源IP / 目的IP
- 源端口 / 目的端口
- 协议类型（TCP/UDP/HTTP/HTTPS/DNS 等）
- 域名（DNS 查询 / HTTP Host 字段）
- URL（HTTP/HTTPS 完整请求路径）
- 解析IP（DNS 响应中的解析结果）

解析结果直接写入 MySQL，同时保留原始 PCAP 文件存入 MinIO 供下载。

> **部署要求**：运行 Worker 的服务器需预先安装 `tshark`（`apt install tshark` 或 `yum install wireshark`）。

### 2.8 PDF 报告生成

**WeasyPrint + Jinja2**

报告模板使用 Jinja2 编写 HTML/CSS，`ReportService` 将静态分析与动态溯源结果填充至模板后，由 WeasyPrint 渲染为 PDF。纯 Python 实现，无需安装浏览器依赖。生成的 PDF 文件上传至 MinIO，接口返回预签名下载链接。

### 2.9 认证

**python-jose + passlib**

`python-jose` 负责 JWT Token 的签发与校验，`passlib` 使用 bcrypt 算法对密码进行哈希存储。FastAPI 的 `Depends` 机制实现路由级鉴权，所有需要登录的接口统一注入鉴权依赖，无需在每个路由中重复编写校验逻辑。

---

## 3. 前端技术栈

### 3.1 框架

**Vue 3 + Vite**

Vue 3 Composition API 适合任务状态轮询、动态列表等逻辑复用场景，`setup` 语法糖让组件逻辑更集中。Vite 提供极快的冷启动与热更新速度，开发体验流畅。

### 3.2 UI 组件库

**Ant Design Vue 4**

Table、Upload、Form、Tag、Drawer、Modal 等组件直接覆盖需求中 90% 的界面场景：

- 任务列表 → `Table` + `Tag`（状态颜色）
- 批量上传 → `Upload`（multiple 模式）+ `Textarea`（URL 批量输入）
- 设备管理 → `Table` + `Modal`（添加/删除确认）
- 搜索过滤 → `Form` + `DateRangePicker` + `Select`

### 3.3 状态管理

**Pinia**

Vue 3 官方推荐的状态管理库，比 Vuex 语法更简洁。按业务模块拆分 Store：

- `useAuthStore`：Token 存储、登录/退出逻辑
- `useTaskStore`：任务列表数据、轮询状态管理
- `useDeviceStore`：设备列表与状态
- `useDashboardStore`：看板统计数据与自动刷新

### 3.4 路由

**Vue Router 4**

全局路由守卫拦截未登录访问，自动跳转至登录页。页面组件懒加载，减少首屏资源体积。

### 3.5 HTTP 请求

**axios**

封装统一的请求实例，统一处理以下逻辑：

- 自动附加 `Authorization: Bearer {token}` 请求头
- 响应拦截器统一处理错误提示
- Token 过期时自动清除本地状态并跳转登录页

按模块拆分 API 文件（`api/tasks.js`、`api/devices.js` 等），与后端路由模块一一对应。

### 3.6 图表

**ECharts 5（通过 vue-echarts 封装）**

看板页面的任务趋势使用折线图或柱状图展示近 7 天/30 天数据，配置式 API 简单直接，无需引入 D3 等复杂图表库。

---

## 4. 基础设施

### 4.1 容器化

**Docker + Docker Compose**

所有服务通过 Docker Compose 统一编排，一条命令完成本地开发与测试环境启动：

| 服务 | 说明 |
|---|---|
| `api` | FastAPI 应用，对外暴露 HTTP 接口 |
| `worker` | Celery Worker，与 `api` 共用同一镜像，启动命令不同 |
| `scheduler` | Celery Beat 或独立调度进程，负责设备轮询与任务分配 |
| `mysql` | MySQL 8，持久化任务与设备数据 |
| `redis` | Redis 7，Celery Broker 与结果缓存 |
| `minio` | MinIO，文件对象存储 |

`api` 与 `worker` 共用同一 Docker 镜像，仅启动命令不同，减少镜像维护成本。

### 4.2 配置管理

所有环境变量（数据库连接、MinIO 地址、JWT 密钥、Redis 地址等）通过 `.env` 文件统一管理，`core/config.py` 使用 `pydantic-settings` 读取，不在代码中硬编码任何配置项。

---

## 5. 项目结构

### 5.1 后端结构

```
backend/
├── main.py                     # FastAPI 入口，注册路由与中间件
├── core/
│   ├── config.py               # 环境变量读取（pydantic-settings）
│   ├── database.py             # PyMySQL 连接池管理
│   └── security.py             # JWT 签发与校验、bcrypt 密码哈希
├── models/                     # 数据结构定义（Pydantic，仅用于校验，非 ORM）
│   ├── task.py
│   └── device.py
├── schemas/                    # Pydantic 请求/响应模型
│   ├── task.py
│   └── device.py
├── api/                        # FastAPI 路由层（薄层，只做参数校验，调用 service）
│   ├── auth.py
│   ├── tasks.py
│   ├── devices.py
│   └── dashboard.py
├── repositories/               # 数据访问层，所有 SQL 集中在此
│   ├── task_repo.py
│   └── device_repo.py
├── services/                   # 业务逻辑层
│   ├── task_service.py
│   ├── device_service.py
│   ├── storage_service.py      # MinIO 封装
│   └── report_service.py       # PDF 报告生成
├── workers/                    # Celery Tasks
│   ├── celery_app.py           # Celery 实例与队列配置
│   ├── download.py             # 异步下载任务
│   ├── static_analysis.py      # 静态分析任务
│   ├── dynamic_trace.py        # 动态溯源任务
│   └── scheduler.py            # 设备调度（轮询 waiting_device 队列）
├── analyzers/                  # 分析引擎（纯逻辑，无 HTTP 依赖）
│   ├── apk_parser.py           # androguard 封装，提取静态分析结果
│   ├── adb_controller.py       # subprocess 调用 adb，控制设备
│   └── pcap_parser.py          # subprocess 调用 tshark，解析流量
├── templates/                  # Jinja2 报告 HTML 模板
│   └── report.html
├── migrations/                 # 手动维护的数据库迁移 SQL 脚本
│   ├── v1_init.sql
│   └── v2_xxx.sql
├── requirements.txt
└── .env
```

### 5.2 前端结构

```
frontend/
├── index.html
├── vite.config.js
├── src/
│   ├── main.js                     # 入口，注册插件（Vue、Router、Pinia、Antd）
│   ├── App.vue
│   ├── router/
│   │   └── index.js                # 路由定义 + 全局登录守卫
│   ├── stores/                     # Pinia Store
│   │   ├── auth.js                 # Token 管理、登录/退出
│   │   ├── task.js                 # 任务列表、轮询逻辑
│   │   ├── device.js               # 设备列表与状态
│   │   └── dashboard.js            # 看板数据与自动刷新
│   ├── api/                        # axios 请求封装
│   │   ├── request.js              # axios 实例（拦截器、baseURL 配置）
│   │   ├── auth.js
│   │   ├── tasks.js
│   │   ├── devices.js
│   │   └── dashboard.js
│   ├── views/                      # 页面级组件
│   │   ├── Login.vue
│   │   ├── Dashboard.vue
│   │   ├── TaskList.vue
│   │   ├── TaskDetail.vue          # 静态分析 + 动态溯源 Tab 页
│   │   └── DeviceList.vue
│   ├── components/                 # 可复用业务组件
│   │   ├── TaskStatusTag.vue       # 8种状态对应的颜色标签
│   │   ├── TaskUploadModal.vue     # 批量上传弹窗（APK文件 / URL 两个Tab）
│   │   ├── StaticResult.vue        # 静态分析结果展示
│   │   ├── DynamicResult.vue       # 动态溯源操作记录列表
│   │   ├── TrafficLogTable.vue     # 流量日志表格（含展开行查看详情）
│   │   └── ScreenshotViewer.vue    # 截图放大查看器（支持左右切换）
│   └── utils/
│       ├── polling.js              # 通用轮询工具（终态自动停止）
│       └── format.js               # 文件大小、时间格式化
└── package.json
```

---

## 6. 关键数据流

### 6.1 APK 上传分析流程

```
用户上传 APK
    → api/tasks（接收文件，写任务记录至 MySQL，状态: static_analyzing）
    → APK 存入 MinIO
    → 触发 Celery Task: static_analysis
        → apk_parser 解析，结果写入 MySQL
        → 状态更新: waiting_device
    → scheduler 轮询到等待任务 + 空闲设备
        → 更新任务状态: dynamic_tracing，写入分配设备
        → 触发 Celery Task: dynamic_trace
            → adb_controller 安装APK、执行操作、截图 pull 至服务端
            → tcpdump 采集流量，PCAP pull 至服务端
            → 截图上传 MinIO
            → pcap_parser（tshark）解析流量，结构化数据写入 MySQL
            → PCAP 上传 MinIO
            → 状态更新: completed
            → report_service 生成 PDF → 上传 MinIO
```

### 6.2 URL 批量提交流程

```
用户提交 URL 列表
    → api/tasks 为每条 URL 独立创建任务记录（状态: downloading）
    → 立即返回任务 ID 列表
    → 每个任务触发 Celery Task: download
        → 下载成功 → APK 存入 MinIO → 状态: static_analyzing → 进入 6.1 静态分析流程
        → 下载失败 → 状态: download_failed，记录失败原因
```

### 6.3 前端状态轮询流程

```
TaskList / TaskDetail 页面加载
    → 对非终态任务启动轮询（每5秒调用 GET /api/tasks/{id}/status）
    → 状态变为终态（completed / *_failed）时自动停止轮询
    → TaskList 刷新对应行数据，TaskDetail 刷新结果 Tab
```

---

## 7. 技术栈汇总

### 后端

| 类别 | 选型 | 说明 |
|---|---|---|
| Web 框架 | FastAPI | 异步、自动文档、Pydantic 校验 |
| 数据库 | MySQL 8 | 主数据存储 |
| 数据库驱动 | PyMySQL | 直接执行 SQL，不使用 ORM |
| 任务队列 | Celery + Redis | 异步任务调度，Redis 兼作 Broker |
| 文件存储 | MinIO + minio-py | APK、截图、PCAP、PDF 统一存储 |
| 静态分析 | androguard | 纯 Python 解析 APK |
| 文件校验 | python-magic | 校验上传文件是否为 APK 格式 |
| 动态溯源 | subprocess + adb | 调用系统 adb 控制 Android 设备 |
| 流量解析 | subprocess + tshark | 解析 PCAP，提取8项流量字段 |
| PDF 生成 | WeasyPrint + Jinja2 | HTML 模板渲染为 PDF |
| 认证 | python-jose + passlib | JWT Token + bcrypt 密码哈希 |
| 配置管理 | pydantic-settings | 读取 .env 环境变量 |

### 前端

| 类别 | 选型 | 说明 |
|---|---|---|
| 框架 | Vue 3 + Vite | Composition API，极速构建 |
| UI 组件库 | Ant Design Vue 4 | 覆盖所有界面场景 |
| 状态管理 | Pinia | Vue 3 官方推荐 |
| 路由 | Vue Router 4 | 路由守卫做登录拦截 |
| HTTP | axios | 统一拦截器、Token 处理 |
| 图表 | ECharts 5 + vue-echarts | 看板趋势图 |

### 基础设施

| 类别 | 选型 | 说明 |
|---|---|---|
| 容器化 | Docker + Docker Compose | 一键启动所有服务 |
| 缓存/消息 | Redis 7 | Celery Broker + 结果缓存 |

### 外部工具依赖

| 工具 | 用途 | 安装方式 |
|---|---|---|
| adb | 控制 Android 设备执行动态溯源 | 随 Android SDK 安装，或 `apt install adb` |
| tshark | 解析 PCAP 流量文件 | `apt install tshark` 或 `yum install wireshark` |
| tcpdump | 在 Android 设备端采集网络流量 | 需推送至 Android 设备，或使用 root 权限下的内置版本 |
