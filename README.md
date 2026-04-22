# 诈骗APP分析系统

该项目用于对可疑 APK 进行静态分析与动态溯源，输出结构化结果与 PDF 报告，支持任务看板与设备管理。

## 技术栈概览

- 后端：FastAPI + Celery + Redis + MySQL + MinIO
- 前端：Vue 3 + Vite + Ant Design Vue + Pinia + Vue Router
- 分析：androguard + adb + tshark + WeasyPrint

## 快速启动（开发模式）

本项目当前阶段仅完成工程骨架与基础文件创建，尚未包含可运行服务。

## 数据库初始化（阶段二）

1. 使用 MySQL 客户端连接到目标数据库实例
2. 执行初始化脚本：`backend/migrations/v1_init.sql`
3. 手动插入一条管理员用户记录（`users.password_hash` 使用 bcrypt 预生成哈希）
4. 可选：运行连接测试脚本 `backend/scripts/db_test.py` 验证数据库连通性

## 服务器排障：`adb command not found`（CentOS 7）

当 URL 上传任务或动态分析任务卡在 `waiting_device` / `dynamic_tracing`，且日志出现 `adb: command not found` 时，可按以下步骤处理：

1. 安装 ADB（系统级依赖）：
   ```bash
   sudo yum install -y epel-release
   sudo yum install -y android-tools
   ```
2. 验证安装：
   ```bash
   command -v adb
   adb version
   adb devices
   ```
3. 在后端虚拟环境下重启相关进程（后端 API / Celery Worker / 调度器）：
   ```bash
   cd /home/yxh/app_analysis/backend
   source .venv/bin/activate

   # API
   nohup uvicorn main:app --host 0.0.0.0 --port 8000 --app-dir /home/yxh/app_analysis/backend > /home/yxh/app_analysis/run_logs/backend.log 2>&1 &

   # Worker
   nohup celery -A workers.celery_app worker --loglevel=info > /home/yxh/app_analysis/run_logs/celery_worker.log 2>&1 &

   # Scheduler
   nohup python -m workers.scheduler > /home/yxh/app_analysis/run_logs/scheduler.log 2>&1 &
   ```

> 说明：本项目使用虚拟环境部署时，`adb` 仍是系统命令，需在服务器 OS 层可用，不能仅通过 Python 依赖安装替代。

## 目录结构

- backend/：后端代码
- frontend/：前端代码
- infra/：部署与基础设施文件（仅用于后续一键部署）
- docs/：项目文档
