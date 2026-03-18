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

## 目录结构

- backend/：后端代码
- frontend/：前端代码
- infra/：部署与基础设施文件（仅用于后续一键部署）
- docs/：项目文档
