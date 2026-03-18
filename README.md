# 诈骗APP分析系统

该项目用于对可疑 APK 进行静态分析与动态溯源，输出结构化结果与 PDF 报告，支持任务看板与设备管理。

## 技术栈概览

- 后端：FastAPI + Celery + Redis + MySQL + MinIO
- 前端：Vue 3 + Vite + Ant Design Vue + Pinia + Vue Router
- 分析：androguard + adb + tshark + WeasyPrint

## 快速启动（开发模式）

本项目当前阶段仅完成工程骨架与基础文件创建，尚未包含可运行服务。

## 目录结构

- backend/：后端代码
- frontend/：前端代码
- infra/：部署与基础设施文件（仅用于后续一键部署）
- docs/：项目文档

