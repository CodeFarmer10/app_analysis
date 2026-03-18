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
