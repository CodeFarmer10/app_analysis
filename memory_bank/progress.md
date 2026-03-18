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
