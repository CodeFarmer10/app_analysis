# 隔离设备自动恢复设计

## 目标

系统每 60 秒扫描一次隔离设备，直接执行设备恢复，不投递 Celery 恢复任务。恢复流程会重启设备、清理导致隔离的残留 APP、检查设备运行能力，并用专用 APK 完成真实安装和卸载验证。只有全部步骤成功，设备才能重新变为 `online`；任一步失败则变为 `error`。

动态分析任务与设备恢复相互独立。设备故障导致动态任务回到 `waiting_device` 的现有逻辑保持不变；恢复扫描不会重新投递动态分析任务。

## 状态模型

设备状态扩展为：

```text
quarantined -> recovering -> online
                          -> error
```

- `quarantined`：设备已隔离，等待自动恢复。
- `recovering`：恢复进程已经原子抢占设备，正在直接执行恢复。
- `online`：恢复和真实 APK 验证全部成功，可以参与调度。
- `error`：重启、清理或验证失败，不再自动重试，等待人工处理。
- `recovering` 和 `error` 永远不能参与动态任务调度。
- 心跳不得自动恢复 `quarantined`、`recovering` 或 `error`。

人工处理 `error` 设备后，需要明确将其重新设置为 `quarantined`，才会再次进入自动恢复流程。本次改动不增加自动循环重试。

## 持久化字段

`devices` 表增加：

- `quarantine_task_id VARCHAR(36)`：导致本次隔离的任务 ID。
- `quarantine_package_name VARCHAR(256)`：需要清理的残留业务 APP 包名。
- `recovery_started_at DATETIME`：恢复真正开始的时间。
- `last_recovery_at DATETIME`：最后一次恢复结束的时间。
- `recovery_error TEXT`：恢复失败的步骤和原始错误。

`status` 枚举增加 `recovering` 和 `error`。基础建表 SQL 与现有数据库兼容迁移同时更新，迁移必须可重复执行。

设备因动态任务故障进入隔离时，已知包名必须写入 `quarantine_package_name`；心跳发现的空闲设备故障没有任务包名时允许为空。自动清理只卸载该字段记录的业务 APP，不批量卸载其他第三方应用，也不删除 ADBKeyboard、Frida 或系统应用。

## 独立恢复进程

新增 `backend/workers/device_recovery.py`，由 `start.sh` 以独立进程启动，由 `stop.sh` 停止。该进程不使用 Celery 队列或 Celery Beat。

主循环每 60 秒执行一次扫描。最多使用两个工作线程直接恢复不同设备：

1. 查询 `status='quarantined' AND current_task_id IS NULL` 的设备。
2. 对每台设备执行带条件的原子更新：`quarantined -> recovering`，同时设置 `recovery_started_at=NOW()` 并清空旧的 `recovery_error`。
3. 只有更新成功的进程可以恢复该设备；其他进程或下一轮扫描会跳过 `recovering`。
4. 每个工作线程只处理一台设备，同一设备不会并发恢复。
5. 单台设备处理结束后释放线程，不影响下一轮扫描和其他设备。

即使误启动多个恢复进程，数据库条件更新仍保证单台设备只有一个恢复执行者。

## 恢复流程

恢复步骤严格按以下顺序执行：

1. 执行 `adb -s <serial> reboot`。
2. 最长等待 180 秒：
   - TCP ADB 设备允许重新执行 `adb connect`。
   - `adb get-state` 必须返回 `device`。
   - `adb shell getprop sys.boot_completed` 必须返回 `1`。
   - `adb shell echo __device_recovery_ok__` 必须返回完整标记。
3. 如果 `quarantine_package_name` 非空，卸载该残留 APP，并通过包管理器确认包名已经不存在。
4. 执行设备能力检查：
   - Package Manager 可用。
   - `/data` 可用空间不少于 5 GiB。
   - `adb shell ps -A` 执行成功且输出非空。
   - 输出不得包含 `fork failed`、`resource temporarily unavailable` 等设备资源错误。
   - 不限制进程数量。
5. 使用专用健康检查 APK 做真实验证：
   - APK 路径：`backend/tools/device_health/DeviceHealthCheck.apk`。
   - 固定包名：`com.fraudanalysis.devicehealth`。
   - 安装成功后确认包存在。
   - 卸载成功后确认包不存在。
6. 再执行一次基础健康检查，避免卸载或包管理器操作后设备状态发生变化。

本次恢复流程不会安装待分析的诈骗 APP，也不改变“动态任务分配后到首次业务 APK 安装前不额外健康检查”的现有规则。

## 成功与失败处理

### 成功

使用带 `status='recovering'` 条件的更新：

- 状态改为 `online`。
- 清空 `quarantine_reason`、`quarantined_at`。
- 清空 `quarantine_task_id`、`quarantine_package_name`。
- 清空 `recovery_error`、`recovery_started_at`。
- 设置 `last_recovery_at=NOW()`。
- 设置 `last_heartbeat_at=NOW()`。

只有该条件更新成功，设备才算恢复完成。

### 失败

重启命令失败、180 秒内未启动、残留 APP 清理失败、存储或进程检查失败、健康 APK 缺失、安装失败、安装后不可见、卸载失败、卸载后仍存在，任何一种情况都执行：

- 状态改为 `error`。
- 保留原 `quarantine_reason`、`quarantined_at`、任务和包名，便于排查。
- `recovery_error` 写入失败步骤和裁剪后的原始错误。
- 清空 `recovery_started_at`。
- 设置 `last_recovery_at=NOW()`。

异常处理不得把设备改回 `online`。

## 进程异常保护

每轮扫描开始时，将 `status='recovering'` 且 `recovery_started_at` 超过 10 分钟的设备改为 `error`，错误信息记录为恢复进程超时或异常退出。该设备不再自动恢复。

停止服务时，`stop.sh` 先向恢复进程发送正常终止信号。正在执行的 ADB 子进程使用有限超时；若进程最终被强制结束，10 分钟保护会在服务重新启动后收敛状态。

## 专用健康检查 APK

仓库内保存专用、无业务功能的最小 APK 和说明文件。APK 只用于包管理器安装/卸载验证，不申请敏感权限、不启动后台服务、不联网。恢复代码在运行前检查文件存在、ZIP/APK 文件头和固定包名；文件缺失或包名不符时设备进入 `error`，防止误用其他 APK。

在线和离线安装包会随项目目录一起携带该 APK，不增加外部下载步骤。

## 前端展示

设备列表增加：

- `recovering`：显示“恢复中”，不可用遮罩。
- `error`：显示“异常”，不可用遮罩。
- 隔离设备优先显示 `quarantine_reason`。
- 异常设备优先显示 `recovery_error`，同时保留原隔离原因供详情查看。

前端只展示状态和原因，本次不增加手工重试按钮。人工重置状态继续通过运维或后续管理接口完成。

## 配置

增加配置项并提供默认值：

- `DEVICE_RECOVERY_SCAN_INTERVAL_SECONDS=60`
- `DEVICE_RECOVERY_REBOOT_TIMEOUT_SECONDS=180`
- `DEVICE_RECOVERY_STALE_SECONDS=600`
- `DEVICE_RECOVERY_MAX_WORKERS=2`
- `DEVICE_RECOVERY_APK_PATH=backend/tools/device_health/DeviceHealthCheck.apk`
- `DEVICE_RECOVERY_APK_PACKAGE=com.fraudanalysis.devicehealth`

## 测试

单元测试覆盖：

- 只有无当前任务的 `quarantined` 设备能够被原子抢占。
- 重复扫描和多个恢复进程不能重复恢复同一设备。
- `recovering`、`error` 不参与调度且不会被心跳恢复。
- TCP ADB 重连、启动完成等待和 180 秒超时。
- 只卸载记录的残留业务 APP。
- Package Manager、5 GiB 存储、`ps -A` 检查。
- 不设置进程数量阈值。
- 专用 APK 文件、包名、安装、存在性、卸载和卸载后不存在验证。
- 每个失败步骤均进入 `error` 并记录步骤。
- 全部成功才清空隔离数据并转为 `online`。
- 超过 10 分钟的 `recovering` 转为 `error`。
- `start.sh`、`stop.sh` 包含恢复进程。

最终运行完整后端测试、前端生产构建和 `git diff --check`。真实 Android 设备上的重启及 APK 安装/卸载仍需要在部署前做一次集成验证。
