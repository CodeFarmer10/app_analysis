# Quarantined Device Auto-Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a standalone process that scans quarantined Android devices every 60 seconds, directly reboots and validates at most two devices concurrently, restores fully verified devices to `online`, and leaves every failed recovery in `error`.

**Architecture:** Recovery persistence is isolated in a new repository, ADB recovery steps are isolated in a new service, and a standalone worker owns the one-minute scan plus a two-thread executor. Database conditional updates provide cross-process ownership; no Celery recovery task or Celery Beat is introduced.

**Tech Stack:** Python 3, PyMySQL, `concurrent.futures.ThreadPoolExecutor`, ADB subprocesses, Androguard, MySQL 8-compatible SQL, Vue 3, Ant Design Vue, shell process management.

## Global Constraints

- Scan every 60 seconds and directly execute recovery; do not enqueue a Celery recovery task.
- Recover at most two different devices concurrently; never recover the same device twice.
- Wait at most 180 seconds for reboot and `sys.boot_completed=1`.
- Only devices with `status='quarantined' AND current_task_id IS NULL` may be claimed.
- `recovering` and `error` devices are never scheduled and are never auto-recovered by heartbeat.
- A failed recovery changes the device to `error` and is not retried automatically.
- A `recovering` device older than 600 seconds changes to `error`.
- Clean only `quarantine_package_name`; never bulk-uninstall third-party packages.
- Require at least 5 GiB free under `/data`.
- Require `ps -A` to succeed and return output, but do not impose a process-count threshold.
- Validate install and uninstall using `backend/tools/device_health/DeviceHealthCheck.apk` with package `com.fraudanalysis.devicehealth`.
- Preserve the existing invariant that no health probe runs between dynamic-task allocation and the first business APK install.

---

### Task 1: Recovery State Schema And Repository

**Files:**
- Modify: `backend/migrations/v1_init.sql`
- Modify: `backend/repositories/device_repo.py`
- Create: `backend/repositories/device_recovery_repo.py`
- Modify: `backend/schemas/device.py`
- Create: `backend/tests/test_device_recovery_repository.py`

**Interfaces:**
- Produces: `list_quarantined_devices(limit: int) -> list[dict]`
- Produces: `claim_quarantined_device(device_id: str) -> dict | None`
- Produces: `complete_device_recovery(device_id: str) -> bool`
- Produces: `fail_device_recovery(device_id: str, error: str) -> bool`
- Produces: `expire_stale_recoveries(stale_seconds: int) -> int`
- Produces fields on every device API row: `quarantine_task_id`, `quarantine_package_name`, `recovery_started_at`, `last_recovery_at`, `recovery_error`

- [ ] **Step 1: Write failing repository and schema tests**

Create tests that mock database calls and assert ownership guards:

```python
class DeviceRecoveryRepositoryTest(unittest.TestCase):
    def test_claim_requires_idle_quarantined_device(self):
        claimed = claim_quarantined_device("device-1")
        sql = execute_mock.call_args.args[0]
        self.assertIn("status = 'quarantined'", sql)
        self.assertIn("current_task_id IS NULL", sql)
        self.assertIn("status = 'recovering'", sql)
        self.assertIn("recovery_started_at = NOW()", sql)

    def test_success_requires_recovering_and_clears_isolation(self):
        self.assertTrue(complete_device_recovery("device-1"))
        sql = execute_mock.call_args.args[0]
        self.assertIn("status = 'recovering'", sql)
        self.assertIn("quarantine_reason = NULL", sql)
        self.assertIn("recovery_error = NULL", sql)

    def test_failure_requires_recovering_and_sets_error(self):
        self.assertTrue(fail_device_recovery("device-1", "reboot: timeout"))
        self.assertIn("status = 'error'", execute_mock.call_args.args[0])

    def test_stale_recovering_device_becomes_error(self):
        expire_stale_recoveries(600)
        self.assertIn("INTERVAL 600 SECOND", execute_mock.call_args.args[0])
```

Also assert `DeviceItem` exposes all five fields and that `device_repo` select lists include them.

- [ ] **Step 2: Run the focused tests and confirm failure**

Run:

```bash
/Users/yxh/work/code/app_analysis/backend/.venv/bin/python -m unittest tests.test_device_recovery_repository -v
```

Expected: import failures because `device_recovery_repo.py` and the schema fields do not exist.

- [ ] **Step 3: Extend the base schema and idempotent migration**

Update the base `devices` definition to:

```sql
status ENUM('online', 'offline', 'busy', 'quarantined', 'recovering', 'error') NOT NULL DEFAULT 'online',
quarantine_reason TEXT NULL,
quarantined_at DATETIME NULL,
quarantine_task_id VARCHAR(36) NULL,
quarantine_package_name VARCHAR(256) NULL,
recovery_started_at DATETIME NULL,
last_recovery_at DATETIME NULL,
recovery_error TEXT NULL,
```

Replace the existing enum compatibility check so it modifies the column whenever either `recovering` or `error` is absent. Add one information-schema guarded `ALTER TABLE devices ADD COLUMN` block for every new column. Do not add a foreign key for `quarantine_task_id`; historical task deletion must not block device recovery metadata.

- [ ] **Step 4: Implement focused recovery repository operations**

Implement `backend/repositories/device_recovery_repo.py` with conditional updates. `claim_quarantined_device` executes:

```sql
UPDATE devices
SET status = 'recovering',
    recovery_started_at = NOW(),
    recovery_error = NULL
WHERE id = %s
  AND status = 'quarantined'
  AND current_task_id IS NULL
```

Return `None` when affected rows are not exactly one; otherwise fetch and return the claimed row. Success clears all isolation metadata and sets heartbeat/recovery completion time. Failure preserves quarantine metadata, clears `recovery_started_at`, sets `last_recovery_at=NOW()`, and clips errors to 2000 characters. `expire_stale_recoveries` updates only stale `recovering` rows and stores a deterministic timeout message.

- [ ] **Step 5: Add fields to all device projections and API schema**

Extend `create_device`, `get_device_by_id`, `get_device_by_serial`, `list_devices`, `get_available_devices`, and `DeviceItem`. New device creation supplies `None` for recovery fields.

- [ ] **Step 6: Run focused and existing device tests**

```bash
/Users/yxh/work/code/app_analysis/backend/.venv/bin/python -m unittest \
  tests.test_device_recovery_repository tests.test_device_health tests.test_scheduler_device_health -v
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add backend/migrations/v1_init.sql backend/repositories/device_repo.py \
  backend/repositories/device_recovery_repo.py backend/schemas/device.py \
  backend/tests/test_device_recovery_repository.py
git commit -m "feat: add device recovery lifecycle state"
```

---

### Task 2: Preserve Quarantine Task And Package Metadata

**Files:**
- Modify: `backend/workers/dynamic_trace.py`
- Modify: `backend/workers/scheduler.py`
- Modify: `backend/services/device_service.py`
- Modify: `backend/tests/test_dynamic_device_failures.py`
- Modify: `backend/tests/test_scheduler_device_health.py`
- Modify: `backend/tests/test_device_health.py`

**Interfaces:**
- Consumes: new device columns from Task 1.
- Produces: every task-caused quarantine stores `quarantine_task_id` and `quarantine_package_name`.
- Produces: heartbeat quarantine clears task/package metadata because it has no owning business task.

- [ ] **Step 1: Write failing metadata propagation tests**

```python
def test_dynamic_device_failure_records_task_and_package():
    _quarantine_and_requeue_owned_task(
        "task-1", "device-1", "device offline", "com.example.badapp"
    )
    device_update = find_update("UPDATE devices")
    self.assertIn("quarantine_task_id = %s", device_update.sql)
    self.assertIn("quarantine_package_name = %s", device_update.sql)

def test_uninstall_failure_records_package_for_recovery():
    _cleanup_device_after_trace(
        task_id="task-1",
        device_id="device-1",
        package_name="com.example.badapp",
        adb_device_id="serial-1",
        app_installed=True,
    )
    quarantine_mock.assert_called_once_with(
        "task-1", "device-1", ANY, "com.example.badapp"
    )

def test_stale_recovery_records_static_package_name():
    self.assertIn("LEFT JOIN static_results", stale_select_sql)

def test_heartbeat_quarantine_clears_stale_task_metadata():
    fields = update_idle_mock.call_args.args[2]
    self.assertIsNone(fields["quarantine_task_id"])
    self.assertIsNone(fields["quarantine_package_name"])
```

- [ ] **Step 2: Run focused tests and confirm failure**

```bash
/Users/yxh/work/code/app_analysis/backend/.venv/bin/python -m unittest \
  tests.test_dynamic_device_failures tests.test_scheduler_device_health tests.test_device_health -v
```

Expected: failures because quarantine SQL does not write the new metadata.

- [ ] **Step 3: Thread package metadata through dynamic quarantine helpers**

Change `_quarantine_owned_device` and `_quarantine_and_requeue_owned_task` to accept the same fourth argument, `package_name: str | None = None`, while preserving their `bool` return type.

The guarded updates set `quarantine_task_id=task_id` and the normalized package. Pass the extracted package from install failures, runtime failures, accessibility cleanup, and uninstall cleanup. Existing ownership and rollback guards remain unchanged.

- [ ] **Step 4: Record metadata during scheduler and heartbeat quarantine**

Join stale tasks to `static_results` to select `package_name`, then store task ID and package in the device quarantine update. Heartbeat-created quarantine explicitly sets both metadata fields to `NULL` so stale package data cannot be removed later.

- [ ] **Step 5: Run ownership tests**

```bash
/Users/yxh/work/code/app_analysis/backend/.venv/bin/python -m unittest \
  tests.test_dynamic_device_failures tests.test_dynamic_task_ownership \
  tests.test_scheduler_device_health tests.test_device_health -v
```

Expected: all tests pass, including the no-preinstall-health-probe test.

- [ ] **Step 6: Commit**

```bash
git add backend/workers/dynamic_trace.py backend/workers/scheduler.py \
  backend/services/device_service.py backend/tests/test_dynamic_device_failures.py \
  backend/tests/test_scheduler_device_health.py backend/tests/test_device_health.py
git commit -m "feat: retain quarantined app metadata"
```

---

### Task 3: Dedicated Health APK And Recovery Service

**Files:**
- Create: `backend/tools/device_health/src/AndroidManifest.xml`
- Create: `backend/tools/device_health/build_health_apk.sh`
- Create: `backend/tools/device_health/README.md`
- Create binary: `backend/tools/device_health/DeviceHealthCheck.apk`
- Modify: `backend/core/config.py`
- Create: `backend/services/device_recovery_service.py`
- Create: `backend/tests/test_device_recovery_service.py`
- Create: `backend/tests/test_device_health_apk.py`

**Interfaces:**
- Produces: `RecoveryStepError(step: str, detail: str)`
- Produces: `validate_health_apk(path: Path, expected_package: str) -> None`
- Produces: `wait_for_device_boot(serial: str, timeout_seconds: int) -> None`
- Produces: `perform_device_recovery(device: dict) -> None`
- Consumes: existing `check_device_health`, `install_apk`, and `uninstall_apk` helpers.

- [ ] **Step 1: Add minimal manifest source and failing APK tests**

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.fraudanalysis.devicehealth"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35" />
    <application
        android:allowBackup="false"
        android:debuggable="false"
        android:hasCode="false"
        android:label="Device Health Check" />
</manifest>
```

Use Androguard in `test_device_health_apk.py`:

```python
def test_health_apk_is_minimal_and_has_expected_package():
    apk = APK(str(HEALTH_APK))
    self.assertEqual(apk.get_package(), "com.fraudanalysis.devicehealth")
    self.assertEqual(apk.get_permissions(), [])
    self.assertEqual(apk.get_activities(), [])
    self.assertEqual(apk.get_services(), [])
    self.assertEqual(apk.get_receivers(), [])
    self.assertEqual(apk.get_providers(), [])
```

- [ ] **Step 2: Build and check in the dedicated APK**

`build_health_apk.sh` accepts `AAPT2`, `ANDROID_JAR`, `KEYTOOL`, and `APKSIGNER` environment overrides. It runs `aapt2 link`, creates a temporary non-production signing key, signs with APK Signature Scheme v2 through `apksigner`, verifies the signature, and writes `DeviceHealthCheck.apk`. Build tools and keys are not committed. `README.md` records package, purpose, source manifest, and rebuild command.

```bash
cd backend/tools/device_health
AAPT2=/path/to/aapt2 ANDROID_JAR=/path/to/android.jar \
  APKSIGNER=/path/to/apksigner ./build_health_apk.sh
cd ../..
.venv/bin/python -m unittest tests.test_device_health_apk -v
```

Expected: the APK test passes and the file is a signed ZIP/APK.

- [ ] **Step 3: Write failing recovery-step tests**

```python
def test_wait_for_boot_requires_boot_property_and_marker():
    command_mock.side_effect = ["device", "1", "__device_recovery_ok__"]
    wait_for_device_boot("serial-1", timeout_seconds=180)
    self.assertEqual(command_mock.call_count, 3)

def test_process_check_rejects_fork_failure_without_counting_processes():
    command_mock.return_value = "shell: fork failed: Resource temporarily unavailable"
    with self.assertRaisesRegex(RecoveryStepError, "process"):
        require_process_command("serial-1")

def test_health_apk_round_trip_verifies_both_transitions():
    package_exists_mock.side_effect = [True, False]
    verify_apk_round_trip(
        "serial-1", Path("DeviceHealthCheck.apk"), "com.fraudanalysis.devicehealth"
    )
    install_mock.assert_called_once()
    uninstall_mock.assert_called_once()
```

Add separate named tests for the 180-second timeout, empty `ps -A`, residual-package-only cleanup, install failure, package absent after install, uninstall failure, package still present after uninstall, and stable `RecoveryStepError.step` values.

Run:

```bash
/Users/yxh/work/code/app_analysis/backend/.venv/bin/python -m unittest tests.test_device_recovery_service -v
```

Expected: import failure because the recovery service does not exist.

- [ ] **Step 4: Add exact configuration defaults**

```python
DEVICE_RECOVERY_SCAN_INTERVAL_SECONDS: int = 60
DEVICE_RECOVERY_REBOOT_TIMEOUT_SECONDS: int = 180
DEVICE_RECOVERY_STALE_SECONDS: int = 600
DEVICE_RECOVERY_MAX_WORKERS: int = 2
DEVICE_RECOVERY_APK_PATH: str = str(BASE_DIR / "tools" / "device_health" / "DeviceHealthCheck.apk")
DEVICE_RECOVERY_APK_PACKAGE: str = "com.fraudanalysis.devicehealth"
```

- [ ] **Step 5: Implement ordered recovery steps**

`perform_device_recovery` executes exactly:

```python
validate_health_apk(apk_path, expected_package)
run_adb(serial, ["reboot"])
wait_for_device_boot(serial, timeout_seconds=180)
remove_residual_package(serial, device.get("quarantine_package_name"))
require_device_health(serial)
require_process_command(serial)
verify_apk_round_trip(serial, apk_path, expected_package)
require_device_health(serial)
```

Every helper maps timeout/nonzero status to `RecoveryStepError` with a stable step name: `reboot`, `wait_boot`, `cleanup_app`, `storage`, `process`, `verify_install`, or `verify_uninstall`. Package checks use `adb shell cmd package path <package>`. `ps -A` is checked only for successful nonempty output and resource errors, never for process count.

- [ ] **Step 6: Run APK and service tests**

```bash
/Users/yxh/work/code/app_analysis/backend/.venv/bin/python -m unittest \
  tests.test_device_health_apk tests.test_device_recovery_service -v
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add backend/tools/device_health backend/core/config.py \
  backend/services/device_recovery_service.py backend/tests/test_device_recovery_service.py \
  backend/tests/test_device_health_apk.py
git commit -m "feat: add android device recovery validation"
```

---

### Task 4: Standalone Recovery Process And Service Scripts

**Files:**
- Create: `backend/workers/device_recovery.py`
- Create: `backend/tests/test_device_recovery_worker.py`
- Modify: `start.sh`
- Modify: `stop.sh`

**Interfaces:**
- Consumes: repository lifecycle functions from Task 1.
- Consumes: `perform_device_recovery(device: dict) -> None` from Task 3.
- Produces: `recover_claimed_device(device: dict) -> None`
- Produces: `run_recovery_scan(executor, in_flight: set[Future]) -> set[Future]`
- Produces: `run_recovery_forever() -> None`

- [ ] **Step 1: Write failing worker tests**

```python
def test_scan_expires_stale_recoveries_first():
    run_recovery_scan(executor, set())
    expire_mock.assert_called_once_with(600)

def test_scan_claims_only_available_thread_slots():
    in_flight = {unfinished_future}
    run_recovery_scan(executor, in_flight)
    list_mock.assert_called_once_with(limit=1)

def test_claim_failure_is_not_submitted():
    claim_mock.return_value = None
    run_recovery_scan(executor, set())
    executor.submit.assert_not_called()

def test_duplicate_scan_cannot_submit_recovering_device():
    claim_mock.side_effect = [device, None]
    run_recovery_scan(executor, set())
    run_recovery_scan(executor, set())
    self.assertEqual(executor.submit.call_count, 1)

def test_recovery_success_marks_online():
    recover_claimed_device(device)
    perform_mock.assert_called_once_with(device)
    success_mock.assert_called_once_with(device["id"])

def test_recovery_failure_marks_error_with_step():
    perform_mock.side_effect = RecoveryStepError("wait_boot", "timeout")
    recover_claimed_device(device)
    failure_mock.assert_called_once_with(device["id"], "wait_boot: timeout")
```

Add script-text assertions that `start.sh` contains `workers.device_recovery` and `stop.sh` contains `device_recovery`.

- [ ] **Step 2: Run worker tests and confirm failure**

```bash
/Users/yxh/work/code/app_analysis/backend/.venv/bin/python -m unittest tests.test_device_recovery_worker -v
```

Expected: import failure because the worker does not exist.

- [ ] **Step 3: Implement direct scan and bounded thread execution**

Use one long-lived `ThreadPoolExecutor(max_workers=settings.DEVICE_RECOVERY_MAX_WORKERS)`. Each cycle:

1. Remove completed futures and log exceptions.
2. Expire stale `recovering` rows.
3. Calculate free slots as `max_workers - len(in_flight)`.
4. Query at most that many quarantined devices.
5. Atomically claim each device before `executor.submit`.
6. Submit `recover_claimed_device`; do not call Celery and do not create another queue.
7. Sleep until 60 seconds from scan start, with a minimum zero delay.

Catch loop exceptions so one scan failure does not stop later scans. Register SIGTERM/SIGINT to stop new scans and shut down the executor.

- [ ] **Step 4: Add process management**

In `start.sh`:

```bash
start_process device_recovery "${BACKEND_DIR}" \
  "${PYTHON_BIN}" -m workers.device_recovery
```

Add `device_recovery` before `scheduler` in `stop.sh` so no new recovery begins during shutdown.

- [ ] **Step 5: Run worker and shell tests**

```bash
/Users/yxh/work/code/app_analysis/backend/.venv/bin/python -m unittest tests.test_device_recovery_worker -v
bash -n start.sh
bash -n stop.sh
```

Expected: all commands succeed.

- [ ] **Step 6: Commit**

```bash
git add backend/workers/device_recovery.py backend/tests/test_device_recovery_worker.py start.sh stop.sh
git commit -m "feat: run quarantined device recovery process"
```

---

### Task 5: Frontend State, Documentation, And Full Verification

**Files:**
- Modify: `frontend/src/views/DeviceList.vue`
- Modify: `memory_bank/architecture.md`
- Modify: `memory_bank/progress.md`

**Interfaces:**
- Consumes: `recovering`, `error`, and recovery fields returned by the device API.
- Produces: visible unavailable states and recovery failure reason.

- [ ] **Step 1: Update device status presentation**

```javascript
recovering: { status: 'processing', text: '恢复中' },
error: { status: 'error', text: '异常' },
```

Include both states in `isUnavailable`. `getUnavailableTitle` returns `recovery_error` first for `error`, `quarantine_reason` for `quarantined`, and a stable fallback for `recovering`. Add status-dot styles. Change device-list polling from five minutes to 60 seconds.

- [ ] **Step 2: Document the workflow**

Record the standalone process, direct one-minute scan, two-device concurrency, 180-second reboot timeout, residual-package scope, no process-count threshold, real APK round trip, and manual-only retry from `error`.

- [ ] **Step 3: Run complete backend verification**

```bash
/Users/yxh/work/code/app_analysis/backend/.venv/bin/python -m unittest discover -s tests -p 'test_*.py'
```

Expected: all tests pass.

- [ ] **Step 4: Run frontend and repository verification**

```bash
cd frontend && npm run build
cd .. && bash -n start.sh && bash -n stop.sh
git diff --check
```

Expected: build succeeds; the existing Vite large-chunk warning is acceptable; shell syntax and diff checks pass.

- [ ] **Step 5: Perform a no-device smoke check**

Run one recovery scan with repository calls mocked or an empty test database. Confirm it logs zero claimed devices and does not invoke ADB. Do not reboot a real device during automated tests.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/views/DeviceList.vue memory_bank/architecture.md memory_bank/progress.md
git commit -m "docs: document automatic device recovery"
```

## Deployment Validation

1. Apply `backend/migrations/v1_init.sql` to a staging MySQL copy twice to verify idempotence.
2. Put one non-production Android device into `quarantined` with a known test package.
3. Start `workers.device_recovery` and verify exactly one recovery begins.
4. Confirm reboot, boot completion, residual-package cleanup, `ps -A`, 5 GiB storage check, health APK install, and health APK uninstall in logs.
5. Confirm status becomes `online` only after all checks and isolation fields are cleared.
6. Repeat with an invalid health APK and verify status becomes `error` without automatic retry.
