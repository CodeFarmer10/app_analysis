# Device Health Circuit Breaker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop unhealthy Android devices from receiving batches of dynamic tasks by strengthening heartbeat checks, gating allocation, and atomically quarantining devices while requeuing device-failed tasks.

**Architecture:** Device health is centralized in `device_service` and represented by a persistent `quarantined` device state. The scheduler trusts only recent successful heartbeats, while the dynamic worker classifies runtime device failures and uses ownership-guarded transactions so stale workers cannot release devices or persist results after task reassignment.

**Tech Stack:** Python 3.13, FastAPI, Celery, PyMySQL, MySQL 8, Vue 3, Python `unittest`

## Global Constraints

- Heartbeat interval is exactly 60 seconds.
- Health requires ADB state, shell marker, package-manager response, and at least 5 GiB free under `/data`.
- `quarantined` is persistent and is never automatically changed to `online` by heartbeat.
- Scheduler health freshness is at most 120 seconds.
- Do not run a health probe between dynamic-task allocation and the first APK install attempt.
- An opaque install failure may run a health probe only after installation has failed, for classification.
- Device failures requeue the active task; APK-specific failures remain `dynamic_failed`.
- APK uninstall failure always quarantines the device and prevents release.
- Do not add automatic reboot or automatic quarantine recovery.

---

### Task 1: Device health probe, persistence, and UI state

**Files:**
- Modify: `backend/migrations/v1_init.sql`
- Modify: `backend/repositories/device_repo.py`
- Modify: `backend/services/device_service.py`
- Create: `backend/tests/test_device_health.py`
- Modify: `frontend/src/views/DeviceList.vue`

**Interfaces:**
- Produces: `DeviceHealthResult(state: str, reason: str | None, available_kib: int | None)`.
- Produces: `check_device_health(serial: str) -> DeviceHealthResult`.
- Produces: `devices.status='quarantined'`, `quarantine_reason`, and `quarantined_at`.

- [ ] **Step 1: Write failing health and heartbeat tests**

Cover these behaviors with real parsing and patched subprocess boundaries:

```python
def test_health_probe_requires_shell_marker(): ...
def test_health_probe_requires_package_manager(): ...
def test_health_probe_rejects_less_than_five_gib_available(): ...
def test_health_probe_accepts_healthy_device(): ...
def test_idle_unhealthy_device_is_quarantined(): ...
def test_transport_offline_device_is_offline(): ...
def test_quarantined_device_is_not_automatically_recovered(): ...
def test_busy_unhealthy_device_is_not_reassigned_by_heartbeat(): ...
```

- [ ] **Step 2: Verify RED**

Run: `/Users/yxh/work/code/app_analysis/backend/.venv/bin/python -m unittest tests.test_device_health -v`

Expected: failure because the health result and full probe do not exist.

- [ ] **Step 3: Implement schema and health probe**

Update the base schema and add idempotent compatibility migration blocks for:

```sql
status ENUM('online', 'offline', 'busy', 'quarantined')
quarantine_reason TEXT NULL
quarantined_at DATETIME NULL
```

Implement the four-stage probe with short command timeouts and robust `df -k`
parsing. Change `HEARTBEAT_REFRESH_INTERVAL_SECONDS` to `60`. Preserve
`quarantined`; set idle transport failures to `offline`; set idle shell,
package-manager, or storage failures to `quarantined`; log busy failures without
changing ownership.

- [ ] **Step 4: Expose and render quarantine state**

Return the two quarantine fields from device repository queries. Add
`quarantined: { status: 'error', text: '已隔离' }` to `DeviceList.vue`, treat it
as unavailable, and show the reason as the overlay title or visible detail.

- [ ] **Step 5: Verify and commit**

Run the focused test, full backend tests, `npm run build`, and `git diff --check`.
Commit: `feat: add device health quarantine state`

---

### Task 2: Healthy-device scheduling gate and stale recovery

**Files:**
- Modify: `backend/workers/scheduler.py`
- Create: `backend/tests/test_scheduler_device_health.py`

**Interfaces:**
- Consumes: `devices.status='quarantined'` and successful `last_heartbeat_at`.
- Produces: scheduler allocation restricted to a 120-second healthy window.
- Produces: stale dynamic tasks returned to `waiting_device` with their device quarantined.

- [ ] **Step 1: Write failing scheduler tests**

```python
def test_allocation_requires_recent_healthy_heartbeat(): ...
def test_stale_task_is_requeued_and_device_is_quarantined(): ...
def test_stale_recovery_keeps_task_device_ownership_guard(): ...
```

Assert the executed SQL and transaction outcomes, including:

```sql
status = 'online'
current_task_id IS NULL
last_heartbeat_at >= DATE_SUB(NOW(), INTERVAL 120 SECOND)
```

- [ ] **Step 2: Verify RED**

Run: `/Users/yxh/work/code/app_analysis/backend/.venv/bin/python -m unittest tests.test_scheduler_device_health -v`

Expected: failures because freshness and quarantine recovery do not exist.

- [ ] **Step 3: Implement allocation and stale recovery changes**

Keep allocation atomic. Change stale-task recovery from `dynamic_failed` plus
device `online` to task `waiting_device` with `device_id=NULL`, and device
`quarantined` with reason/time. Every update must match the task/device ownership
selected under `FOR UPDATE`.

- [ ] **Step 4: Verify and commit**

Run focused and full backend tests plus `git diff --check`.
Commit: `feat: gate scheduling on device health`

---

### Task 3: Dynamic device-error circuit breaker and safe cleanup

**Files:**
- Modify: `backend/workers/dynamic_trace.py`
- Modify: `backend/tests/test_dynamic_task_ownership.py`
- Create: `backend/tests/test_dynamic_device_failures.py`

**Interfaces:**
- Consumes: `check_device_health(serial)` only after an opaque install failure.
- Produces: `is_device_error_message(message: str) -> bool`.
- Produces: an ownership-guarded quarantine/requeue transaction.
- Produces: cleanup logic that never releases a quarantined device.

- [ ] **Step 1: Write failing classification and transition tests**

```python
def test_fork_failure_is_device_error(): ...
def test_offline_and_abb_exec_closed_are_device_errors(): ...
def test_invalid_apk_is_not_device_error(): ...
def test_device_error_requeues_task_and_quarantines_owner(): ...
def test_stale_worker_cannot_requeue_new_owner(): ...
def test_release_requires_busy_status_and_current_owner(): ...
def test_uninstall_failure_quarantines_completed_task_device(): ...
def test_no_health_probe_occurs_before_first_install_attempt(): ...
def test_opaque_install_failure_probes_health_after_failure(): ...
```

- [ ] **Step 2: Verify RED**

Run: `/Users/yxh/work/code/app_analysis/backend/.venv/bin/python -m unittest tests.test_dynamic_task_ownership tests.test_dynamic_device_failures -v`

Expected: failures for missing classification and quarantine behavior.

- [ ] **Step 3: Implement device failure handling**

Introduce a specific device-unavailable exception and a conservative message
classifier. On device error, atomically change the owned task to
`waiting_device`, clear its `device_id`, and quarantine/clear the owned device.
Do not call the health probe before install. For an opaque install error, probe
after failure and convert it to a device error only when the probe is unhealthy.

- [ ] **Step 4: Make persistence and cleanup ownership-safe**

Before deleting/inserting dynamic results, lock and verify that the task is
still `dynamic_tracing` on the expected device. Make `_set_device_online`
require `status='busy'` and matching `current_task_id`. Track isolation through
`finally`; uninstall failure always quarantines and skips release. Device-level
accessibility cleanup failure also quarantines.

- [ ] **Step 5: Verify and commit**

Run focused tests, the full backend suite, `npm run build`, and
`git diff --check`.
Commit: `feat: quarantine unhealthy dynamic devices`

---

### Task 4: Cross-feature verification and operational documentation

**Files:**
- Modify: `memory_bank/architecture.md`
- Modify: `memory_bank/progress.md`

**Interfaces:**
- Consumes: completed Tasks 1-3.
- Produces: documented device-health state machine and operational behavior.

- [ ] **Step 1: Document exact behavior**

Record the 60-second probe, 120-second freshness gate, persistent quarantine,
device-error requeue, uninstall quarantine, and absence of automatic reboot.

- [ ] **Step 2: Run final verification**

Run:

```bash
cd backend && /Users/yxh/work/code/app_analysis/backend/.venv/bin/python -m unittest discover -s tests -p 'test_*.py'
cd frontend && npm run build
git diff --check
git status --short
```

Expected: all tests pass, frontend builds, and only planned files are changed.

- [ ] **Step 3: Commit documentation**

Commit: `docs: document device health circuit breaker`
