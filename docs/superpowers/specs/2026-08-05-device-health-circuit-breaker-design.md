# Device Health Circuit Breaker Design

## Goal

Prevent an unhealthy Android device from receiving a batch of dynamic-tracing
tasks. A device-level failure must affect at most the active task: the device
is quarantined and the task is returned to the shared waiting queue.

## Scope

- Strengthen the periodic heartbeat from ADB transport-only detection to a
  full device health probe.
- Allocate tasks only to recently healthy devices.
- Classify device-level dynamic-analysis failures, quarantine the device, and
  requeue the affected task.
- Quarantine a device when APK uninstall fails and never release it from the
  task `finally` block.
- Do not implement automatic reboot or automatic quarantine recovery in this
  change.

## Device State

Add `quarantined` to `devices.status`. Add nullable `quarantine_reason` and
`quarantined_at` columns. A quarantined device is persistent: heartbeat does
not automatically return it to `online`, and the scheduler never selects it.

The UI displays quarantined devices as unavailable and shows the status as
`已隔离`. Recovery remains an explicit operational action outside this scope.

## Health Probe

Run the heartbeat every 60 seconds. A device is healthy only when all checks
finish within their short timeouts:

1. `adb get-state` returns `device`.
2. `adb shell echo __device_health_ok__` returns the marker.
3. `adb shell cmd package path android` returns a package path.
4. `/data` has at least 5 GiB available.

Successful probes refresh `last_heartbeat_at`. Failed probes quarantine idle
devices with a stage-specific reason. The heartbeat records but does not
reassign a busy device; the owning dynamic worker handles that transition to
avoid racing with an active worker.

## Scheduling Gate

The scheduler selects only devices where:

- `status = 'online'`
- `current_task_id IS NULL`
- `last_heartbeat_at` is no older than two heartbeat intervals

The dynamic worker performs the same probe immediately before APK install, so
a device that fails between heartbeat and allocation is still rejected.

## Dynamic Failure Handling

Device-level failures include health-probe failures and messages containing
known transport or resource signatures such as `fork failed`,
`failed to run abb_exec`, `device offline`, `not enough space`, ADB timeouts,
or package-manager failures. An opaque install failure such as byte `0x02` is
treated as a device failure only when the immediate health probe also fails.

For a device failure, one transaction:

1. Changes the active task from `dynamic_tracing` to `waiting_device`.
2. Clears the task's `device_id` and records the reason.
3. Changes the owning device to `quarantined`.
4. Clears `current_task_id` and records the quarantine reason and time.

All updates are ownership-guarded. A stale worker cannot release a device or
overwrite a task after ownership changes.

## Cleanup And Release

The dynamic worker tracks whether the device must remain isolated. APK
uninstall failure always quarantines the device, regardless of task outcome.
Accessibility cleanup failures quarantine only when they contain a known
device-level signature. `_set_device_online` succeeds only for a `busy` device
still owned by the same task.

Scheduler stale-task recovery returns the task to `waiting_device` and
quarantines the device instead of marking the task failed and releasing the
device as online.

## Verification

- Unit-test health-probe success, shell failure, package-manager failure, and
  low-storage failure.
- Unit-test heartbeat transitions and persistent quarantine.
- Unit-test scheduler freshness constraints and stale-task recovery.
- Unit-test device-error classification, transactional requeue, uninstall
  quarantine, and stale-worker release protection.
- Run the complete backend test suite and the frontend build.
