#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from typing import Any

import frida


def _run(cmd: list[str], timeout: int = 10) -> tuple[bool, str]:
    try:
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT, timeout=timeout)
        return True, output.strip()
    except Exception as exc:
        return False, str(exc)


def _adb_prefix(device_id: str | None) -> list[str]:
    cmd = ["adb"]
    if device_id:
        cmd.extend(["-s", device_id])
    return cmd


def _pidof(device_id: str | None, process_name: str) -> int | None:
    ok, output = _run(_adb_prefix(device_id) + ["shell", "pidof", process_name], timeout=8)
    if not ok:
        return None
    for part in output.split():
        try:
            pid = int(part)
        except ValueError:
            continue
        if pid > 0:
            return pid
    return None


def _probe_java(device: frida.core.Device, pid: int, sleep_seconds: float = 1.0) -> dict[str, Any]:
    session = device.attach(pid)
    result: dict[str, Any] = {"pid": pid, "java_defined": None, "java_available": None, "error": None}
    script = session.create_script(
        """
setImmediate(function () {
  try {
    var javaDefined = (typeof Java !== 'undefined');
    var javaAvailable = javaDefined && Java.available;
    send({ type: 'java_probe', java_defined: javaDefined, java_available: javaAvailable });
  } catch (e) {
    send({ type: 'java_probe_error', error: String(e) });
  }
});
"""
    )

    def _on_message(message: dict[str, Any], _data: bytes | None) -> None:
        if message.get("type") != "send":
            return
        payload = message.get("payload") or {}
        if payload.get("type") == "java_probe":
            result["java_defined"] = bool(payload.get("java_defined"))
            result["java_available"] = bool(payload.get("java_available"))
        elif payload.get("type") == "java_probe_error":
            result["error"] = str(payload.get("error") or "")

    script.on("message", _on_message)
    script.load()
    time.sleep(sleep_seconds)
    try:
        script.unload()
    finally:
        session.detach()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Check Frida + Java bridge availability on Android.")
    parser.add_argument("--device-id", required=True, help="ADB serial, e.g. 192.168.50.99:5555")
    parser.add_argument("--package", default="", help="Target package name for PID probe")
    parser.add_argument("--system-process", default="com.android.systemui", help="Known Java process to probe")
    parser.add_argument("--json", action="store_true", help="Print JSON only")
    args = parser.parse_args()

    report: dict[str, Any] = {
        "frida_python_version": getattr(frida, "__version__", "unknown"),
        "adb_device_state": None,
        "frida_devices": [],
        "frida_target_device": None,
        "frida_server_version": None,
        "package_probe": None,
        "system_probe": None,
        "errors": [],
    }

    ok, state = _run(_adb_prefix(args.device_id) + ["get-state"], timeout=8)
    report["adb_device_state"] = state if ok else None
    if not ok:
        report["errors"].append(f"adb get-state failed: {state}")

    ok, frida_server_ver = _run(
        _adb_prefix(args.device_id) + ["shell", "su", "-c", "/data/local/tmp/frida-server --version"],
        timeout=8,
    )
    report["frida_server_version"] = frida_server_ver if ok else None
    if not ok:
        report["errors"].append(f"frida-server version check failed: {frida_server_ver}")

    manager = frida.get_device_manager()
    try:
        report["frida_devices"] = [
            {"id": d.id, "name": d.name, "type": str(d.type)} for d in manager.enumerate_devices()
        ]
    except Exception as exc:
        report["errors"].append(f"enumerate_devices failed: {exc}")

    device = None
    try:
        device = manager.get_device(args.device_id, timeout=5)
        report["frida_target_device"] = {"id": device.id, "name": device.name, "type": str(device.type)}
    except Exception as exc:
        report["errors"].append(f"get_device failed: {exc}")

    if device is not None:
        if args.package:
            package_pid = _pidof(args.device_id, args.package)
            if package_pid is None:
                report["package_probe"] = {"package": args.package, "pid": None, "error": "pidof not found"}
            else:
                try:
                    probe = _probe_java(device, package_pid)
                    report["package_probe"] = {"package": args.package, **probe}
                except Exception as exc:
                    report["package_probe"] = {"package": args.package, "pid": package_pid, "error": str(exc)}

        system_pid = _pidof(args.device_id, args.system_process)
        if system_pid is None:
            report["system_probe"] = {"process": args.system_process, "pid": None, "error": "pidof not found"}
        else:
            try:
                probe = _probe_java(device, system_pid)
                report["system_probe"] = {"process": args.system_process, **probe}
            except Exception as exc:
                report["system_probe"] = {"process": args.system_process, "pid": system_pid, "error": str(exc)}

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        package_ok = bool((report.get("package_probe") or {}).get("java_available"))
        system_ok = bool((report.get("system_probe") or {}).get("java_available"))
        if package_ok or system_ok:
            print("\n[PASS] Java bridge available in at least one process.")
        else:
            print("\n[FAIL] Java bridge unavailable in probed processes.")

    package_ok = bool((report.get("package_probe") or {}).get("java_available"))
    system_ok = bool((report.get("system_probe") or {}).get("java_available"))
    return 0 if (package_ok or system_ok) else 2


if __name__ == "__main__":
    raise SystemExit(main())
