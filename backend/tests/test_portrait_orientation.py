from __future__ import annotations

import unittest
from subprocess import CompletedProcess
from unittest.mock import patch

from phone_agent.adb import device
from protection import unpacker


class PortraitOrientationTest(unittest.TestCase):
    def test_monkey_launch_relocks_portrait_before_returning(self) -> None:
        events: list[tuple[str, ...]] = []

        def adb_run(args, **kwargs):
            events.append(tuple(args))
            return CompletedProcess(args, 0, stdout="Events injected: 1", stderr="")

        def shell(args, *, device_id=None, timeout=30):
            self.assertEqual(device_id, "serial-1")
            events.append(tuple(args))
            return True, ""

        with patch.object(device.subprocess, "run", side_effect=adb_run), \
                patch.object(device, "run_shell_command", side_effect=shell), \
                patch.object(device.time, "sleep"):
            launched = device.launch_app_by_package("example.app", "serial-1", delay=0)

        self.assertTrue(launched)
        self.assertEqual(events, [
            ("adb", "-s", "serial-1", "shell", "monkey", "-p", "example.app",
             "-c", "android.intent.category.LAUNCHER", "1"),
            ("wm", "user-rotation", "lock", "0"),
            ("wm", "fixed-to-user-rotation", "enabled"),
        ])

    def test_unpacker_monkey_launch_relocks_portrait_before_returning(self) -> None:
        events: list[tuple[str, ...]] = []

        def adb_run(serial, args, timeout=30):
            self.assertEqual(serial, "serial-1")
            events.append(tuple(args))
            return CompletedProcess(args, 0, stdout="Events injected: 1", stderr="")

        def shell(args, *, device_id=None, timeout=30):
            self.assertEqual(device_id, "serial-1")
            events.append(("shell", *args))
            return True, ""

        with patch.object(unpacker, "_run_adb", side_effect=adb_run), \
                patch.object(device, "run_shell_command", side_effect=shell):
            unpacker._launch_app("example.app", "serial-1")

        self.assertEqual(events, [
            ("shell", "am", "force-stop", "example.app"),
            ("shell", "monkey", "-p", "example.app", "-c", "android.intent.category.LAUNCHER", "1"),
            ("shell", "wm", "user-rotation", "lock", "0"),
            ("shell", "wm", "fixed-to-user-rotation", "enabled"),
        ])

    def test_monkey_relock_uses_legacy_settings_when_window_commands_are_missing(self) -> None:
        commands: list[tuple[str, ...]] = []

        def shell(args, *, device_id=None, timeout=30):
            commands.append(tuple(args))
            if args[0] in {"wm", "cmd"}:
                return False, "Unknown command"
            return True, "Success"

        with patch.object(device, "run_shell_command", side_effect=shell):
            locked, _ = device.relock_portrait_after_monkey("serial-1")

        self.assertTrue(locked)
        self.assertIn(("settings", "put", "system", "accelerometer_rotation", "0"), commands)
        self.assertIn(("settings", "put", "system", "user_rotation", "0"), commands)

    def test_modern_device_forces_portrait_then_restores_previous_rotation(self) -> None:
        settings = {"accelerometer_rotation": "1", "user_rotation": "2"}
        window = {"rotation": "lock 2", "ignore": "false", "fixed": "default"}
        commands: list[tuple[str, ...]] = []

        def shell(args, *, device_id=None, timeout=30):
            self.assertEqual(device_id, "serial-1")
            commands.append(tuple(args))
            if args[:3] == ["settings", "get", "system"]:
                return True, settings[args[3]]
            if args[:3] == ["settings", "put", "system"]:
                return False, "java.lang.SecurityException: android.permission.WRITE_SETTINGS"
            if args == ["cmd", "window", "user-rotation"]:
                return True, window["rotation"]
            if args == ["cmd", "window", "get-ignore-orientation-request"]:
                return True, f'ignoreOrientationRequest {window["ignore"]} for displayId=0'
            if args == ["cmd", "window", "fixed-to-user-rotation"]:
                return True, window["fixed"]
            if args[:3] == ["cmd", "window", "fixed-to-user-rotation"]:
                window["fixed"] = args[3]
                return True, ""
            if args[:3] == ["cmd", "window", "user-rotation"]:
                window["rotation"] = " ".join(args[3:])
                return True, ""
            if args[:3] == ["cmd", "window", "set-ignore-orientation-request"]:
                window["ignore"] = args[3]
                return True, ""
            self.fail(f"unexpected command: {args}")

        with patch.object(device, "run_shell_command", side_effect=shell):
            previous = device.lock_portrait_orientation("serial-1")
            self.assertEqual(settings, {"accelerometer_rotation": "1", "user_rotation": "2"})
            self.assertEqual(window, {"rotation": "lock 0", "ignore": "true", "fixed": "enabled"})
            restored, _ = device.restore_orientation(previous, "serial-1")

        self.assertTrue(restored)
        self.assertEqual(settings, {"accelerometer_rotation": "1", "user_rotation": "2"})
        self.assertEqual(window, {"rotation": "lock 2", "ignore": "false", "fixed": "default"})
        self.assertIn(("cmd", "window", "fixed-to-user-rotation", "enabled"), commands)
        self.assertIn(("cmd", "window", "set-ignore-orientation-request", "true"), commands)
        self.assertFalse(any(cmd[:3] == ("settings", "put", "system") for cmd in commands))

    def test_legacy_device_uses_settings_and_restores_missing_setting(self) -> None:
        settings = {"accelerometer_rotation": "1", "user_rotation": "null"}
        commands: list[tuple[str, ...]] = []

        def shell(args, *, device_id=None, timeout=30):
            commands.append(tuple(args))
            if args[:3] == ["settings", "get", "system"]:
                return True, settings[args[3]]
            if args[:3] == ["settings", "put", "system"]:
                settings[args[3]] = args[4]
                return True, ""
            if args[:3] == ["settings", "delete", "system"]:
                settings[args[3]] = "null"
                return True, ""
            if args[:2] == ["cmd", "window"]:
                return False, "Unknown command"
            self.fail(f"unexpected command: {args}")

        with patch.object(device, "run_shell_command", side_effect=shell):
            previous = device.lock_portrait_orientation("serial-1")
            self.assertEqual(settings, {"accelerometer_rotation": "0", "user_rotation": "0"})
            restored, _ = device.restore_orientation(previous, "serial-1")

        self.assertTrue(restored)
        self.assertEqual(settings, {"accelerometer_rotation": "1", "user_rotation": "null"})
        self.assertNotIn(("cmd", "window", "set-ignore-orientation-request", "true"), commands)

    def test_window_lock_works_when_fixed_to_user_rotation_is_unsupported(self) -> None:
        window = {"rotation": "free", "ignore": "false"}

        def shell(args, *, device_id=None, timeout=30):
            if args[:3] == ["settings", "get", "system"]:
                return True, "1"
            if args == ["cmd", "window", "fixed-to-user-rotation"]:
                return False, "Unknown command"
            if args == ["cmd", "window", "user-rotation"]:
                return True, window["rotation"]
            if args == ["cmd", "window", "get-ignore-orientation-request"]:
                return True, f'ignoreOrientationRequest {window["ignore"]} for displayId=0'
            if args[:3] == ["cmd", "window", "user-rotation"]:
                window["rotation"] = " ".join(args[3:])
                return True, ""
            if args[:3] == ["cmd", "window", "set-ignore-orientation-request"]:
                window["ignore"] = args[3]
                return True, ""
            self.fail(f"unexpected command: {args}")

        with patch.object(device, "run_shell_command", side_effect=shell):
            previous = device.lock_portrait_orientation("serial-1")

        self.assertEqual(window, {"rotation": "lock 0", "ignore": "true"})
        self.assertIsNone(previous.fixed_to_user_rotation)

    def test_unsupported_window_override_keeps_system_portrait_preference(self) -> None:
        settings = {"accelerometer_rotation": "1", "user_rotation": "1"}
        window_rotation = "lock 1"

        def shell(args, *, device_id=None, timeout=30):
            nonlocal window_rotation
            if args[:3] == ["settings", "get", "system"]:
                return True, settings[args[3]]
            if args[:3] == ["settings", "put", "system"]:
                settings[args[3]] = args[4]
                return True, ""
            if args == ["cmd", "window", "user-rotation"]:
                return True, window_rotation
            if args == ["cmd", "window", "get-ignore-orientation-request"]:
                return True, "ignoreOrientationRequest false for displayId=0"
            if args == ["cmd", "window", "fixed-to-user-rotation"]:
                return False, "Unknown command"
            if args[:3] == ["cmd", "window", "user-rotation"]:
                window_rotation = " ".join(args[3:])
                return True, ""
            if args[:3] == ["cmd", "window", "set-ignore-orientation-request"]:
                return False, "Unknown command"
            self.fail(f"unexpected command: {args}")

        with patch.object(device, "run_shell_command", side_effect=shell):
            previous = device.lock_portrait_orientation("serial-1")

        self.assertEqual(settings, {"accelerometer_rotation": "0", "user_rotation": "0"})
        self.assertEqual(window_rotation, "lock 1")
        self.assertIsNone(previous.window_rotation)

    def test_legacy_device_without_write_settings_continues_without_lock(self) -> None:
        commands: list[tuple[str, ...]] = []

        def shell(args, *, device_id=None, timeout=30):
            commands.append(tuple(args))
            if args[:3] == ["settings", "get", "system"]:
                return True, "1"
            if args[:3] == ["settings", "put", "system"]:
                return False, "java.lang.SecurityException: android.permission.WRITE_SETTINGS"
            if args[:2] == ["cmd", "window"]:
                return False, "Unknown command"
            self.fail(f"unexpected command: {args}")

        with patch.object(device, "run_shell_command", side_effect=shell):
            previous = device.lock_portrait_orientation("serial-1")
            restored, _ = device.restore_orientation(previous, "serial-1")

        self.assertFalse(previous.portrait_applied)
        self.assertTrue(restored)
        self.assertEqual(
            [cmd for cmd in commands if cmd[:3] == ("settings", "put", "system")],
            [("settings", "put", "system", "accelerometer_rotation", "0")],
        )

    def test_reasserts_portrait_when_device_releases_rotation_during_run(self) -> None:
        window = {"rotation": "free", "ignore": "true", "fixed": "disabled"}
        commands: list[tuple[str, ...]] = []

        def shell(args, *, device_id=None, timeout=30):
            commands.append(tuple(args))
            if args == ["cmd", "window", "user-rotation"]:
                return True, window["rotation"]
            if args == ["cmd", "window", "get-ignore-orientation-request"]:
                return True, f'ignoreOrientationRequest {window["ignore"]} for displayId=0'
            if args == ["cmd", "window", "fixed-to-user-rotation"]:
                return True, window["fixed"]
            if args[:3] == ["cmd", "window", "fixed-to-user-rotation"]:
                window["fixed"] = args[3]
                return True, ""
            if args[:3] == ["cmd", "window", "user-rotation"]:
                window["rotation"] = " ".join(args[3:])
                return True, ""
            if args[:3] == ["cmd", "window", "set-ignore-orientation-request"]:
                window["ignore"] = args[3]
                return True, ""
            self.fail(f"unexpected command: {args}")

        state = device.OrientationState(
            None, None, window_rotation="free", ignore_orientation_request="false",
            fixed_to_user_rotation="default",
        )
        with patch.object(device, "run_shell_command", side_effect=shell):
            ok, detail = device.reassert_portrait_orientation(state, "serial-1")
            again_ok, again_detail = device.reassert_portrait_orientation(state, "serial-1")

        self.assertTrue(ok)
        self.assertEqual(detail, "portrait reapplied")
        self.assertTrue(again_ok)
        self.assertEqual(again_detail, "already portrait")
        self.assertEqual(window, {"rotation": "lock 0", "ignore": "true", "fixed": "enabled"})
        self.assertEqual(commands.count(("cmd", "window", "user-rotation", "lock", "0")), 1)


if __name__ == "__main__":
    unittest.main()
