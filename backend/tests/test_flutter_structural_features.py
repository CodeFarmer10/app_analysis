import tempfile
import unittest
from pathlib import Path

from analyzers.flutter_structural_features import extract_flutter_structural_features


class FlutterStructuralFeaturesTest(unittest.TestCase):
    def _write_asm(self, body: str) -> Path:
        root = Path(tempfile.mkdtemp())
        asm_dir = root / "asm"
        asm_dir.mkdir()
        (asm_dir / "main.dart").write_text(body, encoding="utf-8")
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        return asm_dir

    def test_extracts_direct_and_object_pool_strings_by_structural_class(self):
        asm_dir = self._write_asm(
            """
// lib: app, url: package:obf/main.dart
class A {

  _ a(/* No info */) {
    // ** addr: 0x1000, size: 0x30
    // 0x1000: ldr x0, [x27, #0x40]  ; [pp+0x40] String: "username"
    // 0x1004: bl 0x2000
    // 0x1008: mov x1, "password"
    // 0x100c: ret
  }

  _ b(/* No info */) {
    // ** addr: 0x1100, size: 0x10
    // 0x1100: ldr x2, [x27, #0x78]  ; [pp+0x78] Array: ["deviceId", "package:flutter/widgets.dart"]
    // 0x1104: ret
  }
}
""".strip()
        )

        features = extract_flutter_structural_features(asm_dir)

        self.assertEqual(
            features,
            [
                {
                    "class_strings": ["deviceId", "password", "username"],
                    "functions": [
                        {
                            "aot_fp": features[0]["functions"][0]["aot_fp"],
                            "strings": ["password", "username"],
                        },
                        {
                            "aot_fp": features[0]["functions"][1]["aot_fp"],
                            "strings": ["deviceId"],
                        },
                    ],
                }
            ],
        )
        self.assertRegex(features[0]["functions"][0]["aot_fp"], r"^[0-9a-f]{16}$")

    def test_ignores_names_addresses_registers_pool_offsets_and_stack_offsets_for_fingerprint(self):
        first = self._write_asm(
            """
class LoginScreen {
  _ submit(/* No info */) {
    // ** addr: 0x1000, size: 0x18
    // 0x1000: stp x29, x30, [sp, #-0x20]!
    // 0x1004: ldr x0, [x27, #0x40]  ; [pp+0x40] String: "username"
    // 0x1008: cmp x0, x1
    // 0x100c: b.eq 0x1020
    // 0x1010: ret
  }
}
""".strip()
        )
        second = self._write_asm(
            """
class X {
  _ y(/* No info */) {
    // ** addr: 0x9a00, size: 0x18
    // 0x9a00: stp x8, x9, [sp, #-0x90]!
    // 0x9a04: ldr x12, [x27, #0x220]  ; [pp+0x220] String: "username"
    // 0x9a08: cmp x12, x13
    // 0x9a0c: b.eq 0xa000
    // 0x9a10: ret
  }
}
""".strip()
        )

        left = extract_flutter_structural_features(first)[0]["functions"][0]
        right = extract_flutter_structural_features(second)[0]["functions"][0]

        self.assertEqual(left["aot_fp"], right["aot_fp"])
        self.assertEqual(left["strings"], right["strings"])

    def test_drops_empty_string_functions(self):
        asm_dir = self._write_asm(
            """
class A {
  _ empty(/* No info */) {
    // ** addr: 0x1000, size: 0x8
    // 0x1000: mov x0, x1
    // 0x1004: ret
  }
}
""".strip()
        )

        self.assertEqual(extract_flutter_structural_features(asm_dir), [])


if __name__ == "__main__":
    unittest.main()
