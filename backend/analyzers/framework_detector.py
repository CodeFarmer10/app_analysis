from __future__ import annotations

import struct
import zipfile
from dataclasses import dataclass, field
from typing import Any


FRAMEWORK_RULES: list[tuple[str, list[tuple[str, str]], str, str]] = [
    (
        "Flutter",
        [("so", "libflutter.so"), ("so", "libapp.so"), ("path", "flutter_assets/")],
        "业务逻辑在 lib/<abi>/libapp.so(Dart AOT 机器码)",
        "blutter 恢复符号 / reFlutter 动态 hook；不是脱壳",
    ),
    (
        "React Native",
        [("path", "index.android.bundle"), ("so", "libhermes"), ("so", "libreactnativejni"), ("so", "libjsc")],
        "JS 在 assets/index.android.bundle(新版可能为 Hermes 字节码)，原生模块在 dex/.so",
        "hermes-dec/hbctool 反编译 .hbc；敏感逻辑看 dex/.so 原生模块",
    ),
    (
        "uni-app/DCloud",
        [("path", "assets/apps/__UNI__"), ("path", "dcloud_control"), ("so", "libweexcore"), ("path", "io/dcloud")],
        "前端 JS 在 assets/apps/<id>/www/(app-service.js)，容器在 dex(io.dcloud)",
        "取 www/ 美化 JS；可能加密则 hook WebView evaluateJavascript",
    ),
    (
        "Unity",
        [("so", "libil2cpp.so"), ("so", "libunity.so"), ("path", "global-metadata.dat"), ("path", "assets/bin/Data")],
        "il2cpp: lib/<abi>/libil2cpp.so + global-metadata.dat；Mono: assets/.../Managed/*.dll",
        "Il2CppDumper 配 global-metadata 恢复符号；Mono 用 dnSpy",
    ),
    (
        "Unreal Engine",
        [("so", "libUE4.so"), ("so", "libUnreal")],
        "lib/<abi>/libUE4.so",
        "IDA/Ghidra 逆 native；资源在 obb",
    ),
    (
        "Xamarin/.NET MAUI",
        [("so", "libmonodroid"), ("so", "libxamarin"), ("so", "libmonosgen"), ("path", "assemblies/")],
        "C# 编译成 assets/assemblies/*.dll(或 assemblies.blob)",
        "dnSpy/ILSpy 反编译 DLL",
    ),
    (
        "Cordova/PhoneGap",
        [("path", "assets/www/cordova.js"), ("path", "assets/www/cordova_plugins"), ("path", "res/xml/config.xml")],
        "前端 HTML/JS 在 assets/www/",
        "直接取 assets/www/ 美化 JS",
    ),
    (
        "Capacitor",
        [("path", "assets/public/"), ("path", "capacitor.config.json"), ("path", "capacitor.plugins.json")],
        "前端在 assets/public/",
        "直接取 assets/public/ 美化 JS",
    ),
    (
        "APICloud",
        [("path", "assets/widget/"), ("path", "com/uzmap"), ("path", "com/apicloud")],
        "前端在 assets/widget/",
        "取 assets/widget/；可能加密需 hook",
    ),
    (
        "Cocos2d-x",
        [("so", "libcocos2d"), ("so", "libcocos"), ("path", "assets/src/project.json")],
        "脚本/资源在 assets/(libcocos2d* 引擎)",
        "JS/Lua 在 assets，可能加密(xxtea)需逆 .so 取密钥",
    ),
]


@dataclass
class FrameworkMatch:
    framework: str
    score: int
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "score": self.score,
            "evidence": self.evidence,
        }


@dataclass
class FrameworkDetectResult:
    primary: str = "原生 (Native Android)"
    code_location: str = "业务逻辑在 dex(Java/Kotlin)"
    reverse_hint: str = "脱壳(如加固)后 jadx 反编译 dex"
    confidence: str = "default"
    matches: list[FrameworkMatch] = field(default_factory=list)

    def to_static_fields(self) -> dict[str, Any]:
        return {
            "framework_name": self.primary,
            "framework_matches": [match.to_dict() for match in self.matches],
        }


def detect_framework(apk_path: str) -> FrameworkDetectResult:
    names = _list_entry_names(apk_path)
    so_names = [name.rsplit("/", 1)[-1] for name in names if name.endswith(".so")]

    scored: list[tuple[str, int, list[str], str, str]] = []
    for framework_name, signatures, code_location, reverse_hint in FRAMEWORK_RULES:
        evidence: list[str] = []
        for kind, pattern in signatures:
            if kind == "so":
                hit = next((so_name for so_name in so_names if pattern in so_name), None)
                if hit:
                    evidence.append(f"lib/*/{hit}")
                continue

            hit = next((name for name in names if pattern in name), None)
            if hit:
                evidence.append(hit)

        if evidence:
            scored.append((framework_name, len(evidence), evidence, code_location, reverse_hint))

    if not scored:
        return FrameworkDetectResult()

    scored.sort(key=lambda item: item[1], reverse=True)
    primary = scored[0]
    return FrameworkDetectResult(
        primary=primary[0],
        code_location=primary[3],
        reverse_hint=primary[4],
        confidence="high" if primary[1] >= 2 else "low",
        matches=[FrameworkMatch(framework=item[0], score=item[1], evidence=item[2]) for item in scored],
    )


def _list_entry_names(apk_path: str) -> list[str]:
    """List APK entries; fall back to carving local ZIP headers if central directory is damaged."""
    try:
        with zipfile.ZipFile(apk_path) as archive:
            return archive.namelist()
    except (zipfile.BadZipFile, OSError):
        pass

    try:
        with open(apk_path, "rb") as file_obj:
            data = file_obj.read()
    except OSError:
        return []

    names: list[str] = []
    signature = b"PK\x03\x04"
    offset = data.find(signature)
    while offset >= 0:
        try:
            name_length = struct.unpack_from("<H", data, offset + 26)[0]
            name = data[offset + 30 : offset + 30 + name_length].decode("utf-8", "replace")
            if name:
                names.append(name)
        except struct.error:
            pass
        offset = data.find(signature, offset + 4)
    return names
