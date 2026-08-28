from __future__ import annotations

import re
import struct
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Optional, Tuple


FRAMEWORK_RULES: list[tuple[str, list[tuple[str, str]], str, str]] = [
    (
        "Flutter",
        [("so", "libflutter.so"), ("so", "libapp.so")],
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
        [
            ("path", "assets/apps/"),
            ("path", "dcloud_control.xml"),
            ("so", "libweexcore.so"),
        ],
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

FLUTTER_LIBRARY_PATH = re.compile(r"^lib/([^/]+)/(libapp\.so|libflutter\.so)$")
DCLOUD_DIRECT_RESOURCE = re.compile(
    r"^assets/apps/([^/]+)/www/(manifest\.json|index\.html|app-config-service\.js)$"
)
DCLOUD_APP_ROOT = re.compile(r"^assets/apps/([^/]+)(?:/|$)")
VALID_DCLOUD_APPID = re.compile(r"^[A-Za-z0-9_.-]+$")
ANDROID_NAME = "{http://schemas.android.com/apk/res/android}name"
ANDROID_TARGET_ACTIVITY = "{http://schemas.android.com/apk/res/android}targetActivity"
KNOWN_DCLOUD_LAUNCHERS = {
    "io.dcloud.PandoraEntry",
    "io.dcloud.PandoraEntryActivity",
    "io.dcloud.uniapp.UniAppActivity",
}


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
        if framework_name == "Flutter":
            candidate = _flutter_candidate(names)
            if candidate:
                score, evidence = candidate
                scored.append((framework_name, score, evidence, code_location, reverse_hint))
            continue

        if framework_name == "uni-app/DCloud":
            candidate = _dcloud_candidate(apk_path, names)
            if candidate:
                score, evidence = candidate
                scored.append((framework_name, score, evidence, code_location, reverse_hint))
            continue

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


def _flutter_candidate(names: list[str]) -> Optional[Tuple[int, list[str]]]:
    libraries_by_abi: dict[str, set[str]] = {}
    for name in names:
        match = FLUTTER_LIBRARY_PATH.fullmatch(name)
        if match:
            libraries_by_abi.setdefault(match.group(1), set()).add(match.group(2))

    for abi in sorted(libraries_by_abi):
        if {"libapp.so", "libflutter.so"}.issubset(libraries_by_abi[abi]):
            return (
                2,
                [
                    f"lib/{abi}/libapp.so",
                    f"lib/{abi}/libflutter.so",
                ],
            )
    return None


def _is_valid_dcloud_appid(value: str) -> bool:
    return value not in {".", ".."} and VALID_DCLOUD_APPID.fullmatch(value) is not None


def _dcloud_direct_candidate(names: list[str]) -> Optional[Tuple[int, list[str]]]:
    for name in names:
        match = DCLOUD_DIRECT_RESOURCE.fullmatch(name)
        if match and _is_valid_dcloud_appid(match.group(1)):
            root = f"assets/apps/{match.group(1)}/www/"
            return 3, [root, name]
    return None


def _dcloud_auxiliary_evidence(names: list[str]) -> list[str]:
    evidence: list[str] = []

    control = next(
        (name for name in names if name.rsplit("/", 1)[-1] == "dcloud_control.xml"),
        None,
    )
    if control:
        evidence.append(control)

    for name in names:
        match = DCLOUD_APP_ROOT.match(name)
        if match and _is_valid_dcloud_appid(match.group(1)):
            evidence.append(name)
            break

    weex = next(
        (name for name in names if name.rsplit("/", 1)[-1] == "libweexcore.so"),
        None,
    )
    if weex:
        evidence.append(weex)

    return evidence


def _dcloud_candidate(
    apk_path: str,
    names: list[str],
) -> Optional[Tuple[int, list[str]]]:
    direct = _dcloud_direct_candidate(names)
    if direct:
        return direct

    auxiliary = _dcloud_auxiliary_evidence(names)
    if not auxiliary:
        return None

    launcher = _known_dcloud_launcher(apk_path)
    if not launcher:
        return None

    return 2, [f"launcher:{launcher}", auxiliary[0]]


def _manifest_xml(apk_path: str) -> str:
    try:
        with zipfile.ZipFile(apk_path) as archive:
            raw = archive.read("AndroidManifest.xml")
        if raw.lstrip().startswith(b"<"):
            return raw.decode("utf-8", "replace")
    except (KeyError, OSError, zipfile.BadZipFile):
        return ""

    try:
        from apkInspector.axml import parse_apk_for_manifest

        manifest = parse_apk_for_manifest(apk_path)
        if isinstance(manifest, bytes):
            return manifest.decode("utf-8", "replace")
        return manifest or ""
    except Exception:
        return ""


def _known_dcloud_launcher(apk_path: str) -> Optional[str]:
    manifest = _manifest_xml(apk_path)
    if not manifest:
        return None

    try:
        root = ET.fromstring(manifest)
    except (ET.ParseError, TypeError, ValueError):
        return None

    package_name = root.attrib.get("package", "")
    for component in root.iter():
        component_type = _local_name(component.tag)
        if component_type not in {"activity", "activity-alias"}:
            continue
        if not _has_launcher_intent(component):
            continue

        attribute = ANDROID_TARGET_ACTIVITY if component_type == "activity-alias" else ANDROID_NAME
        activity_name = _normalize_activity_name(
            component.attrib.get(attribute, ""),
            package_name,
        )
        if activity_name in KNOWN_DCLOUD_LAUNCHERS:
            return activity_name
    return None


def _has_launcher_intent(component: ET.Element) -> bool:
    for intent_filter in component:
        if _local_name(intent_filter.tag) != "intent-filter":
            continue

        actions: set[str] = set()
        categories: set[str] = set()
        for item in intent_filter:
            item_type = _local_name(item.tag)
            if item_type == "action":
                actions.add(item.attrib.get(ANDROID_NAME, ""))
            elif item_type == "category":
                categories.add(item.attrib.get(ANDROID_NAME, ""))

        if (
            "android.intent.action.MAIN" in actions
            and "android.intent.category.LAUNCHER" in categories
        ):
            return True
    return False


def _normalize_activity_name(name: str, package_name: str) -> str:
    if not name:
        return ""
    if name.startswith("."):
        return package_name + name
    if "." not in name and package_name:
        return package_name + "." + name
    return name


def _local_name(tag: object) -> str:
    return str(tag).rsplit("}", 1)[-1]


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
