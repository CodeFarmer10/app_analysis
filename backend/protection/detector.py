from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ProtectionVendor:
    name_cn: str
    name_en: str
    product: str
    open_source: bool = False

    @property
    def is_other(self) -> bool:
        return self.name_en == "Other"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name_cn": self.name_cn,
            "name_en": self.name_en,
            "product": self.product,
            "open_source": self.open_source,
            "is_other": self.is_other,
        }


OTHER_VENDOR = ProtectionVendor(name_cn="其他", name_en="Other", product="Unknown")


_VENDOR_RULES: list[tuple[str, ProtectionVendor]] = [
    (r"bangcle|secshell", ProtectionVendor("梆梆安全", "Bangcle", "Bangcle / SecShell")),
    (r"secneo", ProtectionVendor("梆梆安全", "Bangcle", "Bangcle SecNeo")),
    (r"\bjiagu\b|qihoo\s*360|360\s*jiagu", ProtectionVendor("奇虎360", "Qihoo 360", "360加固保")),
    (
        r"tencent.*legu|legu|mobile\s*tencent\s*protect|tencent\s*security\s*enterprise|txappentry|stubshell",
        ProtectionVendor("腾讯", "Tencent", "腾讯乐固 / 御安全"),
    ),
    (r"\bijiami\b", ProtectionVendor("爱加密", "Ijiami", "爱加密")),
    (r"\bnaga\b", ProtectionVendor("娜迦信息", "Nagain", "娜迦 (Naga)")),
    (r"\bbaidu\b", ProtectionVendor("百度", "Baidu", "百度加固")),
    (
        r"alibaba|alipay|mobisecenhance|ali\s+security|com/ali/",
        ProtectionVendor("阿里巴巴", "Alibaba", "阿里聚安全 / 阿里加固"),
    ),
    (r"\bkiro\b|kiwisec|kiwi\s*enc|kiwivm", ProtectionVendor("几维安全", "KiwiSec", "几维安全 (KiwiSec)")),
    (r"tongfu\s*shield|tongfudun|payegis", ProtectionVendor("通付盾", "Payegis", "通付盾 (Payegis)")),
    (r"dingxiang", ProtectionVendor("顶象技术", "DingXiang", "顶象 (DingXiang)")),
    (r"haiyun", ProtectionVendor("海云安", "Haiyun'an", "海云安")),
    (r"dxshield", ProtectionVendor("东信和平", "DxShield", "DxShield")),
    (r"appsuit", ProtectionVendor("Stealien", "Stealien", "AppSuit")),
    (r"appsealing", ProtectionVendor("INKA Entworks", "INKA Entworks", "AppSealing")),
    (r"dexprotector", ProtectionVendor("Licel", "Licel", "DexProtector")),
    (r"dexguard", ProtectionVendor("Guardsquare", "Guardsquare", "DexGuard")),
    (r"arxan|guardit", ProtectionVendor("Digital.ai (Arxan)", "Arxan", "Arxan / GuardIT")),
    (r"whitecryption", ProtectionVendor("Intertrust", "Intertrust", "whiteCryption SCP")),
    (r"promon", ProtectionVendor("Promon", "Promon", "Promon SHIELD")),
    (r"nhn\s*appguard|appguard", ProtectionVendor("NHN", "NHN", "AppGuard")),
    (r"nq\s*shield|netqin|\bnqshield\b", ProtectionVendor("网秦", "NetQin", "NQ Shield")),
    (r"\bvirbox\b", ProtectionVendor("深思数盾", "SenseShield", "Virbox Protector")),
    (r"\bliapp\b", ProtectionVendor("Lockin Company", "Lockin", "LIAPP")),
    (r"\bkony\b", ProtectionVendor("Kony", "Kony", "Kony")),
    (
        r"insidesecure|metafortress|verimatrix",
        ProtectionVendor("Verimatrix", "Verimatrix", "Inside Secure / MetaFortress"),
    ),
    (r"apkprotect", ProtectionVendor("APKProtect", "APKProtect", "APKProtect")),
    (r"apkguard", ProtectionVendor("APKGuard", "APKGuard", "APKGuard")),
    (r"ahope|appshield", ProtectionVendor("Ahope", "Ahope", "AppShield")),
    (r"shield\s*sdk|com/shield/android", ProtectionVendor("SHIELD", "SHIELD", "SHIELD SDK")),
    (r"quarks\s*appshield|epona", ProtectionVendor("Quarkslab", "Quarkslab", "Quarks AppShield (Epona)")),
    (r"\bbshield\b", ProtectionVendor("BShield", "BShield", "BShield")),
    (r"proguard", ProtectionVendor("Guardsquare", "Guardsquare", "ProGuard", open_source=True)),
    (
        r"obfuscator-?llvm|\bollvm\b",
        ProtectionVendor("OLLVM 项目", "Obfuscator-LLVM", "Obfuscator-LLVM (OLLVM)", open_source=True),
    ),
    (r"armariris", ProtectionVendor("复旦大学", "Fudan", "Armariris", open_source=True)),
    (r"\bhikari\b", ProtectionVendor("Hikari 项目", "Hikari", "Hikari Obfuscator", open_source=True)),
    (r"advobfuscator", ProtectionVendor("Andrivet", "Andrivet", "ADVobfuscator", open_source=True)),
    (r"blackobfuscator", ProtectionVendor("CodingGay", "CodingGay", "BlackObfuscator", open_source=True)),
    (r"stringfog", ProtectionVendor("MegatronKing", "MegatronKing", "StringFog", open_source=True)),
    (r"beebyte", ProtectionVendor("Beebyte", "Beebyte", "Beebyte Obfuscator")),
    (r"safeengine", ProtectionVendor("Safengine", "Safengine", "Safengine LLVM")),
    (r"lsposed", ProtectionVendor("LSPosed 项目", "LSPosed", "LSPosed Obfuscator", open_source=True)),
    (r"easyprotector", ProtectionVendor("lamster2018", "lamster2018", "EasyProtector", open_source=True)),
    (r"mt\s*protector|mtprotector", ProtectionVendor("MT管理器", "MT Manager", "MT Protector")),
    (r"\bupx\b", ProtectionVendor("UPX 项目", "UPX", "UPX", open_source=True)),
    (r"kangapack|kangaroo", ProtectionVendor("其他", "Other", "KangaPack (袋鼠壳)")),
    (r"qdbh", ProtectionVendor("其他", "Other", "qdbh packer")),
    (r"joker", ProtectionVendor("其他", "Other", "Joker (恶意家族壳)")),
]

_COMPILED_VENDOR_RULES = [(re.compile(pattern, re.IGNORECASE), vendor) for pattern, vendor in _VENDOR_RULES]
_PACKER_TAGS = {"packer", "protector"}
_OBFUSCATOR_TAGS = {"obfuscator"}


@dataclass
class ProtectionFinding:
    category: str
    description: str
    vendor: ProtectionVendor
    matched_file: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "name": self.description,
            "matched_file": self.matched_file,
            "vendor": self.vendor.to_dict(),
        }


@dataclass
class ProtectionDetectResult:
    apk_path: str
    is_packed: bool = False
    is_obfuscated: bool = False
    packers: list[ProtectionFinding] = field(default_factory=list)
    obfuscators: list[ProtectionFinding] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def packer_vendors(self) -> list[ProtectionVendor]:
        return _dedupe_vendors([finding.vendor for finding in self.packers])

    @property
    def obfuscation_vendors(self) -> list[ProtectionVendor]:
        return _dedupe_vendors([finding.vendor for finding in self.obfuscators])

    def to_static_fields(self) -> dict[str, Any]:
        return {
            "is_packed": 1 if self.is_packed else 0,
            "packer_vendor": _vendor_summary(self.packer_vendors),
            "packer_vendors": [vendor.to_dict() for vendor in self.packer_vendors],
            "packer_details": [finding.to_dict() for finding in self.packers],
            "is_obfuscated": 1 if self.is_obfuscated else 0,
            "obfuscation_vendor": _vendor_summary(self.obfuscation_vendors),
            "obfuscation_vendors": [vendor.to_dict() for vendor in self.obfuscation_vendors],
            "obfuscator_details": [finding.to_dict() for finding in self.obfuscators],
            "protection_detect_error": None,
        }


class ApkidNotFound(RuntimeError):
    pass


def classify_vendor(description: str) -> ProtectionVendor:
    desc = (description or "").strip()
    for pattern, vendor in _COMPILED_VENDOR_RULES:
        if pattern.search(desc):
            return vendor
    return ProtectionVendor(name_cn="其他", name_en="Other", product=desc or "Unknown")


def detect_protection(apk_path: str, timeout: int = 120) -> ProtectionDetectResult:
    raw = run_apkid(apk_path, timeout=timeout)
    return parse_apkid_result(apk_path, raw)


def run_apkid(apk_path: str, timeout: int = 120) -> dict[str, Any]:
    if not os.path.exists(apk_path):
        raise FileNotFoundError(apk_path)

    apkid_bin = _find_apkid_binary()
    if apkid_bin is None:
        raise ApkidNotFound("未找到 apkid 可执行文件，请在当前虚拟环境安装 apkid")
    cmd = [apkid_bin, "-j", apk_path]

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    output = (proc.stdout or "").strip()
    if not output:
        raise RuntimeError(f"apkid 没有输出: {(proc.stderr or '').strip()[:500]}")
    brace_index = output.find("{")
    if brace_index > 0:
        output = output[brace_index:]
    return json.loads(output)


def _find_apkid_binary() -> str | None:
    executable_name = "apkid.exe" if os.name == "nt" else "apkid"
    environment_apkid = Path(sys.executable).parent / executable_name
    if environment_apkid.is_file() and os.access(environment_apkid, os.X_OK):
        return str(environment_apkid)
    return shutil.which("apkid")


def parse_apkid_result(apk_path: str, raw: dict[str, Any]) -> ProtectionDetectResult:
    result = ProtectionDetectResult(apk_path=apk_path, raw=raw)
    for file_entry in raw.get("files", []):
        if not isinstance(file_entry, dict):
            continue
        matched_file = str(file_entry.get("filename") or apk_path)
        matches = file_entry.get("matches") or {}
        if not isinstance(matches, dict):
            continue
        for tag_key, descriptions in matches.items():
            tags = {tag.strip() for tag in str(tag_key).split(",")}
            if not isinstance(descriptions, list):
                descriptions = [descriptions]
            for raw_description in descriptions:
                description = str(raw_description or "").strip()
                if not description:
                    continue
                if tags & _PACKER_TAGS:
                    category = "protector" if "protector" in tags else "packer"
                    result.packers.append(
                        ProtectionFinding(category, description, classify_vendor(description), matched_file)
                    )
                elif tags & _OBFUSCATOR_TAGS:
                    result.obfuscators.append(
                        ProtectionFinding("obfuscator", description, classify_vendor(description), matched_file)
                    )

    result.is_packed = bool(result.packers)
    result.is_obfuscated = bool(result.obfuscators)
    return result


def _dedupe_vendors(vendors: list[ProtectionVendor]) -> list[ProtectionVendor]:
    seen: dict[str, ProtectionVendor] = {}
    for vendor in vendors:
        key = f"{vendor.name_en}|{vendor.product}"
        seen.setdefault(key, vendor)
    return list(seen.values())


def _vendor_summary(vendors: list[ProtectionVendor]) -> str | None:
    if not vendors:
        return None
    return "、".join(
        vendor.product if vendor.is_other else f"{vendor.name_cn}/{vendor.name_en}"
        for vendor in vendors
    )
