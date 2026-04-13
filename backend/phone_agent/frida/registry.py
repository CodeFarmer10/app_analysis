from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

AGENT_BUNDLE_PATH = Path(__file__).resolve().parent / "agent.bundle.js"


@dataclass
class FridaHookRule:
    id: str
    class_name: str
    method_name: str
    enabled: bool = True
    arg_count: int | None = None
    hook_args: int = 0
    stringify_args: bool = True
    stringify_retval: bool = True
    include_retval: bool = True

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "FridaHookRule":
        raw_hook_arg = payload.get("hook_args", 0)
        hook_arg = 0
        if isinstance(raw_hook_arg, list):
            for item in raw_hook_arg:
                try:
                    index = int(item)
                except (TypeError, ValueError):
                    continue
                if index >= 0:
                    hook_arg = index
                    break
        else:
            try:
                parsed = int(raw_hook_arg)
            except (TypeError, ValueError):
                parsed = 0
            if parsed >= 0:
                hook_arg = parsed
        return cls(
            id=str(payload.get("id") or "").strip() or f"{payload.get('class_name')}#{payload.get('method_name')}",
            class_name=str(payload.get("class_name") or "").strip(),
            method_name=str(payload.get("method_name") or "").strip(),
            enabled=bool(payload.get("enabled", True)),
            arg_count=int(payload["arg_count"]) if payload.get("arg_count") is not None else None,
            hook_args=hook_arg,
            stringify_args=bool(payload.get("stringify_args", True)),
            stringify_retval=bool(payload.get("stringify_retval", True)),
            include_retval=bool(payload.get("include_retval", True)),
        )

    def is_valid(self) -> bool:
        return bool(self.enabled and self.class_name and self.method_name)

    def to_script_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_frida_rules(path: str | Path) -> list[FridaHookRule]:
    file_path = Path(path)
    if not file_path.exists():
        return []
    with file_path.open("r", encoding="utf-8") as file_obj:
        payload = json.load(file_obj)
    raw_rules = payload.get("rules") if isinstance(payload, dict) else payload
    if not isinstance(raw_rules, list):
        return []

    rules: list[FridaHookRule] = []
    for item in raw_rules:
        if not isinstance(item, dict):
            continue
        rule = FridaHookRule.from_dict(item)
        if rule.is_valid():
            rules.append(rule)
    return rules


def build_frida_script(rules: list[FridaHookRule]) -> str:
    rules_json = json.dumps([rule.to_script_dict() for rule in rules], ensure_ascii=False)
    if not AGENT_BUNDLE_PATH.exists():
        raise FileNotFoundError(
            f"frida agent bundle missing: {AGENT_BUNDLE_PATH}. "
            "please run backend/scripts/build_frida_bundle.sh first"
        )
    bundle_source = AGENT_BUNDLE_PATH.read_text(encoding="utf-8")
    bootstrap = f"""
'use strict';
globalThis.__frida_rules__ = {rules_json};
"""
    return bootstrap + "\n" + bundle_source
