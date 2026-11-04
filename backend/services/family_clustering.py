from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Sequence

from services.family_cluster_reference import (
    AppRecord,
    Family,
    dcloud_families,
    native_components_v2_families,
    native_families,
)


FLUTTER_THRESHOLD = 0.8
MIN_FAMILY_SIZE = 5
STAGE_FIELDS = {
    "components": "components",
    "pages": "dcloud_pages",
    "api_routes": "dcloud_api_routes",
}


@dataclass(frozen=True)
class ClusterCandidate:
    family_key: str
    framework_name: str
    strategy: str
    stage: str
    members: tuple[int, ...]
    fingerprints: tuple[str, ...]
    rule_expression: str
    center_index: int | None = None
    min_pair_similarity: float | None = None


def parse_values(value: Any) -> tuple[str, ...]:
    if value is None or value == "":
        return ()
    if isinstance(value, (tuple, list, set)):
        return tuple(str(item).strip() for item in value if str(item).strip())
    text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
    try:
        decoded = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        decoded = None
    if isinstance(decoded, list):
        return tuple(str(item).strip() for item in decoded if str(item).strip())
    return tuple(item.strip() for item in re.split(r"[,;\n\r]+", text) if item.strip())


def build_apps(rows: Sequence[dict[str, Any]]) -> tuple[list[AppRecord], dict[str, list[str]]]:
    apps: list[AppRecord] = []
    task_ids_by_md5: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        md5 = str(row.get("file_md5") or "").strip().lower()
        task_id = str(row.get("task_id") or "").strip()
        if not md5 or not task_id:
            continue
        task_ids_by_md5[md5].append(task_id)
        if len(task_ids_by_md5[md5]) > 1:
            continue
        apps.append(AppRecord(
            task_id=task_id,
            md5=md5,
            app_name=str(row.get("app_name") or ""),
            package_name=str(row.get("package_name") or ""),
            framework_name=str(row.get("framework_name") or "").strip(),
            component_string=str(row.get("components") or ""),
            so_files=parse_values(row.get("so_libraries")),
            dcloud_pages=parse_values(row.get("dcloud_pages")),
            dcloud_api_routes=parse_values(row.get("dcloud_api_routes")),
            flutter_primary_package=str(row.get("flutter_primary_package") or ""),
            flutter_library_uris=parse_values(row.get("flutter_library_uris")),
            flutter_primary_package_classes=parse_values(row.get("flutter_primary_package_classes")),
        ))
    return apps, task_ids_by_md5


def _strategy_for(framework_name: str) -> str:
    name = framework_name.lower()
    if "flutter" in name:
        return "flutter"
    if "dcloud" in name or "uni-app" in name or "uniapp" in name:
        return "dcloud"
    if "native" in name or "原生" in framework_name:
        return "native"
    return "framework_component"


def _family_key(framework: str, stage: str, apps: Sequence[AppRecord], members: Sequence[int]) -> str:
    source = "\x00".join((framework, stage, *sorted(apps[index].md5 for index in members)))
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _component_pattern(fingerprint: str, members: Sequence[AppRecord]) -> str:
    if fingerprint.startswith("F:"):
        full_name = fingerprint[2:].strip()
        packages = {app.package_name for app in members if app.package_name}
        if len(packages) == 1:
            package = next(iter(packages))
            if full_name.startswith(f"{package}."):
                relative = full_name[len(package):]
                if all(relative in re.split(r"[\s,;]+", app.component_string or "") for app in members):
                    return relative
        return full_name
    if fingerprint.startswith("H:"):
        value = fingerprint[2:].strip()
        return f"{value.replace('*', '%').rstrip('.')}.%"
    if fingerprint.startswith(("S:", "L:")):
        return f"%.{fingerprint[2:].strip().lstrip('.')}"
    return fingerprint


def _reference_rule(family: Family, apps: Sequence[AppRecord]) -> str:
    field = STAGE_FIELDS[family.stage]
    members = [apps[index] for index in family.members]
    patterns = list(dict.fromkeys(
        _component_pattern(item, members) if family.stage == "components" else f"%{item}%"
        for item in family.fingerprints
        if item.strip()
    ))
    if not patterns:
        raise ValueError(f"family {family.family_id} has no fingerprints")
    value = ",".join(patterns).replace("\\", "\\\\").replace("'", "''")
    return f"content_include({field},'{value}')"


def _flutter_candidates(apps: Sequence[AppRecord], indices: Sequence[int], rows_by_task: dict[str, dict]) -> list[ClusterCandidate]:
    from scipy.cluster.hierarchy import fcluster, linkage

    usable = []
    gram_sets = []
    for index in indices:
        grams = set(parse_values(rows_by_task[apps[index].task_id].get("flutter_aot_opcode_4grams")))
        if grams:
            usable.append(index)
            gram_sets.append(grams)
    if len(usable) < MIN_FAMILY_SIZE:
        return []

    token_to_bit = {
        token: offset
        for offset, token in enumerate(sorted(set().union(*gram_sets)))
    }
    masks = [sum(1 << token_to_bit[token] for token in grams) for grams in gram_sets]
    sizes = [len(grams) for grams in gram_sets]

    def similarity(left: int, right: int) -> float:
        overlap = (masks[left] & masks[right]).bit_count()
        return overlap / (sizes[left] + sizes[right] - overlap)

    parent = list(range(len(usable)))

    def find(position: int) -> int:
        while parent[position] != position:
            parent[position] = parent[parent[position]]
            position = parent[position]
        return position

    ordered = sorted(range(len(usable)), key=lambda position: (sizes[position], apps[usable[position]].md5))
    for offset, left in enumerate(ordered):
        for right in ordered[offset + 1:]:
            if sizes[left] / sizes[right] <= FLUTTER_THRESHOLD:
                break
            if similarity(left, right) > FLUTTER_THRESHOLD:
                parent[find(right)] = find(left)
    components: dict[int, list[int]] = defaultdict(list)
    for position in range(len(usable)):
        components[find(position)].append(position)

    candidates = []
    for component in components.values():
        if len(component) < MIN_FAMILY_SIZE:
            continue
        distances = [
            1.0 - similarity(left, right)
            for offset, left in enumerate(component[:-1])
            for right in component[offset + 1:]
        ]
        labels = fcluster(
            linkage(distances, method="complete"),
            t=1.0 - FLUTTER_THRESHOLD - 1e-12,
            criterion="distance",
        )
        groups: dict[int, list[int]] = defaultdict(list)
        for offset, label in enumerate(labels):
            groups[int(label)].append(component[offset])
        for positions in groups.values():
            if len(positions) < MIN_FAMILY_SIZE:
                continue
            scores = {position: [] for position in positions}
            for left_offset, left in enumerate(positions):
                for right in positions[left_offset + 1:]:
                    score = similarity(left, right)
                    scores[left].append(score)
                    scores[right].append(score)
            minimum = min(score for values in scores.values() for score in values)
            if minimum <= FLUTTER_THRESHOLD:
                raise AssertionError("Flutter family violates pairwise similarity threshold")
            center = max(positions, key=lambda position: (sum(scores[position]) / len(scores[position]), apps[usable[position]].md5))
            members = tuple(sorted(usable[position] for position in positions))
            fingerprints = tuple(sorted(gram_sets[center]))
            value = ",".join(fingerprints)
            candidates.append(ClusterCandidate(
                family_key=_family_key("Flutter", "aot_opcode_4grams", apps, members),
                framework_name="Flutter",
                strategy="flutter_aot_complete_link",
                stage="aot_opcode_4grams",
                members=members,
                fingerprints=fingerprints,
                rule_expression=f"jaccard_sim(flutter_aot_opcode_4grams,'{value}')>{FLUTTER_THRESHOLD}",
                center_index=usable[center],
                min_pair_similarity=minimum,
            ))
    return candidates


def cluster_candidates(apps: Sequence[AppRecord], rows: Sequence[dict[str, Any]]) -> list[ClusterCandidate]:
    by_framework: dict[str, list[int]] = defaultdict(list)
    rows_by_task = {str(row["task_id"]): row for row in rows}
    for index, app in enumerate(apps):
        if app.framework_name:
            by_framework[app.framework_name].append(index)

    result: list[ClusterCandidate] = []
    for framework, indices in sorted(by_framework.items()):
        strategy = _strategy_for(framework)
        if strategy == "flutter":
            result.extend(_flutter_candidates(apps, indices, rows_by_task))
            continue
        if strategy == "dcloud":
            families = dcloud_families(apps, indices)
        elif strategy == "native":
            families = native_components_v2_families(apps, indices, framework_name=framework)
        else:
            families = native_families(apps, indices, framework_name=framework, strategy="framework_component", prefix="CMP")
        for family in families:
            if len(family.members) < MIN_FAMILY_SIZE:
                continue
            result.append(ClusterCandidate(
                family_key=_family_key(framework, family.stage, apps, family.members),
                framework_name=framework,
                strategy=family.strategy,
                stage=family.stage,
                members=family.members,
                fingerprints=family.fingerprints,
                rule_expression=_reference_rule(family, apps),
            ))
    return sorted(result, key=lambda item: (-len(item.members), item.family_key))
