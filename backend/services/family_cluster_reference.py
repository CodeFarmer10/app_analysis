"""Framework clustering rules copied from cluster/framework_family_cluster/clustering.py."""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Callable, Iterable, Sequence


KNOWN_ANDROID_PREFIXES = (
    "android.",
    "androidx.",
    "cn.bmob.v3",
    "cn.jpush",
    "com.airbnb.",
    "com.alibaba.",
    "com.alipay.",
    "com.amap.",
    "com.anddoes.",
    "com.android.",
    "com.baidu.",
    "com.baseflow",
    "com.bjz.comm",
    "com.blankj.",
    "com.bumptech.",
    "com.bytedance",
    "com.coloros.",
    "com.crazecoder.openfile",
    "com.dexterous.flutterlocalnotifications",
    "com.dmcbig.mediapicker",
    "com.download.library",
    "com.example.myapplication",
    "com.facebook.",
    "com.getui",
    "com.google.",
    "com.heytap.",
    "com.htc.",
    "com.huawei.",
    "com.igexin",
    "com.journeyapps",
    "com.just.agentweb",
    "com.luck.picture",
    "com.lxj.xpopup",
    "com.lzy.imagepicker",
    "com.majeur.",
    "com.meizu.",
    "com.netease",
    "com.oppo.",
    "com.pichillilorenzo",
    "com.sec.",
    "com.snail.antifake",
    "com.sonyericsson.",
    "com.sonymobile.",
    "com.squareup.",
    "com.taobao.weex",
    "com.tencent.",
    "com.trtc",
    "com.vivo.",
    "com.xiaomi.",
    "com.yalantis.ucrop",
    "com.yzq.zxinglibrary",
    "de.julianassmann",
    "dev.fluttercommunity",
    "im.zego",
    "io.agora",
    "io.dcloud",
    "io.flutter.",
    "io.openim",
    "io.reactivex",
    "kotlin",
    "me.everything.",
    "me.jessyan.autosize",
    "org.apache.",
    "org.webrtc.",
    "pub.devrel.",
    "uts.sdk",
)

COMPONENTS_V2_SDK_PREFIXES = (
    "com.google.",
    "androidx.",
    "android.",
    "com.android.",
    "org.apache.",
    "com.huawei.",
    "com.sec.",
    "com.htc.",
    "com.oppo.",
    "com.heytap.",
    "com.coloros.",
    "com.sonymobile.",
    "com.sonyericsson.",
    "com.majeur.",
    "com.anddoes.",
    "me.everything.",
    "com.vivo.",
    "com.xiaomi.",
    "com.meizu.",
    "com.just.agentweb",
    "com.baidu.",
    "org.webrtc.",
    "pub.devrel.",
    "com.snail.antifake",
    "io.flutter.",
    "io.dcloud",
    "uts.sdk",
    "com.taobao.weex",
    "com.facebook.",
    "com.tencent.",
    "com.bumptech.",
    "com.squareup.",
    "io.reactivex.",
    "kotlin",
    "com.airbnb.",
    "com.bjz.comm",
    "com.getui",
    "com.igexin",
    "cn.jpush",
    "com.amap.",
    "com.alipay.",
    "com.yalantis.ucrop",
    "com.luck.picture",
    "com.dmcbig.mediapicker",
    "com.lzy.imagepicker",
    "com.journeyapps",
    "com.yzq.zxinglibrary",
    "me.jessyan.autosize",
    "com.lxj.xpopup",
    "com.bytedance",
    "io.agora",
    "io.openim",
    "im.zego",
    "com.trtc",
    "com.netease",
    "dev.fluttercommunity",
    "com.baseflow",
    "com.pichillilorenzo",
    "com.crazecoder.openfile",
    "com.download.library",
    "com.dexterous.flutterlocalnotifications",
    "de.julianassmann",
    "com.example.myapplication",
    "cn.bmob.v3",
)

COMPONENTS_V2_GENERIC_LAST_NAMES = frozenset(
    {
        "MainActivity",
        "WXEntryActivity",
        "WXPayEntryActivity",
    }
)

FRAMEWORK_SO = {
    "libapp.so",
    "libc++.so",
    "libc++_shared.so",
    "libfbjni.so",
    "libflutter.so",
    "libfolly_runtime.so",
    "libglog.so",
    "libhermes.so",
    "libjsc.so",
    "libreactnativejni.so",
    "libuts-runtime.so",
    "libweexcore.so",
    "libweexjsb.so",
    "libweexjss.so",
    "libyoga.so",
}

COMMON_DART_PACKAGES = {
    "analyzer",
    "archive",
    "args",
    "asn1lib",
    "async",
    "bloc",
    "characters",
    "clock",
    "collection",
    "convert",
    "crypto",
    "dio",
    "encrypt",
    "equatable",
    "ffi",
    "file",
    "flutter_bloc",
    "flutter_localizations",
    "flutter_riverpod",
    "flutter_svg",
    "get",
    "get_it",
    "go_router",
    "html",
    "http",
    "http_parser",
    "intl",
    "js",
    "json_annotation",
    "logging",
    "meta",
    "mime",
    "nested",
    "path",
    "plugin_platform_interface",
    "pointycastle",
    "pool",
    "protobuf",
    "provider",
    "riverpod",
    "rxdart",
    "source_span",
    "stack_trace",
    "stream_channel",
    "synchronized",
    "typed_data",
    "uuid",
    "vector_math",
    "web",
    "web_socket_channel",
    "win32",
    "xml",
    "yaml",
}

GENERIC_FLUTTER_CLASSES = {
    "App",
    "Application",
    "BaseModel",
    "BasePage",
    "BaseState",
    "BaseView",
    "Config",
    "Constants",
    "Controller",
    "Error",
    "Home",
    "HomePage",
    "HttpClient",
    "Loading",
    "LoginPage",
    "MainPage",
    "Model",
    "MyApp",
    "Network",
    "Response",
    "Result",
    "Router",
    "Service",
    "Settings",
    "SplashPage",
    "State",
    "Utils",
    "ViewModel",
}

PLATFORM_PLUGIN_SUFFIXES = (
    "_android",
    "_ios",
    "_linux",
    "_macos",
    "_platform_interface",
    "_web",
    "_windows",
)

_VOWELS = set("aeiou")
_TRIVIAL_NAME_STEMS = {
    "",
    "android",
    "app",
    "demo",
    "test",
    "xxxxx",
    "应用",
    "未知",
}


@dataclass(frozen=True)
class AppRecord:
    task_id: str
    md5: str
    app_name: str
    package_name: str
    framework_name: str
    component_string: str
    so_files: tuple[str, ...]
    dcloud_pages: tuple[str, ...]
    dcloud_api_routes: tuple[str, ...]
    flutter_primary_package: str
    flutter_library_uris: tuple[str, ...]
    flutter_primary_package_classes: tuple[str, ...]


@dataclass(frozen=True)
class Family:
    family_id: str
    framework_name: str
    strategy: str
    stage: str
    members: tuple[int, ...]
    fingerprints: tuple[str, ...]


NATIVE_COMPONENTS_V2_LAST_STATS: dict[str, int] = {}


def stable_family_id(prefix: str, apps: Sequence[AppRecord], members: Iterable[int]) -> str:
    md5s = sorted(apps[index].md5 for index in members)
    digest = hashlib.sha256(";".join(md5s).encode("utf-8")).hexdigest()[:12]
    return f"{prefix}_{digest}"


def looks_random(segment: str) -> bool:
    value = segment.lower()
    if len(value) < 6 or not re.fullmatch(r"[a-z0-9]+", value):
        return False
    if any(char.isdigit() for char in value):
        return True
    vowels = sum(char in _VOWELS for char in value)
    longest_consonants = max(
        (
            len(match)
            for match in re.findall(r"[bcdfghjklmnpqrstvwxyz]+", value)
        ),
        default=0,
    )
    return vowels / len(value) < 0.28 or longest_consonants >= 5


def canonical_root(component: str, depth: int = 3) -> str:
    parts = component.split(".")
    head = parts[:depth] if len(parts) > depth else parts[:-1]
    return ".".join("*" if looks_random(part) else part for part in head)


def suffix_skeleton(component: str) -> str:
    parts = component.split(".")
    if len(parts) < 2:
        return ""
    return f"{parts[-2]}.{parts[-1].split('$', 1)[0]}"


def is_code_component(value: str) -> bool:
    if "." not in value or ".permission." in value.lower():
        return False
    last = value.rsplit(".", 1)[-1].split("$", 1)[0]
    return bool(last) and last[0].isupper()


def component_tokens(app: AppRecord) -> set[str]:
    raw_tokens = re.split(r"[\s,;]+", app.component_string or "")
    output: set[str] = set()
    for raw in raw_tokens:
        value = raw.strip().strip("\"'")
        if not value:
            continue
        if value.startswith(".") and app.package_name:
            value = app.package_name + value
        if is_code_component(value):
            output.add(value)
    return output


def is_perm_like_v2(value: str) -> bool:
    last = value.split(".")[-1]
    lowered = value.lower()
    last_lowered = last.lower()
    return (
        ".permission." in lowered
        or "permission" in last_lowered
        or lowered.startswith("android.permission.")
        or lowered.startswith("android.hardware.")
        or lowered.startswith("android.feature.")
        or (last.isupper() and len(last) > 2)
    )


def is_component_candidate_v2(value: str) -> bool:
    if not value or "." not in value or is_perm_like_v2(value):
        return False
    return re.fullmatch(r"[A-Za-z_][A-Za-z0-9_$.]*", value) is not None


def component_tokens_v2(app: AppRecord) -> set[str]:
    output: set[str] = set()
    for raw in re.split(r"[\s,;]+", app.component_string or ""):
        value = raw.strip().strip("\"'")
        if not value:
            continue
        if value.startswith(".") and app.package_name:
            value = app.package_name + value
        if is_component_candidate_v2(value):
            output.add(value)
    return output


def suffix_skeleton_v2(component: str) -> str:
    parts = component.split(".")
    if len(parts) < 2:
        return ""
    return f"{parts[-2]}.{parts[-1]}"


def is_generic_component_feature_v2(feature: str) -> bool:
    if not feature.startswith(("S:", "L:")):
        return False
    return feature[2:].rsplit(".", 1)[-1] in COMPONENTS_V2_GENERIC_LAST_NAMES


def normalized_so_files(app: AppRecord) -> frozenset[str]:
    output = set()
    for value in app.so_files:
        name = PurePosixPath(str(value).replace("\\", "/")).name
        if not name or name in FRAMEWORK_SO:
            continue
        if re.fullmatch(r"lib[0-9a-fA-F]{6,}\.so", name):
            continue
        output.add(name)
    return frozenset(output)


def name_stem(value: str) -> str:
    stem = re.sub(r"[\d\W_]+$", "", value or "", flags=re.UNICODE).strip()
    if len(stem) < 2 or stem.lower() in _TRIVIAL_NAME_STEMS:
        return ""
    return stem


def jaccard(left: set[str] | frozenset[str], right: set[str] | frozenset[str]) -> float:
    if not left or not right:
        return 0.0
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def weighted_cosine(left: set[str], right: set[str], weights: dict[str, float]) -> float:
    if not left or not right:
        return 0.0
    intersection = left & right
    if not intersection:
        return 0.0
    numerator = sum(weights.get(item, 1.0) ** 2 for item in intersection)
    left_norm = math.sqrt(sum(weights.get(item, 1.0) ** 2 for item in left))
    right_norm = math.sqrt(sum(weights.get(item, 1.0) ** 2 for item in right))
    return numerator / (left_norm * right_norm) if left_norm and right_norm else 0.0


def weighted_jaccard(
    left: set[str], right: set[str], weights: dict[str, float]
) -> tuple[float, int, float]:
    intersection = left & right
    union = left | right
    if not union:
        return 0.0, 0, 0.0
    common_weight = sum(weights.get(item, 1.0) for item in intersection)
    union_weight = sum(weights.get(item, 1.0) for item in union)
    smaller_weight = min(
        sum(weights.get(item, 1.0) for item in left),
        sum(weights.get(item, 1.0) for item in right),
    )
    return (
        common_weight / union_weight,
        len(intersection),
        common_weight / smaller_weight if smaller_weight else 0.0,
    )


def connected_components(nodes: Iterable[int], adjacency: dict[int, set[int]]) -> list[set[int]]:
    remaining = set(nodes)
    components: list[set[int]] = []
    while remaining:
        start = min(remaining)
        stack = [start]
        component = set()
        remaining.remove(start)
        while stack:
            node = stack.pop()
            component.add(node)
            neighbors = adjacency.get(node, set()) & remaining
            remaining -= neighbors
            stack.extend(neighbors)
        components.append(component)
    return components


def strict_groups(
    nodes: Iterable[int],
    feature_sets: dict[int, set[str]],
    adjacency: dict[int, set[int]],
    min_family_size: int,
    *,
    coherence_first: bool = False,
) -> list[tuple[tuple[int, ...], tuple[str, ...]]]:
    """把图分量拆成至少具有一个全体共有特征的互斥家族。"""
    groups: list[tuple[tuple[int, ...], tuple[str, ...]]] = []
    for component in connected_components(nodes, adjacency):
        if len(component) < min_family_size:
            continue
        intersection = set.intersection(*(feature_sets[index] for index in component))
        if intersection and not coherence_first:
            groups.append((tuple(sorted(component)), tuple(sorted(intersection))))
            continue

        inverted: dict[str, set[int]] = defaultdict(set)
        for index in component:
            for feature in feature_sets[index]:
                inverted[feature].add(index)

        candidates: list[tuple[tuple[int, ...], str, int, float]] = []
        for feature, feature_nodes in inverted.items():
            if len(feature_nodes) < min_family_size:
                continue
            for subgroup in connected_components(feature_nodes, adjacency):
                if len(subgroup) >= min_family_size:
                    candidate = tuple(sorted(subgroup))
                    common_count = len(
                        set.intersection(
                            *(feature_sets[index] for index in candidate)
                        )
                    )
                    coherence = common_count * math.log2(len(candidate) + 1)
                    candidates.append(
                        (candidate, feature, common_count, coherence)
                    )
        if coherence_first:
            candidates.sort(
                key=lambda item: (
                    -item[3],
                    -item[2],
                    -len(item[0]),
                    item[1],
                    item[0],
                )
            )
        else:
            candidates.sort(
                key=lambda item: (-len(item[0]), item[1], item[0])
            )

        assigned: set[int] = set()
        for candidate, _anchor, _common_count, _coherence in candidates:
            available = set(candidate) - assigned
            for subgroup in connected_components(available, adjacency):
                if len(subgroup) < min_family_size:
                    continue
                common = set.intersection(*(feature_sets[index] for index in subgroup))
                if not common:
                    continue
                members = tuple(sorted(subgroup))
                groups.append((members, tuple(sorted(common))))
                assigned.update(subgroup)
    return groups


def build_similarity_graph(
    indices: Sequence[int],
    feature_sets: dict[int, set[str]],
    *,
    min_feature_count: int,
    min_shared: int,
    threshold: float,
    min_containment: float,
    dcloud_mode: bool = False,
) -> tuple[dict[int, set[int]], dict[str, int]]:
    eligible = [
        index for index in indices if len(feature_sets.get(index, set())) >= min_feature_count
    ]
    document_frequency: Counter[str] = Counter()
    for index in eligible:
        document_frequency.update(feature_sets[index])
    weights = {
        feature: math.log((len(eligible) + 1) / (frequency + 1)) + 1.0
        for feature, frequency in document_frequency.items()
    }
    adjacency = {index: set() for index in eligible}
    for position, left_index in enumerate(eligible):
        left = feature_sets[left_index]
        for right_index in eligible[position + 1 :]:
            right = feature_sets[right_index]
            shared = len(left & right)
            if shared < min_shared:
                continue
            if dcloud_mode:
                union_size = len(left | right)
                jac = shared / union_size if union_size else 0.0
                containment = shared / min(len(left), len(right))
                cosine = weighted_cosine(left, right, weights)
                linked = (
                    left == right
                    or cosine >= threshold
                    or (jac >= 0.55 and containment >= min_containment)
                )
            else:
                score, _, containment = weighted_jaccard(left, right, weights)
                linked = score >= threshold and containment >= min_containment
            if linked:
                adjacency[left_index].add(right_index)
                adjacency[right_index].add(left_index)
    return adjacency, dict(document_frequency)


def feature_families(
    apps: Sequence[AppRecord],
    indices: Sequence[int],
    feature_sets: dict[int, set[str]],
    *,
    framework_name: str,
    strategy: str,
    stage: str,
    prefix: str,
    min_feature_count: int,
    min_shared: int,
    threshold: float,
    min_containment: float,
    min_family_size: int,
    dcloud_mode: bool = False,
) -> list[Family]:
    adjacency, document_frequency = build_similarity_graph(
        indices,
        feature_sets,
        min_feature_count=min_feature_count,
        min_shared=min_shared,
        threshold=threshold,
        min_containment=min_containment,
        dcloud_mode=dcloud_mode,
    )
    groups = strict_groups(adjacency, feature_sets, adjacency, min_family_size)
    families = []
    for members, common in groups:
        fingerprints = tuple(
            sorted(common, key=lambda value: (document_frequency.get(value, 10**9), value))
        )
        families.append(
            Family(
                family_id=stable_family_id(prefix, apps, members),
                framework_name=framework_name,
                strategy=strategy,
                stage=stage,
                members=members,
                fingerprints=fingerprints,
            )
        )
    families.sort(key=lambda family: (-len(family.members), family.family_id))
    return families


def native_feature_sets(
    apps: Sequence[AppRecord], indices: Sequence[int]
) -> tuple[dict[int, set[str]], dict[str, int], dict[str, int]]:
    heads_by_app: dict[int, set[str]] = {}
    suffixes_by_app: dict[int, set[str]] = {}
    head_df: Counter[str] = Counter()
    suffix_df: Counter[str] = Counter()
    for index in indices:
        heads: set[str] = set()
        suffixes: set[str] = set()
        for component in component_tokens(apps[index]):
            if component.startswith(KNOWN_ANDROID_PREFIXES):
                continue
            root = canonical_root(component)
            literal_segments = [
                segment for segment in root.split(".") if segment and segment != "*"
            ]
            if (
                not root
                or len(literal_segments) < 2
                or root.startswith(KNOWN_ANDROID_PREFIXES)
            ):
                continue
            heads.add(root)
            suffix = suffix_skeleton(component)
            if suffix:
                suffixes.add(suffix)
        heads_by_app[index] = heads
        suffixes_by_app[index] = suffixes
        head_df.update(heads)
        suffix_df.update(suffixes)

    count = len(indices)
    head_max = max(2, math.floor(0.12 * count))
    suffix_max = max(2, math.floor(0.20 * count))
    feature_sets: dict[int, set[str]] = {}
    for index in indices:
        features = {
            f"H:{value}"
            for value in heads_by_app[index]
            if 2 <= head_df[value] <= head_max
        }
        features |= {
            f"S:{value}"
            for value in suffixes_by_app[index]
            if 2 <= suffix_df[value] <= suffix_max
        }
        feature_sets[index] = features
    return feature_sets, dict(head_df), dict(suffix_df)


def native_families(
    apps: Sequence[AppRecord],
    indices: Sequence[int],
    *,
    framework_name: str,
    strategy: str = "native_component",
    prefix: str = "NAT",
) -> list[Family]:
    feature_sets, head_df, suffix_df = native_feature_sets(apps, indices)
    weights = {
        feature: math.log((len(indices) + 1) / (frequency + 1)) + 1.0
        for feature, frequency in {
            **{f"H:{name}": count for name, count in head_df.items()},
            **{f"S:{name}": count for name, count in suffix_df.items()},
        }.items()
    }
    so_sets = {index: normalized_so_files(apps[index]) for index in indices}
    stems = {index: name_stem(apps[index].app_name) for index in indices}
    inverted: dict[str, list[int]] = defaultdict(list)
    for index in indices:
        for feature in feature_sets[index]:
            inverted[feature].append(index)

    candidate_pairs: set[tuple[int, int]] = set()
    posting_cap = max(2, min(500, math.floor(0.12 * len(indices))))
    for feature, members in inverted.items():
        if len(members) > posting_cap:
            continue
        for left_position, left in enumerate(members):
            for right in members[left_position + 1 :]:
                candidate_pairs.add((min(left, right), max(left, right)))

    adjacency = {index: set() for index in indices}
    mid_cut = max(2, math.floor(0.06 * len(indices)))
    suffix_distinctive_cut = max(2, math.floor(0.20 * len(indices)))
    for left, right in candidate_pairs:
        common = feature_sets[left] & feature_sets[right]
        common_heads = {
            feature
            for feature in common
            if feature.startswith("H:") and head_df.get(feature[2:], 10**9) <= mid_cut
        }
        common_suffixes = {
            feature
            for feature in common
            if feature.startswith("S:")
            and suffix_df.get(feature[2:], 10**9) <= suffix_distinctive_cut
        }
        cosine = weighted_cosine(feature_sets[left], feature_sets[right], weights)
        so_score = jaccard(so_sets[left], so_sets[right])
        both_empty_so = not so_sets[left] and not so_sets[right]
        fork = False
        if len(common_suffixes) >= 10:
            namespace_counts = Counter(
                feature[2:].split(".", 1)[0] for feature in common_suffixes
            )
            top_count = namespace_counts.most_common(1)[0][1]
            fork = top_count >= 10 and top_count / len(common_suffixes) >= 0.60
        linked = (
            fork
            or (bool(common_heads) and so_score >= 0.50)
            or (
                bool(common_heads)
                and bool(stems[left])
                and stems[left] == stems[right]
            )
            or (bool(common_heads) and both_empty_so and cosine >= 0.80)
            or (cosine >= 0.50 and so_score >= 0.30)
        )
        if linked:
            adjacency[left].add(right)
            adjacency[right].add(left)

    document_frequency = Counter()
    for features in feature_sets.values():
        document_frequency.update(features)
    groups = strict_groups(indices, feature_sets, adjacency, min_family_size=2)
    families = []
    for members, common in groups:
        fingerprints = tuple(
            sorted(common, key=lambda value: (document_frequency[value], value))
        )
        families.append(
            Family(
                family_id=stable_family_id(prefix, apps, members),
                framework_name=framework_name,
                strategy=strategy,
                stage="components",
                members=members,
                fingerprints=fingerprints,
            )
        )
    families.sort(key=lambda family: (-len(family.members), family.family_id))
    return families


def native_components_v2_feature_sets(
    apps: Sequence[AppRecord], indices: Sequence[int]
) -> tuple[
    dict[int, set[str]],
    dict[int, set[str]],
    dict[int, set[str]],
    dict[str, int],
    dict[str, int],
    dict[str, float],
]:
    """构建聚类 H/S/L 特征及仅用于指纹提取的 F 特征。"""
    heads_by_app: dict[int, set[str]] = {}
    suffixes_by_app: dict[int, set[str]] = {}
    full_names_by_app: dict[int, set[str]] = {}
    last_names_by_app: dict[int, set[str]] = {}
    head_df: Counter[str] = Counter()
    feature_df: Counter[str] = Counter()

    for index in indices:
        heads: set[str] = set()
        suffixes: set[str] = set()
        full_names: set[str] = set()
        last_names: set[str] = set()
        for component in component_tokens_v2(apps[index]):
            # F 只用于最终指纹，因此保留完整类名；仍在过滤表中的 SDK 必须
            # 基于尚未将随机包段泛化为 "*" 的原始类名判断，避免绕过前缀过滤。
            full_names.add(component)
            if component.startswith(COMPONENTS_V2_SDK_PREFIXES):
                continue
            root = canonical_root(component)
            if not root:
                continue
            heads.add(root)
            last_names.add(component.rsplit(".", 1)[-1])
            suffix = suffix_skeleton_v2(component)
            if suffix:
                suffixes.add(suffix)
        heads_by_app[index] = heads
        suffixes_by_app[index] = suffixes
        full_names_by_app[index] = full_names
        last_names_by_app[index] = last_names
        for head in heads:
            head_df[head] += 1
            feature_df[f"H:{head}"] += 1
        for suffix in suffixes:
            feature_df[f"S:{suffix}"] += 1
        for full_name in full_names:
            feature_df[f"F:{full_name}"] += 1
        for last_name in last_names:
            feature_df[f"L:{last_name}"] += 1

    app_count = len(indices)
    head_high_cut = 0.20 * app_count
    suffix_last_high_cut = 0.80 * app_count
    kept = {
        feature
        for feature, frequency in feature_df.items()
        if frequency >= 5
        and (
            (
                feature.startswith("H:")
                and frequency <= head_high_cut
            )
            or (
                feature.startswith(("S:", "L:"))
                and frequency <= suffix_last_high_cut
            )
        )
    }
    idf = {
        feature: math.log(app_count / feature_df[feature])
        for feature in kept
    }
    suffix_max = 0.80 * app_count
    feature_sets: dict[int, set[str]] = {}
    fingerprint_feature_sets: dict[int, set[str]] = {}
    distinctive_suffixes: dict[int, set[str]] = {}
    for index in indices:
        features = {
            f"H:{head}" for head in heads_by_app[index] if f"H:{head}" in kept
        }
        features |= {
            f"S:{suffix}"
            for suffix in suffixes_by_app[index]
            if f"S:{suffix}" in kept
        }
        features |= {
            f"L:{last_name}"
            for last_name in last_names_by_app[index]
            if f"L:{last_name}" in kept
        }
        feature_sets[index] = features
        fingerprint_feature_sets[index] = features | {
            f"F:{full_name}" for full_name in full_names_by_app[index]
        }
        distinctive_suffixes[index] = {
            feature
            for feature in features
            if feature.startswith("S:") and feature_df[feature] <= suffix_max
        }
    return (
        feature_sets,
        fingerprint_feature_sets,
        distinctive_suffixes,
        dict(head_df),
        dict(feature_df),
        idf,
    )


def merge_redundant_component_fingerprints(
    fingerprints: Iterable[str],
) -> tuple[str, ...]:
    """合并 F/S/L 后缀包含及 H 包根被 F 完整类名包含的冗余表达。"""
    unique = set(fingerprints)
    component_features = {
        feature: "." + feature[2:].lstrip(".")
        for feature in unique
        if feature.startswith(("F:", "S:", "L:"))
    }
    redundant = set()
    for feature, dotted_value in component_features.items():
        for other, other_dotted_value in component_features.items():
            if feature == other:
                continue
            if (
                len(other_dotted_value) > len(dotted_value)
                and other_dotted_value.endswith(dotted_value)
            ):
                redundant.add(feature)
                break

    full_names = [feature[2:] for feature in unique if feature.startswith("F:")]
    for head_feature in (feature for feature in unique if feature.startswith("H:")):
        head_parts = head_feature[2:].split(".")
        for full_name in full_names:
            full_parts = full_name.split(".")
            if len(full_parts) < len(head_parts):
                continue
            if all(
                head_part == "*" or head_part == full_parts[position]
                for position, head_part in enumerate(head_parts)
            ):
                redundant.add(head_feature)
                break
    return tuple(sorted(unique - redundant))


def native_family_merge_score(
    left_core: set[str], right_core: set[str]
) -> tuple[int, float, int] | None:
    """返回家族级归并强度；无稳定 H 或充分 fork 骨架交集时不归并。"""
    shared = left_core & right_core
    if not shared:
        return None

    stable_heads = {
        feature
        for feature in shared
        if feature.startswith("H:") and "*" not in feature
    }
    if stable_heads:
        return (2, 1.0, len(stable_heads))

    left_code = {
        feature for feature in left_core if feature.startswith(("S:", "L:"))
    }
    right_code = {
        feature for feature in right_core if feature.startswith(("S:", "L:"))
    }
    shared_code = left_code & right_code
    shared_last_names = {
        feature for feature in shared_code if feature.startswith("L:")
    }
    smaller = min(len(left_code), len(right_code))
    containment = len(shared_code) / smaller if smaller else 0.0
    if len(shared_last_names) >= 5 and (
        containment >= 0.50 or len(shared_code) >= 10
    ):
        return (1, containment, len(shared_code))
    return None


def merge_native_family_groups(
    groups: Sequence[tuple[tuple[int, ...], tuple[str, ...]]],
    feature_sets: dict[int, set[str]],
) -> tuple[list[tuple[tuple[int, ...], tuple[str, ...]]], int]:
    """按当前家族全体核心做交集约束的凝聚归并，避免单链造成空交集。"""
    clusters = []
    for members, _common in groups:
        member_set = set(members)
        core = set.intersection(*(feature_sets[index] for index in member_set))
        clusters.append({"members": member_set, "core": core})

    merge_operations = 0
    while True:
        best: tuple[tuple[int, float, int, int], int, int] | None = None
        for left_index, left in enumerate(clusters):
            for right_index in range(left_index + 1, len(clusters)):
                right = clusters[right_index]
                score = native_family_merge_score(left["core"], right["core"])
                if score is None:
                    continue
                candidate = (
                    (
                        score[0],
                        score[1],
                        score[2],
                        len(left["members"]) + len(right["members"]),
                    ),
                    left_index,
                    right_index,
                )
                if best is None or candidate[0] > best[0]:
                    best = candidate
        if best is None:
            break

        _, left_index, right_index = best
        merged_members = (
            clusters[left_index]["members"] | clusters[right_index]["members"]
        )
        merged_core = set.intersection(
            *(feature_sets[index] for index in merged_members)
        )
        clusters[left_index] = {
            "members": merged_members,
            "core": merged_core,
        }
        del clusters[right_index]
        merge_operations += 1

    output = [
        (
            tuple(sorted(cluster["members"])),
            tuple(sorted(cluster["core"])),
        )
        for cluster in clusters
    ]
    output.sort(key=lambda item: (-len(item[0]), item[0]))
    return output, merge_operations


def has_sufficient_family_fingerprint(fingerprints: Iterable[str]) -> bool:
    """自定义 H/F 任一强指纹即可；否则至少需要两个非通用 S/L 指纹。"""
    values = set(fingerprints)
    if any(feature.startswith("H:") for feature in values):
        return True
    if any(
        feature.startswith("F:")
        and not feature[2:].startswith(COMPONENTS_V2_SDK_PREFIXES)
        for feature in values
    ):
        return True
    return (
        sum(
            feature.startswith(("S:", "L:"))
            and not is_generic_component_feature_v2(feature)
            for feature in values
        )
        >= 2
    )


def iterative_two_core_mask(adjacency_matrix):
    """返回图的 2-core 节点掩码，迭代删除当前度数小于 2 的节点。"""
    import numpy as np

    active = np.ones(adjacency_matrix.shape[0], dtype=np.bool_)
    while True:
        active_degrees = adjacency_matrix[:, active].sum(axis=1)
        remove = active & (active_degrees < 2)
        if not np.any(remove):
            return active
        active[remove] = False


def native_components_v2_pair_linked(
    left: set[str],
    right: set[str],
    *,
    head_df: dict[str, int],
    feature_df: dict[str, int],
    idf: dict[str, float],
    mid_cut: float,
    suffix_max: float,
) -> bool:
    """使用原生 v2 主图的同一规则判断二次聚类中的一对 APP 是否连边。"""
    common = left & right
    if not common:
        return False
    anchor_count = sum(
        feature.startswith("H:")
        and head_df.get(feature[2:], 10**18) <= mid_cut
        for feature in common
    )
    cosine = weighted_cosine(left, right, idf)
    if (
        (anchor_count >= 2 and cosine >= 0.35)
        or (anchor_count >= 1 and cosine >= 0.55)
        or (len(common) >= 3 and cosine >= 0.75)
    ):
        return True

    shared_suffixes = {
        feature
        for feature in common
        if feature.startswith("S:")
        and feature_df.get(feature, 10**18) <= suffix_max
    }
    if len(shared_suffixes) < 10:
        return False
    namespace_counts = Counter(
        feature[2:].split(".", 1)[0] for feature in shared_suffixes
    )
    if not namespace_counts:
        return False
    top_count = namespace_counts.most_common(1)[0][1]
    return top_count >= 10 and top_count / len(shared_suffixes) >= 0.60


def recluster_weak_native_group(
    members: Sequence[int],
    feature_sets: dict[int, set[str]],
    *,
    head_df: dict[str, int],
    feature_df: dict[str, int],
    idf: dict[str, float],
    mid_cut: float,
    suffix_max: float,
) -> tuple[list[tuple[tuple[int, ...], tuple[str, ...]]], int]:
    """移除弱候选公共桥接特征，在候选内部重建图并进行一次严格二次聚类。"""
    member_tuple = tuple(sorted(members))
    if len(member_tuple) < 2:
        return [], 0
    weak_common = set.intersection(
        *(feature_sets[index] for index in member_tuple)
    )
    residual_feature_sets = {
        index: feature_sets[index] - weak_common for index in member_tuple
    }
    adjacency = {index: set() for index in member_tuple}
    for position, left_index in enumerate(member_tuple):
        for right_index in member_tuple[position + 1 :]:
            if native_components_v2_pair_linked(
                residual_feature_sets[left_index],
                residual_feature_sets[right_index],
                head_df=head_df,
                feature_df=feature_df,
                idf=idf,
                mid_cut=mid_cut,
                suffix_max=suffix_max,
            ):
                adjacency[left_index].add(right_index)
                adjacency[right_index].add(left_index)

    active = set(member_tuple)
    while True:
        remove = {
            index
            for index in active
            if len(adjacency[index] & active) < 2
        }
        if not remove:
            break
        active -= remove
    if len(active) < 2:
        return [], 0

    groups = strict_groups(
        active,
        residual_feature_sets,
        adjacency,
        min_family_size=2,
        coherence_first=True,
    )
    return merge_native_family_groups(groups, residual_feature_sets)


def native_family_fingerprints(
    members: Sequence[int],
    fingerprint_feature_sets: dict[int, set[str]],
    feature_df: dict[str, int],
) -> tuple[str, ...]:
    common_fingerprints = set.intersection(
        *(fingerprint_feature_sets[index] for index in members)
    )
    merged_fingerprints = merge_redundant_component_fingerprints(
        common_fingerprints
    )
    return tuple(
        sorted(
            merged_fingerprints,
            key=lambda feature: (
                {
                    "H:": 0,
                    "F:": 1,
                    "S:": 2,
                    "L:": 3,
                }.get(feature[:2], 4),
                feature_df.get(feature, 1),
                feature,
            ),
        )
    )


def native_components_v2_families(
    apps: Sequence[AppRecord],
    indices: Sequence[int],
    *,
    framework_name: str,
) -> list[Family]:
    """使用 H/S/F/L components 连边规则聚类，并强制指纹为全体交集。"""
    (
        feature_sets,
        fingerprint_feature_sets,
        distinctive_suffixes,
        head_df,
        feature_df,
        idf,
    ) = native_components_v2_feature_sets(apps, indices)
    app_count = len(indices)
    mid_cut = 0.06 * app_count
    suffix_max = 0.80 * app_count

    try:
        import numpy as np
        from scipy.sparse import csr_matrix
    except ImportError as exc:
        raise RuntimeError(
            "components-only v2 全量聚类需要 NumPy 和 SciPy 稀疏矩阵支持"
        ) from exc

    local_to_global = list(indices)
    global_to_local = {
        global_index: local_index
        for local_index, global_index in enumerate(local_to_global)
    }
    feature_names = sorted(idf)
    feature_columns = {
        feature: column for column, feature in enumerate(feature_names)
    }
    rows: list[int] = []
    columns: list[int] = []
    binary_data: list[int] = []
    weighted_data: list[float] = []
    anchor_data: list[int] = []
    suffix_data: list[int] = []
    for global_index in indices:
        row = global_to_local[global_index]
        for feature in feature_sets[global_index]:
            rows.append(row)
            columns.append(feature_columns[feature])
            binary_data.append(1)
            weighted_data.append(idf[feature])
            anchor_data.append(
                int(
                    feature.startswith("H:")
                    and head_df.get(feature[2:], 10**18) <= mid_cut
                )
            )
            suffix_data.append(
                int(
                    feature.startswith("S:")
                    and feature_df[feature] <= suffix_max
                )
            )

    shape = (app_count, len(feature_names))
    row_array = np.asarray(rows, dtype=np.int32)
    column_array = np.asarray(columns, dtype=np.int32)
    binary_matrix = csr_matrix(
        (
            np.asarray(binary_data, dtype=np.uint16),
            (row_array, column_array),
        ),
        shape=shape,
    )
    weighted_matrix = csr_matrix(
        (
            np.asarray(weighted_data, dtype=np.float64),
            (row_array, column_array),
        ),
        shape=shape,
    )
    anchor_matrix = csr_matrix(
        (
            np.asarray(anchor_data, dtype=np.uint16),
            (row_array, column_array),
        ),
        shape=shape,
    )
    suffix_matrix = csr_matrix(
        (
            np.asarray(suffix_data, dtype=np.uint16),
            (row_array, column_array),
        ),
        shape=shape,
    )
    anchor_matrix.eliminate_zeros()
    suffix_matrix.eliminate_zeros()
    norms = np.sqrt(weighted_matrix.multiply(weighted_matrix).sum(axis=1)).A1
    norms[norms == 0] = 1e-9

    adjacency_matrix = np.zeros((app_count, app_count), dtype=np.bool_)

    block_size = 128
    for start in range(0, app_count, block_size):
        stop = min(start + block_size, app_count)
        binary_block = binary_matrix[start:stop]
        weighted_block = weighted_matrix[start:stop]
        shared_counts = (binary_block @ binary_matrix.T).toarray()
        weighted_dots = (weighted_block @ weighted_matrix.T).toarray()
        anchor_counts = (
            anchor_matrix[start:stop] @ anchor_matrix.T
        ).toarray()
        suffix_counts = (
            suffix_matrix[start:stop] @ suffix_matrix.T
        ).toarray()
        cosine = weighted_dots / (
            norms[start:stop, np.newaxis] * norms[np.newaxis, :]
        )
        linked = (
            ((anchor_counts >= 2) & (cosine >= 0.35))
            | ((anchor_counts >= 1) & (cosine >= 0.55))
            | ((shared_counts >= 3) & (cosine >= 0.75))
        )

        fork_candidates = np.argwhere((suffix_counts >= 10) & ~linked)
        for left_offset, right_local in fork_candidates:
            left_local = start + int(left_offset)
            right_local = int(right_local)
            if left_local >= right_local:
                continue
            left_global = local_to_global[left_local]
            right_global = local_to_global[right_local]
            shared_suffixes = (
                distinctive_suffixes[left_global]
                & distinctive_suffixes[right_global]
            )
            namespace_counts = Counter(
                feature[2:].split(".", 1)[0]
                for feature in shared_suffixes
            )
            if not namespace_counts:
                continue
            top_count = namespace_counts.most_common(1)[0][1]
            if top_count >= 10 and top_count / len(shared_suffixes) >= 0.60:
                linked[int(left_offset), right_local] = True

        adjacency_matrix[start:stop, :] = linked

    adjacency_matrix |= adjacency_matrix.T
    np.fill_diagonal(adjacency_matrix, False)
    initial_degrees = adjacency_matrix.sum(axis=1)
    initially_connected = initial_degrees > 0

    # 反复删除度数小于 2 的节点，得到图的 2-core。
    active = iterative_two_core_mask(adjacency_matrix)

    active_locals = np.flatnonzero(active)
    groups: list[tuple[tuple[int, ...], tuple[str, ...]]] = []
    core_component_count = 0
    if active_locals.size:
        from scipy.sparse.csgraph import connected_components as sparse_components

        core_adjacency = csr_matrix(
            adjacency_matrix[np.ix_(active_locals, active_locals)]
        )
        core_component_count, labels = sparse_components(
            core_adjacency,
            directed=False,
            return_labels=True,
        )
        for component_label in range(core_component_count):
            component_locals = active_locals[labels == component_label]
            component_globals = tuple(
                local_to_global[int(local)] for local in component_locals
            )
            if len(component_globals) < 2:
                continue
            common = set.intersection(
                *(feature_sets[index] for index in component_globals)
            )
            if common:
                groups.append((tuple(sorted(component_globals)), tuple(sorted(common))))
                continue

            # 仅在连通分量没有共有聚类特征时，构建该小分量的完整邻接表继续严格拆分。
            component_adjacency: dict[int, set[int]] = {
                index: set() for index in component_globals
            }
            for left_position, left_local in enumerate(component_locals):
                linked_positions = np.flatnonzero(
                    adjacency_matrix[int(left_local), component_locals]
                )
                left_global = local_to_global[int(left_local)]
                for right_position in linked_positions:
                    if int(right_position) == left_position:
                        continue
                    right_global = local_to_global[
                        int(component_locals[int(right_position)])
                    ]
                    component_adjacency[left_global].add(right_global)
            groups.extend(
                strict_groups(
                    component_globals,
                    feature_sets,
                    component_adjacency,
                    min_family_size=2,
                )
            )

    NATIVE_COMPONENTS_V2_LAST_STATS.clear()
    NATIVE_COMPONENTS_V2_LAST_STATS.update(
        {
            "apps": app_count,
            "graph_edges": int(np.count_nonzero(np.triu(adjacency_matrix, 1))),
            "initially_connected_apps": int(np.count_nonzero(initially_connected)),
            "isolated_apps": int(np.count_nonzero(~initially_connected)),
            "two_core_apps": int(active_locals.size),
            "two_core_pruned_apps": int(app_count - active_locals.size),
            "connected_nonisolated_pruned_apps": int(
                np.count_nonzero(initially_connected & ~active)
            ),
            "two_core_components": int(core_component_count),
        }
    )

    initial_strict_family_count = len(groups)
    groups, family_merge_operations = merge_native_family_groups(
        groups,
        feature_sets,
    )

    families = []
    primary_weak_groups: list[tuple[tuple[int, ...], tuple[str, ...]]] = []
    primary_weak_candidate_apps = 0
    for members, common in groups:
        fingerprints = native_family_fingerprints(
            members,
            fingerprint_feature_sets,
            feature_df,
        )
        if not fingerprints or not has_sufficient_family_fingerprint(fingerprints):
            primary_weak_groups.append((members, common))
            primary_weak_candidate_apps += len(members)
            continue
        families.append(
            Family(
                family_id=stable_family_id("NC2", apps, members),
                framework_name=framework_name,
                strategy="native_components_only_v2",
                stage="components",
                members=members,
                fingerprints=fingerprints,
            )
        )

    secondary_candidate_families = 0
    secondary_family_merge_operations = 0
    secondary_recovered_families = 0
    secondary_recovered_apps = 0
    weak_fingerprint_rejected_families = 0
    weak_fingerprint_rejected_apps = 0
    for members, _common in primary_weak_groups:
        secondary_groups, secondary_merges = recluster_weak_native_group(
            members,
            feature_sets,
            head_df=head_df,
            feature_df=feature_df,
            idf=idf,
            mid_cut=mid_cut,
            suffix_max=suffix_max,
        )
        secondary_candidate_families += len(secondary_groups)
        secondary_family_merge_operations += secondary_merges
        recovered_members: set[int] = set()
        for secondary_members, _secondary_common in secondary_groups:
            fingerprints = native_family_fingerprints(
                secondary_members,
                fingerprint_feature_sets,
                feature_df,
            )
            if (
                not fingerprints
                or not has_sufficient_family_fingerprint(fingerprints)
            ):
                continue
            recovered_members.update(secondary_members)
            secondary_recovered_families += 1
            secondary_recovered_apps += len(secondary_members)
            families.append(
                Family(
                    family_id=stable_family_id(
                        "NC2", apps, secondary_members
                    ),
                    framework_name=framework_name,
                    strategy="native_components_only_v2",
                    stage="components",
                    members=secondary_members,
                    fingerprints=fingerprints,
                )
            )

        unrecovered_count = len(set(members) - recovered_members)
        if unrecovered_count:
            weak_fingerprint_rejected_families += 1
            weak_fingerprint_rejected_apps += unrecovered_count
    families.sort(key=lambda family: (-len(family.members), family.family_id))
    NATIVE_COMPONENTS_V2_LAST_STATS.update(
        {
            "initial_strict_families": initial_strict_family_count,
            "family_merge_operations": family_merge_operations,
            "post_merge_candidate_families": len(groups),
            "primary_weak_candidate_families": len(primary_weak_groups),
            "primary_weak_candidate_apps": primary_weak_candidate_apps,
            "secondary_candidate_families": secondary_candidate_families,
            "secondary_family_merge_operations": (
                secondary_family_merge_operations
            ),
            "secondary_recovered_families": secondary_recovered_families,
            "secondary_recovered_apps": secondary_recovered_apps,
            "weak_fingerprint_rejected_families": (
                weak_fingerprint_rejected_families
            ),
            "weak_fingerprint_rejected_apps": weak_fingerprint_rejected_apps,
            "final_families": len(families),
            "final_assigned_apps": sum(
                len(family.members) for family in families
            ),
        }
    )
    return families


def normalize_dcloud_feature(value: str) -> str:
    feature = str(value).strip().strip("\"'").replace("\\/", "/")
    feature = feature.split("?", 1)[0].split("#", 1)[0]
    feature = re.sub(r"/+", "/", feature).strip("/")
    if feature.endswith(".vue"):
        feature = feature[:-4]
    return feature


def dcloud_families(
    apps: Sequence[AppRecord], indices: Sequence[int]
) -> list[Family]:
    page_sets = {
        index: {
            value
            for raw in apps[index].dcloud_pages
            if (value := normalize_dcloud_feature(raw))
        }
        for index in indices
    }
    page_families = feature_families(
        apps,
        indices,
        page_sets,
        framework_name="uni-app/DCloud",
        strategy="dcloud_staged",
        stage="pages",
        prefix="DCP",
        min_feature_count=5,
        min_shared=5,
        threshold=0.82,
        min_containment=0.70,
        min_family_size=3,
        dcloud_mode=True,
    )
    assigned = {index for family in page_families for index in family.members}
    remaining = [index for index in indices if index not in assigned]
    api_sets = {
        index: {
            value
            for raw in apps[index].dcloud_api_routes
            if (value := normalize_dcloud_feature(raw))
        }
        for index in remaining
    }
    api_families = feature_families(
        apps,
        remaining,
        api_sets,
        framework_name="uni-app/DCloud",
        strategy="dcloud_staged",
        stage="api_routes",
        prefix="DCA",
        min_feature_count=5,
        min_shared=5,
        threshold=0.82,
        min_containment=0.70,
        min_family_size=3,
        dcloud_mode=True,
    )
    return page_families + api_families


def flutter_library_sets(
    apps: Sequence[AppRecord], indices: Sequence[int]
) -> dict[int, set[str]]:
    raw_sets: dict[int, set[str]] = {}
    root_df: Counter[str] = Counter()
    for index in indices:
        values = {str(value).strip() for value in apps[index].flutter_library_uris if value}
        raw_sets[index] = values
        roots = {
            match.group(1)
            for value in values
            if (match := re.match(r"^package:([^/]+)/", value))
        }
        root_df.update(roots)

    high_df_cut = max(8, math.floor(0.20 * len(indices)))
    output: dict[int, set[str]] = {}
    for index in indices:
        primary = apps[index].flutter_primary_package
        retained = set()
        for uri in raw_sets[index]:
            if uri.startswith(("dart:", "package:flutter/")):
                continue
            match = re.match(r"^package:([^/]+)/", uri)
            root = match.group(1) if match else ""
            if root and root != primary:
                if root in COMMON_DART_PACKAGES:
                    continue
                if root.endswith(PLATFORM_PLUGIN_SUFFIXES):
                    continue
                if root_df[root] > high_df_cut:
                    continue
            if uri.startswith("file:") and "/.pub-cache/" in uri:
                continue
            retained.add(uri)
        output[index] = retained
    return output


def informative_flutter_class(value: str) -> bool:
    name = re.sub(r"<.*>", "", str(value)).strip()
    if not name or name in GENERIC_FLUTTER_CLASSES:
        return False
    if name.startswith(("_", "$")) or len(name) < 4:
        return False
    return not bool(re.fullmatch(r"[A-Za-z]\d?", name))


def flutter_families(
    apps: Sequence[AppRecord], indices: Sequence[int]
) -> list[Family]:
    library_sets = flutter_library_sets(apps, indices)
    library_families = feature_families(
        apps,
        indices,
        library_sets,
        framework_name="Flutter",
        strategy="flutter_staged",
        stage="library_uri",
        prefix="FLU",
        min_feature_count=8,
        min_shared=8,
        threshold=0.58,
        min_containment=0.68,
        min_family_size=2,
    )
    assigned = {index for family in library_families for index in family.members}
    remaining = [index for index in indices if index not in assigned]
    class_sets = {
        index: {
            str(value).strip()
            for value in apps[index].flutter_primary_package_classes
            if informative_flutter_class(str(value))
        }
        for index in remaining
    }
    class_families = feature_families(
        apps,
        remaining,
        class_sets,
        framework_name="Flutter",
        strategy="flutter_staged",
        stage="primary_package_classes",
        prefix="FLC",
        min_feature_count=8,
        min_shared=8,
        threshold=0.58,
        min_containment=0.68,
        min_family_size=2,
    )
    return library_families + class_families


def assert_strict_fingerprints(
    families: Sequence[Family],
    feature_provider: Callable[[Family, int], set[str]],
) -> None:
    for family in families:
        if not family.fingerprints:
            raise AssertionError(f"{family.family_id} 没有严格共有指纹")
        for index in family.members:
            features = feature_provider(family, index)
            missing = set(family.fingerprints) - features
            if missing:
                raise AssertionError(
                    f"{family.family_id}/{index} 缺少指纹: {sorted(missing)[:3]}"
                )
