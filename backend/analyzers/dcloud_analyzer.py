from __future__ import annotations

import json
import re
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from analyzers.artifact_policy import MAX_TEXT_FILE_BYTES


TEXT_EXTENSIONS = {".js", ".json", ".html", ".htm", ".txt", ".css", ".map"}
URL_RE = re.compile(r"""(?i)\b(?:https?|wss?)://[^\s"'<>\\`]+""")
QUOTED_RE = re.compile(r"""(?P<q>["'`])(?P<s>[^"'`\\]{1,300})(?P=q)""")
PATH_LITERAL_RE = re.compile(r"""(?P<q>["'`])(?P<route>/[A-Za-z0-9_./${}?=&:%-]{2,260})(?P=q)""")
ROUTE_RE = re.compile(
    r"""(?P<q>["'])/?(?P<route>[A-Za-z0-9_-]*pages[A-Za-z0-9_/-]*(?:/[A-Za-z0-9_.-]+)+)(?:\.vue)?(?P=q)"""
)
REQUEST_CONTEXT_RE = re.compile(
    r"""(?i)(uni\.request|request\s*\(|axios|fetch\s*\(|ajax\s*\(|uploadFile|downloadFile|"""
    r"""baseURL|baseUrl|base_url|apiUrl|api_url|apiBase|host|domain|networkList|"""
    r"""domainList|apiList|srcarr|srcArr|urlList|nodeList|lineList|webviewUrl|webUrl|app_url|"""
    r"""loadURL|plus\.webview\.create|createWebview|location\.href|location\.replace)"""
)

NOISE_DOMAINS = {
    "api.map.baidu.com",
    "api.next.bspapp.com",
    "api.bspapp.com",
    "apis.map.qq.com",
    "at.alicdn.com",
    "cdn.jsdelivr.net",
    "developer.mozilla.org",
    "developers.weixin.qq.com",
    "ext.dcloud.net.cn",
    "github.com",
    "jquery.com",
    "map.qq.com",
    "maps.googleapis.com",
    "mui.ucmed.cn",
    "service.dcloud.net.cn",
    "stackoverflow.com",
    "unpkg.com",
    "vuejs.org",
    "webapi.amap.com",
    "www.google.com",
    "www.googleapis.com",
    "www.w3.org",
}
NOISE_DOMAIN_SUFFIXES = (".vuejs.org", ".w3.org")
API_FIRST_SEGMENTS = {
    "api",
    "apis",
    "ajax",
    "app",
    "auth",
    "bank",
    "card",
    "common",
    "config",
    "customer",
    "file",
    "finance",
    "group",
    "home",
    "image",
    "index",
    "login",
    "market",
    "message",
    "my",
    "news",
    "notice",
    "order",
    "pay",
    "product",
    "public",
    "publics",
    "qrLogin",
    "recharge",
    "register",
    "stock",
    "stock-record",
    "stock-sales",
    "team",
    "trade",
    "upload",
    "user",
    "users",
    "video",
    "wallet",
    "withdraw",
    "withdrawal",
}
SKIP_ROUTE_PREFIXES = (
    "/assets/",
    "/css/",
    "/fonts/",
    "/hybrid/",
    "/img/",
    "/images/",
    "/js/",
    "/pages/",
    "/static/",
    "/uni_modules/",
    "/wxcomponents/",
)
SKIP_ROUTE_EXTENSIONS = (
    ".apk",
    ".css",
    ".gif",
    ".htm",
    ".html",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".json",
    ".map",
    ".mp3",
    ".mp4",
    ".png",
    ".svg",
    ".ttf",
    ".txt",
    ".wasm",
    ".webp",
    ".woff",
    ".woff2",
)
SKIP_EXACT_ROUTES = {
    "/api/js",
    "/image/gif",
    "/image/jpeg",
    "/image/jpg",
    "/image/png",
    "/image/svg+xml",
    "/image/webp",
}


@dataclass
class DCloudAnalysisResult:
    tech_type: str = "unknown"
    appids: list[str] = field(default_factory=list)
    pages: list[str] = field(default_factory=list)
    api_routes: list[str] = field(default_factory=list)
    remote_service_urls: list[str] = field(default_factory=list)
    remote_service_domains: list[str] = field(default_factory=list)
    is_confused: bool = False
    confusion_details: list[str] = field(default_factory=list)
    is_obfuscated: bool = False

    def to_static_field(self) -> dict:
        return {
            "tech_type": self.tech_type,
            "appids": self.appids,
            "pages": self.pages,
            "api_routes": self.api_routes,
            "remote_service_urls": self.remote_service_urls,
            "remote_service_domains": self.remote_service_domains,
            "is_confused": self.is_confused,
            "confusion_details": self.confusion_details,
            "is_obfuscated": self.is_obfuscated,
        }


def analyze_dcloud_apk(apk_path: str) -> DCloudAnalysisResult:
    pages: list[str] = []
    urls: set[str] = set()
    domains: set[str] = set()
    api_routes: set[str] = set()
    text_by_name: dict[str, str] = {}

    with zipfile.ZipFile(apk_path) as archive:
        names = archive.namelist()
        appids = _get_dcloud_appids(names)
        is_confused, confusion_details = _detect_dcloud_confusion(archive, names)

        _collect_pages(archive, names, pages)

        for name in names:
            if not _is_dcloud_text_asset(name):
                continue
            text = _safe_read_text(archive, name)
            if not text:
                continue
            text_by_name[name] = text
            _collect_plain_text_features(text, urls, domains, api_routes)

            if name.endswith(("/www/index.html", ".html")) and _should_try_html_deobfuscation(text):
                restored = _node_deobfuscate_html(text)
                if restored:
                    _collect_plain_text_features(restored, urls, domains, api_routes, force_service_urls=True)

    return DCloudAnalysisResult(
        tech_type=_classify_tech_type(names, text_by_name, appids),
        appids=appids,
        pages=pages,
        api_routes=sorted(api_routes),
        remote_service_urls=sorted(urls),
        remote_service_domains=sorted(domains),
        is_confused=is_confused,
        confusion_details=confusion_details,
        is_obfuscated=is_confused,
    )


def _safe_read_text(archive: zipfile.ZipFile, name: str, max_bytes: int = MAX_TEXT_FILE_BYTES) -> str:
    try:
        info = archive.getinfo(name)
        if info.file_size > max_bytes:
            return ""
        return archive.read(name).decode("utf-8", "replace")
    except (KeyError, OSError, UnicodeDecodeError):
        return ""


def _get_dcloud_appids(names: list[str]) -> list[str]:
    appids = set()
    for name in names:
        match = re.match(r"assets/apps/([^/]+)/www/", name)
        if match:
            appids.add(match.group(1))
    return sorted(appids)


def _is_dcloud_text_asset(name: str) -> bool:
    return name.startswith("assets/apps/") and Path(name).suffix.lower() in TEXT_EXTENSIONS


def _normalize_page(value: object) -> str | None:
    if not value:
        return None
    page = str(value).strip().strip("\"'")
    page = page.split("?", 1)[0].split("#", 1)[0]
    page = page.replace("\\/", "/").replace("\\\\", "/").lstrip("/")
    if page.endswith(".vue"):
        page = page[:-4]
    page = re.sub(r"/+", "/", page).strip("/")
    if not page or "page" not in page.split("/", 1)[0].lower():
        return None
    if page.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js")):
        return None
    if not re.fullmatch(r"[A-Za-z0-9_./-]+", page):
        return None
    return page


def _add_page(pages: list[str], value: object) -> None:
    page = _normalize_page(value)
    if page and page not in pages:
        pages.append(page)


def _parse_js_value(text: str, var_name: str) -> object | None:
    match = re.search(rf"\b(?:var\s+)?{re.escape(var_name)}\s*=", text)
    if not match:
        return None
    index = match.end()
    while index < len(text) and text[index].isspace():
        index += 1
    try:
        value, _ = json.JSONDecoder().raw_decode(text[index:])
        return value
    except json.JSONDecodeError:
        return None


def _collect_from_uni_config(value: object, pages: list[str]) -> None:
    if not isinstance(value, dict):
        return
    for page in value.get("pages") or []:
        _add_page(pages, page)
    _add_page(pages, value.get("entryPagePath"))
    tabbar = value.get("tabBar") or {}
    if isinstance(tabbar, dict):
        for item in tabbar.get("list") or []:
            if isinstance(item, dict):
                _add_page(pages, item.get("pagePath"))


def _collect_from_uni_routes(value: object, pages: list[str]) -> None:
    if not isinstance(value, list):
        return
    for route in value:
        if isinstance(route, dict):
            _add_page(pages, route.get("path"))


def _collect_from_manifest(text: str, pages: list[str]) -> None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    plus = data.get("plus") or {}
    tabbar = plus.get("tabBar") if isinstance(plus, dict) else None
    if isinstance(tabbar, dict):
        for item in tabbar.get("list") or []:
            if isinstance(item, dict):
                _add_page(pages, item.get("pagePath"))


def _collect_page_regex(text: str, pages: list[str], max_hits: int = 300) -> None:
    for index, match in enumerate(ROUTE_RE.finditer(text)):
        if index >= max_hits:
            break
        _add_page(pages, match.group("route"))


def _collect_from_filenames(names: list[str], pages: list[str]) -> None:
    for name in names:
        if "/www/" not in name or "/pages" not in name.lower():
            continue
        if not name.lower().endswith((".js", ".css", ".html", ".vue")):
            continue
        route = re.sub(r"\.(?:js|css|html|vue)$", "", name.split("/www/", 1)[1], flags=re.I)
        _add_page(pages, route)


def _collect_pages(archive: zipfile.ZipFile, names: list[str], pages: list[str]) -> None:
    config_names = sorted(
        [name for name in names if name.endswith("app-config-service.js")],
        key=lambda name: ("/www/" not in name, name),
    )
    config_names += sorted(
        [name for name in names if name.endswith("app-config.js") and name not in config_names],
        key=lambda name: ("/www/" not in name, name),
    )
    manifest_names = sorted([name for name in names if name.endswith("/manifest.json")])
    regex_names = sorted(
        [name for name in names if name.endswith(("app-service.js", "app-view.js"))],
        key=lambda name: (name.endswith("app-view.js"), name),
    )

    for name in config_names:
        text = _safe_read_text(archive, name)
        _collect_from_uni_config(_parse_js_value(text, "__uniConfig"), pages)
        _collect_from_uni_routes(_parse_js_value(text, "__uniRoutes"), pages)
        _collect_page_regex(text, pages)

    for name in manifest_names:
        _collect_from_manifest(_safe_read_text(archive, name), pages)

    if not pages:
        for name in regex_names:
            _collect_page_regex(_safe_read_text(archive, name), pages)
    if not pages:
        _collect_from_filenames(names, pages)


def _normalize_url(url: str, strip_query: bool = False) -> str:
    url = url.replace("\\/", "/").rstrip(".,);]}>'\"")
    url = re.sub(r"&amp;", "&", url)
    if strip_query:
        try:
            parsed = urlsplit(url)
            return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "", "", ""))
        except ValueError:
            return url
    return url


def _normalize_api_route(route: str) -> str | None:
    route = route.strip().replace("\\/", "/")
    if not route.startswith("/"):
        route = "/" + route
    route = route.split("#", 1)[0].split("?", 1)[0]
    route = route.rstrip(".,);]}")
    route = re.sub(r"/+", "/", route)
    if len(route) < 3 or route == "/" or route in SKIP_EXACT_ROUTES:
        return None
    lower = route.lower()
    if lower.startswith(SKIP_ROUTE_PREFIXES):
        return None
    path_part = route.split("${", 1)[0]
    if path_part.lower().endswith(SKIP_ROUTE_EXTENSIONS):
        return None
    first = route.lstrip("/").split("/", 1)[0]
    if first not in API_FIRST_SEGMENTS and not first.lower().startswith("api"):
        return None
    return route


def _is_noise_domain(parsed) -> bool:
    netloc = parsed.netloc.lower()
    hostname = (parsed.hostname or "").lower()
    if hostname in NOISE_DOMAINS or netloc in NOISE_DOMAINS:
        return True
    return any(hostname.endswith(suffix) for suffix in NOISE_DOMAIN_SUFFIXES)


def _add_service_url(urls: set[str], domains: set[str], url: str, keep_path: bool = False) -> None:
    normalized = _normalize_url(url, strip_query=True)
    try:
        parsed = urlsplit(normalized)
    except ValueError:
        return
    if parsed.scheme not in {"http", "https", "ws", "wss"} or not parsed.netloc:
        return
    hostname = (parsed.hostname or "").lower()
    netloc = parsed.netloc.lower()
    if any(char in netloc for char in "${},\\") or "@" in netloc:
        return
    if not re.fullmatch(r"[a-z0-9.-]+", hostname):
        return
    is_ipv4 = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname))
    if "." not in hostname and hostname != "localhost" and not is_ipv4:
        return
    if _is_noise_domain(parsed):
        return
    service_url = normalized if keep_path and parsed.path and parsed.path != "/" else urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    urls.add(service_url)
    domains.add(netloc)


def _collect_from_url_path(api_routes: set[str], url: str) -> None:
    try:
        parsed = urlsplit(_normalize_url(url))
    except ValueError:
        return
    route = _normalize_api_route(parsed.path or "")
    if route:
        api_routes.add(route)


def _has_business_api_path(url: str) -> bool:
    try:
        parsed = urlsplit(_normalize_url(url))
    except ValueError:
        return False
    return bool(_normalize_api_route(parsed.path or ""))


def _in_request_context(text: str, start: int, end: int) -> bool:
    return bool(REQUEST_CONTEXT_RE.search(text[max(0, start - 180):start]) or REQUEST_CONTEXT_RE.search(text[end:end + 80]))


def _collect_plain_text_features(
    text: str,
    urls: set[str],
    domains: set[str],
    api_routes: set[str],
    force_service_urls: bool = False,
) -> None:
    for match in URL_RE.finditer(text):
        url = match.group(0)
        _collect_from_url_path(api_routes, url)
        keep = force_service_urls or _in_request_context(text, match.start(), match.end()) or _has_business_api_path(url)
        if keep:
            _add_service_url(urls, domains, url, keep_path=_has_business_api_path(url) or force_service_urls)

    for match in PATH_LITERAL_RE.finditer(text):
        route = _normalize_api_route(match.group("route"))
        if route:
            api_routes.add(route)

    for match in QUOTED_RE.finditer(text):
        value = match.group("s").strip()
        if value.startswith(("http://", "https://", "ws://", "wss://")):
            _collect_from_url_path(api_routes, value)
            keep = force_service_urls or _in_request_context(text, match.start(), match.end()) or _has_business_api_path(value)
            if keep:
                _add_service_url(urls, domains, value, keep_path=_has_business_api_path(value) or force_service_urls)
        elif value.startswith("/") or re.match(r"^[A-Za-z0-9_-]+/[A-Za-z0-9_./${}?=&:-]+$", value):
            route = _normalize_api_route(value)
            if route:
                api_routes.add(route)


def _detect_dcloud_confusion(archive: zipfile.ZipFile, names: list[str]) -> tuple[bool, list[str]]:
    details: list[str] = []
    if any(name.endswith("/app-confusion.js") for name in names):
        details.append("app-confusion.js")

    for name in names:
        if not name.startswith("assets/apps/") or not name.endswith(("/manifest.json", "/mani.json")):
            continue
        text = _safe_read_text(archive, name)
        if not text:
            continue
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            if "confusion" in text:
                details.append(f"{name}:confusion_text")
            continue
        candidates = []
        if isinstance(data.get("plus"), dict):
            candidates.append(("plus.confusion", data["plus"].get("confusion")))
        if isinstance(data.get("app-plus"), dict):
            candidates.append(("app-plus.confusion", data["app-plus"].get("confusion")))
        if "confusion" in data:
            candidates.append(("confusion", data.get("confusion")))
        for label, value in candidates:
            if value not in (None, "", {}, []):
                details.append(f"{name}:{label}")
    return bool(details), sorted(set(details))


def _classify_tech_type(names: list[str], text_by_name: dict[str, str], appids: list[str]) -> str:
    has_uni_config = any(name.endswith("/app-config-service.js") for name in names)
    has_app_service = any(name.endswith("/app-service.js") for name in names)
    has_hybrid = any("/www/hybrid/html/" in name for name in names)
    has_index = any(name.startswith("assets/apps/") and name.endswith("/www/index.html") for name in names)
    joined = "\n".join(
        text for name, text in text_by_name.items()
        if name.endswith(("/app-service.js", "/app-config-service.js", "/app-view.js", "/index.html"))
    )
    has_uni_routes = "__uniRoutes" in joined or "__uniConfig" in joined
    has_webview = any(marker in joined for marker in ("web-view", "<web-view", "plus.webview", "createWebview", "webviewUrl", "loadURL("))
    if has_uni_config or has_app_service or has_uni_routes:
        return "混合" if has_hybrid or has_webview else "uni-app"
    if appids and has_index:
        return "h5壳"
    if appids:
        return "h5壳"
    return "unknown"


def _should_try_html_deobfuscation(text: str) -> bool:
    if "http://" in text or "https://" in text:
        return False
    indicators = ["document.writeln", "document.write", "_0x", "Function(\"return this\")", "constructor(\"return this\")"]
    return "_0x" in text and len(text) > 2000 or sum(1 for item in indicators if item in text) >= 2


def _node_deobfuscate_html(html: str) -> str:
    script = r"""
const fs = require('fs');
const vm = require('vm');
const html = fs.readFileSync(process.argv[1], 'utf8');
const code = (html.match(/<script[^>]*>([\s\S]*)<\/script>/i) || [, html])[1];
let out = [];
function rec(type, ...args) { out.push(type + "\t" + args.map(v => String(v).slice(0, 4000)).join("\t")); }
const loc = {};
Object.defineProperty(loc, 'href', {set(v) { rec('location.href', v); }, get() { return ''; }});
loc.assign = v => rec('location.assign', v);
loc.replace = v => rec('location.replace', v);
function makeEl(tag) { return {tagName: tag, setAttribute(k, v) { rec('setAttribute', tag, k, v); }, appendChild() {}, addEventListener() {}}; }
const doc = {body: makeEl('body'), head: makeEl('head'), documentElement: makeEl('html'), createElement: makeEl, write: s => rec('document.write', s), writeln: s => rec('document.writeln', s), addEventListener() {}, querySelector: () => makeEl('qs'), querySelectorAll: () => []};
const win = {document: doc, location: loc, navigator: {userAgent: 'Mozilla/5.0 Html5Plus'}, screen: {width: 390, height: 844}, addEventListener() {}, open: u => rec('window.open', u)};
win.window = win; win.self = win; win.top = win; win.parent = win;
const plus = {webview: {create: u => { rec('plus.webview.create', u); return {loadURL: u => rec('webview.loadURL', u), show() {}, hide() {}}; }}, runtime: {openURL: u => rec('plus.runtime.openURL', u)}, storage: {getItem: () => null, setItem() {}}};
const sandbox = {window: win, self: win, top: win, parent: win, document: doc, navigator: win.navigator, location: loc, plus, screen: win.screen, console: {log() {}, error() {}, warn() {}}, setTimeout: () => 1, setInterval: () => 1, clearTimeout() {}, clearInterval() {}, XMLHttpRequest: function() { return {open: (m, u) => rec('xhr.open', m, u), send() {}, setRequestHeader() {}}; }, fetch: u => { rec('fetch', u); return Promise.reject(new Error('blocked')); }, atob: s => Buffer.from(s, 'base64').toString('binary'), btoa: s => Buffer.from(s, 'binary').toString('base64')};
sandbox.global = sandbox; sandbox.globalThis = sandbox;
try { vm.runInNewContext(code, sandbox, {timeout: 8000}); } catch (e) { rec('VM_ERROR', e && e.message || e); }
process.stdout.write(out.join('\n'));
"""
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".html", delete=False) as html_file:
        html_file.write(html)
        html_path = html_file.name
    try:
        proc = subprocess.run(
            ["node", "-e", script, html_path],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
        return proc.stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""
    finally:
        Path(html_path).unlink(missing_ok=True)
