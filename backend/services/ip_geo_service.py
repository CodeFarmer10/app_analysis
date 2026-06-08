from __future__ import annotations

import ipaddress
import logging
from functools import lru_cache
from pathlib import Path
from threading import Lock
from typing import Any

try:
    from geoip2 import database as geoip2_database
    from geoip2.errors import AddressNotFoundError
except ImportError:  # pragma: no cover - depends on runtime environment
    geoip2_database = None

    class AddressNotFoundError(Exception):
        """Fallback exception when geoip2 is unavailable."""


logger = logging.getLogger(__name__)

_MMDB_PATH = Path(__file__).resolve().parents[1] / "tools" / "GeoLite2-Country.mmdb"
_READER_LOCK = Lock()
_READER = None
_READER_READY = False


def is_local_ip(value: Any) -> bool:
    """判断 IP 是否属于本机/内网/保留地址。"""
    text = str(value or "").strip()
    if not text:
        return False
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return False
    return (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_reserved
        or parsed.is_multicast
        or parsed.is_unspecified
    )


def is_uplink_flow(src_ip: Any, dst_ip: Any) -> bool:
    """判断一条流量是否属于上行流量。"""
    src_text = str(src_ip or "").strip()
    dst_text = str(dst_ip or "").strip()
    if not src_text or not dst_text:
        return False

    src_local = is_local_ip(src_text)
    dst_local = is_local_ip(dst_text)
    if src_local and not dst_local:
        return True
    if src_local and dst_local:
        return True
    return False


def pick_non_local_ip(src_ip: Any, dst_ip: Any) -> str | None:
    """从一条流量中选出需要查询归属地的非本机 IP。"""
    src_text = str(src_ip or "").strip()
    dst_text = str(dst_ip or "").strip()
    if not src_text and not dst_text:
        return None
    if is_local_ip(src_text) and not is_local_ip(dst_text):
        return dst_text or None
    if is_local_ip(dst_text) and not is_local_ip(src_text):
        return src_text or None
    if not is_local_ip(dst_text):
        return dst_text or None
    if not is_local_ip(src_text):
        return src_text or None
    return None


def _get_reader():
    global _READER, _READER_READY
    if _READER_READY:
        return _READER

    with _READER_LOCK:
        if _READER_READY:
            return _READER

        _READER_READY = True
        if geoip2_database is None:
            logger.warning("geoip2 is not installed; IP country lookup disabled")
            return None
        if not _MMDB_PATH.exists():
            logger.warning("GeoLite2 database not found: %s", _MMDB_PATH)
            return None
        try:
            _READER = geoip2_database.Reader(str(_MMDB_PATH))
        except Exception as exc:  # pragma: no cover - depends on runtime environment
            logger.warning("open GeoLite2 database failed path=%s err=%s", _MMDB_PATH, exc)
            _READER = None
        return _READER


@lru_cache(maxsize=4096)
def lookup_ip_country(ip_value: Any) -> str | None:
    """查询单个公网 IP 的国家名称。"""
    ip_text = str(ip_value or "").strip()
    if not ip_text or is_local_ip(ip_text):
        return None

    reader = _get_reader()
    if reader is None:
        return None

    try:
        response = reader.country(ip_text)
    except AddressNotFoundError:
        return None
    except ValueError:
        return None
    except Exception as exc:  # pragma: no cover - depends on runtime environment
        logger.warning("lookup IP country failed ip=%s err=%s", ip_text, exc)
        return None

    country = (
        response.country.names.get("zh-CN")
        or response.country.name
        or response.country.iso_code
    )
    if not country:
        return None
    country_text = str(country).strip()
    return country_text[:128] if country_text else None


def resolve_non_local_ip_country(src_ip: Any, dst_ip: Any) -> str | None:
    """解析一条流量中非本机 IP 的归属地国家。"""
    target_ip = pick_non_local_ip(src_ip, dst_ip)
    if not target_ip:
        return None
    return lookup_ip_country(target_ip)
