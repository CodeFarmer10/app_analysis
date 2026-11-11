"""Shared HTTPS URL projection for controller evidence and operation details."""

from typing import Any, Iterable

from analyzers.ecapture_parser import is_https_transaction


def collect_https_urls(*sources: Iterable[dict[str, Any]] | None) -> list[str]:
    urls: dict[str, None] = {}
    for source in sources:
        if not isinstance(source, (list, tuple)):
            continue
        for event in source:
            if not isinstance(event, dict):
                continue
            url = str(event.get("url") or "").strip()
            if is_https_transaction(url):
                urls.setdefault(url, None)
    return list(urls)
