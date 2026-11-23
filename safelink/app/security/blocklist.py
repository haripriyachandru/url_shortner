"""Malicious-domain blocklist with hot reload.

* Matches the domain itself and every parent domain (blocking ``evil.com`` also
  blocks ``login.evil.com``).
* Re-reads the file when it changes (checked at most every 30 s), so ops can add a
  domain without restarting the service.
* The redirect path re-checks this list on every click, so a domain added today also
  neutralises links that were created last month.
"""
from __future__ import annotations

import logging
import threading
import time
from functools import lru_cache
from pathlib import Path

from app.config import get_settings

log = logging.getLogger(__name__)
_CHECK_INTERVAL = 30.0


class Blocklist:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._domains: frozenset[str] = frozenset()
        self._mtime = 0.0
        self._last_check = 0.0
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        try:
            mtime = self._path.stat().st_mtime
            lines = self._path.read_text(encoding="utf-8").splitlines()
        except OSError:
            log.warning("Blocklist file %s not readable; using empty list", self._path)
            self._domains, self._mtime = frozenset(), 0.0
            return
        self._domains = frozenset(
            line.strip().lower().rstrip(".")
            for line in lines
            if line.strip() and not line.lstrip().startswith("#")
        )
        self._mtime = mtime
        log.info("Loaded %d blocklist entries", len(self._domains))

    def _refresh_if_needed(self) -> None:
        now = time.monotonic()
        if now - self._last_check < _CHECK_INTERVAL:
            return
        with self._lock:
            self._last_check = now
            try:
                if self._path.stat().st_mtime != self._mtime:
                    self._load()
            except OSError:
                pass

    def matches(self, host: str) -> str | None:
        """Return the blocklist entry that matches ``host`` (or a parent), else None."""
        self._refresh_if_needed()
        labels = host.lower().rstrip(".").split(".")
        for i in range(len(labels)):
            candidate = ".".join(labels[i:])
            if candidate in self._domains:
                return candidate
        return None


@lru_cache
def get_blocklist() -> Blocklist:
    return Blocklist(get_settings().blocklist_path)
