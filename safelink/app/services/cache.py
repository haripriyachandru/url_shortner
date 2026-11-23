"""Cache + counter backends.

Redis is used when REDIS_URL is set and reachable; otherwise an in-process fallback
keeps the project runnable with zero installs. Both expose the same tiny interface.

Failure policy (a good design talking point): if Redis dies at runtime we FAIL OPEN.
Cache misses fall through to the database and rate limiting is skipped, because a
cache outage should degrade performance, not take the whole service down.
"""
from __future__ import annotations

import logging
import math
import threading
import time
from functools import lru_cache
from typing import Protocol

import redis

from app.config import get_settings

log = logging.getLogger(__name__)


class Cache(Protocol):
    kind: str

    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str, ttl: int) -> None: ...
    def delete(self, key: str) -> None: ...
    def hit(self, key: str, window: int) -> tuple[int, int]:
        """Count one event in a fixed window. Returns (count_in_window, seconds_left)."""
        ...


class MemoryCache:
    kind = "memory"
    _MAX_ENTRIES = 50_000

    def __init__(self) -> None:
        self._store: dict[str, tuple[str, float]] = {}
        self._counters: dict[str, tuple[int, float]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _make_room(table: dict, limit: int) -> None:
        if len(table) < limit:
            return
        now = time.monotonic()
        for key in [k for k, v in table.items() if v[1] <= now]:
            del table[key]
        if len(table) >= limit:  # still full: drop the oldest half
            for key in list(table)[: len(table) // 2]:
                del table[key]

    def get(self, key: str) -> str | None:
        with self._lock:
            item = self._store.get(key)
            if item is None:
                return None
            value, expires = item
            if expires <= time.monotonic():
                del self._store[key]
                return None
            return value

    def set(self, key: str, value: str, ttl: int) -> None:
        with self._lock:
            self._make_room(self._store, self._MAX_ENTRIES)
            self._store[key] = (value, time.monotonic() + ttl)

    def delete(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)

    def hit(self, key: str, window: int) -> tuple[int, int]:
        now = time.monotonic()
        with self._lock:
            count, expires = self._counters.get(key, (0, 0.0))
            if expires <= now:
                self._make_room(self._counters, self._MAX_ENTRIES)
                count, expires = 0, now + window
            count += 1
            self._counters[key] = (count, expires)
            return count, max(1, math.ceil(expires - now))


class RedisCache:
    kind = "redis"

    def __init__(self, url: str) -> None:
        self._client = redis.Redis.from_url(
            url, decode_responses=True, socket_connect_timeout=1, socket_timeout=1
        )

    def ping(self) -> None:
        self._client.ping()

    def get(self, key: str) -> str | None:
        try:
            return self._client.get(key)
        except redis.RedisError:
            log.warning("Redis GET failed; falling back to the database")
            return None

    def set(self, key: str, value: str, ttl: int) -> None:
        try:
            self._client.setex(key, ttl, value)
        except redis.RedisError:
            log.warning("Redis SET failed")

    def delete(self, key: str) -> None:
        try:
            self._client.delete(key)
        except redis.RedisError:
            log.warning("Redis DEL failed")

    def hit(self, key: str, window: int) -> tuple[int, int]:
        try:
            pipe = self._client.pipeline()
            pipe.incr(key)
            pipe.ttl(key)
            count, ttl = pipe.execute()
            if ttl < 0:  # first hit in this window (or key lost its TTL)
                self._client.expire(key, window)
                ttl = window
            return int(count), int(ttl)
        except redis.RedisError:
            log.warning("Redis unavailable; rate limiting is failing open")
            return 0, 0


@lru_cache
def get_cache() -> Cache:
    url = get_settings().redis_url
    if url:
        try:
            cache = RedisCache(url)
            cache.ping()
            log.info("Using Redis cache")
            return cache
        except (redis.RedisError, ValueError) as exc:
            log.warning("Redis unreachable (%s); using in-memory cache instead", exc)
    else:
        log.info("REDIS_URL not set; using in-memory cache")
    return MemoryCache()
