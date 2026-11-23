"""Per-IP fixed-window rate limiting as FastAPI dependencies.

Fixed window = one counter per (scope, IP) that expires after the window. It is O(1)
and trivially works in Redis (INCR + EXPIRE). Trade-off: a client can burst up to 2x the
limit across a window boundary; a sliding-window or token-bucket removes that at the
cost of more state.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request

from app.config import get_settings
from app.services.cache import Cache, get_cache


def client_ip(request: Request) -> str:
    """Best-effort real client IP.

    X-Forwarded-For is attacker-controlled unless it was appended by a proxy WE run.
    Each proxy appends the address it saw on the right, so with N trusted proxies the
    client is the N-th entry from the right. With N=0 the header is ignored entirely.
    """
    trusted = get_settings().trusted_proxy_count
    if trusted > 0:
        hops = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]
        if len(hops) >= trusted:
            return hops[-trusted]
    return request.client.host if request.client else "unknown"


class RateLimiter:
    def __init__(self, scope: str, limit: int, window: int) -> None:
        self.scope, self.limit, self.window = scope, limit, window

    def __call__(self, request: Request, cache: Cache = Depends(get_cache)) -> None:
        count, ttl = cache.hit(f"rl:{self.scope}:{client_ip(request)}", self.window)
        if count > self.limit:
            raise HTTPException(
                status_code=429,
                detail="Too many requests. Please slow down.",
                headers={"Retry-After": str(ttl), "X-RateLimit-Limit": str(self.limit)},
            )


_s = get_settings()
create_limiter = RateLimiter("create", _s.create_rate_limit, _s.create_rate_window)
scan_limiter = RateLimiter("scan", _s.create_rate_limit, _s.create_rate_window)
report_limiter = RateLimiter("report", _s.create_rate_limit, _s.create_rate_window)
redirect_limiter = RateLimiter("redirect", _s.redirect_rate_limit, _s.redirect_rate_window)
