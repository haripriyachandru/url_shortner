"""Business logic for links: creation, cached lookup, analytics, reports, cleanup."""
from __future__ import annotations

import json
import logging
import secrets
import string
import time
from dataclasses import asdict, dataclass
from datetime import timedelta
from urllib.parse import urlsplit

from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import SessionLocal
from app.models import Click, Link, Report, utcnow
from app.security.tokens import hash_token, new_owner_token
from app.security.url_validator import Assessment, is_suspicious
from app.services.cache import Cache

log = logging.getLogger(__name__)

RESERVED_CODES = frozenset({"api", "docs", "redoc", "openapi", "health", "static", "admin", "favicon"})
_ALPHABET = string.ascii_letters + string.digits  # base62
_MISSING = "__missing__"  # negative-cache marker
_MAX_CODE_ATTEMPTS = 5
PURGE_AFTER_DAYS = 7  # keep expired links this long so users see "expired", not "not found"


class AliasUnavailableError(Exception):
    pass


class CodeGenerationError(Exception):
    pass


@dataclass(frozen=True)
class LinkView:
    """The small, cacheable slice of a link needed on the redirect hot path."""

    id: int
    url: str
    status: str
    expires_at: float | None  # unix timestamp
    score: int
    reasons: list[str]

    def is_expired(self) -> bool:
        return self.expires_at is not None and self.expires_at <= time.time()


def _cache_key(code: str) -> str:
    return f"link:{code}"


def generate_code(length: int) -> str:
    """Random (not sequential) codes cannot be enumerated or guessed by scrapers."""
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def create_link(
    db: Session,
    cache: Cache,
    *,
    assessment: Assessment,
    expires_in_hours: int | None,
    alias: str | None,
) -> tuple[Link, str]:
    settings = get_settings()
    if alias and alias.lower() in RESERVED_CODES:
        raise AliasUnavailableError("That alias is reserved")

    token = new_owner_token()
    expires_at = utcnow() + timedelta(hours=expires_in_hours) if expires_in_hours else None
    status = "warn" if is_suspicious(assessment, settings) else "active"

    for _ in range(1 if alias else _MAX_CODE_ATTEMPTS):
        link = Link(
            code=alias or generate_code(settings.code_length),
            target_url=assessment.url,
            status=status,
            risk_score=assessment.score,
            risk_reasons=json.dumps(assessment.reasons),
            owner_token_hash=hash_token(token),
            expires_at=expires_at,
        )
        db.add(link)
        try:
            db.commit()
        except IntegrityError:  # unique(code) violated -> collision
            db.rollback()
            if alias:
                raise AliasUnavailableError("That alias is already taken") from None
            continue
        cache.delete(_cache_key(link.code))  # clear any negative-cache entry
        return link, token
    raise CodeGenerationError("Could not allocate a unique code")


def _to_view(link: Link) -> LinkView:
    return LinkView(
        id=link.id,
        url=link.target_url,
        status=link.status,
        expires_at=link.expires_at.timestamp() if link.expires_at else None,
        score=link.risk_score,
        reasons=json.loads(link.risk_reasons),
    )


def _ttl_for(view: LinkView) -> int:
    ttl = get_settings().cache_ttl_seconds
    if view.expires_at is not None:  # never cache past the expiry moment
        ttl = min(ttl, int(view.expires_at - time.time()))
    return max(ttl, 1)


def get_link_view(db: Session, cache: Cache, code: str) -> LinkView | None:
    """Cache-aside lookup with negative caching.

    hit -> Redis/memory only, no DB. miss -> one indexed DB query, then populate.
    Unknown codes are cached briefly too, so scanners probing random codes cannot
    hammer the database.
    """
    key = _cache_key(code)
    cached = cache.get(key)
    if cached == _MISSING:
        return None
    if cached:
        return LinkView(**json.loads(cached))

    link = db.scalar(select(Link).where(Link.code == code))
    if link is None:
        cache.set(key, _MISSING, get_settings().negative_cache_ttl_seconds)
        return None
    view = _to_view(link)
    cache.set(key, json.dumps(asdict(view)), _ttl_for(view))
    return view


def disable_link(db: Session, cache: Cache, link: Link) -> None:
    link.status = "disabled"
    db.commit()
    cache.delete(_cache_key(link.code))  # invalidate so the takedown is immediate


def record_click(link_id: int, ip_hash: str, user_agent: str, referrer: str | None) -> None:
    """Runs as a background task AFTER the redirect response is sent."""
    host = (urlsplit(referrer).hostname if referrer else None) or "direct"
    try:
        with SessionLocal() as db:
            db.add(Click(link_id=link_id, ip_hash=ip_hash, user_agent=user_agent[:256], referrer=host[:255]))
            # Atomic SQL increment: safe under concurrent clicks (no read-modify-write).
            db.execute(update(Link).where(Link.id == link_id).values(click_count=Link.click_count + 1))
            db.commit()
    except Exception:  # analytics must never break redirects
        log.exception("Failed to record click for link %s", link_id)


def build_stats(db: Session, link: Link) -> dict:
    unique = db.scalar(
        select(func.count(func.distinct(Click.ip_hash))).where(Click.link_id == link.id)
    )
    day = func.date(Click.clicked_at)
    per_day = db.execute(
        select(day.label("day"), func.count().label("clicks"))
        .where(Click.link_id == link.id)
        .group_by(day)
        .order_by(day.desc())
        .limit(30)
    ).all()
    referrers = db.execute(
        select(Click.referrer, func.count().label("clicks"))
        .where(Click.link_id == link.id)
        .group_by(Click.referrer)
        .order_by(func.count().desc())
        .limit(5)
    ).all()
    return {
        "code": link.code,
        "target_url": link.target_url,
        "status": link.status,
        "created_at": link.created_at,
        "expires_at": link.expires_at,
        "total_clicks": link.click_count,
        "unique_visitors": unique or 0,
        "clicks_per_day": [{"day": str(d), "clicks": c} for d, c in reversed(per_day)],
        "top_referrers": [{"referrer": r, "clicks": c} for r, c in referrers],
    }


def add_report(db: Session, cache: Cache, link: Link, reporter_hash: str, reason: str) -> tuple[int, bool]:
    """Community moderation: N distinct reporters auto-disable a link."""
    db.add(Report(link_id=link.id, reporter_hash=reporter_hash, reason=reason))
    try:
        db.commit()
    except IntegrityError:  # same reporter again: counted once (DB-enforced)
        db.rollback()
    total = db.scalar(select(func.count()).select_from(Report).where(Report.link_id == link.id)) or 0
    disabled = link.status == "disabled"
    if total >= get_settings().report_threshold and not disabled:
        disable_link(db, cache, link)
        disabled = True
        log.warning("Link %s auto-disabled after %d reports", link.code, total)
    return total, disabled


def purge_expired(db: Session) -> int:
    """Delete links (and their clicks/reports) that expired more than a week ago."""
    cutoff = utcnow() - timedelta(days=PURGE_AFTER_DAYS)
    stale = select(Link.id).where(Link.expires_at.is_not(None), Link.expires_at < cutoff)
    db.execute(delete(Click).where(Click.link_id.in_(stale)))
    db.execute(delete(Report).where(Report.link_id.in_(stale)))
    result = db.execute(delete(Link).where(Link.id.in_(stale)))
    db.commit()
    return result.rowcount or 0
