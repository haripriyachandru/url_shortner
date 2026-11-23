"""ORM models.

Indexing decisions (a good interview talking point):
  * links.code            UNIQUE index  -> the hot path: every redirect looks up by code.
  * links.expires_at      index         -> the periodic purge job scans by expiry.
  * clicks (link_id, clicked_at) composite index -> analytics always filter by link and
    group by time, so one index serves both the WHERE and the ORDER/GROUP BY.
  * reports (link_id, reporter_hash) UNIQUE -> one report per person per link, enforced
    by the database rather than by application code (no race conditions).
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    """Store UTC, always return timezone-aware datetimes (SQLite drops tzinfo)."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime not allowed; use timezone-aware UTC")
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect):
        return value.replace(tzinfo=timezone.utc) if value else None


class Link(Base):
    __tablename__ = "links"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    target_url: Mapped[str] = mapped_column(String(2048))
    # active -> redirect | warn -> interstitial first | disabled -> taken down
    status: Mapped[str] = mapped_column(String(16), default="active")
    risk_score: Mapped[int] = mapped_column(default=0)
    risk_reasons: Mapped[str] = mapped_column(Text, default="[]")  # JSON list
    owner_token_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime, nullable=True, index=True
    )
    click_count: Mapped[int] = mapped_column(default=0)  # denormalised counter


class Click(Base):
    __tablename__ = "clicks"
    __table_args__ = (Index("ix_clicks_link_time", "link_id", "clicked_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    link_id: Mapped[int] = mapped_column(ForeignKey("links.id"))
    clicked_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    ip_hash: Mapped[str] = mapped_column(String(64))  # salted hash, never the raw IP
    user_agent: Mapped[str] = mapped_column(String(256), default="")
    referrer: Mapped[str] = mapped_column(String(255), default="direct")  # host only


class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (UniqueConstraint("link_id", "reporter_hash", name="uq_report"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    link_id: Mapped[int] = mapped_column(ForeignKey("links.id"))
    reporter_hash: Mapped[str] = mapped_column(String(64))
    reason: Mapped[str] = mapped_column(String(16), default="other")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
