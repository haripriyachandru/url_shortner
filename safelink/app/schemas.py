"""Pydantic request/response models (the public API contract)."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Verdict = Literal["safe", "suspicious", "blocked"]


class CreateLinkRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048, examples=["https://example.com/docs"])
    expires_in_hours: int | None = Field(default=None, ge=1, le=24 * 365)
    custom_alias: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{3,32}$")


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class ScanResponse(BaseModel):
    verdict: Verdict
    risk_score: int
    reasons: list[str]
    normalized_url: str | None = None


class CreateLinkResponse(BaseModel):
    code: str
    short_url: str
    target_url: str
    expires_at: datetime | None
    verdict: Verdict
    risk_score: int
    risk_reasons: list[str]
    owner_token: str = Field(description="Shown once. Needed for stats and deletion.")


class DailyClicks(BaseModel):
    day: str
    clicks: int


class ReferrerCount(BaseModel):
    referrer: str
    clicks: int


class StatsResponse(BaseModel):
    code: str
    target_url: str
    status: str
    created_at: datetime
    expires_at: datetime | None
    total_clicks: int
    unique_visitors: int
    clicks_per_day: list[DailyClicks]
    top_referrers: list[ReferrerCount]


class ReportRequest(BaseModel):
    reason: Literal["phishing", "malware", "spam", "other"] = "other"


class ReportResponse(BaseModel):
    message: str
    total_reports: int
    link_disabled: bool
