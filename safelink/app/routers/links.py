"""JSON API: create/scan links, owner-only stats and deletion, abuse reports."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models import Link
from app.schemas import (
    CreateLinkRequest,
    CreateLinkResponse,
    ReportRequest,
    ReportResponse,
    ScanRequest,
    ScanResponse,
    StatsResponse,
)
from app.security.blocklist import Blocklist, get_blocklist
from app.security.rate_limit import client_ip, create_limiter, report_limiter, scan_limiter
from app.security.tokens import hash_ip, tokens_match
from app.security.url_validator import Assessment, UrlRejected, assess_url, is_suspicious
from app.services import links as service
from app.services.cache import Cache, get_cache

router = APIRouter(prefix="/api", tags=["links"])


def _verdict(assessment: Assessment) -> str:
    return "suspicious" if is_suspicious(assessment, get_settings()) else "safe"


def owned_link(
    code: str,
    x_owner_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Link:
    """Auth dependency: the caller must present the token issued at creation."""
    if not x_owner_token:
        raise HTTPException(401, "Missing X-Owner-Token header")
    link = db.scalar(select(Link).where(Link.code == code))
    if link is None:
        raise HTTPException(404, "Link not found")
    if not tokens_match(x_owner_token, link.owner_token_hash):
        raise HTTPException(403, "Invalid owner token")
    return link


@router.post("/scan", response_model=ScanResponse, dependencies=[Depends(scan_limiter)])
def scan_url(payload: ScanRequest, blocklist: Blocklist = Depends(get_blocklist)) -> ScanResponse:
    """Risk-check a URL without creating anything."""
    try:
        result = assess_url(payload.url, settings=get_settings(), blocklist=blocklist)
    except UrlRejected as exc:
        return ScanResponse(verdict="blocked", risk_score=100, reasons=[str(exc)])
    return ScanResponse(
        verdict=_verdict(result),  # type: ignore[arg-type]
        risk_score=result.score,
        reasons=result.reasons,
        normalized_url=result.url,
    )


@router.post(
    "/links",
    response_model=CreateLinkResponse,
    status_code=201,
    dependencies=[Depends(create_limiter)],
)
def create_short_link(
    payload: CreateLinkRequest,
    db: Session = Depends(get_db),
    cache: Cache = Depends(get_cache),
    blocklist: Blocklist = Depends(get_blocklist),
) -> CreateLinkResponse:
    settings = get_settings()
    try:
        assessment = assess_url(payload.url, settings=settings, blocklist=blocklist)
    except UrlRejected as exc:
        raise HTTPException(422, str(exc)) from None
    try:
        link, token = service.create_link(
            db,
            cache,
            assessment=assessment,
            expires_in_hours=payload.expires_in_hours,
            alias=payload.custom_alias,
        )
    except service.AliasUnavailableError as exc:
        raise HTTPException(409, str(exc)) from None
    except service.CodeGenerationError:
        raise HTTPException(503, "Could not allocate a short code, please retry") from None

    return CreateLinkResponse(
        code=link.code,
        short_url=f"{settings.base_url}/{link.code}",
        target_url=link.target_url,
        expires_at=link.expires_at,
        verdict=_verdict(assessment),  # type: ignore[arg-type]
        risk_score=assessment.score,
        risk_reasons=assessment.reasons,
        owner_token=token,
    )


@router.get("/links/{code}/stats", response_model=StatsResponse)
def link_stats(link: Link = Depends(owned_link), db: Session = Depends(get_db)) -> dict:
    return service.build_stats(db, link)


@router.delete("/links/{code}", status_code=204)
def delete_link(
    link: Link = Depends(owned_link),
    db: Session = Depends(get_db),
    cache: Cache = Depends(get_cache),
) -> None:
    service.disable_link(db, cache, link)


@router.post(
    "/links/{code}/report",
    response_model=ReportResponse,
    dependencies=[Depends(report_limiter)],
)
def report_link(
    code: str,
    payload: ReportRequest,
    request: Request,
    db: Session = Depends(get_db),
    cache: Cache = Depends(get_cache),
) -> ReportResponse:
    link = db.scalar(select(Link).where(Link.code == code))
    if link is None:
        raise HTTPException(404, "Link not found")
    total, disabled = service.add_report(db, cache, link, hash_ip(client_ip(request)), payload.reason)
    return ReportResponse(message="Thanks, report received.", total_reports=total, link_disabled=disabled)
