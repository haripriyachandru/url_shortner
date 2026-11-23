"""The public hot path: GET /{code}."""
from __future__ import annotations

import html
import re
from urllib.parse import urlsplit

from fastapi import APIRouter, BackgroundTasks, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.security.blocklist import Blocklist, get_blocklist
from app.security.rate_limit import client_ip, redirect_limiter
from app.security.tokens import hash_ip
from app.services import links as service
from app.services.cache import Cache, get_cache

router = APIRouter(tags=["redirect"])
_CODE_RE = re.compile(r"^[A-Za-z0-9_-]{3,32}$")

_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:560px;margin:10vh auto;padding:0 1rem;color:#1b1b1f}}
.card{{border:1px solid #ddd;border-radius:12px;padding:1.5rem}}code{{word-break:break-all;background:#f3f3f5;padding:2px 6px;border-radius:4px}}
a.btn{{display:inline-block;margin-top:1rem;padding:.6rem 1rem;border-radius:8px;background:#b3261e;color:#fff;text-decoration:none}}</style>
</head><body><div class="card">{body}</div></body></html>"""


def _page(status: int, title: str, body: str) -> HTMLResponse:
    # Every dynamic value in `body` must already be html.escape()d by the caller.
    return HTMLResponse(
        _PAGE.format(title=html.escape(title), body=body),
        status_code=status,
        headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"},
    )


def _warning_page(url: str, reasons: list[str], code: str) -> HTMLResponse:
    items = "".join(f"<li>{html.escape(r)}</li>" for r in reasons) or "<li>Flagged as unusual</li>"
    body = (
        "<h2>&#9888; Check this link before you continue</h2>"
        "<p>This short link points to:</p>"
        f"<p><code>{html.escape(url)}</code></p>"
        f"<p>Why we are warning you:</p><ul>{items}</ul>"
        f'<a class="btn" href="/{html.escape(code)}?proceed=1" rel="noopener noreferrer">I understand, continue</a>'
    )
    return _page(200, "Warning", body)


@router.get("/{code}", include_in_schema=False)
def follow_link(
    code: str,
    request: Request,
    background: BackgroundTasks,
    proceed: bool = False,
    db: Session = Depends(get_db),
    cache: Cache = Depends(get_cache),
    blocklist: Blocklist = Depends(get_blocklist),
    _: None = Depends(redirect_limiter),
) -> Response:
    if not _CODE_RE.match(code):
        return _page(404, "Not found", "<h2>Link not found</h2>")

    view = service.get_link_view(db, cache, code)
    if view is None:
        return _page(404, "Not found", "<h2>Link not found</h2>")
    if view.status == "disabled":
        return _page(403, "Disabled", "<h2>This link has been disabled</h2><p>It was removed by its owner or after abuse reports.</p>")
    if view.is_expired():
        return _page(410, "Expired", "<h2>This link has expired</h2>")

    # Re-validate against the CURRENT blocklist: protects links created before a domain was listed.
    host = urlsplit(view.url).hostname or ""
    if blocklist.matches(host):
        return _page(403, "Blocked", "<h2>This destination has been blocked</h2><p>It is on our malicious-domain list.</p>")

    if view.status == "warn" and not proceed:
        return _warning_page(view.url, view.reasons, code)

    background.add_task(
        service.record_click,
        view.id,
        hash_ip(client_ip(request)),
        request.headers.get("user-agent", ""),
        request.headers.get("referer"),
    )
    # 302 (not 301): browsers must not cache it, so analytics, expiry and takedowns keep working.
    return RedirectResponse(
        view.url, status_code=302, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}
    )
