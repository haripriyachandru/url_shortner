"""URL safety analysis: the heart of the "abuse protection" feature.

``assess_url`` does two kinds of checks:

1. HARD REJECTS (raise ``UrlRejected``): things that are never legitimate for a public
   shortener: non-http(s) schemes, credentials in the URL, private/internal targets
   (SSRF-style abuse), obfuscated IPs, blocklisted domains, links to ourselves.
2. RISK SCORING (0-100): soft signals that are common in phishing. Low scores pass,
   mid scores are allowed but show a warning page before redirecting, high scores are
   rejected.

Nothing here fetches the target page, so the service is not itself exploitable as a
request proxy.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import SplitResult, urlsplit, urlunsplit

from app.config import Settings
from app.security.blocklist import Blocklist

MAX_URL_LENGTH = 2048

SUSPICIOUS_TLDS = frozenset(
    {"zip", "mov", "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "country", "work"}
)
KNOWN_SHORTENERS = frozenset(
    {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "rebrand.ly", "cutt.ly"}
)
PHISHING_KEYWORDS = frozenset(
    {"login", "signin", "verify", "secure", "account", "update", "wallet",
     "password", "billing", "support", "confirm", "banking"}
)
INTERNAL_SUFFIXES = (".local", ".internal", ".localhost", ".lan", ".home", ".corp")

_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f]")
_EMBEDDED_URL = re.compile(r"https?(?:://|%3a%2f%2f)", re.IGNORECASE)
# Numeric-looking hosts such as 2130706433, 0x7f.1 or 017.0.0.1 (IP obfuscation tricks)
_NUMERIC_HOST = re.compile(r"(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+))*", re.IGNORECASE)


class UrlRejected(ValueError):
    """The URL must not be shortened. The message is safe to show to the user."""


@dataclass(frozen=True)
class Assessment:
    url: str  # normalised URL that will be stored
    score: int
    reasons: list[str] = field(default_factory=list)


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _resolve_all(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return [ipaddress.ip_address(info[4][0].split("%")[0]) for info in infos]


def _rebuild(parts: SplitResult, ascii_host: str, port: int | None) -> str:
    host = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
    netloc = f"{host}:{port}" if port else host
    return urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment))


def assess_url(raw: str, *, settings: Settings, blocklist: Blocklist) -> Assessment:
    url = raw.strip()
    if not url:
        raise UrlRejected("URL is empty")
    if len(url) > MAX_URL_LENGTH:
        raise UrlRejected(f"URL is longer than {MAX_URL_LENGTH} characters")
    # Whitespace/control chars enable header injection (CRLF) and parser confusion.
    if _CONTROL_OR_SPACE.search(url):
        raise UrlRejected("URL contains spaces or control characters")

    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise UrlRejected("URL is malformed") from None

    if parts.scheme.lower() not in {"http", "https"}:
        raise UrlRejected("Only http:// and https:// URLs are allowed")
    if parts.username is not None or parts.password is not None:
        # https://paypal.com@evil.com is a classic phishing trick.
        raise UrlRejected("URLs containing a username or password are not allowed")

    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise UrlRejected("URL has no hostname")

    score = 0
    reasons: list[str] = []

    def flag(points: int, reason: str) -> None:
        nonlocal score
        score += points
        reasons.append(reason)

    ip = _parse_ip(host)
    if ip is not None:
        if not ip.is_global:
            raise UrlRejected("URLs pointing to private or internal addresses are not allowed")
        flag(30, "Link points to a raw IP address instead of a domain name")
        ascii_host = host
    else:
        if _NUMERIC_HOST.fullmatch(host):
            raise UrlRejected("Obfuscated IP address hostnames are not allowed")
        if "." not in host or host.endswith(INTERNAL_SUFFIXES):
            raise UrlRejected("URLs pointing to private or internal hosts are not allowed")
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise UrlRejected("Hostname is not valid") from None
        if ascii_host != host or any(l.startswith("xn--") for l in ascii_host.split(".")):
            flag(25, "Internationalised domain name (possible look-alike/homograph attack)")

    # --- policy checks -----------------------------------------------------------
    matched = blocklist.matches(ascii_host)
    if matched:
        raise UrlRejected(f"Domain is on the malicious-domain blocklist ({matched})")

    own_host = urlsplit(settings.base_url).hostname
    if own_host and ascii_host == own_host.lower():
        raise UrlRejected("Cannot shorten links that point to this service (redirect loops)")

    # --- DNS check: block hostnames that RESOLVE to internal addresses -------------
    if settings.resolve_dns and ip is None:
        try:
            addresses = _resolve_all(ascii_host)
        except (socket.gaierror, UnicodeError):
            raise UrlRejected("Domain does not resolve") from None
        if any(not a.is_global for a in addresses):
            raise UrlRejected("Domain resolves to a private or internal address")

    # --- risk scoring --------------------------------------------------------------
    labels = ascii_host.split(".")
    tld = labels[-1]
    if ip is None:
        if tld in SUSPICIOUS_TLDS:
            flag(20, f"Top-level domain .{tld} is frequently abused")
        if len(labels) > 4:
            flag(15, "Unusually deep subdomain nesting")
        if ascii_host.count("-") >= 3:
            flag(10, "Many hyphens in the domain name")
        keywords = sorted(k for k in PHISHING_KEYWORDS if k in ascii_host)
        if len(keywords) >= 2:
            flag(25, f"Domain contains several phishing-style words ({', '.join(keywords)})")
        elif keywords:
            flag(10, f"Domain contains a phishing-style word ({keywords[0]})")
        if any(ascii_host == s or ascii_host.endswith("." + s) for s in KNOWN_SHORTENERS):
            flag(25, "Target is another URL shortener (hides the real destination)")

    if port not in (None, 80, 443):
        flag(15, f"Non-standard port {port}")
    rest = f"{parts.path}?{parts.query}"
    if _EMBEDDED_URL.search(rest):
        flag(15, "URL contains another URL (open-redirect pattern)")
    if "%25" in rest:
        flag(10, "Double-encoded characters")
    if len(url) > 500:
        flag(5, "Very long URL")

    score = min(score, 100)
    if score >= settings.block_score:
        raise UrlRejected(
            f"URL looks malicious (risk score {score}/100): " + "; ".join(reasons)
        )
    return Assessment(url=_rebuild(parts, ascii_host, port), score=score, reasons=reasons)


def is_suspicious(assessment: Assessment, settings: Settings) -> bool:
    return assessment.score >= settings.warn_score
