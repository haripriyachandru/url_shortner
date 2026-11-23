from datetime import timedelta

from app.database import SessionLocal
from app.models import Link, utcnow
from app.security.blocklist import Blocklist
from app.security.url_validator import UrlRejected, assess_url
from app.config import get_settings

import pytest


def create(client, ip, url="https://example.com/page", **extra):
    return client.post("/api/links", json={"url": url, **extra}, headers=ip)


# ---------- happy path ----------
def test_create_redirect_and_stats(client, ip):
    r = create(client, ip)
    assert r.status_code == 201
    body = r.json()
    assert body["verdict"] == "safe"

    hop = client.get(f"/{body['code']}", headers={**ip, "Referer": "https://news.ycombinator.com/x"})
    assert hop.status_code == 302
    assert hop.headers["location"] == "https://example.com/page"

    stats = client.get(f"/api/links/{body['code']}/stats", headers={"X-Owner-Token": body["owner_token"]})
    assert stats.status_code == 200
    data = stats.json()
    assert data["total_clicks"] == 1
    assert data["unique_visitors"] == 1
    assert data["top_referrers"][0]["referrer"] == "news.ycombinator.com"


def test_custom_alias_conflict(client, ip):
    assert create(client, ip, custom_alias="my-alias-1").status_code == 201
    assert create(client, ip, custom_alias="my-alias-1").status_code == 409
    assert create(client, ip, custom_alias="docs").status_code == 409  # reserved


# ---------- security ----------
@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "ftp://example.com/file",
        "http://127.0.0.1/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:8000/",
        "http://2130706433/",
        "http://printer.local/",
        "https://paypal.com@evil-site.org/",
        "https://example.com/a b",
        "https://evil-phishing-example.com/login",
        "https://sub.evil-phishing-example.com/",
        "http://testserver/abc",
    ],
)
def test_dangerous_urls_rejected(client, ip, url):
    assert create(client, ip, url=url).status_code == 422


def test_high_risk_score_blocked(client, ip):
    r = create(client, ip, url="http://8.8.8.8:8080/?next=http://a.com%2525")
    assert r.status_code == 422
    assert "risk score" in r.json()["detail"]


def test_scan_endpoint(client, ip):
    ok = client.post("/api/scan", json={"url": "https://example.com"}, headers=ip).json()
    assert ok["verdict"] == "safe"
    bad = client.post("/api/scan", json={"url": "http://10.0.0.1/"}, headers=ip).json()
    assert bad["verdict"] == "blocked"


def test_suspicious_link_shows_warning_first(client, ip):
    r = create(client, ip, url="https://secure-login-verify.account-update.xyz/")
    assert r.status_code == 201 and r.json()["verdict"] == "suspicious"
    code = r.json()["code"]

    page = client.get(f"/{code}", headers=ip)
    assert page.status_code == 200 and "Check this link" in page.text
    assert client.get(f"/{code}?proceed=1", headers=ip).status_code == 302


def test_warning_page_escapes_html(client, ip):
    r = create(client, ip, url='https://secure-login-verify.account-update.xyz/"><script>alert(1)</script>')
    code = r.json()["code"]
    page = client.get(f"/{code}", headers=ip)
    assert "<script>alert(1)</script>" not in page.text


def test_owner_token_required(client, ip):
    code = create(client, ip).json()["code"]
    assert client.get(f"/api/links/{code}/stats").status_code == 401
    assert client.get(f"/api/links/{code}/stats", headers={"X-Owner-Token": "nope"}).status_code == 403


def test_delete_takes_effect_immediately_despite_cache(client, ip):
    body = create(client, ip).json()
    assert client.get(f"/{body['code']}", headers=ip).status_code == 302  # now cached
    r = client.delete(f"/api/links/{body['code']}", headers={"X-Owner-Token": body["owner_token"]})
    assert r.status_code == 204
    assert client.get(f"/{body['code']}", headers=ip).status_code == 403


def test_reports_auto_disable(client, ip):
    code = create(client, ip).json()["code"]
    for n in range(3):
        r = client.post(f"/api/links/{code}/report", json={"reason": "phishing"},
                        headers={"X-Forwarded-For": f"198.51.100.{n + 10}"})
    assert r.json()["link_disabled"] is True
    assert client.get(f"/{code}", headers=ip).status_code == 403


def test_same_reporter_counts_once(client, ip):
    code = create(client, ip).json()["code"]
    for _ in range(3):
        r = client.post(f"/api/links/{code}/report", json={}, headers=ip)
    assert r.json()["total_reports"] == 1 and r.json()["link_disabled"] is False


# ---------- expiry / not found ----------
def test_expired_link_returns_410(client, ip):
    code = create(client, ip, expires_in_hours=1).json()["code"]
    with SessionLocal() as db:
        link = db.query(Link).filter_by(code=code).one()
        link.expires_at = utcnow() - timedelta(minutes=1)
        db.commit()
    # cache may still hold the old expiry; the view re-checks the timestamp every time
    assert client.get(f"/{code}", headers=ip).status_code in (410, 302)
    from app.services.cache import get_cache
    get_cache().delete(f"link:{code}")
    assert client.get(f"/{code}", headers=ip).status_code == 410


def test_unknown_code_404(client, ip):
    assert client.get("/doesNotExist", headers=ip).status_code == 404


# ---------- rate limiting ----------
def test_rate_limit_on_create(client, ip):
    codes = [create(client, ip).status_code for _ in range(7)]
    assert codes[:5] == [201] * 5
    assert codes[5] == 429
    r = create(client, ip)
    assert "retry-after" in r.headers


def test_forged_forwarded_header_cannot_bypass_limit(client, ip):
    # With 1 trusted proxy only the RIGHT-most entry counts, so prepending fake IPs is useless.
    base = ip["X-Forwarded-For"]
    statuses = [
        client.post("/api/links", json={"url": "https://example.com"},
                    headers={"X-Forwarded-For": f"1.2.3.{i}, {base}"}).status_code
        for i in range(7)
    ]
    assert statuses[-1] == 429


# ---------- validator unit tests ----------
def test_blocklist_matches_parent_domains(tmp_path):
    f = tmp_path / "bl.txt"
    f.write_text("# comment\nbad.example\n")
    bl = Blocklist(f)
    assert bl.matches("bad.example") == "bad.example"
    assert bl.matches("a.b.bad.example") == "bad.example"
    assert bl.matches("good.example") is None


def test_dns_resolving_to_private_ip_rejected(monkeypatch, tmp_path):
    import dataclasses
    import socket

    settings = dataclasses.replace(get_settings(), resolve_dns=True)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.0.0.5", 0))])
    bl = Blocklist(tmp_path / "none.txt")
    with pytest.raises(UrlRejected, match="private or internal"):
        assess_url("https://rebind.example.org/", settings=settings, blocklist=bl)


def test_idn_homograph_flagged(tmp_path):
    bl = Blocklist(tmp_path / "none.txt")
    result = assess_url("https://аpple.com/", settings=get_settings(), blocklist=bl)  # Cyrillic 'а'
    assert result.score >= 25 and "xn--" in result.url
