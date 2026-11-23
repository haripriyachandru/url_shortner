# SafeLink: URL Shortener with Abuse Protection

FastAPI + SQLAlchemy + Redis (optional). Backend only, no Docker needed.

## What makes it different: "Trust layer"
Most shorteners just map code -> URL. SafeLink treats every link as untrusted:

| Control | Where | Why it matters |
|---|---|---|
| SSRF / internal-target guard (private IPs, `localhost`, obfuscated IPs like `2130706433`, DNS that resolves to private IPs) | `security/url_validator.py` | Stops the service being used to point people at internal networks / DNS-rebinding tricks |
| Phishing risk score (0-100) with reasons: look-alike (IDN) domains, abused TLDs, keyword stuffing, nested redirects, odd ports | same | Low = redirect, mid = **warning page first**, high = rejected |
| Malicious-domain blocklist, hot-reloaded, **re-checked on every click** | `security/blocklist.py`, `routers/redirect.py` | A domain listed today neutralises links created last month |
| Per-IP rate limiting (create, scan, report, redirect) with spoof-proof `X-Forwarded-For` handling | `security/rate_limit.py` | Prevents bulk link creation and scraping |
| Community takedown: N distinct reporters auto-disable a link (DB-enforced one-report-per-IP) | `services/links.py` | Self-healing moderation |
| Owner tokens (stored hashed, constant-time compare), salted IP hashes, random non-guessable codes, escaped HTML, CSP, 302 not 301 | `security/tokens.py` etc. | Privacy and access control basics |

## Architecture / request flow
```
GET /abc123
  -> rate limit (Redis INCR+EXPIRE, per IP)
  -> cache lookup  link:abc123  (Redis or in-memory)
       hit  -> no DB access
       miss -> 1 indexed query on links.code -> populate cache (TTL capped at expiry)
       unknown code -> negative-cached for 60s (protects DB from scanners)
  -> status / expiry / CURRENT-blocklist checks
  -> suspicious? show warning page : 302 redirect
  -> click saved in a BACKGROUND task (does not slow the redirect)
```

## Interview talking points
* **Caching:** cache-aside, negative caching, TTL never exceeds link expiry, explicit invalidation on delete/takedown. Redis outage = fail open to the DB.
* **Indexing:** unique index on `code` (hot path), composite `(link_id, clicked_at)` for analytics, `expires_at` for purge, unique `(link_id, reporter_hash)` to enforce reports atomically.
* **Scaling path:** stateless app (run N copies) -> Redis shared cache/limits -> Postgres -> click writes go to a queue and are batch-inserted -> read replicas for analytics.
* **Rate limiter trade-off:** fixed window is O(1) but allows 2x bursts at window edges; sliding window / token bucket fix that at more cost.
* **Counter:** `click_count` is incremented with an atomic SQL `UPDATE ... SET n = n + 1`, no read-modify-write race.

## Run locally
```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate      macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # Windows: copy .env.example .env
uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000/docs and try the endpoints.

## Try it (curl)
```bash
curl -X POST localhost:8000/api/links -H "content-type: application/json" \
  -d '{"url":"https://example.com/hello","expires_in_hours":24}'
curl -i localhost:8000/<code>                                  # 302 redirect
curl localhost:8000/api/links/<code>/stats -H "X-Owner-Token: <token>"
curl -X POST localhost:8000/api/scan -H "content-type: application/json" -d '{"url":"http://127.0.0.1/admin"}'
```

## Tests
```bash
pytest -q
```

## Optional: real Redis
Set `REDIS_URL=redis://localhost:6379/0` in `.env`. `/health` shows which cache is active.

## Deploy free (Render)
Build: `pip install -r requirements.txt` | Start: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
Env: `BASE_URL=https://<your-app>.onrender.com`, `SECRET_SALT=<random>`, `TRUSTED_PROXY_COUNT=1`.
Free tier disk is ephemeral, so SQLite data resets on redeploy; use a free Postgres (`DATABASE_URL`) for persistence (add `psycopg[binary]` to requirements).
