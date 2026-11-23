"""Test setup: env vars MUST be set before the app is imported."""
import itertools
import os
import tempfile

_tmp = tempfile.mkdtemp()
os.environ.update(
    DATABASE_URL=f"sqlite:///{_tmp}/test.db",
    RESOLVE_DNS="false",
    CREATE_RATE_LIMIT="5",
    TRUSTED_PROXY_COUNT="1",
    REPORT_THRESHOLD="3",
    BASE_URL="http://testserver",
    REDIS_URL="",
)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

_ips = itertools.count(1)


@pytest.fixture(scope="session")
def client():
    with TestClient(app, follow_redirects=False) as c:
        yield c


@pytest.fixture
def ip():
    """A unique fake client IP per test, so rate limits never leak between tests."""
    n = next(_ips)
    return {"X-Forwarded-For": f"203.0.113.{n}"}
