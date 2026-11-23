"""Application settings, loaded once from environment variables (.env supported)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")


def _env_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    return int(os.getenv(name, str(default)))


@dataclass(frozen=True)
class Settings:
    base_url: str
    database_url: str
    redis_url: str | None
    secret_salt: str
    code_length: int
    cache_ttl_seconds: int
    negative_cache_ttl_seconds: int
    create_rate_limit: int
    create_rate_window: int
    redirect_rate_limit: int
    redirect_rate_window: int
    report_threshold: int
    warn_score: int
    block_score: int
    resolve_dns: bool
    trusted_proxy_count: int
    blocklist_path: Path
    purge_interval_seconds: int


@lru_cache
def get_settings() -> Settings:
    return Settings(
        base_url=os.getenv("BASE_URL", "http://127.0.0.1:8000").rstrip("/"),
        database_url=os.getenv("DATABASE_URL", "sqlite:///./safelink.db"),
        redis_url=os.getenv("REDIS_URL") or None,
        secret_salt=os.getenv("SECRET_SALT", "dev-only-change-me"),
        code_length=_env_int("CODE_LENGTH", 7),
        cache_ttl_seconds=_env_int("CACHE_TTL_SECONDS", 3600),
        negative_cache_ttl_seconds=_env_int("NEGATIVE_CACHE_TTL_SECONDS", 60),
        create_rate_limit=_env_int("CREATE_RATE_LIMIT", 10),
        create_rate_window=_env_int("CREATE_RATE_WINDOW", 60),
        redirect_rate_limit=_env_int("REDIRECT_RATE_LIMIT", 120),
        redirect_rate_window=_env_int("REDIRECT_RATE_WINDOW", 60),
        report_threshold=_env_int("REPORT_THRESHOLD", 3),
        warn_score=_env_int("WARN_SCORE", 40),
        block_score=_env_int("BLOCK_SCORE", 70),
        resolve_dns=_env_bool("RESOLVE_DNS", True),
        trusted_proxy_count=_env_int("TRUSTED_PROXY_COUNT", 0),
        blocklist_path=Path(
            os.getenv("BLOCKLIST_PATH", str(PROJECT_ROOT / "data" / "blocklist.txt"))
        ),
        purge_interval_seconds=_env_int("PURGE_INTERVAL_SECONDS", 3600),
    )
