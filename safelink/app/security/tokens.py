"""Secrets and privacy helpers: owner tokens and salted IP hashing."""
from __future__ import annotations

import hashlib
import hmac
import secrets

from app.config import get_settings


def new_owner_token() -> str:
    """256-bit-ish random token handed to the link creator exactly once."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Only the SHA-256 of a token is stored, so a DB leak does not leak access."""
    return hashlib.sha256(token.encode()).hexdigest()


def tokens_match(presented: str, stored_hash: str) -> bool:
    """Constant-time comparison (avoids timing side channels)."""
    return hmac.compare_digest(hash_token(presented), stored_hash)


def hash_ip(ip: str) -> str:
    """Salted hash: lets us count unique visitors without storing personal data."""
    salt = get_settings().secret_salt
    return hashlib.sha256(f"{salt}:{ip}".encode()).hexdigest()
