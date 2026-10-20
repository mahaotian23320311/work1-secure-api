"""Password hashing, JWT handling and output escaping.

Every function here is deliberately small and testable, because these are the
three primitives the whole security story of the API rests on.
"""

from __future__ import annotations

import hmac
import time
import uuid

import bcrypt
import jwt
from markupsafe import escape

_DUMMY_HASHES: dict[int, str] = {}

# Characters that have no business in a title/body we echo back.
_CONTROL_CHARS = "".join(chr(c) for c in range(0, 32) if chr(c) not in "\n\t")


def hash_password(password: str, rounds: int) -> str:
    """Hash a password with bcrypt (per-password random salt, embedded cost)."""
    digest = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=rounds))
    return digest.decode("ascii")


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time-ish bcrypt comparison that never raises on bad input."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


def dummy_hash(rounds: int) -> str:
    """A hash of a throw-away value, used to burn the same CPU time for
    unknown usernames as for known ones (anti user-enumeration)."""
    if rounds not in _DUMMY_HASHES:
        _DUMMY_HASHES[rounds] = hash_password("not-a-real-password", rounds)
    return _DUMMY_HASHES[rounds]


def issue_token(
    *,
    secret: str,
    issuer: str,
    ttl_seconds: int,
    user_id: int,
    username: str,
    role: str,
) -> str:
    """Create a signed, expiring JWT for an authenticated user."""
    now = int(time.time())
    claims = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iss": issuer,
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(claims, secret, algorithm="HS256")


def decode_token(*, token: str, secret: str, issuer: str) -> dict:
    """Verify signature, expiry, not-before and issuer.

    Only HS256 is accepted, which defeats the classic ``alg: none`` and
    algorithm-confusion attacks against JWT libraries.
    """
    return jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        issuer=issuer,
        options={"require": ["exp", "iat", "sub", "iss"]},
    )


def escape_deep(value):
    """Recursively HTML-escape every string that leaves the API.

    Returning JSON does not make an application XSS-proof: clients regularly
    take the JSON and inject it into the DOM. Escaping at the trust boundary
    means a stored ``<script>`` can never execute, whoever renders it.
    """
    if isinstance(value, str):
        return str(escape(value))
    if isinstance(value, dict):
        return {key: escape_deep(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [escape_deep(item) for item in value]
    return value


def clean_text(value: str, *, max_length: int) -> str:
    """Strip leading/trailing whitespace and reject control characters."""
    cleaned = value.strip()
    if any(ch in _CONTROL_CHARS for ch in cleaned):
        raise ValueError("control characters are not allowed")
    if len(cleaned) > max_length:
        raise ValueError(f"value is longer than {max_length} characters")
    return cleaned


def tokens_equal(left: str, right: str) -> bool:
    """Timing-safe comparison for opaque strings."""
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
