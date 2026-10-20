"""Configuration for the Secure Notes API.

Secrets are never hard-coded: they come from the environment, and in
development an ephemeral random secret is generated so that a forgotten
`export JWT_SECRET=...` can never silently ship a known key.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def load_config() -> dict:
    """Return the base configuration dictionary."""
    jwt_secret = os.environ.get("JWT_SECRET") or secrets.token_hex(32)

    return {
        "JWT_SECRET": jwt_secret,
        "JWT_ALGORITHM": "HS256",
        "JWT_ISSUER": "secure-notes-api",
        "JWT_TTL_SECONDS": int(os.environ.get("JWT_TTL_SECONDS", "1800")),
        "DATABASE": os.environ.get("DATABASE", str(BASE_DIR / "data" / "app.db")),
        "BCRYPT_ROUNDS": int(os.environ.get("BCRYPT_ROUNDS", "12")),
        # Hard cap on request bodies: a small API never needs more.
        "MAX_CONTENT_LENGTH": 64 * 1024,
        "SEED_DEMO": os.environ.get("SEED_DEMO", "1") == "1",
        # Never expose interactive debugger or tracebacks to clients.
        "PROPAGATE_EXCEPTIONS": False,
    }
