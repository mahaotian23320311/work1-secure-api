"""Authentication blueprint: login + the JWT guard used everywhere else."""

from __future__ import annotations

from functools import wraps

import jwt
from flask import Blueprint, current_app, g, jsonify, request

from .db import get_db
from .errors import ApiError, error_response
from .security import decode_token, dummy_hash, issue_token, verify_password

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

# One message for every credential failure: never reveal which half was wrong.
_INVALID_CREDENTIALS = ("invalid_credentials", "Invalid username or password.")


def _bearer_token() -> str:
    header = request.headers.get("Authorization", "")
    parts = header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise ApiError(
            401,
            "missing_token",
            "A Bearer token is required.",
            {"WWW-Authenticate": 'Bearer realm="api"'},
        )
    return parts[1]


def token_required(view):
    """Verify the JWT and bind the *current* user row to ``g``.

    The token is only a claim: the user is re-read from the database so that a
    deleted or downgraded account cannot keep using an old token.
    """

    @wraps(view)
    def wrapper(*args, **kwargs):
        token = _bearer_token()
        cfg = current_app.config
        try:
            claims = decode_token(
                token=token, secret=cfg["JWT_SECRET"], issuer=cfg["JWT_ISSUER"]
            )
        except jwt.ExpiredSignatureError:
            raise ApiError(
                401,
                "token_expired",
                "The access token has expired.",
                {"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )
        except jwt.InvalidTokenError:
            raise ApiError(
                401,
                "invalid_token",
                "The access token is not valid.",
                {"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )

        row = get_db().execute(
            "SELECT id, username, role FROM users WHERE id = ?", (int(claims["sub"]),)
        ).fetchone()
        if row is None:
            raise ApiError(401, "invalid_token", "The access token is not valid.")

        g.current_user = row
        g.claims = claims
        return view(*args, **kwargs)

    return wrapper


@auth_bp.post("/login")
def login():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise ApiError(400, "invalid_request", "Body must be a JSON object.")

    username = payload.get("username")
    password = payload.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        raise ApiError(400, "invalid_request", "'username' and 'password' are required strings.")
    if not 1 <= len(username) <= 64 or not 1 <= len(password) <= 128:
        raise ApiError(400, "invalid_request", "Credentials have an invalid length.")

    db = get_db()
    user = db.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    if user is None:
        # Same bcrypt work as a real check, so response time does not leak
        # whether the account exists.
        verify_password(password, dummy_hash(current_app.config["BCRYPT_ROUNDS"]))
        return error_response(401, *_INVALID_CREDENTIALS)

    if not verify_password(password, user["password_hash"]):
        return error_response(401, *_INVALID_CREDENTIALS)

    cfg = current_app.config
    token = issue_token(
        secret=cfg["JWT_SECRET"],
        issuer=cfg["JWT_ISSUER"],
        ttl_seconds=cfg["JWT_TTL_SECONDS"],
        user_id=user["id"],
        username=user["username"],
        role=user["role"],
    )
    return (
        jsonify(
            {
                "access_token": token,
                # "Bearer" is the RFC 6750 scheme name, not a credential.
                "token_type": "Bearer",  # nosec B105
                "expires_in": cfg["JWT_TTL_SECONDS"],
            }
        ),
        200,
    )
