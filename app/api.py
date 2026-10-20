"""Protected data endpoints."""

from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, g, jsonify, request

from .auth import token_required
from .db import get_db
from .errors import ApiError
from .security import clean_text, escape_deep

api_bp = Blueprint("api", __name__, url_prefix="/api")


def _like_pattern(term: str) -> str:
    """Build a safe LIKE pattern.

    The value is still bound as a parameter (that is what stops SQL injection);
    escaping the wildcards additionally stops a user from turning ``%`` into a
    match-everything search. ``ESCAPE '\\'`` in the query makes this work.
    """
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


@api_bp.get("/data")
@token_required
def list_data():
    """Return the post feed. Authentication is mandatory."""
    search = request.args.get("search", "", type=str).strip()
    if len(search) > 100:
        raise ApiError(400, "invalid_request", "'search' is too long (max 100).")

    db = get_db()
    if search:
        pattern = _like_pattern(search)
        rows = db.execute(
            """
            SELECT p.id, p.title, p.body, p.created_at, u.username AS author
              FROM posts p
              JOIN users u ON u.id = p.user_id
             WHERE p.title LIKE ? ESCAPE '\\'
                OR p.body  LIKE ? ESCAPE '\\'
             ORDER BY p.id
            """,
            (pattern, pattern),
        ).fetchall()
    else:
        rows = db.execute(
            """
            SELECT p.id, p.title, p.body, p.created_at, u.username AS author
              FROM posts p
              JOIN users u ON u.id = p.user_id
             ORDER BY p.id
            """
        ).fetchall()

    return jsonify(
        escape_deep(
            {
                "count": len(rows),
                "items": [
                    {
                        "id": row["id"],
                        "title": row["title"],
                        "body": row["body"],
                        "author": row["author"],
                        "created_at": row["created_at"],
                    }
                    for row in rows
                ],
            }
        )
    )


@api_bp.get("/me")
@token_required
def me():
    """Who am I? Handy for the client and for demonstrating the token guard."""
    user = g.current_user
    return jsonify(
        {"id": user["id"], "username": user["username"], "role": user["role"]}
    )


@api_bp.post("/notes")
@token_required
def create_note():
    """Third endpoint (self-chosen): create a note owned by the caller."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise ApiError(400, "invalid_request", "Body must be a JSON object.")

    title = payload.get("title")
    body = payload.get("body")
    if not isinstance(title, str) or not isinstance(body, str):
        raise ApiError(400, "invalid_request", "'title' and 'body' must be strings.")

    try:
        title = clean_text(title, max_length=120)
        body = clean_text(body, max_length=2000)
    except ValueError as exc:
        raise ApiError(400, "invalid_request", str(exc)) from exc
    if not title or not body:
        raise ApiError(400, "invalid_request", "'title' and 'body' must not be empty.")

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    db = get_db()
    cursor = db.execute(
        "INSERT INTO posts (user_id, title, body, created_at) VALUES (?, ?, ?, ?)",
        (g.current_user["id"], title, body, now),
    )
    db.commit()

    return (
        jsonify(
            escape_deep(
                {
                    "id": cursor.lastrowid,
                    "title": title,
                    "body": body,
                    "author": g.current_user["username"],
                    "created_at": now,
                }
            )
        ),
        201,
    )


@api_bp.get("/notes/<int:note_id>")
@token_required
def get_note(note_id: int):
    """Read one note: owner or admin only (broken access control guard)."""
    row = get_db().execute(
        """
        SELECT p.id, p.title, p.body, p.created_at, p.user_id, u.username AS author
          FROM posts p
          JOIN users u ON u.id = p.user_id
         WHERE p.id = ?
        """,
        (note_id,),
    ).fetchone()

    if row is None:
        raise ApiError(404, "not_found", "Note not found.")

    is_owner = row["user_id"] == g.current_user["id"]
    is_admin = g.current_user["role"] == "admin"
    if not (is_owner or is_admin):
        raise ApiError(403, "forbidden", "You may only read your own notes.")

    return jsonify(
        escape_deep(
            {
                "id": row["id"],
                "title": row["title"],
                "body": row["body"],
                "author": row["author"],
                "created_at": row["created_at"],
            }
        )
    )
