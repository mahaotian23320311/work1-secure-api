"""SQLite access layer.

Every statement in this file is parameterised. There is not a single f-string
or ``%`` interpolation building SQL, which is the actual mitigation for
CWE-89 (SQL injection) -- the driver sends the query text and the values
separately, so user input can never become query syntax.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    created_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS posts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title      TEXT    NOT NULL,
    body       TEXT    NOT NULL,
    created_at TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_posts_user_id ON posts(user_id);
"""

DEMO_USERS = [
    ("alice", "Alice-Passw0rd!", "admin"),
    ("bob", "Bob-Passw0rd!", "user"),
]

DEMO_POSTS = [
    (1, "Welcome to the secure notes API", "This post is visible to every authenticated user."),
    (1, "SQL injection is a data/query mixing bug", "Values are bound as parameters; they are never parsed as SQL."),
    (2, "Escaping belongs at the trust boundary", "User supplied HTML is escaped on the way out of the API."),
]


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_db() -> sqlite3.Connection:
    """One connection per request, closed by ``close_db``."""
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(_exc: BaseException | None = None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db(app) -> None:
    """Create the schema and, for the demo, a couple of seed rows."""
    path = Path(app.config["DATABASE"])
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = connect(str(path))
    try:
        conn.executescript(SCHEMA)
        conn.commit()
        if app.config.get("SEED_DEMO", True):
            _seed(conn, rounds=app.config["BCRYPT_ROUNDS"])
    finally:
        conn.close()


def _seed(conn: sqlite3.Connection, *, rounds: int) -> None:
    from datetime import datetime, timezone

    from .security import hash_password

    existing = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    if existing:
        return

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for username, password, role in DEMO_USERS:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, hash_password(password, rounds), role, now),
        )
    for user_id, title, body in DEMO_POSTS:
        conn.execute(
            "INSERT INTO posts (user_id, title, body, created_at) VALUES (?, ?, ?, ?)",
            (user_id, title, body, now),
        )
    conn.commit()
