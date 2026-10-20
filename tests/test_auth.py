"""Authentication tests: JWT issuance, hashing, and credential handling."""

from __future__ import annotations

from tests.conftest import auth, login, token_for


def test_login_returns_jwt(client):
    response = login(client)
    assert response.status_code == 200
    body = response.get_json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] > 0
    # A JWT is three dot-separated base64url segments.
    assert body["access_token"].count(".") == 2


def test_login_wrong_password_is_rejected(client):
    response = login(client, password="wrong-password")
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "invalid_credentials"


def test_unknown_user_looks_identical_to_wrong_password(client):
    unknown = login(client, username="nobody-here")
    wrong = login(client, password="nope")
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.get_json() == wrong.get_json()


def test_login_requires_json(client):
    response = client.post("/auth/login", data="username=alice")
    assert response.status_code == 415


def test_login_rejects_missing_fields(client):
    assert client.post("/auth/login", json={"username": "alice"}).status_code == 400
    assert client.post("/auth/login", json={"username": 5, "password": []}).status_code == 400


def test_passwords_are_bcrypt_hashed_not_stored_in_plaintext(app):
    from app.db import get_db

    with app.app_context():
        rows = get_db().execute("SELECT username, password_hash FROM users").fetchall()

    assert rows, "demo users should be seeded"
    for row in rows:
        assert row["password_hash"].startswith(("$2b$", "$2a$", "$2y$"))
        assert "Passw0rd" not in row["password_hash"]
        # bcrypt hashes are 60 chars and contain a per-user salt.
    assert len({row["password_hash"] for row in rows}) == len(rows)


def test_token_grants_access(client):
    token = token_for(client)
    response = client.get("/api/me", headers=auth(token))
    assert response.status_code == 200
    assert response.get_json()["username"] == "alice"
