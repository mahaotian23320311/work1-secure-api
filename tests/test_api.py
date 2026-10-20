"""API behaviour and access-control tests."""

from __future__ import annotations

import time

import jwt

from tests.conftest import TEST_SECRET, auth, token_for

ISSUER = "secure-notes-api"


def test_data_requires_a_token(client):
    response = client.get("/api/data")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"].lower().startswith("bearer")


def test_data_with_token_returns_posts(client):
    token = token_for(client)
    response = client.get("/api/data", headers=auth(token))
    assert response.status_code == 200
    body = response.get_json()
    assert body["count"] >= 3
    assert {"id", "title", "body", "author"} <= set(body["items"][0])


def test_garbage_token_is_rejected(client):
    response = client.get("/api/data", headers=auth("not.a.jwt"))
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "invalid_token"


def test_expired_token_is_rejected(client):
    now = int(time.time())
    expired = jwt.encode(
        {
            "sub": "1",
            "username": "alice",
            "role": "admin",
            "iss": ISSUER,
            "iat": now - 3600,
            "nbf": now - 3600,
            "exp": now - 60,
        },
        TEST_SECRET,
        algorithm="HS256",
    )
    response = client.get("/api/data", headers=auth(expired))
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "token_expired"


def test_alg_none_token_is_rejected(client):
    unsigned = jwt.encode({"sub": "1", "iss": ISSUER, "exp": int(time.time()) + 600}, None, algorithm="none")
    response = client.get("/api/data", headers=auth(unsigned))
    assert response.status_code == 401


def test_token_signed_with_another_key_is_rejected(client):
    forged = jwt.encode(
        {"sub": "1", "iss": ISSUER, "iat": int(time.time()), "exp": int(time.time()) + 600},
        "attacker-controlled-key-0000000000000000",
        algorithm="HS256",
    )
    assert client.get("/api/data", headers=auth(forged)).status_code == 401


def test_create_and_read_own_note(client):
    token = token_for(client)
    created = client.post(
        "/api/notes",
        json={"title": "Shopping", "body": "milk and honey"},
        headers=auth(token),
    )
    assert created.status_code == 201
    note = created.get_json()

    fetched = client.get(f"/api/notes/{note['id']}", headers=auth(token))
    assert fetched.status_code == 200
    assert fetched.get_json()["title"] == "Shopping"
    assert fetched.get_json()["author"] == "alice"


def test_user_cannot_read_someone_elses_note(client):
    alice = token_for(client)
    alice_note = client.post(
        "/api/notes", json={"title": "private", "body": "secret"}, headers=auth(alice)
    ).get_json()

    bob = token_for(client, "bob", "Bob-Passw0rd!")
    response = client.get(f"/api/notes/{alice_note['id']}", headers=auth(bob))
    assert response.status_code == 403


def test_missing_note_is_404(client):
    token = token_for(client)
    assert client.get("/api/notes/9999", headers=auth(token)).status_code == 404


def test_note_validation(client):
    token = token_for(client)
    assert client.post("/api/notes", json={"title": "", "body": "x"}, headers=auth(token)).status_code == 400
    assert client.post("/api/notes", json={"title": "x" * 200, "body": "y"}, headers=auth(token)).status_code == 400
    assert client.post("/api/notes", json={"title": 1, "body": 2}, headers=auth(token)).status_code == 400
