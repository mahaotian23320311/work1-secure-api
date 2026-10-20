"""Negative tests that pin down the security properties of the API.

These are the tests a reviewer should read first: each one takes an attack
payload and asserts that it is defused.
"""

from __future__ import annotations

from tests.conftest import auth, login, token_for

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "alice' --",
    "' UNION SELECT id, username, password_hash, role, created_at FROM users --",
    "'; DROP TABLE users; --",
]


def test_sqli_in_login_never_authenticates(client):
    # A payload is refused either by length validation (400) or by the
    # credential check (401). What must never happen is a 200.
    for payload in SQLI_PAYLOADS:
        assert login(client, password=payload).status_code in (400, 401), payload
        assert login(client, username=payload, password=payload).status_code in (400, 401), payload


def test_sqli_in_search_returns_zero_rows_without_error(client):
    token = token_for(client)
    for payload in SQLI_PAYLOADS:
        response = client.get("/api/data", query_string={"search": payload}, headers=auth(token))
        assert response.status_code == 200, payload
        assert response.get_json() == {"count": 0, "items": []}, payload


def test_like_wildcards_are_not_injectable(client):
    token = token_for(client)
    response = client.get("/api/data", query_string={"search": "%"}, headers=auth(token))
    assert response.get_json()["count"] == 0  # '%' is a literal, not "everything"


def test_xss_payload_is_escaped_on_output(client):
    token = token_for(client)
    payload = "<script>alert('xss')</script>"
    created = client.post(
        "/api/notes", json={"title": payload, "body": payload + " body"}, headers=auth(token)
    )
    assert created.status_code == 201
    note_id = created.get_json()["id"]

    fetched = client.get(f"/api/notes/{note_id}", headers=auth(token))
    body = fetched.get_data(as_text=True)
    assert "<script>" not in body
    assert "&lt;script&gt;" in body
    assert fetched.mimetype == "application/json"


def test_xss_payload_stays_escaped_in_the_feed(client):
    token = token_for(client)
    markup = "<img src=x onerror=alert(1)>"
    client.post("/api/notes", json={"title": markup, "body": "see title"}, headers=auth(token))

    feed = client.get("/api/data", query_string={"search": "img"}, headers=auth(token)).get_json()
    assert feed["count"] == 1
    assert "<img" not in feed["items"][0]["title"]


def test_security_headers_present(client):
    response = client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]


def test_auth_responses_are_not_cacheable(client):
    response = login(client)
    assert response.headers["Cache-Control"] == "no-store"


def test_error_responses_do_not_leak_tracebacks(client):
    token = token_for(client)
    response = client.get("/api/notes/%s" % ("9" * 3), headers=auth(token))
    text = response.get_data(as_text=True).lower()
    assert response.status_code == 404
    for leak in ("traceback", "sqlite3", "site-packages", "werkzeug"):
        assert leak not in text
