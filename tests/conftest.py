"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

from app import create_app

TEST_SECRET = "unit-test-secret-key-0123456789abcdef"


@pytest.fixture()
def app(tmp_path):
    application = create_app(
        {
            "DATABASE": str(tmp_path / "test.db"),
            "JWT_SECRET": TEST_SECRET,
            "BCRYPT_ROUNDS": 4,
            "TESTING": True,
        }
    )
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client, username="alice", password="Alice-Passw0rd!"):
    response = client.post("/auth/login", json={"username": username, "password": password})
    return response


def token_for(client, username="alice", password="Alice-Passw0rd!"):
    response = login(client, username, password)
    assert response.status_code == 200, response.get_json()
    return response.get_json()["access_token"]


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
