"""Pytest configuration: make the repo-root `app` module importable and expose
a shared Flask test client with isolated in-memory state per test."""
import pytest

import app as app_module


@pytest.fixture()
def client():
    """Fresh test client; clear issued tokens so tests don't leak auth state."""
    app_module.TOKENS.clear()
    app_module.app.config.update(TESTING=True)
    return app_module.app.test_client()


def login(client, username, password):
    """Log in via the API and return the bearer token (mirrors a real client)."""
    resp = client.post("/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"login failed for {username!r}: {resp.status_code}"
    return resp.get_json()["token"]
