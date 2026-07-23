"""
Regression test for the admin user-directory endpoint (GET /admin/users).

Invariant under test:
  Only an authenticated administrator may list the full user directory. An
  anonymous caller and a caller bearing an unrecognized token MUST be rejected
  with 401. An authenticated but non-admin caller MUST be rejected with 403.
  In no case may any account's plaintext password appear in the response body.

These tests use Flask's native test client (no live server, no seeded harness
DB). The app keeps its "database" in-memory, so we mint tokens the same way the
app does — by exercising the real /login flow — rather than reading any harness
credential file.
"""
import importlib
import json

import pytest


@pytest.fixture
def client():
    app_module = importlib.import_module("app")
    importlib.reload(app_module)  # fresh in-memory USERS/TOKENS per test
    app_module.app.config.update(TESTING=True)
    return app_module.app.test_client()


def _login(client, username, password):
    resp = client.post("/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return resp.get_json()["token"]


def _body_has_password(resp):
    """True if any plaintext password field leaks in the response body."""
    text = resp.get_data(as_text=True)
    if '"password"' not in text:
        return False
    # A redacted/omitted field is fine; a real seeded value is a leak.
    return any(pw in text for pw in ("alice-pw", "bob-pw", "admin-pw"))


def test_control_login_and_account_auth_works(client):
    """Positive control: the app's own auth pattern is healthy."""
    # No credential to /accounts/<id> is correctly rejected.
    assert client.get("/accounts/1").status_code == 401
    # A valid login yields a usable token.
    token = _login(client, "admin", "admin-pw")
    ok = client.get("/accounts/3", headers={"Authorization": f"Bearer {token}"})
    assert ok.status_code == 200


def test_anonymous_is_rejected_and_no_password_leak(client):
    resp = client.get("/admin/users")
    assert resp.status_code == 401, resp.get_data(as_text=True)
    assert not _body_has_password(resp)


def test_garbage_token_is_rejected_and_no_password_leak(client):
    resp = client.get(
        "/admin/users",
        headers={"Authorization": "Bearer totally-invalid-garbage"},
    )
    assert resp.status_code == 401, resp.get_data(as_text=True)
    assert not _body_has_password(resp)


def test_non_admin_user_is_forbidden_and_no_password_leak(client):
    token = _login(client, "alice", "alice-pw")  # alice is not an admin
    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403, resp.get_data(as_text=True)
    assert not _body_has_password(resp)


def test_authenticated_admin_gets_directory_without_plaintext_passwords(client):
    token = _login(client, "admin", "admin-pw")
    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    # The admin still receives the directory (every account present)...
    users = data["users"]
    assert set(users) == {"alice", "bob", "admin"}
    # ...but no plaintext password is ever serialized, even for an admin.
    assert not _body_has_password(resp)
    for account in users.values():
        assert account.get("password") in (None, "<redacted>")
