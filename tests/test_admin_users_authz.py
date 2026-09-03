"""
Regression tests for authz + sensitive-field exposure on GET /admin/users.

Self-contained: uses Flask's in-process test client (app.test_client()); it does
NOT depend on the live container. Requires flask==3.0.3 and pytest.

These tests assert the durable invariant:
  An unauthenticated (or non-admin) visitor must not be able to retrieve the
  user directory, and the account password must never be serialized in the
  response for any caller.

Against the unfixed app.py all three tests fail (the endpoint returns HTTP 200
with every account's plaintext password to any caller); after the fix they pass.
"""
import os
import sys

# Make the application package importable regardless of the working directory
# from which pytest is invoked (the repo root is the parent of this tests/ dir).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from app import app, USERS, TOKENS

# Opaque test tokens. Per the app's data contract, TOKENS maps an opaque token
# STRING to the owning USERNAME (TOKENS[token] -> username). We register tokens
# directly rather than embedding seed passwords in the test.
ADMIN_TOKEN = "test-admin-token"
NONADMIN_TOKEN = "test-nonadmin-token"


def _pick(is_admin):
    return next(u for u, d in USERS.items() if bool(d.get("admin")) == is_admin)


ADMIN_USER = _pick(True)
NONADMIN_USER = _pick(False)


@pytest.fixture()
def client():
    app.config["TESTING"] = True
    # Register valid tokens for the duration of the test, then clean up so tests
    # remain independent and the module-level TOKENS map is left untouched.
    TOKENS[ADMIN_TOKEN] = ADMIN_USER
    TOKENS[NONADMIN_TOKEN] = NONADMIN_USER
    try:
        with app.test_client() as c:
            yield c
    finally:
        TOKENS.pop(ADMIN_TOKEN, None)
        TOKENS.pop(NONADMIN_TOKEN, None)


def _assert_no_directory_leaked(payload):
    """No account record and no password may appear anywhere in the body."""
    blob = str(payload)
    assert "password" not in blob, "response must never contain a password field"
    users = payload.get("users") if isinstance(payload, dict) else None
    assert not users, "unauthorized caller must not receive the user directory"


def test_unauthenticated_request_is_rejected_and_leaks_nothing(client):
    resp = client.get("/admin/users")
    assert resp.status_code in (401, 403), (
        f"anonymous caller must be rejected, got {resp.status_code}"
    )
    _assert_no_directory_leaked(resp.get_json(silent=True) or {})


def test_non_admin_token_is_rejected(client):
    resp = client.get(
        "/admin/users",
        headers={"Authorization": f"Bearer {NONADMIN_TOKEN}"},
    )
    assert resp.status_code in (401, 403), (
        f"non-admin caller must be rejected, got {resp.status_code}"
    )
    _assert_no_directory_leaked(resp.get_json(silent=True) or {})


def test_admin_token_succeeds_without_exposing_passwords(client):
    resp = client.get(
        "/admin/users",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    assert resp.status_code == 200, (
        f"admin caller must succeed, got {resp.status_code}"
    )
    body = resp.get_json()
    assert isinstance(body, dict) and body.get("users"), "admin must receive the directory"
    returned = body["users"]
    assert len(returned) == len(USERS), "admin should see all accounts"
    for username, record in returned.items():
        assert "password" not in record, (
            f"password must never be serialized (leaked for {username!r})"
        )
