"""
Regression tests for the /admin/users authorization + credential-redaction fix.

These exercise the Flask app in-process via ``app.test_client()`` (no live
server, no Docker), so they are safe and fast to run in any environment.

Invariant under test:
  1. An unauthenticated caller must NOT be able to retrieve the user directory
     (must get 401/403, never a 200 dump of the directory).
  2. Only an admin bearer token may read the directory; a non-admin token is
     rejected.
  3. No /admin/users response may ever contain credential material
     (``password`` or ``password_hash``), even for an authorized admin caller.
"""
import os
import sys

import pytest

# Make the application module importable regardless of the pytest rootdir.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import app as sieve_app  # noqa: E402

# Any field that carries a secret; the response must never expose these,
# whatever the storage scheme is named.
CREDENTIAL_FIELDS = ("password", "password_hash")


@pytest.fixture
def client():
    sieve_app.app.config["TESTING"] = True
    return sieve_app.app.test_client()


def _login(client, username, password):
    resp = client.post("/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return resp.get_json()["token"]


def test_unauthenticated_admin_users_is_rejected(client):
    """Anonymous GET /admin/users must be denied and leak no directory data.

    FAILS on the unfixed handler (returns 200 with the full USERS dict);
    PASSES once the route is gated behind an admin bearer token.
    """
    resp = client.get("/admin/users")

    assert resp.status_code in (401, 403), (
        "unauthenticated GET /admin/users returned "
        f"{resp.status_code}, expected 401/403"
    )

    body = resp.get_data(as_text=True)
    assert "password" not in body.lower(), "denied response leaked a password field"
    assert "@sieve.test" not in body, "denied response leaked directory email data"

    data = resp.get_json(silent=True) or {}
    assert "users" not in data, "denied response still returned the user directory"


def test_non_admin_token_is_rejected(client):
    """A valid but non-admin bearer token must not read the directory."""
    token = _login(client, "alice", "alice-pw")
    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code in (401, 403), (
        f"non-admin GET /admin/users returned {resp.status_code}, expected 401/403"
    )
    body = resp.get_data(as_text=True)
    assert "password" not in body.lower()
    data = resp.get_json(silent=True) or {}
    assert "users" not in data


def test_authenticated_admin_response_has_no_credentials(client):
    """An authorized admin may read the directory, but it must carry no secrets."""
    token = _login(client, "admin", "admin-pw")
    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    users = data["users"]
    assert users, "expected a non-empty user directory for an admin caller"

    for name, record in users.items():
        for field in CREDENTIAL_FIELDS:
            assert field not in record, (
                f"user {name!r} response leaked credential field {field!r}"
            )
        # Safe, expected fields survive the allowlist projection.
        assert "email" in record, f"user {name!r} missing expected 'email' field"

    raw = resp.get_data(as_text=True).lower()
    assert "password" not in raw, "admin response body contained a password field"
