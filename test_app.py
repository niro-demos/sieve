"""
Regression tests for Sieve security fixes.

These tests verify:
1. /admin/users requires authentication (TC-23B796CC)
2. /admin/users requires admin authorization (TC-23B796CC)
3. /admin/users does not serialize plaintext passwords (TC-45559D10)

Run with: pip install pytest flask && python -m pytest test_app.py -v
"""
import pytest
import json
from app import app, USERS, TOKENS


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def reset_tokens():
    """Clear TOKENS before each test so logins are explicit."""
    TOKENS.clear()
    yield
    TOKENS.clear()


class TestAdminUsersRequiresAuth:
    """TC-23B796CC: /admin/users must enforce authentication."""

    def test_no_auth_returns_401(self, client, reset_tokens):
        """An unauthenticated request must not return the user list."""
        resp = client.get("/admin/users")
        assert resp.status_code == 401, (
            f"Expected 401 for unauthenticated request, got {resp.status_code}"
        )

    def test_bogus_token_returns_401(self, client, reset_tokens):
        """A garbage token must not authenticate."""
        resp = client.get("/admin/users", headers={"Authorization": "garbage"})
        assert resp.status_code == 401, (
            f"Expected 401 for bogus token, got {resp.status_code}"
        )

    def test_forged_token_returns_401(self, client, reset_tokens):
        """A hand-crafted token-N must not authenticate without prior login."""
        resp = client.get("/admin/users", headers={"Authorization": "token-3"})
        assert resp.status_code == 401, (
            f"Expected 401 for forged token, got {resp.status_code}"
        )


class TestAdminUsersRequiresAdmin:
    """TC-23B796CC: /admin/users must enforce admin authorization."""

    def test_non_admin_user_gets_403(self, client, reset_tokens):
        """A valid non-admin token must not access /admin/users."""
        # Log in as alice (non-admin)
        resp = client.post(
            "/login",
            data=json.dumps({"username": "alice", "password": "alice-pw"}),
            content_type="application/json",
        )
        token = resp.get_json()["token"]
        resp = client.get("/admin/users", headers={"Authorization": token})
        assert resp.status_code == 403, (
            f"Expected 403 for non-admin user, got {resp.status_code}"
        )

    def test_admin_user_gets_200(self, client, reset_tokens):
        """A valid admin token must access /admin/users."""
        resp = client.post(
            "/login",
            data=json.dumps({"username": "admin", "password": "admin-pw"}),
            content_type="application/json",
        )
        token = resp.get_json()["token"]
        resp = client.get("/admin/users", headers={"Authorization": token})
        assert resp.status_code == 200, (
            f"Expected 200 for admin user, got {resp.status_code}"
        )


class TestNoPlaintextPasswords:
    """TC-45559D10: /admin/users must not serialize passwords."""

    def test_admin_response_has_no_password_field(self, client, reset_tokens):
        """No user object in /admin/users may contain a 'password' key."""
        resp = client.post(
            "/login",
            data=json.dumps({"username": "admin", "password": "admin-pw"}),
            content_type="application/json",
        )
        token = resp.get_json()["token"]
        resp = client.get("/admin/users", headers={"Authorization": token})
        body = resp.get_json()
        for username, user_data in body.get("users", {}).items():
            assert "password" not in user_data, (
                f"User '{username}' has a 'password' field in the response"
            )
