"""Regression tests for TC-C0087E66.

Invariant: the admin user directory endpoint must not be accessible without
admin authentication, and must never expose users' plaintext passwords.

These run against the Flask test client (no running server required). They
recreate the scenario the PoC exercised using the app's own seeded users.
"""
from conftest import login


def test_account_endpoint_requires_token(client):
    """Positive control: the auth mechanism works elsewhere, so any failure
    in the admin tests below is the admin invariant, not a broken setup."""
    token = login(client, "alice", "alice-pw")

    ok = client.get("/accounts/1", headers={"Authorization": f"Bearer {token}"})
    assert ok.status_code == 200

    no_token = client.get("/accounts/1")
    assert no_token.status_code == 401


def test_admin_users_rejects_unauthenticated(client):
    """An unauthenticated caller must not reach the user directory."""
    resp = client.get("/admin/users")
    assert resp.status_code in (401, 403), (
        f"unauthenticated GET /admin/users should be rejected, got {resp.status_code}"
    )


def test_admin_users_rejects_non_admin(client):
    """A valid but non-admin token must not reach the user directory."""
    token = login(client, "alice", "alice-pw")
    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403, (
        f"non-admin GET /admin/users should be forbidden, got {resp.status_code}"
    )


def test_admin_users_admin_response_has_no_passwords(client):
    """Even an admin must never receive plaintext password fields."""
    token = login(client, "admin", "admin-pw")
    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, f"admin GET /admin/users should succeed, got {resp.status_code}"

    users = resp.get_json().get("users", {})
    assert users, "admin response should list users"
    for username, record in users.items():
        assert "password" not in record, (
            f"plaintext password leaked for user {username!r}"
        )
