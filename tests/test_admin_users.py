"""Regression tests for the /admin/users endpoint (TC-92000272).

Invariant under test:
    The full user directory — including every user's plaintext password and
    admin status — must NOT be retrievable without authentication, nor by a
    non-admin user, and an authorized admin read must never serialize plaintext
    credentials.

These tests drive the app through Flask's test client against its own seeded
in-memory store, so no external target or database is required. The positive
controls prove auth enforcement works and the environment is healthy, which
isolates any failure below to the endpoint under test rather than a broken setup.
"""
import pytest

import app as sieve_app


@pytest.fixture
def client():
    sieve_app.app.config["TESTING"] = True
    # Start each test from a clean token store.
    sieve_app.TOKENS.clear()
    return sieve_app.app.test_client()


def login(client, username, password):
    resp = client.post("/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"login for {username} failed: {resp.status_code}"
    return resp.get_json()["token"]


# ---- Positive controls: auth enforcement works and the env is healthy --------

def test_control_unauthenticated_account_read_is_rejected(client):
    # The sibling protected route rejects an unauthenticated read -> auth works.
    assert client.get("/accounts/1").status_code == 401


def test_control_authenticated_account_read_succeeds(client):
    token = login(client, "alice", "alice-pw")
    resp = client.get("/accounts/1", headers={"Authorization": f"Bearer {token}"})
    # A legitimate read still works -> the environment is healthy.
    assert resp.status_code == 200


# ---- Invariant assertions ----------------------------------------------------

def test_admin_users_rejects_anonymous(client):
    resp = client.get("/admin/users")
    assert resp.status_code == 401, (
        f"unauthenticated /admin/users returned {resp.status_code}; the full user "
        "directory must not be retrievable without authentication"
    )


def test_admin_users_rejects_non_admin(client):
    token = login(client, "alice", "alice-pw")  # alice is a non-admin account
    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403, (
        f"non-admin /admin/users returned {resp.status_code}; a non-admin user "
        "must not be able to read the full user directory"
    )


def test_admin_users_allows_admin_without_leaking_passwords(client):
    token = login(client, "admin", "admin-pw")  # admin account
    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200  # an authorized admin can still read the directory

    users = resp.get_json()["users"]
    assert set(users) == {"alice", "bob", "admin"}  # directory is still served in full
    for name, record in users.items():
        assert "password" not in record, (
            f"record for {name!r} still contains a plaintext 'password' field; "
            "credentials must never be serialized in the response"
        )
