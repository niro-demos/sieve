"""Regression test for the GET /accounts/<id> IDOR (broken object-level
authorization).

Invariant under test: a user must NOT be able to read another user's account
details by changing the numeric account id in the request path. Cross-user reads
must be rejected (403/401); only the authenticated user's own account is a
legitimate read.
"""
import pytest

from app import app


@pytest.fixture()
def client():
    app.testing = True
    return app.test_client()


def login(client, username, password):
    resp = client.post("/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()["token"]


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def account_id(username):
    return {"alice": 1, "bob": 2, "admin": 3}[username]


# --- Positive control: a user reading their own account stays green (200). ----

@pytest.mark.parametrize("username", ["alice", "bob", "admin"])
def test_self_read_returns_own_account(client, username):
    token = login(client, username, f"{username}-pw")
    resp = client.get(f"/accounts/{account_id(username)}", headers=auth_header(token))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["id"] == account_id(username)
    assert body["username"] == username


# --- Negative control: an unauthenticated request is rejected (401). ---------

def test_unauthenticated_read_is_rejected(client):
    resp = client.get("/accounts/1")
    assert resp.status_code == 401


# --- Invariant under test: cross-user reads must be forbidden (403/401). -----

@pytest.mark.parametrize(
    "actor,target_owner",
    [
        ("alice", "bob"),
        ("alice", "admin"),
        ("bob", "alice"),
        ("bob", "admin"),
        ("admin", "alice"),
        ("admin", "bob"),
    ],
)
def test_cross_user_read_is_forbidden(client, actor, target_owner):
    token = login(client, actor, f"{actor}-pw")
    resp = client.get(
        f"/accounts/{account_id(target_owner)}", headers=auth_header(token)
    )
    assert resp.status_code in (401, 403), (
        f"{actor} read /accounts/{account_id(target_owner)} owned by "
        f"{target_owner}: expected 403/401, got {resp.status_code} -> "
        f"{resp.get_json()}"
    )
    # The body must not leak the other user's account details.
    body = resp.get_json() or {}
    assert body.get("id") != account_id(target_owner)
    assert target_owner not in (body.get("username"), body.get("email"))
