import pytest

from app import TOKENS, app


@pytest.fixture(autouse=True)
def clear_tokens():
    TOKENS.clear()


@pytest.fixture
def client():
    return app.test_client()


def login(client, username, password):
    response = client.post(
        "/login",
        json={"username": username, "password": password},
    )
    assert response.status_code == 200
    return response.get_json()["token"]


def test_admin_directory_requires_admin_bearer_token(client):
    admin_token = login(client, "admin", "admin-pw")

    authorized = client.get(
        "/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert authorized.status_code == 200
    assert "users" in authorized.get_json()

    unauthenticated = client.get("/admin/users")
    assert unauthenticated.status_code in {401, 403}
    assert "users" not in unauthenticated.get_json()

    user_token = login(client, "alice", "alice-pw")
    forbidden = client.get(
        "/admin/users",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert forbidden.status_code == 403
    assert "users" not in forbidden.get_json()


def test_admin_directory_does_not_serialize_password_fields(client):
    admin_token = login(client, "admin", "admin-pw")

    response = client.get(
        "/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    users = response.get_json()["users"]
    assert users
    assert all("password" not in user for user in users.values())
