import json
import secrets
import unittest
import uuid
from unittest.mock import patch

from werkzeug.security import generate_password_hash

from app import USERS, TOKENS, app


class RouteAuthorizationTests(unittest.TestCase):
    def setUp(self):
        actor_suffix = uuid.uuid4().hex
        self.owner_username = f"a97-owner-{actor_suffix}"
        self.other_username = f"a97-other-{actor_suffix}"
        self.admin_username = f"a97-admin-{actor_suffix}"
        self.owner_password = secrets.token_urlsafe(24)
        self.other_password = secrets.token_urlsafe(24)
        self.admin_password = secrets.token_urlsafe(24)

        self.users = {
            self.owner_username: {
                "id": 101,
                "email": f"{self.owner_username}@example.test",
                "balance": 1250,
                "admin": False,
            },
            self.other_username: {
                "id": 102,
                "email": f"{self.other_username}@example.test",
                "balance": 250,
                "admin": False,
            },
            self.admin_username: {
                "id": 103,
                "email": f"{self.admin_username}@example.test",
                "balance": 0,
                "admin": True,
            },
        }

        credential_key = self._credential_key()
        credentials = (
            (self.owner_username, self.owner_password),
            (self.other_username, self.other_password),
            (self.admin_username, self.admin_password),
        )
        for username, password in credentials:
            self.users[username][credential_key] = (
                generate_password_hash(password, method="pbkdf2:sha256:1")
                if credential_key == "password_hash"
                else password
            )

        users_patch = patch.dict(USERS, self.users, clear=True)
        users_patch.start()
        self.addCleanup(users_patch.stop)
        TOKENS.clear()
        self.addCleanup(TOKENS.clear)
        app.config["TESTING"] = True
        self.client = app.test_client()

    def _credential_key(self):
        sample_user = next(iter(USERS.values()))
        if "password_hash" in sample_user:
            return "password_hash"
        if "password" in sample_user:
            return "password"
        self.fail("users have no password credential field")

    def login(self, username, password):
        response = self.client.post(
            "/login",
            data=json.dumps({"username": username, "password": password}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.get_json())
        token = response.get_json().get("token")
        self.assertIsInstance(token, str)
        return token

    def test_account_read_is_limited_to_its_owner(self):
        owner_token = self.login(self.owner_username, self.owner_password)
        other_token = self.login(self.other_username, self.other_password)

        legitimate = self.client.get(
            "/accounts/101", headers={"Authorization": f"Bearer {owner_token}"}
        )
        self.assertEqual(legitimate.status_code, 200)
        self.assertEqual(
            legitimate.get_json(),
            {
                "id": 101,
                "username": self.owner_username,
                "email": f"{self.owner_username}@example.test",
                "balance": 1250,
            },
        )

        for token in (None, "invalid-token"):
            headers = {} if token is None else {"Authorization": f"Bearer {token}"}
            unauthenticated = self.client.get("/accounts/101", headers=headers)
            self.assertEqual(unauthenticated.status_code, 401)
            self.assertEqual(unauthenticated.get_json(), {"error": "unauthorized"})

        missing = self.client.get(
            "/accounts/999", headers={"Authorization": f"Bearer {owner_token}"}
        )
        self.assertEqual(missing.status_code, 404)

        cross_account_cases = (
            ("/accounts/102", owner_token, self.other_username),
            ("/accounts/103", owner_token, self.admin_username),
            ("/accounts/101", other_token, self.owner_username),
        )
        for path, token, victim_username in cross_account_cases:
            with self.subTest(path=path, victim=victim_username):
                response = self.client.get(
                    path, headers={"Authorization": f"Bearer {token}"}
                )
                self.assertIn(response.status_code, (403, 404))
                self.assertNotEqual(response.get_json().get("username"), victim_username)
                self.assertNotIn("email", response.get_json())
                self.assertNotIn("balance", response.get_json())

    def test_user_directory_requires_an_administrator(self):
        admin_token = self.login(self.admin_username, self.admin_password)
        legitimate = self.client.get(
            "/admin/users", headers={"Authorization": f"Bearer {admin_token}"}
        )
        self.assertEqual(legitimate.status_code, 200)
        self.assertEqual(set(legitimate.get_json().get("users", {})), set(USERS))

        standard_token = self.login(self.owner_username, self.owner_password)
        unauthorized_cases = (
            ("anonymous", None),
            ("invalid bearer token", "invalid-token"),
            ("standard user", standard_token),
        )
        for case_name, token in unauthorized_cases:
            with self.subTest(requester=case_name):
                headers = {} if token is None else {"Authorization": f"Bearer {token}"}
                response = self.client.get("/admin/users", headers=headers)
                self.assertIn(response.status_code, (401, 403))
                self.assertNotIn("users", response.get_json())


if __name__ == "__main__":
    unittest.main()
