import unittest

from app import TOKENS, USERS, app


class AdminUsersEndpointTest(unittest.TestCase):
    def setUp(self):
        TOKENS.clear()
        self.client = app.test_client()

    def login(self, username):
        response = self.client.post(
            "/login",
            json={"username": username, "password": USERS[username]["password"]},
        )
        self.assertEqual(response.status_code, 200)
        return response.get_json()["token"]

    def assert_no_user_directory(self, response):
        payload = response.get_json()
        users = payload.get("users") if isinstance(payload, dict) else None
        self.assertIsNone(users)

    def assert_passwords_omitted(self, payload):
        self.assertIsInstance(payload.get("users"), dict)
        for username, user in payload["users"].items():
            with self.subTest(username=username):
                self.assertNotIn("password", user)

    def test_admin_users_requires_valid_bearer_token(self):
        for headers in ({}, {"Authorization": "Bearer intentionally-invalid-token"}):
            with self.subTest(headers=headers):
                response = self.client.get("/admin/users", headers=headers)

                self.assertEqual(response.status_code, 401)
                self.assert_no_user_directory(response)

    def test_admin_users_requires_admin_principal(self):
        alice_token = self.login("alice")

        response = self.client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {alice_token}"},
        )

        self.assertEqual(response.status_code, 403)
        self.assert_no_user_directory(response)

    def test_admin_users_allows_admin_without_password_fields(self):
        admin_token = self.login("admin")

        response = self.client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(payload["users"]), {"alice", "bob", "admin"})
        self.assert_passwords_omitted(payload)


if __name__ == "__main__":
    unittest.main()
