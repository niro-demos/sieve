import unittest

from app import TOKENS, app


class AdminUsersTests(unittest.TestCase):
    def setUp(self):
        TOKENS.clear()
        self.client = app.test_client()

    def login(self, username, password):
        response = self.client.post(
            "/login",
            json={"username": username, "password": password},
        )
        self.assertEqual(response.status_code, 200)
        token = response.get_json()["token"]
        return {"Authorization": f"Bearer {token}"}

    def assert_no_passwords(self, payload):
        users = payload.get("users", {})
        leaked = sorted(
            username
            for username, record in users.items()
            if isinstance(record, dict) and "password" in record
        )
        self.assertEqual(leaked, [], f"password fields leaked for {leaked}")

    def test_controls_preserve_login_and_account_authentication(self):
        admin_headers = self.login("admin", "admin-pw")

        unauthorized = self.client.get("/accounts/1")
        self.assertEqual(unauthorized.status_code, 401)

        authorized = self.client.get("/accounts/1", headers=admin_headers)
        self.assertEqual(authorized.status_code, 200)
        self.assertNotIn("password", authorized.get_json())

    def test_admin_users_rejects_unauthenticated_callers(self):
        response = self.client.get("/admin/users")

        self.assertEqual(response.status_code, 401)
        self.assert_no_passwords(response.get_json() or {})

    def test_admin_users_rejects_non_admin_callers(self):
        alice_headers = self.login("alice", "alice-pw")

        response = self.client.get("/admin/users", headers=alice_headers)

        self.assertEqual(response.status_code, 403)
        self.assert_no_passwords(response.get_json() or {})

    def test_admin_users_allows_admins_without_returning_passwords(self):
        admin_headers = self.login("admin", "admin-pw")

        response = self.client.get("/admin/users", headers=admin_headers)

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(
            payload["users"]["admin"],
            {"admin": True, "email": "admin@sieve.test", "id": 3},
        )
        self.assert_no_passwords(payload)


if __name__ == "__main__":
    unittest.main()
