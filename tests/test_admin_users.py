import unittest

from app import TOKENS, app


class AdminUsersTest(unittest.TestCase):
    def setUp(self):
        TOKENS.clear()
        self.client = app.test_client()

    def login(self, username, password):
        response = self.client.post(
            "/login",
            json={"username": username, "password": password},
        )
        self.assertEqual(response.status_code, 200)
        return response.get_json()["token"]

    def test_admin_directory_rejects_unauthenticated_callers(self):
        response = self.client.get("/admin/users")

        self.assertEqual(response.status_code, 401)

    def test_admin_directory_rejects_standard_users(self):
        token = self.login("alice", "alice-pw")

        response = self.client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 403)

    def test_admin_directory_allows_admins_without_password_fields(self):
        token = self.login("admin", "admin-pw")

        response = self.client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 200)
        users = response.get_json()["users"]
        self.assertIn("admin", users)
        for user in users.values():
            self.assertNotIn("password", user)


if __name__ == "__main__":
    unittest.main()
