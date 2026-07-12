import unittest

import app as sieve


class SecurityRegressionTests(unittest.TestCase):
    def setUp(self):
        sieve.TOKENS.clear()
        self.client = sieve.app.test_client()

    def login(self, username, password):
        response = self.client.post(
            "/login", json={"username": username, "password": password}
        )
        self.assertEqual(response.status_code, 200)
        return response.get_json()["token"]

    @staticmethod
    def bearer(token):
        return {"Authorization": f"Bearer {token}"}

    def test_each_login_issues_a_fresh_unpredictable_token(self):
        first = self.login("alice", "alice-pw")
        second = self.login("alice", "alice-pw")

        self.assertNotEqual(first, second)
        self.assertNotEqual(first, "token-1")
        self.assertNotEqual(second, "token-1")

        response = self.client.get("/accounts/1", headers=self.bearer(second))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["username"], "alice")

    def test_account_reads_are_limited_to_the_owner(self):
        token = self.login("alice", "alice-pw")

        own = self.client.get("/accounts/1", headers=self.bearer(token))
        self.assertEqual(own.status_code, 200)
        self.assertEqual(own.get_json()["username"], "alice")

        other = self.client.get("/accounts/2", headers=self.bearer(token))
        self.assertEqual(other.status_code, 403)
        self.assertNotIn("bob", other.get_data(as_text=True))

    def test_admin_directory_requires_an_admin(self):
        admin_token = self.login("admin", "admin-pw")
        admin_response = self.client.get(
            "/admin/users", headers=self.bearer(admin_token)
        )
        self.assertEqual(admin_response.status_code, 200)
        self.assertIn("users", admin_response.get_json())

        anonymous = self.client.get("/admin/users")
        self.assertEqual(anonymous.status_code, 401)

        user_token = self.login("alice", "alice-pw")
        standard_user = self.client.get(
            "/admin/users", headers=self.bearer(user_token)
        )
        self.assertEqual(standard_user.status_code, 403)

    def test_admin_directory_never_serializes_passwords(self):
        token = self.login("admin", "admin-pw")
        response = self.client.get("/admin/users", headers=self.bearer(token))

        self.assertEqual(response.status_code, 200)
        users = response.get_json()["users"]
        self.assertTrue(users)
        for record in users.values():
            self.assertNotIn("password", record)


if __name__ == "__main__":
    unittest.main()
