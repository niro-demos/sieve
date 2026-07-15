import unittest

import app as sieve


class SecurityRegressionTests(unittest.TestCase):
    def setUp(self):
        sieve.app.config.update(TESTING=True)
        sieve.TOKENS.clear()
        if hasattr(sieve, "LOGIN_FAILURES"):
            sieve.LOGIN_FAILURES.clear()
        self.client = sieve.app.test_client()

    def login(self, username, password, *, remote_addr="127.0.0.1"):
        return self.client.post(
            "/login",
            json={"username": username, "password": password},
            environ_base={"REMOTE_ADDR": remote_addr},
        )

    def test_repeated_login_failures_are_rate_limited(self):
        self.assertEqual(self.login("alice", "alice-pw").status_code, 200)

        failures = [
            self.login("alice", f"wrong-{attempt}").status_code
            for attempt in range(6)
        ]

        self.assertEqual(failures[:5], [401] * 5)
        self.assertEqual(failures[5], 429)
        self.assertEqual(
            self.login("alice", "wrong-again", remote_addr="192.0.2.10").status_code,
            401,
        )

    def test_login_tokens_are_opaque_rotate_and_revoke(self):
        first = self.login("bob", "bob-pw")
        second = self.login("bob", "bob-pw")
        self.assertEqual((first.status_code, second.status_code), (200, 200))

        first_token = first.get_json()["token"]
        second_token = second.get_json()["token"]
        self.assertNotEqual(first_token, second_token)
        self.assertNotEqual(second_token, "token-2")
        self.assertGreaterEqual(len(second_token), 32)
        self.assertEqual(
            self.client.get(
                "/accounts/2", headers={"Authorization": "Bearer token-2"}
            ).status_code,
            401,
        )
        self.assertEqual(
            self.client.get(
                "/accounts/2", headers={"Authorization": f"Bearer {first_token}"}
            ).status_code,
            401,
        )
        self.assertEqual(
            self.client.get(
                "/accounts/2", headers={"Authorization": f"Bearer {second_token}"}
            ).status_code,
            200,
        )

    def test_directory_never_serializes_passwords(self):
        token = self.login("admin", "admin-pw").get_json()["token"]
        response = self.client.get(
            "/admin/users", headers={"Authorization": f"Bearer {token}"}
        )

        self.assertEqual(response.status_code, 200)
        users = response.get_json()["users"]
        self.assertTrue(users)
        self.assertTrue(all("email" in user for user in users.values()))
        self.assertTrue(all("password" not in user for user in users.values()))

    def test_directory_requires_an_administrator(self):
        anonymous = self.client.get("/admin/users")
        user_token = self.login("alice", "alice-pw").get_json()["token"]
        non_admin = self.client.get(
            "/admin/users", headers={"Authorization": f"Bearer {user_token}"}
        )
        admin_token = self.login("admin", "admin-pw").get_json()["token"]
        admin = self.client.get(
            "/admin/users", headers={"Authorization": f"Bearer {admin_token}"}
        )

        self.assertEqual(anonymous.status_code, 401)
        self.assertNotIn("users", anonymous.get_json())
        self.assertEqual(non_admin.status_code, 403)
        self.assertNotIn("users", non_admin.get_json())
        self.assertEqual(admin.status_code, 200)
        self.assertIn("users", admin.get_json())


if __name__ == "__main__":
    unittest.main()
