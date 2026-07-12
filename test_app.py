import unittest

from werkzeug.security import check_password_hash

import app as sieve


class AuthenticationAndAuthorizationTests(unittest.TestCase):
    def setUp(self):
        sieve.app.config.update(TESTING=True)
        sieve.TOKENS.clear()
        self.client = sieve.app.test_client()

    def login(self, username, password):
        response = self.client.post(
            "/login", json={"username": username, "password": password}
        )
        self.assertEqual(200, response.status_code)
        return response.get_json()["token"]

    def test_login_rotates_unpredictable_tokens(self):
        first_token = self.login("alice", "alice-pw")
        second_token = self.login("alice", "alice-pw")

        own_account = self.client.get(
            "/accounts/1", headers={"Authorization": f"Bearer {second_token}"}
        )
        self.assertEqual(200, own_account.status_code)
        self.assertEqual("alice", own_account.get_json()["username"])

        self.assertNotEqual(first_token, second_token)
        guessed = self.client.get(
            "/accounts/3", headers={"Authorization": "Bearer token-3"}
        )
        self.assertEqual(401, guessed.status_code)

    def test_account_reads_require_ownership_or_admin_role(self):
        alice_token = self.login("alice", "alice-pw")
        own_account = self.client.get(
            "/accounts/1", headers={"Authorization": f"Bearer {alice_token}"}
        )
        self.assertEqual(200, own_account.status_code)

        other_account = self.client.get(
            "/accounts/2", headers={"Authorization": f"Bearer {alice_token}"}
        )
        self.assertEqual(403, other_account.status_code)

        admin_token = self.login("admin", "admin-pw")
        admin_read = self.client.get(
            "/accounts/2", headers={"Authorization": f"Bearer {admin_token}"}
        )
        self.assertEqual(200, admin_read.status_code)
        self.assertEqual("bob", admin_read.get_json()["username"])

    def test_user_directory_requires_admin_and_omits_credentials(self):
        anonymous = self.client.get("/admin/users")
        self.assertEqual(401, anonymous.status_code)

        alice_token = self.login("alice", "alice-pw")
        standard_user = self.client.get(
            "/admin/users", headers={"Authorization": f"Bearer {alice_token}"}
        )
        self.assertEqual(403, standard_user.status_code)

        admin_token = self.login("admin", "admin-pw")
        directory = self.client.get(
            "/admin/users", headers={"Authorization": f"Bearer {admin_token}"}
        )
        self.assertEqual(200, directory.status_code)
        for user in directory.get_json()["users"].values():
            self.assertNotIn("password", user)
            self.assertNotIn("password_hash", user)

    def test_seeded_passwords_are_hashed_at_rest(self):
        expected_passwords = {
            "alice": "alice-pw",
            "bob": "bob-pw",
            "admin": "admin-pw",
        }
        for username, password in expected_passwords.items():
            user = sieve.USERS[username]
            self.assertNotIn("password", user)
            self.assertTrue(check_password_hash(user["password_hash"], password))


if __name__ == "__main__":
    unittest.main()
