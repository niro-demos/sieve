import unittest

import app as sieve


class LoginSecurityTest(unittest.TestCase):
    def setUp(self):
        sieve.TOKENS.clear()
        if hasattr(sieve, "LOGIN_FAILURES"):
            sieve.LOGIN_FAILURES.clear()
        self.client = sieve.app.test_client()

    def login(self, password, username="alice"):
        return self.client.post(
            "/login",
            json={"username": username, "password": password},
            environ_base={"REMOTE_ADDR": "192.0.2.10"},
        )

    def test_login_issues_fresh_unpredictable_bearer_tokens(self):
        first = self.login("alice-pw")
        second = self.login("alice-pw")

        self.assertEqual(200, first.status_code)
        self.assertEqual(200, second.status_code)
        first_token = first.get_json()["token"]
        second_token = second.get_json()["token"]

        self.assertNotEqual("token-1", first_token)
        self.assertNotEqual(first_token, second_token)
        self.assertGreaterEqual(len(first_token), 32)

        legitimate = self.client.get(
            "/accounts/1", headers={"Authorization": f"Bearer {first_token}"}
        )
        guessed = self.client.get(
            "/accounts/1", headers={"Authorization": "Bearer token-1"}
        )
        self.assertEqual(200, legitimate.status_code)
        self.assertEqual(401, guessed.status_code)

    def test_repeated_failures_temporarily_throttle_login(self):
        for attempt in range(5):
            response = self.login(f"wrong-{attempt}")
            self.assertEqual(401, response.status_code)

        throttled_guess = self.login("wrong-5")
        throttled_correct_password = self.login("alice-pw")

        self.assertEqual(429, throttled_guess.status_code)
        self.assertEqual(429, throttled_correct_password.status_code)
        self.assertEqual("60", throttled_guess.headers.get("Retry-After"))

    def test_failures_are_tracked_by_username_and_source(self):
        for attempt in range(5):
            self.login(f"wrong-{attempt}")

        same_source = self.login("bob-pw", username="bob")
        same_username = self.client.post(
            "/login",
            json={"username": "alice", "password": "alice-pw"},
            environ_base={"REMOTE_ADDR": "198.51.100.20"},
        )
        unrelated = self.client.post(
            "/login",
            json={"username": "bob", "password": "bob-pw"},
            environ_base={"REMOTE_ADDR": "198.51.100.20"},
        )

        self.assertEqual(429, same_source.status_code)
        self.assertEqual(429, same_username.status_code)
        self.assertEqual(200, unrelated.status_code)


if __name__ == "__main__":
    unittest.main()
