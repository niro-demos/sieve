import unittest

import app as sieve


class LoginThrottlingTest(unittest.TestCase):
    def setUp(self):
        sieve.TOKENS.clear()
        if hasattr(sieve, "LOGIN_FAILURES"):
            sieve.LOGIN_FAILURES.clear()
        self.client = sieve.app.test_client()

    def login(self, username, password, client_ip):
        return self.client.post(
            "/login",
            json={"username": username, "password": password},
            environ_base={"REMOTE_ADDR": client_ip},
        )

    def assert_valid_login(self, username, password, client_ip):
        response = self.login(username, password, client_ip)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertIsInstance(response.get_json().get("token"), str)

    def test_invalid_password_attempts_are_bounded_per_account_and_client(self):
        attacker_ip = "203.0.113.77"
        other_ip = "203.0.113.88"

        self.assert_valid_login("alice", "alice-pw", other_ip)
        self.assert_valid_login("bob", "bob-pw", attacker_ip)

        final_response = None
        for attempt in range(6):
            final_response = self.login(
                "alice",
                f"TC-5120238D-invalid-password-{attempt}",
                attacker_ip,
            )

        self.assertEqual(final_response.status_code, 429, final_response.get_data(as_text=True))
        self.assertIn("too many", final_response.get_json()["error"].lower())

        locked_response = self.login("alice", "alice-pw", attacker_ip)
        self.assertEqual(locked_response.status_code, 429, locked_response.get_data(as_text=True))

        self.assert_valid_login("alice", "alice-pw", other_ip)
        self.assert_valid_login("bob", "bob-pw", attacker_ip)


if __name__ == "__main__":
    unittest.main()
