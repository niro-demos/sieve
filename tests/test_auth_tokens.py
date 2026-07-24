import unittest

from app import TOKENS, app


class LoginTokenTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()
        TOKENS.clear()

    def login(self, username, password):
        response = self.client.post(
            "/login",
            json={"username": username, "password": password},
        )
        self.assertEqual(response.status_code, 200)
        token = response.get_json()["token"]
        self.assertTrue(token)
        return token

    def get_account(self, account_id, token):
        return self.client.get(
            f"/accounts/{account_id}",
            headers={"Authorization": f"Bearer {token}"},
        )

    def test_login_issues_unique_unpredictable_tokens(self):
        first_token = self.login("bob", "bob-pw")
        second_token = self.login("bob", "bob-pw")

        self.assertNotEqual(first_token, second_token)
        self.assertNotEqual(first_token, "token-2")
        self.assertNotEqual(second_token, "token-2")

    def test_predicted_account_token_cannot_read_profile(self):
        issued_token = self.login("bob", "bob-pw")

        predicted_response = self.get_account(2, "token-2")
        self.assertEqual(predicted_response.status_code, 401)

        legitimate_response = self.get_account(2, issued_token)
        self.assertEqual(legitimate_response.status_code, 200)
        self.assertEqual(legitimate_response.get_json()["username"], "bob")


if __name__ == "__main__":
    unittest.main()
