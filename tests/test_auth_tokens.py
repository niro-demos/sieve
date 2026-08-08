import unittest

from app import TOKENS, USERS, app


class BearerTokenTests(unittest.TestCase):
    def setUp(self):
        TOKENS.clear()
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def tearDown(self):
        TOKENS.clear()

    def login(self, username):
        user = USERS[username]
        return self.client.post(
            "/login",
            json={"username": username, "password": user["password"]},
        )

    def account(self, account_id, token):
        return self.client.get(
            f"/accounts/{account_id}",
            headers={"Authorization": f"Bearer {token}"},
        )

    def test_account_id_derived_bearer_token_cannot_be_forged(self):
        admin = USERS["admin"]
        login_response = self.login("admin")
        self.assertEqual(login_response.status_code, 200)
        issued_token = login_response.get_json()["token"]

        legitimate_response = self.account(admin["id"], issued_token)
        self.assertEqual(legitimate_response.status_code, 200)
        self.assertEqual(legitimate_response.get_json()["username"], "admin")

        unrelated_token_response = self.account(
            admin["id"], "definitely-not-an-issued-token"
        )
        self.assertEqual(unrelated_token_response.status_code, 401)

        guessed_account_token = f"token-{admin['id']}"
        forged_response = self.account(admin["id"], guessed_account_token)
        self.assertEqual(forged_response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
