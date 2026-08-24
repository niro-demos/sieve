#!/usr/bin/env python3
"""Security regression tests for Sieve's authentication and authorization."""

import secrets
import time
import unittest
from copy import deepcopy

import app


class SieveSecurityTestCase(unittest.TestCase):
    def setUp(self):
        self.users = {
            "owner": {
                "id": 101,
                "password": secrets.token_urlsafe(24),
                "email": "owner@example.test",
                "balance": 100,
                "admin": False,
            },
            "other": {
                "id": 202,
                "password": secrets.token_urlsafe(24),
                "email": "other@example.test",
                "balance": 200,
                "admin": False,
            },
            "administrator": {
                "id": 303,
                "password": secrets.token_urlsafe(24),
                "email": "administrator@example.test",
                "balance": 300,
                "admin": True,
            },
        }

        app.USERS.clear()
        app.USERS.update(deepcopy(self.users))
        app.TOKENS.clear()
        getattr(app, "LOGIN_FAILURES", {}).clear()
        self.client = app.app.test_client()

    def login(self, username, password=None):
        response = self.client.post(
            "/login",
            json={
                "username": username,
                "password": self.users[username]["password"]
                if password is None
                else password,
            },
        )
        self.assertEqual(response.status_code, 200, response.get_json())
        token = response.get_json().get("token")
        self.assertIsInstance(token, str)
        self.assertTrue(token)
        return token

    def request_account(self, account_id, token=None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return self.client.get(f"/accounts/{account_id}", headers=headers)

    def login_from_source(self, username, source_ip, password=None):
        return self.client.post(
            "/login",
            json={
                "username": username,
                "password": self.users[username]["password"]
                if password is None
                else password,
            },
            environ_base={"REMOTE_ADDR": source_ip},
        )


class SessionSecurityTests(SieveSecurityTestCase):
    def test_relogin_rotates_the_session_token(self):
        first_token = self.login("owner")
        self.assertEqual(self.request_account(101, first_token).status_code, 200)

        second_token = self.login("owner")
        self.assertNotEqual(first_token, second_token)
        self.assertEqual(
            self.request_account(101, first_token).status_code,
            401,
            "re-authentication must retire the previous token",
        )
        self.assertEqual(self.request_account(101, second_token).status_code, 200)

    def test_expired_session_is_rejected(self):
        token = self.login("owner")
        session = app.TOKENS.get(token)
        expired_at = time.time() - 1
        if isinstance(session, dict):
            session["expires_at"] = expired_at
        else:
            app.TOKENS[token] = {"username": "owner", "expires_at": expired_at}

        response = self.request_account(101, token)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json(), {"error": "unauthorized"})

    def test_logout_revokes_the_session(self):
        token = self.login("owner")
        self.assertEqual(self.request_account(101, token).status_code, 200)

        response = self.client.post(
            "/logout", headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(response.status_code, 204)
        self.assertEqual(self.request_account(101, token).status_code, 401)


class TokenPredictabilityTests(SieveSecurityTestCase):
    def test_sequential_user_id_is_not_a_valid_token(self):
        attacker_token = self.login("owner")
        self.assertEqual(self.request_account(101, attacker_token).status_code, 200)

        victim_token = self.login("other")
        guessed_token = f"token-{self.users['other']['id']}"
        self.assertNotEqual(guessed_token, victim_token)
        self.assertEqual(
            self.request_account(202, guessed_token).status_code,
            401,
            "a token reconstructed from the sequential user id must be rejected",
        )
        self.assertEqual(self.request_account(202, victim_token).status_code, 200)


class LoginThrottlingTests(SieveSecurityTestCase):
    def test_repeated_failures_lock_the_account(self):
        self.login("owner")
        wrong_password = secrets.token_urlsafe(24)
        limit = getattr(app, "MAX_LOGIN_FAILURES", 5)

        for _ in range(limit):
            response = self.client.post(
                "/login",
                json={"username": "owner", "password": wrong_password},
            )
            self.assertEqual(response.status_code, 401)

        response = self.client.post(
            "/login", json={"username": "owner", "password": wrong_password}
        )
        self.assertEqual(response.status_code, 429)
        retry_after = response.headers.get("Retry-After")
        self.assertIsNotNone(retry_after)
        self.assertGreater(int(retry_after), 0)

        # Correct credentials must not bypass a lockout once it has engaged.
        response = self.client.post(
            "/login",
            json={
                "username": "owner",
                "password": self.users["owner"]["password"],
            },
        )
        self.assertEqual(response.status_code, 429)

    def test_source_limit_bounds_username_rotation(self):
        limit = getattr(app, "MAX_LOGIN_FAILURES", 5)
        attacker_ip = "203.0.113.10"
        self.assertEqual(
            self.login_from_source("owner", attacker_ip).status_code,
            200,
        )

        wrong_password = secrets.token_urlsafe(24)
        for username in ("owner", "other"):
            attempts = limit - 1 if username == "owner" else 1
            for attempt in range(attempts):
                response = self.login_from_source(
                    username,
                    attacker_ip,
                    f"{wrong_password}-{attempt}",
                )
                self.assertEqual(response.status_code, 401)

        # A valid login from the same source must not reset its retry budget.
        response = self.login_from_source("owner", attacker_ip)
        self.assertEqual(response.status_code, 429)

        # The budget is source-specific and does not lock an unrelated network.
        response = self.login_from_source("owner", "203.0.113.20")
        self.assertEqual(response.status_code, 200)


class AccountAuthorizationTests(SieveSecurityTestCase):
    def test_standard_users_cannot_read_other_accounts(self):
        owner_token = self.login("owner")
        other_token = self.login("other")

        self.assertEqual(self.request_account(101, owner_token).status_code, 200)
        self.assertEqual(self.request_account(202, other_token).status_code, 200)

        for token, account_id in ((owner_token, 202), (other_token, 101)):
            with self.subTest(token=token, account_id=account_id):
                response = self.request_account(account_id, token)
                self.assertEqual(response.status_code, 403)
                payload = response.get_json()
                self.assertEqual(payload, {"error": "forbidden"})
                self.assertNotIn("other@example.test", str(payload))
                self.assertNotIn("owner@example.test", str(payload))


class AdminDirectoryAuthorizationTests(SieveSecurityTestCase):
    def test_unauthenticated_caller_cannot_read_user_directory(self):
        response = self.client.get("/admin/users")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json(), {"error": "unauthorized"})

    def test_directory_requires_admin_and_never_returns_credentials(self):
        standard_token = self.login("owner")
        response = self.client.get(
            "/admin/users", headers={"Authorization": f"Bearer {standard_token}"}
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json(), {"error": "forbidden"})

        admin_token = self.login("administrator")
        response = self.client.get(
            "/admin/users", headers={"Authorization": f"Bearer {admin_token}"}
        )
        self.assertEqual(response.status_code, 200)
        directory = response.get_json()["users"]
        self.assertEqual(set(directory), set(self.users))
        for username, user in directory.items():
            with self.subTest(username=username):
                self.assertNotIn("password", user)
                response_text = response.get_data(as_text=True)
                self.assertNotIn(self.users[username]["password"], response_text)


if __name__ == "__main__":
    unittest.main()
