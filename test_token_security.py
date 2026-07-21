#!/usr/bin/env python3
"""Regression tests for the deterministic-token fix (TC-673AAEDC).

These tests fail (RED) on the vulnerable code (token = f"token-{user['id']}")
and pass (GREEN) after the fix (secrets.token_urlsafe):
  - Tokens issued for the same user are unique (non-deterministic).
  - A hand-crafted token-<id> string is rejected by authenticated endpoints.
"""
import unittest

from app import app


class TokenSecurityTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def _login(self, username, password):
        resp = self.client.post(
            "/login", json={"username": username, "password": password}
        )
        self.assertEqual(resp.status_code, 200, resp.get_json())
        return resp.get_json()["token"]

    def test_tokens_are_unique_per_login(self):
        token1 = self._login("alice", "alice-pw")
        token2 = self._login("alice", "alice-pw")
        self.assertNotEqual(token1, token2, "tokens must be non-deterministic")

    def test_token_is_not_id_based(self):
        token = self._login("admin", "admin-pw")
        self.assertFalse(
            token.startswith("token-"),
            "token must not be a deterministic id-based string",
        )

    def test_forged_id_based_token_rejected(self):
        """A hand-crafted token-<id> string must not authenticate."""
        # Ensure admin has logged in so token-3 would be valid on the old code
        self._login("admin", "admin-pw")
        resp = self.client.get(
            "/accounts/3", headers={"Authorization": "Bearer token-3"}
        )
        self.assertEqual(resp.status_code, 401, "forged token-3 must be rejected")

    def test_forged_token_for_other_user_rejected(self):
        self._login("alice", "alice-pw")
        resp = self.client.get(
            "/accounts/2", headers={"Authorization": "Bearer token-2"}
        )
        self.assertEqual(resp.status_code, 401, "forged token-2 must be rejected")

    def test_legitimate_token_still_works(self):
        token = self._login("alice", "alice-pw")
        resp = self.client.get(
            "/accounts/1", headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
