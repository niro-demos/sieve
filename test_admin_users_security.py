#!/usr/bin/env python3
"""Regression tests for the /admin/users access-control and password-leak fixes.

These tests fail (RED) on the vulnerable code and pass (GREEN) after the fix:
  - TC-23CC9BA1: /admin/users must require a valid admin bearer token.
  - TC-9DE5E0D1: /admin/users must never include a password field in the response.
"""
import json
import unittest

from app import app


class AdminUsersSecurityTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def _login(self, username, password):
        resp = self.client.post(
            "/login", json={"username": username, "password": password}
        )
        self.assertEqual(resp.status_code, 200, resp.get_json())
        return resp.get_json()["token"]

    # --- TC-23CC9BA1: authentication & authorization gate ---

    def test_no_auth_token_returns_401(self):
        resp = self.client.get("/admin/users")
        self.assertEqual(resp.status_code, 401)

    def test_garbage_token_returns_401(self):
        resp = self.client.get(
            "/admin/users", headers={"Authorization": "Bearer garbage"}
        )
        self.assertEqual(resp.status_code, 401)

    def test_non_admin_token_returns_403(self):
        token = self._login("alice", "alice-pw")
        resp = self.client.get(
            "/admin/users", headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(resp.status_code, 403)

    def test_admin_token_returns_200(self):
        token = self._login("admin", "admin-pw")
        resp = self.client.get(
            "/admin/users", headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(resp.status_code, 200)

    # --- TC-9DE5E0D1: no password field in response ---

    def test_response_has_no_password_field(self):
        token = self._login("admin", "admin-pw")
        resp = self.client.get(
            "/admin/users", headers={"Authorization": f"Bearer {token}"}
        )
        body = resp.get_json()
        for username, user_data in body["users"].items():
            self.assertNotIn(
                "password", user_data, f"password field present for {username}"
            )

    def test_unauthenticated_response_has_no_password_field(self):
        """Even a 401 response body must not leak user data."""
        resp = self.client.get("/admin/users")
        body = resp.get_json()
        self.assertNotIn("users", body)


if __name__ == "__main__":
    unittest.main()
