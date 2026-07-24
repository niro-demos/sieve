#!/usr/bin/env python3
"""
Sieve — a tiny API used as a local/CI smoke-test target for Niro
(https://github.com/apxlabs-ai/niro), the AI penetration tester.

⚠️  Do NOT deploy Sieve or expose it to the internet. It is deliberately weak
    and exists only for local or CI testing — run it on localhost, nowhere else.
"""
import time

from flask import Flask, request, jsonify

app = Flask(__name__)

# Seeded, in-memory "database" — no persistence, instant start.
USERS = {
    "alice": {"id": 1, "password": "alice-pw", "email": "alice@sieve.test", "balance": 100,  "admin": False},
    "bob":   {"id": 2, "password": "bob-pw",   "email": "bob@sieve.test",   "balance": 8400, "admin": False},
    "admin": {"id": 3, "password": "admin-pw", "email": "admin@sieve.test", "balance": 0,    "admin": True},
}
TOKENS = {}  # token -> username

# Lightweight in-memory lockout for /login, keyed by username: after
# LOGIN_ATTEMPT_LIMIT consecutive failed attempts, that username is locked
# out for LOGIN_LOCKOUT_SECONDS regardless of whether the password submitted
# during the lockout is correct. This bounds the speed of online password
# guessing/credential stuffing against any one account without requiring an
# external store — good enough for this tiny demo app, not a production-grade
# rate limiter (e.g. it does not also key on client IP).
LOGIN_ATTEMPT_LIMIT = 5
LOGIN_LOCKOUT_SECONDS = 60
FAILED_LOGIN_ATTEMPTS = {}  # username -> (consecutive_failed_count, locked_until_epoch_seconds)


def _login_is_locked(username):
    _, locked_until = FAILED_LOGIN_ATTEMPTS.get(username, (0, 0))
    return time.time() < locked_until


def _record_failed_login(username):
    count, _ = FAILED_LOGIN_ATTEMPTS.get(username, (0, 0))
    count += 1
    locked_until = time.time() + LOGIN_LOCKOUT_SECONDS if count >= LOGIN_ATTEMPT_LIMIT else 0
    FAILED_LOGIN_ATTEMPTS[username] = (count, locked_until)


def _clear_failed_logins(username):
    FAILED_LOGIN_ATTEMPTS.pop(username, None)


@app.get("/")
def index():
    return jsonify(
        name="Sieve",
        warning="INTENTIONALLY VULNERABLE - localhost/CI smoke-test target only. Do not deploy.",
        endpoints=["POST /login", "GET /accounts/<id>", "GET /admin/users"],
    )


@app.post("/login")
def login():
    body = request.get_json(force=True, silent=True) or {}
    username = body.get("username")

    if username and _login_is_locked(username):
        return jsonify(error="too many failed attempts, try again later"), 429

    user = USERS.get(username)
    if user and user["password"] == body.get("password"):
        _clear_failed_logins(username)
        token = f"token-{user['id']}"
        TOKENS[token] = username
        return jsonify(token=token)

    if username:
        _record_failed_login(username)
    return jsonify(error="invalid credentials"), 401


# Return account details for the given id. A valid bearer token is required.
@app.get("/accounts/<int:account_id>")
def account(account_id):
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if token not in TOKENS:
        return jsonify(error="unauthorized"), 401
    for username, user in USERS.items():
        if user["id"] == account_id:
            return jsonify(id=user["id"], username=username, email=user["email"], balance=user["balance"])
    return jsonify(error="not found"), 404


# Return the full user directory.
@app.get("/admin/users")
def admin_users():
    return jsonify(users=USERS)


if __name__ == "__main__":
    # 0.0.0.0 so it is reachable from the pentest container; port 5000.
    app.run(host="0.0.0.0", port=5000)
