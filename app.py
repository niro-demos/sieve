#!/usr/bin/env python3
"""
Sieve — a tiny API used as a local/CI smoke-test target for Niro
(https://github.com/apxlabs-ai/niro), the AI penetration tester.

⚠️  Do NOT deploy Sieve or expose it to the internet. It is deliberately weak
    and exists only for local or CI testing — run it on localhost, nowhere else.
"""
import secrets
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
LOGIN_FAILURES = {}  # (normalized username, client IP) -> monotonic timestamps
LOGIN_FAILURE_LIMIT = 5
LOGIN_FAILURE_WINDOW_SECONDS = 15 * 60


def authenticated_username():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    return TOKENS.get(token)


def public_user(user):
    """Return the allowlisted API representation of a stored user."""
    return {
        key: user[key]
        for key in ("id", "email", "balance", "admin")
    }


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
    normalized_username = username.casefold() if isinstance(username, str) else ""
    failure_key = (normalized_username, request.remote_addr or "unknown")
    now = time.monotonic()
    recent_failures = [
        timestamp
        for timestamp in LOGIN_FAILURES.get(failure_key, [])
        if now - timestamp < LOGIN_FAILURE_WINDOW_SECONDS
    ]
    if len(recent_failures) >= LOGIN_FAILURE_LIMIT:
        LOGIN_FAILURES[failure_key] = recent_failures
        return jsonify(error="too many login attempts"), 429

    user = USERS.get(normalized_username)
    if user and user["password"] == body.get("password"):
        LOGIN_FAILURES.pop(failure_key, None)
        for old_token, token_username in list(TOKENS.items()):
            if token_username == normalized_username:
                del TOKENS[old_token]
        token = secrets.token_urlsafe(32)
        TOKENS[token] = normalized_username
        return jsonify(token=token)
    recent_failures.append(now)
    LOGIN_FAILURES[failure_key] = recent_failures
    return jsonify(error="invalid credentials"), 401


# Return account details for the given id. A valid bearer token is required.
@app.get("/accounts/<int:account_id>")
def account(account_id):
    if authenticated_username() is None:
        return jsonify(error="unauthorized"), 401
    for username, user in USERS.items():
        if user["id"] == account_id:
            return jsonify(id=user["id"], username=username, email=user["email"], balance=user["balance"])
    return jsonify(error="not found"), 404


# Return the full user directory.
@app.get("/admin/users")
def admin_users():
    username = authenticated_username()
    if username is None:
        return jsonify(error="unauthorized"), 401
    if not USERS[username]["admin"]:
        return jsonify(error="forbidden"), 403
    return jsonify(
        users={username: public_user(user) for username, user in USERS.items()}
    )


if __name__ == "__main__":
    # 0.0.0.0 so it is reachable from the pentest container; port 5000.
    app.run(host="0.0.0.0", port=5000)
