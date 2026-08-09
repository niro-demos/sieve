#!/usr/bin/env python3
"""
Sieve — a tiny API used as a local/CI smoke-test target for Niro
(https://github.com/apxlabs-ai/niro), the AI penetration tester.

⚠️  Do NOT deploy Sieve or expose it to the internet. It is deliberately weak
    and exists only for local or CI testing — run it on localhost, nowhere else.
"""
from time import time

from flask import Flask, request, jsonify

app = Flask(__name__)

# Seeded, in-memory "database" — no persistence, instant start.
USERS = {
    "alice": {"id": 1, "password": "alice-pw", "email": "alice@sieve.test", "balance": 100,  "admin": False},
    "bob":   {"id": 2, "password": "bob-pw",   "email": "bob@sieve.test",   "balance": 8400, "admin": False},
    "admin": {"id": 3, "password": "admin-pw", "email": "admin@sieve.test", "balance": 0,    "admin": True},
}
TOKENS = {}  # token -> username

# Per-username failed-login tracking for brute-force throttling (TC-21EB3215).
# In-memory, matching the app's existing USERS/TOKENS pattern; for a real
# deployment back this with a shared store (e.g. Redis) so it survives
# restarts and works across multiple app instances.
FAILED_ATTEMPTS = {}  # username -> (count, first_failure_ts)
LOCKOUT_THRESHOLD = 5
LOCKOUT_WINDOW_SECONDS = 60


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
    now = time()

    count, first_ts = FAILED_ATTEMPTS.get(username, (0, now))
    if count >= LOCKOUT_THRESHOLD and now - first_ts < LOCKOUT_WINDOW_SECONDS:
        return jsonify(error="too many attempts, try again later"), 429

    user = USERS.get(username)
    if user and user["password"] == body.get("password"):
        FAILED_ATTEMPTS.pop(username, None)
        token = f"token-{user['id']}"
        TOKENS[token] = username
        return jsonify(token=token)

    if now - first_ts >= LOCKOUT_WINDOW_SECONDS:
        count, first_ts = 0, now
    FAILED_ATTEMPTS[username] = (count + 1, first_ts)
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
