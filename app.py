#!/usr/bin/env python3
"""
Sieve — a tiny API used as a local/CI smoke-test target for Niro
(https://github.com/apxlabs-ai/niro), the AI penetration tester.

⚠️  Do NOT deploy Sieve or expose it to the internet. It is deliberately weak
    and exists only for local or CI testing — run it on localhost, nowhere else.
"""
import secrets
import threading
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
LOGIN_FAILURES = {}  # (dimension, value) -> monotonic failure timestamps
LOGIN_LOCK = threading.Lock()
LOGIN_FAILURE_LIMIT = 5
LOGIN_FAILURE_WINDOW_SECONDS = 60
FAILED_LOGIN_DELAY_SECONDS = 0.05


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
    source_ip = request.remote_addr or "unknown"
    failure_keys = (("username", username), ("source_ip", source_ip))
    now = time.monotonic()

    with LOGIN_LOCK:
        recent_failures = {}
        for failure_key in failure_keys:
            recent_failures[failure_key] = [
                failed_at
                for failed_at in LOGIN_FAILURES.get(failure_key, [])
                if now - failed_at < LOGIN_FAILURE_WINDOW_SECONDS
            ]
            LOGIN_FAILURES[failure_key] = recent_failures[failure_key]

        if any(
            len(failures) >= LOGIN_FAILURE_LIMIT
            for failures in recent_failures.values()
        ):
            return (
                jsonify(error="too many login attempts"),
                429,
                {"Retry-After": str(LOGIN_FAILURE_WINDOW_SECONDS)},
            )

        user = USERS.get(username)
        if not user or not secrets.compare_digest(
            user["password"], str(body.get("password", ""))
        ):
            for failure_key in failure_keys:
                recent_failures[failure_key].append(now)
                LOGIN_FAILURES[failure_key] = recent_failures[failure_key]
        else:
            for failure_key in failure_keys:
                LOGIN_FAILURES.pop(failure_key, None)
            token = secrets.token_urlsafe(32)
            TOKENS[token] = username

    if user and secrets.compare_digest(
        user["password"], str(body.get("password", ""))
    ):
        return jsonify(token=token)

    time.sleep(FAILED_LOGIN_DELAY_SECONDS)
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
