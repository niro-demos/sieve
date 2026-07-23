#!/usr/bin/env python3
"""
Sieve — a tiny API used as a local/CI smoke-test target for Niro
(https://github.com/apxlabs-ai/niro), the AI penetration tester.

⚠️  Do NOT deploy Sieve or expose it to the internet. It is deliberately weak
    and exists only for local or CI testing — run it on localhost, nowhere else.
"""
import math
import time
from threading import Lock

from flask import Flask, request, jsonify

app = Flask(__name__)

# Seeded, in-memory "database" — no persistence, instant start.
USERS = {
    "alice": {"id": 1, "password": "alice-pw", "email": "alice@sieve.test", "balance": 100,  "admin": False},
    "bob":   {"id": 2, "password": "bob-pw",   "email": "bob@sieve.test",   "balance": 8400, "admin": False},
    "admin": {"id": 3, "password": "admin-pw", "email": "admin@sieve.test", "balance": 0,    "admin": True},
}
TOKENS = {}  # token -> username
LOGIN_FAILURE_LIMIT = 5
LOGIN_LOCKOUT_SECONDS = 60
LOGIN_FAILURES = {}  # normalized username -> {"count": int, "locked_until": float}
LOGIN_FAILURES_LOCK = Lock()


def _login_key(username):
    if not isinstance(username, str):
        return ""
    return username.strip().casefold()


def _lockout_response(locked_until, now=None):
    now = time.monotonic() if now is None else now
    retry_after = max(1, math.ceil(locked_until - now))
    response = jsonify(error="too many login attempts")
    response.status_code = 429
    response.headers["Retry-After"] = str(retry_after)
    return response


def _active_lockout_for(key, now):
    record = LOGIN_FAILURES.get(key)
    if not record:
        return None

    locked_until = record.get("locked_until", 0)
    if locked_until > now:
        return locked_until

    if locked_until:
        LOGIN_FAILURES.pop(key, None)
    return None


def _record_failed_login(key, now):
    record = LOGIN_FAILURES.get(key, {"count": 0, "locked_until": 0})
    count = record["count"] + 1
    locked_until = 0
    if count >= LOGIN_FAILURE_LIMIT:
        locked_until = now + LOGIN_LOCKOUT_SECONDS
    LOGIN_FAILURES[key] = {"count": count, "locked_until": locked_until}
    return locked_until or None


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
    username = _login_key(body.get("username"))

    with LOGIN_FAILURES_LOCK:
        now = time.monotonic()
        locked_until = _active_lockout_for(username, now)
    if locked_until:
        return _lockout_response(locked_until, now)

    user = USERS.get(username)
    if user and user["password"] == body.get("password"):
        token = f"token-{user['id']}"
        TOKENS[token] = username
        with LOGIN_FAILURES_LOCK:
            LOGIN_FAILURES.pop(username, None)
        return jsonify(token=token)

    with LOGIN_FAILURES_LOCK:
        now = time.monotonic()
        locked_until = _active_lockout_for(username, now)
        if not locked_until:
            locked_until = _record_failed_login(username, now)
    if locked_until:
        return _lockout_response(locked_until, now)

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
