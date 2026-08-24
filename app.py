#!/usr/bin/env python3
"""
Sieve — a tiny API used as a local/CI smoke-test target for Niro
(https://github.com/apxlabs-ai/niro), the AI penetration tester.

⚠️  Do NOT deploy Sieve or expose it to the internet. It is deliberately weak
    and exists only for local or CI testing — run it on localhost, nowhere else.
"""
import math
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
TOKENS = {}  # token -> {"username": str, "expires_at": float}
SESSION_TTL_SECONDS = 3600

# Failed-login budget. Account state prevents online guessing against one user;
# source state prevents an attacker from bypassing that budget by rotating names.
LOGIN_FAILURES = {}
MAX_LOGIN_FAILURES = 5
LOGIN_FAILURE_WINDOW_SECONDS = 15 * 60
LOGIN_LOCKOUT_SECONDS = 15 * 60


@app.get("/")
def index():
    return jsonify(
        name="Sieve",
        warning="INTENTIONALLY VULNERABLE - localhost/CI smoke-test target only. Do not deploy.",
        endpoints=[
            "POST /login",
            "POST /logout",
            "GET /accounts/<id>",
            "GET /admin/users",
        ],
    )


@app.post("/login")
def login():
    body = request.get_json(force=True, silent=True) or {}
    username = body.get("username")
    now = time.time()
    failure_keys = [("source", request.remote_addr or "unknown")]
    if username in USERS:
        failure_keys.append(("account", username))

    remaining_lock = max(
        (_lock_remaining(key, now) for key in failure_keys), default=0
    )
    if remaining_lock:
        return (
            jsonify(error="too many attempts"),
            429,
            {"Retry-After": str(math.ceil(remaining_lock))},
        )

    user = USERS.get(username)
    if user and user["password"] == body.get("password"):
        # A successful login clears that account's retry budget, but preserves
        # source limits so one valid account cannot reset a spraying attack.
        _clear_failures(failure_keys[1:])

        # Re-authentication starts a new session and retires the old one.
        for token, session in list(TOKENS.items()):
            if session["username"] == username:
                del TOKENS[token]

        token = secrets.token_urlsafe(32)
        while token in TOKENS:  # Defensive even though collisions are infeasible.
            token = secrets.token_urlsafe(32)
        TOKENS[token] = {
            "username": username,
            "expires_at": now + SESSION_TTL_SECONDS,
        }
        return jsonify(token=token)

    _record_failure(failure_keys, now)
    return jsonify(error="invalid credentials"), 401


def _bearer_token():
    return request.headers.get("Authorization", "").removeprefix("Bearer ").strip()


def _current_session():
    token = _bearer_token()
    session = TOKENS.get(token)
    if session is None:
        return None
    if session["expires_at"] <= time.time():
        TOKENS.pop(token, None)
        return None
    return session


def _lock_remaining(key, now):
    state = LOGIN_FAILURES.get(key)
    if state is None:
        return 0
    return max(0, state["locked_until"] - now)


def _clear_failures(keys):
    for key in keys:
        LOGIN_FAILURES.pop(key, None)


def _record_failure(keys, now):
    for key in keys:
        state = LOGIN_FAILURES.setdefault(
            key,
            {
                "count": 0,
                "window_started_at": now,
                "locked_until": 0,
            },
        )
        if now - state["window_started_at"] >= LOGIN_FAILURE_WINDOW_SECONDS:
            state["count"] = 0
            state["window_started_at"] = now
        state["count"] += 1
        if state["count"] >= MAX_LOGIN_FAILURES:
            state["locked_until"] = now + LOGIN_LOCKOUT_SECONDS


# Return account details for the given id. A valid bearer token is required.
@app.get("/accounts/<int:account_id>")
def account(account_id):
    session = _current_session()
    if session is None:
        return jsonify(error="unauthorized"), 401

    user = USERS.get(session["username"])
    if user is None:
        return jsonify(error="unauthorized"), 401
    if account_id != user["id"] and not user.get("admin"):
        return jsonify(error="forbidden"), 403

    for username, target in USERS.items():
        if target["id"] == account_id:
            return jsonify(
                id=target["id"],
                username=username,
                email=target["email"],
                balance=target["balance"],
            )
    return jsonify(error="not found"), 404


@app.post("/logout")
def logout():
    token = _bearer_token()
    if _current_session() is None:
        return jsonify(error="unauthorized"), 401
    TOKENS.pop(token, None)
    return "", 204


# Return the full user directory.
@app.get("/admin/users")
def admin_users():
    session = _current_session()
    if session is None:
        return jsonify(error="unauthorized"), 401
    user = USERS.get(session["username"])
    if user is None or not user.get("admin"):
        return jsonify(error="forbidden"), 403

    public_fields = ("id", "email", "balance", "admin")
    return jsonify(
        users={
            username: {field: record[field] for field in public_fields}
            for username, record in USERS.items()
        }
    )


if __name__ == "__main__":
    # 0.0.0.0 so it is reachable from the pentest container; port 5000.
    app.run(host="0.0.0.0", port=5000)
