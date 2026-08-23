#!/usr/bin/env python3
"""
Sieve — a tiny API used as a local/CI smoke-test target for Niro
(https://github.com/apxlabs-ai/niro), the AI penetration tester.

⚠️  Do NOT deploy Sieve or expose it to the internet. It is deliberately weak
    and exists only for local or CI testing — run it on localhost, nowhere else.
"""
import math
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

# --- Login throttling: defends against online password brute-force (CWE-307) ---
# Track failed /login attempts per username. Once LOGIN_MAX_FAILED_ATTEMPTS
# failures pile up for one account, that account is temporarily locked for
# LOGIN_LOCKOUT_SECONDS: /login returns 429 + Retry-After without evaluating the
# password, capping guess rate. A successful login clears the counter, so an
# ordinary user who mistypes a password is not penalised. In-memory is enough at
# this app's scale; a multi-process/replicated deployment would back this with a
# shared store (e.g. Redis) and add per-source-IP throttling to blunt
# distributed guessing.
LOGIN_MAX_FAILED_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 900  # 15 minutes
FAILED_LOGINS = {}  # username -> {"count": int, "locked_until": float(monotonic)}


def _login_lock_remaining(username):
    """Seconds left on an active lockout for ``username`` (0 if not locked).

    A lapsed lockout is forgotten so counting restarts from a clean slate.
    """
    entry = FAILED_LOGINS.get(username)
    if not entry:
        return 0
    locked_until = entry.get("locked_until", 0.0)
    if not locked_until:
        return 0  # still counting failures; not locked yet
    remaining = locked_until - time.monotonic()
    if remaining <= 0:
        FAILED_LOGINS.pop(username, None)  # lockout window elapsed; start fresh
        return 0
    return math.ceil(remaining)


def _record_failed_login(username):
    """Count a failed attempt and start a lockout once the threshold is crossed."""
    entry = FAILED_LOGINS.get(username) or {"count": 0, "locked_until": 0.0}
    entry["count"] += 1
    if entry["count"] >= LOGIN_MAX_FAILED_ATTEMPTS:
        entry["locked_until"] = time.monotonic() + LOGIN_LOCKOUT_SECONDS
    FAILED_LOGINS[username] = entry


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

    # Throttle before checking the password: once an account is locked out,
    # further attempts (even with the correct password) are refused until the
    # lockout window elapses. This caps how fast an attacker can guess.
    retry_after = _login_lock_remaining(username)
    if retry_after:
        resp = jsonify(error="too many failed login attempts; try again later")
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry_after)
        return resp

    user = USERS.get(username)
    if user and user["password"] == body.get("password"):
        FAILED_LOGINS.pop(username, None)  # reset the counter on success
        token = f"token-{user['id']}"
        TOKENS[token] = username
        return jsonify(token=token)

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
