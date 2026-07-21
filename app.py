#!/usr/bin/env python3
"""
Sieve — a tiny API used as a local/CI smoke-test target for Niro
(https://github.com/apxlabs-ai/niro), the AI penetration tester.

⚠️  Do NOT deploy Sieve or expose it to the internet. It is deliberately weak
    and exists only for local or CI testing — run it on localhost, nowhere else.
"""
import os
import secrets

from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

DEFAULT_PASSWORDS = {
    "alice": "alice-pw",
    "bob": "bob-pw",
    "admin": "admin-pw",
}


def _password_hash_for(username):
    configured_password = os.environ.get(f"SIEVE_{username.upper()}_PASSWORD")
    if configured_password and configured_password != DEFAULT_PASSWORDS[username]:
        return generate_password_hash(configured_password)
    return generate_password_hash(secrets.token_urlsafe(32))


# Seeded, in-memory "database" — no persistence, instant start.
USERS = {
    "alice": {"id": 1, "password_hash": _password_hash_for("alice"), "email": "alice@sieve.test", "balance": 100,  "admin": False},
    "bob":   {"id": 2, "password_hash": _password_hash_for("bob"),   "email": "bob@sieve.test",   "balance": 8400, "admin": False},
    "admin": {"id": 3, "password_hash": _password_hash_for("admin"), "email": "admin@sieve.test", "balance": 0,    "admin": True},
}
TOKENS = {}  # token -> username


def _password_matches(user, candidate):
    if "password" in user:
        return secrets.compare_digest(user["password"], candidate or "")
    return check_password_hash(user["password_hash"], candidate or "")


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
    user = USERS.get(body.get("username"))
    if user and _password_matches(user, body.get("password")):
        token = secrets.token_urlsafe(32)
        TOKENS[token] = body["username"]
        return jsonify(token=token)
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
