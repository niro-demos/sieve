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

app = Flask(__name__)


def configured_password(env_var):
    return os.environ.get(env_var) or secrets.token_urlsafe(32)


# Seeded, in-memory "database" — no persistence, instant start.
USERS = {
    "alice": {
        "id": 1,
        "password": configured_password("SIEVE_ALICE_PASSWORD"),
        "email": "alice@sieve.test",
        "balance": 100,
        "admin": False,
    },
    "bob": {
        "id": 2,
        "password": configured_password("SIEVE_BOB_PASSWORD"),
        "email": "bob@sieve.test",
        "balance": 8400,
        "admin": False,
    },
    "admin": {
        "id": 3,
        "password": configured_password("SIEVE_ADMIN_PASSWORD"),
        "email": "admin@sieve.test",
        "balance": 0,
        "admin": True,
    },
}
TOKENS = {}  # token -> username


def bearer_token():
    return request.headers.get("Authorization", "").removeprefix("Bearer ").strip()


def current_username():
    username = TOKENS.get(bearer_token())
    if username not in USERS:
        return None
    return username


def public_user(username, user):
    return {
        "id": user["id"],
        "username": username,
        "email": user["email"],
        "balance": user["balance"],
        "admin": user["admin"],
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
    user = USERS.get(body.get("username"))
    if user and user["password"] == body.get("password"):
        token = secrets.token_urlsafe(32)
        TOKENS[token] = body["username"]
        return jsonify(token=token)
    return jsonify(error="invalid credentials"), 401


# Return account details for the given id. A valid bearer token is required.
@app.get("/accounts/<int:account_id>")
def account(account_id):
    username = current_username()
    if username is None:
        return jsonify(error="unauthorized"), 401
    if USERS[username]["id"] != account_id:
        return jsonify(error="forbidden"), 403
    for username, user in USERS.items():
        if user["id"] == account_id:
            return jsonify(
                id=user["id"],
                username=username,
                email=user["email"],
                balance=user["balance"],
            )
    return jsonify(error="not found"), 404


# Return the non-secret user directory to administrators only.
@app.get("/admin/users")
def admin_users():
    username = current_username()
    if username is None:
        return jsonify(error="unauthorized"), 401
    if not USERS[username]["admin"]:
        return jsonify(error="forbidden"), 403
    return jsonify(
        users={
            directory_username: public_user(directory_username, user)
            for directory_username, user in USERS.items()
        }
    )


if __name__ == "__main__":
    # 0.0.0.0 so it is reachable from the pentest container; port 5000.
    app.run(host="0.0.0.0", port=5000)
