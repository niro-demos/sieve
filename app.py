#!/usr/bin/env python3
"""
Sieve — a tiny API used as a local/CI smoke-test target for Niro
(https://github.com/apxlabs-ai/niro), the AI penetration tester.

⚠️  Do NOT deploy Sieve or expose it to the internet. It is deliberately weak
    and exists only for local or CI testing — run it on localhost, nowhere else.
"""
import secrets

from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# Seeded, in-memory "database" — no persistence, instant start.
USERS = {
    "alice": {"id": 1, "password_hash": generate_password_hash("alice-pw"), "email": "alice@sieve.test", "balance": 100,  "admin": False},
    "bob":   {"id": 2, "password_hash": generate_password_hash("bob-pw"),   "email": "bob@sieve.test",   "balance": 8400, "admin": False},
    "admin": {"id": 3, "password_hash": generate_password_hash("admin-pw"), "email": "admin@sieve.test", "balance": 0,    "admin": True},
}
TOKENS = {}  # token -> username


def authenticated_user():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    username = TOKENS.get(token)
    if username is None:
        return None
    return username, USERS[username]


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
    if user and check_password_hash(user["password_hash"], body.get("password", "")):
        username = body["username"]
        for old_token, owner in list(TOKENS.items()):
            if owner == username:
                del TOKENS[old_token]
        token = secrets.token_urlsafe(32)
        TOKENS[token] = username
        return jsonify(token=token)
    return jsonify(error="invalid credentials"), 401


# Return account details for the given id. A valid bearer token is required.
@app.get("/accounts/<int:account_id>")
def account(account_id):
    actor = authenticated_user()
    if actor is None:
        return jsonify(error="unauthorized"), 401
    _, current_user = actor
    if current_user["id"] != account_id and not current_user["admin"]:
        return jsonify(error="forbidden"), 403
    for username, user in USERS.items():
        if user["id"] == account_id:
            return jsonify(id=user["id"], username=username, email=user["email"], balance=user["balance"])
    return jsonify(error="not found"), 404


# Return the full user directory.
@app.get("/admin/users")
def admin_users():
    actor = authenticated_user()
    if actor is None:
        return jsonify(error="unauthorized"), 401
    if not actor[1]["admin"]:
        return jsonify(error="forbidden"), 403
    users = {
        username: {
            "id": user["id"],
            "email": user["email"],
            "balance": user["balance"],
            "admin": user["admin"],
        }
        for username, user in USERS.items()
    }
    return jsonify(users=users)


if __name__ == "__main__":
    # 0.0.0.0 so it is reachable from the pentest container; port 5000.
    app.run(host="0.0.0.0", port=5000)
