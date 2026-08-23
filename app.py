#!/usr/bin/env python3
"""
Sieve — a tiny API used as a local/CI smoke-test target for Niro
(https://github.com/apxlabs-ai/niro), the AI penetration tester.

⚠️  Do NOT deploy Sieve or expose it to the internet. It is deliberately weak
    and exists only for local or CI testing — run it on localhost, nowhere else.
"""
from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash

app = Flask(__name__)

# Seeded, in-memory "database" — no persistence, instant start.
USERS = {
    "alice": {
        "id": 1,
        "password_hash": "pbkdf2:sha256:1000000$GpFtwjFukS8h1cH1$b7159b6273b21a81ac399838aaa73445df86ee717401a1ab75df4eee03f7c4f2",
        "email": "alice@sieve.test",
        "balance": 100,
        "admin": False,
    },
    "bob": {
        "id": 2,
        "password_hash": "pbkdf2:sha256:1000000$g1hRjiMJFu6HHi6i$ba7ef4069020febffac6c1247ecce6721ce8ebc7d41910a082bed7210784da8e",
        "email": "bob@sieve.test",
        "balance": 8400,
        "admin": False,
    },
    "admin": {
        "id": 3,
        "password_hash": "pbkdf2:sha256:1000000$QEeAHdel7QkvNylS$510efb7d527ca64bd11080603354a1ded0db235a8ae92433ac7642606ec89728",
        "email": "admin@sieve.test",
        "balance": 0,
        "admin": True,
    },
}
USER_PUBLIC_FIELDS = ("id", "email", "balance", "admin")
TOKENS = {}  # token -> username


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
    password = body.get("password")
    if (
        user
        and isinstance(password, str)
        and check_password_hash(user["password_hash"], password)
    ):
        token = f"token-{user['id']}"
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
    return jsonify(
        users={
            username: {field: user[field] for field in USER_PUBLIC_FIELDS}
            for username, user in USERS.items()
        }
    )


if __name__ == "__main__":
    # 0.0.0.0 so it is reachable from the pentest container; port 5000.
    app.run(host="0.0.0.0", port=5000)
