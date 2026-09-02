#!/usr/bin/env python3
"""
Sieve — a tiny API used as a local/CI smoke-test target for Niro
(https://github.com/apxlabs-ai/niro), the AI penetration tester.

⚠️  Do NOT deploy Sieve or expose it to the internet. It is deliberately weak
    and exists only for local or CI testing — run it on localhost, nowhere else.
"""
import os

from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# Credentials are sourced from the environment at startup and stored ONLY as
# non-reversible password hashes — never as plaintext, in source or in the
# in-memory store. The values below are clearly-marked, overridable DEV-ONLY
# defaults for local/CI smoke tests; a production deployment MUST supply real
# secrets externally (e.g. `SIEVE_ADMIN_PASSWORD=...`) so that nothing usable
# can ever be copied out of this file or its git history and replayed.
_DEV_ONLY_DEFAULT_PASSWORDS = {
    "alice": "dev-only-alice-secret",
    "bob":   "dev-only-bob-secret",
    "admin": "dev-only-admin-secret",
}


def _seed_password(username):
    """Return a user's configured password (env var, else the dev-only
    default). The caller hashes this immediately; it is never retained in
    plaintext."""
    return os.environ.get(
        f"SIEVE_{username.upper()}_PASSWORD", _DEV_ONLY_DEFAULT_PASSWORDS[username]
    )


# Seeded, in-memory "database" — no persistence, instant start. Each account
# stores only a werkzeug password *hash* ("password_hash"), not plaintext.
USERS = {
    "alice": {"id": 1, "password_hash": generate_password_hash(_seed_password("alice")), "email": "alice@sieve.test", "balance": 100,  "admin": False},
    "bob":   {"id": 2, "password_hash": generate_password_hash(_seed_password("bob")),   "email": "bob@sieve.test",   "balance": 8400, "admin": False},
    "admin": {"id": 3, "password_hash": generate_password_hash(_seed_password("admin")), "email": "admin@sieve.test", "balance": 0,    "admin": True},
}
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
    if user and check_password_hash(user["password_hash"], body.get("password") or ""):
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
    return jsonify(users=USERS)


if __name__ == "__main__":
    # 0.0.0.0 so it is reachable from the pentest container; port 5000.
    app.run(host="0.0.0.0", port=5000)
