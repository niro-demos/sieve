# Sieve

> ⚠️ **INTENTIONALLY VULNERABLE.** Do **not** deploy Sieve or expose it to the
> internet. It exists only as a small, local/CI smoke-test target for
> [Niro](https://github.com/apxlabs-ai/niro), the AI penetration tester. Run it
> on `localhost` or inside CI — nowhere else.

Sieve is a tiny API — a few endpoints, in-memory, instant start — small enough
that a full Niro pentest runs **end to end in a few minutes**. It's a canary for
"is the pipeline working?", not a challenge and not a realistic application.

## Run

```bash
docker build -t sieve .
docker run --rm -p 5000:5000 \
  -e SIEVE_ALICE_PASSWORD="$(openssl rand -base64 24)" \
  -e SIEVE_BOB_PASSWORD="$(openssl rand -base64 24)" \
  -e SIEVE_ADMIN_PASSWORD="$(openssl rand -base64 24)" \
  sieve
# → http://localhost:5000/
```

If a password environment variable is omitted, Sieve generates a random
per-process password for that account at startup. No deployable account password
is published in source.

## Endpoints

| Method | Path | Notes |
|--------|------|-------|
| `GET`  | `/`              | info + warning |
| `POST` | `/login`         | body `{"username","password"}` → `{"token"}` |
| `GET`  | `/accounts/<id>` | account details (requires a bearer token) |
| `GET`  | `/admin/users`   | list non-secret user details (requires an administrator bearer token) |

Seeded users: `alice`, `bob`, and `admin`.

## Test

```bash
python3 -m venv /tmp/sieve-venv
/tmp/sieve-venv/bin/python -m pip install -r requirements.txt
/tmp/sieve-venv/bin/python -m unittest discover -s tests -v
```

## License

[MIT](LICENSE).
