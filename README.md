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
docker run --rm -p 5000:5000 sieve
# → http://localhost:5000/
```

## Endpoints

| Method | Path | Notes |
|--------|------|-------|
| `GET`  | `/`              | info + warning |
| `POST` | `/login`         | body `{"username","password"}` → `{"token"}` |
| `GET`  | `/accounts/<id>` | account details (requires a bearer token) |
| `GET`  | `/admin/users`   | list all users |

Seeded users: `alice`, `bob`, and `admin`. Set `SIEVE_ALICE_PASSWORD`,
`SIEVE_BOB_PASSWORD`, and `SIEVE_ADMIN_PASSWORD` to unique values before login;
the previously published `*-pw` defaults are rejected.

## License

[MIT](LICENSE).
