"""Shared pytest fixtures for the Sieve test suite.

The app is a single-file Flask app (`app.py` at the repo root) that seeds its
users in memory at import time, so tests can drive it in-process through the
Flask test client with no live server and no seeded database.
"""
import os
import sys

import pytest

# Make the repo-root `app.py` importable regardless of where pytest is invoked.
sys.path.insert(0, os.path.dirname(__file__))

import app as sieve  # noqa: E402


@pytest.fixture
def client():
    """A Flask test client with an isolated, empty session-token store.

    `app.TOKENS` is a process-global dict; clearing it around each test keeps
    tokens minted in one test from leaking into another. If a co-resident
    security fix adds other process-global auth state (e.g. the login
    brute-force throttle's `FAILED_LOGINS` counter), reset that too so a
    lockout raised in one test can't spuriously fail an unrelated login in the
    next; the `getattr` keeps this a no-op when that state isn't present.
    """
    sieve.TOKENS.clear()
    getattr(sieve, "FAILED_LOGINS", {}).clear()
    sieve.app.config.update(TESTING=True)
    with sieve.app.test_client() as c:
        yield c
    sieve.TOKENS.clear()
    getattr(sieve, "FAILED_LOGINS", {}).clear()
