#!/usr/bin/env python3
"""
Sentinel Auth — a login system with Argon2id, TOTP 2FA, and lockout.

The three things I set out to get right:

  Hashing. Argon2id, not SHA-256. Fast hashes are a liability here: the
  speed that makes SHA good for checksums is exactly what lets an attacker
  test billions of candidates against a stolen table. Argon2id is
  deliberately slow and memory-hard, so parallel cracking gets expensive.

  Second factor. TOTP (RFC 6238) — the server stores a shared secret,
  both sides derive the same 6 digits from the current 30-second window.
  Used codes are burned so a shoulder-surfed code can't be replayed.

  Lockout. Throttling per account only lets one attacker lock out every
  user. Throttling per IP only lets a botnet spread out. This does both.

Run:
    pip install flask argon2-cffi pyotp qrcode
    python3 app.py
"""

import base64
import io
import os
import secrets
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone

import pyotp
import qrcode
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from flask import Flask, g, jsonify, request, session

DB = os.environ.get("SENTINEL_DB", "sentinel.db")

# Tuned so a single verify takes ~100ms on my machine. Slow enough to
# punish bulk cracking, fast enough that a real login doesn't feel broken.
ph = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2)

MAX_FAILS = 5              # failures before the account locks
WINDOW = 900               # seconds those failures are counted over
IP_MAX_FAILS = 15          # failures from one address before it's blocked
MIN_PASSWORD_LEN = 12

app = Flask(__name__)
# In production this comes from the environment. A hardcoded key means
# anyone with the source can forge a session cookie.
app.secret_key = os.environ.get("SENTINEL_SECRET") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # JavaScript can't read it
    SESSION_COOKIE_SAMESITE="Lax",  # blunts CSRF
    SESSION_COOKIE_SECURE=bool(os.environ.get("SENTINEL_HTTPS")),
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)


# ── Storage ─────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    pw_hash       TEXT NOT NULL,
    totp_secret   TEXT,
    totp_enabled  INTEGER DEFAULT 0,
    last_totp     TEXT,
    locked_until  REAL DEFAULT 0,
    created       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attempts (
    id       INTEGER PRIMARY KEY,
    username TEXT,
    ip       TEXT,
    ok       INTEGER,
    at       REAL
);
CREATE INDEX IF NOT EXISTS idx_attempts_at ON attempts(at);
"""


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn:
        conn.close()


def init_db():
    with closing(sqlite3.connect(DB)) as c:
        c.executescript(SCHEMA)
        c.commit()


# ── Attempt tracking ────────────────────────────────────────────────

def log_attempt(username, ip, ok):
    db().execute(
        "INSERT INTO attempts (username, ip, ok, at) VALUES (?,?,?,?)",
        (username, ip, int(ok), time.time()),
    )
    db().commit()


# Column names cannot be parameterised by the driver, only values can.
# Rather than interpolate the column into the string — which is how SQL
# injection starts, even when today's only callers pass safe constants —
# each query is written out in full and selected by key.
FAIL_QUERIES = {
    "username": "SELECT COUNT(*) n FROM attempts WHERE username=? AND ok=0 AND at>?",
    "ip":       "SELECT COUNT(*) n FROM attempts WHERE ip=?       AND ok=0 AND at>?",
}


def recent_fails(field, value):
    try:
        sql = FAIL_QUERIES[field]
    except KeyError:
        raise ValueError(f"recent_fails: unsupported field {field!r}") from None
    row = db().execute(sql, (value, time.time() - WINDOW)).fetchone()
    return row["n"]


def lockout_remaining(username):
    row = db().execute(
        "SELECT locked_until FROM users WHERE username=?", (username,)
    ).fetchone()
    if not row:
        return 0
    return max(0, row["locked_until"] - time.time())


def apply_lockout(username):
    """Escalating backoff — each additional failure past the limit doubles
    the wait, capped at an hour so a user isn't locked out forever."""
    fails = recent_fails("username", username)
    if fails < MAX_FAILS:
        return 0
    penalty = min(3600, 60 * (2 ** (fails - MAX_FAILS)))
    db().execute(
        "UPDATE users SET locked_until=? WHERE username=?",
        (time.time() + penalty, username),
    )
    db().commit()
    return penalty


def client_ip():
    # Behind a proxy this must come from a header you actually trust.
    return request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()


# ── Routes ──────────────────────────────────────────────────────────

@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""

    if not 3 <= len(username) <= 32 or not username.replace("_", "").isalnum():
        return jsonify(error="Username must be 3-32 characters, letters, numbers, or underscore."), 400
    if len(password) < MIN_PASSWORD_LEN:
        return jsonify(error=f"Password must be at least {MIN_PASSWORD_LEN} characters."), 400

    secret = pyotp.random_base32()
    try:
        db().execute(
            "INSERT INTO users (username, pw_hash, totp_secret, created) VALUES (?,?,?,?)",
            (username, ph.hash(password), secret,
             datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )
        db().commit()
    except sqlite3.IntegrityError:
        # Deliberately vague. "That username is taken" is a free
        # account-enumeration oracle.
        return jsonify(error="Could not create that account."), 409

    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="Sentinel")
    return jsonify(
        message="Account created. Scan the QR code, then confirm a code to turn on 2FA.",
        totp_uri=uri,
        qr_png_base64=qr_base64(uri),
    ), 201


@app.post("/enable-2fa")
def enable_2fa():
    data = request.get_json(silent=True) or {}
    user = fetch_user(data.get("username", "").strip().lower())
    if not user:
        return jsonify(error="Could not verify that code."), 400

    totp = pyotp.TOTP(user["totp_secret"])
    if not totp.verify(str(data.get("code", "")), valid_window=1):
        return jsonify(error="Could not verify that code."), 400

    db().execute("UPDATE users SET totp_enabled=1 WHERE id=?", (user["id"],))
    db().commit()
    return jsonify(message="Two-factor authentication is on.")


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""
    code = str(data.get("code") or "")
    ip = client_ip()

    if recent_fails("ip", ip) >= IP_MAX_FAILS:
        return jsonify(error="Too many attempts from this address. Try again later."), 429

    wait = lockout_remaining(username)
    if wait:
        return jsonify(error=f"Account locked. Try again in {int(wait)} seconds."), 423

    user = fetch_user(username)

    # Hash even when the user doesn't exist. Skipping the work here makes
    # missing accounts measurably faster to reject, which leaks who exists.
    stored = user["pw_hash"] if user else ph.hash("dummy-timing-equalizer")

    ok = False
    try:
        ph.verify(stored, password)
        ok = user is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        ok = False

    if not ok:
        log_attempt(username, ip, False)
        penalty = apply_lockout(username)
        msg = "Incorrect username or password."
        if penalty:
            msg = f"Too many failed attempts. Locked for {int(penalty)} seconds."
        return jsonify(error=msg), 401

    # Rehash transparently if the cost parameters have since been raised.
    if ph.check_needs_rehash(stored):
        db().execute("UPDATE users SET pw_hash=? WHERE id=?", (ph.hash(password), user["id"]))
        db().commit()

    if user["totp_enabled"]:
        if not code:
            return jsonify(error="Enter your 6-digit code.", need_code=True), 401

        totp = pyotp.TOTP(user["totp_secret"])
        # valid_window=1 tolerates modest clock drift, no more.
        if not totp.verify(code, valid_window=1):
            log_attempt(username, ip, False)
            apply_lockout(username)
            return jsonify(error="Incorrect code."), 401

        # Burn the code so an observed one can't be reused in its window.
        if user["last_totp"] == code:
            return jsonify(error="That code was already used. Wait for the next one."), 401
        db().execute("UPDATE users SET last_totp=? WHERE id=?", (code, user["id"]))

    db().execute("UPDATE users SET locked_until=0 WHERE id=?", (user["id"],))
    db().commit()
    log_attempt(username, ip, True)

    # New session id on login — otherwise a pre-set cookie survives
    # authentication and the attacker rides in on it.
    session.clear()
    session.permanent = True
    session["uid"] = user["id"]
    session["user"] = user["username"]
    session["issued"] = time.time()

    return jsonify(message=f"Signed in as {user['username']}.")


@app.post("/logout")
def logout():
    session.clear()
    return jsonify(message="Signed out.")


@app.get("/me")
def me():
    if "uid" not in session:
        return jsonify(error="Not signed in."), 401
    return jsonify(user=session["user"], since=session.get("issued"))


# ── Helpers ─────────────────────────────────────────────────────────

def fetch_user(username):
    return db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()


def qr_base64(uri):
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


if __name__ == "__main__":
    init_db()
    print("Sentinel Auth on http://127.0.0.1:5000")
    app.run(debug=False, port=5000)
