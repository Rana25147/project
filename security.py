"""
utils/security.py
-----------------
Security Module — password hashing, time-based brute-force protection, JWT.

Brute-force strategy:
  - Increments `failed_login_attempts` on the user row on each bad password.
  - When attempts >= MAX_FAILED_ATTEMPTS, sets `blocked_until = now + BLOCK_WINDOW_MINUTES`.
  - Login gate calls is_account_locked() *before* the password check so the
    timing of a correct hash check cannot be used to enumerate valid accounts.

All configuration is read from config.Config — no os.environ calls here.
"""

import sqlite3
import bcrypt
import jwt

from datetime import datetime, timezone, timedelta

from config import Config


# ─────────────────────────────────────────────────────────────────────────────
# Password Hashing
# ─────────────────────────────────────────────────────────────────────────────

def hash_password(plain_password: str) -> str:
    """
    Hash a plain-text password using bcrypt with a freshly generated salt
    (12 rounds). Returns a UTF-8 string safe to store in the database.
    """
    password_bytes = plain_password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")


def check_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain-text password against a stored bcrypt hash.
    Uses bcrypt's built-in constant-time comparison to prevent timing attacks.
    """
    plain_bytes = plain_password.encode("utf-8")
    hash_bytes  = hashed_password.encode("utf-8")
    return bcrypt.checkpw(plain_bytes, hash_bytes)


# ─────────────────────────────────────────────────────────────────────────────
# Brute-Force Protection
# ─────────────────────────────────────────────────────────────────────────────

def is_account_locked(username: str) -> tuple[bool, str | None]:
    """
    Return (True, locked_until_iso) if the account is currently locked,
    (True, None) if permanently blocked by an admin,
    (False, None) otherwise.
    """
    conn = sqlite3.connect(Config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT is_blocked, blocked_until FROM users WHERE username = ?",
        (username,),
    )
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return False, None

    is_blocked, blocked_until = row

    # Permanent administrative block
    if is_blocked:
        return True, None

    # Time-based block — check if the window has expired
    if blocked_until:
        blocked_until_dt = datetime.fromisoformat(blocked_until).replace(
            tzinfo=timezone.utc
        )
        if datetime.now(timezone.utc) < blocked_until_dt:
            return True, blocked_until_dt.isoformat()

    return False, None


def increment_failed_attempts(username: str) -> int:
    """
    Increment failed_login_attempts counter.
    If the new count reaches MAX_FAILED_ATTEMPTS, set blocked_until accordingly.

    Returns the updated failed_login_attempts count.
    """
    conn = sqlite3.connect(Config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT failed_login_attempts FROM users WHERE username = ?",
        (username,),
    )
    row = cursor.fetchone()
    if row is None:
        conn.close()
        return 0

    new_count = row[0] + 1

    if new_count >= Config.MAX_FAILED_ATTEMPTS:
        locked_until = datetime.now(timezone.utc) + timedelta(
            minutes=Config.BLOCK_WINDOW_MINUTES
        )
        cursor.execute(
            """
            UPDATE users
               SET failed_login_attempts = ?,
                   blocked_until         = ?,
                   updated_at            = CURRENT_TIMESTAMP
             WHERE username = ?
            """,
            (new_count, locked_until.isoformat(), username),
        )
    else:
        cursor.execute(
            """
            UPDATE users
               SET failed_login_attempts = ?,
                   updated_at            = CURRENT_TIMESTAMP
             WHERE username = ?
            """,
            (new_count, username),
        )

    conn.commit()
    conn.close()
    return new_count


def reset_failed_attempts(username: str) -> None:
    """
    Clear the failed-attempt counter and blocked_until on successful login.
    Also updates last_login_at.
    """
    conn = sqlite3.connect(Config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE users
           SET failed_login_attempts = 0,
               blocked_until         = NULL,
               last_login_at         = CURRENT_TIMESTAMP,
               updated_at            = CURRENT_TIMESTAMP
         WHERE username = ?
        """,
        (username,),
    )
    conn.commit()
    conn.close()


def block_user(username: str) -> None:
    """Permanently block a user (administrative action)."""
    conn = sqlite3.connect(Config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET is_blocked = 1, updated_at = CURRENT_TIMESTAMP WHERE username = ?",
        (username,),
    )
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# JWT Generation
# ─────────────────────────────────────────────────────────────────────────────

def generate_jwt(username: str) -> str:
    """
    Issue a signed JSON Web Token for the authenticated user.

    Claims:
        sub      — Subject (username)
        username — Redundant claim for convenience
        iat      — Issued-at UTC timestamp
        exp      — Expiry UTC timestamp (iat + JWT_EXP_DELTA_MINS)
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub":      username,
        "username": username,
        "iat":      now,
        "exp":      now + timedelta(minutes=Config.JWT_EXP_DELTA_MINS),
    }
    return jwt.encode(payload, Config.JWT_SECRET_KEY, algorithm="HS256")
