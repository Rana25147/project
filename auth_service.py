"""
services/auth_service.py
------------------------
Authentication Service — all business logic for registration and login.

Routes delegate to these functions and only handle the HTTP translation
(parse request body, call service, return JSON response).  No Flask
imports exist in this file; it is framework-agnostic.

Return Contract
---------------
Every function returns a dict with the following keys:

    ok          bool    True on success, False on any kind of failure.
    status      int     The HTTP status code the route should return.
    payload     dict    The JSON body to send back to the client.
    event       str     The audit event-type label.

login_user() additionally returns, on success:

    session_data  dict  {"username": str, "user_id": str} — the route
                        writes these into the Flask session.
"""

import json
import sqlite3
import uuid

from config import Config
from models.database import get_connection
from utils.validators import validate_input, validate_email
from utils.security import (
    hash_password,
    check_password,
    is_account_locked,
    increment_failed_attempts,
    reset_failed_attempts,
    generate_jwt,
)
from utils.logger import log_audit_event, log_login_attempt


# ─────────────────────────────────────────────────────────────────────────────
# Registration
# ─────────────────────────────────────────────────────────────────────────────

def register_user(
    username: str,
    email: str,
    password: str,
    ip_address: str,
    user_agent: str,
) -> dict:
    """
    Validate inputs, hash the password, and persist a new user record.

    Flow:
        1. Validate username + password (format, complexity)
        2. Validate email format
        3. Hash password with bcrypt (12 rounds)
        4. INSERT user row; catch UNIQUE constraint on username/email
        5. Emit audit event and return result dict
    """
    request_payload = json.dumps(
        {"username": username, "email": email, "password": "***"},
        ensure_ascii=False,
    )

    # ── Step 1: Validate username + password ──────────────────────────────────
    valid, err = validate_input(username, password)
    if not valid:
        log_audit_event(
            "/register", "POST", request_payload, 400, "Error",
            ip_address, json.dumps({"error": err}, ensure_ascii=False),
            event_type="REGISTRATION_FAILED", user_agent=user_agent,
        )
        return {
            "ok": False,
            "status": 400,
            "event": "REGISTRATION_FAILED",
            "payload": {
                "status": "error",
                "message": err,
                "error_code": "VALIDATION_ERROR",
            },
        }

    # ── Step 2: Validate email ────────────────────────────────────────────────
    email_valid, email_err = validate_email(email)
    if not email_valid:
        log_audit_event(
            "/register", "POST", request_payload, 400, "Error",
            ip_address, json.dumps({"error": email_err}, ensure_ascii=False),
            event_type="REGISTRATION_FAILED", user_agent=user_agent,
        )
        return {
            "ok": False,
            "status": 400,
            "event": "REGISTRATION_FAILED",
            "payload": {
                "status": "error",
                "message": email_err,
                "error_code": "VALIDATION_ERROR",
            },
        }

    # ── Step 3 & 4: Hash and persist ──────────────────────────────────────────
    hashed  = hash_password(password)
    user_id = str(uuid.uuid4())

    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)",
            (user_id, username, email.strip().lower(), hashed),
        )
        conn.commit()
        conn.close()

    except sqlite3.IntegrityError:
        log_audit_event(
            "/register", "POST", request_payload, 409, "Error",
            ip_address,
            json.dumps({"error": "Username or email already taken"}, ensure_ascii=False),
            event_type="REGISTRATION_FAILED", user_agent=user_agent,
        )
        return {
            "ok": False,
            "status": 409,
            "event": "REGISTRATION_FAILED",
            "payload": {
                "status": "error",
                "message": "Username or email already taken",
                "error_code": "CONFLICT",
            },
        }

    except sqlite3.Error:
        log_audit_event(
            "/register", "POST", request_payload, 500, "Error",
            ip_address,
            json.dumps({"error": "Database error"}, ensure_ascii=False),
            event_type="REGISTRATION_FAILED", user_agent=user_agent,
        )
        return {
            "ok": False,
            "status": 500,
            "event": "REGISTRATION_FAILED",
            "payload": {
                "status": "error",
                "message": "An internal error occurred",
                "error_code": "SERVER_ERROR",
            },
        }

    # ── Step 5: Emit success audit event ──────────────────────────────────────
    log_audit_event(
        "/register", "POST", request_payload, 201, "Success",
        ip_address,
        json.dumps({"message": "User registered successfully"}, ensure_ascii=False),
        event_type="REGISTRATION", user_id=user_id, user_agent=user_agent,
    )
    return {
        "ok": True,
        "status": 201,
        "event": "REGISTRATION",
        "payload": {
            "status": "success",
            "message": "User registered successfully",
            "data": {"user_id": user_id},
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Login
# ─────────────────────────────────────────────────────────────────────────────

def login_user(
    username: str,
    password: str,
    ip_address: str,
    user_agent: str,
) -> dict:
    """
    Authenticate a user (LLD login flow, Section 3.2).

    Flow:
        1. Validate inputs (format, complexity)
        2. Fetch user record from DB
        3. Account lock gate — checked BEFORE password verification
        4. Verify bcrypt hash
        5a. Success → reset counters, issue JWT, set session_data
        5b. Failure → increment counters; apply time-lock if threshold hit

    Returns a result dict.  On success, "session_data" carries the values
    that the route handler must write into the Flask session.
    """
    request_payload = json.dumps(
        {"username": username, "password": "***"}, ensure_ascii=False
    )

    # ── Step 1: Input presence check (no complexity rules on login) ──────────
    if not username or not password:
        log_audit_event(
            "/login", "POST", request_payload, 400, "Error",
            ip_address, json.dumps({"error": "Missing username or password"}, ensure_ascii=False),
            event_type="LOGIN_FAILED", user_agent=user_agent,
        )
        return {
            "ok": False,
            "status": 400,
            "event": "LOGIN_FAILED",
            "payload": {
                "status": "error",
                "message": "Please enter your username and password.",
                "error_code": "VALIDATION_ERROR",
            },
        }

    if "\x00" in username or "\x00" in password:
        log_audit_event(
            "/login", "POST", request_payload, 400, "Error",
            ip_address, json.dumps({"error": "Null bytes detected"}, ensure_ascii=False),
            event_type="LOGIN_FAILED", user_agent=user_agent,
        )
        return {
            "ok": False,
            "status": 400,
            "event": "LOGIN_FAILED",
            "payload": {
                "status": "error",
                "message": "Invalid input detected.",
                "error_code": "VALIDATION_ERROR",
            },
        }

    # ── Step 2: Fetch user record ─────────────────────────────────────────────
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, password, is_blocked, blocked_until FROM users WHERE username = ?",
            (username,),
        )
        user = cursor.fetchone()
        conn.close()

    except sqlite3.Error:
        log_audit_event(
            "/login", "POST", request_payload, 500, "Error",
            ip_address, json.dumps({"error": "Database error"}, ensure_ascii=False),
            event_type="LOGIN_FAILED", user_agent=user_agent,
        )
        return {
            "ok": False,
            "status": 500,
            "event": "LOGIN_FAILED",
            "payload": {
                "status": "error",
                "message": "An internal error occurred",
                "error_code": "SERVER_ERROR",
            },
        }

    # Generic 401 for unknown username — prevents user enumeration
    if not user:
        log_login_attempt(username, ip_address, "FAILURE")
        log_audit_event(
            "/login", "POST", request_payload, 401, "Error",
            ip_address, json.dumps({"error": "Invalid credentials"}, ensure_ascii=False),
            event_type="LOGIN_FAILED", user_agent=user_agent,
        )
        return {
            "ok": False,
            "status": 401,
            "event": "LOGIN_FAILED",
            "payload": {
                "status": "error",
                "message": "Invalid username or password",
                "error_code": "AUTH_FAILED",
            },
        }

    user_id, stored_hash = user["id"], user["password"]

    # ── Step 3: Account lock gate (BEFORE password check per LLD) ────────────
    locked, locked_until_iso = is_account_locked(username)
    if locked:
        log_audit_event(
            "/login", "POST", request_payload, 403, "Error",
            ip_address,
            json.dumps(
                {"error": "Account locked", "locked_until": locked_until_iso},
                ensure_ascii=False,
            ),
            event_type="ATTEMPT_ON_LOCKED_ACCOUNT",
            user_id=user_id,
            user_agent=user_agent,
        )
        body = {
            "status": "error",
            "message": (
                "Account temporarily locked due to multiple failed login attempts. "
                "Try again later."
            ),
            "error_code": "ACCOUNT_LOCKED",
        }
        if locked_until_iso:
            body["details"] = {"locked_until": locked_until_iso}
        return {
            "ok": False,
            "status": 403,
            "event": "ATTEMPT_ON_LOCKED_ACCOUNT",
            "payload": body,
        }

    # ── Step 4: Password verification ─────────────────────────────────────────
    if check_password(password, stored_hash):

        # ── 5a: Success ───────────────────────────────────────────────────────
        reset_failed_attempts(username)
        token = generate_jwt(username)

        log_login_attempt(username, ip_address, "SUCCESS")
        log_audit_event(
            "/login", "POST", request_payload, 200, "Success",
            ip_address,
            json.dumps({"message": "Login successful"}, ensure_ascii=False),
            event_type="LOGIN_SUCCESS", user_id=user_id, user_agent=user_agent,
        )
        return {
            "ok": True,
            "status": 200,
            "event": "LOGIN_SUCCESS",
            "session_data": {"username": username, "user_id": user_id},
            "payload": {
                "status": "success",
                "message": "Authentication successful",
                "data": {
                    "token": token,
                    "expires_in": Config.JWT_EXP_DELTA_MINS * 60,
                    "username": username,
                },
            },
        }

    else:
        # ── 5b: Failure ───────────────────────────────────────────────────────
        new_count = increment_failed_attempts(username)
        remaining = max(Config.MAX_FAILED_ATTEMPTS - new_count, 0)

        log_login_attempt(username, ip_address, "FAILURE")

        if new_count >= Config.MAX_FAILED_ATTEMPTS:
            log_audit_event(
                "/login", "POST", request_payload, 403, "Warning",
                ip_address,
                json.dumps(
                    {"event": "Account locked after repeated failures"},
                    ensure_ascii=False,
                ),
                event_type="LOCKOUT", user_id=user_id, user_agent=user_agent,
            )
        else:
            log_audit_event(
                "/login", "POST", request_payload, 401, "Error",
                ip_address,
                json.dumps(
                    {"error": "Invalid credentials", "attempts_remaining": remaining},
                    ensure_ascii=False,
                ),
                event_type="LOGIN_FAILED", user_id=user_id, user_agent=user_agent,
            )

        return {
            "ok": False,
            "status": 401,
            "event": "LOGIN_FAILED",
            "payload": {
                "status": "error",
                "message": "Invalid username or password",
                "error_code": "AUTH_FAILED",
            },
        }
