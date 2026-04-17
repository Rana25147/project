"""
utils/logger.py
---------------
Logging Module — persists login attempts, fuzz results, and structured audit
events to SQLite.

All DB writes are fire-and-forget helpers; callers (services, routes) should
not depend on a return value. Configuration (DB_PATH) is read from Config.
"""

import sqlite3

from config import Config


# ─────────────────────────────────────────────────────────────────────────────
# Login Attempt Log
# ─────────────────────────────────────────────────────────────────────────────

def log_login_attempt(username: str, ip_address: str, status: str) -> None:
    """
    Record a login attempt in login_logs.

    Args:
        username   : Username that attempted login.
        ip_address : Client IP address.
        status     : "SUCCESS" or "FAILURE".
    """
    conn = sqlite3.connect(Config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO login_logs (username, ip_address, status) VALUES (?, ?, ?)",
        (username, ip_address, status),
    )
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Fuzz Result Log
# ─────────────────────────────────────────────────────────────────────────────

def log_fuzz_result(
    input_data: str, response_status: int, response_message: str
) -> None:
    """
    Record a single fuzz payload outcome in fuzz_logs.

    Args:
        input_data       : The serialized payload that was sent.
        response_status  : HTTP status code received (0 on connection error).
        response_message : Response body or error description.
    """
    conn = sqlite3.connect(Config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO fuzz_logs (input_data, response_status, response_message)
        VALUES (?, ?, ?)
        """,
        (input_data, response_status, response_message),
    )
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Structured Audit Log
# ─────────────────────────────────────────────────────────────────────────────

def log_audit_event(
    endpoint: str,
    method: str,
    request_payload: str,
    response_status: int,
    result: str,
    ip_address: str,
    response_body: str = "",
    event_type: str = "",
    user_id: str = "",
    user_agent: str = "",
) -> None:
    """
    Record a structured security event in audit_logs.

    Args:
        endpoint        : Route path (e.g. "/login").
        method          : HTTP method ("POST", "GET", …).
        request_payload : Serialized request body (passwords must be masked by caller).
        response_status : HTTP status code returned.
        result          : High-level outcome: "Success", "Error", or "Warning".
        ip_address      : Client IP address.
        response_body   : Serialized response body (optional).
        event_type      : Semantic label: "LOGIN_SUCCESS", "LOCKOUT", etc.
        user_id         : UUID of the affected user (optional).
        user_agent      : Browser / client user-agent string (optional).
    """
    conn = sqlite3.connect(Config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO audit_logs (
            endpoint, method, request_payload, response_status,
            result, ip_address, response_body, event_type, user_id, user_agent
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            endpoint,
            method,
            request_payload,
            response_status,
            result,
            ip_address,
            response_body,
            event_type,
            user_id,
            user_agent,
        ),
    )
    conn.commit()
    conn.close()
