"""
services/audit_service.py
--------------------------
Audit Log Service — dynamic query building, sensitive-data masking,
suspicious-payload detection, and paginated log retrieval.

All database access for the /logs admin view is centralised here.
No Flask imports — purely Python business logic.
"""

import math
import re

from models.database import get_connection

# Characters that commonly appear in injection / XSS payloads
_SUSPICIOUS_CHARS = re.compile(r"[<>\"'`;|&]")


# ─────────────────────────────────────────────────────────────────────────────
# Data Sanitisation Helpers
# ─────────────────────────────────────────────────────────────────────────────

def mask_sensitive_data(value: str) -> str:
    """
    Redact passwords, tokens, and Bearer values from a serialised string
    before it is displayed in the admin log viewer.

    Handles three patterns:
        JSON key-value    "password": "secret"  →  "password": "***"
        Bearer token      Bearer abc123         →  Bearer ***
        Query-string      password=secret       →  password=***
    """
    if not value:
        return value

    masked = re.sub(
        r'(?i)("?(?:password|pass|token|auth|api_key)"?\s*[=:]\s*")([^\"]+)(")',
        r'\1***\3',
        value,
    )
    masked = re.sub(
        r'(?i)Bearer\s+[A-Za-z0-9\-\._~\+/]+=*',
        'Bearer ***',
        masked,
    )
    masked = re.sub(
        r'(?i)(password|pass|pwd)=([^&\s]+)',
        r'\1=***',
        masked,
    )
    return masked


def is_suspicious_payload(value: str) -> bool:
    """
    Return True if the payload looks like an injection attempt:
      - Contains shell / XSS / SQLi special characters, OR
      - Exceeds 80 characters (unusually long for a normal field value)
    """
    if not value:
        return False
    if len(value) >= 80:
        return True
    return bool(_SUSPICIOUS_CHARS.search(value))


# ─────────────────────────────────────────────────────────────────────────────
# Query Builder
# ─────────────────────────────────────────────────────────────────────────────

def build_audit_query(
    params: dict,
    *,
    count_only: bool = False,
    paginate: bool = True,
    page: int = 1,
    per_page: int = 14,
) -> tuple[str, list]:
    """
    Build a parameterised SELECT or COUNT query for audit_logs based on
    the filter values in params.

    Supported params keys:
        q           — Full-text search across endpoint, method, payload, IP, result
        status      — "Success" | "Error" | "Warning"
        endpoint    — Exact endpoint path filter
        start_date  — ISO datetime lower bound (inclusive)
        end_date    — ISO datetime upper bound (inclusive)

    Returns:
        (sql_string, bound_values_list)
    """
    base       = "SELECT * FROM audit_logs"
    count_base = "SELECT COUNT(*) FROM audit_logs"
    clauses: list[str] = []
    values:  list      = []

    search          = params.get("q",          "").strip()
    status_filter   = params.get("status",     "").strip()
    endpoint_filter = params.get("endpoint",   "").strip()
    start_date      = params.get("start_date", "").strip()
    end_date        = params.get("end_date",   "").strip()

    if search:
        like = f"%{search}%"
        clauses.append(
            "(endpoint LIKE ? OR method LIKE ? OR request_payload LIKE ?"
            " OR response_body LIKE ? OR ip_address LIKE ? OR result LIKE ?"
            " OR event_type LIKE ?)"
        )
        values.extend([like] * 7)

    if status_filter in {"Success", "Error", "Warning"}:
        clauses.append("result = ?")
        values.append(status_filter)

    if endpoint_filter:
        clauses.append("endpoint = ?")
        values.append(endpoint_filter)

    if start_date:
        clauses.append("timestamp >= ?")
        values.append(start_date.replace("T", " "))

    if end_date:
        clauses.append("timestamp <= ?")
        values.append(end_date.replace("T", " "))

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""

    if count_only:
        return count_base + where, values

    query = base + where + " ORDER BY timestamp DESC"

    if paginate:
        offset = (page - 1) * per_page
        query += " LIMIT ? OFFSET ?"
        values = values + [per_page, offset]

    return query, values


# ─────────────────────────────────────────────────────────────────────────────
# Log Fetcher
# ─────────────────────────────────────────────────────────────────────────────

def fetch_audit_logs(
    params: dict,
    page: int = 1,
    per_page: int = 14,
    paginate: bool = True,
) -> tuple[list[dict], int, int, list[str]]:
    """
    Query audit_logs with optional filters and pagination.

    Returns:
        logs        — List of enriched log dicts ready for the template.
        total       — Total matching row count (for pagination controls).
        total_pages — Number of pages at the given per_page size.
        endpoints   — Sorted list of distinct endpoint paths (for the filter dropdown).
    """
    conn   = get_connection()
    cursor = conn.cursor()

    # Count query (same filters, no LIMIT/OFFSET)
    count_q, count_v = build_audit_query(params, count_only=True)
    cursor.execute(count_q, count_v)
    total = cursor.fetchone()[0]

    # Data query
    data_q, data_v = build_audit_query(
        params, paginate=paginate, page=page, per_page=per_page
    )
    cursor.execute(data_q, data_v)
    rows = cursor.fetchall()

    # Distinct endpoints for filter dropdown
    cursor.execute("SELECT DISTINCT endpoint FROM audit_logs ORDER BY endpoint")
    endpoints = [r[0] for r in cursor.fetchall()]
    conn.close()

    logs: list[dict] = []
    for row in rows:
        payload       = row["request_payload"] or ""
        response_body = row["response_body"]    or ""
        result        = row["result"].title()
        resp_status   = row["response_status"]

        # Derive a CSS class for colour-coding the status column
        status_class = "status-success"
        if result == "Error" or (resp_status and resp_status >= 400):
            status_class = "status-error"
        elif 300 <= (resp_status or 0) < 400 or result == "Warning":
            status_class = "status-warning"

        masked_payload = mask_sensitive_data(payload)
        masked_body    = mask_sensitive_data(response_body)

        logs.append(
            {
                "id":              row["id"],
                "timestamp":       row["timestamp"],
                "event_type":      row["event_type"] or "",
                "endpoint":        row["endpoint"],
                "method":          row["method"],
                "request_payload": masked_payload,
                "response_status": resp_status if resp_status is not None else "—",
                "result":          result,
                "status_class":    status_class,
                "ip_address":      row["ip_address"] or "unknown",
                "user_agent":      row["user_agent"] or "",
                "response_body":   masked_body,
                "suspicious":      (
                    is_suspicious_payload(payload)
                    or is_suspicious_payload(response_body)
                ),
                "payload_preview": (
                    (masked_payload[:90] + "…")
                    if len(payload) > 90
                    else masked_payload
                ),
            }
        )

    total_pages = max(1, math.ceil(total / per_page))
    return logs, total, total_pages, endpoints
