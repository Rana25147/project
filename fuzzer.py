"""
fuzz/fuzzer.py
--------------
API Fuzz Testing Module — Identity Security Framework for E-commerce.

Sends a wide variety of crafted / adversarial payloads to the /register
and /login endpoints, logs every response to fuzz_logs, and prints a
colour-coded summary report.

Usage (from the project root directory):
    python app.py                # start the Flask server first
    python fuzz/fuzzer.py        # run this in a second terminal

The module manipulates sys.path so it can import utils.logger regardless
of whether it is invoked as a script or via `python -m fuzz.fuzzer`.
"""

import json
import os
import sys
import sqlite3
from datetime import datetime

import requests

# ── Make sure the project root is on sys.path so utils can be imported ───────
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from utils.logger import log_fuzz_result  # noqa: E402  (import after path fix)


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

BASE_URL        = "http://127.0.0.1:5000"
LOGIN_URL       = f"{BASE_URL}/login"
REGISTER_URL    = f"{BASE_URL}/register"
REQUEST_TIMEOUT = 5   # seconds per request


# ─────────────────────────────────────────────────────────────────────────────
# Fuzz Payload Library
# ─────────────────────────────────────────────────────────────────────────────

FUZZ_PAYLOADS = [
    # ── Empty / missing fields ─────────────────────────────────────────────────
    {"username": "",           "password": ""},
    {"username": "admin",      "password": ""},
    {"username": "",           "password": "Password1!"},
    {"username": "   ",        "password": "   "},

    # ── SQL Injection ──────────────────────────────────────────────────────────
    {"username": "' OR '1'='1",            "password": "anything"},
    {"username": "admin'--",               "password": "x"},
    {"username": "'; DROP TABLE users;--", "password": "x"},
    {"username": "admin",                  "password": "' OR '1'='1"},

    # ── XSS Attempts ──────────────────────────────────────────────────────────
    {"username": "<script>alert(1)</script>",    "password": "Test1234!"},
    {"username": "admin",                         "password": "<img src=x onerror=alert(1)>"},

    # ── Oversized Strings ─────────────────────────────────────────────────────
    {"username": "A" * 1000,  "password": "B" * 1000},
    {"username": "a" * 21,    "password": "ValidPass1!"},   # 1 char over limit
    {"username": "ab",        "password": "ValidPass1!"},   # 1 char under min

    # ── Special & Control Characters ──────────────────────────────────────────
    {"username": "admin\x00",   "password": "Pass1234!"},
    {"username": "admin\n",     "password": "Pass1234!"},
    {"username": "admin\r\n",   "password": "Pass1234!"},
    {"username": "admin\t",     "password": "Pass1234!"},

    # ── Unicode / Emoji ────────────────────────────────────────────────────────
    {"username": "用户名",        "password": "密码密码密码密码"},
    {"username": "😀🔥💻",       "password": "✅🚀🎯"},
    {"username": "ñoño",        "password": "pässwörD1!"},

    # ── Type Confusion (non-string values) ────────────────────────────────────
    {"username": 12345,         "password": 67890},
    {"username": True,          "password": False},
    {"username": None,          "password": None},
    {"username": ["admin"],     "password": "Pass1234!"},
    {"username": {"k": "v"},    "password": "Pass1234!"},

    # ── Missing / wrong keys ──────────────────────────────────────────────────
    {"user": "admin", "pass": "Password1!"},
    {},

    # ── Brute-force simulation (sequential wrong passwords) ───────────────────
    {"username": "testuser", "password": "wrongpass1!"},
    {"username": "testuser", "password": "wrongpass2!"},
    {"username": "testuser", "password": "wrongpass3!"},
    {"username": "testuser", "password": "wrongpass4!"},
    {"username": "testuser", "password": "wrongpass5!"},
    {"username": "testuser", "password": "wrongpass6!"},  # should trigger lockout

    # ── Null-byte injection via username ──────────────────────────────────────
    {"username": "admin\x00injected", "password": "Pass1234!"},

    # ── Path traversal ────────────────────────────────────────────────────────
    {"username": "../../etc/passwd", "password": "Pass1234!"},
]


# ─────────────────────────────────────────────────────────────────────────────
# Core Fuzzer
# ─────────────────────────────────────────────────────────────────────────────

def run_fuzzer(target_url: str, payloads: list) -> dict:
    """
    POST each payload to target_url as JSON, log every response, and
    return a summary dict bucketed by HTTP status class.

    Args:
        target_url : Full URL of the endpoint to fuzz.
        payloads   : List of dicts (or any value) to send as the JSON body.

    Returns:
        dict with keys: total, 2xx, 3xx, 4xx, 5xx, errors
    """
    summary = {
        "total":  len(payloads),
        "2xx":    0,
        "3xx":    0,
        "4xx":    0,
        "5xx":    0,
        "errors": 0,
    }

    _divider()
    print(f"  FUZZ TARGET   : {target_url}")
    print(f"  TOTAL PAYLOADS: {len(payloads)}")
    print(f"  STARTED AT    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    _divider()

    for idx, payload in enumerate(payloads, start=1):
        payload_str = json.dumps(payload, ensure_ascii=False)

        try:
            response = requests.post(
                target_url,
                json=payload,
                timeout=REQUEST_TIMEOUT,
                headers={"Content-Type": "application/json"},
            )
            status_code = response.status_code

            try:
                response_obj  = response.json()
                response_text = json.dumps(response_obj)
            except ValueError:
                response_text = response.text[:300]

            if 200 <= status_code < 300:
                summary["2xx"] += 1
                label = "✅ OK"
            elif 300 <= status_code < 400:
                summary["3xx"] += 1
                label = "↪  REDIRECT"
            elif 400 <= status_code < 500:
                summary["4xx"] += 1
                label = "⚠  CLIENT ERR"
            else:
                summary["5xx"] += 1
                label = "🔴 SERVER ERR"

            print(f"\n[{idx:02d}] {label} | HTTP {status_code}")
            print(f"     Payload  : {payload_str[:120]}")
            print(f"     Response : {response_text[:120]}")

            if status_code >= 500:
                print("     !! ABNORMAL: Server error detected — review logs!")

            log_fuzz_result(payload_str, status_code, response_text)

        except requests.ConnectionError:
            summary["errors"] += 1
            msg = "Connection failed — is the Flask server running?"
            print(f"\n[{idx:02d}] ❌ ERROR  | {msg}")
            print(f"     Payload: {payload_str[:120]}")
            log_fuzz_result(payload_str, 0, msg)

        except requests.Timeout:
            summary["errors"] += 1
            msg = "Request timed out"
            print(f"\n[{idx:02d}] ⏱  TIMEOUT | {msg}")
            print(f"     Payload: {payload_str[:120]}")
            log_fuzz_result(payload_str, 0, msg)

        except Exception as exc:
            summary["errors"] += 1
            msg = f"Unexpected error: {exc}"
            print(f"\n[{idx:02d}] 💥 EXCEPTION | {msg}")
            log_fuzz_result(payload_str, 0, msg)

    return summary


# ─────────────────────────────────────────────────────────────────────────────
# Summary Report
# ─────────────────────────────────────────────────────────────────────────────

def print_summary(summary: dict, endpoint_name: str) -> None:
    """Print a formatted summary table after fuzzing an endpoint."""
    print("\n")
    _divider()
    print(f"  FUZZ SUMMARY — {endpoint_name}")
    _divider()
    print(f"  Total Payloads  : {summary['total']}")
    print(f"  2xx (Success)   : {summary['2xx']}")
    print(f"  3xx (Redirect)  : {summary['3xx']}")
    print(f"  4xx (Client Err): {summary['4xx']}")
    print(f"  5xx (Server Err): {summary['5xx']}  {'⚠  CHECK LOGS!' if summary['5xx'] else ''}")
    print(f"  Network Errors  : {summary['errors']}")
    _divider()

    from config import Config as _Cfg  # lazy import — avoids circular deps at top
    if summary["5xx"] > 0:
        print("\n  ⚠  WARNING: Server errors detected — review fuzz_logs!")
    elif summary["errors"] > 0:
        print("\n  ⚠  Some requests could not be sent. Is the server running?")
    else:
        print("\n  ✅ All requests completed. No server errors detected.")

    print(f"\n  Results saved to: {_Cfg.DB_PATH} → fuzz_logs table")
    print(f"  Completed at    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    _divider()


def _divider() -> None:
    print("=" * 65)


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n🔍 Identity Security Framework — API Fuzz Tester\n")

    # Verify server is reachable before starting
    try:
        health = requests.get(BASE_URL, timeout=3)
        print(f"✅ Server reachable — HTTP {health.status_code} from {BASE_URL}\n")
    except requests.ConnectionError:
        print(f"❌ Cannot connect to {BASE_URL}")
        print("   Start the Flask server first:  python app.py")
        sys.exit(1)

    # ── Fuzz /login ───────────────────────────────────────────────────────────
    print("\n📌 Fuzzing: POST /login\n")
    login_summary = run_fuzzer(LOGIN_URL, FUZZ_PAYLOADS)
    print_summary(login_summary, "POST /login")

    # ── Fuzz /register ────────────────────────────────────────────────────────
    print("\n📌 Fuzzing: POST /register\n")
    reg_summary = run_fuzzer(REGISTER_URL, FUZZ_PAYLOADS)
    print_summary(reg_summary, "POST /register")

    print("\n✅ Fuzz testing complete.\n")
