"""
config.py
---------
Centralized configuration for the Identity Security Framework.

All modules import settings from here — no scattered os.environ.get() calls
anywhere else in the codebase. Values are loaded from the .env file at import
time via python-dotenv.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# Compute once so random fallback is stable for the entire process lifetime
_secret = os.environ.get("SECRET_KEY", "change-me-in-production!")


class Config:
    # ── Flask Core ────────────────────────────────────────────────────────────
    SECRET_KEY = _secret
    DEBUG = os.environ.get("FLASK_ENV", "development").lower() == "development"

    # ── Session ───────────────────────────────────────────────────────────────
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_COOKIE_SECURE = os.environ.get(
        "SESSION_COOKIE_SECURE", "False"
    ).lower() in ("1", "true", "yes")
    PERMANENT_SESSION_LIFETIME = int(
        os.environ.get("SESSION_LIFETIME_SECONDS", "3600")
    )

    # ── Database ──────────────────────────────────────────────────────────────
    # Accepts DB_PATH or the legacy DATABASE_URI key from the original .env
    DB_PATH = (
        os.environ.get("DB_PATH")
        or os.environ.get("DATABASE_URI", "database.db")
    )

    # ── Authentication ────────────────────────────────────────────────────────
    MAX_FAILED_ATTEMPTS  = int(os.environ.get("MAX_FAILED_ATTEMPTS",  "5"))
    BLOCK_WINDOW_MINUTES = int(os.environ.get("BLOCK_WINDOW_MINUTES", "15"))

    # ── JWT ───────────────────────────────────────────────────────────────────
    JWT_SECRET_KEY      = _secret
    JWT_EXP_DELTA_MINS  = int(os.environ.get("JWT_EXP_DELTA_MINS", "60"))

    # ── Admin ─────────────────────────────────────────────────────────────────
    ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "AdminSecret123!")

    # ── Rate Limiting ─────────────────────────────────────────────────────────
    RATELIMIT_DEFAULT     = ["200 per day", "50 per hour"]
    RATELIMIT_STORAGE_URI = "memory://"
