"""
app.py
------
Application Factory — Identity Security Framework for E-commerce.

This file is intentionally thin:
    - create_app() wires together Config, extensions, blueprints, and hooks.
    - No route logic, no business logic, no database access lives here.

Entry point:
    python app.py
"""

from flask import request

from config import Config
from extensions import limiter
from models.database import init_db
from routes.auth import auth_bp
from routes.admin import admin_bp

from flask import Flask


def create_app() -> Flask:
    """
    Application factory.

    Creates the Flask instance, loads configuration, initialises the rate
    limiter, registers blueprints, and installs the security-headers hook.
    """
    app = Flask(__name__)

    # ── Load configuration ────────────────────────────────────────────────────
    # Flask reads its own keys (SECRET_KEY, SESSION_*, DEBUG …) from the object.
    app.config.from_object(Config)

    # ── Rate Limiter ──────────────────────────────────────────────────────────
    limiter.init_app(app)

    # ── Blueprints ────────────────────────────────────────────────────────────
    # auth_bp  — /login  /register  /logout
    # admin_bp — /       /favicon   /admin-login  /logs
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)

    # ── Security Response Headers ─────────────────────────────────────────────
    @app.after_request
    def set_security_headers(response):
        """Apply security headers to every outgoing response."""
        response.headers.setdefault("X-Content-Type-Options",  "nosniff")
        response.headers.setdefault("X-Frame-Options",          "DENY")
        response.headers.setdefault("X-XSS-Protection",         "1; mode=block")
        response.headers.setdefault(
            "Referrer-Policy", "strict-origin-when-cross-origin"
        )
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        if request.is_secure:
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response

    return app


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    print("[APP] Starting Identity Security Framework...")
    flask_app = create_app()
    flask_app.run(
        debug=Config.DEBUG,
        host="0.0.0.0",
        port=5000,
    )
