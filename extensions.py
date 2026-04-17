"""
extensions.py
-------------
Shared Flask extension instances.

Created here (without an app) so that both the application factory (app.py)
and route blueprints (routes/auth.py) can import the same object.
Call limiter.init_app(app) inside create_app() to bind it to the Flask app.
"""

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)
