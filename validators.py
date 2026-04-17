"""
utils/validators.py
-------------------
Input Validation Module — pure Python, zero Flask dependency.

All field-level validation logic lives here so it can be imported
by the service layer and tested independently of the web framework.
"""

import re

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
EMAIL_REGEX    = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


def validate_input(username: str, password: str) -> tuple[bool, str]:
    """
    Validate username and password fields.

    Checks:
      - Both fields are present and non-empty
      - No leading/trailing whitespace
      - No null-byte injection characters
      - Username matches USERNAME_REGEX (3-20 chars, alphanumeric + underscore)
      - Password minimum length: 8 characters
      - Password contains at least one uppercase letter
      - Password contains at least one digit
      - Password contains at least one special character

    Returns:
        (True, "")             on success
        (False, error_message) on failure
    """
    if not username or not password:
        return False, "Missing username or password"

    if username != username.strip() or password != password.strip():
        return False, "Username and password must not have leading/trailing spaces"

    # Null-byte injection guard
    if "\x00" in username or "\x00" in password:
        return False, "Null bytes are not allowed"

    if not USERNAME_REGEX.match(username):
        return False, "Username must be 3–20 characters (letters, digits, underscores only)"

    if len(password) < 8:
        return False, "Password must be at least 8 characters long"

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"

    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit"

    if not re.search(r"[^a-zA-Z0-9]", password):
        return False, "Password must contain at least one special character"

    return True, ""


def validate_email(email: str) -> tuple[bool, str]:
    """
    Validate an email address format.

    Returns:
        (True, "")             on success
        (False, error_message) on failure
    """
    if not email or not isinstance(email, str):
        return False, "Email is required"

    email = email.strip()

    if len(email) > 255:
        return False, "Email address is too long"

    if not EMAIL_REGEX.match(email):
        return False, "Invalid email address format"

    return True, ""
