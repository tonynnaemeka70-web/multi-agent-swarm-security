
import os
import jwt
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Load the private signing key.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SECRET_FILE = PROJECT_ROOT / "security" / ".jwt_secret"

SECRET_KEY = SECRET_FILE.read_text().strip()

ALGORITHM = "HS256"


def create_token(delegator_id, permitted_tool, recipient_id):
    """Create a signed token with limited permissions."""

    now = datetime.now(timezone.utc)

    payload = {
        "delegator_id": delegator_id,
        "recipient_id": recipient_id,
        "permitted_tool": permitted_tool,
        "iat": now,
        "exp": now + timedelta(minutes=5)
    }

    token = jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return token


def verify_token(token, expected_recipient, required_tool):
    """Verify token signature, expiry and permissions."""

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        if payload.get("recipient_id") != expected_recipient:
            return False, "Wrong recipient"

        if payload.get("permitted_tool") != required_tool:
            return False, "Unauthorized tool"

        return True, payload

    except jwt.ExpiredSignatureError:
        return False, "Token expired"

    except jwt.InvalidTokenError:
        return False, "Invalid token"
