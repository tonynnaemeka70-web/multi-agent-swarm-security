
import jwt
from datetime import datetime, timedelta, timezone

from security.jwt_auth import (
    create_token,
    verify_token,
    SECRET_KEY,
    ALGORITHM
)

print("\n=== JWT SECURITY TESTS ===")

# TEST 1: Forged token
token = create_token(
    delegator_id="agent_a",
    permitted_tool="system_check",
    recipient_id="agent_b"
)

parts = token.split(".")
signature = parts[2]

replacement = "A" if signature[-1] != "A" else "B"
parts[2] = signature[:-1] + replacement

forged_token = ".".join(parts)

valid, result = verify_token(
    forged_token,
    expected_recipient="agent_b",
    required_tool="system_check"
)

print("\n1. FORGED TOKEN TEST:")
print("Correctly rejected" if not valid else "FAILED")


# TEST 2: Expired token
expired_payload = {
    "delegator_id": "agent_a",
    "recipient_id": "agent_b",
    "permitted_tool": "system_check",
    "exp": datetime.now(timezone.utc) - timedelta(seconds=10)
}

expired_token = jwt.encode(
    expired_payload,
    SECRET_KEY,
    algorithm=ALGORITHM
)

valid, result = verify_token(
    expired_token,
    expected_recipient="agent_b",
    required_tool="system_check"
)

print("\n2. EXPIRED TOKEN TEST:")
print("Correctly rejected" if not valid else "FAILED")

print("\n=== TESTS COMPLETED ===")
