
from security.jwt_auth import create_token, verify_token

# Create a token for Agent B.
token = create_token(
    delegator_id="agent_a",
    permitted_tool="system_check",
    recipient_id="agent_b"
)

print("\n1. TOKEN CREATED:")
print("Token generated successfully (value hidden)")

# Test the correct recipient and permission.
valid, result = verify_token(
    token,
    expected_recipient="agent_b",
    required_tool="system_check"
)

print("\n2. VALID TOKEN TEST:")
print("Passed" if valid else result)

# Test an unauthorized tool.
valid, result = verify_token(
    token,
    expected_recipient="agent_b",
    required_tool="delete_all_files"
)

print("\n3. UNAUTHORIZED TOOL TEST:")
print("Correctly rejected:" + " " + str(result) if not valid else "FAILED")

# Test the wrong recipient.
valid, result = verify_token(
    token,
    expected_recipient="agent_c",
    required_tool="system_check"
)

print("\n4. WRONG RECIPIENT TEST:")
print("Correctly rejected:" + " " + str(result) if not valid else "FAILED")
