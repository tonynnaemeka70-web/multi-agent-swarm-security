from flask import Flask, jsonify, request
from security.jwt_auth import verify_token
import hmac
from pathlib import Path

app = Flask(__name__)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
GATEWAY_SECRET_FILE = PROJECT_ROOT / "security" / ".agent_gateway_secret"
GATEWAY_SECRET = GATEWAY_SECRET_FILE.read_text().strip()

AGENT_NAME = "Data Retrieval Agent"

SECURITY_RECORDS = [
    {
        "id": 1,
        "event": "Failed login",
        "severity": "Medium"
    },
    {
        "id": 2,
        "event": "Suspicious PowerShell activity",
        "severity": "High"
    },
    {
        "id": 3,
        "event": "New user account created",
        "severity": "Low"
    }
]


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "agent": AGENT_NAME,
        "status": "running"
    })


@app.route("/records", methods=["GET"])
def get_records():
 # Require authentication from the trusted gateway.
    supplied_gateway_secret = request.headers.get("X-Agent-Gateway-Auth", "")

    if not hmac.compare_digest(supplied_gateway_secret, GATEWAY_SECRET):
        return jsonify({
            "error": "Request must come through the trusted gateway"
        }), 403

    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("Bearer "):
        return jsonify({
            "error": "Missing or invalid authorization token"
        }), 403

    token = auth_header.split(" ", 1)[1]

    valid, result = verify_token(
        token,
        expected_recipient="agent_c",
        required_tool="read_records"
    )

    if not valid:
        return jsonify({
            "error": result
        }), 403

    return jsonify({
        "agent": AGENT_NAME,
        "delegator": result["delegator_id"],
        "records": SECURITY_RECORDS,
        "status": "authorized"
    })


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5003,
        debug=False
    )
