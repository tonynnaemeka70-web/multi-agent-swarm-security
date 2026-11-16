
from flask import Flask, request, jsonify
from security.jwt_auth import verify_token
import hmac
from pathlib import Path

app = Flask(__name__)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
GATEWAY_SECRET_FILE = PROJECT_ROOT / "security" / ".agent_gateway_secret"
GATEWAY_SECRET = GATEWAY_SECRET_FILE.read_text().strip()

AGENT_NAME = "Code Runner Agent"

ALLOWED_ACTIONS = {
    "system_check": "System check completed successfully",
    "security_status": "Security status check completed"
}


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "agent": AGENT_NAME,
        "status": "running"
    })


@app.route("/execute", methods=["POST"])
def execute_task():

    data = request.get_json(silent=True) or {}
    action = data.get("action")

    if not action:
        return jsonify({
            "error": "No action provided"
        }), 400

    if action not in ALLOWED_ACTIONS:
        return jsonify({
            "error": "Action not allowed"
        }), 403

    # Require authentication from the trusted gateway.
    supplied_gateway_secret = request.headers.get("X-Agent-Gateway-Auth", "")

    if not hmac.compare_digest(supplied_gateway_secret, GATEWAY_SECRET):
        return jsonify({
            "error": "Request must come through the trusted gateway"
        }), 403

    # Require a signed JWT.
    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("Bearer "):
        return jsonify({
            "error": "Missing or invalid authorization token"
        }), 403

    token = auth_header.split(" ", 1)[1]

    # Verify token signature, expiry, recipient and tool permission.
    valid, result = verify_token(
        token,
        expected_recipient="agent_b",
        required_tool=action
    )

    if not valid:
        return jsonify({
            "error": result
        }), 403

    return jsonify({
        "agent": AGENT_NAME,
        "delegator": result["delegator_id"],
        "action": action,
        "result": ALLOWED_ACTIONS[action],
        "status": "completed"
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=False)

