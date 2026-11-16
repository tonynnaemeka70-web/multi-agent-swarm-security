
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pathlib import Path
from security.jwt_auth import create_token
import requests
import re
import hmac

app = Flask(__name__)

# Rate limiting.
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10 per minute"]
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Load the gateway client secret.
GATEWAY_SECRET_FILE = (
    PROJECT_ROOT / "security" / ".gateway_client_secret"
)

GATEWAY_SECRET = GATEWAY_SECRET_FILE.read_text().strip()
AGENT_GATEWAY_SECRET_FILE = (
    PROJECT_ROOT / "security" / ".agent_gateway_secret"
)

AGENT_GATEWAY_SECRET = AGENT_GATEWAY_SECRET_FILE.read_text().strip()

# Registered agents.
AGENTS = {
    "agent_b": {
        "url": "http://127.0.0.1:5002",
        "actions": ["system_check", "security_status"],
        "method": "POST",
        "endpoint": "/execute"
    },
    "agent_c": {
        "url": "http://127.0.0.1:5003",
        "actions": ["read_records"],
        "method": "GET",
        "endpoint": "/records"
    }
}

def sanitize_input(message):
    """Reject suspicious inter-agent instructions."""

    suspicious_patterns = [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"reveal\s+(all\s+)?secrets",
        r"dump\s+(all\s+)?sensitive\s+records",
        r"bypass\s+(the\s+)?security",
        r"ignore\s+security\s+rules"
    ]

    for pattern in suspicious_patterns:
        if re.search(pattern, message, re.IGNORECASE):
            return False

    return True


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "gateway": "Agent Mesh Security Gateway",
        "status": "running"
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "protected_agents": list(AGENTS.keys())
    })


@app.route("/forward/<agent_id>", methods=["POST"])
@limiter.limit("10 per minute")
def forward_request(agent_id):

    # Confirm the destination exists.
    if agent_id not in AGENTS:
        return jsonify({
            "error": "Unknown agent"
        }), 404

    # Authenticate the caller.
    supplied_secret = request.headers.get(
        "X-Gateway-Key", ""
    )

    if not hmac.compare_digest(
        supplied_secret,
        GATEWAY_SECRET
    ):
        return jsonify({
            "error": "Unauthorized gateway client"
        }), 403

    data = request.get_json(silent=True) or {}

    action = data.get("action")
    message = data.get("message", "")

    if not isinstance(action, str) or not action:
        return jsonify({
            "error": "Action is required"
        }), 400

    if not isinstance(message, str):
        return jsonify({
            "error": "Message must be text"
        }), 400

    # Enforce destination-specific permissions.
    if action not in AGENTS[agent_id]["actions"]:
        return jsonify({
            "error": "Action not permitted for this agent"
        }), 403

    # Inspect incoming message.
    if not sanitize_input(message):
        return jsonify({
            "error": "Suspicious inter-agent instruction blocked"
        }), 403

    # The gateway assigns the delegator identity.
    token = create_token(
        delegator_id="agent_a",
        permitted_tool=action,
        recipient_id=agent_id
    )

    
   # Forward the authorized request.
    try:
        if AGENTS[agent_id]["method"] == "GET":
            response = requests.get(
                AGENTS[agent_id]["url"] + AGENTS[agent_id]["endpoint"],
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-Agent-Gateway-Auth": AGENT_GATEWAY_SECRET
                },
                timeout=5
            )
        else:
            response = requests.post(
                AGENTS[agent_id]["url"] + AGENTS[agent_id]["endpoint"],
                json={"action": action},
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-Agent-Gateway-Auth": AGENT_GATEWAY_SECRET
                },
                timeout=5
            )

        try:
            agent_result = response.json()
        except ValueError:
            agent_result = {"error": "Invalid agent response"}
        # Inspect the agent response before returning it.
        agent_response_text = str(agent_result)

        if not sanitize_input(agent_response_text):
            return jsonify({
                "error": "Suspicious content detected in agent response",
                "destination": agent_id
            }), 502
        return jsonify({
            "gateway": "Agent Mesh Security Gateway",
            "destination": agent_id,
            "agent_status": response.status_code,
            "agent_response": agent_result
        }), response.status_code

    except requests.RequestException:
        return jsonify({
            "error": "Could not reach destination agent"
        }), 502

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
