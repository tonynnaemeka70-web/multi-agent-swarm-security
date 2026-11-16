
from flask import Flask, request, jsonify

app = Flask(__name__)

AGENT_NAME = "Supervisor Agent"


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "agent": AGENT_NAME,
        "status": "running",
        "message": "Supervisor is ready"
    })


@app.route("/task", methods=["POST"])
def receive_task():
    data = request.get_json(silent=True) or {}

    task = data.get("task")

    if not task:
        return jsonify({
            "error": "No task provided"
        }), 400

    return jsonify({
        "agent": AGENT_NAME,
        "received_task": task,
        "status": "accepted"
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
