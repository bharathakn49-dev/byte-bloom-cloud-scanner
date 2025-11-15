# backend/app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import time
import traceback

# cloud scanner will be imported (defined separately)
from cloud_scanner import scan_with_credentials, sample_mock_report

# Simple demo auth functions in-file (no DB)
FAKE_USERS = {
    "demo_user": "demo12345",
    "our_1st_demo": "password123",
    "bytebloom": "cloudscan"
}

def login_user(username, password):
    if username in FAKE_USERS and FAKE_USERS[username] == password:
        return {"ok": True, "token": "fake_token_" + username, "username": username}
    else:
        return {"ok": False, "error": "Invalid"}

def register_user(username, password):
    # Add to fake DB
    FAKE_USERS[username] = password
    return {"ok": True, "token": "fake_token_" + username, "username": username}

# Flask app
app = Flask(__name__)
CORS(app)

@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "ok", "message": "Byte Bloom scanner backend (demo) is running."})

# Auth endpoints (demo)
@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"ok": False, "error": "Missing username/password"}), 400
    resp = login_user(username, password)
    if resp.get("ok"):
        return jsonify(resp)
    return jsonify(resp), 400

@app.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"ok": False, "error": "Missing username/password"}), 400
    resp = register_user(username, password)
    return jsonify(resp)

# Quick test endpoint to validate keys (minimal call)
@app.route("/keys/test", methods=["POST"])
def test_keys():
    data = request.get_json() or {}
    ak = data.get("access_key")
    sk = data.get("secret_key")
    region = data.get("region", "us-east-1")
    if not ak or not sk:
        return jsonify({"ok": False, "error": "Missing access_key or secret_key"}), 400

    # If keys look like demo/fake, return mock summary
    if "EXAMPLE" in ak.upper() or "FAKE" in ak.upper() or "EXAMPLE" in sk.upper() or "FAKE" in sk.upper():
        report = sample_mock_report()
        return jsonify({"ok": True, "summary": report.get("summary", {}), "fake": True})

    # Otherwise attempt a real scan but keep it timeboxed
    try:
        report = scan_with_credentials(ak, sk, region, timeout_seconds=10)
        return jsonify({"ok": True, "summary": report.get("summary", {}), "report": report})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 400

# Full scan endpoint
@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json() or {}
    ak = data.get("access_key")
    sk = data.get("secret_key")
    region = data.get("region", "us-east-1")

    if not ak or not sk:
        return jsonify({"error": "Missing access_key or secret_key"}), 400

    # If keys look fake/demo, return mock report immediately
    if "EXAMPLE" in ak.upper() or "FAKE" in ak.upper() or "EXAMPLE" in sk.upper() or "FAKE" in sk.upper():
        report = sample_mock_report()
        # include small server-side timestamp and source label
        report["_meta"] = {"demo_mode": True, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        return jsonify({"ok": True, "report": report})

    # Try a real scan (may fail if keys invalid)
    try:
        report = scan_with_credentials(ak, sk, region)
        return jsonify({"ok": True, "report": report})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500

if __name__ == "__main__":
    # Dev server
    app.run(host="0.0.0.0", port=5000, debug=True)

