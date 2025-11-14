# backend/app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from cloud_scanner import scan_with_credentials

app = Flask(__name__)
CORS(app)  # allow all origins (OK for demo; restrict in prod)

@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "ok", "message": "Byte Bloom scanner backend is running."})

# quick test endpoint to validate keys (minimal call)
@app.route("/keys/test", methods=["POST"])
def test_keys():
    data = request.get_json() or {}
    ak = data.get("access_key")
    sk = data.get("secret_key")
    region = data.get("region", "us-east-1")
    if not ak or not sk:
        return jsonify({"ok": False, "error": "Missing access_key or secret_key"}), 400
    try:
        # Run a minimal scan but timeboxed/fast. Use scan_with_credentials which returns report
        report = scan_with_credentials(ak, sk, region)
        return jsonify({"ok": True, "summary": report.get("summary", {})})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

# full scan endpoint
@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json() or {}
    ak = data.get("access_key")
    sk = data.get("secret_key")
    region = data.get("region", "us-east-1")
    try:
        report = scan_with_credentials(ak, sk, region)
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    # Local dev only. Render will use gunicorn.
    app.run(host="0.0.0.0", port=5000, debug=True)

