import os, json
from flask import Flask, request, jsonify
from flask_cors import CORS
from models import init_db, SessionLocal, User, Scan
from auth import hash_password, verify_password, create_access_token, decode_access_token
from cloud_scanner import scan_with_credentials

app = Flask(__name__)
CORS(app)

init_db()

def get_user_from_token(header):
    if not header or " " not in header:
        return None
    token = header.split(" ", 1)[1]
    payload = decode_access_token(token)
    if not payload:
        return None

    db = SessionLocal()
    user = db.query(User).filter(User.username == payload["sub"]).first()
    db.close()
    return user


@app.get("/")
def home():
    return jsonify({"ok": True})


@app.post("/auth/register")
def register():
    data = request.json
    username = data["username"]
    password = data["password"]

    db = SessionLocal()
    if db.query(User).filter(User.username == username).first():
        return {"ok": False, "error": "Username exists"}, 400

    u = User(username=username, hashed_password=hash_password(password))
    db.add(u)
    db.commit()
    token = create_access_token({"sub": username})
    db.close()
    return {"ok": True, "token": token}


@app.post("/auth/login")
def login():
    data = request.json
    username = data["username"]
    password = data["password"]

    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return {"ok": False, "error": "Invalid"}, 400

    token = create_access_token({"sub": username})
    db.close()
    return {"ok": True, "token": token}


@app.post("/scan")
def scan():
    user = get_user_from_token(request.headers.get("Authorization", ""))
    if not user:
        return {"ok": False, "error": "Login required"}, 401

    data = request.json
    ak, sk = data["access_key"], data["secret_key"]
    region = data.get("region", "us-east-1")

    result = scan_with_credentials(ak, sk, region)

    db = SessionLocal()
    s = Scan(
        user_id=user.id,
        region=region,
        summary_json=json.dumps(result.get("summary", {})),
        report_json=json.dumps(result)
    )
    db.add(s)
    db.commit()
    db.close()

    return {"ok": True, "report": result}


@app.get("/history")
def history():
    user = get_user_from_token(request.headers.get("Authorization", ""))
    if not user:
        return {"ok": False, "error": "Login required"}, 401

    db = SessionLocal()
    scans = db.query(Scan).filter(Scan.user_id == user.id).all()
    out = []
    for s in scans:
        out.append({
            "id": s.id,
            "region": s.region,
            "timestamp": s.timestamp.isoformat(),
            "summary": json.loads(s.summary_json)
        })
    db.close()
    return {"ok": True, "history": out}


@app.get("/history/<id>")
def history_item(id):
    user = get_user_from_token(request.headers.get("Authorization", ""))
    if not user:
        return {"ok": False, "error": "Login required"}, 401

    db = SessionLocal()
    s = db.query(Scan).filter(Scan.id == id, Scan.user_id == user.id).first()
    db.close()

    if not s:
        return {"ok": False, "error": "Not found"}, 404

    return {"ok": True, "report": json.loads(s.report_json)}


if __name__ == "__main__":
    app.run(port=5000)
