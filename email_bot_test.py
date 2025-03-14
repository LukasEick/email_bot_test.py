from flask import Flask, jsonify, session, request
from flask_cors import CORS
from flask_session import Session
import os

app = Flask(__name__)

# 🔥 Sichere Session-Konfiguration für Netlify + Render
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "supersecretkey")

Session(app)

# ✅ **Richtige CORS-Konfiguration**
CORS(app, resources={r"/*": {"origins": "https://emailcrawlerlukas.netlify.app"}}, supports_credentials=True)

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "https://emailcrawlerlukas.netlify.app"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

# ✅ **Test-Route: Session setzen**
@app.route("/set_session", methods=["POST"])
def set_session():
    data = request.get_json()
    session["test_data"] = data.get("value", "default_value")
    return jsonify({"message": "✅ Session gespeichert!", "session_value": session["test_data"]})

# ✅ **Test-Route: Session abrufen**
@app.route("/get_session", methods=["GET"])
def get_session():
    session_value = session.get("test_data")
    if session_value:
        return jsonify({"message": "✅ Session gefunden!", "session_value": session_value})
    return jsonify({"error": "❌ Keine gespeicherte Session gefunden!"}), 401

# ✅ **Test-Route: CORS Debug**
@app.route("/test_cors", methods=["GET"])
def test_cors():
    return jsonify({"message": "✅ CORS funktioniert!"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8080)), debug=False)
