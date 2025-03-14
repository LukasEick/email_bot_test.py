from flask import Flask, jsonify, session, request
from flask_cors import CORS
from flask_session import Session
import os

app = Flask(__name__)

# ✅ **Korrigierte Session-Konfiguration**
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"  # Falls Redis verfügbar ist, kann man hier "redis" nutzen
app.config["SESSION_FILE_DIR"] = "/tmp/flask_session"  # 🔥 Wichtig für Render
app.config["SESSION_COOKIE_SECURE"] = True  # HTTPS
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "None"  # 🔥 Wichtig für CORS mit Netlify
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "supersecretkey")

Session(app)

# ✅ **CORS-Konfiguration für Netlify**
CORS(app, resources={r"/*": {"origins": "https://emailcrawlerlukas.netlify.app"}}, supports_credentials=True)

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "https://emailcrawlerlukas.netlify.app"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

# ✅ **Session setzen**
@app.route("/set_session", methods=["POST"])
def set_session():
    try:
        data = request.get_json()
        session["test_data"] = data.get("value", "default_value")
        return jsonify({"message": "✅ Session gespeichert!", "session_value": session["test_data"]})
    except Exception as e:
        return jsonify({"error": f"❌ Fehler beim Setzen der Session: {str(e)}"}), 500

# ✅ **Session abrufen**
@app.route("/get_session", methods=["GET"])
def get_session():
    try:
        session_value = session.get("test_data")
        if session_value:
            return jsonify({"message": "✅ Session gefunden!", "session_value": session_value})
        return jsonify({"error": "❌ Keine gespeicherte Session gefunden!"}), 401
    except Exception as e:
        return jsonify({"error": f"❌ Fehler beim Abrufen der Session: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8080)), debug=False)
