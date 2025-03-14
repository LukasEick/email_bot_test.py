from flask import Flask, session, jsonify
from flask_session import Session
from flask_cors import CORS
import os

app = Flask(__name__)

# 🔥 Wichtige Session-Konfiguration
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_COOKIE_SECURE"] = True  # Muss bei HTTPS aktiviert sein
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "None"  # 🔥 Sehr wichtig für CORS
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "fallback_sicherer_schlüssel")

Session(app)

# **Richtige CORS-Konfiguration**
CORS(app, resources={r"/*": {"origins": "https://emailcrawlerlukas.netlify.app"}}, supports_credentials=True)

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "https://emailcrawlerlukas.netlify.app"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

@app.route("/set_session")
def set_session():
    session["test"] = "Session funktioniert!"
    return jsonify({"message": "✅ Session wurde gesetzt!"})

@app.route("/get_session")
def get_session():
    test_value = session.get("test")
    if test_value:
        return jsonify({"message": f"✅ Session-Wert: {test_value}"})
    return jsonify({"error": "❌ Keine Session gefunden!"}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8080)), debug=True)