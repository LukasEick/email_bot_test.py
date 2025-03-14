from flask import Flask, session, jsonify
from flask_session import Session
from flask_cors import CORS
import os

app = Flask(__name__)

# Konfiguration für Sessions (Filesystem oder Redis, je nach Render-Support)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"  # Falls es nicht klappt, versuche "redis"
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "fallback_sicherer_schlüssel")

Session(app)

CORS(app, supports_credentials=True)  # CORS für Session-Cookies erlauben

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
