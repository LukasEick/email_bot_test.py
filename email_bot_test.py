import imaplib
import email
import logging
import smtplib
import os
import requests
import openai
from flask import Flask, jsonify, request, session
from flask_cors import CORS
from email.mime.text import MIMEText
from dotenv import load_dotenv
from flask_session import Session
from cryptography.fernet import Fernet

# 🔥 Lade Umgebungsvariablen aus .env Datei
load_dotenv()

# 🔑 Wichtige Umgebungsvariablen setzen
PORT = os.getenv("PORT", "8080")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
SECRET_KEY = os.getenv("SECRET_KEY", "super_secret_fallback")

# 🔍 Debugging – Prüfe, ob alle Umgebungsvariablen geladen wurden
missing_vars = [var for var in ["SUPABASE_URL", "SUPABASE_KEY", "OPENAI_API_KEY", "ENCRYPTION_KEY"] if not globals().get(var)]
if missing_vars:
    raise ValueError(f"❌ Fehlende Umgebungsvariablen: {', '.join(missing_vars)}. Bitte in Render setzen.")

# 🔒 Verschlüsselung für Passwörter
cipher = Fernet(ENCRYPTION_KEY)

# 📧 Unterstützte Provider (Dropdown)
EMAIL_PROVIDERS = {
    "gmail.com": {"imap": "imap.gmail.com", "smtp": "smtp.gmail.com"},
    "gmx.de": {"imap": "imap.gmx.net", "smtp": "mail.gmx.net"},
    "yahoo.com": {"imap": "imap.mail.yahoo.com", "smtp": "smtp.mail.yahoo.com"},
    "outlook.com": {"imap": "outlook.office365.com", "smtp": "smtp.office365.com"},
}

SMTP_PORT = 587

# 🎯 Flask-Setup
app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SECRET_KEY"] = SECRET_KEY

Session(app)
CORS(app, supports_credentials=True)

# 📌 Logging Setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# 🔒 Funktionen für Passwort-Verschlüsselung
def encrypt_password(password):
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    return cipher.decrypt(encrypted_password.encode()).decode()

# 🛡 Supabase: Login-Daten speichern (optional)
def save_login_credentials(email, password):
    try:
        url = f"{SUPABASE_URL}/rest/v1/emails"
        headers = {"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}", "Content-Type": "application/json"}
        encrypted_password = encrypt_password(password)
        response = requests.post(url, json={"email": email, "password": encrypted_password}, headers=headers)
        return response.status_code == 201
    except Exception as e:
        logging.error(f"❌ Fehler beim Speichern in Supabase: {e}")
        return False

# ✅ **Login-API** – Speichert Daten in der Session
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")
        provider = data.get("provider")

        if not email or not password or not provider:
            return jsonify({"error": "❌ E-Mail, Passwort & Provider sind erforderlich!"}), 400

        if provider not in EMAIL_PROVIDERS:
            return jsonify({"error": "❌ Ungültiger Provider!"}), 400

        # 🔥 Session speichern
        session["email"] = email
        session["password"] = password
        session["provider"] = provider
        session.modified = True

        logging.info(f"🔐 Login gespeichert für: {email}")
        return jsonify({"message": "✅ Login erfolgreich!", "email": email}), 200

    except Exception as e:
        logging.error(f"❌ Fehler beim Login: {e}")
        return jsonify({"error": f"❌ Interner Serverfehler: {e}"}), 500

# 📧 **E-Mail abrufen**
@app.route('/get_email', methods=['POST'])
def get_email():
    email = session.get("email")
    password = session.get("password")
    provider = session.get("provider")

    if not email or not password or not provider:
        return jsonify({"error": "❌ Keine gespeicherten Login-Daten gefunden!"}), 401

    provider_data = EMAIL_PROVIDERS.get(provider)
    if not provider_data:
        return jsonify({"error": "❌ Unbekannter Provider!"}), 400

    try:
        mail = imaplib.IMAP4_SSL(provider_data["imap"])
        mail.login(email, password)
        mail.select("inbox")

        status, messages = mail.search(None, "UNSEEN")
        mail_ids = messages[0].split()
        if not mail_ids:
            return jsonify({"error": "📭 Keine neuen E-Mails gefunden!"})

        email_id = mail_ids[-1]
        status, data = mail.fetch(email_id, "(RFC822)")
        msg = email.message_from_bytes(data[0][1])

        return jsonify({"email": msg["from"], "subject": msg["subject"], "body": msg.get_payload(decode=True).decode(errors="ignore")})

    except Exception as e:
        logging.error(f"❌ Fehler beim Abrufen der E-Mail: {e}")
        return jsonify({"error": "❌ Fehler beim Abrufen der E-Mail"}), 500

# 🌍 **API-Status-Check**
@app.route("/")
def home():
    return jsonify({"message": "✅ Flask API läuft!"})

# ✅ **Session-Test**
@app.route('/session_test', methods=['GET'])
def session_test():
    email = session.get("email")
    return jsonify({"message": "✅ Session funktioniert!", "email": email}) if email else jsonify({"error": "❌ Keine gespeicherten Login-Daten!"}), 401

# 🚀 **Starte den Server**
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(PORT), debug=False)
