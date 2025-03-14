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
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask_session import Session

# 🔥 Lade Umgebungsvariablen
load_dotenv()

PORT = os.getenv("PORT", "8080")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
SECRET_KEY = os.getenv("SECRET_KEY", "fallback_sicherer_schlüssel")

# 🔥 Fehlerprüfung für Umgebungsvariablen
missing_vars = [var for var in ["SUPABASE_URL", "SUPABASE_KEY", "OPENAI_API_KEY", "ENCRYPTION_KEY"] if not globals().get(var)]
if missing_vars:
    raise ValueError(f"❌ Fehlende Umgebungsvariablen: {', '.join(missing_vars)}. Bitte in Render setzen.")

cipher = Fernet(ENCRYPTION_KEY)

# 🔥 Flask Setup
app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SECRET_KEY"] = SECRET_KEY

Session(app)
CORS(app, supports_credentials=True)

# 🔥 Logging Setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# 🔥 Verfügbare E-Mail Anbieter (Für Dropdown-Menü!)
EMAIL_PROVIDERS = {
    "Gmail": {"imap": "imap.gmail.com", "smtp": "smtp.gmail.com"},
    "GMX": {"imap": "imap.gmx.net", "smtp": "mail.gmx.net"},
    "Yahoo": {"imap": "imap.mail.yahoo.com", "smtp": "smtp.mail.yahoo.com"},
    "Outlook": {"imap": "outlook.office365.com", "smtp": "smtp.office365.com"},
    "Web.de": {"imap": "imap.web.de", "smtp": "smtp.web.de"},
}

SMTP_PORT = 587

# 🔒 Passwort-Verschlüsselung
def encrypt_password(password):
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    return cipher.decrypt(encrypted_password.encode()).decode()

# 🔑 Speichert Login-Daten in Supabase
def save_login_credentials(email, password, provider):
    try:
        url = f"{SUPABASE_URL}/rest/v1/emails"
        headers = {
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": "application/json"
        }
        encrypted_password = encrypt_password(password)

        logging.info(f"📡 Speichere Login in Supabase für: {email} ({provider})")

        response = requests.post(url, json={"email": email, "password": encrypted_password, "provider": provider}, headers=headers)
        response_json = response.json()

        if response.status_code == 201:
            logging.info(f"✅ Login erfolgreich gespeichert: {email}")
            return True
        else:
            logging.error(f"❌ Fehler beim Speichern in Supabase: {response.status_code} - {response_json}")
            return False
    except Exception as e:
        logging.error(f"❌ Fehler beim Speichern in Supabase: {e}")
        return False

# 🔑 Holt gespeicherte Login-Daten aus Supabase
def get_login_credentials(email):
    try:
        url = f"{SUPABASE_URL}/rest/v1/emails?select=password,provider&email=eq.{email}"
        headers = {
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
        }
        response = requests.get(url, headers=headers)

        if response.status_code == 200 and response.json():
            data = response.json()[0]
            return decrypt_password(data["password"]), data["provider"]
    except Exception as e:
        logging.error(f"❌ Fehler beim Abrufen aus Supabase: {e}")
    return None, None

# 📧 Holt letzte E-Mail (Manuell gewählter Provider!)
def fetch_latest_email(email_address, email_password, provider):
    if provider not in EMAIL_PROVIDERS:
        return None, "❌ Unbekannter E-Mail-Anbieter!"

    try:
        mail = imaplib.IMAP4_SSL(EMAIL_PROVIDERS[provider]["imap"])
        mail.login(email_address, email_password)
        mail.select("inbox")

        status, messages = mail.search(None, "UNSEEN")
        mail_ids = messages[0].split()

        if not mail_ids:
            return None, "📭 Keine neuen E-Mails gefunden!"

        email_id = mail_ids[-1]
        status, data = mail.fetch(email_id, "(RFC822)")

        for response_part in data:
            if isinstance(response_part, tuple):
                return email.message_from_bytes(response_part[1]), None
    except Exception as e:
        logging.error(f"❌ Fehler beim Abrufen der E-Mail: {e}")
        return None, "❌ Fehler beim Abrufen der E-Mail!"

# 🔥 API-Endpoints

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data or "email" not in data or "password" not in data or "provider" not in data:
            return jsonify({"error": "❌ E-Mail, Passwort und Provider erforderlich!"}), 400

        email = data["email"]
        password = data["password"]
        provider = data["provider"]

        if provider not in EMAIL_PROVIDERS:
            return jsonify({"error": "❌ Ungültiger Provider!"}), 400

        session["email"] = email
        session["password"] = password
        session["provider"] = provider
        logging.info(f"🔐 Session gespeichert für: {email} ({provider})")

        save_login_credentials(email, password, provider)

        return jsonify({"message": "✅ Login erfolgreich!", "email": email, "provider": provider}), 200
    except Exception as e:
        logging.error(f"❌ Fehler beim Login: {e}")
        return jsonify({"error": f"❌ Serverfehler: {e}"}), 500

@app.route('/get_email', methods=['POST'])
def api_get_email():
    data = request.get_json()
    email_address = data.get("email")
    provider = data.get("provider")

    if not email_address or not provider:
        return jsonify({"error": "❌ E-Mail und Provider erforderlich!"}), 400

    email_password, saved_provider = get_login_credentials(email_address)

    if not email_password or provider != saved_provider:
        return jsonify({"error": "❌ Falsche oder fehlende Login-Daten!"}), 401

    msg, error = fetch_latest_email(email_address, email_password, provider)
    if error:
        return jsonify({"error": error})

    return jsonify({
        "email": msg["from"],
        "subject": msg["subject"],
        "body": msg.get_payload(decode=True).decode(errors="ignore"),
    })

@app.route("/")
def home():
    return jsonify({"message": "✅ Flask API läuft!"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(PORT), debug=False)
