import imaplib
import email
import logging
import os
import requests
import redis
from flask import Flask, jsonify, request, session
from flask_cors import CORS
from dotenv import load_dotenv
from flask_session import Session
from cryptography.fernet import Fernet
from bs4 import BeautifulSoup

# 🔥 Lade Umgebungsvariablen
load_dotenv()

# 🚀 Lade die Redis-URL aus den Umgebungsvariablen
REDIS_URL = os.getenv("REDIS_URL")

if not REDIS_URL:
    raise ValueError("❌ Keine REDIS_URL gefunden! Stelle sicher, dass sie in den Render-Umgebungsvariablen gesetzt ist.")

# ✅ Initialisiere Redis-Client
try:
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    redis_client.ping()  # Testet die Verbindung
    print("✅ Verbindung zu Redis erfolgreich!")
except redis.ConnectionError:
    raise ValueError("❌ Verbindung zu Redis fehlgeschlagen! Überprüfe die REDIS_URL.")

# 🔥 Lade andere Umgebungsvariablen
PORT = os.getenv("PORT", "8080")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
SECRET_KEY = os.getenv("SECRET_KEY", "super_secret_key")

# 🔥 Fehlerprüfung für alle wichtigen Umgebungsvariablen
if not all([SUPABASE_URL, SUPABASE_KEY, ENCRYPTION_KEY, SECRET_KEY]):
    raise ValueError("❌ Fehlende Umgebungsvariablen! Stelle sicher, dass alle Werte in Render gesetzt sind.")

# 🔐 Initialisiere Verschlüsselung
cipher = Fernet(ENCRYPTION_KEY)

# 📩 E-Mail Provider Konfiguration
EMAIL_PROVIDERS = {
    "gmail.com": {"imap": "imap.gmail.com"},
    "gmx.de": {"imap": "imap.gmx.net"},
    "yahoo.com": {"imap": "imap.mail.yahoo.com"},
    "outlook.com": {"imap": "outlook.office365.com"},
}

# 🔥 Flask Setup mit Redis für Sessions
app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SESSION_KEY_PREFIX"] = "session:"
app.config["SESSION_REDIS"] = redis.from_url(REDIS_URL, decode_responses=True)

Session(app)
CORS(app, supports_credentials=True)

# ✅ Logging Setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "https://emailcrawlerlukas.netlify.app"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

# 🔒 **Passwort-Verschlüsselung**
def encrypt_password(password):
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    return cipher.decrypt(encrypted_password.encode()).decode()

def detect_email_provider(email_address):
    """Erkennt den E-Mail-Anbieter anhand der Domain."""
    if not email_address:
        logging.error("❌ Keine E-Mail-Adresse übergeben!")
        return None

    domain = email_address.split("@")[-1].lower()
    logging.info(f"🔍 Überprüfe E-Mail-Domain: {domain}")

    return EMAIL_PROVIDERS.get(domain, None)

# ✅ **Login API mit Session & Supabase**
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")
        provider = data.get("provider")

        if not email or not password or not provider:
            return jsonify({"error": "❌ E-Mail, Passwort & Provider sind erforderlich!"}), 400

        # 🔥 Speichere in der Redis-Session
        session["user"] = email
        session["password"] = password
        session["provider"] = provider
        session.modified = True

        logging.info(f"✅ Redis-Session gespeichert für: {email}")

        # 🔥 Backup in Supabase
        save_login_credentials(email, password)

        return jsonify({"message": "✅ Login erfolgreich!", "email": email}), 200

    except Exception as e:
        logging.error(f"❌ Fehler beim Login: {e}")
        return jsonify({"error": f"❌ Interner Serverfehler: {e}"}), 500

# ✅ **Speichern der Anmeldedaten in Supabase**
def save_login_credentials(email, password):
    """Speichert Login-Daten in Supabase, falls sie noch nicht existieren."""
    try:
        url = f"{SUPABASE_URL}/rest/v1/emails"
        headers = {
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": "application/json"
        }

        # ✅ Vor dem Speichern prüfen, ob E-Mail existiert
        check_response = requests.get(f"{url}?email=eq.{email}&select=email", headers=headers)

        if check_response.status_code == 200 and check_response.json():
            logging.info(f"⚠️ E-Mail {email} existiert bereits in Supabase. Kein erneutes Speichern nötig.")
            return True  # E-Mail existiert bereits → Kein Speichern nötig

        encrypted_password = encrypt_password(password)
        response = requests.post(url, json={"email": email, "password": encrypted_password}, headers=headers)

        if response.status_code == 201:
            logging.info(f"✅ Login-Daten erfolgreich gespeichert für {email}")
            return True
        else:
            logging.error(f"❌ Fehler beim Speichern in Supabase: {response.status_code} - {response.json()}")
            return False

    except Exception as e:
        logging.error(f"❌ Fehler beim Speichern der Login-Daten in Supabase: {e}")
        return False

# 📧 **IMAP: Letzte ungelesene E-Mail abrufen**
@app.route('/get_email', methods=['POST'])
def api_get_email():
    try:
        logging.info("📡 API-Aufruf: /get_email")

        # 🔥 Abrufen der Benutzerspezifischen Session-Daten
        email_address = session.get("user")
        email_password = session.get("password")
        provider = session.get("provider")

        if not email_address or not email_password or not provider:
            logging.warning("⚠️ Keine gültigen Login-Daten gefunden!")
            return jsonify({"error": "❌ Keine gespeicherten Login-Daten gefunden!"}), 401

        logging.info(f"🔑 E-Mail-Adresse erkannt: {email_address}")

        provider_info = EMAIL_PROVIDERS.get(provider)

        if not provider_info:
            logging.error(f"❌ Unbekannter E-Mail-Anbieter für: {email_address}")
            return jsonify({"error": "❌ Unbekannter E-Mail-Anbieter!"}), 400

        mail = imaplib.IMAP4_SSL(provider_info["imap"])
        mail.login(email_address, email_password)
        mail.select("inbox")

        status, messages = mail.search(None, "UNSEEN")
        mail_ids = messages[0].split()

        if not mail_ids:
            return jsonify({"error": "📭 Keine neuen E-Mails gefunden!"})

        email_id = mail_ids[-1]
        status, data = mail.fetch(email_id, "(RFC822)")

        for response_part in data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])

                return jsonify({"email": msg["from"], "subject": msg["subject"], "body": msg.get_payload(decode=True).decode(errors="ignore")})

    except Exception as e:
        logging.error(f"❌ Fehler beim Abrufen der E-Mail: {e}")
        return jsonify({"error": "❌ Fehler beim Abrufen der E-Mail!"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(PORT), debug=False)
