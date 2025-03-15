import imaplib
import email
import logging
import os
import requests
from flask import Flask, jsonify, request, session
from flask_cors import CORS
from dotenv import load_dotenv
from flask_session import Session
from cryptography.fernet import Fernet

# 🔥 Lade Umgebungsvariablen
load_dotenv()

PORT = os.getenv("PORT", "8080")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
SECRET_KEY = os.getenv("SECRET_KEY", "super_secret_key")

# 🔥 Fehlerprüfung für Umgebungsvariablen
if not all([SUPABASE_URL, SUPABASE_KEY, ENCRYPTION_KEY, SECRET_KEY]):
    raise ValueError("❌ Fehlende Umgebungsvariablen! Stelle sicher, dass alle Werte in Render gesetzt sind.")

cipher = Fernet(ENCRYPTION_KEY)

EMAIL_PROVIDERS = {
    "gmail.com": {"imap": "imap.gmail.com"},
    "gmx.de": {"imap": "imap.gmx.net"},
    "yahoo.com": {"imap": "imap.mail.yahoo.com"},
    "outlook.com": {"imap": "outlook.office365.com"},
}

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

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# 🔒 **Passwort-Verschlüsselung**
def encrypt_password(password):
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    return cipher.decrypt(encrypted_password.encode()).decode()

# 🛡 **Speichern der Login-Daten in Supabase**
def save_login_credentials(email, password):
    try:
        url = f"{SUPABASE_URL}/rest/v1/emails"
        headers = {
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": "application/json"
        }

        encrypted_password = encrypt_password(password)
        response = requests.post(url, json={"email": email, "password": encrypted_password}, headers=headers)

        if response.status_code == 201:
            logging.info(f"✅ Login gespeichert: {email}")
            return True
        else:
            logging.error(f"❌ Fehler beim Speichern in Supabase: {response.json()}")
            return False
    except Exception as e:
        logging.error(f"❌ Fehler beim Speichern der Login-Daten: {e}")
        return False

# 🔑 **Login-Daten aus Supabase abrufen**
def get_login_credentials(email):
    try:
        url = f"{SUPABASE_URL}/rest/v1/emails?select=password&email=eq.{email}"
        headers = {"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"}
        response = requests.get(url, headers=headers)

        if response.status_code == 200 and response.json():
            encrypted_password = response.json()[0]["password"]
            return decrypt_password(encrypted_password)

    except Exception as e:
        logging.error(f"❌ Fehler beim Abrufen der Login-Daten: {e}")

    return None

# 📧 **IMAP: Letzte ungelesene E-Mail abrufen**
def fetch_latest_unread_email(email_address, email_password, provider):
    try:
        mail = imaplib.IMAP4_SSL(provider["imap"])
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
                msg = email.message_from_bytes(response_part[1])
                sender = msg["from"]
                subject = msg["subject"]
                body = extract_email_body(msg)
                return {"email": sender, "subject": subject, "body": body}, None

    except Exception as e:
        logging.error(f"❌ Fehler beim Abrufen der E-Mail: {e}")
        return None, "❌ Fehler beim Abrufen der E-Mail!"

    return None, "❌ Unbekannter Fehler!"

# 📜 **E-Mail-Text extrahieren**
def extract_email_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body = part.get_payload(decode=True).decode(errors="ignore")
                break
    else:
        body = msg.get_payload(decode=True).decode(errors="ignore")
    return body.strip()

# 🏠 **API-Startseite**
@app.route("/")
def home():
    return jsonify({"message": "✅ Flask API läuft!"})

# 🔥 **Login API (Speichert Session-Daten)**
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")
        provider = data.get("provider")

        if not email or not password or not provider:
            return jsonify({"error": "❌ Fehlende Login-Daten!"}), 400

        session["email"] = email
        session["password"] = password
        session["provider"] = provider

        save_login_credentials(email, password)

        return jsonify({"message": "✅ Login erfolgreich!"}), 200

    except Exception as e:
        logging.error(f"❌ Fehler beim Login: {e}")
        return jsonify({"error": f"❌ Fehler: {e}"}), 500

# 📩 **Letzte ungelesene E-Mail abrufen**
@app.route('/get_email', methods=['POST'])
def api_get_email():
    email_address = session.get("email")
    email_password = session.get("password")
    provider_name = session.get("provider")

    if not email_address or not email_password or not provider_name:
        return jsonify({"error": "❌ Keine gespeicherten Login-Daten!"}), 401

    provider = EMAIL_PROVIDERS.get(provider_name)
    if not provider:
        return jsonify({"error": "❌ Unbekannter E-Mail-Anbieter!"}), 400

    email_data, error = fetch_latest_unread_email(email_address, email_password, provider)
    if error:
        return jsonify({"error": error}), 400

    return jsonify(email_data)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(PORT), debug=False)
