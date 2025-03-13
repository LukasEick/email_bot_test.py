import imaplib
import email
import logging
import smtplib
import os
import requests
import openai
import re
from flask import Flask, jsonify, request, session
from flask_cors import CORS
from email.mime.text import MIMEText
from email.header import decode_header
from bs4 import BeautifulSoup
from langdetect import detect
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask_session import Session

# 🔥 Lade Umgebungsvariablen
load_dotenv()

PORT = os.getenv("PORT", "8080")  # Falls PORT nicht existiert, setze Standardwert 8080

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
app.config.update(
    SESSION_PERMANENT=False,
    SESSION_TYPE="filesystem",
    SECRET_KEY=SECRET_KEY,
)

Session(app)
CORS(app, supports_credentials=True)

# 🔥 Logging Setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# 🔥 E-Mail Anbieter
EMAIL_PROVIDERS = {
    "gmail.com": {"imap": "imap.gmail.com", "smtp": "smtp.gmail.com"},
    "gmx.de": {"imap": "imap.gmx.net", "smtp": "mail.gmx.net"},
    "yahoo.com": {"imap": "imap.mail.yahoo.com", "smtp": "smtp.mail.yahoo.com"},
    "outlook.com": {"imap": "outlook.office365.com", "smtp": "smtp.office365.com"},
}

SMTP_PORT = 587

# 🔒 Verschlüsselung
def encrypt_password(password):
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    return cipher.decrypt(encrypted_password.encode()).decode()

# 📧 Supabase: Login speichern & abrufen
def save_login_credentials(email, password):
    """Speichert Login-Daten sicher in Supabase, falls noch nicht vorhanden."""
    try:
        url = f"{SUPABASE_URL}/rest/v1/emails"
        headers = {"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}", "Content-Type": "application/json"}

        check_response = requests.get(f"{url}?select=email&email=eq.{email}", headers=headers)
        if check_response.status_code == 200 and check_response.json():
            return True  # Login bereits gespeichert

        encrypted_password = encrypt_password(password)
        response = requests.post(url, json={"email": email, "password": encrypted_password}, headers=headers)
        return response.status_code == 201

    except Exception as e:
        logging.error(f"❌ Fehler beim Speichern der Login-Daten: {e}")
        return False

def get_login_credentials():
    """Holt Login-Daten aus der Session."""
    email = session.get("email")
    password = session.get("password")
    return (email, password) if email and password else (None, None)

# 📧 IMAP: E-Mail abrufen
def fetch_latest_email():
    email_address, email_password = get_login_credentials()
    if not email_address or not email_password:
        return None, "❌ Keine gültigen Login-Daten gefunden!"

    provider = EMAIL_PROVIDERS.get(email_address.split("@")[-1])
    if not provider:
        return None, "❌ Unbekannter E-Mail-Anbieter!"

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
                return email.message_from_bytes(response_part[1]), None

    except Exception as e:
        logging.error(f"❌ Fehler beim Abrufen der E-Mail: {e}")
        return None, "❌ Fehler beim Abrufen der E-Mail!"

# 🤖 KI-Antwort generieren
def generate_ai_reply(email_body):
    language = detect(email_body)
    prompt = f"Antwort in {'Deutsch' if language == 'de' else 'Englisch'}:\n{email_body}"

    try:
        response = openai.ChatCompletion.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7
        )
        return response["choices"][0]["message"]["content"].strip()
    except Exception as e:
        logging.error(f"❌ OpenAI API Fehler: {e}")
        return "⚠️ AI-Antwort konnte nicht generiert werden."

# 📤 E-Mail senden
def send_email(recipient, subject, body):
    email_address, email_password = get_login_credentials()
    provider = EMAIL_PROVIDERS.get(email_address.split("@")[-1])

    if not provider:
        return "❌ Unbekannter E-Mail-Anbieter!"

    try:
        with smtplib.SMTP(provider["smtp"], SMTP_PORT) as server:
            server.starttls()
            server.login(email_address, email_password)

            msg = MIMEText(body, "plain", "utf-8")
            msg["From"] = email_address
            msg["To"] = recipient
            msg["Subject"] = subject

            server.sendmail(email_address, recipient, msg.as_string())

        return "✅ Antwort erfolgreich gesendet!"
    except Exception as e:
        logging.error(f"❌ SMTP Fehler: {e}")
        return "❌ Fehler beim Senden der E-Mail!"

# 🔥 Flask Routen
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data or "email" not in data or "password" not in data:
            return jsonify({"error": "❌ E-Mail und Passwort erforderlich!"}), 400

        session["email"] = data["email"]
        session["password"] = data["password"]

        return jsonify({"message": "✅ Login erfolgreich!", "email": data["email"]}), 200
    except Exception as e:
        logging.error(f"❌ Fehler beim Login: {e}")
        return jsonify({"error": "❌ Interner Serverfehler"}), 500

@app.route('/get_email', methods=['GET'])
def api_get_email():
    msg, error = fetch_latest_email()
    if error:
        return jsonify({"error": error})

    body = msg.get_payload(decode=True).decode(errors="ignore") if msg else "⚠️ Kein Inhalt gefunden."
    ai_reply = generate_ai_reply(body)

    return jsonify({"body": body, "reply": ai_reply})

@app.route("/")
def home():
    return jsonify({"message": "✅ Flask API läuft!"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(PORT), debug=False)
