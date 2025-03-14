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
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"  # Alternativ "redis" falls du Redis nutzt
app.config["SESSION_COOKIE_SECURE"] = True  # 🔥 Wichtig für HTTPS
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "None"  # 🔥 Wichtig für CORS!
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "fallback_sicherer_schlüssel")

Session(app)  # 🔥 Initialisiere Flask-Session


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

def save_login_credentials(email, password):
    """Speichert Login-Daten sicher in Supabase."""
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
            logging.info(f"✅ Login-Daten für {email} in Supabase gespeichert.")
            return True
        else:
            logging.error(f"❌ Fehler beim Speichern der Login-Daten in Supabase: {response.text}")
            return False

    except Exception as e:
        logging.error(f"❌ Fehler beim Speichern in Supabase: {e}")
        return False


def get_login_credentials(email):
    """Holt Login-Daten aus Supabase."""
    try:
        url = f"{SUPABASE_URL}/rest/v1/emails?select=password&email=eq.{email}"
        headers = {
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
        }
        response = requests.get(url, headers=headers)

        if response.status_code == 200 and response.json():
            encrypted_password = response.json()[0]["password"]
            return decrypt_password(encrypted_password)

    except Exception as e:
        logging.error(f"❌ Fehler beim Abrufen der Login-Daten aus Supabase: {e}")

    return None


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

@app.route('/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == "OPTIONS":
        return jsonify({"message": "CORS Preflight OK"}), 200

    try:
        data = request.get_json()
        if not data or "email" not in data or "password" not in data:
            return jsonify({"error": "❌ E-Mail und Passwort erforderlich!"}), 400

        email = data["email"]
        password = data["password"]

        # Speichere die Login-Daten in der Session
        session["email"] = email
        session["password"] = password
        logging.info(f"🔐 Session gespeichert für: {email}")

        # Backup in Supabase
        save_login_credentials(email, password)

        return jsonify({"message": "✅ Login erfolgreich!", "email": email}), 200

    except Exception as e:
        logging.error(f"❌ Fehler beim Login: {e}")
        return jsonify({"error": f"❌ Interner Serverfehler: {e}"}), 500


@app.route('/get_email', methods=['POST'])
def api_get_email():
    """Holt die letzte E-Mail basierend auf gespeicherten Supabase-Daten."""
    data = request.get_json()
    email_address = data.get("email")

    if not email_address:
        return jsonify({"error": "❌ E-Mail erforderlich!"}), 400

    email_password = get_login_credentials(email_address)

    if not email_password:
        return jsonify({"error": "❌ Keine gespeicherten Login-Daten gefunden!"}), 401

    provider = EMAIL_PROVIDERS.get(email_address.split("@")[-1])
    if not provider:
        return jsonify({"error": "❌ Unbekannter E-Mail-Anbieter!"}), 400

    try:
        mail = imaplib.IMAP4_SSL(provider["imap"])
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

                sender = msg["from"]
                subject = msg["subject"]
                body = msg.get_payload(decode=True).decode(errors="ignore")

                return jsonify({
                    "email": sender,
                    "subject": subject,
                    "body": body
                })

    except Exception as e:
        logging.error(f"❌ Fehler beim Abrufen der E-Mail: {e}")
        return jsonify({"error": "❌ Fehler beim Abrufen der E-Mail"}), 500



@app.route("/")
def home():
    return jsonify({"message": "✅ Flask API läuft!"})

@app.route('/session_test', methods=['GET'])
def session_test():
    """Prüft, ob die Session richtig gespeichert wird."""
    email = session.get("email")
    password = session.get("password")

    if not email or not password:
        logging.warning("⚠️ Keine gespeicherten Login-Daten gefunden!")
        return jsonify({"error": "❌ Keine gespeicherten Login-Daten gefunden!"}), 401

    logging.info(f"✅ Session vorhanden: {email}")
    return jsonify({"message": "✅ Session gespeichert!", "email": email, "password": "*****"}), 200



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(PORT), debug=False)
