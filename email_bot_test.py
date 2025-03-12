import imaplib
import email
import logging
import smtplib
from email.mime.text import MIMEText
from flask import Flask, jsonify, request, session
from flask_cors import CORS
import os
import openai
from flask_session import Session
import secrets
from bs4 import BeautifulSoup
from email.header import decode_header
from dotenv import load_dotenv

# 🔥 Lade Umgebungsvariablen
load_dotenv()

# Flask Setup
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")
if not app.secret_key:
    raise ValueError("❌ FLASK_SECRET_KEY ist nicht gesetzt! Bitte in .env hinzufügen.")

CORS(app, supports_credentials=True)

# ✅ **Flask-Session Konfiguration**
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = os.getenv("FLASK_COOKIE_SECURE", "False").lower() == "true"
app.config["SESSION_FILE_DIR"] = "./flask_sessions"

Session(app)

# OpenAI API Key (GPT-4)
client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Standard E-Mail-Anbieter & Server
EMAIL_PROVIDERS = {
    "gmail.com": {"imap": "imap.gmail.com", "smtp": "smtp.gmail.com"},
    "gmx.de": {"imap": "imap.gmx.net", "smtp": "mail.gmx.net"},
    "yahoo.com": {"imap": "imap.mail.yahoo.com", "smtp": "smtp.mail.yahoo.com"},
    "outlook.com": {"imap": "outlook.office365.com", "smtp": "smtp.office365.com"},
    "hotmail.com": {"imap": "outlook.office365.com", "smtp": "smtp.office365.com"},
    "web.de": {"imap": "imap.web.de", "smtp": "smtp.web.de"}
}

SMTP_PORT = 587

# Logging Setup
logging.basicConfig(filename="app.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("EmailAI")
logger.setLevel(logging.INFO)


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or "email" not in data or "password" not in data or "provider" not in data:
        return jsonify({"error": "❌ E-Mail, Passwort und Provider erforderlich!"}), 400

    email_address = data["email"].strip()
    email_password = data["password"].strip()
    provider = data["provider"].strip()

    if provider == "custom":
        imap_server = data.get("imap", "").strip()
        smtp_server = data.get("smtp", "").strip()
        if not imap_server or not smtp_server:
            return jsonify({"error": "❌ Custom-IMAP und SMTP müssen angegeben werden!"}), 400
    else:
        provider_info = EMAIL_PROVIDERS.get(provider)
        if not provider_info:
            return jsonify({"error": "❌ Unbekannter Provider!"}), 400
        imap_server = provider_info["imap"]
        smtp_server = provider_info["smtp"]

    session.clear()
    session["email"] = email_address
    session["imap_server"] = imap_server
    session["smtp_server"] = smtp_server

    logger.info(f"✅ Login erfolgreich für {email_address}")
    return jsonify({"message": "✅ Login erfolgreich!", "email": email_address}), 200


@app.route('/get_email', methods=['GET'])
def get_email():
    email_address = session.get("email")
    imap_server = session.get("imap_server")

    if not email_address or not imap_server:
        return jsonify({"error": "❌ Keine gültigen Login-Daten gefunden!"}), 401

    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(email_address, os.getenv("EMAIL_PASSWORD"))  # Verwende Umgebungsvariable für Sicherheit
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
                return jsonify({"email": sender, "subject": subject, "body": extract_email_body(msg)})
    except Exception as e:
        logger.error(f"❌ Fehler beim Abrufen der E-Mail: {e}")
        return jsonify({"error": "❌ Fehler beim Abrufen der E-Mail"}), 500


def extract_email_body(msg):
    body = None
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            if "attachment" not in content_disposition:
                try:
                    body = part.get_payload(decode=True).decode()
                except:
                    pass
    else:
        body = msg.get_payload(decode=True).decode()

    if body and "html" in msg.get_content_type():
        soup = BeautifulSoup(body, "html.parser")
        body = soup.get_text()

    return body.strip() if body else "❌ Kein E-Mail-Text verfügbar."


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    logger.info("✅ Benutzer wurde ausgeloggt")
    return jsonify({"message": "✅ Logout erfolgreich"}), 200


if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8080)), debug=debug_mode)