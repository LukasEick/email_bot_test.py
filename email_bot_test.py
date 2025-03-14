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

# 🔥 Lade Umgebungsvariablen
load_dotenv()

# 🔑 Wichtige Umgebungsvariablen
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
SECRET_KEY = os.getenv("SECRET_KEY", "fallback_secure_key")

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

# 🌐 E-Mail-Anbieter-Liste
EMAIL_PROVIDERS = {
    "gmail.com": {"imap": "imap.gmail.com", "smtp": "smtp.gmail.com"},
    "gmx.de": {"imap": "imap.gmx.net", "smtp": "mail.gmx.net"},
    "yahoo.com": {"imap": "imap.mail.yahoo.com", "smtp": "smtp.mail.yahoo.com"},
    "outlook.com": {"imap": "outlook.office365.com", "smtp": "smtp.office365.com"},
    "hotmail.com": {"imap": "imap-mail.outlook.com", "smtp": "smtp-mail.outlook.com"},
    "web.de": {"imap": "imap.web.de", "smtp": "smtp.web.de"}
}

SMTP_PORT = 587

# 📧 IMAP: E-Mail abrufen
def fetch_latest_email(email_address, email_password, provider):
    """Holt die neueste ungelesene E-Mail."""
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

# 📤 SMTP: E-Mail senden
def send_email(email_address, email_password, recipient, subject, body, provider):
    """Sendet eine E-Mail über den SMTP-Server des Anbieters."""
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
        logging.error(f"❌ Fehler beim Senden der E-Mail: {e}")
        return "❌ Fehler beim Senden der E-Mail!"


# 🟢 API-ROUTEN
@app.route("/login", methods=["POST"])
def login():
    """Speichert Login-Daten in der Session."""
    data = request.get_json()
    email_address = data.get("email")
    password = data.get("password")
    provider_domain = data.get("provider")

    if not email_address or not password or not provider_domain:
        return jsonify({"error": "❌ Alle Felder müssen ausgefüllt werden!"}), 400

    provider = EMAIL_PROVIDERS.get(provider_domain)
    if not provider:
        return jsonify({"error": "❌ Ungültiger Provider!"}), 400

    session["email"] = email_address
    session["password"] = password
    session["provider"] = provider_domain

    return jsonify({"message": "✅ Login erfolgreich!"}), 200


@app.route("/get_email", methods=["GET"])
def get_email():
    """Holt die letzte ungelesene E-Mail aus dem Postfach."""
    email_address = session.get("email")
    email_password = session.get("password")
    provider_domain = session.get("provider")

    if not email_address or not email_password or not provider_domain:
        return jsonify({"error": "❌ Keine gespeicherten Login-Daten!"}), 401

    provider = EMAIL_PROVIDERS.get(provider_domain)
    if not provider:
        return jsonify({"error": "❌ Ungültiger Provider!"}), 400

    msg, error = fetch_latest_email(email_address, email_password, provider)

    if error:
        return jsonify({"error": error}), 400

    return jsonify({
        "email": msg["from"],
        "subject": msg["subject"],
        "body": msg.get_payload(decode=True).decode(errors="ignore"),
    })


@app.route("/test_session", methods=["GET"])
def test_session():
    """Testet, ob die Session korrekt gespeichert wurde."""
    return jsonify({"email": session.get("email"), "provider": session.get("provider")})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
