import imaplib
import email
import logging
import smtplib
from email.mime.text import MIMEText
from flask import Flask, jsonify, request, session
from flask_cors import CORS
import re
from bs4 import BeautifulSoup
from email.header import decode_header
from langdetect import detect
from dotenv import load_dotenv
import os
import openai


# Lade Umgebungsvariablen
load_dotenv()

# Flask Setup
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecretkey")  # 🔒 Sicherheit für Sessions
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# OpenAI API Key (GPT-4o)
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

SMTP_PORT = 587  # Standard SMTP-Port für Authentifizierung

# Logging aktivieren
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


@app.route('/login', methods=['POST'])
def login():
    """Speichert Login-Daten in der Session & erlaubt Provider-Override."""
    data = request.get_json()

    if not data or "email" not in data or "password" not in data or "provider" not in data:
        return jsonify({"error": "❌ E-Mail, Passwort und Provider erforderlich!"}), 400

    email = data["email"].strip()
    password = data["password"].strip()
    provider = data["provider"].strip()

    # Falls "custom" gewählt wurde, IMAP & SMTP aus den Eingaben nutzen
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

    session["email"] = email
    session["password"] = password
    session["imap_server"] = imap_server
    session["smtp_server"] = smtp_server

    logging.info(f"✅ Login erfolgreich für {email}")
    return jsonify({"message": "✅ Login erfolgreich!", "email": email}), 200


@app.route('/get_email', methods=['GET'])
def api_get_email():
    """Holt die neueste ungelesene E-Mail für den aktuell eingeloggten Benutzer."""
    email_address = session.get("email")
    email_password = session.get("password")

    if not email_address or not email_password:
        logging.error("❌ Fehler: Keine gültigen Login-Daten in der Session gefunden!")
        return jsonify({"error": "❌ Keine gültigen Login-Daten gefunden!"}), 401

    provider = detect_email_provider(email_address)
    if not provider:
        logging.error(f"❌ Fehler: Unbekannter E-Mail-Anbieter für {email_address}")
        return jsonify({"error": "❌ Unbekannter E-Mail-Anbieter!"}), 400

    try:
        mail = imaplib.IMAP4_SSL(provider["imap"])
        mail.login(email_address, email_password)
        mail.select("inbox")

        status, messages = mail.search(None, "UNSEEN")
        mail_ids = messages[0].split()

        if not mail_ids:
            logging.info("📭 Keine neuen E-Mails gefunden.")
            return jsonify({"error": "📭 Keine neuen E-Mails gefunden!"})

        email_id = mail_ids[-1]
        status, data = mail.fetch(email_id, "(RFC822)")

        for response_part in data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])

                sender = msg["from"]
                subject = msg["subject"]
                body = extract_email_body(msg)

                return jsonify({
                    "email": sender,
                    "subject": subject,
                    "body": body
                })

    except Exception as e:
        logging.error(f"❌ Fehler beim Abrufen der E-Mail: {e}")
        return jsonify({"error": "❌ Fehler beim Abrufen der E-Mail"}), 500



@app.route('/send_reply', methods=['POST'])
def send_reply():
    """Sendet eine Antwort-E-Mail über den gespeicherten SMTP-Server."""
    email_address = session.get("email")
    email_password = session.get("password")
    smtp_server = session.get("smtp_server")

    if not email_address or not email_password or not smtp_server:
        return jsonify({"error": "❌ Keine gültigen Login-Daten gefunden!"}), 401

    data = request.get_json()

    if not data or "email" not in data or "subject" not in data or "body" not in data:
        return jsonify({"error": "❌ Fehlende Daten für die Antwort!"}), 400

    recipient = data["email"]
    subject = data["subject"]
    body = data["body"]

    try:
        server = smtplib.SMTP(smtp_server, SMTP_PORT)
        server.starttls()
        server.login(email_address, email_password)

        msg = MIMEText(body, "plain", "utf-8")
        msg["From"] = email_address
        msg["To"] = recipient
        msg["Subject"] = subject

        server.sendmail(email_address, recipient, msg.as_string())
        server.quit()

        logging.info(f"✅ Antwort gesendet an {recipient}")
        return jsonify({"message": "✅ Antwort erfolgreich gesendet!"}), 200

    except Exception as e:
        logging.error(f"❌ Fehler beim Senden der Antwort: {e}")
        return jsonify({"error": "❌ Fehler beim Senden der Antwort!"}), 500

@app.route('/logout', methods=['POST'])
def logout():
    """Löscht die aktuelle Session, damit sich Benutzer sauber abmelden können."""
    session.clear()  # 🔥 Löscht alle Session-Daten
    logging.info("✅ Benutzer wurde ausgeloggt")
    return jsonify({"message": "✅ Logout erfolgreich"}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))  # Nutzt PORT-Variable von Render
    app.run(host="0.0.0.0", port=port, debug=True)

