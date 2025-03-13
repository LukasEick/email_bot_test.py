import imaplib
import email
import logging
import smtplib
import os
import requests
import openai
import re
from flask import Flask, jsonify, request
from flask_cors import CORS
from email.mime.text import MIMEText
from email.header import decode_header
from bs4 import BeautifulSoup
from langdetect import detect
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Lade Umgebungsvariablen
load_dotenv()

SUPABASE_URL = "https://qulqaxpvnaupdvuycxoe.supabase.co"
SUPABASE_KEY = os.environ.get("SUPABASE_KEY") or "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InF1bHFheHB2bmF1cGR2dXljeG9lIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDExNjExMDIsImV4cCI6MjA1NjczNzEwMn0.n3Z1yiac6hEfzxAJreuH1eTFMlkS6v-6D_i6OOpHBLw"


OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
PORT = os.environ.get("PORT", 8080)  # Falls PORT fehlt, nutze 5000

# Prüfe, ob alle Variablen vorhanden sind
missing_vars = [var for var in ["SUPABASE_URL", "SUPABASE_KEY", "OPENAI_API_KEY", "ENCRYPTION_KEY"] if not globals().get(var)]
if missing_vars:
    raise ValueError(f"❌ Fehlende Umgebungsvariablen: {', '.join(missing_vars)}. Bitte in Render setzen.")


cipher = Fernet(ENCRYPTION_KEY)

# Flask Setup
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "https://emailcrawlerlukas.netlify.app"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


# Logging aktivieren
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Logge alle Umgebungsvariablen, um zu sehen, was wirklich geladen wird
print("🔍 DEBUG: Alle Render-Umgebungsvariablen")
for key, value in os.environ.items():
    print(f"{key}: {value[:10]}******")  # Zeigt nur die ersten 10 Zeichen für Sicherheit

# Prüfe, ob SUPABASE_KEY da ist
if "SUPABASE_KEY" not in os.environ:
    raise ValueError("❌ SUPABASE_KEY fehlt! Render hat es nicht geladen.")
else:
    print(f"✅ SUPABASE_KEY geladen: {SUPABASE_KEY[:5]}******")  # Zeigt die ersten 5 Zeichen


# E-Mail-Anbieter (IMAP & SMTP)
EMAIL_PROVIDERS = {
    "gmail.com": {"imap": "imap.gmail.com", "smtp": "smtp.gmail.com"},
    "gmx.de": {"imap": "imap.gmx.net", "smtp": "mail.gmx.net"},
    "yahoo.com": {"imap": "imap.mail.yahoo.com", "smtp": "smtp.mail.yahoo.com"},
    "outlook.com": {"imap": "outlook.office365.com", "smtp": "smtp.office365.com"},
}

SMTP_PORT = 587  # Standard SMTP Port


### 🔒 Passwort-Verschlüsselung ###
def encrypt_password(password):
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    return cipher.decrypt(encrypted_password.encode()).decode()


### 🛡 Supabase: Login-Daten sicher speichern ###
def save_login_credentials(email, password):
    """Speichert Login-Daten sicher in Supabase, falls noch nicht vorhanden."""
    try:
        url = f"{SUPABASE_URL}/rest/v1/emails"
        headers = {
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": "application/json"
        }

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
    """Holt die verschlüsselten Login-Daten aus Supabase."""
    try:
        url = f"{SUPABASE_URL}/rest/v1/emails?select=email,password&order=id.desc&limit=1"
        headers = {
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200 and response.json():
            data = response.json()[0]
            return data["email"], decrypt_password(data["password"])
    except Exception as e:
        logging.error(f"❌ Fehler beim Abrufen der Login-Daten: {e}")

    return None, None


### 📧 IMAP: E-Mails abrufen ###
def fetch_latest_email():
    """Holt die neueste ungelesene E-Mail sicher und effizient."""
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
        mail_ids = messages[0].split()[-1:]  # Nur letzte ungelesene E-Mail holen
        if not mail_ids:
            return None, "📭 Keine neuen E-Mails gefunden!"

        status, data = mail.fetch(mail_ids[-1], "(BODY.PEEK[])")
        for response_part in data:
            if isinstance(response_part, tuple):
                return email.message_from_bytes(response_part[1]), None

    except Exception as e:
        logging.error(f"❌ Fehler beim Abrufen der E-Mail: {e}")
        return None, "❌ Fehler beim Abrufen der E-Mail!"

    return None, "❌ Unbekannter Fehler!"


### 🤖 OpenAI GPT-4o: KI-Antwort generieren ###
def generate_ai_reply(email_body):
    """Erstellt eine KI-generierte Antwort mit OpenAI GPT-4o."""
    language = detect(email_body)
    prompt = {
        "de": f"Antwort in Deutsch:\n{email_body}",
        "en": f"Response in English:\n{email_body}"
    }.get(language, email_body)

    try:
        response = openai.ChatCompletion.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7,
            timeout=10
        )
        return response["choices"][0]["message"]["content"].strip()
    except openai.error.OpenAIError as e:
        logging.error(f"❌ OpenAI API Fehler: {e}")
        return "⚠️ AI-Antwort konnte nicht generiert werden."


### 📤 SMTP: E-Mail senden ###
def send_email(recipient, subject, body):
    """Sendet eine E-Mail über den SMTP-Server des Anbieters."""
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


### 🌍 Flask API ###
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
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8080)), debug=False)
