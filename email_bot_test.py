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
from flask import session  # 🔥 Importiere die Session
from flask import Flask, session
from flask_session import Session

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

app = Flask(__name__)

# 🔥 Session-Konfiguration
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"  # 🔥 Speichert Sessions auf dem Server
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "fallback_sicherer_schlüssel")
Session(app)  # 🔥 Flask-Session aktivieren


# 🔥 Erlaube Anfragen von Netlify-Frontend (CORS für alle Routen aktivieren)
CORS(app, resources={r"/*": {"origins": "https://emailcrawlerlukas.netlify.app"}}, supports_credentials=True)

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
    """Holt Login-Daten aus der Session & gibt Fehler aus."""
    try:
        email = session.get("email")
        password = session.get("password")

        if email and password:
            print(f"✅ Gefundene Session-Daten: {email}, Passwort: {password[:5]}******")
            return email, password

        print("🚨 Keine Session-Login-Daten gefunden!")
        return None, None

    except Exception as e:
        print(f"❌ Fehler beim Abrufen der Session-Daten: {e}")
        return None, None


@app.route('/get_email', methods=['POST'])
def api_get_email():
    """Holt die aktuelle E-Mail, auch wenn keine Session existiert."""
    data = request.get_json()

    # Falls Login-Daten mitgegeben wurden, nutze diese
    email_address = data.get("email") if data else session.get("email")
    email_password = data.get("password") if data else session.get("password")

    if not email_address or not email_password:
        return jsonify({"error": "❌ Keine gültigen Login-Daten gefunden!"}), 401

    provider = detect_email_provider(email_address)
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

                sender = extract_email_address(msg["from"])
                subject = clean_subject(msg["subject"])
                body = extract_email_body(msg)

                language = detect_language(body)
                ai_reply = generate_ai_reply(body)

                return jsonify({
                    "email": sender,
                    "subject": subject,
                    "body": body,
                    "reply": ai_reply,
                    "language": language
                })

    except Exception as e:
        logging.error(f"❌ Fehler beim Abrufen der E-Mail: {e}")
        return jsonify({"error": "❌ Fehler beim Abrufen der E-Mail"}), 500


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


@app.route('/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == "OPTIONS":
        return jsonify({"message": "CORS Preflight OK"}), 200

    try:
        data = request.get_json()
        print(f"📡 Anfrage erhalten: {data}")  # 🔍 Debugging

        if not data or "email" not in data or "password" not in data:
            return jsonify({"error": "E-Mail und Passwort erforderlich!"}), 400

        email = data["email"]
        password = data["password"]

        print(f"🔍 Speichere Login in Session: {email}")

        session["email"] = email  # 🔥 Falls es hier crasht, wird es geloggt!
        session["password"] = password

        print(f"✅ Login erfolgreich für {email}")
        return jsonify({"message": "✅ Login erfolgreich!", "email": email}), 200

    except Exception as e:
        print(f"❌ Fehler beim Login: {str(e)}")  # 🔥 Logge die genaue Exception
        return jsonify({"error": f"❌ Interner Serverfehler: {str(e)}"}), 500


@app.route("/")
def home():
    return jsonify({"message": "✅ Flask API läuft!"})

@app.route('/session_test', methods=['GET'])
def session_test():
    try:
        session["test"] = "Hallo"
        return jsonify({"message": "✅ Session funktioniert!"}), 200
    except Exception as e:
        print(f"❌ Fehler mit Flask-Session: {str(e)}")
        return jsonify({"error": f"❌ Fehler mit Session: {str(e)}"}), 500



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8080)), debug=False)
