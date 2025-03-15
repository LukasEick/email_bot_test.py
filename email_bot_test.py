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
from bs4 import BeautifulSoup
import redis



# 🔥 Lade Umgebungsvariablen
load_dotenv()

# Hole die Redis-URL aus den Render-Umgebungsvariablen
REDIS_URL = os.getenv("REDIS_URL")

# Initialisiere Redis-Verbindung
redis_client = redis.StrictRedis.from_url(REDIS_URL, decode_responses=True)

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
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SECRET_KEY"] = SECRET_KEY

Session(app)
CORS(app, supports_credentials=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# 🔥 Verbinde mit Redis für Sessions
app.config["SESSION_REDIS"] = Redis(
    host=os.getenv("REDIS_HOST"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    password=os.getenv("REDIS_PASSWORD"),
    decode_responses=True
)


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "https://emailcrawlerlukas.netlify.app"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

# Teste die Verbindung
try:
    redis_client.ping()
    print("✅ Verbindung zu Redis erfolgreich!")
except redis.ConnectionError:
    print("❌ Verbindung zu Redis fehlgeschlagen!")

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

# 📧 IMAP: Letzte ungelesene E-Mail abrufen (mit Fehlerhandling & MIME-Support)
def fetch_latest_unread_email(email_address, email_password, provider):
    """Holt die letzte ungelesene E-Mail, unterstützt verschiedene MIME-Typen."""
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
                body = extract_email_body(msg)  # 🔥 Verbesserte Methode verwenden!

                return {"email": sender, "subject": subject, "body": body}, None

    except Exception as e:
        logging.error(f"❌ Fehler beim Abrufen der E-Mail: {e}")
        return None, "❌ Fehler beim Abrufen der E-Mail!"

    return None, "❌ Unbekannter Fehler!"

def extract_email_body(msg):
    """Extrahiert den besten verfügbaren Text aus der E-Mail (Plaintext oder HTML)."""
    if msg.is_multipart():
        text_body = None
        html_body = None

        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            try:
                payload = part.get_payload(decode=True)
                decoded_text = payload.decode(errors="ignore") if payload else None

                # Falls es eine Klartext-Version gibt, speichern
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    text_body = decoded_text

                # Falls es HTML gibt, speichern
                elif content_type == "text/html" and "attachment" not in content_disposition:
                    html_body = BeautifulSoup(decoded_text, "html.parser").get_text() if decoded_text else None

            except Exception as e:
                logging.error(f"❌ Fehler beim Dekodieren der E-Mail: {e}")
                continue

        return text_body or html_body or "⚠️ Kein lesbarer Inhalt gefunden."

    # Falls es keine Multipart-E-Mail ist:
    payload = msg.get_payload(decode=True)
    return payload.decode(errors="ignore") if payload else "⚠️ Kein Inhalt gefunden."


# 🏠 **API-Startseite**
@app.route("/")
def home():
    return jsonify({"message": "✅ Flask API läuft!"})

@app.route('/login', methods=['POST'])
def login():
    """Speichert Login-Daten in der Session & Supabase"""
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")
        provider = data.get("provider")

        if not email or not password or not provider:
            return jsonify({"error": "❌ E-Mail, Passwort & Provider sind erforderlich!"}), 400

        # 🔥 Speichere in der REDIS-SESSION
        session["user"] = email
        session["password"] = password
        session["provider"] = provider
        session.modified = True  # Sicherstellen, dass Flask die Session speichert!

        logging.info(f"✅ Redis-Session gespeichert für: {email}")

        # Backup in Supabase (falls gewünscht)
        save_login_credentials(email, password)

        return jsonify({"message": "✅ Login erfolgreich!", "email": email}), 200

    except Exception as e:
        logging.error(f"❌ Fehler beim Login: {e}")
        return jsonify({"error": f"❌ Interner Serverfehler: {e}"}), 500



@app.route('/get_email', methods=['POST'])
def api_get_email():
    """Holt die letzte ungelesene E-Mail mit benutzerspezifischer Redis-Session"""
    try:
        logging.info("📡 API-Aufruf: /get_email")

        # 🔥 User-spezifische Session-Daten abrufen
        email_address = session.get("user")
        email_password = session.get("password")
        provider = session.get("provider")

        if not email_address or not email_password or not provider:
            logging.warning("⚠️ Keine gültigen Login-Daten gefunden!")
            return jsonify({"error": "❌ Keine gespeicherten Login-Daten gefunden!"}), 401

        logging.info(f"🔑 E-Mail-Adresse erkannt: {email_address}")

        # Verbindung zum IMAP-Server
        provider_info = EMAIL_PROVIDERS.get(provider)

        if not provider_info:
            logging.error(f"❌ Unbekannter E-Mail-Anbieter für: {email_address}")
            return jsonify({"error": "❌ Unbekannter E-Mail-Anbieter!"}), 400

        mail = imaplib.IMAP4_SSL(provider_info["imap"])
        mail.login(email_address, email_password)
        mail.select("inbox")

        status, messages = mail.search(None, "UNSEEN")
        mail_ids = messages[0].split()

        logging.info(f"📩 {len(mail_ids)} ungelesene E-Mails gefunden")

        if not mail_ids:
            return jsonify({"error": "📭 Keine neuen E-Mails gefunden!"})

        email_id = mail_ids[-1]
        status, data = mail.fetch(email_id, "(RFC822)")

        for response_part in data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])

                sender = msg["from"]
                subject = msg["subject"]
                body = extract_email_body(msg)

                logging.info(f"📨 E-Mail erhalten von {sender}: {subject}")

                return jsonify({"email": sender, "subject": subject, "body": body})

    except Exception as e:
        logging.error(f"❌ Fehler beim Abrufen der E-Mail: {e}")
        return jsonify({"error": "❌ Fehler beim Abrufen der E-Mail!"}), 500

@app.route('/session_test', methods=['GET'])
def session_test():
    """Testet, ob die Session richtig gespeichert wird."""
    try:
        email = session.get("email")
        password = session.get("password")

        if not email or not password:
            logging.warning("⚠️ Keine gespeicherten Login-Daten gefunden!")
            return jsonify({"error": "❌ Keine gespeicherten Login-Daten gefunden!"}), 401

        logging.info(f"✅ Session vorhanden: {email}")
        return jsonify({"message": "✅ Session gespeichert!", "email": email, "password": "*****"}), 200

    except Exception as e:
        logging.error(f"❌ Fehler mit Flask-Session: {str(e)}")
        return jsonify({"error": f"❌ Fehler mit Session: {str(e)}"}), 500



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(PORT), debug=False)
