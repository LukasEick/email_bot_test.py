import imaplib
import email
import logging
import os
import requests
import redis
import smtplib
import re
from flask import Flask, jsonify, request, session
from flask_cors import CORS
from dotenv import load_dotenv
from flask_session import Session
from cryptography.fernet import Fernet
from bs4 import BeautifulSoup
from email.mime.text import MIMEText
from email.header import decode_header
from langdetect import detect
from openai import OpenAI
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
import imaplib
import base64
import json
from google_auth_oauthlib.flow import Flow
from flask import redirect, url_for


google_credentials_json = os.getenv("GOOGLE_CREDENTIALS")

if not google_credentials_json:
    raise ValueError("❌ GOOGLE_CREDENTIALS fehlt!")

credentials_data = json.loads(google_credentials_json)

# 🔥 Debugging: Zeigt, was in credentials_data wirklich drin ist
print("✅ GOOGLE_CREDENTIALS Struktur:", json.dumps(credentials_data, indent=4))

if "web" not in credentials_data:
    raise ValueError("❌ Der 'web'-Eintrag fehlt in GOOGLE_CREDENTIALS JSON!")

print("✅ 'web' Eintrag existiert in GOOGLE_CREDENTIALS.")


flow = Flow.from_client_config(
    credentials_data,
    scopes=["https://mail.google.com/", "openid", "https://www.googleapis.com/auth/userinfo.email"],
    redirect_uri="https://email-bot-s8vw.onrender.com/oauth/callback"
)



# 🔥 Lade Umgebungsvariablen
load_dotenv()

# 🚀 Lade die Redis-URL aus den Umgebungsvariablen
REDIS_URL = os.getenv("REDIS_URL")

if not REDIS_URL:
    raise ValueError("❌ Keine REDIS_URL gefunden! Stelle sicher, dass sie in den Render-Umgebungsvariablen gesetzt ist.")

# ✅ Initialisiere Redis-Client
try:
    redis_client = redis.from_url(REDIS_URL, decode_responses=False)
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
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=OPENAI_API_KEY)

# 📩 E-Mail Provider Konfiguration
EMAIL_PROVIDERS = {
    "gmail.com": {"imap": "imap.gmail.com", "smtp": "smtp.gmail.com", "port": 587},
    "gmx.de": {"imap": "imap.gmx.net", "smtp": "mail.gmx.net", "port": 465},
    "yahoo.com": {"imap": "imap.mail.yahoo.com", "smtp": "smtp.mail.yahoo.com", "port": 587},
    "outlook.com": {"imap": "outlook.office365.com", "smtp": "smtp.office365.com", "port": 587},
    "web.de": {"imap": "imap.web.de", "smtp": "smtp.web.de", "port": 587}
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
app.config["SESSION_REDIS"] = redis.from_url(REDIS_URL, decode_responses=False)

Session(app)
CORS(app, supports_credentials=True)

# ✅ Logging Setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

@app.route('/oauth/login')
def oauth_login():
    """Startet den Google OAuth-Flow"""
    google_credentials_json = os.getenv("GOOGLE_CREDENTIALS")

    if not google_credentials_json:
        return jsonify({"error": "❌ GOOGLE_CREDENTIALS fehlt!"}), 500

    credentials_data = json.loads(google_credentials_json)

    flow = Flow.from_client_config(
        credentials_data,
        scopes=["https://mail.google.com/", "openid", "https://www.googleapis.com/auth/userinfo.email"],
        redirect_uri="https://email-bot-s8vw.onrender.com/oauth/callback"
    )

    auth_url, _ = flow.authorization_url(prompt="consent")
    return redirect(auth_url)  # Nutzer wird zur Google-Anmeldeseite weitergeleitet



def authenticate_gmail():
    creds = None
    # Falls Token existiert, laden
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)

    # Falls keine gültigen Credentials existieren, erneuere sie
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("client_secret.json", SCOPES)
            creds = flow.run_local_server(port=0)

        # Speichere die Credentials für spätere Logins
        with open("token.json", "w") as token:
            token.write(creds.to_json())

    return creds

def connect_gmail_oauth():
    creds = authenticate_gmail()  # OAuth-Authentifizierung

    email_address = creds.id_token["email"]
    access_token = creds.token

    auth_string = f"user={email_address}\x01auth=Bearer {access_token}\x01\x01"
    auth_string = base64.b64encode(auth_string.encode()).decode()

    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.authenticate("XOAUTH2", lambda x: auth_string)
    mail.select("inbox")

    return mail


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

def detect_language(text):
    """Erkennt die Sprache der E-Mail."""
    try:
        return "de" if detect(text) == "de" else "en"
    except:
        return "en"


@app.route('/oauth/callback')
def oauth_callback():
    """Empfängt das OAuth-Token nach erfolgreichem Login"""
    google_credentials_json = os.getenv("GOOGLE_CREDENTIALS")

    if not google_credentials_json:
        return jsonify({"error": "❌ GOOGLE_CREDENTIALS fehlt!"}), 500

    credentials_data = json.loads(google_credentials_json)

    flow = Flow.from_client_config(
        credentials_data,
        scopes=["https://mail.google.com/", "openid", "https://www.googleapis.com/auth/userinfo.email"],
        redirect_uri="https://email-bot-s8vw.onrender.com/oauth/callback"
    )

    flow.fetch_token(authorization_response=request.url)

    creds = flow.credentials
    access_token = creds.token  # ✅ Speichert das Token des Nutzers
    user_email = creds.id_token.get("email")

    if not user_email:
        return jsonify({"error": "❌ E-Mail-Adresse konnte nicht ermittelt werden."}), 400

    # 🔥 Speichert das Token in Redis mit der Nutzer-E-Mail als Key
    redis_client.set(f"oauth_token:{user_email}", access_token)

    logging.info(f"✅ OAuth-Token für {user_email} gespeichert.")
    return redirect(url_for("home"))  # Weiterleitung zur Startseite


def gmail_login(user_email):
    """Meldet sich mit OAuth-Token bei Gmail IMAP an"""
    access_token = redis_client.get(f"oauth_token:{user_email}")

    if not access_token:
        raise ValueError("❌ Kein OAuth-Token für den Benutzer gefunden!")

    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    auth_string = f"user={user_email}\1auth=Bearer {access_token}\1\1"
    mail.authenticate("XOAUTH2", lambda x: auth_string.encode("utf-8"))
    mail.select("inbox")
    return mail


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
        session["user"] = email.encode("utf-8")
        session["password"] = password.encode("utf-8")
        session["provider"] = provider.encode("utf-8")
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

def get_login_credentials():
    """Holt Login-Daten entweder aus Redis-Session oder aus Supabase."""
    try:
        # 🔥 Versuche zuerst, die Login-Daten aus der Redis-Session zu bekommen
        email = session.get("user")
        password = session.get("password")

        if isinstance(email, bytes):  # Falls es als Bytes gespeichert ist, dekodieren
            email = email.decode("utf-8")
        if isinstance(password, bytes):
            password = password.decode("utf-8")

        if email and password:
            logging.info(f"✅ Login-Daten aus Redis-Session abgerufen: {email}")
            return email, password  # Direkt aus Redis zurückgeben!

        # 🔥 Falls nicht in Redis vorhanden, aus Supabase abrufen
        url = f"{SUPABASE_URL}/rest/v1/emails?select=email,password&order=id.desc&limit=1"
        headers = {
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": "application/json"
        }
        response = requests.get(url, headers=headers)

        if response.status_code == 200 and response.json():
            data = response.json()[0]
            logging.info(f"✅ Login-Daten aus Supabase erhalten: {data.get('email')}")

            # Speichere sie jetzt auch direkt in Redis-Session
            session["user"] = data.get("email").encode("utf-8")
            session["password"] = data.get("password").encode("utf-8")
            session.modified = True  # Session speichern!

            return data.get("email"), data.get("password")

    except Exception as e:
        logging.error(f"❌ Fehler beim Abrufen der Login-Daten: {e}")

    return None, None  # Falls kein Login gefunden wurde


def extract_email_body(msg):
    """Extrahiert und bereinigt den Inhalt einer E-Mail (Text bevorzugt, HTML als Fallback)."""
    body = None

    try:
        # Prüfe, ob die E-Mail mehrere Teile hat (HTML + Text)
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))

                # Falls eine reine Text-Version vorhanden ist, nimm diese zuerst
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body = payload.decode(errors="ignore").strip()
                    break  # Falls wir reinen Text gefunden haben, hören wir hier auf

                # Falls nur HTML vorhanden ist, nutze diese als Fallback
                elif content_type == "text/html" and not body:
                    payload = part.get_payload(decode=True)
                    if payload:
                        soup = BeautifulSoup(payload, "html.parser")
                        body = soup.get_text("\n").strip()

        else:
            # Falls die E-Mail nur aus einem einzigen Part besteht
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode(errors="ignore").strip()

        # Falls body immer noch None ist, setze einen Fallback
        if not body:
            return "⚠️ No readable content found."

        # 🔥 **Verbesserte Bereinigung**
        body = clean_email_body(body)

        return body

    except Exception as e:
        logging.error(f"❌ Fehler beim Extrahieren des E-Mail-Texts: {e}")
        return "⚠️ Error processing email content."

def extract_email_address(sender):
    """Extrahiert die reine E-Mail-Adresse aus dem 'Von'-Feld."""
    match = re.search(r'<(.+?)>', sender)
    return match.group(1) if match else sender  # Falls keine <>-Klammern, nehme den Originaltext

def clean_subject(subject):
    """Dekodiert und bereinigt den E-Mail-Betreff."""
    decoded_parts = decode_header(subject)
    subject_clean = ''.join(
        part.decode(encoding or "utf-8") if isinstance(part, bytes) else part
        for part, encoding in decoded_parts
    )
    return subject_clean.strip()

def clean_email_body(body):
    """Entfernt unnötige Leerzeichen, HTML-Tags, Links und typische Header-Zeilen aus der E-Mail."""
    try:
        # 1️⃣ Entferne überflüssige Leerzeichen & Zeilenumbrüche
        body = re.sub(r'\n+', '\n', body).strip()  # Entferne doppelte Leerzeilen
        body = re.sub(r'\s+', ' ', body)  # Entferne doppelte Leerzeichen

        # 2️⃣ Entferne CSS & HTML-Kommandos
        body = re.sub(r'<.*?>', '', body)  # Entfernt HTML-Tags
        body = re.sub(r'{.*?}', '', body)  # Entfernt CSS-Code
        body = re.sub(r'!DOCTYPE.*', '', body)  # Entfernt DOCTYPE-Zeilen
        body = re.sub(r'http\S+', '', body)  # Entfernt Links

        # 3️⃣ Entferne typische Header-Zeilen, die E-Mails oft haben
        header_keywords = [
            "View this email", "Unsubscribe", "Copyright", "Terms of Service",
            "Privacy Policy", "All rights reserved", "Reply-To", "Sent from"
        ]
        body_lines = body.split("\n")
        filtered_body = "\n".join(
            [line for line in body_lines if not any(keyword in line for keyword in header_keywords)]
        )

        # Falls nach der Bereinigung nichts mehr übrig ist, setze Standardtext
        if not filtered_body.strip():
            return "⚠️ No readable content found."

        return filtered_body.strip()

    except Exception as e:
        logging.error(f"❌ Fehler beim Bereinigen des E-Mail-Texts: {e}")
        return "⚠️ Error cleaning email content."

def generate_ai_reply(email_body):
    """Erstellt eine KI-Antwort mit OpenAI GPT-4o in der erkannten Sprache."""
    language = detect_language(email_body)  # 🔥 Spracherkennung

    prompts = {
        "de": f"""
        Du bist ein professioneller virtueller Assistent.
        Hier ist eine E-Mail, auf die du höflich und professionell antworten sollst.

        **E-Mail-Inhalt**:
        {email_body}

        Bitte schreibe direkt eine passende Antwort auf Deutsch, ohne Betreff oder Anrede.
        """,
        "en": f"""
        You are a professional virtual assistant.
        Here is an email that you should respond to politely and professionally.

        **Email content**:
        {email_body}

        Please write a suitable response in English, without subject or salutation.
        """
    }

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a professional assistant."},
                {"role": "user", "content": prompts[language]}
            ],
            temperature=0.7
        )

        return response.choices[0].message.content.strip() if response.choices else "Error generating AI response."

    except Exception as e:
        logging.error(f"❌ Error generating AI response: {e}")
        return "There was a problem generating the response."

@app.route('/get_email', methods=['POST'])
def api_get_email():
    """Holt die letzte ungelesene E-Mail mit OAuth-Unterstützung für Gmail."""
    email_address = session.get("user")
    provider = session.get("provider")

    if isinstance(email_address, bytes):
        email_address = email_address.decode("utf-8")
    if isinstance(provider, bytes):
        provider = provider.decode("utf-8")

    if not email_address or not provider:
        logging.warning("⚠️ Keine gültigen Login-Daten gefunden!")
        return jsonify({"error": "❌ Keine gespeicherten Login-Daten gefunden!"}), 401

    logging.info(f"🔑 E-Mail-Adresse erkannt: {email_address}")

    if provider == "gmail.com":
        mail = gmail_login(email_address)  # 🔥 OAuth-Login für Gmail
    else:
        email_password = session.get("password")
        if isinstance(email_password, bytes):
            email_password = email_password.decode("utf-8")

        provider_info = EMAIL_PROVIDERS.get(provider)
        if not provider_info:
            return jsonify({"error": "❌ Unbekannter E-Mail-Anbieter!"}), 400

        mail = imaplib.IMAP4_SSL(provider_info["imap"])
        mail.login(email_address, email_password)

    mail.select("inbox")

    status, messages = mail.search(None, "UNSEEN")
    mail_ids = messages[0].split()

    if not mail_ids:
        return jsonify({"error": "📭 Keine neuen E-Mails gefunden!"})

    latest_email_id = mail_ids[-1]
    status, data = mail.fetch(latest_email_id, "(RFC822)")

    for response_part in data:
        if isinstance(response_part, tuple):
            msg = email.message_from_bytes(response_part[1])

            sender = extract_email_address(msg["from"])
            subject = clean_subject(msg["subject"])
            body = extract_email_body(msg)

            return jsonify({"email": sender, "subject": subject, "body": body})

    return jsonify({"error": "❌ Fehler beim Abrufen der E-Mail!"})



@app.route('/send_reply', methods=['POST', 'OPTIONS'])
def send_reply():
    """Sendet eine Antwort auf eine E-Mail über SMTP, mit Anmeldeinformationen aus der Redis-Session."""
    if request.method == "OPTIONS":
        return '', 204  # Antwortet mit 204 auf Preflight-Anfragen

    data = request.get_json()

    if not data or "email" not in data or "subject" not in data or "body" not in data:
        return jsonify({"error": "❌ Fehlende Daten für die Antwort!"}), 400

    # 🔥 Benutzeranmeldedaten aus der Redis-Session abrufen
    email_address = session.get("user")
    email_password = session.get("password")
    provider = session.get("provider")

    # Falls die Werte als Bytes gespeichert sind, dekodieren wir sie
    if isinstance(email_address, bytes):
        email_address = email_address.decode("utf-8")
    if isinstance(email_password, bytes):
        email_password = email_password.decode("utf-8")
    if isinstance(provider, bytes):
        provider = provider.decode("utf-8")

    if not email_address or not email_password or not provider:
        return jsonify({"error": "❌ Keine gültigen Login-Daten gefunden!"}), 401

    recipient = data["email"]
    subject = data["subject"]
    body = data["body"]

    # 🔍 E-Mail-Anbieter bestimmen
    provider_info = EMAIL_PROVIDERS.get(provider)
    if not provider_info or "smtp" not in provider_info:
        return jsonify({"error": "❌ Unbekannter E-Mail-Anbieter!"}), 400

    try:
        # 📤 E-Mail über SMTP senden
        server = smtplib.SMTP(provider_info["smtp"], provider_info["port"])
        server.starttls()  # TLS-Verschlüsselung aktivieren
        server.login(email_address, email_password)  # Authentifizierung

        # ✉️ E-Mail-Nachricht erstellen
        msg = MIMEText(body, "plain", "utf-8")
        msg["From"] = email_address
        msg["To"] = recipient
        msg["Subject"] = subject

        # 📩 E-Mail senden
        server.sendmail(email_address, recipient, msg.as_string())
        server.quit()

        logging.info(f"✅ E-Mail erfolgreich gesendet an {recipient}")
        return jsonify({"message": "✅ Antwort erfolgreich gesendet!"}), 200

    except Exception as e:
        logging.error(f"❌ Fehler beim Senden der Antwort: {e}")
        return jsonify({"error": "❌ Fehler beim Senden der Antwort!"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(PORT), debug=False)
