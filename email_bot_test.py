import imaplib
import email
import logging
import smtplib
from email.mime.text import MIMEText
from flask import Flask, jsonify, request
from flask_cors import CORS
import requests
from openai import OpenAI
import re
from bs4 import BeautifulSoup
from email.header import decode_header
from langdetect import detect
import os
from dotenv import load_dotenv


# Flask Setup
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# Supabase API-Daten
SUPABASE_URL = "https://qulqaxpvnaupdvuycxoe.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InF1bHFheHB2bmF1cGR2dXljeG9lIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc0MTE2MTEwMiwiZXhwIjoyMDU2NzM3MTAyfQ.RNpI3GkITsv9VJ-e3VNIM0hidDW4FsXJIQ8UdKARpUc"


load_dotenv()  # ✅ Lädt die Umgebungsvariablen aus der `.env`-Datei

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


# Logging aktivieren
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# E-Mail-Anbieter & ihre IMAP-/SMTP-Server
EMAIL_PROVIDERS = {
    "gmail.com": {"imap": "imap.gmail.com", "smtp": "smtp.gmail.com"},
    "gmx.de": {"imap": "imap.gmx.net", "smtp": "mail.gmx.net"},
    "yahoo.com": {"imap": "imap.mail.yahoo.com", "smtp": "smtp.mail.yahoo.com"},
    "outlook.com": {"imap": "outlook.office365.com", "smtp": "smtp.office365.com"},
    "hotmail.com": {"imap": "outlook.office365.com", "smtp": "smtp.office365.com"},
    "web.de": {"imap": "imap.web.de", "smtp": "smtp.web.de"}
}

# Globale Variablen für E-Mail-Warteschlange und Index
email_queue = []
current_email_index = 0

SMTP_PORT = 587  # Standard-Port für SMTP

def save_login_credentials(email, password):
    """Speichert Login-Daten in Supabase, falls sie noch nicht existieren."""
    try:
        url = f"{SUPABASE_URL}/rest/v1/emails"
        headers = {
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": "application/json"
        }

        # Überprüfen, ob die E-Mail bereits existiert
        check_url = f"{SUPABASE_URL}/rest/v1/emails?select=email&email=eq.{email}"
        check_response = requests.get(check_url, headers=headers)

        if check_response.status_code == 200 and check_response.json():
            logging.info(f"🔄 Benutzer {email} existiert bereits, Login erlaubt.")
            return True  # Benutzer existiert bereits, Login erlaubt

        # Falls nicht vorhanden, neuen Datensatz anlegen
        payload = {"email": email, "password": password}
        response = requests.post(url, json=payload, headers=headers)

        if response.status_code == 201:
            logging.info(f"✅ Login-Daten gespeichert für: {email}")
            return True
        else:
            logging.error(f"❌ Fehler beim Speichern: {response.text}")
            return False
    except Exception as e:
        logging.error(f"❌ Ausnahmefehler beim Speichern: {e}")
        return False

def get_login_credentials():
    """Holt Login-Daten aus Supabase."""
    try:
        url = f"{SUPABASE_URL}/rest/v1/emails?select=email,password&order=id.desc&limit=1"
        headers = {
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": "application/json"
        }
        response = requests.get(url, headers=headers)

        if response.status_code == 200 and response.json():
            data = response.json()[0]
            logging.info(f"✅ Login-Daten erhalten: {data.get('email')}")
            return data.get("email"), data.get("password")

    except Exception as e:
        logging.error(f"❌ Fehler beim Abrufen der Supabase-Daten: {e}")

    return None, None

def detect_email_provider(email_address):
    """Erkennt den E-Mail-Anbieter anhand der Domain."""
    domain = email_address.split("@")[-1].lower()
    return EMAIL_PROVIDERS.get(domain, None)

def detect_language(text):
    """Erkennt die Sprache der E-Mail und gibt 'de' oder 'en' zurück."""
    try:
        lang = detect(text)
        return "de" if lang == "de" else "en"  # Falls nicht Deutsch, setze Englisch
    except:
        return "en"  # Falls Fehler, Standard auf Englisch


def extract_email_body(msg):
    """Extrahiert den lesbaren Inhalt aus einer E-Mail (text/plain bevorzugt, text/html als Fallback)."""
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
        logging.error(f"❌ Fehler beim Extrahieren des E-Mail-Texts: {e}")
        return "⚠️ Error processing email content."


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
            messages=[{"role": "system", "content": "You are a professional assistant."},
                      {"role": "user", "content": prompts[language]}],
            temperature=0.7
        )

        return response.choices[0].message.content.strip() if response.choices else "Error generating AI response."

    except Exception as e:
        logging.error(f"❌ Error generating AI response: {e}")
        return "There was a problem generating the response."


@app.after_request
def after_request(response):
    """Stellt sicher, dass CORS für alle Anfragen erlaubt ist."""
    response.headers["Access-Control-Allow-Origin"] = "https://emailcrawlerlukas.netlify.app"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


@app.route('/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == "OPTIONS":
        return '', 204  # ✅ Antwort für CORS-Preflight-Requests

    data = request.get_json()

    if not data or "email" not in data or "password" not in data:
        return jsonify({"error": "E-Mail und Passwort erforderlich!"}), 400

    email = data["email"]
    password = data["password"]

    # ✅ Falls die Daten bereits in Supabase existieren, nutze sie einfach weiter
    existing_email, existing_password = get_login_credentials()
    if existing_email == email and existing_password == password:
        return jsonify({"message": "✅ Login erfolgreich!", "email": email}), 200

    # ✅ Falls nicht vorhanden, speichere neue Anmeldeinformationen
    if save_login_credentials(email, password):
        return jsonify({"message": "✅ Login erfolgreich und gespeichert!", "email": email}), 200
    else:
        return jsonify({"error": "❌ Fehler beim Speichern in Supabase!"}), 500


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

@app.route('/get_email', methods=['GET'])
def api_get_email():
    """Holt die aktuelle E-Mail, erkennt die Sprache und generiert eine KI-Antwort."""
    global email_queue, current_email_index

    email_address, email_password = get_login_credentials()
    if not email_address or not email_password:
        return jsonify({"error": "❌ No valid login data found!"}), 401

    provider = detect_email_provider(email_address)
    if not provider:
        return jsonify({"error": "❌ Unknown email provider!"}), 400

    try:
        mail = imaplib.IMAP4_SSL(provider["imap"])
        mail.login(email_address, email_password)
        mail.select("inbox")

        status, messages = mail.search(None, "UNSEEN")
        mail_ids = messages[0].split()

        if not mail_ids:
            return jsonify({"error": "📭 No new emails found!"})

        email_id = mail_ids[-1]
        status, data = mail.fetch(email_id, "(RFC822)")

        for response_part in data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])

                sender_raw = msg["from"]
                subject_raw = msg["subject"]

                sender = extract_email_address(sender_raw)  # ✅ Extract clean email
                subject = clean_subject(subject_raw)  # ✅ Decode subject
                body = extract_email_body(msg)  # ✅ Extract and clean email content

                language = detect_language(body)  # 🔥 Detect language
                ai_reply = generate_ai_reply(body)  # ✅ Generate AI response

                return jsonify({
                    "email": sender,
                    "subject": subject,
                    "body": body,
                    "reply": ai_reply,
                    "language": language  # 🔥 Send detected language to frontend
                })

    except Exception as e:
        logging.error(f"❌ Error retrieving email: {e}")
        return jsonify({"error": "❌ Error retrieving email"})

@app.route('/send_reply', methods=['POST', 'OPTIONS'])
def send_reply():
    if request.method == "OPTIONS":
        return '', 204  # Antwortet mit 204 auf Preflight-Anfragen

    data = request.get_json()

    if not data or "email" not in data or "subject" not in data or "body" not in data:
        return jsonify({"error": "❌ Fehlende Daten für die Antwort!"}), 400

    email_address, email_password = get_login_credentials()
    if not email_address or not email_password:
        return jsonify({"error": "❌ Keine gültigen Login-Daten gefunden!"}), 401

    recipient = data["email"]
    subject = data["subject"]
    body = data["body"]

    provider = detect_email_provider(email_address)
    if not provider:
        return jsonify({"error": "❌ Unbekannter E-Mail-Anbieter!"}), 400

    try:
        # E-Mail über SMTP senden
        server = smtplib.SMTP(provider["smtp"], SMTP_PORT)
        server.starttls()
        server.login(email_address, email_password)

        msg = MIMEText(body, "plain", "utf-8")
        msg["From"] = email_address
        msg["To"] = recipient
        msg["Subject"] = subject

        server.sendmail(email_address, recipient, msg.as_string())
        server.quit()

        return jsonify({"message": "✅ Antwort erfolgreich gesendet!"}), 200

    except Exception as e:
        logging.error(f"❌ Fehler beim Senden der Antwort: {e}")
        return jsonify({"error": "❌ Fehler beim Senden der Antwort!"}), 500


if __name__ == "__main__":
    # Lade Umgebungsvariablen (insbesondere für den API-Key)
    load_dotenv()

    # Starte die Flask-App auf Port 5000
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)

