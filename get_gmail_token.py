from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
import json

# Scopes für Gmail IMAP-Zugriff
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

def main():
    # OAuth2 Authentifizierung starten
    flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
    creds = flow.run_local_server(port=0)

    # Speichere das Token für spätere Nutzung
    with open("token.json", "w") as token_file:
        token_file.write(creds.to_json())

    print("✅ OAuth-Token gespeichert! Du kannst jetzt dein IMAP-Skript verwenden.")

if __name__ == "__main__":
    main()
