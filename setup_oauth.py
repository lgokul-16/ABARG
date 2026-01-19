import os
import json
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

# Scopes required for the application
SCOPES = ['https://www.googleapis.com/auth/drive']

def main():
    """Shows basic usage of the Drive v3 API.
    Prints the names and ids of the first 10 files the user has access to.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('user_creds.json'):
        creds = Credentials.from_authorized_user_file('user_creds.json', SCOPES)

    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists('client_secret.json'):
                print("❌ ERROR: 'client_secret.json' not found!")
                print("1. Go to Google Cloud Console > APIs & Services > Credentials")
                print("2. Create Credentials > OAuth Client ID > Desktop App")
                print("3. Download the JSON and rename it to 'client_secret.json'")
                print("4. Place it in this folder and run this script again.")
                return

            flow = InstalledAppFlow.from_client_secrets_file(
                'client_secret.json', SCOPES)
            creds = flow.run_local_server(port=0)
        
        # Save the credentials for the next run
        with open('user_creds.json', 'w') as token:
            token.write(creds.to_json())
            print("✅ 'user_creds.json' created successfully!")
            print("👉 Now COMMIT and PUSH 'user_creds.json' to your repository.")

if __name__ == '__main__':
    main()
