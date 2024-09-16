import base64
import json
import os
import threading
from .logging_config import configure_logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from email import message_from_bytes
from email.header import decode_header, make_header
from dateutil import parser as date_parser
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from retry import retry

from .file_utils import sanitize_filename, save_attachment, extract_email_address
from .shared import exit_requested

# Configure logger
script_logger = configure_logging()

gmail_lock = threading.Lock()

def get_last_run_timestamp(criteria_data):
    try:
        if 'last_run' not in criteria_data:
            criteria_data['last_run'] = '2003-01-01T00:00:00'
        return datetime.fromisoformat(criteria_data.get('last_run', ''))
    except ValueError as e:
        script_logger.error(f"Error reading last run timestamp: {e}")
        return datetime.fromisoformat('2003-01-01T00:00:00')

def update_last_run_timestamp(criteria_path, criteria_data):
    criteria_data['last_run'] = datetime.now().isoformat()
    with open(criteria_path, 'w', encoding='utf-8') as f:
        json.dump(criteria_data, f, ensure_ascii=False, indent=4)

@retry(tries=5, delay=2, backoff=2, exceptions=(Exception,))
# Function to authenticate and build the Gmail API service
def authenticate_gmail(credential_path):
    SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(credential_path, SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    service = build('gmail', 'v1', credentials=creds)
    return service

def process_email(service, msg_id, smb_server, smb_folder, filters, username, password, content_filters=None):
    global exit_requested
    with gmail_lock:
        msg_data = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()
    msg_bytes = base64.urlsafe_b64decode(msg_data['raw'].encode('ASCII'))
    msg = message_from_bytes(msg_bytes)
    msg_date = date_parser.parse(msg['Date'])
    subject = str(make_header(decode_header(msg['subject'])))
    sender = str(make_header(decode_header(msg.get('From', 'unknown_sender'))))
    sender_email = sanitize_filename(extract_email_address(sender))
    script_logger.info(f"Processing email: {subject}\nSMB Folder: {smb_folder}\nDate: {msg_date}")

    if smb_folder:
        year = msg_date.year
        month = f"{msg_date.month:0>2}"
        day = f"{msg_date.day:0>2}"
        hierarchical_folder = os.path.join(f"\\\\{smb_server}", smb_folder, sender_email, str(year), str(month), str(day))

        for part in msg.walk():
            if exit_requested:
                script_logger.info("Exit requested. Stopping email processing.")
                return
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') is None:
                continue
            filename = part.get_filename()
            if filename:
                filename = sanitize_filename(str(make_header(decode_header(filename))))
                if any(filename.lower().endswith(filter) for filter in filters):
                    file_data = part.get_payload(decode=True)
                    try:
                        save_attachment(smb_server, hierarchical_folder, filename, file_data, username, password, content_filters)
                    except Exception as e:
                        script_logger.error(f"Failed to save attachment {filename}: {e}")

def process_emails(service, since_date, username, password, criteria_data):
    global exit_requested
    script_logger.info(f"Processing emails since: {since_date}")
    try:
        timestamp = int(since_date.timestamp())
    except Exception as e:
        script_logger.error(f"Error converting since_date to timestamp: {e}")
        return

    criteria = criteria_data['criteria']
    smb_server = criteria_data['smb_server']
  
    base_query = f'after:{timestamp}'
    messages_with_smb_folder = []

    for criterion in criteria:
        if exit_requested:
            script_logger.info("Exit requested. Stopping email processing.")
            return
        if not criterion.get('enabled', True):
            continue
        query = criterion["query"]
        smb_folder = criterion["smb_folder"]
        filters = criterion.get("filters", [])
        content_filters = criterion.get("attachment_content_filter", [])
        full_query = f'{base_query} {query}'
        script_logger.info(f"Query: {full_query}")

        messages = []
        next_page_token = None

        while True:
            if exit_requested:
                script_logger.info("Exit requested. Stopping email processing.")
                return
            try:
                results = service.users().messages().list(userId='me', q=full_query, pageToken=next_page_token).execute()
            except Exception as e:
                script_logger.error(f"Failed to fetch messages: {e}")
                break
            messages.extend(results.get('messages', []))
            next_page_token = results.get('nextPageToken')
            if not next_page_token:
                break

        script_logger.info(f"Total messages retrieved for query '{query}': {len(messages)}")

        for msg in messages:
            messages_with_smb_folder.append((msg['id'], smb_folder, filters, content_filters))

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(process_email, service, msg_id, smb_server, smb_folder, filters, username, password, content_filters) for msg_id, smb_folder, filters, content_filters in messages_with_smb_folder]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                script_logger.error(f"Error processing email: {e}")