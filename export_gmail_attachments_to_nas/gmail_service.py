import base64
import json
import os
import threading
import time
from .logging_config import configure_logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from email import message_from_bytes
from email.header import decode_header, make_header
from dateutil import parser as date_parser
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from retry import retry

from .file_utils import sanitize_filename, save_attachment, extract_email_address

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

def list_messages(service, query, page_token=None):
    try:
        response = service.users().messages().list(userId='me', q=query, pageToken=page_token).execute()
        return response.get('messages', []), response.get('nextPageToken')
    except HttpError as error:
        script_logger.error(f'An error occurred: {error}')
        return [], None
      
def get_message(service, msg_id):
    try:
        message = service.users().messages().get(userId='me', id=msg_id).execute()
        return message
    except HttpError as error:
        script_logger.error(f'An error occurred: {error}')
        return None

def fetch_attachment_with_retries(service, user_id, message_id, attachment_id, max_retries=3, delay=2):
    for attempt in range(max_retries):
        try:
            attachment = service.users().messages().attachments().get(userId=user_id, messageId=message_id, id=attachment_id).execute()
            return attachment
        except Exception as e:
            script_logger.error(f"Failed to fetch attachment (attempt {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                time.sleep(delay)
            else:
                raise

def process_email(service, msg_id, smb_server, smb_folder, filters, username, password, exit_event, content_filters=None):
    if exit_event.is_set():
        script_logger.info("Exit requested. Stopping email processing.")
        return
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
            if exit_event.is_set():
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

def process_individual_email(service,message, smb_server, smb_folder, filters, username, password, exit_event, attachment_content_filter=None):
    if exit_event.is_set():
        script_logger.info("Exit requested. Stopping email processing.")
        return

    # Decode the message payload
    payload = message['payload']
    headers = payload['headers']
    parts = payload.get('parts', [])

    # Extract metadata
    msg_date = None
    subject = None
    sender = None

    for header in headers:
        if header['name'] == 'Date':
            msg_date = date_parser.parse(header['value'])
        elif header['name'] == 'Subject':
            subject = str(make_header(decode_header(header['value'])))
        elif header['name'] == 'From':
            sender = str(make_header(decode_header(header['value'])))

    if not msg_date or not subject or not sender:
        script_logger.error("Missing required email headers.")
        return

    
    sender_email = sanitize_filename(extract_email_address(sender))
    script_logger.info(f"Processing email: {subject}\nSMB Folder: {smb_folder}\nDate: {msg_date}")

    if smb_folder:
        year = msg_date.year
        month = f"{msg_date.month:0>2}"
        day = f"{msg_date.day:0>2}"
        hierarchical_folder = os.path.join(f"\\\\{smb_server}", smb_folder, sender_email, str(year), str(month), str(day))

        for part in parts:
            if exit_event.is_set():
                script_logger.info("Exit requested. Stopping email processing.")
                return
            if part['mimeType'].startswith('multipart') :
                continue
            if 'filename' not in part:
                continue
            filename = part['filename']
            if filename:
                filename = sanitize_filename(str(make_header(decode_header(filename))))
                if any(filename.lower().endswith(filter) for filter in filters):
                    attachment_id = part['body']['attachmentId']
                    try:
                      attachment = fetch_attachment_with_retries(service, 'me', message['id'], attachment_id)
                      file_data = base64.urlsafe_b64decode(attachment['data'].encode('ASCII'))
                    except Exception as e:
                      script_logger.error(f"Failed to fetch attachment {filename}: {e}")
                      continue
                    try:
                        save_attachment(smb_server, hierarchical_folder, filename, file_data, username, password, attachment_content_filter)
                    except Exception as e:
                        script_logger.error(f"Failed to save attachment {filename}: {e}")

def process_emails_old(service, since_date, username, password, criteria_data, exit_event):    
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
        if exit_event.is_set():
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
            if exit_event.is_set():
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

    with ThreadPoolExecutor(max_workers=1) as executor:
        futures = [executor.submit(process_email, service, msg_id, smb_server, smb_folder, filters, username, password, exit_event, content_filters) for msg_id, smb_folder, filters, content_filters in messages_with_smb_folder]
        for future in as_completed(futures):
            try:
                if exit_event.is_set():
                    script_logger.info("Exit requested. Stopping email processing.")
                    return
                future.result()
            except Exception as e:
                script_logger.error(f"Error processing email: {e}")
                if exit_event.is_set():
                  return
                
def process_emails(service, since_date, username, password, criteria_data, exit_event):
    base_query = f'after:{int(since_date.timestamp())}'
    smb_server = criteria_data['smb_server']
    criteria = criteria_data['criteria']
    messages_with_smb_folder = []

    for criterion in criteria:
        if exit_event.is_set():
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
            if exit_event.is_set():
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

    with ThreadPoolExecutor(max_workers=1) as executor:
        futures = [executor.submit(process_individual_email, service, service.users().messages().get(userId='me', id=msg_id).execute(), smb_server, smb_folder, filters, username, password, exit_event, content_filters) for msg_id, smb_folder, filters, content_filters in messages_with_smb_folder]
        for future in as_completed(futures):
            try:
                if exit_event.is_set():
                    script_logger.info("Exit requested. Stopping email processing.")
                    return
                future.result()
            except Exception as e:
                script_logger.error(f"Error processing email: {e}")