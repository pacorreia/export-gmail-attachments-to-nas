import base64
import json
import os
import re
import time
from .logging_config import configure_logging
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

from .file_utils import sanitize_filename, save_attachment, extract_email_address, convert_attachment

# Configure logger
script_logger = configure_logging()

def get_last_run_timestamp(criteria_data):
    """
    Get the timestamp of the last program run from criteria data.
    
    Args:
        criteria_data: Dictionary containing criteria configuration
        
    Returns:
        datetime object of last run, defaults to 2003-01-01 if not found or invalid
    """
    try:
        if 'last_run' not in criteria_data:
            criteria_data['last_run'] = '2003-01-01T00:00:00'
        return datetime.fromisoformat(criteria_data.get('last_run', ''))
    except ValueError as e:
        script_logger.error(f"Error reading last run timestamp: {e}")
        return datetime.fromisoformat('2003-01-01T00:00:00')

def update_last_run_timestamp(criteria_path, criteria_data):
    """
    Update the last run timestamp in the criteria file.
    
    Args:
        criteria_path: Path to the criteria JSON file
        criteria_data: Dictionary containing criteria configuration
    """
    criteria_data['last_run'] = datetime.now().isoformat()
    with open(criteria_path, 'w', encoding='utf-8') as f:
        json.dump(criteria_data, f, ensure_ascii=False, indent=4)

@retry(tries=5, delay=2, backoff=2, exceptions=(Exception,))
def authenticate_gmail(credential_path):
    """
    Authenticate with Gmail API and return service object.
    
    Args:
        credential_path: Path to the Gmail API credentials file
        
    Returns:
        Authenticated Gmail API service object
    """
    SCOPES = ['https://mail.google.com/']
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

def fetch_messages(service, query, exit_event):
    """
    Fetch Gmail messages matching a query.
    
    Args:
        service: Authenticated Gmail API service object
        query: Gmail search query string
        exit_event: Threading event to signal early termination
        
    Returns:
        List of message dictionaries containing message IDs
    """
    messages = []
    next_page_token = None
    while True:
        if exit_event.is_set():
            script_logger.info("Exit requested. Stopping email fetching.")
            return messages
        try:
            results = service.users().messages().list(userId='me', q=query, pageToken=next_page_token).execute()
        except Exception as e:
            script_logger.error(f"Failed to fetch messages: {e}")
            break
        messages.extend(results.get('messages', []))
        next_page_token = results.get('nextPageToken')
        if not next_page_token:
            break
    return messages

def process_email(service, msg_id, smb_server, smb_folder, filters, username, password, exit_event, content_filters=None, delete_after_save=False, convert=None):
    """
    Process a single email message and save attachments.
    
    Args:
        service: Authenticated Gmail API service object
        msg_id: Gmail message ID
        smb_server: SMB server hostname
        smb_folder: Target folder path on SMB share
        filters: List of file extensions to save (e.g., ['.pdf'])
        username: SMB username
        password: SMB password
        exit_event: Threading event to signal early termination
        content_filters: Optional list of strings to filter attachment content
        delete_after_save: Whether to delete the email after saving attachments
        convert: Optional dict specifying conversion options:
            - 'to': target format string (e.g., 'txt', 'png', 'jpeg')
            - 'output_folder': SMB folder path for converted files
            - 'extension_filter': optional list of extensions to convert (e.g., ['.pdf'])
            - 'filename_filter': optional regex pattern to match filenames for conversion
    """
    if exit_event.is_set():
        script_logger.info("Exit requested. Stopping email processing.")
        return
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
        attachment_saved = False

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
                        script_logger.info(f"Saved attachment to {os.path.join(hierarchical_folder, filename)}")
                        attachment_saved = True  # pragma: no cover
                    except Exception as e:
                        script_logger.error(f"Failed to save attachment {filename}: {e}")
                        attachment_saved = False  # pragma: no cover

                    if convert and convert.get('enabled', True):
                        convert_ext_filter = convert.get('extension_filter', [])
                        convert_name_filter = convert.get('filename_filter')
                        should_convert = True
                        if convert_ext_filter and not any(filename.lower().endswith(ext) for ext in convert_ext_filter):
                            should_convert = False
                        if should_convert and convert_name_filter:
                            if not re.search(convert_name_filter, filename, re.IGNORECASE):
                                should_convert = False
                        if should_convert:
                            target_format = convert['to']
                            convert_output_folder = os.path.join(f"\\\\{smb_server}", convert['output_folder'], sender_email, str(year), str(month), str(day))
                            for new_filename, converted_data in convert_attachment(filename, file_data, target_format):
                                try:
                                    save_attachment(smb_server, convert_output_folder, new_filename, converted_data, username, password)
                                    script_logger.info(f"Saved converted attachment to {os.path.join(convert_output_folder, new_filename)}")
                                except Exception as e:
                                    script_logger.error(f"Failed to save converted attachment {new_filename}: {e}")

        if attachment_saved and delete_after_save:
            try:
                service.users().messages().delete(userId='me', id=msg_id).execute()
                script_logger.info(f"Deleted email with ID: {msg_id}")
            except Exception as e:
                script_logger.error(f"Failed to delete email with ID: {msg_id}, error: {e}")
        elif attachment_saved:
            script_logger.info(f"Skipping delete for email with ID: {msg_id}")

def process_emails(service, since_date, username, password, criteria_data, exit_event):
    """
    Process all emails matching criteria and save their attachments.
    
    Args:
        service: Authenticated Gmail API service object
        since_date: datetime object to process emails after this date
        username: SMB username
        password: SMB password
        criteria_data: Dictionary containing search criteria and configuration
        exit_event: Threading event to signal early termination
    """
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
        delete_after_save = criterion.get("delete_after_save", False)
        convert = criterion.get("convert", None)
        full_query = f'{base_query} {query}'
        script_logger.info(f"Query: {full_query}")

        messages = fetch_messages(service, full_query, exit_event)
        script_logger.info(f"Total messages retrieved for query '{query}': {len(messages)}")

        for msg in messages:
            messages_with_smb_folder.append((msg['id'], smb_folder, filters, content_filters, delete_after_save, convert))

    # Process emails iteratively
    for msg_id, smb_folder, filters, content_filters, delete_after_save, convert in messages_with_smb_folder:
        if exit_event.is_set():
            script_logger.info("Exit requested. Stopping email processing.")
            return
        try:
            process_email(
                service,
                msg_id,
                smb_server,
                smb_folder,
                filters,
                username,
                password,
                exit_event,
                content_filters,
                delete_after_save=delete_after_save,
                convert=convert,
            )
        except Exception as e:
            script_logger.error(f"Error processing email: {e}")
            if exit_event.is_set():
                return