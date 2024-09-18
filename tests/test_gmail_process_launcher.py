from unittest.mock import patch, MagicMock
from threading import Event
from datetime import datetime
import base64
from export_gmail_attachments_to_nas.gmail_service import process_emails, script_logger

from unittest.mock import patch, MagicMock
from threading import Event
from datetime import datetime
import base64
from export_gmail_attachments_to_nas.gmail_service import process_emails, script_logger

@patch.object(script_logger, 'info')
@patch('export_gmail_attachments_to_nas.gmail_service.process_email')
@patch('export_gmail_attachments_to_nas.gmail_service.build')
@patch('export_gmail_attachments_to_nas.gmail_service.authenticate_gmail')
def test_process_multiple_emails(mock_get_authenticated_service, mock_build, mock_process_email, mock_info):
    service = MagicMock()
    since_date = datetime(2021, 1, 1)
    username = 'test_user'
    password = 'test_password'
    criteria_data = {
        'smb_server': 'test_smb_server',
        'smb_folder': 'test_smb_folder',
        'filters': ['.pdf'],
        'criteria': [{'enabled': True, 'query': 'some_query', 'smb_folder': 'test_smb_folder', 'filters': ['.pdf'], 'attachment_content_filter': []}]
    }
    exit_event = Event()

    # Mock the Gmail API service
    mock_service = MagicMock()
    mock_build.return_value = mock_service
    mock_get_authenticated_service.return_value = mock_service

    # Mock the list_messages function to return a list of message IDs
    mock_service.users().messages().list.return_value.execute.return_value = {
        'messages': [{'id': 'msg_id_1'}, {'id': 'msg_id_2'}, {'id': 'msg_id_3'}],
        'nextPageToken': None
    }

    # Mock the get_message function to return a mock message
    mock_service.users().messages().get.return_value.execute.return_value = {
        'raw': base64.urlsafe_b64encode(b'Test email content').decode('ASCII')
    }

    # Mock the process_email function to simulate processing
    mock_process_email.return_value = None

    process_emails(service, since_date, username, password, criteria_data, exit_event)

    # Ensure that list_messages was called with the correct arguments
    mock_service.users().messages().list.assert_called_once_with(userId='me', q='after:1609459200 some_query', pageToken=None)

    # Ensure that get_message was called for each message ID
    assert mock_service.users().messages().get.call_count == 3
    for msg_id in ['msg_id_1', 'msg_id_2', 'msg_id_3']:
        mock_service.users().messages().get.assert_any_call(userId='me', id=msg_id)

    # Ensure that process_email was called for each message
    assert mock_process_email.call_count == 3
    for msg_id in ['msg_id_1', 'msg_id_2', 'msg_id_3']:
        mock_process_email.assert_any_call(service, msg_id, 'test_smb_server', 'test_smb_folder', ['.pdf'], username, password, exit_event, [])



@patch.object(script_logger, 'info')
def test_no_emails_to_process(mock_info):
    service = MagicMock()
    msg_ids = []
    smb_server = 'test_smb_server'
    smb_folder = 'test_smb_folder'
    filters = ['.pdf']
    username = 'test_user'
    password = 'test_password'
    exit_event = Event()

    # Mock the process_email function to simulate processing
    with patch('export_gmail_attachments_to_nas.gmail_service.process_email') as mock_process_email:
        process_emails(service, msg_ids, smb_server, smb_folder, filters, username, password, exit_event)

        # Ensure that process_email was not called
        mock_process_email.assert_not_called()