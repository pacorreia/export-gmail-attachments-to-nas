from unittest.mock import patch, MagicMock
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from threading import Event
from base64 import urlsafe_b64encode
from export_gmail_attachments_to_nas.gmail_service import process_emails,process_email, script_logger
    
@patch('export_gmail_attachments_to_nas.gmail_service.base64.urlsafe_b64decode')
@patch('export_gmail_attachments_to_nas.gmail_service.message_from_bytes')
@patch('export_gmail_attachments_to_nas.gmail_service.date_parser.parse')
@patch('export_gmail_attachments_to_nas.gmail_service.sanitize_filename')
@patch('export_gmail_attachments_to_nas.gmail_service.extract_email_address')
@patch('export_gmail_attachments_to_nas.gmail_service.save_attachment')
@patch.object(script_logger, 'info')
def test_exit_event_set(mock_info, mock_save_attachment, mock_extract_email_address, mock_sanitize_filename, mock_date_parser, mock_message_from_bytes, mock_b64decode):
    service = MagicMock()
    msg_id = 'test_msg_id'
    smb_server = 'test_smb_server'
    smb_folder = 'test_smb_folder'
    filters = ['.pdf']
    username = 'test_user'
    password = 'test_password'
    exit_event = Event()
    exit_event.set()  # Set the exit event

    process_email(service, msg_id, smb_server, smb_folder, filters, username, password, exit_event)

    # Ensure that the log message was generated
    mock_info.assert_called_with("Exit requested. Stopping email processing.")

    # Ensure that none of the mocked functions are called
    mock_b64decode.assert_not_called()
    mock_message_from_bytes.assert_not_called()
    mock_date_parser.assert_not_called()
    mock_sanitize_filename.assert_not_called()
    mock_extract_email_address.assert_not_called()
    mock_save_attachment.assert_not_called()
    
@patch.object(script_logger, 'info')
def test_exit_event_set_with_multipart_message(mock_info):
    service = MagicMock()
    msg_id = 'test_msg_id'
    smb_server = 'test_smb_server'
    smb_folder = 'test_smb_folder'
    filters = ['.pdf']
    username = 'test_user'
    password = 'test_password'
    exit_event = Event()

    # Create a multipart email message
    msg = MIMEMultipart()
    msg['From'] = 'test@example.com'
    msg['To'] = 'recipient@example.com'
    msg['Subject'] = 'Test Subject'
    msg['Date'] = 'Mon, 01 Jan 2021 00:00:00 -0000'  # Add Date header
    msg.attach(MIMEText('This is the body of the email', 'plain'))
    msg.attach(MIMEText('This is another part of the email', 'plain'))

    # Encode the message to base64
    raw_msg = {'raw': urlsafe_b64encode(msg.as_bytes()).decode('utf-8')}

    # Mock the service to return the multipart message
    def side_effect(*args, **kwargs):
        exit_event.set()  # Set the exit event right before processing the parts
        return raw_msg

    service.users().messages().get().execute.side_effect = side_effect

    process_email(service, msg_id, smb_server, smb_folder, filters, username, password, exit_event)

    # Ensure that the log message was generated
    mock_info.assert_called_with("Exit requested. Stopping email processing.")

    # Ensure that none of the mocked functions are called
    service.users().messages().get().execute.assert_called_once()
    
@patch.object(script_logger, 'info')
def test_exit_event_stops_processing(mock_info):
    service = MagicMock()
    msg_ids = ['msg_id_1', 'msg_id_2', 'msg_id_3']
    smb_server = 'test_smb_server'
    smb_folder = 'test_smb_folder'
    filters = ['.pdf']
    username = 'test_user'
    password = 'test_password'
    exit_event = Event()

    # Mock the process_email function to simulate processing
    with patch('export_gmail_attachments_to_nas.gmail_service.process_email') as mock_process_email:
        # Set the exit event after the first call
        def side_effect(*args, **kwargs):
            exit_event.set()
        mock_process_email.side_effect = side_effect

        process_emails(service, msg_ids, smb_server, smb_folder, filters, username, password, exit_event)

        # Ensure that process_email was called only once
        assert mock_process_email.call_count == 1
        mock_process_email.assert_called_once_with(service, 'msg_id_1', smb_server, smb_folder, filters, username, password, exit_event)