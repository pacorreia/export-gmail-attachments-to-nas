from unittest.mock import patch, MagicMock
from email.message import EmailMessage
from threading import Event
from datetime import datetime
from export_gmail_attachments_to_nas.gmail_service import process_email, script_logger
    
@patch('export_gmail_attachments_to_nas.gmail_service.base64.urlsafe_b64decode')
@patch('export_gmail_attachments_to_nas.gmail_service.message_from_bytes')
@patch('export_gmail_attachments_to_nas.gmail_service.date_parser.parse')
@patch('export_gmail_attachments_to_nas.gmail_service.sanitize_filename')
@patch('export_gmail_attachments_to_nas.gmail_service.extract_email_address')
@patch('export_gmail_attachments_to_nas.gmail_service.save_attachment')
def test_no_attachments(mock_save_attachment, mock_extract_email_address, mock_sanitize_filename, mock_date_parser, mock_message_from_bytes, mock_b64decode):
    service = MagicMock()
    msg_id = 'test_msg_id'
    smb_server = 'test_smb_server'
    smb_folder = 'test_smb_folder'
    filters = ['.pdf']
    username = 'test_user'
    password = 'test_password'
    exit_event = Event()

    msg = EmailMessage()
    msg.set_payload('This is a test email with no attachments.')
    msg['subject'] = 'Test Subject'  # Set a subject for the email
    msg['Date'] = 'Mon, 01 Jan 2021 00:00:00 -0000'  # Set a date for the email
    mock_message_from_bytes.return_value = msg

    # Configure mock_date_parser to return a valid datetime object
    mock_date_parser.return_value = datetime(2021, 1, 1, 0, 0, 0)

    process_email(service, msg_id, smb_server, smb_folder, filters, username, password, exit_event)

    mock_save_attachment.assert_not_called()

@patch('export_gmail_attachments_to_nas.gmail_service.base64.urlsafe_b64decode')
@patch('export_gmail_attachments_to_nas.gmail_service.message_from_bytes')
@patch('export_gmail_attachments_to_nas.gmail_service.date_parser.parse')
@patch('export_gmail_attachments_to_nas.gmail_service.sanitize_filename')
@patch('export_gmail_attachments_to_nas.gmail_service.extract_email_address')
@patch('export_gmail_attachments_to_nas.gmail_service.save_attachment')
def test_attachments_matching_filters(mock_save_attachment, mock_extract_email_address, mock_sanitize_filename, mock_date_parser, mock_message_from_bytes, mock_b64decode):
    service = MagicMock()
    msg_id = 'test_msg_id'
    smb_server = 'test_smb_server'
    smb_folder = 'test_smb_folder'
    filters = ['.pdf']
    username = 'test_user'
    password = 'test_password'
    exit_event = Event()

    msg = EmailMessage()
    msg.set_payload('This is a test email with attachments.')
    msg['subject'] = 'Test Subject'  # Set a subject for the email
    msg['Date'] = 'Mon, 01 Jan 2021 00:00:00 -0000'  # Set a date for the email
    msg.add_attachment(b'This is a test PDF attachment.', maintype='application', subtype='pdf', filename='test.pdf')
    mock_message_from_bytes.return_value = msg
    
    # Configure mock_date_parser to return a valid datetime object
    mock_date_parser.return_value = datetime(2021, 1, 1, 0, 0, 0)

    process_email(service, msg_id, smb_server, smb_folder, filters, username, password, exit_event)

    mock_save_attachment.assert_called_once()

@patch('export_gmail_attachments_to_nas.gmail_service.base64.urlsafe_b64decode')
@patch('export_gmail_attachments_to_nas.gmail_service.message_from_bytes')
@patch('export_gmail_attachments_to_nas.gmail_service.date_parser.parse')
@patch('export_gmail_attachments_to_nas.gmail_service.sanitize_filename')
@patch('export_gmail_attachments_to_nas.gmail_service.extract_email_address')
@patch('export_gmail_attachments_to_nas.gmail_service.save_attachment')
@patch.object(script_logger, 'info')
def test_attachments_not_matching_filters(mock_info, mock_save_attachment, mock_extract_email_address, mock_sanitize_filename, mock_date_parser, mock_message_from_bytes, mock_b64decode):
    service = MagicMock()
    msg_id = 'test_msg_id'
    smb_server = 'test_smb_server'
    smb_folder = 'test_smb_folder'
    filters = ['.pdf']
    username = 'test_user'
    password = 'test_password'
    exit_event = Event()

    msg = EmailMessage()
    msg.set_payload('This is a test email with attachments.')
    msg['subject'] = 'Test Subject'  # Set a subject for the email
    msg['Date'] = 'Mon, 01 Jan 2021 00:00:00 -0000'  # Set a date for the email
    msg.add_attachment(b'This is a test TXT attachment.', maintype='text', subtype='plain', filename='test.txt')
    mock_message_from_bytes.return_value = msg

    # Configure mock_date_parser to return a valid datetime object
    mock_date_parser.return_value = datetime(2021, 1, 1, 0, 0, 0)
    
    # Configure mock_sanitize_filename to return a valid sanitized filename
    mock_sanitize_filename.side_effect = lambda x: x

    process_email(service, msg_id, smb_server, smb_folder, filters, username, password, exit_event)

    # Check the log messages for debugging
    for call in mock_info.call_args_list:
        print(call)

    mock_save_attachment.assert_not_called()

@patch('export_gmail_attachments_to_nas.gmail_service.base64.urlsafe_b64decode')
@patch('export_gmail_attachments_to_nas.gmail_service.message_from_bytes')
@patch('export_gmail_attachments_to_nas.gmail_service.date_parser.parse')
@patch('export_gmail_attachments_to_nas.gmail_service.sanitize_filename')
@patch('export_gmail_attachments_to_nas.gmail_service.extract_email_address')
@patch('export_gmail_attachments_to_nas.gmail_service.save_attachment')
@patch.object(script_logger, 'error')
def test_save_attachment_exception(mock_logger_error, mock_save_attachment, mock_extract_email_address, mock_sanitize_filename, mock_date_parser, mock_message_from_bytes, mock_b64decode):
    service = MagicMock()
    msg_id = 'test_msg_id'
    smb_server = 'test_smb_server'
    smb_folder = 'test_smb_folder'
    filters = ['.pdf']
    username = 'test_user'
    password = 'test_password'
    exit_event = Event()

    msg = EmailMessage()
    msg.set_payload('This is a test email with attachments.')
    msg['subject'] = 'Test Subject'  # Set a subject for the email
    msg['Date'] = 'Mon, 01 Jan 2021 00:00:00 -0000'  # Set a date for the email
    msg.add_attachment(b'This is a test PDF attachment.', maintype='application', subtype='pdf', filename='test.pdf')
    mock_message_from_bytes.return_value = msg

    # Configure mock_date_parser to return a valid datetime object
    mock_date_parser.return_value = datetime(2021, 1, 1, 0, 0, 0)

    # Configure mock_sanitize_filename to return a valid sanitized filename
    mock_sanitize_filename.side_effect = lambda x: x

    # Mock save_attachment to raise an exception
    mock_save_attachment.side_effect = Exception('Test exception')

    process_email(service, msg_id, smb_server, smb_folder, filters, username, password, exit_event)

    # Check that the error log was called with the expected message
    mock_logger_error.assert_called_with("Failed to save attachment test.pdf: Test exception")

@patch('export_gmail_attachments_to_nas.gmail_service.base64.urlsafe_b64decode')
@patch('export_gmail_attachments_to_nas.gmail_service.message_from_bytes')
@patch('export_gmail_attachments_to_nas.gmail_service.date_parser.parse')
@patch('export_gmail_attachments_to_nas.gmail_service.sanitize_filename')
@patch('export_gmail_attachments_to_nas.gmail_service.extract_email_address')
@patch('export_gmail_attachments_to_nas.gmail_service.save_attachment')
def test_delete_after_save_true_deletes_email(mock_save_attachment, mock_extract_email_address, mock_sanitize_filename, mock_date_parser, mock_message_from_bytes, mock_b64decode):
    service = MagicMock()
    msg_id = 'test_msg_id'
    smb_server = 'test_smb_server'
    smb_folder = 'test_smb_folder'
    filters = ['.pdf']
    username = 'test_user'
    password = 'test_password'
    exit_event = Event()

    msg = EmailMessage()
    msg.set_payload('This is a test email with attachments.')
    msg['subject'] = 'Test Subject'
    msg['Date'] = 'Mon, 01 Jan 2021 00:00:00 -0000'
    msg.add_attachment(b'This is a test PDF attachment.', maintype='application', subtype='pdf', filename='test.pdf')
    mock_message_from_bytes.return_value = msg
    mock_date_parser.return_value = datetime(2021, 1, 1, 0, 0, 0)
    mock_sanitize_filename.side_effect = lambda x: x

    process_email(
        service,
        msg_id,
        smb_server,
        smb_folder,
        filters,
        username,
        password,
        exit_event,
        delete_after_save=True,
    )

    service.users().messages().delete.assert_called_once_with(userId='me', id=msg_id)
    service.users().messages().delete().execute.assert_called_once()

@patch('export_gmail_attachments_to_nas.gmail_service.base64.urlsafe_b64decode')
@patch('export_gmail_attachments_to_nas.gmail_service.message_from_bytes')
@patch('export_gmail_attachments_to_nas.gmail_service.date_parser.parse')
@patch('export_gmail_attachments_to_nas.gmail_service.sanitize_filename')
@patch('export_gmail_attachments_to_nas.gmail_service.extract_email_address')
@patch('export_gmail_attachments_to_nas.gmail_service.save_attachment')
def test_delete_after_save_false_skips_delete(mock_save_attachment, mock_extract_email_address, mock_sanitize_filename, mock_date_parser, mock_message_from_bytes, mock_b64decode):
    service = MagicMock()
    msg_id = 'test_msg_id'
    smb_server = 'test_smb_server'
    smb_folder = 'test_smb_folder'
    filters = ['.pdf']
    username = 'test_user'
    password = 'test_password'
    exit_event = Event()

    msg = EmailMessage()
    msg.set_payload('This is a test email with attachments.')
    msg['subject'] = 'Test Subject'
    msg['Date'] = 'Mon, 01 Jan 2021 00:00:00 -0000'
    msg.add_attachment(b'This is a test PDF attachment.', maintype='application', subtype='pdf', filename='test.pdf')
    mock_message_from_bytes.return_value = msg
    mock_date_parser.return_value = datetime(2021, 1, 1, 0, 0, 0)
    mock_sanitize_filename.side_effect = lambda x: x

    process_email(
        service,
        msg_id,
        smb_server,
        smb_folder,
        filters,
        username,
        password,
        exit_event,
        delete_after_save=False,
    )

    service.users().messages().delete.assert_not_called()
