import pytest
import logging
import smbprotocol.exceptions as smb_exceptions
from unittest.mock import patch, mock_open, MagicMock
from export_gmail_attachments_to_nas.file_utils import sanitize_filename, extract_email_address, extract_text_from_pdf, save_attachment

def test_sanitize_filename():
    assert sanitize_filename("test:file/name") == "test_file_name"
    assert sanitize_filename("test<file>name") == "test_file_name"
    assert sanitize_filename("test|file?name") == "test_file_name"

def test_extract_email_address():
    assert extract_email_address("John Doe <john.doe@example.com>") == "john.doe@example.com"
    assert extract_email_address("john.doe@example.com") == "john.doe@example.com"
    assert extract_email_address("John Doe") == "John Doe"

@patch('export_gmail_attachments_to_nas.file_utils.pymupdf.Document')
@patch('export_gmail_attachments_to_nas.file_utils.exit_event')
def test_extract_text_from_pdf(mock_exit_event, mock_document):
    mock_exit_event.is_set.return_value = False
    mock_page = MagicMock()
    mock_page.get_text.return_value = "Sample text"
    mock_document.return_value.load_page.return_value = mock_page
    mock_document.return_value.page_count = 1

    file_data = b'%PDF-1.4...'
    text = extract_text_from_pdf(file_data)
    assert text == "Sample text"

    mock_exit_event.is_set.return_value = True
    text = extract_text_from_pdf(file_data)
    assert text == ""

@patch('export_gmail_attachments_to_nas.file_utils.script_logger')
@patch('export_gmail_attachments_to_nas.file_utils.pymupdf.Document')
def test_extract_text_from_pdf_error(mock_document, mock_logger):
    mock_document.side_effect = Exception("Error")
    file_data = b'%PDF-1.4...'
    text = extract_text_from_pdf(file_data)
    assert text == ""
    mock_logger.error.assert_called_once_with("Error extracting text from PDF: Error")

@patch('smbclient.open_file', new_callable=mock_open)
@patch('smbclient.makedirs')
@patch('smbclient.register_session')
@patch('smbclient.stat')
@patch('export_gmail_attachments_to_nas.file_utils.script_logger')
def test_save_attachment_file_exists(mock_logger, mock_stat, mock_register_session, mock_makedirs, mock_open_file):
    smb_server = 'test_server'
    smb_folder = f"\\\\{smb_server}\\test_folder"
    filename = 'test_file.txt'
    file_data = b'Test data'
    username = 'test_user'
    password = 'test_password'

    # Mock stat to simulate file already exists
    mock_stat.return_value = True

    save_attachment(smb_server, smb_folder, filename, file_data, username, password)

    mock_register_session.assert_called_once_with(server=smb_server, username=username, password=password)
    mock_makedirs.assert_called_once_with(smb_folder, exist_ok=True)
    mock_stat.assert_called_once_with(f"{smb_folder}\\{filename}")
    mock_open_file.assert_not_called()
    mock_logger.info.assert_called_with(f"File already exists, skipping: {filename}")

@patch('smbclient.open_file', new_callable=mock_open)
@patch('smbclient.makedirs')
@patch('smbclient.register_session')
@patch('smbclient.stat', side_effect=smb_exceptions.SMBOSError(ntstatus=0, filename='test_file.txt'))
@patch('export_gmail_attachments_to_nas.file_utils.script_logger')
def test_save_attachment_file_new(mock_logger, mock_stat, mock_register_session, mock_makedirs, mock_open_file):
    smb_server = 'test_server'
    smb_folder = f"\\\\{smb_server}\\test_folder"
    filename = 'test_file.txt'
    file_data = b'Test data'
    username = 'test_user'
    password = 'test_password'

    save_attachment(smb_server, smb_folder, filename, file_data, username, password)

    mock_register_session.assert_called_once_with(server=smb_server, username=username, password=password)
    mock_makedirs.assert_called_once_with(smb_folder, exist_ok=True)
    mock_stat.assert_called_once_with(f"{smb_folder}\\{filename}")
    mock_open_file.assert_called_once_with(f"{smb_folder}\\{filename}", mode='wb')
    mock_open_file().write.assert_called_once_with(file_data)

@patch('smbclient.open_file', new_callable=mock_open)
@patch('smbclient.makedirs')
@patch('smbclient.register_session')
@patch('smbclient.stat', side_effect=smb_exceptions.SMBOSError(ntstatus=0, filename='test_file.pdf'))
@patch('export_gmail_attachments_to_nas.file_utils.script_logger')
@patch('export_gmail_attachments_to_nas.file_utils.extract_text_from_pdf', return_value="filter1 match")
def test_save_attachment_content_filter_match_pdf(mock_extract_text, mock_logger, mock_stat, mock_register_session, mock_makedirs, mock_open_file):
    smb_server = 'test_server'
    smb_folder = f"\\\\{smb_server}\\test_folder"
    filename = 'test_file.pdf'
    file_data = b'Test data'
    username = 'test_user'
    password = 'test_password'
    content_filters = ['filter1', 'filter2']

    save_attachment(smb_server, smb_folder, filename, file_data, username, password, content_filters)

    mock_register_session.assert_called_once_with(server=smb_server, username=username, password=password)
    mock_makedirs.assert_called_once_with(smb_folder, exist_ok=True)
    mock_stat.assert_called_once_with(f"{smb_folder}\\{filename}")
    mock_open_file.assert_called_once_with(f"{smb_folder}\\{filename}", mode='wb')
    mock_open_file().write.assert_called_once_with(file_data)
    
@patch('smbclient.open_file', new_callable=mock_open)
@patch('smbclient.makedirs')
@patch('smbclient.register_session')
@patch('smbclient.stat', side_effect=smb_exceptions.SMBOSError(ntstatus=0, filename='test_file.txt'))
@patch('export_gmail_attachments_to_nas.file_utils.script_logger')
def test_save_attachment_content_filter_match_no_pdf(mock_logger, mock_stat, mock_register_session, mock_makedirs, mock_open_file):
    smb_server = 'test_server'
    smb_folder = f"\\\\{smb_server}\\test_folder"
    filename = 'test_file.txt'
    file_data = MagicMock()
    file_data.decode.return_value = "filter1 match"
    username = 'test_user'
    password = 'test_password'
    content_filters = ['filter1', 'filter2']

    save_attachment(smb_server, smb_folder, filename, file_data, username, password, content_filters)

    mock_register_session.assert_called_once_with(server=smb_server, username=username, password=password)
    mock_makedirs.assert_called_once_with(smb_folder, exist_ok=True)
    mock_stat.assert_called_once_with(f"{smb_folder}\\{filename}")
    mock_open_file.assert_called_once_with(f"{smb_folder}\\{filename}", mode='wb')
    mock_open_file().write.assert_called_once_with(file_data)
    file_data.decode.assert_called_once_with('utf-8', errors='ignore')

@patch('smbclient.open_file', new_callable=mock_open)
@patch('smbclient.makedirs')
@patch('smbclient.register_session')
@patch('smbclient.stat', side_effect=smb_exceptions.SMBOSError(ntstatus=0, filename='test_file.txt'))
@patch('export_gmail_attachments_to_nas.file_utils.script_logger')
@patch('export_gmail_attachments_to_nas.file_utils.extract_text_from_pdf', return_value="mock extracted text")
def test_save_attachment_content_filter_no_match(mock_extract_text, mock_logger, mock_stat, mock_register_session, mock_makedirs, mock_open_file):
    smb_server = 'test_server'
    smb_folder = f"\\\\{smb_server}\\test_folder"
    filename = 'test_file.pdf'
    file_data = b'Test data'
    username = 'test_user'
    password = 'test_password'
    content_filters = ['filter1', 'filter2']

    save_attachment(smb_server, smb_folder, filename, file_data, username, password, content_filters)

    mock_register_session.assert_called_once_with(server=smb_server, username=username, password=password)
    mock_makedirs.assert_called_once_with(smb_folder, exist_ok=True)
    mock_stat.assert_not_called()
    mock_open_file.assert_not_called()
    mock_logger.info.assert_called_with(f"None of the content filters {content_filters} found in {filename}, skipping.")

@patch('smbclient.open_file', new_callable=mock_open)
@patch('smbclient.makedirs')
@patch('smbclient.register_session')
@patch('smbclient.stat', side_effect=smb_exceptions.SMBOSError(ntstatus=0, filename='test_file.txt'))
@patch('export_gmail_attachments_to_nas.file_utils.script_logger')
def test_save_attachment_exception_logging(mock_logger, mock_stat, mock_register_session, mock_makedirs, mock_open_file):
    smb_server = 'test_server'
    smb_folder = f"\\\\{smb_server}\\test_folder"
    filename = 'test_file.txt'
    file_data = b'Test data'
    username = 'test_user'
    password = 'test_password'

    # Mock open_file to raise an exception
    mock_open_file.side_effect = Exception("Test exception")

    save_attachment(smb_server, smb_folder, filename, file_data, username, password)

    mock_register_session.assert_called_once_with(server=smb_server, username=username, password=password)
    mock_makedirs.assert_called_once_with(smb_folder, exist_ok=True)
    mock_stat.assert_called_once_with(f"{smb_folder}\\{filename}")
    mock_open_file.assert_called_once_with(f"{smb_folder}\\{filename}", mode='wb')
    mock_logger.error.assert_called_with("Error saving attachment: Test exception")

if __name__ == '__main__':
    pytest.main()