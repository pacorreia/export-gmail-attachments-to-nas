from dateutil import parser as date_parser
from unittest.mock import Mock, patch
from export_gmail_attachments_to_nas.gmail_service import process_emails, fetch_messages

@patch('export_gmail_attachments_to_nas.gmail_service.script_logger', Mock())
@patch('export_gmail_attachments_to_nas.gmail_service.fetch_messages')
@patch('export_gmail_attachments_to_nas.gmail_service.process_email')
def test_process_emails(mock_process_email, mock_fetch_messages):
    # Mock the service
    mock_service = Mock()
    
    # Mock the exit event
    mock_exit_event = Mock()
    mock_exit_event.is_set.return_value = False
    
    # Mock the fetch_messages function
    mock_fetch_messages.return_value = [{'id': 'test_msg_id'}]
    
    # Mock the process_email function
    mock_process_email.return_value = None
    
    # Define criteria data
    criteria_data = {
        'criteria': [
            {
                'enabled': True,
                'query': 'test_query',
                'smb_folder': 'test_folder',
                'filters': [],
                'attachment_content_filter': []
            }
        ],
        'smb_server': 'test_server'
    }
    
    # Call the function
    process_emails(mock_service, date_parser.parse('2023-01-01T00:00:00Z'), 'username', 'password', criteria_data, mock_exit_event)
    
    # Assertions
    mock_fetch_messages.assert_called_once_with(mock_service, 'after:1672531200 test_query', mock_exit_event)
    mock_process_email.assert_called_once_with(
        mock_service,
        'test_msg_id',
        'test_server',
        'test_folder',
        [],
        'username',
        'password',
        mock_exit_event,
        [],
        delete_after_save=False,
    )

def test_fetch_messages():
    # Mock the service
    mock_service = Mock()
    mock_service.users().messages().list().execute.side_effect = [
        {'messages': [{'id': 'msg1'}], 'nextPageToken': 'token'},
        {'messages': [{'id': 'msg2'}], 'nextPageToken': None}
    ]
    
    # Mock the exit event
    mock_exit_event = Mock()
    mock_exit_event.is_set.return_value = False
    
    # Call the function
    messages = fetch_messages(mock_service, 'test_query', mock_exit_event)
    
    # Assertions
    assert len(messages) == 2
    assert messages[0]['id'] == 'msg1'
    assert messages[1]['id'] == 'msg2'
    
@patch('export_gmail_attachments_to_nas.gmail_service.script_logger')
def test_fetch_messages_exception(mock_script_logger):
    # Mock the service
    mock_service = Mock()
    mock_service.users().messages().list().execute.side_effect = Exception("Test exception")
    
    # Mock the exit event
    mock_exit_event = Mock()
    mock_exit_event.is_set.return_value = False
    
    # Call the function
    messages = fetch_messages(mock_service, 'test_query', mock_exit_event)
    
    # Assertions
    assert len(messages) == 0
    mock_script_logger.error.assert_called_with("Failed to fetch messages: Test exception")
    
@patch('export_gmail_attachments_to_nas.gmail_service.script_logger')
def test_process_emails_timestamp_exception(mock_script_logger):
    # Mock the service
    mock_service = Mock()
    
    # Mock the exit event
    mock_exit_event = Mock()
    mock_exit_event.is_set.return_value = False
    
    # Mock the since_date to raise an exception
    mock_since_date = Mock()
    mock_since_date.timestamp.side_effect = Exception("Test exception")
    
    # Define criteria data
    criteria_data = {
        'criteria': [],
        'smb_server': 'test_server'
    }
    
    # Call the function
    process_emails(mock_service, mock_since_date, 'username', 'password', criteria_data, mock_exit_event)
    
    # Assertions
    mock_script_logger.error.assert_called_with("Error converting since_date to timestamp: Test exception")

@patch('export_gmail_attachments_to_nas.gmail_service.script_logger')
def test_process_emails_exit_event_set(mock_script_logger):
    # Mock the service
    mock_service = Mock()
    
    # Mock the exit event
    mock_exit_event = Mock()
    mock_exit_event.is_set.return_value = True
    
    # Define criteria data
    criteria_data = {
        'criteria': [{'enabled': True, 'query': 'test_query', 'smb_folder': 'test_folder'}],
        'smb_server': 'test_server'
    }
    
    # Call the function
    process_emails(mock_service, date_parser.parse('2023-01-01T00:00:00Z'), 'username', 'password', criteria_data, mock_exit_event)
    
    # Assertions
    mock_script_logger.info.assert_called_with("Exit requested. Stopping email processing.")
    
@patch('export_gmail_attachments_to_nas.gmail_service.script_logger')
def test_process_emails_criterion_disabled(mock_script_logger):
    # Mock the service
    mock_service = Mock()
    
    # Mock the exit event
    mock_exit_event = Mock()
    mock_exit_event.is_set.return_value = False
    
    # Define criteria data with one disabled criterion
    criteria_data = {
        'criteria': [
            {'enabled': False, 'query': 'test_query', 'smb_folder': 'test_folder'}
        ],
        'smb_server': 'test_server'
    }
    
    # Call the function
    process_emails(mock_service, date_parser.parse('2023-01-01T00:00:00Z'), 'username', 'password', criteria_data, mock_exit_event)
    
    # Assertions
    mock_script_logger.info.assert_called_with("Processing emails since: 2023-01-01 00:00:00+00:00")
    mock_service.users().messages().list.assert_not_called()

@patch('export_gmail_attachments_to_nas.gmail_service.script_logger')
@patch('export_gmail_attachments_to_nas.gmail_service.process_email')
def test_process_emails_exception_in_executor(mock_process_email, mock_script_logger):
    # Mock the service
    mock_service = Mock()
    mock_service.users().messages().list().execute.return_value = {'messages': [{'id': 'test_msg_id'}]}
    
    # Mock the exit event
    mock_exit_event = Mock()
    mock_exit_event.is_set.return_value = False
    
    # Mock the process_email to raise an exception
    mock_process_email.side_effect = Exception("Test exception")
    
    # Define criteria data
    criteria_data = {
        'criteria': [{'enabled': True, 'query': 'test_query', 'smb_folder': 'test_folder'}],
        'smb_server': 'test_server'
    }
    
    # Call the function
    process_emails(mock_service, date_parser.parse('2023-01-01T00:00:00Z'), 'username', 'password', criteria_data, mock_exit_event)
    
    # Assertions
    mock_script_logger.error.assert_called_with("Error processing email: Test exception")
    mock_exit_event.is_set.assert_called()