from unittest.mock import patch, MagicMock, Mock
import signal
from export_gmail_attachments_to_nas.main import signal_handler, script_logger, exit_event
from export_gmail_attachments_to_nas.gmail_service import fetch_messages

@patch.object(script_logger, 'info')
@patch.object(exit_event, 'set')
def test_signal_handler(mock_set, mock_info):
    # Mock signal and frame
    mock_signal = signal.SIGINT
    mock_frame = MagicMock()

    # Call the signal_handler function
    signal_handler(mock_signal, mock_frame)

    # Assert that script_logger.info was called with the expected message
    mock_info.assert_called_once_with("Exit signal received. Shutting down gracefully...")

    # Assert that exit_event.set was called
    mock_set.assert_called_once()

@patch('export_gmail_attachments_to_nas.gmail_service.script_logger')
def test_fetch_messages_exit_event_set(mock_script_logger):
    # Mock the service
    mock_service = Mock()
    
    # Mock the exit event
    mock_exit_event = Mock()
    mock_exit_event.is_set.return_value = True
    
    # Call the function
    messages = fetch_messages(mock_service, 'test_query', mock_exit_event)
    
    # Assertions
    assert len(messages) == 0
    mock_script_logger.info.assert_called_with("Exit requested. Stopping email fetching.")

