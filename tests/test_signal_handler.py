from unittest.mock import patch, MagicMock
import signal
from export_gmail_attachments_to_nas.main import signal_handler, script_logger, exit_event

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