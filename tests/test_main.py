import pytest
from unittest.mock import MagicMock, patch, mock_open
import json
from export_gmail_attachments_to_nas.main import main_loop, exit_event

@patch('export_gmail_attachments_to_nas.main.script_logger')
@patch('export_gmail_attachments_to_nas.gmail_service.authenticate_gmail')
@patch('export_gmail_attachments_to_nas.gmail_service.process_emails')
@patch('export_gmail_attachments_to_nas.gmail_service.get_last_run_timestamp')
@patch('export_gmail_attachments_to_nas.gmail_service.update_last_run_timestamp')
@patch('export_gmail_attachments_to_nas.main.time.sleep', return_value=None)  # Mock sleep to avoid actual delay
def test_main_loop_criteria_file_error(mock_sleep, mock_update_last_run_timestamp, mock_get_last_run_timestamp, mock_process_emails, mock_authenticate_gmail, mock_script_logger):
    # Mock the arguments
    mock_args = MagicMock()
    mock_args.username = 'test_user'
    mock_args.password = 'test_pass'
    mock_args.criteria = 'criteria.json'
    mock_args.credentials = 'credentials.json'

    # Mock the environment variables
    with patch.dict('os.environ', {'NAS_USERNAME': '', 'NAS_PASSWORD': ''}):
        # Mock the open function to raise an exception
        with patch('builtins.open', mock_open(read_data='')) as mock_file:
            mock_file.side_effect = Exception("File not found")

            # Call the function
            with pytest.raises(SystemExit):
                main_loop(mock_args)

            # Assertions
            mock_script_logger.error.assert_any_call("Error loading criteria.json: File not found")
            mock_authenticate_gmail.assert_not_called()
            mock_process_emails.assert_not_called()
            mock_update_last_run_timestamp.assert_not_called()